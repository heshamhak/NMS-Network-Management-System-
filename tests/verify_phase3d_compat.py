#!/usr/bin/env python3
"""
Phase 3D: OpenWrt Cross-Version & Isolated Runtime Lifecycle Verification
- Executes Phase 3A, 3B, and 3C ucode suites directly inside isolated OpenWrt 24.10.0 (opkg) AND 25.12.6 (apk) chroots
- Executes scripts/install.sh (fresh, in-place upgrade, fail-point rollback) and scripts/uninstall.sh INSIDE the actual OpenWrt rootfs chroots using OpenWrt's own /bin/sh & BusyBox utilities
- Verifies /etc/sysupgrade.conf byte-for-byte preservation, file type, mode, UID, and GID across every lifecycle step, plus LuCI preservation
- Verifies zero ELF binaries in runtime deliverables (100% portable ucode + POSIX sh + vanilla JS); non-x86_64 execution is NOT claimed on this x86_64 host
"""

import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOTFS_2512 = "/tmp/openwrt-x86-64-rootfs"
ROOTFS_2410 = "/tmp/openwrt-24.10-x86-64-rootfs"

passed = 0
failed = 0
skipped = 0


def check(cond, label, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"[PASS] {label}")
    else:
        failed += 1
        print(f"[FAIL] {label}" + (f" ({detail})" if detail else ""))


def skip(label, reason):
    global skipped
    skipped += 1
    print(f"[SKIP] {label}: {reason}")


def generate_phase3a_vectors(td_arc):
    def fix_chksum(hdr_bytes):
        b = bytearray(hdr_bytes)
        b[148:156] = b"        "
        chk = sum(b)
        b[148:156] = f"{chk:06o}\0 ".encode("ascii")
        return bytes(b)

    def raw_tar_block(name, tflag=b"0", size=0, linkname=b"", payload=b""):
        b = bytearray(512)
        b[0:len(name)] = name
        b[100:108] = b"0000644\0"
        b[108:116] = b"0000000\0"
        b[116:124] = b"0000000\0"
        b[124:136] = f"{size:011o}\0".encode("ascii")
        b[136:148] = b"00000000000\0"
        b[156:157] = tflag
        b[157:157 + len(linkname)] = linkname
        b[257:263] = b"ustar\0"
        b[263:265] = b"00"
        out = fix_chksum(b)
        if payload:
            pad = (512 - (len(payload) % 512)) % 512
            out += payload + (b"\x00" * pad)
        return out

    def pax_rec(k, v):
        body = f" {k}={v}\n".encode("utf-8")
        l = len(body) + 2
        while len(f"{l}".encode("ascii")) + len(body) != l:
            l = len(f"{l}".encode("ascii")) + len(body)
        return f"{l}".encode("ascii") + body

    def make_tar(fn, builder):
        p = os.path.join(td_arc, fn)
        with tarfile.open(p, "w") as tf:
            builder(tf)
        return p

    def add_reg(tf, name, data=b"x\n"):
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))

    def add_sym(tf, name, target):
        si = tarfile.TarInfo(name)
        si.type = tarfile.SYMTYPE
        si.linkname = target
        tf.addfile(si)

    def add_hard(tf, name, target):
        hi = tarfile.TarInfo(name)
        hi.type = tarfile.LNKTYPE
        hi.linkname = target
        tf.addfile(hi)

    valid_tar = make_tar("valid.tar", lambda tf: (
        add_reg(tf, "etc/config/network"),
        add_reg(tf, "etc/my file -> with arrow.conf"),
        add_sym(tf, "etc/rc.d/S10boot", "../init.d/boot"),
        add_hard(tf, "etc/config/network.bak", "etc/config/network"),
    ))
    make_tar("abs_sym.tar", lambda tf: add_sym(tf, "etc/bad", "/etc/shadow"))
    make_tar("abs_hard.tar", lambda tf: add_hard(tf, "etc/badh", "/etc/passwd"))
    make_tar("rel_esc.tar", lambda tf: add_sym(tf, "etc/sub/esc", "../../../etc/shadow"))
    make_tar("rel_scope.tar", lambda tf: add_sym(tf, "etc/sub/esc2", "../../tmp/evil"))
    make_tar("nested_trav.tar", lambda tf: add_reg(tf, "etc/a/../../b"))
    make_tar("nl_name.tar", lambda tf: add_reg(tf, "etc/bad\nname"))
    make_tar("out_scope.tar", lambda tf: add_reg(tf, "tmp/evil.sh"))
    open(os.path.join(td_arc, "partial.tar"), "wb").write(open(valid_tar, "rb").read()[:300])
    make_tar("empty.tar", lambda tf: None)

    bad_chk_data = bytearray(open(valid_tar, "rb").read())
    bad_chk_data[148] = ord("9")
    open(os.path.join(td_arc, "bad_chksum.tar"), "wb").write(bad_chk_data)

    bad_oct = bytearray(raw_tar_block(b"etc/x", size=2))
    bad_oct[124:136] = b"00000000099\0"
    bad_oct = bytearray(fix_chksum(bad_oct[:512])) + bad_oct[512:] + b"\x00" * 1024
    open(os.path.join(td_arc, "bad_octal.tar"), "wb").write(bad_oct)

    bad_pax_payload = b"11 badrecord\n"
    open(os.path.join(td_arc, "bad_pax.tar"), "wb").write(
        raw_tar_block(b"PaxHeader/x", tflag=b"x", size=len(bad_pax_payload), payload=bad_pax_payload)
        + raw_tar_block(b"etc/x") + b"\x00" * 1024
    )

    gpax_bad = pax_rec("path", "/etc/shadow")
    open(os.path.join(td_arc, "gpax_bad.tar"), "wb").write(
        raw_tar_block(b"pax_global_header", tflag=b"g", size=len(gpax_bad), payload=gpax_bad)
        + raw_tar_block(b"etc/x") + b"\x00" * 1024
    )
    gpax_ok = pax_rec("mtime", "1700000000")
    open(os.path.join(td_arc, "gpax_ok.tar"), "wb").write(
        raw_tar_block(b"pax_global_header", tflag=b"g", size=len(gpax_ok), payload=gpax_ok)
        + raw_tar_block(b"etc/x") + b"\x00" * 1024
    )

    long_ok = b"etc/" + (b"a" * 110) + b".conf\0"
    open(os.path.join(td_arc, "gnu_long_ok.tar"), "wb").write(
        raw_tar_block(b"././@LongLink", tflag=b"L", size=len(long_ok), payload=long_ok)
        + raw_tar_block(b"etc/short") + b"\x00" * 1024
    )
    long_bad = b"etc/../../etc/shadow\0"
    open(os.path.join(td_arc, "gnu_long_trav.tar"), "wb").write(
        raw_tar_block(b"././@LongLink", tflag=b"L", size=len(long_bad), payload=long_bad)
        + raw_tar_block(b"etc/short") + b"\x00" * 1024
    )
    open(os.path.join(td_arc, "missing_eof.tar"), "wb").write(raw_tar_block(b"etc/x") + b"\x00" * 512)

    pax_conf = pax_rec("path", "etc/a")
    gnu_conf = b"etc/b\0"
    open(os.path.join(td_arc, "conflicting_meta.tar"), "wb").write(
        raw_tar_block(b"PaxHeader/x", tflag=b"x", size=len(pax_conf), payload=pax_conf)
        + raw_tar_block(b"././@LongLink", tflag=b"L", size=len(gnu_conf), payload=gnu_conf)
        + raw_tar_block(b"etc/c") + b"\x00" * 1024
    )

    cases = [
        {"name": "valid_spaces_arrows_links", "file": "valid.tar", "expect_valid": True},
        {"name": "abs_symlink", "file": "abs_sym.tar", "expect_valid": False},
        {"name": "abs_hardlink", "file": "abs_hard.tar", "expect_valid": False},
        {"name": "rel_symlink_escape_root", "file": "rel_esc.tar", "expect_valid": False},
        {"name": "rel_symlink_escape_scope", "file": "rel_scope.tar", "expect_valid": False},
        {"name": "nested_traversal", "file": "nested_trav.tar", "expect_valid": False},
        {"name": "newline_filename", "file": "nl_name.tar", "expect_valid": False},
        {"name": "out_of_scope", "file": "out_scope.tar", "expect_valid": False},
        {"name": "partial_write", "file": "partial.tar", "expect_valid": False},
        {"name": "empty_archive", "file": "empty.tar", "expect_valid": False},
        {"name": "bad_checksum", "file": "bad_chksum.tar", "expect_valid": False},
        {"name": "bad_octal_size", "file": "bad_octal.tar", "expect_valid": False},
        {"name": "malformed_pax", "file": "bad_pax.tar", "expect_valid": False},
        {"name": "global_pax_path_override", "file": "gpax_bad.tar", "expect_valid": False},
        {"name": "global_pax_valid_mtime", "file": "gpax_ok.tar", "expect_valid": True},
        {"name": "gnu_longname_valid", "file": "gnu_long_ok.tar", "expect_valid": True},
        {"name": "gnu_longname_traversal", "file": "gnu_long_trav.tar", "expect_valid": False},
        {"name": "missing_eof_markers", "file": "missing_eof.tar", "expect_valid": False},
        {"name": "conflicting_pax_gnu", "file": "conflicting_meta.tar", "expect_valid": False},
    ]
    with open(os.path.join(td_arc, "manifest.json"), "w", encoding="utf-8") as mf:
        json.dump({"cases": cases}, mf)


def build_helperd_prod_slice():
    helperd_src = open(os.path.join(REPO_ROOT, "backend", "noc-helperd"), "r", encoding="utf-8").read()
    m_aw = re.search(r"(function atomic_write\(.*?\n\}\n\nfunction atomic_write_or_reply\(.*?\n\})", helperd_src, re.DOTALL)
    m_frz = re.search(r"(function get_freeze_state\(.*?\n\}\n\nfunction enter_emergency_freeze\(.*?\n\}\n\nfunction enforce_mutation_gate\(.*?\n\})", helperd_src, re.DOTALL)
    m_fw = re.search(r"(function fw_check_and_reload\(.*?\n\})", helperd_src, re.DOTALL)
    m_su = re.search(r"(function handle_sys_sysupgrade_conf_save\(.*?\n\})", helperd_src, re.DOTALL)
    m_rr = re.search(r"(function handle_rollback_revert\(.*?\n\})", helperd_src, re.DOTALL)
    m_rb = re.search(r"(function rollback_client_rules\(.*?\n\})", helperd_src, re.DOTALL)
    m_net = re.search(r"(function array_eq\(.*?\n\}\n\nfunction handle_network_phase3b_verb\(.*?\n\})", helperd_src, re.DOTALL)
    m_p3c = re.search(r"(function handle_phase3c_verb\(.*?\n\})", helperd_src, re.DOTALL)
    assert all([m_aw, m_frz, m_fw, m_su, m_rr, m_rb, m_net, m_p3c]), "Failed to extract noc-helperd production handlers"
    return (
        "import * as real_fs from 'fs';\n"
        "import * as uci from 'uci';\n"
        "import * as nms_archive from '/tmp/p3a_test/nms_archive.uc';\n"
        "import * as nms_network from '/tmp/p3a_test/nms_network.uc';\n"
        "import * as nms_fw_wifi from '/tmp/p3a_test/nms_fw_wifi.uc';\n"
        "export let test_audits = [];\n"
        "export let test_locks_released = 0;\n"
        "export let test_warns = [];\n"
        "export let ETC_DIR = '/tmp/p3a_test/etc_mock';\n"
        "export let SYSUPGRADE_CONF_PATH = '/tmp/p3a_test/sysupgrade.conf';\n"
        "export let CAP_GENERAL = 65536;\n"
        "export let emergency_freeze_state = null;\n"
        "export let mock_exec_res = { ok: false };\n"
        "export let mock_apply_res = { ok: true };\n"
        "export let mock_readfile_null_path = null;\n"
        "export let spy_mutations = 0;\n"
        "let fs = {\n"
        "  stat: real_fs.stat,\n"
        "  lstat: real_fs.lstat,\n"
        "  open: function(p, fl, m) { spy_mutations++; return real_fs.open(p, fl, m); },\n"
        "  writefile: function(p, c) { spy_mutations++; return real_fs.writefile(p, c); },\n"
        "  chown: function(p, u, g) { spy_mutations++; return real_fs.chown(p, u, g); },\n"
        "  chmod: function(p, m) { spy_mutations++; return real_fs.chmod(p, m); },\n"
        "  rename: function(s, d) { spy_mutations++; return real_fs.rename(s, d); },\n"
        "  unlink: function(p) { spy_mutations++; return real_fs.unlink(p); },\n"
        "  readfile: function(p) { if (mock_readfile_null_path != null && p == mock_readfile_null_path) return null; return real_fs.readfile(p); }\n"
        "};\n"
        "function read_json(p, fb) { let r = fs.readfile(p); if (!r) return fb; try { return json(r); } catch (e) { return fb; } }\n"
        "function now_mono_ms() { return 12345; }\n"
        "function now_iso() { return '2026-11-22T00:00:00Z'; }\n"
        "function urandom_hex(n) { return 'abcd'; }\n"
        "function system(cmd) { return 0; }\n"
        "function warn(msg) { push(test_warns, msg); }\n"
        "function audit_append(actor, act, tgt, res, det) { push(test_audits, { actor: actor, action: act, target: tgt, result: res, details: det }); }\n"
        "function release_lock() { test_locks_released++; }\n"
        "function exec_argv_async(exe, argv, t, c, cb) { cb(mock_exec_res); }\n"
        "function apply_bridge_block_rules(rules, cb) { cb(mock_apply_res); }\n"
        "function check_staging_guard() { return { ok: true }; }\n"
        "function check_storage_budget() { return { ok: true }; }\n"
        "function acquire_lock(o, op) { return { ok: true }; }\n"
        "function set_mock(ec, ap, ed, su_p, null_p) { ETC_DIR = ed; mock_exec_res = ec; mock_apply_res = ap; if (su_p != null) SYSUPGRADE_CONF_PATH = su_p; mock_readfile_null_path = null_p; spy_mutations = 0; }\n"
        "function clear_freeze_mem() { emergency_freeze_state = null; }\n"
        + m_aw.group(1) + "\n"
        + m_frz.group(1) + "\n"
        + m_fw.group(1) + "\n"
        + m_su.group(1) + "\n"
        + m_rr.group(1) + "\n"
        + m_rb.group(1) + "\n"
        + m_net.group(1) + "\n"
        + m_p3c.group(1) + "\n"
        + "\nexport { atomic_write, atomic_write_or_reply, get_freeze_state, enter_emergency_freeze, enforce_mutation_gate, fw_check_and_reload, handle_sys_sysupgrade_conf_save, handle_rollback_revert, rollback_client_rules, handle_network_phase3b_verb, handle_phase3c_verb, set_mock, clear_freeze_mem };\n"
    )


EXPECTED_SUITES = {
    "verify_phase3a_ucode.uc": ("UCODE_SUMMARY", 48),
    "verify_phase3b_ucode.uc": ("UCODE3B_SUMMARY", 39),
    "verify_phase3c_ucode.uc": ("UCODE3C_SUMMARY", 47),
}


def evaluate_ucode_suite_output(script_name, returncode, stdout):
    prefix, exp_passed = EXPECTED_SUITES[script_name]
    matches = re.findall(rf"^{re.escape(prefix)}:\s*(\d+)\s+passed,\s*(\d+)\s+failed\s*$", stdout or "", re.M)
    if returncode != 0 or len(matches) != 1:
        return False, f"rc={returncode} summary_matches={len(matches)}"
    got_passed, got_failed = int(matches[0][0]), int(matches[0][1])
    if got_failed != 0 or got_passed != exp_passed:
        return False, f"expected={exp_passed}/0 got={got_passed}/{got_failed}"
    return True, f"{got_passed} passed, {got_failed} failed (expected {exp_passed})"


def run_ucode_suite_in_chroot(rootfs_dir, ver_label, script_name, helperd_prod_src):
    if not os.path.isdir(rootfs_dir) or not os.path.isfile(os.path.join(rootfs_dir, "usr/bin/ucode")):
        skip(f"P3D-CHROOT[{ver_label},{script_name}]", f"rootfs missing at {rootfs_dir}")
        return
    p3a_dir = os.path.join(rootfs_dir, "tmp", "p3a_test")
    if os.path.exists(p3a_dir):
        shutil.rmtree(p3a_dir, ignore_errors=True)
    os.makedirs(p3a_dir, exist_ok=True)
    libexec_dir = os.path.join(rootfs_dir, "usr", "libexec")
    os.makedirs(libexec_dir, exist_ok=True)
    preexisting_backups = []
    created_libexec = []
    try:
        for mod in ("nms_archive.uc", "nms_network.uc", "nms_fw_wifi.uc"):
            src_mod = os.path.join(REPO_ROOT, "backend", mod)
            shutil.copy2(src_mod, os.path.join(p3a_dir, mod))
            dst_lib = os.path.join(libexec_dir, mod)
            if os.path.lexists(dst_lib):
                st = os.lstat(dst_lib)
                preexisting_backups.append((dst_lib, open(dst_lib, "rb").read(), st.st_mode & 0o777, st.st_uid, st.st_gid))
            else:
                created_libexec.append(dst_lib)
            shutil.copy2(src_mod, dst_lib)
        with open(os.path.join(p3a_dir, "helperd_aw_prod.uc"), "w", encoding="utf-8") as f:
            f.write(helperd_prod_src)
        shutil.copy2(os.path.join(REPO_ROOT, "tests", script_name), os.path.join(p3a_dir, script_name))

        vec_dir = os.path.join(p3a_dir, "vec")
        os.makedirs(vec_dir, exist_ok=True)
        os.makedirs(os.path.join(p3a_dir, "etc_mock"), exist_ok=True)
        if script_name == "verify_phase3a_ucode.uc":
            generate_phase3a_vectors(vec_dir)
            args = ["/tmp/p3a_test/nms_archive.uc", "/tmp/p3a_test/vec"]
        else:
            args = ["/tmp/p3a_test/vec"]

        res = subprocess.run(
            ["unshare", "-r", "/usr/sbin/chroot", rootfs_dir, "/usr/bin/ucode", f"/tmp/p3a_test/{script_name}"] + args,
            capture_output=True, text=True, timeout=30
        )
        ok, detail = evaluate_ucode_suite_output(script_name, res.returncode, res.stdout)
        check(ok, f"P3D-CHROOT[{ver_label},{script_name}]", detail if ok else f"{detail} tail={(res.stderr or res.stdout)[-200:]}")
    finally:
        shutil.rmtree(p3a_dir, ignore_errors=True)
        for p in created_libexec:
            if os.path.lexists(p):
                os.unlink(p)
        for dst_lib, raw_bytes, mode, uid, gid in preexisting_backups:
            with open(dst_lib, "wb") as bf:
                bf.write(raw_bytes)
            os.chmod(dst_lib, mode)
            try:
                os.chown(dst_lib, uid, gid)
            except PermissionError:
                pass


def verify_sysupgrade_preservation(sb, expected_bytes, orig_uid, orig_gid, label):
    p = os.path.join(sb, "etc", "sysupgrade.conf")
    if not os.path.lexists(p):
        check(False, label, "missing /etc/sysupgrade.conf")
        return
    st = os.lstat(p)
    actual_bytes = open(p, "rb").read()
    ok = (
        stat.S_ISREG(st.st_mode)
        and (st.st_mode & 0o777) == 0o644
        and st.st_uid == orig_uid
        and st.st_gid == orig_gid
        and actual_bytes == expected_bytes
    )
    check(ok, label, f"mode={oct(st.st_mode & 0o777)} uid={st.st_uid} gid={st.st_gid} len={len(actual_bytes)}")


def test_in_chroot_lifecycle(rootfs_dir, ver_label):
    if not os.path.isdir(rootfs_dir) or not os.path.isfile(os.path.join(rootfs_dir, "bin/sh")):
        skip(f"P3D-LIFECYCLE[{ver_label}]", f"rootfs missing at {rootfs_dir}")
        return
    with tempfile.TemporaryDirectory(prefix=f"nms_p3d_chroot_{ver_label}_") as tmp:
        sb = os.path.join(tmp, "rootfs")
        shutil.copytree(rootfs_dir, sb, symlinks=True)

        # Stage NMS repository cleanly inside sandbox /tmp/nms_repo (no host paths touched)
        repo_dst = os.path.join(sb, "tmp", "nms_repo")
        for sub in ("backend", "frontend", "init.d", "scripts", "schemas"):
            shutil.copytree(os.path.join(REPO_ROOT, sub), os.path.join(repo_dst, sub), symlinks=True)

        # Seed LuCI files and /etc/sysupgrade.conf
        os.makedirs(os.path.join(sb, "www"), exist_ok=True)
        os.makedirs(os.path.join(sb, "etc", "config"), exist_ok=True)
        os.makedirs(os.path.join(sb, "tmp", "lock"), exist_ok=True)
        luci_html = b"<html><body>LuCI-Active</body></html>\n"
        luci_uhttpd = b"config uhttpd 'main'\n\tlist listen_http '0.0.0.0:80'\n"
        sysupgrade_orig = b"# User custom sysupgrade\n/etc/dropbear/\n/etc/config/wireless\n"
        with open(os.path.join(sb, "www", "index.html"), "wb") as f:
            f.write(luci_html)
        with open(os.path.join(sb, "etc", "config", "uhttpd"), "wb") as f:
            f.write(luci_uhttpd)
        su_path = os.path.join(sb, "etc", "sysupgrade.conf")
        with open(su_path, "wb") as f:
            f.write(sysupgrade_orig)
        os.chmod(su_path, 0o644)
        su_orig_st = os.lstat(su_path)

        # Controlled service runner inside chroot (avoids procd/socket startup in minimal chroot)
        runner_in = os.path.join(sb, "tmp", "svc_runner.sh")
        with open(runner_in, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(runner_in, 0o755)

        def run_in_openwrt(cmd_args, extra_env=None):
            env_prefix = "NMS_SKIP_PKG_INSTALL=1 NMS_SKIP_SERVICE_START=1 NMS_SERVICE_RUNNER=/tmp/svc_runner.sh"
            if extra_env:
                for k, v in extra_env.items():
                    env_prefix += f" {k}={v}"
            shell_cmd = f"env {env_prefix} /bin/sh " + " ".join(cmd_args)
            return subprocess.run(
                ["unshare", "-r", "/usr/sbin/chroot", sb, "/bin/sh", "-c", shell_cmd],
                capture_output=True, text=True, timeout=30
            )

        # Probe required ucode modules inside the isolated rootfs (no network/pkg install allowed)
        probe = subprocess.run(
            ["unshare", "-r", "/usr/sbin/chroot", sb, "/usr/bin/ucode", "-e",
             "import * as a from 'fs'; import * as b from 'ubus'; import * as c from 'uci'; "
             "import * as d from 'socket'; import * as e from 'math'; import * as f from 'struct'; "
             "import * as g from 'uloop'; import * as h from 'digest';"],
            capture_output=True, text=True, timeout=10
        )
        if probe.returncode != 0:
            # Verify install.sh fails closed without attempting package install, and preserves LuCI + /etc/sysupgrade.conf
            r_fail_pre = run_in_openwrt(["/tmp/nms_repo/scripts/install.sh", "--allow-insecure-lan-http"])
            pre_fail_ok = (
                r_fail_pre.returncode != 0
                and "package installation is disabled" in (r_fail_pre.stderr + r_fail_pre.stdout)
                and open(os.path.join(sb, "www", "index.html"), "rb").read() == luci_html
                and open(os.path.join(sb, "etc", "config", "uhttpd"), "rb").read() == luci_uhttpd
            )
            check(pre_fail_ok, f"P3D-CHROOT-PREREQ[{ver_label},fails_closed_when_ucode_mods_missing]")
            verify_sysupgrade_preservation(sb, sysupgrade_orig, su_orig_st.st_uid, su_orig_st.st_gid, f"P3D-CHROOT-SYSUPGRADE[{ver_label},preserved_on_prereq_abort]")
            skip(f"P3D-CHROOT-LIFECYCLE[{ver_label}]", "minimal offline rootfs lacks ucode-mod-socket/struct/uloop/digest and network pkg install is forbidden")
            return

        # 1. Fresh Install inside actual OpenWrt rootfs
        r_inst = run_in_openwrt(["/tmp/nms_repo/scripts/install.sh", "--allow-insecure-lan-http"])
        inst_ok = (
            r_inst.returncode == 0
            and os.path.isfile(os.path.join(sb, "usr", "libexec", "nms_archive.uc"))
            and os.path.isfile(os.path.join(sb, "usr", "libexec", "nms_network.uc"))
            and os.path.isfile(os.path.join(sb, "usr", "libexec", "nms_fw_wifi.uc"))
            and os.path.isfile(os.path.join(sb, "usr", "libexec", "noc-helperd"))
            and os.path.isfile(os.path.join(sb, "usr", "libexec", "noc-apid"))
            and os.path.isfile(os.path.join(sb, "etc", "init.d", "noc-helperd"))
            and os.path.isfile(os.path.join(sb, "etc", "init.d", "noc-apid"))
            and os.path.isfile(os.path.join(sb, "www", "pro", "index.html"))
        )
        check(inst_ok, f"P3D-CHROOT-INSTALL[{ver_label},fresh]", f"rc={r_inst.returncode} " + (r_inst.stderr or r_inst.stdout)[-260:])
        check(
            open(os.path.join(sb, "www", "index.html"), "rb").read() == luci_html
            and open(os.path.join(sb, "etc", "config", "uhttpd"), "rb").read() == luci_uhttpd,
            f"P3D-CHROOT-LUCI[{ver_label},preserved_after_install]"
        )
        verify_sysupgrade_preservation(sb, sysupgrade_orig, su_orig_st.st_uid, su_orig_st.st_gid, f"P3D-CHROOT-SYSUPGRADE[{ver_label},preserved_after_install]")

        # 2. In-Place Upgrade inside actual OpenWrt rootfs
        r_upg = run_in_openwrt(["/tmp/nms_repo/scripts/install.sh", "--allow-insecure-lan-http"])
        check(r_upg.returncode == 0, f"P3D-CHROOT-UPGRADE[{ver_label},in_place]", f"rc={r_upg.returncode} " + (r_upg.stderr or r_upg.stdout)[-260:])
        check(
            open(os.path.join(sb, "www", "index.html"), "rb").read() == luci_html
            and open(os.path.join(sb, "etc", "config", "uhttpd"), "rb").read() == luci_uhttpd,
            f"P3D-CHROOT-LUCI[{ver_label},preserved_after_upgrade]"
        )
        verify_sysupgrade_preservation(sb, sysupgrade_orig, su_orig_st.st_uid, su_orig_st.st_gid, f"P3D-CHROOT-SYSUPGRADE[{ver_label},preserved_after_upgrade]")

        # 3. Failed Install Rollback (fail_point=after_backend) -> must restore managed files & manifest, clean tmp, and keep LuCI/sysupgrade.conf intact
        import hashlib
        def snap_state():
            tracked = [
                os.path.join(sb, "usr", "libexec", "noc-helperd"),
                os.path.join(sb, "usr", "libexec", "nms_archive.uc"),
                os.path.join(sb, "etc", "noc-console", "installed_files.manifest"),
            ]
            return {p: (hashlib.sha256(open(p, "rb").read()).hexdigest(), os.lstat(p).st_mode & 0o777) for p in tracked}

        pre_fail_state = snap_state()
        r_fail = run_in_openwrt(["/tmp/nms_repo/scripts/install.sh", "--allow-insecure-lan-http"], {"NMS_TEST_FAIL_POINT": "after_backend"})
        post_fail_state = snap_state()
        orphan_tmps = [
            fn for d in (os.path.join(sb, "etc", "noc-console"), os.path.join(sb, "usr", "libexec"))
            for fn in os.listdir(d) if ".tmp." in fn or ".bak." in fn
        ]
        rb_ok = (
            r_fail.returncode != 0
            and post_fail_state == pre_fail_state
            and len(orphan_tmps) == 0
            and open(os.path.join(sb, "www", "index.html"), "rb").read() == luci_html
            and open(os.path.join(sb, "etc", "config", "uhttpd"), "rb").read() == luci_uhttpd
        )
        check(rb_ok, f"P3D-CHROOT-FAILROLLBACK[{ver_label},restored_managed_files_manifest_and_luci]", f"rc={r_fail.returncode} orphans={orphan_tmps}")
        verify_sysupgrade_preservation(sb, sysupgrade_orig, su_orig_st.st_uid, su_orig_st.st_gid, f"P3D-CHROOT-SYSUPGRADE[{ver_label},preserved_after_failed_install]")

        # 4. Clean Uninstall inside actual OpenWrt rootfs
        r_un = run_in_openwrt(["/tmp/nms_repo/scripts/uninstall.sh"])
        un_ok = (
            r_un.returncode == 0
            and not os.path.exists(os.path.join(sb, "usr", "libexec", "noc-helperd"))
            and not os.path.exists(os.path.join(sb, "etc", "noc-console", "installed_files.manifest"))
            and open(os.path.join(sb, "www", "index.html"), "rb").read() == luci_html
            and open(os.path.join(sb, "etc", "config", "uhttpd"), "rb").read() == luci_uhttpd
        )
        check(un_ok, f"P3D-CHROOT-UNINSTALL[{ver_label},clean_restore_and_luci_intact]", f"rc={r_un.returncode} " + (r_un.stderr or r_un.stdout)[-260:])
        verify_sysupgrade_preservation(sb, sysupgrade_orig, su_orig_st.st_uid, su_orig_st.st_gid, f"P3D-CHROOT-SYSUPGRADE[{ver_label},preserved_after_uninstall]")


def test_architecture_portability():
    elf_hits = []
    for sub in ("backend", "frontend", "init.d", "scripts", "schemas"):
        base = os.path.join(REPO_ROOT, sub)
        for root, _, files in os.walk(base):
            for fn in files:
                p = os.path.join(root, fn)
                with open(p, "rb") as f:
                    if f.read(4) == b"\x7fELF":
                        elf_hits.append(p)
    check(len(elf_hits) == 0, "P3D-ARCH[zero_elf_binaries_in_deliverables]", str(elf_hits))


def test_sandboxed_lifecycle_with_rollback():
    import hashlib
    with tempfile.TemporaryDirectory(prefix="nms_p3d_sb_") as tmp:
        sb = os.path.join(tmp, "sandbox")
        os.makedirs(os.path.join(sb, "etc", "config"), exist_ok=True)
        os.makedirs(os.path.join(sb, "etc", "init.d"), exist_ok=True)
        os.makedirs(os.path.join(sb, "www"), exist_ok=True)
        os.makedirs(os.path.join(sb, "usr", "libexec"), exist_ok=True)
        os.makedirs(os.path.join(sb, "tmp"), exist_ok=True)
        shutil.copy2(os.path.join(ROOTFS_2512, "etc", "passwd"), os.path.join(sb, "etc", "passwd"))
        shutil.copy2(os.path.join(ROOTFS_2512, "etc", "group"), os.path.join(sb, "etc", "group"))

        luci_html = b"<html><body>LuCI-Active</body></html>\n"
        luci_uhttpd = b"config uhttpd 'main'\n\tlist listen_http '0.0.0.0:80'\n"
        sysupgrade_orig = b"# User custom sysupgrade\n/etc/dropbear/\n/etc/config/wireless\n"
        with open(os.path.join(sb, "www", "index.html"), "wb") as f:
            f.write(luci_html)
        with open(os.path.join(sb, "etc", "config", "uhttpd"), "wb") as f:
            f.write(luci_uhttpd)
        su_path = os.path.join(sb, "etc", "sysupgrade.conf")
        with open(su_path, "wb") as f:
            f.write(sysupgrade_orig)
        os.chmod(su_path, 0o644)
        su_orig_st = os.lstat(su_path)

        runner = os.path.join(tmp, "svc_runner.sh")
        with open(runner, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(runner, 0o755)

        env = os.environ.copy()
        env["NMS_ROOT_PREFIX"] = sb
        env["NMS_SKIP_SERVICE_START"] = "1"
        env["NMS_SERVICE_RUNNER"] = runner

        r1 = subprocess.run(["/bin/sh", os.path.join(REPO_ROOT, "scripts", "install.sh")], env=env, capture_output=True, text=True, timeout=30)
        check(r1.returncode == 0 and os.path.isfile(os.path.join(sb, "etc", "noc-console", "tls.crt")), "P3D-SB-INSTALL[fresh]")
        verify_sysupgrade_preservation(sb, sysupgrade_orig, su_orig_st.st_uid, su_orig_st.st_gid, "P3D-SB-SYSUPGRADE[after_install]")

        r2 = subprocess.run(["/bin/sh", os.path.join(REPO_ROOT, "scripts", "install.sh")], env=env, capture_output=True, text=True, timeout=30)
        check(r2.returncode == 0, "P3D-SB-UPGRADE[in_place]")
        verify_sysupgrade_preservation(sb, sysupgrade_orig, su_orig_st.st_uid, su_orig_st.st_gid, "P3D-SB-SYSUPGRADE[after_upgrade]")

        tracked = [
            os.path.join(sb, "usr", "libexec", "noc-helperd"),
            os.path.join(sb, "usr", "libexec", "nms_archive.uc"),
            os.path.join(sb, "etc", "noc-console", "installed_files.manifest"),
        ]
        pre_snap = {p: (hashlib.sha256(open(p, "rb").read()).hexdigest(), os.lstat(p).st_mode & 0o777) for p in tracked}
        env_fail = env.copy()
        env_fail["NMS_TEST_FAIL_POINT"] = "after_backend"
        rf = subprocess.run(["/bin/sh", os.path.join(REPO_ROOT, "scripts", "install.sh")], env=env_fail, capture_output=True, text=True, timeout=30)
        post_snap = {p: (hashlib.sha256(open(p, "rb").read()).hexdigest(), os.lstat(p).st_mode & 0o777) for p in tracked}
        orphans = [fn for d in (os.path.join(sb, "etc", "noc-console"), os.path.join(sb, "usr", "libexec")) for fn in os.listdir(d) if ".tmp." in fn or ".bak." in fn]
        check(
            rf.returncode != 0 and post_snap == pre_snap and len(orphans) == 0
            and open(os.path.join(sb, "www", "index.html"), "rb").read() == luci_html
            and open(os.path.join(sb, "etc", "config", "uhttpd"), "rb").read() == luci_uhttpd,
            "P3D-SB-FAILROLLBACK[restored_managed_files_manifest_and_luci]",
            f"rc={rf.returncode} orphans={orphans}"
        )
        verify_sysupgrade_preservation(sb, sysupgrade_orig, su_orig_st.st_uid, su_orig_st.st_gid, "P3D-SB-SYSUPGRADE[after_failed_install]")

        ru = subprocess.run(["/bin/sh", os.path.join(REPO_ROOT, "scripts", "uninstall.sh")], env=env, capture_output=True, text=True, timeout=30)
        check(
            ru.returncode == 0
            and not os.path.exists(os.path.join(sb, "usr", "libexec", "noc-helperd"))
            and not os.path.exists(os.path.join(sb, "etc", "noc-console", "installed_files.manifest"))
            and open(os.path.join(sb, "www", "index.html"), "rb").read() == luci_html,
            "P3D-SB-UNINSTALL[clean_restore_and_luci_intact]"
        )
        verify_sysupgrade_preservation(sb, sysupgrade_orig, su_orig_st.st_uid, su_orig_st.st_gid, "P3D-SB-SYSUPGRADE[after_uninstall]")


def test_harness_integrity(prod_slice):
    # 1. Negative summary evaluator checks (must reject missing, duplicated, reduced, failed, or nonzero rc)
    neg_cases = [
        ("missing_summary", 0, "all good\n"),
        ("duplicated_summary", 0, "UCODE_SUMMARY: 48 passed, 0 failed\nUCODE_SUMMARY: 48 passed, 0 failed\n"),
        ("reduced_count", 0, "UCODE_SUMMARY: 47 passed, 0 failed\n"),
        ("nonzero_failed", 0, "UCODE_SUMMARY: 48 passed, 1 failed\n"),
        ("nonzero_rc", 1, "UCODE_SUMMARY: 48 passed, 0 failed\n"),
    ]
    for lbl, rc, out in neg_cases:
        ok, _ = evaluate_ucode_suite_output("verify_phase3a_ucode.uc", rc, out)
        check(not ok, f"P3D-HARNESS-NEG[{lbl}_rejected]")

    # 2. Pre-existing staged /usr/libexec file preservation & restoration
    if os.path.isdir(ROOTFS_2512):
        with tempfile.TemporaryDirectory(prefix="nms_p3d_preexist_") as tmp:
            sb = os.path.join(tmp, "rootfs")
            shutil.copytree(ROOTFS_2512, sb, symlinks=True)
            os.makedirs(os.path.join(sb, "usr", "libexec"), exist_ok=True)
            for fn in ("nms_network.uc", "nms_fw_wifi.uc"):
                lp = os.path.join(sb, "usr", "libexec", fn)
                if os.path.lexists(lp):
                    os.unlink(lp)
            sentinel_path = os.path.join(sb, "usr", "libexec", "nms_archive.uc")
            sentinel_bytes = b"// PRE-EXISTING CUSTOM MODULE\n"
            with open(sentinel_path, "wb") as f:
                f.write(sentinel_bytes)
            os.chmod(sentinel_path, 0o640)
            run_ucode_suite_in_chroot(sb, "preexist-check", "verify_phase3b_ucode.uc", prod_slice)
            restored_ok = (
                os.path.isfile(sentinel_path)
                and open(sentinel_path, "rb").read() == sentinel_bytes
                and (os.lstat(sentinel_path).st_mode & 0o777) == 0o640
                and not os.path.lexists(os.path.join(sb, "usr", "libexec", "nms_network.uc"))
                and not os.path.lexists(os.path.join(sb, "usr", "libexec", "nms_fw_wifi.uc"))
            )
            check(restored_ok, "P3D-HARNESS[preserves_and_restores_preexisting_libexec_file]")

        # 3. Missing ucode module MUST fail cleanly when NMS_SKIP_PKG_INSTALL=1 (no apk/opkg attempted)
        with tempfile.TemporaryDirectory(prefix="nms_p3d_prereq_") as tmp:
            sb = os.path.join(tmp, "rootfs")
            shutil.copytree(ROOTFS_2512, sb, symlinks=True)
            repo_dst = os.path.join(sb, "tmp", "nms_repo")
            for sub in ("backend", "frontend", "init.d", "scripts", "schemas"):
                shutil.copytree(os.path.join(REPO_ROOT, sub), os.path.join(repo_dst, sub), symlinks=True)
            uc_bin = os.path.join(sb, "usr", "bin", "ucode")
            os.unlink(uc_bin)
            with open(uc_bin, "w") as f:
                f.write("#!/bin/sh\necho \"$*\" | grep -q \"digest\" && exit 1\nexit 0\n")
            os.chmod(uc_bin, 0o755)
            r_pre = subprocess.run(
                ["unshare", "-r", "/usr/sbin/chroot", sb, "/bin/sh", "-c",
                 "env NMS_SKIP_PKG_INSTALL=1 NMS_SKIP_SERVICE_START=1 /bin/sh /tmp/nms_repo/scripts/install.sh --allow-insecure-lan-http"],
                capture_output=True, text=True, timeout=15
            )
            pre_ok = (
                r_pre.returncode != 0
                and "digest" in (r_pre.stderr + r_pre.stdout)
                and not os.path.exists(os.path.join(sb, "usr", "libexec", "noc-helperd"))
            )
            check(pre_ok, "P3D-PREREQ[missing_ucode_mod_fails_offline_without_pkg_install]", (r_pre.stderr or r_pre.stdout)[-200:])


def main():
    prod_slice = build_helperd_prod_slice()
    print("=== Phase 3D: OpenWrt 24.10.0 (opkg) & 25.12.6 (apk) Chroot Suites & Lifecycle ===")
    for rootfs, ver in [(ROOTFS_2410, "24.10.0-opkg"), (ROOTFS_2512, "25.12.6-apk")]:
        for sc in ("verify_phase3a_ucode.uc", "verify_phase3b_ucode.uc", "verify_phase3c_ucode.uc"):
            run_ucode_suite_in_chroot(rootfs, ver, sc, prod_slice)
        test_in_chroot_lifecycle(rootfs, ver)

    test_sandboxed_lifecycle_with_rollback()
    test_harness_integrity(prod_slice)
    test_architecture_portability()
    print(f"\n=== PHASE 3D SUMMARY: {passed} passed, {failed} failed, {skipped} skipped ===")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
