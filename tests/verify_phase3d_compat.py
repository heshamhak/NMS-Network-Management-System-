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
    "verify_phase4a_ucode.uc": ("UCODE4A_SUMMARY", 19),
    "verify_phase4b_ucode.uc": ("UCODE4B_SUMMARY", 14),
    "verify_phase4c_ucode.uc": ("UCODE4C_SUMMARY", 17),
    "verify_phase4d_ucode.uc": ("UCODE4D_SUMMARY", 16),
    "verify_phase4e_ucode.uc": ("UCODE4E_SUMMARY", 23),
    "verify_phase4f_ucode.uc": ("UCODE4F_SUMMARY", 21),
    "verify_phase5b_ucode.uc": ("UCODE5B_SUMMARY", 22),
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


def restore_preexisting_entry(dst_lib, entry_info, chown_fn=os.chown, lchown_fn=os.lchown):
    kind, data, mode, uid, gid = entry_info
    if os.path.lexists(dst_lib):
        os.unlink(dst_lib)
    if kind == "symlink":
        os.symlink(data, dst_lib)
        cur_st = os.lstat(dst_lib)
        if cur_st.st_uid != uid or cur_st.st_gid != gid:
            lchown_fn(dst_lib, uid, gid)
        ver_st = os.lstat(dst_lib)
        if not stat.S_ISLNK(ver_st.st_mode) or os.readlink(dst_lib) != data or ver_st.st_uid != uid or ver_st.st_gid != gid:
            raise RuntimeError(f"Failed to verify restored symlink {dst_lib}")
    elif kind == "reg":
        with open(dst_lib, "wb") as bf:
            bf.write(data)
        cur_st = os.lstat(dst_lib)
        if cur_st.st_uid != uid or cur_st.st_gid != gid:
            chown_fn(dst_lib, uid, gid)
        os.chmod(dst_lib, mode)
        ver_st = os.lstat(dst_lib)
        if (not stat.S_ISREG(ver_st.st_mode) or stat.S_IMODE(ver_st.st_mode) != mode
                or ver_st.st_uid != uid or ver_st.st_gid != gid or open(dst_lib, "rb").read() != data):
            raise RuntimeError(f"Failed to verify restored regular file {dst_lib}")
    else:
        raise RuntimeError(f"Unsupported entry kind {kind}")


def run_ucode_suite_in_chroot(rootfs_dir, ver_label, script_name, helperd_prod_src, run_fn=subprocess.run, chown_fn=os.chown, lchown_fn=os.lchown, raise_on_restore_err=False):
    if not os.path.isdir(rootfs_dir) or not os.path.isfile(os.path.join(rootfs_dir, "usr/bin/ucode")):
        check(False, f"P3D-CHROOT[{ver_label},{script_name}]", f"required OpenWrt rootfs or ucode missing at {rootfs_dir}")
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
        for mod in ("nms_archive.uc", "nms_network.uc", "nms_fw_wifi.uc", "nms_discovery.uc", "nms_clients.uc", "nms_access_dhcp.uc", "nms_sqm.uc", "nms_topology.uc"):
            src_mod = os.path.join(REPO_ROOT, "backend", mod)
            shutil.copy2(src_mod, os.path.join(p3a_dir, mod))
            dst_lib = os.path.join(libexec_dir, mod)
            if os.path.lexists(dst_lib):
                st = os.lstat(dst_lib)
                if stat.S_ISLNK(st.st_mode):
                    preexisting_backups.append((dst_lib, ("symlink", os.readlink(dst_lib), None, st.st_uid, st.st_gid)))
                    # Unlink symlink BEFORE copying so we NEVER overwrite the symlink target
                    os.unlink(dst_lib)
                elif stat.S_ISREG(st.st_mode):
                    preexisting_backups.append((dst_lib, ("reg", open(dst_lib, "rb").read(), stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)))
                else:
                    raise RuntimeError(f"Unsupported pre-existing entry type at {dst_lib}: mode={oct(st.st_mode)}")
            else:
                created_libexec.append(dst_lib)
            shutil.copy2(src_mod, dst_lib)
        with open(os.path.join(p3a_dir, "helperd_aw_prod.uc"), "w", encoding="utf-8") as f:
            f.write(helperd_prod_src)
        h_raw = open(os.path.join(REPO_ROOT, "backend", "noc-helperd"), "r", encoding="utf-8").read()
        m_exec = re.search(r"(function collect_descendant_pids\(.*?\n\}\n\nfunction kill_pid_tree\(.*?\n\}\n\nfunction exec_argv_async\(.*?\n\})", h_raw, re.S)
        if not m_exec:
            raise RuntimeError("Failed to extract collect_descendant_pids/kill_pid_tree/exec_argv_async from backend/noc-helperd")
        with open(os.path.join(p3a_dir, "helperd_exec_prod.uc"), "w", encoding="utf-8") as f:
            f.write("import * as fs from 'fs';\nimport * as uloop from 'uloop';\nconst CAP_GENERAL = 65536;\n" + m_exec.group(1) + "\nexport { exec_argv_async };\n")
        with open(os.path.join(p3a_dir, "helperd_exec_race_prod.uc"), "w", encoding="utf-8") as f:
            f.write(
                "import * as fs from 'fs';\n"
                "const CAP_GENERAL = 65536;\n"
                "let sched = { timer_fn: null, worker_fn: null, done_fn: null };\n"
                "let uloop = {\n"
                "  timer: function(ms, fn) { sched.timer_fn = fn; return { cancel: function() {} }; },\n"
                "  task: function(wfn, dfn) { sched.worker_fn = wfn; sched.done_fn = dfn; return { pid: function() { return null; } }; }\n"
                "};\n"
                + m_exec.group(1) + "\nexport { exec_argv_async, sched };\n"
            )
        if script_name == "verify_phase5b_ucode.uc":
            m_vba = re.search(r"(function validate_backup_archive\(.*?\n\})", h_raw, re.S)
            m_rst = re.search(r"(\tif \(verb == 'sys_backup_restore'\) \{.*?\n\t\treturn;\n\t\})", h_raw, re.S)
            if not m_vba or not m_rst:
                raise RuntimeError("Failed to extract validate_backup_archive/sys_backup_restore from backend/noc-helperd")
            with open(os.path.join(p3a_dir, "helperd_restore_prod.uc"), "w", encoding="utf-8") as f:
                f.write(
                    "import * as raw_fs from 'fs';\n"
                    "import * as digest from 'digest';\n"
                    "import * as nms_archive from '/tmp/p3a_test/nms_archive.uc';\n"
                    "const CAP_GENERAL = 65536;\n"
                    "const BACKUP_MAX_BYTES = 2 * 1024 * 1024;\n"
                    "const BACKUP_MAX_B64 = 3 * 1024 * 1024;\n"
                    "let RUN_DIR = '/tmp/p3a_test/run5b';\n"
                    "let ROOT_MAP = '/tmp/p3a_test/root5b';\n"
                    "let cfg = { fail_write_target: null, fail_rollback_target: null, fail_reload_svc: null, fail_rollback_reload_svc: null, lock_held: false, freeze_calls: [], audits: [], reloads: [], in_rollback: false };\n"
                    "function map_path(p) {\n"
                    "  if (type(p) == 'string' && (index(p, '/etc/config/') == 0 || index(p, '/etc/noc-console/') == 0 || p == '/etc/config' || p == '/etc/noc-console')) return ROOT_MAP + p;\n"
                    "  if (type(p) == 'string' && index(p, '/etc/init.d/') == 0) return ROOT_MAP + p;\n"
                    "  return p;\n"
                    "}\n"
                    "let fs = {\n"
                    "  stat: (p) => raw_fs.stat(map_path(p)),\n"
                    "  lstat: (p) => raw_fs.lstat(map_path(p)),\n"
                    "  readfile: (p) => raw_fs.readfile(map_path(p)),\n"
                    "  writefile: (p, c) => raw_fs.writefile(map_path(p), c),\n"
                    "  chmod: (p, m) => raw_fs.chmod(map_path(p), m),\n"
                    "  unlink: (p) => raw_fs.unlink(map_path(p)),\n"
                    "  mkdir: (p, m) => raw_fs.mkdir(map_path(p), m),\n"
                    "  rmdir: (p) => raw_fs.rmdir(map_path(p)),\n"
                    "  lsdir: (p) => raw_fs.lsdir(map_path(p))\n"
                    "};\n"
                    "let _seq = 0;\n"
                    "function now_mono_ms() { return 10000 + (++_seq); }\n"
                    "function urandom_hex(n) { return sprintf('%08x', ++_seq); }\n"
                    "function find_exe(list) { for (let p in list) { if (raw_fs.stat(p)) return p; } return ''; }\n"
                    "function atomic_write(path, content, mode, uid, gid) {\n"
                    "  if (cfg.fail_write_target && path == cfg.fail_write_target && !cfg.in_rollback) {\n"
                    "    cfg.in_rollback = true;\n"
                    "    return { ok: false, error: 'injected_write_fail' };\n"
                    "  }\n"
                    "  if (cfg.fail_rollback_target && path == cfg.fail_rollback_target && cfg.in_rollback) {\n"
                    "    return { ok: false, error: 'injected_rollback_fail' };\n"
                    "  }\n"
                    "  let mp = map_path(path);\n"
                    "  let w = raw_fs.writefile(mp, content);\n"
                    "  if (w == null) return { ok: false, error: 'write_failed' };\n"
                    "  if (mode) raw_fs.chmod(mp, mode);\n"
                    "  return { ok: true };\n"
                    "}\n"
                    "function release_lock() { cfg.lock_held = false; }\n"
                    "function enter_emergency_freeze(reason) { push(cfg.freeze_calls, reason); return { freeze_persisted: true }; }\n"
                    "function audit_append(actor, verb, target, status, detail) { push(cfg.audits, { actor, verb, target, status, detail }); return true; }\n"
                    "function exec_argv_async(exe, argv, t, c, cb) {\n"
                    "  if (index(exe, '/etc/init.d/') == 0) {\n"
                    "    let svc = substr(exe, 12);\n"
                    "    push(cfg.reloads, svc);\n"
                    "    if (cfg.fail_reload_svc && svc == cfg.fail_reload_svc && !cfg.in_rollback) {\n"
                    "      cfg.in_rollback = true;\n"
                    "      cb({ ok: false, error: 'injected_reload_fail_' + svc });\n"
                    "      return;\n"
                    "    }\n"
                    "    if (cfg.fail_rollback_reload_svc && svc == cfg.fail_rollback_reload_svc && cfg.in_rollback) {\n"
                    "      cb({ ok: false, error: 'injected_rollback_reload_fail_' + svc });\n"
                    "      return;\n"
                    "    }\n"
                    "    cb({ ok: true, output: '' });\n"
                    "    return;\n"
                    "  }\n"
                    "  let cmd = [exe]; for (let a in (argv || [])) push(cmd, '' + a);\n"
                    "  let tmp_out = RUN_DIR + '/exec_out_' + (++_seq);\n"
                    "  let q = (s) => \"'\" + replace('' + s, /'/g, \"'\\\\''\") + \"'\";\n"
                    "  let sh_cmd = join(' ', map(cmd, q)) + ' >' + q(tmp_out) + ' 2>&1';\n"
                    "  let rc = system(['/bin/sh', '-c', sh_cmd]);\n"
                    "  let out = raw_fs.readfile(tmp_out) || '';\n"
                    "  if (raw_fs.stat(tmp_out)) raw_fs.unlink(tmp_out);\n"
                    "  cb({ ok: rc == 0, exit_code: rc, output: out, overflow: false });\n"
                    "}\n"
                    + m_vba.group(1) + "\n"
                    "export function run_restore(actor, params, reply_cb) {\n"
                    "  if (cfg.lock_held) { reply_cb({ ok: false, status: 409, error_code: 'VALIDATION', message_ar: 'locked' }); return; }\n"
                    "  cfg.lock_held = true;\n"
                    "  let verb = 'sys_backup_restore';\n"
                    + m_rst.group(1) + "\n"
                    "};\n"
                    "export { cfg, RUN_DIR, ROOT_MAP };\n"
                )
        shutil.copy2(os.path.join(REPO_ROOT, "tests", script_name), os.path.join(p3a_dir, script_name))

        vec_dir = os.path.join(p3a_dir, "vec")
        os.makedirs(vec_dir, exist_ok=True)
        os.makedirs(os.path.join(p3a_dir, "etc_mock"), exist_ok=True)
        if script_name == "verify_phase3a_ucode.uc":
            generate_phase3a_vectors(vec_dir)
            args = ["/tmp/p3a_test/nms_archive.uc", "/tmp/p3a_test/vec"]
        else:
            args = ["/tmp/p3a_test/vec"]

        os.makedirs(os.path.join(rootfs_dir, "proc"), exist_ok=True)
        unshare_cmd = ["unshare", "-r"]
        if script_name == "verify_phase4f_ucode.uc":
            unshare_cmd = ["unshare", "-rpf", f"--mount-proc={os.path.join(rootfs_dir, 'proc')}"]
        res = run_fn(
            unshare_cmd + ["/usr/sbin/chroot", rootfs_dir, "/usr/bin/ucode", f"/tmp/p3a_test/{script_name}"] + args,
            capture_output=True, text=True, timeout=30
        )
        ok, detail = evaluate_ucode_suite_output(script_name, res.returncode, res.stdout)
        check(ok, f"P3D-CHROOT[{ver_label},{script_name}]", detail if ok else f"{detail} tail={(res.stderr or res.stdout)[-200:]}")
    finally:
        shutil.rmtree(p3a_dir, ignore_errors=True)
        for p in created_libexec:
            if os.path.lexists(p):
                os.unlink(p)
        for dst_lib, entry_info in preexisting_backups:
            try:
                restore_preexisting_entry(dst_lib, entry_info, chown_fn=chown_fn, lchown_fn=lchown_fn)
            except Exception as exc:
                if raise_on_restore_err:
                    raise
                check(False, f"P3D-RESTORE[{ver_label},{os.path.basename(dst_lib)}]", str(exc))


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
    if not os.path.isdir(rootfs_dir) or not os.path.isfile(os.path.join(rootfs_dir, "bin/sh")) or not os.path.isfile(os.path.join(rootfs_dir, "usr/bin/ucode")):
        check(False, f"P3D-LIFECYCLE[{ver_label}]", f"required OpenWrt rootfs, /bin/sh, or /usr/bin/ucode missing at {rootfs_dir}")
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
            env_prefix = "NMS_SKIP_PKG_INSTALL=1 NMS_SKIP_CHOWN=1 NMS_SKIP_SERVICE_START=1 NMS_SERVICE_RUNNER=/tmp/svc_runner.sh"
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
            probe_err = (probe.stderr or "") + (probe.stdout or "")
            if "Unable to resolve path for module" not in probe_err and "Unable to load module" not in probe_err:
                check(False, f"P3D-CHROOT-PREREQ[{ver_label},ucode_probe_failed]", probe_err[:200])
                return
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
            and os.path.isfile(os.path.join(sb, "usr", "libexec", "nms_discovery.uc"))
            and os.path.isfile(os.path.join(sb, "usr", "libexec", "nms_clients.uc"))
            and os.path.isfile(os.path.join(sb, "usr", "libexec", "nms_access_dhcp.uc"))
            and os.path.isfile(os.path.join(sb, "usr", "libexec", "nms_sqm.uc"))
            and os.path.isfile(os.path.join(sb, "usr", "libexec", "nms_topology.uc"))
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


def test_apk_provenance_verification():
    import hashlib
    key_path = os.path.join(ROOTFS_2512, "etc", "apk", "keys", "openwrt-25.12.pem")
    check(os.path.isfile(key_path), "P3D-PROVENANCE[openwrt_25_12_signing_key_present]")
    cache_dir = "/tmp/openwrt-pkg-cache/25.12.6"
    expected_pkg_hashes = {
        "ucode-mod-digest-2026.07.09~b885dd0f-r3.apk": "82ef7e42c7981316f5b4194d1aa5cf7aeb1f5b36898f048b26d7d1a4537f0750",
        "ucode-mod-socket-2026.07.09~b885dd0f-r3.apk": "f34de956b2af4320ae1a6152c968a1d9dc25409976f8b1cc0e33506b8d2ee81a",
        "ucode-mod-struct-2026.07.09~b885dd0f-r3.apk": "d0dbcdfec18899b77f3920fdd1bad2101d395dd2deed0400bae8331193afaf59",
    }
    required_files = ["packages.adb"] + list(expected_pkg_hashes.keys())
    if not all(os.path.isfile(os.path.join(cache_dir, fn)) for fn in required_files):
        check(False, "P3D-PROVENANCE[official_apk_cache_present]", f"missing files in {cache_dir}")
        return
    adb_size = os.path.getsize(os.path.join(cache_dir, "packages.adb"))
    check(adb_size > 0, "P3D-PROVENANCE[packages_adb_present_for_sig_verify]", f"size={adb_size}")
    for fn, exp_sha in expected_pkg_hashes.items():
        got_sha = hashlib.sha256(open(os.path.join(cache_dir, fn), "rb").read()).hexdigest()
        check(got_sha == exp_sha, f"P3D-PROVENANCE[sha256,{fn}]", f"got={got_sha}")

    with tempfile.TemporaryDirectory(prefix="nms_p3d_prov_") as tmp:
        sb = os.path.join(tmp, "rootfs")
        shutil.copytree(ROOTFS_2512, sb, symlinks=True)
        repo_in = os.path.join(sb, "tmp", "apk_repo")
        repo_arch = os.path.join(repo_in, "x86_64")
        os.makedirs(repo_arch, exist_ok=True)
        for fn in required_files:
            shutil.copy2(os.path.join(cache_dir, fn), os.path.join(repo_in, fn))
            shutil.copy2(os.path.join(cache_dir, fn), os.path.join(repo_arch, fn))
        r_ver = subprocess.run(
            ["unshare", "-r", "/usr/sbin/chroot", sb, "/usr/bin/apk", "verify", "/tmp/apk_repo/packages.adb"],
            capture_output=True, text=True, timeout=15
        )
        check(r_ver.returncode == 0 and "packages.adb: OK" in r_ver.stdout, "P3D-PROVENANCE[apk_verify_signed_packages_adb]", (r_ver.stderr or r_ver.stdout)[-200:])

        # Actual offline trusted installation inside isolated 25.12.6 rootfs (uninstall first, then install WITHOUT --allow-untrusted)
        r_del = subprocess.run(
            ["unshare", "-r", "/usr/sbin/chroot", sb, "/bin/sh", "-c",
             "/usr/bin/apk del --no-network ucode-mod-digest ucode-mod-socket ucode-mod-struct"],
            capture_output=True, text=True, timeout=15
        )
        pre_absent = (r_del.returncode == 0) and not os.path.exists(os.path.join(sb, "usr", "lib", "ucode", "digest.so"))
        open(os.path.join(sb, "tmp", "apk_repos.list"), "w").write("/tmp/apk_repo/packages.adb\n")
        r_add = subprocess.run(
            ["unshare", "-r", "/usr/sbin/chroot", sb, "/bin/sh", "-c",
             "/usr/bin/apk add --no-network --repositories-file /tmp/apk_repos.list ucode-mod-digest ucode-mod-socket ucode-mod-struct"],
            capture_output=True, text=True, timeout=15
        )
        r_chk = subprocess.run(
            ["unshare", "-r", "/usr/sbin/chroot", sb, "/bin/sh", "-c",
             "/usr/bin/apk list --installed ucode* && /usr/bin/ucode -e \"import * as d from 'digest'; import * as s from 'socket'; import * as t from 'struct'; printf('APK_TRUSTED_INSTALL_OK\\n');\""],
            capture_output=True, text=True, timeout=15
        )
        add_ok = (
            pre_absent
            and r_add.returncode == 0
            and r_chk.returncode == 0
            and "APK_TRUSTED_INSTALL_OK" in r_chk.stdout
            and "ucode-mod-digest-2026.07.09~b885dd0f-r3 x86_64" in r_chk.stdout
            and "ucode-mod-socket-2026.07.09~b885dd0f-r3 x86_64" in r_chk.stdout
            and "ucode-mod-struct-2026.07.09~b885dd0f-r3 x86_64" in r_chk.stdout
        )
        check(add_ok, "P3D-PROVENANCE[offline_trusted_apk_add_without_allow_untrusted]", (r_add.stderr or r_chk.stderr or r_add.stdout)[-240:])

        # Negative test: tampered packages.adb MUST fail apk verify AND fail apk add without installing
        subprocess.run(
            ["unshare", "-r", "/usr/sbin/chroot", sb, "/usr/bin/apk", "del", "--no-network", "ucode-mod-digest"],
            capture_output=True, text=True, timeout=15
        )
        adb_p = os.path.join(repo_in, "packages.adb")
        adb_arch_p = os.path.join(repo_arch, "packages.adb")
        adb_raw = bytearray(open(adb_p, "rb").read())
        adb_raw[-10] ^= 0xFF
        open(adb_p, "wb").write(adb_raw)
        open(adb_arch_p, "wb").write(adb_raw)
        r_tamper = subprocess.run(
            ["unshare", "-r", "/usr/sbin/chroot", sb, "/usr/bin/apk", "verify", "/tmp/apk_repo/packages.adb"],
            capture_output=True, text=True, timeout=15
        )
        check(r_tamper.returncode != 0, "P3D-PROVENANCE[tampered_packages_adb_rejected]")
        r_tamper_add = subprocess.run(
            ["unshare", "-r", "/usr/sbin/chroot", sb, "/bin/sh", "-c",
             "/usr/bin/apk add --no-network --repositories-file /tmp/apk_repos.list ucode-mod-digest"],
            capture_output=True, text=True, timeout=15
        )
        check(
            r_tamper_add.returncode != 0 and not os.path.exists(os.path.join(sb, "usr", "lib", "ucode", "digest.so")),
            "P3D-PROVENANCE[tampered_packages_adb_blocks_apk_add]",
            f"rc={r_tamper_add.returncode}"
        )

    r_inst_list = subprocess.run(
        ["unshare", "-r", "/usr/sbin/chroot", ROOTFS_2512, "/bin/sh", "-c", "/usr/bin/apk list --installed ucode*"],
        capture_output=True, text=True, timeout=15
    )
    inst_ok = (
        r_inst_list.returncode == 0
        and "ucode-mod-digest-2026.07.09~b885dd0f-r3 x86_64" in r_inst_list.stdout
        and "ucode-mod-socket-2026.07.09~b885dd0f-r3 x86_64" in r_inst_list.stdout
        and "ucode-mod-struct-2026.07.09~b885dd0f-r3 x86_64" in r_inst_list.stdout
    )
    check(inst_ok, "P3D-PROVENANCE[installed_apk_versions_and_arch_verified]")


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

    # 2. Adversarial staging preservation & cleanup checks (regular file, symlink->target, broken symlink, chown failure, timeout cleanup)
    if not os.path.isdir(ROOTFS_2512):
        check(False, "P3D-HARNESS[rootfs_2512_required_for_staging_tests]")
    else:
        with tempfile.TemporaryDirectory(prefix="nms_p3d_preexist_") as tmp:
            sb = os.path.join(tmp, "rootfs")
            shutil.copytree(ROOTFS_2512, sb, symlinks=True)
            libexec = os.path.join(sb, "usr", "libexec")
            os.makedirs(libexec, exist_ok=True)
            for fn in ("nms_archive.uc", "nms_network.uc", "nms_fw_wifi.uc"):
                lp = os.path.join(libexec, fn)
                if os.path.lexists(lp):
                    os.unlink(lp)
            sentinel_reg = os.path.join(libexec, "nms_archive.uc")
            sentinel_bytes = b"// PRE-EXISTING REGULAR MODULE\n"
            with open(sentinel_reg, "wb") as f:
                f.write(sentinel_bytes)
            os.chmod(sentinel_reg, 0o640)

            sym_target = os.path.join(tmp, "precious_target.uc")
            sym_target_bytes = b"// DO NOT OVERWRITE SYMLINK TARGET\n"
            with open(sym_target, "wb") as f:
                f.write(sym_target_bytes)
            sym_link = os.path.join(libexec, "nms_network.uc")
            os.symlink(sym_target, sym_link)

            broken_link = os.path.join(libexec, "nms_fw_wifi.uc")
            os.symlink("/nonexistent/dangling/module.uc", broken_link)

            run_ucode_suite_in_chroot(sb, "preexist-adv", "verify_phase3b_ucode.uc", prod_slice)
            adv_ok = (
                stat.S_ISREG(os.lstat(sentinel_reg).st_mode)
                and open(sentinel_reg, "rb").read() == sentinel_bytes
                and (os.lstat(sentinel_reg).st_mode & 0o777) == 0o640
                and stat.S_ISLNK(os.lstat(sym_link).st_mode)
                and os.readlink(sym_link) == sym_target
                and open(sym_target, "rb").read() == sym_target_bytes
                and stat.S_ISLNK(os.lstat(broken_link).st_mode)
                and os.readlink(broken_link) == "/nonexistent/dangling/module.uc"
            )
            check(adv_ok, "P3D-HARNESS[preserves_reg_symlink_target_and_broken_symlink]")

            # Timeout cleanup check
            def timeout_runner(*a, **kw):
                raise subprocess.TimeoutExpired(cmd="ucode", timeout=30)
            timed_out = False
            try:
                run_ucode_suite_in_chroot(sb, "timeout-chk", "verify_phase3b_ucode.uc", prod_slice, run_fn=timeout_runner)
            except subprocess.TimeoutExpired:
                timed_out = True
            check(
                timed_out
                and not os.path.exists(os.path.join(sb, "tmp", "p3a_test"))
                and open(sym_target, "rb").read() == sym_target_bytes
                and stat.S_ISLNK(os.lstat(broken_link).st_mode),
                "P3D-HARNESS[cleanup_and_restore_after_subprocess_timeout]"
            )

            # Verify setuid (0o4755), setgid (0o2755), and sticky (0o1777) special permission bits restoration
            for sp_mode, sp_name in ((0o4755, "setuid_4755"), (0o2755, "setgid_2755"), (0o1777, "sticky_1777")):
                sp_bytes = f"// SPECIAL {sp_name}\n".encode()
                with open(sentinel_reg, "wb") as f:
                    f.write(sp_bytes)
                os.chmod(sentinel_reg, sp_mode)
                sp_orig = os.lstat(sentinel_reg)
                run_ucode_suite_in_chroot(sb, f"special-{sp_name}", "verify_phase3b_ucode.uc", prod_slice)
                sp_after = os.lstat(sentinel_reg)
                sp_ok = (
                    stat.S_ISREG(sp_after.st_mode)
                    and stat.S_IMODE(sp_after.st_mode) == sp_mode
                    and sp_after.st_uid == sp_orig.st_uid
                    and sp_after.st_gid == sp_orig.st_gid
                    and open(sentinel_reg, "rb").read() == sp_bytes
                )
                check(sp_ok, f"P3D-HARNESS[preserves_special_mode_{sp_name}]", f"mode={oct(stat.S_IMODE(sp_after.st_mode))}")

            # Ownership restoration failure check (must NOT silently ignore PermissionError)
            st_reg = os.lstat(sentinel_reg)
            chown_failed = False
            try:
                restore_preexisting_entry(
                    sentinel_reg,
                    ("reg", sentinel_bytes, 0o640, st_reg.st_uid + 1, st_reg.st_gid),
                    chown_fn=lambda p, u, g: (_ for _ in ()).throw(PermissionError("EPERM simulated"))
                )
            except PermissionError:
                chown_failed = True
            check(chown_failed, "P3D-HARNESS[ownership_restore_failure_is_not_ignored]")

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
        for sc in ("verify_phase3a_ucode.uc", "verify_phase3b_ucode.uc", "verify_phase3c_ucode.uc", "verify_phase4a_ucode.uc", "verify_phase4b_ucode.uc", "verify_phase4c_ucode.uc", "verify_phase4d_ucode.uc", "verify_phase4e_ucode.uc", "verify_phase4f_ucode.uc", "verify_phase5b_ucode.uc"):
            run_ucode_suite_in_chroot(rootfs, ver, sc, prod_slice)
        test_in_chroot_lifecycle(rootfs, ver)

    test_sandboxed_lifecycle_with_rollback()
    test_harness_integrity(prod_slice)
    test_apk_provenance_verification()
    test_architecture_portability()
    print(f"\n=== PHASE 3D SUMMARY: {passed} passed, {failed} failed, {skipped} skipped ===")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
