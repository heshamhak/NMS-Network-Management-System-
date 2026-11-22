#!/usr/bin/env python3
"""Phase 5A verification: OpenWrt 24.10.0 (opkg) & 25.12.6 (apk) native packaging,
signed repository indexes, package signature verification, full lifecycle
(install/upgrade/remove/reinstall), and safe migration from legacy scripts/install.sh.
"""

import gzip
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zlib

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ROOTFS_2410 = "/tmp/openwrt-24.10-x86-64-rootfs"
ROOTFS_2512 = "/tmp/openwrt-x86-64-rootfs"
SDK_APK_BIN = os.environ.get(
    "APK_BIN",
    "/home/iot/owrt/openwrt-sdk-25.12.5-x86-64_gcc-14.3.0_musl.Linux-x86_64/staging_dir/host/bin/apk",
)

passes = []
failures = []


def check(cond, name, detail=""):
    if cond:
        passes.append(name)
        print(f"[PASS] {name}")
    else:
        failures.append((name, detail))
        print(f"[FAIL] {name}" + (f" ({detail})" if detail else ""))


def chroot_run(sb, cmd):
    return subprocess.run(
        [
            "unshare", "-rm", "/bin/sh", "-c",
            f"touch {sb}/dev/null {sb}/dev/urandom && "
            f"mount --bind /dev/null {sb}/dev/null && "
            f"mount --bind /dev/urandom {sb}/dev/urandom && "
            f"exec /usr/sbin/chroot {sb} /bin/sh -c {subprocess.list2cmdline([cmd])}",
        ],
        capture_output=True, text=True, timeout=45,
    )


def has_elf_in_archive(path):
    raw = open(path, "rb").read()
    if raw.startswith(b"ADBd"):
        d = zlib.decompress(raw[4:], -15)
        return "embedded_elf_in_adb" if b"\x7fELF" in d else None
    if raw.startswith(b"\x1f\x8b"):
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                data = tf.extractfile(m).read()
                if data[:4] == b"\x7fELF":
                    return m.name
                if m.name.endswith(".tar.gz"):
                    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as itf:
                        for im in itf.getmembers():
                            if im.isfile() and itf.extractfile(im).read(4) == b"\x7fELF":
                                return f"{m.name}:{im.name}"
    return None


def register_2410_ucode_status(sb):
    status_path = os.path.join(sb, "usr/lib/opkg/status")
    st_txt = open(status_path, "r", encoding="utf-8").read()
    for mod in ("ucode-mod-socket", "ucode-mod-struct", "ucode-mod-uloop", "ucode-mod-digest"):
        if f"Package: {mod}\n" not in st_txt:
            st_txt += (
                f"\nPackage: {mod}\nVersion: 2024.07.22-r1\nDepends: libc, ucode\n"
                f"Status: install user installed\nArchitecture: x86_64\n"
            )
    open(status_path, "w", encoding="utf-8").write(st_txt)


def build_signed_opkg_repo(sb, repo_dir, ipk_files):
    os.makedirs(repo_dir, exist_ok=True)
    pkgs_buf = []
    for ipkf in ipk_files:
        bn = os.path.basename(ipkf)
        shutil.copy2(ipkf, os.path.join(repo_dir, bn))
        raw = open(ipkf, "rb").read()
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
            ctrl_m = tf.extractfile("./control.tar.gz").read()
            with tarfile.open(fileobj=io.BytesIO(ctrl_m), mode="r:gz") as ctf:
                ctrl_txt = ctf.extractfile("./control").read().decode("utf-8").strip()
        sha = hashlib.sha256(raw).hexdigest()
        pkgs_buf.append(f"{ctrl_txt}\nFilename: {bn}\nSize: {len(raw)}\nSHA256sum: {sha}\n\n")
    pkgs_bytes = "".join(pkgs_buf).encode("utf-8")
    open(os.path.join(repo_dir, "Packages"), "wb").write(pkgs_bytes)
    with gzip.open(os.path.join(repo_dir, "Packages.gz"), "wb") as gf:
        gf.write(pkgs_bytes)
    assert chroot_run(sb, "/usr/bin/usign -S -m /tmp/ipk_repo/Packages -s /tmp/test.sec").returncode == 0
    assert chroot_run(sb, "/usr/bin/usign -S -m /tmp/ipk_repo/Packages.gz -s /tmp/test.sec").returncode == 0


def build_signed_apk_repo(apk_bin, priv_key, keys_dir, repo_dir, apk_files):
    os.makedirs(repo_dir, exist_ok=True)
    os.makedirs(os.path.join(repo_dir, "noarch"), exist_ok=True)
    os.makedirs(os.path.join(repo_dir, "x86_64"), exist_ok=True)
    copied = []
    for apkf in apk_files:
        bn = os.path.basename(apkf)
        dst = os.path.join(repo_dir, bn)
        shutil.copy2(apkf, dst)
        shutil.copy2(apkf, os.path.join(repo_dir, "noarch", bn))
        shutil.copy2(apkf, os.path.join(repo_dir, "x86_64", bn))
        copied.append(dst)
    ndx_path = os.path.join(repo_dir, "packages.adb")
    subprocess.run(
        [apk_bin, "mkndx", "--keys-dir", keys_dir, "--sign-key", priv_key, "--output", ndx_path] + copied,
        check=True, capture_output=True, text=True,
    )
    return ndx_path


def main():
    print("=== Phase 5A: OpenWrt Native Packaging (.ipk / .apk), Signing & Migration Verification ===")

    mk_path = os.path.join(REPO_ROOT, "packaging", "openwrt", "Makefile")
    mk_src = open(mk_path, "r", encoding="utf-8").read() if os.path.isfile(mk_path) else ""
    check(
        all(p in mk_src for p in ("PKG_NAME:=nms-console", "PKG_ARCH:=all", "/www/pro", "/usr/libexec", "/etc/init.d", "/etc/noc-console")),
        "P5A-MAKEFILE[production_paths_and_noarch]",
    )

    priv_markers = ("BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN PRIVATE KEY", "untrusted comment: secret key")
    key_found = None
    for rel in ("packaging/openwrt/Makefile", "scripts/build_packages.py", "scripts/install.sh"):
        txt = open(os.path.join(REPO_ROOT, rel), "r", encoding="utf-8").read()
        for pm in priv_markers:
            if pm in txt:
                key_found = f"{rel}:{pm}"
    check(key_found is None, "P5A-SEC[zero_private_keys_in_repo]", str(key_found))

    pkg_dir = tempfile.mkdtemp(prefix="p5a_pkgs_")
    try:
        # Generate ephemeral ECDSA P-256 keypair for apk v3 signing (never committed)
        apk_priv = os.path.join(pkg_dir, "ephemeral_apk.key")
        apk_pub = os.path.join(pkg_dir, "ephemeral_apk.pem")
        subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", apk_priv], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", apk_priv, "-pubout", "-out", apk_pub], check=True, capture_output=True)

        # Build signed 5.0.0-1 and 5.0.1-1 (.ipk + signed ADB v3 .apk) + an unsigned .apk for negative testing
        for ver in ("5.0.0", "5.0.1"):
            subprocess.run(
                ["python3", os.path.join(REPO_ROOT, "scripts", "build_packages.py"),
                 "--out-dir", pkg_dir, "--version", ver, "--release", "1",
                 "--apk-bin", SDK_APK_BIN, "--sign-key", apk_priv],
                capture_output=True, text=True, check=True,
            )
        unsigned_dir = os.path.join(pkg_dir, "unsigned")
        os.makedirs(unsigned_dir, exist_ok=True)
        subprocess.run(
            ["python3", os.path.join(REPO_ROOT, "scripts", "build_packages.py"),
             "--out-dir", unsigned_dir, "--version", "5.0.0", "--release", "1",
             "--apk-bin", SDK_APK_BIN],
            capture_output=True, text=True, check=True,
        )

        ipk_500 = os.path.join(pkg_dir, "nms-console_5.0.0-1_all.ipk")
        ipk_501 = os.path.join(pkg_dir, "nms-console_5.0.1-1_all.ipk")
        apk_500 = os.path.join(pkg_dir, "nms-console-5.0.0-r1.apk")
        apk_501 = os.path.join(pkg_dir, "nms-console-5.0.1-r1.apk")
        apk_unsigned = os.path.join(unsigned_dir, "nms-console-5.0.0-r1.apk")

        check(all(os.path.isfile(p) for p in (ipk_500, ipk_501, apk_500, apk_501)), "P5A-BUILD[ipk_and_signed_apk_artifacts_created]")
        elf_hit = has_elf_in_archive(ipk_500) or has_elf_in_archive(apk_500)
        check(elf_hit is None, "P5A-ARCH[zero_elf_binaries_in_ipk_and_apk]", str(elf_hit))

        # --- 1. OpenWrt 24.10.0 (opkg) Lifecycle, Signed Feed & Legacy Migration ---
        if not os.path.isdir(ROOTFS_2410):
            check(False, "P5A-OPKG[rootfs_present]", ROOTFS_2410)
        else:
            sb = tempfile.mkdtemp(prefix="p5a_2410_")
            try:
                shutil.copytree(ROOTFS_2410, sb, symlinks=True, dirs_exist_ok=True)
                os.makedirs(os.path.join(sb, "var/lock"), exist_ok=True)
                register_2410_ucode_status(sb)
                luci_sentinel = os.path.join(sb, "www/index.html")
                os.makedirs(os.path.dirname(luci_sentinel), exist_ok=True)
                open(luci_sentinel, "w").write("LUCI_SENTINEL_2410\n")

                assert chroot_run(sb, "/usr/bin/usign -G -p /tmp/test.pub -s /tmp/test.sec").returncode == 0
                fp = chroot_run(sb, "/usr/bin/usign -F -p /tmp/test.pub").stdout.strip()
                shutil.copy2(os.path.join(sb, "tmp/test.pub"), os.path.join(sb, "etc/opkg/keys", fp))
                open(os.path.join(sb, "etc/opkg/distfeeds.conf"), "w").write("")
                open(os.path.join(sb, "etc/opkg/customfeeds.conf"), "w").write("src/gz local file:///tmp/ipk_repo\n")

                repo_dir = os.path.join(sb, "tmp/ipk_repo")
                build_signed_opkg_repo(sb, repo_dir, [ipk_500])

                # Tampered feed rejected
                orig_gz = open(os.path.join(repo_dir, "Packages.gz"), "rb").read()
                tampered_gz = io.BytesIO()
                with gzip.GzipFile(fileobj=tampered_gz, mode="wb", mtime=0) as gf:
                    gf.write(open(os.path.join(repo_dir, "Packages"), "rb").read() + b"# tampered\n")
                open(os.path.join(repo_dir, "Packages.gz"), "wb").write(tampered_gz.getvalue())
                r_bad = chroot_run(sb, "/bin/opkg update")
                r_bad_inst = chroot_run(sb, "/bin/opkg install nms-console")
                check(
                    (r_bad.returncode != 0 or "Signature check failed" in (r_bad.stdout + r_bad.stderr)) and r_bad_inst.returncode != 0,
                    "P5A-OPKG[tampered_feed_rejected]",
                )

                # Signed fresh install
                open(os.path.join(repo_dir, "Packages.gz"), "wb").write(orig_gz)
                r_upd = chroot_run(sb, "/bin/opkg update")
                r_inst = chroot_run(sb, "/bin/opkg install nms-console")
                r_list = chroot_run(sb, "/bin/opkg list-installed nms-console")
                r_files = chroot_run(sb, "/bin/opkg files nms-console")
                check(
                    r_upd.returncode == 0 and "Signature check passed" in r_upd.stdout and
                    r_inst.returncode == 0 and "5.0.0-1" in r_list.stdout and
                    "/www/pro/index.html" in r_files.stdout and "/usr/libexec/noc-apid" in r_files.stdout and
                    open(luci_sentinel).read() == "LUCI_SENTINEL_2410\n",
                    "P5A-OPKG[signed_fresh_install_and_luci_preserved]",
                    r_inst.stderr,
                )

                # Upgrade 5.0.0-1 -> 5.0.1-1 preserves TLS & users
                etc_dir = os.path.join(sb, "etc/noc-console")
                os.makedirs(etc_dir, exist_ok=True)
                open(os.path.join(etc_dir, "tls.crt"), "w").write("CERT_DATA_2410\n")
                open(os.path.join(etc_dir, "tls.key"), "w").write("KEY_DATA_2410\n")
                open(os.path.join(etc_dir, "users.json"), "w").write('{"admin":{"role":"admin"}}\n')

                build_signed_opkg_repo(sb, repo_dir, [ipk_500, ipk_501])
                assert chroot_run(sb, "/bin/opkg update").returncode == 0
                r_upg = chroot_run(sb, "/bin/opkg upgrade nms-console")
                r_list2 = chroot_run(sb, "/bin/opkg list-installed nms-console")
                check(
                    r_upg.returncode == 0 and "5.0.1-1" in r_list2.stdout and
                    open(os.path.join(etc_dir, "tls.crt")).read() == "CERT_DATA_2410\n" and
                    open(os.path.join(etc_dir, "tls.key")).read() == "KEY_DATA_2410\n" and
                    open(os.path.join(etc_dir, "users.json")).read() == '{"admin":{"role":"admin"}}\n',
                    "P5A-OPKG[upgrade_preserves_tls_and_users]",
                    r_upg.stderr,
                )

                # Remove & reinstall
                r_rem = chroot_run(sb, "/bin/opkg remove nms-console")
                removed_ok = r_rem.returncode == 0 and not os.path.exists(os.path.join(sb, "usr/libexec/noc-apid"))
                r_re = chroot_run(sb, "/bin/opkg install nms-console")
                check(
                    removed_ok and r_re.returncode == 0 and
                    open(os.path.join(etc_dir, "tls.crt")).read() == "CERT_DATA_2410\n" and
                    open(luci_sentinel).read() == "LUCI_SENTINEL_2410\n" and
                    os.path.isfile(os.path.join(sb, "usr/libexec/noc-apid")),
                    "P5A-OPKG[remove_preserves_config_and_reinstall_clean]",
                )
            finally:
                shutil.rmtree(sb, ignore_errors=True)

            # Legacy install.sh migration -> opkg
            sb_mig = tempfile.mkdtemp(prefix="p5a_2410_mig_")
            try:
                shutil.copytree(ROOTFS_2410, sb_mig, symlinks=True, dirs_exist_ok=True)
                os.makedirs(os.path.join(sb_mig, "var/lock"), exist_ok=True)
                register_2410_ucode_status(sb_mig)
                luci_s = os.path.join(sb_mig, "www/index.html")
                os.makedirs(os.path.dirname(luci_s), exist_ok=True)
                open(luci_s, "w").write("LUCI_MIG_2410\n")

                shutil.copytree(REPO_ROOT, os.path.join(sb_mig, "tmp/nms_src"), ignore=shutil.ignore_patterns(".git", "__pycache__"))
                r_leg = chroot_run(sb_mig, "NMS_SKIP_PKG_INSTALL=1 NMS_SKIP_CHOWN=1 NMS_SKIP_SERVICE_START=1 /tmp/nms_src/scripts/install.sh --allow-insecure-lan-http")
                etc_m = os.path.join(sb_mig, "etc/noc-console")
                open(os.path.join(etc_m, "tls.crt"), "w").write("LEGACY_CERT_2410\n")
                open(os.path.join(etc_m, "tls.key"), "w").write("LEGACY_KEY_2410\n")
                open(os.path.join(etc_m, "users.json"), "w").write('{"admin":{"role":"admin"}}\n')
                pre_opkg = chroot_run(sb_mig, "/bin/opkg list-installed nms-console")
                pre_ok = (
                    r_leg.returncode == 0 and
                    os.path.isfile(os.path.join(etc_m, "installed_files.manifest")) and
                    "nms-console" not in pre_opkg.stdout
                )

                assert chroot_run(sb_mig, "/usr/bin/usign -G -p /tmp/test.pub -s /tmp/test.sec").returncode == 0
                fp = chroot_run(sb_mig, "/usr/bin/usign -F -p /tmp/test.pub").stdout.strip()
                shutil.copy2(os.path.join(sb_mig, "tmp/test.pub"), os.path.join(sb_mig, "etc/opkg/keys", fp))
                open(os.path.join(sb_mig, "etc/opkg/distfeeds.conf"), "w").write("")
                open(os.path.join(sb_mig, "etc/opkg/customfeeds.conf"), "w").write("src/gz local file:///tmp/ipk_repo\n")
                build_signed_opkg_repo(sb_mig, os.path.join(sb_mig, "tmp/ipk_repo"), [ipk_500])
                assert chroot_run(sb_mig, "/bin/opkg update").returncode == 0
                r_mig = chroot_run(sb_mig, "/bin/opkg install nms-console")
                post_opkg = chroot_run(sb_mig, "/bin/opkg list-installed nms-console")
                post_files = chroot_run(sb_mig, "/bin/opkg files nms-console")
                mig_state = open(os.path.join(etc_m, ".pkg_migration_state")).read() if os.path.isfile(os.path.join(etc_m, ".pkg_migration_state")) else ""
                check(
                    pre_ok and r_mig.returncode == 0 and "5.0.0-1" in post_opkg.stdout and
                    "/usr/libexec/noc-apid" in post_files.stdout and "/www/pro/index.html" in post_files.stdout and
                    "status=migrated" in mig_state and
                    os.path.isfile(os.path.join(etc_m, "installed_files.manifest.migrated")) and
                    open(os.path.join(etc_m, "tls.crt")).read() == "LEGACY_CERT_2410\n" and
                    open(os.path.join(etc_m, "tls.key")).read() == "LEGACY_KEY_2410\n" and
                    open(luci_s).read() == "LUCI_MIG_2410\n",
                    "P5A-OPKG[legacy_install_sh_migration_and_ownership_transfer]",
                    r_mig.stderr,
                )
            finally:
                shutil.rmtree(sb_mig, ignore_errors=True)

        # --- 2. OpenWrt 25.12.6 (apk) Signed Repo, Lifecycle & Legacy Migration ---
        if not os.path.isdir(ROOTFS_2512):
            check(False, "P5A-APK[rootfs_present]", ROOTFS_2512)
        else:
            sb = tempfile.mkdtemp(prefix="p5a_2512_")
            try:
                shutil.copytree(ROOTFS_2512, sb, symlinks=True, dirs_exist_ok=True)
                luci_sentinel = os.path.join(sb, "www/index.html")
                os.makedirs(os.path.dirname(luci_sentinel), exist_ok=True)
                open(luci_sentinel, "w").write("LUCI_SENTINEL_2512\n")
                shutil.copy2(apk_pub, os.path.join(sb, "etc/apk/keys/ephemeral_apk.pem"))
                shutil.copy2(apk_unsigned, os.path.join(sb, "tmp/unsigned.apk"))

                repo_25 = os.path.join(sb, "tmp/apk_repo")
                ndx_path = build_signed_apk_repo(SDK_APK_BIN, apk_priv, os.path.join(sb, "etc/apk/keys"), repo_25, [apk_500])
                open(os.path.join(sb, "tmp/apk_repos.list"), "w").write("/tmp/apk_repo/packages.adb\n")

                # Negative tests: unsigned .apk and tampered packages.adb MUST be rejected without --allow-untrusted
                r_untr = chroot_run(sb, "/usr/bin/apk verify /tmp/unsigned.apk")
                orig_ndx = open(ndx_path, "rb").read()
                open(ndx_path, "wb").write(orig_ndx[:-10] + bytes(b ^ 0xff for b in orig_ndx[-10:]))
                r_tamp_ver = chroot_run(sb, "/usr/bin/apk verify /tmp/apk_repo/packages.adb")
                r_tamp_add = chroot_run(sb, "/usr/bin/apk add --no-network --repositories-file /tmp/apk_repos.list nms-console")
                check(
                    r_untr.returncode != 0 and r_tamp_ver.returncode != 0 and r_tamp_add.returncode != 0,
                    "P5A-APK[unsigned_pkg_and_tampered_index_rejected]",
                )

                # Restore signed packages.adb -> verify & install WITHOUT --allow-untrusted or --force-non-repository
                open(ndx_path, "wb").write(orig_ndx)
                r_ver_ndx = chroot_run(sb, "/usr/bin/apk verify /tmp/apk_repo/packages.adb")
                r_ver_pkg = chroot_run(sb, "/usr/bin/apk verify /tmp/apk_repo/nms-console-5.0.0-r1.apk")
                r_inst = chroot_run(sb, "/usr/bin/apk add --no-network --repositories-file /tmp/apk_repos.list nms-console")
                r_list = chroot_run(sb, "/usr/bin/apk list --installed nms-console")
                r_files = chroot_run(sb, "/usr/bin/apk info -L nms-console")
                check(
                    r_ver_ndx.returncode == 0 and r_ver_pkg.returncode == 0 and
                    r_inst.returncode == 0 and "nms-console-5.0.0-r1" in r_list.stdout and
                    "www/pro/index.html" in r_files.stdout and "usr/libexec/noc-apid" in r_files.stdout and
                    open(luci_sentinel).read() == "LUCI_SENTINEL_2512\n",
                    "P5A-APK[signed_repo_fresh_install_and_luci_preserved]",
                    (r_ver_ndx.stderr + r_ver_pkg.stderr + r_inst.stderr)[-240:],
                )

                # Seed TLS & users, rebuild signed repo with 5.0.1-r1, and upgrade
                etc_dir = os.path.join(sb, "etc/noc-console")
                os.makedirs(etc_dir, exist_ok=True)
                open(os.path.join(etc_dir, "tls.crt"), "w").write("CERT_DATA_2512\n")
                open(os.path.join(etc_dir, "tls.key"), "w").write("KEY_DATA_2512\n")
                open(os.path.join(etc_dir, "users.json"), "w").write('{"admin":{"role":"admin"}}\n')

                build_signed_apk_repo(SDK_APK_BIN, apk_priv, os.path.join(sb, "etc/apk/keys"), repo_25, [apk_500, apk_501])
                r_upg = chroot_run(sb, "/usr/bin/apk upgrade --no-network --repositories-file /tmp/apk_repos.list nms-console")
                r_list2 = chroot_run(sb, "/usr/bin/apk list --installed nms-console")
                check(
                    r_upg.returncode == 0 and "nms-console-5.0.1-r1" in r_list2.stdout and
                    open(os.path.join(etc_dir, "tls.crt")).read() == "CERT_DATA_2512\n" and
                    open(os.path.join(etc_dir, "tls.key")).read() == "KEY_DATA_2512\n" and
                    open(os.path.join(etc_dir, "users.json")).read() == '{"admin":{"role":"admin"}}\n',
                    "P5A-APK[signed_upgrade_preserves_tls_and_users]",
                    r_upg.stderr,
                )

                # Remove & reinstall
                r_rem = chroot_run(sb, "/usr/bin/apk del --no-network nms-console")
                removed_ok = r_rem.returncode == 0 and not os.path.exists(os.path.join(sb, "usr/libexec/noc-apid"))
                r_re = chroot_run(sb, "/usr/bin/apk add --no-network --repositories-file /tmp/apk_repos.list nms-console")
                check(
                    removed_ok and r_re.returncode == 0 and
                    open(os.path.join(etc_dir, "tls.crt")).read() == "CERT_DATA_2512\n" and
                    open(luci_sentinel).read() == "LUCI_SENTINEL_2512\n" and
                    os.path.isfile(os.path.join(sb, "usr/libexec/noc-apid")),
                    "P5A-APK[remove_preserves_config_and_reinstall_clean]",
                )
            finally:
                shutil.rmtree(sb, ignore_errors=True)

            # Legacy install.sh migration -> signed apk repo
            sb_mig = tempfile.mkdtemp(prefix="p5a_2512_mig_")
            try:
                shutil.copytree(ROOTFS_2512, sb_mig, symlinks=True, dirs_exist_ok=True)
                luci_s = os.path.join(sb_mig, "www/index.html")
                os.makedirs(os.path.dirname(luci_s), exist_ok=True)
                open(luci_s, "w").write("LUCI_MIG_2512\n")
                shutil.copytree(REPO_ROOT, os.path.join(sb_mig, "tmp/nms_src"), ignore=shutil.ignore_patterns(".git", "__pycache__"))
                r_leg = chroot_run(sb_mig, "NMS_SKIP_PKG_INSTALL=1 NMS_SKIP_CHOWN=1 NMS_SKIP_SERVICE_START=1 /tmp/nms_src/scripts/install.sh --allow-insecure-lan-http")
                etc_m = os.path.join(sb_mig, "etc/noc-console")
                open(os.path.join(etc_m, "tls.crt"), "w").write("LEGACY_CERT_2512\n")
                open(os.path.join(etc_m, "tls.key"), "w").write("LEGACY_KEY_2512\n")
                open(os.path.join(etc_m, "users.json"), "w").write('{"admin":{"role":"admin"}}\n')
                pre_apk = chroot_run(sb_mig, "/usr/bin/apk list --installed nms-console")
                pre_ok = (
                    r_leg.returncode == 0 and
                    os.path.isfile(os.path.join(etc_m, "installed_files.manifest")) and
                    "nms-console" not in pre_apk.stdout
                )

                shutil.copy2(apk_pub, os.path.join(sb_mig, "etc/apk/keys/ephemeral_apk.pem"))
                repo_m = os.path.join(sb_mig, "tmp/apk_repo")
                build_signed_apk_repo(SDK_APK_BIN, apk_priv, os.path.join(sb_mig, "etc/apk/keys"), repo_m, [apk_500])
                open(os.path.join(sb_mig, "tmp/apk_repos.list"), "w").write("/tmp/apk_repo/packages.adb\n")
                r_mig = chroot_run(sb_mig, "/usr/bin/apk add --no-network --repositories-file /tmp/apk_repos.list nms-console")
                post_apk = chroot_run(sb_mig, "/usr/bin/apk list --installed nms-console")
                post_files = chroot_run(sb_mig, "/usr/bin/apk info -L nms-console")
                mig_state = open(os.path.join(etc_m, ".pkg_migration_state")).read() if os.path.isfile(os.path.join(etc_m, ".pkg_migration_state")) else ""
                check(
                    pre_ok and r_mig.returncode == 0 and "nms-console-5.0.0-r1" in post_apk.stdout and
                    "usr/libexec/noc-apid" in post_files.stdout and "www/pro/index.html" in post_files.stdout and
                    "status=migrated" in mig_state and
                    os.path.isfile(os.path.join(etc_m, "installed_files.manifest.migrated")) and
                    open(os.path.join(etc_m, "tls.crt")).read() == "LEGACY_CERT_2512\n" and
                    open(os.path.join(etc_m, "tls.key")).read() == "LEGACY_KEY_2512\n" and
                    open(luci_s).read() == "LUCI_MIG_2512\n",
                    "P5A-APK[legacy_install_sh_migration_and_ownership_transfer]",
                    r_mig.stderr,
                )
            finally:
                shutil.rmtree(sb_mig, ignore_errors=True)
    finally:
        shutil.rmtree(pkg_dir, ignore_errors=True)

    print(f"\n=== PHASE 5A SUMMARY: {len(passes)} passed, {len(failures)} failed ===")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
