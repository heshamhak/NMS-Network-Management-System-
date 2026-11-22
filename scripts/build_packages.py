#!/usr/bin/env python3
"""Build OpenWrt 24.10.0 (.ipk) and 25.12.6 (.apk) packages for nms-console.

Produces pure noarch/all packages with zero ELF binaries and zero private keys,
using exact production paths (/www/pro, /usr/libexec, /etc/init.d, /etc/noc-console)
and package-manager-specific lifecycle scripts for opkg and apk.
"""

import argparse
import gzip
import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

DEPENDS_LIST = [
    "ucode",
    "ucode-mod-fs",
    "ucode-mod-ubus",
    "ucode-mod-uci",
    "ucode-mod-socket",
    "ucode-mod-math",
    "ucode-mod-struct",
    "ucode-mod-uloop",
    "ucode-mod-digest",
]

CONFFILES_TEXT = "/etc/noc-console/config.json\n/etc/noc-console/adguard.json\n/etc/noc-console/users.json\n"


def collect_payload_files():
    """Return sorted list of (archive_rel_path, host_abs_path, mode) tuples."""
    items = []
    frontend_dir = os.path.join(REPO_ROOT, "frontend")
    for fn in sorted(os.listdir(frontend_dir)):
        fp = os.path.join(frontend_dir, fn)
        if os.path.isfile(fp):
            items.append((f"www/pro/{fn}", fp, 0o644))

    backend_dir = os.path.join(REPO_ROOT, "backend")
    for fn in sorted(os.listdir(backend_dir)):
        fp = os.path.join(backend_dir, fn)
        if not os.path.isfile(fp):
            continue
        if fn in ("noc-apid", "noc-helperd"):
            items.append((f"usr/libexec/{fn}", fp, 0o755))
        elif fn.startswith("nms_") and fn.endswith(".uc"):
            items.append((f"usr/libexec/{fn}", fp, 0o644))

    init_dir = os.path.join(REPO_ROOT, "init.d")
    for fn in ("noc-apid", "noc-helperd"):
        fp = os.path.join(init_dir, fn)
        if os.path.isfile(fp):
            items.append((f"etc/init.d/{fn}", fp, 0o755))
    return items


def make_ustar_gz(entries, prefix_dot=False):
    """Build deterministic gzipped USTAR tar archive from (rel_path, bytes_or_None, mode, is_dir)."""
    buf = io.BytesIO()
    seen_dirs = set()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        if prefix_dot:
            d0 = tarfile.TarInfo("./")
            d0.type = tarfile.DIRTYPE
            d0.mode = 0o755
            d0.uid = 0
            d0.gid = 0
            d0.uname = "root"
            d0.gname = "root"
            tf.addfile(d0)
        for rel_path, data, mode, is_dir in entries:
            parts = rel_path.strip("/").split("/")
            # Ensure parent directories exist in archive
            for i in range(1, len(parts) + (1 if is_dir else 0)):
                d_rel = "/".join(parts[:i])
                if d_rel and d_rel not in seen_dirs:
                    seen_dirs.add(d_rel)
                    d_name = f"./{d_rel}/" if prefix_dot else f"{d_rel}/"
                    ti = tarfile.TarInfo(d_name)
                    ti.type = tarfile.DIRTYPE
                    ti.mode = 0o700 if d_rel == "etc/noc-console" else 0o755
                    ti.uid = 0
                    ti.gid = 0
                    ti.uname = "root"
                    ti.gname = "root"
                    tf.addfile(ti)
            if not is_dir:
                f_name = f"./{rel_path}" if prefix_dot else rel_path
                ti = tarfile.TarInfo(f_name)
                ti.size = len(data)
                ti.mode = mode
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                tf.addfile(ti, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gf:
        gf.write(buf.getvalue())
    return out.getvalue()


def opkg_preinst():
    return (
        "#!/bin/sh\n"
        '[ -n "${IPKG_INSTROOT}" ] && R="${IPKG_INSTROOT}" || R=""\n'
        'ETC_DIR="${R}/etc/noc-console"\n'
        'INIT_DIR="${R}/etc/init.d"\n'
        'MANIFEST="${ETC_DIR}/installed_files.manifest"\n'
        'MIG_DIR="${ETC_DIR}/.pkg_migration_backup"\n'
        'MIG_STATE="${ETC_DIR}/.pkg_migration_state"\n'
        'if [ -z "${IPKG_INSTROOT}" ]; then\n'
        '  [ -x "${INIT_DIR}/noc-apid" ] && "${INIT_DIR}/noc-apid" stop >/dev/null 2>&1 || true\n'
        '  [ -x "${INIT_DIR}/noc-helperd" ] && "${INIT_DIR}/noc-helperd" stop >/dev/null 2>&1 || true\n'
        'fi\n'
        'if [ -f "${MANIFEST}" ]; then\n'
        '  mkdir -p "${MIG_DIR}" && chmod 0700 "${MIG_DIR}" 2>/dev/null || true\n'
        '  while IFS= read -r rel_path || [ -n "${rel_path}" ]; do\n'
        '    [ -z "${rel_path}" ] && continue\n'
        '    src="${R}/${rel_path#/}"\n'
        '    if [ -f "${src}" ] && [ ! -L "${src}" ]; then\n'
        '      dst="${MIG_DIR}/${rel_path#/}"\n'
        '      mkdir -p "$(dirname "${dst}")"\n'
        '      cp -p "${src}" "${dst}" 2>/dev/null || true\n'
        '    fi\n'
        '  done < "${MANIFEST}"\n'
        '  printf "status=in_progress\\nmanager=opkg\\n" > "${MIG_STATE}"\n'
        '  chmod 0600 "${MIG_STATE}" 2>/dev/null || true\n'
        'fi\n'
        'exit 0\n'
    ).encode("utf-8")


def opkg_postinst():
    return (
        "#!/bin/sh\n"
        '[ -n "${IPKG_INSTROOT}" ] && R="${IPKG_INSTROOT}" || R=""\n'
        'ETC_DIR="${R}/etc/noc-console"\n'
        'RUN_DIR="${R}/tmp/noc-console"\n'
        'INIT_DIR="${R}/etc/init.d"\n'
        'LIBEXEC_DIR="${R}/usr/libexec"\n'
        'MANIFEST="${ETC_DIR}/installed_files.manifest"\n'
        'MIG_DIR="${ETC_DIR}/.pkg_migration_backup"\n'
        'MIG_STATE="${ETC_DIR}/.pkg_migration_state"\n'
        'mkdir -p "${ETC_DIR}" "${RUN_DIR}"\n'
        'chmod 0700 "${ETC_DIR}" "${RUN_DIR}" 2>/dev/null || true\n'
        'chmod 0755 "${LIBEXEC_DIR}/noc-apid" "${LIBEXEC_DIR}/noc-helperd" "${INIT_DIR}/noc-apid" "${INIT_DIR}/noc-helperd" 2>/dev/null || true\n'
        'if [ -f "${MIG_STATE}" ]; then\n'
        '  rm -rf "${MIG_DIR}" 2>/dev/null || true\n'
        '  [ -f "${MANIFEST}" ] && mv -f "${MANIFEST}" "${MANIFEST}.migrated" 2>/dev/null || true\n'
        '  printf "status=migrated\\nmanager=opkg\\n" > "${MIG_STATE}"\n'
        '  chmod 0600 "${MIG_STATE}" 2>/dev/null || true\n'
        'fi\n'
        'if [ -z "${IPKG_INSTROOT}" ] && [ -d /proc/1 ]; then\n'
        '  "${INIT_DIR}/noc-helperd" enable >/dev/null 2>&1 || true\n'
        '  "${INIT_DIR}/noc-apid" enable >/dev/null 2>&1 || true\n'
        '  "${INIT_DIR}/noc-helperd" restart >/dev/null 2>&1 || true\n'
        '  "${INIT_DIR}/noc-apid" restart >/dev/null 2>&1 || true\n'
        'fi\n'
        'exit 0\n'
    ).encode("utf-8")


def opkg_prerm():
    return (
        "#!/bin/sh\n"
        '[ -n "${IPKG_INSTROOT}" ] && R="${IPKG_INSTROOT}" || R=""\n'
        'INIT_DIR="${R}/etc/init.d"\n'
        'if [ -z "${IPKG_INSTROOT}" ] && [ "${PKG_UPGRADE:-0}" != "1" ]; then\n'
        '  [ -x "${INIT_DIR}/noc-apid" ] && "${INIT_DIR}/noc-apid" stop >/dev/null 2>&1 || true\n'
        '  [ -x "${INIT_DIR}/noc-helperd" ] && "${INIT_DIR}/noc-helperd" stop >/dev/null 2>&1 || true\n'
        '  [ -x "${INIT_DIR}/noc-apid" ] && "${INIT_DIR}/noc-apid" disable >/dev/null 2>&1 || true\n'
        '  [ -x "${INIT_DIR}/noc-helperd" ] && "${INIT_DIR}/noc-helperd" disable >/dev/null 2>&1 || true\n'
        'fi\n'
        'exit 0\n'
    ).encode("utf-8")


def apk_pre_script(is_upgrade=False):
    return (
        "#!/bin/sh\n"
        'ETC_DIR="/etc/noc-console"\n'
        'INIT_DIR="/etc/init.d"\n'
        'MANIFEST="${ETC_DIR}/installed_files.manifest"\n'
        'MIG_DIR="${ETC_DIR}/.pkg_migration_backup"\n'
        'MIG_STATE="${ETC_DIR}/.pkg_migration_state"\n'
        '[ -x "${INIT_DIR}/noc-apid" ] && "${INIT_DIR}/noc-apid" stop >/dev/null 2>&1 || true\n'
        '[ -x "${INIT_DIR}/noc-helperd" ] && "${INIT_DIR}/noc-helperd" stop >/dev/null 2>&1 || true\n'
        + (
            'if [ -f "${MANIFEST}" ]; then\n'
            '  mkdir -p "${MIG_DIR}" && chmod 0700 "${MIG_DIR}" 2>/dev/null || true\n'
            '  while IFS= read -r rel_path || [ -n "${rel_path}" ]; do\n'
            '    [ -z "${rel_path}" ] && continue\n'
            '    src="/${rel_path#/}"\n'
            '    if [ -f "${src}" ] && [ ! -L "${src}" ]; then\n'
            '      dst="${MIG_DIR}/${rel_path#/}"\n'
            '      mkdir -p "$(dirname "${dst}")"\n'
            '      cp -p "${src}" "${dst}" 2>/dev/null || true\n'
            '    fi\n'
            '  done < "${MANIFEST}"\n'
            '  printf "status=in_progress\\nmanager=apk\\n" > "${MIG_STATE}"\n'
            '  chmod 0600 "${MIG_STATE}" 2>/dev/null || true\n'
            'fi\n'
            if not is_upgrade else ""
        )
        + "exit 0\n"
    ).encode("utf-8")


def apk_post_script():
    return (
        "#!/bin/sh\n"
        'ETC_DIR="/etc/noc-console"\n'
        'RUN_DIR="/tmp/noc-console"\n'
        'INIT_DIR="/etc/init.d"\n'
        'LIBEXEC_DIR="/usr/libexec"\n'
        'MANIFEST="${ETC_DIR}/installed_files.manifest"\n'
        'MIG_DIR="${ETC_DIR}/.pkg_migration_backup"\n'
        'MIG_STATE="${ETC_DIR}/.pkg_migration_state"\n'
        'mkdir -p "${ETC_DIR}" "${RUN_DIR}"\n'
        'chmod 0700 "${ETC_DIR}" "${RUN_DIR}" 2>/dev/null || true\n'
        'chmod 0755 "${LIBEXEC_DIR}/noc-apid" "${LIBEXEC_DIR}/noc-helperd" "${INIT_DIR}/noc-apid" "${INIT_DIR}/noc-helperd" 2>/dev/null || true\n'
        'if [ -f "${MIG_STATE}" ]; then\n'
        '  rm -rf "${MIG_DIR}" 2>/dev/null || true\n'
        '  [ -f "${MANIFEST}" ] && mv -f "${MANIFEST}" "${MANIFEST}.migrated" 2>/dev/null || true\n'
        '  printf "status=migrated\\nmanager=apk\\n" > "${MIG_STATE}"\n'
        '  chmod 0600 "${MIG_STATE}" 2>/dev/null || true\n'
        'fi\n'
        'if [ -d /proc/1 ]; then\n'
        '  "${INIT_DIR}/noc-helperd" enable >/dev/null 2>&1 || true\n'
        '  "${INIT_DIR}/noc-apid" enable >/dev/null 2>&1 || true\n'
        '  "${INIT_DIR}/noc-helperd" restart >/dev/null 2>&1 || true\n'
        '  "${INIT_DIR}/noc-apid" restart >/dev/null 2>&1 || true\n'
        'fi\n'
        'exit 0\n'
    ).encode("utf-8")


def apk_pre_deinstall():
    return (
        "#!/bin/sh\n"
        'INIT_DIR="/etc/init.d"\n'
        '[ -x "${INIT_DIR}/noc-apid" ] && "${INIT_DIR}/noc-apid" stop >/dev/null 2>&1 || true\n'
        '[ -x "${INIT_DIR}/noc-helperd" ] && "${INIT_DIR}/noc-helperd" stop >/dev/null 2>&1 || true\n'
        '[ -x "${INIT_DIR}/noc-apid" ] && "${INIT_DIR}/noc-apid" disable >/dev/null 2>&1 || true\n'
        '[ -x "${INIT_DIR}/noc-helperd" ] && "${INIT_DIR}/noc-helperd" disable >/dev/null 2>&1 || true\n'
        'exit 0\n'
    ).encode("utf-8")


def build_ipk(out_dir, version="5.0.0", release="1"):
    payload = collect_payload_files()
    installed_size = sum(os.path.getsize(fp) for _, fp, _ in payload)
    data_entries = [(rel, open(fp, "rb").read(), mode, False) for rel, fp, mode in payload]
    data_entries.append(("etc/noc-console", None, 0o700, True))
    data_tgz = make_ustar_gz(data_entries, prefix_dot=True)

    full_ver = f"{version}-{release}"
    control_txt = (
        f"Package: nms-console\n"
        f"Version: {full_ver}\n"
        f"Depends: {', '.join(DEPENDS_LIST)}\n"
        f"Section: admin\n"
        f"Architecture: all\n"
        f"Installed-Size: {installed_size}\n"
        f"Maintainer: Hesham Amjad <heshamhak@users.noreply.github.com>\n"
        f"License: MIT\n"
        f"Description: Open-source bilingual (EN/AR) network management and monitoring console for OpenWrt.\n"
    ).encode("utf-8")

    ctrl_entries = [
        ("control", control_txt, 0o644, False),
        ("conffiles", CONFFILES_TEXT.encode("utf-8"), 0o644, False),
        ("preinst", opkg_preinst(), 0o755, False),
        ("postinst", opkg_postinst(), 0o755, False),
        ("prerm", opkg_prerm(), 0o755, False),
    ]
    ctrl_tgz = make_ustar_gz(ctrl_entries, prefix_dot=True)

    ipk_bytes = make_ustar_gz(
        [
            ("debian-binary", b"2.0\n", 0o644, False),
            ("control.tar.gz", ctrl_tgz, 0o644, False),
            ("data.tar.gz", data_tgz, 0o644, False),
        ],
        prefix_dot=True,
    )
    out_name = f"nms-console_{full_ver}_all.ipk"
    out_path = os.path.join(out_dir, out_name)
    with open(out_path, "wb") as f:
        f.write(ipk_bytes)
    return out_path, control_txt.decode("utf-8"), hashlib.sha256(ipk_bytes).hexdigest()


def find_apk_mkpkg_bin(explicit=None):
    candidates = [
        explicit,
        os.environ.get("APK_BIN"),
        shutil.which("apk"),
        "/home/iot/owrt/openwrt-sdk-25.12.5-x86-64_gcc-14.3.0_musl.Linux-x86_64/staging_dir/host/bin/apk",
    ]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def build_apk(out_dir, version="5.0.0", release="1", apk_bin=None, sign_key=None):
    apk_exe = find_apk_mkpkg_bin(apk_bin)
    if not apk_exe:
        raise RuntimeError("apk-tools mkpkg binary not found; pass --apk-bin or set APK_BIN")

    payload = collect_payload_files()
    pkgver = f"{version}-r{release}"
    out_name = f"nms-console-{pkgver}.apk"
    out_path = os.path.join(out_dir, out_name)

    stage = tempfile.mkdtemp(prefix="nms_apk_stage_")
    try:
        files_root = os.path.join(stage, "root")
        os.makedirs(os.path.join(files_root, "etc/noc-console"), mode=0o700, exist_ok=True)
        for rel, fp, mode in payload:
            dst = os.path.join(files_root, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(fp, dst)
            os.chmod(dst, mode)

        scripts_dir = os.path.join(stage, "scripts")
        os.makedirs(scripts_dir, exist_ok=True)
        script_map = {
            "pre-install": apk_pre_script(is_upgrade=False),
            "post-install": apk_post_script(),
            "pre-upgrade": apk_pre_script(is_upgrade=True),
            "post-upgrade": apk_post_script(),
            "pre-deinstall": apk_pre_deinstall(),
        }
        cmd = [
            apk_exe, "mkpkg",
            "--files", files_root,
            "--info", "name:nms-console",
            "--info", f"version:{pkgver}",
            "--info", "arch:noarch",
            "--info", "license:MIT",
            "--info", "origin:nms-console",
            "--info", "maintainer:Hesham Amjad <heshamhak@users.noreply.github.com>",
            "--info", "url:https://github.com/heshamhak/NMS-Network-Management-System-",
            "--info", "description:Open-source bilingual (EN/AR) network management and monitoring console for OpenWrt",
            "--info", f"depends:{' '.join(DEPENDS_LIST)}",
        ]
        for stype, sbytes in script_map.items():
            sp = os.path.join(scripts_dir, stype)
            with open(sp, "wb") as sf:
                sf.write(sbytes)
            os.chmod(sp, 0o755)
            cmd.extend(["--script", f"{stype}:{sp}"])
        if sign_key:
            cmd.extend(["--sign-key", sign_key])
        cmd.extend(["--output", out_path])
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    apk_bytes = open(out_path, "rb").read()
    return out_path, hashlib.sha256(apk_bytes).hexdigest()


def main():
    ap = argparse.ArgumentParser(description="Build nms-console .ipk and .apk packages")
    ap.add_argument("--out-dir", required=True, help="Output directory for built packages")
    ap.add_argument("--version", default="5.0.0", help="Package version")
    ap.add_argument("--release", default="1", help="Package release number")
    ap.add_argument("--apk-bin", default=None, help="Path to apk-tools v3 binary with mkpkg")
    ap.add_argument("--sign-key", default=None, help="Optional ephemeral private key for apk mkpkg")
    args = ap.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    ipk_path, _, ipk_sha = build_ipk(args.out_dir, args.version, args.release)
    apk_path, apk_sha = build_apk(args.out_dir, args.version, args.release, apk_bin=args.apk_bin, sign_key=args.sign_key)
    print(f"IPK: {ipk_path} sha256={ipk_sha}")
    print(f"APK: {apk_path} sha256={apk_sha}")


if __name__ == "__main__":
    main()
