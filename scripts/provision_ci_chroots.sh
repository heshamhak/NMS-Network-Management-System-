#!/bin/sh
# Provision isolated OpenWrt 24.10.0 (opkg) & 25.12.6 (apk) chroot rootfs and ucode modules for CI.
set -eu

if [ ! -x /usr/sbin/chroot ]; then
  CHROOT_REAL="$(command -v chroot || true)"
  if [ -n "$CHROOT_REAL" ] && [ -x "$CHROOT_REAL" ]; then
    sudo ln -sf "$CHROOT_REAL" /usr/sbin/chroot
  fi
fi

mkdir -p /tmp/openwrt-24.10-x86-64-rootfs /tmp/openwrt-x86-64-rootfs /tmp/openwrt-pkg-cache/25.12.6

if [ ! -x /tmp/openwrt-24.10-x86-64-rootfs/bin/opkg ]; then
  curl -fsSL https://downloads.openwrt.org/releases/24.10.0/targets/x86/64/openwrt-24.10.0-x86-64-rootfs.tar.gz \
    | tar -xz --no-same-owner --exclude='./dev/*' --exclude='dev/*' -C /tmp/openwrt-24.10-x86-64-rootfs
  mkdir -p /tmp/openwrt-24.10-x86-64-rootfs/dev
fi

if [ ! -x /tmp/openwrt-x86-64-rootfs/usr/bin/apk ]; then
  curl -fsSL https://downloads.openwrt.org/releases/25.12.6/targets/x86/64/openwrt-25.12.6-x86-64-rootfs.tar.gz \
    | tar -xz --no-same-owner --exclude='./dev/*' --exclude='dev/*' -C /tmp/openwrt-x86-64-rootfs
  mkdir -p /tmp/openwrt-x86-64-rootfs/dev
fi

python3 - <<'PY'
import io
import os
import shutil
import subprocess
import tarfile
import urllib.request

cache_25 = "/tmp/openwrt-pkg-cache/25.12.6"
base_25 = "https://downloads.openwrt.org/releases/25.12.6/packages/x86_64/base"
files_25 = [
    "packages.adb",
    "ucode-mod-digest-2026.07.09~b885dd0f-r3.apk",
    "ucode-mod-socket-2026.07.09~b885dd0f-r3.apk",
    "ucode-mod-struct-2026.07.09~b885dd0f-r3.apk",
]
for fn in files_25:
    dst = os.path.join(cache_25, fn)
    if not os.path.isfile(dst):
        urllib.request.urlretrieve(f"{base_25}/{fn}", dst)

rfs25 = "/tmp/openwrt-x86-64-rootfs"
repo25 = os.path.join(rfs25, "tmp", "apk_init")
os.makedirs(os.path.join(repo25, "x86_64"), exist_ok=True)
for fn in files_25:
    raw = open(os.path.join(cache_25, fn), "rb").read()
    open(os.path.join(repo25, fn), "wb").write(raw)
    if fn.endswith(".apk"):
        open(os.path.join(repo25, "x86_64", fn), "wb").write(raw)
repos_list = os.path.join(rfs25, "tmp", "apk_repos.list")
open(repos_list, "w").write("/tmp/apk_init/packages.adb\n")
subprocess.run(
    [
        "unshare", "-r", "/usr/sbin/chroot", rfs25,
        "/usr/bin/apk", "add", "--no-network", "--repositories-file", "/tmp/apk_repos.list",
        "ucode-mod-digest", "ucode-mod-socket", "ucode-mod-struct",
    ],
    check=True,
)
shutil.rmtree(repo25, ignore_errors=True)
if os.path.exists(repos_list):
    os.unlink(repos_list)

base_24 = "https://downloads.openwrt.org/releases/24.10.0/packages/x86_64/base"
pkgs_txt = urllib.request.urlopen(f"{base_24}/Packages").read().decode("utf-8")
rfs24 = "/tmp/openwrt-24.10-x86-64-rootfs"
wanted = {"ucode", "libucode20230711", "ucode-mod-digest", "ucode-mod-socket", "ucode-mod-struct", "ucode-mod-uloop"}
cur = None
for line in pkgs_txt.splitlines():
    if line.startswith("Package: "):
        cur = line.split(": ", 1)[1].strip()
    elif line.startswith("Filename: ") and cur in wanted:
        fn = line.split(": ", 1)[1].strip()
        raw = urllib.request.urlopen(f"{base_24}/{fn}").read()
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as outer:
            dm = outer.extractfile("./data.tar.gz") or outer.extractfile("data.tar.gz")
            with tarfile.open(fileobj=io.BytesIO(dm.read()), mode="r:gz") as dtf:
                dtf.extractall(rfs24)
        wanted.discard(cur)
assert not wanted, f"missing 24.10 packages: {wanted}"
print("PROVISION_CI_CHROOTS_OK")
PY
