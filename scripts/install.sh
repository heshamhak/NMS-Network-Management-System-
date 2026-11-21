#!/bin/sh
set -eu

# NMS (Network Management System) - One-Command Installer
# Target: x86_64 / embedded Linux gateways with ucode + procd + nftables

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: Please run install.sh as root." >&2
  exit 1
fi

echo "[1/5] Checking dependencies..."
if ! command -v ucode >/dev/null 2>&1; then
  if command -v apk >/dev/null 2>&1; then
    apk update >/dev/null 2>&1 || true
    apk add ucode ucode-mod-fs ucode-mod-ubus ucode-mod-uci ucode-mod-socket ucode-mod-math ucode-mod-struct
  elif command -v opkg >/dev/null 2>&1; then
    opkg update >/dev/null 2>&1 || true
    opkg install ucode ucode-mod-fs ucode-mod-ubus ucode-mod-uci ucode-mod-socket ucode-mod-math ucode-mod-struct
  else
    echo "ERROR: 'ucode' is not installed and no supported package manager (apk/opkg) was found." >&2
    exit 1
  fi
fi

echo "[2/5] Creating service user and directories..."
if ! grep -q '^noc-api:' /etc/passwd 2>/dev/null; then
  if command -v useradd >/dev/null 2>&1; then
    useradd -r -s /bin/false -d /var/run/noc-console noc-api 2>/dev/null || true
  else
    UID_NUM=65001
    while grep -q ":${UID_NUM}:" /etc/passwd 2>/dev/null; do UID_NUM=$((UID_NUM + 1)); done
    echo "noc-api:x:${UID_NUM}:${UID_NUM}:NMS API Daemon:/var/run/noc-console:/bin/false" >> /etc/passwd
    echo "noc-api:x:${UID_NUM}:" >> /etc/group
  fi
fi

mkdir -p /etc/noc-console /var/run/noc-console /www/pro /usr/libexec
chmod 700 /etc/noc-console
chown -R noc-api:noc-api /var/run/noc-console 2>/dev/null || true

echo "[3/5] Installing backend daemons and frontend assets..."
cp "$REPO_ROOT/backend/noc-helperd" /usr/libexec/noc-helperd
cp "$REPO_ROOT/backend/noc-apid" /usr/libexec/noc-apid
chmod 755 /usr/libexec/noc-helperd /usr/libexec/noc-apid

cp -r "$REPO_ROOT/frontend/"* /www/pro/
chmod -R 644 /www/pro/*
chmod 755 /www/pro

echo "[4/5] Installing and enabling init.d services..."
cp "$REPO_ROOT/init.d/noc-helperd" /etc/init.d/noc-helperd
cp "$REPO_ROOT/init.d/noc-apid" /etc/init.d/noc-apid
chmod 755 /etc/init.d/noc-helperd /etc/init.d/noc-apid

/etc/init.d/noc-helperd enable
/etc/init.d/noc-apid enable

echo "[5/5] Starting NMS services..."
/etc/init.d/noc-helperd restart
sleep 1
/etc/init.d/noc-apid restart
sleep 1

LAN_IP="$(uci -q get network.lan.ipaddr 2>/dev/null || echo '192.168.1.1')"
echo ""
echo "=================================================="
echo " NMS (Network Management System) installed!"
echo " URL: http://${LAN_IP}:8780/"
if [ -f /etc/noc-console/bootstrap.token ]; then
  echo " Bootstrap Token: $(cat /etc/noc-console/bootstrap.token)"
else
  echo " Bootstrap Token: /etc/noc-console/bootstrap.token"
fi
echo "=================================================="
