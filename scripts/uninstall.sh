#!/bin/sh
set -eu

# NMS (Network Management System) - Clean Uninstaller
# Usage: ./uninstall.sh [--purge]

PURGE=0
if [ "${1:-}" = "--purge" ]; then
  PURGE=1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: Please run uninstall.sh as root." >&2
  exit 1
fi

echo "[1/3] Stopping and disabling NMS services..."
if [ -x /etc/init.d/noc-apid ]; then
  /etc/init.d/noc-apid stop 2>/dev/null || true
  /etc/init.d/noc-apid disable 2>/dev/null || true
fi
if [ -x /etc/init.d/noc-helperd ]; then
  /etc/init.d/noc-helperd stop 2>/dev/null || true
  /etc/init.d/noc-helperd disable 2>/dev/null || true
fi

echo "[2/3] Removing binaries, init scripts, and web assets..."
rm -f /etc/init.d/noc-apid /etc/init.d/noc-helperd
rm -f /usr/libexec/noc-apid /usr/libexec/noc-helperd
rm -rf /www/pro /var/run/noc-console

if [ "$PURGE" -eq 1 ]; then
  echo "[3/3] Purging configuration and credentials (/etc/noc-console)..."
  rm -rf /etc/noc-console
else
  echo "[3/3] Keeping /etc/noc-console (pass --purge to remove credentials/config)."
fi

echo "NMS uninstalled cleanly."
