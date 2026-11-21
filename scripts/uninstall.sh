#!/bin/sh
set -eu

# NMS (Network Management System) - Ownership-Aware Uninstaller (P3)
# Usage: ./uninstall.sh [--purge]
# Restores any pre-existing user files backed up during installation with original permissions.
# Supports sandboxed testing via NMS_ROOT_PREFIX=/path/to/sandbox

PURGE=0
if [ "${1:-}" = "--purge" ]; then
  PURGE=1
fi

ROOT_PREFIX="${NMS_ROOT_PREFIX:-}"
SKIP_SERVICE_STOP="${NMS_SKIP_SERVICE_STOP:-0}"

if [ -z "$ROOT_PREFIX" ] && [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: Please run uninstall.sh as root." >&2
  exit 1
fi

ETC_DIR="${ROOT_PREFIX}/etc/noc-console"
BACKUP_DIR="${ETC_DIR}/preexisting_backup"
RUN_DIR="${ROOT_PREFIX}/tmp/noc-console"
WEB_DIR="${ROOT_PREFIX}/www/pro"
MANIFEST_FILE="${ETC_DIR}/installed_files.manifest"
RESTORE_FILE="${ETC_DIR}/restorable_files.manifest"

echo "[1/4] Stopping and disabling NMS services..."
if [ "$SKIP_SERVICE_STOP" -eq 0 ] && [ -z "$ROOT_PREFIX" ]; then
  if [ -x /etc/init.d/noc-apid ]; then
    /etc/init.d/noc-apid stop 2>/dev/null || true
    /etc/init.d/noc-apid disable 2>/dev/null || true
  fi
  if [ -x /etc/init.d/noc-helperd ]; then
    /etc/init.d/noc-helperd stop 2>/dev/null || true
    /etc/init.d/noc-helperd disable 2>/dev/null || true
  fi
fi

echo "[2/4] Removing NMS-owned files via manifest..."
if [ -f "$MANIFEST_FILE" ]; then
  while IFS= read -r rel_path || [ -n "$rel_path" ]; do
    case "$rel_path" in
      /*)
        target="${ROOT_PREFIX}${rel_path}"
        if [ -f "$target" ] || [ -L "$target" ]; then
          rm -f "$target"
        fi
        ;;
    esac
  done < "$MANIFEST_FILE"
  rm -f "$MANIFEST_FILE"
else
  echo "WARNING: Manifest not found; removing only known NMS binaries and init scripts."
  rm -f "${ROOT_PREFIX}/etc/init.d/noc-apid" "${ROOT_PREFIX}/etc/init.d/noc-helperd"
  rm -f "${ROOT_PREFIX}/usr/libexec/noc-apid" "${ROOT_PREFIX}/usr/libexec/noc-helperd"
fi

echo "[3/4] Restoring any pre-existing user files..."
if [ -f "$RESTORE_FILE" ]; then
  while IFS='|' read -r rel_path orig_mode bak_name || [ -n "$rel_path" ]; do
    [ -z "$rel_path" ] && continue
    target="${ROOT_PREFIX}${rel_path}"
    bak_src="${BACKUP_DIR}/${bak_name}"
    if [ -f "$bak_src" ]; then
      mkdir -p "$(dirname "$target")"
      cp -p "$bak_src" "$target"
      chmod "$orig_mode" "$target" 2>/dev/null || true
      rm -f "$bak_src"
    fi
  done < "$RESTORE_FILE"
  rm -f "$RESTORE_FILE"
fi

if [ -d "$WEB_DIR" ]; then
  find "$WEB_DIR" -depth -type d -exec rmdir {} + 2>/dev/null || true
fi
if [ -d "$RUN_DIR" ]; then
  rm -f "${RUN_DIR}/helper.sock" "${RUN_DIR}/mutation.lock" "${RUN_DIR}/boot_id"
  rmdir "$RUN_DIR" 2>/dev/null || true
fi

if [ "$PURGE" -eq 1 ]; then
  echo "[4/4] Purging configuration, TLS certs, and credentials (${ETC_DIR})..."
  rm -rf "$ETC_DIR"
else
  echo "[4/4] Preserving user configuration and credentials in ${ETC_DIR} (pass --purge to delete)."
fi

echo "NMS uninstalled cleanly."
