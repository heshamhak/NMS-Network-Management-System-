#!/bin/sh
set -eu

# NMS (Network Management System) - Ownership-Aware Uninstaller (Phase 2 Final)
# Usage: ./uninstall.sh [--purge]
# Restores any pre-existing user files backed up during installation with original permissions.
# Reports and fails on any restoration or removal error without hiding failures.
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

UNINSTALL_ERR=0

echo "[1/4] Stopping and disabling NMS services..."
if [ "$SKIP_SERVICE_STOP" -eq 0 ] && [ -z "$ROOT_PREFIX" ]; then
  if [ -e /etc/init.d/noc-apid ]; then
    /etc/init.d/noc-apid stop || { echo "UNINSTALL ERROR: failed to stop /etc/init.d/noc-apid" >&2; UNINSTALL_ERR=1; }
    /etc/init.d/noc-apid disable || { echo "UNINSTALL ERROR: failed to disable /etc/init.d/noc-apid" >&2; UNINSTALL_ERR=1; }
  fi
  if [ -e /etc/init.d/noc-helperd ]; then
    /etc/init.d/noc-helperd stop || { echo "UNINSTALL ERROR: failed to stop /etc/init.d/noc-helperd" >&2; UNINSTALL_ERR=1; }
    /etc/init.d/noc-helperd disable || { echo "UNINSTALL ERROR: failed to disable /etc/init.d/noc-helperd" >&2; UNINSTALL_ERR=1; }
  fi
fi

echo "[2/4] Removing NMS-owned files via manifest..."
REM_ERR=0
if [ -f "$MANIFEST_FILE" ]; then
  while IFS= read -r rel_path || [ -n "$rel_path" ]; do
    case "$rel_path" in
      /*)
        target="${ROOT_PREFIX}${rel_path}"
        if [ -e "$target" ] || [ -L "$target" ]; then
          if ! rm -f "$target"; then
            echo "UNINSTALL ERROR: failed to remove $target" >&2
            REM_ERR=1
            UNINSTALL_ERR=1
          fi
        fi
        ;;
    esac
  done < "$MANIFEST_FILE"
  if [ "$REM_ERR" -eq 0 ]; then
    rm -f "$MANIFEST_FILE" || { echo "UNINSTALL ERROR: failed to remove $MANIFEST_FILE" >&2; UNINSTALL_ERR=1; }
  else
    echo "UNINSTALL WARNING: preserving $MANIFEST_FILE due to removal errors." >&2
  fi
else
  echo "WARNING: Manifest not found; removing only known NMS binaries and init scripts."
  rm -f "${ROOT_PREFIX}/etc/init.d/noc-apid" "${ROOT_PREFIX}/etc/init.d/noc-helperd" || UNINSTALL_ERR=1
  rm -f "${ROOT_PREFIX}/usr/libexec/noc-apid" "${ROOT_PREFIX}/usr/libexec/noc-helperd" || UNINSTALL_ERR=1
fi

echo "[3/4] Restoring any pre-existing user files..."
RESTORE_ERR=0
if [ -f "$RESTORE_FILE" ]; then
  while IFS='|' read -r rel_path orig_mode bak_name || [ -n "$rel_path" ]; do
    [ -z "$rel_path" ] && continue
    target="${ROOT_PREFIX}${rel_path}"
    bak_src="${BACKUP_DIR}/${bak_name}"
    if [ ! -f "$bak_src" ]; then
      echo "UNINSTALL ERROR: missing backup $bak_src for $target" >&2
      RESTORE_ERR=1
      UNINSTALL_ERR=1
      continue
    fi
    if ! mkdir -p "$(dirname "$target")" || ! cp -p "$bak_src" "$target" || ! chmod "$orig_mode" "$target"; then
      echo "UNINSTALL ERROR: failed to restore $target with mode $orig_mode" >&2
      RESTORE_ERR=1
      UNINSTALL_ERR=1
      continue
    fi
    cur_mode="$(stat -c '%a' "$target" 2>/dev/null || echo '')"
    if ! cmp -s "$bak_src" "$target" || [ "$cur_mode" != "$orig_mode" ]; then
      echo "UNINSTALL ERROR: verification failed for restored $target (mode=${cur_mode}/${orig_mode})" >&2
      RESTORE_ERR=1
      UNINSTALL_ERR=1
      continue
    fi
  done < "$RESTORE_FILE"
  if [ "$RESTORE_ERR" -eq 0 ]; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      bak_src=$(printf '%s' "$line" | cut -f1)
      rm -f "$bak_src" || { echo "UNINSTALL ERROR: failed to clean backup $bak_src" >&2; UNINSTALL_ERR=1; }
    done < "$RESTORE_FILE"
    rm -f "$RESTORE_FILE" || { echo "UNINSTALL ERROR: failed to remove $RESTORE_FILE" >&2; UNINSTALL_ERR=1; }
  else
    echo "UNINSTALL WARNING: preserving $RESTORE_FILE and backups due to restoration errors." >&2
  fi
fi

if [ -d "$WEB_DIR" ]; then
  for _d in $(find "$WEB_DIR" -depth -type d 2>/dev/null); do
    if [ -z "$(ls -A "$_d" 2>/dev/null)" ]; then
      rmdir "$_d" || { echo "UNINSTALL ERROR: failed to remove empty dir $_d" >&2; UNINSTALL_ERR=1; }
    fi
  done
fi
if [ -d "$RUN_DIR" ]; then
  rm -f "${RUN_DIR}/helper.sock" "${RUN_DIR}/mutation.lock" "${RUN_DIR}/boot_id" || UNINSTALL_ERR=1
  if [ -z "$(ls -A "$RUN_DIR" 2>/dev/null)" ]; then
    rmdir "$RUN_DIR" || { echo "UNINSTALL ERROR: failed to remove empty dir $RUN_DIR" >&2; UNINSTALL_ERR=1; }
  fi
fi

if [ "$UNINSTALL_ERR" -ne 0 ]; then
  echo "UNINSTALL FAILED: One or more cleanup or restoration operations failed." >&2
  exit 1
fi

if [ "$PURGE" -eq 1 ]; then
  echo "[4/4] Purging configuration, TLS certs, and credentials (${ETC_DIR})..."
  rm -rf "$ETC_DIR"
else
  echo "[4/4] Preserving user configuration and credentials in ${ETC_DIR} (pass --purge to delete)."
fi

echo "NMS uninstalled cleanly."
