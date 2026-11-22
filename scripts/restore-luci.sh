#!/bin/sh
set -eu

# NMS Atomic LuCI Restorer (Option A)
# Usage: restore-luci [--cleanup-nms-owned-backups]
# Verifies SHA-256 of /www/index.luci.bak.html and /www/cgi-bin/luci.orig.bak
# and atomically restores /www/index.html and /www/cgi-bin/luci byte-for-byte.
# Idempotent: safe to run repeatedly; never deletes pre-existing backups not created by NMS.

CLEANUP_OWNED=0
if [ "${1:-}" = "--cleanup-nms-owned-backups" ]; then
  CLEANUP_OWNED=1
fi

ROOT_PREFIX="${NMS_ROOT_PREFIX:-}"
FAIL_POINT="${NMS_TEST_RESTORE_LUCI_FAIL_POINT:-}"

if [ -z "$ROOT_PREFIX" ] && [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: Please run restore-luci as root." >&2
  exit 1
fi

ETC_DIR="${ROOT_PREFIX}/etc/noc-console"
WEB_DIR="${ROOT_PREFIX}/www"
CGI_DIR="${WEB_DIR}/cgi-bin"

WEB_INDEX="${WEB_DIR}/index.html"
WEB_INDEX_BAK="${WEB_DIR}/index.luci.bak.html"
LUCI_CGI="${CGI_DIR}/luci"
LUCI_CGI_BAK="${CGI_DIR}/luci.orig.bak"
LUCI_META="${ETC_DIR}/luci_backup.manifest"

file_sha256() {
  sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

get_mode() {
  if command -v ucode >/dev/null 2>&1; then
    ucode -e "import * as fs from 'fs'; let s = fs.stat(ARGV[0]); if (!s) exit(1); printf('%o\n', s.mode & 0o7777);" "$1" 2>/dev/null && return 0
  fi
  stat -c '%a' "$1" 2>/dev/null || echo '644'
}

if [ ! -s "$WEB_INDEX_BAK" ]; then
  echo "RESTORE-LUCI ERROR: Missing or empty LuCI index backup: $WEB_INDEX_BAK" >&2
  exit 1
fi
if [ ! -s "$LUCI_CGI_BAK" ]; then
  echo "RESTORE-LUCI ERROR: Missing or empty LuCI CGI backup: $LUCI_CGI_BAK" >&2
  exit 1
fi

INDEX_BAK_SHA="$(file_sha256 "$WEB_INDEX_BAK")"
CGI_BAK_SHA="$(file_sha256 "$LUCI_CGI_BAK")"
INDEX_MODE="$(get_mode "$WEB_INDEX_BAK")"
CGI_MODE="$(get_mode "$LUCI_CGI_BAK")"
INDEX_OWNER=""
CGI_OWNER=""
INDEX_OWNED_BY_NMS=0
CGI_OWNED_BY_NMS=0

if [ -f "$LUCI_META" ]; then
  _exp_idx_sha="$(awk -F'|' '$1=="/www/index.html"{print $2}' "$LUCI_META" 2>/dev/null || true)"
  _exp_cgi_sha="$(awk -F'|' '$1=="/www/cgi-bin/luci"{print $2}' "$LUCI_META" 2>/dev/null || true)"
  _m_idx="$(awk -F'|' '$1=="/www/index.html"{print $3}' "$LUCI_META" 2>/dev/null || true)"
  _m_cgi="$(awk -F'|' '$1=="/www/cgi-bin/luci"{print $3}' "$LUCI_META" 2>/dev/null || true)"
  INDEX_OWNER="$(awk -F'|' '$1=="/www/index.html"{print $4}' "$LUCI_META" 2>/dev/null || true)"
  CGI_OWNER="$(awk -F'|' '$1=="/www/cgi-bin/luci"{print $4}' "$LUCI_META" 2>/dev/null || true)"
  INDEX_OWNED_BY_NMS="$(awk -F'|' '$1=="/www/index.html"{print $5}' "$LUCI_META" 2>/dev/null || echo 0)"
  CGI_OWNED_BY_NMS="$(awk -F'|' '$1=="/www/cgi-bin/luci"{print $5}' "$LUCI_META" 2>/dev/null || echo 0)"
  if [ -n "$_exp_idx_sha" ] && [ "$_exp_idx_sha" != "$INDEX_BAK_SHA" ]; then
    echo "RESTORE-LUCI ERROR: SHA-256 mismatch on $WEB_INDEX_BAK (expected $_exp_idx_sha, got $INDEX_BAK_SHA)" >&2
    exit 1
  fi
  if [ -n "$_exp_cgi_sha" ] && [ "$_exp_cgi_sha" != "$CGI_BAK_SHA" ]; then
    echo "RESTORE-LUCI ERROR: SHA-256 mismatch on $LUCI_CGI_BAK (expected $_exp_cgi_sha, got $CGI_BAK_SHA)" >&2
    exit 1
  fi
  [ -n "$_m_idx" ] && INDEX_MODE="$_m_idx"
  [ -n "$_m_cgi" ] && CGI_MODE="$_m_cgi"
fi

TMP_INDEX="${WEB_INDEX}.restore.tmp.$$"
TMP_CGI="${LUCI_CGI}.restore.tmp.$$"
PREV_INDEX="${WEB_INDEX}.prev.tmp.$$"
COMMITTED=0

cleanup_restore() {
  _rc=$?
  trap - EXIT INT TERM
  if [ "$COMMITTED" -eq 0 ] && [ -f "$PREV_INDEX" ]; then
    mv -f "$PREV_INDEX" "$WEB_INDEX" 2>/dev/null || true
  fi
  rm -f "$TMP_INDEX" "$TMP_CGI" "$PREV_INDEX" 2>/dev/null || true
  exit "$_rc"
}
trap 'cleanup_restore' EXIT INT TERM

# Stage both files completely and verify SHA-256 before moving either file into place
cp -p "$WEB_INDEX_BAK" "$TMP_INDEX"
chmod "$INDEX_MODE" "$TMP_INDEX"
if [ -n "$INDEX_OWNER" ] && [ "$INDEX_OWNER" != ":" ]; then
  chown "$INDEX_OWNER" "$TMP_INDEX" 2>/dev/null || true
fi

cp -p "$LUCI_CGI_BAK" "$TMP_CGI"
chmod "$CGI_MODE" "$TMP_CGI"
if [ -n "$CGI_OWNER" ] && [ "$CGI_OWNER" != ":" ]; then
  chown "$CGI_OWNER" "$TMP_CGI" 2>/dev/null || true
fi

if [ "$(file_sha256 "$TMP_INDEX")" != "$INDEX_BAK_SHA" ] || [ "$(file_sha256 "$TMP_CGI")" != "$CGI_BAK_SHA" ]; then
  echo "RESTORE-LUCI ERROR: Staged files failed SHA-256 verification." >&2
  exit 1
fi

[ "$FAIL_POINT" = "before_commit" ] && { echo "RESTORE-LUCI ERROR: Injected failure before_commit" >&2; exit 1; }

[ -f "$WEB_INDEX" ] && cp -p "$WEB_INDEX" "$PREV_INDEX"
mv -f "$TMP_INDEX" "$WEB_INDEX"
[ "$FAIL_POINT" = "after_index_move" ] && { echo "RESTORE-LUCI ERROR: Injected failure after_index_move" >&2; exit 1; }
mv -f "$TMP_CGI" "$LUCI_CGI"

# Post-move byte-for-byte SHA-256 verification
if [ "$(file_sha256 "$WEB_INDEX")" != "$INDEX_BAK_SHA" ] || [ "$(file_sha256 "$LUCI_CGI")" != "$CGI_BAK_SHA" ]; then
  echo "RESTORE-LUCI ERROR: Post-restore SHA-256 verification failed." >&2
  exit 1
fi

COMMITTED=1
rm -f "$PREV_INDEX" 2>/dev/null || true

if [ "$CLEANUP_OWNED" -eq 1 ]; then
  [ "${INDEX_OWNED_BY_NMS:-0}" = "1" ] && rm -f "$WEB_INDEX_BAK" || true
  [ "${CGI_OWNED_BY_NMS:-0}" = "1" ] && rm -f "$LUCI_CGI_BAK" || true
  rm -f "$LUCI_META" 2>/dev/null || true
fi

echo "LuCI restored cleanly (SHA-256 verified: index=${INDEX_BAK_SHA}, cgi=${CGI_BAK_SHA})."
