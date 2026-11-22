#!/bin/sh
set -eu

# NMS Atomic LuCI Restorer (Option A)
# Usage: restore-luci [--cleanup-nms-owned-backups]
# Strictly requires a valid /etc/noc-console/luci_backup.manifest with both expected records,
# verifies SHA-256 of /www/index.luci.bak.html and /www/cgi-bin/luci.orig.bak before any mutation,
# preserves both previous destination files, and rolls back both on any failure.

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

get_owner() {
  if command -v ucode >/dev/null 2>&1; then
    ucode -e "import * as fs from 'fs'; let s = fs.stat(ARGV[0]); if (!s) exit(1); printf('%d:%d\n', s.uid, s.gid);" "$1" 2>/dev/null && return 0
  fi
  stat -c '%u:%g' "$1" 2>/dev/null || echo '0:0'
}

# 1. Require a valid, non-empty luci_backup.manifest containing both strict records
if [ ! -s "$LUCI_META" ]; then
  echo "RESTORE-LUCI ERROR: Mandatory manifest $LUCI_META is missing or empty." >&2
  exit 1
fi

IDX_REC="$(awk -F'|' '$1=="/www/index.html"{print $0}' "$LUCI_META" 2>/dev/null || true)"
CGI_REC="$(awk -F'|' '$1=="/www/cgi-bin/luci"{print $0}' "$LUCI_META" 2>/dev/null || true)"
IDX_COUNT="$(awk -F'|' '$1=="/www/index.html"{c++} END{print c+0}' "$LUCI_META" 2>/dev/null || echo 0)"
CGI_COUNT="$(awk -F'|' '$1=="/www/cgi-bin/luci"{c++} END{print c+0}' "$LUCI_META" 2>/dev/null || echo 0)"

if [ "$IDX_COUNT" -ne 1 ] || [ "$CGI_COUNT" -ne 1 ] || [ -z "$IDX_REC" ] || [ -z "$CGI_REC" ]; then
  echo "RESTORE-LUCI ERROR: Manifest $LUCI_META is incomplete or contains duplicate records." >&2
  exit 1
fi

EXP_IDX_SHA="$(printf '%s\n' "$IDX_REC" | awk -F'|' '{print $2}')"
INDEX_MODE="$(printf '%s\n' "$IDX_REC" | awk -F'|' '{print $3}')"
INDEX_OWNER="$(printf '%s\n' "$IDX_REC" | awk -F'|' '{print $4}')"
INDEX_OWNED_BY_NMS="$(printf '%s\n' "$IDX_REC" | awk -F'|' '{print $5}')"
INDEX_BAK_REL="$(printf '%s\n' "$IDX_REC" | awk -F'|' '{print $6}')"
INDEX_EXTRA="$(printf '%s\n' "$IDX_REC" | awk -F'|' '{print NF}')"

EXP_CGI_SHA="$(printf '%s\n' "$CGI_REC" | awk -F'|' '{print $2}')"
CGI_MODE="$(printf '%s\n' "$CGI_REC" | awk -F'|' '{print $3}')"
CGI_OWNER="$(printf '%s\n' "$CGI_REC" | awk -F'|' '{print $4}')"
CGI_OWNED_BY_NMS="$(printf '%s\n' "$CGI_REC" | awk -F'|' '{print $5}')"
CGI_BAK_REL="$(printf '%s\n' "$CGI_REC" | awk -F'|' '{print $6}')"
CGI_EXTRA="$(printf '%s\n' "$CGI_REC" | awk -F'|' '{print NF}')"

validate_manifest_fields() {
  _sha="$1"
  _mode="$2"
  _owner="$3"
  _owned="$4"
  _bak_rel="$5"
  _exp_bak_rel="$6"
  _nf="$7"
  [ "$_nf" = "6" ] || return 1
  printf '%s\n' "$_sha" | grep -Eq '^[0-9a-f]{64}$' || return 1
  printf '%s\n' "$_mode" | grep -Eq '^[0-7]{3,4}$' || return 1
  printf '%s\n' "$_owner" | grep -Eq '^[0-9]+:[0-9]+$' || return 1
  printf '%s\n' "$_owned" | grep -Eq '^[01]$' || return 1
  [ "$_bak_rel" = "$_exp_bak_rel" ] || return 1
  return 0
}

if ! validate_manifest_fields "$EXP_IDX_SHA" "$INDEX_MODE" "$INDEX_OWNER" "$INDEX_OWNED_BY_NMS" "$INDEX_BAK_REL" "/www/index.luci.bak.html" "$INDEX_EXTRA"; then
  echo "RESTORE-LUCI ERROR: Malformed /www/index.html record in $LUCI_META" >&2
  exit 1
fi
if ! validate_manifest_fields "$EXP_CGI_SHA" "$CGI_MODE" "$CGI_OWNER" "$CGI_OWNED_BY_NMS" "$CGI_BAK_REL" "/www/cgi-bin/luci.orig.bak" "$CGI_EXTRA"; then
  echo "RESTORE-LUCI ERROR: Malformed /www/cgi-bin/luci record in $LUCI_META" >&2
  exit 1
fi

# 2. Verify both backup files exist and match manifest SHA-256 BEFORE modifying any destination
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

if [ "$INDEX_BAK_SHA" != "$EXP_IDX_SHA" ]; then
  echo "RESTORE-LUCI ERROR: SHA-256 mismatch on $WEB_INDEX_BAK (expected $EXP_IDX_SHA, got $INDEX_BAK_SHA)" >&2
  exit 1
fi
if [ "$CGI_BAK_SHA" != "$EXP_CGI_SHA" ]; then
  echo "RESTORE-LUCI ERROR: SHA-256 mismatch on $LUCI_CGI_BAK (expected $EXP_CGI_SHA, got $CGI_BAK_SHA)" >&2
  exit 1
fi

TMP_INDEX="${WEB_INDEX}.restore.tmp.$$"
TMP_CGI="${LUCI_CGI}.restore.tmp.$$"
PREV_INDEX="${WEB_INDEX}.prev.tmp.$$"
PREV_CGI="${LUCI_CGI}.prev.tmp.$$"
HAD_PREV_INDEX=0
HAD_PREV_CGI=0
PREV_INDEX_MODE="644"
PREV_CGI_MODE="755"
PREV_INDEX_OWNER="0:0"
PREV_CGI_OWNER="0:0"
COMMITTED=0

cleanup_restore() {
  _rc=$?
  trap - EXIT INT TERM
  if [ "$COMMITTED" -eq 0 ]; then
    if [ "$HAD_PREV_INDEX" -eq 1 ] && [ -f "$PREV_INDEX" ]; then
      cp -p "$PREV_INDEX" "${WEB_INDEX}.rb.$$" 2>/dev/null && chmod "$PREV_INDEX_MODE" "${WEB_INDEX}.rb.$$" 2>/dev/null && chown "$PREV_INDEX_OWNER" "${WEB_INDEX}.rb.$$" 2>/dev/null || true
      mv -f "${WEB_INDEX}.rb.$$" "$WEB_INDEX" 2>/dev/null || true
    fi
    if [ "$HAD_PREV_CGI" -eq 1 ] && [ -f "$PREV_CGI" ]; then
      cp -p "$PREV_CGI" "${LUCI_CGI}.rb.$$" 2>/dev/null && chmod "$PREV_CGI_MODE" "${LUCI_CGI}.rb.$$" 2>/dev/null && chown "$PREV_CGI_OWNER" "${LUCI_CGI}.rb.$$" 2>/dev/null || true
      mv -f "${LUCI_CGI}.rb.$$" "$LUCI_CGI" 2>/dev/null || true
    fi
  fi
  rm -f "$TMP_INDEX" "$TMP_CGI" "$PREV_INDEX" "$PREV_CGI" "${WEB_INDEX}.rb.$$" "${LUCI_CGI}.rb.$$" 2>/dev/null || true
  exit "$_rc"
}
trap 'cleanup_restore' EXIT INT TERM

# 3. Preserve both previous destination files before any modification
if [ -f "$WEB_INDEX" ]; then
  PREV_INDEX_MODE="$(get_mode "$WEB_INDEX")"
  PREV_INDEX_OWNER="$(get_owner "$WEB_INDEX")"
  cp -p "$WEB_INDEX" "$PREV_INDEX"
  HAD_PREV_INDEX=1
fi
if [ -f "$LUCI_CGI" ]; then
  PREV_CGI_MODE="$(get_mode "$LUCI_CGI")"
  PREV_CGI_OWNER="$(get_owner "$LUCI_CGI")"
  cp -p "$LUCI_CGI" "$PREV_CGI"
  HAD_PREV_CGI=1
fi

# 4. Stage both files completely and verify SHA-256 before moving either file into place
cp -p "$WEB_INDEX_BAK" "$TMP_INDEX"
chmod "$INDEX_MODE" "$TMP_INDEX"
chown "$INDEX_OWNER" "$TMP_INDEX" 2>/dev/null || true

cp -p "$LUCI_CGI_BAK" "$TMP_CGI"
chmod "$CGI_MODE" "$TMP_CGI"
chown "$CGI_OWNER" "$TMP_CGI" 2>/dev/null || true

if [ "$(file_sha256 "$TMP_INDEX")" != "$INDEX_BAK_SHA" ] || [ "$(file_sha256 "$TMP_CGI")" != "$CGI_BAK_SHA" ]; then
  echo "RESTORE-LUCI ERROR: Staged files failed SHA-256 verification." >&2
  exit 1
fi

[ "$FAIL_POINT" = "before_commit" ] && { echo "RESTORE-LUCI ERROR: Injected failure before_commit" >&2; exit 1; }

mv -f "$TMP_INDEX" "$WEB_INDEX"
[ "$FAIL_POINT" = "after_index_move" ] && { echo "RESTORE-LUCI ERROR: Injected failure after_index_move" >&2; exit 1; }

mv -f "$TMP_CGI" "$LUCI_CGI"
[ "$FAIL_POINT" = "after_cgi_move" ] && { echo "RESTORE-LUCI ERROR: Injected failure after_cgi_move" >&2; exit 1; }

if [ "$FAIL_POINT" = "during_final_verify" ]; then
  printf 'CORRUPT' >> "$LUCI_CGI"
fi

# 5. Post-move byte-for-byte SHA-256 verification of both files
if [ "$(file_sha256 "$WEB_INDEX")" != "$INDEX_BAK_SHA" ] || [ "$(file_sha256 "$LUCI_CGI")" != "$CGI_BAK_SHA" ]; then
  echo "RESTORE-LUCI ERROR: Post-restore SHA-256 verification failed." >&2
  exit 1
fi

COMMITTED=1
rm -f "$PREV_INDEX" "$PREV_CGI" 2>/dev/null || true

if [ "$CLEANUP_OWNED" -eq 1 ]; then
  [ "${INDEX_OWNED_BY_NMS:-0}" = "1" ] && rm -f "$WEB_INDEX_BAK" || true
  [ "${CGI_OWNED_BY_NMS:-0}" = "1" ] && rm -f "$LUCI_CGI_BAK" || true
  rm -f "$LUCI_META" 2>/dev/null || true
fi

echo "LuCI restored cleanly (SHA-256 verified: index=${INDEX_BAK_SHA}, cgi=${CGI_BAK_SHA})."
