#!/bin/sh
set -eu

# NMS Root-Interface Redirect Activator (Option A)
# Safely installs /www/index.html (launcher_index.html) and /www/cgi-bin/luci (luci_redirect_cgi.uc)
# while preserving original LuCI backups (/www/index.luci.bak.html and /www/cgi-bin/luci.orig.bak)
# with pinned SHA-256 verification and transactional rollback.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROOT_PREFIX="${NMS_ROOT_PREFIX:-}"
FAIL_POINT="${NMS_TEST_ROOT_REDIRECT_FAIL_POINT:-}"

PINNED_INDEX_BAK_SHA="${NMS_EXPECTED_INDEX_BAK_SHA:-f68138db6165da195c2b8347ebdfa43b1c1a13e1c96386d2abed09578cb06b30}"
PINNED_CGI_BAK_SHA="${NMS_EXPECTED_CGI_BAK_SHA:-aced6c9b2e621bb6e1dd1bb7d675925e9325ed901f49b1aabb0696a06942dacb}"

if [ -z "$ROOT_PREFIX" ] && [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: Please run enable-root-redirect.sh as root." >&2
  exit 1
fi

ETC_DIR="${ROOT_PREFIX}/etc/noc-console"
WEB_DIR="${ROOT_PREFIX}/www"
CGI_DIR="${WEB_DIR}/cgi-bin"
PRO_DIR="${WEB_DIR}/pro"

WEB_INDEX="${WEB_DIR}/index.html"
WEB_INDEX_BAK="${WEB_DIR}/index.luci.bak.html"
LUCI_CGI="${CGI_DIR}/luci"
LUCI_CGI_BAK="${CGI_DIR}/luci.orig.bak"
LUCI_META="${ETC_DIR}/luci_backup.manifest"

LAUNCHER_HTML_SRC="${REPO_ROOT}/frontend/launcher_index.html"
LAUNCHER_JS_SRC="${REPO_ROOT}/frontend/launcher.js"
REDIRECT_CGI_SRC="${REPO_ROOT}/scripts/luci_redirect_cgi.uc"
if [ ! -f "$LAUNCHER_HTML_SRC" ] && [ -f "${PRO_DIR}/launcher_index.html" ]; then
  LAUNCHER_HTML_SRC="${PRO_DIR}/launcher_index.html"
fi
if [ ! -f "$LAUNCHER_JS_SRC" ] && [ -f "${PRO_DIR}/launcher.js" ]; then
  LAUNCHER_JS_SRC="${PRO_DIR}/launcher.js"
fi
if [ ! -f "$REDIRECT_CGI_SRC" ] && [ -f "${ROOT_PREFIX}/usr/libexec/nms_luci_redirect_cgi.uc" ]; then
  REDIRECT_CGI_SRC="${ROOT_PREFIX}/usr/libexec/nms_luci_redirect_cgi.uc"
elif [ ! -f "$REDIRECT_CGI_SRC" ] && [ -f "/usr/libexec/nms_luci_redirect_cgi.uc" ]; then
  REDIRECT_CGI_SRC="/usr/libexec/nms_luci_redirect_cgi.uc"
fi

for req_src in "$LAUNCHER_HTML_SRC" "$LAUNCHER_JS_SRC" "$REDIRECT_CGI_SRC"; do
  if [ ! -s "$req_src" ]; then
    echo "ERROR: Missing required redirect source file: $req_src" >&2
    exit 1
  fi
done

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

is_nms_redirect_content() {
  grep -Eq '/pro/launcher\.js|:8743|:8780|غرفة عمليات البوابة|نظام إدارة الشبكة NMS' "$1" 2>/dev/null
}

mkdir -p "$ETC_DIR" "$WEB_DIR" "$CGI_DIR" "$PRO_DIR"

TX_DIR="${ETC_DIR}/.root_redirect_tx.$$"
rm -rf "$TX_DIR"
mkdir -p "$TX_DIR"
chmod 0700 "$TX_DIR"

COMMITTED=0
CREATED_INDEX_BAK=0
CREATED_CGI_BAK=0

rollback_tx() {
  _rc=$?
  trap - EXIT INT TERM
  if [ "$COMMITTED" -eq 0 ]; then
    echo "WARNING: Rolling back root-interface redirect transaction..." >&2
    if [ -f "${TX_DIR}/prev_index.html" ]; then
      cp -p "${TX_DIR}/prev_index.html" "${WEB_INDEX}.rb.$$" && mv -f "${WEB_INDEX}.rb.$$" "$WEB_INDEX"
    fi
    if [ -f "${TX_DIR}/prev_luci_cgi" ]; then
      cp -p "${TX_DIR}/prev_luci_cgi" "${LUCI_CGI}.rb.$$" && mv -f "${LUCI_CGI}.rb.$$" "$LUCI_CGI"
    fi
    if [ -f "${TX_DIR}/prev_meta" ]; then
      cp -p "${TX_DIR}/prev_meta" "${LUCI_META}.rb.$$" && mv -f "${LUCI_META}.rb.$$" "$LUCI_META"
    elif [ ! -f "${TX_DIR}/had_meta" ]; then
      rm -f "$LUCI_META"
    fi
    [ "$CREATED_INDEX_BAK" -eq 1 ] && rm -f "$WEB_INDEX_BAK" || true
    [ "$CREATED_CGI_BAK" -eq 1 ] && rm -f "$LUCI_CGI_BAK" || true
  fi
  rm -rf "$TX_DIR" "${WEB_INDEX}.tmp."* "${LUCI_CGI}.tmp."* "${LUCI_META}.tmp."* 2>/dev/null || true
  exit "$_rc"
}
trap 'rollback_tx' EXIT INT TERM

[ -f "$WEB_INDEX" ] && cp -p "$WEB_INDEX" "${TX_DIR}/prev_index.html"
[ -f "$LUCI_CGI" ] && cp -p "$LUCI_CGI" "${TX_DIR}/prev_luci_cgi"
if [ -f "$LUCI_META" ]; then
  touch "${TX_DIR}/had_meta"
  cp -p "$LUCI_META" "${TX_DIR}/prev_meta"
fi

INDEX_OWNED_BY_NMS=0
CGI_OWNED_BY_NMS=0
if [ -f "$LUCI_META" ]; then
  INDEX_OWNED_BY_NMS="$(awk -F'|' '$1=="/www/index.html"{print $5}' "$LUCI_META" 2>/dev/null || echo 0)"
  CGI_OWNED_BY_NMS="$(awk -F'|' '$1=="/www/cgi-bin/luci"{print $5}' "$LUCI_META" 2>/dev/null || echo 0)"
  [ -z "$INDEX_OWNED_BY_NMS" ] && INDEX_OWNED_BY_NMS=0
  [ -z "$CGI_OWNED_BY_NMS" ] && CGI_OWNED_BY_NMS=0
fi

# 1. Verify or create /www/index.luci.bak.html (NEVER overwrite existing backup)
if [ -f "$WEB_INDEX_BAK" ]; then
  if [ ! -s "$WEB_INDEX_BAK" ] || is_nms_redirect_content "$WEB_INDEX_BAK"; then
    echo "ERROR: Existing backup $WEB_INDEX_BAK is empty or contains redirect stub instead of original LuCI." >&2
    exit 1
  fi
else
  if [ ! -s "$WEB_INDEX" ] || is_nms_redirect_content "$WEB_INDEX"; then
    echo "ERROR: Cannot create LuCI backup from $WEB_INDEX (missing or already an NMS redirect without $WEB_INDEX_BAK)." >&2
    exit 1
  fi
  _src_sha="$(file_sha256 "$WEB_INDEX")"
  if [ "$_src_sha" != "$PINNED_INDEX_BAK_SHA" ]; then
    echo "ERROR: Pinned SHA-256 verification failed for $WEB_INDEX (expected $PINNED_INDEX_BAK_SHA, got $_src_sha)" >&2
    exit 1
  fi
  cp -p "$WEB_INDEX" "${WEB_INDEX_BAK}.tmp.$$"
  _bak_sha="$(file_sha256 "${WEB_INDEX_BAK}.tmp.$$")"
  if [ -z "$_src_sha" ] || [ "$_src_sha" != "$_bak_sha" ]; then
    rm -f "${WEB_INDEX_BAK}.tmp.$$"
    echo "ERROR: SHA-256 verification failed when backing up $WEB_INDEX" >&2
    exit 1
  fi
  mv -f "${WEB_INDEX_BAK}.tmp.$$" "$WEB_INDEX_BAK"
  CREATED_INDEX_BAK=1
  INDEX_OWNED_BY_NMS=1
fi

# 2. Verify or create /www/cgi-bin/luci.orig.bak (NEVER overwrite existing backup)
if [ -f "$LUCI_CGI_BAK" ]; then
  if [ ! -s "$LUCI_CGI_BAK" ] || is_nms_redirect_content "$LUCI_CGI_BAK"; then
    echo "ERROR: Existing backup $LUCI_CGI_BAK is empty or contains redirect stub instead of original LuCI." >&2
    exit 1
  fi
else
  if [ ! -s "$LUCI_CGI" ] || is_nms_redirect_content "$LUCI_CGI"; then
    echo "ERROR: Cannot create LuCI CGI backup from $LUCI_CGI (missing or already an NMS redirect without $LUCI_CGI_BAK)." >&2
    exit 1
  fi
  _src_sha="$(file_sha256 "$LUCI_CGI")"
  if [ "$_src_sha" != "$PINNED_CGI_BAK_SHA" ]; then
    echo "ERROR: Pinned SHA-256 verification failed for $LUCI_CGI (expected $PINNED_CGI_BAK_SHA, got $_src_sha)" >&2
    exit 1
  fi
  cp -p "$LUCI_CGI" "${LUCI_CGI_BAK}.tmp.$$"
  _bak_sha="$(file_sha256 "${LUCI_CGI_BAK}.tmp.$$")"
  if [ -z "$_src_sha" ] || [ "$_src_sha" != "$_bak_sha" ]; then
    rm -f "${LUCI_CGI_BAK}.tmp.$$"
    echo "ERROR: SHA-256 verification failed when backing up $LUCI_CGI" >&2
    exit 1
  fi
  mv -f "${LUCI_CGI_BAK}.tmp.$$" "$LUCI_CGI_BAK"
  CREATED_CGI_BAK=1
  CGI_OWNED_BY_NMS=1
fi

INDEX_BAK_SHA="$(file_sha256 "$WEB_INDEX_BAK")"
CGI_BAK_SHA="$(file_sha256 "$LUCI_CGI_BAK")"

# Enforce pinned SHA-256 verification on existing backups without ever overwriting them
if [ "$INDEX_BAK_SHA" != "$PINNED_INDEX_BAK_SHA" ]; then
  echo "ERROR: Existing backup $WEB_INDEX_BAK SHA-256 ($INDEX_BAK_SHA) does not match pinned value ($PINNED_INDEX_BAK_SHA)" >&2
  exit 1
fi
if [ "$CGI_BAK_SHA" != "$PINNED_CGI_BAK_SHA" ]; then
  echo "ERROR: Existing backup $LUCI_CGI_BAK SHA-256 ($CGI_BAK_SHA) does not match pinned value ($PINNED_CGI_BAK_SHA)" >&2
  exit 1
fi

INDEX_BAK_MODE="$(get_mode "$WEB_INDEX_BAK")"
CGI_BAK_MODE="$(get_mode "$LUCI_CGI_BAK")"
INDEX_BAK_OWNER="$(get_owner "$WEB_INDEX_BAK")"
CGI_BAK_OWNER="$(get_owner "$LUCI_CGI_BAK")"

if [ -f "$LUCI_META" ]; then
  _rec_idx_sha="$(awk -F'|' '$1=="/www/index.html"{print $2}' "$LUCI_META" 2>/dev/null || true)"
  _rec_cgi_sha="$(awk -F'|' '$1=="/www/cgi-bin/luci"{print $2}' "$LUCI_META" 2>/dev/null || true)"
  if [ -n "$_rec_idx_sha" ] && [ "$_rec_idx_sha" != "$INDEX_BAK_SHA" ]; then
    echo "ERROR: Backup SHA-256 mismatch for $WEB_INDEX_BAK (expected $_rec_idx_sha, got $INDEX_BAK_SHA)" >&2
    exit 1
  fi
  if [ -n "$_rec_cgi_sha" ] && [ "$_rec_cgi_sha" != "$CGI_BAK_SHA" ]; then
    echo "ERROR: Backup SHA-256 mismatch for $LUCI_CGI_BAK (expected $_rec_cgi_sha, got $CGI_BAK_SHA)" >&2
    exit 1
  fi
fi

# 3. Record verified backup manifest
cat > "${LUCI_META}.tmp.$$" <<EOF
/www/index.html|${INDEX_BAK_SHA}|${INDEX_BAK_MODE}|${INDEX_BAK_OWNER}|${INDEX_OWNED_BY_NMS}|/www/index.luci.bak.html
/www/cgi-bin/luci|${CGI_BAK_SHA}|${CGI_BAK_MODE}|${CGI_BAK_OWNER}|${CGI_OWNED_BY_NMS}|/www/cgi-bin/luci.orig.bak
EOF
chmod 0600 "${LUCI_META}.tmp.$$"
mv -f "${LUCI_META}.tmp.$$" "$LUCI_META"

# 4. Install launcher.js, /www/index.html, and /www/cgi-bin/luci atomically
cp "$LAUNCHER_JS_SRC" "${PRO_DIR}/launcher.js.tmp.$$"
chmod 0644 "${PRO_DIR}/launcher.js.tmp.$$"
mv -f "${PRO_DIR}/launcher.js.tmp.$$" "${PRO_DIR}/launcher.js"

cp "$LAUNCHER_HTML_SRC" "${WEB_INDEX}.tmp.$$"
chmod 0644 "${WEB_INDEX}.tmp.$$"
mv -f "${WEB_INDEX}.tmp.$$" "$WEB_INDEX"
[ "$FAIL_POINT" = "after_index" ] && { echo "ERROR: Injected failure after_index" >&2; exit 1; }

cp "$REDIRECT_CGI_SRC" "${LUCI_CGI}.tmp.$$"
chmod 0755 "${LUCI_CGI}.tmp.$$"
mv -f "${LUCI_CGI}.tmp.$$" "$LUCI_CGI"
[ "$FAIL_POINT" = "after_cgi" ] && { echo "ERROR: Injected failure after_cgi" >&2; exit 1; }

# 5. Final verification: backups untouched and new files match sources
[ "$(file_sha256 "$WEB_INDEX_BAK")" = "$INDEX_BAK_SHA" ] || { echo "ERROR: $WEB_INDEX_BAK modified during activation" >&2; exit 1; }
[ "$(file_sha256 "$LUCI_CGI_BAK")" = "$CGI_BAK_SHA" ] || { echo "ERROR: $LUCI_CGI_BAK modified during activation" >&2; exit 1; }
[ "$(file_sha256 "$WEB_INDEX")" = "$(file_sha256 "$LAUNCHER_HTML_SRC")" ] || { echo "ERROR: $WEB_INDEX verification failed" >&2; exit 1; }
[ "$(file_sha256 "$LUCI_CGI")" = "$(file_sha256 "$REDIRECT_CGI_SRC")" ] || { echo "ERROR: $LUCI_CGI verification failed" >&2; exit 1; }

COMMITTED=1
echo "NMS root-interface redirect enabled cleanly (LuCI backups verified and preserved)."
