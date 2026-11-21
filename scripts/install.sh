#!/bin/sh
set -eu

# NMS (Network Management System) - Transactional, Collision-Safe Installer (Phase 2 Final)
# Usage: ./install.sh [--allow-insecure-lan-http]
# Supports sandboxed testing via NMS_ROOT_PREFIX=/path/to/sandbox

ALLOW_INSECURE=0
for arg in "$@"; do
  case "$arg" in
    --allow-insecure-lan-http) ALLOW_INSECURE=1 ;;
  esac
done

ROOT_PREFIX="${NMS_ROOT_PREFIX:-}"
SKIP_SERVICE_START="${NMS_SKIP_SERVICE_START:-0}"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"

if [ -z "$ROOT_PREFIX" ] && [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: Please run install.sh as root." >&2
  exit 1
fi

ETC_DIR="${ROOT_PREFIX}/etc/noc-console"
BACKUP_DIR="${ETC_DIR}/preexisting_backup"
RUN_DIR="${ROOT_PREFIX}/tmp/noc-console"
WEB_DIR="${ROOT_PREFIX}/www/pro"
LIBEXEC_DIR="${ROOT_PREFIX}/usr/libexec"
INIT_DIR="${ROOT_PREFIX}/etc/init.d"
PASSWD_FILE="${ROOT_PREFIX}/etc/passwd"
GROUP_FILE="${ROOT_PREFIX}/etc/group"
MANIFEST_FILE="${ETC_DIR}/installed_files.manifest"
RESTORE_FILE="${ETC_DIR}/restorable_files.manifest"

REQUIRED_UCODE_MODS="fs ubus uci socket math struct uloop digest"
REQUIRED_PKGS="ucode ucode-mod-fs ucode-mod-ubus ucode-mod-uci ucode-mod-socket ucode-mod-math ucode-mod-struct ucode-mod-uloop ucode-mod-digest"
TLS_PKGS="socat openssl-util"

# Transaction state for atomic rollback on any failure
COMMITTED=0
TX_TMP_DIR=""
TX_CREATED_FILES=""
TX_CREATED_DIRS=""
TX_RESTORE_LIST=""
TMP_MANIFEST=""
TMP_RESTORE=""

ensure_dir() {
  _dir="$1"
  _mode="$2"
  if [ ! -d "$_dir" ]; then
    mkdir -p "$_dir"
    chmod "$_mode" "$_dir"
    TX_CREATED_DIRS="${_dir}
${TX_CREATED_DIRS}"
  fi
}

rollback_tx() {
  _rc=$?
  if [ "$COMMITTED" -eq 0 ]; then
    echo "ROLLBACK: Reverting partial installation..." >&2
    # Remove temporary staging files
    [ -n "$TMP_MANIFEST" ] && rm -f "$TMP_MANIFEST" 2>/dev/null || true
    [ -n "$TMP_RESTORE" ] && rm -f "$TMP_RESTORE" 2>/dev/null || true

    # Restore any pre-existing files overwritten during this transaction
    if [ -n "$TX_RESTORE_LIST" ] && [ -f "$TX_RESTORE_LIST" ]; then
      while IFS='|' read -r _dst _mode _bak || [ -n "$_dst" ]; do
        [ -z "$_dst" ] && continue
        if [ -f "$_bak" ]; then
          cp -p "$_bak" "$_dst" 2>/dev/null || true
          chmod "$_mode" "$_dst" 2>/dev/null || true
        fi
      done < "$TX_RESTORE_LIST"
    fi

    # Remove newly created files that did not exist before this transaction
    printf '%s\n' "$TX_CREATED_FILES" | while IFS= read -r _f; do
      [ -n "$_f" ] && rm -f "$_f" 2>/dev/null || true
    done

    # Remove newly created directories (deepest first) if empty
    printf '%s\n' "$TX_CREATED_DIRS" | while IFS= read -r _d; do
      [ -n "$_d" ] && rmdir "$_d" 2>/dev/null || true
    done
  fi
  [ -n "$TX_TMP_DIR" ] && [ -d "$TX_TMP_DIR" ] && rm -rf "$TX_TMP_DIR" 2>/dev/null || true
  return "$_rc"
}
trap rollback_tx EXIT INT TERM

echo "[1/6] Pre-flight checks & dependencies..."
for d in "${ROOT_PREFIX}/etc" "${ROOT_PREFIX}/tmp" "${ROOT_PREFIX}/www" "${ROOT_PREFIX}/usr"; do
  if [ ! -d "$d" ]; then
    mkdir -p "$d" 2>/dev/null || true
  fi
  if [ ! -w "$d" ]; then
    echo "ERROR: Directory not writable: $d" >&2
    exit 1
  fi
done

if [ -z "$ROOT_PREFIX" ]; then
  if ! command -v ucode >/dev/null 2>&1; then
    if command -v apk >/dev/null 2>&1; then
      apk update >/dev/null 2>&1 || true
      apk add $REQUIRED_PKGS
    elif command -v opkg >/dev/null 2>&1; then
      opkg update >/dev/null 2>&1 || true
      opkg install $REQUIRED_PKGS
    else
      echo "ERROR: 'ucode' not found and no supported package manager (apk/opkg) available." >&2
      exit 1
    fi
  fi

  MISSING_MODS=""
  for mod in $REQUIRED_UCODE_MODS; do
    if ! ucode -e "import * as m from '${mod}';" >/dev/null 2>&1; then
      MISSING_MODS="$MISSING_MODS ucode-mod-${mod}"
    fi
  done
  if [ -n "$MISSING_MODS" ]; then
    if command -v apk >/dev/null 2>&1; then
      apk update >/dev/null 2>&1 || true
      apk add $MISSING_MODS
    elif command -v opkg >/dev/null 2>&1; then
      opkg update >/dev/null 2>&1 || true
      opkg install $MISSING_MODS
    fi
    for mod in $REQUIRED_UCODE_MODS; do
      if ! ucode -e "import * as m from '${mod}';" >/dev/null 2>&1; then
        echo "ERROR: Required ucode module '${mod}' failed to load." >&2
        exit 1
      fi
    done
  fi
fi

# Mandatory TLS verification (P1)
TLS_READY=0
if command -v socat >/dev/null 2>&1 && socat -V 2>&1 | grep -qi openssl && command -v openssl >/dev/null 2>&1; then
  TLS_READY=1
elif [ -z "$ROOT_PREFIX" ]; then
  if command -v apk >/dev/null 2>&1; then
    apk add $TLS_PKGS >/dev/null 2>&1 || true
  elif command -v opkg >/dev/null 2>&1; then
    opkg install $TLS_PKGS >/dev/null 2>&1 || true
  fi
  if command -v socat >/dev/null 2>&1 && socat -V 2>&1 | grep -qi openssl && command -v openssl >/dev/null 2>&1; then
    TLS_READY=1
  fi
fi

if [ "$TLS_READY" -ne 1 ] && [ "$ALLOW_INSECURE" -ne 1 ]; then
  echo "ERROR: Mandatory TLS prerequisites (socat with OpenSSL + openssl) are unavailable." >&2
  echo "Refusing to expose unencrypted HTTP admin UI. Install 'socat' + 'openssl-util' or pass --allow-insecure-lan-http." >&2
  exit 1
fi

echo "[2/6] Initializing directories (preserving pre-existing permissions)..."
ensure_dir "$ETC_DIR" 0700
ensure_dir "$BACKUP_DIR" 0700
ensure_dir "$RUN_DIR" 0755
ensure_dir "$WEB_DIR" 0755
ensure_dir "$LIBEXEC_DIR" 0755
ensure_dir "$INIT_DIR" 0755

TX_TMP_DIR="${ETC_DIR}/.tx_tmp.$$"
mkdir -p "$TX_TMP_DIR"
chmod 0700 "$TX_TMP_DIR"
TX_RESTORE_LIST="${TX_TMP_DIR}/tx_restore.list"
: > "$TX_RESTORE_LIST"

if [ ! -f "$PASSWD_FILE" ]; then : > "$PASSWD_FILE"; fi
if [ ! -f "$GROUP_FILE" ]; then : > "$GROUP_FILE"; fi

if ! grep -q '^noc-api:' "$GROUP_FILE" 2>/dev/null; then
  GID_NUM=65001
  while grep -q ":${GID_NUM}:" "$GROUP_FILE" 2>/dev/null; do GID_NUM=$((GID_NUM + 1)); done
  echo "noc-api:x:${GID_NUM}:" >> "$GROUP_FILE"
fi
NOC_GID="$(awk -F: '$1=="noc-api"{print $3; exit}' "$GROUP_FILE")"

if ! grep -q '^noc-api:' "$PASSWD_FILE" 2>/dev/null; then
  UID_NUM="${NOC_GID:-65001}"
  while grep -q ":${UID_NUM}:" "$PASSWD_FILE" 2>/dev/null; do UID_NUM=$((UID_NUM + 1)); done
  echo "noc-api:x:${UID_NUM}:${NOC_GID:-65001}:NMS API Daemon:/tmp/noc-console:/bin/false" >> "$PASSWD_FILE"
fi

if [ -z "$ROOT_PREFIX" ]; then
  chown -R noc-api:noc-api "$RUN_DIR"
fi

# Stage and verify TLS certificate BEFORE modifying any system files
if [ "$TLS_READY" -eq 1 ] && [ ! -s "${ETC_DIR}/tls.crt" ]; then
  LAN_IP="192.168.1.1"
  if [ -z "$ROOT_PREFIX" ] && command -v uci >/dev/null 2>&1; then
    LAN_IP="$(uci -q get network.lan.ipaddr 2>/dev/null || echo '192.168.1.1')"
  fi
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${TX_TMP_DIR}/tls.key" -out "${TX_TMP_DIR}/tls.crt" -days 825 \
    -subj "/CN=nms.lan" \
    -addext "subjectAltName=IP:${LAN_IP},DNS:nms.lan" >/dev/null 2>&1 || \
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${TX_TMP_DIR}/tls.key" -out "${TX_TMP_DIR}/tls.crt" -days 825 \
    -subj "/CN=nms.lan" >/dev/null 2>&1
  grep -q "BEGIN CERTIFICATE" "${TX_TMP_DIR}/tls.crt"
  openssl x509 -in "${TX_TMP_DIR}/tls.crt" -noout -fingerprint -sha256 > "${TX_TMP_DIR}/tls.fingerprint"
fi

TMP_MANIFEST="${MANIFEST_FILE}.tmp.$$"
TMP_RESTORE="${RESTORE_FILE}.tmp.$$"
: > "$TMP_MANIFEST"
if [ -f "$RESTORE_FILE" ]; then
  cp "$RESTORE_FILE" "$TMP_RESTORE"
else
  : > "$TMP_RESTORE"
fi

install_managed_file() {
  _src="$1"
  _dst_rel="$2"
  _mode="$3"
  _dst="${ROOT_PREFIX}${_dst_rel}"
  _dst_dir="$(dirname "$_dst")"
  ensure_dir "$_dst_dir" 0755

  if [ -e "$_dst" ] || [ -L "$_dst" ]; then
    _orig_mode="$(stat -c '%a' "$_dst" 2>/dev/null || echo '644')"
    _tx_bak="${TX_TMP_DIR}/$(printf '%s' "$_dst_rel" | tr '/' '_')"
    cp -p "$_dst" "$_tx_bak"
    echo "${_dst}|${_orig_mode}|${_tx_bak}" >> "$TX_RESTORE_LIST"

    _already_nms=0
    if [ -f "$MANIFEST_FILE" ] && grep -Fxq "$_dst_rel" "$MANIFEST_FILE" 2>/dev/null; then
      _already_nms=1
    fi
    if [ "$_already_nms" -eq 0 ] && ! grep -q "^${_dst_rel}|" "$TMP_RESTORE" 2>/dev/null; then
      _perm_bak_name="$(printf '%s' "$_dst_rel" | tr '/' '_')"
      cp -p "$_dst" "${BACKUP_DIR}/${_perm_bak_name}"
      echo "${_dst_rel}|${_orig_mode}|${_perm_bak_name}" >> "$TMP_RESTORE"
    fi
  else
    TX_CREATED_FILES="${TX_CREATED_FILES}
${_dst}"
  fi

  cp "$_src" "$_dst"
  chmod "$_mode" "$_dst"
  echo "$_dst_rel" >> "$TMP_MANIFEST"
}

echo "[3/6] Installing backend, init.d, and frontend files (collision-safe)..."
install_managed_file "${REPO_ROOT}/backend/noc-helperd" "/usr/libexec/noc-helperd" 0755
install_managed_file "${REPO_ROOT}/backend/noc-apid" "/usr/libexec/noc-apid" 0755
install_managed_file "${REPO_ROOT}/init.d/noc-helperd" "/etc/init.d/noc-helperd" 0755
install_managed_file "${REPO_ROOT}/init.d/noc-apid" "/etc/init.d/noc-apid" 0755

for rel in $(cd "${REPO_ROOT}/frontend" && find . -type f | sed 's|^\./||' | sort); do
  install_managed_file "${REPO_ROOT}/frontend/${rel}" "/www/pro/${rel}" 0644
done

# Optional test hook to verify transactional rollback on mid-install failure
if [ "${NMS_TEST_FAIL_AFTER_COPY:-0}" = "1" ]; then
  echo "ERROR: Simulated mid-install failure for rollback test" >&2
  exit 1
fi

echo "[4/6] Committing TLS artifacts and ownership manifests..."
if [ -s "${TX_TMP_DIR}/tls.crt" ] && [ ! -s "${ETC_DIR}/tls.crt" ]; then
  chmod 0600 "${TX_TMP_DIR}/tls.key"
  chmod 0644 "${TX_TMP_DIR}/tls.crt" "${TX_TMP_DIR}/tls.fingerprint"
  mv "${TX_TMP_DIR}/tls.key" "${ETC_DIR}/tls.key"
  mv "${TX_TMP_DIR}/tls.crt" "${ETC_DIR}/tls.crt"
  mv "${TX_TMP_DIR}/tls.fingerprint" "${ETC_DIR}/tls.fingerprint"
fi

chmod 0600 "$TMP_MANIFEST" "$TMP_RESTORE"
mv "$TMP_MANIFEST" "$MANIFEST_FILE"
mv "$TMP_RESTORE" "$RESTORE_FILE"
COMMITTED=1

if [ "$SKIP_SERVICE_START" -eq 0 ] && [ -z "$ROOT_PREFIX" ]; then
  echo "[5/6] Enabling and starting NMS services..."
  /etc/init.d/noc-helperd enable
  /etc/init.d/noc-apid enable
  /etc/init.d/noc-helperd restart
  sleep 1
  /etc/init.d/noc-apid restart
  sleep 1

  LAN_IP="$(uci -q get network.lan.ipaddr 2>/dev/null || echo '192.168.1.1')"
  echo ""
  echo "=================================================="
  echo " NMS (Network Management System) installed!"
  if [ "$TLS_READY" -eq 1 ]; then
    echo " HTTPS URL: https://${LAN_IP}:8743/"
    [ -f "${ETC_DIR}/tls.fingerprint" ] && echo " Cert Fingerprint: $(cat "${ETC_DIR}/tls.fingerprint")"
  else
    echo " WARNING: Running HTTP (LAN only, explicit override): http://${LAN_IP}:8780/"
  fi
  if [ -f /etc/noc-console/bootstrap.token ]; then
    echo " Bootstrap Token: $(cat /etc/noc-console/bootstrap.token)"
  else
    echo " Bootstrap Token: /etc/noc-console/bootstrap.token"
  fi
  echo "=================================================="
else
  echo "[6/6] Sandbox/offline install committed cleanly."
fi
