#!/bin/sh
set -eu

# NMS (Network Management System) - Hardened Installer (P2)
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

echo "[1/6] Pre-flight checks & dependencies..."
for d in "${ROOT_PREFIX}/etc" "${ROOT_PREFIX}/tmp" "${ROOT_PREFIX}/www" "${ROOT_PREFIX}/usr"; do
  mkdir -p "$d" 2>/dev/null || true
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

# Mandatory TLS verification (P1): never silently leave unencrypted HTTP unless --allow-insecure-lan-http
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
  echo "Refusing to expose unencrypted HTTP admin UI. Install 'socat' + 'openssl-util' or pass --allow-insecure-lan-http for isolated lab use." >&2
  exit 1
fi

echo "[2/6] Verifying service user 'noc-api' and unified directories..."
mkdir -p "$ETC_DIR" "$BACKUP_DIR" "$RUN_DIR" "$LIBEXEC_DIR" "$INIT_DIR"
if [ ! -d "$WEB_DIR" ]; then
  mkdir -p "$WEB_DIR"
  chmod 0755 "$WEB_DIR"
fi
chmod 0700 "$ETC_DIR" "$BACKUP_DIR"
chmod 0755 "$RUN_DIR"

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

echo "[3/6] Installing backend daemons and frontend assets (collision-safe)..."
cp "$REPO_ROOT/backend/noc-helperd" "${LIBEXEC_DIR}/noc-helperd"
cp "$REPO_ROOT/backend/noc-apid" "${LIBEXEC_DIR}/noc-apid"
chmod 0755 "${LIBEXEC_DIR}/noc-helperd" "${LIBEXEC_DIR}/noc-apid"

TMP_MANIFEST="${MANIFEST_FILE}.tmp.$$"
TMP_RESTORE="${RESTORE_FILE}.tmp.$$"
: > "$TMP_MANIFEST"
if [ -f "$RESTORE_FILE" ]; then
  cp "$RESTORE_FILE" "$TMP_RESTORE"
else
  : > "$TMP_RESTORE"
fi

{
  echo "/usr/libexec/noc-helperd"
  echo "/usr/libexec/noc-apid"
  echo "/etc/init.d/noc-helperd"
  echo "/etc/init.d/noc-apid"
} >> "$TMP_MANIFEST"

# Copy each NMS frontend file individually; back up any pre-existing non-NMS collision
for rel in $(cd "$REPO_ROOT/frontend" && find . -type f | sed 's|^\./||' | sort); do
  src_f="${REPO_ROOT}/frontend/${rel}"
  dst_f="${WEB_DIR}/${rel}"
  dst_rel="/www/pro/${rel}"
  dst_dir="$(dirname "$dst_f")"
  if [ ! -d "$dst_dir" ]; then
    mkdir -p "$dst_dir"
    chmod 0755 "$dst_dir"
  fi
  if [ -e "$dst_f" ]; then
    already_nms=0
    if [ -f "$MANIFEST_FILE" ] && grep -Fxq "$dst_rel" "$MANIFEST_FILE" 2>/dev/null; then
      already_nms=1
    fi
    if [ "$already_nms" -eq 0 ] && ! grep -q "^${dst_rel}|" "$TMP_RESTORE" 2>/dev/null; then
      orig_mode="$(stat -c '%a' "$dst_f" 2>/dev/null || echo '644')"
      bak_name="$(printf '%s' "$dst_rel" | tr '/' '_')"
      cp -p "$dst_f" "${BACKUP_DIR}/${bak_name}"
      echo "${dst_rel}|${orig_mode}|${bak_name}" >> "$TMP_RESTORE"
    fi
  fi
  cp "$src_f" "$dst_f"
  chmod 0644 "$dst_f"
  echo "$dst_rel" >> "$TMP_MANIFEST"
done

echo "[4/6] Installing init.d services..."
cp "$REPO_ROOT/init.d/noc-helperd" "${INIT_DIR}/noc-helperd"
cp "$REPO_ROOT/init.d/noc-apid" "${INIT_DIR}/noc-apid"
chmod 0755 "${INIT_DIR}/noc-helperd" "${INIT_DIR}/noc-apid"

echo "[5/6] Finalizing ownership & restore manifests..."
chmod 0600 "$TMP_MANIFEST" "$TMP_RESTORE"
mv "$TMP_MANIFEST" "$MANIFEST_FILE"
mv "$TMP_RESTORE" "$RESTORE_FILE"

if [ "$TLS_READY" -eq 1 ] && [ ! -s "${ETC_DIR}/tls.crt" ]; then
  LAN_IP="192.168.1.1"
  if [ -z "$ROOT_PREFIX" ] && command -v uci >/dev/null 2>&1; then
    LAN_IP="$(uci -q get network.lan.ipaddr 2>/dev/null || echo '192.168.1.1')"
  fi
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${ETC_DIR}/tls.key" -out "${ETC_DIR}/tls.crt" -days 825 \
    -subj "/CN=nms.lan" \
    -addext "subjectAltName=IP:${LAN_IP},DNS:nms.lan" >/dev/null 2>&1 || \
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${ETC_DIR}/tls.key" -out "${ETC_DIR}/tls.crt" -days 825 \
    -subj "/CN=nms.lan" >/dev/null 2>&1
  chmod 0600 "${ETC_DIR}/tls.key"
  chmod 0644 "${ETC_DIR}/tls.crt"
  openssl x509 -in "${ETC_DIR}/tls.crt" -noout -fingerprint -sha256 > "${ETC_DIR}/tls.fingerprint" 2>/dev/null || true
  chmod 0644 "${ETC_DIR}/tls.fingerprint" 2>/dev/null || true
fi

if [ "$SKIP_SERVICE_START" -eq 0 ] && [ -z "$ROOT_PREFIX" ]; then
  echo "[6/6] Enabling and starting NMS services..."
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
    if [ -f "${ETC_DIR}/tls.fingerprint" ]; then
      echo " Cert Fingerprint: $(cat "${ETC_DIR}/tls.fingerprint")"
    fi
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
  echo "[6/6] Sandbox/offline install completed."
fi
