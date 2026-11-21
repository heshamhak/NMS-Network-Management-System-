#!/bin/sh
set -eu

# NMS (Network Management System) - Hardened Installer (P2)
# Supports sandboxed testing via NMS_ROOT_PREFIX=/path/to/sandbox

ROOT_PREFIX="${NMS_ROOT_PREFIX:-}"
SKIP_SERVICE_START="${NMS_SKIP_SERVICE_START:-0}"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"

if [ -z "$ROOT_PREFIX" ] && [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: Please run install.sh as root." >&2
  exit 1
fi

ETC_DIR="${ROOT_PREFIX}/etc/noc-console"
RUN_DIR="${ROOT_PREFIX}/tmp/noc-console"
WEB_DIR="${ROOT_PREFIX}/www/pro"
LIBEXEC_DIR="${ROOT_PREFIX}/usr/libexec"
INIT_DIR="${ROOT_PREFIX}/etc/init.d"
PASSWD_FILE="${ROOT_PREFIX}/etc/passwd"
GROUP_FILE="${ROOT_PREFIX}/etc/group"
MANIFEST_FILE="${ETC_DIR}/installed_files.manifest"

REQUIRED_UCODE_MODS="fs ubus uci socket math struct uloop digest"
REQUIRED_PKGS="ucode ucode-mod-fs ucode-mod-ubus ucode-mod-uci ucode-mod-socket ucode-mod-math ucode-mod-struct ucode-mod-uloop ucode-mod-digest"

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

  # Verify every required ucode module actually loads
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

echo "[2/6] Verifying service user 'noc-api' and unified directories..."
mkdir -p "$ETC_DIR" "$RUN_DIR" "$WEB_DIR" "$LIBEXEC_DIR" "$INIT_DIR"
chmod 0700 "$ETC_DIR"
chmod 0755 "$RUN_DIR" "$WEB_DIR"

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

echo "[3/6] Installing backend daemons and frontend assets..."
cp "$REPO_ROOT/backend/noc-helperd" "${LIBEXEC_DIR}/noc-helperd"
cp "$REPO_ROOT/backend/noc-apid" "${LIBEXEC_DIR}/noc-apid"
chmod 0755 "${LIBEXEC_DIR}/noc-helperd" "${LIBEXEC_DIR}/noc-apid"

cp -r "$REPO_ROOT/frontend/." "${WEB_DIR}/"
# Separate directory vs file permissions (INS-02)
find "$WEB_DIR" -type d -exec chmod 0755 {} +
find "$WEB_DIR" -type f -exec chmod 0644 {} +

echo "[4/6] Installing init.d services..."
cp "$REPO_ROOT/init.d/noc-helperd" "${INIT_DIR}/noc-helperd"
cp "$REPO_ROOT/init.d/noc-apid" "${INIT_DIR}/noc-apid"
chmod 0755 "${INIT_DIR}/noc-helperd" "${INIT_DIR}/noc-apid"

echo "[5/6] Writing ownership manifest (${MANIFEST_FILE})..."
TMP_MANIFEST="${MANIFEST_FILE}.tmp.$$"
{
  echo "/usr/libexec/noc-helperd"
  echo "/usr/libexec/noc-apid"
  echo "/etc/init.d/noc-helperd"
  echo "/etc/init.d/noc-apid"
  (cd "$REPO_ROOT/frontend" && find . -type f | sed 's|^\.|/www/pro|' | sort)
} > "$TMP_MANIFEST"
chmod 0600 "$TMP_MANIFEST"
mv "$TMP_MANIFEST" "$MANIFEST_FILE"

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
  if command -v socat >/dev/null 2>&1 && socat -V 2>&1 | grep -qi openssl && [ -s /etc/noc-console/tls.crt ]; then
    echo " HTTPS URL: https://${LAN_IP}:8743/"
  else
    echo " HTTP URL (LAN only): http://${LAN_IP}:8780/"
    echo " NOTE: Install 'socat' + 'openssl-util' for native HTTPS on :8743."
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
