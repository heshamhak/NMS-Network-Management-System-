#!/bin/sh
set -eu

# NMS (Network Management System) - Transactional Installer (Phase 2 Final Integrity)
# Usage: ./install.sh [--allow-insecure-lan-http]
# Supports sandboxed testing via NMS_ROOT_PREFIX=/path/to/sandbox
# Note: Prerequisite OS package installation (apk/opkg) runs BEFORE the NMS transaction
# and is NOT claimed to be reversible by this script.

ALLOW_INSECURE=0
for arg in "$@"; do
  case "$arg" in
    --allow-insecure-lan-http) ALLOW_INSECURE=1 ;;
  esac
done

ROOT_PREFIX="${NMS_ROOT_PREFIX:-}"
SKIP_SERVICE_START="${NMS_SKIP_SERVICE_START:-0}"
SKIP_PKG_INSTALL="${NMS_SKIP_PKG_INSTALL:-0}"
FAIL_POINT="${NMS_TEST_FAIL_POINT:-}"
SERVICE_RUNNER="${NMS_SERVICE_RUNNER:-}"

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

# --- Stage 0: Irreversible System Prerequisite Installation (Pre-Transaction) ---
echo "[0/6] Checking system prerequisites (non-transactional OS packages)..."
if [ -z "$ROOT_PREFIX" ]; then
  if ! command -v ucode >/dev/null 2>&1; then
    if [ "$SKIP_PKG_INSTALL" -eq 1 ]; then
      echo "ERROR: 'ucode' not found and package installation is disabled (NMS_SKIP_PKG_INSTALL=1)." >&2
      exit 1
    elif command -v apk >/dev/null 2>&1; then
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
    if [ "$SKIP_PKG_INSTALL" -eq 1 ]; then
      echo "ERROR: Required ucode modules missing (${MISSING_MODS}) and package installation is disabled." >&2
      exit 1
    elif command -v apk >/dev/null 2>&1; then
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

TLS_READY=0
if command -v socat >/dev/null 2>&1 && socat -V 2>&1 | grep -qi openssl && command -v openssl >/dev/null 2>&1; then
  TLS_READY=1
elif [ -z "$ROOT_PREFIX" ] && [ "$SKIP_PKG_INSTALL" -ne 1 ]; then
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
  echo "Refusing to expose unencrypted HTTP admin UI." >&2
  exit 1
fi

validate_tls_set() {
  _crt="$1"
  _key="$2"
  _fp="$3"
  [ -s "$_crt" ] && [ -s "$_key" ] && [ -s "$_fp" ] || return 1
  openssl x509 -in "$_crt" -noout -checkend 0 >/dev/null 2>&1 || return 1
  (openssl pkey -in "$_key" -noout >/dev/null 2>&1 || openssl rsa -in "$_key" -check -noout >/dev/null 2>&1) || return 1
  _crt_pub="$(openssl x509 -in "$_crt" -pubkey -noout 2>/dev/null || true)"
  _key_pub="$(openssl pkey -in "$_key" -pubout 2>/dev/null || openssl rsa -in "$_key" -pubout 2>/dev/null || true)"
  [ -n "$_crt_pub" ] && [ "$_crt_pub" = "$_key_pub" ] || return 1
  _calc_fp="$(openssl x509 -in "$_crt" -noout -fingerprint -sha256 2>/dev/null || true)"
  _disk_fp="$(cat "$_fp" 2>/dev/null || true)"
  [ -n "$_calc_fp" ] && [ "$_calc_fp" = "$_disk_fp" ] || return 1
  return 0
}

run_svc() {
  _svc_path="$1"
  _svc_act="$2"
  if [ -n "$SERVICE_RUNNER" ]; then
    "$SERVICE_RUNNER" "$_svc_path" "$_svc_act"
  else
    "$_svc_path" "$_svc_act"
  fi
}

# --- Begin NMS Installation Transaction ---
COMMITTED=0
TX_TMP_DIR=""
TX_CREATED_FILES=""
TX_CREATED_DIRS=""
TX_RESTORE_LIST=""
TMP_MANIFEST=""
TMP_RESTORE=""
RUN_DIR_EXISTED=0
RUN_DIR_ORIG_OWNER=""
SVC_TOUCHED=0
PREV_HELPERD_EXISTED=0
PREV_APID_EXISTED=0
PREV_HELPERD_EN=0
PREV_APID_EN=0
PREV_HELPERD_RUN=0
PREV_APID_RUN=0

ensure_dir() {
  _dir="$1"
  _mode="$2"
  if [ ! -d "$_dir" ]; then
    _parent="$(dirname "$_dir")"
    if [ "$_parent" != "/" ] && [ "$_parent" != "$ROOT_PREFIX" ] && [ ! -d "$_parent" ]; then
      ensure_dir "$_parent" 0755
    fi
    mkdir "$_dir"
    chmod "$_mode" "$_dir"
    TX_CREATED_DIRS="${_dir}
${TX_CREATED_DIRS}"
  fi
}

get_file_mode() {
  if command -v ucode >/dev/null 2>&1; then
    ucode -e "import * as fs from 'fs'; let s = fs.stat(ARGV[0]); if (!s) exit(1); printf('%o\n', s.mode & 0o7777);" "$1" 2>/dev/null && return 0
  fi
  stat -c '%a' "$1" 2>/dev/null
}

get_file_uid() {
  if command -v ucode >/dev/null 2>&1; then
    ucode -e "import * as fs from 'fs'; let s = fs.stat(ARGV[0]); if (!s) exit(1); printf('%d\n', s.uid);" "$1" 2>/dev/null && return 0
  fi
  stat -c '%u' "$1" 2>/dev/null
}

get_file_gid() {
  if command -v ucode >/dev/null 2>&1; then
    ucode -e "import * as fs from 'fs'; let s = fs.stat(ARGV[0]); if (!s) exit(1); printf('%d\n', s.gid);" "$1" 2>/dev/null && return 0
  fi
  stat -c '%g' "$1" 2>/dev/null
}

backup_for_tx() {
  _target="$1"
  if [ -e "$_target" ] || [ -L "$_target" ]; then
    _omode="$(get_file_mode "$_target" || echo '644')"
    _tbak="${TX_TMP_DIR}/$(printf '%s' "$_target" | tr '/' '_').txbak"
    cp -p "$_target" "$_tbak"
    echo "${_target}|${_omode}|${_tbak}" >> "$TX_RESTORE_LIST"
  else
    TX_CREATED_FILES="${_target}
${TX_CREATED_FILES}"
  fi
}

restore_one_service() {
  _svc="$1"
  _prev_en="$2"
  _prev_run="$3"
  if [ ! -e "$_svc" ]; then
    echo "ROLLBACK ERROR: missing expected service script $_svc" >&2
    return 1
  fi

  if [ "$_prev_en" -eq 1 ]; then
    run_svc "$_svc" enable || { echo "ROLLBACK ERROR: failed to enable $_svc" >&2; return 1; }
  else
    run_svc "$_svc" disable || { echo "ROLLBACK ERROR: failed to disable $_svc" >&2; return 1; }
  fi

  if [ "$_prev_run" -eq 1 ]; then
    run_svc "$_svc" restart || { echo "ROLLBACK ERROR: failed to restart $_svc" >&2; return 1; }
  else
    run_svc "$_svc" stop || { echo "ROLLBACK ERROR: failed to stop $_svc" >&2; return 1; }
  fi

  _now_en=0; run_svc "$_svc" enabled >/dev/null 2>&1 && _now_en=1 || true
  _now_run=0; run_svc "$_svc" running >/dev/null 2>&1 && _now_run=1 || true
  if [ "$_now_en" -ne "$_prev_en" ] || [ "$_now_run" -ne "$_prev_run" ]; then
    echo "ROLLBACK ERROR: service state mismatch for $_svc (en=${_now_en}/${_prev_en}, run=${_now_run}/${_prev_run})" >&2
    return 1
  fi
  return 0
}

rollback_tx() {
  _rc=$?
  if [ "$COMMITTED" -eq 0 ]; then
    echo "ROLLBACK: Reverting NMS installation transaction..." >&2
    _rb_err=0
    [ -n "$TMP_MANIFEST" ] && rm -f "$TMP_MANIFEST" 2>/dev/null || true
    [ -n "$TMP_RESTORE" ] && rm -f "$TMP_RESTORE" 2>/dev/null || true

    # 1. Stop any newly started services BEFORE restoring files
    if [ "$SVC_TOUCHED" -eq 1 ]; then
      if [ -e "${INIT_DIR}/noc-apid" ]; then
        run_svc "${INIT_DIR}/noc-apid" stop || { echo "ROLLBACK ERROR: failed to stop noc-apid" >&2; _rb_err=1; }
      fi
      if [ -e "${INIT_DIR}/noc-helperd" ]; then
        run_svc "${INIT_DIR}/noc-helperd" stop || { echo "ROLLBACK ERROR: failed to stop noc-helperd" >&2; _rb_err=1; }
      fi
    fi

    # 2. Restore RUN_DIR ownership if it existed prior to transaction
    if [ "$RUN_DIR_EXISTED" -eq 1 ] && [ -n "$RUN_DIR_ORIG_OWNER" ] && [ -z "$ROOT_PREFIX" ]; then
      chown -R "$RUN_DIR_ORIG_OWNER" "$RUN_DIR" || { echo "ROLLBACK ERROR: chown failed on $RUN_DIR" >&2; _rb_err=1; }
    fi

    # 3. Restore pre-existing files & verify exact content + permissions (no silent || true)
    if [ -n "$TX_RESTORE_LIST" ] && [ -f "$TX_RESTORE_LIST" ]; then
      while IFS='|' read -r _dst _mode _bak || [ -n "$_dst" ]; do
        [ -z "$_dst" ] && continue
        if [ ! -f "$_bak" ]; then
          echo "ROLLBACK ERROR: missing backup $_bak for $_dst" >&2
          _rb_err=1
          continue
        fi
        if ! cp -p "$_bak" "$_dst" || ! chmod "$_mode" "$_dst"; then
          echo "ROLLBACK ERROR: failed to restore $_dst" >&2
          _rb_err=1
          continue
        fi
        _cur_mode="$(get_file_mode "$_dst" || echo '')"
        if ! cmp -s "$_bak" "$_dst" || [ "$_cur_mode" != "$_mode" ]; then
          echo "ROLLBACK ERROR: verification failed after restoring $_dst (mode=${_cur_mode}/${_mode})" >&2
          _rb_err=1
        fi
      done < "$TX_RESTORE_LIST"
    fi

    # 4. Remove newly created files from this transaction
    for _f in $TX_CREATED_FILES; do
      [ -n "$_f" ] || continue
      if [ -e "$_f" ] || [ -L "$_f" ]; then
        rm -f "$_f" || { echo "ROLLBACK ERROR: failed to remove $_f" >&2; _rb_err=1; }
      fi
    done

    # 5. Remove newly created directories (deepest first) if empty; fail on unexpected rmdir errors
    for _d in $TX_CREATED_DIRS; do
      [ -n "$_d" ] || continue
      if [ -d "$_d" ]; then
        if [ -z "$(ls -A "$_d" 2>/dev/null)" ]; then
          rmdir "$_d" || { echo "ROLLBACK ERROR: failed to remove empty dir $_d" >&2; _rb_err=1; }
        fi
      fi
    done

    # 6. Restore previous enabled/running state ONLY for services that existed prior to transaction
    if [ "$SVC_TOUCHED" -eq 1 ]; then
      if [ "$PREV_HELPERD_EXISTED" -eq 1 ]; then
        restore_one_service "${INIT_DIR}/noc-helperd" "$PREV_HELPERD_EN" "$PREV_HELPERD_RUN" || _rb_err=1
      fi
      if [ "$PREV_APID_EXISTED" -eq 1 ]; then
        restore_one_service "${INIT_DIR}/noc-apid" "$PREV_APID_EN" "$PREV_APID_RUN" || _rb_err=1
      fi
    fi

    if [ "$_rb_err" -ne 0 ]; then
      echo "ROLLBACK FAILED: One or more restoration steps failed." >&2
      _rc=1
    fi
  fi
  [ -n "$TX_TMP_DIR" ] && [ -d "$TX_TMP_DIR" ] && rm -rf "$TX_TMP_DIR" 2>/dev/null || true
  return "$_rc"
}
trap rollback_tx EXIT INT TERM

echo "[1/6] Pre-flight writable checks & tracked directory setup..."
for d in "${ROOT_PREFIX}/etc" "${ROOT_PREFIX}/tmp" "${ROOT_PREFIX}/www" "${ROOT_PREFIX}/usr"; do
  ensure_dir "$d" 0755
  if [ ! -w "$d" ]; then
    echo "ERROR: Directory not writable: $d" >&2
    exit 1
  fi
done

if [ -d "$RUN_DIR" ]; then
  RUN_DIR_EXISTED=1
  _u="$(get_file_uid "$RUN_DIR" || true)"
  _g="$(get_file_gid "$RUN_DIR" || true)"
  RUN_DIR_ORIG_OWNER=""
  [ -n "$_u" ] && [ -n "$_g" ] && RUN_DIR_ORIG_OWNER="${_u}:${_g}"
fi

ensure_dir "$ETC_DIR" 0700
ensure_dir "$BACKUP_DIR" 0700
ensure_dir "$RUN_DIR" 0755
ensure_dir "$WEB_DIR" 0755
ensure_dir "$LIBEXEC_DIR" 0755
ensure_dir "$INIT_DIR" 0755

TX_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nms_tx.XXXXXX")"
chmod 0700 "$TX_TMP_DIR"
TX_RESTORE_LIST="${TX_TMP_DIR}/tx_restore.list"
: > "$TX_RESTORE_LIST"

echo "[2/6] Tracking passwd/group and cryptographically validating TLS set..."
backup_for_tx "$PASSWD_FILE"
backup_for_tx "$GROUP_FILE"
if [ ! -f "$PASSWD_FILE" ]; then : > "$PASSWD_FILE"; chmod 0644 "$PASSWD_FILE"; fi
if [ ! -f "$GROUP_FILE" ]; then : > "$GROUP_FILE"; chmod 0644 "$GROUP_FILE"; fi

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

if [ -z "$ROOT_PREFIX" ] && [ "$SKIP_PKG_INSTALL" -ne 1 ]; then
  chown -R noc-api:noc-api "$RUN_DIR"
fi

NEED_NEW_TLS=0
if [ "$TLS_READY" -eq 1 ]; then
  if ! validate_tls_set "${ETC_DIR}/tls.crt" "${ETC_DIR}/tls.key" "${ETC_DIR}/tls.fingerprint"; then
    NEED_NEW_TLS=1
  fi
fi

if [ "$NEED_NEW_TLS" -eq 1 ]; then
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
  openssl x509 -in "${TX_TMP_DIR}/tls.crt" -noout -fingerprint -sha256 > "${TX_TMP_DIR}/tls.fingerprint"
  validate_tls_set "${TX_TMP_DIR}/tls.crt" "${TX_TMP_DIR}/tls.key" "${TX_TMP_DIR}/tls.fingerprint" || {
    echo "ERROR: Newly generated TLS set failed cryptographic validation." >&2
    exit 1
  }
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

  backup_for_tx "$_dst"

  if [ -e "$_dst" ] || [ -L "$_dst" ]; then
    _orig_mode="$(get_file_mode "$_dst" || echo '644')"
    _orig_uid="$(get_file_uid "$_dst" || echo '')"
    _orig_gid="$(get_file_gid "$_dst" || echo '')"
    _orig_owner=""
    [ -n "$_orig_uid" ] && [ -n "$_orig_gid" ] && _orig_owner="${_orig_uid}:${_orig_gid}"
    _already_nms=0
    if [ -f "$MANIFEST_FILE" ] && grep -Fxq "$_dst_rel" "$MANIFEST_FILE" 2>/dev/null; then
      _already_nms=1
    fi
    if [ "$_already_nms" -eq 0 ] && ! grep -q "^${_dst_rel}|" "$TMP_RESTORE" 2>/dev/null; then
      _perm_bak_name="$(printf '%s' "$_dst_rel" | tr '/' '_')"
      cp -p "$_dst" "${BACKUP_DIR}/${_perm_bak_name}"
      echo "${_dst_rel}|${_orig_mode}|${_perm_bak_name}|${_orig_owner}" >> "$TMP_RESTORE"
    fi
  fi

  cp "$_src" "$_dst"
  chmod "$_mode" "$_dst"
  echo "$_dst_rel" >> "$TMP_MANIFEST"
}

if [ -e "${INIT_DIR}/noc-helperd" ]; then
  PREV_HELPERD_EXISTED=1
  run_svc "${INIT_DIR}/noc-helperd" enabled >/dev/null 2>&1 && PREV_HELPERD_EN=1 || true
  run_svc "${INIT_DIR}/noc-helperd" running >/dev/null 2>&1 && PREV_HELPERD_RUN=1 || true
fi
if [ -e "${INIT_DIR}/noc-apid" ]; then
  PREV_APID_EXISTED=1
  run_svc "${INIT_DIR}/noc-apid" enabled >/dev/null 2>&1 && PREV_APID_EN=1 || true
  run_svc "${INIT_DIR}/noc-apid" running >/dev/null 2>&1 && PREV_APID_RUN=1 || true
fi

echo "[3/6] Installing backend, init.d, and frontend files (collision-safe)..."
install_managed_file "${REPO_ROOT}/backend/noc-helperd" "/usr/libexec/noc-helperd" 0755
install_managed_file "${REPO_ROOT}/backend/nms_archive.uc" "/usr/libexec/nms_archive.uc" 0644
install_managed_file "${REPO_ROOT}/backend/nms_network.uc" "/usr/libexec/nms_network.uc" 0644
install_managed_file "${REPO_ROOT}/backend/nms_fw_wifi.uc" "/usr/libexec/nms_fw_wifi.uc" 0644
install_managed_file "${REPO_ROOT}/backend/nms_discovery.uc" "/usr/libexec/nms_discovery.uc" 0644
install_managed_file "${REPO_ROOT}/backend/nms_clients.uc" "/usr/libexec/nms_clients.uc" 0644
install_managed_file "${REPO_ROOT}/backend/nms_access_dhcp.uc" "/usr/libexec/nms_access_dhcp.uc" 0644
install_managed_file "${REPO_ROOT}/backend/nms_sqm.uc" "/usr/libexec/nms_sqm.uc" 0644
install_managed_file "${REPO_ROOT}/backend/nms_topology.uc" "/usr/libexec/nms_topology.uc" 0644
install_managed_file "${REPO_ROOT}/backend/noc-apid" "/usr/libexec/noc-apid" 0755
[ "$FAIL_POINT" = "after_backend" ] && { echo "ERROR: Injected failure after_backend" >&2; exit 1; }

install_managed_file "${REPO_ROOT}/init.d/noc-helperd" "/etc/init.d/noc-helperd" 0755
install_managed_file "${REPO_ROOT}/init.d/noc-apid" "/etc/init.d/noc-apid" 0755
[ "$FAIL_POINT" = "after_initd" ] && { echo "ERROR: Injected failure after_initd" >&2; exit 1; }

for rel in $(cd "${REPO_ROOT}/frontend" && find . -type f | sed 's|^\./||' | sort); do
  install_managed_file "${REPO_ROOT}/frontend/${rel}" "/www/pro/${rel}" 0644
done
[ "$FAIL_POINT" = "after_frontend" ] && { echo "ERROR: Injected failure after_frontend" >&2; exit 1; }

echo "[4/6] Installing TLS artifacts & ownership manifests..."
if [ "$NEED_NEW_TLS" -eq 1 ] && [ -s "${TX_TMP_DIR}/tls.crt" ]; then
  backup_for_tx "${ETC_DIR}/tls.key"
  backup_for_tx "${ETC_DIR}/tls.crt"
  backup_for_tx "${ETC_DIR}/tls.fingerprint"

  chmod 0600 "${TX_TMP_DIR}/tls.key"
  mv "${TX_TMP_DIR}/tls.key" "${ETC_DIR}/tls.key"
  [ "$FAIL_POINT" = "during_tls_key" ] && { echo "ERROR: Injected failure during_tls_key" >&2; exit 1; }

  chmod 0644 "${TX_TMP_DIR}/tls.crt"
  mv "${TX_TMP_DIR}/tls.crt" "${ETC_DIR}/tls.crt"
  [ "$FAIL_POINT" = "during_tls_crt" ] && { echo "ERROR: Injected failure during_tls_crt" >&2; exit 1; }

  chmod 0644 "${TX_TMP_DIR}/tls.fingerprint"
  mv "${TX_TMP_DIR}/tls.fingerprint" "${ETC_DIR}/tls.fingerprint"
  [ "$FAIL_POINT" = "during_tls_fp" ] && { echo "ERROR: Injected failure during_tls_fp" >&2; exit 1; }
fi
[ "$FAIL_POINT" = "during_tls" ] && { echo "ERROR: Injected failure during_tls" >&2; exit 1; }

backup_for_tx "$MANIFEST_FILE"
backup_for_tx "$RESTORE_FILE"
chmod 0600 "$TMP_MANIFEST" "$TMP_RESTORE"
mv "$TMP_MANIFEST" "$MANIFEST_FILE"
mv "$TMP_RESTORE" "$RESTORE_FILE"
# Optional test hook to corrupt a backup BEFORE failure to verify rollback detects restoration failure
if [ -n "${NMS_TEST_CORRUPT_BACKUP_MATCH:-}" ] && [ -f "$TX_RESTORE_LIST" ]; then
  while IFS='|' read -r _dst _mode _bak || [ -n "$_dst" ]; do
    case "$_dst" in
      *"$NMS_TEST_CORRUPT_BACKUP_MATCH"*) rm -f "$_bak" ;;
    esac
  done < "$TX_RESTORE_LIST"
fi
[ "$FAIL_POINT" = "during_manifest" ] && { echo "ERROR: Injected failure during_manifest" >&2; exit 1; }

echo "[5/6] Enabling and starting NMS services..."
if [ "$SKIP_SERVICE_START" -eq 0 ] || [ -n "$SERVICE_RUNNER" ]; then
  SVC_TOUCHED=1
  run_svc "${INIT_DIR}/noc-helperd" enable
  [ "$FAIL_POINT" = "during_service_after_helperd_enable" ] && { echo "ERROR: Injected failure during_service_after_helperd_enable" >&2; exit 1; }
  run_svc "${INIT_DIR}/noc-apid" enable
  [ "$FAIL_POINT" = "during_service_after_apid_enable" ] && { echo "ERROR: Injected failure during_service_after_apid_enable" >&2; exit 1; }
  run_svc "${INIT_DIR}/noc-helperd" restart
  [ -z "$SERVICE_RUNNER" ] && sleep 1 || true
  [ "$FAIL_POINT" = "during_service_after_helperd_restart" ] && { echo "ERROR: Injected failure during_service_after_helperd_restart" >&2; exit 1; }
  run_svc "${INIT_DIR}/noc-apid" restart
  [ -z "$SERVICE_RUNNER" ] && sleep 1 || true
fi
[ "$FAIL_POINT" = "during_service" ] && { echo "ERROR: Injected failure during_service" >&2; exit 1; }

COMMITTED=1
echo "[6/6] NMS installation transaction committed."

if [ "$SKIP_SERVICE_START" -eq 0 ] && [ -z "$ROOT_PREFIX" ]; then
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
fi
