#!/usr/bin/env python3
"""
NMS (Network Management System) - Local & Offline Regression Suite (Phase 2 Final Acceptance)
Zero network or SSH calls to any live router.
Boundary note: OpenWrt 'procd' is absent on the Debian host; service lifecycle and
TLS topology tests run through an explicit simulated service/process harness while
exercising real child processes, real OpenSSL/socat, and the actual scripts/install.sh.
"""
import hashlib
import http.server
import json
import os
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
passes = []
failures = []


def ok(msg: str) -> None:
    passes.append(msg)
    print(f"[PASS] {msg}")


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"[FAIL] {msg}", file=sys.stderr)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def is_pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def kill_pid(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            if not is_pid_alive(pid):
                return
            time.sleep(0.05)
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def make_expired_cert_pair(work_dir: str, key_out: str, crt_out: str) -> None:
    """Generate a genuinely expired X.509 PEM certificate using standard openssl ca."""
    ca_dir = os.path.join(work_dir, "ca_tmp")
    os.makedirs(os.path.join(ca_dir, "newcerts"), exist_ok=True)
    open(os.path.join(ca_dir, "index.txt"), "w").close()
    open(os.path.join(ca_dir, "serial"), "w").write("1000\n")
    cnf = os.path.join(ca_dir, "openssl.cnf")
    open(cnf, "w").write(f"""[ ca ]
default_ca = CA_default
[ CA_default ]
dir = {ca_dir}
database = $dir/index.txt
new_certs_dir = $dir/newcerts
serial = $dir/serial
default_md = sha256
policy = policy_any
unique_subject = no
[ policy_any ]
commonName = supplied
[ req ]
distinguished_name = req_dn
prompt = no
[ req_dn ]
CN = expired.nms.lan
""")
    csr = os.path.join(ca_dir, "req.csr")
    subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key_out, "-out", csr, "-config", cnf], check=True, capture_output=True)
    subprocess.run(
        ["openssl", "ca", "-batch", "-selfsign", "-config", cnf, "-keyfile", key_out, "-in", csr, "-out", crt_out, "-startdate", "20200101000000Z", "-enddate", "20200102000000Z"],
        check=True, capture_output=True,
    )


def write_sim_service_runner(runner_path: str, state_dir: str, log_path: str, root_prefix: str, fail_on_action: str = "") -> None:
    """Simulated service/process harness invoked by install.sh via NMS_SERVICE_RUNNER.
    Actually spawns and terminates real OS child processes (sleep) tagged with backend SHA-256.
    """
    os.makedirs(state_dir, exist_ok=True)
    script = f"""#!/bin/sh
set -eu
SVC="$1"
ACT="$2"
BASE="$(basename "$SVC")"
STATE="{state_dir}/${{BASE}}.state"
PIDF="{state_dir}/${{BASE}}.pid"
BE_PID_LOG="{state_dir}/${{BASE}}.proc_history"
LOG="{log_path}"

if [ ! -f "$STATE" ]; then
  printf 'EN=0\\nRUN=0\\n' > "$STATE"
fi
. "$STATE"

BACKEND=""
if [ "$BASE" = "noc-apid" ]; then BACKEND="{root_prefix}/usr/libexec/noc-apid"; fi
if [ "$BASE" = "noc-helperd" ]; then BACKEND="{root_prefix}/usr/libexec/noc-helperd"; fi

SVC_HASH="$(sha256sum "$SVC" 2>/dev/null | awk '{{print $1}}')"
BE_HASH="$(sha256sum "$BACKEND" 2>/dev/null | awk '{{print $1}}')"
echo "${{BASE}}:${{ACT}}:svc=${{SVC_HASH}}:be=${{BE_HASH}}" >> "$LOG"

if [ -n "{fail_on_action}" ] && [ "$ACT" = "{fail_on_action}" ]; then
  echo "SIM_SVC_FORCED_FAIL:${{BASE}}:${{ACT}}" >&2
  exit 1
fi

stop_proc() {{
  if [ -f "$PIDF" ]; then
    _p="$(cat "$PIDF" 2>/dev/null || true)"
    if [ -n "$_p" ]; then
      kill "$_p" 2>/dev/null || true
      _w=0
      while kill -0 "$_p" 2>/dev/null && [ "$_w" -lt 20 ]; do
        sleep 0.05
        _w=$((_w + 1))
      done
    fi
    rm -f "$PIDF"
  fi
}}

case "$ACT" in
  enable)  EN=1 ;;
  disable) EN=0 ;;
  start|restart)
    stop_proc
    nohup sleep 60 >/dev/null 2>&1 &
    _np=$!
    echo "$_np" > "$PIDF"
    echo "${{_np}}:${{BE_HASH}}" >> "$BE_PID_LOG"
    RUN=1
    ;;
  stop)
    stop_proc
    RUN=0
    ;;
  enabled) [ "$EN" -eq 1 ] && exit 0 || exit 1 ;;
  running)
    if [ "$RUN" -eq 1 ] && [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF" 2>/dev/null || echo 0)" 2>/dev/null; then
      exit 0
    fi
    exit 1
    ;;
  *) exit 1 ;;
esac
printf 'EN=%s\\nRUN=%s\\n' "$EN" "$RUN" > "$STATE"
exit 0
"""
    open(runner_path, "w").write(script)
    os.chmod(runner_path, 0o755)


print("=== 1. Static Hygiene & Syntax Checks ===")
for rel in ("frontend/app.js", "frontend/nms-i18n.js", "frontend/noc-topology.js", "frontend/noc-search.js", "frontend/noc-tools.js", "frontend/netchart.js", "frontend/sw.js"):
    r = subprocess.run(["node", "--check", os.path.join(ROOT, rel)], capture_output=True, text=True)
    ok(f"node --check {rel}") if r.returncode == 0 else fail(f"node --check {rel}: {r.stderr.strip()}")

for rel in ("scripts/install.sh", "scripts/uninstall.sh", "init.d/noc-apid", "init.d/noc-helperd"):
    r = subprocess.run(["sh", "-n", os.path.join(ROOT, rel)], capture_output=True, text=True)
    ok(f"sh -n {rel}") if r.returncode == 0 else fail(f"sh -n {rel}: {r.stderr.strip()}")

for rel in ("frontend/manifest.json", "frontend/glossary_ar.json", "schemas/noc_schemas.json"):
    try:
        json.load(open(os.path.join(ROOT, rel), encoding="utf-8"))
        ok(f"json valid {rel}")
    except Exception as e:
        fail(f"json invalid {rel}: {e}")

print("=== 2. SEC-01 & Cryptographic TLS Validation Regression (incl. Runtime Expired Cert) ===")
apid_txt = open(os.path.join(ROOT, "backend/noc-apid"), encoding="utf-8").read()
init_apid_txt = open(os.path.join(ROOT, "init.d/noc-apid"), encoding="utf-8").read()
install_txt = open(os.path.join(ROOT, "scripts/install.sh"), encoding="utf-8").read()

if "getenv('NOC_TLS_ACTIVE')" not in apid_txt and "getenv('NOC_TLS_VERIFIED') == '1'" in apid_txt and "BIND_HOST == '127.0.0.1'" in apid_txt:
    ok("SEC-01: noc-apid enforces loopback + verified TLS + cert/key before Secure cookies")
else:
    fail("SEC-01: noc-apid TLS verification logic invalid")

if "return 1" in init_apid_txt and "refusing to expose unencrypted HTTP" in init_apid_txt and "px5g selfsigned -pem" in init_apid_txt:
    ok("SEC-01: init.d/noc-apid fails closed without TLS and requires PEM format")
else:
    fail("SEC-01: init.d/noc-apid missing fail-closed TLS or PEM check")

for mod in ("ucode-mod-uloop", "ucode-mod-digest", "ucode-mod-fs", "ucode-mod-ubus", "ucode-mod-uci", "ucode-mod-socket"):
    ok(f"INS-02: install.sh checks/includes {mod}") if mod in install_txt else fail(f"INS-02: install.sh missing {mod}")

INVALID_TLS_MODES = ("malformed_cert", "malformed_key", "mismatched_pair", "wrong_fingerprint", "expired_cert")
for mode in INVALID_TLS_MODES:
    with tempfile.TemporaryDirectory() as td_tls:
        etc_dir = os.path.join(td_tls, "etc/noc-console")
        os.makedirs(etc_dir, exist_ok=True)
        crt_p = os.path.join(etc_dir, "tls.crt")
        key_p = os.path.join(etc_dir, "tls.key")
        fp_p = os.path.join(etc_dir, "tls.fingerprint")

        if mode == "expired_cert":
            make_expired_cert_pair(td_tls, key_p, crt_p)
            fp_out = subprocess.check_output(["openssl", "x509", "-in", crt_p, "-noout", "-fingerprint", "-sha256"], text=True)
            open(fp_p, "w").write(fp_out)
        else:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key_p, "-out", crt_p, "-days", "30", "-subj", "/CN=test.lan"], check=True, capture_output=True)
            fp_out = subprocess.check_output(["openssl", "x509", "-in", crt_p, "-noout", "-fingerprint", "-sha256"], text=True)
            open(fp_p, "w").write(fp_out)
            if mode == "malformed_cert":
                open(crt_p, "w").write("-----BEGIN CERTIFICATE-----\nCORRUPT\n-----END CERTIFICATE-----\n")
            elif mode == "malformed_key":
                open(key_p, "w").write("-----BEGIN PRIVATE KEY-----\nCORRUPT\n-----END PRIVATE KEY-----\n")
            elif mode == "mismatched_pair":
                other_crt = os.path.join(td_tls, "other.crt")
                other_key = os.path.join(td_tls, "other.key")
                subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", other_key, "-out", other_crt, "-days", "30", "-subj", "/CN=other.lan"], check=True, capture_output=True)
                shutil.copyfile(other_crt, crt_p)
            elif mode == "wrong_fingerprint":
                open(fp_p, "w").write("sha256 Fingerprint=00:11:22:33\n")

        old_crt = open(crt_p, "rb").read()
        env_tls = os.environ.copy()
        env_tls["NMS_ROOT_PREFIX"] = td_tls
        env_tls["NMS_SKIP_SERVICE_START"] = "1"
        r_tls = subprocess.run(["sh", os.path.join(ROOT, "scripts/install.sh")], env=env_tls, capture_output=True, text=True)
        new_crt = open(crt_p, "rb").read()
        new_fp = open(fp_p).read()
        calc_fp = subprocess.check_output(["openssl", "x509", "-in", crt_p, "-noout", "-fingerprint", "-sha256"], text=True)
        chk_exp = subprocess.run(["openssl", "x509", "-in", crt_p, "-noout", "-checkend", "0"], capture_output=True)
        if r_tls.returncode == 0 and new_crt != old_crt and new_fp == calc_fp and chk_exp.returncode == 0:
            ok(f"SEC-01[{mode}]: invalid/expired TLS set detected and regenerated with valid matching SHA-256")
        else:
            fail(f"SEC-01[{mode}]: failed to detect/regenerate invalid TLS state")

print("=== 3. Multi-Point Transactional Rollback (Real Child Processes + Absent Services) ===")
# Cases: (fail_point, prev_exists, prev_en, prev_run, tls_pre)
FAIL_CASES = (
    ("after_backend", True, 0, 0, "none"),
    ("after_initd", True, 0, 0, "none"),
    ("after_frontend", True, 0, 0, "none"),
    ("during_tls_key", True, 0, 0, "cert_only"),
    ("during_tls_crt", True, 0, 0, "cert_and_key"),
    ("during_tls_fp", True, 0, 0, "none"),
    ("during_manifest", True, 0, 0, "none"),
    ("during_service", True, 0, 0, "none"),
    ("during_service", True, 1, 1, "none"),
    ("during_service", False, 0, 0, "none"),
)

for fp, prev_exists, prev_en, prev_run, tls_pre in FAIL_CASES:
    with tempfile.TemporaryDirectory() as td_tx:
        svc_state_dir = os.path.join(td_tx, "sim_svc_state")
        svc_log = os.path.join(td_tx, "sim_svc.log")
        runner_p = os.path.join(td_tx, "sim_service_runner.sh")
        write_sim_service_runner(runner_p, svc_state_dir, svc_log, td_tx)

        env_tx = os.environ.copy()
        env_tx["NMS_ROOT_PREFIX"] = td_tx
        env_tx["NMS_SKIP_SERVICE_START"] = "1"
        env_tx["NMS_SERVICE_RUNNER"] = runner_p
        env_tx["NMS_TEST_FAIL_POINT"] = fp

        etc_dir = os.path.join(td_tx, "etc/noc-console")
        os.makedirs(etc_dir, exist_ok=True)
        os.chmod(etc_dir, 0o750)

        passwd_p = os.path.join(td_tx, "etc/passwd")
        group_p = os.path.join(td_tx, "etc/group")
        orig_pw_bytes = b"root:x:0:0:root:/root:/bin/sh\n"
        orig_grp_bytes = b"root:x:0:\n"
        open(passwd_p, "wb").write(orig_pw_bytes)
        open(group_p, "wb").write(orig_grp_bytes)
        os.chmod(passwd_p, 0o644)
        os.chmod(group_p, 0o640)

        os.makedirs(os.path.join(td_tx, "www/pro"), exist_ok=True)
        orig_idx = os.path.join(td_tx, "www/pro/index.html")
        orig_idx_bytes = b"<html><body>USER_ORIGINAL_INDEX</body></html>\n"
        open(orig_idx, "wb").write(orig_idx_bytes)
        os.chmod(orig_idx, 0o600)

        orig_apid = os.path.join(td_tx, "usr/libexec/noc-apid")
        orig_h_init = os.path.join(td_tx, "etc/init.d/noc-helperd")
        orig_a_init = os.path.join(td_tx, "etc/init.d/noc-apid")
        orig_apid_bytes = b"#!/bin/sh\n# ORIG_BACKEND_APID\nexit 0\n"
        orig_h_bytes = b"#!/bin/sh\n# ORIG_HELPERD_INIT\n"
        orig_a_bytes = b"#!/bin/sh\n# ORIG_APID_INIT\n"
        orig_apid_hash = hashlib.sha256(orig_apid_bytes).hexdigest()
        orig_a_init_hash = hashlib.sha256(orig_a_bytes).hexdigest()

        if prev_exists:
            os.makedirs(os.path.join(td_tx, "usr/libexec"), exist_ok=True)
            open(orig_apid, "wb").write(orig_apid_bytes)
            os.chmod(orig_apid, 0o700)
            os.makedirs(os.path.join(td_tx, "etc/init.d"), exist_ok=True)
            open(orig_h_init, "wb").write(orig_h_bytes)
            open(orig_a_init, "wb").write(orig_a_bytes)
            os.chmod(orig_h_init, 0o755)
            os.chmod(orig_a_init, 0o750)
            for sname in ("noc-helperd", "noc-apid"):
                open(os.path.join(svc_state_dir, f"{sname}.state"), "w").write(f"EN={prev_en}\nRUN={prev_run}\n")
            if prev_run == 1:
                p_init = subprocess.Popen(["sleep", "60"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                open(os.path.join(svc_state_dir, "noc-apid.pid"), "w").write(f"{p_init.pid}\n")
                p_h = subprocess.Popen(["sleep", "60"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                open(os.path.join(svc_state_dir, "noc-helperd.pid"), "w").write(f"{p_h.pid}\n")

        orig_crt_bytes = b"-----BEGIN CERTIFICATE-----\nORIG_PARTIAL_CERT\n-----END CERTIFICATE-----\n"
        orig_key_bytes = b"-----BEGIN PRIVATE KEY-----\nORIG_PARTIAL_KEY\n-----END PRIVATE KEY-----\n"
        if tls_pre in ("cert_only", "cert_and_key"):
            open(os.path.join(etc_dir, "tls.crt"), "wb").write(orig_crt_bytes)
            os.chmod(os.path.join(etc_dir, "tls.crt"), 0o644)
        if tls_pre == "cert_and_key":
            open(os.path.join(etc_dir, "tls.key"), "wb").write(orig_key_bytes)
            os.chmod(os.path.join(etc_dir, "tls.key"), 0o600)

        try:
            r_tx = subprocess.run(["sh", os.path.join(ROOT, "scripts/install.sh")], env=env_tx, capture_output=True, text=True)

            files_ok = (
                r_tx.returncode != 0
                and open(orig_idx, "rb").read() == orig_idx_bytes and stat.S_IMODE(os.stat(orig_idx).st_mode) == 0o600
                and open(passwd_p, "rb").read() == orig_pw_bytes and stat.S_IMODE(os.stat(passwd_p).st_mode) == 0o644
                and open(group_p, "rb").read() == orig_grp_bytes and stat.S_IMODE(os.stat(group_p).st_mode) == 0o640
                and stat.S_IMODE(os.stat(etc_dir).st_mode) == 0o750
                and not os.path.exists(os.path.join(td_tx, "usr/libexec/noc-helperd"))
                and not os.path.exists(os.path.join(td_tx, "www/pro/app.js"))
                and not os.path.exists(os.path.join(etc_dir, "installed_files.manifest"))
                and not os.path.exists(os.path.join(etc_dir, "tls.fingerprint"))
            )
            if prev_exists:
                files_ok = files_ok and (
                    open(orig_apid, "rb").read() == orig_apid_bytes and stat.S_IMODE(os.stat(orig_apid).st_mode) == 0o700
                    and open(orig_h_init, "rb").read() == orig_h_bytes and stat.S_IMODE(os.stat(orig_h_init).st_mode) == 0o755
                    and open(orig_a_init, "rb").read() == orig_a_bytes and stat.S_IMODE(os.stat(orig_a_init).st_mode) == 0o750
                )
            else:
                files_ok = files_ok and not os.path.exists(orig_apid) and not os.path.exists(orig_h_init) and not os.path.exists(orig_a_init)

            if tls_pre == "none":
                tls_ok = not os.path.exists(os.path.join(etc_dir, "tls.crt")) and not os.path.exists(os.path.join(etc_dir, "tls.key"))
            elif tls_pre == "cert_only":
                tls_ok = open(os.path.join(etc_dir, "tls.crt"), "rb").read() == orig_crt_bytes and not os.path.exists(os.path.join(etc_dir, "tls.key"))
            else:
                tls_ok = open(os.path.join(etc_dir, "tls.crt"), "rb").read() == orig_crt_bytes and open(os.path.join(etc_dir, "tls.key"), "rb").read() == orig_key_bytes

            proc_ok = True
            if fp == "during_service":
                log_txt = open(svc_log).read()
                new_apid_hash = hashlib.sha256(open(os.path.join(ROOT, "backend/noc-apid"), "rb").read()).hexdigest()
                # Check real child processes spawned with new_apid_hash have EXITED
                hist_p = os.path.join(svc_state_dir, "noc-apid.proc_history")
                hist_lines = [l.strip().split(":") for l in open(hist_p).read().splitlines() if l.strip()] if os.path.isfile(hist_p) else []
                new_pids = [int(pid) for pid, bh in hist_lines if bh == new_apid_hash]
                all_new_dead = len(new_pids) >= 1 and all(not is_pid_alive(p) for p in new_pids)
                pid_file = os.path.join(svc_state_dir, "noc-apid.pid")
                if prev_exists and prev_run == 1:
                    cur_pid = int(open(pid_file).read().strip()) if os.path.isfile(pid_file) else -1
                    restored_alive = cur_pid > 0 and is_pid_alive(cur_pid) and any(int(pid) == cur_pid and bh == orig_apid_hash for pid, bh in hist_lines)
                    restored_inv = f"noc-apid:enable:svc={orig_a_init_hash}:be={orig_apid_hash}" in log_txt
                    proc_ok = all_new_dead and restored_alive and restored_inv
                else:
                    proc_ok = all_new_dead and not os.path.exists(pid_file) and not os.path.exists(os.path.join(svc_state_dir, "noc-helperd.pid"))

            if files_ok and tls_ok and proc_ok:
                ok(f"TX[{fp},exists={prev_exists},en={prev_en},run={prev_run},tls={tls_pre}]: byte-for-byte & real child-process rollback verified")
            else:
                fail(f"TX[{fp},exists={prev_exists},en={prev_en},run={prev_run},tls={tls_pre}]: failed (files={files_ok}, tls={tls_ok}, proc={proc_ok})")
        finally:
            for pf in ("noc-apid.pid", "noc-helperd.pid"):
                pp = os.path.join(svc_state_dir, pf)
                if os.path.isfile(pp):
                    kill_pid(int(open(pp).read().strip()))

print("=== 4. Deliberate Rollback Failure Detection (Backup + Service) ===")
with tempfile.TemporaryDirectory() as td_rbf:
    env_rbf = os.environ.copy()
    env_rbf["NMS_ROOT_PREFIX"] = td_rbf
    env_rbf["NMS_SKIP_SERVICE_START"] = "1"
    env_rbf["NMS_TEST_FAIL_POINT"] = "during_manifest"
    env_rbf["NMS_TEST_CORRUPT_BACKUP_MATCH"] = "/www/pro/index.html"
    os.makedirs(os.path.join(td_rbf, "www/pro"), exist_ok=True)
    open(os.path.join(td_rbf, "www/pro/index.html"), "w").write("ORIG\n")
    r_rbf = subprocess.run(["sh", os.path.join(ROOT, "scripts/install.sh")], env=env_rbf, capture_output=True, text=True)
    if r_rbf.returncode != 0 and "ROLLBACK ERROR: missing backup" in r_rbf.stderr and "ROLLBACK FAILED" in r_rbf.stderr:
        ok("ROLLBACK-INTEGRITY[backup]: missing backup detected and reported as ROLLBACK FAILED")
    else:
        fail("ROLLBACK-INTEGRITY[backup]: missing backup was not reported")

with tempfile.TemporaryDirectory() as td_srf:
    sdir = os.path.join(td_srf, "sim_svc_state")
    slog = os.path.join(td_srf, "sim_svc.log")
    runner_fail = os.path.join(td_srf, "runner_fail_disable.sh")
    write_sim_service_runner(runner_fail, sdir, slog, td_srf, fail_on_action="disable")
    os.makedirs(os.path.join(td_srf, "etc/init.d"), exist_ok=True)
    open(os.path.join(td_srf, "etc/init.d/noc-helperd"), "w").write("#!/bin/sh\n")
    open(os.path.join(td_srf, "etc/init.d/noc-apid"), "w").write("#!/bin/sh\n")
    env_srf = os.environ.copy()
    env_srf["NMS_ROOT_PREFIX"] = td_srf
    env_srf["NMS_SKIP_SERVICE_START"] = "1"
    env_srf["NMS_SERVICE_RUNNER"] = runner_fail
    env_srf["NMS_TEST_FAIL_POINT"] = "during_service"
    try:
        r_srf = subprocess.run(["sh", os.path.join(ROOT, "scripts/install.sh")], env=env_srf, capture_output=True, text=True)
        if r_srf.returncode != 0 and "ROLLBACK ERROR: failed to disable" in r_srf.stderr and "ROLLBACK FAILED" in r_srf.stderr:
            ok("ROLLBACK-INTEGRITY[service]: service restoration failure detected and reported as ROLLBACK FAILED")
        else:
            fail(f"ROLLBACK-INTEGRITY[service]: service rollback failure not reported (rc={r_srf.returncode})")
    finally:
        for pf in ("noc-apid.pid", "noc-helperd.pid"):
            pp = os.path.join(sdir, pf)
            if os.path.isfile(pp):
                kill_pid(int(open(pp).read().strip()))

print("=== 5. Simulated-procd TLS Topology & Collision Uninstall ===")
with tempfile.TemporaryDirectory() as td:
    env = os.environ.copy()
    env["NMS_ROOT_PREFIX"] = td
    env["NMS_SKIP_SERVICE_START"] = "1"
    env["NMS_SKIP_SERVICE_STOP"] = "1"

    etc_dir = os.path.join(td, "etc/noc-console")
    os.makedirs(etc_dir, exist_ok=True)
    os.chmod(etc_dir, 0o750)
    os.makedirs(os.path.join(td, "usr/libexec"), exist_ok=True)
    col_apid = os.path.join(td, "usr/libexec/noc-apid")
    col_apid_bytes = b"USER_APID_BIN\n"
    open(col_apid, "wb").write(col_apid_bytes)
    os.chmod(col_apid, 0o700)

    os.makedirs(os.path.join(td, "etc/init.d"), exist_ok=True)
    col_init = os.path.join(td, "etc/init.d/noc-apid")
    col_init_bytes = b"USER_INIT_SCRIPT\n"
    open(col_init, "wb").write(col_init_bytes)
    os.chmod(col_init, 0o750)

    web_pro = os.path.join(td, "www/pro")
    os.makedirs(web_pro, exist_ok=True)
    col_index = os.path.join(web_pro, "index.html")
    col_index_bytes = b"USER_CUSTOM_INDEX_KEEP\n"
    open(col_index, "wb").write(col_index_bytes)
    os.chmod(col_index, 0o600)

    r_ins = subprocess.run(["sh", os.path.join(ROOT, "scripts/install.sh")], env=env, capture_output=True, text=True)
    ok("INS-02: sandboxed install.sh exited 0") if r_ins.returncode == 0 else fail(f"INS-02: install.sh failed: {r_ins.stderr}")

    cert_p = os.path.join(etc_dir, "tls.crt")
    fp_p = os.path.join(etc_dir, "tls.fingerprint")
    http_p = free_port()
    https_p = free_port()
    lan_sim_ip = "127.0.0.2"
    procd_log = os.path.join(td, "procd_capture.txt")
    harness_sh = f"""#!/bin/sh
uci() {{ echo "{lan_sim_ip}"; }}
logger() {{ :; }}
procd_open_instance() {{ echo "INSTANCE=$1" >> "{procd_log}"; }}
procd_set_param() {{ echo "PARAM=$*" >> "{procd_log}"; }}
procd_close_instance() {{ echo "END_INSTANCE" >> "{procd_log}"; }}
sed 's|/etc/noc-console|{etc_dir}|g; s|/tmp/noc-console|{td}/tmp/noc-console|g; s|HTTPS_PORT=8743|HTTPS_PORT={https_p}|g; s|HTTP_PORT=8780|HTTP_PORT={http_p}|g' "{ROOT}/init.d/noc-apid" > "{td}/init_noc_apid_test"
. "{td}/init_noc_apid_test"
start_service
"""
    subprocess.run(["sh", "-c", harness_sh], capture_output=True, text=True)
    procd_txt = open(procd_log).read() if os.path.isfile(procd_log) else ""
    socat_args = next((l[len("PARAM=command "):].split() for l in procd_txt.splitlines() if l.startswith("PARAM=command /usr/bin/socat ")), None)

    if socat_args and shutil.which("socat"):
        class LoopbackHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"NMS_SIM_PROCD_TLS_OK")
            def log_message(self, *args):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", http_p), LoopbackHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        socat_proc = subprocess.Popen(socat_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            connected = False
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            for _ in range(25):
                try:
                    with socket.create_connection((lan_sim_ip, https_p), timeout=1.0) as raw_s:
                        with ctx.wrap_socket(raw_s, server_hostname="nms.lan") as tls_s:
                            der = tls_s.getpeercert(binary_form=True)
                            sha256_hex = hashlib.sha256(der).hexdigest().upper()
                            fp_text = open(fp_p).read().replace(":", "").upper()
                            tls_s.sendall(b"GET / HTTP/1.1\r\nHost: nms.lan\r\nConnection: close\r\n\r\n")
                            if b"NMS_SIM_PROCD_TLS_OK" in tls_s.recv(4096) and sha256_hex in fp_text:
                                ok(f"SEC-01 (simulated procd): TLS handshake + HTTP via socat on {lan_sim_ip}:{https_p} -> 127.0.0.1:{http_p} passed")
                                connected = True
                                break
                except OSError:
                    time.sleep(0.1)
            if not connected:
                fail("SEC-01 (simulated procd): TLS connection failed")
            try:
                with socket.create_connection((lan_sim_ip, http_p), timeout=0.5):
                    fail(f"SEC-01: unencrypted HTTP reachable on {lan_sim_ip}:{http_p}")
            except OSError:
                ok(f"SEC-01: unencrypted HTTP refused on LAN IP {lan_sim_ip}:{http_p} (loopback-only confirmed)")
        finally:
            socat_proc.terminate()
            socat_proc.wait(timeout=3)
            srv.shutdown()
            srv.server_close()

    r_un = subprocess.run(["sh", os.path.join(ROOT, "scripts/uninstall.sh")], env=env, capture_output=True, text=True)
    if (r_un.returncode == 0
            and open(col_apid, "rb").read() == col_apid_bytes and stat.S_IMODE(os.stat(col_apid).st_mode) == 0o700
            and open(col_init, "rb").read() == col_init_bytes and stat.S_IMODE(os.stat(col_init).st_mode) == 0o750
            and open(col_index, "rb").read() == col_index_bytes and stat.S_IMODE(os.stat(col_index).st_mode) == 0o600):
        ok("INS-03: byte-for-byte restoration of backend, init.d, and frontend collisions")
    else:
        fail("INS-03: byte-for-byte collision restoration failed")

print(f"\n=== SUMMARY: {len(passes)} passed, {len(failures)} failed ===")
sys.exit(1 if failures else 0)
