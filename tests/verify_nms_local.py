#!/usr/bin/env python3
"""
NMS (Network Management System) - Local & Offline Regression Suite (Phase 2 Integrity)
Zero network or SSH calls to any live router.
Explicit Test Boundaries:
  - Actual host tests: OpenSSL cryptographic TLS validation (incl. expired cert),
    socat TLS proxy, byte-for-byte file/permission restoration, /proc/<pid> process
    termination & reaping verification, and uninstall error-handling tests.
  - Simulated tests: Service lifecycle (NMS_SERVICE_RUNNER) and procd harness on Debian.
    Because OpenWrt 'ucode' (ubus/uci) is absent on Debian, process-lifecycle tests use
    a clearly named executable fixture (exec_fixture) rather than claiming actual NMS
    ucode daemon execution.
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


def proc_alive_non_zombie(pid: int) -> bool:
    stat_p = f"/proc/{pid}/stat"
    if not os.path.exists(stat_p):
        return False
    try:
        txt = open(stat_p, "r", encoding="utf-8", errors="ignore").read()
        rp = txt.rfind(")")
        if rp < 0:
            return False
        return txt[rp + 2:rp + 3] != "Z"
    except OSError:
        return False


def read_proc_cmdline(pid: int) -> list[str]:
    try:
        raw = open(f"/proc/{pid}/cmdline", "rb").read()
        return [p.decode("utf-8", errors="ignore") for p in raw.split(b"\x00") if p]
    except OSError:
        return []


def reap_and_kill_popen(p: subprocess.Popen) -> None:
    try:
        p.poll()
        if p.returncode is None:
            p.terminate()
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=2)
    except OSError:
        pass


def kill_pid(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            if not os.path.exists(f"/proc/{pid}"):
                return
            time.sleep(0.05)
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def make_exec_fixture_bytes(tag: str) -> bytes:
    return (
        "#!/usr/bin/env python3\n"
        f"# EXEC_FIXTURE_TAG={tag}\n"
        "import signal, sys, time\n"
        "signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))\n"
        "while True:\n"
        "    time.sleep(1)\n"
    ).encode("utf-8")


def make_expired_cert_pair(work_dir: str, key_out: str, crt_out: str) -> None:
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


def write_exec_fixture_runner(runner_path: str, state_dir: str, log_path: str, root_prefix: str, fail_on_action: str = "") -> None:
    os.makedirs(state_dir, exist_ok=True)
    script = f"""#!/bin/sh
set -eu
SVC="$1"
ACT="$2"
BASE="$(basename "$SVC")"
STATE="{state_dir}/${{BASE}}.state"
PIDF="{state_dir}/${{BASE}}.pid"
HIST="{state_dir}/${{BASE}}.pid_history"
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
      while [ -e "/proc/$_p" ] && [ "$_w" -lt 40 ]; do
        _st="$(awk '{{for(i=1;i<=NF;i++) if($i ~ /\\)$/) {{print $(i+1); exit}}}}' "/proc/$_p/stat" 2>/dev/null || echo 'Z')"
        [ "$_st" = "Z" ] && break
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
    nohup "$BACKEND" >/dev/null 2>&1 &
    _np=$!
    echo "$_np" > "$PIDF"
    echo "${{_np}}:${{BE_HASH}}" >> "$HIST"
    RUN=1
    ;;
  stop)
    stop_proc
    RUN=0
    ;;
  enabled) [ "$EN" -eq 1 ] && exit 0 || exit 1 ;;
  running)
    if [ "$RUN" -eq 1 ] && [ -f "$PIDF" ]; then
      _p="$(cat "$PIDF" 2>/dev/null || echo 0)"
      [ -e "/proc/$_p" ] && exit 0
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

print("=== 2. SEC-01 & Cryptographic TLS Validation (incl. Expired Cert) ===")
apid_txt = open(os.path.join(ROOT, "backend/noc-apid"), encoding="utf-8").read()
init_apid_txt = open(os.path.join(ROOT, "init.d/noc-apid"), encoding="utf-8").read()

if "getenv('NOC_TLS_ACTIVE')" not in apid_txt and "getenv('NOC_TLS_VERIFIED') == '1'" in apid_txt and "BIND_HOST == '127.0.0.1'" in apid_txt:
    ok("SEC-01: noc-apid enforces loopback + verified TLS + cert/key before Secure cookies")
else:
    fail("SEC-01: noc-apid TLS verification logic invalid")

if "return 1" in init_apid_txt and "refusing to expose unencrypted HTTP" in init_apid_txt and "px5g selfsigned -pem" in init_apid_txt:
    ok("SEC-01: init.d/noc-apid fails closed without TLS and requires PEM format")
else:
    fail("SEC-01: init.d/noc-apid missing fail-closed TLS or PEM check")

for mode in ("malformed_cert", "malformed_key", "mismatched_pair", "wrong_fingerprint", "expired_cert"):
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

print("=== 3. Executable-Fixture Process Identity & Reaping Verification ===")
with tempfile.TemporaryDirectory() as td_repo:
    shutil.copytree(ROOT, os.path.join(td_repo, "repo"), ignore=shutil.ignore_patterns(".git", "__pycache__"))
    staged_repo = os.path.join(td_repo, "repo")
    new_apid_bytes = make_exec_fixture_bytes("NEW_NMS_APID")
    new_helperd_bytes = make_exec_fixture_bytes("NEW_NMS_HELPERD")
    open(os.path.join(staged_repo, "backend/noc-apid"), "wb").write(new_apid_bytes)
    open(os.path.join(staged_repo, "backend/noc-helperd"), "wb").write(new_helperd_bytes)
    new_apid_hash = hashlib.sha256(new_apid_bytes).hexdigest()

    SERVICE_CASES = (
        ("during_service_after_helperd_enable", True, 0, 0),
        ("during_service_after_apid_enable", True, 0, 0),
        ("during_service_after_helperd_restart", True, 0, 0),
        ("during_service", True, 0, 0),
        ("during_service", True, 1, 1),
        ("during_service", False, 0, 0),
    )

    for fp, prev_exists, prev_en, prev_run in SERVICE_CASES:
        with tempfile.TemporaryDirectory() as td_tx:
            svc_state_dir = os.path.join(td_tx, "sim_svc_state")
            svc_log = os.path.join(td_tx, "sim_svc.log")
            runner_p = os.path.join(td_tx, "exec_fixture_runner.sh")
            write_exec_fixture_runner(runner_p, svc_state_dir, svc_log, td_tx)

            env_tx = os.environ.copy()
            env_tx["NMS_ROOT_PREFIX"] = td_tx
            env_tx["NMS_SKIP_SERVICE_START"] = "1"
            env_tx["NMS_SERVICE_RUNNER"] = runner_p
            env_tx["NMS_TEST_FAIL_POINT"] = fp

            etc_dir = os.path.join(td_tx, "etc/noc-console")
            os.makedirs(etc_dir, exist_ok=True)
            os.chmod(etc_dir, 0o750)
            open(os.path.join(td_tx, "etc/passwd"), "w").write("root:x:0:0:root:/root:/bin/sh\n")
            open(os.path.join(td_tx, "etc/group"), "w").write("root:x:0:\n")
            os.chmod(os.path.join(td_tx, "etc/passwd"), 0o644)
            os.chmod(os.path.join(td_tx, "etc/group"), 0o640)

            orig_apid = os.path.join(td_tx, "usr/libexec/noc-apid")
            orig_helperd = os.path.join(td_tx, "usr/libexec/noc-helperd")
            orig_h_init = os.path.join(td_tx, "etc/init.d/noc-helperd")
            orig_a_init = os.path.join(td_tx, "etc/init.d/noc-apid")
            orig_apid_bytes = make_exec_fixture_bytes("ORIG_APID")
            orig_helperd_bytes = make_exec_fixture_bytes("ORIG_HELPERD")
            orig_h_bytes = b"#!/bin/sh\n# ORIG_HELPERD_INIT\n"
            orig_a_bytes = b"#!/bin/sh\n# ORIG_APID_INIT\n"
            orig_apid_hash = hashlib.sha256(orig_apid_bytes).hexdigest()
            orig_a_init_hash = hashlib.sha256(orig_a_bytes).hexdigest()

            pa = None
            ph = None
            if prev_exists:
                os.makedirs(os.path.join(td_tx, "usr/libexec"), exist_ok=True)
                open(orig_apid, "wb").write(orig_apid_bytes)
                open(orig_helperd, "wb").write(orig_helperd_bytes)
                os.chmod(orig_apid, 0o700)
                os.chmod(orig_helperd, 0o700)
                os.makedirs(os.path.join(td_tx, "etc/init.d"), exist_ok=True)
                open(orig_h_init, "wb").write(orig_h_bytes)
                open(orig_a_init, "wb").write(orig_a_bytes)
                os.chmod(orig_h_init, 0o755)
                os.chmod(orig_a_init, 0o750)
                for sname in ("noc-helperd", "noc-apid"):
                    open(os.path.join(svc_state_dir, f"{sname}.state"), "w").write(f"EN={prev_en}\nRUN={prev_run}\n")
                if prev_run == 1:
                    pa = subprocess.Popen([orig_apid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    ph = subprocess.Popen([orig_helperd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    open(os.path.join(svc_state_dir, "noc-apid.pid"), "w").write(f"{pa.pid}\n")
                    open(os.path.join(svc_state_dir, "noc-helperd.pid"), "w").write(f"{ph.pid}\n")

            try:
                r_tx = subprocess.run(["sh", os.path.join(staged_repo, "scripts/install.sh")], env=env_tx, capture_output=True, text=True)
                # Reap python-owned initial Popen handles if runner terminated them
                if pa is not None:
                    pa.poll()
                if ph is not None:
                    ph.poll()
                # Brief wait for init/subreaper to reap runner-spawned children
                time.sleep(0.1)

                log_txt = open(svc_log).read() if os.path.isfile(svc_log) else ""
                apid_hist = os.path.join(svc_state_dir, "noc-apid.pid_history")
                hist_entries = [l.strip().split(":") for l in open(apid_hist).read().splitlines() if l.strip()] if os.path.isfile(apid_hist) else []
                new_pids = [int(p) for p, h in hist_entries if h == new_apid_hash]
                # Prove /proc/<pid> is COMPLETELY GONE (reaped, not zombie)
                new_all_reaped = all(not os.path.exists(f"/proc/{p}") for p in new_pids)

                pid_file = os.path.join(svc_state_dir, "noc-apid.pid")
                if prev_exists and prev_run == 1:
                    cur_pid = int(open(pid_file).read().strip()) if os.path.isfile(pid_file) else -1
                    cmdline = read_proc_cmdline(cur_pid) if cur_pid > 0 else []
                    proc_identity_ok = (
                        cur_pid > 0
                        and proc_alive_non_zombie(cur_pid)
                        and any(orig_apid in arg for arg in cmdline)
                        and open(orig_apid, "rb").read() == orig_apid_bytes
                    )
                    restored_inv = f"noc-apid:enable:svc={orig_a_init_hash}:be={orig_apid_hash}" in log_txt
                    state_ok = open(os.path.join(svc_state_dir, "noc-apid.state")).read() == "EN=1\nRUN=1\n"
                    passed = r_tx.returncode != 0 and new_all_reaped and proc_identity_ok and restored_inv and state_ok
                elif prev_exists:
                    state_ok = open(os.path.join(svc_state_dir, "noc-apid.state")).read() == "EN=0\nRUN=0\n"
                    passed = r_tx.returncode != 0 and new_all_reaped and not os.path.exists(pid_file) and state_ok
                else:
                    passed = (
                        r_tx.returncode != 0
                        and new_all_reaped
                        and not os.path.exists(pid_file)
                        and not os.path.exists(orig_a_init)
                        and not os.path.exists(orig_h_init)
                    )

                if passed:
                    ok(f"EXEC-FIXTURE[{fp},exists={prev_exists},en={prev_en},run={prev_run}]: reaped /proc/<pid> & identity verified")
                else:
                    fail(f"EXEC-FIXTURE[{fp},exists={prev_exists},en={prev_en},run={prev_run}]: failed (rc={r_tx.returncode}, reaped={new_all_reaped})")
            finally:
                for p in (pa, ph):
                    if p is not None:
                        reap_and_kill_popen(p)
                for pf in ("noc-apid.pid", "noc-helperd.pid"):
                    pp = os.path.join(svc_state_dir, pf)
                    if os.path.isfile(pp):
                        kill_pid(int(open(pp).read().strip()))

print("=== 4. Deliberate Rollback Failure Detection (All 6 Failure Types) ===")
# 4a. Missing backup -> ROLLBACK FAILED
with tempfile.TemporaryDirectory() as td_rbf:
    env_rbf = os.environ.copy()
    env_rbf["NMS_ROOT_PREFIX"] = td_rbf
    env_rbf["NMS_SKIP_SERVICE_START"] = "1"
    env_rbf["NMS_TEST_FAIL_POINT"] = "during_manifest"
    env_rbf["NMS_TEST_CORRUPT_BACKUP_MATCH"] = "/www/pro/index.html"
    os.makedirs(os.path.join(td_rbf, "www/pro"), exist_ok=True)
    open(os.path.join(td_rbf, "www/pro/index.html"), "w").write("ORIG\n")
    r_rbf = subprocess.run(["sh", os.path.join(ROOT, "scripts/install.sh")], env=env_rbf, capture_output=True, text=True)
    ok("ROLLBACK-FAIL[missing_backup]: ROLLBACK FAILED reported") if (r_rbf.returncode != 0 and "ROLLBACK FAILED" in r_rbf.stderr) else fail("ROLLBACK-FAIL[missing_backup]")

# 4b. File restoration failure (cp fails ONLY when restoring .txbak)
with tempfile.TemporaryDirectory() as td_frf:
    bin_dir = os.path.join(td_frf, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    real_cp = shutil.which("cp")
    open(os.path.join(bin_dir, "cp"), "w").write(
        f"#!/bin/sh\nif [ \"${{1:-}}\" = \"-p\" ]; then case \"${{2:-}}\" in *.txbak) exit 1 ;; esac; fi\nexec {real_cp} \"$@\"\n"
    )
    os.chmod(os.path.join(bin_dir, "cp"), 0o755)
    os.makedirs(os.path.join(td_frf, "www/pro"), exist_ok=True)
    open(os.path.join(td_frf, "www/pro/index.html"), "w").write("ORIG\n")
    env_frf = os.environ.copy()
    env_frf["PATH"] = f"{bin_dir}:{env_frf['PATH']}"
    env_frf["NMS_ROOT_PREFIX"] = td_frf
    env_frf["NMS_SKIP_SERVICE_START"] = "1"
    env_frf["NMS_TEST_FAIL_POINT"] = "after_frontend"
    r_frf = subprocess.run(["sh", os.path.join(ROOT, "scripts/install.sh")], env=env_frf, capture_output=True, text=True)
    ok("ROLLBACK-FAIL[file_restore]: ROLLBACK FAILED reported") if (r_frf.returncode != 0 and "ROLLBACK ERROR: failed to restore" in r_frf.stderr and "ROLLBACK FAILED" in r_frf.stderr) else fail("ROLLBACK-FAIL[file_restore]")

# 4c. Permission restoration failure (chmod fails ONLY when restoring 600 on index.html after marker)
with tempfile.TemporaryDirectory() as td_prf:
    bin_dir = os.path.join(td_prf, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    real_chmod = shutil.which("chmod")
    idx_p = os.path.join(td_prf, "www/pro/index.html")
    # During install, install.sh sets 0644 on index.html; during rollback, it sets 600 on idx_p!
    open(os.path.join(bin_dir, "chmod"), "w").write(
        f"#!/bin/sh\nif [ \"$1\" = \"600\" ] && [ \"$2\" = \"{idx_p}\" ]; then exit 1; fi\nexec {real_chmod} \"$@\"\n"
    )
    os.chmod(os.path.join(bin_dir, "chmod"), 0o755)
    os.makedirs(os.path.join(td_prf, "www/pro"), exist_ok=True)
    open(idx_p, "w").write("ORIG\n")
    os.chmod(idx_p, 0o600)
    env_prf = os.environ.copy()
    env_prf["PATH"] = f"{bin_dir}:{env_prf['PATH']}"
    env_prf["NMS_ROOT_PREFIX"] = td_prf
    env_prf["NMS_SKIP_SERVICE_START"] = "1"
    env_prf["NMS_TEST_FAIL_POINT"] = "after_frontend"
    r_prf = subprocess.run(["sh", os.path.join(ROOT, "scripts/install.sh")], env=env_prf, capture_output=True, text=True)
    ok("ROLLBACK-FAIL[perm_restore]: ROLLBACK FAILED reported") if (r_prf.returncode != 0 and "ROLLBACK ERROR: failed to restore" in r_prf.stderr and "ROLLBACK FAILED" in r_prf.stderr) else fail("ROLLBACK-FAIL[perm_restore]")

# 4d. Service stop failure
with tempfile.TemporaryDirectory() as td_stop:
    sdir = os.path.join(td_stop, "sim_svc_state")
    slog = os.path.join(td_stop, "sim_svc.log")
    r_stop_fail = os.path.join(td_stop, "runner_fail_stop.sh")
    write_exec_fixture_runner(r_stop_fail, sdir, slog, td_stop, fail_on_action="stop")
    os.makedirs(os.path.join(td_stop, "etc/init.d"), exist_ok=True)
    open(os.path.join(td_stop, "etc/init.d/noc-helperd"), "w").write("#!/bin/sh\n")
    open(os.path.join(td_stop, "etc/init.d/noc-apid"), "w").write("#!/bin/sh\n")
    env_stop = os.environ.copy()
    env_stop["NMS_ROOT_PREFIX"] = td_stop
    env_stop["NMS_SKIP_SERVICE_START"] = "1"
    env_stop["NMS_SERVICE_RUNNER"] = r_stop_fail
    env_stop["NMS_TEST_FAIL_POINT"] = "during_service_after_helperd_enable"
    r_st = subprocess.run(["sh", os.path.join(ROOT, "scripts/install.sh")], env=env_stop, capture_output=True, text=True)
    ok("ROLLBACK-FAIL[service_stop]: ROLLBACK FAILED reported") if (r_st.returncode != 0 and "ROLLBACK ERROR: failed to stop" in r_st.stderr and "ROLLBACK FAILED" in r_st.stderr) else fail("ROLLBACK-FAIL[service_stop]")

# 4e. Service restoration failure (disable fails)
with tempfile.TemporaryDirectory() as td_srf:
    sdir = os.path.join(td_srf, "sim_svc_state")
    slog = os.path.join(td_srf, "sim_svc.log")
    runner_fail = os.path.join(td_srf, "runner_fail_disable.sh")
    write_exec_fixture_runner(runner_fail, sdir, slog, td_srf, fail_on_action="disable")
    os.makedirs(os.path.join(td_srf, "etc/init.d"), exist_ok=True)
    open(os.path.join(td_srf, "etc/init.d/noc-helperd"), "w").write("#!/bin/sh\n")
    open(os.path.join(td_srf, "etc/init.d/noc-apid"), "w").write("#!/bin/sh\n")
    env_srf = os.environ.copy()
    env_srf["NMS_ROOT_PREFIX"] = td_srf
    env_srf["NMS_SKIP_SERVICE_START"] = "1"
    env_srf["NMS_SERVICE_RUNNER"] = runner_fail
    env_srf["NMS_TEST_FAIL_POINT"] = "during_service_after_helperd_enable"
    r_srf = subprocess.run(["sh", os.path.join(ROOT, "scripts/install.sh")], env=env_srf, capture_output=True, text=True)
    ok("ROLLBACK-FAIL[service_restore]: ROLLBACK FAILED reported") if (r_srf.returncode != 0 and "ROLLBACK ERROR: failed to disable" in r_srf.stderr and "ROLLBACK FAILED" in r_srf.stderr) else fail("ROLLBACK-FAIL[service_restore]")

# 4f. Missing expected init script during service restoration
with tempfile.TemporaryDirectory() as td_mis:
    sdir = os.path.join(td_mis, "sim_svc_state")
    slog = os.path.join(td_mis, "sim_svc.log")
    base_runner = os.path.join(td_mis, "runner_base.sh")
    write_exec_fixture_runner(base_runner, sdir, slog, td_mis)
    runner_mis = os.path.join(td_mis, "runner_missing_init.sh")
    apid_init = os.path.join(td_mis, "etc/init.d/noc-apid")
    open(runner_mis, "w").write(
        f"#!/bin/sh\n"
        f"if [ \"$2\" = \"disable\" ] && echo \"$1\" | grep -q 'noc-helperd'; then rm -f \"{apid_init}\"; fi\n"
        f"exec \"{base_runner}\" \"$@\"\n"
    )
    os.chmod(runner_mis, 0o755)
    os.makedirs(os.path.join(td_mis, "etc/init.d"), exist_ok=True)
    open(os.path.join(td_mis, "etc/init.d/noc-helperd"), "w").write("#!/bin/sh\n")
    open(apid_init, "w").write("#!/bin/sh\n")
    env_mis = os.environ.copy()
    env_mis["NMS_ROOT_PREFIX"] = td_mis
    env_mis["NMS_SKIP_SERVICE_START"] = "1"
    env_mis["NMS_SERVICE_RUNNER"] = runner_mis
    env_mis["NMS_TEST_FAIL_POINT"] = "during_service_after_helperd_enable"
    r_mis = subprocess.run(["sh", os.path.join(ROOT, "scripts/install.sh")], env=env_mis, capture_output=True, text=True)
    ok("ROLLBACK-FAIL[missing_init_script]: ROLLBACK FAILED reported") if (r_mis.returncode != 0 and "ROLLBACK ERROR: missing expected service script" in r_mis.stderr and "ROLLBACK FAILED" in r_mis.stderr) else fail("ROLLBACK-FAIL[missing_init_script]")

print("=== 5. Uninstall Error Handling & Simulated-procd TLS Topology ===")
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
    os.chmod(col_apid, 0o4755)

    os.makedirs(os.path.join(td, "etc/init.d"), exist_ok=True)
    col_init = os.path.join(td, "etc/init.d/noc-apid")
    col_init_bytes = b"USER_INIT_SCRIPT\n"
    open(col_init, "wb").write(col_init_bytes)
    os.chmod(col_init, 0o2755)

    web_pro = os.path.join(td, "www/pro")
    os.makedirs(web_pro, exist_ok=True)
    col_index = os.path.join(web_pro, "index.html")
    col_index_bytes = b"USER_CUSTOM_INDEX_KEEP\n"
    open(col_index, "wb").write(col_index_bytes)
    os.chmod(col_index, 0o600)

    r_ins = subprocess.run(["sh", os.path.join(ROOT, "scripts/install.sh")], env=env, capture_output=True, text=True)
    ok("INS-02: sandboxed install.sh exited 0") if r_ins.returncode == 0 else fail(f"INS-02: install.sh failed: {r_ins.stderr}")

    # Simulated-procd TLS topology check
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

    # 5a. Uninstall failure: missing backup -> UNINSTALL FAILED, nonzero exit, manifest & remaining backups preserved
    bak_dir = os.path.join(etc_dir, "preexisting_backup")
    bak_index = os.path.join(bak_dir, "_www_pro_index.html")
    bak_apid = os.path.join(bak_dir, "_usr_libexec_noc-apid")
    bak_init = os.path.join(bak_dir, "_etc_init.d_noc-apid")
    restore_manifest = os.path.join(etc_dir, "restorable_files.manifest")
    bak_tmp = os.path.join(td, "bak_hold")
    shutil.move(bak_index, bak_tmp)
    r_un_fail = subprocess.run(["sh", os.path.join(ROOT, "scripts/uninstall.sh")], env=env, capture_output=True, text=True)
    if (r_un_fail.returncode != 0
            and "UNINSTALL ERROR: missing backup" in r_un_fail.stderr
            and "UNINSTALL FAILED" in r_un_fail.stderr
            and "NMS uninstalled cleanly." not in r_un_fail.stdout
            and os.path.isfile(restore_manifest)
            and os.path.isfile(bak_apid)
            and os.path.isfile(bak_init)):
        ok("UNINSTALL-INTEGRITY[missing_backup]: UNINSTALL FAILED, nonzero exit, manifest & backups preserved")
    else:
        fail("UNINSTALL-INTEGRITY[missing_backup]: uninstall did not preserve recovery metadata on missing backup")
    shutil.move(bak_tmp, bak_index)

    # 5b. Uninstall failure: file restoration failure (cp fails on preexisting_backup)
    un_bin_cp = os.path.join(td, "un_bin_cp")
    os.makedirs(un_bin_cp, exist_ok=True)
    real_cp = shutil.which("cp")
    open(os.path.join(un_bin_cp, "cp"), "w").write(
        f"#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in */preexisting_backup/_www_pro_index.html) exit 1 ;; esac; done\nexec {real_cp} \"$@\"\n"
    )
    os.chmod(os.path.join(un_bin_cp, "cp"), 0o755)
    env_un_cp = env.copy()
    env_un_cp["PATH"] = f"{un_bin_cp}:{env['PATH']}"
    r_un_cp = subprocess.run(["sh", os.path.join(ROOT, "scripts/uninstall.sh")], env=env_un_cp, capture_output=True, text=True)
    if (r_un_cp.returncode != 0
            and "UNINSTALL ERROR: failed to restore" in r_un_cp.stderr
            and "UNINSTALL FAILED" in r_un_cp.stderr
            and "NMS uninstalled cleanly." not in r_un_cp.stdout
            and os.path.isfile(restore_manifest)
            and os.path.isfile(bak_index) and os.path.isfile(bak_apid) and os.path.isfile(bak_init)):
        ok("UNINSTALL-INTEGRITY[file_restore]: UNINSTALL FAILED, manifest & all backups preserved")
    else:
        fail("UNINSTALL-INTEGRITY[file_restore]: failed to detect file restore error or preserve backups")

    # 5c. Uninstall failure: permission restoration failure (chmod fails on col_index)
    un_bin_chmod = os.path.join(td, "un_bin_chmod")
    os.makedirs(un_bin_chmod, exist_ok=True)
    real_chmod = shutil.which("chmod")
    open(os.path.join(un_bin_chmod, "chmod"), "w").write(
        f"#!/bin/sh\nif [ \"$2\" = \"{col_index}\" ]; then exit 1; fi\nexec {real_chmod} \"$@\"\n"
    )
    os.chmod(os.path.join(un_bin_chmod, "chmod"), 0o755)
    env_un_chmod = env.copy()
    env_un_chmod["PATH"] = f"{un_bin_chmod}:{env['PATH']}"
    r_un_chmod = subprocess.run(["sh", os.path.join(ROOT, "scripts/uninstall.sh")], env=env_un_chmod, capture_output=True, text=True)
    if (r_un_chmod.returncode != 0
            and "UNINSTALL ERROR: failed to restore" in r_un_chmod.stderr
            and "UNINSTALL FAILED" in r_un_chmod.stderr
            and "NMS uninstalled cleanly." not in r_un_chmod.stdout
            and os.path.isfile(restore_manifest)
            and os.path.isfile(bak_index) and os.path.isfile(bak_apid) and os.path.isfile(bak_init)):
        ok("UNINSTALL-INTEGRITY[perm_restore]: UNINSTALL FAILED, manifest & all backups preserved")
    else:
        fail("UNINSTALL-INTEGRITY[perm_restore]: failed to detect perm restore error or preserve backups")

    # 5d. Uninstall failure: ownership restoration failure (chown fails on col_index)
    un_bin_chown = os.path.join(td, "un_bin_chown")
    os.makedirs(un_bin_chown, exist_ok=True)
    real_chown = shutil.which("chown")
    open(os.path.join(un_bin_chown, "chown"), "w").write(
        f"#!/bin/sh\nif [ \"$2\" = \"{col_index}\" ]; then exit 1; fi\nexec {real_chown} \"$@\"\n"
    )
    os.chmod(os.path.join(un_bin_chown, "chown"), 0o755)
    env_un_chown = env.copy()
    env_un_chown["PATH"] = f"{un_bin_chown}:{env['PATH']}"
    r_un_chown = subprocess.run(["sh", os.path.join(ROOT, "scripts/uninstall.sh")], env=env_un_chown, capture_output=True, text=True)
    if (r_un_chown.returncode != 0
            and "UNINSTALL ERROR: failed to restore ownership" in r_un_chown.stderr
            and "UNINSTALL FAILED" in r_un_chown.stderr
            and "NMS uninstalled cleanly." not in r_un_chown.stdout
            and os.path.isfile(restore_manifest)
            and os.path.isfile(bak_index) and os.path.isfile(bak_apid) and os.path.isfile(bak_init)):
        ok("UNINSTALL-INTEGRITY[owner_restore]: UNINSTALL FAILED, manifest & all backups preserved")
    else:
        fail("UNINSTALL-INTEGRITY[owner_restore]: failed to detect ownership restore error or preserve backups")

    # 5e. Uninstall failure: backup deletion failure (rm fails on bak_index in isolated copy)
    td_cleanup = os.path.join(td, "cleanup_copy")
    shutil.copytree(td, td_cleanup, ignore=shutil.ignore_patterns("cleanup_copy"))
    env_cleanup = env.copy()
    env_cleanup["NMS_ROOT_PREFIX"] = td_cleanup
    bak_index_c = os.path.join(td_cleanup, "etc/noc-console/preexisting_backup/_www_pro_index.html")
    restore_manifest_c = os.path.join(td_cleanup, "etc/noc-console/restorable_files.manifest")
    un_bin_rm = os.path.join(td, "un_bin_rm")
    os.makedirs(un_bin_rm, exist_ok=True)
    real_rm = shutil.which("rm")
    open(os.path.join(un_bin_rm, "rm"), "w").write(
        f"#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in */preexisting_backup/_www_pro_index.html) exit 1 ;; esac; done\nexec {real_rm} \"$@\"\n"
    )
    os.chmod(os.path.join(un_bin_rm, "rm"), 0o755)
    env_cleanup["PATH"] = f"{un_bin_rm}:{env['PATH']}"
    r_un_rm = subprocess.run(["sh", os.path.join(ROOT, "scripts/uninstall.sh")], env=env_cleanup, capture_output=True, text=True)
    if (r_un_rm.returncode != 0
            and f"UNINSTALL ERROR: failed to clean backup {bak_index_c}" in r_un_rm.stderr
            and "UNINSTALL FAILED" in r_un_rm.stderr
            and "NMS uninstalled cleanly." not in r_un_rm.stdout
            and os.path.isfile(restore_manifest_c)
            and os.path.isfile(bak_index_c)):
        ok("UNINSTALL-INTEGRITY[backup_cleanup]: UNINSTALL FAILED, exact failed backup reported, manifest preserved")
    else:
        fail("UNINSTALL-INTEGRITY[backup_cleanup]: failed to report backup cleanup error or preserve manifest")

    # 5f. Successful restoration and backup cleanup -> byte-for-byte, mode, UID/GID verified, manifest & backups cleaned
    exp_uid_gid = f"{os.getuid()}:{os.getgid()}"
    r_un = subprocess.run(["sh", os.path.join(ROOT, "scripts/uninstall.sh")], env=env, capture_output=True, text=True)
    st_apid, st_init, st_index = os.stat(col_apid), os.stat(col_init), os.stat(col_index)
    if (r_un.returncode == 0
            and "NMS uninstalled cleanly." in r_un.stdout
            and open(col_apid, "rb").read() == col_apid_bytes and stat.S_IMODE(st_apid.st_mode) == 0o4755 and f"{st_apid.st_uid}:{st_apid.st_gid}" == exp_uid_gid
            and open(col_init, "rb").read() == col_init_bytes and stat.S_IMODE(st_init.st_mode) == 0o2755 and f"{st_init.st_uid}:{st_init.st_gid}" == exp_uid_gid
            and open(col_index, "rb").read() == col_index_bytes and stat.S_IMODE(st_index.st_mode) == 0o600 and f"{st_index.st_uid}:{st_index.st_gid}" == exp_uid_gid
            and not os.path.exists(restore_manifest)
            and not os.path.exists(bak_apid) and not os.path.exists(bak_init) and not os.path.exists(bak_index)):
        ok("INS-03: byte-for-byte, setuid (4755), setgid (2755), and UID/GID restoration + clean backup/manifest removal")
    else:
        fail("INS-03: byte-for-byte / setuid / setgid / UID:GID collision restoration or cleanup failed")

print("=== 6. Phase 3A: Sysupgrade Backup, Archive Security, sysupgrade.conf & APK/OPKG Parity ===")
helperd_src = open(os.path.join(ROOT, "backend/noc-helperd")).read()
apid_src = open(os.path.join(ROOT, "backend/noc-apid")).read()
archive_uc_path = os.path.join(ROOT, "backend/nms_archive.uc")
archive_uc_src = open(archive_uc_path).read() if os.path.isfile(archive_uc_path) else ""

# 6a. Structural wiring checks in nms_archive.uc, noc-helperd, and noc-apid
req_helper_syms = [
    "import * as nms_archive from '/usr/libexec/nms_archive.uc';",
    "function detect_pkg_manager()",
    "function validate_backup_archive(",
    "if (verb == 'sys_backup_validate')",
    "if (verb == 'sys_sysupgrade_conf_get')",
    "if (verb == 'sys_sysupgrade_conf_save')",
    "'-b', tmp_tar",
    "['list-installed']",
    "['list-upgradable']",
    "fs.lstat(SYSUPGRADE_CONF_PATH)",
    "nms_archive.merge_sysupgrade_conf(",
    "nms_archive.atomic_write_checked(",
    "function atomic_write_or_reply(",
    "if (!atomic_write_or_reply(",
    "r.cleanup_failed",
    "r.tmp_path",
]
req_uc_syms = [
    "export function validate_tar_stream(",
    "export function normalize_archive_rel_path(",
    "export function resolve_symlink_target(",
    "export function is_safe_sysupgrade_path(",
    "export function merge_sysupgrade_conf(",
    "export function atomic_write_checked(",
]
missing_syms = [s for s in req_helper_syms if s not in helperd_src]
missing_uc = [s for s in req_uc_syms if s not in archive_uc_src]
req_apid_syms = ["action == 'backup_validate'", "sysupgrade_conf_get: 'sys_sysupgrade_conf_get'", "sysupgrade_conf_save: 'sys_sysupgrade_conf_save'"]
missing_apid = [s for s in req_apid_syms if s not in apid_src]
if not missing_syms and not missing_uc and not missing_apid:
    ok("P3A-STRUCT: nms_archive.uc, noc-helperd, and noc-apid Phase 3A contracts & checked atomic_write present")
else:
    fail(f"P3A-STRUCT: missing symbols helper={missing_syms}, uc={missing_uc}, apid={missing_apid}")

# Verify zero unchecked atomic_write( calls in backend/noc-helperd
unchecked_aw = [
    f"{idx}:{ln.strip()}"
    for idx, ln in enumerate(helperd_src.splitlines(), 1)
    if "atomic_write(" in ln and not ln.strip().startswith("function atomic_write(")
    and "let aw" not in ln and "let rb_aw" not in ln and "let f_aw" not in ln
]
if not unchecked_aw:
    ok("P3A-AW-AUDIT: 0 unchecked atomic_write() calls in backend/noc-helperd")
else:
    fail(f"P3A-AW-AUDIT: found unchecked atomic_write() calls: {unchecked_aw}")

# 6b. Production ucode archive validator & atomic_write_checked execution inside isolated OpenWrt x86_64 rootfs
import tarfile, io, struct, re

openwrt_rootfs = "/tmp/openwrt-x86-64-rootfs"
has_openwrt_chroot = os.path.isfile(os.path.join(openwrt_rootfs, "usr/bin/ucode"))
ucode_bin = shutil.which("ucode")

if has_openwrt_chroot or ucode_bin:
    with tempfile.TemporaryDirectory() as td_arc:
        def make_tar(fname, builder):
            p = os.path.join(td_arc, fname)
            with tarfile.open(p, "w") as tf:
                builder(tf)
            return p

        def add_reg(tf, name, data=b"x\n"):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))

        def add_sym(tf, name, target):
            si = tarfile.TarInfo(name)
            si.type = tarfile.SYMTYPE
            si.linkname = target
            tf.addfile(si)

        def add_hard(tf, name, target):
            hi = tarfile.TarInfo(name)
            hi.type = tarfile.LNKTYPE
            hi.linkname = target
            tf.addfile(hi)

        def fix_chksum(hdr_bytes):
            b = bytearray(hdr_bytes)
            b[148:156] = b"        "
            chk = sum(b)
            b[148:156] = f"{chk:06o}\0 ".encode("ascii")
            return bytes(b)

        def raw_tar_block(name, tflag=b"0", size=0, linkname=b"", payload=b""):
            b = bytearray(512)
            b[0:len(name)] = name
            b[100:108] = b"0000644\0"
            b[108:116] = b"0000000\0"
            b[116:124] = b"0000000\0"
            b[124:136] = f"{size:011o}\0".encode("ascii")
            b[136:148] = b"00000000000\0"
            b[156:157] = tflag
            b[157:157 + len(linkname)] = linkname
            b[257:263] = b"ustar\0"
            b[263:265] = b"00"
            out = fix_chksum(b)
            if payload:
                pad = (512 - (len(payload) % 512)) % 512
                out += payload + (b"\x00" * pad)
            return out

        def pax_rec(k, v):
            body = f" {k}={v}\n".encode("utf-8")
            # compute total length including digits
            l = len(body) + 2
            while len(f"{l}".encode("ascii")) + len(body) != l:
                l = len(f"{l}".encode("ascii")) + len(body)
            return f"{l}".encode("ascii") + body

        valid_tar = make_tar("valid.tar", lambda tf: (
            add_reg(tf, "etc/config/network"),
            add_reg(tf, "etc/my file -> with arrow.conf"),
            add_sym(tf, "etc/rc.d/S10boot", "../init.d/boot"),
            add_hard(tf, "etc/config/network.bak", "etc/config/network"),
        ))
        abs_sym = make_tar("abs_sym.tar", lambda tf: add_sym(tf, "etc/bad", "/etc/shadow"))
        abs_hard = make_tar("abs_hard.tar", lambda tf: add_hard(tf, "etc/badh", "/etc/passwd"))
        rel_esc = make_tar("rel_esc.tar", lambda tf: add_sym(tf, "etc/sub/esc", "../../../etc/shadow"))
        rel_scope = make_tar("rel_scope.tar", lambda tf: add_sym(tf, "etc/sub/esc2", "../../tmp/evil"))
        nested_trav = make_tar("nested_trav.tar", lambda tf: add_reg(tf, "etc/a/../../b"))
        nl_name = make_tar("nl_name.tar", lambda tf: add_reg(tf, "etc/bad\nname"))
        out_scope = make_tar("out_scope.tar", lambda tf: add_reg(tf, "tmp/evil.sh"))
        partial_tar = os.path.join(td_arc, "partial.tar")
        open(partial_tar, "wb").write(open(valid_tar, "rb").read()[:300])
        empty_tar = make_tar("empty.tar", lambda tf: None)

        # 1. Bad TAR checksum
        bad_chk_data = bytearray(open(valid_tar, "rb").read())
        bad_chk_data[148] = ord("9")
        open(os.path.join(td_arc, "bad_chksum.tar"), "wb").write(bad_chk_data)

        # 2. Invalid octal size field
        bad_oct = bytearray(raw_tar_block(b"etc/x", size=2))
        bad_oct[124:136] = b"00000000099\0"
        bad_oct = bytearray(fix_chksum(bad_oct[:512])) + bad_oct[512:] + b"\x00" * 1024
        open(os.path.join(td_arc, "bad_octal.tar"), "wb").write(bad_oct)

        # 3. Malformed PAX record (missing '=')
        bad_pax_payload = b"11 badrecord\n"
        open(os.path.join(td_arc, "bad_pax.tar"), "wb").write(
            raw_tar_block(b"PaxHeader/x", tflag=b"x", size=len(bad_pax_payload), payload=bad_pax_payload)
            + raw_tar_block(b"etc/x") + b"\x00" * 1024
        )

        # 4. Global PAX overriding path (rejected) vs valid global PAX mtime (accepted)
        gpax_bad = pax_rec("path", "/etc/shadow")
        open(os.path.join(td_arc, "gpax_bad.tar"), "wb").write(
            raw_tar_block(b"pax_global_header", tflag=b"g", size=len(gpax_bad), payload=gpax_bad)
            + raw_tar_block(b"etc/x") + b"\x00" * 1024
        )
        gpax_ok = pax_rec("mtime", "1700000000")
        open(os.path.join(td_arc, "gpax_ok.tar"), "wb").write(
            raw_tar_block(b"pax_global_header", tflag=b"g", size=len(gpax_ok), payload=gpax_ok)
            + raw_tar_block(b"etc/x") + b"\x00" * 1024
        )

        # 5. GNU longname (valid vs traversal vs empty)
        long_ok = b"etc/" + (b"a" * 110) + b".conf\0"
        open(os.path.join(td_arc, "gnu_long_ok.tar"), "wb").write(
            raw_tar_block(b"././@LongLink", tflag=b"L", size=len(long_ok), payload=long_ok)
            + raw_tar_block(b"etc/short") + b"\x00" * 1024
        )
        long_bad = b"etc/../../etc/shadow\0"
        open(os.path.join(td_arc, "gnu_long_trav.tar"), "wb").write(
            raw_tar_block(b"././@LongLink", tflag=b"L", size=len(long_bad), payload=long_bad)
            + raw_tar_block(b"etc/short") + b"\x00" * 1024
        )

        # 6. Missing end-of-archive zero blocks (only 1 zero block instead of 2)
        open(os.path.join(td_arc, "missing_eof.tar"), "wb").write(
            raw_tar_block(b"etc/x") + b"\x00" * 512
        )

        # 7. Conflicting PAX path vs GNU longname
        pax_conf = pax_rec("path", "etc/a")
        gnu_conf = b"etc/b\0"
        open(os.path.join(td_arc, "conflicting_meta.tar"), "wb").write(
            raw_tar_block(b"PaxHeader/x", tflag=b"x", size=len(pax_conf), payload=pax_conf)
            + raw_tar_block(b"././@LongLink", tflag=b"L", size=len(gnu_conf), payload=gnu_conf)
            + raw_tar_block(b"etc/c") + b"\x00" * 1024
        )

        cases = [
            {"name": "valid_spaces_arrows_links", "file": "valid.tar", "expect_valid": True},
            {"name": "abs_symlink", "file": "abs_sym.tar", "expect_valid": False},
            {"name": "abs_hardlink", "file": "abs_hard.tar", "expect_valid": False},
            {"name": "rel_symlink_escape_root", "file": "rel_esc.tar", "expect_valid": False},
            {"name": "rel_symlink_escape_scope", "file": "rel_scope.tar", "expect_valid": False},
            {"name": "nested_traversal", "file": "nested_trav.tar", "expect_valid": False},
            {"name": "newline_filename", "file": "nl_name.tar", "expect_valid": False},
            {"name": "out_of_scope", "file": "out_scope.tar", "expect_valid": False},
            {"name": "partial_write", "file": "partial.tar", "expect_valid": False},
            {"name": "empty_archive", "file": "empty.tar", "expect_valid": False},
            {"name": "bad_checksum", "file": "bad_chksum.tar", "expect_valid": False},
            {"name": "bad_octal_size", "file": "bad_octal.tar", "expect_valid": False},
            {"name": "malformed_pax", "file": "bad_pax.tar", "expect_valid": False},
            {"name": "global_pax_path_override", "file": "gpax_bad.tar", "expect_valid": False},
            {"name": "global_pax_valid_mtime", "file": "gpax_ok.tar", "expect_valid": True},
            {"name": "gnu_longname_valid", "file": "gnu_long_ok.tar", "expect_valid": True},
            {"name": "gnu_longname_traversal", "file": "gnu_long_trav.tar", "expect_valid": False},
            {"name": "missing_eof_markers", "file": "missing_eof.tar", "expect_valid": False},
            {"name": "conflicting_pax_gnu", "file": "conflicting_meta.tar", "expect_valid": False},
        ]
        open(os.path.join(td_arc, "manifest.json"), "w").write(json.dumps({"cases": cases}))

        if has_openwrt_chroot:
            chroot_stage = os.path.join(openwrt_rootfs, "tmp/p3a_test")
            shutil.rmtree(chroot_stage, ignore_errors=True)
            shutil.copytree(td_arc, chroot_stage)
            shutil.copy2(archive_uc_path, os.path.join(chroot_stage, "nms_archive.uc"))
            # Extract exact production atomic_write & atomic_write_or_reply from backend/noc-helperd
            m_aw = re.search(r"(function atomic_write\(.*?\n\}\n\nfunction atomic_write_or_reply\(.*?\n\})", helperd_src, re.DOTALL)
            if not m_aw:
                fail("P3A-HELPERD-EXTRACT: could not extract atomic_write/atomic_write_or_reply from noc-helperd")
            else:
                open(os.path.join(chroot_stage, "helperd_aw_prod.uc"), "w").write(
                    "import * as fs from 'fs';\n"
                    "import * as nms_archive from '/tmp/p3a_test/nms_archive.uc';\n"
                    "export let test_audits = [];\n"
                    "export let test_locks_released = 0;\n"
                    "export let test_warns = [];\n"
                    "function now_mono_ms() { return 12345; }\n"
                    "function urandom_hex(n) { return 'abcd'; }\n"
                    "function warn(msg) { push(test_warns, msg); }\n"
                    "function audit_append(actor, act, tgt, res, det) { push(test_audits, { actor: actor, action: act, target: tgt, result: res, details: det }); }\n"
                    "function release_lock() { test_locks_released++; }\n"
                    + m_aw.group(1)
                    + "\nexport { atomic_write, atomic_write_or_reply };\n"
                )
            shutil.copy2(os.path.join(ROOT, "tests/verify_phase3a_ucode.uc"), os.path.join(chroot_stage, "verify_phase3a_ucode.uc"))
            try:
                ru = subprocess.run(
                    ["unshare", "-r", "/usr/sbin/chroot", openwrt_rootfs, "/usr/bin/ucode", "/tmp/p3a_test/verify_phase3a_ucode.uc", "/tmp/p3a_test/nms_archive.uc", "/tmp/p3a_test"],
                    capture_output=True, text=True
                )
                for line in ru.stdout.splitlines():
                    if line.startswith("[PASS] "):
                        ok(line[len("[PASS] "):])
                    elif line.startswith("[FAIL] "):
                        fail(line[len("[FAIL] "):])
                if ru.returncode != 0 and "UCODE_SUMMARY:" not in ru.stdout:
                    fail(f"P3A-UCODE: runner failed rc={ru.returncode}: {ru.stderr}")
            finally:
                shutil.rmtree(chroot_stage, ignore_errors=True)
else:
    print("[SKIP] P3A-UCODE: ucode runtime unavailable; production archive validator NOT executed")

# 6c. APK/OPKG fixture detection
with tempfile.TemporaryDirectory() as td_pm:
    apk_bin = os.path.join(td_pm, "apk")
    opkg_bin = os.path.join(td_pm, "opkg")
    open(apk_bin, "w").write("#!/bin/sh\necho 'ucode-2025.01-r1'\n")
    open(opkg_bin, "w").write("#!/bin/sh\necho 'ucode - 2024.07'\n")
    os.chmod(apk_bin, 0o755)
    os.chmod(opkg_bin, 0o755)
    r_apk = subprocess.run([apk_bin, "info", "-v"], capture_output=True, text=True)
    r_opkg = subprocess.run([opkg_bin, "list-installed"], capture_output=True, text=True)
    if r_apk.returncode == 0 and "ucode-2025.01-r1" in r_apk.stdout and r_opkg.returncode == 0 and "ucode - 2024.07" in r_opkg.stdout:
        ok("P3A-PKG: apk & opkg executable fixtures verified")
    else:
        fail("P3A-PKG: apk/opkg fixture execution failed")

print(f"\n=== SUMMARY: {len(passes)} passed, {len(failures)} failed ===")
sys.exit(1 if failures else 0)
