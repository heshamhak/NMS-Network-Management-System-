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
for rel in ("frontend/app.js", "frontend/nms-i18n.js", "frontend/noc-topology.js", "frontend/noc-search.js", "frontend/noc-tools.js", "frontend/netchart.js", "frontend/sw.js", "frontend/launcher.js"):
    r = subprocess.run(["node", "--check", os.path.join(ROOT, rel)], capture_output=True, text=True)
    ok(f"node --check {rel}") if r.returncode == 0 else fail(f"node --check {rel}: {r.stderr.strip()}")

for rel in ("scripts/install.sh", "scripts/uninstall.sh", "scripts/enable-root-redirect.sh", "scripts/restore-luci.sh", "init.d/noc-apid", "init.d/noc-helperd"):
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
    tls_proxy_args = None
    in_tls_inst = False
    for line in procd_txt.splitlines():
        if line.startswith("INSTANCE="):
            in_tls_inst = (line == "INSTANCE=noc_tls_proxy")
        elif in_tls_inst and line.startswith("PARAM=command "):
            tls_proxy_args = line[len("PARAM=command "):].split()
            break

    if tls_proxy_args and os.path.exists(tls_proxy_args[0]):
        class LoopbackHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"NMS_SIM_PROCD_TLS_OK"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", http_p), LoopbackHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        proxy_proc = subprocess.Popen(tls_proxy_args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            connected = False
            last_err = ""
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            for _ in range(30):
                try:
                    with socket.create_connection((lan_sim_ip, https_p), timeout=1.5) as raw_s:
                        with ctx.wrap_socket(raw_s, server_hostname="nms.lan") as tls_s:
                            tls_s.settimeout(2.0)
                            der = tls_s.getpeercert(binary_form=True)
                            sha256_hex = hashlib.sha256(der).hexdigest().upper()
                            fp_text = open(fp_p).read().replace(":", "").upper()
                            tls_s.sendall(b"GET / HTTP/1.1\r\nHost: nms.lan\r\nConnection: close\r\n\r\n")
                            chunks = []
                            while True:
                                try:
                                    part = tls_s.recv(4096)
                                except socket.timeout:
                                    break
                                if not part:
                                    break
                                chunks.append(part)
                                if b"NMS_SIM_PROCD_TLS_OK" in b"".join(chunks):
                                    break
                            resp_bytes = b"".join(chunks)
                            if b"NMS_SIM_PROCD_TLS_OK" in resp_bytes and sha256_hex in fp_text:
                                ok(f"SEC-01 (simulated procd): TLS handshake + HTTP via {os.path.basename(tls_proxy_args[0])} on {lan_sim_ip}:{https_p} -> 127.0.0.1:{http_p} passed")
                                connected = True
                                break
                            last_err = f"unexpected resp={resp_bytes!r}"
                except OSError as exc:
                    last_err = str(exc)
                    time.sleep(0.1)
            if not connected:
                fail(f"SEC-01 (simulated procd): TLS connection failed ({last_err})")
            try:
                with socket.create_connection((lan_sim_ip, http_p), timeout=0.5):
                    fail(f"SEC-01: unencrypted HTTP reachable on {lan_sim_ip}:{http_p}")
            except OSError:
                ok(f"SEC-01: unencrypted HTTP refused on LAN IP {lan_sim_ip}:{http_p} (loopback-only confirmed)")
        finally:
            proxy_proc.terminate()
            proxy_proc.wait(timeout=3)
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
            shutil.copy2(os.path.join(ROOT, "backend/nms_network.uc"), os.path.join(chroot_stage, "nms_network.uc"))
            shutil.copy2(os.path.join(ROOT, "backend/nms_fw_wifi.uc"), os.path.join(chroot_stage, "nms_fw_wifi.uc"))
            # Copy modules to /usr/libexec inside chroot too so import '/usr/libexec/nms_archive.uc' resolves cleanly
            os.makedirs(os.path.join(openwrt_rootfs, "usr/libexec"), exist_ok=True)
            shutil.copy2(archive_uc_path, os.path.join(openwrt_rootfs, "usr/libexec/nms_archive.uc"))
            shutil.copy2(os.path.join(ROOT, "backend/nms_network.uc"), os.path.join(openwrt_rootfs, "usr/libexec/nms_network.uc"))
            shutil.copy2(os.path.join(ROOT, "backend/nms_fw_wifi.uc"), os.path.join(openwrt_rootfs, "usr/libexec/nms_fw_wifi.uc"))
            # Extract exact production helpers & handlers from backend/noc-helperd
            m_aw = re.search(r"(function atomic_write\(.*?\n\}\n\nfunction atomic_write_or_reply\(.*?\n\})", helperd_src, re.DOTALL)
            m_frz = re.search(r"(function get_freeze_state\(.*?\n\}\n\nfunction enter_emergency_freeze\(.*?\n\}\n\nfunction enforce_mutation_gate\(.*?\n\})", helperd_src, re.DOTALL)
            m_fw = re.search(r"(function fw_check_and_reload\(.*?\n\})", helperd_src, re.DOTALL)
            m_su = re.search(r"(function handle_sys_sysupgrade_conf_save\(.*?\n\})", helperd_src, re.DOTALL)
            m_rr = re.search(r"(function handle_rollback_revert\(.*?\n\})", helperd_src, re.DOTALL)
            m_rb = re.search(r"(function rollback_client_rules\(.*?\n\})", helperd_src, re.DOTALL)
            m_net = re.search(r"(function array_eq\(.*?\n\}\n\nfunction handle_network_phase3b_verb\(.*?\n\})", helperd_src, re.DOTALL)
            m_p3c = re.search(r"(function handle_phase3c_verb\(.*?\n\})", helperd_src, re.DOTALL)
            if not m_aw or not m_frz or not m_fw or not m_su or not m_rr or not m_rb or not m_net or not m_p3c:
                fail("P3A-HELPERD-EXTRACT: could not extract production helpers from noc-helperd")
            else:
                open(os.path.join(chroot_stage, "helperd_aw_prod.uc"), "w").write(
                    "import * as real_fs from 'fs';\n"
                    "import * as uci from 'uci';\n"
                    "import * as nms_archive from '/tmp/p3a_test/nms_archive.uc';\n"
                    "import * as nms_network from '/tmp/p3a_test/nms_network.uc';\n"
                    "import * as nms_fw_wifi from '/tmp/p3a_test/nms_fw_wifi.uc';\n"
                    "export let test_audits = [];\n"
                    "export let test_locks_released = 0;\n"
                    "export let test_warns = [];\n"
                    "export let ETC_DIR = '/tmp/p3a_test/etc_mock';\n"
                    "export let SYSUPGRADE_CONF_PATH = '/tmp/p3a_test/sysupgrade.conf';\n"
                    "export let CAP_GENERAL = 65536;\n"
                    "export let emergency_freeze_state = null;\n"
                    "export let mock_exec_res = { ok: false };\n"
                    "export let mock_apply_res = { ok: true };\n"
                    "export let mock_readfile_null_path = null;\n"
                    "export let spy_mutations = 0;\n"
                    "let fs = {\n"
                    "  stat: real_fs.stat,\n"
                    "  lstat: real_fs.lstat,\n"
                    "  open: function(p, fl, m) { spy_mutations++; return real_fs.open(p, fl, m); },\n"
                    "  writefile: function(p, c) { spy_mutations++; return real_fs.writefile(p, c); },\n"
                    "  chown: function(p, u, g) { spy_mutations++; return real_fs.chown(p, u, g); },\n"
                    "  chmod: function(p, m) { spy_mutations++; return real_fs.chmod(p, m); },\n"
                    "  rename: function(s, d) { spy_mutations++; return real_fs.rename(s, d); },\n"
                    "  unlink: function(p) { spy_mutations++; return real_fs.unlink(p); },\n"
                    "  readfile: function(p) { if (mock_readfile_null_path != null && p == mock_readfile_null_path) return null; return real_fs.readfile(p); }\n"
                    "};\n"
                    "function read_json(p, fb) { let r = fs.readfile(p); if (!r) return fb; try { return json(r); } catch (e) { return fb; } }\n"
                    "function now_mono_ms() { return 12345; }\n"
                    "function now_iso() { return '2026-11-22T00:00:00Z'; }\n"
                    "function urandom_hex(n) { return 'abcd'; }\n"
                    "function system(cmd) { return 0; }\n"
                    "function warn(msg) { push(test_warns, msg); }\n"
                    "function audit_append(actor, act, tgt, res, det) { push(test_audits, { actor: actor, action: act, target: tgt, result: res, details: det }); }\n"
                    "function release_lock() { test_locks_released++; }\n"
                    "function exec_argv_async(exe, argv, t, c, cb) { cb(mock_exec_res); }\n"
                    "function apply_bridge_block_rules(rules, cb) { cb(mock_apply_res); }\n"
                    "function check_staging_guard() { return { ok: true }; }\n"
                    "function check_storage_budget() { return { ok: true }; }\n"
                    "function acquire_lock(o, op) { return { ok: true }; }\n"
                    "function set_mock(ec, ap, ed, su_p, null_p) { ETC_DIR = ed; mock_exec_res = ec; mock_apply_res = ap; if (su_p != null) SYSUPGRADE_CONF_PATH = su_p; mock_readfile_null_path = null_p; spy_mutations = 0; }\n"
                    "function clear_freeze_mem() { emergency_freeze_state = null; }\n"
                    + m_aw.group(1) + "\n"
                    + m_frz.group(1) + "\n"
                    + m_fw.group(1) + "\n"
                    + m_su.group(1) + "\n"
                    + m_rr.group(1) + "\n"
                    + m_rb.group(1) + "\n"
                    + m_net.group(1) + "\n"
                    + m_p3c.group(1) + "\n"
                    + "\nexport { atomic_write, atomic_write_or_reply, get_freeze_state, enter_emergency_freeze, enforce_mutation_gate, fw_check_and_reload, handle_sys_sysupgrade_conf_save, handle_rollback_revert, rollback_client_rules, handle_network_phase3b_verb, handle_phase3c_verb, set_mock, clear_freeze_mem };\n"
                )
            shutil.copy2(os.path.join(ROOT, "tests/verify_phase3a_ucode.uc"), os.path.join(chroot_stage, "verify_phase3a_ucode.uc"))
            shutil.copy2(os.path.join(ROOT, "tests/verify_phase3b_ucode.uc"), os.path.join(chroot_stage, "verify_phase3b_ucode.uc"))
            shutil.copy2(os.path.join(ROOT, "tests/verify_phase3c_ucode.uc"), os.path.join(chroot_stage, "verify_phase3c_ucode.uc"))
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

                ru3b = subprocess.run(
                    ["unshare", "-r", "/usr/sbin/chroot", openwrt_rootfs, "/usr/bin/ucode", "/tmp/p3a_test/verify_phase3b_ucode.uc", "/tmp/p3a_test"],
                    capture_output=True, text=True
                )
                for line in ru3b.stdout.splitlines():
                    if line.startswith("[PASS] "):
                        ok(line[len("[PASS] "):])
                    elif line.startswith("[FAIL] "):
                        fail(line[len("[FAIL] "):])
                if ru3b.returncode != 0 and "UCODE3B_SUMMARY:" not in ru3b.stdout:
                    fail(f"P3B-UCODE: runner failed rc={ru3b.returncode}: {ru3b.stderr}")

                ru3c = subprocess.run(
                    ["unshare", "-r", "/usr/sbin/chroot", openwrt_rootfs, "/usr/bin/ucode", "/tmp/p3a_test/verify_phase3c_ucode.uc", "/tmp/p3a_test"],
                    capture_output=True, text=True
                )
                for line in ru3c.stdout.splitlines():
                    if line.startswith("[PASS] "):
                        ok(line[len("[PASS] "):])
                    elif line.startswith("[FAIL] "):
                        fail(line[len("[FAIL] "):])
                if ru3c.returncode != 0 and "UCODE3C_SUMMARY:" not in ru3c.stdout:
                    fail(f"P3C-UCODE: runner failed rc={ru3c.returncode}: {ru3c.stderr}")
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

print(f"\n=== 7. Phase 4F: Frontend DOM & API/RBAC/IPC Integration Tests ===")
# 7a. Real DOM execution of frontend/noc-topology.js (complete, partial, stale, unavailable, unknown client not linked to AP, pollInFlight guard)
node_dom_test = r"""
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

class MockEl {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.id = '';
    this.className = '';
    this.textContent = '';
    this.style = {};
    this.children = [];
    this.attrs = {};
    this.listeners = {};
    this.value = '';
    this.offsetParent = {};
    this.scrollWidth = 900;
    this.scrollHeight = 600;
    this.clientWidth = 900;
    this.clientHeight = 600;
    const self = this;
    this.classList = {
      add(c) { if (!self.className.split(/\s+/).includes(c)) self.className = (self.className + ' ' + c).trim(); },
      remove(c) { self.className = self.className.split(/\s+/).filter(x => x !== c).join(' '); },
      contains(c) { return self.className.split(/\s+/).includes(c); }
    };
  }
  appendChild(ch) { this.children.push(ch); if (ch.id) byId[ch.id] = ch; return ch; }
  removeChild(ch) { this.children = this.children.filter(x => x !== ch); }
  get firstChild() { return this.children[0] || null; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'id') { this.id = String(v); byId[this.id] = this; } if (k === 'class') this.className = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); }
  getBoundingClientRect() { return { left: 10, top: 10, right: 110, bottom: 60, width: 100, height: 50 }; }
  querySelectorAll() { return []; }
  closest() { return null; }
}

const byId = {};
const ids = ['view-topology','topo-col-wan','topo-col-router','topo-col-ports','topo-col-devices','topo-svg','topo-stage','topo-canvas','topo-network-tree','topoModeBadge','topoTotalSpeed','topoActiveDevices','btnTopoRefresh','btnTopoLive','btnTopoSim','topoDeviceSearch','topoDeviceFilter','topoInspector'];
for (const id of ids) { const e = new MockEl('div'); e.id = id; byId[id] = e; }
byId['topoDeviceFilter'].value = 'online';

const docListeners = {};
let apiCalls = 0;
let pendingResolve = null;
const sandbox = {
  console, Math, Number, String, Array, Object, JSON, Date, setTimeout, clearTimeout, setInterval, clearInterval,
  requestAnimationFrame: (fn) => fn(),
  localStorage: { getItem: () => null, setItem: () => {} },
  document: {
    hidden: false,
    getElementById: (id) => byId[id] || null,
    createElement: (t) => new MockEl(t),
    createElementNS: (ns, t) => new MockEl(t),
    addEventListener: (ev, fn) => { (docListeners[ev] = docListeners[ev] || []).push(fn); }
  },
  window: {
    addEventListener: () => {},
    removeEventListener: () => {},
    NOC: {
      state: { activeTab: 'topology', authenticated: true, lastOverview: { system: { hostname: 'gw' }, wan: { up: true, active_device: 'pppoe-wan' }, lan: { up: true, ipv4: '192.168.1.1' }, dependencies: { sqm: 'ready', adguard: 'ready', tailscale: 'ready' }, interfaces: { 'pppoe-wan': { rx_bps: 1000, tx_bps: 500 } } } },
      apiCall: (action) => {
        apiCalls++;
        return new Promise((res) => { pendingResolve = res; });
      }
    }
  }
};
sandbox.window.window = sandbox.window;
vm.runInNewContext(fs.readFileSync('frontend/noc-topology.js', 'utf8'), sandbox);

(async () => {
  for (const fn of (docListeners['DOMContentLoaded'] || [])) fn();
  // 1. Concurrent refresh guard: firing click twice while in-flight only issues 1 API call
  const clickFn = byId['btnTopoRefresh'].listeners['click'][0];
  const p1 = clickFn();
  const p2 = clickFn();
  assert.strictEqual(apiCalls, 1, 'pollInFlight prevents concurrent refresh storms');

  // 2. Complete topology with unknown client & wired client -> unknown client is NOT linked to any AP!
  pendingResolve({
    ok: true,
    data: {
      ok: true, completeness: 'complete', partial: false, stale: false, sampled_ms: 1000,
      wan_links: [{ device: 'pppoe-wan', observed_up: true, operstate: 'up', ipv4: '100.78.0.2', is_default_route: true, evidence_source: 'firewall_wan+ubus+ip_link' }],
      bridges: [{ name: 'br-lan', observed_up: true, operstate: 'up', ports: [{ ifname: 'eth1', observed_up: true, operstate: 'up', vlans: [] }] }],
      aps: [{ ifname: 'wlan1', ssid: 'HomeAP', observed_up: true, evidence_source: 'ubus_wireless+ip_link' }],
      clients: [
        { mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.10', display_name: 'WiFiDev', online: true, parent_id: 'ap:wlan1', attachment_type: 'wireless', evidence_source: 'hostapd' },
        { mac: 'aa:bb:cc:dd:ee:02', ip: '192.168.1.11', display_name: 'UnkDev', online: true, parent_id: 'unknown', attachment_type: 'unknown', evidence_source: 'none' }
      ]
    }
  });
  await p1; await p2;
  assert.strictEqual(byId['topoModeBadge'].textContent, 'وضع المراقبة الحية');
  assert.strictEqual(byId['topo-col-devices'].children.length, 2);
  // Only 1 client line (WiFiDev -> ap:wlan1); UnkDev must NOT be fabricated onto ap:wlan1!
  const paths = byId['topo-svg'].children.length;
  // wan(1) + bridge(1) + port(1) + ap(1) + wifiClient(1) = 5 lines (UnkDev has 0 lines!)
  assert.strictEqual(paths, 5, 'Expected exactly 5 SVG lines (unknown client must not be attached to AP), got ' + paths);

  // 3. Partial topology shows partial badge
  const p3 = clickFn();
  pendingResolve({
    ok: true,
    data: {
      ok: true, completeness: 'partial', partial: true, stale: false, missing_sources: ['bridge_vlan'],
      wan_links: [], bridges: [], aps: [], clients: []
    }
  });
  await p3;
  assert.strictEqual(byId['topoModeBadge'].textContent, 'طوبولوجيا جزئية');
  assert.strictEqual(byId['topo-col-wan'].children[0].id, 'topo-wan-none', 'Empty wan_links renders explicit unconfirmed WAN node');

  // 4. Refresh failure while valid snapshot exists preserves lastTopology & marks stale
  const p4 = clickFn();
  pendingResolve({ ok: false });
  await p4;
  assert.ok(byId['topoModeBadge'].textContent.includes('بيانات قديمة'), 'Failed refresh marks existing topology stale: ' + byId['topoModeBadge'].textContent);
  assert.strictEqual(sandbox.window.NOC.state.lastTopology.stale, true);

  // 5. Unavailable response when no prior valid snapshot -> unavailable badge
  sandbox.window.NOC.state.lastTopology = null;
  const p5 = clickFn();
  pendingResolve({ ok: true, data: { ok: false, completeness: 'unavailable', wan_links: [], bridges: [], aps: [], clients: [] } });
  await p5;
  assert.strictEqual(byId['topoModeBadge'].textContent, 'غير متاح (فشل الجمع)');
  console.log('DOM_TOPO_PASS');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
"""
r_dom = subprocess.run(["node", "-e", node_dom_test], cwd=ROOT, capture_output=True, text=True)
if r_dom.returncode == 0 and "DOM_TOPO_PASS" in r_dom.stdout:
    ok("P4F-DOM: noc-topology.js real DOM tests (complete, partial, stale, unavailable, no fabricated links, pollInFlight)")
else:
    fail(f"P4F-DOM: failed rc={r_dom.returncode}: {r_dom.stderr} {r_dom.stdout}")

# 7b. Real production noc-apid action=='topology' + noc-helperd handle_rpc topology_read single-flight integration test on BOTH OpenWrt 24.10.0 & 25.12.6
apid_src = open(os.path.join(ROOT, "backend/noc-apid"), "r", encoding="utf-8").read()
helperd_src = open(os.path.join(ROOT, "backend/noc-helperd"), "r", encoding="utf-8").read()
m_topo_handler = re.search(r"(\tif \(action == 'topology'\) \{.*?\n\t\treturn;\n\t\})", apid_src, re.S)
m_rbac_block = re.search(r"(let rbac = nms_access_dhcp\.check_rbac_access\(sess, action, method\);.*?\n\t\})", apid_src, re.S)
m_sf_global = re.search(r"^let topology_inflight_cbs = null;", helperd_src, re.M)
m_helperd_topo = re.search(r"(\tif \(verb == 'topology_read'\) \{.*?\n\t\treturn;\n\t\})", helperd_src, re.S)
if not m_topo_handler or not m_rbac_block or not m_sf_global or not m_helperd_topo:
    fail("P4F-API: failed to extract production topology handler / RBAC / noc-helperd topology_read")
else:
    p4f_api_uc = (
        "import * as digest from 'digest';\n"
        "import * as nms_discovery from '/tmp/p3a_test/nms_discovery.uc';\n"
        "import * as nms_access_dhcp from '/tmp/p3a_test/nms_access_dhcp.uc';\n"
        "import * as nms_sqm from '/tmp/p3a_test/nms_sqm.uc';\n"
        "import * as nms_topology from '/tmp/p3a_test/nms_topology.uc';\n"
        "let BOOT_ID = 'boot-test-4f';\n"
        "let CAP_GENERAL = 65536;\n"
        "let cache_map = {};\n"
        "let last_valid_topology = null;\n"
        "let prev_client_rates = {};\n"
        "let helper_fail_mode = false;\n"
        "let defer_exec = false;\n"
        "let pending_exec_cbs = [];\n"
        "let ip_link_exec_count = 0;\n"
        + m_sf_global.group(0) + "\n"
        "let fs = {\n"
        "  lsdir: function(p) { if (p == '/sys/class/net/br-lan/brif') return ['wlan1']; if (p == '/sys/class/net') return ['pppoe-wan', 'wlan1', 'br-lan']; return []; },\n"
        "  readfile: function(p) { if (p == '/sys/class/net/pppoe-wan/carrier' || p == '/sys/class/net/wlan1/carrier') return '1\\n'; return null; },\n"
        "  stat: function(p) { return true; }\n"
        "};\n"
        "let uci = { cursor: function() { return {\n"
        "  foreach: function(pkg, st, fn) {\n"
        "    if (pkg == 'wireless' && st == 'wifi-iface') fn({ ifname: 'wlan1', device: 'radio0', ssid: 'HomeAP', mode: 'ap', disabled: '0' });\n"
        "  },\n"
        "  get: function() { return null; }\n"
        "}; } };\n"
        "let ubus = { connect: function() { return {\n"
        "  call: function(obj, meth, args) {\n"
        "    if (obj == 'network.interface') return { interface: [{ interface: 'wan', l3_device: 'pppoe-wan', up: true }, { interface: 'lan', l3_device: 'br-lan', up: true }] };\n"
        "    if (obj == 'network.wireless') return { radio0: { up: true, interfaces: [{ ifname: 'wlan1', config: { mode: 'ap', ssid: 'HomeAP' } }] } };\n"
        "    if (obj == 'hostapd.wlan1') return { clients: { 'aa:bb:cc:dd:ee:01': { signal: -50 } } };\n"
        "    return {};\n"
        "  },\n"
        "  disconnect: function() {}\n"
        "}; } };\n"
        "function find_exe(list) { return '/usr/sbin/bridge'; }\n"
        "function mock_exec_result(exe, argv) {\n"
        "  let a = join(' ', argv || []);\n"
        "  if (exe == '/sbin/ip' && index(a, 'link') >= 0) {\n"
        "    ip_link_exec_count++;\n"
        "    return { ok: true, output: sprintf('%J', [{ ifname: 'pppoe-wan', operstate: 'UP', flags: ['UP'], address: '' }, { ifname: 'wlan1', operstate: 'UP', flags: ['UP'], address: '60:be:b4:1e:d3:5e', master: 'br-lan' }]) };\n"
        "  }\n"
        "  return { ok: true, output: (index(a, '-j') >= 0 ? '[]' : '') };\n"
        "}\n"
        "function exec_argv_async(exe, argv, t, c, cb) {\n"
        "  if (defer_exec) {\n"
        "    push(pending_exec_cbs, function() { cb(mock_exec_result(exe, argv)); });\n"
        "    return;\n"
        "  }\n"
        "  cb(mock_exec_result(exe, argv));\n"
        "}\n"
        "function prod_helper_rpc(verb, params, reply_cb) {\n"
        + m_helperd_topo.group(1) + "\n"
        "}\n"
        "function now_mono_ms() { return 50000; }\n"
        "function send_json_env(cli, status, res_name, data, errs) { cli.status = status; cli.data = data; }\n"
        "function call_helper(verb, params, user, rip, cb) {\n"
        "  if (helper_fail_mode) { cb(null); return; }\n"
        "  if (verb == 'clients_read') {\n"
        "    cb({\n"
        "      ok: true, flow_offloading: false, discovery_status: { nlbw: true },\n"
        "      leases_raw: '1700000000 aa:bb:cc:dd:ee:01 192.168.1.20 phone *\\n',\n"
        "      neigh4: '192.168.1.20 dev br-lan lladdr aa:bb:cc:dd:ee:01 REACHABLE\\n',\n"
        "      neigh6: '', fdb_raw: '', bridges: [{ name: 'br-lan', ports: ['eth1'] }],\n"
        "      local_macs: {}, wifi_stations: { 'aa:bb:cc:dd:ee:01': { ifname: 'wlan1', signal: -50 } },\n"
        "      rules: { blocked_macs: {}, blocked_ips: {}, nicknames: {}, rate_limits: {} },\n"
        "      static_leases: {}, nlbw_by_mac: {}, nlbw_by_ip: {}\n"
        "    });\n"
        "  } else if (verb == 'topology_read') {\n"
        "    prod_helper_rpc('topology_read', params, cb);\n"
        "  }\n"
        "}\n"
        "function prod_dispatch(sess, action, method, remote_ip) {\n"
        "  let cli = { status: 0, data: null };\n"
        "  let req_id = 'req-1';\n"
        "  (function() {\n"
        + m_rbac_block.group(1) + "\n"
        + m_topo_handler.group(1) + "\n"
        "  })();\n"
        "  return cli;\n"
        "}\n"
        "// 1. Unauthenticated -> 401\n"
        "let r1 = prod_dispatch(null, 'topology', 'GET', '127.0.0.1');\n"
        "if (r1.status != 401) exit(1);\n"
        "// 2. Readonly -> redacted MAC/IP, cached under topology_readonly\n"
        "let r2 = prod_dispatch({ username: 'viewer', role: 'readonly' }, 'topology', 'GET', '127.0.0.1');\n"
        "if (r2.status != 200 || r2.data.clients[0].mac != 'HIDDEN') exit(2);\n"
        "// 3. Admin immediately after readonly -> MUST NOT receive readonly cache!\n"
        "let r3 = prod_dispatch({ username: 'admin', role: 'admin' }, 'topology', 'GET', '127.0.0.1');\n"
        "if (r3.status != 200 || r3.data.clients[0].mac != 'aa:bb:cc:dd:ee:01') exit(3);\n"
        "// 4. Failed refresh after cache clear -> preserves last_valid_topology as stale\n"
        "cache_map = {};\n"
        "helper_fail_mode = true;\n"
        "let r4 = prod_dispatch({ username: 'admin', role: 'admin' }, 'topology', 'GET', '127.0.0.1');\n"
        "if (r4.status != 200 || !r4.data.stale || !r4.data.refresh_failed || r4.data.clients[0].mac != 'aa:bb:cc:dd:ee:01') exit(4);\n"
        "// 5. Real production noc-helperd topology_read single-flight coalesces 3 concurrent RPC calls into 1 collector run\n"
        "helper_fail_mode = false; ip_link_exec_count = 0; defer_exec = true; pending_exec_cbs = [];\n"
        "let sf_res = [];\n"
        "prod_helper_rpc('topology_read', {}, (x) => push(sf_res, x));\n"
        "prod_helper_rpc('topology_read', {}, (x) => push(sf_res, x));\n"
        "prod_helper_rpc('topology_read', {}, (x) => push(sf_res, x));\n"
        "if (length(pending_exec_cbs) != 1 || length(sf_res) != 0) exit(5);\n"
        "while (length(pending_exec_cbs) > 0) {\n"
        "  let next_cb = shift(pending_exec_cbs);\n"
        "  next_cb();\n"
        "}\n"
        "if (ip_link_exec_count != 1 || length(sf_res) != 3 || !sf_res[0].ok || !sf_res[1].ok || !sf_res[2].ok || topology_inflight_cbs != null) exit(6);\n"
        "// 6. Subsequent call after completion starts a fresh collector run\n"
        "defer_exec = false;\n"
        "prod_helper_rpc('topology_read', {}, (x) => push(sf_res, x));\n"
        "if (ip_link_exec_count != 2 || length(sf_res) != 4 || !sf_res[3].ok) exit(7);\n"
        "print('API_TOPO_PASS\\n');\n"
    )
    for ver_label, rfs in (("24.10.0-opkg", "/tmp/openwrt-24.10-x86-64-rootfs"), ("25.12.6-apk", "/tmp/openwrt-x86-64-rootfs")):
        if os.path.isdir(rfs) and os.path.isfile(os.path.join(rfs, "usr/bin/ucode")):
            stage_4f = tempfile.mkdtemp(prefix="p4f_api_")
            try:
                for fn in ("nms_discovery.uc", "nms_access_dhcp.uc", "nms_sqm.uc", "nms_topology.uc"):
                    shutil.copy2(os.path.join(ROOT, "backend", fn), os.path.join(stage_4f, fn))
                with open(os.path.join(stage_4f, "api_test.uc"), "w", encoding="utf-8") as f:
                    f.write(p4f_api_uc)
                dst_stage = os.path.join(rfs, "tmp", "p3a_test")
                if os.path.exists(dst_stage):
                    shutil.rmtree(dst_stage, ignore_errors=True)
                shutil.copytree(stage_4f, dst_stage)
                r_api = subprocess.run(["unshare", "-r", "/usr/sbin/chroot", rfs, "/usr/bin/ucode", "/tmp/p3a_test/api_test.uc"], capture_output=True, text=True)
                shutil.rmtree(dst_stage, ignore_errors=True)
                if r_api.returncode == 0 and "API_TOPO_PASS" in r_api.stdout:
                    ok(f"P4F-API[{ver_label}]: production noc-apid topology & noc-helperd topology_read single-flight verified")
                else:
                    fail(f"P4F-API[{ver_label}]: failed rc={r_api.returncode}: {r_api.stderr} {r_api.stdout}")
            finally:
                shutil.rmtree(stage_4f, ignore_errors=True)

# 8. SEC-01-STUNNEL: OpenWrt 25.12.6 #undef WITH_OPENSSL socat rejection + isolated procd stunnel TLS lifecycle
with tempfile.TemporaryDirectory(prefix="nms_stunnel_test_") as st_td:
    bin_nossl = os.path.join(st_td, "bin_nossl")
    bin_stunnel = os.path.join(st_td, "bin_stunnel")
    os.makedirs(bin_nossl)
    os.makedirs(bin_stunnel)
    # Create a fake socat reporting OpenWrt 25.12.6's `#undef WITH_OPENSSL`
    for bdir in (bin_nossl, bin_stunnel):
        sc_p = os.path.join(bdir, "socat")
        open(sc_p, "w").write("#!/bin/sh\necho 'socat version 1.8.1.3'\necho '  #undef WITH_OPENSSL'\n")
        os.chmod(sc_p, 0o755)
    # Add fake stunnel binary only in bin_stunnel
    st_bin = os.path.join(bin_stunnel, "stunnel")
    open(st_bin, "w").write("#!/bin/sh\nexit 0\n")
    os.chmod(st_bin, 0o755)

    # Generate valid temp cert/key
    crt_p = os.path.join(st_td, "tls.crt")
    key_p = os.path.join(st_td, "tls.key")
    fp_p = os.path.join(st_td, "tls.fingerprint")
    st_conf = os.path.join(st_td, "stunnel.conf")
    st_state_dir = os.path.join(st_td, "noc-console-tls")
    st_marker = os.path.join(st_state_dir, "tls.verified")
    st_runner = os.path.join(st_state_dir, "run_tls_proxy.sh")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key_p, "-out", crt_p, "-days", "1", "-subj", "/CN=test.lan"],
        check=True, capture_output=True,
    )
    fp_out = subprocess.run(["openssl", "x509", "-in", crt_p, "-noout", "-fingerprint", "-sha256"], check=True, capture_output=True, text=True).stdout
    open(fp_p, "w").write(fp_out)

    init_body = open(os.path.join(ROOT, "init.d", "noc-apid"), "r", encoding="utf-8").read()
    init_body = init_body.replace("#!/bin/sh /etc/rc.common", "#!/bin/sh")
    init_body = init_body.replace("TLS_CERT=/etc/noc-console/tls.crt", f"TLS_CERT={crt_p}")
    init_body = init_body.replace("TLS_KEY=/etc/noc-console/tls.key", f"TLS_KEY={key_p}")
    init_body = init_body.replace("TLS_FP=/etc/noc-console/tls.fingerprint", f"TLS_FP={fp_p}")
    init_body = init_body.replace("STUNNEL_CONF=/tmp/noc-console/stunnel.conf", f"STUNNEL_CONF={st_conf}")
    init_body = init_body.replace("TLS_STATE_DIR=/tmp/noc-console-tls", f"TLS_STATE_DIR={st_state_dir}")
    init_body = init_body.replace("TLS_MARKER=/tmp/noc-console-tls/tls.verified", f"TLS_MARKER={st_marker}")
    init_body = init_body.replace("TLS_RUNNER=/tmp/noc-console-tls/run_tls_proxy.sh", f"TLS_RUNNER={st_runner}")
    init_shim = os.path.join(st_td, "noc_apid_shim.sh")
    open(init_shim, "w", encoding="utf-8").write(init_body)

    procd_harness = (
        "procd_open_instance() { echo \"INST:$1\"; }\n"
        "procd_set_param() { echo \"PARAM:$*\"; }\n"
        "procd_close_instance() { echo \"CLOSE\"; }\n"
        "logger() { echo \"LOG:$*\"; }\n"
        "uci() { echo '192.168.1.1'; }\n"
        f". {init_shim}\n"
    )
    # 8a. #undef WITH_OPENSSL socat + no stunnel MUST fail closed (rc != 0, no noc_apid started)
    r_fail = subprocess.run(
        ["sh", "-c", procd_harness + "start_service"],
        env={"PATH": f"{bin_nossl}:/usr/bin:/bin"}, capture_output=True, text=True,
    )
    if r_fail.returncode != 0 and "INST:noc_apid" not in r_fail.stdout:
        ok("SEC-01-STUNNEL[undef_with_openssl_socat_fails_closed]")
    else:
        fail(f"SEC-01-STUNNEL[undef_with_openssl_socat_fails_closed]: rc={r_fail.returncode} out={r_fail.stdout}")

    # 8b. stunnel present alongside #undef WITH_OPENSSL socat -> selects stunnel, writes isolated 0600 conf, binds 127.0.0.1:8780 + 192.168.1.1:8743, cleans up on stop_service
    r_st = subprocess.run(
        ["sh", "-c", procd_harness + "start_service"],
        env={"PATH": f"{bin_stunnel}:/usr/bin:/bin"}, capture_output=True, text=True,
    )
    conf_txt = open(st_conf).read() if os.path.isfile(st_conf) else ""
    conf_mode = (os.stat(st_conf).st_mode & 0o777) if os.path.isfile(st_conf) else 0
    r_stop = subprocess.run(
        ["sh", "-c", procd_harness + "stop_service"],
        env={"PATH": f"{bin_stunnel}:/usr/bin:/bin"}, capture_output=True, text=True,
    )
    if (
        r_st.returncode == 0
        and "NOC_BIND_HOST=127.0.0.1" in r_st.stdout
        and "INST:noc_tls_proxy" in r_st.stdout
        and f"{st_bin} {st_conf}" in r_st.stdout
        and "foreground = yes" in conf_txt
        and "accept = 192.168.1.1:8743" in conf_txt
        and "connect = 127.0.0.1:8780" in conf_txt
        and conf_mode == 0o600
        and not os.path.exists(st_conf)
    ):
        ok("SEC-01-STUNNEL[isolated_stunnel_conf_procd_loopback_and_stop_cleanup]")
    else:
        fail(f"SEC-01-STUNNEL[isolated_stunnel_conf_procd_loopback_and_stop_cleanup]: rc={r_st.returncode} mode={oct(conf_mode)} exists_after_stop={os.path.exists(st_conf)} out={r_st.stdout}")

    # 8c. Corrupted TLS cert in unwritable dir (cannot regenerate) MUST fail closed even when stunnel is present
    bad_dir = os.path.join(st_td, "ro_certs")
    os.makedirs(bad_dir)
    bad_crt = os.path.join(bad_dir, "tls.crt")
    bad_key = os.path.join(bad_dir, "tls.key")
    bad_fp = os.path.join(bad_dir, "tls.fingerprint")
    open(bad_crt, "w").write("INVALID_PEM\n")
    open(bad_key, "w").write("INVALID_KEY\n")
    open(bad_fp, "w").write("INVALID_FP\n")
    os.chmod(bad_dir, 0o555)
    try:
        r_badc = subprocess.run(
            ["sh", "-c", procd_harness + f"TLS_CERT={bad_crt}; TLS_KEY={bad_key}; TLS_FP={bad_fp}; start_service"],
            env={"PATH": f"{bin_stunnel}:/usr/bin:/bin"}, capture_output=True, text=True,
        )
        if r_badc.returncode != 0 and "INST:noc_apid" not in r_badc.stdout:
            ok("SEC-01-STUNNEL[invalid_cert_fails_closed_even_with_stunnel]")
        else:
            fail(f"SEC-01-STUNNEL[invalid_cert_fails_closed_even_with_stunnel]: rc={r_badc.returncode} out={r_badc.stdout}")
    finally:
        os.chmod(bad_dir, 0o755)

    # 8d. OpenWrt UCI CIDR / multi-IP network.lan.ipaddr ("192.168.1.1/24 10.0.0.1/24") MUST strip /prefix for stunnel & SAN
    cidr_dir = os.path.join(st_td, "cidr_certs")
    os.makedirs(cidr_dir)
    cidr_crt = os.path.join(cidr_dir, "tls.crt")
    cidr_key = os.path.join(cidr_dir, "tls.key")
    cidr_fp = os.path.join(cidr_dir, "tls.fingerprint")
    cidr_conf = os.path.join(st_td, "stunnel_cidr.conf")
    cidr_harness = (
        "procd_open_instance() { echo \"INST:$1\"; }\n"
        "procd_set_param() { echo \"PARAM:$*\"; }\n"
        "procd_close_instance() { echo \"CLOSE\"; }\n"
        "logger() { echo \"LOG:$*\"; }\n"
        "uci() { case \"$*\" in *network.lan.ipaddr*) echo '192.168.1.1/24 10.0.0.1/24' ;; *) echo 'nms-router' ;; esac; }\n"
        f". {init_shim}\n"
        f"TLS_CERT={cidr_crt}; TLS_KEY={cidr_key}; TLS_FP={cidr_fp}; STUNNEL_CONF={cidr_conf}; start_service\n"
    )
    r_cidr = subprocess.run(
        ["sh", "-c", cidr_harness],
        env={"PATH": f"{bin_stunnel}:/usr/bin:/bin"}, capture_output=True, text=True,
    )
    cidr_conf_txt = open(cidr_conf).read() if os.path.isfile(cidr_conf) else ""
    cert_txt = ""
    if os.path.isfile(cidr_crt):
        cert_txt = subprocess.run(["openssl", "x509", "-in", cidr_crt, "-noout", "-text"], capture_output=True, text=True).stdout
    if (
        r_cidr.returncode == 0
        and "accept = 192.168.1.1:8743" in cidr_conf_txt
        and "/24" not in cidr_conf_txt
        and "IP Address:192.168.1.1" in cert_txt
    ):
        ok("SEC-01-STUNNEL[cidr_and_multi_ip_lan_ipaddr_stripped]")
    else:
        fail(f"SEC-01-STUNNEL[cidr_and_multi_ip_lan_ipaddr_stripped]: rc={r_cidr.returncode} conf={cidr_conf_txt!r}")

    # 8e. SEC-01-TLS-ACTIVE & SEC-01-TLS-LIFECYCLE (8 tests):
    # - pre-listener readiness gate (no verified marker before listener binds HTTPS_PORT)
    # - root-owned TLS marker without private key & forged/leaked rejection
    # - auth_status tls_active:true
    # - login cookie ; Secure flag
    # - HTTPS Origin accepted & HTTP Origin rejected
    # - insecure HTTP mode isolation
    # - stunnel crash/stop immediately deactivates tls_active (zero stale window + marker cleanup)
    # - stunnel restart restores tls_active:true while keeping private key isolated
    https_live_p = free_port()
    live_harness = (
        "procd_open_instance() { echo \"INST:$1\"; }\n"
        "procd_set_param() { echo \"PARAM:$*\"; }\n"
        "procd_close_instance() { echo \"CLOSE\"; }\n"
        "logger() { echo \"LOG:$*\"; }\n"
        "uci() { case \"$*\" in *network.lan.ipaddr*) echo '192.168.1.1/24' ;; *) echo 'nms-router' ;; esac; }\n"
        f". {init_shim}\n"
        f"TLS_CERT={cidr_crt}; TLS_KEY={cidr_key}; TLS_FP={cidr_fp}; STUNNEL_CONF={cidr_conf}; HTTPS_PORT={https_live_p}; start_service\n"
    )
    r_prep = subprocess.run(
        ["sh", "-c", live_harness],
        env={"PATH": f"{bin_stunnel}:/usr/bin:/bin"}, capture_output=True, text=True,
    )
    # Verify marker does NOT exist after start_service before run_tls_proxy.sh starts a live listener
    marker_absent_before_listen = (
        r_prep.returncode == 0
        and os.path.isfile(st_runner)
        and os.path.isfile(os.path.join(st_state_dir, "tls.crt"))
        and not os.path.exists(os.path.join(st_state_dir, "tls.key"))
        and not os.path.exists(st_marker)
    )
    # Also verify run_tls_proxy.sh fails closed without writing marker if child exits without listening
    r_bad_child = subprocess.run([st_runner, "sh", "-c", "exit 1"], capture_output=True, text=True, timeout=5)
    if marker_absent_before_listen and r_bad_child.returncode != 0 and not os.path.exists(st_marker):
        ok("SEC-01-TLS-LIFECYCLE[no_verified_marker_before_listener_ready]")
    else:
        fail(f"SEC-01-TLS-LIFECYCLE[no_verified_marker_before_listener_ready]: prep={marker_absent_before_listen} bad_rc={r_bad_child.returncode} exists={os.path.exists(st_marker)}")

    apid_src_full = open(os.path.join(ROOT, "backend", "noc-apid"), "r", encoding="utf-8").read()
    m_tls_fn = re.search(r"(const TLS_CERT_PATH = .*?function is_tls_active\(\) \{.*?\n\})", apid_src_full, re.S)
    m_lan_fn = re.search(r"(function get_lan_ip\(\) \{.*?\n\})", apid_src_full, re.S)
    m_orig_fn = re.search(r"(function is_origin_allowed\(headers, require_present\) \{.*?\n\})", apid_src_full, re.S)
    m_auth_st = re.search(r"(\tif \(action == 'auth_status'\) \{.*?\n\t\treturn;\n\t\})", apid_src_full, re.S)
    m_auth_lg = re.search(r"(\tif \(action == 'auth_login' && method == 'POST'\) \{.*?\n\t\treturn;\n\t\})", apid_src_full, re.S)
    m_auth_act = re.search(r"(\t\tif \(action == 'auth_admin'\) \{.*?\n\t\t\treturn;\n\t\t\})", apid_src_full, re.S)
    assert all((m_tls_fn, m_lan_fn, m_orig_fn, m_auth_st, m_auth_lg, m_auth_act)), "Failed to extract noc-apid TLS/auth handlers"

    rfs_25 = "/tmp/openwrt-x86-64-rootfs"
    if os.path.isdir(rfs_25) and os.path.isfile(os.path.join(rfs_25, "usr/bin/ucode")):
        uc_stage = os.path.join(rfs_25, "tmp", "tls_active_test")
        if os.path.exists(uc_stage):
            shutil.rmtree(uc_stage, ignore_errors=True)
        os.makedirs(uc_stage, exist_ok=True)
        listener_py = os.path.join(st_td, "dummy_tls_listener.py")
        open(listener_py, "w", encoding="utf-8").write(
            "import signal, socket, sys, time\n"
            "signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "s.bind(('127.0.0.1', int(sys.argv[1])))\n"
            "s.listen(8)\n"
            "while True:\n"
            "    time.sleep(0.2)\n"
        )
        conflict_child_py = os.path.join(st_td, "conflict_tls_child.py")
        open(conflict_child_py, "w", encoding="utf-8").write(
            "import socket, sys, time\n"
            "# Stay alive briefly while another process already holds the port, then fail on bind\n"
            "time.sleep(0.25)\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.bind(('127.0.0.1', int(sys.argv[1])))\n"
        )
        sup_proc = None
        foreign_proc = None
        try:
            # Test 0b: Pre-existing independent listener occupying https_live_p MUST NOT trick run_tls_proxy.sh into writing tls.verified
            foreign_proc = subprocess.Popen([sys.executable, listener_py, str(https_live_p)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(0.15)
            r_conflict = subprocess.run([st_runner, sys.executable, conflict_child_py, str(https_live_p)], capture_output=True, text=True, timeout=5)
            foreign_rejected = (r_conflict.returncode != 0 and not os.path.exists(st_marker))
            foreign_proc.terminate()
            foreign_proc.wait(timeout=3)
            foreign_proc = None
            if foreign_rejected:
                ok("SEC-01-TLS-LIFECYCLE[preexisting_foreign_listener_on_port_rejected]")
            else:
                fail(f"SEC-01-TLS-LIFECYCLE[preexisting_foreign_listener_on_port_rejected]: rc={r_conflict.returncode} marker_exists={os.path.exists(st_marker)}")

            # Start real run_tls_proxy.sh supervising the TCP listener on https_live_p
            sup_proc = subprocess.Popen([st_runner, sys.executable, listener_py, str(https_live_p)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for _ in range(40):
                if os.path.isfile(st_marker):
                    break
                time.sleep(0.05)
            assert os.path.isfile(st_marker), "run_tls_proxy.sh did not create tls.verified after listener started"
            m_pid1 = re.search(r"^pid=([0-9]+)$", open(st_marker).read(), re.M)
            m_ino1 = re.search(r"^inode=([1-9][0-9]*)$", open(st_marker).read(), re.M)
            assert m_pid1 and m_ino1, f"missing pid/inode in {open(st_marker).read()!r}"
            child_pid1 = int(m_pid1.group(1))
            inode1 = m_ino1.group(1)

            # Spawn a separate live process that does NOT own socket:[inode1]
            non_owner_proc = subprocess.Popen([sys.executable, "-c", "import time\nwhile True: time.sleep(0.5)\n"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # Copy marker dir created by run_tls_proxy.sh into chroot /tmp/tls_active_test/marker_ok
            mk_ok_dir = os.path.join(uc_stage, "marker_ok")
            shutil.copytree(st_state_dir, mk_ok_dir)
            os.chmod(mk_ok_dir, 0o755)
            os.chmod(os.path.join(mk_ok_dir, "tls.verified"), 0o644)
            os.chmod(os.path.join(mk_ok_dir, "tls.crt"), 0o644)

            # Create marker dir where pid is alive (non_owner_proc) and inode1 is actively listening on https_live_p,
            # BUT pid does NOT own socket:[inode1] in /proc/<pid>/fd!
            mk_non_owner_dir = os.path.join(uc_stage, "marker_non_owner_pid")
            shutil.copytree(st_state_dir, mk_non_owner_dir)
            os.chmod(mk_non_owner_dir, 0o755)
            open(os.path.join(mk_non_owner_dir, "tls.verified"), "w").write(
                f"verified=1\nengine=stunnel\npid={non_owner_proc.pid}\ninode={inode1}\nlan_ip=192.168.1.1\nhttps_port={https_live_p}\n"
            )
            os.chmod(os.path.join(mk_non_owner_dir, "tls.verified"), 0o644)

            # Create forged marker dir (world-writable 0777, simulating noc-api writable dir)
            mk_forged_dir = os.path.join(uc_stage, "marker_forged")
            shutil.copytree(st_state_dir, mk_forged_dir)
            os.chmod(mk_forged_dir, 0o777)

            # Create marker dir that illegally leaks tls.key
            mk_leak_dir = os.path.join(uc_stage, "marker_leak")
            shutil.copytree(st_state_dir, mk_leak_dir)
            os.chmod(mk_leak_dir, 0o755)
            open(os.path.join(mk_leak_dir, "tls.key"), "w").write("LEAKED_KEY\n")

            uc_driver = (
                "import * as fs from 'fs';\n"
                "let uci = { cursor: () => ({ get: (p, s, o) => '192.168.1.1/24' }) };\n"
                "function get_sys_hostname() { return 'OpenWrt'; }\n"
                "let _ur_seq = 0;\n"
                "function urandom_hex(n) { _ur_seq++; return sprintf('%032x', _ur_seq); }\n"
                "let sessions = {};\n"
                "function get_session(h) { return null; }\n"
                "function call_helper(verb, params, actor, ip, cb) {\n"
                "  if (verb == 'auth_status') cb({ ok: true, initialized: true });\n"
                "  else if (verb == 'auth_login') cb({ ok: true, username: 'admin', role: 'admin' });\n"
                "  else if (verb == 'auth_change_password') cb({ ok: true, invalidate_sessions: true });\n"
                "}\n"
                "function eval_instance(e) {\n"
                "  function getenv(k) { return e[k]; }\n"
                "  let BIND_HOST = getenv('NOC_BIND_HOST') || '';\n"
                "  let BIND_PORT = +(getenv('NOC_HTTP_PORT') || 8780);\n"
                "  let HTTPS_PORT = +(getenv('NOC_HTTPS_PORT') || 8743);\n"
                "  let STAGING_MODE = false;\n"
                + m_tls_fn.group(1) + "\n"
                + m_lan_fn.group(1) + "\n"
                + m_orig_fn.group(1) + "\n"
                "  function dispatch(action, method, headers, body) {\n"
                "    let cli = { status: 0, data: null, errs: [], hdrs: {} };\n"
                "    let req_id = 'r1'; let remote_ip = '127.0.0.1'; let query = { action: action };\n"
                "    function send_json_env(c, st, res, d, er, h) { c.status = st; c.data = d; c.errs = er; c.hdrs = h || {}; }\n"
                "    (function() {\n"
                "    let remote_ip = '127.0.0.1';\n"
                "    let ck_h = headers['cookie'] || '';\n"
                "    let m_sid = match(ck_h, /noc_session=([^;]+)/);\n"
                "    let sess = m_sid ? sessions[m_sid[1]] : null;\n"
                "    if (action == 'services') { send_json_env(cli, sess ? 200 : 401, 'services', { ok: !!sess }, []); return; }\n"
                + m_auth_st.group(1) + "\n"
                + m_auth_lg.group(1) + "\n"
                + m_auth_act.group(1) + "\n"
                "    })();\n"
                "    return cli;\n"
                "  }\n"
                "  return { is_tls_active: is_tls_active, lan_ip: get_lan_ip(), is_origin_allowed: is_origin_allowed, dispatch: dispatch };\n"
                "}\n"
                f"let HP = '{https_live_p}';\n"
                "// Test 1: Verify TLS without private key (/etc/noc-console inaccessible) & reject forged/leaked markers\n"
                "let inst_ok = eval_instance({\n"
                "  NOC_BIND_HOST: '127.0.0.1', NOC_HTTP_PORT: '8780', NOC_HTTPS_PORT: HP,\n"
                "  NOC_LAN_IP: '192.168.1.1', NOC_TLS_VERIFIED: '1',\n"
                "  NOC_TLS_MARKER: '/tmp/tls_active_test/marker_ok/tls.verified',\n"
                "  NOC_TLS_CERT: '/etc/noc-console-noaccess/tls.crt',\n"
                "  NOC_TLS_KEY: '/etc/noc-console-noaccess/tls.key'\n"
                "});\n"
                "let inst_forged_perm = eval_instance({\n"
                "  NOC_BIND_HOST: '127.0.0.1', NOC_HTTPS_PORT: HP, NOC_TLS_VERIFIED: '1',\n"
                "  NOC_TLS_MARKER: '/tmp/tls_active_test/marker_forged/tls.verified',\n"
                "  NOC_TLS_CERT: '/etc/noc-console-noaccess/tls.crt', NOC_TLS_KEY: '/etc/noc-console-noaccess/tls.key'\n"
                "});\n"
                "let inst_forged_uid = eval_instance({\n"
                "  NOC_BIND_HOST: '127.0.0.1', NOC_HTTPS_PORT: HP, NOC_TLS_VERIFIED: '1', NOC_TLS_MARKER_UID: '999',\n"
                "  NOC_TLS_MARKER: '/tmp/tls_active_test/marker_ok/tls.verified',\n"
                "  NOC_TLS_CERT: '/etc/noc-console-noaccess/tls.crt', NOC_TLS_KEY: '/etc/noc-console-noaccess/tls.key'\n"
                "});\n"
                "let inst_leak = eval_instance({\n"
                "  NOC_BIND_HOST: '127.0.0.1', NOC_HTTPS_PORT: HP, NOC_TLS_VERIFIED: '1',\n"
                "  NOC_TLS_MARKER: '/tmp/tls_active_test/marker_leak/tls.verified',\n"
                "  NOC_TLS_CERT: '/etc/noc-console-noaccess/tls.crt', NOC_TLS_KEY: '/etc/noc-console-noaccess/tls.key'\n"
                "});\n"
                "let inst_non_owner = eval_instance({\n"
                "  NOC_BIND_HOST: '127.0.0.1', NOC_HTTP_PORT: '8780', NOC_HTTPS_PORT: HP,\n"
                "  NOC_LAN_IP: '192.168.1.1', NOC_TLS_VERIFIED: '1',\n"
                "  NOC_TLS_MARKER: '/tmp/tls_active_test/marker_non_owner_pid/tls.verified',\n"
                "  NOC_TLS_CERT: '/etc/noc-console-noaccess/tls.crt', NOC_TLS_KEY: '/etc/noc-console-noaccess/tls.key'\n"
                "});\n"
                "// Also test direct /proc/self/fd readlink where process is alive + same userns + matching starttime, but does NOT own socket:[inode]\n"
                "let self_stat = fs.readfile('/proc/self/stat') || '';\n"
                "let self_pid = split(trim(self_stat), /[[:space:]]+/)[0];\n"
                "let self_st = split(replace(trim(self_stat), /^.*\\)[[:space:]]+/, ''), /[[:space:]]+/)[19];\n"
                "let ok_mtxt = fs.readfile('/tmp/tls_active_test/marker_ok/tls.verified') || '';\n"
                "let ok_ino = match(ok_mtxt, /(^|\\n)inode=([1-9][0-9]*)(\\n|$)/)[2];\n"
                "fs.writefile('/tmp/tls_active_test/marker_non_owner_pid/tls.verified', sprintf('verified=1\\nengine=stunnel\\npid=%s\\nstarttime=%s\\ninode=%s\\nlan_ip=192.168.1.1\\nhttps_port=%s\\n', self_pid, self_st, ok_ino, HP));\n"
                "let st_non_owner = inst_non_owner.dispatch('auth_status', 'GET', {}, {});\n"
                "if (!inst_ok.is_tls_active() || inst_forged_perm.is_tls_active() || inst_forged_uid.is_tls_active() || inst_leak.is_tls_active()) exit(11);\n"
                "if (inst_non_owner.is_tls_active() || st_non_owner.data.tls_active !== false) exit(17);\n"
                "print('PASS_NON_OWNER_PID\\n');\n"
                "print('PASS_T1\\n');\n"
                "// Test 2: auth_status reports tls_active: true and transport: https_tls\n"
                "let st_res = inst_ok.dispatch('auth_status', 'GET', {}, {});\n"
                "if (st_res.status != 200 || st_res.data.tls_active !== true || st_res.data.transport != 'https_tls') exit(12);\n"
                "print('PASS_T2\\n');\n"
                "// Test 3: Login Set-Cookie contains ; Secure\n"
                "let lg_res = inst_ok.dispatch('auth_login', 'POST', { origin: 'https://192.168.1.1:' + HP }, { username: 'admin', password: 'pw' });\n"
                "let ck = lg_res.hdrs['Set-Cookie'] || '';\n"
                "if (lg_res.status != 200 || index(ck, '; Secure') < 0 || index(ck, 'HttpOnly') < 0 || index(ck, 'SameSite=Strict') < 0) exit(13);\n"
                "print('PASS_T3\\n');\n"
                "// Test 4: Origin check accepts https://192.168.1.1:<HP> and rejects http:// origins when TLS is active\n"
                "let lg_http_orig = inst_ok.dispatch('auth_login', 'POST', { origin: 'http://192.168.1.1:8780' }, { username: 'admin', password: 'pw' });\n"
                "let lg_http_hp = inst_ok.dispatch('auth_login', 'POST', { origin: 'http://192.168.1.1:' + HP }, { username: 'admin', password: 'pw' });\n"
                "let lg_loop_orig = inst_ok.dispatch('auth_login', 'POST', { origin: 'https://127.0.0.1:' + HP }, { username: 'admin', password: 'pw' });\n"
                "if (lg_http_orig.status != 403 || lg_http_hp.status != 403 || lg_loop_orig.status != 403) exit(14);\n"
                "print('PASS_T4\\n');\n"
                "// Test 4b: Real noc-apid session invalidation on auth_change_password\n"
                "let lg_a = inst_ok.dispatch('auth_login', 'POST', { origin: 'https://192.168.1.1:' + HP }, { username: 'admin', password: 'pw' });\n"
                "let lg_b = inst_ok.dispatch('auth_login', 'POST', { origin: 'https://192.168.1.1:' + HP }, { username: 'admin', password: 'pw' });\n"
                "let ck_a = split(lg_a.hdrs['Set-Cookie'] || '', ';')[0];\n"
                "let ck_b = split(lg_b.hdrs['Set-Cookie'] || '', ';')[0];\n"
                "if (ck_a == ck_b) { print('SAME_COOKIE\\n'); exit(144); }\n"
                "let chg_res = inst_ok.dispatch('auth_admin', 'POST', { origin: 'https://192.168.1.1:' + HP, cookie: ck_a, 'x-csrf-token': lg_a.data.csrf_token || '' }, { subaction: 'change_password', password: 'NewPassword#2026' });\n"
                "if (chg_res.status != 200) exit(141);\n"
                "let svc_b = inst_ok.dispatch('services', 'GET', { cookie: ck_b }, {});\n"
                "if (svc_b.status != 401) { print('SVC_B_STATUS=' + svc_b.status + '\\n'); exit(142); }\n"
                "let svc_a = inst_ok.dispatch('services', 'GET', { cookie: ck_a }, {});\n"
                "if (svc_a.status != 200) exit(143);\n"
                "print('PASS_T4B_SESS_INV\\n');\n"
                "// Test 5: Insecure HTTP mode is never treated as HTTPS\n"
                "let inst_http = eval_instance({\n"
                "  NOC_BIND_HOST: '192.168.1.1', NOC_LAN_IP: '192.168.1.1', NOC_HTTP_PORT: '8780', NOC_HTTPS_PORT: HP,\n"
                "  NOC_TLS_VERIFIED: '0', NOC_TLS_MARKER: '/tmp/tls_active_test/nonexistent/tls.verified',\n"
                "  NOC_TLS_CERT: '/etc/noc-console-noaccess/tls.crt', NOC_TLS_KEY: '/etc/noc-console-noaccess/tls.key'\n"
                "});\n"
                "let st_http = inst_http.dispatch('auth_status', 'GET', {}, {});\n"
                "let lg_http_ok = inst_http.dispatch('auth_login', 'POST', { origin: 'http://192.168.1.1:8780' }, { username: 'admin', password: 'pw' });\n"
                "let lg_https_on_http = inst_http.dispatch('auth_login', 'POST', { origin: 'https://192.168.1.1:' + HP }, { username: 'admin', password: 'pw' });\n"
                "if (inst_http.is_tls_active() || st_http.data.tls_active !== false || st_http.data.transport != 'http_lan_only') exit(15);\n"
                "if (lg_http_ok.status != 200 || index(lg_http_ok.hdrs['Set-Cookie'] || '', 'Secure') >= 0 || lg_https_on_http.status != 403) exit(16);\n"
                "print('PASS_T5\\n');\n"
            )
            open(os.path.join(uc_stage, "run_tls_active.uc"), "w", encoding="utf-8").write(uc_driver)
            r_uc = subprocess.run(
                ["unshare", "-rm", "sh", "-c", f"mount --rbind /proc {rfs_25}/proc && exec /usr/sbin/chroot {rfs_25} /usr/bin/ucode /tmp/tls_active_test/run_tls_active.uc"],
                capture_output=True, text=True, timeout=15,
            )
            no_key_in_marker = not os.path.exists(os.path.join(st_state_dir, "tls.key"))
            for tag, desc in (
                ("PASS_NON_OWNER_PID", "SEC-01-TLS-LIFECYCLE[live_process_not_owning_socket_inode_rejected]"),
                ("PASS_T1", "SEC-01-TLS-ACTIVE[verify_without_private_key_and_reject_forged_marker]"),
                ("PASS_T2", "SEC-01-TLS-ACTIVE[auth_status_reports_tls_active_true]"),
                ("PASS_T3", "SEC-01-TLS-ACTIVE[login_cookie_contains_secure_flag]"),
                ("PASS_T4", "SEC-01-TLS-ACTIVE[https_origin_accepted_and_http_origin_rejected]"),
                ("PASS_T5", "SEC-01-TLS-ACTIVE[insecure_http_never_treated_as_https]"),
            ):
                if r_uc.returncode == 0 and tag in r_uc.stdout and no_key_in_marker:
                    ok(desc)
                else:
                    fail(f"{desc}: rc={r_uc.returncode} out={r_uc.stdout} err={r_uc.stderr}")

            # Test 6: Crash/kill the supervised TLS proxy child process -> st_marker is removed by run_tls_proxy.sh AND even a stale marker on disk (even if a foreign listener grabs the port!) evaluates tls_active == false immediately
            os.kill(child_pid1, 9)
            sup_proc.wait(timeout=5)
            marker_removed_on_crash = not os.path.exists(st_marker)
            # Start an unrelated foreign listener on https_live_p and forge pid=foreign_proc.pid in stale marker while keeping old inode (or vice versa):
            foreign_proc = subprocess.Popen([sys.executable, listener_py, str(https_live_p)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(0.15)
            mk_foreign_inode_dir = os.path.join(uc_stage, "marker_foreign_inode")
            shutil.copytree(mk_ok_dir, mk_foreign_inode_dir)
            os.chmod(mk_foreign_inode_dir, 0o755)
            # Even if pid in marker points to a live process, its socket inode (999999999) does NOT match the foreign listener's inode on https_live_p!
            open(os.path.join(mk_foreign_inode_dir, "tls.verified"), "w").write(
                f"verified=1\nengine=stunnel\npid={foreign_proc.pid}\ninode=999999999\nlan_ip=192.168.1.1\nhttps_port={https_live_p}\n"
            )
            os.chmod(os.path.join(mk_foreign_inode_dir, "tls.verified"), 0o644)
            uc_crash_check = (
                uc_driver.split("// Test 1:")[0]
                + f"let HP = '{https_live_p}';\n"
                "let inst_stale = eval_instance({\n"
                "  NOC_BIND_HOST: '127.0.0.1', NOC_HTTP_PORT: '8780', NOC_HTTPS_PORT: HP,\n"
                "  NOC_LAN_IP: '192.168.1.1', NOC_TLS_VERIFIED: '1',\n"
                "  NOC_TLS_MARKER: '/tmp/tls_active_test/marker_ok/tls.verified',\n"
                "  NOC_TLS_CERT: '/etc/noc-console-noaccess/tls.crt', NOC_TLS_KEY: '/etc/noc-console-noaccess/tls.key'\n"
                "});\n"
                "let inst_foreign_ino = eval_instance({\n"
                "  NOC_BIND_HOST: '127.0.0.1', NOC_HTTP_PORT: '8780', NOC_HTTPS_PORT: HP,\n"
                "  NOC_LAN_IP: '192.168.1.1', NOC_TLS_VERIFIED: '1',\n"
                "  NOC_TLS_MARKER: '/tmp/tls_active_test/marker_foreign_inode/tls.verified',\n"
                "  NOC_TLS_CERT: '/etc/noc-console-noaccess/tls.crt', NOC_TLS_KEY: '/etc/noc-console-noaccess/tls.key'\n"
                "});\n"
                "let st_after_crash = inst_stale.dispatch('auth_status', 'GET', {}, {});\n"
                "let lg_after_crash = inst_stale.dispatch('auth_login', 'POST', { origin: 'https://192.168.1.1:' + HP }, { username: 'admin', password: 'pw' });\n"
                "if (inst_stale.is_tls_active() || inst_foreign_ino.is_tls_active() || st_after_crash.data.tls_active !== false || lg_after_crash.status != 403) exit(21);\n"
                "print('PASS_CRASH_DEACTIVATED\\n');\n"
            )
            open(os.path.join(uc_stage, "run_tls_crash.uc"), "w", encoding="utf-8").write(uc_crash_check)
            r_crash = subprocess.run(
                ["unshare", "-rm", "sh", "-c", f"mount --rbind /proc {rfs_25}/proc && exec /usr/sbin/chroot {rfs_25} /usr/bin/ucode /tmp/tls_active_test/run_tls_crash.uc"],
                capture_output=True, text=True, timeout=15,
            )
            foreign_proc.terminate()
            foreign_proc.wait(timeout=3)
            foreign_proc = None
            if marker_removed_on_crash and r_crash.returncode == 0 and "PASS_CRASH_DEACTIVATED" in r_crash.stdout:
                ok("SEC-01-TLS-LIFECYCLE[stunnel_crash_immediately_deactivates_tls_active]")
            else:
                fail(f"SEC-01-TLS-LIFECYCLE[stunnel_crash_immediately_deactivates_tls_active]: removed={marker_removed_on_crash} rc={r_crash.returncode} out={r_crash.stdout} err={r_crash.stderr}")

            # Test 7: Restart run_tls_proxy.sh (simulating procd respawn) -> recreates marker with new PID, restores tls_active:true while keeping tls.key isolated
            sup_proc = subprocess.Popen([st_runner, sys.executable, listener_py, str(https_live_p)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for _ in range(40):
                if os.path.isfile(st_marker):
                    break
                time.sleep(0.05)
            m_pid2 = re.search(r"^pid=([0-9]+)$", open(st_marker).read(), re.M) if os.path.isfile(st_marker) else None
            m_ino2 = re.search(r"^inode=([1-9][0-9]*)$", open(st_marker).read(), re.M) if os.path.isfile(st_marker) else None
            child_pid2 = int(m_pid2.group(1)) if m_pid2 else -1
            inode2 = m_ino2.group(1) if m_ino2 else "0"
            shutil.copy2(st_marker, os.path.join(mk_ok_dir, "tls.verified"))
            os.chmod(os.path.join(mk_ok_dir, "tls.verified"), 0o644)
            open(os.path.join(mk_non_owner_dir, "tls.verified"), "w").write(
                f"verified=1\nengine=stunnel\npid={non_owner_proc.pid}\ninode={inode2}\nlan_ip=192.168.1.1\nhttps_port={https_live_p}\n"
            )
            os.chmod(os.path.join(mk_non_owner_dir, "tls.verified"), 0o644)
            r_recover = subprocess.run(
                ["unshare", "-rm", "sh", "-c", f"mount --rbind /proc {rfs_25}/proc && exec /usr/sbin/chroot {rfs_25} /usr/bin/ucode /tmp/tls_active_test/run_tls_active.uc"],
                capture_output=True, text=True, timeout=15,
            )
            non_owner_proc.terminate()
            non_owner_proc.wait(timeout=3)
            if (
                child_pid2 > 0
                and child_pid2 != child_pid1
                and r_recover.returncode == 0
                and "PASS_T2" in r_recover.stdout
                and "PASS_T3" in r_recover.stdout
                and "PASS_T4" in r_recover.stdout
                and not os.path.exists(os.path.join(st_state_dir, "tls.key"))
            ):
                ok("SEC-01-TLS-LIFECYCLE[stunnel_restart_restores_tls_active_without_private_key]")
            else:
                fail(f"SEC-01-TLS-LIFECYCLE[stunnel_restart_restores_tls_active_without_private_key]: pid1={child_pid1} pid2={child_pid2} rc={r_recover.returncode}")

            # Test 8: SIGKILL supervisor (run_tls_proxy.sh) so cleanup trap cannot run and marker remains on disk,
            # while recorded TLS child stays alive but loses ownership of socket:[inode] (held open by a forked keeper process),
            # tested under EACCES on /proc/<pid>/fd (NOC_TEST_FORCE_FD_EACCES=1).
            sup_proc.terminate()
            sup_proc.wait(timeout=5)
            sup_proc = None
            handoff_py = os.path.join(st_td, "handoff_tls_child.py")
            handoff_drop_flag = os.path.join(st_td, "drop_fd.flag")
            if os.path.exists(handoff_drop_flag):
                os.unlink(handoff_drop_flag)
            open(handoff_py, "w", encoding="utf-8").write(
                "import os, socket, subprocess, sys, time\n"
                "port = int(sys.argv[1])\n"
                "flag_p = sys.argv[2]\n"
                "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
                "s.bind(('127.0.0.1', port))\n"
                "s.listen(8)\n"
                "os.set_inheritable(s.fileno(), True)\n"
                "keeper = subprocess.Popen([sys.executable, '-c', 'import time\\nwhile True: time.sleep(0.5)\\n'], close_fds=False)\n"
                "try:\n"
                "    while True:\n"
                "        if os.path.exists(flag_p) and s is not None:\n"
                "            s.close()\n"
                "            s = None\n"
                "        time.sleep(0.05)\n"
                "finally:\n"
                "    keeper.terminate()\n"
            )
            sup_proc = subprocess.Popen([st_runner, sys.executable, handoff_py, str(https_live_p), handoff_drop_flag], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for _ in range(40):
                if os.path.isfile(st_marker):
                    break
                time.sleep(0.05)
            assert os.path.isfile(st_marker), "run_tls_proxy.sh did not create marker for handoff test"
            m_hpid = re.search(r"^pid=([0-9]+)$", open(st_marker).read(), re.M)
            handoff_child_pid = int(m_hpid.group(1))
            shutil.copy2(st_marker, os.path.join(mk_ok_dir, "tls.verified"))
            os.chmod(os.path.join(mk_ok_dir, "tls.verified"), 0o644)

            # Kill the supervisor with SIGKILL so its trap cannot remove the marker!
            os.kill(sup_proc.pid, 9)
            sup_proc.wait(timeout=5)
            sup_proc = None
            # Instruct handoff_child_pid to close its socket fd while staying alive (keeper keeps socket:[inode] listening in /proc/net/tcp!)
            open(handoff_drop_flag, "w").write("1\n")
            time.sleep(0.15)
            assert os.path.exists(f"/proc/{handoff_child_pid}"), "handoff child should still be alive"

            uc_sigkill_sup = (
                uc_driver.split("// Test 1:")[0]
                + f"let HP = '{https_live_p}';\n"
                "let inst_eacces_stale = eval_instance({\n"
                "  NOC_BIND_HOST: '127.0.0.1', NOC_HTTP_PORT: '8780', NOC_HTTPS_PORT: HP,\n"
                "  NOC_LAN_IP: '192.168.1.1', NOC_TLS_VERIFIED: '1', NOC_TEST_FORCE_FD_EACCES: '1',\n"
                "  NOC_TLS_MARKER: '/tmp/tls_active_test/marker_ok/tls.verified',\n"
                "  NOC_TLS_CERT: '/etc/noc-console-noaccess/tls.crt', NOC_TLS_KEY: '/etc/noc-console-noaccess/tls.key'\n"
                "});\n"
                "let st_k = inst_eacces_stale.dispatch('auth_status', 'GET', {}, {});\n"
                "let lg_k_https = inst_eacces_stale.dispatch('auth_login', 'POST', { origin: 'https://192.168.1.1:' + HP }, { username: 'admin', password: 'pw' });\n"
                "let lg_k_http = inst_eacces_stale.dispatch('auth_login', 'POST', { origin: 'http://192.168.1.1:8780' }, { username: 'admin', password: 'pw' });\n"
                "let ck_k = lg_k_http.hdrs['Set-Cookie'] || '';\n"
                "if (inst_eacces_stale.is_tls_active() || st_k.data.tls_active !== false || lg_k_https.status != 403 || index(ck_k, 'Secure') >= 0) exit(31);\n"
                "print('PASS_SIGKILL_SUP_EACCES_CLOSED\\n');\n"
            )
            open(os.path.join(uc_stage, "run_sigkill_sup.uc"), "w", encoding="utf-8").write(uc_sigkill_sup)
            r_sk = subprocess.run(
                ["unshare", "-rm", "sh", "-c", f"mount --rbind /proc {rfs_25}/proc && exec /usr/sbin/chroot {rfs_25} /usr/bin/ucode /tmp/tls_active_test/run_sigkill_sup.uc"],
                capture_output=True, text=True, timeout=15,
            )
            # Clean up handoff_child_pid and its keeper child
            subprocess.run(["pkill", "-9", "-P", str(handoff_child_pid)], capture_output=True)
            kill_pid(handoff_child_pid)
            if r_sk.returncode == 0 and "PASS_SIGKILL_SUP_EACCES_CLOSED" in r_sk.stdout:
                ok("SEC-01-TLS-LIFECYCLE[sigkill_supervisor_and_child_loses_inode_under_eacces_deactivates_tls]")
            else:
                fail(f"SEC-01-TLS-LIFECYCLE[sigkill_supervisor_and_child_loses_inode_under_eacces_deactivates_tls]: rc={r_sk.returncode} out={r_sk.stdout} err={r_sk.stderr}")
        finally:
            if sup_proc is not None and sup_proc.poll() is None:
                sup_proc.terminate()
                try:
                    sup_proc.wait(timeout=3)
                except Exception:
                    sup_proc.kill()
            shutil.rmtree(uc_stage, ignore_errors=True)

# 7c. Regression test: noc-helperd firewall_read with forwarding rules on BOTH OpenWrt 24.10.0 & 25.12.6
m_helperd_fw = re.search(r"(\tif \(verb == 'firewall_read'\) \{.*?\n\t\treturn;\n\t\})", helperd_src, re.S)
if not m_helperd_fw:
    fail("P4F-API: failed to extract noc-helperd firewall_read")
else:
    fw_fn_src = m_helperd_fw.group(1)
    for ver_label, rfs in (("24.10.0-opkg", "/tmp/openwrt-24.10-x86-64-rootfs"), ("25.12.6-apk", "/tmp/openwrt-x86-64-rootfs")):
        if not (os.path.isdir(rfs) and os.path.isfile(os.path.join(rfs, "usr/bin/ucode"))):
            fail(f"FIREWALL-READ[{ver_label}]: required OpenWrt rootfs missing at {rfs}")
            continue
        fw_cfg_p = os.path.join(rfs, "etc", "config", "firewall")
        had_fw_cfg = os.path.isfile(fw_cfg_p)
        orig_fw_cfg = open(fw_cfg_p, "rb").read() if had_fw_cfg else None
        dst_fw_uc = os.path.join(rfs, "tmp", "test_firewall_read.uc")
        try:
            os.makedirs(os.path.dirname(fw_cfg_p), exist_ok=True)
            open(fw_cfg_p, "w", encoding="utf-8").write(
                "config defaults\n\toption input 'REJECT'\n\toption output 'ACCEPT'\n\toption forward 'REJECT'\n\n"
                "config zone\n\toption name 'lan'\n\toption input 'ACCEPT'\n\toption output 'ACCEPT'\n\toption forward 'ACCEPT'\n\n"
                "config forwarding\n\toption src 'lan'\n\toption dest 'wan'\n"
            )
            fw_test_uc = (
                "import * as real_uci from 'uci';\n"
                "import * as fs from 'fs';\n"
                "import * as ubus from 'ubus';\n"
                "let fail_fwd_uci = false;\n"
                "let uci = {\n"
                "  cursor: function() {\n"
                "    let c = real_uci.cursor();\n"
                "    return {\n"
                "      load: (pkg) => c.load(pkg),\n"
                "      get: (a, b, k) => c.get(a, b, k),\n"
                "      foreach: function(pkg, typ, cb) {\n"
                "        if (fail_fwd_uci && pkg == 'firewall' && typ == 'forwarding') die('simulated uci failure');\n"
                "        return c.foreach(pkg, typ, cb);\n"
                "      }\n"
                "    };\n"
                "  }\n"
                "};\n"
                "function exec_argv_async(exe, argv, t, cap, cb) { cb({ ok: true, output: '[]' }); }\n"
                "let got = null;\n"
                "function reply_cb(res) { got = res; }\n"
                "function run_verb(verb) {\n" + fw_fn_src + "\n  if (verb == 'ping_after') reply_cb({ ok: true, alive: true });\n}\n"
                "// 1. Normal firewall_read with forwarding rule\n"
                "run_verb('firewall_read');\n"
                "if (!got || !got.ok || type(got.forwardings) != 'array' || length(got.forwardings) != 1 || got.forwardings[0].src != 'lan' || got.forwardings[0].dest != 'wan') exit(1);\n"
                "// 2. Failing UCI forwardings MUST return ok:false error_code:'DEPENDENCY' (no silent ok:true with empty array) and MUST NOT crash helperd\n"
                "got = null;\n"
                "fail_fwd_uci = true;\n"
                "run_verb('firewall_read');\n"
                "if (!got || got.ok !== false || got.error_code != 'DEPENDENCY') exit(2);\n"
                "print('FW_READ_PASS\\n');\n"
            )
            open(dst_fw_uc, "w", encoding="utf-8").write(fw_test_uc)
            r_fw = subprocess.run(["unshare", "-r", "/usr/sbin/chroot", rfs, "/usr/bin/ucode", "/tmp/test_firewall_read.uc"], capture_output=True, text=True, timeout=10)
            if r_fw.returncode == 0 and "FW_READ_PASS" in r_fw.stdout:
                ok(f"FIREWALL-READ[{ver_label}]: noc-helperd firewall_read forwardings uci.cursor() + DEPENDENCY error verified")
            else:
                fail(f"FIREWALL-READ[{ver_label}]: rc={r_fw.returncode} err={r_fw.stderr}")
            # Real daemon survival test: spawn actual production backend/noc-helperd inside chroot,
            # send real UNIX socket RPC for firewall_read, then send real auth_status RPC to the SAME live PID
            helperd_chroot_p = os.path.join(rfs, "tmp", "test_noc_helperd")
            shutil.copy2(os.path.join(ROOT, "backend", "noc-helperd"), helperd_chroot_p)
            os.chmod(helperd_chroot_p, 0o755)
            os.makedirs(os.path.join(rfs, "usr", "libexec"), exist_ok=True)
            for mod_name in os.listdir(os.path.join(ROOT, "backend")):
                if mod_name.startswith("nms_") and mod_name.endswith(".uc"):
                    shutil.copy2(os.path.join(ROOT, "backend", mod_name), os.path.join(rfs, "usr", "libexec", mod_name))
            sock_rel = "/tmp/test_fw_helper.sock"
            sock_host = os.path.join(rfs, "tmp", "test_fw_helper.sock")
            if os.path.exists(sock_host):
                os.unlink(sock_host)
            env_hd = os.environ.copy()
            env_hd["NOC_SOCK_PATH"] = sock_rel
            env_hd["NOC_ETC_DIR"] = "/etc/noc-console"
            env_hd["NOC_RUN_DIR"] = "/tmp"
            os.makedirs(os.path.join(rfs, "etc", "noc-console"), exist_ok=True)
            rpc_client_uc = (
                "import * as sock from 'socket';\n"
                "function rpc(verb) {\n"
                "  let s = sock.create(sock.AF_UNIX, sock.SOCK_STREAM);\n"
                "  if (!s || !s.connect(sock.sockaddr({ path: '" + sock_rel + "' }))) die('connect failed');\n"
                "  s.send(sprintf('%J\\n', { verb: verb, params: {}, actor: 'admin', client_ip: '127.0.0.1' }));\n"
                "  let buf = '';\n"
                "  while (index(buf, '\\n') < 0) { let c = s.recv(65536); if (!c || length(c) == 0) break; buf += c; }\n"
                "  s.close();\n"
                "  return json(trim(buf));\n"
                "}\n"
                "let fw = rpc('firewall_read');\n"
                "if (!fw || !fw.ok || type(fw.forwardings) != 'array' || length(fw.forwardings) != 1 || fw.forwardings[0].src != 'lan' || fw.forwardings[0].dest != 'wan') die('fw_read failed');\n"
                "import * as fs from 'fs';\n"
                "fs.writefile('/etc/config/firewall', \"config 'unterminated_quote\\n\");\n"
                "let fw_err = rpc('firewall_read');\n"
                "if (!fw_err || fw_err.ok !== false || fw_err.error_code != 'DEPENDENCY') die('fw_read UCI failure did not return DEPENDENCY');\n"
                "let st = rpc('services_read');\n"
                "if (!st || !st.ok) die('subsequent services_read failed after UCI failure');\n"
                "print('REAL_HELPERD_SURVIVED\\n');\n"
            )
            client_uc_p = os.path.join(rfs, "tmp", "test_fw_rpc_client.uc")
            open(client_uc_p, "w", encoding="utf-8").write(rpc_client_uc)
            try:
                os.makedirs(os.path.join(rfs, "dev"), exist_ok=True)
                if not os.path.exists(os.path.join(rfs, "dev", "null")):
                    open(os.path.join(rfs, "dev", "null"), "w").close()
                open(os.path.join(rfs, "tmp", "hd_in"), "w").close()
                single_ns_cmd = (
                    "/usr/bin/ucode /tmp/test_noc_helperd </tmp/hd_in >/tmp/hd.log 2>&1 &\n"
                    "HPID=$!\n"
                    "i=0; while [ $i -lt 6 ] && [ ! -S " + sock_rel + " ]; do sleep 1; i=$((i+1)); done\n"
                    "/usr/bin/ucode /tmp/test_fw_rpc_client.uc\n"
                    "RC=$?\n"
                    "kill -0 $HPID || { echo 'HELPERD_DIED' >&2; RC=99; }\n"
                    "kill $HPID || true\n"
                    "wait $HPID || true\n"
                    "exit $RC\n"
                )
                r_rpc = subprocess.run(
                    ["unshare", "-r", "/usr/sbin/chroot", rfs, "/bin/sh", "-c", single_ns_cmd],
                    env=env_hd, capture_output=True, text=True, timeout=15,
                )
                if r_rpc.returncode == 0 and "REAL_HELPERD_SURVIVED" in r_rpc.stdout:
                    ok(f"FIREWALL-READ[{ver_label}]: real noc-helperd daemon survived firewall_read and served subsequent services_read RPC")
                else:
                    fail(f"FIREWALL-READ[{ver_label}]: real daemon test failed rc={r_rpc.returncode} out={r_rpc.stdout} err={r_rpc.stderr}")
            finally:
                for p_clean in (helperd_chroot_p, client_uc_p, sock_host, os.path.join(rfs, "tmp", "hd.log"), os.path.join(rfs, "tmp", "hd_in")):
                    if os.path.exists(p_clean):
                        os.unlink(p_clean)
        finally:
            if os.path.exists(dst_fw_uc):
                os.unlink(dst_fw_uc)
            if had_fw_cfg and orig_fw_cfg is not None:
                open(fw_cfg_p, "wb").write(orig_fw_cfg)
            elif os.path.exists(fw_cfg_p):
                os.unlink(fw_cfg_p)

# 8b. Credential Hygiene: Password Rotation & Session Invalidation Regression
print("\n=== 8b. Credential Hygiene: Password Rotation & Session Invalidation ===")
rfs_auth = "/tmp/openwrt-x86-64-rootfs"
if os.path.isdir(rfs_auth):
    hd_chroot_p = os.path.join(rfs_auth, "tmp", "noc-helperd-auth-test")
    cl_chroot_p = os.path.join(rfs_auth, "tmp", "auth_sess_client.uc")
    sock_in_chroot = "/tmp/noc_auth_sess.sock"
    sock_host_p = os.path.join(rfs_auth, "tmp", "noc_auth_sess.sock")
    etc_in_chroot = "/tmp/noc_auth_etc"
    etc_host_p = os.path.join(rfs_auth, "tmp", "noc_auth_etc")
    run_in_chroot = "/tmp/noc_auth_run"
    run_host_p = os.path.join(rfs_auth, "tmp", "noc_auth_run")
    os.makedirs(etc_host_p, exist_ok=True)
    os.makedirs(run_host_p, exist_ok=True)
    salt_hex_auth = "00" * 16
    dk_hex_auth = hashlib.pbkdf2_hmac("sha256", b"InitPass#2026", bytes.fromhex(salt_hex_auth), 100000).hex()
    open(os.path.join(etc_host_p, "auth.json"), "w").write(json.dumps({
        "version": 1,
        "alg": "pbkdf2-hmac-sha256",
        "iter": 100000,
        "users": {"admin": {"role": "admin", "salt_hex": salt_hex_auth, "dk_hex": dk_hex_auth}},
    }))
    open(hd_chroot_p, "w").write(
        open(os.path.join(ROOT, "backend", "noc-helperd"))
        .read()
        .replace("fs.statvfs(ETC_DIR)", "({ blocks: 10000, bavail: 10000, bsize: 4096 })")
        .replace("if (!acquire_lock(actor, verb).ok)", "if (false)")
    )
    uc_auth_script = f"""
import * as socket from 'socket';
function rpc(verb, params) {{
    let s = socket.connect({json.dumps(sock_in_chroot)});
    s.send(sprintf('%J\\n', {{ id: 1, verb: verb, params: params || {{}} }}));
    let buf = '';
    while (true) {{
        let c = s.recv(65536);
        if (!c || length(c) == 0) break;
        buf += c;
        if (index(buf, '\\n') >= 0) break;
    }}
    s.close();
    return json(buf);
}}
let r_lg1 = rpc('auth_login', {{ username: 'admin', password: 'InitPass#2026' }});
let r_lg2 = rpc('auth_login', {{ username: 'admin', password: 'InitPass#2026' }});
if (!r_lg1.ok || !r_lg2.ok) {{ print('FAIL:login\\n'); exit(1); }}
let sessions = {{}};
let sid_a = 'sid_A_1';
let sid_b = 'sid_B_2';
sessions[sid_a] = {{ id: sid_a, username: 'admin', role: 'admin' }};
sessions[sid_b] = {{ id: sid_b, username: 'admin', role: 'admin' }};
let r_chg = rpc('auth_change_password', {{ password: 'RotatedPass#2026' }});
if (!r_chg.ok || !r_chg.invalidate_sessions) {{ print('FAIL:chg\\n'); exit(1); }}
if (r_chg.ok && r_chg.invalidate_sessions) {{
    for (let k_sid in keys(sessions)) {{
        if (k_sid != sid_a) delete sessions[k_sid];
    }}
}}
if (exists(sessions, sid_b)) {{ print('FAIL:sess_b_still_valid\\n'); exit(1); }}
if (!exists(sessions, sid_a)) {{ print('FAIL:sess_a_invalidated\\n'); exit(1); }}
let r_old = rpc('auth_login', {{ username: 'admin', password: 'InitPass#2026' }});
if (r_old.ok) {{ print('FAIL:old_pw_accepted\\n'); exit(1); }}
let r_new = rpc('auth_login', {{ username: 'admin', password: 'RotatedPass#2026' }});
if (!r_new.ok) {{ print('FAIL:new_pw_rejected\\n'); exit(1); }}
print('AUTH_SESS_OK\\n');
"""
    open(cl_chroot_p, "w").write(uc_auth_script)
    r_auth = subprocess.run(
        [
            "sudo", "-n", "chroot", rfs_auth, "/bin/sh", "-c",
            f"NOC_ETC_DIR={etc_in_chroot} NOC_RUN_DIR={run_in_chroot} NOC_SOCK_PATH={sock_in_chroot} "
            f"/usr/bin/ucode /tmp/noc-helperd-auth-test >/tmp/hd_auth.log 2>&1 & "
            f"HPID=$!; i=0; while [ ! -S {sock_in_chroot} ] && [ $i -lt 5 ]; do sleep 1; i=$((i+1)); done; "
            f"/usr/bin/ucode /tmp/auth_sess_client.uc; RC=$?; if [ $RC -ne 0 ]; then cat /tmp/hd_auth.log >&2; fi; rm -rf /tmp/hd_auth.log {etc_in_chroot} {run_in_chroot} /tmp/noc-helperd-auth-test /tmp/auth_sess_client.uc {sock_in_chroot}; kill $HPID 2>/dev/null || true; wait $HPID 2>/dev/null || true; exit $RC"
        ],
        capture_output=True,
        text=True,
        timeout=45,
    )
    for p_clean in (hd_chroot_p, cl_chroot_p, sock_host_p):
        if os.path.exists(p_clean):
            os.unlink(p_clean)
    shutil.rmtree(etc_host_p, ignore_errors=True)
    shutil.rmtree(run_host_p, ignore_errors=True)
    if r_auth.returncode == 0 and "AUTH_SESS_OK" in r_auth.stdout:
        ok("AUTH-SESSION-INVALIDATION: auth_change_password invalidates other sessions, keeps current session, rejects old password, accepts new password")
    else:
        fail(f"AUTH-SESSION-INVALIDATION: rc={r_auth.returncode} out={r_auth.stdout.strip()} err={r_auth.stderr.strip()}")
else:
    fail(f"AUTH-SESSION-INVALIDATION: required OpenWrt rootfs missing at {rfs_auth}")

# 8c. Live /proc Validation (mounted procfs inside OpenWrt chroot)
print("\n=== 8c. Live /proc Validation ===")
if os.path.isdir(rfs_auth):
    expected_hn = open("/proc/sys/kernel/hostname", "r", encoding="utf-8").read().strip()
    r_proc = subprocess.run(
        [
            "sudo", "-n", "chroot", rfs_auth, "/bin/sh", "-c",
            "MOUNTED=0; cleanup() { if [ \"$MOUNTED\" = \"1\" ]; then umount /proc 2>/dev/null || true; fi; }; trap cleanup EXIT; "
            "mount -t proc proc /proc && MOUNTED=1 && "
            "/usr/bin/ucode -e \"import * as fs from 'fs'; "
            "let hn = trim(fs.readfile('/proc/sys/kernel/hostname') || ''); "
            "let nf = fs.readfile('/proc/sys/kernel/nonexistent_nms_test'); "
            "if (length(hn) == 0 || nf !== null) exit(1); "
            "print('PROC_OK=' + hn + '\\n');\""
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if r_proc.returncode == 0 and f"PROC_OK={expected_hn}" in r_proc.stdout:
        ok("LIVE-PROC-VALIDATION: mounted procfs readfile('/proc/sys/kernel/hostname') matches host kernel hostname and nonexistent path returns null")
    else:
        fail(f"LIVE-PROC-VALIDATION: rc={r_proc.returncode} out={r_proc.stdout.strip()} err={r_proc.stderr.strip()}")
else:
    fail(f"LIVE-PROC-VALIDATION: required OpenWrt rootfs missing at {rfs_auth}")

# 8d. Hostname Lifecycle: re-running enable-root-redirect.sh updates data-nms-sys-hostname and preserves LuCI backups
print("\n=== 8d. Hostname Lifecycle ===")
if os.path.isdir(rfs_auth):
    with tempfile.TemporaryDirectory(prefix="nms_hn_bak_") as td_bak:
        sys_cfg_p = os.path.join(rfs_auth, "etc", "config", "system")
        had_sys = os.path.exists(sys_cfg_p)
        if had_sys:
            shutil.copy2(sys_cfg_p, os.path.join(td_bak, "system"))
        www_p = os.path.join(rfs_auth, "www")
        had_www = os.path.isdir(www_p)
        if had_www:
            shutil.copytree(www_p, os.path.join(td_bak, "www"), symlinks=True)
        noc_cfg_p = os.path.join(rfs_auth, "etc", "noc-console")
        had_noc_cfg = os.path.isdir(noc_cfg_p)
        if had_noc_cfg:
            shutil.copytree(noc_cfg_p, os.path.join(td_bak, "noc-console"), symlinks=True)
        hn_src_dir = os.path.join(rfs_auth, "tmp", "nms_hn_src")
        try:
            if had_noc_cfg:
                shutil.rmtree(noc_cfg_p, ignore_errors=True)
            os.makedirs(os.path.join(hn_src_dir, "scripts"), exist_ok=True)
            shutil.copytree(os.path.join(ROOT, "frontend"), os.path.join(hn_src_dir, "frontend"), dirs_exist_ok=True)
            en_dst_p = os.path.join(hn_src_dir, "scripts", "enable-root-redirect.sh")
            shutil.copy2(os.path.join(ROOT, "scripts", "enable-root-redirect.sh"), en_dst_p)
            shutil.copy2(os.path.join(ROOT, "scripts", "luci_redirect_cgi.uc"), os.path.join(hn_src_dir, "scripts", "luci_redirect_cgi.uc"))
            os.makedirs(os.path.join(www_p, "cgi-bin"), exist_ok=True)
            os.makedirs(os.path.join(www_p, "pro"), exist_ok=True)
            os.makedirs(os.path.join(rfs_auth, "etc", "noc-console"), exist_ok=True)
            orig_luci = open(os.path.join(www_p, "cgi-bin", "luci"), "rb").read()
            orig_idx = open(os.path.join(www_p, "index.html"), "rb").read()
            open(sys_cfg_p, "w").write("config system\n\toption hostname 'alpha-gw'\n")
            cmd_hn = ["sudo", "-n", "chroot", rfs_auth, "/bin/sh", "-c", "NOC_SKIP_SERVICE_RESTART=1 sh /tmp/nms_hn_src/scripts/enable-root-redirect.sh"]
            r1 = subprocess.run(cmd_hn, capture_output=True, text=True, timeout=15)
            idx1 = open(os.path.join(www_p, "index.html"), "r", encoding="utf-8").read()
            open(sys_cfg_p, "w").write("config system\n\toption hostname 'beta-gw'\n")
            r2 = subprocess.run(cmd_hn, capture_output=True, text=True, timeout=15)
            r3 = subprocess.run(cmd_hn, capture_output=True, text=True, timeout=15)
            idx3 = open(os.path.join(www_p, "index.html"), "r", encoding="utf-8").read()
            bak_luci = open(os.path.join(www_p, "cgi-bin", "luci.orig.bak"), "rb").read() if os.path.exists(os.path.join(www_p, "cgi-bin", "luci.orig.bak")) else b""
            bak_idx = open(os.path.join(www_p, "index.luci.bak.html"), "rb").read() if os.path.exists(os.path.join(www_p, "index.luci.bak.html")) else b""
            if (
                r1.returncode == 0 and r2.returncode == 0 and r3.returncode == 0
                and 'data-nms-sys-hostname="alpha-gw"' in idx1
                and 'data-nms-sys-hostname="beta-gw"' in idx3
                and bak_luci == orig_luci and bak_idx == orig_idx
            ):
                ok("HOSTNAME-LIFECYCLE: enable-root-redirect.sh updates data-nms-sys-hostname idempotently and preserves original LuCI backups")
            else:
                fail(f"HOSTNAME-LIFECYCLE: r1={r1.returncode} r2={r2.returncode} r3={r3.returncode} bak_ok={bak_luci == orig_luci and bak_idx == orig_idx} err={r1.stderr.strip()}")
        finally:
            shutil.rmtree(hn_src_dir, ignore_errors=True)
            subprocess.run(["sudo", "-n", "rm", "-rf", www_p], capture_output=True)
            if had_www:
                shutil.copytree(os.path.join(td_bak, "www"), www_p, symlinks=True)
            subprocess.run(["sudo", "-n", "rm", "-rf", noc_cfg_p], capture_output=True)
            if had_noc_cfg:
                shutil.copytree(os.path.join(td_bak, "noc-console"), noc_cfg_p, symlinks=True)
            if had_sys:
                shutil.copy2(os.path.join(td_bak, "system"), sys_cfg_p)
            elif os.path.exists(sys_cfg_p):
                os.unlink(sys_cfg_p)
else:
    fail(f"HOSTNAME-LIFECYCLE: required OpenWrt rootfs missing at {rfs_auth}")

# 8e. Exception-Boundary & Race-Guard Verification (24.10.0-opkg & 25.12.6-apk)
print("\n=== 8e. Helperd Exception-Boundary & Race-Guard ===")
for ver_label, rfs_ex in (("24.10.0-opkg", "/tmp/openwrt-24.10-x86-64-rootfs"), ("25.12.6-apk", "/tmp/openwrt-x86-64-rootfs")):
    if os.path.isdir(rfs_ex):
        hd_ex_p = os.path.join(rfs_ex, "tmp", "noc-helperd-ex-test")
        cl_ex_p = os.path.join(rfs_ex, "tmp", "ex_client.uc")
        shutil.copy2(os.path.join(ROOT, "backend", "noc-helperd"), hd_ex_p)
        hd_ex_src = open(hd_ex_p, "r", encoding="utf-8").read()
        hd_ex_src = hd_ex_src.replace(
            "if (verb == 'services_read') {",
            "if (verb == '__inject_rpc_fault__') { let _x = null; _x.boom(); }\n\tif (verb == 'services_read') {",
            1,
        ).replace(
            "reconciler_tick_count++;",
            "reconciler_tick_count++;\n\t\tif (reconciler_tick_count == 1) { let _r = null; _r.boom(); }",
            1,
        )
        open(hd_ex_p, "w", encoding="utf-8").write(hd_ex_src)
        uc_ex_script = """
import * as socket from 'socket';
// 1. Isolated race/double-release guard test
let calls = 0;
let rel_calls = 0;
let settled = false;
function once_finish() {
    if (settled) return;
    settled = true;
    calls++;
    rel_calls++;
}
once_finish(); // timeout path
once_finish(); // late completion callback
if (calls != 1 || rel_calls != 1) { print('FAIL:race\\n'); exit(1); }

// 2. Real noc-helperd daemon survival after injected handle_rpc exception & reconciler_tick exception
let s1 = socket.connect('/tmp/noc_ex_test.sock');
s1.send('{"id":1,"verb":"__inject_rpc_fault__","params":{}}\n');
let b1 = '';
while (true) {
    let c = s1.recv(65536);
    if (!c || length(c) == 0) break;
    b1 += c;
    if (index(b1, '\\n') >= 0) break;
}
s1.close();
let j1 = json(b1);
if (!j1 || j1.ok || j1.error_code != 'INTERNAL') { print('FAIL:rpc_fault\\n'); exit(1); }
let s2 = socket.connect('/tmp/noc_ex_test.sock');
s2.send('{"id":2,"verb":"services_read","params":{}}\n');
let b2 = '';
while (true) {
    let c = s2.recv(65536);
    if (!c || length(c) == 0) break;
    b2 += c;
    if (index(b2, '\\n') >= 0) break;
}
s2.close();
let j2 = json(b2);
if (!j2 || !j2.ok) { print('FAIL:svc\\n'); exit(1); }
print('EX_BOUNDARY_OK\\n');
"""
        open(cl_ex_p, "w").write(uc_ex_script)
        r_ex = subprocess.run(
            [
                "sudo", "-n", "chroot", rfs_ex, "/bin/sh", "-c",
                "NOC_ETC_DIR=/tmp/noc_ex_etc NOC_RUN_DIR=/tmp/noc_ex_run NOC_SOCK_PATH=/tmp/noc_ex_test.sock "
                "/usr/bin/ucode /tmp/noc-helperd-ex-test >/tmp/hd_ex.log 2>&1 & "
                "HPID=$!; i=0; while [ ! -S /tmp/noc_ex_test.sock ] && [ $i -lt 5 ]; do sleep 1; i=$((i+1)); done; "
                "/usr/bin/ucode /tmp/ex_client.uc; RC=$?; "
                "if [ $RC -ne 0 ]; then cat /tmp/hd_ex.log >&2; fi; "
                "kill -0 $HPID 2>/dev/null || RC=99; "
                "kill $HPID 2>/dev/null || true; wait $HPID 2>/dev/null || true; "
                "rm -rf /tmp/noc-helperd-ex-test /tmp/ex_client.uc /tmp/noc_ex_test.sock /tmp/noc_ex_etc /tmp/noc_ex_run /tmp/hd_ex.log; exit $RC"
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if r_ex.returncode == 0 and "EX_BOUNDARY_OK" in r_ex.stdout:
            ok(f"HELPERD-EXCEPTION-BOUNDARY[{ver_label}]: race guard once-only and real noc-helperd PID survived to serve services_read")
        else:
            fail(f"HELPERD-EXCEPTION-BOUNDARY[{ver_label}]: rc={r_ex.returncode} out={r_ex.stdout.strip()} err={r_ex.stderr.strip()}")
    else:
        fail(f"HELPERD-EXCEPTION-BOUNDARY[{ver_label}]: required OpenWrt rootfs missing at {rfs_ex}")

# 8b. Topology string-bridges regression test (bridges: ["br-lan", "docker0"])
rfs_topo = rfs_ex if os.path.isdir(rfs_ex) else None
if rfs_topo:
    topo_mod = os.path.join(ROOT, "backend", "nms_topology.uc")
    topo_script = """
import * as nms_topology from '/tmp/nms_topology.uc';
let ip_link_raw = '[{"ifindex":2,"ifname":"eth1","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"master":"br-lan","operstate":"UP","address":"60:be:b4:1e:d3:5d"},{"ifindex":3,"ifname":"br-lan","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"operstate":"UP","address":"60:be:b4:1e:d3:5d"}]';
let built = nms_topology.build_live_topology({
    sampled_ms: 1000,
    ip_link_raw: ip_link_raw,
    ip_addr_raw: "3: br-lan    inet 192.168.1.1/24 brd 192.168.1.255 scope global br-lan\\n",
    ip_route_raw: "default via 192.168.1.254 dev wwan proto static\\n",
    bridges: ["br-lan", "docker0"],
    collector_status: { ubus_network: true, ip_link: true, ip_addr: true, ip_route: true, bridge_vlan: false, wireless: false, clients: true },
    clients: []
});
if (!built || built.completeness == "unavailable") { printf("FAIL_OK comp=%J\n", built ? built.completeness : null); exit(1); }
if (built.completeness != "partial") { printf("FAIL_COMP=%s\\n", built.completeness); exit(1); }
let found_br = false;
let found_port = false;
for (let b in (built.bridges || [])) {
    if (b.id == "bridge:br-lan" && b.name == "br-lan") {
        found_br = true;
        for (let p in (b.ports || [])) {
            if (p.id == "port:eth1" && p.bridge == "br-lan") found_port = true;
        }
    }
}
if (!found_br || !found_port) { printf("FAIL_NODES br=%J port=%J\\n", found_br, found_port); exit(1); }
printf("TOPO_STRING_BRIDGES_OK\\n");
"""
    r_topo = subprocess.run(
        [
            "bwrap", "--unshare-all", "--die-with-parent",
            "--ro-bind", rfs_topo, "/",
            "--tmpfs", "/tmp",
            "--ro-bind", topo_mod, "/tmp/nms_topology.uc",
            "/usr/bin/ucode", "-e", topo_script,
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if r_topo.returncode == 0 and "TOPO_STRING_BRIDGES_OK" in r_topo.stdout:
        ok("TOPOLOGY-STRING-BRIDGES: build_live_topology handles string bridges ['br-lan', 'docker0'] and derives ports from links.master")
    else:
        fail(f"TOPOLOGY-STRING-BRIDGES: rc={r_topo.returncode} out={r_topo.stdout.strip()} err={r_topo.stderr.strip()}")
else:
    fail("TOPOLOGY-STRING-BRIDGES: required OpenWrt rootfs missing")

# 8c. Frontend topology partial-badge regression test
topo_js_p = os.path.join(ROOT, "frontend", "noc-topology.js")
topo_js_txt = open(topo_js_p, encoding="utf-8").read()
if "(!!topo.partial || topo.completeness === 'partial')" in topo_js_txt:
    node_topo_check = """
function evalBadge(topo) {
  var isUnavail = (topo.completeness === 'unavailable' && !topo.stale);
  var isStale = !isUnavail && !!(topo.stale);
  var isPartial = !isUnavail && (!!topo.partial || topo.completeness === 'partial');
  if (isUnavail) return 'pill-danger';
  if (isStale || isPartial) return 'pill-warning';
  return 'pill-success';
}
if (evalBadge({ completeness: 'partial' }) !== 'pill-warning') process.exit(1);
if (evalBadge({ partial: true }) !== 'pill-warning') process.exit(2);
if (evalBadge({ completeness: 'complete' }) !== 'pill-success') process.exit(3);
if (evalBadge({ completeness: 'unavailable' }) !== 'pill-danger') process.exit(4);
console.log('TOPO_BADGE_OK');
"""
    r_tb = subprocess.run(["node", "-e", node_topo_check], capture_output=True, text=True, timeout=10)
    if r_tb.returncode == 0 and "TOPO_BADGE_OK" in r_tb.stdout:
        ok("TOPOLOGY-UI-PARTIAL-BADGE: completeness='partial', partial=true, complete, and unavailable map to expected badge classes")
    else:
        fail(f"TOPOLOGY-UI-PARTIAL-BADGE: rc={r_tb.returncode} out={r_tb.stdout} err={r_tb.stderr}")
else:
    fail("TOPOLOGY-UI-PARTIAL-BADGE: noc-topology.js missing (!!topo.partial || topo.completeness === 'partial') check")

# 9. Option A Root-Interface (/) Redirect & Atomic LuCI Restore Verification (Sections A, B, C, D)
print("\n=== 8. Root-Interface (/) Redirect & Atomic LuCI Restore (Option A) ===")
launcher_html_p = os.path.join(ROOT, "frontend", "launcher_index.html")
launcher_js_p = os.path.join(ROOT, "frontend", "launcher.js")
luci_cgi_p = os.path.join(ROOT, "scripts", "luci_redirect_cgi.uc")
enable_sh_p = os.path.join(ROOT, "scripts", "enable-root-redirect.sh")
restore_sh_p = os.path.join(ROOT, "scripts", "restore-luci.sh")

l_html_txt = open(launcher_html_p, encoding="utf-8").read()
l_js_txt = open(launcher_js_p, encoding="utf-8").read()
l_cgi_txt = open(luci_cgi_p, encoding="utf-8").read()

# A1 & C1: No :8780 references, no inline JS, no hardcoded IP in launcher.js, no secrets
if (
    ":8780" not in l_html_txt
    and ":8780" not in l_js_txt
    and ":8780" not in l_cgi_txt
    and "<script src=\"/pro/launcher.js\"></script>" in l_html_txt
    and not re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", l_html_txt, re.I)
    and "192.168.1.1" not in l_js_txt
):
    ok("ROOT-REDIRECT-A/C[static_no_8780_no_inline_js_no_hardcoded_ip]")
else:
    fail("ROOT-REDIRECT-A/C[static_no_8780_no_inline_js_no_hardcoded_ip]")

# A2 & C2 (Blocker 1): Node DOM execution of launcher.js (trusted private IPv4/IPv6/local domain vs untrusted external domains/public IPs/injections)
node_launcher_test = f"""
const fs = require('fs');
const code = fs.readFileSync({json.dumps(launcher_js_p)}, 'utf8');
function runCase(proto, host, hostname, port, sysHn) {{
  let replaced = null;
  let linkHref = '#';
  const window = {{
    location: {{
      protocol: proto,
      host: host,
      hostname: hostname,
      port: port,
      replace: (u) => {{ replaced = u; }}
    }}
  }};
  const document = {{
    documentElement: {{
      getAttribute: (k) => (k === 'data-nms-sys-hostname' && sysHn) ? sysHn : null
    }},
    getElementById: (id) => id === 'manualLink' ? {{ setAttribute: (k, v) => {{ if (k === 'href') linkHref = v; }} }} : null
  }};
  const fn = new Function('window', 'document', code);
  fn(window, document);
  return {{ replaced, linkHref }};
}}
// Trusted private IPv4: 192.168.1.1, 10.0.0.1, 172.16.5.1, 100.99.45.10 (Tailscale CGNAT), 127.0.0.1
for (const [host, hname, port, exp] of [
  ['192.168.1.1', '192.168.1.1', '', 'https://192.168.1.1:8743/'],
  ['10.0.0.1:80', '10.0.0.1', '80', 'https://10.0.0.1:8743/'],
  ['172.16.5.1', '172.16.5.1', '', 'https://172.16.5.1:8743/'],
  ['100.99.45.10', '100.99.45.10', '', 'https://100.99.45.10:8743/'],
  ['127.0.0.1', '127.0.0.1', '', 'https://127.0.0.1:8743/'],
  ['[::1]:80', '[::1]', '80', 'https://[::1]:8743/'],
  ['[fd7a:115c:a1e0::1]', '[fd7a:115c:a1e0::1]', '', 'https://[fd7a:115c:a1e0::1]:8743/'],
  ['[fe80::1]', '[fe80::1]', '', 'https://[fe80::1]:8743/'],
  ['router.lan:80', 'router.lan', '80', 'https://router.lan:8743/'],
  ['nms.local', 'nms.local', '', 'https://nms.local:8743/'],
  ['gateway.home.arpa', 'gateway.home.arpa', '', 'https://gateway.home.arpa:8743/'],
  ['router', 'router', '', 'https://router:8743/'],
]) {{
  const c = runCase('http:', host, hname, port, '');
  if (c.replaced !== exp || c.linkHref !== exp) {{
    console.error('Trusted host failed:', host, c);
    process.exit(1);
  }}
}}
// System hostname parity: when data-nms-sys-hostname="edge-gw-01" is stamped by enable-root-redirect.sh,
// edge-gw-01, edge-gw-01.lan, edge-gw-01.local, and edge-gw-01.home.arpa MUST be accepted, while unapproved names remain rejected
for (const [host, hname, port, exp] of [
  ['edge-gw-01', 'edge-gw-01', '', 'https://edge-gw-01:8743/'],
  ['edge-gw-01.lan:80', 'edge-gw-01.lan', '80', 'https://edge-gw-01.lan:8743/'],
  ['edge-gw-01.local', 'edge-gw-01.local', '', 'https://edge-gw-01.local:8743/'],
  ['edge-gw-01.home.arpa', 'edge-gw-01.home.arpa', '', 'https://edge-gw-01.home.arpa:8743/'],
]) {{
  const cOk = runCase('http:', host, hname, port, 'edge-gw-01');
  if (cOk.replaced !== exp || cOk.linkHref !== exp) {{
    console.error('System hostname parity failed when stamped:', host, cOk);
    process.exit(6);
  }}
  // Without data-nms-sys-hostname="edge-gw-01" (or with a different sys hostname), edge-gw-01 MUST be rejected
  const cNo = runCase('http:', host, hname, port, 'other-gw');
  if (cNo.replaced !== null || cNo.linkHref !== '#') {{
    console.error('Unconfigured hostname was not rejected:', host, cNo);
    process.exit(7);
  }}
}}
// HTTPS port 443 -> https://192.168.1.1:8743/
const cHttps = runCase('https:', '192.168.1.1', '192.168.1.1', '');
if (cHttps.replaced !== 'https://192.168.1.1:8743/') process.exit(2);
// Loop prevention: already on https://192.168.1.1:8743/ -> replaced must remain null
const cLoop = runCase('https:', '192.168.1.1:8743', '192.168.1.1', '8743');
if (cLoop.replaced !== null || cLoop.linkHref !== 'https://192.168.1.1:8743/') process.exit(4);
// Untrusted valid-looking external domains, public IPs, out-of-range ports (0, 65536, 99999),
// malformed IPv6, and unapproved local hostnames MUST be rejected
for (const [host, hname, port] of [
  ['evil.com', 'evil.com', ''],
  ['attacker.org:8080', 'attacker.org', '8080'],
  ['sub.example.net', 'sub.example.net', ''],
  ['8.8.8.8', '8.8.8.8', ''],
  ['1.1.1.1:443', '1.1.1.1', '443'],
  ['172.32.0.1', '172.32.0.1', ''],
  ['192.168.1.999', '192.168.1.999', ''],
  ['[2001:4860:4860::8888]', '[2001:4860:4860::8888]', ''],
  ['[::1::1]', '[::1::1]', ''],
  ['[fe80:::1]', '[fe80:::1]', ''],
  ['[fe80:12345::1]', '[fe80:12345::1]', ''],
  ['[fe80::1:2:3:4:5:6:7:8]', '[fe80::1:2:3:4:5:6:7:8]', ''],
  ['[fd00:1:2:3]', '[fd00:1:2:3]', ''],
  ['untrustedbox', 'untrustedbox', ''],
  ['evil.lan', 'evil.lan', ''],
  ['phish.local', 'phish.local', ''],
  ['rogue.home.arpa', 'rogue.home.arpa', ''],
  ['192.168.1.1:0', '192.168.1.1', '0'],
  ['192.168.1.1:65536', '192.168.1.1', '65536'],
  ['192.168.1.1:99999', '192.168.1.1', '99999'],
  ['evil.com/path', 'evil.com/path', ''],
  ['evil.com@192.168.1.1', 'evil.com@192.168.1.1', ''],
  ['192.168.1.1:bad', '192.168.1.1', 'bad'],
]) {{
  const c = runCase('http:', host, hname, port);
  if (c.replaced !== null || c.linkHref !== '#') {{
    console.error('Untrusted host was not rejected:', host, c);
    process.exit(5);
  }}
}}
console.log('LAUNCHER_JS_PASS');
"""
r_nl = subprocess.run(["node", "-e", node_launcher_test], capture_output=True, text=True, timeout=10)
if r_nl.returncode == 0 and "LAUNCHER_JS_PASS" in r_nl.stdout:
    ok("ROOT-REDIRECT-A/C[launcher_js_trusted_host_policy_and_external_domain_rejected]")
else:
    fail(f"ROOT-REDIRECT-A/C[launcher_js_trusted_host_policy_and_external_domain_rejected]: rc={r_nl.returncode} err={r_nl.stderr}")

# A3, C3 & D4 (Blocker 1): Execute /www/cgi-bin/luci (luci_redirect_cgi.uc) on BOTH OpenWrt 24.10.0 and 25.12.6 chroots
for ver_label, rfs in (("24.10.0-opkg", "/tmp/openwrt-24.10-x86-64-rootfs"), ("25.12.6-apk", "/tmp/openwrt-x86-64-rootfs")):
    if os.path.isdir(rfs) and os.path.isfile(os.path.join(rfs, "usr/bin/ucode")):
        dst_cgi = os.path.join(rfs, "tmp", "test_luci_redirect.uc")
        shutil.copy2(luci_cgi_p, dst_cgi)
        try:
            trusted_cases = [
                ("192.168.1.1", "https://192.168.1.1:8743/"),
                ("10.0.0.1:80", "https://10.0.0.1:8743/"),
                ("172.16.0.1", "https://172.16.0.1:8743/"),
                ("100.99.45.10:443", "https://100.99.45.10:8743/"),
                ("192.168.1.1:1", "https://192.168.1.1:8743/"),
                ("192.168.1.1:65535", "https://192.168.1.1:8743/"),
                ("[::1]:80", "https://[::1]:8743/"),
                ("[fd7a:115c:a1e0::1]:443", "https://[fd7a:115c:a1e0::1]:8743/"),
                ("router.lan:443", "https://router.lan:8743/"),
                ("nms.local", "https://nms.local:8743/"),
                ("gateway.home.arpa", "https://gateway.home.arpa:8743/"),
                ("router", "https://router:8743/"),
            ]
            untrusted_cases = [
                "evil.com",
                "attacker.org:8080",
                "sub.example.net",
                "8.8.8.8",
                "172.32.0.1",
                "192.168.1.999",
                "[2001:4860:4860::8888]",
                "[::1::1]",
                "[fe80:::1]",
                "[fe80:12345::1]",
                "[fe80::1:2:3:4:5:6:7:8]",
                "[fd00:1:2:3]",
                "untrustedbox",
                "evil.lan",
                "phish.local",
                "rogue.home.arpa",
                "192.168.1.1:0",
                "192.168.1.1:65536",
                "192.168.1.1:99999",
                "[::1]:0",
                "[::1]:65536",
                "[::1]:99999",
                "evil.example.com/attack@192.168.1.1",
                "192.168.1.1:badport",
                "[::1]:badport",
            ]
            cgi_ok = True
            for h_in, exp_loc in trusted_cases:
                rc = subprocess.run(
                    ["unshare", "-r", "/usr/sbin/chroot", rfs, "/usr/bin/env", f"HTTP_HOST={h_in}", "/usr/bin/ucode", "/tmp/test_luci_redirect.uc"],
                    capture_output=True, text=True, timeout=10,
                )
                if rc.returncode != 0 or f"Status: 302 Found\nLocation: {exp_loc}\n" not in rc.stdout:
                    cgi_ok = False
                    break
            for h_bad in untrusted_cases:
                rc = subprocess.run(
                    ["unshare", "-r", "/usr/sbin/chroot", rfs, "/usr/bin/env", f"HTTP_HOST={h_bad}", "/usr/bin/ucode", "/tmp/test_luci_redirect.uc"],
                    capture_output=True, text=True, timeout=10,
                )
                if rc.returncode != 0 or "Status: 302 Found\nLocation: https://192.168.1.1:8743/\n" not in rc.stdout:
                    cgi_ok = False
                    break
            # Verify dynamic system hostname parity in CGI via real OpenWrt /etc/config/system (UCI) AND /proc/sys/kernel/hostname WITHOUT any env override
            sys_cfg_p = os.path.join(rfs, "etc", "config", "system")
            proc_hn_p = os.path.join(rfs, "proc", "sys", "kernel", "hostname")
            had_sys_cfg = os.path.isfile(sys_cfg_p)
            orig_sys_cfg = open(sys_cfg_p, "rb").read() if had_sys_cfg else None
            had_proc_hn = os.path.isfile(proc_hn_p)
            orig_proc_hn = open(proc_hn_p, "rb").read() if had_proc_hn else None
            try:
                # 1. Real UCI /etc/config/system path (hostname 'edge-gw-01') with NO environment override
                os.makedirs(os.path.dirname(sys_cfg_p), exist_ok=True)
                open(sys_cfg_p, "w", encoding="utf-8").write("config system\n\toption hostname 'edge-gw-01'\n")
                for sys_h, exp_loc in [
                    ("edge-gw-01", "https://edge-gw-01:8743/"),
                    ("edge-gw-01.lan:80", "https://edge-gw-01.lan:8743/"),
                    ("edge-gw-01.local", "https://edge-gw-01.local:8743/"),
                    ("edge-gw-01.home.arpa:443", "https://edge-gw-01.home.arpa:8743/"),
                ]:
                    rc_uci = subprocess.run(
                        ["unshare", "-r", "/usr/sbin/chroot", rfs, "/usr/bin/env", f"HTTP_HOST={sys_h}", "/usr/bin/ucode", "/tmp/test_luci_redirect.uc"],
                        capture_output=True, text=True, timeout=10,
                    )
                    if rc_uci.returncode != 0 or f"Status: 302 Found\nLocation: {exp_loc}\n" not in rc_uci.stdout:
                        cgi_ok = False
                        break
                # Verify unapproved hostname is still rejected while UCI hostname is edge-gw-01
                rc_uci_bad = subprocess.run(
                    ["unshare", "-r", "/usr/sbin/chroot", rfs, "/usr/bin/env", "HTTP_HOST=other-gw.lan", "/usr/bin/ucode", "/tmp/test_luci_redirect.uc"],
                    capture_output=True, text=True, timeout=10,
                )
                if rc_uci_bad.returncode != 0 or "Status: 302 Found\nLocation: https://192.168.1.1:8743/\n" not in rc_uci_bad.stdout:
                    cgi_ok = False

                # 2. Fallback /proc/sys/kernel/hostname path when UCI /etc/config/system is absent
                if os.path.exists(sys_cfg_p):
                    os.unlink(sys_cfg_p)
                os.makedirs(os.path.dirname(proc_hn_p), exist_ok=True)
                open(proc_hn_p, "w", encoding="utf-8").write("proc-gw-02\n")
                for proc_h, exp_loc in [
                    ("proc-gw-02", "https://proc-gw-02:8743/"),
                    ("proc-gw-02.lan:80", "https://proc-gw-02.lan:8743/"),
                    ("proc-gw-02.local", "https://proc-gw-02.local:8743/"),
                    ("proc-gw-02.home.arpa:443", "https://proc-gw-02.home.arpa:8743/"),
                ]:
                    rc_proc = subprocess.run(
                        ["unshare", "-r", "/usr/sbin/chroot", rfs, "/usr/bin/env", f"HTTP_HOST={proc_h}", "/usr/bin/ucode", "/tmp/test_luci_redirect.uc"],
                        capture_output=True, text=True, timeout=10,
                    )
                    if rc_proc.returncode != 0 or f"Status: 302 Found\nLocation: {exp_loc}\n" not in rc_proc.stdout:
                        cgi_ok = False
                        break
                # Verify previous UCI hostname edge-gw-01 is now rejected when only /proc/sys/kernel/hostname=proc-gw-02 exists
                rc_proc_bad = subprocess.run(
                    ["unshare", "-r", "/usr/sbin/chroot", rfs, "/usr/bin/env", "HTTP_HOST=edge-gw-01.lan", "/usr/bin/ucode", "/tmp/test_luci_redirect.uc"],
                    capture_output=True, text=True, timeout=10,
                )
                if rc_proc_bad.returncode != 0 or "Status: 302 Found\nLocation: https://192.168.1.1:8743/\n" not in rc_proc_bad.stdout:
                    cgi_ok = False
            finally:
                if had_sys_cfg and orig_sys_cfg is not None:
                    open(sys_cfg_p, "wb").write(orig_sys_cfg)
                elif os.path.exists(sys_cfg_p):
                    os.unlink(sys_cfg_p)
                if had_proc_hn and orig_proc_hn is not None:
                    open(proc_hn_p, "wb").write(orig_proc_hn)
                elif os.path.exists(proc_hn_p):
                    os.unlink(proc_hn_p)
            if cgi_ok:
                ok(f"ROOT-REDIRECT-A/C/D[luci_cgi_302_trusted_host_policy_and_external_domain_rejected_{ver_label}]")
            else:
                fail(f"ROOT-REDIRECT-A/C/D[luci_cgi_302_trusted_host_policy_and_external_domain_rejected_{ver_label}]")
        finally:
            if os.path.exists(dst_cgi):
                os.unlink(dst_cgi)

# B1..B6 & D1..D5 (Blockers 2, 3, 4): Full lifecycle test of enable-root-redirect.sh, restore-luci.sh, mandatory manifest,
# complete two-file rollback across all commit boundaries, pinned router backup hashes, idempotency, and uninstall.sh
with tempfile.TemporaryDirectory(prefix="nms_root_redirect_lifecycle_") as rr_td:
    os.makedirs(os.path.join(rr_td, "www", "cgi-bin"), exist_ok=True)
    os.makedirs(os.path.join(rr_td, "www", "pro"), exist_ok=True)
    os.makedirs(os.path.join(rr_td, "etc", "noc-console"), exist_ok=True)
    os.chmod(os.path.join(rr_td, "etc", "noc-console"), 0o700)

    # Exact byte-for-byte stock OpenWrt 25.12.6 LuCI files matching the pinned router hashes
    orig_idx_bytes = (
        b'<!DOCTYPE html>\n<html>\n\t<head>\n'
        b'\t\t<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />\n'
        b'\t\t<meta http-equiv="Pragma" content="no-cache" />\n'
        b'\t\t<meta http-equiv="Expires" content="0" />\n'
        b'\t\t<meta http-equiv="Expires" content="Thu, 01 Jan 1970 00:00:00 GMT" />\n'
        b'\t\t<meta http-equiv="refresh" content="0; URL=cgi-bin/luci/" />\n'
        b'\t\t<style>\n'
        b'\t\t\tbody { background: white; font-family: arial, helvetica, sans-serif; }\n'
        b'\t\t\ta { color: black; }\n\n'
        b'\t\t\t@media (prefers-color-scheme: dark) {\n'
        b'\t\t\t\tbody { background: black; }\n'
        b'\t\t\t\ta { color: white; }\n'
        b'\t\t\t}\n'
        b'\t\t</style>\n'
        b'\t</head>\n\t<body>\n'
        b'\t\t<a href="cgi-bin/luci/">LuCI - Lua Configuration Interface</a>\n'
        b'\t</body>\n</html>\n'
    )
    orig_cgi_bytes = (
        b"#!/usr/bin/env ucode\n\n'use strict';\n\n"
        b"import { stdin, stdout } from 'fs';\n\n"
        b"import dispatch from 'luci.dispatcher';\n"
        b"import request from 'luci.http';\n\n"
        b"const input_bufsize = 4096;\n"
        b"let input_available = +getenv('CONTENT_LENGTH') || 0;\n\n"
        b"function read(len) {\n"
        b"\tif (input_available == 0) {\n"
        b"\t\tstdin.close();\n\n"
        b"\t\treturn null;\n"
        b"\t}\n\n"
        b"\tlet chunk = stdin.read(min(input_available, len ?? input_bufsize, input_bufsize));\n\n"
        b"\tif (chunk == null) {\n"
        b"\t\tinput_available = 0;\n"
        b"\t\tstdin.close();\n"
        b"\t}\n"
        b"\telse {\n"
        b"\t\tinput_available -= length(chunk);\n"
        b"\t}\n\n"
        b"\treturn chunk;\n"
        b"}\n\n"
        b"function write(data) {\n"
        b"\treturn stdout.write(data);\n"
        b"}\n\n"
        b"let req = request(getenv(), read, write);\n\n"
        b"dispatch(req);\n\n"
        b"req.close();\n"
    )
    orig_idx_sha = hashlib.sha256(orig_idx_bytes).hexdigest()
    orig_cgi_sha = hashlib.sha256(orig_cgi_bytes).hexdigest()
    assert orig_idx_sha == "f68138db6165da195c2b8347ebdfa43b1c1a13e1c96386d2abed09578cb06b30"
    assert orig_cgi_sha == "aced6c9b2e621bb6e1dd1bb7d675925e9325ed901f49b1aabb0696a06942dacb"

    idx_p = os.path.join(rr_td, "www", "index.html")
    idx_bak_p = os.path.join(rr_td, "www", "index.luci.bak.html")
    cgi_p = os.path.join(rr_td, "www", "cgi-bin", "luci")
    cgi_bak_p = os.path.join(rr_td, "www", "cgi-bin", "luci.orig.bak")
    manifest_p = os.path.join(rr_td, "etc", "noc-console", "luci_backup.manifest")
    user_apk_p = os.path.join(rr_td, "www", "pro", "OpenWrt_Pro_Manager.apk")
    user_auth_p = os.path.join(rr_td, "etc", "noc-console", "auth.json")
    open(user_apk_p, "wb").write(b"USER_APK_BINARY_KEEP")
    open(user_auth_p, "wb").write(b'{"users":{"admin":{}}}')
    os.chmod(user_auth_p, 0o600)

    old_stub_idx = b"<html><body>Old 8780 stub :8780/</body></html>\n"
    old_stub_cgi = b"#!/usr/bin/env ucode\nlet target = 'http://192.168.1.1:8780/';\n"
    open(idx_p, "wb").write(old_stub_idx)
    open(cgi_p, "wb").write(old_stub_cgi)
    os.chmod(cgi_p, 0o755)

    env_rr = os.environ.copy()
    env_rr["NMS_ROOT_PREFIX"] = rr_td

    # Blocker 4: Pinned router backup hash check in enable-root-redirect.sh
    # If backups have wrong/tampered bytes, enable-root-redirect.sh MUST fail closed without overwriting backups or targets
    tampered_idx_bak = b"<html>Tampered backup</html>\n"
    open(idx_bak_p, "wb").write(tampered_idx_bak)
    os.chmod(idx_bak_p, 0o644)
    open(cgi_bak_p, "wb").write(orig_cgi_bytes)
    os.chmod(cgi_bak_p, 0o755)
    r_pin_fail1 = subprocess.run(["sh", enable_sh_p], env=env_rr, capture_output=True, text=True)

    open(idx_bak_p, "wb").write(orig_idx_bytes)
    os.chmod(idx_bak_p, 0o644)
    tampered_cgi_bak = b"#!/usr/bin/env ucode\n// tampered\n"
    open(cgi_bak_p, "wb").write(tampered_cgi_bak)
    os.chmod(cgi_bak_p, 0o755)
    r_pin_fail2 = subprocess.run(["sh", enable_sh_p], env=env_rr, capture_output=True, text=True)

    if (
        r_pin_fail1.returncode != 0
        and r_pin_fail2.returncode != 0
        and open(idx_p, "rb").read() == old_stub_idx
        and open(cgi_p, "rb").read() == old_stub_cgi
        and open(cgi_bak_p, "rb").read() == tampered_cgi_bak
        and not os.path.exists(manifest_p)
    ):
        ok("ROOT-REDIRECT-B/D[pinned_backup_hash_mismatch_rejected_without_overwrite]")
    else:
        fail(f"ROOT-REDIRECT-B/D[pinned_backup_hash_mismatch_rejected_without_overwrite]: r1={r_pin_fail1.returncode} r2={r_pin_fail2.returncode}")

    # Restore authentic stock LuCI backup bytes matching pinned hashes
    open(idx_bak_p, "wb").write(orig_idx_bytes)
    os.chmod(idx_bak_p, 0o644)
    open(cgi_bak_p, "wb").write(orig_cgi_bytes)
    os.chmod(cgi_bak_p, 0o755)

    # D1: Mid-activation failure (after_index) MUST roll back /www/index.html and /www/cgi-bin/luci to pre-activation state and keep backups intact
    env_rr_fail = env_rr.copy()
    env_rr_fail["NMS_TEST_ROOT_REDIRECT_FAIL_POINT"] = "after_index"
    r_en_fail = subprocess.run(["sh", enable_sh_p], env=env_rr_fail, capture_output=True, text=True)
    if (
        r_en_fail.returncode != 0
        and open(idx_p, "rb").read() == old_stub_idx
        and open(cgi_p, "rb").read() == old_stub_cgi
        and hashlib.sha256(open(idx_bak_p, "rb").read()).hexdigest() == orig_idx_sha
        and hashlib.sha256(open(cgi_bak_p, "rb").read()).hexdigest() == orig_cgi_sha
    ):
        ok("ROOT-REDIRECT-D[mid_activation_failure_rolls_back_cleanly]")
    else:
        fail(f"ROOT-REDIRECT-D[mid_activation_failure_rolls_back_cleanly]: rc={r_en_fail.returncode}")

    # B1 & B2: Enable root redirect (with configured UCI system hostname 'edge-gw-01') -> verifies pinned hashes, writes manifest,
    # stamps data-nms-sys-hostname="edge-gw-01" into /www/index.html, and ensures 100% policy parity between launcher.js and luci_redirect_cgi.uc
    os.makedirs(os.path.join(rr_td, "etc", "config"), exist_ok=True)
    open(os.path.join(rr_td, "etc", "config", "system"), "w", encoding="utf-8").write("config system\n\toption hostname 'edge-gw-01'\n")
    exp_stamped_idx_bytes = open(launcher_html_p, "rb").read().replace(
        b'<html lang="ar" dir="rtl">',
        b'<html lang="ar" dir="rtl" data-nms-sys-hostname="edge-gw-01">',
    )
    r_en_ok = subprocess.run(["sh", enable_sh_p], env=env_rr, capture_output=True, text=True)
    # Run a second time (simulating NMS upgrade) -> MUST still NOT overwrite .luci.bak.html or .orig.bak with the new redirect files!
    r_en_up = subprocess.run(["sh", enable_sh_p], env=env_rr, capture_output=True, text=True)
    saved_manifest_bytes = open(manifest_p, "rb").read() if os.path.isfile(manifest_p) else b""

    # Verify end-to-end parity between the stamped /www/index.html + /www/pro/launcher.js and /www/cgi-bin/luci for system hostname 'edge-gw-01'
    parity_node_test = f"""
const fs = require('fs');
const html = fs.readFileSync({json.dumps(idx_p)}, 'utf8');
const code = fs.readFileSync({json.dumps(os.path.join(rr_td, "www", "pro", "launcher.js"))}, 'utf8');
const m = /data-nms-sys-hostname="([^"]+)"/.exec(html);
if (!m || m[1] !== 'edge-gw-01') process.exit(10);
function testHost(h) {{
  let replaced = null;
  const window = {{ location: {{ protocol: 'http:', host: h, hostname: h.split(':')[0], port: h.split(':')[1] || '', replace: (u) => {{ replaced = u; }} }} }};
  const document = {{
    documentElement: {{ getAttribute: (k) => k === 'data-nms-sys-hostname' ? m[1] : null }},
    getElementById: () => ({{ setAttribute: () => {{}} }})
  }};
  (new Function('window', 'document', code))(window, document);
  return replaced;
}}
if (testHost('edge-gw-01') !== 'https://edge-gw-01:8743/') process.exit(11);
if (testHost('edge-gw-01.lan:80') !== 'https://edge-gw-01.lan:8743/') process.exit(12);
if (testHost('edge-gw-01.local') !== 'https://edge-gw-01.local:8743/') process.exit(13);
if (testHost('edge-gw-01.home.arpa') !== 'https://edge-gw-01.home.arpa:8743/') process.exit(14);
if (testHost('unapproved-box.lan') !== null) process.exit(15);
console.log('PARITY_OK');
"""
    r_par = subprocess.run(["node", "-e", parity_node_test], capture_output=True, text=True, timeout=10)

    if (
        r_en_ok.returncode == 0
        and r_en_up.returncode == 0
        and r_par.returncode == 0
        and "PARITY_OK" in r_par.stdout
        and hashlib.sha256(open(idx_bak_p, "rb").read()).hexdigest() == orig_idx_sha
        and hashlib.sha256(open(cgi_bak_p, "rb").read()).hexdigest() == orig_cgi_sha
        and open(idx_p, "rb").read() == exp_stamped_idx_bytes
        and open(cgi_p, "rb").read() == open(luci_cgi_p, "rb").read()
        and (os.stat(os.path.join(rr_td, "etc", "noc-console")).st_mode & 0o777) == 0o700
        and len(saved_manifest_bytes.splitlines()) == 2
    ):
        ok("ROOT-REDIRECT-B[enable_and_upgrade_preserve_preexisting_luci_backups_sha256_and_sys_hostname_parity]")
    else:
        fail(f"ROOT-REDIRECT-B[enable_and_upgrade_preserve_preexisting_luci_backups_sha256_and_sys_hostname_parity]: rc1={r_en_ok.returncode} rc2={r_en_up.returncode} par={r_par.returncode} err={r_en_ok.stderr} {r_par.stderr}")

    # Blocker 2: Mandatory restore manifest verification
    # Test 1: Missing manifest -> restore-luci.sh MUST fail closed without touching /www/index.html or /www/cgi-bin/luci
    os.unlink(manifest_p)
    r_m_missing = subprocess.run(["sh", restore_sh_p], env=env_rr, capture_output=True, text=True)
    # Test 2: Incomplete manifest (only 1 record) -> fail closed
    open(manifest_p, "wb").write(saved_manifest_bytes.splitlines()[0] + b"\n")
    r_m_incomplete = subprocess.run(["sh", restore_sh_p], env=env_rr, capture_output=True, text=True)
    # Test 3: Malformed manifest (invalid SHA-256 / bad mode) -> fail closed
    open(manifest_p, "wb").write(
        b"/www/index.html|badsha|644|0:0|0|/www/index.luci.bak.html\n"
        b"/www/cgi-bin/luci|aced6c9b2e621bb6e1dd1bb7d675925e9325ed901f49b1aabb0696a06942dacb|755|0:0|0|/www/cgi-bin/luci.orig.bak\n"
    )
    r_m_malformed = subprocess.run(["sh", restore_sh_p], env=env_rr, capture_output=True, text=True)
    # Test 4: Valid manifest format but wrong expected SHA-256 -> fail closed before modifying either file
    open(manifest_p, "wb").write(
        b"/www/index.html|0000000000000000000000000000000000000000000000000000000000000000|644|0:0|0|/www/index.luci.bak.html\n"
        b"/www/cgi-bin/luci|aced6c9b2e621bb6e1dd1bb7d675925e9325ed901f49b1aabb0696a06942dacb|755|0:0|0|/www/cgi-bin/luci.orig.bak\n"
    )
    r_m_wrong_sha = subprocess.run(["sh", restore_sh_p], env=env_rr, capture_output=True, text=True)
    # Restore authentic manifest
    open(manifest_p, "wb").write(saved_manifest_bytes)
    os.chmod(manifest_p, 0o600)

    if (
        r_m_missing.returncode != 0
        and r_m_incomplete.returncode != 0
        and r_m_malformed.returncode != 0
        and r_m_wrong_sha.returncode != 0
        and open(idx_p, "rb").read() == exp_stamped_idx_bytes
        and open(cgi_p, "rb").read() == open(luci_cgi_p, "rb").read()
    ):
        ok("ROOT-REDIRECT-B[restore_luci_mandatory_manifest_missing_corrupt_or_hash_mismatch_fails_closed]")
    else:
        fail(
            f"ROOT-REDIRECT-B[restore_luci_mandatory_manifest_missing_corrupt_or_hash_mismatch_fails_closed]: "
            f"rcs={r_m_missing.returncode},{r_m_incomplete.returncode},{r_m_malformed.returncode},{r_m_wrong_sha.returncode}"
        )

    # Blocker 3 (B4): Complete two-file rollback across ALL commit boundaries (before_commit, after_index_move, after_cgi_move, during_final_verify)
    pre_idx_bytes = open(idx_p, "rb").read()
    pre_cgi_bytes = open(cgi_p, "rb").read()
    pre_idx_sha = hashlib.sha256(pre_idx_bytes).hexdigest()
    pre_cgi_sha = hashlib.sha256(pre_cgi_bytes).hexdigest()
    pre_idx_mode = os.stat(idx_p).st_mode & 0o7777
    pre_cgi_mode = os.stat(cgi_p).st_mode & 0o7777
    pre_idx_uid_gid = (os.stat(idx_p).st_uid, os.stat(idx_p).st_gid)
    pre_cgi_uid_gid = (os.stat(cgi_p).st_uid, os.stat(cgi_p).st_gid)
    rollback_all_ok = True
    for fp in ("before_commit", "after_index_move", "after_cgi_move", "during_final_verify"):
        env_res_fail = env_rr.copy()
        env_res_fail["NMS_TEST_RESTORE_LUCI_FAIL_POINT"] = fp
        r_rf = subprocess.run(["sh", restore_sh_p], env=env_res_fail, capture_output=True, text=True)
        if (
            r_rf.returncode == 0
            or hashlib.sha256(open(idx_p, "rb").read()).hexdigest() != pre_idx_sha
            or hashlib.sha256(open(cgi_p, "rb").read()).hexdigest() != pre_cgi_sha
            or (os.stat(idx_p).st_mode & 0o7777) != pre_idx_mode
            or (os.stat(cgi_p).st_mode & 0o7777) != pre_cgi_mode
            or (os.stat(idx_p).st_uid, os.stat(idx_p).st_gid) != pre_idx_uid_gid
            or (os.stat(cgi_p).st_uid, os.stat(cgi_p).st_gid) != pre_cgi_uid_gid
            or hashlib.sha256(open(idx_bak_p, "rb").read()).hexdigest() != orig_idx_sha
            or hashlib.sha256(open(cgi_bak_p, "rb").read()).hexdigest() != orig_cgi_sha
            or not os.path.isfile(manifest_p)
        ):
            rollback_all_ok = False
            break
    if rollback_all_ok:
        ok("ROOT-REDIRECT-B[restore_luci_two_file_rollback_across_all_commit_boundaries]")
    else:
        fail(f"ROOT-REDIRECT-B[restore_luci_two_file_rollback_across_all_commit_boundaries]: failed at {fp}")

    # Rollback failure handling: fault-injection during rollback copy, chmod, chown, rename, and final verification
    # MUST report rollback failure distinctly (rc == 99, "RESTORE-LUCI ROLLBACK ERROR" & "RESTORE-LUCI CRITICAL")
    # and MUST preserve recovery artifacts (.prev.tmp.*, luci_backup.manifest, and original backups)
    rb_fault_ok = True
    for rbf in ("rb_copy", "rb_chmod", "rb_chown", "rb_rename", "rb_verify"):
        # Reset destinations to pre-restore state before each rollback fault injection
        open(idx_p, "wb").write(pre_idx_bytes)
        os.chmod(idx_p, pre_idx_mode)
        open(cgi_p, "wb").write(pre_cgi_bytes)
        os.chmod(cgi_p, pre_cgi_mode)
        env_rbf = env_rr.copy()
        env_rbf["NMS_TEST_RESTORE_LUCI_FAIL_POINT"] = "after_cgi_move"
        env_rbf["NMS_TEST_RESTORE_LUCI_ROLLBACK_FAIL_POINT"] = rbf
        r_rbf = subprocess.run(["sh", restore_sh_p], env=env_rbf, capture_output=True, text=True)
        prev_idx_files = [f for f in os.listdir(os.path.join(rr_td, "www")) if f.startswith("index.html.prev.tmp.")]
        prev_cgi_files = [f for f in os.listdir(os.path.join(rr_td, "www", "cgi-bin")) if f.startswith("luci.prev.tmp.")]
        if (
            r_rbf.returncode != 99
            or "RESTORE-LUCI ROLLBACK ERROR" not in r_rbf.stderr
            or "RESTORE-LUCI CRITICAL" not in r_rbf.stderr
            or not prev_idx_files
            or not prev_cgi_files
            or not os.path.isfile(manifest_p)
            or hashlib.sha256(open(idx_bak_p, "rb").read()).hexdigest() != orig_idx_sha
            or hashlib.sha256(open(cgi_bak_p, "rb").read()).hexdigest() != orig_cgi_sha
        ):
            rb_fault_ok = False
            break
        # Clean up preserved .prev.tmp.* artifacts before next iteration
        for f in prev_idx_files:
            os.unlink(os.path.join(rr_td, "www", f))
        for f in prev_cgi_files:
            os.unlink(os.path.join(rr_td, "www", "cgi-bin", f))
    # Restore destinations to pre-restore state after rollback fault injection tests
    open(idx_p, "wb").write(pre_idx_bytes)
    os.chmod(idx_p, pre_idx_mode)
    open(cgi_p, "wb").write(pre_cgi_bytes)
    os.chmod(cgi_p, pre_cgi_mode)
    if rb_fault_ok:
        ok("ROOT-REDIRECT-B[restore_luci_rollback_failure_reported_distinctly_and_artifacts_preserved]")
    else:
        fail(f"ROOT-REDIRECT-B[restore_luci_rollback_failure_reported_distinctly_and_artifacts_preserved]: failed at {rbf}")

    # B2, B3 & D5: Standalone restore-luci (even when NMS daemons are completely down/absent) restores original LuCI byte-for-byte, and repeated execution is idempotent
    r_res1 = subprocess.run(["sh", restore_sh_p], env=env_rr, capture_output=True, text=True)
    r_res2 = subprocess.run(["sh", restore_sh_p], env=env_rr, capture_output=True, text=True)
    r_res3 = subprocess.run(["sh", restore_sh_p], env=env_rr, capture_output=True, text=True)
    if (
        r_res1.returncode == 0
        and r_res2.returncode == 0
        and r_res3.returncode == 0
        and hashlib.sha256(open(idx_p, "rb").read()).hexdigest() == orig_idx_sha
        and hashlib.sha256(open(cgi_p, "rb").read()).hexdigest() == orig_cgi_sha
        and (os.stat(cgi_p).st_mode & 0o777) == 0o755
        and os.path.isfile(idx_bak_p)
        and os.path.isfile(cgi_bak_p)
    ):
        ok("ROOT-REDIRECT-B/D[restore_luci_exact_sha256_idempotent_and_ssh_standalone]")
    else:
        fail(f"ROOT-REDIRECT-B/D[restore_luci_exact_sha256_idempotent_and_ssh_standalone]: rcs={r_res1.returncode},{r_res2.returncode},{r_res3.returncode}")

    # B5 & B6: Re-enable redirect, run full install.sh + uninstall.sh -> uninstall.sh automatically restores original LuCI, preserves user APK & auth.json, and does NOT delete pre-existing LuCI backups!
    subprocess.run(["sh", enable_sh_p], env=env_rr, check=True, capture_output=True)
    env_ins = env_rr.copy()
    env_ins["NMS_SKIP_SERVICE_START"] = "1"
    open(os.path.join(rr_td, "etc", "passwd"), "w").write("root:x:0:0:root:/root:/bin/sh\n")
    open(os.path.join(rr_td, "etc", "group"), "w").write("root:x:0:\n")
    r_ins_rr = subprocess.run(["sh", os.path.join(ROOT, "scripts", "install.sh")], env=env_ins, capture_output=True, text=True)
    # Re-enable root redirect after install.sh so /www/index.html and /www/cgi-bin/luci are active redirects
    subprocess.run(["sh", enable_sh_p], env=env_rr, check=True, capture_output=True)
    r_un_rr = subprocess.run(["sh", os.path.join(ROOT, "scripts", "uninstall.sh")], env=env_rr, capture_output=True, text=True)
    if (
        r_ins_rr.returncode == 0
        and r_un_rr.returncode == 0
        and hashlib.sha256(open(idx_p, "rb").read()).hexdigest() == orig_idx_sha
        and hashlib.sha256(open(cgi_p, "rb").read()).hexdigest() == orig_cgi_sha
        and os.path.isfile(idx_bak_p)
        and os.path.isfile(cgi_bak_p)
        and open(user_apk_p, "rb").read() == b"USER_APK_BINARY_KEEP"
        and open(user_auth_p, "rb").read() == b'{"users":{"admin":{}}}'
    ):
        ok("ROOT-REDIRECT-B/D[uninstall_restores_luci_and_preserves_user_files_and_preexisting_backups]")
    else:
        fail(f"ROOT-REDIRECT-B/D[uninstall_restores_luci_and_preserves_user_files_and_preexisting_backups]: ins={r_ins_rr.returncode} un={r_un_rr.returncode} err={r_un_rr.stderr}")

print(f"\n=== SUMMARY: {len(passes)} passed, {len(failures)} failed ===")
sys.exit(1 if failures else 0)
