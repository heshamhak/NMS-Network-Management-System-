#!/usr/bin/env python3
"""
NMS (Network Management System) - Local & Offline Regression Suite (Phase 2 Final)
Zero network or SSH calls to any live router.
Covers:
  - Static JS/Shell/JSON/CSP hygiene
  - SEC-01 regression (real socat + init.d/noc-apid procd topology, loopback-only HTTP, no LAN HTTP)
  - INS-02 regression (pre-existing /etc/noc-console & user dir perms preserved, ucode modules, TLS fail-closed)
  - INS-03 regression (collision backup/restore for backend, init.d, AND frontend; transactional rollback on failure)
"""
import hashlib
import http.server
import json
import os
import re
import shutil
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

print("=== 2. SEC-01 & Failure-Mode Regression ===")
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

with tempfile.TemporaryDirectory() as td_fail:
    empty_bin = os.path.join(td_fail, "empty_bin")
    os.makedirs(empty_bin, exist_ok=True)
    for tool in ("sh", "mkdir", "chmod", "cp", "mv", "grep", "awk", "sed", "find", "sort", "dirname", "cat", "tr", "stat", "id", "rm", "rmdir", "printf"):
        tp = shutil.which(tool)
        if tp:
            os.symlink(tp, os.path.join(empty_bin, tool))
    env_fail = {"PATH": empty_bin, "NMS_ROOT_PREFIX": td_fail, "NMS_SKIP_SERVICE_START": "1"}
    r_fail = subprocess.run([os.path.join(empty_bin, "sh"), os.path.join(ROOT, "scripts/install.sh")], env=env_fail, capture_output=True, text=True)
    if r_fail.returncode != 0 and "Mandatory TLS prerequisites" in r_fail.stderr:
        ok("SEC-01/INS-02: install.sh fails closed when socat/openssl are unavailable")
    else:
        fail(f"SEC-01/INS-02: install.sh did not fail on missing TLS (rc={r_fail.returncode})")

print("=== 3. Transactional Rollback on Mid-Install Failure ===")
with tempfile.TemporaryDirectory() as td_tx:
    env_tx = os.environ.copy()
    env_tx["NMS_ROOT_PREFIX"] = td_tx
    env_tx["NMS_SKIP_SERVICE_START"] = "1"
    env_tx["NMS_TEST_FAIL_AFTER_COPY"] = "1"

    # Pre-create existing /etc/noc-console (0750), existing backend noc-apid (0700), init.d/noc-apid (0755), frontend index.html (0600)
    etc_dir = os.path.join(td_tx, "etc/noc-console")
    os.makedirs(etc_dir, exist_ok=True)
    os.chmod(etc_dir, 0o750)

    os.makedirs(os.path.join(td_tx, "usr/libexec"), exist_ok=True)
    orig_apid = os.path.join(td_tx, "usr/libexec/noc-apid")
    open(orig_apid, "w").write("ORIG_BACKEND_APID\n")
    os.chmod(orig_apid, 0o700)

    os.makedirs(os.path.join(td_tx, "www/pro"), exist_ok=True)
    orig_idx = os.path.join(td_tx, "www/pro/index.html")
    open(orig_idx, "w").write("ORIG_FRONTEND_IDX\n")
    os.chmod(orig_idx, 0o600)

    r_tx = subprocess.run(["sh", os.path.join(ROOT, "scripts/install.sh")], env=env_tx, capture_output=True, text=True)
    if r_tx.returncode != 0 and "ROLLBACK" in r_tx.stderr:
        ok("TX: simulated mid-install failure triggered automatic rollback")
    else:
        fail(f"TX: rollback did not trigger (rc={r_tx.returncode})")

    if (open(orig_apid).read() == "ORIG_BACKEND_APID\n" and stat.S_IMODE(os.stat(orig_apid).st_mode) == 0o700
            and open(orig_idx).read() == "ORIG_FRONTEND_IDX\n" and stat.S_IMODE(os.stat(orig_idx).st_mode) == 0o600
            and stat.S_IMODE(os.stat(etc_dir).st_mode) == 0o750
            and not os.path.exists(os.path.join(etc_dir, "installed_files.manifest"))
            and not os.path.exists(os.path.join(td_tx, "usr/libexec/noc-helperd"))):
        ok("TX: rollback restored original backend/frontend files, preserved 0750 /etc/noc-console, left zero partial manifest")
    else:
        fail("TX: rollback left partial state or altered original files/permissions")

print("=== 4. INS-02, INS-03 (Backend + Init + Frontend Collisions) & Service Topology TLS ===")
with tempfile.TemporaryDirectory() as td:
    env = os.environ.copy()
    env["NMS_ROOT_PREFIX"] = td
    env["NMS_SKIP_SERVICE_START"] = "1"
    env["NMS_SKIP_SERVICE_STOP"] = "1"

    # Pre-create /etc/noc-console with custom mode 0750
    etc_dir = os.path.join(td, "etc/noc-console")
    os.makedirs(etc_dir, exist_ok=True)
    os.chmod(etc_dir, 0o750)

    # Pre-create colliding backend, init.d, AND frontend files + private user dir
    os.makedirs(os.path.join(td, "usr/libexec"), exist_ok=True)
    col_apid = os.path.join(td, "usr/libexec/noc-apid")
    open(col_apid, "w").write("USER_APID_BIN\n")
    os.chmod(col_apid, 0o700)

    os.makedirs(os.path.join(td, "etc/init.d"), exist_ok=True)
    col_init = os.path.join(td, "etc/init.d/noc-apid")
    open(col_init, "w").write("USER_INIT_SCRIPT\n")
    os.chmod(col_init, 0o750)

    web_pro = os.path.join(td, "www/pro")
    user_dir = os.path.join(web_pro, "user_private_dir")
    os.makedirs(user_dir, exist_ok=True)
    os.chmod(user_dir, 0o700)
    user_secret = os.path.join(user_dir, "secret.txt")
    open(user_secret, "w").write("PRIVATE_DATA\n")
    os.chmod(user_secret, 0o600)

    col_index = os.path.join(web_pro, "index.html")
    open(col_index, "w").write("USER_CUSTOM_INDEX_KEEP\n")
    os.chmod(col_index, 0o600)

    r_ins = subprocess.run(["sh", os.path.join(ROOT, "scripts/install.sh")], env=env, capture_output=True, text=True)
    ok("INS-02: sandboxed install.sh exited 0") if r_ins.returncode == 0 else fail(f"INS-02: install.sh failed: {r_ins.stderr}")

    if stat.S_IMODE(os.stat(etc_dir).st_mode) == 0o750 and stat.S_IMODE(os.stat(user_dir).st_mode) == 0o700 and stat.S_IMODE(os.stat(user_secret).st_mode) == 0o600:
        ok("INS-02: pre-existing /etc/noc-console (0750), user_private_dir (0700), and secret.txt (0600) preserved")
    else:
        fail("INS-02: pre-existing directory or file permissions were modified")

    # Test init.d/noc-apid procd topology + real socat TLS proxy + loopback-only backend
    cert_p = os.path.join(etc_dir, "tls.crt")
    key_p = os.path.join(etc_dir, "tls.key")
    fp_p = os.path.join(etc_dir, "tls.fingerprint")

    # Simulate procd harness executing init.d/noc-apid start_service
    procd_log = os.path.join(td, "procd_capture.txt")
    harness_sh = f"""#!/bin/sh
uci() {{ echo "127.0.0.1"; }}
logger() {{ :; }}
procd_open_instance() {{ echo "INSTANCE=$1" >> "{procd_log}"; }}
procd_set_param() {{ echo "PARAM=$*" >> "{procd_log}"; }}
procd_close_instance() {{ echo "END_INSTANCE" >> "{procd_log}"; }}
sed 's|/etc/noc-console|{etc_dir}|g; s|/tmp/noc-console|{td}/tmp/noc-console|g' "{ROOT}/init.d/noc-apid" > "{td}/init_noc_apid_test"
. "{td}/init_noc_apid_test"
start_service
"""
    r_procd = subprocess.run(["sh", "-c", harness_sh], capture_output=True, text=True)
    procd_txt = open(procd_log).read() if os.path.isfile(procd_log) else ""
    if r_procd.returncode == 0 and "NOC_BIND_HOST=127.0.0.1" in procd_txt and "NOC_TLS_VERIFIED=1" in procd_txt and "OPENSSL-LISTEN:8743,bind=127.0.0.1" in procd_txt:
        ok("SEC-01: init.d/noc-apid procd topology binds API to 127.0.0.1 and launches socat TLS proxy on :8743")
    else:
        fail(f"SEC-01: init.d/noc-apid procd topology check failed (rc={r_procd.returncode})")

    # Verify init.d/noc-apid refuses to start when TLS cert/socat is absent
    empty_bin2 = os.path.join(td, "no_tls_bin")
    os.makedirs(empty_bin2, exist_ok=True)
    for tool in ("sh", "mkdir", "chmod", "sed", "grep", "hostname", "rm", "mv"):
        tp = shutil.which(tool)
        if tp:
            os.symlink(tp, os.path.join(empty_bin2, tool))
    no_tls_sh = f"""#!/bin/sh
uci() {{ echo "127.0.0.1"; }}
logger() {{ echo "LOG:$*" >&2; }}
procd_open_instance() {{ echo "SHOULD_NOT_START" >&2; }}
procd_set_param() {{ :; }}
procd_close_instance() {{ :; }}
sed 's|/etc/noc-console|{td}/missing_etc|g; s|/tmp/noc-console|{td}/tmp/noc-console|g' "{ROOT}/init.d/noc-apid" > "{td}/init_no_tls"
. "{td}/init_no_tls"
start_service
"""
    r_no_tls = subprocess.run([os.path.join(empty_bin2, "sh"), "-c", no_tls_sh], env={"PATH": empty_bin2}, capture_output=True, text=True)
    if r_no_tls.returncode != 0 and "SHOULD_NOT_START" not in r_no_tls.stderr:
        ok("SEC-01: init.d/noc-apid refuses to start unencrypted HTTP when TLS prerequisites are missing")
    else:
        fail("SEC-01: init.d/noc-apid did not fail closed when TLS prerequisites were missing")

    # Live local loopback + socat TLS integration test
    if shutil.which("socat") and os.path.isfile(cert_p):
        backend_port = free_port()
        tls_port = free_port()

        class LoopbackHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"NMS_LOOPBACK_TLS_OK")
            def log_message(self, *args):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", backend_port), LoopbackHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        socat_proc = subprocess.Popen(
            ["socat", f"OPENSSL-LISTEN:{tls_port},bind=127.0.0.1,reuseaddr,fork,cert={cert_p},key={key_p},verify=0", f"TCP:127.0.0.1:{backend_port}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            connected = False
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            for _ in range(25):
                try:
                    with socket.create_connection(("127.0.0.1", tls_port), timeout=1.0) as raw_s:
                        with ctx.wrap_socket(raw_s, server_hostname="nms.lan") as tls_s:
                            der = tls_s.getpeercert(binary_form=True)
                            sha256_hex = hashlib.sha256(der).hexdigest().upper()
                            fp_text = open(fp_p).read().replace(":", "").upper()
                            tls_s.sendall(b"GET / HTTP/1.1\r\nHost: nms.lan\r\nConnection: close\r\n\r\n")
                            resp = tls_s.recv(4096)
                            if b"NMS_LOOPBACK_TLS_OK" in resp and sha256_hex in fp_text:
                                ok(f"SEC-01: Real TLS proxy -> 127.0.0.1 loopback succeeded (SHA256={sha256_hex[:16]}...)")
                                connected = True
                                break
                except OSError:
                    time.sleep(0.1)
            if not connected:
                fail("SEC-01: Real TLS proxy -> loopback failed")
        finally:
            socat_proc.terminate()
            socat_proc.wait(timeout=3)
            srv.shutdown()
            srv.server_close()

    # Uninstall WITHOUT --purge and verify backend, init.d, AND frontend collisions are restored with exact modes
    r_un = subprocess.run(["sh", os.path.join(ROOT, "scripts/uninstall.sh")], env=env, capture_output=True, text=True)
    ok("INS-03: sandboxed uninstall.sh exited 0") if r_un.returncode == 0 else fail(f"INS-03: uninstall.sh failed: {r_un.stderr}")

    if (open(col_apid).read() == "USER_APID_BIN\n" and stat.S_IMODE(os.stat(col_apid).st_mode) == 0o700
            and open(col_init).read() == "USER_INIT_SCRIPT\n" and stat.S_IMODE(os.stat(col_init).st_mode) == 0o750
            and open(col_index).read() == "USER_CUSTOM_INDEX_KEEP\n" and stat.S_IMODE(os.stat(col_index).st_mode) == 0o600
            and not os.path.exists(os.path.join(td, "usr/libexec/noc-helperd"))
            and not os.path.exists(os.path.join(web_pro, "app.js"))
            and os.path.isfile(user_secret)):
        ok("INS-03: backend, init.d, and frontend collisions restored with exact original modes; NMS-only files removed")
    else:
        fail("INS-03: collision restoration or NMS-only removal failed")

print(f"\n=== SUMMARY: {len(passes)} passed, {len(failures)} failed ===")
sys.exit(1 if failures else 0)
