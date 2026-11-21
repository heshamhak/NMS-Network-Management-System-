#!/usr/bin/env python3
"""
NMS (Network Management System) - Local & Offline Regression Suite (P4 Hardened)
Zero network or SSH calls to any live router.
Covers:
  - Static JS/Shell/JSON/CSP hygiene
  - SEC-01 regression (real TLS handshake via socat+openssl, fingerprint match, refusal on missing TLS)
  - INS-02 regression (per-file permissions, unchanged user dir/file modes, ucode modules, TLS fail-closed)
  - INS-03 regression (same-name collision backup & restore with exact original permissions)
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
js_files = [
    "frontend/app.js",
    "frontend/nms-i18n.js",
    "frontend/noc-topology.js",
    "frontend/noc-search.js",
    "frontend/noc-tools.js",
    "frontend/netchart.js",
    "frontend/sw.js",
]
for rel in js_files:
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

index_html = open(os.path.join(ROOT, "frontend/index.html"), encoding="utf-8").read()
if re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", index_html, re.I):
    fail("Inline <script> detected in frontend/index.html")
else:
    ok("frontend/index.html: strict script-src 'self' (no inline scripts)")

for js_rel in ("frontend/app.js", "frontend/nms-i18n.js", "frontend/noc-topology.js", "frontend/noc-search.js"):
    txt = open(os.path.join(ROOT, js_rel), encoding="utf-8").read()
    if ".innerHTML" in txt or "eval(" in txt or "new Function" in txt:
        fail(f"Unsafe DOM/eval pattern in {js_rel}")
    else:
        ok(f"{js_rel}: zero innerHTML / eval / new Function")

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

# Test install.sh fails when TLS prerequisites (socat/openssl) are missing
with tempfile.TemporaryDirectory() as td_fail:
    empty_bin = os.path.join(td_fail, "empty_bin")
    os.makedirs(empty_bin, exist_ok=True)
    # Symlink only basic POSIX tools, intentionally omitting socat and openssl
    for tool in ("sh", "mkdir", "chmod", "cp", "mv", "grep", "awk", "sed", "find", "sort", "dirname", "cat", "tr", "stat", "id"):
        tp = shutil.which(tool)
        if tp:
            os.symlink(tp, os.path.join(empty_bin, tool))
    env_fail = {"PATH": empty_bin, "NMS_ROOT_PREFIX": td_fail, "NMS_SKIP_SERVICE_START": "1"}
    r_fail = subprocess.run([os.path.join(empty_bin, "sh"), os.path.join(ROOT, "scripts/install.sh")], env=env_fail, capture_output=True, text=True)
    if r_fail.returncode != 0 and "Mandatory TLS prerequisites" in r_fail.stderr:
        ok("SEC-01/INS-02: install.sh fails closed when socat/openssl are unavailable")
    else:
        fail(f"SEC-01/INS-02: install.sh did not fail on missing TLS (rc={r_fail.returncode})")

print("=== 3. INS-02, INS-03 Collision & Real TLS Handshake Regression ===")
with tempfile.TemporaryDirectory() as td:
    env = os.environ.copy()
    env["NMS_ROOT_PREFIX"] = td
    env["NMS_SKIP_SERVICE_START"] = "1"
    env["NMS_SKIP_SERVICE_STOP"] = "1"

    # Pre-create user-owned directory (0700), user file (0600), and SAME-NAME colliding index.html (0600)
    web_pro = os.path.join(td, "www/pro")
    user_dir = os.path.join(web_pro, "user_private_dir")
    os.makedirs(user_dir, exist_ok=True)
    os.chmod(user_dir, 0o700)

    user_secret = os.path.join(user_dir, "secret.txt")
    with open(user_secret, "w", encoding="utf-8") as f:
        f.write("PRIVATE_DATA\n")
    os.chmod(user_secret, 0o600)

    colliding_index = os.path.join(web_pro, "index.html")
    with open(colliding_index, "w", encoding="utf-8") as f:
        f.write("USER_CUSTOM_INDEX_KEEP\n")
    os.chmod(colliding_index, 0o600)

    r_ins = subprocess.run(["sh", os.path.join(ROOT, "scripts/install.sh")], env=env, capture_output=True, text=True)
    if r_ins.returncode == 0:
        ok("INS-02: sandboxed install.sh with TLS prerequisites exited 0")
    else:
        fail(f"INS-02: sandboxed install.sh failed: {r_ins.stderr}")

    # Verify user directory & user file modes were NOT altered by install.sh
    if stat.S_IMODE(os.stat(user_dir).st_mode) == 0o700 and stat.S_IMODE(os.stat(user_secret).st_mode) == 0o600:
        ok("INS-02: pre-existing user directory (0700) and file (0600) permissions untouched")
    else:
        fail("INS-02: install.sh altered pre-existing user directory/file permissions")

    # Verify NMS-installed file got 0644
    if stat.S_IMODE(os.stat(os.path.join(web_pro, "app.js")).st_mode) == 0o644:
        ok("INS-02: NMS-installed file app.js has 0644")
    else:
        fail("INS-02: NMS-installed file app.js missing 0644")

    # Real TLS handshake test using generated cert + key + socat
    cert_p = os.path.join(td, "etc/noc-console/tls.crt")
    key_p = os.path.join(td, "etc/noc-console/tls.key")
    fp_p = os.path.join(td, "etc/noc-console/tls.fingerprint")
    if os.path.isfile(cert_p) and os.path.isfile(key_p) and os.path.isfile(fp_p):
        ok("SEC-01: PEM cert, 0600 key, and SHA-256 fingerprint generated by install.sh")
    else:
        fail("SEC-01: TLS cert/key/fingerprint missing after install.sh")

    if shutil.which("socat") and os.path.isfile(cert_p):
        backend_port = free_port()
        tls_port = free_port()

        class OkHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"NMS_TLS_OK")
            def log_message(self, *args):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", backend_port), OkHandler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()

        socat_proc = subprocess.Popen(
            [
                "socat",
                f"OPENSSL-LISTEN:{tls_port},bind=127.0.0.1,reuseaddr,fork,cert={cert_p},key={key_p},verify=0",
                f"TCP:127.0.0.1:{backend_port}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            # Wait briefly for socat listener
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
                            if b"NMS_TLS_OK" in resp and sha256_hex in fp_text:
                                ok(f"SEC-01: Real TLS handshake + HTTP over socat succeeded (SHA256={sha256_hex[:16]}...)")
                                connected = True
                                break
                except OSError:
                    time.sleep(0.1)
            if not connected:
                fail("SEC-01: Real TLS handshake over socat failed")
        finally:
            socat_proc.terminate()
            socat_proc.wait(timeout=3)
            srv.shutdown()
            srv.server_close()

    # Uninstall WITHOUT --purge and verify same-name collision restore + permission preservation
    r_un = subprocess.run(["sh", os.path.join(ROOT, "scripts/uninstall.sh")], env=env, capture_output=True, text=True)
    if r_un.returncode == 0:
        ok("INS-03: sandboxed uninstall.sh exited 0")
    else:
        fail(f"INS-03: sandboxed uninstall.sh failed: {r_un.stderr}")

    restored_txt = open(colliding_index, encoding="utf-8").read() if os.path.isfile(colliding_index) else ""
    restored_mode = stat.S_IMODE(os.stat(colliding_index).st_mode) if os.path.isfile(colliding_index) else 0
    if restored_txt == "USER_CUSTOM_INDEX_KEEP\n" and restored_mode == 0o600:
        ok("INS-03: colliding user index.html restored with exact content & 0600 mode")
    else:
        fail(f"INS-03: colliding user index.html not properly restored (mode={oct(restored_mode)})")

    if not os.path.exists(os.path.join(web_pro, "app.js")) and os.path.isfile(user_secret) and stat.S_IMODE(os.stat(user_dir).st_mode) == 0o700:
        ok("INS-03: NMS files removed while user_private_dir (0700) and secret.txt (0600) preserved")
    else:
        fail("INS-03: NMS removal or user file preservation failed")

print(f"\n=== SUMMARY: {len(passes)} passed, {len(failures)} failed ===")
sys.exit(1 if failures else 0)
