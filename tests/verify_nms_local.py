#!/usr/bin/env python3
"""
NMS (Network Management System) - Local & Offline Regression Suite (P4)
Zero network or SSH calls to any live router.
Covers:
  - Static JS/Shell/JSON/CSP hygiene
  - SEC-01 regression (real TLS enforcement, no blind NOC_TLS_ACTIVE trust)
  - INS-02 regression (sandboxed install.sh permissions, ucode modules, unified /tmp/noc-console)
  - INS-03 regression (sandboxed uninstall.sh ownership manifest & shared-dir preservation)
"""
import json
import os
import re
import stat
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
passes = []
failures = []


def ok(msg: str) -> None:
    passes.append(msg)
    print(f"[PASS] {msg}")


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"[FAIL] {msg}", file=sys.stderr)


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
    p = os.path.join(ROOT, rel)
    r = subprocess.run(["node", "--check", p], capture_output=True, text=True)
    if r.returncode == 0:
        ok(f"node --check {rel}")
    else:
        fail(f"node --check {rel}: {r.stderr.strip()}")

for rel in ("scripts/install.sh", "scripts/uninstall.sh", "init.d/noc-apid", "init.d/noc-helperd"):
    p = os.path.join(ROOT, rel)
    r = subprocess.run(["sh", "-n", p], capture_output=True, text=True)
    if r.returncode == 0:
        ok(f"sh -n {rel}")
    else:
        fail(f"sh -n {rel}: {r.stderr.strip()}")

for rel in ("frontend/manifest.json", "frontend/glossary_ar.json", "schemas/noc_schemas.json"):
    p = os.path.join(ROOT, rel)
    try:
        json.load(open(p, encoding="utf-8"))
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

print("=== 2. SEC-01 Regression: Real TLS & Cookie Enforcement ===")
apid_txt = open(os.path.join(ROOT, "backend/noc-apid"), encoding="utf-8").read()
init_apid_txt = open(os.path.join(ROOT, "init.d/noc-apid"), encoding="utf-8").read()

if "getenv('NOC_TLS_ACTIVE')" in apid_txt:
    fail("SEC-01: noc-apid still reads unverified NOC_TLS_ACTIVE env var")
else:
    ok("SEC-01: blind NOC_TLS_ACTIVE flag removed from noc-apid")

if "getenv('NOC_TLS_VERIFIED') == '1'" in apid_txt and "BIND_HOST == '127.0.0.1'" in apid_txt and "fs.stat(TLS_CERT_PATH)" in apid_txt:
    ok("SEC-01: noc-apid enforces loopback + verified TLS + cert/key before Secure cookies")
else:
    fail("SEC-01: noc-apid missing strict TLS_ACTIVE verification")

if "HTTPS_PORT=8743" in init_apid_txt and "OPENSSL-LISTEN:" in init_apid_txt and "TCP:127.0.0.1:" in init_apid_txt:
    ok("SEC-01: init.d/noc-apid configures TLS termination on :8743 (no :80/:443 LuCI conflict)")
else:
    fail("SEC-01: init.d/noc-apid missing TLS termination setup on :8743")

print("=== 3. INS-02 & INS-03 Regression: Sandboxed Install & Uninstall ===")
install_txt = open(os.path.join(ROOT, "scripts/install.sh"), encoding="utf-8").read()
for mod in ("ucode-mod-uloop", "ucode-mod-digest", "ucode-mod-fs", "ucode-mod-ubus", "ucode-mod-uci", "ucode-mod-socket"):
    if mod in install_txt:
        ok(f"INS-02: install.sh checks/includes {mod}")
    else:
        fail(f"INS-02: install.sh missing {mod}")

with tempfile.TemporaryDirectory() as td:
    env = os.environ.copy()
    env["NMS_ROOT_PREFIX"] = td
    env["NMS_SKIP_SERVICE_START"] = "1"
    env["NMS_SKIP_SERVICE_STOP"] = "1"

    # Pre-create a user-owned file in /www/pro to test INS-03 preservation
    user_web_dir = os.path.join(td, "www/pro/custom_dir")
    os.makedirs(user_web_dir, exist_ok=True)
    user_file = os.path.join(td, "www/pro/user_custom_keep.txt")
    with open(user_file, "w", encoding="utf-8") as f:
        f.write("user-owned-content\n")

    r_ins = subprocess.run(["sh", os.path.join(ROOT, "scripts/install.sh")], env=env, capture_output=True, text=True)
    if r_ins.returncode != 0:
        fail(f"INS-02: sandboxed install.sh failed: {r_ins.stderr}")
    else:
        ok("INS-02: sandboxed install.sh exited 0")

    web_root_mode = stat.S_IMODE(os.stat(os.path.join(td, "www/pro")).st_mode)
    sub_dir_mode = stat.S_IMODE(os.stat(user_web_dir).st_mode)
    idx_file_mode = stat.S_IMODE(os.stat(os.path.join(td, "www/pro/index.html")).st_mode)
    if web_root_mode == 0o755 and sub_dir_mode == 0o755 and idx_file_mode == 0o644:
        ok("INS-02: directories have 0755 and web files have 0644")
    else:
        fail(f"INS-02: bad modes web_root={oct(web_root_mode)} subdir={oct(sub_dir_mode)} file={oct(idx_file_mode)}")

    manifest_p = os.path.join(td, "etc/noc-console/installed_files.manifest")
    if os.path.isfile(manifest_p) and "/www/pro/index.html" in open(manifest_p).read():
        ok("INS-02/INS-03: installed_files.manifest created with NMS-owned paths")
    else:
        fail("INS-02/INS-03: installed_files.manifest missing or incomplete")

    if os.path.isdir(os.path.join(td, "tmp/noc-console")):
        ok("INS-02: unified /tmp/noc-console runtime directory created")
    else:
        fail("INS-02: /tmp/noc-console missing")

    # Simulate user config in /etc/noc-console
    user_cfg = os.path.join(td, "etc/noc-console/auth.json")
    with open(user_cfg, "w", encoding="utf-8") as f:
        f.write('{"test":true}\n')

    # Run uninstall WITHOUT --purge
    r_un = subprocess.run(["sh", os.path.join(ROOT, "scripts/uninstall.sh")], env=env, capture_output=True, text=True)
    if r_un.returncode == 0:
        ok("INS-03: sandboxed uninstall.sh exited 0")
    else:
        fail(f"INS-03: sandboxed uninstall.sh failed: {r_un.stderr}")

    if not os.path.exists(os.path.join(td, "www/pro/index.html")) and not os.path.exists(os.path.join(td, "usr/libexec/noc-apid")):
        ok("INS-03: NMS-owned files removed cleanly")
    else:
        fail("INS-03: NMS-owned files still remain after uninstall")

    if os.path.isfile(user_file) and os.path.isfile(user_cfg):
        ok("INS-03: user-owned /www/pro file and /etc/noc-console config preserved")
    else:
        fail("INS-03: uninstall deleted user-owned file or config")

    # Run uninstall WITH --purge
    r_purge = subprocess.run(["sh", os.path.join(ROOT, "scripts/uninstall.sh"), "--purge"], env=env, capture_output=True, text=True)
    if r_purge.returncode == 0 and not os.path.exists(os.path.join(td, "etc/noc-console")) and os.path.isfile(user_file):
        ok("INS-03: uninstall.sh --purge removed /etc/noc-console while keeping user-owned /www/pro file")
    else:
        fail("INS-03: uninstall.sh --purge failed preservation or purge check")

print(f"\n=== SUMMARY: {len(passes)} passed, {len(failures)} failed ===")
sys.exit(1 if failures else 0)
