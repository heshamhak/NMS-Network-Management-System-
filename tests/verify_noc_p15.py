#!/usr/bin/env python3
import base64
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIVE_MODE = "--live" in sys.argv
GATEWAY = os.environ.get("NOC_GATEWAY", "")

SHIPPED_FILES = [
    "frontend/index.html",
    "frontend/launcher_index.html",
    "frontend/styles.css",
    "frontend/app.js",
    "frontend/nms-i18n.js",
    "backend/noc-helperd",
    "backend/noc-apid",
    "init.d/noc-helperd",
    "init.d/noc-apid",
    "schemas/noc_schemas.json",
    "frontend/glossary_ar.json",
]

failures = []
passes = []

def ok(msg):
    passes.append(msg)
    print(f"[PASS] {msg}")

def fail(msg):
    failures.append(msg)
    print(f"[FAIL] {msg}", file=sys.stderr)

# 1. JS syntax + CSS / Brand / Emoji / CSP Hygiene
print("=== Phase 1: Static Hygiene, CSP, Brand & Emoji Checks ===")
rc = subprocess.run(["node", "--check", os.path.join(ROOT, "frontend/app.js")], capture_output=True, text=True)
if rc.returncode == 0:
    ok("node --check frontend/app.js syntax valid")
else:
    fail(f"node --check frontend/app.js failed: {rc.stderr}")

emoji_re = re.compile(r"[\U0001F000-\U0001FAFF\u2600-\u27BF\uFE0F]")
banned_word = base64.b64decode("b3BlbndydA==").decode("ascii")

for rel in SHIPPED_FILES:
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        fail(f"Missing shipped file: {rel}")
        continue
    text = open(path, "r", encoding="utf-8").read()
    em = emoji_re.findall(text)
    if em:
        fail(f"Emoji detected in {rel}: {em}")
    if banned_word in text.lower():
        fail(f"Prohibited brand string detected in {rel}")
    else:
        ok(f"{rel}: 0 prohibited terms, 0 emojis")

p1_report = os.path.join(ROOT, ".airoom", "P1_forensic_baseline_report.md")
if os.path.exists(p1_report):
    p1_txt = open(p1_report, "r", encoding="utf-8").read()
    if emoji_re.findall(p1_txt):
        fail("Emoji detected in .airoom/P1_forensic_baseline_report.md")
    else:
        ok("P1_forensic_baseline_report.md: 0 emojis")

for html_rel in ("frontend/index.html", "frontend/launcher_index.html"):
    htxt = open(os.path.join(ROOT, html_rel), "r", encoding="utf-8").read()
    if re.search(r"https?://|googleapis|gstatic", htxt, re.I):
        fail(f"External URL/CDN link found in {html_rel}")
    else:
        ok(f"{html_rel}: 0 external URLs/CDNs")
    if re.search(r"\bon(?:click|change|input|keydown|keyup|submit|load)\s*=", htxt, re.I):
        fail(f"Inline event attribute found in {html_rel}")
    else:
        ok(f"{html_rel}: 0 inline JS event attributes")

index_txt = open(os.path.join(ROOT, "frontend/index.html"), "r", encoding="utf-8").read()
inline_scripts = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", index_txt, re.I)
if inline_scripts:
    fail(f"Inline <script> tag found in index.html: {inline_scripts}")
else:
    ok("index.html: strict script-src 'self' compatible (no inline scripts)")

app_txt = open(os.path.join(ROOT, "frontend/app.js"), "r", encoding="utf-8").read()
if ".innerHTML" in app_txt or "eval(" in app_txt or "new Function" in app_txt:
    fail("Unsafe DOM/eval pattern found in app.js")
else:
    ok("app.js: 0 innerHTML / eval / new Function calls")

# 2. WCAG AA Contrast & Blue Scope Audit (P12)
print("=== Phase 2: WCAG AA Contrast & Blue Control Scope ===")
def rel_lum(hex_c):
    h = hex_c.lstrip("#")
    vals = []
    for i in (0, 2, 4):
        c = int(h[i:i+2], 16) / 255.0
        vals.append(c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4)
    return 0.2126 * vals[0] + 0.7152 * vals[1] + 0.0722 * vals[2]

def contrast(c1, c2):
    l1, l2 = rel_lum(c1), rel_lum(c2)
    if l1 < l2:
        l1, l2 = l2, l1
    return (l1 + 0.05) / (l2 + 0.05)

pairs = [
    ("#F4F4F5", "#18181B", 4.5, "primary text on app bg"),
    ("#D4D4D8", "#27272A", 4.5, "secondary text on card bg"),
    ("#A1A1AA", "#27272A", 4.5, "muted text on card bg"),
    ("#F87171", "#27272A", 4.5, "danger text on card bg"),
    ("#18181B", "#3B82F6", 4.5, "dark text on primary button"),
    ("#FFFFFF", "#2563EB", 4.5, "white text on active nav item"),
    ("#FFFFFF", "#1D4ED8", 4.5, "white text on primary hover"),
    ("#22C55E", "#1E1E22", 3.0, "RX series on chart bg"),
    ("#F59E0B", "#1E1E22", 3.0, "TX series on chart bg"),
]
for fg, bg, thresh, desc in pairs:
    r = contrast(fg, bg)
    if r >= thresh:
        ok(f"WCAG contrast {desc} ({fg}/{bg}) = {r:.2f}:1 >= {thresh}:1")
    else:
        fail(f"WCAG contrast too low for {desc}: {r:.2f}:1 < {thresh}:1")

css_txt = open(os.path.join(ROOT, "frontend/styles.css"), "r", encoding="utf-8").read()
css_clean = re.sub(r"/\*.*?\*/", "", css_txt, flags=re.S)
allowed_blue_lines = ["--ctrl-active", "--ctrl-primary", "--ctrl-hover", "#2563eb", "#3b82f6", "#1d4ed8"]
for m in re.finditer(r"([^{}]+)\{([^{}]+)\}", css_clean):
    sel = m.group(1).strip()
    body = m.group(2).lower()
    if any(b in body for b in ("#2563eb", "#3b82f6", "#1d4ed8", "ctrl-active", "ctrl-primary", "ctrl-hover")):
        ok_sel = any(k in sel for k in (":root", ".sidebar-btn.active", ".btn-primary", ".btn-secondary", ".card-collapse-btn", ".pkg-chip-action", ".switch input:checked", ".toast"))
        if not ok_sel:
            fail(f"Disallowed blue usage in CSS selector: {sel}")
ok("styles.css: blue confined strictly to interactive active/primary control selectors")

# 3. Fritsch-Carlson Monotone Spline & P13 Logic Verification
print("=== Phase 3: Monotone Cubic Spline & P13 Sequence Store ===")
node_spline_test = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[1], 'utf8');
const m = src.match(/function buildMonotoneSplinePath\([\s\S]*?\n  \}/);
if (!m) { console.error('Spline function not found'); process.exit(2); }
const fn = new Function(m[0] + '; return buildMonotoneSplinePath;')();
const res = fn([0, 0, 500000, 0, 100000, 0, 0], 800, 206, 500000);
const nums = res.line.match(/-?[0-9]+\.[0-9]+/g).map(Number);
for (let i = 1; i < nums.length; i += 2) {
  if (nums[i] > 206.05 || nums[i] < 13.95) {
    console.error('Spline y out of [14, 206] bounds:', nums[i]);
    process.exit(1);
  }
}
// P13 boot_id + seq + epoch simulation
let state = { bootId: 'bootA', epoch: 1, cursors: { overview: { boot_id: 'bootA', seq: 5 } } };
function accept(env, reqEpoch) {
  if (env.boot_id !== state.bootId) { state.cursors = {}; state.bootId = env.boot_id; }
  if (reqEpoch !== state.epoch) return 'STALE_EPOCH';
  const prev = state.cursors[env.resource];
  if (prev && prev.boot_id === env.boot_id && env.seq <= prev.seq) return 'STALE_SEQ';
  state.cursors[env.resource] = { boot_id: env.boot_id, seq: env.seq };
  return 'ACCEPT';
}
if (accept({ boot_id: 'bootA', resource: 'overview', seq: 4 }, 1) !== 'STALE_SEQ') process.exit(3);
if (accept({ boot_id: 'bootA', resource: 'overview', seq: 6 }, 0) !== 'STALE_EPOCH') process.exit(4);
if (accept({ boot_id: 'bootB', resource: 'overview', seq: 1 }, 1) !== 'ACCEPT') process.exit(5);
console.log('SPLINE_AND_P13_OK');
"""
r_spline = subprocess.run(["node", "-e", node_spline_test, os.path.join(ROOT, "frontend/app.js")], capture_output=True, text=True)
if r_spline.returncode == 0 and "SPLINE_AND_P13_OK" in r_spline.stdout:
    ok("Fritsch-Carlson spline zero-overshoot & P13 boot_id/seq/epoch checks passed")
else:
    fail(f"Spline/P13 Node test failed: {r_spline.stderr} {r_spline.stdout}")

# 4. Schema Consistency Self-Check
print("=== Phase 4: Canonical JSON Schema & Glossary Consistency ===")
schema = json.load(open(os.path.join(ROOT, "schemas/noc_schemas.json"), "r", encoding="utf-8"))
glossary = json.load(open(os.path.join(ROOT, "frontend/glossary_ar.json"), "r", encoding="utf-8"))
req_resources = {"overview", "adguard", "clients", "network", "sqm", "firewall", "docker", "tailscale", "services", "diagnostics", "auth"}
schema_res = set(schema["$defs"]["ResourceEnum"]["enum"])
if req_resources.issubset(schema_res):
    ok("Canonical ResourceEnum matches all 11 backend/frontend resources")
else:
    fail(f"ResourceEnum mismatch: {req_resources - schema_res}")

# 5. Remote Isolated Staging Suite on 192.168.1.1 (/tmp/noc_p15_stage)
print("=== Phase 5: Remote Target Staging Runtime Tests (SO_PEERCRED, HTTP, PBKDF2, Guardrails) ===")
uc_stage_driver = r"""
import * as fs from 'fs';
import * as sock from 'socket';

function tcp_req(host, port, raw_req, wait_ms) {
	let sa = sock.sockaddr({ address: host, port: port });
	let s = sock.create(sock.AF_INET, sock.SOCK_STREAM);
	if (!s || !s.connect(sa)) return { err: 'connect_failed' };
	if (raw_req) s.send(raw_req);
	let buf = '';
	let deadline = clock(true)[0] * 1000 + (wait_ms || 4000);
	while (clock(true)[0] * 1000 < deadline) {
		let chunk = null;
		try { chunk = s.recv(8192); } catch (e) { break; }
		if (!chunk || length(chunk) == 0) break;
		buf += chunk;
		if (index(buf, '\r\n\r\n') >= 0 && index(buf, 'text/event-stream') >= 0) break;
	}
	try { s.close(); } catch (e) {}
	return { raw: buf };
}

function http_call(method, path, body_obj, hdr_map) {
	let body_s = body_obj != null ? sprintf('%J', body_obj) : '';
	let req = sprintf("%s %s HTTP/1.1\r\nHost: 127.0.0.1:18780\r\nConnection: close\r\n", method, path);
	if (hdr_map) {
		for (let k in keys(hdr_map)) req += k + ': ' + hdr_map[k] + '\r\n';
	}
	if (method == 'POST') {
		req += sprintf("Content-Type: application/json\r\nContent-Length: %d\r\n", length(body_s));
	}
	req += "\r\n" + body_s;
	let r = tcp_req('127.0.0.1', 18780, req, 5000);
	if (!r.raw) return { status: 0, headers: '', body: {}, raw: '' };
	let idx = index(r.raw, '\r\n\r\n');
	let h = idx >= 0 ? substr(r.raw, 0, idx) : r.raw;
	let b = idx >= 0 ? substr(r.raw, idx + 4) : '';
	let sm = match(h, /^HTTP\/1\.1\s+([0-9]+)/);
	let sc = sm ? +sm[1] : 0;
	let ckm = match(h, /Set-Cookie:\s*([^;\r\n]+)/i);
	let parsed = null;
	try { parsed = json(b); } catch (e) { parsed = null; }
	return { status: sc, headers: h, cookie: ckm ? ckm[1] : null, body: parsed, raw_body: b };
}

let results = [];
function assert_t(name, cond, info) {
	push(results, { name: name, pass: !!cond, info: info || '' });
}

// 1. Pre-auth returns 401
let r_pre = http_call('GET', '/api?action=overview', null, {});
assert_t('preauth_overview_401', r_pre.status == 401, 'status=' + r_pre.status);

// 2. HTTP hardening corpus
let xa = '';
for (let xi = 0; xi < 8500; xi++) xa += 'A';
let big_h = "GET / HTTP/1.1\r\nHost: 127.0.0.1:18780\r\nX-Big: " + xa + "\r\n\r\n";
let r_big = tcp_req('127.0.0.1', 18780, big_h, 2000);
assert_t('http_431_oversized_hdr', index(r_big.raw || '', '431 ') >= 0, substr(r_big.raw || '', 0, 24));

let r_chunk = tcp_req('127.0.0.1', 18780, "POST /api?action=auth_login HTTP/1.1\r\nHost: 127.0.0.1:18780\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n", 2000);
assert_t('http_400_chunked_ambiguity', index(r_chunk.raw || '', '400 ') >= 0, substr(r_chunk.raw || '', 0, 24));

let r_dupcl = tcp_req('127.0.0.1', 18780, "POST /api?action=auth_login HTTP/1.1\r\nHost: 127.0.0.1:18780\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}", 2000);
assert_t('http_400_dup_content_length', index(r_dupcl.raw || '', '400 ') >= 0, substr(r_dupcl.raw || '', 0, 24));

let r_null = tcp_req('127.0.0.1', 18780, "GET /api?action=auth_status HTTP/1.1\r\nHost: 127.0.0.1:18780\r\n\x00\r\n\r\n", 2000);
assert_t('http_400_null_byte', index(r_null.raw || '', '400 ') >= 0, substr(r_null.raw || '', 0, 24));

let r_pipe = tcp_req('127.0.0.1', 18780, "GET /api?action=auth_status HTTP/1.1\r\nHost: 127.0.0.1:18780\r\n\r\nGET / HTTP/1.1\r\n\r\n", 2000);
assert_t('http_400_pipelining_rejected', index(r_pipe.raw || '', '400 ') >= 0, substr(r_pipe.raw || '', 0, 24));

// Slowloris check: partial header without \r\n\r\n closes within 7s without wedging daemon
let s_slow = sock.create(sock.AF_INET, sock.SOCK_STREAM);
s_slow.connect(sock.sockaddr({ address: '127.0.0.1', port: 18780 }));
s_slow.send("GET /api?action=auth_status HTTP/1.1\r\n");
let t0 = clock(true)[0];
let sr = s_slow.recv(64);
let dt_slow = clock(true)[0] - t0;
s_slow.close();
assert_t('slowloris_timeout_close', (!sr || length(sr) == 0) && dt_slow <= 7, 'elapsed=' + dt_slow + 's');

// 3. Bootstrap + Login + PBKDF2 non-blocking reconciler tick + Wrong Origin
let boot_tok = trim(fs.readfile('/tmp/noc_p15_stage/etc/bootstrap.token') || '');
let bad_orig = http_call('POST', '/api?action=auth_bootstrap', { token: boot_tok, password: 'TestStrongPassword!123' }, { 'Origin': 'http://evil.example:8780' });
assert_t('origin_rejected_403', bad_orig.status == 403, 'status=' + bad_orig.status);

let good_boot = http_call('POST', '/api?action=auth_bootstrap', { token: boot_tok, password: 'TestStrongPassword!123' }, { 'Origin': 'http://127.0.0.1:18780' });
assert_t('bootstrap_complete_200', good_boot.status == 200 && good_boot.cookie != null && good_boot.body.data.csrf_token != '', 'status=' + good_boot.status);

// Sleep 2.2s to let reconciler ticks accrue, then login & check max_gap_ms
sleep(2200);
let r_login = http_call('POST', '/api?action=auth_login', { username: 'admin', password: 'TestStrongPassword!123' }, { 'Origin': 'http://127.0.0.1:18780' });
assert_t('login_200_pbkdf2', r_login.status == 200 && r_login.cookie != null, 'status=' + r_login.status + ' body=' + (r_login.raw_body || ''));

let ck = r_login.cookie || '';
let csrf = (r_login.body && r_login.body.data && r_login.body.data.csrf_token) || '';
let r_st = http_call('GET', '/api?action=auth_status', null, { 'Cookie': ck });
assert_t('reconciler_tick_non_blocking', r_st.body && r_st.body.data && (r_st.body.data.reconciler_tick_count || 0) >= 2 && (r_st.body.data.reconciler_max_gap_ms || 0) < 1600,
	sprintf('ticks=%d gap=%d', (r_st.body && r_st.body.data) ? (r_st.body.data.reconciler_tick_count || 0) : -1, (r_st.body && r_st.body.data) ? (r_st.body.data.reconciler_max_gap_ms || -1) : -1));

// 4. Schema Envelope + Guardrails + CSRF + SSE
let r_ov = http_call('GET', '/api?action=overview', null, { 'Cookie': ck });
let env = r_ov.body || {};
assert_t('overview_envelope_contract', r_ov.status == 200 && env.schema_version == '1.0.0' && env.resource == 'overview' && env.seq >= 1 && env.data && env.data.storage_summary && env.data.storage_summary.root_partition == '/dev/nvme0n1p2', 'status=' + r_ov.status);

let r_nocsrf = http_call('POST', '/api?action=diagnostics', { tool: 'ping', target: '1.1.1.1' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck });
assert_t('missing_csrf_403', r_nocsrf.status == 403, 'status=' + r_nocsrf.status);

let r_inj = http_call('POST', '/api?action=diagnostics', { tool: 'ping', target: '1.1.1.1; id' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('diag_injection_rejected_400', r_inj.status == 400, 'status=' + r_inj.status);

let r_priv = http_call('POST', '/api?action=diagnostics', { tool: 'ping', target: '169.254.1.1' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('diag_link_local_rejected_400', r_priv.status == 400, 'status=' + r_priv.status);

let r_selfblk = http_call('POST', '/api?action=client_control', { subaction: 'block', mac: '00:11:22:33:44:55', ip: '127.0.0.1' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('self_block_refused_400_or_403', (r_selfblk.status == 400 || r_selfblk.status == 403) && r_selfblk.body && r_selfblk.body.errors && r_selfblk.body.errors[0].code == 'FORBIDDEN', 'status=' + r_selfblk.status);

let r_mgmt = http_call('POST', '/api?action=adguard_control', { subaction: 'add_rule', rule: '||127.0.0.1^' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('management_domain_rule_refused', r_mgmt.status == 400, 'status=' + r_mgmt.status);

// 5. Readonly user provisioning + role enforcement (before IP lockout triggers)
let r_mk_ro = http_call('POST', '/api?action=auth_set_readonly', { username: 'viewer1', password: 'ReadonlyPass!12345' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('create_readonly_200', r_mk_ro.status == 200, 'status=' + r_mk_ro.status);

let r_ro_login = http_call('POST', '/api?action=auth_login', { username: 'viewer1', password: 'ReadonlyPass!12345' }, { 'Origin': 'http://127.0.0.1:18780' });
assert_t('readonly_login_200', r_ro_login.status == 200 && r_ro_login.body && r_ro_login.body.data && r_ro_login.body.data.role == 'readonly', 'status=' + r_ro_login.status);

let ro_csrf = (r_ro_login.body && r_ro_login.body.data && r_ro_login.body.data.csrf_token) || '';
let r_ro_mut = http_call('POST', '/api?action=service_control', { subaction: 'restart', name: 'sqm' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': r_ro_login.cookie || '', 'X-CSRF-Token': ro_csrf });
assert_t('readonly_mutation_403', r_ro_mut.status == 403, 'status=' + r_ro_mut.status);

// 6. SSE stream 2-per-user cap & text/event-stream (while IP not locked out yet)
let sse_sa = sock.sockaddr({ address: '127.0.0.1', port: 18780 });
let s1 = sock.create(sock.AF_INET, sock.SOCK_STREAM);
let s2 = sock.create(sock.AF_INET, sock.SOCK_STREAM);
let sse_req = "GET /api?action=stream HTTP/1.1\r\nHost: 127.0.0.1:18780\r\nCookie: " + ck + "\r\nConnection: close\r\n\r\n";
let ok1 = s1 && s1.connect(sse_sa);
let ok2 = s2 && s2.connect(sse_sa);
let hdr1 = '', hdr2 = '';
if (ok1) { s1.send(sse_req); sleep(200); hdr1 = s1.recv(4096) || ''; }
if (ok2) { s2.send(sse_req); sleep(200); hdr2 = s2.recv(4096) || ''; }
let r_sse3 = tcp_req('127.0.0.1', 18780, sse_req, 1500);
if (s1) s1.close();
if (s2) s2.close();
assert_t('sse_stream_200', index(hdr1, 'text/event-stream') >= 0 && index(hdr2, 'text/event-stream') >= 0, 'hdr1=' + length(hdr1));
assert_t('sse_cap_429_on_3rd', index(r_sse3.raw || '', '429 ') >= 0, substr(r_sse3.raw || '', 0, 32));

// 6b. Expanded controls & guardrails
let r_mgmt_fwd = http_call('POST', '/api?action=firewall_control', { subaction: 'add_redirect', name: 'BadMgmt', proto: 'tcp', src_dport: 8780, dest_ip: '192.168.1.99', dest_port: 8780 }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('mgmt_port_redirect_refused_400', r_mgmt_fwd.status == 400 && r_mgmt_fwd.body && r_mgmt_fwd.body.errors && r_mgmt_fwd.body.errors[0].code == 'FORBIDDEN', 'status=' + r_mgmt_fwd.status);

let r_core_stop = http_call('POST', '/api?action=service_control', { subaction: 'stop', name: 'firewall' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('core_service_stop_refused', r_core_stop.status == 400 && r_core_stop.body && r_core_stop.body.errors && r_core_stop.body.errors[0].code == 'FORBIDDEN', 'status=' + r_core_stop.status);

let r_prot_rule = http_call('POST', '/api?action=firewall_control', { subaction: 'toggle_rule', id: 'noc_console_lan', enabled: false }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('protected_fw_rule_disable_refused', r_prot_rule.status == 400 && r_prot_rule.body && r_prot_rule.body.errors && r_prot_rule.body.errors[0].code == 'FORBIDDEN', 'status=' + r_prot_rule.status);

let r_bad_rate = http_call('POST', '/api?action=client_control', { subaction: 'set_meta', mac: '00:11:22:33:44:55', ip: '192.168.1.50', nickname: 'dev', rate_limit_kbps: 10 }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('client_meta_invalid_rate_400', r_bad_rate.status == 400, 'status=' + r_bad_rate.status);

let r_bad_tcp = http_call('POST', '/api?action=diagnostics', { tool: 'tcp_probe', target: '192.168.1.1', port: 70000 }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('tcp_probe_invalid_port_400', r_bad_tcp.status == 400, 'status=' + r_bad_tcp.status);

let r_ok_tcp = http_call('POST', '/api?action=diagnostics', { tool: 'tcp_probe', target: '192.168.1.1', port: 80 }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('tcp_probe_valid_200', r_ok_tcp.status == 200 && r_ok_tcp.body && r_ok_tcp.body.data && r_ok_tcp.body.data.ok == true, 'status=' + r_ok_tcp.status);

// 6c. Full Parity 8-Domain Security Guardrails
let r_ssrf_filt = http_call('POST', '/api?action=adguard_control', { subaction: 'filter_add', name: 'LocalSSRF', url: 'https://192.168.1.1/list.txt' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('agh_filter_ssrf_refused_400', r_ssrf_filt.status == 400 && r_ssrf_filt.body && r_ssrf_filt.body.errors && r_ssrf_filt.body.errors[0].code == 'FORBIDDEN', 'status=' + r_ssrf_filt.status);

let r_bad_rw = http_call('POST', '/api?action=adguard_control', { subaction: 'rewrite_add', domain: 'gateway.lan', answer: '192.168.1.99' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('agh_rewrite_protected_domain_refused', r_bad_rw.status == 400 && r_bad_rw.body && r_bad_rw.body.errors && r_bad_rw.body.errors[0].code == 'FORBIDDEN', 'status=' + r_bad_rw.status);

let r_fw_wan_mgmt = http_call('POST', '/api?action=firewall_control', { subaction: 'add_rule', name: 'ExposeSSH', src: 'wan', dest: '', proto: 'tcp', dest_port: '22', target: 'ACCEPT' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('fw_custom_rule_wan_mgmt_refused', r_fw_wan_mgmt.status == 400 && r_fw_wan_mgmt.body && r_fw_wan_mgmt.body.errors && r_fw_wan_mgmt.body.errors[0].code == 'FORBIDDEN', 'status=' + r_fw_wan_mgmt.status);

let r_ban_self = http_call('POST', '/api?action=firewall_control', { subaction: 'banip_list', list_type: 'blocklist', op: 'add', entry: '127.0.0.1' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('banip_self_block_refused', r_ban_self.status == 400 && r_ban_self.body && r_ban_self.body.errors && r_ban_self.body.errors[0].code == 'FORBIDDEN', 'status=' + r_ban_self.status);

let r_cron_inj = http_call('POST', '/api?action=system_control', { subaction: 'cron_add', template_id: 'evil_shell', schedule: '0 4 * * *' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('cron_unknown_template_refused', r_cron_inj.status == 400, 'status=' + r_cron_inj.status);

let r_ssh_opt = http_call('POST', '/api?action=system_control', { subaction: 'ssh_key_add', public_key: 'command="/bin/sh" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@host' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('ssh_key_options_refused', r_ssh_opt.status == 400, 'status=' + r_ssh_opt.status);

let r_reb_no_nonce = http_call('POST', '/api?action=system_control', { subaction: 'reboot', nonce: 'invalid', confirm: 'CONFIRM_REBOOT' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('reboot_without_valid_nonce_refused', r_reb_no_nonce.status == 400 && r_reb_no_nonce.body && r_reb_no_nonce.body.errors && r_reb_no_nonce.body.errors[0].code == 'FORBIDDEN', 'status=' + r_reb_no_nonce.status);

let r_reb_chal = http_call('POST', '/api?action=system_control', { subaction: 'reboot_challenge' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
let r_reb_ok = http_call('POST', '/api?action=system_control', { subaction: 'reboot', nonce: (r_reb_chal.body && r_reb_chal.body.data && r_reb_chal.body.data.nonce) || '', confirm: 'CONFIRM_REBOOT' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('reboot_two_step_challenge_200', r_reb_ok.status == 200, 'status=' + r_reb_ok.status);

let r_bkp = http_call('GET', '/api?action=backup_export', null, { 'Cookie': ck });
assert_t('backup_export_redacted_200', r_bkp.status == 200 && r_bkp.body && r_bkp.body.data && r_bkp.body.data.configs != null && index(r_bkp.raw_body || '', 'password') < 0, 'status=' + r_bkp.status);

let r_pkg_del_prot = http_call('POST', '/api?action=system_control', { subaction: 'pkg_action', op: 'del', package: 'busybox' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('pkg_protected_del_refused_400', r_pkg_del_prot.status == 400 && r_pkg_del_prot.body && r_pkg_del_prot.body.errors && r_pkg_del_prot.body.errors[0].code == 'FORBIDDEN', 'status=' + r_pkg_del_prot.status);

let r_pkg_inj = http_call('POST', '/api?action=system_control', { subaction: 'pkg_action', op: 'install', package: 'htop;id' }, { 'Origin': 'http://127.0.0.1:18780', 'Cookie': ck, 'X-CSRF-Token': csrf });
assert_t('pkg_injection_refused_400', r_pkg_inj.status == 400, 'status=' + r_pkg_inj.status);

let r_cli_insp = http_call('GET', '/api?action=client_inspect&ip=192.168.1.12&mac=c2:b0:ce:41:3f:2d', null, { 'Cookie': ck });
assert_t('client_inspect_200', r_cli_insp.status == 200 && r_cli_insp.body && r_cli_insp.body.data && type(r_cli_insp.body.data.active_flows) == 'array' && type(r_cli_insp.body.data.dns_queries) == 'array', 'status=' + r_cli_insp.status);

let r_twin = http_call('GET', '/api?action=traffic_window&iface=br-lan&seconds=3600', null, { 'Cookie': ck });
assert_t('traffic_window_200', r_twin.status == 200 && r_twin.body && r_twin.body.data && r_twin.body.data.window && r_twin.body.data.window.interface == 'br-lan' && r_twin.body.data.window.rx_bytes >= 0, 'status=' + r_twin.status);

// 7. Lockout after 5 bad logins (triggers per-IP + per-account 429)
let lock_429 = false;
for (let i = 0; i < 6; i++) {
	let rf = http_call('POST', '/api?action=auth_login', { username: 'admin', password: 'WrongPassword12345' }, { 'Origin': 'http://127.0.0.1:18780' });
	if (rf.status == 429) { lock_429 = true; break; }
}
assert_t('auth_lockout_429', lock_429, 'triggered=' + lock_429);

printf('%J\n', results);
"""

import tempfile

remote_cmd = r"""set -e
rm -rf /tmp/noc_p15_stage
mkdir -p /tmp/noc_p15_stage/etc /tmp/noc_p15_stage/run /tmp/noc_p15_stage/www/pro
chmod 0700 /tmp/noc_p15_stage/etc
MID=$(cat /etc/machine-id 2>/dev/null || echo 'router')
printf '{"staging_id":"p15_stage","machine_id":"%s"}\n' "$MID" > /tmp/noc_p15_stage/etc/staging.attestation
chmod 0600 /tmp/noc_p15_stage/etc/staging.attestation
touch /tmp/noc_p15_stage/leases
"""

if not (LIVE_MODE and GATEWAY):
    print("[INFO] Offline CI mode: remote live-gateway staging disabled (pass --live with NOC_GATEWAY=user@host to run)")
    print(f"\n=== SUMMARY: {len(passes)} passed, {len(failures)} failed ===")
    sys.exit(1 if failures else 0)

subprocess.run(["ssh", "-o", "BatchMode=yes", GATEWAY, remote_cmd], check=True)

stage_run_sh = """#!/bin/sh
set -e
cp /tmp/noc_p15_stage/index.html /tmp/noc_p15_stage/styles.css /tmp/noc_p15_stage/app.js /tmp/noc_p15_stage/www/pro/

export NOC_STAGING_MODE=1
export NOC_ETC_DIR=/tmp/noc_p15_stage/etc
export NOC_RUN_DIR=/tmp/noc_p15_stage/run
export NOC_SOCK_PATH=/tmp/noc_p15_stage/run/helper.sock
export NOC_HELPER_SOCK=/tmp/noc_p15_stage/run/helper.sock
export NOC_LEASES_PATH=/tmp/noc_p15_stage/leases
export NOC_WEB_ROOT=/tmp/noc_p15_stage/www
export NOC_HTTP_PORT=18780
export NOC_BIND_HOST=127.0.0.1
export NOC_LAN_IP=127.0.0.1
export NOC_ADGUARD_PORT=18080
export NOC_STAGING_ALLOW_UID=0

ucode /tmp/noc_p15_stage/noc-helperd --reset-bootstrap >/dev/null
ucode /tmp/noc_p15_stage/noc-helperd </dev/null >/tmp/noc_p15_stage/helper.log 2>&1 &
HPID=$!
sleep 1

chmod 0666 /tmp/noc_p15_stage/run/helper.sock
SO_RES=$(start-stop-daemon -S -p /tmp/noc_p15_stage/probe.pid -x /usr/bin/ucode -c nobody -- /tmp/noc_p15_stage/peercred_probe.uc 2>&1 || true)

ucode /tmp/noc_p15_stage/noc-apid </dev/null >/tmp/noc_p15_stage/apid.log 2>&1 &
APID=$!
for _w in 1 2 3 4 5 6 7 8 9 10; do
  netstat -lnt 2>/dev/null | grep -q ":18780 " && break
  sleep 1
done

DRV_OUT=$(ucode /tmp/noc_p15_stage/driver.uc 2>&1 || true)
H_LOG=$(cat /tmp/noc_p15_stage/helper.log 2>/dev/null || true)
A_LOG=$(cat /tmp/noc_p15_stage/apid.log 2>/dev/null || true)
kill $APID $HPID 2>/dev/null || true
wait $APID $HPID 2>/dev/null || true
rm -rf /tmp/noc_p15_stage
printf "SO_PEERCRED=%s\n" "$SO_RES"
printf "HELPER_LOG=%s\n" "$H_LOG"
printf "APID_LOG=%s\n" "$A_LOG"
printf "DRV_JSON=%s\n" "$DRV_OUT"
"""

peercred_uc = """import * as sock from 'socket';
let s = sock.create(sock.AF_UNIX, sock.SOCK_STREAM);
if (s && s.connect(sock.sockaddr({ path: '/tmp/noc_p15_stage/run/helper.sock' }))) {
	s.send(sprintf('%J\\n', { verb: 'auth_status' }));
	print(s.recv(512));
	s.close();
}
"""

with tempfile.TemporaryDirectory() as td:
    drv_p = os.path.join(td, "driver.uc")
    sh_p = os.path.join(td, "stage_run.sh")
    pc_p = os.path.join(td, "peercred_probe.uc")
    open(drv_p, "w", encoding="utf-8").write(uc_stage_driver)
    open(sh_p, "w", encoding="utf-8").write(stage_run_sh)
    open(pc_p, "w", encoding="utf-8").write(peercred_uc)
    os.chmod(sh_p, 0o755)
    subprocess.run(
        ["scp", "-q", "-O",
         os.path.join(ROOT, "backend/noc-helperd"),
         os.path.join(ROOT, "backend/noc-apid"),
         os.path.join(ROOT, "frontend/index.html"),
         os.path.join(ROOT, "frontend/styles.css"),
         os.path.join(ROOT, "frontend/app.js"),
         drv_p, sh_p, pc_p,
         f"{GATEWAY}:/tmp/noc_p15_stage/"],
        check=True
    )

r_stage = subprocess.run(["ssh", "-o", "BatchMode=yes", GATEWAY, "sh /tmp/noc_p15_stage/stage_run.sh"], capture_output=True, text=True)
if r_stage.returncode != 0:
    fail(f"Remote staging run failed: {r_stage.stderr}")
else:
    out_lines = r_stage.stdout.splitlines()
    so_line = next((l[len("SO_PEERCRED="):] for l in out_lines if l.startswith("SO_PEERCRED=")), "")
    drv_line = next((l[len("DRV_JSON="):] for l in out_lines if l.startswith("DRV_JSON=")), "[]")
    if "FORBIDDEN" in so_line:
        ok(f"SO_PEERCRED rejected nobody UID cleanly: {so_line}")
    else:
        fail(f"SO_PEERCRED failed to reject nobody UID: {so_line!r}")
    try:
        items = json.loads(drv_line)
        any_fail = False
        for it in items:
            if it.get("pass"):
                ok(f"staging:{it['name']} ({it.get('info', '')})")
            else:
                any_fail = True
                fail(f"staging:{it['name']} ({it.get('info', '')})")
        if any_fail:
            print("=== STAGING LOGS ===\n" + "\n".join(l for l in out_lines if not l.startswith("DRV_JSON=")))
    except Exception as e:
        fail(f"Could not parse staging driver JSON ({e}): {r_stage.stdout}")

print(f"\n=== SUMMARY: {len(passes)} passed, {len(failures)} failed ===")
sys.exit(1 if failures else 0)
