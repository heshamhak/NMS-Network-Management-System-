#!/usr/bin/env python3
"""Unit & integration tests for scripts/smoke_check.py."""

import http.server
import json
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import smoke_check  # noqa: E402


class _MockState:
    def __init__(self):
        self.requests: list[tuple[str, str]] = []
        self.fail_action: str | None = None
        self.hang_action: str | None = None


def _make_handler(state: _MockState):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):  # noqa: A002
            pass

        def _send_json(self, code: int, obj: dict):
            raw = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            state.requests.append(("POST", self.path))
            if self.path == "/api/v1/auth/login":
                length = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(length)
                self._send_json(200, {"ok": True, "token": "test-token-123"})
                return
            self._send_json(405, {"ok": False, "error": "unexpected POST"})

        def do_GET(self):
            state.requests.append(("GET", self.path))
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            action = (qs.get("action") or [""])[0]

            if self.headers.get("Authorization") != "Bearer test-token-123":
                self._send_json(401, {"ok": False, "error": "unauthorized"})
                return

            if state.hang_action == action:
                time.sleep(0.8)

            if state.fail_action == action:
                self._send_json(503, {"ok": False, "error_code": "UNAVAILABLE"})
                return

            if action == "firewall":
                self._send_json(200, {"ok": True, "zones": [{"name": "lan"}], "forwardings": [{"src": "lan", "dest": "wan"}]})
            elif action == "topology":
                self._send_json(200, {
                    "ok": True,
                    "collector_status": {
                        "ubus_network": True,
                        "ip_link": True,
                        "ip_addr": True,
                        "ip_route": True,
                    },
                })
            elif action == "services":
                self._send_json(200, {"ok": True, "services": [{"name": "noc-helperd"}]})
            elif action in ("network", "diagnostics", "auth_users"):
                self._send_json(200, {"ok": True})
            else:
                self._send_json(404, {"ok": False, "error": "unknown action"})

    return Handler


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    passed = 0
    failed = 0

    def check(name: str, cond: bool, detail: str = ""):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"[PASS] {name}")
        else:
            failed += 1
            print(f"[FAIL] {name}: {detail}")

    state = _MockState()
    port = _free_port()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), _make_handler(state))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base_url = f"http://127.0.0.1:{port}"

    try:
        # 1. All-pass + read-only guarantee
        rep = smoke_check.run_smoke_check(base_url, username="admin", password="secret", timeout=2.0)
        check("all_pass", rep["ok"] and rep["failed"] == 0 and rep["passed"] == 8, str(rep))
        non_get = [r for r in state.requests if r[0] != "GET" and r[1] != "/api/v1/auth/login"]
        check("read_only_requests_only", len(non_get) == 0, str(non_get))

        # 2. Service unavailable (503) on topology
        state.fail_action = "topology"
        rep_fail = smoke_check.run_smoke_check(base_url, token="test-token-123", timeout=2.0)
        check("detects_503_topology", (not rep_fail["ok"]) and rep_fail["failed"] == 1, str(rep_fail))
        state.fail_action = None

        # 3. Timeout handling
        state.hang_action = "firewall"
        rep_to = smoke_check.run_smoke_check(base_url, token="test-token-123", timeout=0.25)
        check("detects_timeout", (not rep_to["ok"]) and rep_to["failed"] >= 1, str(rep_to))
        state.hang_action = None

        # 4. Recovery after failure
        rep_rec = smoke_check.run_smoke_check(base_url, token="test-token-123", timeout=2.0)
        check("recovery_after_failure", rep_rec["ok"] and rep_rec["failed"] == 0, str(rep_rec))

        # 5. CLI invocation
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "smoke_check.py"), "--base-url", base_url, "--token", "test-token-123", "--json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        check("cli_exit_zero", proc.returncode == 0 and '"ok": true' in proc.stdout, proc.stderr)
    finally:
        srv.shutdown()
        srv.server_close()

    # 6. Connection refused (service down)
    rep_down = smoke_check.run_smoke_check(f"http://127.0.0.1:{port}", token="test-token-123", timeout=1.0)
    check("detects_connection_refused", (not rep_down["ok"]) and rep_down["failed"] >= 1, str(rep_down))

    print(f"SUMMARY: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
