#!/usr/bin/env python3
"""Read-only post-deployment smoke check for NMS OpenWrt Console.

Strictly issues only:
  - GET requests to read-only router/API endpoints
  - Optional POST /api/v1/auth/login when --username/--password are provided
Never mutates router state, UCI, firewall, network, or services.
"""

import argparse
import json
import ssl
import sys
import time
import urllib.error
import urllib.request


READ_ONLY_ACTIONS = (
    "firewall",
    "topology",
    "services",
    "network",
    "diagnostics",
    "auth_users",
)


def _make_ssl_ctx(insecure: bool) -> ssl.SSLContext | None:
    if not insecure:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 5.0,
    ssl_ctx: ssl.SSLContext | None = None,
) -> tuple[int, str, str | None]:
    """Return (status_code, response_text, error_string)."""
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace"), None
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return exc.code, text, None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, "", str(exc)


def _validate_action_payload(action: str, data: object) -> tuple[bool, str]:
    if not isinstance(data, dict):
        return False, f"expected JSON object, got {type(data).__name__}"
    if not data.get("ok"):
        return False, f"ok is not true: {data.get('error_code', data.get('error', 'unknown'))}"
    if action == "firewall":
        if "zones" not in data or "forwardings" not in data:
            return False, "missing zones or forwardings in firewall response"
    elif action == "topology":
        cstat = data.get("collector_status") or {}
        for key in ("ubus_network", "ip_link", "ip_addr", "ip_route"):
            if not cstat.get(key):
                return False, f"topology collector_status.{key} is false"
    elif action == "services":
        if not isinstance(data.get("services"), list):
            return False, "services is not a list"
    return True, "ok"


def run_smoke_check(
    base_url: str,
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    timeout: float = 5.0,
    insecure: bool = False,
) -> dict:
    base = base_url.rstrip("/")
    ssl_ctx = _make_ssl_ctx(insecure)
    results: list[dict] = []
    started = time.monotonic()

    # 1. Verify unauthenticated access is rejected (401)
    status, _, err = _http_request(
        f"{base}/api/v1/router?action=services",
        method="GET",
        timeout=timeout,
        ssl_ctx=ssl_ctx,
    )
    if err:
        results.append({"check": "auth_gate", "ok": False, "status": 0, "detail": err})
        return {
            "ok": False,
            "passed": 0,
            "failed": 1,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "results": results,
        }
    auth_gate_ok = status == 401
    results.append({
        "check": "auth_gate",
        "ok": auth_gate_ok,
        "status": status,
        "detail": "401 enforced" if auth_gate_ok else f"expected 401, got {status}",
    })

    # 2. Obtain bearer token if username/password provided
    if not token and username and password is not None:
        login_body = json.dumps({"username": username, "password": password}).encode("utf-8")
        l_status, l_text, l_err = _http_request(
            f"{base}/api/v1/auth/login",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=login_body,
            timeout=timeout,
            ssl_ctx=ssl_ctx,
        )
        if l_err or l_status != 200:
            results.append({
                "check": "auth_login",
                "ok": False,
                "status": l_status,
                "detail": l_err or f"login failed with HTTP {l_status}",
            })
            passed = sum(1 for r in results if r["ok"])
            return {
                "ok": False,
                "passed": passed,
                "failed": len(results) - passed,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "results": results,
            }
        try:
            l_json = json.loads(l_text)
            token = l_json.get("token")
        except json.JSONDecodeError:
            token = None
        if not token:
            results.append({"check": "auth_login", "ok": False, "status": l_status, "detail": "missing token in login response"})
            passed = sum(1 for r in results if r["ok"])
            return {
                "ok": False,
                "passed": passed,
                "failed": len(results) - passed,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "results": results,
            }
        results.append({"check": "auth_login", "ok": True, "status": 200, "detail": "token acquired"})

    auth_headers = {"Authorization": f"Bearer {token}"} if token else {}

    # 3. Read-only GET checks for core router actions
    for action in READ_ONLY_ACTIONS:
        st, text, req_err = _http_request(
            f"{base}/api/v1/router?action={action}",
            method="GET",
            headers=auth_headers,
            timeout=timeout,
            ssl_ctx=ssl_ctx,
        )
        if req_err:
            results.append({"check": f"read:{action}", "ok": False, "status": 0, "detail": req_err})
            continue
        if st != 200:
            results.append({"check": f"read:{action}", "ok": False, "status": st, "detail": f"HTTP {st}"})
            continue
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            results.append({"check": f"read:{action}", "ok": False, "status": st, "detail": f"invalid JSON: {exc}"})
            continue
        valid, detail = _validate_action_payload(action, payload)
        results.append({"check": f"read:{action}", "ok": valid, "status": st, "detail": detail})

    passed = sum(1 for r in results if r["ok"])
    failed = len(results) - passed
    return {
        "ok": failed == 0,
        "passed": passed,
        "failed": failed,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only NMS post-deployment smoke check")
    parser.add_argument("--base-url", required=True, help="Base URL of NMS API (e.g. http://192.168.1.1:8081)")
    parser.add_argument("--token", default=None, help="Pre-issued Bearer token")
    parser.add_argument("--username", default=None, help="Username for login")
    parser.add_argument("--password", default=None, help="Password for login")
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-request timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    parser.add_argument("--json", action="store_true", help="Print JSON summary")
    args = parser.parse_args()

    report = run_smoke_check(
        base_url=args.base_url,
        token=args.token,
        username=args.username,
        password=args.password,
        timeout=args.timeout,
        insecure=args.insecure,
    )
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for r in report["results"]:
            tag = "PASS" if r["ok"] else "FAIL"
            print(f"[{tag}] {r['check']} (HTTP {r['status']}): {r['detail']}")
        print(f"SUMMARY: {report['passed']} passed, {report['failed']} failed ({report['elapsed_ms']} ms)")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
