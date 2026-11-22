#!/bin/sh
# Full NMS CI verification runner (local + OpenWrt 24.10.0 & 25.12.6 chroots + packaging + UI).
# Fails closed if ANY required check fails OR if any required chroot suite reports skipped > 0.
set -eu

REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$REPO_ROOT"

run_strict() {
  _label="$1"
  _cmd="$2"
  echo "=== $_label ==="
  _out="$(sh -c "$_cmd")"
  printf '%s\n' "$_out"
  if printf '%s\n' "$_out" | grep -Eq "SUMMARY:.*[1-9][0-9]* failed"; then
    echo "CI ERROR: $_label reported failed tests!" >&2
    exit 1
  fi
  if printf '%s\n' "$_out" | grep -Eq "(\[SKIP\]|[1-9][0-9]* skipped)"; then
    echo "CI ERROR: $_label reported skipped tests!" >&2
    exit 1
  fi
}

run_strict "[1/5] Static & Security/WCAG/Schema Suite (verify_noc_p15.py)" "python3 tests/verify_noc_p15.py"
run_strict "[2/5] Local & Integration Suite (verify_nms_local.py)" "python3 tests/verify_nms_local.py"
run_strict "[3/5] OpenWrt 24.10.0 & 25.12.6 Chroot Compatibility Suite (verify_phase3d_compat.py)" "python3 tests/verify_phase3d_compat.py"
run_strict "[4/5] OpenWrt Native Packaging, Signing & Migration Suite (verify_phase5a_pkg.py)" "python3 tests/verify_phase5a_pkg.py"
run_strict "[5/5] Frontend RBAC, Restore Parity & SSE Suite (verify_phase5c_ui.py)" "python3 tests/verify_phase5c_ui.py"
run_strict "[6/6] Post-Deployment Smoke Check Suite (verify_smoke_check.py)" "python3 tests/verify_smoke_check.py"

echo "=== ALL NMS CI SUITES PASSED (0 failed, 0 skipped) ==="
