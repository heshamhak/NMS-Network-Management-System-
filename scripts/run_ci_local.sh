#!/bin/sh
# Full NMS CI verification runner (local + OpenWrt 24.10.0 & 25.12.6 chroots + packaging + UI).
# Fails closed if ANY required check fails OR if any required chroot suite reports skipped > 0.
set -eu

REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== [1/5] Static & Security/WCAG/Schema Suite (verify_noc_p15.py) ==="
python3 tests/verify_noc_p15.py

echo "=== [2/5] Local & Integration Suite (verify_nms_local.py) ==="
python3 tests/verify_nms_local.py

echo "=== [3/5] OpenWrt 24.10.0 & 25.12.6 Chroot Compatibility Suite (verify_phase3d_compat.py) ==="
OUT_3D="$(python3 tests/verify_phase3d_compat.py)"
printf '%s\n' "$OUT_3D"
if ! printf '%s\n' "$OUT_3D" | grep -Eq "PHASE 3D SUMMARY: [0-9]+ passed, 0 failed, 0 skipped"; then
  echo "CI ERROR: verify_phase3d_compat.py had failures or skipped tests!" >&2
  exit 1
fi

echo "=== [4/5] OpenWrt Native Packaging, Signing & Migration Suite (verify_phase5a_pkg.py) ==="
python3 tests/verify_phase5a_pkg.py

echo "=== [5/5] Frontend RBAC, Restore Parity & SSE Suite (verify_phase5c_ui.py) ==="
python3 tests/verify_phase5c_ui.py

echo "=== ALL NMS CI SUITES PASSED (0 failed, 0 skipped) ==="
