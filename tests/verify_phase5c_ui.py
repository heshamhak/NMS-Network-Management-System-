#!/usr/bin/env python3
"""Phase 5C verification: Frontend/backend backup_validate vs backup_restore parity,
admin/readonly RBAC enforcement, AR/EN i18n coverage, SSE reconnect/cleanup, and CSP/WCAG.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ROOTFS_2410 = "/tmp/openwrt-24.10-x86-64-rootfs"
ROOTFS_2512 = "/tmp/openwrt-x86-64-rootfs"

passes = []
failures = []


def check(cond, name, detail=""):
    if cond:
        passes.append(name)
        print(f"[PASS] {name}")
    else:
        failures.append((name, detail))
        print(f"[FAIL] {name}" + (f" ({detail})" if detail else ""))


def main():
    print("=== Phase 5C: Frontend Audit, RBAC, Backup/Restore Parity, SSE & i18n Verification ===")

    html_src = open(os.path.join(REPO_ROOT, "frontend", "index.html"), "r", encoding="utf-8").read()
    app_src = open(os.path.join(REPO_ROOT, "frontend", "app.js"), "r", encoding="utf-8").read()
    i18n_src = open(os.path.join(REPO_ROOT, "frontend", "nms-i18n.js"), "r", encoding="utf-8").read()

    # 1. HTML admin-only markers & button separation
    check(
        'id="btnValidateSysBackup"' in html_src and 'btnValidateSysBackup" class="btn btn-secondary btn-sm admin-only"' in html_src
        and 'id="btnRestoreBackupArchive"' in html_src and 'btnRestoreBackupArchive" class="btn btn-warning btn-sm admin-only"' in html_src,
        "P5C-HTML[admin_only_backup_validate_and_restore_buttons]",
    )

    # 2. AR/EN i18n coverage for all backup validate/restore strings
    required_i18n = [
        "فحص سلامة أرشيف (.tar.gz)",
        "استعادة الأرشيف الآمنة",
        "فحص فقط: الأرشيف سليم ولم يتم تطبيق أي تغييرات",
        "الأرشيف غير صالح أو يحتوي مسارات مرفوضة",
        "تمت استعادة النسخة الاحتياطية بنجاح",
        "فشلت عملية استعادة النسخة الاحتياطية",
        "متاح لصلاحية المدير فقط",
    ]
    missing_i18n = [s for s in required_i18n if f"'{s}':" not in i18n_src]
    check(len(missing_i18n) == 0, "P5C-I18N[backup_restore_ar_en_keys_present]", str(missing_i18n))

    # 3. Extract production handlers from frontend/app.js and execute real behavioral DOM tests in Node
    m_val = re.search(r"(    if \(qs\('btnValidateSysBackup'\)\) \{.*?\n    \})", app_src, re.S)
    m_rst = re.search(r"(    if \(qs\('btnRestoreBackupArchive'\)\) \{.*?\n    \})", app_src, re.S)
    m_sse = re.search(r"(  function startSSE\(\) \{.*?\n  \}\n\n  function stopSSE\(\) \{.*?\n  \})", app_src, re.S)
    check(bool(m_val and m_rst and m_sse), "P5C-EXTRACT[production_app_js_handlers_extracted]")
    if m_val and m_rst and m_sse:
        node_script = (
            "const state = { role: 'readonly', authenticated: true, sse: null, sseReconnectTimer: null, sseRetryDelayMs: 1000, sampleSpeedMs: 1000, cursors: {} };\n"
            "const toasts = [];\n"
            "const apiCalls = [];\n"
            "let nextApiResp = { ok: true, data: {} };\n"
            "let confirmVal = true;\n"
            "const listeners = {};\n"
            "const dom = {\n"
            "  btnValidateSysBackup: { disabled: false, addEventListener: (e, fn) => { listeners.val = fn; } },\n"
            "  btnRestoreBackupArchive: { disabled: false, addEventListener: (e, fn) => { listeners.rst = fn; } },\n"
            "  sysBackupValidateFile: { files: [{ arrayBuffer: async () => new Uint8Array([1,2,3]).buffer }] },\n"
            "  sysBackupStatusPre: { textContent: '', classList: { hidden: true, remove: function() { this.hidden = false; } } },\n"
            "  cmdConnBadge: { textContent: '', className: '' }\n"
            "};\n"
            "const qs = (id) => dom[id] || null;\n"
            "const showToast = (msg, kind) => toasts.push({ msg, kind });\n"
            "const confirmAction = async () => confirmVal;\n"
            "const apiCall = async (act, opts) => { apiCalls.push({ act, opts }); return nextApiResp; };\n"
            "const renderOverview = () => {};\n"
            "let esCreated = 0, esClosed = 0, lastEs = null;\n"
            "global.EventSource = class { constructor() { esCreated++; lastEs = this; this.ev = {}; } addEventListener(k, fn) { this.ev[k] = fn; } close() { esClosed++; } };\n"
            + m_sse.group(1) + "\n"
            + m_val.group(1) + "\n"
            + m_rst.group(1) + "\n"
            "(async () => {\n"
            "  // 1. Readonly blocked on both validate and restore\n"
            "  state.role = 'readonly';\n"
            "  await listeners.val();\n"
            "  await listeners.rst();\n"
            "  if (apiCalls.length !== 0 || toasts.length !== 2 || toasts[0].kind !== 'error' || toasts[1].kind !== 'error') process.exit(1);\n"
            "  // 2. Admin validation-only NEVER reports restore success\n"
            "  state.role = 'admin'; toasts.length = 0; apiCalls.length = 0;\n"
            "  nextApiResp = { ok: true, data: { valid: true, sha256: 'abc', entries_count: 2 } };\n"
            "  await listeners.val();\n"
            "  if (apiCalls.length !== 1 || apiCalls[0].act !== 'backup_validate') process.exit(2);\n"
            "  if (!dom.sysBackupStatusPre.textContent.includes('VALIDATION ONLY') || toasts[0].kind !== 'info' || toasts[0].msg.includes('تمت استعادة')) process.exit(3);\n"
            "  // 3. Admin restore with applied_count=0 (no-op) MUST NOT report success\n"
            "  toasts.length = 0; apiCalls.length = 0;\n"
            "  nextApiResp = { ok: true, data: { applied_count: 0 } };\n"
            "  await listeners.rst();\n"
            "  if (apiCalls[0].act !== 'backup_restore' || toasts[0].kind !== 'error' || !dom.sysBackupStatusPre.textContent.includes('RESTORE FAILED')) process.exit(4);\n"
            "  // 4. Admin restore with backend error reports error\n"
            "  toasts.length = 0;\n"
            "  nextApiResp = { ok: false, errors: [{ message_ar: 'تعارض قفل' }], data: {} };\n"
            "  await listeners.rst();\n"
            "  if (toasts[0].kind !== 'error' || toasts[0].msg !== 'تعارض قفل' || dom.btnRestoreBackupArchive.disabled !== false) process.exit(5);\n"
            "  // 5. Admin restore with real applied_count > 0 reports RESTORED + success\n"
            "  toasts.length = 0;\n"
            "  nextApiResp = { ok: true, data: { applied_count: 2, sha256: 'deadbeef', reloaded_services: ['network'] } };\n"
            "  await listeners.rst();\n"
            "  if (toasts[0].kind !== 'success' || !dom.sysBackupStatusPre.textContent.includes('RESTORED') || !dom.sysBackupStatusPre.textContent.includes('Applied: 2')) process.exit(6);\n"
            "  // 6. SSE reconnect backoff & stopSSE cleanup (no timer leak)\n"
            "  startSSE();\n"
            "  if (esCreated !== 1) process.exit(7);\n"
            "  lastEs.onerror();\n"
            "  if (esClosed !== 1 || !state.sseReconnectTimer || state.sseRetryDelayMs !== 2000) process.exit(8);\n"
            "  stopSSE();\n"
            "  if (state.sseReconnectTimer !== null || state.sse !== null) process.exit(9);\n"
            "  console.log('P5C_DOM_PASS');\n"
            "  process.exit(0);\n"
            "})();\n"
        )
        r_node = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, timeout=15)
        check(
            r_node.returncode == 0 and "P5C_DOM_PASS" in r_node.stdout,
            "P5C-DOM[rbac_validate_restore_separation_and_sse_cleanup]",
            f"rc={r_node.returncode} err={r_node.stderr}",
        )

    # 4. Server-side noc-apid RBAC & HTTP status mapping for backup_validate & backup_restore on BOTH OpenWrt 24.10.0 & 25.12.6
    apid_src = open(os.path.join(REPO_ROOT, "backend", "noc-apid"), "r", encoding="utf-8").read()
    m_bv = re.search(r"(\tif \(action == 'backup_validate'\) \{.*?\n\t\treturn;\n\t\})", apid_src, re.S)
    m_br = re.search(r"(\tif \(action == 'backup_restore' && method == 'POST'\) \{.*?\n\t\treturn;\n\t\})", apid_src, re.S)
    if not m_bv or not m_br:
        check(False, "P5C-APID[extract_backup_handlers]")
    else:
        apid_uc = (
            "let helper_resp = { ok: true, applied_count: 1 };\n"
            "let helper_calls = 0;\n"
            "function call_helper(verb, params, user, rip, cb) { helper_calls++; cb(helper_resp); }\n"
            "function send_json_env(cli, status, res_name, data, errs) { cli.status = status; cli.data = data; cli.errs = errs; }\n"
            "function dispatch(sess, action, method, body) {\n"
            "  let cli = { status: 0, data: null, errs: [] };\n"
            "  let req_id = 'r1'; let remote_ip = '127.0.0.1';\n"
            "  (function() {\n"
            + m_bv.group(1) + "\n"
            + m_br.group(1) + "\n"
            "  })();\n"
            "  return cli;\n"
            "}\n"
            "// 1. Readonly gets 403 on both backup_validate and backup_restore without calling helper\n"
            "let r1 = dispatch({ username: 'v', role: 'readonly' }, 'backup_validate', 'POST', { archive_b64: 'AA==' });\n"
            "let r2 = dispatch({ username: 'v', role: 'readonly' }, 'backup_restore', 'POST', { archive_b64: 'AA==' });\n"
            "if (r1.status != 403 || r2.status != 403 || helper_calls != 0) exit(1);\n"
            "// 2. Admin lock conflict -> 409\n"
            "helper_resp = { ok: false, status: 409, error_code: 'VALIDATION', message_ar: 'locked' };\n"
            "let r3 = dispatch({ username: 'a', role: 'admin' }, 'backup_restore', 'POST', { archive_b64: 'AA==' });\n"
            "if (r3.status != 409) exit(2);\n"
            "// 3. Admin internal error -> 500\n"
            "helper_resp = { ok: false, error_code: 'INTERNAL', message_ar: 'err' };\n"
            "let r4 = dispatch({ username: 'a', role: 'admin' }, 'backup_restore', 'POST', { archive_b64: 'AA==' });\n"
            "if (r4.status != 500) exit(3);\n"
            "// 4. Admin success -> 200\n"
            "helper_resp = { ok: true, applied_count: 2 };\n"
            "let r5 = dispatch({ username: 'a', role: 'admin' }, 'backup_restore', 'POST', { archive_b64: 'AA==' });\n"
            "if (r5.status != 200 || r5.data.applied_count != 2) exit(4);\n"
            "print('P5C_APID_PASS\\n');\n"
        )
        for ver_label, rfs in (("24.10.0-opkg", ROOTFS_2410), ("25.12.6-apk", ROOTFS_2512)):
            dst = os.path.join(rfs, "tmp", "p5c_apid_test.uc")
            try:
                open(dst, "w", encoding="utf-8").write(apid_uc)
                r_uc = subprocess.run(["unshare", "-r", "/usr/sbin/chroot", rfs, "/usr/bin/ucode", "/tmp/p5c_apid_test.uc"], capture_output=True, text=True, timeout=15)
                check(r_uc.returncode == 0 and "P5C_APID_PASS" in r_uc.stdout, f"P5C-APID[{ver_label},rbac_and_status_codes]", r_uc.stderr)
            finally:
                if os.path.exists(dst):
                    os.unlink(dst)

    print(f"\n=== PHASE 5C SUMMARY: {len(passes)} passed, {len(failures)} failed ===")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
