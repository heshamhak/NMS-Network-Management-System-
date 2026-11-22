// Executed directly by OpenWrt 24.10.0 & 25.12.6 ucode runtime against production backend/nms_access_dhcp.uc
import * as nms_ad from '/tmp/p3a_test/nms_access_dhcp.uc';

let passed = 0;
let failed = 0;

function check(cond, label, detail) {
	if (cond) {
		passed++;
		printf('[PASS] %s\n', label);
	} else {
		failed++;
		printf('[FAIL] %s (%s)\n', label, detail || '');
	}
}

// 1. RBAC: readonly denied on admin-only GET endpoints and all POSTs
let r_ro_alerts = nms_ad.check_rbac_access({ username: 'viewer', role: 'readonly' }, 'alerts', 'GET');
let r_ro_quotas = nms_ad.check_rbac_access({ username: 'viewer', role: 'readonly' }, 'device_quotas', 'GET');
let r_ro_post = nms_ad.check_rbac_access({ username: 'viewer', role: 'readonly' }, 'clients', 'POST');
let r_ro_ov = nms_ad.check_rbac_access({ username: 'viewer', role: 'readonly' }, 'overview', 'GET');
let r_adm_alerts = nms_ad.check_rbac_access({ username: 'admin', role: 'admin' }, 'alerts', 'GET');
check(!r_ro_alerts.ok && r_ro_alerts.status == 403 && !r_ro_quotas.ok && !r_ro_post.ok && r_ro_ov.ok && r_adm_alerts.ok, 'P4D-RBAC[admin_only_endpoints_enforced]');

// 2. Session revocation on credential/role change
let sess_map = {
	s1: { username: 'viewer', role: 'readonly' },
	s2: { username: 'viewer', role: 'readonly' },
	s3: { username: 'admin', role: 'admin' }
};
let rev = nms_ad.revoke_sessions_for_user(sess_map, 'viewer', null);
check(rev == 2 && !sess_map.s1 && !sess_map.s2 && !!sess_map.s3, 'P4D-RBAC[revokes_target_user_sessions_only]');

// 3. DHCP pool config validation (rejects out-of-range, 0m/0h, non-numeric, fractions, empty strings)
let dp_bad_range = nms_ad.validate_dhcp_pool_config({ start: 200, limit: 60, leasetime: '1h' });
let dp_zero_m = nms_ad.validate_dhcp_pool_config({ start: 10, limit: 50, leasetime: '0m' });
let dp_zero_h = nms_ad.validate_dhcp_pool_config({ start: 10, limit: 50, leasetime: '0h' });
let dp_abc = nms_ad.validate_dhcp_pool_config({ start: 'abc', limit: 50, leasetime: '1h' });
let dp_frac = nms_ad.validate_dhcp_pool_config({ start: 10.5, limit: 50, leasetime: '1h' });
let dp_empty = nms_ad.validate_dhcp_pool_config({ start: '', limit: 50, leasetime: '1h' });
let dp_csize_bad = nms_ad.validate_dhcp_pool_config({ start: 10, limit: 50, leasetime: '1h', cachesize: '12.5' });
let dp_ok = nms_ad.validate_dhcp_pool_config({ start: 10, limit: 50, leasetime: '2h', rebind_protection: true, cachesize: 500 });
check(!dp_bad_range.ok && !dp_zero_m.ok && !dp_zero_h.ok && !dp_abc.ok && !dp_frac.ok && !dp_empty.ok && !dp_csize_bad.ok && dp_ok.ok && dp_ok.start == '10' && dp_ok.leasetime == '2h', 'P4D-DHCP[pool_validation_strict_ints_and_min_leasetime]');

// 4. Local domain duplicate detection
let fqdn_ok = function(d) { return !!match(d, /^[a-z0-9.-]+$/); };
let blocked_no = function(d) { return d == 'router.lan'; };
let ip_ok = function(i) { return !!match(i, /^192\.168\.[0-9]+\.[0-9]+$/); };
let doms = [{ name: 'nas.lan', ip: '192.168.1.50' }];
let d_dup = nms_ad.validate_local_domain_input('NAS.LAN', '192.168.1.60', doms, fqdn_ok, blocked_no, ip_ok);
let d_blk = nms_ad.validate_local_domain_input('router.lan', '192.168.1.60', doms, fqdn_ok, blocked_no, ip_ok);
let d_ok = nms_ad.validate_local_domain_input('printer.lan', '192.168.1.60', doms, fqdn_ok, blocked_no, ip_ok);
check(!d_dup.ok && d_dup.error_code == 'CONFLICT' && !d_blk.ok && d_ok.ok && d_ok.name == 'printer.lan', 'P4D-DHCP[local_domain_duplicate_rejected]');

// Mock UCI store for transactional DHCP tests
function make_mock_uci(init_data) {
	let db = init_data;
	let mk = function() {
		return {
			get: function(c, s, k) {
				if (!db[s]) return null;
				return (k == null) ? db[s]['.type'] : db[s][k];
			},
			get_all: function(c, s) { return db[s] || null; },
			set: function(c, s, k, v) {
				if (v == null) {
					if (!db[s]) db[s] = {};
					db[s]['.type'] = k;
				} else {
					if (!db[s]) db[s] = {};
					db[s][k] = v;
				}
			},
			delete: function(c, s) { delete db[s]; },
			commit: function(c) { return true; }
		};
	};
	return { db: db, cursor: mk };
}

// 5. apply_dhcp_tx: success commits & reloads
let u1 = make_mock_uci({ lan: { '.type': 'dhcp', start: '5', limit: '31', leasetime: '1h' } });
let audits1 = [];
let res1 = null;
nms_ad.apply_dhcp_tx([{ cfg: 'dhcp', sid: 'lan' }], function(c) {
	c.set('dhcp', 'lan', 'start', '20');
}, function(vc) { return vc.get('dhcp', 'lan', 'start') == '20'; }, {
	uci_cursor: u1.cursor,
	reload_dnsmasq: function(cb) { cb({ ok: true }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function(a, v, t, st) { push(audits1, st); },
	actor: 'admin', verb: 'network_save_dhcp', target_id: 'lan'
}, function(r) { res1 = r; });
check(res1.ok === true && u1.db.lan.start == '20' && audits1[0] == 'committed', 'P4D-TX[dhcp_commit_and_reload_success]');

// 6. apply_dhcp_tx: post-commit verify failure rolls back UCI cleanly
let u2 = make_mock_uci({ lan: { '.type': 'dhcp', start: '5', limit: '31', leasetime: '1h' } });
let audits2 = [];
let res2 = null;
nms_ad.apply_dhcp_tx([{ cfg: 'dhcp', sid: 'lan' }], function(c) {
	c.set('dhcp', 'lan', 'start', '20');
}, function(vc) { return false; }, {
	uci_cursor: u2.cursor,
	reload_dnsmasq: function(cb) { cb({ ok: true }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function(a, v, t, st) { push(audits2, st); },
	actor: 'admin', verb: 'network_save_dhcp', target_id: 'lan'
}, function(r) { res2 = r; });
check(!res2.ok && res2.rolled_back === true && u2.db.lan.start == '5' && audits2[0] == 'rolled_back', 'P4D-TX[verify_fail_rolls_back_uci]');

// 7. apply_dhcp_tx: dnsmasq reload failure rolls back UCI AND reloads previous config
let u3 = make_mock_uci({ lan: { '.type': 'dhcp', start: '5', limit: '31', leasetime: '1h' } });
let reload_calls3 = 0;
let res3 = null;
nms_ad.apply_dhcp_tx([{ cfg: 'dhcp', sid: 'lan' }], function(c) {
	c.set('dhcp', 'lan', 'start', '25');
}, function(vc) { return true; }, {
	uci_cursor: u3.cursor,
	reload_dnsmasq: function(cb) { reload_calls3++; cb({ ok: reload_calls3 > 1 }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function() {},
	actor: 'admin', verb: 'network_save_dhcp', target_id: 'lan'
}, function(r) { res3 = r; });
check(!res3.ok && res3.rolled_back === true && res3.rollback_failed === false && u3.db.lan.start == '5' && reload_calls3 == 2, 'P4D-TX[reload_fail_rolls_back_and_reloads]');

// 8. apply_dhcp_tx: rollback dnsmasq reload failure triggers emergency freeze (never claims rolled_back=true)
let u4 = make_mock_uci({ lan: { '.type': 'dhcp', start: '5', limit: '31', leasetime: '1h' } });
let freezes4 = [];
let audits4 = [];
let res4 = null;
nms_ad.apply_dhcp_tx([{ cfg: 'dhcp', sid: 'lan' }], function(c) {
	c.set('dhcp', 'lan', 'start', '25');
}, function(vc) { return true; }, {
	uci_cursor: u4.cursor,
	reload_dnsmasq: function(cb) { cb({ ok: false }); },
	enter_emergency_freeze: function(w) { push(freezes4, w); return { freeze_persisted: true, freeze_persist_failed: false }; },
	audit_append: function(a, v, t, st) { push(audits4, st); },
	actor: 'admin', verb: 'network_save_dhcp', target_id: 'lan'
}, function(r) { res4 = r; });
check(!res4.ok && res4.rolled_back === false && res4.rollback_failed === true && res4.freeze_persisted === true && length(freezes4) == 1 && audits4[0] == 'rollback_failed', 'P4D-TX[rollback_reload_fail_triggers_freeze]');

// 9. apply_dhcp_tx: rollback of newly created section deletes it completely
let u5 = make_mock_uci({});
let res5 = null;
nms_ad.apply_dhcp_tx([{ cfg: 'dhcp', sid: 'noc_dom_1' }], function(c) {
	c.set('dhcp', 'noc_dom_1', 'domain');
	c.set('dhcp', 'noc_dom_1', 'name', 'test.lan');
}, function(vc) { return true; }, {
	uci_cursor: u5.cursor,
	reload_dnsmasq: function(cb) { reload_calls3++; cb({ ok: u5.db.noc_dom_1 == null }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function() {},
	actor: 'admin', verb: 'client_domain_add', target_id: 'test.lan'
}, function(r) { res5 = r; });
check(!res5.ok && res5.rolled_back === true && u5.db.noc_dom_1 == null, 'P4D-TX[new_section_rollback_deletes_section]');

// 10. apply_dhcp_tx: rollback of deleted section restores all its fields
let u6 = make_mock_uci({ noc_aabbccddeeff: { '.type': 'host', mac: 'aa:bb:cc:dd:ee:ff', ip: '192.168.1.55', name: 'nas' } });
let rc6 = 0;
let res6 = null;
nms_ad.apply_dhcp_tx([{ cfg: 'dhcp', sid: 'noc_aabbccddeeff' }], function(c) {
	c.delete('dhcp', 'noc_aabbccddeeff');
}, function(vc) { return true; }, {
	uci_cursor: u6.cursor,
	reload_dnsmasq: function(cb) { rc6++; cb({ ok: rc6 > 1 }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function() {},
	actor: 'admin', verb: 'client_lease_delete', target_id: 'noc_aabbccddeeff'
}, function(r) { res6 = r; });
check(!res6.ok && res6.rolled_back === true && u6.db.noc_aabbccddeeff && u6.db.noc_aabbccddeeff.ip == '192.168.1.55', 'P4D-TX[deleted_section_rollback_restores_fields]');

// 11. verify_dhcp_pool_uci fails if rebind_protection or cachesize is missing/unpersisted and triggers full rollback
let u7 = make_mock_uci({
	lan: { '.type': 'dhcp', start: '5', limit: '31', leasetime: '1h' },
	dm0: { '.type': 'dnsmasq', rebind_protection: '1', cachesize: '1000' }
});
let vp7 = nms_ad.validate_dhcp_pool_config({ start: 10, limit: 40, leasetime: '2h', rebind_protection: false, cachesize: 500 });
let res7 = null;
nms_ad.apply_dhcp_tx([{ cfg: 'dhcp', sid: 'lan' }, { cfg: 'dhcp', sid: 'dm0' }], function(c) {
	c.set('dhcp', 'lan', 'start', vp7.start);
	c.set('dhcp', 'lan', 'limit', vp7.limit);
	c.set('dhcp', 'lan', 'leasetime', vp7.leasetime);
	// Deliberately omit rebind_protection & cachesize persistence
}, function(vc) {
	return nms_ad.verify_dhcp_pool_uci(vc, 'dm0', vp7);
}, {
	uci_cursor: u7.cursor,
	reload_dnsmasq: function(cb) { cb({ ok: true }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function() {},
	actor: 'admin', verb: 'network_save_dhcp', target_id: 'lan'
}, function(r) { res7 = r; });
check(!res7.ok && res7.rolled_back === true && u7.db.lan.start == '5' && u7.db.dm0.rebind_protection == '1' && u7.db.dm0.cachesize == '1000', 'P4D-TX[missing_rebind_or_cachesize_fails_verify_and_rolls_back]');

// 12. Forward UCI commit failure rolls back & verifies cleanly
let u8 = make_mock_uci({ lan: { '.type': 'dhcp', start: '5', limit: '31', leasetime: '1h' } });
let cm_calls8 = 0;
let cur8 = function() {
	let base = u8.cursor();
	base.commit = function(c) { cm_calls8++; return cm_calls8 > 1; };
	return base;
};
let res8 = null;
nms_ad.apply_dhcp_tx([{ cfg: 'dhcp', sid: 'lan' }], function(c) {
	c.set('dhcp', 'lan', 'start', '30');
}, function(vc) { return true; }, {
	uci_cursor: cur8,
	reload_dnsmasq: function(cb) { cb({ ok: true }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function() {},
	actor: 'admin', verb: 'network_save_dhcp', target_id: 'lan'
}, function(r) { res8 = r; });
check(!res8.ok && res8.rolled_back === true && res8.rollback_failed === false && u8.db.lan.start == '5', 'P4D-TX[forward_commit_fail_rolls_back_and_verifies]');

// 13. Rollback commit failure on existing section triggers emergency freeze & rollback_failed (never rolled_back=true)
let u9 = make_mock_uci({ lan: { '.type': 'dhcp', start: '5', limit: '31', leasetime: '1h' } });
let cm_calls9 = 0;
let freezes9 = [];
let audits9 = [];
let cur9 = function() {
	let base = u9.cursor();
	base.commit = function(c) { cm_calls9++; return cm_calls9 == 1; }; // 1st commit succeeds, 2nd (rollback) fails!
	return base;
};
let res9 = null;
nms_ad.apply_dhcp_tx([{ cfg: 'dhcp', sid: 'lan' }], function(c) {
	c.set('dhcp', 'lan', 'start', '30');
}, function(vc) { return false; }, {
	uci_cursor: cur9,
	reload_dnsmasq: function(cb) { cb({ ok: true }); },
	enter_emergency_freeze: function(w) { push(freezes9, w); return { freeze_persisted: true, freeze_persist_failed: false }; },
	audit_append: function(a, v, t, st) { push(audits9, st); },
	actor: 'admin', verb: 'network_save_dhcp', target_id: 'lan'
}, function(r) { res9 = r; });
check(!res9.ok && res9.rolled_back === false && res9.rollback_failed === true && res9.freeze_persisted === true && length(freezes9) == 1 && audits9[0] == 'rollback_failed', 'P4D-TX[existing_section_rollback_commit_fail_freezes]');

// 14. Rollback failure to delete newly created section triggers emergency freeze & rollback_failed
let u10 = make_mock_uci({});
let freezes10 = [];
let audits10 = [];
let cur10 = function() {
	let base = u10.cursor();
	base.delete = function(c, s) {}; // Simulate delete silently failing to remove newly created section!
	return base;
};
let res10 = null;
nms_ad.apply_dhcp_tx([{ cfg: 'dhcp', sid: 'noc_dom_fail' }], function(c) {
	c.set('dhcp', 'noc_dom_fail', 'domain');
	c.set('dhcp', 'noc_dom_fail', 'name', 'bad.lan');
}, function(vc) { return false; }, {
	uci_cursor: cur10,
	reload_dnsmasq: function(cb) { cb({ ok: true }); },
	enter_emergency_freeze: function(w) { push(freezes10, w); return { freeze_persisted: true, freeze_persist_failed: false }; },
	audit_append: function(a, v, t, st) { push(audits10, st); },
	actor: 'admin', verb: 'client_domain_add', target_id: 'bad.lan'
}, function(r) { res10 = r; });
check(!res10.ok && res10.rolled_back === false && res10.rollback_failed === true && res10.freeze_persisted === true && length(freezes10) == 1 && audits10[0] == 'rollback_failed', 'P4D-TX[new_section_delete_fail_freezes]');

// 15. Post-restore snapshot verification mismatch (corrupted value on re-read) triggers emergency freeze & rollback_failed
let u11 = make_mock_uci({ lan: { '.type': 'dhcp', start: '5', limit: '31', leasetime: '1h' } });
let freezes11 = [];
let audits11 = [];
let set_calls11 = 0;
let cur11 = function() {
	let base = u11.cursor();
	let orig_set = base.set;
	base.set = function(c, s, k, v) {
		set_calls11++;
		if (set_calls11 > 2 && k == 'start') orig_set(c, s, k, '99'); // Corrupt value during restore
		else orig_set(c, s, k, v);
	};
	return base;
};
let res11 = null;
nms_ad.apply_dhcp_tx([{ cfg: 'dhcp', sid: 'lan' }], function(c) {
	c.set('dhcp', 'lan', 'start', '30');
}, function(vc) { return false; }, {
	uci_cursor: cur11,
	reload_dnsmasq: function(cb) { cb({ ok: true }); },
	enter_emergency_freeze: function(w) { push(freezes11, w); return { freeze_persisted: true, freeze_persist_failed: false }; },
	audit_append: function(a, v, t, st) { push(audits11, st); },
	actor: 'admin', verb: 'network_save_dhcp', target_id: 'lan'
}, function(r) { res11 = r; });
check(!res11.ok && res11.rolled_back === false && res11.rollback_failed === true && res11.freeze_persisted === true && length(freezes11) == 1 && audits11[0] == 'rollback_failed', 'P4D-TX[post_restore_snapshot_mismatch_freezes]');

// 16. verify_dhcp_pool_uci returns true only when all 5 fields match
let u12 = make_mock_uci({
	lan: { '.type': 'dhcp', start: '10', limit: '40', leasetime: '2h' },
	dm0: { '.type': 'dnsmasq', rebind_protection: '0', cachesize: '500' }
});
check(nms_ad.verify_dhcp_pool_uci(u12.cursor(), 'dm0', vp7) === true, 'P4D-DHCP[verify_all_5_fields_true_when_persisted]');

printf('UCODE4D_SUMMARY: %d passed, %d failed\n', passed, failed);
exit(failed == 0 ? 0 : 1);
