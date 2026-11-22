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

// 3. DHCP pool config validation (rejects out-of-range and 0m/0h lease times)
let dp_bad_range = nms_ad.validate_dhcp_pool_config({ start: 200, limit: 60, leasetime: '1h' });
let dp_zero_m = nms_ad.validate_dhcp_pool_config({ start: 10, limit: 50, leasetime: '0m' });
let dp_zero_h = nms_ad.validate_dhcp_pool_config({ start: 10, limit: 50, leasetime: '0h' });
let dp_ok = nms_ad.validate_dhcp_pool_config({ start: 10, limit: 50, leasetime: '2h', rebind_protection: true, cachesize: 500 });
check(!dp_bad_range.ok && !dp_zero_m.ok && !dp_zero_h.ok && dp_ok.ok && dp_ok.start == '10' && dp_ok.leasetime == '2h', 'P4D-DHCP[pool_validation_and_min_leasetime]');

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
			commit: function(c) {}
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

printf('UCODE4D_SUMMARY: %d passed, %d failed\n', passed, failed);
exit(failed == 0 ? 0 : 1);
