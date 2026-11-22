// Executed directly by OpenWrt 24.10.0 & 25.12.6 ucode runtime against production backend/nms_sqm.uc
import * as nms_sqm from '/tmp/p3a_test/nms_sqm.uc';

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

let topo = {
	lan_ifaces: { 'lo': true, 'br-lan': true, 'eth1': true, 'tailscale0': true },
	wan_ifaces: { 'pppoe-wan': true, 'wlan0': true },
	iface_exists: function(iface) { return iface == 'pppoe-wan' || iface == 'wlan0' || iface == 'br-lan'; }
};

// 17. Production build_sqm_topology: accepts verified PPPoE & wireless WAN, rejects guest/vpn/mgmt/LAN/bridge-members
function make_topo_uci(ifaces, zones, devs) {
	return {
		foreach: function(cfg, stype, fn) {
			if (cfg == 'network' && stype == 'interface') { for (let s in ifaces) fn(s); }
			else if (cfg == 'firewall' && stype == 'zone') { for (let z in zones) fn(z); }
			else if (cfg == 'network' && stype == 'device') { for (let d in devs) fn(d); }
		}
	};
}
let t_uci = make_topo_uci(
	[
		{ '.name': 'loopback', device: 'lo', proto: 'none' },
		{ '.name': 'lan', device: 'br-lan', proto: 'static' },
		{ '.name': 'wan', device: 'eth0', proto: 'pppoe' },
		{ '.name': 'wwan', device: 'wlan0', proto: 'dhcp' },
		{ '.name': 'guest', device: 'eth2', proto: 'static' },
		{ '.name': 'vpn', device: 'wg0', proto: 'wireguard' },
		{ '.name': 'mgmt', device: 'eth3', proto: 'static' }
	],
	[
		{ name: 'lan', network: ['lan'] },
		{ name: 'wan', network: ['wan', 'wwan'] },
		{ name: 'guest', network: ['guest'] },
		{ name: 'vpn', network: ['vpn'] },
		{ name: 'mgmt', network: ['mgmt'] }
	],
	[{ name: 'br-lan', ports: ['eth1'] }]
);
let t_ubus = {
	interface: [
		{ 'interface': 'lan', up: true, l3_device: 'br-lan', device: 'br-lan' },
		{ 'interface': 'wan', up: true, l3_device: 'pppoe-wan', device: 'eth0' },
		{ 'interface': 'wwan', up: true, l3_device: 'wlan0', device: 'wlan0' },
		{ 'interface': 'guest', up: true, l3_device: 'eth2', device: 'eth2' },
		{ 'interface': 'vpn', up: true, l3_device: 'wg0', device: 'wg0' },
		{ 'interface': 'mgmt', up: true, l3_device: 'eth3', device: 'eth3' }
	]
};
let real_topo = nms_sqm.build_sqm_topology(t_uci, t_ubus, ['.', '..', 'eth1', 'eth4'], function() { return true; });
check(
	nms_sqm.validate_sqm_config({ enabled: true, interface: 'pppoe-wan', download_kbps: 4000, upload_kbps: 2000 }, real_topo).ok === true &&
	nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 4000, upload_kbps: 2000 }, real_topo).ok === true &&
	nms_sqm.validate_sqm_config({ enabled: true, interface: 'eth2', download_kbps: 4000, upload_kbps: 2000 }, real_topo).ok === false &&
	nms_sqm.validate_sqm_config({ enabled: true, interface: 'wg0', download_kbps: 4000, upload_kbps: 2000 }, real_topo).ok === false &&
	nms_sqm.validate_sqm_config({ enabled: true, interface: 'eth3', download_kbps: 4000, upload_kbps: 2000 }, real_topo).ok === false &&
	nms_sqm.validate_sqm_config({ enabled: true, interface: 'br-lan', download_kbps: 4000, upload_kbps: 2000 }, real_topo).ok === false &&
	nms_sqm.validate_sqm_config({ enabled: true, interface: 'eth1', download_kbps: 4000, upload_kbps: 2000 }, real_topo).ok === false &&
	nms_sqm.validate_sqm_config({ enabled: true, interface: 'eth4', download_kbps: 4000, upload_kbps: 2000 }, real_topo).ok === false,
	'P4E-TOPO[real_builder_accepts_wan_rejects_guest_vpn_mgmt_lan]'
);

// 18. Production build_sqm_topology: missing ubus fails closed & conflicting UCI/runtime rejected
let topo_noubus = nms_sqm.build_sqm_topology(t_uci, null, ['eth1'], function() { return true; });
let ubus_conflict = { interface: [{ 'interface': 'wwan', up: true, l3_device: 'eth9', device: 'eth9' }] };
let topo_conflict = nms_sqm.build_sqm_topology(t_uci, ubus_conflict, ['eth1'], function() { return true; });
check(
	!nms_sqm.validate_sqm_config({ enabled: true, interface: 'pppoe-wan', download_kbps: 4000, upload_kbps: 2000 }, topo_noubus).ok &&
	!nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 4000, upload_kbps: 2000 }, topo_noubus).ok &&
	!nms_sqm.validate_sqm_config({ enabled: true, interface: 'eth9', download_kbps: 4000, upload_kbps: 2000 }, topo_conflict).ok &&
	!nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 4000, upload_kbps: 2000 }, topo_conflict).ok,
	'P4E-TOPO[missing_ubus_and_conflict_fail_closed]'
);

// 1. Strict Boolean validation across all 4 Boolean fields (enabled, debug_logging, squash_dscp, squash_ingress)
let b_fields = ['enabled', 'debug_logging', 'squash_dscp', 'squash_ingress'];
let bad_bool_vals = ['false', '0', 'true', '1', 0, 1, [], {}];
let all_bad_bools_rejected = true;
for (let bf in b_fields) {
	for (let bv in bad_bool_vals) {
		let p = { enabled: true, interface: 'wlan0', download_kbps: 4000, upload_kbps: 2000 };
		p[bf] = bv;
		let r = nms_sqm.validate_sqm_config(p, topo);
		if (r.ok) { all_bad_bools_rejected = false; }
	}
}
let b_valid_t = nms_sqm.validate_sqm_config({ enabled: true, debug_logging: true, squash_dscp: false, squash_ingress: false, interface: 'wlan0', download_kbps: 4000, upload_kbps: 2000 }, topo);
let b_valid_f = nms_sqm.validate_sqm_config({ enabled: false, debug_logging: false, squash_dscp: true, squash_ingress: true, interface: 'wlan0', download_kbps: 0, upload_kbps: 0 }, topo);
check(
	all_bad_bools_rejected &&
	b_valid_t.ok && b_valid_t.enabled == '1' && b_valid_t.debug_logging == '1' && b_valid_t.squash_dscp == '0' && b_valid_t.squash_ingress == '0' &&
	b_valid_f.ok && b_valid_f.enabled == '0' && b_valid_f.debug_logging == '0' && b_valid_f.squash_dscp == '1' && b_valid_f.squash_ingress == '1',
	'P4E-BOOL[strict_boolean_all_4_fields]'
);

// 2. LAN, loopback, management, and unverified interface rejection
let r_brlan = nms_sqm.validate_sqm_config({ enabled: true, interface: 'br-lan', download_kbps: 4000, upload_kbps: 2000 }, topo);
let r_lo = nms_sqm.validate_sqm_config({ enabled: true, interface: 'lo', download_kbps: 4000, upload_kbps: 2000 }, topo);
let r_ts = nms_sqm.validate_sqm_config({ enabled: true, interface: 'tailscale0', download_kbps: 4000, upload_kbps: 2000 }, topo);
let r_lanp = nms_sqm.validate_sqm_config({ enabled: true, interface: 'eth1', download_kbps: 4000, upload_kbps: 2000 }, topo);
let r_unv = nms_sqm.validate_sqm_config({ enabled: true, interface: 'eth0', download_kbps: 4000, upload_kbps: 2000 }, topo);
let r_wan = nms_sqm.validate_sqm_config({ enabled: true, interface: 'pppoe-wan', download_kbps: 4000, upload_kbps: 2000 }, topo);
check(
	!r_brlan.ok && r_brlan.error_code == 'FORBIDDEN' &&
	!r_lo.ok && r_lo.error_code == 'FORBIDDEN' &&
	!r_ts.ok && r_ts.error_code == 'FORBIDDEN' &&
	!r_lanp.ok && r_lanp.error_code == 'FORBIDDEN' &&
	!r_unv.ok && r_wan.ok,
	'P4E-TOPO[rejects_lan_mgmt_unverified_allows_wan]'
);

// 3. Strict numeric validation & boundaries/overflow
let v_abc = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 'abc', upload_kbps: 2000 }, topo);
let v_frac = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 1000.5, upload_kbps: 2000 }, topo);
let v_empty = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: '', upload_kbps: 2000 }, topo);
let v_low = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 63, upload_kbps: 2000 }, topo);
let v_ovf = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 1000001, upload_kbps: 2000 }, topo);
let v_neg = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: -1, upload_kbps: 2000 }, topo);
let v_ovh = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 4000, upload_kbps: 2000, overhead: 129 }, topo);
let v_vrb = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 4000, upload_kbps: 2000, verbosity: 11 }, topo);
check(!v_abc.ok && !v_frac.ok && !v_empty.ok && !v_low.ok && !v_ovf.ok && !v_neg.ok && !v_ovh.ok && !v_vrb.ok, 'P4E-VAL[strict_int_bounds_and_overflow]');

// 4. Enabled=true with 0/0 rates and qdisc/script mismatch
let v_zero = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 0, upload_kbps: 0 }, topo);
let v_mis = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 4000, upload_kbps: 2000, qdisc: 'fq_codel', script: 'piece_of_cake.qos' }, topo);
let v_ok = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 4000, upload_kbps: 2000, qdisc: 'cake', script: 'piece_of_cake.qos' }, topo);
check(!v_zero.ok && !v_mis.ok && v_ok.ok, 'P4E-VAL[enabled_zero_rates_and_qdisc_script_compat]');

// 5. Root-vs-child qdisc detection in verify_tc_qdisc_active & parse_tc_qdisc_summary
let tc_root = "qdisc cake 8001: dev wlan0 root refcnt 2 bandwidth 2Mbit\n Sent 1234 bytes 10 pkt (dropped 3, overlimits 7 requeues 0)\n";
let tc_child_only = "qdisc mq 0: dev wlan0 root\nqdisc cake 8010: dev wlan0 parent 1:1 bandwidth 2Mbit\n Sent 100 bytes 1 pkt (dropped 1, overlimits 2 requeues 0)\n";
let tc_wrong_if = "qdisc cake 8001: dev eth0 root refcnt 2\n";
let tc_wrong_qd = "qdisc noqueue 0: dev wlan0 root refcnt 2\n";
check(
	nms_sqm.verify_tc_qdisc_active(tc_root, 'wlan0', 'cake') === true &&
	nms_sqm.verify_tc_qdisc_active(tc_child_only, 'wlan0', 'cake') === false &&
	nms_sqm.verify_tc_qdisc_active(tc_wrong_if, 'wlan0', 'cake') === false &&
	nms_sqm.verify_tc_qdisc_active(tc_wrong_qd, 'wlan0', 'cake') === false &&
	nms_sqm.verify_tc_qdisc_active('', 'wlan0', 'cake') === false &&
	nms_sqm.verify_tc_qdisc_active('garbage output', 'wlan0', 'cake') === false,
	'P4E-TC[root_vs_child_and_malformed_qdisc_check]'
);

// 6. parse_tc_qdisc_summary ignores child cake for active_shaper_detected
let sum_root = nms_sqm.parse_tc_qdisc_summary(tc_root, 'wlan0');
let sum_child = nms_sqm.parse_tc_qdisc_summary(tc_child_only, 'wlan0');
check(
	sum_root.active_shaper_detected === true && sum_root.qdiscs[0].dropped == 3 && sum_root.qdiscs[0].overlimits == 7 &&
	sum_child.active_shaper_detected === false,
	'P4E-TC[summary_requires_root_shaper]'
);

function make_mock_sqm(init_eth1) {
	let db = {};
	if (init_eth1) {
		db.eth1 = {};
		for (let k in keys(init_eth1)) db.eth1[k] = init_eth1[k];
	}
	let mk = function() {
		return {
			get: function(c, s, k) {
				if (!db[s]) return null;
				return (k == null) ? db[s]['.type'] : db[s][k];
			},
			get_all: function(c, s) { return db[s] || null; },
			set: function(c, s, k, v) {
				if (v == null) { if (!db[s]) db[s] = {}; db[s]['.type'] = k; }
				else { if (!db[s]) db[s] = {}; db[s][k] = v; }
			},
			delete: function(c, s) { delete db[s]; },
			commit: function(c) { return true; }
		};
	};
	return { db: db, cursor: mk };
}

let orig_enabled = {
	'.type': 'queue', enabled: '1', interface: 'pppoe-wan', download: '4000', upload: '2000',
	qdisc: 'cake', script: 'piece_of_cake.qos', overhead: '44', linklayer: 'ethernet',
	squash_dscp: '1', squash_ingress: '1', ingress_ecn: 'ECN', egress_ecn: 'ECN',
	debug_logging: '0', verbosity: '5'
};
let orig_disabled = {
	'.type': 'queue', enabled: '0', interface: 'pppoe-wan', download: '4000', upload: '2000',
	qdisc: 'cake', script: 'piece_of_cake.qos', overhead: '44', linklayer: 'ethernet',
	squash_dscp: '1', squash_ingress: '1', ingress_ecn: 'ECN', egress_ecn: 'ECN',
	debug_logging: '0', verbosity: '5'
};
let tc_pppoe_root = "qdisc cake 8001: dev pppoe-wan root refcnt 2 bandwidth 2Mbit\n";

// 7. Forward success with UCI commit + 15-field verify + reload + root tc verify
let u1 = make_mock_sqm(orig_enabled);
let audits1 = [];
let res1 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: u1.cursor,
	reload_sqm: function(cb) { cb({ ok: true }); },
	show_tc: function(iface, cb) { cb({ ok: true, output: tc_root }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function(a, v, t, st) { push(audits1, st); },
	actor: 'admin'
}, function(r) { res1 = r; });
check(res1.ok === true && res1.tc_verified === true && u1.db.eth1.interface == 'wlan0' && audits1[0] == 'committed', 'P4E-TX[commit_reload_root_tc_verified]');

// 8. UCI commit failure triggers rollback & verifies original snapshot
let u2 = make_mock_sqm(orig_enabled);
let cm2 = 0;
let res2 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: function() { let b = u2.cursor(); b.commit = function() { cm2++; return cm2 > 1; }; return b; },
	reload_sqm: function(cb) { cb({ ok: true }); },
	show_tc: function(iface, cb) { cb({ ok: true, output: tc_root }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function() {},
	actor: 'admin'
}, function(r) { res2 = r; });
check(!res2.ok && res2.rolled_back === true && res2.rollback_failed === false && u2.db.eth1.interface == 'pppoe-wan', 'P4E-TX[uci_commit_fail_rolls_back]');

// 9. Post-commit verify mismatch triggers rollback
let u3 = make_mock_sqm(orig_enabled);
let verb_corrupted = false;
let res3 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: function() {
		let b = u3.cursor();
		let os = b.set;
		b.set = function(c, s, k, v) {
			if (k == 'verbosity' && !verb_corrupted) { verb_corrupted = true; os(c, s, k, '99'); }
			else os(c, s, k, v);
		};
		return b;
	},
	reload_sqm: function(cb) { cb({ ok: true }); },
	show_tc: function(iface, cb) { cb({ ok: true, output: tc_root }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function() {},
	actor: 'admin'
}, function(r) { res3 = r; });
check(!res3.ok && res3.rolled_back === true && u3.db.eth1.interface == 'pppoe-wan', 'P4E-TX[post_commit_verify_mismatch_rolls_back]');

// 10. Previously enabled SQM: reload fail -> UCI restored + reload + tc verifies previous root qdisc active -> rolled_back=true
let u4 = make_mock_sqm(orig_enabled);
let rc4 = 0;
let res4 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: u4.cursor,
	reload_sqm: function(cb) { rc4++; cb({ ok: rc4 > 1 }); },
	show_tc: function(iface, cb) { cb({ ok: true, output: iface == 'pppoe-wan' ? tc_pppoe_root : '' }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function() {},
	actor: 'admin'
}, function(r) { res4 = r; });
check(!res4.ok && res4.rolled_back === true && res4.rollback_failed === false && rc4 == 2 && u4.db.eth1.interface == 'pppoe-wan', 'P4E-RB[prev_enabled_runtime_restored_ok]');

// 11. Previously disabled SQM: reload fail -> UCI restored + reload + tc shows unrelated qdisc (pfifo_fast, no cake/fq_codel) -> rolled_back=true
let u5 = make_mock_sqm(orig_disabled);
let rc5 = 0;
let res5 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: u5.cursor,
	reload_sqm: function(cb) { rc5++; cb({ ok: rc5 > 1 }); },
	show_tc: function(iface, cb) { cb({ ok: true, output: 'qdisc pfifo_fast 0: dev ' + iface + ' root refcnt 2\n' }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function() {},
	actor: 'admin'
}, function(r) { res5 = r; });
check(!res5.ok && res5.rolled_back === true && res5.rollback_failed === false && u5.db.eth1.enabled == '0', 'P4E-RB[prev_disabled_unrelated_qdisc_ok]');

// 12. Previously enabled SQM: reload succeeds during rollback BUT restored tc qdisc is missing/wrong -> rollback_failed=true + freeze
let u6 = make_mock_sqm(orig_enabled);
let rc6 = 0;
let freezes6 = [];
let audits6 = [];
let res6 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: u6.cursor,
	reload_sqm: function(cb) { rc6++; cb({ ok: rc6 > 1 }); },
	show_tc: function(iface, cb) { cb({ ok: true, output: 'qdisc noqueue 0: dev pppoe-wan root\n' }); },
	enter_emergency_freeze: function(w) { push(freezes6, w); return { freeze_persisted: true, freeze_persist_failed: false }; },
	audit_append: function(a, v, t, st) { push(audits6, st); },
	actor: 'admin'
}, function(r) { res6 = r; });
check(!res6.ok && res6.rolled_back === false && res6.rollback_failed === true && res6.freeze_persisted === true && length(freezes6) == 1 && audits6[0] == 'rollback_failed', 'P4E-RB[wrong_restored_qdisc_freezes]');

// 13. Runtime tc query failure during rollback -> rollback_failed=true + freeze
let u7 = make_mock_sqm(orig_enabled);
let rc7 = 0;
let freezes7 = [];
let res7 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: u7.cursor,
	reload_sqm: function(cb) { rc7++; cb({ ok: rc7 > 1 }); },
	show_tc: function(iface, cb) { cb({ ok: false, output: '' }); },
	enter_emergency_freeze: function(w) { push(freezes7, w); return { freeze_persisted: true, freeze_persist_failed: false }; },
	audit_append: function() {},
	actor: 'admin'
}, function(r) { res7 = r; });
check(!res7.ok && res7.rolled_back === false && res7.rollback_failed === true && res7.freeze_persisted === true && length(freezes7) == 1, 'P4E-RB[tc_query_fail_during_rollback_freezes]');

// 14. Forward tc verification failure (child qdisc only, not root) triggers rollback & verifies previous state
let u8 = make_mock_sqm(orig_enabled);
let res8 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: u8.cursor,
	reload_sqm: function(cb) { cb({ ok: true }); },
	show_tc: function(iface, cb) { cb({ ok: true, output: iface == 'wlan0' ? tc_child_only : tc_pppoe_root }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function() {},
	actor: 'admin'
}, function(r) { res8 = r; });
check(!res8.ok && res8.rolled_back === true && u8.db.eth1.interface == 'pppoe-wan', 'P4E-TX[child_qdisc_only_fails_and_rolls_back]');

// 15. Rollback reload failure triggers emergency freeze & rollback_failed
let u9 = make_mock_sqm(orig_enabled);
let freezes9 = [];
let res9 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: u9.cursor,
	reload_sqm: function(cb) { cb({ ok: false }); },
	show_tc: function(iface, cb) { cb({ ok: true, output: tc_pppoe_root }); },
	enter_emergency_freeze: function(w) { push(freezes9, w); return { freeze_persisted: true, freeze_persist_failed: false }; },
	audit_append: function() {},
	actor: 'admin'
}, function(r) { res9 = r; });
check(!res9.ok && res9.rolled_back === false && res9.rollback_failed === true && res9.freeze_persisted === true && length(freezes9) == 1, 'P4E-RB[rollback_reload_fail_freezes]');

// 16. UCI restoration failure during rollback triggers emergency freeze & rollback_failed
let u10 = make_mock_sqm(orig_enabled);
let cm10 = 0;
let freezes10 = [];
let res10 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: function() { let b = u10.cursor(); b.commit = function() { cm10++; return cm10 == 1; }; return b; },
	reload_sqm: function(cb) { cb({ ok: false }); },
	show_tc: function(iface, cb) { cb({ ok: true, output: tc_pppoe_root }); },
	enter_emergency_freeze: function(w) { push(freezes10, w); return { freeze_persisted: true, freeze_persist_failed: false }; },
	audit_append: function() {},
	actor: 'admin'
}, function(r) { res10 = r; });
check(!res10.ok && res10.rolled_back === false && res10.rollback_failed === true && res10.freeze_persisted === true && length(freezes10) == 1, 'P4E-RB[uci_restore_fail_freezes]');

// 19. Previous disabled + new cake + cake remains after rollback reload -> rollback_failed=true + freeze
let u11 = make_mock_sqm(orig_disabled);
let rc11 = 0;
let fr11 = [];
let res11 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: u11.cursor,
	reload_sqm: function(cb) { rc11++; cb({ ok: rc11 > 1 }); },
	show_tc: function(iface, cb) { cb({ ok: true, output: 'qdisc cake 8001: dev ' + iface + ' root refcnt 2\n' }); },
	enter_emergency_freeze: function(w) { push(fr11, w); return { freeze_persisted: true, freeze_persist_failed: false }; },
	audit_append: function() {},
	actor: 'admin'
}, function(r) { res11 = r; });
check(!res11.ok && res11.rolled_back === false && res11.rollback_failed === true && length(fr11) == 1, 'P4E-RB[prev_disabled_cake_remains_freezes]');

// 20. Previous disabled + new fq_codel + fq_codel remains after rollback reload -> rollback_failed=true + freeze
let v_fq = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 4000, upload_kbps: 2000, qdisc: 'fq_codel', script: 'simple.qos' }, topo);
let u12 = make_mock_sqm(orig_disabled);
let rc12 = 0;
let fr12 = [];
let res12 = null;
nms_sqm.apply_sqm_tx(v_fq, {
	uci_cursor: u12.cursor,
	reload_sqm: function(cb) { rc12++; cb({ ok: rc12 > 1 }); },
	show_tc: function(iface, cb) { cb({ ok: true, output: 'qdisc fq_codel 0: dev ' + iface + ' root refcnt 2\n' }); },
	enter_emergency_freeze: function(w) { push(fr12, w); return { freeze_persisted: true, freeze_persist_failed: false }; },
	audit_append: function() {},
	actor: 'admin'
}, function(r) { res12 = r; });
check(!res12.ok && res12.rolled_back === false && res12.rollback_failed === true && length(fr12) == 1, 'P4E-RB[prev_disabled_fq_codel_remains_freezes]');

// 21. Previous disabled (pppoe-wan) + interface changed (wlan0) + unrelated noqueue on both -> rolled_back=true
let u13 = make_mock_sqm(orig_disabled);
let rc13 = 0;
let checked_ifs13 = [];
let res13 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: u13.cursor,
	reload_sqm: function(cb) { rc13++; cb({ ok: rc13 > 1 }); },
	show_tc: function(iface, cb) { push(checked_ifs13, iface); cb({ ok: true, output: 'qdisc noqueue 0: dev ' + iface + ' root refcnt 2\n' }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function() {},
	actor: 'admin'
}, function(r) { res13 = r; });
check(!res13.ok && res13.rolled_back === true && res13.rollback_failed === false && length(checked_ifs13) == 2, 'P4E-RB[prev_disabled_iface_changed_noqueue_ok]');

// 22. Previous disabled + runtime query failure on interface -> rollback_failed=true + freeze
let u14 = make_mock_sqm(orig_disabled);
let rc14 = 0;
let fr14 = [];
let res14 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: u14.cursor,
	reload_sqm: function(cb) { rc14++; cb({ ok: rc14 > 1 }); },
	show_tc: function(iface, cb) { cb({ ok: false, output: '' }); },
	enter_emergency_freeze: function(w) { push(fr14, w); return { freeze_persisted: true, freeze_persist_failed: false }; },
	audit_append: function() {},
	actor: 'admin'
}, function(r) { res14 = r; });
check(!res14.ok && res14.rolled_back === false && res14.rollback_failed === true && length(fr14) == 1, 'P4E-RB[prev_disabled_tc_query_fail_freezes]');

// 23. build_sqm_topology: strict rt.up === true required (rejects up: false, missing up, up: null, non-Boolean up)
let check_up_val = function(has_up, up_val) {
	let entry = { 'interface': 'wwan', l3_device: 'wlan0', device: 'wlan0' };
	if (has_up) entry.up = up_val;
	let tp = nms_sqm.build_sqm_topology(t_uci, { interface: [entry] }, ['eth1'], function() { return true; });
	return nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 4000, upload_kbps: 2000 }, tp).ok;
};
check(
	check_up_val(true, true) === true &&
	check_up_val(true, false) === false &&
	check_up_val(false, null) === false &&
	check_up_val(true, null) === false &&
	check_up_val(true, 'true') === false &&
	check_up_val(true, 1) === false,
	'P4E-TOPO[requires_strict_boolean_up_true]'
);

printf('UCODE4E_SUMMARY: %d passed, %d failed\n', passed, failed);
exit(failed == 0 ? 0 : 1);
