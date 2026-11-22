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

let if_exists = function(iface) { return iface == 'pppoe-wan' || iface == 'wlan0'; };

// 1. Strict int validation rejects non-numeric, fractions, empty strings
let v_abc = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 'abc', upload_kbps: 2000 }, if_exists);
let v_frac = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 1000.5, upload_kbps: 2000 }, if_exists);
let v_empty = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: '', upload_kbps: 2000 }, if_exists);
let v_low = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 32, upload_kbps: 2000 }, if_exists);
check(!v_abc.ok && !v_frac.ok && !v_empty.ok && !v_low.ok, 'P4E-VAL[strict_int_and_min_kbps]');

// 2. Reject enabled=true with both dl=0 and ul=0, and reject qdisc/script mismatch
let v_zero = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 0, upload_kbps: 0 }, if_exists);
let v_mis = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 4000, upload_kbps: 2000, qdisc: 'fq_codel', script: 'piece_of_cake.qos' }, if_exists);
let v_ok = nms_sqm.validate_sqm_config({ enabled: true, interface: 'wlan0', download_kbps: 4000, upload_kbps: 2000, qdisc: 'cake', script: 'piece_of_cake.qos' }, if_exists);
check(!v_zero.ok && !v_mis.ok && v_ok.ok && v_ok.download == '4000' && v_ok.upload == '2000', 'P4E-VAL[enabled_zero_rates_and_qdisc_script_compatibility]');

// 3. Reject non-existent interface when enabled, and parse tc summary
let v_noif = nms_sqm.validate_sqm_config({ enabled: true, interface: 'eth0', download_kbps: 4000, upload_kbps: 2000 }, if_exists);
let tc_sample = "qdisc cake 8001: dev wlan0 root refcnt 2 bandwidth 2Mbit besteffort triple-isolate nonat nowash no-ack-filter split-gso rtt 100ms noatm overhead 44\n Sent 1234 bytes 10 pkt (dropped 3, overlimits 7 requeues 0)\n";
let tcs = nms_sqm.parse_tc_qdisc_summary(tc_sample, 'wlan0');
check(!v_noif.ok && v_noif.error_code == 'DEPENDENCY' && tcs.active_shaper_detected === true && tcs.qdiscs[0].dropped == 3 && tcs.qdiscs[0].overlimits == 7, 'P4E-TC[iface_exists_and_tc_summary_parse]');

// Mock UCI store for SQM transactions (deep-clones init_eth1 so tests stay isolated)
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

let orig_eth1 = {
	'.type': 'queue', enabled: '1', interface: 'pppoe-wan', download: '4000', upload: '2000',
	qdisc: 'cake', script: 'piece_of_cake.qos', overhead: '44', linklayer: 'ethernet',
	squash_dscp: '1', squash_ingress: '1', ingress_ecn: 'ECN', egress_ecn: 'ECN',
	debug_logging: '0', verbosity: '5'
};

// 4. apply_sqm_tx: full success with UCI commit + 15-field verify + reload + tc qdisc verify
let u1 = make_mock_sqm(orig_eth1);
let audits1 = [];
let res1 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: u1.cursor,
	reload_sqm: function(cb) { cb({ ok: true }); },
	show_tc: function(iface, cb) { cb({ ok: true, output: tc_sample }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function(a, v, t, st) { push(audits1, st); },
	actor: 'admin'
}, function(r) { res1 = r; });
check(res1.ok === true && res1.tc_verified === true && u1.db.eth1.interface == 'wlan0' && audits1[0] == 'committed', 'P4E-TX[sqm_commit_reload_tc_verified]');

// 5. apply_sqm_tx: UCI commit failure triggers rollback & verifies original snapshot
let u2 = make_mock_sqm(orig_eth1);
let cm2 = 0;
let res2 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: function() { let b = u2.cursor(); b.commit = function() { cm2++; return cm2 > 1; }; return b; },
	reload_sqm: function(cb) { cb({ ok: true }); },
	show_tc: function(iface, cb) { cb({ ok: true, output: tc_sample }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function() {},
	actor: 'admin'
}, function(r) { res2 = r; });
check(!res2.ok && res2.rolled_back === true && res2.rollback_failed === false && u2.db.eth1.interface == 'pppoe-wan', 'P4E-TX[uci_commit_fail_rolls_back]');

// 6. apply_sqm_tx: post-commit verify mismatch (e.g. verbosity not persisted) triggers rollback
let u3 = make_mock_sqm(orig_eth1);
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
	show_tc: function(iface, cb) { cb({ ok: true, output: tc_sample }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function() {},
	actor: 'admin'
}, function(r) { res3 = r; });
check(!res3.ok && res3.rolled_back === true && u3.db.eth1.interface == 'pppoe-wan', 'P4E-TX[post_commit_verify_mismatch_rolls_back]');

// 7. apply_sqm_tx: sqm reload failure rolls back UCI AND reloads previous SQM
let u4 = make_mock_sqm(orig_eth1);
let rc4 = 0;
let res4 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: u4.cursor,
	reload_sqm: function(cb) { rc4++; cb({ ok: rc4 > 1 }); },
	show_tc: function(iface, cb) { cb({ ok: true, output: tc_sample }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function() {},
	actor: 'admin'
}, function(r) { res4 = r; });
check(!res4.ok && res4.rolled_back === true && rc4 == 2 && u4.db.eth1.interface == 'pppoe-wan', 'P4E-TX[reload_fail_rolls_back_and_reloads]');

// 8. apply_sqm_tx: tc qdisc verification failure (cake not attached) rolls back UCI & reloads
let u5 = make_mock_sqm(orig_eth1);
let res5 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: u5.cursor,
	reload_sqm: function(cb) { cb({ ok: true }); },
	show_tc: function(iface, cb) { cb({ ok: true, output: 'qdisc noqueue 0: dev wlan0 root refcnt 2\n' }); },
	enter_emergency_freeze: function(w) { return { freeze_persisted: true }; },
	audit_append: function() {},
	actor: 'admin'
}, function(r) { res5 = r; });
check(!res5.ok && res5.rolled_back === true && u5.db.eth1.interface == 'pppoe-wan', 'P4E-TX[tc_qdisc_missing_rolls_back]');

// 9. apply_sqm_tx: rollback reload failure triggers emergency freeze & rollback_failed (never rolled_back=true)
let u6 = make_mock_sqm(orig_eth1);
let freezes6 = [];
let audits6 = [];
let res6 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: u6.cursor,
	reload_sqm: function(cb) { cb({ ok: false }); },
	show_tc: function(iface, cb) { cb({ ok: true, output: tc_sample }); },
	enter_emergency_freeze: function(w) { push(freezes6, w); return { freeze_persisted: true, freeze_persist_failed: false }; },
	audit_append: function(a, v, t, st) { push(audits6, st); },
	actor: 'admin'
}, function(r) { res6 = r; });
check(!res6.ok && res6.rolled_back === false && res6.rollback_failed === true && res6.freeze_persisted === true && length(freezes6) == 1 && audits6[0] == 'rollback_failed', 'P4E-TX[rollback_reload_fail_triggers_freeze]');

// 10. apply_sqm_tx: UCI restore failure after reload failure triggers emergency freeze & rollback_failed
let u7 = make_mock_sqm(orig_eth1);
let cm7 = 0;
let freezes7 = [];
let res7 = null;
nms_sqm.apply_sqm_tx(v_ok, {
	uci_cursor: function() { let b = u7.cursor(); b.commit = function() { cm7++; return cm7 == 1; }; return b; },
	reload_sqm: function(cb) { cb({ ok: false }); },
	show_tc: function(iface, cb) { cb({ ok: true, output: tc_sample }); },
	enter_emergency_freeze: function(w) { push(freezes7, w); return { freeze_persisted: true, freeze_persist_failed: false }; },
	audit_append: function() {},
	actor: 'admin'
}, function(r) { res7 = r; });
check(!res7.ok && res7.rolled_back === false && res7.rollback_failed === true && res7.freeze_persisted === true && length(freezes7) == 1, 'P4E-TX[uci_restore_fail_triggers_freeze]');

printf('UCODE4E_SUMMARY: %d passed, %d failed\n', passed, failed);
exit(failed == 0 ? 0 : 1);
