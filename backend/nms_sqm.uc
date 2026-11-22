// Phase 4E: QoS & SQM Hardening (Validation, Transactional UCI + tc qdisc Verification & Rollback)
// Zero external dependencies; executed in-process by noc-helperd and OpenWrt chroot suites.

const ALLOWED_IFACES = {
	'pppoe-wan': true,
	'wlan0': true,
	'eth0': true,
	'eth1': true,
	'br-lan': true,
	'wan': true,
	'wwan': true
};

const ALLOWED_QDISCS = { 'cake': true, 'fq_codel': true };
const ALLOWED_SCRIPTS = { 'piece_of_cake.qos': true, 'layer_cake.qos': true, 'simple.qos': true };
const SCRIPT_QDISC_MAP = {
	'piece_of_cake.qos': 'cake',
	'layer_cake.qos': 'cake',
	'simple.qos': 'fq_codel'
};
const ALLOWED_LINKLAYERS = { 'ethernet': true, 'atm': true, 'none': true };
const ALLOWED_ECN = { 'ECN': true, 'NOECN': true };

export function parse_strict_int(val, fallback) {
	if (val == null) return { ok: true, value: fallback };
	let tv = type(val);
	if (tv == 'int') return { ok: true, value: val };
	if (tv == 'double') {
		if (val != val || int(val) != val) return { ok: false };
		return { ok: true, value: int(val) };
	}
	if (tv == 'string') {
		let s = trim(val);
		if (!match(s, /^-?[0-9]+$/)) return { ok: false };
		return { ok: true, value: int(s) };
	}
	return { ok: false };
};

export function validate_sqm_config(params, iface_exists_fn) {
	let p = (type(params) == 'object') ? params : {};
	let en = !!p.enabled;
	let iface = trim(p.interface || '');
	let qdisc = trim(p.qdisc || 'cake');
	let script = trim(p.script || 'piece_of_cake.qos');
	let linkl = trim(p.linklayer || 'ethernet');
	let sq_dscp = p.squash_dscp === false ? '0' : '1';
	let sq_ing = p.squash_ingress === false ? '0' : '1';
	let in_ecn = trim(p.ingress_ecn || 'ECN');
	let eg_ecn = trim(p.egress_ecn || 'ECN');
	let dbg = p.debug_logging ? '1' : '0';

	let pdl = parse_strict_int(p.download_kbps, 0);
	let pul = parse_strict_int(p.upload_kbps, 0);
	let pov = parse_strict_int(p.overhead, 44);
	let pvb = parse_strict_int(p.verbosity, 5);
	if (!pdl.ok || !pul.ok || !pov.ok || !pvb.ok) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'يجب أن تكون قيم السرعة والحمل الإضافي ومستوى السجل أعداداً صحيحة صالحة' };
	}
	let dl = pdl.value;
	let ul = pul.value;
	let overh = pov.value;
	let verb_lvl = pvb.value;

	if (!ALLOWED_IFACES[iface]) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'واجهة الشبكة غير مدرجة ضمن واجهات SQM المعتمدة' };
	}
	if (en && iface_exists_fn && !iface_exists_fn(iface)) {
		return { ok: false, error_code: 'DEPENDENCY', message_ar: 'واجهة الشبكة المحددة (' + iface + ') غير موجودة أو غير نشطة حالياً' };
	}
	if (!ALLOWED_QDISCS[qdisc] || !ALLOWED_SCRIPTS[script] || !ALLOWED_LINKLAYERS[linkl] || !ALLOWED_ECN[in_ecn] || !ALLOWED_ECN[eg_ecn]) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'معاملات خوارزمية SQM غير صالحة' };
	}
	if (SCRIPT_QDISC_MAP[script] != qdisc) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'تعارض: السكربت ' + script + ' يتطلب خوارزمية ' + SCRIPT_QDISC_MAP[script] };
	}
	if (dl < 0 || dl > 1000000 || ul < 0 || ul > 1000000 || (dl > 0 && dl < 64) || (ul > 0 && ul < 64)) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'حدود سرعة SQM يجب أن تكون 0 أو بين 64 و 1000000 Kbps' };
	}
	if (en && dl == 0 && ul == 0) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'لا يمكن تفعيل SQM مع تعيين التنزيل والرفع إلى 0 معاً' };
	}
	if (overh < 0 || overh > 128 || verb_lvl < 0 || verb_lvl > 10) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'قيم overhead (0..128) أو verbosity (0..10) خارج النطاق' };
	}

	return {
		ok: true,
		enabled: en ? '1' : '0',
		interface: iface,
		download: '' + dl,
		upload: '' + ul,
		qdisc: qdisc,
		script: script,
		overhead: '' + overh,
		linklayer: linkl,
		squash_dscp: sq_dscp,
		squash_ingress: sq_ing,
		ingress_ecn: in_ecn,
		egress_ecn: eg_ecn,
		debug_logging: dbg,
		verbosity: '' + verb_lvl
	};
};

export function verify_sqm_uci(vcur, cfg) {
	if (!vcur || !cfg) return false;
	return (
		vcur.get('sqm', 'eth1') == 'queue' &&
		vcur.get('sqm', 'eth1', 'enabled') == cfg.enabled &&
		vcur.get('sqm', 'eth1', 'interface') == cfg.interface &&
		vcur.get('sqm', 'eth1', 'download') == cfg.download &&
		vcur.get('sqm', 'eth1', 'upload') == cfg.upload &&
		vcur.get('sqm', 'eth1', 'qdisc') == cfg.qdisc &&
		vcur.get('sqm', 'eth1', 'script') == cfg.script &&
		vcur.get('sqm', 'eth1', 'overhead') == cfg.overhead &&
		vcur.get('sqm', 'eth1', 'linklayer') == cfg.linklayer &&
		vcur.get('sqm', 'eth1', 'squash_dscp') == cfg.squash_dscp &&
		vcur.get('sqm', 'eth1', 'squash_ingress') == cfg.squash_ingress &&
		vcur.get('sqm', 'eth1', 'ingress_ecn') == cfg.ingress_ecn &&
		vcur.get('sqm', 'eth1', 'egress_ecn') == cfg.egress_ecn &&
		vcur.get('sqm', 'eth1', 'debug_logging') == cfg.debug_logging &&
		vcur.get('sqm', 'eth1', 'verbosity') == cfg.verbosity
	);
};

export function parse_tc_qdisc_summary(tc_raw, target_iface) {
	let lines = split(tc_raw || '', '\n');
	let qdiscs = [];
	let cur = null;
	for (let ln in lines) {
		let m = match(ln, /^qdisc\s+([a-zA-Z0-9_]+)\s+\S+\s+dev\s+(\S+)/);
		if (m) {
			if (cur) push(qdiscs, cur);
			cur = { qdisc: m[1], dev: m[2], dropped: 0, overlimits: 0 };
			continue;
		}
		if (cur) {
			let md = match(ln, /dropped\s+([0-9]+),\s+overlimits\s+([0-9]+)/);
			if (md) {
				cur.dropped = +md[1];
				cur.overlimits = +md[2];
			}
		}
	}
	if (cur) push(qdiscs, cur);
	let active_match = false;
	for (let q in qdiscs) {
		if ((!target_iface || q.dev == target_iface) && (q.qdisc == 'cake' || q.qdisc == 'fq_codel')) {
			active_match = true;
			break;
		}
	}
	return { qdiscs: qdiscs, active_shaper_detected: active_match };
};

export function verify_tc_qdisc_active(tc_raw, iface, expected_qdisc) {
	let lines = split(tc_raw || '', '\n');
	for (let ln in lines) {
		let m = match(ln, /^qdisc\s+([a-zA-Z0-9_]+)\s+\S+\s+dev\s+(\S+)/);
		if (m && m[1] == expected_qdisc && m[2] == iface) return true;
	}
	return false;
};

function snapshot_sqm(cur) {
	let stype = cur.get('sqm', 'eth1');
	if (!stype) return { exists: false, stype: null, values: {} };
	let vals = cur.get_all('sqm', 'eth1') || {};
	let clean = {};
	for (let k in keys(vals)) {
		if (substr(k, 0, 1) != '.') clean[k] = vals[k];
	}
	return { exists: true, stype: stype, values: clean };
}

function verify_sqm_snapshot(cur, snap) {
	let stype = cur.get('sqm', 'eth1');
	if (!snap || !snap.exists) return !stype;
	if (stype != snap.stype) return false;
	let actual = cur.get_all('sqm', 'eth1') || {};
	let expected = snap.values || {};
	for (let k in keys(expected)) {
		if (actual[k] != expected[k]) return false;
	}
	for (let k in keys(actual)) {
		if (substr(k, 0, 1) != '.' && actual[k] != expected[k]) return false;
	}
	return true;
}

function restore_and_verify_sqm(snap, deps) {
	try {
		let rcur = deps.uci_cursor();
		rcur.delete('sqm', 'eth1');
		if (snap && snap.exists) {
			rcur.set('sqm', 'eth1', snap.stype);
			for (let k in keys(snap.values || {})) {
				rcur.set('sqm', 'eth1', k, snap.values[k]);
			}
		}
		let cm = rcur.commit('sqm');
		if (cm === false || cm == null) return false;
		let vcur = deps.uci_cursor();
		return verify_sqm_snapshot(vcur, snap);
	} catch (e) {
		return false;
	}
}

export function apply_sqm_tx(cfg, deps, cb) {
	let cur = deps.uci_cursor();
	let snap = snapshot_sqm(cur);

	let commit_ok = true;
	try {
		cur.set('sqm', 'eth1', 'queue');
		cur.set('sqm', 'eth1', 'enabled', cfg.enabled);
		cur.set('sqm', 'eth1', 'interface', cfg.interface);
		cur.set('sqm', 'eth1', 'download', cfg.download);
		cur.set('sqm', 'eth1', 'upload', cfg.upload);
		cur.set('sqm', 'eth1', 'qdisc', cfg.qdisc);
		cur.set('sqm', 'eth1', 'script', cfg.script);
		cur.set('sqm', 'eth1', 'overhead', cfg.overhead);
		cur.set('sqm', 'eth1', 'linklayer', cfg.linklayer);
		cur.set('sqm', 'eth1', 'squash_dscp', cfg.squash_dscp);
		cur.set('sqm', 'eth1', 'squash_ingress', cfg.squash_ingress);
		cur.set('sqm', 'eth1', 'ingress_ecn', cfg.ingress_ecn);
		cur.set('sqm', 'eth1', 'egress_ecn', cfg.egress_ecn);
		cur.set('sqm', 'eth1', 'debug_logging', cfg.debug_logging);
		cur.set('sqm', 'eth1', 'verbosity', cfg.verbosity);
		let cm0 = cur.commit('sqm');
		if (cm0 === false || cm0 == null) commit_ok = false;
	} catch (e) {
		commit_ok = false;
	}

	if (!commit_ok || !verify_sqm_uci(deps.uci_cursor(), cfg)) {
		let rb_ok = restore_and_verify_sqm(snap, deps);
		let fr = !rb_ok ? deps.enter_emergency_freeze('sqm_update uci rollback failed') : null;
		deps.audit_append(deps.actor, 'sqm_update', cfg.interface, rb_ok ? 'rolled_back' : 'rollback_failed', commit_ok ? 'Post-commit UCI verify failed' : 'UCI commit failed');
		cb({
			ok: false,
			error_code: 'INTERNAL',
			rolled_back: rb_ok,
			rollback_failed: !rb_ok,
			freeze_persisted: fr ? !!fr.freeze_persisted : false,
			freeze_persist_failed: fr ? !!fr.freeze_persist_failed : false,
			message_ar: rb_ok ? 'فشل حفظ أو التحقق من إعدادات SQM وتم التراجع تلقائياً' : 'فشل حرج: تعذر استعادة إعدادات SQM — تم تجميد التعديلات'
		});
		return;
	}

	let rollback_with_reload = function(reason_msg, detail_msg) {
		let rb_cur_ok = restore_and_verify_sqm(snap, deps);
		if (!rb_cur_ok) {
			let fr = deps.enter_emergency_freeze('sqm_update uci restore failed');
			deps.audit_append(deps.actor, 'sqm_update', cfg.interface, 'rollback_failed', detail_msg + '; UCI restore failed');
			cb({
				ok: false,
				error_code: 'INTERNAL',
				rolled_back: false,
				rollback_failed: true,
				freeze_persisted: !!fr.freeze_persisted,
				freeze_persist_failed: !!fr.freeze_persist_failed,
				message_ar: 'فشل حرج: تعذر استعادة إعدادات SQM بعد فشل التطبيق — تم تجميد التعديلات'
			});
			return;
		}
		deps.reload_sqm(function(rr) {
			let all_ok = !!(rr && rr.ok);
			let fr = !all_ok ? deps.enter_emergency_freeze('sqm_update reload rollback failed') : null;
			deps.audit_append(deps.actor, 'sqm_update', cfg.interface, all_ok ? 'rolled_back' : 'rollback_failed', detail_msg);
			cb({
				ok: false,
				error_code: all_ok ? 'DEPENDENCY' : 'INTERNAL',
				rolled_back: all_ok,
				rollback_failed: !all_ok,
				freeze_persisted: fr ? !!fr.freeze_persisted : false,
				freeze_persist_failed: fr ? !!fr.freeze_persist_failed : false,
				message_ar: all_ok ? reason_msg : 'فشل حرج: تعذر استعادة خدمة SQM — تم تجميد التعديلات'
			});
		});
	};

	deps.reload_sqm(function(r) {
		if (!r || !r.ok) {
			rollback_with_reload('فشل إعادة تحميل خدمة SQM وتم التراجع عن الإعدادات', 'sqm reload failed');
			return;
		}
		if (cfg.enabled != '1') {
			deps.audit_append(deps.actor, 'sqm_update', cfg.interface, 'committed', 'en=0');
			cb({ ok: true, message_ar: 'تم حفظ وتعطيل SQM بنجاح' });
			return;
		}
		deps.show_tc(cfg.interface, function(tc_res) {
			if (!tc_res || !tc_res.ok || !verify_tc_qdisc_active(tc_res.output, cfg.interface, cfg.qdisc)) {
				rollback_with_reload('لم يتم رصد خوارزمية ' + cfg.qdisc + ' على الواجهة ' + cfg.interface + ' وتم التراجع تلقائياً', 'tc qdisc verification failed');
				return;
			}
			deps.audit_append(deps.actor, 'sqm_update', cfg.interface, 'committed', sprintf('en=1 dl=%s ul=%s qdisc=%s', cfg.download, cfg.upload, cfg.qdisc));
			cb({ ok: true, tc_verified: true, message_ar: 'تم حفظ وتطبيق والتحقق من إعدادات SQM بنجاح' });
		});
	});
};
