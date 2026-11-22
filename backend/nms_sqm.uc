// Phase 4E: QoS & SQM Hardening (Strict Validation, Runtime Topology Protection, Transactional UCI + Root tc qdisc Verification & Rollback)
// Zero external dependencies; executed in-process by noc-helperd and OpenWrt chroot suites.

const ALLOWED_QDISCS = { 'cake': true, 'fq_codel': true };
const ALLOWED_SCRIPTS = { 'piece_of_cake.qos': true, 'layer_cake.qos': true, 'simple.qos': true };
const SCRIPT_QDISC_MAP = {
	'piece_of_cake.qos': 'cake',
	'layer_cake.qos': 'cake',
	'simple.qos': 'fq_codel'
};
const ALLOWED_LINKLAYERS = { 'ethernet': true, 'atm': true, 'none': true };
const ALLOWED_ECN = { 'ECN': true, 'NOECN': true };
const HARD_PROTECTED_IFACES = { 'lo': true, 'br-lan': true, 'tailscale0': true, 'docker0': true };

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

export function parse_strict_bool(val, default_val) {
	if (val == null) return { ok: true, value: !!default_val };
	if (type(val) == 'bool') return { ok: true, value: val };
	return { ok: false };
};

export function build_sqm_topology(uci_cur, ubus_dump, br_if_entries, iface_exists_fn) {
	let lan_ifaces = { 'lo': true, 'br-lan': true, 'tailscale0': true, 'docker0': true };
	let wan_ifaces = {};
	for (let e in (br_if_entries || [])) {
		if (e && e != '.' && e != '..') lan_ifaces[e] = true;
	}

	let uci_ifaces = {};
	let wan_nets = {};
	let non_wan_nets = {};

	if (uci_cur) {
		try {
			uci_cur.foreach('network', 'device', function(s) {
				if (s.name == 'br-lan' && type(s.ports) == 'array') {
					for (let pt in s.ports) if (pt) lan_ifaces[pt] = true;
				}
			});
			uci_cur.foreach('network', 'interface', function(s) {
				let nm = s['.name'] || '';
				let dev = s.device || s.ifname || '';
				let proto = s.proto || '';
				if (nm != '') uci_ifaces[nm] = { device: dev, proto: proto };
				if (nm == 'lan' || nm == 'loopback') {
					if (dev != '') lan_ifaces[dev] = true;
				}
			});
			uci_cur.foreach('firewall', 'zone', function(z) {
				let zname = lc(trim(z.name || ''));
				let nets = [];
				if (type(z.network) == 'array') nets = z.network;
				else if (type(z.network) == 'string' && trim(z.network) != '') nets = filter(split(trim(z.network), ' '), (x) => x != '');
				for (let n in nets) {
					if (zname == 'wan') wan_nets[n] = true;
					else non_wan_nets[n] = true;
				}
			});
		} catch (e) {}
	}

	// Mark any device bound to a non-WAN firewall zone (lan, guest, vpn, iot, mgmt) as protected
	for (let n in keys(non_wan_nets)) {
		if (uci_ifaces[n] && uci_ifaces[n].device != '') lan_ifaces[uci_ifaces[n].device] = true;
	}

	// Fail closed if runtime ubus network.interface dump is missing or invalid
	if (ubus_dump && type(ubus_dump.interface) == 'array') {
		let rt_by_net = {};
		for (let itf in ubus_dump.interface) {
			if (!itf || !itf['interface']) continue;
			let inm = itf['interface'];
			rt_by_net[inm] = itf;
			if (inm == 'lan' || inm == 'loopback' || non_wan_nets[inm]) {
				if (itf.l3_device) lan_ifaces[itf.l3_device] = true;
				if (itf.device) lan_ifaces[itf.device] = true;
			}
		}
		for (let wn in keys(wan_nets)) {
			if (wn == 'lan' || wn == 'loopback' || non_wan_nets[wn]) continue;
			let rt = rt_by_net[wn];
			if (!rt || rt.up === false) continue;
			let rt_l3 = rt.l3_device || '';
			let rt_l2 = rt.device || '';
			let rt_dev = rt_l3 != '' ? rt_l3 : rt_l2;
			if (rt_dev == '') continue;
			let ui = uci_ifaces[wn];
			if (ui && ui.device != '') {
				if (ui.proto == 'pppoe') {
					if (rt_l2 != '' && rt_l2 != ui.device) continue; // PPPoE L2 mismatch conflict
				} else {
					if (rt_dev != ui.device && rt_l2 != ui.device) continue; // UCI vs runtime conflict
				}
			}
			if (!HARD_PROTECTED_IFACES[rt_dev] && !lan_ifaces[rt_dev]) {
				wan_ifaces[rt_dev] = true;
			}
		}
	}

	return {
		lan_ifaces: lan_ifaces,
		wan_ifaces: wan_ifaces,
		iface_exists: iface_exists_fn
	};
};

export function validate_sqm_config(params, topology) {
	let p = (type(params) == 'object') ? params : {};
	let topo = (type(topology) == 'object') ? topology : {};

	let ben = parse_strict_bool(p.enabled, false);
	let bdbg = parse_strict_bool(p.debug_logging, false);
	let bsqd = parse_strict_bool(p.squash_dscp, true);
	let bsqi = parse_strict_bool(p.squash_ingress, true);
	if (!ben.ok || !bdbg.ok || !bsqd.ok || !bsqi.ok) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'القيم المنطقية لخيارات SQM يجب أن تكون true أو false فقط' };
	}
	let en = ben.value;
	let dbg = bdbg.value ? '1' : '0';
	let sq_dscp = bsqd.value ? '1' : '0';
	let sq_ing = bsqi.value ? '1' : '0';

	let iface = trim(p.interface || '');
	if (!match(iface, /^[a-zA-Z0-9_.-]{1,15}$/)) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'اسم واجهة الشبكة غير صالح' };
	}

	let lan_ifaces = (type(topo.lan_ifaces) == 'object') ? topo.lan_ifaces : {};
	let wan_ifaces = (type(topo.wan_ifaces) == 'object') ? topo.wan_ifaces : {};
	if (HARD_PROTECTED_IFACES[iface] || lan_ifaces[iface]) {
		return { ok: false, error_code: 'FORBIDDEN', status: 403, message_ar: 'مرفوض: لا يُسمح بتطبيق SQM على واجهات الشبكة المحلية أو الإدارة أو الحلقة الراجعة' };
	}
	if (!wan_ifaces[iface]) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'الواجهة المحددة (' + iface + ') غير مثبتة كواجهة WAN صالحة في طوبولوجيا الشبكة الحالية' };
	}
	if (en && topo.iface_exists && !topo.iface_exists(iface)) {
		return { ok: false, error_code: 'DEPENDENCY', message_ar: 'واجهة الشبكة المحددة (' + iface + ') غير موجودة أو غير نشطة حالياً' };
	}

	let qdisc = trim(p.qdisc || 'cake');
	let script = trim(p.script || 'piece_of_cake.qos');
	let linkl = trim(p.linklayer || 'ethernet');
	let in_ecn = trim(p.ingress_ecn || 'ECN');
	let eg_ecn = trim(p.egress_ecn || 'ECN');

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
		let m = match(ln, /^qdisc\s+([a-zA-Z0-9_]+)\s+\S+\s+dev\s+(\S+)\s+(root|parent)(\s|$)/);
		if (m) {
			if (cur) push(qdiscs, cur);
			cur = { qdisc: m[1], dev: m[2], is_root: (m[3] == 'root'), dropped: 0, overlimits: 0 };
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
		if (q.is_root && (!target_iface || q.dev == target_iface) && (q.qdisc == 'cake' || q.qdisc == 'fq_codel')) {
			active_match = true;
			break;
		}
	}
	return { qdiscs: qdiscs, active_shaper_detected: active_match };
};

export function verify_tc_qdisc_active(tc_raw, iface, expected_qdisc) {
	if (!tc_raw || !iface || !expected_qdisc) return false;
	let lines = split(tc_raw, '\n');
	for (let ln in lines) {
		let m = match(ln, /^qdisc\s+([a-zA-Z0-9_]+)\s+\S+\s+dev\s+(\S+)\s+root(\s|$)/);
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
	let prev_enabled = !!(snap.exists && snap.values.enabled == '1');
	let prev_iface = (snap.exists && snap.values.interface) ? snap.values.interface : cfg.interface;
	let prev_qdisc = (snap.exists && snap.values.qdisc) ? snap.values.qdisc : 'cake';

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
			if (!rr || !rr.ok) {
				let fr = deps.enter_emergency_freeze('sqm_update reload rollback failed');
				deps.audit_append(deps.actor, 'sqm_update', cfg.interface, 'rollback_failed', detail_msg + '; rollback reload failed');
				cb({
					ok: false,
					error_code: 'INTERNAL',
					rolled_back: false,
					rollback_failed: true,
					freeze_persisted: !!fr.freeze_persisted,
					freeze_persist_failed: !!fr.freeze_persist_failed,
					message_ar: 'فشل حرج: تعذر إعادة تحميل خدمة SQM أثناء التراجع — تم تجميد التعديلات'
				});
				return;
			}
			let check_ifaces = [cfg.interface];
			if (prev_iface != '' && prev_iface != cfg.interface) push(check_ifaces, prev_iface);
			let check_idx = 0;
			let verify_next_tc = null;
			verify_next_tc = function() {
				if (check_idx >= length(check_ifaces)) {
					deps.audit_append(deps.actor, 'sqm_update', cfg.interface, 'rolled_back', detail_msg + '; runtime restored');
					cb({
						ok: false,
						error_code: 'DEPENDENCY',
						rolled_back: true,
						rollback_failed: false,
						freeze_persisted: false,
						freeze_persist_failed: false,
						message_ar: reason_msg
					});
					return;
				}
				let tif = check_ifaces[check_idx];
				check_idx++;
				deps.show_tc(tif, function(tc_rb) {
					let rt_ok = !!(tc_rb && tc_rb.ok);
					if (rt_ok) {
						if (prev_enabled) {
							if (tif == prev_iface) rt_ok = verify_tc_qdisc_active(tc_rb.output, prev_iface, prev_qdisc);
							else rt_ok = !verify_tc_qdisc_active(tc_rb.output, tif, 'cake') && !verify_tc_qdisc_active(tc_rb.output, tif, 'fq_codel');
						} else {
							rt_ok = !verify_tc_qdisc_active(tc_rb.output, tif, 'cake') && !verify_tc_qdisc_active(tc_rb.output, tif, 'fq_codel');
						}
					}
					if (!rt_ok) {
						let fr = deps.enter_emergency_freeze('sqm_update runtime rollback verify failed');
						deps.audit_append(deps.actor, 'sqm_update', cfg.interface, 'rollback_failed', detail_msg + '; runtime verify failed on ' + tif);
						cb({
							ok: false,
							error_code: 'INTERNAL',
							rolled_back: false,
							rollback_failed: true,
							freeze_persisted: !!fr.freeze_persisted,
							freeze_persist_failed: !!fr.freeze_persist_failed,
							message_ar: 'فشل حرج: تعذر التحقق من استعادة حالة SQM التشغيلية — تم تجميد التعديلات'
						});
						return;
					}
					verify_next_tc();
				});
			};
			if (prev_enabled) check_ifaces = (prev_iface != cfg.interface) ? [prev_iface, cfg.interface] : [prev_iface];
			verify_next_tc();
		});
	};

	deps.reload_sqm(function(r) {
		if (!r || !r.ok) {
			rollback_with_reload('فشل إعادة تحميل خدمة SQM وتم التراجع والتحقق من استعادة الحالة السابقة', 'sqm reload failed');
			return;
		}
		if (cfg.enabled != '1') {
			deps.audit_append(deps.actor, 'sqm_update', cfg.interface, 'committed', 'en=0');
			cb({ ok: true, message_ar: 'تم حفظ وتعطيل SQM بنجاح' });
			return;
		}
		deps.show_tc(cfg.interface, function(tc_res) {
			if (!tc_res || !tc_res.ok || !verify_tc_qdisc_active(tc_res.output, cfg.interface, cfg.qdisc)) {
				rollback_with_reload('لم يتم رصد خوارزمية ' + cfg.qdisc + ' على جذر الواجهة ' + cfg.interface + ' وتم التراجع والتحقق من استعادة الحالة السابقة', 'tc qdisc verification failed');
				return;
			}
			deps.audit_append(deps.actor, 'sqm_update', cfg.interface, 'committed', sprintf('en=1 dl=%s ul=%s qdisc=%s', cfg.download, cfg.upload, cfg.qdisc));
			cb({ ok: true, tc_verified: true, message_ar: 'تم حفظ وتطبيق والتحقق من إعدادات SQM بنجاح' });
		});
	});
};
