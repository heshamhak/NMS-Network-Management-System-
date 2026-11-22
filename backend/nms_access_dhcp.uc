// Phase 4D: Access Control (RBAC & Session Hardening) & DHCP Hardening Helpers
// Zero external dependencies; executed in-process by noc-apid, noc-helperd, and OpenWrt chroot suites.

const ADMIN_ONLY_GET_ACTIONS = {
	logs: true,
	audit: true,
	diagnostics: true,
	backup_export: true,
	backup_validate: true,
	auth_users: true,
	packages: true,
	client_inspect: true,
	alerts: true,
	security_audit: true,
	totp_status: true,
	device_quotas: true
};

export function is_admin_only_action(action, method) {
	if (method == 'POST') return true;
	return !!ADMIN_ONLY_GET_ACTIONS[action || ''];
};

export function check_rbac_access(sess, action, method) {
	if (!sess || type(sess) != 'object') {
		return { ok: false, status: 401, error_code: 'AUTH', message_ar: 'انتهت الجلسة أو يلزم تسجيل الدخول أولاً' };
	}
	if (is_admin_only_action(action, method) && sess.role != 'admin') {
		return { ok: false, status: 403, error_code: 'FORBIDDEN', message_ar: 'هذه العملية متاحة لصلاحية المدير فقط' };
	}
	return { ok: true };
};

export function revoke_sessions_for_user(sessions_map, username, except_sid) {
	if (type(sessions_map) != 'object' || !username || username == '') return 0;
	let removed = 0;
	for (let sid in keys(sessions_map)) {
		let s = sessions_map[sid];
		if (s && s.username == username && (!except_sid || sid != except_sid)) {
			delete sessions_map[sid];
			removed++;
		}
	}
	return removed;
};

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

export function validate_dhcp_pool_config(params) {
	let p = (type(params) == 'object') ? params : {};
	let pst = parse_strict_int(p.start, 5);
	let plim = parse_strict_int(p.limit, 31);
	let pcsize = parse_strict_int(p.cachesize, 1000);
	if (!pst.ok || !plim.ok || !pcsize.ok) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'يجب أن تكون قيم نطاق DHCP وحجم الذاكرة أعداداً صحيحة صالحة' };
	}
	let st = pst.value;
	let lim = plim.value;
	let csize = pcsize.value;
	let ltime = trim(p.leasetime || '1h');
	let rebind = p.rebind_protection !== false ? '1' : '0';

	if (st < 2 || st > 250 || lim < 5 || lim > 250 || (st + lim) > 254) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'نطاق عناوين DHCP غير صالح أو يتجاوز حدود الشبكة' };
	}
	if (csize < 0 || csize > 10000) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'حجم ذاكرة التخزين المؤقت DNS غير صالح (0..10000)' };
	}
	if (ltime != 'infinite') {
		let m = match(ltime, /^([0-9]{1,4})([hm])$/);
		if (!m) {
			return { ok: false, error_code: 'VALIDATION', message_ar: 'مدة إيجار DHCP غير صالحة (مثال: 1h أو 30m أو infinite)' };
		}
		let num = +m[1];
		let unit = m[2];
		if ((unit == 'm' && num < 2) || (unit == 'h' && num < 1)) {
			return { ok: false, error_code: 'VALIDATION', message_ar: 'مدة إيجار DHCP قصيرة جداً (الحد الأدنى 2m أو 1h)' };
		}
	}
	return { ok: true, start: '' + st, limit: '' + lim, leasetime: ltime, rebind_protection: rebind, cachesize: '' + csize };
};

export function verify_dhcp_pool_uci(vcur, dm_sid, vp) {
	if (!vcur || !vp) return false;
	return (
		vcur.get('dhcp', 'lan', 'start') == vp.start &&
		vcur.get('dhcp', 'lan', 'limit') == vp.limit &&
		vcur.get('dhcp', 'lan', 'leasetime') == vp.leasetime &&
		vcur.get('dhcp', dm_sid, 'rebind_protection') == vp.rebind_protection &&
		vcur.get('dhcp', dm_sid, 'cachesize') == vp.cachesize
	);
};

export function validate_local_domain_input(dname, dip, existing_domains, is_valid_fqdn_fn, is_blocked_fn, is_valid_ipv4_fn) {
	let name = lc(trim(dname || ''));
	let ip = trim(dip || '');
	if (!is_valid_fqdn_fn(name) || is_blocked_fn(name) || !is_valid_ipv4_fn(ip)) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'اسم النطاق أو عنوان IP غير صالح' };
	}
	if (type(existing_domains) == 'array') {
		for (let d in existing_domains) {
			if (d && lc(trim(d.name || '')) == name) {
				return { ok: false, error_code: 'CONFLICT', message_ar: 'النطاق المحلي مسجل مسبقاً (' + name + ')' };
			}
		}
	}
	return { ok: true, name: name, ip: ip };
};

export function snapshot_uci_section(cur, cfg, sid) {
	let stype = cur.get(cfg, sid);
	if (!stype) return { exists: false, stype: null, values: {} };
	let vals = cur.get_all(cfg, sid) || {};
	let clean = {};
	for (let k in keys(vals)) {
		if (substr(k, 0, 1) != '.') clean[k] = vals[k];
	}
	return { exists: true, stype: stype, values: clean };
};

export function restore_uci_section(cur, cfg, sid, snap) {
	if (!snap || !snap.exists) {
		cur.delete(cfg, sid);
		return;
	}
	cur.delete(cfg, sid);
	cur.set(cfg, sid, snap.stype);
	for (let k in keys(snap.values || {})) {
		cur.set(cfg, sid, k, snap.values[k]);
	}
};

export function verify_uci_snapshot(cur, cfg, sid, snap) {
	let stype = cur.get(cfg, sid);
	if (!snap || !snap.exists) {
		return !stype;
	}
	if (stype != snap.stype) return false;
	let actual = cur.get_all(cfg, sid) || {};
	let expected = snap.values || {};
	for (let k in keys(expected)) {
		if (actual[k] != expected[k]) return false;
	}
	for (let k in keys(actual)) {
		if (substr(k, 0, 1) != '.' && actual[k] != expected[k]) return false;
	}
	return true;
};

function restore_and_verify_uci(saved, deps) {
	try {
		let rcur = deps.uci_cursor();
		for (let item in saved) restore_uci_section(rcur, item.cfg, item.sid, item.snap);
		let cm = rcur.commit('dhcp');
		if (cm === false || cm == null) return false;
		let vcur = deps.uci_cursor();
		for (let item in saved) {
			if (!verify_uci_snapshot(vcur, item.cfg, item.sid, item.snap)) return false;
		}
		return true;
	} catch (e) {
		return false;
	}
}

export function apply_dhcp_tx(snapshots, apply_fn, verify_fn, deps, cb) {
	let snap_list = (type(snapshots) == 'array') ? snapshots : [];
	let cur = deps.uci_cursor();
	let saved = [];
	for (let s in snap_list) {
		push(saved, { cfg: s.cfg || 'dhcp', sid: s.sid, snap: snapshot_uci_section(cur, s.cfg || 'dhcp', s.sid) });
	}
	let commit_ok = true;
	try {
		apply_fn(cur);
		let cm0 = cur.commit('dhcp');
		if (cm0 === false || cm0 == null) commit_ok = false;
	} catch (e) {
		commit_ok = false;
	}
	if (!commit_ok) {
		let rb_ok = restore_and_verify_uci(saved, deps);
		let fr = !rb_ok ? deps.enter_emergency_freeze(deps.verb + ' commit rollback failed') : null;
		deps.audit_append(deps.actor, deps.verb, deps.target_id, rb_ok ? 'rolled_back' : 'rollback_failed', 'UCI commit failed');
		cb({
			ok: false,
			error_code: 'INTERNAL',
			rolled_back: rb_ok,
			rollback_failed: !rb_ok,
			freeze_persisted: fr ? !!fr.freeze_persisted : false,
			freeze_persist_failed: fr ? !!fr.freeze_persist_failed : false,
			message_ar: rb_ok ? 'فشل حفظ إعدادات DHCP وتم التراجع والتحقق منه' : 'فشل حرج: تعذر حفظ أو استرجاع إعدادات DHCP — تم تجميد التعديلات'
		});
		return;
	}
	let v_ok = true;
	try {
		v_ok = !verify_fn || !!verify_fn(deps.uci_cursor());
	} catch (e) {
		v_ok = false;
	}
	if (!v_ok) {
		let rb_ok = restore_and_verify_uci(saved, deps);
		let fr = !rb_ok ? deps.enter_emergency_freeze(deps.verb + ' verify rollback failed') : null;
		deps.audit_append(deps.actor, deps.verb, deps.target_id, rb_ok ? 'rolled_back' : 'rollback_failed', 'Post-commit UCI verification failed');
		cb({
			ok: false,
			error_code: 'INTERNAL',
			rolled_back: rb_ok,
			rollback_failed: !rb_ok,
			freeze_persisted: fr ? !!fr.freeze_persisted : false,
			freeze_persist_failed: fr ? !!fr.freeze_persist_failed : false,
			message_ar: rb_ok ? 'فشل التحقق من إعدادات DHCP وتم التراجع والتحقق منه' : 'فشل حرج: تعذر التراجع عن إعدادات DHCP — تم تجميد التعديلات'
		});
		return;
	}
	deps.reload_dnsmasq(function(r) {
		if (r && r.ok) {
			deps.audit_append(deps.actor, deps.verb, deps.target_id, 'committed', deps.commit_detail || 'Verified UCI + dnsmasq reload');
			cb({ ok: true });
			return;
		}
		let rb_cur_ok = restore_and_verify_uci(saved, deps);
		if (!rb_cur_ok) {
			let fr = deps.enter_emergency_freeze(deps.verb + ' dnsmasq rollback UCI failed');
			deps.audit_append(deps.actor, deps.verb, deps.target_id, 'rollback_failed', 'dnsmasq reload failed and UCI restore/verify failed');
			cb({
				ok: false,
				error_code: 'INTERNAL',
				rolled_back: false,
				rollback_failed: true,
				freeze_persisted: !!fr.freeze_persisted,
				freeze_persist_failed: !!fr.freeze_persist_failed,
				message_ar: 'فشل حرج: تعذر إعادة تحميل dnsmasq وفشل استرجاع الإعدادات — تم تجميد التعديلات'
			});
			return;
		}
		deps.reload_dnsmasq(function(rr) {
			let all_ok = !!(rr && rr.ok);
			let fr = !all_ok ? deps.enter_emergency_freeze(deps.verb + ' dnsmasq rollback reload failed') : null;
			deps.audit_append(deps.actor, deps.verb, deps.target_id, all_ok ? 'rolled_back' : 'rollback_failed', all_ok ? 'Restored & verified UCI and reloaded dnsmasq' : 'Restored UCI but dnsmasq rollback reload failed');
			cb({
				ok: false,
				error_code: 'INTERNAL',
				rolled_back: all_ok,
				rollback_failed: !all_ok,
				freeze_persisted: fr ? !!fr.freeze_persisted : false,
				freeze_persist_failed: fr ? !!fr.freeze_persist_failed : false,
				message_ar: all_ok ? 'فشل إعادة تحميل dnsmasq وتم التراجع عن تغييرات DHCP والتحقق منه' : 'فشل حرج: تعذر استعادة خدمة dnsmasq — تم تجميد التعديلات'
			});
		});
	});
};
