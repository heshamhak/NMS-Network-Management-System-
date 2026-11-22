// Phase 4C: Pure Client Management, Quotas, Schedules & Static Lease Helpers
// Zero external dependencies; executed in-process by noc-helperd and OpenWrt chroot suites.

export function is_valid_mac(mac) {
	let m = lc(trim(mac || ''));
	if (!match(m, /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/)) return false;
	if (m == '00:00:00:00:00:00' || m == 'ff:ff:ff:ff:ff:ff') return false;
	let b0 = hex(substr(m, 0, 2));
	if ((b0 & 1) != 0) return false; // reject multicast MAC
	return true;
};

export function is_valid_ipv4(ip) {
	let s = trim(ip || '');
	let p = split(s, '.');
	if (length(p) != 4) return false;
	for (let seg in p) {
		if (!match(seg, /^(0|[1-9][0-9]{0,2})$/)) return false;
		let v = +seg;
		if (v < 0 || v > 255) return false;
	}
	if (s == '0.0.0.0' || s == '255.255.255.255') return false;
	let o1 = +p[0];
	if (o1 == 127 || (o1 >= 224 && o1 <= 239)) return false;
	return true;
};

export function is_valid_hhmm(s) {
	return !!match(trim(s || ''), /^([01][0-9]|2[0-3]):[0-5][0-9]$/);
};

export function hhmm_to_minutes(s) {
	let t = trim(s || '');
	if (!is_valid_hhmm(t)) return -1;
	let p = split(t, ':');
	return (+p[0] * 60) + (+p[1]);
};

export function is_schedule_active(start_hhmm, end_hhmm, now_hhmm) {
	let s = hhmm_to_minutes(start_hhmm);
	let e = hhmm_to_minutes(end_hhmm);
	let n = hhmm_to_minutes(now_hhmm);
	if (s < 0 || e < 0 || n < 0 || s == e) return false;
	if (s < e) return (n >= s && n < e);
	return (n >= s || n < e);
};

export function is_protected_client(mac, ip, client_ip, gw_macs, gw_ips) {
	let m = lc(trim(mac || ''));
	let a = trim(ip || '');
	let cip = trim(client_ip || '');
	let gm = (type(gw_macs) == 'object') ? gw_macs : {};
	let gi = (type(gw_ips) == 'object') ? gw_ips : {};
	if (m != '' && gm[m]) return true;
	if (a != '' && (gi[a] || (cip != '' && a == cip))) return true;
	return false;
};

export function parse_leases_ip_map(leases_raw) {
	let out = {};
	for (let ln in split(leases_raw || '', '\n')) {
		let p = filter(split(trim(ln), ' '), (x) => x != '');
		if (length(p) >= 3) {
			let mac = lc(p[1]);
			let ip = p[2];
			if (is_valid_mac(mac) && is_valid_ipv4(ip)) out[mac] = ip;
		}
	}
	return out;
};

export function validate_quota_input(params, ip_by_mac, client_ip, gw_macs, gw_ips) {
	let p = (type(params) == 'object') ? params : {};
	let mac = lc(trim(p.mac || ''));
	if (!is_valid_mac(mac)) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'عنوان MAC غير صالح' };
	}
	let qmb = (p.quota_mb != null) ? +p.quota_mb : 0;
	let tkbps = (p.throttle_kbps != null) ? +p.throttle_kbps : 0;
	if (qmb < 0 || qmb > 10485760 || tkbps < 0 || tkbps > 1000000 || (tkbps > 0 && tkbps < 64)) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'قيم الحصة أو حد السرعة غير صالحة (0 أو 64..1000000 Kbps)' };
	}
	let ip = (type(ip_by_mac) == 'object' && ip_by_mac[mac]) ? ip_by_mac[mac] : trim(p.ip || '');
	if ((qmb > 0 || tkbps > 0) && is_protected_client(mac, ip, client_ip, gw_macs, gw_ips)) {
		return { ok: false, error_code: 'FORBIDDEN', message_ar: 'مرفوض: لا يُسمح بتطبيق حصة أو تقييد سرعة على البوابة أو الجهاز المدير' };
	}
	return { ok: true, mac: mac, quota_mb: int(qmb), throttle_kbps: int(tkbps) };
};

export function validate_schedule_input(params, ip_by_mac, client_ip, gw_macs, gw_ips) {
	let p = (type(params) == 'object') ? params : {};
	let mac = lc(trim(p.mac || ''));
	let action_type = trim(p.action_type || 'block');
	let start_h = trim(p.start_time || '');
	let end_h = trim(p.end_time || '');
	if (!is_valid_mac(mac)) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'عنوان MAC غير صالح' };
	}
	if (action_type != 'block' && action_type != 'throttle') {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'نوع الإجراء المجدول غير مدعوم (المتاح: block أو throttle)' };
	}
	if (!is_valid_hhmm(start_h) || !is_valid_hhmm(end_h) || start_h == end_h) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'نطاق الوقت غير صالح (يجب أن يكون HH:MM ومختلفين)' };
	}
	let tkbps = 0;
	if (action_type == 'throttle') {
		tkbps = (p.throttle_kbps != null && +p.throttle_kbps != 0) ? +p.throttle_kbps : 512;
		if (tkbps < 64 || tkbps > 1000000) {
			return { ok: false, error_code: 'VALIDATION', message_ar: 'حد السرعة المجدول يجب أن يكون بين 64 و 1000000 Kbps' };
		}
		tkbps = int(tkbps);
	}
	let ip = (type(ip_by_mac) == 'object' && ip_by_mac[mac]) ? ip_by_mac[mac] : trim(p.ip || '');
	if (is_protected_client(mac, ip, client_ip, gw_macs, gw_ips)) {
		return { ok: false, error_code: 'FORBIDDEN', message_ar: 'مرفوض: لا يُسمح بجدولة حظر أو تقييد على البوابة أو الجهاز المدير' };
	}
	return { ok: true, mac: mac, action_type: action_type, start_time: start_h, end_time: end_h, throttle_kbps: tkbps };
};

export function validate_static_lease_conflict(mac, ip, hostname, enable, lan_ip, gw_ips, existing_hosts) {
	let m = lc(trim(mac || ''));
	let a = trim(ip || '');
	let hn = trim(hostname || '');
	if (!is_valid_mac(m)) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'عنوان MAC غير صالح' };
	}
	if (hn != '' && !match(hn, /^[a-zA-Z0-9_-]{1,32}$/)) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'اسم المضيف غير صالح' };
	}
	if (!enable) return { ok: true, mac: m, ip: a, hostname: hn };
	if (!is_valid_ipv4(a) || a == trim(lan_ip || '') || (type(gw_ips) == 'object' && gw_ips[a])) {
		return { ok: false, error_code: 'VALIDATION', message_ar: 'عنوان IP غير صالح أو يتعارض مع البوابة' };
	}
	if (type(existing_hosts) == 'array') {
		for (let h in existing_hosts) {
			let hmac = lc(trim(h.mac || ''));
			let hip = trim(h.ip || '');
			if (hip == a && hmac != '' && hmac != m) {
				return { ok: false, error_code: 'CONFLICT', message_ar: 'عنوان IP مستخدم مسبقاً في حجز DHCP لجهاز آخر (' + hmac + ')' };
			}
		}
	}
	return { ok: true, mac: m, ip: a, hostname: hn };
};

export function compute_effective_client_rules(manual_rules, quotas, schedules, usage_by_mac, ip_by_mac, now_hhmm, gw_macs, gw_ips) {
	let mr = (type(manual_rules) == 'object') ? manual_rules : {};
	let gm = (type(gw_macs) == 'object') ? gw_macs : {};
	let gi = (type(gw_ips) == 'object') ? gw_ips : {};
	let ipm = (type(ip_by_mac) == 'object') ? ip_by_mac : {};
	let usg = (type(usage_by_mac) == 'object') ? usage_by_mac : {};

	let eff_blocked_macs = {};
	let eff_blocked_ips = {};
	let eff_rate_limits = {};
	let active_schedules = {};
	let exceeded_quotas = {};

	for (let mac in keys(mr.blocked_macs || {})) {
		let m = lc(mac);
		if (mr.blocked_macs[mac] && is_valid_mac(m) && !gm[m]) eff_blocked_macs[m] = true;
	}
	for (let ip in keys(mr.blocked_ips || {})) {
		if (mr.blocked_ips[ip] && is_valid_ipv4(ip) && !gi[ip]) eff_blocked_ips[ip] = true;
	}
	for (let ip in keys(mr.rate_limits || {})) {
		let kbps = +(mr.rate_limits[ip] || 0);
		if (kbps >= 64 && kbps <= 1000000 && is_valid_ipv4(ip) && !gi[ip]) eff_rate_limits[ip] = int(kbps);
	}

	if (type(schedules) == 'array') {
		for (let sc in schedules) {
			if (type(sc) != 'object' || sc.enabled === false) continue;
			let m = lc(trim(sc.mac || ''));
			if (!is_valid_mac(m) || gm[m]) continue;
			if (!is_schedule_active(sc.start_time, sc.end_time, now_hhmm)) continue;
			if (sc.id) active_schedules[sc.id] = true;
			let ip = ipm[m] || '';
			if (sc.action_type == 'block') {
				eff_blocked_macs[m] = true;
				if (is_valid_ipv4(ip) && !gi[ip]) eff_blocked_ips[ip] = true;
			} else if (sc.action_type == 'throttle' && is_valid_ipv4(ip) && !gi[ip]) {
				let tk = +(sc.throttle_kbps || 512);
				if (tk < 64) tk = 64;
				if (tk > 1000000) tk = 1000000;
				tk = int(tk);
				eff_rate_limits[ip] = eff_rate_limits[ip] != null ? (eff_rate_limits[ip] < tk ? eff_rate_limits[ip] : tk) : tk;
			}
		}
	}

	if (type(quotas) == 'object') {
		for (let raw_m in keys(quotas)) {
			let m = lc(trim(raw_m));
			let q = quotas[raw_m];
			if (!q || type(q) != 'object' || !is_valid_mac(m) || gm[m]) continue;
			let qmb = +(q.quota_mb || 0);
			let tk = +(q.throttle_kbps || 0);
			let used_bytes = +(usg[m] || 0);
			let ip = ipm[m] || '';
			if (qmb > 0 && used_bytes >= (qmb * 1048576)) {
				exceeded_quotas[m] = true;
				if (tk >= 64 && tk <= 1000000) {
					if (is_valid_ipv4(ip) && !gi[ip]) {
						tk = int(tk);
						eff_rate_limits[ip] = eff_rate_limits[ip] != null ? (eff_rate_limits[ip] < tk ? eff_rate_limits[ip] : tk) : tk;
					}
				} else {
					eff_blocked_macs[m] = true;
					if (is_valid_ipv4(ip) && !gi[ip]) eff_blocked_ips[ip] = true;
				}
			}
		}
	}

	let sig_parts = [
		'M:' + join(',', sort(keys(eff_blocked_macs))),
		'I:' + join(',', sort(keys(eff_blocked_ips))),
		'R:' + join(',', map(sort(keys(eff_rate_limits)), (ip) => ip + '=' + eff_rate_limits[ip]))
	];

	return {
		blocked_macs: eff_blocked_macs,
		blocked_ips: eff_blocked_ips,
		rate_limits: eff_rate_limits,
		active_schedules: active_schedules,
		exceeded_quotas: exceeded_quotas,
		signature: join('|', sig_parts)
	};
};
