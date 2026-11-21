// Shared production ucode module for Network, VLAN, Bridge, DSA, and IPv6 validation & transactional rollback.
// Imported by /usr/libexec/noc-helperd and directly executable by ucode test harnesses.

import * as nms_archive from '/usr/libexec/nms_archive.uc';

export function is_valid_ifname(s) {
	return type(s) == 'string' && match(s, /^[a-zA-Z][a-zA-Z0-9_]{0,14}$/) != null;
};

export function is_valid_devname(s) {
	return type(s) == 'string' && match(s, /^[a-zA-Z0-9._:-]{1,32}$/) != null && index(s, '..') < 0;
};

export function is_valid_ipv4(ip) {
	if (type(ip) != 'string') return false;
	let p = split(ip, '.');
	if (length(p) != 4) return false;
	for (let seg in p) {
		if (!match(seg, /^[0-9]{1,3}$/)) return false;
		let v = +seg;
		if (v < 0 || v > 255) return false;
	}
	return true;
};

export function is_valid_ipv6_addr(addr) {
	if (type(addr) != 'string' || length(addr) < 2 || length(addr) > 45) return false;
	if (index(addr, '%') >= 0) return false;
	if (!match(addr, /^[0-9a-fA-F:]+$/)) return false;
	let dbl = index(addr, '::');
	if (dbl >= 0 && index(substr(addr, dbl + 2), '::') >= 0) return false; // at most one ::
	if (dbl >= 0) {
		let left = substr(addr, 0, dbl);
		let right = substr(addr, dbl + 2);
		let lp = left != '' ? split(left, ':') : [];
		let rp = right != '' ? split(right, ':') : [];
		if (length(lp) + length(rp) >= 8) return false;
		for (let g in lp) if (!match(g, /^[0-9a-fA-F]{1,4}$/)) return false;
		for (let g in rp) if (!match(g, /^[0-9a-fA-F]{1,4}$/)) return false;
		return true;
	}
	let groups = split(addr, ':');
	if (length(groups) != 8) return false;
	for (let g in groups) if (!match(g, /^[0-9a-fA-F]{1,4}$/)) return false;
	return true;
};

export function is_valid_ipv6_cidr(cidr) {
	if (type(cidr) != 'string') return false;
	let p = split(cidr, '/');
	if (length(p) != 2) return false;
	if (!is_valid_ipv6_addr(p[0])) return false;
	if (!match(p[1], /^[0-9]{1,3}$/)) return false;
	let plen = +p[1];
	return plen >= 1 && plen <= 128;
};

export function is_valid_vlan_id(vid) {
	let n = +vid;
	return ('' + int(n)) == trim('' + vid) && n >= 1 && n <= 4094;
};

export function validate_dsa_port_entry(p) {
	if (type(p) != 'string') return false;
	return match(p, /^[a-zA-Z0-9._-]{1,16}(:[ut]\*?)?$/) != null && index(p, '..') < 0;
};

export function validate_interface_cfg(cfg) {
	if (type(cfg) != 'object') return { ok: false, error: 'كائن بيانات الواجهة غير صالح' };
	let name = trim('' + (cfg.name || ''));
	if (!is_valid_ifname(name)) return { ok: false, error: 'اسم الواجهة غير صالح' };
	if (name == 'loopback') return { ok: false, error: 'لا يُسمح بتعديل واجهة loopback الأساسية' };

	let proto = trim('' + (cfg.proto || 'static'));
	let allow_proto = { 'static': true, 'dhcp': true, 'dhcpv6': true, 'pppoe': true, 'none': true };
	if (!allow_proto[proto]) return { ok: false, error: 'بروتوكول الواجهة غير مدعوم: ' + proto };

	let dev = trim('' + (cfg.device || ''));
	if (dev != '' && !is_valid_devname(dev)) return { ok: false, error: 'اسم الجهاز الفيزيائي للواجهة غير صالح' };

	if (proto == 'static') {
		let ipaddr = trim('' + (cfg.ipaddr || ''));
		let netmask = trim('' + (cfg.netmask || '255.255.255.0'));
		let ip6addr = trim('' + (cfg.ip6addr || ''));
		if (ipaddr == '' && ip6addr == '') return { ok: false, error: 'يلزم تحديد عنوان IPv4 أو IPv6 للواجهة الثابتة' };
		if (ipaddr != '' && !is_valid_ipv4(ipaddr)) return { ok: false, error: 'عنوان IPv4 غير صالح' };
		if (ipaddr != '' && !is_valid_ipv4(netmask)) return { ok: false, error: 'قناع الشبكة غير صالح' };
		if (ip6addr != '' && !is_valid_ipv6_cidr(ip6addr)) return { ok: false, error: 'عنوان IPv6 CIDR غير صالح' };
	}

	let gw = trim('' + (cfg.gateway || ''));
	if (gw != '' && !is_valid_ipv4(gw)) return { ok: false, error: 'عنوان البوابة IPv4 غير صالح' };

	let ip6gw = trim('' + (cfg.ip6gw || ''));
	if (ip6gw != '' && !is_valid_ipv6_addr(ip6gw)) return { ok: false, error: 'عنوان بوابة IPv6 غير صالح' };

	if (cfg.mtu != null && cfg.mtu != '') {
		let mtu = +cfg.mtu;
		if (mtu < 576 || mtu > 9000) return { ok: false, error: 'قيمة MTU خارج النطاق المسموح (576..9000)' };
	}
	if (cfg.metric != null && cfg.metric != '') {
		let metric = +cfg.metric;
		if (metric < 0 || metric > 1000) return { ok: false, error: 'قيمة Metric خارج النطاق المسموح (0..1000)' };
	}
	if (cfg.ip6assign != null && cfg.ip6assign != '') {
		let a6 = +cfg.ip6assign;
		if (a6 < 0 || a6 > 64) return { ok: false, error: 'قيمة ip6assign خارج النطاق (0..64)' };
	}
	if (cfg.dns != null) {
		if (type(cfg.dns) != 'array' || length(cfg.dns) > 6) return { ok: false, error: 'قائمة خوادم DNS غير صالحة' };
		for (let d in cfg.dns) {
			let ds = trim('' + d);
			if (!is_valid_ipv4(ds) && !is_valid_ipv6_addr(ds)) return { ok: false, error: 'عنوان خادم DNS غير صالح: ' + ds };
		}
	}
	return { ok: true, name: name, proto: proto, device: dev };
};

export function validate_device_cfg(cfg) {
	if (type(cfg) != 'object') return { ok: false, error: 'بيانات جهاز الشبكة غير صالحة' };
	let name = trim('' + (cfg.name || ''));
	if (!is_valid_devname(name)) return { ok: false, error: 'اسم الجهاز غير صالح' };
	let dev_type = trim('' + (cfg.type || 'bridge'));
	let allow_t = { 'bridge': true, '8021q': true, '8021ad': true };
	if (!allow_t[dev_type]) return { ok: false, error: 'نوع الجهاز غير مدعوم: ' + dev_type };
	if (dev_type == 'bridge') {
		if (type(cfg.ports) != 'array' || length(cfg.ports) == 0 || length(cfg.ports) > 32) {
			return { ok: false, error: 'يجب تحديد منفذ واحد على الأقل للجسر' };
		}
		let seen = {};
		for (let p in cfg.ports) {
			let ps = trim('' + p);
			if (!is_valid_devname(ps)) return { ok: false, error: 'اسم منفذ الجسر غير صالح: ' + ps };
			if (seen[ps]) return { ok: false, error: 'منفذ مكرر في الجسر: ' + ps };
			seen[ps] = true;
		}
	} else {
		let ifname = trim('' + (cfg.ifname || ''));
		if (!is_valid_devname(ifname)) return { ok: false, error: 'الجهاز الأساسي لـ VLAN غير صالح' };
		if (!is_valid_vlan_id(cfg.vid)) return { ok: false, error: 'معرف VLAN غير صالح (1..4094)' };
	}
	if (cfg.mtu != null && cfg.mtu != '') {
		let mtu = +cfg.mtu;
		if (mtu < 576 || mtu > 9000) return { ok: false, error: 'قيمة MTU خارج النطاق (576..9000)' };
	}
	return { ok: true, name: name, dev_type: dev_type };
};

export function validate_bridge_vlan_cfg(cfg) {
	if (type(cfg) != 'object') return { ok: false, error: 'بيانات Bridge-VLAN غير صالحة' };
	let device = trim('' + (cfg.device || 'br-lan'));
	if (!is_valid_devname(device)) return { ok: false, error: 'اسم الجسر في Bridge-VLAN غير صالح' };
	if (!is_valid_vlan_id(cfg.vlan)) return { ok: false, error: 'رقم VLAN خارج النطاق (1..4094)' };
	if (type(cfg.ports) != 'array' || length(cfg.ports) == 0 || length(cfg.ports) > 32) {
		return { ok: false, error: 'يجب تحديد منفذ DSA واحد على الأقل' };
	}
	let seen_base = {};
	for (let p in cfg.ports) {
		let ps = trim('' + p);
		if (!validate_dsa_port_entry(ps)) return { ok: false, error: 'صيغة منفذ DSA غير صالحة: ' + ps };
		let base = split(ps, ':')[0];
		if (seen_base[base]) return { ok: false, error: 'تضارب منفذ DSA مكرر في نفس VLAN: ' + base };
		seen_base[base] = true;
	}
	return { ok: true, device: device, vlan: +cfg.vlan };
};

export function validate_ipv6_dhcp_cfg(cfg) {
	if (type(cfg) != 'object') return { ok: false, error: 'بيانات إعدادات IPv6 غير صالحة' };
	let iface = trim('' + (cfg.interface || 'lan'));
	if (!is_valid_ifname(iface)) return { ok: false, error: 'اسم الواجهة غير صالح لإعدادات IPv6' };
	let allow_mode = { 'disabled': true, 'server': true, 'relay': true, 'hybrid': true };
	let ra = trim('' + (cfg.ra || 'server'));
	let dhcpv6 = trim('' + (cfg.dhcpv6 || 'server'));
	let ndp = trim('' + (cfg.ndp || 'disabled'));
	if (!allow_mode[ra] || !allow_mode[dhcpv6] || (ndp != 'disabled' && ndp != 'relay' && ndp != 'hybrid')) {
		return { ok: false, error: 'وضع RA أو DHCPv6 أو NDP غير مدعوم' };
	}
	if (cfg.ra_management != null && cfg.ra_management != '') {
		let rm = +cfg.ra_management;
		if (rm < 0 || rm > 2) return { ok: false, error: 'قيمة ra_management غير صالحة (0..2)' };
	}
	if (cfg.ra_default != null && cfg.ra_default != '') {
		let rd = +cfg.ra_default;
		if (rd < 0 || rd > 2) return { ok: false, error: 'قيمة ra_default غير صالحة (0..2)' };
	}
	if (cfg.ula_prefix != null && trim('' + cfg.ula_prefix) != '') {
		if (!is_valid_ipv6_cidr(trim('' + cfg.ula_prefix))) return { ok: false, error: 'بادئة ULA IPv6 غير صالحة (مثال: fd00::/48)' };
	}
	if (cfg.ra_flags != null) {
		if (type(cfg.ra_flags) != 'array') return { ok: false, error: 'رايات RA غير صالحة' };
		let allow_fl = { 'managed-config': true, 'other-config': true, 'home-agent': true, 'none': true };
		for (let fl in cfg.ra_flags) {
			if (!allow_fl[trim('' + fl)]) return { ok: false, error: 'راية RA غير مدعومة: ' + fl };
		}
	}
	if (cfg.dns != null) {
		if (type(cfg.dns) != 'array' || length(cfg.dns) > 6) return { ok: false, error: 'قائمة خوادم DNSv6 غير صالحة' };
		for (let d in cfg.dns) {
			if (!is_valid_ipv6_addr(trim('' + d))) return { ok: false, error: 'عنوان DNSv6 غير صالح: ' + d };
		}
	}
	return { ok: true, interface: iface, ra: ra, dhcpv6: dhcpv6, ndp: ndp };
};

export function apply_network_tx(cfg_paths, ops) {
	// 1. Snapshot original files and metadata before any mutation
	let snaps = [];
	for (let p in cfg_paths) {
		let st = ops.lstat(p);
		if (st && st.type != 'file') {
			return { ok: false, rolled_back: false, rollback_failed: false, error: 'not_regular_file', message_ar: 'ملف الإعدادات ليس ملفاً عادياً: ' + p };
		}
		let raw = null;
		if (st) {
			raw = ops.readfile(p);
			if (raw == null) {
				return { ok: false, rolled_back: false, rollback_failed: false, error: 'read_failed', message_ar: 'تعذر قراءة ملف الإعدادات الأصلي قبل التعديل: ' + p };
			}
		}
		push(snaps, {
			path: p,
			existed: !!st,
			raw: raw,
			mode: st ? (st.mode & 0o7777) : 0o644,
			uid: st ? st.uid : null,
			gid: st ? st.gid : null
		});
	}

	// 2. Apply UCI mutation
	let ap = ops.apply_uci();
	if (!ap || !ap.ok) {
		// Ensure on-disk files are restored if apply_uci partially modified anything
		let rb_err = false;
		for (let s in snaps) {
			if (s.existed) {
				let aw = nms_archive.atomic_write_checked(s.path, s.raw, s.mode, s.uid, s.gid, ops.aw_ops);
				let st_c = ops.lstat(s.path);
				let cur_c = ops.readfile(s.path);
				if (!aw.ok || !st_c || (st_c.mode & 0o7777) != s.mode || cur_c != s.raw) rb_err = true;
			}
		}
		if (rb_err) {
			ops.on_rollback_failed('apply_uci rollback failed');
			return { ok: false, rolled_back: false, rollback_failed: true, error: 'apply_failed', message_ar: 'فشل تطبيق تعديل UCI وفشل استعادة الحالة الأصلية' };
		}
		return { ok: false, rolled_back: true, rollback_failed: false, error: 'apply_failed', message_ar: (ap && ap.error) || 'فشل تطبيق تعديل UCI وتم الحفاظ على الحالة الأصلية' };
	}

	// 3. Pre-reload validation, service reload, and post-apply verification
	let fail_stage = '';
	let fail_msg = '';
	let val = ops.validate_config();
	if (!val || !val.ok) {
		fail_stage = 'validate_failed';
		fail_msg = (val && val.error) || 'فشل التحقق من صحة إعدادات الشبكة قبل التطبيق';
	} else {
		let rel = ops.reload_service();
		if (!rel || !rel.ok) {
			fail_stage = 'reload_failed';
			fail_msg = (rel && rel.error) || 'فشل إعادة تحميل خدمة الشبكة';
		} else {
			let ver = ops.verify_applied();
			if (!ver || !ver.ok) {
				fail_stage = 'verify_failed';
				fail_msg = (ver && ver.error) || 'فشل التحقق من تطبيق إعدادات الشبكة';
			}
		}
	}

	if (fail_stage == '') {
		return { ok: true, rolled_back: false, rollback_failed: false, error: '', message_ar: 'تم تطبيق إعدادات الشبكة والتحقق منها بنجاح' };
	}

	// 4. Rollback every snapped file & verify bytes + metadata
	let rb_all_ok = true;
	let cleanup_failed = false;
	let tmp_path = '';
	for (let s in snaps) {
		if (s.existed) {
			let aw = nms_archive.atomic_write_checked(s.path, s.raw, s.mode, s.uid, s.gid, ops.aw_ops);
			if (aw.cleanup_failed) { cleanup_failed = true; tmp_path = aw.tmp_path || ''; }
			let st_rb = ops.lstat(s.path);
			let cur_rb = ops.readfile(s.path);
			if (!aw.ok || !st_rb || st_rb.type != 'file' || (st_rb.mode & 0o7777) != s.mode ||
			    (s.uid != null && (st_rb.uid != s.uid || st_rb.gid != s.gid)) || cur_rb != s.raw) {
				rb_all_ok = false;
			}
		} else if (ops.stat(s.path)) {
			if (!ops.unlink(s.path) || ops.stat(s.path)) rb_all_ok = false;
		}
	}
	if (rb_all_ok) {
		let rb_rel = ops.reload_service();
		if (!rb_rel || !rb_rel.ok) rb_all_ok = false;
	}
	if (!rb_all_ok) {
		let fr = ops.on_rollback_failed(fail_stage + ' rollback failed');
		return {
			ok: false,
			rolled_back: false,
			rollback_failed: true,
			freeze_persisted: fr ? !!fr.freeze_persisted : false,
			freeze_persist_failed: fr ? !!fr.freeze_persist_failed : false,
			cleanup_failed: cleanup_failed,
			tmp_path: tmp_path,
			error: fail_stage,
			message_ar: 'فشل حرج: ' + fail_msg + ' وفشل التراجع — تم تفعيل التجميد الطارئ'
		};
	}
	return { ok: false, rolled_back: true, rollback_failed: false, error: fail_stage, message_ar: fail_msg + ' وتم التراجع التلقائي والتحقق منه بنجاح' };
};
