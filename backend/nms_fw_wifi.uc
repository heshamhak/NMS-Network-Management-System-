// Shared production ucode module for Phase 3C: Firewall Zones, Forwardings & Advanced Wireless validation.
// Imported by /usr/libexec/noc-helperd and directly executable by ucode test harnesses.

import * as nms_network from '/usr/libexec/nms_network.uc';

export function is_valid_zone_name(s) {
	return type(s) == 'string' && match(s, /^[a-zA-Z][a-zA-Z0-9_]{0,14}$/) != null;
};

export function validate_fw_zone_cfg(cfg) {
	if (type(cfg) != 'object') return { ok: false, error: 'بيانات منطقة الجدار الناري غير صالحة' };
	let name = trim('' + (cfg.name || ''));
	if (!is_valid_zone_name(name)) return { ok: false, error: 'اسم المنطقة غير صالح' };

	let allow_pol = { 'ACCEPT': true, 'REJECT': true, 'DROP': true };
	let inp = uc(trim('' + (cfg.input || 'REJECT')));
	let outp = uc(trim('' + (cfg.output || 'ACCEPT')));
	let fwd = uc(trim('' + (cfg.forward || 'REJECT')));
	if (!allow_pol[inp] || !allow_pol[outp] || !allow_pol[fwd]) {
		return { ok: false, error: 'سياسة المنطقة يجب أن تكون ACCEPT أو REJECT أو DROP' };
	}
	if (name == 'lan' && inp != 'ACCEPT') {
		return { ok: false, error: 'مرفوض: لا يُسمح بحجب حركة الدخول (input) على منطقة lan لتجنب فقدان الوصول الإداري' };
	}
	if (cfg.network != null) {
		if (type(cfg.network) != 'array' || length(cfg.network) > 16) {
			return { ok: false, error: 'قائمة شبكات المنطقة غير صالحة' };
		}
		for (let n in cfg.network) {
			if (!nms_network.is_valid_ifname(trim('' + n))) {
				return { ok: false, error: 'اسم شبكة غير صالح داخل المنطقة: ' + n };
			}
		}
	}
	return { ok: true, name: name, input: inp, output: outp, forward: fwd };
};

export function validate_fw_forwarding_cfg(cfg) {
	if (type(cfg) != 'object') return { ok: false, error: 'بيانات التوجيه بين المناطق غير صالحة' };
	let src = trim('' + (cfg.src || ''));
	let dest = trim('' + (cfg.dest || ''));
	if (!is_valid_zone_name(src) || !is_valid_zone_name(dest)) {
		return { ok: false, error: 'اسم منطقة المصدر أو الوجهة غير صالح' };
	}
	if (src == dest) return { ok: false, error: 'لا يمكن إنشاء توجيه من المنطقة إلى نفسها' };
	return { ok: true, src: src, dest: dest };
};

export function validate_wifi_radio_cfg(cfg) {
	if (type(cfg) != 'object') return { ok: false, error: 'بيانات جهاز الراديو غير صالحة' };
	let radio = trim('' + (cfg.radio || 'radio0'));
	if (!match(radio, /^radio[0-9]{1,2}$/)) return { ok: false, error: 'معرف جهاز الراديو غير صالح' };

	let band = lc(trim('' + (cfg.band || '5g')));
	if (band != '2g' && band != '5g' && band != '6g') return { ok: false, error: 'نطاق التردد غير مدعوم (2g/5g/6g)' };

	let ch = trim('' + (cfg.channel || 'auto'));
	if (ch != 'auto') {
		if (!match(ch, /^[0-9]{1,3}$/)) return { ok: false, error: 'رقم القناة غير صالح' };
		let chn = +ch;
		if (band == '2g' && (chn < 1 || chn > 14)) return { ok: false, error: 'قناة 2.4GHz يجب أن تكون بين 1 و 14' };
		if (band == '5g' && (chn < 36 || chn > 177)) return { ok: false, error: 'قناة 5GHz يجب أن تكون بين 36 و 177' };
		if (band == '6g' && (chn < 1 || chn > 233)) return { ok: false, error: 'قناة 6GHz يجب أن تكون بين 1 و 233' };
	}

	let htmode = uc(trim('' + (cfg.htmode || 'HE80')));
	let allow_ht = {
		'HT20': true, 'HT40': true, 'VHT20': true, 'VHT40': true, 'VHT80': true, 'VHT160': true,
		'HE20': true, 'HE40': true, 'HE80': true, 'HE160': true, 'EHT20': true, 'EHT40': true, 'EHT80': true, 'EHT160': true, 'EHT320': true
	};
	if (!allow_ht[htmode]) return { ok: false, error: 'عرض النطاق (htmode) غير مدعوم: ' + htmode };

	let country = uc(trim('' + (cfg.country || 'IQ')));
	if (!match(country, /^[A-Z]{2}$/)) return { ok: false, error: 'رمز الدولة (Country Code) يجب أن يكون حرفين مثل IQ أو US' };

	if (cfg.txpower != null && cfg.txpower != '') {
		let txp = +cfg.txpower;
		if (('' + int(txp)) != trim('' + cfg.txpower) || txp < 0 || txp > 30) {
			return { ok: false, error: 'قدرة الإرسال TX Power يجب أن تكون بين 0 و 30 dBm' };
		}
	}
	if (cfg.dfs && band == '2g') {
		return { ok: false, error: 'خيار DFS غير مدعوم على نطاق 2.4GHz' };
	}
	return { ok: true, radio: radio, band: band, channel: ch, htmode: htmode, country: country };
};

export function validate_wifi_iface_cfg(cfg) {
	if (type(cfg) != 'object') return { ok: false, error: 'بيانات الشبكة اللاسلكية غير صالحة' };
	if (cfg.id != null && trim('' + cfg.id) != '') {
		if (!match(trim('' + cfg.id), /^[a-zA-Z0-9_-]{1,32}$/)) return { ok: false, error: 'معرف الشبكة اللاسلكية غير صالح' };
	}
	let device = trim('' + (cfg.device || 'radio0'));
	if (!match(device, /^radio[0-9]{1,2}$/)) return { ok: false, error: 'جهاز الراديو المرتبط غير صالح' };

	let mode = lc(trim('' + (cfg.mode || 'ap')));
	if (mode != 'ap' && mode != 'sta' && mode != 'mesh') return { ok: false, error: 'وضع الشبكة اللاسلكية غير مدعوم' };

	let net = trim('' + (cfg.network || 'lan'));
	if (!nms_network.is_valid_ifname(net)) return { ok: false, error: 'واجهة الشبكة المرتبطة غير صالحة' };

	let ssid = '' + (cfg.ssid || '');
	if (length(ssid) < 1 || length(ssid) > 32 || index(ssid, '\0') >= 0 || match(ssid, /[\r\n]/)) {
		return { ok: false, error: 'اسم الشبكة (SSID) يجب أن يكون 1..32 محرفاً بدون أحرف تحكم' };
	}

	let enc = lc(trim('' + (cfg.encryption || 'sae-mixed')));
	let allow_enc = { 'none': true, 'psk': true, 'psk2': true, 'psk-mixed': true, 'sae': true, 'sae-mixed': true };
	if (!allow_enc[enc]) return { ok: false, error: 'نوع التشفير اللاسلكي غير مدعوم: ' + enc };

	let key = '' + (cfg.key || '');
	if (enc != 'none' && key != '') {
		if (length(key) < 8 || length(key) > 63 || index(key, '\0') >= 0 || match(key, /[\r\n]/)) {
			return { ok: false, error: 'مفتاح الأمان اللاسلكي يجب أن يكون 8..63 محرفاً' };
		}
	} else if (enc != 'none' && !cfg.id && key == '') {
		return { ok: false, error: 'مفتاح الأمان مطلوب للشبكة المشفرة الجديدة' };
	}

	if (cfg.ieee80211w != null && cfg.ieee80211w != '') {
		let pmf = '' + cfg.ieee80211w;
		if (pmf != '0' && pmf != '1' && pmf != '2') return { ok: false, error: 'قيمة PMF (802.11w) يجب أن تكون 0 أو 1 أو 2' };
	}
	return { ok: true, device: device, mode: mode, network: net, ssid: ssid, encryption: enc };
};

function htmode_to_bw(htmode) {
	if (match(htmode, /320$/)) return 320;
	if (match(htmode, /160$/)) return 160;
	if (match(htmode, /80$/)) return 80;
	if (match(htmode, /40$/)) return 40;
	return 20;
}

function classify_band_from_freq(freq) {
	if (freq >= 2400 && freq <= 2500) return '2g';
	if (freq >= 4900 && freq <= 5900) return '5g';
	if (freq >= 5925 && freq <= 7125) return '6g';
	return null;
}

export function resolve_wifi_phy_from_sysfs(radio_cfg, sysfs_entries) {
	if (type(sysfs_entries) != 'array' || length(sysfs_entries) == 0) {
		return { ok: false, error: 'تعذر قراءة أجهزة ieee80211 الفعلية من sysfs — تم الرفض الآمن' };
	}
	let req_phy = trim('' + (radio_cfg && radio_cfg.phy || ''));
	let req_path = trim('' + (radio_cfg && radio_cfg.path || ''));
	if (req_phy == '' && req_path == '') {
		return { ok: false, error: 'إعدادات الراديو تفتقر إلى option path أو option phy لتحديد العتاد الفعلي' };
	}
	let matches = [];
	for (let ent in sysfs_entries) {
		if (!ent || !ent.phy) continue;
		if (req_phy != '' && ent.phy == req_phy) {
			push(matches, ent.phy);
			continue;
		}
		if (req_path != '' && ent.device_path) {
			let dp = '' + ent.device_path;
			if (dp == req_path || substr(dp, length(dp) - length(req_path) - 1) == '/' + req_path) {
				push(matches, ent.phy);
			}
		}
	}
	if (length(matches) != 1) {
		return { ok: false, error: length(matches) == 0 ? 'لم يتم العثور على جهاز PHY مطابق لمسار الراديو في النظام' : 'تطابق غامض لأكثر من جهاز PHY لنفس المسار' };
	}
	return { ok: true, phy: matches[0] };
};

export function parse_iw_phy_capabilities(iw_phy_out, iw_reg_out) {
	let wiphy = '';
	let raw_bands = [];
	let cur = null;
	let in_freqs = false;
	for (let raw_ln in split(iw_phy_out || '', '\n')) {
		let ln = trim(raw_ln);
		let mw = match(ln, /^Wiphy\s+([a-zA-Z0-9_-]+)$/);
		if (mw) { wiphy = mw[1]; continue; }
		if (match(ln, /^Band\s+[0-9]+:/)) {
			cur = { channels: {}, htmodes: { 'HT20': true }, band_votes: {} };
			push(raw_bands, cur);
			in_freqs = false;
			continue;
		}
		if (!cur) continue;
		if (index(ln, 'Frequencies:') == 0) { in_freqs = true; continue; }
		if (index(ln, 'Bitrates') == 0 || index(ln, 'VHT Capabilities') == 0 || index(ln, 'HE Iftypes') == 0 || index(ln, 'EHT Iftypes') == 0) in_freqs = false;
		if (index(ln, 'HT20/HT40') >= 0) cur.htmodes['HT40'] = true;
		if (index(ln, 'VHT Capabilities') >= 0) {
			cur.htmodes['VHT20'] = true;
			cur.htmodes['VHT40'] = true;
			cur.htmodes['VHT80'] = true;
		}
		if (index(ln, 'Supported Channel Width: 160 MHz') >= 0 || index(ln, 'VHT160') >= 0) {
			cur.htmodes['VHT160'] = true;
			cur.htmodes['HE160'] = true;
		}
		if (index(ln, 'HE Iftypes') >= 0 || index(ln, 'HE MAC Capabilities') >= 0) {
			cur.htmodes['HE20'] = true;
			cur.htmodes['HE40'] = true;
			cur.htmodes['HE80'] = true;
		}
		if (index(ln, 'EHT Iftypes') >= 0 || index(ln, 'EHT320') >= 0) {
			cur.htmodes['EHT20'] = true;
			cur.htmodes['EHT40'] = true;
			cur.htmodes['EHT80'] = true;
			cur.htmodes['EHT160'] = true;
			if (index(ln, '320 MHz') >= 0 || index(ln, 'EHT320') >= 0) cur.htmodes['EHT320'] = true;
		}
		if (in_freqs) {
			let mf = match(ln, /^\*\s+([0-9.]+)\s+MHz\s+\[([0-9]+)\](\s+\(([0-9.]+)\s+dBm\))?(.*)$/);
			if (mf) {
				let freq = +mf[1];
				let ch = '' + int(+mf[2]);
				let bname = classify_band_from_freq(freq);
				if (!bname) continue;
				cur.band_votes[bname] = (cur.band_votes[bname] || 0) + 1;
				let max_dbm = mf[4] != null && mf[4] != '' ? int(+mf[4]) : 20;
				let flags = lc(mf[5] || '');
				cur.channels[ch] = {
					freq: freq,
					max_dbm: max_dbm,
					radar: index(flags, 'radar detection') >= 0,
					disabled: index(flags, 'disabled') >= 0,
					no_ir: index(flags, 'no ir') >= 0
				};
			}
		}
	}
	let bands = {};
	for (let rb in raw_bands) {
		let vkeys = keys(rb.band_votes);
		if (length(vkeys) != 1 || length(keys(rb.channels)) == 0) continue;
		let bname = vkeys[0];
		bands[bname] = { channels: rb.channels, htmodes: rb.htmodes };
	}
	let reg = { country: '', dfs_region: '', rules: [] };
	for (let raw_ln in split(iw_reg_out || '', '\n')) {
		let ln = trim(raw_ln);
		let mc = match(ln, /^country\s+([A-Z0-9]{2}):(\s+DFS-([A-Z]+))?/);
		if (mc) { reg.country = mc[1]; reg.dfs_region = mc[3] || ''; reg.rules = []; continue; }
		let mr = match(ln, /^\(([0-9.]+)\s*-\s*([0-9.]+)\s*@\s*([0-9.]+)\),\s*\([^,]*,\s*([0-9.]+|N\/A)\),(.*)$/);
		if (mr) {
			push(reg.rules, {
				start_mhz: +mr[1],
				end_mhz: +mr[2],
				max_bw: int(+mr[3]),
				max_dbm: mr[4] == 'N/A' ? null : int(+mr[4]),
				dfs: index(uc(mr[5] || ''), 'DFS') >= 0
			});
		}
	}
	return { wiphy: wiphy, bands: bands, reg: reg };
};

export function parse_iw_dev_info(iw_dev_out) {
	let res = { ifname: '', type: '', ssid: '', channel: '', freq: 0, width: 0, wiphy: null };
	for (let raw_ln in split(iw_dev_out || '', '\n')) {
		let ln = trim(raw_ln);
		let mi = match(ln, /^Interface\s+(.+)$/);
		if (mi) { res.ifname = trim(mi[1]); continue; }
		let mt = match(ln, /^type\s+([a-zA-Z0-9_-]+)$/);
		if (mt) { res.type = lc(mt[1]); continue; }
		let ms = match(ln, /^ssid\s+(.+)$/);
		if (ms) { res.ssid = ms[1]; continue; }
		let mw = match(ln, /^wiphy\s+([0-9]+)$/);
		if (mw) { res.wiphy = 'phy' + mw[1]; continue; }
		let mc = match(ln, /^channel\s+([0-9]+)\s+\(([0-9.]+)\s+MHz\),\s*width:\s*([0-9]+)\s*MHz/);
		if (mc) {
			res.channel = mc[1];
			res.freq = +mc[2];
			res.width = int(+mc[3]);
			continue;
		}
	}
	return res;
};

export function parse_iw_phy_channels_dfs(iw_ch_out) {
	let ch_dfs = {};
	let cur_ch = null;
	for (let raw_ln in split(iw_ch_out || '', '\n')) {
		let ln = trim(raw_ln);
		let mf = match(ln, /^\*\s+([0-9.]+)\s+MHz\s+\[([0-9]+)\]/);
		if (mf) {
			cur_ch = '' + int(+mf[2]);
			ch_dfs[cur_ch] = {
				freq: +mf[1],
				radar: index(lc(ln), 'radar detection') >= 0,
				disabled: index(lc(ln), 'disabled') >= 0,
				dfs_state: ''
			};
			continue;
		}
		if (cur_ch) {
			let md = match(ln, /^DFS state:\s*(usable|available|unavailable)/i);
			if (md) ch_dfs[cur_ch].dfs_state = lc(md[1]);
		}
	}
	return ch_dfs;
};

export function evaluate_dfs_runtime_state(hst, ch_entry, active_channel, active_freq, expected_phy) {
	if (!ch_entry || ch_entry.disabled) {
		return { ok: false, state: 'unverified', error: 'تعذر قراءة حالة قناة DFS من iw phy channels أو القناة معطلة' };
	}
	if (ch_entry.dfs_state == 'unavailable') {
		return { ok: false, state: 'radar_unavailable', error: 'تم اكتشاف رادار أو القناة في حالة حظر (DFS state: unavailable)' };
	}
	if (!ch_entry.radar) {
		return { ok: false, state: 'non_dfs', error: 'القناة النشطة لا تدعم كشف الرادار (non-DFS)' };
	}
	if (!hst || type(hst) != 'object') {
		return { ok: false, state: 'unverified', error: 'تعذر قراءة حالة hostapd عبر ubus — التحقق من DFS غير مدعوم أو فاشل' };
	}
	if (!hst.phy || type(hst.phy) != 'string' || hst.phy == '') {
		return { ok: false, state: 'unverified', error: 'حالة hostapd تفتقر إلى معرف PHY الفعلي (hst.phy)' };
	}
	if (expected_phy && hst.phy != expected_phy) {
		return { ok: false, state: 'stale_mismatch', error: sprintf('عدم تطابق PHY في hostapd (%s) مع (%s)', hst.phy, expected_phy) };
	}
	if (hst.freq == null || (type(hst.freq) != 'int' && type(hst.freq) != 'double') || +hst.freq <= 0) {
		return { ok: false, state: 'unverified', error: 'حالة hostapd تفتقر إلى التردد الفعلي (hst.freq)' };
	}
	let exp_freq = (active_freq && +active_freq > 0) ? +active_freq : +ch_entry.freq;
	if (+hst.freq != exp_freq) {
		return { ok: false, state: 'stale_mismatch', error: sprintf('عدم تطابق تردد hostapd (%d) مع القناة الفعلية (%d)', +hst.freq, exp_freq) };
	}
	if (hst.channel == null || ('' + hst.channel) == '' || (active_channel != '' && ('' + hst.channel) != ('' + active_channel))) {
		return { ok: false, state: 'stale_mismatch', error: 'حالة hostapd تفتقر إلى القناة أو لا تطابق القناة الفعلية للراديو' };
	}
	let d = hst.dfs;
	if (!d || type(d) != 'object') {
		return { ok: false, state: 'unverified', error: 'حالة hostapd تفتقر إلى كائن dfs المتداخل (OpenWrt 25.12.6 schema)' };
	}
	if (type(d.cac_active) != 'bool' || type(d.cac_seconds) != 'int' || type(d.cac_seconds_left) != 'int') {
		return { ok: false, state: 'unverified', error: 'أنواع حقول dfs في hostapd غير صالحة أو غير مكتملة' };
	}
	if (d.cac_seconds <= 0 || d.cac_seconds_left < 0) {
		return { ok: false, state: 'unverified', error: 'قيم مؤقتات DFS في hostapd غير صالحة' };
	}
	if (hst.status == 'DFS' || d.cac_active === true || d.cac_seconds_left > 0 || ch_entry.dfs_state == 'usable') {
		return { ok: false, state: 'cac_in_progress', error: 'فحص الرادار (DFS CAC) ما زال جارياً أو لم يكتمل بعد' };
	}
	if (hst.status != 'ENABLED' || ch_entry.dfs_state != 'available' || d.cac_active !== false || d.cac_seconds_left !== 0) {
		return { ok: false, state: 'unverified', error: 'بيانات اكتمال DFS/CAC غير مكتملة أو متناقضة — تم الرفض الآمن' };
	}
	return { ok: true, state: 'cac_completed' };
};

export function validate_wifi_radio_against_caps(cfg, parsed_caps) {
	let base = validate_wifi_radio_cfg(cfg);
	if (!base.ok) return base;
	if (!parsed_caps || type(parsed_caps.bands) != 'object' || length(keys(parsed_caps.bands)) == 0 || !parsed_caps.wiphy) {
		return { ok: false, error: 'تعذر اكتشاف قدرات وهوية الراديو الفعلية (iw phy) — تم الرفض الآمن' };
	}
	if (cfg._expected_phy && parsed_caps.wiphy != cfg._expected_phy) {
		return { ok: false, error: 'عدم تطابق هوية جهاز PHY الفعلي مع الجهاز المطلوب: ' + parsed_caps.wiphy };
	}
	let reg = parsed_caps.reg || { country: '', dfs_region: '', rules: [] };
	if (!reg.country || reg.country == '00' || !match(reg.country, /^[A-Z]{2}$/) || type(reg.rules) != 'array' || length(reg.rules) == 0) {
		return { ok: false, error: 'النطاق التنظيمي الفعلي (iw reg get) غير مهيأ أو غير مكتمل — تم الرفض الآمن' };
	}
	if (uc(base.country) != uc(reg.country)) {
		return { ok: false, error: 'رمز الدولة المطلوب (' + base.country + ') لا يطابق النطاق التنظيمي النشط (' + reg.country + ')' };
	}
	let band_info = parsed_caps.bands[base.band];
	if (!band_info) {
		return { ok: false, error: 'الراديو الفعلي لا يدعم نطاق التردد: ' + base.band };
	}
	if (!band_info.htmodes[base.htmode]) {
		return { ok: false, error: 'الراديو الفعلي لا يدعم عرض النطاق: ' + base.htmode };
	}
	let req_bw = htmode_to_bw(base.htmode);
	let ch_info = null;
	if (base.channel != 'auto') {
		ch_info = band_info.channels[base.channel];
		if (!ch_info || ch_info.disabled) {
			return { ok: false, error: 'القناة ' + base.channel + ' غير مدعومة أو معطلة تنظيمياً على هذا الراديو' };
		}
		let matched_rule = null;
		for (let rl in reg.rules) {
			if (ch_info.freq >= rl.start_mhz && ch_info.freq <= rl.end_mhz) { matched_rule = rl; break; }
		}
		if (!matched_rule) {
			return { ok: false, error: 'القناة ' + base.channel + ' غير مغطاة بقاعدة تنظيمية صالحة في ' + reg.country };
		}
		if (req_bw > matched_rule.max_bw) {
			return { ok: false, error: sprintf('عرض النطاق %d MHz يتجاوز الحد التنظيمي (%d MHz)', req_bw, matched_rule.max_bw) };
		}
		let needs_dfs = ch_info.radar || matched_rule.dfs;
		if (needs_dfs && cfg.dfs === false) {
			return { ok: false, error: 'القناة ' + base.channel + ' تتطلب تفعيل DFS (radar detection) إلزامياً' };
		}
		if (cfg.dfs && !needs_dfs) {
			return { ok: false, error: 'القناة ' + base.channel + ' ليست قناة DFS ولا تدعم كشف الرادار' };
		}
		if (cfg.txpower != null && cfg.txpower != '') {
			let txp = +cfg.txpower;
			if (txp > ch_info.max_dbm) {
				return { ok: false, error: sprintf('قدرة الإرسال %d dBm تتجاوز حد العتاد للقناة (%d dBm)', txp, ch_info.max_dbm) };
			}
			if (matched_rule.max_dbm != null && txp > matched_rule.max_dbm) {
				return { ok: false, error: sprintf('قدرة الإرسال %d dBm تتجاوز الحد التنظيمي (%d dBm)', txp, matched_rule.max_dbm) };
			}
		}
	} else {
		let valid_auto = false;
		for (let k in keys(band_info.channels)) {
			let c = band_info.channels[k];
			if (c.disabled) continue;
			for (let rl in reg.rules) {
				if (c.freq >= rl.start_mhz && c.freq <= rl.end_mhz && req_bw <= rl.max_bw) {
					if (!cfg.dfs || c.radar || rl.dfs) { valid_auto = true; break; }
				}
			}
			if (valid_auto) break;
		}
		if (!valid_auto) return { ok: false, error: 'لا توجد قنوات صالحة متوافقة مع القيود التنظيمية وعرض النطاق على ' + base.band };
	}
	return { ok: true, radio: base.radio, band: base.band, channel: base.channel, htmode: base.htmode, country: base.country };
};
