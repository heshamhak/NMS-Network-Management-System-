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

export function parse_iw_phy_capabilities(iw_phy_out, iw_reg_out) {
	let bands = {};
	let cur_band = null;
	let in_freqs = false;
	for (let raw_ln in split(iw_phy_out || '', '\n')) {
		let ln = trim(raw_ln);
		if (match(ln, /^Band 1:/)) { cur_band = '2g'; bands['2g'] = { channels: {}, htmodes: { 'HT20': true, 'HT40': true } }; in_freqs = false; continue; }
		if (match(ln, /^Band 2:/)) { cur_band = '5g'; bands['5g'] = { channels: {}, htmodes: { 'HT20': true, 'HT40': true } }; in_freqs = false; continue; }
		if (match(ln, /^Band 4:/)) { cur_band = '6g'; bands['6g'] = { channels: {}, htmodes: { 'HE20': true, 'HE40': true } }; in_freqs = false; continue; }
		if (!cur_band) continue;
		if (index(ln, 'Frequencies:') == 0) { in_freqs = true; continue; }
		if (index(ln, 'Bitrates') == 0 || index(ln, 'VHT Capabilities') == 0 || index(ln, 'HE Iftypes') == 0 || index(ln, 'EHT Iftypes') == 0) in_freqs = false;
		if (index(ln, 'VHT Capabilities') >= 0) {
			bands[cur_band].htmodes['VHT20'] = true;
			bands[cur_band].htmodes['VHT40'] = true;
			bands[cur_band].htmodes['VHT80'] = true;
		}
		if (index(ln, 'Supported Channel Width: 160 MHz') >= 0 || index(ln, 'VHT160') >= 0) {
			bands[cur_band].htmodes['VHT160'] = true;
			bands[cur_band].htmodes['HE160'] = true;
		}
		if (index(ln, 'HE Iftypes') >= 0 || index(ln, 'HE MAC Capabilities') >= 0) {
			bands[cur_band].htmodes['HE20'] = true;
			bands[cur_band].htmodes['HE40'] = true;
			bands[cur_band].htmodes['HE80'] = true;
		}
		if (index(ln, 'EHT Iftypes') >= 0 || index(ln, 'EHT320') >= 0) {
			bands[cur_band].htmodes['EHT20'] = true;
			bands[cur_band].htmodes['EHT40'] = true;
			bands[cur_band].htmodes['EHT80'] = true;
			bands[cur_band].htmodes['EHT160'] = true;
			if (index(ln, '320 MHz') >= 0 || index(ln, 'EHT320') >= 0) bands[cur_band].htmodes['EHT320'] = true;
		}
		if (in_freqs) {
			let mf = match(ln, /^\*\s+([0-9.]+)\s+MHz\s+\[([0-9]+)\](\s+\(([0-9.]+)\s+dBm\))?(.*)$/);
			if (mf) {
				let freq = int(+mf[1]);
				let ch = '' + int(+mf[2]);
				let max_dbm = mf[4] != null && mf[4] != '' ? int(+mf[4]) : 20;
				let flags = lc(mf[5] || '');
				bands[cur_band].channels[ch] = {
					freq: freq,
					max_dbm: max_dbm,
					radar: index(flags, 'radar detection') >= 0,
					disabled: index(flags, 'disabled') >= 0,
					no_ir: index(flags, 'no ir') >= 0
				};
			}
		}
	}
	let reg = { country: '', dfs_region: '', rules: [] };
	for (let raw_ln in split(iw_reg_out || '', '\n')) {
		let ln = trim(raw_ln);
		let mc = match(ln, /^country\s+([A-Z0-9]{2}):(\s+DFS-([A-Z]+))?/);
		if (mc) { reg.country = mc[1]; reg.dfs_region = mc[3] || ''; continue; }
		let mr = match(ln, /^\(([0-9]+)\s*-\s*([0-9]+)\s*@\s*([0-9]+)\),\s*\([^,]*,\s*([0-9]+)\),(.*)$/);
		if (mr) {
			push(reg.rules, {
				start_mhz: int(+mr[1]),
				end_mhz: int(+mr[2]),
				max_bw: int(+mr[3]),
				max_dbm: int(+mr[4]),
				dfs: index(uc(mr[5] || ''), 'DFS') >= 0
			});
		}
	}
	return { bands: bands, reg: reg };
};

export function validate_wifi_radio_against_caps(cfg, parsed_caps) {
	let base = validate_wifi_radio_cfg(cfg);
	if (!base.ok) return base;
	if (!parsed_caps || type(parsed_caps.bands) != 'object' || length(keys(parsed_caps.bands)) == 0) {
		return { ok: false, error: 'تعذر اكتشاف قدرات الراديو الفعلية (iw phy) — تم الرفض الآمن' };
	}
	let band_info = parsed_caps.bands[base.band];
	if (!band_info) {
		return { ok: false, error: 'الراديو الفعلي لا يدعم نطاق التردد: ' + base.band };
	}
	if (!band_info.htmodes[base.htmode]) {
		return { ok: false, error: 'الراديو الفعلي لا يدعم عرض النطاق: ' + base.htmode };
	}
	let reg = parsed_caps.reg || { country: '', dfs_region: '', rules: [] };
	if (reg.country != '' && reg.country != '00' && base.country != reg.country && cfg.require_reg_match) {
		return { ok: false, error: 'رمز الدولة المطلوب لا يطابق النطاق التنظيمي النشط: ' + reg.country };
	}
	let ch_info = null;
	if (base.channel != 'auto') {
		ch_info = band_info.channels[base.channel];
		if (!ch_info || ch_info.disabled) {
			return { ok: false, error: 'القناة ' + base.channel + ' غير مدعومة أو معطلة تنظيمياً على هذا الراديو' };
		}
		if (ch_info.radar && cfg.dfs === false) {
			return { ok: false, error: 'القناة ' + base.channel + ' تتطلب تفعيل DFS (radar detection) إلزامياً' };
		}
		if (cfg.dfs && !ch_info.radar) {
			return { ok: false, error: 'القناة ' + base.channel + ' ليست قناة DFS ولا تدعم كشف الرادار' };
		}
	} else if (cfg.dfs) {
		let has_radar = false;
		for (let k in keys(band_info.channels)) {
			if (band_info.channels[k].radar && !band_info.channels[k].disabled) { has_radar = true; break; }
		}
		if (!has_radar) return { ok: false, error: 'لا توجد قنوات DFS صالحة على نطاق ' + base.band };
	}
	if (cfg.txpower != null && cfg.txpower != '') {
		let txp = +cfg.txpower;
		if (ch_info && txp > ch_info.max_dbm) {
			return { ok: false, error: sprintf('قدرة الإرسال %d dBm تتجاوز حد العتاد للقناة (%d dBm)', txp, ch_info.max_dbm) };
		}
		if (ch_info && length(reg.rules) > 0) {
			for (let rl in reg.rules) {
				if (ch_info.freq >= rl.start_mhz && ch_info.freq <= rl.end_mhz && txp > rl.max_dbm) {
					return { ok: false, error: sprintf('قدرة الإرسال %d dBm تتجاوز الحد التنظيمي (%d dBm)', txp, rl.max_dbm) };
				}
			}
		}
	}
	return { ok: true, radio: base.radio, band: base.band, channel: base.channel, htmode: base.htmode, country: base.country };
};
