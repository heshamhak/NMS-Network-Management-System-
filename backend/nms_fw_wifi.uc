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
