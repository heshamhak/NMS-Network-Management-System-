// Executed directly by OpenWrt 25.12.6 x86_64 ucode runtime against production backend/nms_fw_wifi.uc AND extracted noc-helperd handle_phase3c_verb
import * as fs from 'fs';
import * as uci from 'uci';
import * as nms_fw_wifi from '/tmp/p3a_test/nms_fw_wifi.uc';
import * as helperd_prod from '/tmp/p3a_test/helperd_aw_prod.uc';

let vec_dir = ARGV[0];
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

// 1. Validation unit checks
check(nms_fw_wifi.validate_fw_zone_cfg({ name: 'guest', input: 'REJECT', output: 'ACCEPT', forward: 'REJECT', network: ['guest'], masq: false }).ok, 'P3C-VAL[fw_zone_valid]');
check(!nms_fw_wifi.validate_fw_zone_cfg({ name: 'lan', input: 'DROP', output: 'ACCEPT', forward: 'ACCEPT' }).ok, 'P3C-VAL[fw_zone_reject_lan_lockout]');
check(nms_fw_wifi.validate_fw_forwarding_cfg({ src: 'guest', dest: 'wan' }).ok, 'P3C-VAL[fw_forwarding_valid]');
check(!nms_fw_wifi.validate_fw_forwarding_cfg({ src: 'lan', dest: 'lan' }).ok, 'P3C-VAL[fw_forwarding_reject_same]');
check(nms_fw_wifi.validate_wifi_radio_cfg({ radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true }).ok, 'P3C-VAL[wifi_radio_5g_dfs_valid]');
check(!nms_fw_wifi.validate_wifi_radio_cfg({ radio: 'radio0', band: '2g', channel: '6', htmode: 'HT40', country: 'IQ', dfs: true }).ok, 'P3C-VAL[wifi_radio_reject_2g_dfs]');
check(!nms_fw_wifi.validate_wifi_radio_cfg({ radio: 'radio0', band: '5g', channel: '36', htmode: 'HE80', country: 'IQ', txpower: 40 }).ok, 'P3C-VAL[wifi_radio_reject_txpower_40]');
check(nms_fw_wifi.validate_wifi_iface_cfg({ device: 'radio1', mode: 'ap', network: 'guest', ssid: 'Guest-WPA3', encryption: 'sae', key: 'StrongPass123!', ieee80211w: '2', ieee80211r: true, isolate: true }).ok, 'P3C-VAL[wifi_iface_wpa3_valid]');
check(!nms_fw_wifi.validate_wifi_iface_cfg({ device: 'radio0', mode: 'ap', network: 'lan', ssid: 'Bad', encryption: 'sae', key: 'short' }).ok, 'P3C-VAL[wifi_iface_reject_short_key]');

// 2. Production integration tests with real OpenWrt uci.cursor(uci_dir)
let uci_dir = vec_dir + '/uci_p3c';
fs.mkdir(uci_dir);
let base_fw = "config defaults\n\toption input 'REJECT'\n\toption output 'ACCEPT'\n\toption forward 'REJECT'\n\nconfig zone 'zn_lan'\n\toption name 'lan'\n\toption input 'ACCEPT'\n\toption output 'ACCEPT'\n\toption forward 'ACCEPT'\n\nconfig zone 'zn_wan'\n\toption name 'wan'\n\toption input 'REJECT'\n\toption output 'ACCEPT'\n\toption forward 'REJECT'\n\toption masq '1'\n\nconfig rule 'existing_rule'\n\toption name 'KeepMe'\n\toption src 'wan'\n\toption target 'ACCEPT'\n";
let base_wifi = "config wifi-device 'radio0'\n\toption type 'mac80211'\n\toption path 'platform/soc/18000000.wmac'\n\toption band '2g'\n\toption channel '6'\n\toption htmode 'HT20'\n\toption country 'DE'\n\nconfig wifi-device 'radio1'\n\toption type 'mac80211'\n\toption path 'pci0000:00/0000:00:00.0/0000:01:00.0'\n\toption band '5g'\n\toption channel '36'\n\toption htmode 'HE80'\n\toption country 'DE'\n\nconfig wifi-iface 'default_radio0'\n\toption device 'radio0'\n\toption network 'lan'\n\toption mode 'ap'\n\toption ssid 'MainAP'\n\toption encryption 'psk2'\n\toption key 'MainSecret123'\n";
fs.writefile(uci_dir + '/firewall', base_fw);
fs.chmod(uci_dir + '/firewall', 0o644);
fs.writefile(uci_dir + '/wireless', base_wifi);
fs.chmod(uci_dir + '/wireless', 0o644);

let sysfs_sample = [
	{ phy: 'phy0', device_path: '/sys/devices/platform/soc/18000000.wmac' },
	{ phy: 'phy2', device_path: '/sys/devices/pci0000:00/0000:00:00.0/0000:01:00.0' }
];
let iw_phy0_sample = "Wiphy phy0\n\tBand 1:\n\t\tCapabilities: 0x11ef\n\t\t\tHT20/HT40\n\t\tFrequencies:\n\t\t\t* 2437.0 MHz [6] (20.0 dBm)\n\t\t\t* 2462.0 MHz [11] (20.0 dBm)\n";
let iw_phy2_sample = "Wiphy phy2\n\tBand 2:\n\t\tVHT Capabilities (0x338001b2):\n\t\tSupported Channel Width: 160 MHz\n\t\tHE Iftypes: AP\n\t\tFrequencies:\n\t\t\t* 5180.0 MHz [36] (20.0 dBm)\n\t\t\t* 5500.0 MHz [100] (20.0 dBm) (radar detection)\n\t\t\t* 5520.0 MHz [104] (disabled)\n";
let iw_phy2_channels_sample = "Band 2:\n\t* 5180.0 MHz [36] (20.0 dBm)\n\t* 5500.0 MHz [100] (20.0 dBm) (radar detection)\n\t  DFS state: available\n\t  DFS CAC time: 60000 ms\n";
let iw_reg_sample = "global\ncountry DE: DFS-ETSI\n\t(2400 - 2483.5 @ 40), (N/A, 20), (N/A)\n\t(5150 - 5250 @ 80), (N/A, 20), (N/A)\n\t(5470 - 5725 @ 160), (N/A, 20), (0 ms), DFS\n";

function run_p3c(verb, params, extra_env) {
	let rep = null;
	let env = {
		cfg_dir: uci_dir,
		uci_dir: uci_dir,
		sysfs_ieee80211: sysfs_sample,
		exec_iw_phy: function(phy) { return phy == 'phy0' ? iw_phy0_sample : (phy == 'phy2' ? iw_phy2_sample : ''); },
		exec_iw_reg: function() { return iw_reg_sample; },
		exec_iw_phy_channels: function(phy) { return phy == 'phy2' ? iw_phy2_channels_sample : ''; },
		exec_iw_dev: function(ifname) {
			if (ifname == 'phy2-ap0') {
				let ch = params.channel || '100';
				let fq = ch == '100' ? '5500' : (ch == '36' ? '5180' : '5500');
				return sprintf("Interface phy2-ap0\n\twiphy 2\n\ttype AP\n\tssid %s\n\tchannel %s (%s MHz), width: 80 MHz, center1: %s MHz\n", params.ssid || 'Corp5G', ch, fq, fq);
			}
			return sprintf("Interface phy0-ap0\n\twiphy 0\n\ttype AP\n\tssid %s\n\tchannel %s (2462 MHz), width: 40 MHz, center1: 2452 MHz\n", params.ssid || 'MainAP', params.channel || '11');
		},
		ubus_call: function(obj, method) {
			if (obj == 'network.wireless' && method == 'status') {
				return {
					radio0: { up: !params.disabled, interfaces: [{ section: 'default_radio0', ifname: 'phy0-ap0' }] },
					radio1: { up: !params.disabled, interfaces: [{ section: params.id || 'guest_5g', ifname: 'phy2-ap0' }] }
				};
			}
			if (index(obj, 'hostapd.') == 0 && method == 'get_status') {
				return { status: 'ENABLED', phy: 'phy2', freq: 5500, channel: 100, dfs: { cac_seconds: 60, cac_active: false, cac_seconds_left: 0 } };
			}
			return null;
		},
		validate_fn: function() { return { ok: true }; },
		reload_fn: function() { return { ok: true }; }
	};
	if (extra_env) for (let k in keys(extra_env)) env[k] = extra_env[k];
	helperd_prod.handle_phase3c_verb(verb, params, 'admin', function(r) { rep = r; }, env);
	return rep;
}

// 2a. Firewall Zone save + existing rule preserved + protected zone delete refused + zone delete
let r_zs = run_p3c('fw_zone_save', { name: 'guest', input: 'REJECT', output: 'ACCEPT', forward: 'REJECT', network: ['guest'], masq: false, mtu_fix: true });
let cv1 = uci.cursor(uci_dir);
check(
	r_zs.ok === true && cv1.get('firewall', 'zn_guest', 'name') == 'guest'
	&& cv1.get('firewall', 'zn_guest', 'mtu_fix') == '1'
	&& cv1.get('firewall', 'existing_rule', 'name') == 'KeepMe',
	'P3C-PROD[fw_zone_save_preserves_existing_rules]',
	sprintf('%J', r_zs)
);

let r_fwd = run_p3c('fw_forwarding_save', { src: 'guest', dest: 'wan', enabled: true });
let cv2 = uci.cursor(uci_dir);
check(r_fwd.ok === true && cv2.get('firewall', 'fwd_guest_wan', 'dest') == 'wan', 'P3C-PROD[fw_forwarding_save_verified]', sprintf('%J', r_fwd));

let r_zprot = run_p3c('fw_zone_delete', { name: 'lan' });
check(!r_zprot.ok && r_zprot.error_code == 'FORBIDDEN', 'P3C-PROD[fw_zone_delete_lan_refused]', sprintf('%J', r_zprot));

let r_fdel = run_p3c('fw_forwarding_delete', { id: 'fwd_guest_wan' });
let r_zdel = run_p3c('fw_zone_delete', { name: 'guest' });
let cv3 = uci.cursor(uci_dir);
check(r_fdel.ok === true && r_zdel.ok === true && cv3.get('firewall', 'zn_guest') == null, 'P3C-PROD[fw_zone_and_forwarding_delete_verified]', sprintf('f=%J z=%J', r_fdel, r_zdel));

// 2b. Multi-radio save (radio1 5GHz DFS, Country, TX Power) + Multi-SSID WPA3-SAE save & delete
let r_rad = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true, disabled: false });
let cv4 = uci.cursor(uci_dir);
check(
	r_rad.ok === true && cv4.get('wireless', 'radio1', 'country') == 'DE'
	&& cv4.get('wireless', 'radio1', 'txpower') == '20' && cv4.get('wireless', 'radio1', 'dfs') == '1',
	'P3C-PROD[wifi_radio_multi_dfs_country_txpower_verified]',
	sprintf('%J', r_rad)
);

let r_wif = run_p3c('wifi_iface_save', { id: 'guest_5g', device: 'radio1', mode: 'ap', network: 'guest', ssid: 'Guest-5G-WPA3', encryption: 'sae', key: 'GuestPass123!', ieee80211w: '2', ieee80211r: true, isolate: true, hidden: false, disabled: false });
let cv5 = uci.cursor(uci_dir);
check(
	r_wif.ok === true && cv5.get('wireless', 'guest_5g', 'encryption') == 'sae'
	&& cv5.get('wireless', 'guest_5g', 'ieee80211w') == '2' && cv5.get('wireless', 'guest_5g', 'isolate') == '1',
	'P3C-PROD[wifi_multi_ssid_wpa3_verified]',
	sprintf('%J', r_wif)
);

let r_wif_del = run_p3c('wifi_iface_delete', { id: 'guest_5g' });
let cv6 = uci.cursor(uci_dir);
check(r_wif_del.ok === true && cv6.get('wireless', 'guest_5g') == null, 'P3C-PROD[wifi_iface_delete_verified]', sprintf('%J', r_wif_del));

// 2c. Real post-apply UCI mismatch -> triggers rollback!
let snap_fw = fs.readfile(uci_dir + '/firewall');
let rc_fw = 0;
let r_fw_mis = run_p3c('fw_zone_save', { name: 'dmz', input: 'DROP', output: 'ACCEPT', forward: 'REJECT', masq: true, mtu_fix: false }, {
	reload_fn: function() {
		rc_fw++;
		if (rc_fw == 1) {
			let ct = uci.cursor(uci_dir);
			ct.set('firewall', 'zn_dmz', 'input', 'ACCEPT'); // mismatch!
			ct.commit('firewall');
		}
		return { ok: true };
	}
});
check(!r_fw_mis.ok && r_fw_mis.rolled_back === true && r_fw_mis.error == 'verify_failed' && fs.readfile(uci_dir + '/firewall') == snap_fw, 'P3C-PROD[real_fw_mismatch_triggers_rollback]', sprintf('%J', r_fw_mis));

let snap_wifi = fs.readfile(uci_dir + '/wireless');
let rc_wf = 0;
let r_wf_mis = run_p3c('wifi_radio_save', { radio: 'radio0', band: '2g', channel: '11', htmode: 'HT40', country: 'DE', txpower: 18, disabled: false }, {
	reload_fn: function() {
		rc_wf++;
		if (rc_wf == 1) {
			let ct = uci.cursor(uci_dir);
			ct.set('wireless', 'radio0', 'txpower', '10'); // mismatch!
			ct.commit('wireless');
		}
		return { ok: true };
	}
});
check(!r_wf_mis.ok && r_wf_mis.rolled_back === true && r_wf_mis.error == 'verify_failed' && fs.readfile(uci_dir + '/wireless') == snap_wifi, 'P3C-PROD[real_wifi_mismatch_triggers_rollback]', sprintf('%J', r_wf_mis));

// 2d. Capability, 6GHz frequency classification, regulatory, PHY mapping, and real runtime evidence tests
let phy_6g_sample = "Wiphy phy3\n\tBand 3:\n\t\tHE Iftypes: AP\n\t\tEHT Iftypes: AP\n\t\tFrequencies:\n\t\t\t* 5955.0 MHz [1] (23.0 dBm)\n";
let reg_6g_sample = "country DE: DFS-ETSI\n\t(5945 - 6425 @ 160), (N/A, 23), (N/A)\n";
let caps_6g = nms_fw_wifi.parse_iw_phy_capabilities(phy_6g_sample, reg_6g_sample);
check(caps_6g.bands['6g'] != null && caps_6g.bands['6g'].channels['1'].freq == 5955, 'P3C-CAP[6g_classified_by_frequency_regardless_of_band_num]', sprintf('%J', caps_6g));

let caps_malformed = nms_fw_wifi.parse_iw_phy_capabilities("garbage\nBand 1:\n\tFrequencies:\n", "country 00:\n");
check(!nms_fw_wifi.validate_wifi_radio_against_caps({ radio: 'radio0', band: '2g', channel: '6', htmode: 'HT20', country: 'DE' }, caps_malformed).ok, 'P3C-CAP[reject_malformed_phy_and_country_00]');

let r_bad_band = run_p3c('wifi_radio_save', { radio: 'radio1', band: '6g', channel: '1', htmode: 'HE80', country: 'DE', txpower: 20 });
check(!r_bad_band.ok && r_bad_band.error_code == 'VALIDATION', 'P3C-CAP[reject_unsupported_band_6g]', sprintf('%J', r_bad_band));

let r_bad_bw = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '36', htmode: 'EHT320', country: 'DE', txpower: 20 });
check(!r_bad_bw.ok && r_bad_bw.error_code == 'VALIDATION', 'P3C-CAP[reject_unsupported_eht320]', sprintf('%J', r_bad_bw));

let r_reg_bw = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '36', htmode: 'HE160', country: 'DE', txpower: 20 });
check(!r_reg_bw.ok && r_reg_bw.error_code == 'VALIDATION', 'P3C-CAP[reject_reg_bw_exceeded_he160_on_80_rule]', sprintf('%J', r_reg_bw));

let r_reg_cc = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '36', htmode: 'HE80', country: 'US', txpower: 20 });
check(!r_reg_cc.ok && r_reg_cc.error_code == 'VALIDATION', 'P3C-CAP[reject_reg_country_mismatch]', sprintf('%J', r_reg_cc));

let r_bad_txp = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 25, dfs: true });
check(!r_bad_txp.ok && r_bad_txp.error_code == 'VALIDATION', 'P3C-CAP[reject_txpower_exceeds_reg_and_hw]', sprintf('%J', r_bad_txp));

let r_bad_dfs_ch36 = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '36', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true });
check(!r_bad_dfs_ch36.ok && r_bad_dfs_ch36.error_code == 'VALIDATION', 'P3C-CAP[reject_dfs_on_non_radar_ch36]', sprintf('%J', r_bad_dfs_ch36));

let r_no_dfs_ch100 = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: false });
check(!r_no_dfs_ch100.ok && r_no_dfs_ch100.error_code == 'VALIDATION', 'P3C-CAP[reject_missing_dfs_on_radar_ch100]', sprintf('%J', r_no_dfs_ch100));

// PHY mapping tests (radio1 -> phy2 non-matching index, unmapped path rejected, wiphy mismatch rejected)
let r_unmapped_phy = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true }, {
	sysfs_ieee80211: [{ phy: 'phy0', device_path: '/sys/devices/platform/soc/18000000.wmac' }]
});
check(!r_unmapped_phy.ok && r_unmapped_phy.error_code == 'VALIDATION', 'P3C-PHY[reject_unmapped_radio1_path]', sprintf('%J', r_unmapped_phy));

let r_wiphy_mis = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true }, {
	exec_iw_phy: function(phy) { return iw_phy0_sample; }
});
check(!r_wiphy_mis.ok && r_wiphy_mis.error_code == 'VALIDATION', 'P3C-PHY[reject_wiphy_identity_mismatch]', sprintf('%J', r_wiphy_mis));

// Real runtime adapter failure tests (exercising production ubus + iw adapters, NO read_wifi_runtime stub!)
let snap_wf_rt = fs.readfile(uci_dir + '/wireless');

// Configured DFS in ubus (config.dfs=true) WITHOUT operational hostapd/iw-phy DFS evidence -> MUST roll back!
let r_dfs_unver = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true, disabled: false }, {
	ubus_call: function(obj, method) {
		if (obj == 'network.wireless' && method == 'status') {
			return { radio1: { up: true, config: { dfs: true }, interfaces: [{ section: 'guest_5g', ifname: 'phy2-ap0' }] } };
		}
		return null; // hostapd get_status missing!
	},
	exec_iw_phy_channels: function() { return "Band 2:\n\t* 5500.0 MHz [100] (20.0 dBm) (radar detection)\n\t  DFS state: unavailable\n"; }
});
check(!r_dfs_unver.ok && r_dfs_unver.rolled_back === true && fs.readfile(uci_dir + '/wireless') == snap_wf_rt, 'P3C-RT[reject_configured_dfs_without_operational_dfs_evidence]', sprintf('%J', r_dfs_unver));

// Reject synthetic top-level cac_time_* aliases when nested dfs object is missing -> MUST roll back!
let r_dfs_alias = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true, disabled: false }, {
	ubus_call: function(obj, method) {
		if (obj == 'network.wireless' && method == 'status') return { radio1: { up: true, interfaces: [{ section: 'guest_5g', ifname: 'phy2-ap0' }] } };
		if (obj == 'hostapd.phy2-ap0' && method == 'get_status') return { status: 'ENABLED', phy: 'phy2', freq: 5500, channel: 100, cac_time_seconds: 60, cac_time_left_seconds: 0 };
		return null;
	}
});
check(!r_dfs_alias.ok && r_dfs_alias.rolled_back === true && fs.readfile(uci_dir + '/wireless') == snap_wf_rt, 'P3C-DFS[reject_top_level_aliases_without_nested_dfs]', sprintf('%J', r_dfs_alias));

// Nested DFS CAC in progress (cac_active=true, cac_seconds_left=42, iw DFS state: usable) -> MUST roll back!
let r_dfs_cac_prog = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true, disabled: false }, {
	ubus_call: function(obj, method) {
		if (obj == 'network.wireless' && method == 'status') return { radio1: { up: true, interfaces: [{ section: 'guest_5g', ifname: 'phy2-ap0' }] } };
		if (obj == 'hostapd.phy2-ap0' && method == 'get_status') return { status: 'DFS', phy: 'phy2', freq: 5500, channel: 100, dfs: { cac_seconds: 60, cac_active: true, cac_seconds_left: 42 } };
		return null;
	},
	exec_iw_phy_channels: function() { return "Band 2:\n\t* 5500.0 MHz [100] (20.0 dBm) (radar detection)\n\t  DFS state: usable\n"; }
});
check(!r_dfs_cac_prog.ok && r_dfs_cac_prog.rolled_back === true && fs.readfile(uci_dir + '/wireless') == snap_wf_rt, 'P3C-DFS[reject_nested_cac_in_progress]', sprintf('%J', r_dfs_cac_prog));

// Contradictory: cac_active=true with cac_seconds_left=0 -> MUST roll back!
let r_dfs_c1 = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true, disabled: false }, {
	ubus_call: function(obj, method) {
		if (obj == 'network.wireless' && method == 'status') return { radio1: { up: true, interfaces: [{ section: 'guest_5g', ifname: 'phy2-ap0' }] } };
		if (obj == 'hostapd.phy2-ap0' && method == 'get_status') return { status: 'ENABLED', phy: 'phy2', freq: 5500, channel: 100, dfs: { cac_seconds: 60, cac_active: true, cac_seconds_left: 0 } };
		return null;
	}
});
check(!r_dfs_c1.ok && r_dfs_c1.rolled_back === true && fs.readfile(uci_dir + '/wireless') == snap_wf_rt, 'P3C-DFS[reject_cac_active_true_with_zero_left]', sprintf('%J', r_dfs_c1));

// Contradictory: cac_active=false with cac_seconds_left=15 -> MUST roll back!
let r_dfs_c2 = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true, disabled: false }, {
	ubus_call: function(obj, method) {
		if (obj == 'network.wireless' && method == 'status') return { radio1: { up: true, interfaces: [{ section: 'guest_5g', ifname: 'phy2-ap0' }] } };
		if (obj == 'hostapd.phy2-ap0' && method == 'get_status') return { status: 'ENABLED', phy: 'phy2', freq: 5500, channel: 100, dfs: { cac_seconds: 60, cac_active: false, cac_seconds_left: 15 } };
		return null;
	}
});
check(!r_dfs_c2.ok && r_dfs_c2.rolled_back === true && fs.readfile(uci_dir + '/wireless') == snap_wf_rt, 'P3C-DFS[reject_positive_left_with_cac_active_false]', sprintf('%J', r_dfs_c2));

// Wrongly typed nested dfs fields -> MUST roll back!
let r_dfs_typed = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true, disabled: false }, {
	ubus_call: function(obj, method) {
		if (obj == 'network.wireless' && method == 'status') return { radio1: { up: true, interfaces: [{ section: 'guest_5g', ifname: 'phy2-ap0' }] } };
		if (obj == 'hostapd.phy2-ap0' && method == 'get_status') return { status: 'ENABLED', phy: 'phy2', freq: 5500, channel: 100, dfs: { cac_seconds: '60', cac_active: 'false', cac_seconds_left: '0' } };
		return null;
	}
});
check(!r_dfs_typed.ok && r_dfs_typed.rolled_back === true && fs.readfile(uci_dir + '/wireless') == snap_wf_rt, 'P3C-DFS[reject_wrongly_typed_dfs_fields]', sprintf('%J', r_dfs_typed));

// DFS state: usable even if nested dfs says completed -> MUST roll back!
let r_dfs_usable = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true, disabled: false }, {
	exec_iw_phy_channels: function() { return "Band 2:\n\t* 5500.0 MHz [100] (20.0 dBm) (radar detection)\n\t  DFS state: usable\n"; }
});
check(!r_dfs_usable.ok && r_dfs_usable.rolled_back === true && fs.readfile(uci_dir + '/wireless') == snap_wf_rt, 'P3C-DFS[reject_usable_even_when_hostapd_enabled]', sprintf('%J', r_dfs_usable));

// Missing/mismatched hst.phy or hst.channel or hst.freq -> MUST roll back!
let r_dfs_phy_mis = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true, disabled: false }, {
	ubus_call: function(obj, method) {
		if (obj == 'network.wireless' && method == 'status') return { radio1: { up: true, interfaces: [{ section: 'guest_5g', ifname: 'phy2-ap0' }] } };
		if (obj == 'hostapd.phy2-ap0' && method == 'get_status') return { status: 'ENABLED', phy: 'phy0', freq: 5500, channel: 100, dfs: { cac_seconds: 60, cac_active: false, cac_seconds_left: 0 } };
		return null;
	}
});
check(!r_dfs_phy_mis.ok && r_dfs_phy_mis.rolled_back === true && fs.readfile(uci_dir + '/wireless') == snap_wf_rt, 'P3C-DFS[reject_mismatched_hst_phy]', sprintf('%J', r_dfs_phy_mis));

let r_dfs_no_ch = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true, disabled: false }, {
	ubus_call: function(obj, method) {
		if (obj == 'network.wireless' && method == 'status') return { radio1: { up: true, interfaces: [{ section: 'guest_5g', ifname: 'phy2-ap0' }] } };
		if (obj == 'hostapd.phy2-ap0' && method == 'get_status') return { status: 'ENABLED', phy: 'phy2', freq: 5500, dfs: { cac_seconds: 60, cac_active: false, cac_seconds_left: 0 } };
		return null;
	}
});
check(!r_dfs_no_ch.ok && r_dfs_no_ch.rolled_back === true && fs.readfile(uci_dir + '/wireless') == snap_wf_rt, 'P3C-DFS[reject_missing_hst_channel]', sprintf('%J', r_dfs_no_ch));

let r_dfs_stale = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true, disabled: false }, {
	ubus_call: function(obj, method) {
		if (obj == 'network.wireless' && method == 'status') return { radio1: { up: true, interfaces: [{ section: 'guest_5g', ifname: 'phy2-ap0' }] } };
		if (obj == 'hostapd.phy2-ap0' && method == 'get_status') return { status: 'ENABLED', phy: 'phy2', freq: 5180, channel: 36, dfs: { cac_seconds: 60, cac_active: false, cac_seconds_left: 0 } };
		return null;
	}
});
check(!r_dfs_stale.ok && r_dfs_stale.rolled_back === true && fs.readfile(uci_dir + '/wireless') == snap_wf_rt, 'P3C-DFS[reject_stale_hostapd_freq_mismatch]', sprintf('%J', r_dfs_stale));

// Radar unavailable & non-DFS direct evaluator checks
check(nms_fw_wifi.evaluate_dfs_runtime_state(
	{ status: 'ENABLED', phy: 'phy2', freq: 5500, channel: 100, dfs: { cac_seconds: 60, cac_active: false, cac_seconds_left: 0 } },
	{ freq: 5500, radar: true, disabled: false, dfs_state: 'unavailable' }, '100', 5500, 'phy2'
).state == 'radar_unavailable', 'P3C-DFS[reject_radar_unavailable]');
check(nms_fw_wifi.evaluate_dfs_runtime_state(
	{ status: 'ENABLED', phy: 'phy2', freq: 5180, channel: 36, dfs: { cac_seconds: 60, cac_active: false, cac_seconds_left: 0 } },
	{ freq: 5180, radar: false, disabled: false, dfs_state: '' }, '36', 5180, 'phy2'
).state == 'non_dfs', 'P3C-DFS[reject_non_dfs_channel]');

// Missing runtime channel/country from iw dev / iw reg -> MUST roll back (never silently skipped)!
let r_rt_missing = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true, disabled: false }, {
	exec_iw_dev: function() { return "Interface phy2-ap0\n\twiphy 2\n\ttype AP\n"; }
});
check(!r_rt_missing.ok && r_rt_missing.rolled_back === true && fs.readfile(uci_dir + '/wireless') == snap_wf_rt, 'P3C-RT[reject_missing_runtime_channel_triggers_rollback]', sprintf('%J', r_rt_missing));

// Wrong active runtime country / channel -> MUST roll back!
let r_rt_mis = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true, disabled: false }, {
	exec_iw_dev: function() { return "Interface phy2-ap0\n\twiphy 2\n\ttype AP\n\tchannel 36 (5180 MHz), width: 80 MHz\n"; }
});
check(!r_rt_mis.ok && r_rt_mis.rolled_back === true && r_rt_mis.error == 'verify_failed' && fs.readfile(uci_dir + '/wireless') == snap_wf_rt, 'P3C-PROD[runtime_dfs_channel_mismatch_triggers_rollback]', sprintf('%J', r_rt_mis));

// Disabled radio still reports up=true -> MUST roll back!
let r_rt_dis = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '36', htmode: 'HE80', country: 'DE', txpower: 20, dfs: false, disabled: true }, {
	ubus_call: function(obj, method) {
		if (obj == 'network.wireless' && method == 'status') return { radio1: { up: true, interfaces: [] } };
		return null;
	}
});
check(!r_rt_dis.ok && r_rt_dis.rolled_back === true && fs.readfile(uci_dir + '/wireless') == snap_wf_rt, 'P3C-RT[reject_disabled_radio_still_up]', sprintf('%J', r_rt_dis));

// Interface inactive / wrong active SSID despite radio_up=true and config.ssid matching -> MUST roll back!
let r_if_inact = run_p3c('wifi_iface_save', { id: 'guest_5g', device: 'radio1', mode: 'ap', network: 'guest', ssid: 'Guest-5G-WPA3', encryption: 'sae', key: 'GuestPass123!', ieee80211w: '2', disabled: false }, {
	ubus_call: function(obj, method) {
		if (obj == 'network.wireless' && method == 'status') {
			return { radio1: { up: true, interfaces: [{ section: 'guest_5g', ifname: 'phy2-ap0', config: { ssid: 'Guest-5G-WPA3' } }] } };
		}
		if (obj == 'hostapd.phy2-ap0' && method == 'get_status') return { status: 'UNINITIALIZED' };
		return null;
	},
	exec_iw_dev: function() { return "Interface phy2-ap0\n\twiphy 2\n\ttype AP\n\tssid WrongOtherSSID\n\tchannel 100 (5500 MHz), width: 80 MHz\n"; }
});
check(!r_if_inact.ok && r_if_inact.rolled_back === true && fs.readfile(uci_dir + '/wireless') == snap_wf_rt, 'P3C-RT[reject_inactive_iface_despite_radio_up_and_config_ssid]', sprintf('%J', r_if_inact));

// Wireless reload failure -> MUST roll back wireless UCI config cleanly
let rc_wf_rel = 0;
let r_wf_rel = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true, disabled: false }, {
	reload_fn: function() {
		rc_wf_rel++;
		if (rc_wf_rel == 1) return { ok: false, error: 'wifi_reload_failed' };
		return { ok: true };
	}
});
check(!r_wf_rel.ok && r_wf_rel.rolled_back === true && fs.readfile(uci_dir + '/wireless') == snap_wf_rt, 'P3C-PROD[wifi_reload_failure_triggers_rollback]', sprintf('%J', r_wf_rel));

// Wireless rollback failure -> MUST trigger emergency freeze
let r_wf_rbf = run_p3c('wifi_radio_save', { radio: 'radio1', band: '5g', channel: '100', htmode: 'HE80', country: 'DE', txpower: 20, dfs: true, disabled: false }, {
	reload_fn: function() { return { ok: false, error: 'wifi_reload_failed' }; },
	aw_ops: {
		suffix: function() { return 'rbf'; },
		stat: fs.stat,
		unlink: fs.unlink,
		open: fs.open,
		writefile: fs.writefile,
		chown: fs.chown,
		chmod: fs.chmod,
		rename: function(src, dst) {
			if (dst == uci_dir + '/wireless') return null;
			return fs.rename(src, dst);
		},
		error: function() { return 'EIO: simulated rollback rename failure'; }
	}
});
check(!r_wf_rbf.ok && r_wf_rbf.rollback_failed === true && helperd_prod.get_freeze_state().frozen === true, 'P3C-PROD[wifi_rollback_failure_triggers_emergency_freeze]', sprintf('%J', r_wf_rbf));
helperd_prod.clear_freeze_mem();

printf('UCODE3C_SUMMARY: %d passed, %d failed\n', passed, failed);
exit(failed == 0 ? 0 : 1);
