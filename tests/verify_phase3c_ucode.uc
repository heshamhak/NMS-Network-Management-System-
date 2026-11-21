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
let base_wifi = "config wifi-device 'radio0'\n\toption type 'mac80211'\n\toption band '2g'\n\toption channel '6'\n\toption htmode 'HT20'\n\toption country 'IQ'\n\nconfig wifi-device 'radio1'\n\toption type 'mac80211'\n\toption band '5g'\n\toption channel '36'\n\toption htmode 'HE80'\n\toption country 'IQ'\n\nconfig wifi-iface 'default_radio0'\n\toption device 'radio0'\n\toption network 'lan'\n\toption mode 'ap'\n\toption ssid 'MainAP'\n\toption encryption 'psk2'\n\toption key 'MainSecret123'\n";
fs.writefile(uci_dir + '/firewall', base_fw);
fs.chmod(uci_dir + '/firewall', 0o644);
fs.writefile(uci_dir + '/wireless', base_wifi);
fs.chmod(uci_dir + '/wireless', 0o644);

function run_p3c(verb, params, extra_env) {
	let rep = null;
	let env = {
		cfg_dir: uci_dir,
		uci_dir: uci_dir,
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
let r_wf_mis = run_p3c('wifi_radio_save', { radio: 'radio0', band: '2g', channel: '11', htmode: 'HT40', country: 'US', txpower: 18, disabled: false }, {
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

printf('UCODE3C_SUMMARY: %d passed, %d failed\n', passed, failed);
exit(failed == 0 ? 0 : 1);
