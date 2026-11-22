// Executed directly by OpenWrt 24.10.0 & 25.12.6 ucode runtime against production backend/nms_clients.uc
import * as nms_clients from '/tmp/p3a_test/nms_clients.uc';

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

// 1. MAC validation
check(
	nms_clients.is_valid_mac('aa:bb:cc:dd:ee:01') === true &&
	nms_clients.is_valid_mac('00:00:00:00:00:00') === false &&
	nms_clients.is_valid_mac('ff:ff:ff:ff:ff:ff') === false &&
	nms_clients.is_valid_mac('01:00:5e:00:00:01') === false,
	'P4C-VAL[mac_unicast_only]'
);

// 2. IPv4 validation
check(
	nms_clients.is_valid_ipv4('192.168.1.50') === true &&
	nms_clients.is_valid_ipv4('0.0.0.0') === false &&
	nms_clients.is_valid_ipv4('255.255.255.255') === false &&
	nms_clients.is_valid_ipv4('127.0.0.1') === false &&
	nms_clients.is_valid_ipv4('224.0.0.1') === false,
	'P4C-VAL[ipv4_strict]'
);

// 3. Same-day schedule window
check(
	nms_clients.is_schedule_active('08:00', '17:00', '08:00') === true &&
	nms_clients.is_schedule_active('08:00', '17:00', '16:59') === true &&
	nms_clients.is_schedule_active('08:00', '17:00', '17:00') === false &&
	nms_clients.is_schedule_active('08:00', '17:00', '07:59') === false,
	'P4C-SCHED[same_day_window]'
);

// 4. Overnight wraparound schedule window
check(
	nms_clients.is_schedule_active('23:00', '07:00', '23:30') === true &&
	nms_clients.is_schedule_active('23:00', '07:00', '02:15') === true &&
	nms_clients.is_schedule_active('23:00', '07:00', '06:59') === true &&
	nms_clients.is_schedule_active('23:00', '07:00', '07:00') === false &&
	nms_clients.is_schedule_active('23:00', '07:00', '22:59') === false,
	'P4C-SCHED[overnight_wraparound]'
);

// 5. Invalid schedule times
check(
	nms_clients.is_schedule_active('29:00', '07:00', '02:00') === false &&
	nms_clients.is_schedule_active('24:00', '07:00', '02:00') === false &&
	nms_clients.is_schedule_active('12:00', '12:00', '12:00') === false,
	'P4C-SCHED[rejects_invalid_and_equal_times]'
);

let gw_macs = { '60:be:b4:1e:d3:5d': true };
let gw_ips = { '192.168.1.1': true };
let ip_map = { 'aa:bb:cc:dd:ee:01': '192.168.1.20', 'aa:bb:cc:dd:ee:02': '192.168.1.21', '60:be:b4:1e:d3:5d': '192.168.1.1' };

// 6. Quota input validation & gateway/admin protection
let q_neg = nms_clients.validate_quota_input({ mac: 'aa:bb:cc:dd:ee:01', quota_mb: -5 }, ip_map, '192.168.1.99', gw_macs, gw_ips);
let q_low_t = nms_clients.validate_quota_input({ mac: 'aa:bb:cc:dd:ee:01', quota_mb: 100, throttle_kbps: 32 }, ip_map, '192.168.1.99', gw_macs, gw_ips);
let q_gw = nms_clients.validate_quota_input({ mac: '60:be:b4:1e:d3:5d', quota_mb: 100 }, ip_map, '192.168.1.99', gw_macs, gw_ips);
let q_ok = nms_clients.validate_quota_input({ mac: 'aa:bb:cc:dd:ee:01', quota_mb: 500, throttle_kbps: 256 }, ip_map, '192.168.1.99', gw_macs, gw_ips);
check(!q_neg.ok && !q_low_t.ok && !q_gw.ok && q_gw.error_code == 'FORBIDDEN' && q_ok.ok && q_ok.quota_mb == 500 && q_ok.throttle_kbps == 256, 'P4C-QUOTA[validation_and_gw_protection]');

// 7. Schedule input validation & gateway/admin protection
let s_bad_act = nms_clients.validate_schedule_input({ mac: 'aa:bb:cc:dd:ee:01', action_type: 'reboot', start_time: '23:00', end_time: '07:00' }, ip_map, '192.168.1.99', gw_macs, gw_ips);
let s_bad_hr = nms_clients.validate_schedule_input({ mac: 'aa:bb:cc:dd:ee:01', action_type: 'block', start_time: '25:00', end_time: '07:00' }, ip_map, '192.168.1.99', gw_macs, gw_ips);
let s_gw = nms_clients.validate_schedule_input({ mac: '60:be:b4:1e:d3:5d', action_type: 'block', start_time: '23:00', end_time: '07:00' }, ip_map, '192.168.1.99', gw_macs, gw_ips);
let s_ok = nms_clients.validate_schedule_input({ mac: 'aa:bb:cc:dd:ee:01', action_type: 'throttle', start_time: '23:00', end_time: '07:00', throttle_kbps: 512 }, ip_map, '192.168.1.99', gw_macs, gw_ips);
check(!s_bad_act.ok && !s_bad_hr.ok && !s_gw.ok && s_gw.error_code == 'FORBIDDEN' && s_ok.ok && s_ok.throttle_kbps == 512, 'P4C-SCHED[validation_and_gw_protection]');

// 8. Static lease conflict detection
let hosts = [{ sid: 'noc_102233445566', mac: '10:22:33:44:55:66', ip: '192.168.1.50', name: 'nas' }];
let l_gw = nms_clients.validate_static_lease_conflict('aa:bb:cc:dd:ee:01', '192.168.1.1', 'pc', true, '192.168.1.1', gw_ips, hosts);
let l_conf = nms_clients.validate_static_lease_conflict('aa:bb:cc:dd:ee:01', '192.168.1.50', 'pc', true, '192.168.1.1', gw_ips, hosts);
let l_same = nms_clients.validate_static_lease_conflict('10:22:33:44:55:66', '192.168.1.50', 'nas', true, '192.168.1.1', gw_ips, hosts);
check(!l_gw.ok && !l_conf.ok && l_conf.error_code == 'CONFLICT' && l_same.ok, 'P4C-DHCP[static_lease_conflict_detection]');

// 9. Effective rules: manual block preserved
let manual = { blocked_macs: { 'aa:bb:cc:dd:ee:99': true }, blocked_ips: { '192.168.1.99': true }, rate_limits: {} };
let eff_manual = nms_clients.compute_effective_client_rules(manual, {}, [], {}, ip_map, '12:00', gw_macs, gw_ips);
check(eff_manual.blocked_macs['aa:bb:cc:dd:ee:99'] === true && eff_manual.blocked_ips['192.168.1.99'] === true, 'P4C-EFF[manual_rules_preserved]');

// 10. Effective rules: schedule activates in window and clears after window without altering manual rules
let scheds = [{ id: 's1', mac: 'aa:bb:cc:dd:ee:01', action_type: 'block', start_time: '23:00', end_time: '07:00', enabled: true }];
let eff_in = nms_clients.compute_effective_client_rules(manual, {}, scheds, {}, ip_map, '01:00', gw_macs, gw_ips);
let eff_out = nms_clients.compute_effective_client_rules(manual, {}, scheds, {}, ip_map, '07:00', gw_macs, gw_ips);
check(
	eff_in.blocked_macs['aa:bb:cc:dd:ee:01'] === true && eff_in.blocked_ips['192.168.1.20'] === true && eff_in.active_schedules['s1'] === true &&
	!eff_out.blocked_macs['aa:bb:cc:dd:ee:01'] && !eff_out.blocked_ips['192.168.1.20'] && !eff_out.active_schedules['s1'] &&
	eff_out.blocked_macs['aa:bb:cc:dd:ee:99'] === true,
	'P4C-EFF[schedule_block_lifecycle]'
);

// 11. Effective rules: throttle schedule takes minimum rate with manual rate
let manual_r = { blocked_macs: {}, blocked_ips: {}, rate_limits: { '192.168.1.20': 1024 } };
let scheds_t = [{ id: 's2', mac: 'aa:bb:cc:dd:ee:01', action_type: 'throttle', start_time: '08:00', end_time: '18:00', throttle_kbps: 512, enabled: true }];
let eff_thr = nms_clients.compute_effective_client_rules(manual_r, {}, scheds_t, {}, ip_map, '12:00', gw_macs, gw_ips);
check(eff_thr.rate_limits['192.168.1.20'] == 512 && eff_thr.active_schedules['s2'] === true, 'P4C-EFF[schedule_throttle_min_rate]');

// 12. Effective rules: exceeded quota enforces block (throttle=0) or throttle (throttle>=64)
let quotas = {
	'aa:bb:cc:dd:ee:01': { quota_mb: 100, throttle_kbps: 0 },
	'aa:bb:cc:dd:ee:02': { quota_mb: 200, throttle_kbps: 256 }
};
let usage_over = { 'aa:bb:cc:dd:ee:01': 100 * 1048576, 'aa:bb:cc:dd:ee:02': 250 * 1048576 };
let eff_q_over = nms_clients.compute_effective_client_rules({}, quotas, [], usage_over, ip_map, '12:00', gw_macs, gw_ips);
check(
	eff_q_over.exceeded_quotas['aa:bb:cc:dd:ee:01'] === true && eff_q_over.blocked_macs['aa:bb:cc:dd:ee:01'] === true &&
	eff_q_over.exceeded_quotas['aa:bb:cc:dd:ee:02'] === true && eff_q_over.rate_limits['192.168.1.21'] == 256,
	'P4C-EFF[quota_exceeded_enforces_block_or_throttle]'
);

// 13. Effective rules: under-quota client is untouched
let usage_under = { 'aa:bb:cc:dd:ee:01': 99 * 1048576, 'aa:bb:cc:dd:ee:02': 10 * 1048576 };
let eff_q_under = nms_clients.compute_effective_client_rules({}, quotas, [], usage_under, ip_map, '12:00', gw_macs, gw_ips);
check(!eff_q_under.exceeded_quotas['aa:bb:cc:dd:ee:01'] && !eff_q_under.blocked_macs['aa:bb:cc:dd:ee:01'] && eff_q_under.rate_limits['192.168.1.21'] == null, 'P4C-EFF[under_quota_untouched]');

// 14. Effective rules: defense-in-depth never blocks/throttles gateway MAC/IP
let tampered_m = { blocked_macs: { '60:be:b4:1e:d3:5d': true }, blocked_ips: { '192.168.1.1': true }, rate_limits: { '192.168.1.1': 64 } };
let eff_gw = nms_clients.compute_effective_client_rules(tampered_m, {}, [], {}, ip_map, '12:00', gw_macs, gw_ips);
check(!eff_gw.blocked_macs['60:be:b4:1e:d3:5d'] && !eff_gw.blocked_ips['192.168.1.1'] && eff_gw.rate_limits['192.168.1.1'] == null, 'P4C-EFF[gateway_never_blocked_or_throttled]');

printf('UCODE4C_SUMMARY: %d passed, %d failed\n', passed, failed);
exit(failed == 0 ? 0 : 1);
