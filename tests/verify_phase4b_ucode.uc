// Executed directly by OpenWrt 24.10.0 & 25.12.6 ucode runtime against production backend/nms_discovery.uc
import * as nms_discovery from '/tmp/p3a_test/nms_discovery.uc';

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

let prev_map = {};
let c1 = [{ mac: 'aa:bb:cc:dd:ee:01', total_rx_bytes: 10000, total_tx_bytes: 5000 }];

// 1. First sample -> pending_baseline (null, never fabricated 0)
nms_discovery.compute_client_rates(c1, prev_map, 1000, false, true);
check(c1[0].rate_supported === true && c1[0].rx_bps == null && c1[0].tx_bps == null && c1[0].rate_reason == 'pending_baseline', 'P4B-RATE[first_sample_pending_baseline_null]', sprintf('%J', c1[0]));

// 2. Second sample after 2000ms -> exact bps calculation (+100000 RX -> 400000 bps, +25000 TX -> 100000 bps)
c1[0].total_rx_bytes = 110000;
c1[0].total_tx_bytes = 30000;
nms_discovery.compute_client_rates(c1, prev_map, 3000, false, true);
check(c1[0].rate_supported === true && c1[0].rx_bps == 400000 && c1[0].tx_bps == 100000 && c1[0].rate_reason == 'ok', 'P4B-RATE[accurate_delta_bps]', sprintf('%J', c1[0]));

// 3. Sub-500ms rapid poll retains last valid rate without wiping baseline
c1[0].total_rx_bytes = 120000;
nms_discovery.compute_client_rates(c1, prev_map, 3200, false, true);
check(c1[0].rx_bps == 400000 && c1[0].rate_reason == 'ok', 'P4B-RATE[sub500ms_retains_last_valid_rate]', sprintf('%J', c1[0]));

// 4. Counter reset -> null + counter_reset (never negative!)
c1[0].total_rx_bytes = 500;
nms_discovery.compute_client_rates(c1, prev_map, 5000, false, true);
check(c1[0].rate_supported === true && c1[0].rx_bps == null && c1[0].tx_bps == null && c1[0].rate_reason == 'counter_reset', 'P4B-RATE[counter_reset_returns_null]', sprintf('%J', c1[0]));

// 5. flow_offloading=true -> rate_supported=false, null rates
nms_discovery.compute_client_rates(c1, prev_map, 7000, true, true);
check(c1[0].rate_supported === false && c1[0].rx_bps == null && c1[0].tx_bps == null && c1[0].rate_reason == 'flow_offloading', 'P4B-RATE[flow_offloading_unsupported]', sprintf('%J', c1[0]));

// 6. nlbw_ok=false -> rate_supported=false, null rates
nms_discovery.compute_client_rates(c1, prev_map, 9000, false, false);
check(c1[0].rate_supported === false && c1[0].rx_bps == null && c1[0].tx_bps == null && c1[0].rate_reason == 'nlbw_unavailable', 'P4B-RATE[nlbw_unavailable_unsupported]', sprintf('%J', c1[0]));

// 7. Stale entry pruning (>300s)
prev_map['11:22:33:44:55:66'] = { rx: 1, tx: 1, ts_ms: 1000, last_rx_bps: 0, last_tx_bps: 0 };
nms_discovery.compute_client_rates(c1, prev_map, 400000, false, true);
check(prev_map['11:22:33:44:55:66'] == null, 'P4B-RATE[prunes_stale_entries]');

// 8. Sub-500ms counter reset MUST return null + counter_reset (never preserve old rate)
let c2 = [{ mac: 'aa:bb:cc:dd:ee:02', total_rx_bytes: 100000, total_tx_bytes: 50000 }];
let pmap2 = {};
nms_discovery.compute_client_rates(c2, pmap2, 1000, false, true);
c2[0].total_rx_bytes = 200000;
c2[0].total_tx_bytes = 100000;
nms_discovery.compute_client_rates(c2, pmap2, 3000, false, true); // 400000 bps rx, 200000 bps tx
c2[0].total_rx_bytes = 200;
c2[0].total_tx_bytes = 1000;
nms_discovery.compute_client_rates(c2, pmap2, 3200, false, true); // dt=200ms < 500ms AND reset!
check(c2[0].rx_bps == null && c2[0].tx_bps == null && c2[0].rate_reason == 'counter_reset', 'P4B-RATE[sub500ms_counter_reset_null_not_old_rate]', sprintf('%J', c2[0]));

// 9. Post-reset rise above pre-reset value computes from post-reset baseline (200/1000), NOT old (200000/100000)
c2[0].total_rx_bytes = 250200; // +250000 bytes over post-reset baseline 200 (also > old 200000)
c2[0].total_tx_bytes = 51000;  // +50000 bytes over post-reset baseline 1000
nms_discovery.compute_client_rates(c2, pmap2, 5200, false, true); // dt=2000ms -> 1000000 bps rx, 200000 bps tx
check(c2[0].rx_bps == 1000000 && c2[0].tx_bps == 200000 && c2[0].rate_reason == 'ok', 'P4B-RATE[post_reset_uses_new_baseline]', sprintf('%J', c2[0]));

// 10. CPU collector: 2-core initial baseline
function make_stat(cores, busy_val, idle_val, steal_val) {
	let lines = [sprintf('cpu  %d 0 0 %d 0 0 0 %d 0 0', busy_val * cores, idle_val * cores, steal_val * cores)];
	for (let i = 0; i < cores; i++) {
		push(lines, sprintf('cpu%d %d 0 0 %d 0 0 0 %d 0 0', i, busy_val, idle_val, steal_val));
	}
	return join('\n', lines);
}

let cpu_st2 = { prev_cpu: {}, last_cpu_pct: {}, last_steal_pct: 0, boot_cpu_cores: null };
let r0 = nms_discovery.collect_cpu_from_proc(make_stat(2, 100, 900, 0), 1000, cpu_st2);
check(r0.detected_cores == 2 && r0.expected_cores == 2 && r0.core_drift === false && r0.raw_total_pct == null && r0.total_status == 'unknown', 'P4B-CPU[2core_initial_baseline]', sprintf('%J', r0));

// 11. CPU collector: valid >=800ms delta (200 busy, 800 idle -> 20.0%)
let r1 = nms_discovery.collect_cpu_from_proc(make_stat(2, 300, 1700, 0), 2000, cpu_st2);
check(r1.total_pct == 20.0 && r1.total_status == 'ok' && length(r1.cores) == 2 && r1.cores[0].pct == 20.0, 'P4B-CPU[valid_delta_800ms]', sprintf('%J', r1));

// 12. CPU collector: sub-800ms rapid poll retains last valid reading without overwriting prev_cpu
let r2 = nms_discovery.collect_cpu_from_proc(make_stat(2, 900, 2100, 0), 2300, cpu_st2);
check(r2.total_pct == 20.0 && cpu_st2.prev_cpu['cpu'].mono == 2000, 'P4B-CPU[sub800ms_retains_and_preserves_baseline]', sprintf('pct=%J mono=%J', r2.total_pct, cpu_st2.prev_cpu['cpu'].mono));

// 13. CPU collector: 4-core and 8-core dynamic expected_cores without drift
let st4 = { prev_cpu: {}, last_cpu_pct: {}, last_steal_pct: 0, boot_cpu_cores: null };
let st8 = { prev_cpu: {}, last_cpu_pct: {}, last_steal_pct: 0, boot_cpu_cores: null };
let r4 = nms_discovery.collect_cpu_from_proc(make_stat(4, 100, 900, 0), 1000, st4);
let r8 = nms_discovery.collect_cpu_from_proc(make_stat(8, 100, 900, 0), 1000, st8);
check(r4.detected_cores == 4 && r4.expected_cores == 4 && r4.core_drift === false && r8.detected_cores == 8 && r8.expected_cores == 8 && r8.core_drift === false, 'P4B-CPU[4core_8core_dynamic_expected]', sprintf('4=%J 8=%J', r4.expected_cores, r8.expected_cores));

// 14. CPU collector: core_drift detected when core count drops below expected_cores
let r4_drift = nms_discovery.collect_cpu_from_proc(make_stat(3, 200, 1800, 0), 2000, st4);
check(r4_drift.detected_cores == 3 && r4_drift.expected_cores == 4 && r4_drift.core_drift === true, 'P4B-CPU[core_drift_detected]', sprintf('%J', r4_drift));

printf('UCODE4B_SUMMARY: %d passed, %d failed\n', passed, failed);
exit(failed == 0 ? 0 : 1);
