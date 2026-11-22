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

printf('UCODE4B_SUMMARY: %d passed, %d failed\n', passed, failed);
exit(failed == 0 ? 0 : 1);
