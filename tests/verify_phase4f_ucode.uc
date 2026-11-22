// Executed directly by OpenWrt 24.10.0 & 25.12.6 ucode runtime against production backend/nms_topology.uc & noc-helperd exec_argv_async
import * as fs from 'fs';
import * as uloop from 'uloop';
import * as nms_topo from '/tmp/p3a_test/nms_topology.uc';
import * as h_exec from '/tmp/p3a_test/helperd_exec_prod.uc';

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

let ip_link_ok = sprintf('%J', [
	{ ifname: 'eth0', operstate: 'UP', flags: ['UP', 'LOWER_UP'], address: '60:be:b4:1e:d3:5c' },
	{ ifname: 'pppoe-wan', operstate: 'UP', flags: ['UP', 'POINTOPOINT'], address: '' },
	{ ifname: 'br-lan', operstate: 'UP', flags: ['UP', 'LOWER_UP'], address: '60:be:b4:1e:d3:5d', linkinfo: { info_kind: 'bridge' } },
	{ ifname: 'eth1', operstate: 'UP', flags: ['UP', 'LOWER_UP'], address: '60:be:b4:1e:d3:5d', master: 'br-lan' },
	{ ifname: 'wlan1', operstate: 'UP', flags: ['UP', 'LOWER_UP'], address: '60:be:b4:1e:d3:5e', master: 'br-lan' },
	{ ifname: 'eth1.10', operstate: 'UP', flags: ['UP'], link: 'eth1', linkinfo: { info_kind: 'vlan', info_data: { id: 10 } } }
]);
let ip_addr_ok = sprintf('%J', [
	{ ifname: 'pppoe-wan', addr_info: [{ family: 'inet', local: '100.78.127.23', prefixlen: 32 }] },
	{ ifname: 'br-lan', addr_info: [{ family: 'inet', local: '192.168.1.1', prefixlen: 24 }] }
]);
let ip_route_ok = sprintf('%J', [
	{ dst: 'default', dev: 'pppoe-wan', gateway: '100.78.0.1', metric: 10, protocol: 'static' }
]);
let br_vlan_ok = sprintf('%J', [
	{ ifname: 'br-lan', vlans: [{ vlan: 1, flags: ['PVID', 'Egress Untagged'] }, { vlan: 10, flags: [] }] },
	{ ifname: 'eth1', vlans: [{ vlan: 1, flags: ['PVID', 'Egress Untagged'] }, { vlan: 10, flags: [] }] }
]);
let fdb_ok = "aa:bb:cc:dd:ee:02 dev eth1 master br-lan\n";

let base_sources = {
	sampled_ms: 10000,
	ip_link_raw: ip_link_ok,
	ip_addr_raw: ip_addr_ok,
	ip_route_raw: ip_route_ok,
	bridge_vlan_raw: br_vlan_ok,
	fdb_raw: fdb_ok,
	bridges: [{ name: 'br-lan', ports: ['eth1', 'wlan1'] }],
	uci_wireless: [
		{ ifname: 'wlan1', device: 'radio0', ssid: 'HomeAP', mode: 'ap', disabled: false },
		{ ifname: 'wlan2', device: 'radio1', ssid: 'DisabledAP', mode: 'ap', disabled: true }
	],
	runtime_ap_ifs: { wlan1: { up: true, radio: 'radio0', mode: 'ap', ssid: 'HomeAP' } },
	wifi_stations: { 'aa:bb:cc:dd:ee:01': { ifname: 'wlan1', signal: -52 } },
	wan_topology: { wan_ifaces: { 'pppoe-wan': true }, lan_ifaces: { 'br-lan': true, 'eth1': true, 'lo': true } },
	clients: [
		{ mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.20', display_name: 'Phone', online: true, blocked: false },
		{ mac: 'aa:bb:cc:dd:ee:02', ip: '192.168.1.21', display_name: 'Desktop', online: true, blocked: false },
		{ mac: 'aa:bb:cc:dd:ee:03', ip: '192.168.1.22', display_name: 'Mystery', online: true, blocked: false }
	],
	collector_status: { ubus_network: true, wireless: true, clients: true }
};

let t0 = nms_topo.build_live_topology(base_sources);

// 1. Complete topology & physical/logical link + route parsing
check(t0.ok && t0.completeness == 'complete' && length(t0.missing_sources) == 0, 'P4F-CORE[complete_evidence_topology]');

// 2. Bridge membership & wired FDB client attachment (to port:eth1, NOT AP)
let cl_wired = t0.clients[1];
check(length(t0.bridges) == 1 && length(t0.bridges[0].ports) == 2 && cl_wired.parent_id == 'port:eth1' && cl_wired.attachment_type == 'wired_port' && cl_wired.evidence_source == 'bridge_fdb', 'P4F-BRIDGE[fdb_wired_port_attachment]');

// 3. VLAN relationships & VLAN filtering
check(length(t0.vlans) == 1 && t0.vlans[0].vlan_id == 10 && length(t0.bridges[0].ports[0].vlans) == 2, 'P4F-VLAN[bridge_and_link_vlans]');

// 4. Wireless radio/SSID configured vs observed runtime & station attachment
let cl_wifi = t0.clients[0];
check(length(t0.aps) == 2 && t0.aps[0].observed_up === true && t0.aps[1].observed_up === false && t0.aps[1].evidence_source == 'uci_only' && cl_wifi.parent_id == 'ap:wlan1' && cl_wifi.evidence_source == 'hostapd', 'P4F-WIFI[configured_vs_observed_and_station_link]');

// 5. Unknown client attachment is NEVER fabricated as AP
let cl_unk = t0.clients[2];
check(cl_unk.parent_id == 'unknown' && cl_unk.attachment_type == 'unknown' && cl_unk.evidence_source == 'none', 'P4F-REL[unknown_client_not_fabricated_as_ap]');

// 6. WAN classification uses explicit wan_topology + runtime route/addr
check(length(t0.wan_links) == 1 && t0.wan_links[0].device == 'pppoe-wan' && t0.wan_links[0].observed_up === true && t0.wan_links[0].is_default_route === true && t0.wan_links[0].ipv4 == '100.78.127.23/32', 'P4F-WAN[explicit_evidence_and_default_route]');

// 7. Missing ubus response -> unavailable
let s_noubus = {}; for (let k in keys(base_sources)) s_noubus[k] = base_sources[k];
s_noubus.collector_status = { ubus_network: false, wireless: true, clients: true };
let t_noubus = nms_topo.build_live_topology(s_noubus);
check(!t_noubus.ok && t_noubus.completeness == 'unavailable', 'P4F-FAIL[missing_ubus_unavailable]');

// 8. Malformed ip -j link JSON -> safe unavailable without crash
let s_mal = {}; for (let k in keys(base_sources)) s_mal[k] = base_sources[k];
s_mal.ip_link_raw = '{malformed json';
let t_mal = nms_topo.build_live_topology(s_mal);
check(!t_mal.ok && t_mal.completeness == 'unavailable' && index(t_mal.missing_sources, 'ip_link') >= 0, 'P4F-FAIL[malformed_json_safe]');

// 9. Disappearing WAN interface flagged in conflicts
let s_dis = {}; for (let k in keys(base_sources)) s_dis[k] = base_sources[k];
s_dis.wan_topology = { wan_ifaces: { 'eth9': true }, lan_ifaces: {} };
let t_dis = nms_topo.build_live_topology(s_dis);
check(length(t_dis.wan_links) == 1 && t_dis.wan_links[0].observed_up === false && length(t_dis.conflicts) >= 1 && t_dis.conflicts[0].type == 'disappeared_wan_interface', 'P4F-CONFLICT[disappeared_wan_interface]');

// 10. Stale FDB entry marks client stale & offline (never online)
let s_stale = {}; for (let k in keys(base_sources)) s_stale[k] = base_sources[k];
s_stale.fdb_raw = "aa:bb:cc:dd:ee:02 dev eth1 master br-lan stale\n";
let t_stale = nms_topo.build_live_topology(s_stale);
check(t_stale.clients[1].stale === true && t_stale.clients[1].online === false && t_stale.clients[1].evidence_source == 'fdb_stale', 'P4F-STALE[stale_fdb_never_marked_online]');

// 11. Duplicate MAC in FDB & client inventory flagged in conflicts
let s_dup = {}; for (let k in keys(base_sources)) s_dup[k] = base_sources[k];
s_dup.fdb_raw = "aa:bb:cc:dd:ee:02 dev eth1 master br-lan\naa:bb:cc:dd:ee:02 dev wlan1 master br-lan\n";
let t_dup = nms_topo.build_live_topology(s_dup);
check(t_dup.clients[1].conflict === true && length(t_dup.conflicts) >= 1 && t_dup.conflicts[0].type == 'duplicate_mac_fdb', 'P4F-CONFLICT[duplicate_mac_detected]');

// 12. Conflicting sysfs bridge vs ip link master flagged
let s_bconf = {}; for (let k in keys(base_sources)) s_bconf[k] = base_sources[k];
s_bconf.bridges = [{ name: 'br-guest', ports: ['eth1'] }];
let t_bconf = nms_topo.build_live_topology(s_bconf);
check(length(t_bconf.conflicts) >= 1 && t_bconf.conflicts[0].type == 'bridge_membership_conflict', 'P4F-CONFLICT[bridge_membership_conflict]');

// 13. Partial collector failure (bridge_vlan missing) -> partial=true + missing_sources
let s_part = {}; for (let k in keys(base_sources)) s_part[k] = base_sources[k];
s_part.bridge_vlan_raw = null;
let t_part = nms_topo.build_live_topology(s_part);
check(t_part.ok && t_part.partial === true && t_part.completeness == 'partial' && index(t_part.missing_sources, 'bridge_vlan') >= 0, 'P4F-PARTIAL[missing_bridge_vlan_reported]');

// 14. Last valid topology preserved as stale when refresh fails within max_stale_ms, expired beyond max_stale_ms
let sel_stale = nms_topo.select_topology_snapshot(t_noubus, t0, 25000, 120000);
let sel_exp = nms_topo.select_topology_snapshot(t_noubus, t0, 200000, 120000);
check(sel_stale.ok && sel_stale.stale === true && sel_stale.refresh_failed === true && sel_stale.stale_age_ms == 15000 && length(sel_stale.clients) == 3 && !sel_exp.ok && sel_exp.completeness == 'unavailable', 'P4F-RESIL[preserves_last_valid_as_stale_then_expires]');

// 15. Role-based redaction protects MAC/IP/conflicts for readonly, preserves for admin
let fake_sha = function(s) { return 'abcdef0123456789'; };
let red_ro = nms_topo.redact_topology_for_role(t_dup, 'readonly', 'boot1', fake_sha);
let red_ad = nms_topo.redact_topology_for_role(t_dup, 'admin', 'boot1', fake_sha);
check(red_ro.clients[0].mac == 'HIDDEN' && substr(red_ro.clients[0].ip, 0, 7) == 'PSEUDO-' && length(red_ro.conflicts) == 0 && red_ad.clients[0].mac == 'aa:bb:cc:dd:ee:01' && length(red_ad.conflicts) > 0, 'P4F-RBAC[readonly_redacted_admin_full]');

// 16. P1-1: Wireless interface classification distinguishes AP vs STA, mesh, monitor, unknown, and mode mismatch
let s_wmodes = {}; for (let k in keys(base_sources)) s_wmodes[k] = base_sources[k];
s_wmodes.uci_wireless = [
	{ ifname: 'wlan1', device: 'radio0', ssid: 'HomeAP', mode: 'ap', disabled: false },
	{ ifname: 'wlan_sta', device: 'radio1', ssid: 'Uplink', mode: 'sta', disabled: false },
	{ ifname: 'wlan_mesh', device: 'radio1', ssid: 'MeshNet', mode: 'mesh', disabled: false },
	{ ifname: 'wlan_mon', device: 'radio1', ssid: '', mode: 'monitor', disabled: false },
	{ ifname: 'wlan_unk', device: 'radio1', ssid: 'Mystery', mode: '', disabled: false },
	{ ifname: 'wlan_mis', device: 'radio1', ssid: 'Mismatch', mode: 'ap', disabled: false }
];
s_wmodes.runtime_ap_ifs = {
	wlan1: { up: true, radio: 'radio0', mode: 'ap', ssid: 'HomeAP' },
	wlan_sta: { up: true, radio: 'radio1', mode: 'sta', ssid: 'Uplink' },
	wlan_mesh: { up: true, radio: 'radio1', mode: 'mesh', ssid: 'MeshNet' },
	wlan_mon: { up: true, radio: 'radio1', mode: 'monitor', ssid: '' },
	wlan_mis: { up: true, radio: 'radio1', mode: 'sta', ssid: 'Mismatch' }
};
s_wmodes.wifi_stations = {
	'aa:bb:cc:dd:ee:01': { ifname: 'wlan1', signal: -50 },
	'aa:bb:cc:dd:ee:03': { ifname: 'wlan_sta', signal: -60 } // station on STA iface must NOT link as AP client
};
let t_wm = nms_topo.build_live_topology(s_wmodes);
let ap_names = map(t_wm.aps, (a) => a.ifname);
let has_mis_conflict = length(filter(t_wm.conflicts, (cf) => cf.type == 'wireless_mode_mismatch')) == 1;
check(
	length(t_wm.aps) == 1 && ap_names[0] == 'wlan1' && length(t_wm.wireless_ifaces) == 6 &&
	has_mis_conflict && t_wm.clients[0].parent_id == 'ap:wlan1' && t_wm.clients[2].parent_id != 'ap:wlan_sta',
	'P4F-WIFI[ap_vs_sta_mesh_monitor_unknown_and_mismatch]'
);

// 17. P1-2: Separate administrative UP from operational connectivity (operstate & carrier)
let link_cases = sprintf('%J', [
	{ ifname: 'if_op_down', operstate: 'DOWN', flags: ['UP'], address: '02:00:00:00:00:01' },
	{ ifname: 'if_lldown', operstate: 'LOWERLAYERDOWN', flags: ['UP'], address: '02:00:00:00:00:02' },
	{ ifname: 'if_miss_op', flags: ['UP'], address: '02:00:00:00:00:03' },
	{ ifname: 'if_nocarrier', operstate: 'UP', flags: ['UP'], address: '02:00:00:00:00:04' },
	{ ifname: 'if_adm_down', operstate: 'DOWN', flags: [], address: '02:00:00:00:00:05' },
	{ ifname: 'if_true_up', operstate: 'UP', flags: ['UP', 'LOWER_UP'], address: '02:00:00:00:00:06' }
]);
let pl = nms_topo.parse_ip_links(link_cases, { if_nocarrier: false, if_true_up: true });
check(
	pl.ok &&
	pl.links.if_op_down.admin_up === true && pl.links.if_op_down.operational_up === false && pl.links.if_op_down.connectivity_state == 'down' &&
	pl.links.if_lldown.admin_up === true && pl.links.if_lldown.operational_up === false && pl.links.if_lldown.connectivity_state == 'lowerlayerdown' &&
	pl.links.if_miss_op.admin_up === true && pl.links.if_miss_op.operational_up === false && pl.links.if_miss_op.connectivity_state == 'unknown' &&
	pl.links.if_nocarrier.admin_up === true && pl.links.if_nocarrier.operational_up === false && pl.links.if_nocarrier.connectivity_state == 'no_carrier' &&
	pl.links.if_adm_down.admin_up === false && pl.links.if_adm_down.operational_up === false && pl.links.if_adm_down.connectivity_state == 'admin_down' &&
	pl.links.if_true_up.admin_up === true && pl.links.if_true_up.operational_up === true && pl.links.if_true_up.connectivity_state == 'up',
	'P4F-LINK[admin_up_vs_operational_connectivity_all_6_cases]'
);

// 18. P1-2 applied to WAN: WAN with UP flag but operstate=DOWN must have observed_up=false
let s_wandown = {}; for (let k in keys(base_sources)) s_wandown[k] = base_sources[k];
s_wandown.ip_link_raw = sprintf('%J', [{ ifname: 'pppoe-wan', operstate: 'DOWN', flags: ['UP'], address: '' }]);
let t_wd = nms_topo.build_live_topology(s_wandown);
check(t_wd.wan_links[0].admin_up === true && t_wd.wan_links[0].observed_up === false && t_wd.wan_links[0].connectivity_state == 'down', 'P4F-WAN[admin_up_operstate_down_not_connected]');

// 19. P1-3a: exec_argv_async gives SIGTERM grace period before SIGKILL (process trapping TERM exits cleanly without SIGKILL)
uloop.init();
let exec_cb_count = 0;
let exec_res = null;
h_exec.exec_argv_async('/bin/sh', ['-c', 'trap "exit 0" TERM; /bin/sleep 5'], 150, 65536, function(r) {
	exec_cb_count++;
	exec_res = r;
	uloop.timer(50, function() { uloop.end(); });
});
uloop.run();
let all_pids_dead = true;
for (let kp in (exec_res && exec_res.killed_pids ? exec_res.killed_pids : [])) {
	if (fs.stat('/proc/' + kp)) all_pids_dead = false;
}
check(
	exec_cb_count == 1 && exec_res && exec_res.ok === false && exec_res.error_code == 'TIMEOUT' &&
	exec_res.killed === true && (exec_res.grace_ms || 0) >= 100 &&
	length(exec_res.sigterm_pids || []) >= 1 && length(exec_res.sigkill_pids || []) < length(exec_res.sigterm_pids || []) &&
	all_pids_dead,
	'P4F-EXEC[sigterm_grace_period_allows_clean_exit]',
	sprintf('%J', exec_res)
);

// 20. P1-3b: exec_argv_async escalates to SIGKILL after grace period for TERM-ignoring recursive process tree
uloop.init();
let exec2_cb_count = 0;
let exec2_res = null;
h_exec.exec_argv_async('/bin/sh', ['-c', 'trap "" TERM; /bin/sleep 5'], 150, 65536, function(r) {
	exec2_cb_count++;
	exec2_res = r;
	uloop.timer(50, function() { uloop.end(); });
});
uloop.run();
let all_pids2_dead = true;
for (let kp in (exec2_res && exec2_res.killed_pids ? exec2_res.killed_pids : [])) {
	if (fs.stat('/proc/' + kp)) all_pids2_dead = false;
}
check(
	exec2_cb_count == 1 && exec2_res && exec2_res.ok === false && exec2_res.error_code == 'TIMEOUT' &&
	exec2_res.killed === true && (exec2_res.grace_ms || 0) >= 100 &&
	length(exec2_res.killed_pids || []) >= 2 && length(exec2_res.sigkill_pids || []) >= 1 &&
	all_pids2_dead,
	'P4F-EXEC[sigkill_after_grace_period_kills_recursive_tree]',
	sprintf('%J', exec2_res)
);

// 21. Deterministic regression: timeout fires with unavailable worker PID, cleanup runs, then delayed worker starts -> command never executes
import * as h_race from '/tmp/p3a_test/helperd_exec_race_prod.uc';
let race_marker = '/tmp/p3a_test/vec/race_should_not_exist';
if (fs.stat(race_marker)) fs.unlink(race_marker);
let race_res = null;
let race_cb_count = 0;
h_race.exec_argv_async('/bin/touch', [race_marker], 150, 65536, function(r) {
	race_cb_count++;
	race_res = r;
});
// Step 1: Timeout fires before worker starts (PID is null), kill_pid_tree(null) + on_done runs immediately
h_race.sched.timer_fn();
// Step 2: Delayed worker attempts to start AFTER timeout & cleanup
let delayed_rc = h_race.sched.worker_fn();
// Step 3: Worker completion callback runs in parent to clean up cancel_file
h_race.sched.done_fn(delayed_rc);
check(
	race_cb_count == 1 && race_res && race_res.ok === false && race_res.error_code == 'TIMEOUT' &&
	race_res.killed === false && delayed_rc == 124 && !fs.stat(race_marker),
	'P4F-EXEC[delayed_worker_after_timeout_never_executes]',
	sprintf('delayed_rc=%d marker=%J res=%J', delayed_rc, !!fs.stat(race_marker), race_res)
);

printf('UCODE4F_SUMMARY: %d passed, %d failed\n', passed, failed);
exit(failed == 0 ? 0 : 1);
