// Executed directly by OpenWrt 24.10.0 & 25.12.6 ucode runtime against production backend/nms_topology.uc
import * as nms_topo from '/tmp/p3a_test/nms_topology.uc';

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
		{ ifname: 'wlan1', device: 'radio0', ssid: 'HomeAP', disabled: false },
		{ ifname: 'wlan2', device: 'radio1', ssid: 'DisabledAP', disabled: true }
	],
	runtime_ap_ifs: { wlan1: { up: true, radio: 'radio0', ssid: 'HomeAP' } },
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

printf('UCODE4F_SUMMARY: %d passed, %d failed\n', passed, failed);
exit(failed == 0 ? 0 : 1);
