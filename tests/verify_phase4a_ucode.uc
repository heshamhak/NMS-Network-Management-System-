// Executed directly by OpenWrt 24.10.0 & 25.12.6 ucode runtime against production backend/nms_discovery.uc
import * as fs from 'fs';
import * as nms_discovery from '/tmp/p3a_test/nms_discovery.uc';

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

// 1. Portable CPU model detection (no hardcoded J4125 fallback)
check(nms_discovery.detect_cpu_model("Hardware\t: MediaTek MT7622\n", "") == "MediaTek MT7622", 'P4A-CPU[arm_hardware]');
check(nms_discovery.detect_cpu_model("system type\t: MediaTek MT7621 ver:1 eco:3\n", "") == "MediaTek MT7621 ver:1 eco:3", 'P4A-CPU[mips_system_type]');
check(nms_discovery.detect_cpu_model("", "ARMv8 Processor") == "ARMv8 Processor", 'P4A-CPU[board_system_fallback]');
check(nms_discovery.detect_cpu_model("", "") == "Unknown CPU", 'P4A-CPU[unknown_fallback_no_j4125]');

// 2. Multi-bridge sysfs discovery (no br-lan assumption)
let net_mock = vec_dir + '/sys_net';
fs.mkdir(net_mock);
for (let d in ['lo', 'eth0', 'br-lan', 'br-guest']) fs.mkdir(net_mock + '/' + d);
fs.mkdir(net_mock + '/br-lan/bridge');
fs.mkdir(net_mock + '/br-guest/bridge');
let bridges = nms_discovery.discover_bridges_from_sysfs(net_mock);
check(length(bridges) == 2 && bridges[0] == 'br-guest' && bridges[1] == 'br-lan', 'P4A-BRIDGE[multi_bridge_sysfs_discovery]', sprintf('%J', bridges));

// 3. IPv4 & IPv6 neighbour parsing (multi-device, rejects multicast/broadcast, handles FAILED)
let n4_raw = "192.168.1.50 dev br-lan lladdr aa:bb:cc:dd:ee:01 REACHABLE\n" +
             "192.168.10.20 dev br-guest lladdr aa:bb:cc:dd:ee:02 STALE\n" +
             "192.168.1.99 dev br-lan lladdr 01:00:5e:00:00:01 PERMANENT\n" +
             "192.168.1.88 dev br-lan FAILED\n";
let n4_list = nms_discovery.parse_ip_neigh(n4_raw, 4);
check(length(n4_list) == 2 && n4_list[0].dev == 'br-lan' && n4_list[1].dev == 'br-guest', 'P4A-NEIGH4[multi_dev_and_filter_multicast]', sprintf('%J', n4_list));

let n6_raw = "fdb6:cd6f:63be::50 dev br-lan lladdr aa:bb:cc:dd:ee:01 REACHABLE\n" +
             "fe80::1234 dev br-guest lladdr aa:bb:cc:dd:ee:03 STALE\n" +
             "fe80::99 dev br-lan lladdr 33:33:00:00:00:01 PERMANENT\n";
let n6_list = nms_discovery.parse_ip_neigh(n6_raw, 6);
check(length(n6_list) == 2 && n6_list[1].mac == 'aa:bb:cc:dd:ee:03' && n6_list[1].family == 6, 'P4A-NEIGH6[parse_and_filter_multicast]', sprintf('%J', n6_list));

// 4. Bridge FDB parsing (skips permanent/self, extracts port/bridge/vlan)
let fdb_raw = "60:be:b4:1e:d3:5d dev eth1 master br-lan permanent\n" +
              "aa:bb:cc:dd:ee:01 dev phy1-ap0 vlan 1 master br-lan\n" +
              "aa:bb:cc:dd:ee:02 dev eth2.10 master br-guest\n";
let fdb_map = nms_discovery.parse_bridge_fdb(fdb_raw, { '60:be:b4:1e:d3:5d': true });
check(fdb_map['60:be:b4:1e:d3:5d'] == null && fdb_map['aa:bb:cc:dd:ee:01'].port == 'phy1-ap0' && fdb_map['aa:bb:cc:dd:ee:02'].bridge == 'br-guest', 'P4A-FDB[extracts_port_bridge_skips_permanent]', sprintf('%J', fdb_map));

// 5. Wi-Fi station parsing + graceful empty fallback
let ws_mock = {
	radio1: { config: { band: '5g' }, interfaces: [{ ifname: 'phy1-ap0', config: { ssid: 'Corp-5G' } }] }
};
let hc_mock = {
	'phy1-ap0': { clients: { 'AA:BB:CC:DD:EE:01': { signal: -54, authorized: true } } }
};
let wmap = nms_discovery.parse_wifi_stations(ws_mock, hc_mock);
check(wmap['aa:bb:cc:dd:ee:01'] && wmap['aa:bb:cc:dd:ee:01'].ssid == 'Corp-5G' && wmap['aa:bb:cc:dd:ee:01'].rssi == -54, 'P4A-WIFI[station_ssid_rssi_band]', sprintf('%J', wmap));
check(length(keys(nms_discovery.parse_wifi_stations(null, null))) == 0, 'P4A-WIFI[graceful_empty_when_absent]');

// 6. Full merge (DHCP + IPv4 + IPv6 + FDB + Wi-Fi, deduplication, no fabricated data, IPv6-only client)
let merged = nms_discovery.merge_discovered_clients({
	leases_raw: "1700000000 aa:bb:cc:dd:ee:01 192.168.1.50 Laptop 01:aa\n",
	neigh4: n4_raw,
	neigh6: n6_raw,
	fdb_raw: fdb_raw,
	local_macs: { '60:be:b4:1e:d3:5d': true },
	wifi_stations: wmap,
	rules: { blocked_macs: {}, blocked_ips: {}, nicknames: { 'aa:bb:cc:dd:ee:01': 'Workstation' }, rate_limits: {} },
	static_leases: {},
	nlbw_by_mac: {},
	nlbw_by_ip: {}
});
let by_m = {};
for (let c in merged) by_m[c.mac] = c;
let c1 = by_m['aa:bb:cc:dd:ee:01'];
let c2 = by_m['aa:bb:cc:dd:ee:02'];
let c3 = by_m['aa:bb:cc:dd:ee:03'];
check(length(merged) == 3 && c1 && c1.ip == '192.168.1.50' && length(c1.ipv6) == 1 && c1.link_type == 'wifi' && c1.ssid == 'Corp-5G' && c1.rssi == -54 && length(c1.sources) == 5, 'P4A-MERGE[dedup_v4_v6_fdb_wifi_5_sources]', sprintf('%J', c1));
check(c2 && c2.link_type == 'wired' && c2.port == 'eth2.10' && c2.bridge == 'br-guest' && c2.ssid == null && c2.rssi == null, 'P4A-MERGE[wired_no_fabricated_wifi]', sprintf('%J', c2));
check(c3 && c3.ip == 'fe80::1234' && length(c3.ipv6) == 1 && c3.online === true && index(c3.sources, 'neigh6') >= 0, 'P4A-MERGE[ipv6_only_client_discovered]', sprintf('%J', c3));

// 7. Resource caps (256 MACs max, 8 IPs per MAC max)
let many_leases = '';
for (let i = 0; i < 270; i++) {
	many_leases += sprintf('1700000000 02:00:00:00:%02x:%02x 192.168.%d.%d host%d *\n', (i >> 8) & 0xff, i & 0xff, 1 + (i >> 8), 10 + (i % 200), i);
}
let capped = nms_discovery.merge_discovered_clients({ leases_raw: many_leases });
check(length(capped) == 256, 'P4A-CAP[enforces_256_mac_limit]', 'len=' + length(capped));

let many_ips_n4 = '';
for (let j = 1; j <= 12; j++) {
	many_ips_n4 += sprintf('192.168.1.%d dev br-lan lladdr 02:11:22:33:44:55 REACHABLE\n', 10 + j);
}
let capped_ips = nms_discovery.merge_discovered_clients({ neigh4: many_ips_n4 });
check(length(capped_ips) == 1 && length(capped_ips[0].ips) == 8 && capped_ips[0].overflow_ips === true, 'P4A-CAP[enforces_8_ips_per_mac_limit]', sprintf('%J', capped_ips[0]));

// 8. Regression tests for Phase 4A Review Findings (P1 Wi-Fi unknown auth, P2 static FDB permanent, P2 interface vs bridge)
let hc_unknown = { 'phy1-ap0': { clients: {
	'AA:BB:CC:DD:EE:10': { signal: -61 },
	'AA:BB:CC:DD:EE:11': { signal: -70, authorized: false }
} } };
let w_unk = nms_discovery.parse_wifi_stations(ws_mock, hc_unknown);
let m_unk = nms_discovery.merge_discovered_clients({ wifi_stations: w_unk });
let unk_by_m = {};
for (let c in m_unk) unk_by_m[c.mac] = c;
check(
	w_unk['aa:bb:cc:dd:ee:10'].authorized === null && w_unk['aa:bb:cc:dd:ee:10'].auth_state == 'unknown'
	&& unk_by_m['aa:bb:cc:dd:ee:10'].online === false && unk_by_m['aa:bb:cc:dd:ee:10'].wifi_auth == 'unknown',
	'P4A-REG[wifi_missing_auth_stays_unknown_and_not_online]', sprintf('%J', unk_by_m['aa:bb:cc:dd:ee:10'])
);
check(
	unk_by_m['aa:bb:cc:dd:ee:11'].online === false && unk_by_m['aa:bb:cc:dd:ee:11'].wifi_auth == 'unauthorized',
	'P4A-REG[wifi_false_auth_stays_not_online]', sprintf('%J', unk_by_m['aa:bb:cc:dd:ee:11'])
);

let fdb_perm_raw = "60:be:b4:1e:d3:5d dev eth1 master br-lan permanent\n" +
                   "02:aa:bb:cc:dd:99 dev br-lan self permanent\n" +
                   "aa:bb:cc:dd:ee:44 dev eth2 master br-lan permanent\n";
let fdb_perm = nms_discovery.parse_bridge_fdb(fdb_perm_raw, { '60:be:b4:1e:d3:5d': true });
check(
	fdb_perm['60:be:b4:1e:d3:5d'] == null && fdb_perm['02:aa:bb:cc:dd:99'] == null
	&& fdb_perm['aa:bb:cc:dd:ee:44'] != null && fdb_perm['aa:bb:cc:dd:ee:44'].static_fdb === true && fdb_perm['aa:bb:cc:dd:ee:44'].bridge == 'br-lan',
	'P4A-REG[fdb_preserves_client_permanent_skips_router_local]', sprintf('%J', fdb_perm)
);

let n4_non_br = "10.20.30.40 dev eth0.10 lladdr aa:bb:cc:dd:ee:55 REACHABLE\n192.168.1.51 dev br-lan lladdr aa:bb:cc:dd:ee:56 REACHABLE\n";
let m_if_br = nms_discovery.merge_discovered_clients({ neigh4: n4_non_br, bridges: ['br-lan'] });
let by_if = {};
for (let c in m_if_br) by_if[c.mac] = c;
check(
	by_if['aa:bb:cc:dd:ee:55'].interface == 'eth0.10' && by_if['aa:bb:cc:dd:ee:55'].bridge == ''
	&& by_if['aa:bb:cc:dd:ee:56'].interface == 'br-lan' && by_if['aa:bb:cc:dd:ee:56'].bridge == 'br-lan',
	'P4A-REG[interface_kept_separate_from_bridge]', sprintf('%J', m_if_br)
);

printf('UCODE4A_SUMMARY: %d passed, %d failed\n', passed, failed);
exit(failed == 0 ? 0 : 1);
