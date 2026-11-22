// NMS Phase 4A: Portable Multi-Bridge, IPv4/IPv6 Neighbour, Bridge FDB, Wi-Fi Station & CPU Discovery
import * as fs from 'fs';

const MAX_CLIENTS = 256;
const MAX_IPS_PER_CLIENT = 8;
const MAX_FDB_ENTRIES = 1024;

export function is_valid_mac_addr(mac) {
	return match(lc(trim('' + (mac || ''))), /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/) != null;
};

export function is_unicast_mac(mac) {
	let m = lc(trim('' + (mac || '')));
	if (!is_valid_mac_addr(m) || m == '00:00:00:00:00:00' || m == 'ff:ff:ff:ff:ff:ff') return false;
	let first_octet = hex(substr(m, 0, 2));
	if ((first_octet & 1) == 1) return false; // multicast/broadcast
	return true;
};

export function detect_cpu_model(cpuinfo_raw, board_system) {
	let raw = '' + (cpuinfo_raw || '');
	for (let key in ['model name', 'Hardware', 'system type', 'Processor', 'machine']) {
		for (let ln in split(raw, '\n')) {
			let parts = split(ln, ':', 2);
			if (length(parts) == 2 && trim(parts[0]) == key) {
				let val = trim(parts[1]);
				if (val != '') return val;
			}
		}
	}
	let bs = trim('' + (board_system || ''));
	if (bs != '') return bs;
	return 'Unknown CPU';
};

export function discover_bridges_from_sysfs(net_dir, fs_ops) {
	let ops = fs_ops || fs;
	let dir = net_dir || '/sys/class/net';
	let entries = ops.lsdir(dir);
	if (type(entries) != 'array') return [];
	let bridges = [];
	for (let ifname in entries) {
		if (!ifname || ifname == '.' || ifname == '..' || ifname == 'lo') continue;
		if (ops.stat(dir + '/' + ifname + '/bridge')) {
			push(bridges, ifname);
		}
	}
	sort(bridges);
	return bridges;
};

export function parse_ip_neigh(raw, family) {
	let out = [];
	for (let raw_ln in split('' + (raw || ''), '\n')) {
		let ln = trim(raw_ln);
		if (ln == '') continue;
		let parts = split(ln, /\s+/);
		if (length(parts) < 3) continue;
		let ip = parts[0];
		if (family == 4 && !match(ip, /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)) continue;
		if (family == 6 && index(ip, ':') < 0) continue;
		let dev = '';
		let mac = '';
		let state = '';
		for (let i = 1; i < length(parts); i++) {
			if (parts[i] == 'dev' && i + 1 < length(parts)) { dev = parts[i + 1]; i++; continue; }
			if (parts[i] == 'lladdr' && i + 1 < length(parts)) { mac = lc(parts[i + 1]); i++; continue; }
		}
		state = uc(parts[length(parts) - 1]);
		if (!is_unicast_mac(mac)) continue;
		let online = (state == 'REACHABLE' || state == 'DELAY' || state == 'PROBE' || state == 'STALE');
		push(out, {
			ip: ip,
			mac: mac,
			dev: dev,
			state: state,
			family: family,
			online: online
		});
	}
	return out;
};

export function parse_bridge_fdb(raw, local_macs) {
	let by_mac = {};
	let count = 0;
	let rmacs = (type(local_macs) == 'object') ? local_macs : {};
	for (let raw_ln in split('' + (raw || ''), '\n')) {
		if (count >= MAX_FDB_ENTRIES) break;
		let ln = trim(raw_ln);
		if (ln == '') continue;
		let parts = split(ln, /\s+/);
		if (length(parts) < 3) continue;
		let mac = lc(parts[0]);
		if (!is_unicast_mac(mac) || rmacs[mac]) continue;
		let is_self = false;
		let is_perm = false;
		let port = '';
		let bridge = '';
		let vlan = null;
		for (let i = 1; i < length(parts); i++) {
			if (parts[i] == 'self') is_self = true;
			else if (parts[i] == 'permanent') is_perm = true;
			else if (parts[i] == 'dev' && i + 1 < length(parts)) { port = parts[i + 1]; i++; }
			else if (parts[i] == 'master' && i + 1 < length(parts)) { bridge = parts[i + 1]; i++; }
			else if (parts[i] == 'vlan' && i + 1 < length(parts)) { vlan = int(+parts[i + 1]); i++; }
		}
		// Skip router-local 'self' entries (or 'permanent' entries without a master bridge), preserve legitimate static client FDB entries
		if (is_self || port == '' || (is_perm && bridge == '')) continue;
		if (!by_mac[mac]) {
			by_mac[mac] = { mac: mac, port: port, bridge: bridge, vlan: vlan, static_fdb: is_perm };
			count++;
		}
	}
	return by_mac;
};

export function parse_wifi_stations(wireless_status, hostapd_clients_map) {
	let out = {};
	if (type(wireless_status) != 'object' || type(hostapd_clients_map) != 'object') return out;
	let if_meta = {};
	for (let radio in keys(wireless_status)) {
		let rinfo = wireless_status[radio];
		if (!rinfo || type(rinfo.interfaces) != 'array') continue;
		let band = (rinfo.config && rinfo.config.band) ? ('' + rinfo.config.band) : '';
		for (let itf in rinfo.interfaces) {
			if (!itf || !itf.ifname) continue;
			if_meta[itf.ifname] = {
				radio: radio,
				band: band,
				ssid: (itf.config && itf.config.ssid) ? ('' + itf.config.ssid) : ''
			};
		}
	}
	for (let ifname in keys(hostapd_clients_map)) {
		let hc = hostapd_clients_map[ifname];
		if (!hc || type(hc.clients) != 'object') continue;
		let meta = if_meta[ifname] || { radio: '', band: '', ssid: '' };
		for (let raw_mac in keys(hc.clients)) {
			let mac = lc(trim(raw_mac));
			if (!is_unicast_mac(mac)) continue;
			let st = hc.clients[raw_mac] || {};
			let auth_val = (st.authorized === true) ? true : (st.authorized === false ? false : null);
			let auth_state = (auth_val === true) ? 'authorized' : (auth_val === false ? 'unauthorized' : 'unknown');
			out[mac] = {
				ifname: ifname,
				radio: meta.radio,
				band: meta.band,
				ssid: meta.ssid,
				rssi: st.signal != null ? int(+st.signal) : null,
				authorized: auth_val,
				auth_state: auth_state
			};
		}
	}
	return out;
};

function add_source(c, src) {
	if (index(c.sources, src) < 0) push(c.sources, src);
}

function add_ip_to_client(c, ip, is_v6) {
	if (!ip || ip == '') return;
	if (index(c.ips, ip) < 0) {
		if (length(c.ips) < MAX_IPS_PER_CLIENT) push(c.ips, ip);
		else c.overflow_ips = true;
	}
	if (!is_v6 && (c.ip == '' || index(c.ip, ':') >= 0)) {
		c.ip = ip;
	} else if (c.ip == '') {
		c.ip = ip;
	}
	if (is_v6 && index(c.ipv6, ip) < 0 && length(c.ipv6) < MAX_IPS_PER_CLIENT) {
		push(c.ipv6, ip);
	}
}

export function merge_discovered_clients(inputs) {
	let inp = inputs || {};
	let by_mac = {};
	let bridge_set = {};
	if (type(inp.bridges) == 'array') {
		for (let b in inp.bridges) if (b && b != '') bridge_set[b] = true;
	}

	let ensure_client = function(mac, fallback_ip) {
		if (!is_unicast_mac(mac)) return null;
		if (!by_mac[mac]) {
			if (length(keys(by_mac)) >= MAX_CLIENTS) return null;
			by_mac[mac] = {
				mac: mac,
				ip: fallback_ip || '',
				ipv6: [],
				ips: [],
				hostname: '',
				online: false,
				arp_state: 'UNKNOWN',
				blocked: false,
				overflow_ips: false,
				interface: '',
				bridge: '',
				port: '',
				link_type: 'unknown',
				ssid: null,
				rssi: null,
				band: null,
				wifi_auth: null,
				sources: []
			};
		}
		return by_mac[mac];
	};

	// 1. DHCP leases
	for (let line in split('' + (inp.leases_raw || ''), '\n')) {
		let p = split(trim(line), /\s+/);
		if (length(p) < 4) continue;
		let mac = lc(p[1]), ip = p[2], hn = p[3] != '*' ? p[3] : '';
		let c = ensure_client(mac, ip);
		if (!c) continue;
		add_ip_to_client(c, ip, index(ip, ':') >= 0);
		if (hn != '' && c.hostname == '') c.hostname = hn;
		if (c.arp_state == 'UNKNOWN') c.arp_state = 'LEASED';
		add_source(c, 'dhcp');
	}

	// 2. IPv4 Neighbours (keep interface separate from bridge; only populate bridge if dev is a proven bridge)
	for (let n4 in parse_ip_neigh(inp.neigh4 || '', 4)) {
		let c = ensure_client(n4.mac, n4.ip);
		if (!c) continue;
		add_ip_to_client(c, n4.ip, false);
		if (n4.dev != '') {
			if (c.interface == '') c.interface = n4.dev;
			if (bridge_set[n4.dev] && c.bridge == '') c.bridge = n4.dev;
		}
		if (n4.online) c.online = true;
		if (c.arp_state == 'UNKNOWN' || c.arp_state == 'LEASED' || n4.online) c.arp_state = n4.state;
		add_source(c, 'neigh4');
	}

	// 3. IPv6 Neighbours
	for (let n6 in parse_ip_neigh(inp.neigh6 || '', 6)) {
		let c = ensure_client(n6.mac, n6.ip);
		if (!c) continue;
		add_ip_to_client(c, n6.ip, true);
		if (n6.dev != '') {
			if (c.interface == '') c.interface = n6.dev;
			if (bridge_set[n6.dev] && c.bridge == '') c.bridge = n6.dev;
		}
		if (n6.online) c.online = true;
		if (c.arp_state == 'UNKNOWN' || c.arp_state == 'LEASED') c.arp_state = n6.state;
		add_source(c, 'neigh6');
	}

	// 4. Bridge FDB (L2 port & actual master bridge discovery)
	let fdb_map = (type(inp.fdb_map) == 'object') ? inp.fdb_map : parse_bridge_fdb(inp.fdb_raw || '', inp.local_macs);
	for (let mac in keys(fdb_map)) {
		let f = fdb_map[mac];
		let c = ensure_client(mac, '');
		if (!c) continue;
		if (f.port != '') c.port = f.port;
		if (f.bridge != '') c.bridge = f.bridge;
		if (c.link_type == 'unknown') c.link_type = 'wired';
		add_source(c, 'fdb');
	}

	// 5. Wi-Fi Stations (never mark online when authorization is unknown or false)
	let wifi_map = (type(inp.wifi_stations) == 'object') ? inp.wifi_stations : {};
	for (let mac in keys(wifi_map)) {
		let w = wifi_map[mac];
		let c = ensure_client(mac, '');
		if (!c) continue;
		c.link_type = 'wifi';
		if (w.ifname) c.port = w.ifname;
		if (w.ssid != null && w.ssid != '') c.ssid = w.ssid;
		if (w.rssi != null) c.rssi = w.rssi;
		if (w.band != null && w.band != '') c.band = w.band;
		c.wifi_auth = w.auth_state || (w.authorized === true ? 'authorized' : (w.authorized === false ? 'unauthorized' : 'unknown'));
		if (w.authorized === true) c.online = true;
		add_source(c, 'wifi');
	}

	let rules = inp.rules || { blocked_macs: {}, blocked_ips: {}, nicknames: {}, rate_limits: {} };
	let st_leases = inp.static_leases || {};
	let nlbw_mac = inp.nlbw_by_mac || {};
	let nlbw_ip = inp.nlbw_by_ip || {};

	let list = [];
	for (let mac in keys(by_mac)) {
		let c = by_mac[mac];
		c.blocked = !!rules.blocked_macs[mac];
		c.nickname = (rules.nicknames && rules.nicknames[mac]) || '';
		c.static_lease = !!st_leases[mac];
		c.rate_limit_kbps = (rules.rate_limits && rules.rate_limits[c.ip]) ? +rules.rate_limits[c.ip] : 0;
		c.display_name = c.nickname || c.hostname || ('جهاز ' + (c.ip || mac));
		let nb = nlbw_mac[mac] || (c.ip != '' ? nlbw_ip[c.ip] : null) || { rx_bytes: 0, tx_bytes: 0, conns: 0 };
		c.total_rx_bytes = +nb.rx_bytes || 0;
		c.total_tx_bytes = +nb.tx_bytes || 0;
		c.total_conns = +nb.conns || 0;
		push(list, c);
	}
	return list;
};
