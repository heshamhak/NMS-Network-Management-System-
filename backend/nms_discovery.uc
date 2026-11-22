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

const MAX_RATE_CACHE = 512;
const RATE_STALE_MS = 300000;

export function compute_client_rates(clients, prev_map, now_ms, flow_offloading, nlbw_ok) {
	if (type(clients) != 'array') return clients;
	let pmap = (type(prev_map) == 'object') ? prev_map : {};
	let counters_ok = !flow_offloading && !!nlbw_ok;
	let reason_unavail = flow_offloading ? 'flow_offloading' : 'nlbw_unavailable';

	// Prune stale entries to keep memory bounded
	for (let k in keys(pmap)) {
		if ((now_ms - pmap[k].ts_ms) > RATE_STALE_MS) delete pmap[k];
	}

	for (let c in clients) {
		if (!counters_ok) {
			c.rate_supported = false;
			c.rx_bps = null;
			c.tx_bps = null;
			c.rate_reason = reason_unavail;
			continue;
		}
		let key = c.mac || c.ip || '';
		let rx = +c.total_rx_bytes || 0;
		let tx = +c.total_tx_bytes || 0;
		let prev = key != '' ? pmap[key] : null;
		c.rate_supported = true;
		if (!prev) {
			c.rx_bps = null;
			c.tx_bps = null;
			c.rate_reason = 'pending_baseline';
		} else {
			let dt = now_ms - prev.ts_ms;
			if (rx < prev.rx || tx < prev.tx) {
				c.rx_bps = null;
				c.tx_bps = null;
				c.rate_reason = 'counter_reset';
			} else if (dt < 500) {
				c.rx_bps = prev.last_rx_bps != null ? prev.last_rx_bps : null;
				c.tx_bps = prev.last_tx_bps != null ? prev.last_tx_bps : null;
				c.rate_reason = c.rx_bps != null ? 'ok' : 'pending_baseline';
			} else {
				c.rx_bps = int(((rx - prev.rx) * 8 * 1000) / dt);
				c.tx_bps = int(((tx - prev.tx) * 8 * 1000) / dt);
				c.rate_reason = 'ok';
			}
		}
		if (key != '' && (pmap[key] || length(keys(pmap)) < MAX_RATE_CACHE)) {
			let is_reset = prev && (rx < prev.rx || tx < prev.tx);
			if (is_reset) {
				pmap[key] = { rx: rx, tx: tx, ts_ms: now_ms, last_rx_bps: null, last_tx_bps: null };
			} else if (!prev || (now_ms - prev.ts_ms) >= 500) {
				pmap[key] = { rx: rx, tx: tx, ts_ms: now_ms, last_rx_bps: c.rx_bps, last_tx_bps: c.tx_bps };
			}
		}
	}
	return clients;
};

export function collect_cpu_from_proc(raw, mono, state) {
	if (type(state) != 'object') state = {};
	if (type(state.prev_cpu) != 'object') state.prev_cpu = {};
	if (type(state.last_cpu_pct) != 'object') state.last_cpu_pct = {};
	if (state.last_steal_pct == null) state.last_steal_pct = 0;

	let cores = [];
	let total_pct = null;
	let total_status = 'unknown';
	let steal_pct = state.last_steal_pct;

	for (let line in split(raw || '', '\n')) {
		let p = split(trim(line), /\s+/);
		if (length(p) < 8 || !match(p[0], /^cpu[0-9]*$/)) continue;
		let name = p[0];
		let user = +p[1], nice = +p[2], sys = +p[3], idle = +p[4], iowait = +p[5], irq = +p[6], softirq = +p[7], steal = length(p) > 8 ? +p[8] : 0;
		let total = user + nice + sys + idle + iowait + irq + softirq + steal;
		let busy = total - idle - iowait - steal;

		let pct = state.last_cpu_pct[name] != null ? state.last_cpu_pct[name] : null;
		let st = pct != null ? 'ok' : 'unknown';
		if (!state.prev_cpu[name]) {
			state.prev_cpu[name] = { total: total, busy: busy, steal: steal, mono: mono };
		} else {
			let dt = total - state.prev_cpu[name].total;
			let db = busy - state.prev_cpu[name].busy;
			let ds = steal - state.prev_cpu[name].steal;
			let elapsed_sample = mono - state.prev_cpu[name].mono;
			if (dt > 0 && elapsed_sample >= 800) {
				pct = int((db * 1000) / dt) / 10.0;
				if (pct < 0) pct = 0;
				if (pct > 100) pct = 100;
				st = 'ok';
				state.last_cpu_pct[name] = pct;
				if (name == 'cpu') {
					steal_pct = int((ds * 1000) / dt) / 10.0;
					if (steal_pct < 0) steal_pct = 0;
					state.last_steal_pct = steal_pct;
				}
				state.prev_cpu[name] = { total: total, busy: busy, steal: steal, mono: mono };
			}
		}
		if (name == 'cpu') {
			total_pct = pct;
			total_status = st;
		} else {
			push(cores, { name: name, pct: pct, status: st });
		}
	}
	if (state.boot_cpu_cores == null && length(cores) > 0) state.boot_cpu_cores = length(cores);
	let exp_cores = state.boot_cpu_cores != null ? state.boot_cpu_cores : length(cores);
	return {
		raw_total_pct: total_pct,
		total_status: total_status,
		total_pct: total_pct != null ? total_pct : 0,
		steal_pct: steal_pct,
		detected_cores: length(cores),
		expected_cores: exp_cores,
		core_drift: length(cores) != exp_cores,
		cores: cores
	};
};
