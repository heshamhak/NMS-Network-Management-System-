// Phase 4F: Evidence-Driven Live Topology Builder, Stale/Conflict Handler & Role Redaction
// Zero external dependencies; executed in-process by noc-apid and OpenWrt chroot suites.

const VALID_WIFI_MODES = { 'ap': true, 'sta': true, 'mesh': true, 'monitor': true, 'adhoc': true, 'wds': true };

function safe_json_array(raw) {
	if (!raw || trim(raw) == '') return { ok: false, data: [], error: 'empty' };
	try {
		let parsed = json(raw);
		if (type(parsed) == 'array') return { ok: true, data: parsed, error: null };
		return { ok: false, data: [], error: 'not_array' };
	} catch (e) {
		return { ok: false, data: [], error: 'malformed_json' };
	}
}

export function parse_ip_links(raw, carrier_map) {
	let r = safe_json_array(raw);
	if (!r.ok) return { ok: false, links: {}, error: r.error };
	let cmap = (type(carrier_map) == 'object') ? carrier_map : {};
	let links = {};
	for (let it in r.data) {
		if (!it || type(it) != 'object' || !it.ifname) continue;
		let kind = (it.linkinfo && it.linkinfo.info_kind) ? it.linkinfo.info_kind : '';
		let slave_kind = (it.linkinfo && it.linkinfo.info_slave_kind) ? it.linkinfo.info_slave_kind : '';
		let admin_up = (index(it.flags || [], 'UP') >= 0);
		let operstate = (it.operstate != null && trim('' + it.operstate) != '') ? lc(trim('' + it.operstate)) : 'unknown';
		let carrier = null;
		if (cmap[it.ifname] != null) carrier = !!cmap[it.ifname];
		else if (it.carrier != null) carrier = (it.carrier == 1 || it.carrier === true);

		let operational_up = admin_up && (operstate == 'up') && (carrier !== false);
		let conn_state = 'unknown';
		if (!admin_up) conn_state = 'admin_down';
		else if (carrier === false) conn_state = 'no_carrier';
		else if (operstate == 'down' || operstate == 'lowerlayerdown') conn_state = operstate;
		else if (operstate == 'unknown') conn_state = 'unknown';
		else if (operational_up) conn_state = 'up';
		else conn_state = operstate;

		links[it.ifname] = {
			ifname: it.ifname,
			admin_up: admin_up,
			operstate: operstate,
			carrier: carrier,
			operational_up: operational_up,
			connectivity_state: conn_state,
			mac: lc(it.address || ''),
			master: it.master || '',
			kind: kind,
			slave_kind: slave_kind,
			link: it.link || '',
			vlan_id: (it.linkinfo && it.linkinfo.info_data && it.linkinfo.info_data.id != null) ? +it.linkinfo.info_data.id : null
		};
	}
	return { ok: true, links: links, error: null };
};

export function parse_ip_addrs(raw) {
	let r = safe_json_array(raw);
	if (!r.ok) return { ok: false, addrs: {}, error: r.error };
	let addrs = {};
	for (let it in r.data) {
		if (!it || type(it) != 'object' || !it.ifname) continue;
		let v4 = [], v6 = [];
		for (let ai in (it.addr_info || [])) {
			if (!ai || !ai.local) continue;
			if (ai.family == 'inet') push(v4, ai.local + '/' + (ai.prefixlen || 24));
			else if (ai.family == 'inet6') push(v6, ai.local + '/' + (ai.prefixlen || 64));
		}
		addrs[it.ifname] = { ipv4: v4, ipv6: v6 };
	}
	return { ok: true, addrs: addrs, error: null };
};

export function parse_ip_routes(raw) {
	let r = safe_json_array(raw);
	if (!r.ok) return { ok: false, defaults: [], error: r.error };
	let defaults = [];
	for (let rt in r.data) {
		if (!rt || type(rt) != 'object') continue;
		if (rt.dst == 'default' && rt.dev) {
			push(defaults, {
				dev: rt.dev,
				gateway: rt.gateway || '',
				metric: rt.metric != null ? +rt.metric : 0,
				protocol: rt.protocol || ''
			});
		}
	}
	return { ok: true, defaults: defaults, error: null };
};

export function parse_bridge_vlans(raw) {
	let r = safe_json_array(raw);
	if (!r.ok) return { ok: false, vlans_by_dev: {}, error: r.error };
	let by_dev = {};
	for (let item in r.data) {
		if (!item || type(item) != 'object' || !item.ifname) continue;
		let list = [];
		for (let v in (item.vlans || [])) {
			if (!v || v.vlan == null) continue;
			let flags = type(v.flags) == 'array' ? v.flags : [];
			push(list, {
				vlan: +v.vlan,
				pvid: (index(flags, 'PVID') >= 0),
				untagged: (index(flags, 'Egress Untagged') >= 0)
			});
		}
		by_dev[item.ifname] = list;
	}
	return { ok: true, vlans_by_dev: by_dev, error: null };
};

export function parse_fdb_entries(fdb_raw) {
	let by_mac = {};
	let conflicts = [];
	for (let ln in split(fdb_raw || '', '\n')) {
		let p = filter(split(trim(ln), ' '), (x) => x != '');
		if (length(p) < 3) continue;
		let mac = lc(p[0]);
		if (!match(mac, /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/)) continue;
		if (index(p, 'self') >= 0 || index(p, 'permanent') >= 0) continue;
		let dev = '';
		let master = '';
		let is_stale = (index(p, 'stale') >= 0);
		for (let i = 1; i < length(p) - 1; i++) {
			if (p[i] == 'dev') dev = p[i + 1];
			else if (p[i] == 'master') master = p[i + 1];
		}
		if (dev == '') continue;
		if (by_mac[mac] && by_mac[mac].dev != dev) {
			push(conflicts, {
				type: 'duplicate_mac_fdb',
				mac: mac,
				detail: 'MAC observed on multiple ports: ' + by_mac[mac].dev + ' and ' + dev,
				ports: [by_mac[mac].dev, dev]
			});
			by_mac[mac].conflict = true;
		} else if (!by_mac[mac]) {
			by_mac[mac] = { mac: mac, dev: dev, master: master, stale: is_stale, conflict: false };
		}
	}
	return { by_mac: by_mac, conflicts: conflicts };
};

export function build_live_topology(sources) {
	let src = (type(sources) == 'object') ? sources : {};
	let sampled_ms = src.sampled_ms || 0;
	let cstat = (type(src.collector_status) == 'object') ? src.collector_status : {};

	let p_links = src.ip_link_raw != null ? parse_ip_links(src.ip_link_raw, src.carrier_map) : { ok: false, links: {}, error: 'missing' };
	let p_addrs = src.ip_addr_raw != null ? parse_ip_addrs(src.ip_addr_raw) : { ok: false, addrs: {}, error: 'missing' };
	let p_routes = src.ip_route_raw != null ? parse_ip_routes(src.ip_route_raw) : { ok: false, defaults: [], error: 'missing' };
	let p_vlans = src.bridge_vlan_raw != null ? parse_bridge_vlans(src.bridge_vlan_raw) : { ok: false, vlans_by_dev: {}, error: 'missing' };
	let p_fdb = parse_fdb_entries(src.fdb_raw || '');

	let missing_sources = [];
	let source_health = {
		ip_link: p_links.ok,
		ip_addr: p_addrs.ok,
		ip_route: p_routes.ok,
		bridge_vlan: p_vlans.ok,
		ubus_network: !!cstat.ubus_network,
		wireless: !!cstat.wireless,
		clients: !!cstat.clients
	};
	for (let sk in sort(keys(source_health))) {
		if (!source_health[sk]) push(missing_sources, sk);
	}

	let critical_ok = p_links.ok && !!cstat.ubus_network;
	let completeness = !critical_ok ? 'unavailable' : (length(missing_sources) > 0 ? 'partial' : 'complete');

	let conflicts = [];
	for (let cf in p_fdb.conflicts) push(conflicts, cf);

	let links = p_links.links;
	let addrs = p_addrs.addrs;
	let wan_topo = (type(src.wan_topology) == 'object') ? src.wan_topology : { wan_ifaces: {}, lan_ifaces: {} };
	let wan_ifaces = (type(wan_topo.wan_ifaces) == 'object') ? wan_topo.wan_ifaces : {};
	let lan_ifaces = (type(wan_topo.lan_ifaces) == 'object') ? wan_topo.lan_ifaces : {};

	// 1. WAN links: separate admin_up from operational_up / operstate / carrier
	let default_route_devs = {};
	for (let rt in p_routes.defaults) default_route_devs[rt.dev] = rt;

	let wan_nodes = [];
	for (let wdev in sort(keys(wan_ifaces))) {
		if (!wan_ifaces[wdev] || lan_ifaces[wdev]) continue;
		let lnk = links[wdev];
		let adr = addrs[wdev];
		let dr = default_route_devs[wdev];
		let observed_up = !!(lnk && lnk.operational_up);
		if (p_links.ok && !lnk) {
			push(conflicts, { type: 'disappeared_wan_interface', dev: wdev, detail: 'WAN interface absent from ip link' });
		}
		push(wan_nodes, {
			id: 'wan:' + wdev,
			device: wdev,
			observed_up: observed_up,
			admin_up: lnk ? lnk.admin_up : false,
			operstate: lnk ? lnk.operstate : 'unknown',
			carrier: lnk ? lnk.carrier : null,
			connectivity_state: lnk ? lnk.connectivity_state : 'unknown',
			ipv4: (adr && length(adr.ipv4) > 0) ? adr.ipv4[0] : '',
			is_default_route: !!dr,
			gateway: dr ? dr.gateway : '',
			metric: dr ? dr.metric : null,
			evidence_source: 'firewall_wan+ubus+ip_link'
		});
	}

	// 2. Bridges, physical ports, and VLANs
	let bridge_nodes = [];
	let port_nodes = {};
	let vlan_nodes = [];
	let sys_bridges = (type(src.bridges) == 'array') ? src.bridges : [];
	for (let br in sys_bridges) {
		if (!br || !br.name) continue;
		let br_lnk = links[br.name];
		let br_ports = [];
		for (let pt in (br.ports || [])) {
			let plnk = links[pt];
			if (p_links.ok && plnk && plnk.master != '' && plnk.master != br.name) {
				push(conflicts, { type: 'bridge_membership_conflict', port: pt, detail: 'sysfs bridge ' + br.name + ' != ip link master ' + plnk.master });
			}
			let p_vlans_list = p_vlans.vlans_by_dev[pt] || [];
			let pnode = {
				id: 'port:' + pt,
				ifname: pt,
				bridge: br.name,
				observed_up: !!(plnk && plnk.operational_up),
				admin_up: plnk ? plnk.admin_up : false,
				operstate: plnk ? plnk.operstate : 'unknown',
				carrier: plnk ? plnk.carrier : null,
				connectivity_state: plnk ? plnk.connectivity_state : 'unknown',
				vlans: p_vlans_list,
				evidence_source: plnk ? 'sysfs+ip_link' : 'sysfs_only'
			};
			port_nodes[pt] = pnode;
			push(br_ports, pnode);
		}
		push(bridge_nodes, {
			id: 'bridge:' + br.name,
			name: br.name,
			observed_up: !!(br_lnk && br_lnk.operational_up),
			admin_up: br_lnk ? br_lnk.admin_up : false,
			operstate: br_lnk ? br_lnk.operstate : 'unknown',
			carrier: br_lnk ? br_lnk.carrier : null,
			connectivity_state: br_lnk ? br_lnk.connectivity_state : 'unknown',
			vlans: p_vlans.vlans_by_dev[br.name] || [],
			ports: br_ports,
			evidence_source: br_lnk ? 'sysfs+ip_link' : 'sysfs_only'
		});
	}

	for (let ifn in sort(keys(links))) {
		let lk = links[ifn];
		if (lk.kind == 'vlan' && lk.vlan_id != null) {
			push(vlan_nodes, {
				id: 'vlan:' + ifn,
				ifname: ifn,
				parent_if: lk.link,
				vlan_id: lk.vlan_id,
				observed_up: lk.operational_up,
				admin_up: lk.admin_up,
				operstate: lk.operstate,
				carrier: lk.carrier,
				connectivity_state: lk.connectivity_state,
				evidence_source: 'ip_link'
			});
		}
	}

	// 3. Wireless Interfaces & AP Classification (strict mode check: AP vs STA/mesh/monitor/unknown)
	let wireless_ifaces = [];
	let ap_nodes = {};
	let uci_wifi = (type(src.uci_wireless) == 'array') ? src.uci_wireless : [];
	let wifi_stations = (type(src.wifi_stations) == 'object') ? src.wifi_stations : {};
	let runtime_ap_ifs = (type(src.runtime_ap_ifs) == 'object') ? src.runtime_ap_ifs : {};
	let seen_wifi_ifs = {};

	for (let wcfg in uci_wifi) {
		if (!wcfg || !wcfg.ifname) continue;
		let ifname = wcfg.ifname;
		seen_wifi_ifs[ifname] = true;
		let cfg_mode = lc(trim(wcfg.mode || ''));
		if (!VALID_WIFI_MODES[cfg_mode]) cfg_mode = 'unknown';

		let rt_ap = runtime_ap_ifs[ifname];
		let rt_mode = (rt_ap && rt_ap.mode) ? lc(trim(rt_ap.mode)) : '';
		if (rt_mode != '' && !VALID_WIFI_MODES[rt_mode]) rt_mode = 'unknown';

		let mode_conflict = (cfg_mode != 'unknown' && rt_mode != '' && cfg_mode != rt_mode);
		if (mode_conflict) {
			push(conflicts, { type: 'wireless_mode_mismatch', ifname: ifname, detail: 'UCI mode ' + cfg_mode + ' != runtime mode ' + rt_mode });
		}

		let effective_mode = (rt_mode != '') ? rt_mode : cfg_mode;
		let lnk = links[ifname];
		let obs_up = !!(rt_ap && rt_ap.up && !mode_conflict && (!p_links.ok || (lnk && lnk.operational_up)));
		let ev_src = (rt_ap && rt_ap.up) ? (p_links.ok ? 'ubus_wireless+ip_link' : 'ubus_wireless') : 'uci_only';

		let w_entry = {
			id: (effective_mode == 'ap' ? 'ap:' : 'wifi:') + ifname,
			ifname: ifname,
			radio: wcfg.device || (rt_ap ? (rt_ap.radio || '') : ''),
			ssid: wcfg.ssid || (rt_ap ? (rt_ap.ssid || '') : ''),
			mode: effective_mode,
			configured_mode: cfg_mode,
			runtime_mode: rt_mode != '' ? rt_mode : 'unknown',
			configured_disabled: !!wcfg.disabled,
			observed_up: obs_up,
			connectivity_state: lnk ? lnk.connectivity_state : 'unknown',
			conflict: mode_conflict,
			evidence_source: ev_src
		};
		push(wireless_ifaces, w_entry);
		if (effective_mode == 'ap' && !mode_conflict) {
			ap_nodes[ifname] = w_entry;
		}
	}

	for (let rt_if in sort(keys(runtime_ap_ifs))) {
		if (seen_wifi_ifs[rt_if]) continue;
		let rt_ap = runtime_ap_ifs[rt_if];
		let rt_mode = (rt_ap && rt_ap.mode) ? lc(trim(rt_ap.mode)) : 'unknown';
		if (!VALID_WIFI_MODES[rt_mode]) rt_mode = 'unknown';
		let lnk = links[rt_if];
		let obs_up = !!(rt_ap && rt_ap.up && (!p_links.ok || (lnk && lnk.operational_up)));
		let w_entry = {
			id: (rt_mode == 'ap' ? 'ap:' : 'wifi:') + rt_if,
			ifname: rt_if,
			radio: rt_ap.radio || '',
			ssid: rt_ap.ssid || '',
			mode: rt_mode,
			configured_mode: 'unknown',
			runtime_mode: rt_mode,
			configured_disabled: false,
			observed_up: obs_up,
			connectivity_state: lnk ? lnk.connectivity_state : 'unknown',
			conflict: false,
			evidence_source: 'ubus_wireless'
		};
		push(wireless_ifaces, w_entry);
		if (rt_mode == 'ap') {
			ap_nodes[rt_if] = w_entry;
		}
	}

	// 4. Client-to-AP / Port / Bridge relationships (evidence-only, only verified APs accept station links)
	let raw_clients = (type(src.clients) == 'array') ? src.clients : [];
	let seen_macs = {};
	let client_links = [];
	for (let c in raw_clients) {
		if (!c) continue;
		let mac = lc(c.mac || '');
		if (mac != '') {
			if (seen_macs[mac]) {
				push(conflicts, { type: 'duplicate_client_mac', mac: mac, detail: 'Duplicate client MAC in inventory' });
			}
			seen_macs[mac] = true;
		}
		let ws = mac != '' ? wifi_stations[mac] : null;
		let fdb = mac != '' ? p_fdb.by_mac[mac] : null;
		let parent_id = 'unknown';
		let attach_type = 'unknown';
		let ev_src = 'none';
		let is_stale = false;
		let is_conflict = !!(fdb && fdb.conflict);

		if (ws && ws.ifname && ap_nodes[ws.ifname] && ap_nodes[ws.ifname].observed_up) {
			parent_id = 'ap:' + ws.ifname;
			attach_type = 'wireless';
			ev_src = 'hostapd';
		} else if (ws && ws.ifname && (!ap_nodes[ws.ifname] || !ap_nodes[ws.ifname].observed_up)) {
			is_stale = true;
			ev_src = 'hostapd_stale';
		} else if (fdb && port_nodes[fdb.dev]) {
			if (fdb.stale) {
				is_stale = true;
				attach_type = 'bridge';
				parent_id = fdb.master ? ('bridge:' + fdb.master) : 'unknown';
				ev_src = 'fdb_stale';
			} else {
				parent_id = 'port:' + fdb.dev;
				attach_type = 'wired_port';
				ev_src = 'bridge_fdb';
			}
		} else if (c.bridge && c.bridge != '') {
			parent_id = 'bridge:' + c.bridge;
			attach_type = 'bridge';
			ev_src = 'ip_neigh';
		}

		push(client_links, {
			mac: mac,
			ip: c.ip || '',
			display_name: c.display_name || c.ip || 'جهاز',
			online: is_stale ? false : !!c.online,
			blocked: !!c.blocked,
			parent_id: parent_id,
			attachment_type: attach_type,
			evidence_source: ev_src,
			stale: is_stale,
			conflict: is_conflict,
			rate_supported: c.rate_supported,
			rx_bps: c.rx_bps,
			tx_bps: c.tx_bps,
			rate_reason: c.rate_reason || null,
			rate_limit_kbps: c.rate_limit_kbps || 0,
			total_rx_bytes: c.total_rx_bytes || 0,
			total_tx_bytes: c.total_tx_bytes || 0
		});
	}

	let ap_list = [];
	for (let ak in sort(keys(ap_nodes))) push(ap_list, ap_nodes[ak]);

	return {
		ok: completeness != 'unavailable',
		completeness: completeness,
		partial: completeness == 'partial',
		stale: false,
		refresh_failed: false,
		sampled_ms: sampled_ms,
		stale_age_ms: 0,
		missing_sources: missing_sources,
		source_health: source_health,
		conflicts: conflicts,
		wan_links: wan_nodes,
		bridges: bridge_nodes,
		vlans: vlan_nodes,
		aps: ap_list,
		wireless_ifaces: wireless_ifaces,
		clients: client_links
	};
};

export function select_topology_snapshot(new_snap, last_valid_snap, now_ms, max_stale_ms) {
	let limit_ms = (max_stale_ms != null && max_stale_ms > 0) ? max_stale_ms : 120000;
	if (new_snap && new_snap.completeness != 'unavailable') {
		return new_snap;
	}
	if (last_valid_snap && last_valid_snap.completeness != 'unavailable') {
		let age = now_ms - (last_valid_snap.sampled_ms || now_ms);
		if (age <= limit_ms) {
			let out = {};
			for (let k in keys(last_valid_snap)) out[k] = last_valid_snap[k];
			out.ok = true;
			out.stale = true;
			out.refresh_failed = true;
			out.stale_age_ms = age < 0 ? 0 : age;
			out.missing_sources = (new_snap && new_snap.missing_sources) ? new_snap.missing_sources : ['collector'];
			return out;
		}
	}
	return new_snap || {
		ok: false,
		completeness: 'unavailable',
		partial: false,
		stale: true,
		refresh_failed: true,
		sampled_ms: now_ms,
		stale_age_ms: 0,
		missing_sources: ['collector'],
		conflicts: [],
		wan_links: [],
		bridges: [],
		vlans: [],
		aps: [],
		wireless_ifaces: [],
		clients: []
	};
};

export function redact_topology_for_role(topo, role, boot_id, sha256_fn) {
	if (!topo || role == 'admin') return topo;
	let out = {};
	for (let k in keys(topo)) out[k] = topo[k];
	let redacted_clients = [];
	for (let c in (topo.clients || [])) {
		let orig_mac = c.mac || '';
		let pseudo = sha256_fn ? substr(sha256_fn((boot_id || '') + orig_mac), 0, 8) : 'REDACTED';
		push(redacted_clients, {
			mac: 'HIDDEN',
			ip: 'PSEUDO-' + pseudo,
			display_name: 'جهاز محلي',
			online: c.online,
			blocked: c.blocked,
			parent_id: c.parent_id,
			attachment_type: c.attachment_type,
			evidence_source: c.evidence_source,
			stale: c.stale,
			conflict: c.conflict,
			rate_supported: false,
			rx_bps: null,
			tx_bps: null,
			rate_reason: 'redacted',
			rate_limit_kbps: 0,
			total_rx_bytes: c.total_rx_bytes,
			total_tx_bytes: c.total_tx_bytes
		});
	}
	out.clients = redacted_clients;
	out.conflicts = [];
	return out;
};
