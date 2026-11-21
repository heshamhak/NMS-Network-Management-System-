// Executed directly by OpenWrt 25.12.6 x86_64 ucode runtime against production backend/nms_network.uc AND extracted noc-helperd handlers
import * as fs from 'fs';
import * as uci from 'uci';
import * as nms_network from '/tmp/p3a_test/nms_network.uc';
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

// 1. Interface validation
check(nms_network.validate_interface_cfg({ name: 'guest', proto: 'static', device: 'br-lan.10', ipaddr: '10.10.10.1', netmask: '255.255.255.0', ip6addr: 'fd00:10::1/64', mtu: 1500, dns: ['1.1.1.1', '2606:4700:4700::1111'] }).ok, 'P3B-IFACE[valid_static_v4_v6]');
check(!nms_network.validate_interface_cfg({ name: 'loopback', proto: 'static', ipaddr: '127.0.0.1' }).ok, 'P3B-IFACE[reject_loopback]');
check(!nms_network.validate_interface_cfg({ name: 'bad;name', proto: 'dhcp' }).ok, 'P3B-IFACE[reject_bad_ifname]');
check(!nms_network.validate_interface_cfg({ name: 'guest', proto: 'static', ipaddr: '999.1.1.1', netmask: '255.255.255.0' }).ok, 'P3B-IFACE[reject_bad_ipv4]');
check(!nms_network.validate_interface_cfg({ name: 'guest', proto: 'static', ip6addr: 'fd00::1/129' }).ok, 'P3B-IFACE[reject_bad_ipv6_cidr]');
check(!nms_network.validate_interface_cfg({ name: 'guest', proto: 'dhcp', mtu: 100 }).ok, 'P3B-IFACE[reject_bad_mtu]');

// 2. Device & Bridge-VLAN (DSA) validation
check(nms_network.validate_device_cfg({ name: 'br-lan', type: 'bridge', ports: ['lan1', 'lan2', 'lan3'], mtu: 1500 }).ok, 'P3B-DEV[valid_bridge]');
check(nms_network.validate_device_cfg({ name: 'br-lan.10', type: '8021q', ifname: 'br-lan', vid: 10 }).ok, 'P3B-DEV[valid_8021q]');
check(!nms_network.validate_device_cfg({ name: 'br-lan.0', type: '8021q', ifname: 'br-lan', vid: 0 }).ok, 'P3B-DEV[reject_vid_0]');
check(nms_network.validate_bridge_vlan_cfg({ device: 'br-lan', vlan: 10, ports: ['lan1:u', 'lan2:t', 'eth1:t*'] }).ok, 'P3B-DSA[valid_bridge_vlan]');
check(!nms_network.validate_bridge_vlan_cfg({ device: 'br-lan', vlan: 4095, ports: ['lan1:u'] }).ok, 'P3B-DSA[reject_vid_4095]');
check(!nms_network.validate_bridge_vlan_cfg({ device: 'br-lan', vlan: 10, ports: ['lan1:u', 'lan1:t'] }).ok, 'P3B-DSA[reject_duplicate_dsa_port]');
check(!nms_network.validate_bridge_vlan_cfg({ device: 'br-lan', vlan: 10, ports: ['lan1:bad'] }).ok, 'P3B-DSA[reject_bad_tag]');

// 3. IPv6 / RA / DHCPv6 / NDP / ULA validation
check(nms_network.validate_ipv6_dhcp_cfg({ interface: 'lan', ra: 'server', dhcpv6: 'server', ndp: 'disabled', ra_management: 1, ula_prefix: 'fdb6:cd6f:63be::/48', ra_flags: ['managed-config', 'other-config'], dns: ['fdb6:cd6f:63be::1'] }).ok, 'P3B-IPV6[valid_cfg]');
check(!nms_network.validate_ipv6_dhcp_cfg({ interface: 'lan', ra: 'invalid', dhcpv6: 'server', ndp: 'disabled' }).ok, 'P3B-IPV6[reject_bad_ra]');
check(!nms_network.validate_ipv6_dhcp_cfg({ interface: 'lan', ra: 'server', dhcpv6: 'server', ndp: 'disabled', ula_prefix: 'not-ipv6/48' }).ok, 'P3B-IPV6[reject_bad_ula]');
check(!nms_network.validate_ipv6_dhcp_cfg({ interface: 'lan', ra: 'server', dhcpv6: 'server', ndp: 'disabled', dns: ['192.168.1.1'] }).ok, 'P3B-IPV6[reject_v4_in_dnsv6]');

// 4. Transactional apply_network_tx: success, read failure, validate failure + rollback, reload failure + rollback, verify failure + rollback, rollback failure + freeze
let tx_dir = vec_dir + '/net_tx';
fs.mkdir(tx_dir);
let net_cfg = tx_dir + '/network';
let dhcp_cfg = tx_dir + '/dhcp';
let orig_net = "config interface 'lan'\n\toption ipaddr '192.168.1.1'\n";
let orig_dhcp = "config dhcp 'lan'\n\toption ra 'server'\n";
fs.writefile(net_cfg, orig_net);
fs.chmod(net_cfg, 0o640);
fs.writefile(dhcp_cfg, orig_dhcp);
fs.chmod(dhcp_cfg, 0o640);

let freeze_called = 0;
function make_tx_ops(opts) {
	let reload_cnt = 0;
	return {
		stat: fs.stat,
		lstat: fs.lstat,
		unlink: fs.unlink,
		readfile: function(p) {
			if (opts.read_null && p == net_cfg) return null;
			return fs.readfile(p);
		},
		aw_ops: {
			suffix: function() { return 'nettx'; },
			stat: fs.stat,
			unlink: fs.unlink,
			open: fs.open,
			writefile: fs.writefile,
			chown: fs.chown,
			chmod: fs.chmod,
			rename: function(s, d) {
				if (opts.fail_rb_rename && d == net_cfg) return false;
				return fs.rename(s, d);
			}
		},
		apply_uci: function() {
			if (opts.mutate_disk) {
				fs.writefile(net_cfg, "config interface 'lan'\n\toption ipaddr '10.99.99.1'\n");
				fs.chmod(net_cfg, 0o600);
			}
			return { ok: !opts.fail_apply };
		},
		validate_config: function() { return { ok: !opts.fail_validate, error: 'bad uci' }; },
		reload_service: function() {
			reload_cnt++;
			if (opts.fail_reload && reload_cnt == 1) return { ok: false, error: 'reload failed' };
			return { ok: true };
		},
		verify_applied: function() { return { ok: !opts.fail_verify, error: 'verify failed' }; },
		on_rollback_failed: function(reason) {
			freeze_called++;
			return { freeze_persisted: true, freeze_persist_failed: false };
		}
	};
}

// 4a. Unreadable original file -> aborts before apply
let r_null = nms_network.apply_network_tx([net_cfg, dhcp_cfg], make_tx_ops({ read_null: true, mutate_disk: true }));
check(!r_null.ok && r_null.error == 'read_failed' && fs.readfile(net_cfg) == orig_net, 'P3B-TX[read_null_aborts]', sprintf('%J', r_null));

// 4b. Pre-reload validation failure -> rolls back bytes & mode 0o640
let r_val = nms_network.apply_network_tx([net_cfg, dhcp_cfg], make_tx_ops({ mutate_disk: true, fail_validate: true }));
let st_val = fs.lstat(net_cfg);
check(!r_val.ok && r_val.rolled_back === true && !r_val.rollback_failed && fs.readfile(net_cfg) == orig_net && (st_val.mode & 0o7777) == 0o640, 'P3B-TX[validate_fail_rollback_ok]', sprintf('%J', r_val));

// 4c. Reload failure -> rolls back bytes & mode 0o640
let r_rel = nms_network.apply_network_tx([net_cfg, dhcp_cfg], make_tx_ops({ mutate_disk: true, fail_reload: true }));
check(!r_rel.ok && r_rel.rolled_back === true && !r_rel.rollback_failed && fs.readfile(net_cfg) == orig_net, 'P3B-TX[reload_fail_rollback_ok]', sprintf('%J', r_rel));

// 4d. Verify failure -> rolls back bytes & mode 0o640
let r_ver = nms_network.apply_network_tx([net_cfg, dhcp_cfg], make_tx_ops({ mutate_disk: true, fail_verify: true }));
check(!r_ver.ok && r_ver.rolled_back === true && !r_ver.rollback_failed && fs.readfile(net_cfg) == orig_net, 'P3B-TX[verify_fail_rollback_ok]', sprintf('%J', r_ver));

// 4e. Rollback failure -> triggers emergency freeze & reports rollback_failed=true
let r_rbf = nms_network.apply_network_tx([net_cfg, dhcp_cfg], make_tx_ops({ mutate_disk: true, fail_validate: true, fail_rb_rename: true }));
check(!r_rbf.ok && r_rbf.rollback_failed === true && !r_rbf.rolled_back && freeze_called == 1, 'P3B-TX[rollback_fail_triggers_freeze]', sprintf('%J', r_rbf));

// Restore clean net_cfg and test success path
fs.writefile(net_cfg, orig_net);
fs.chmod(net_cfg, 0o640);
let r_ok = nms_network.apply_network_tx([net_cfg, dhcp_cfg], make_tx_ops({ mutate_disk: true }));
check(r_ok.ok === true && !r_ok.rolled_back && !r_ok.rollback_failed, 'P3B-TX[success]', sprintf('%J', r_ok));

// 4f. Partial file creation (non-existent file created during apply_uci failure -> must be removed on rollback)
let extra_cfg = tx_dir + '/extra_nonexistent';
let r_extra = nms_network.apply_network_tx([net_cfg, extra_cfg], {
	stat: fs.stat, lstat: fs.lstat, readfile: fs.readfile, unlink: fs.unlink,
	aw_ops: { suffix: function() { return 'ex'; }, stat: fs.stat, unlink: fs.unlink, open: fs.open, writefile: fs.writefile, chown: fs.chown, chmod: fs.chmod, rename: fs.rename },
	apply_uci: function() { fs.writefile(extra_cfg, 'PARTIAL\n'); return { ok: false, error: 'partial fail' }; },
	validate_config: function() { return { ok: true }; },
	reload_service: function() { return { ok: true }; },
	verify_applied: function() { return { ok: true }; },
	on_rollback_failed: function() { return { freeze_persisted: true }; }
});
check(!r_extra.ok && r_extra.rolled_back === true && !fs.stat(extra_cfg), 'P3B-TX[apply_fail_removes_newly_created_file]', sprintf('%J', r_extra));

// 5. Production noc-helperd handle_network_phase3b_verb integration tests with real OpenWrt uci.cursor(uci_dir)!
let uci_dir = vec_dir + '/uci_cfg';
fs.mkdir(uci_dir);
let base_net = "config globals 'globals'\n\toption ula_prefix 'fd00:1::/48'\n\nconfig interface 'loopback'\n\toption device 'lo'\n\toption proto 'static'\n\nconfig interface 'lan'\n\toption device 'br-lan'\n\toption proto 'static'\n\toption ipaddr '192.168.1.1'\n\nconfig interface 'wan'\n\toption device 'eth0'\n\toption proto 'pppoe'\n";
let base_dhcp = "config dhcp 'lan'\n\toption interface 'lan'\n\toption ra 'server'\n\toption dhcpv6 'server'\n\toption ndp 'disabled'\n";
fs.writefile(uci_dir + '/network', base_net);
fs.chmod(uci_dir + '/network', 0o644);
fs.writefile(uci_dir + '/dhcp', base_dhcp);
fs.chmod(uci_dir + '/dhcp', 0o644);

function run_prod_net(verb, params, extra_env) {
	let rep = null;
	let env = {
		cfg_dir: uci_dir,
		uci_dir: uci_dir,
		validate_fn: function() { return { ok: true }; },
		reload_fn: function() { return { ok: true }; }
	};
	if (extra_env) for (let k in keys(extra_env)) env[k] = extra_env[k];
	helperd_prod.handle_network_phase3b_verb(verb, params, 'admin', function(r) { rep = r; }, env);
	return rep;
}

// 5a. Interface save & delete + protected interface delete refusal
let r_ifs = run_prod_net('network_interface_save', { name: 'guest', proto: 'static', device: 'br-lan.10', ipaddr: '10.10.10.1', netmask: '255.255.255.0', ip6addr: 'fd00:10::1/64', mtu: 1500, dns: ['1.1.1.1'] });
let cv1 = uci.cursor(uci_dir);
check(r_ifs.ok === true && cv1.get('network', 'guest', 'ipaddr') == '10.10.10.1' && cv1.get('network', 'guest', 'ip6addr') == 'fd00:10::1/64', 'P3B-PROD[interface_save_uci_verified]', sprintf('%J', r_ifs));

let r_ifd_prot = run_prod_net('network_interface_delete', { name: 'lan' });
check(!r_ifd_prot.ok && r_ifd_prot.error_code == 'FORBIDDEN', 'P3B-PROD[protected_interface_delete_refused]', sprintf('%J', r_ifd_prot));

let r_ifd = run_prod_net('network_interface_delete', { name: 'guest' });
let cv2 = uci.cursor(uci_dir);
check(r_ifd.ok === true && cv2.get('network', 'guest') == null, 'P3B-PROD[interface_delete_uci_verified]', sprintf('%J', r_ifd));

// 5b. Bridge & 802.1q device save
let r_dev_br = run_prod_net('network_device_save', { name: 'br-lan', type: 'bridge', ports: ['lan1', 'lan2'], mtu: 1500, igmp_snooping: true });
let r_dev_q = run_prod_net('network_device_save', { name: 'br-lan.10', type: '8021q', ifname: 'br-lan', vid: 10 });
let cv3 = uci.cursor(uci_dir);
check(r_dev_br.ok === true && r_dev_q.ok === true && cv3.get('network', 'dev_br_lan_10', 'vid') == '10', 'P3B-PROD[device_bridge_and_8021q_uci_verified]', sprintf('br=%J q=%J', r_dev_br, r_dev_q));

// 5c. DSA bridge-vlan save & delete
let r_bvs = run_prod_net('network_bridge_vlan_save', { device: 'br-lan', vlan: 10, ports: ['lan1:u', 'lan2:t'] });
let cv4 = uci.cursor(uci_dir);
check(r_bvs.ok === true && cv4.get('network', 'bv_br_lan_10', 'vlan') == '10', 'P3B-PROD[bridge_vlan_save_uci_verified]', sprintf('%J', r_bvs));
let r_bvd = run_prod_net('network_bridge_vlan_delete', { id: 'bv_br_lan_10' });
let cv5 = uci.cursor(uci_dir);
check(r_bvd.ok === true && cv5.get('network', 'bv_br_lan_10') == null, 'P3B-PROD[bridge_vlan_delete_uci_verified]', sprintf('%J', r_bvd));

// 5d. IPv6 save across BOTH network (ula_prefix) and dhcp (ra, dhcpv6, ndp, ra_slaac, ra_flags, dns)
let r_v6 = run_prod_net('network_ipv6_save', {
	interface: 'lan',
	ula_prefix: 'fdb6:cd6f:63be::/48',
	ra: 'hybrid',
	dhcpv6: 'server',
	ndp: 'relay',
	ra_management: 2,
	ra_default: 1,
	ra_slaac: true,
	ra_flags: ['managed-config', 'other-config'],
	dns: ['fdb6:cd6f:63be::1']
});
let cv6 = uci.cursor(uci_dir);
check(
	r_v6.ok === true
	&& cv6.get('network', 'globals', 'ula_prefix') == 'fdb6:cd6f:63be::/48'
	&& cv6.get('dhcp', 'lan', 'ra') == 'hybrid'
	&& cv6.get('dhcp', 'lan', 'ndp') == 'relay'
	&& cv6.get('dhcp', 'lan', 'ra_management') == '2',
	'P3B-PROD[ipv6_network_and_dhcp_uci_verified]',
	sprintf('%J', r_v6)
);

// 5e. Mid-IPv6 failure (after network commit, before dhcp commit) -> MUST roll back ula_prefix in network!
let snap_net_before_mid = fs.readfile(uci_dir + '/network');
let snap_dhcp_before_mid = fs.readfile(uci_dir + '/dhcp');
let r_v6_mid = run_prod_net('network_ipv6_save', {
	interface: 'lan',
	ula_prefix: 'fd99:9999::/48',
	ra: 'disabled',
	dhcpv6: 'disabled',
	ndp: 'disabled'
}, { inject_apply_fail_mid_ipv6: true });
check(
	!r_v6_mid.ok && r_v6_mid.rolled_back === true
	&& fs.readfile(uci_dir + '/network') == snap_net_before_mid
	&& fs.readfile(uci_dir + '/dhcp') == snap_dhcp_before_mid,
	'P3B-PROD[ipv6_mid_commit_fail_rolls_back_network]',
	sprintf('%J', r_v6_mid)
);

// 5f. Post-apply verify_applied mismatch -> MUST detect mismatch and roll back both network & dhcp!
let r_v6_mis = run_prod_net('network_ipv6_save', {
	interface: 'lan',
	ula_prefix: 'fd88:8888::/48',
	ra: 'disabled',
	dhcpv6: 'disabled',
	ndp: 'disabled'
}, { inject_verify_mismatch: true });
check(
	!r_v6_mis.ok && r_v6_mis.rolled_back === true && r_v6_mis.error == 'verify_failed'
	&& fs.readfile(uci_dir + '/network') == snap_net_before_mid
	&& fs.readfile(uci_dir + '/dhcp') == snap_dhcp_before_mid,
	'P3B-PROD[verify_mismatch_triggers_full_rollback]',
	sprintf('%J', r_v6_mis)
);

printf('UCODE3B_SUMMARY: %d passed, %d failed\n', passed, failed);
exit(failed == 0 ? 0 : 1);
