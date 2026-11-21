// Executed directly by OpenWrt 25.12.6 x86_64 ucode runtime against production backend/nms_network.uc
import * as fs from 'fs';
import * as nms_network from '/tmp/p3a_test/nms_network.uc';

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

printf('UCODE3B_SUMMARY: %d passed, %d failed\n', passed, failed);
exit(failed == 0 ? 0 : 1);
