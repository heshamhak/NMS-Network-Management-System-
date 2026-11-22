// Phase 5B: Transactional Backup-Restore Engine — Production Regression & Failure Matrix
// Executed directly inside OpenWrt 24.10.0 (opkg) & 25.12.6 (apk) chroots against
// production backend/nms_archive.uc and extracted backend/noc-helperd sys_backup_restore.

import * as fs from 'fs';
import * as digest from 'digest';
import * as nms_archive from '/tmp/p3a_test/nms_archive.uc';
import * as prod from '/tmp/p3a_test/helperd_restore_prod.uc';

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

function mkdir_p(p) {
	let parts = split(p, '/');
	let cur = '';
	for (let seg in parts) {
		if (seg == '') continue;
		cur += '/' + seg;
		if (!fs.stat(cur)) fs.mkdir(cur, 0o755);
	}
}

function reset_sandbox() {
	mkdir_p(prod.RUN_DIR);
	mkdir_p(prod.ROOT_MAP + '/etc/config');
	mkdir_p(prod.ROOT_MAP + '/etc/noc-console');
	mkdir_p(prod.ROOT_MAP + '/etc/init.d');
	fs.writefile(prod.ROOT_MAP + '/etc/config/network', "config interface 'lan'\n\toption ipaddr '192.168.1.1'\n");
	fs.writefile(prod.ROOT_MAP + '/etc/config/firewall', "config defaults\n\toption input 'ACCEPT'\n");
	fs.writefile(prod.ROOT_MAP + '/etc/noc-console/config.json', '{"orig":true}\n');
	fs.writefile(prod.ROOT_MAP + '/etc/init.d/network', '#!/bin/sh\nexit 0\n');
	fs.writefile(prod.ROOT_MAP + '/etc/init.d/firewall', '#!/bin/sh\nexit 0\n');
	prod.cfg.fail_write_target = null;
	prod.cfg.fail_rollback_target = null;
	prod.cfg.fail_reload_svc = null;
	prod.cfg.fail_rollback_reload_svc = null;
	prod.cfg.lock_held = false;
	prod.cfg.in_rollback = false;
	prod.cfg.freeze_calls = [];
	prod.cfg.audits = [];
	prod.cfg.reloads = [];
}

// Helper: build a real USTAR tar.gz archive in-process via tar+gzip inside chroot
let tar_seq = 0;
function make_targz_b64(file_specs) {
	let d = prod.RUN_DIR + '/mk_tar_' + (++tar_seq);
	mkdir_p(d);
	let rels = [];
	for (let spec in file_specs) {
		let fp = d + '/' + spec.path;
		let dir = substr(fp, 0, rindex(fp, '/'));
		mkdir_p(dir);
		if (spec.symlink) {
			system(['/bin/ln', '-s', spec.symlink, fp]);
		} else {
			fs.writefile(fp, spec.content || '');
		}
		push(rels, spec.path);
	}
	let out_tgz = prod.RUN_DIR + '/mk_tar_' + tar_seq + '.tar.gz';
	let cmd = ['/bin/tar', '-czf', out_tgz, '-C', d];
	for (let r in rels) push(cmd, r);
	system(cmd);
	let raw = fs.readfile(out_tgz) || '';
	return { raw: raw, b64: b64enc(raw), sha256: digest.sha256(raw) };
}

// ===================================================================
// 1-6. Unit checks on nms_archive restore whitelist & UCI JSON renderer
// ===================================================================
let vr_ok = nms_archive.validate_restore_archive_entries([
	{ path: 'etc/config/network', type: '0' },
	{ path: 'etc/noc-console/config.json', type: '0' }
]);
check(vr_ok.ok && length(vr_ok.files) == 2, 'P5B-UNIT[whitelist_accepted]');

check(!nms_archive.validate_restore_archive_entries([{ path: 'etc/config/network', type: '2' }]).ok, 'P5B-UNIT[symlink_rejected]');
check(!nms_archive.validate_restore_archive_entries([{ path: 'etc/config/network', type: '1' }]).ok, 'P5B-UNIT[hardlink_rejected]');
check(!nms_archive.validate_restore_archive_entries([{ path: 'etc/config/network', type: '0' }, { path: './etc/config/network', type: '0' }]).ok, 'P5B-UNIT[duplicate_rejected]');
check(!nms_archive.validate_restore_archive_entries([{ path: 'etc/shadow', type: '0' }]).ok, 'P5B-UNIT[non_whitelist_shadow_rejected]');

let uci_ok = nms_archive.validate_and_render_uci_configs({
	network: { lan: { '.type': 'interface', '.name': 'lan', proto: 'static', ipaddr: '10.0.0.1', dns: ['1.1.1.1'] } }
});
check(
	uci_ok.ok && index(uci_ok.rendered.network, "config interface 'lan'") >= 0 &&
	!nms_archive.validate_and_render_uci_configs({ dropbear: { main: { '.type': 'dropbear', Port: '22' } } }).ok &&
	!nms_archive.validate_and_render_uci_configs({ network: { lan: { '.type': 'interface', proto: "static\noption evil '1'" } } }).ok,
	'P5B-UNIT[uci_render_and_reject_injection]'
);

// ===================================================================
// 7. P5B-PROD-01: Real UCI JSON configs restore writes exact content & reloads services
// ===================================================================
reset_sandbox();
let r7 = null;
prod.run_restore('admin', {
	configs: {
		network: { lan: { '.type': 'interface', '.name': 'lan', proto: 'static', ipaddr: '10.20.30.1' } },
		firewall: { def: { '.type': 'defaults', '.anonymous': true, input: 'REJECT' } }
	}
}, (x) => { r7 = x; });
let net_after7 = fs.readfile(prod.ROOT_MAP + '/etc/config/network') || '';
let fw_after7 = fs.readfile(prod.ROOT_MAP + '/etc/config/firewall') || '';
check(
	r7 && r7.ok === true &&
	index(net_after7, "option ipaddr '10.20.30.1'") >= 0 &&
	index(fw_after7, "option input 'REJECT'") >= 0 &&
	index(prod.cfg.reloads, 'network') >= 0 && index(prod.cfg.reloads, 'firewall') >= 0 &&
	!prod.cfg.lock_held,
	'P5B-PROD[configs_real_restore_and_content_verified]',
	sprintf('%J', r7)
);

// ===================================================================
// 8. P5B-PROD-02: Partial write failure on 2nd config rolls back 1st config byte-for-byte
// ===================================================================
reset_sandbox();
let orig_net8 = fs.readfile(prod.ROOT_MAP + '/etc/config/network');
let orig_fw8 = fs.readfile(prod.ROOT_MAP + '/etc/config/firewall');
prod.cfg.fail_write_target = '/etc/config/firewall';
let r8 = null;
prod.run_restore('admin', {
	configs: {
		network: { lan: { '.type': 'interface', '.name': 'lan', proto: 'static', ipaddr: '10.99.99.1' } },
		firewall: { def: { '.type': 'defaults', '.anonymous': true, input: 'DROP' } }
	}
}, (x) => { r8 = x; });
check(
	r8 && r8.ok === false &&
	fs.readfile(prod.ROOT_MAP + '/etc/config/network') == orig_net8 &&
	fs.readfile(prod.ROOT_MAP + '/etc/config/firewall') == orig_fw8 &&
	length(prod.cfg.freeze_calls) == 0 && !prod.cfg.lock_held,
	'P5B-PROD[configs_partial_write_failure_rolls_back]',
	sprintf('%J', r8)
);

// ===================================================================
// 9. P5B-PROD-03: Service reload failure rolls back both configs byte-for-byte
// ===================================================================
reset_sandbox();
let orig_net9 = fs.readfile(prod.ROOT_MAP + '/etc/config/network');
let orig_fw9 = fs.readfile(prod.ROOT_MAP + '/etc/config/firewall');
prod.cfg.fail_reload_svc = 'firewall';
let r9 = null;
prod.run_restore('admin', {
	configs: {
		network: { lan: { '.type': 'interface', '.name': 'lan', proto: 'static', ipaddr: '10.88.88.1' } },
		firewall: { def: { '.type': 'defaults', '.anonymous': true, input: 'DROP' } }
	}
}, (x) => { r9 = x; });
check(
	r9 && r9.ok === false &&
	fs.readfile(prod.ROOT_MAP + '/etc/config/network') == orig_net9 &&
	fs.readfile(prod.ROOT_MAP + '/etc/config/firewall') == orig_fw9 &&
	length(prod.cfg.freeze_calls) == 0 && !prod.cfg.lock_held,
	'P5B-PROD[configs_reload_failure_rolls_back]',
	sprintf('%J', r9)
);

// ===================================================================
// 10. P5B-PROD-04: Rollback failure triggers emergency freeze + audit
// ===================================================================
reset_sandbox();
prod.cfg.fail_write_target = '/etc/config/firewall';
prod.cfg.fail_rollback_target = '/etc/config/network';
let r10 = null;
prod.run_restore('admin', {
	configs: {
		network: { lan: { '.type': 'interface', '.name': 'lan', proto: 'static', ipaddr: '10.77.77.1' } },
		firewall: { def: { '.type': 'defaults', '.anonymous': true, input: 'DROP' } }
	}
}, (x) => { r10 = x; });
check(
	r10 && r10.ok === false && length(prod.cfg.freeze_calls) == 1 && !prod.cfg.lock_held,
	'P5B-PROD[configs_rollback_failure_triggers_freeze]',
	sprintf('%J', r10)
);

// ===================================================================
// 11. P5B-PROD-05: Real .tar.gz archive restore writes exact bytes & reloads services
// ===================================================================
reset_sandbox();
let new_net_bytes = "config interface 'lan'\n\toption ipaddr '192.168.55.1'\n";
let new_cfg_bytes = '{"restored":true,"ver":5}\n';
let arc11 = make_targz_b64([
	{ path: 'etc/config/network', content: new_net_bytes },
	{ path: 'etc/noc-console/config.json', content: new_cfg_bytes }
]);
let r11 = null;
prod.run_restore('admin', { archive_b64: arc11.b64, expected_sha256: arc11.sha256 }, (x) => { r11 = x; });
check(
	r11 && r11.ok === true && r11.applied_count == 2 &&
	fs.readfile(prod.ROOT_MAP + '/etc/config/network') == new_net_bytes &&
	fs.readfile(prod.ROOT_MAP + '/etc/noc-console/config.json') == new_cfg_bytes &&
	index(prod.cfg.reloads, 'network') >= 0 && !prod.cfg.lock_held,
	'P5B-PROD[archive_real_restore_and_content_verified]',
	sprintf('%J', r11)
);

// ===================================================================
// 12-15. Malicious archives rejected before any disk mutation
// ===================================================================
reset_sandbox();
let orig_net12 = fs.readfile(prod.ROOT_MAP + '/etc/config/network');
let arc_shadow = make_targz_b64([{ path: 'etc/shadow', content: 'root:x:0:0\n' }]);
let r12 = null;
prod.run_restore('admin', { archive_b64: arc_shadow.b64 }, (x) => { r12 = x; });
check(r12 && r12.ok === false && fs.readfile(prod.ROOT_MAP + '/etc/config/network') == orig_net12 && !prod.cfg.lock_held, 'P5B-PROD[archive_non_whitelist_shadow_rejected]');

let arc_sym = make_targz_b64([{ path: 'etc/config/network', symlink: '/etc/passwd' }]);
let r13 = null;
prod.run_restore('admin', { archive_b64: arc_sym.b64 }, (x) => { r13 = x; });
check(r13 && r13.ok === false && fs.readfile(prod.ROOT_MAP + '/etc/config/network') == orig_net12 && !prod.cfg.lock_held, 'P5B-PROD[archive_symlink_rejected]');

let r14 = null;
prod.run_restore('admin', { archive_b64: arc11.b64, expected_sha256: '0000000000000000000000000000000000000000000000000000000000000000' }, (x) => { r14 = x; });
check(r14 && r14.ok === false && fs.readfile(prod.ROOT_MAP + '/etc/config/network') == orig_net12 && !prod.cfg.lock_held, 'P5B-PROD[archive_bad_sha256_rejected]');

let arc_badjson = make_targz_b64([{ path: 'etc/noc-console/config.json', content: '{not-valid-json' }]);
let r15 = null;
prod.run_restore('admin', { archive_b64: arc_badjson.b64 }, (x) => { r15 = x; });
check(r15 && r15.ok === false && fs.readfile(prod.ROOT_MAP + '/etc/noc-console/config.json') == '{"orig":true}\n' && !prod.cfg.lock_held, 'P5B-PROD[archive_invalid_json_rejected]');

// ===================================================================
// 16. P5B-PROD-07: Archive partial write failure rolls back 1st file
// ===================================================================
reset_sandbox();
let orig_net16 = fs.readfile(prod.ROOT_MAP + '/etc/config/network');
let orig_cfg16 = fs.readfile(prod.ROOT_MAP + '/etc/noc-console/config.json');
prod.cfg.fail_write_target = '/etc/noc-console/config.json';
let r16 = null;
prod.run_restore('admin', { archive_b64: arc11.b64 }, (x) => { r16 = x; });
check(
	r16 && r16.ok === false &&
	fs.readfile(prod.ROOT_MAP + '/etc/config/network') == orig_net16 &&
	fs.readfile(prod.ROOT_MAP + '/etc/noc-console/config.json') == orig_cfg16 &&
	length(prod.cfg.freeze_calls) == 0 && !prod.cfg.lock_held,
	'P5B-PROD[archive_partial_write_failure_rolls_back]',
	sprintf('%J', r16)
);

// ===================================================================
// 17. P5B-PROD-08: Archive service reload failure rolls back files
// ===================================================================
reset_sandbox();
let orig_net17 = fs.readfile(prod.ROOT_MAP + '/etc/config/network');
let orig_cfg17 = fs.readfile(prod.ROOT_MAP + '/etc/noc-console/config.json');
prod.cfg.fail_reload_svc = 'network';
let r17 = null;
prod.run_restore('admin', { archive_b64: arc11.b64 }, (x) => { r17 = x; });
check(
	r17 && r17.ok === false &&
	fs.readfile(prod.ROOT_MAP + '/etc/config/network') == orig_net17 &&
	fs.readfile(prod.ROOT_MAP + '/etc/noc-console/config.json') == orig_cfg17 &&
	length(prod.cfg.freeze_calls) == 0 && !prod.cfg.lock_held,
	'P5B-PROD[archive_reload_failure_rolls_back]',
	sprintf('%J', r17)
);

// ===================================================================
// 18. P5B-PROD-09: Archive rollback failure triggers emergency freeze
// ===================================================================
reset_sandbox();
prod.cfg.fail_write_target = '/etc/noc-console/config.json';
prod.cfg.fail_rollback_target = '/etc/config/network';
let r18 = null;
prod.run_restore('admin', { archive_b64: arc11.b64 }, (x) => { r18 = x; });
check(
	r18 && r18.ok === false && length(prod.cfg.freeze_calls) == 1 && !prod.cfg.lock_held,
	'P5B-PROD[archive_rollback_failure_triggers_freeze]',
	sprintf('%J', r18)
);

// ===================================================================
// 19. P5B-PROD-10: Concurrent restore rejected with 409 while lock is held
// ===================================================================
reset_sandbox();
let orig_net19 = fs.readfile(prod.ROOT_MAP + '/etc/config/network');
prod.cfg.lock_held = true;
let r19 = null;
prod.run_restore('admin', { archive_b64: arc11.b64 }, (x) => { r19 = x; });
check(
	r19 && r19.ok === false && r19.status == 409 &&
	fs.readfile(prod.ROOT_MAP + '/etc/config/network') == orig_net19,
	'P5B-PROD[concurrent_restore_rejected_409]',
	sprintf('%J', r19)
);

// ===================================================================
// 20. Empty/missing payload rejected cleanly without lock leak
// ===================================================================
reset_sandbox();
let r20 = null;
prod.run_restore('admin', {}, (x) => { r20 = x; });
check(r20 && r20.ok === false && r20.error_code == 'VALIDATION' && !prod.cfg.lock_held, 'P5B-PROD[empty_payload_rejected]');

// ===================================================================
// 21. P5B-PROD-11: Configs rollback service-reload failure triggers emergency freeze
// ===================================================================
reset_sandbox();
prod.cfg.fail_reload_svc = 'firewall';
prod.cfg.fail_rollback_reload_svc = 'firewall';
let r21 = null;
prod.run_restore('admin', {
	configs: {
		network: { lan: { '.type': 'interface', '.name': 'lan', proto: 'static', ipaddr: '10.66.66.1' } },
		firewall: { def: { '.type': 'defaults', '.anonymous': true, input: 'DROP' } }
	}
}, (x) => { r21 = x; });
check(
	r21 && r21.ok === false && length(prod.cfg.freeze_calls) == 1 && !prod.cfg.lock_held,
	'P5B-PROD[configs_rollback_reload_failure_triggers_freeze]',
	sprintf('%J', r21)
);

// ===================================================================
// 22. P5B-PROD-12: Archive rollback service-reload failure triggers emergency freeze
// ===================================================================
reset_sandbox();
prod.cfg.fail_reload_svc = 'network';
prod.cfg.fail_rollback_reload_svc = 'network';
let r22 = null;
prod.run_restore('admin', { archive_b64: arc11.b64 }, (x) => { r22 = x; });
check(
	r22 && r22.ok === false && length(prod.cfg.freeze_calls) == 1 && !prod.cfg.lock_held,
	'P5B-PROD[archive_rollback_reload_failure_triggers_freeze]',
	sprintf('%J', r22)
);

printf('UCODE5B_SUMMARY: %d passed, %d failed\n', passed, failed);
exit(failed == 0 ? 0 : 1);
