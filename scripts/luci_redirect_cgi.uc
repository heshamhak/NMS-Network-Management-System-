#!/usr/bin/env ucode
'use strict';

import { stdout, readfile } from 'fs';
import * as uci from 'uci';

function is_private_ipv4(h) {
	let m = match(h, /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/);
	if (!m) return false;
	let a = +m[1], b = +m[2], c = +m[3], d = +m[4];
	if (a > 255 || b > 255 || c > 255 || d > 255) return false;
	if (a == 10 || a == 127) return true;
	if (a == 192 && b == 168) return true;
	if (a == 172 && b >= 16 && b <= 31) return true;
	if (a == 100 && b >= 64 && b <= 127) return true;
	return false;
}

function is_local_ipv6(h) {
	if (!match(h, /^\[[0-9a-fA-F:]+\]$/)) return false;
	let inner = lc(substr(h, 1, length(h) - 2));
	if (inner == '::1') return true;
	if (match(inner, /^fe[89ab][0-9a-f]:/)) return true;
	if (match(inner, /^f[cd][0-9a-f][0-9a-f]:/)) return true;
	return false;
}

function get_system_hostname() {
	try {
		let cur = uci.cursor();
		let hn = cur.get_first('system', 'system', 'hostname');
		if (type(hn) == 'string' && hn != '') return lc(trim(hn));
	} catch (e) {}
	let p_hn = readfile('/proc/sys/kernel/hostname');
	if (p_hn) return lc(trim(p_hn));
	return '';
}

function get_fallback_lan_ip() {
	try {
		let cur = uci.cursor();
		let ip = cur.get('network', 'lan', 'ipaddr');
		if (type(ip) == 'array' && length(ip) > 0) ip = ip[0];
		if (type(ip) == 'string' && ip != '') {
			let first = split(trim(ip), /[ \/]/)[0];
			if (first && is_private_ipv4(first)) return first;
		}
	} catch (e) {}
	return '192.168.1.1';
}

function extract_trusted_host(raw_hdr) {
	if (!raw_hdr || type(raw_hdr) != 'string') return '';
	let h = trim(raw_hdr);
	if (match(h, /[\r\n\/\\@ \t]/)) return '';
	if (substr(h, 0, 1) == '[') {
		let end_br = index(h, ']');
		if (end_br <= 1) return '';
		let rest = substr(h, end_br + 1);
		if (rest != '' && !match(rest, /^:[0-9]{1,5}$/)) return '';
		let v6 = substr(h, 0, end_br + 1);
		return is_local_ipv6(v6) ? v6 : '';
	}
	let parts = split(h, ':');
	if (length(parts) > 2) return '';
	if (length(parts) == 2 && !match(parts[1], /^[0-9]{1,5}$/)) return '';
	let host_only = parts[0];
	if (length(host_only) == 0 || length(host_only) > 253) return '';
	if (match(host_only, /^[0-9.]+$/)) {
		return is_private_ipv4(host_only) ? host_only : '';
	}
	let lower = lc(host_only);
	let sys_hn = get_system_hostname();
	if (sys_hn != '' && (lower == sys_hn || lower == sys_hn + '.lan' || lower == sys_hn + '.local')) {
		return host_only;
	}
	if (match(lower, /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/)) return host_only;
	if (match(lower, /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.(lan|local|home\.arpa)$/)) return host_only;
	return '';
}

let https_port = +(getenv('NOC_HTTPS_PORT') || 8743);
let host = extract_trusted_host(getenv('HTTP_HOST') || '');
if (host == '') host = get_fallback_lan_ip();

let target = sprintf('https://%s:%d/', host, https_port);

stdout.write(
	'Status: 302 Found\r\n' +
	'Location: ' + target + '\r\n' +
	'Cache-Control: no-store, no-cache, must-revalidate\r\n' +
	'X-Content-Type-Options: nosniff\r\n' +
	'X-Frame-Options: DENY\r\n' +
	'Referrer-Policy: no-referrer\r\n' +
	'Content-Type: text/html; charset=utf-8\r\n\r\n' +
	'<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8">' +
	'<title>NMS</title></head><body><a href="' + target + '">NMS</a></body></html>\n'
);
