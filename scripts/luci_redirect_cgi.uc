#!/usr/bin/env ucode
'use strict';

import { stdout } from 'fs';
import * as uci from 'uci';

function get_fallback_lan_ip() {
	try {
		let cur = uci.cursor();
		let ip = cur.get('network', 'lan', 'ipaddr');
		if (type(ip) == 'array' && length(ip) > 0) ip = ip[0];
		if (type(ip) == 'string' && ip != '') {
			let first = split(trim(ip), /[ \/]/)[0];
			if (first && match(first, /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/)) return first;
		}
	} catch (e) {}
	return '192.168.1.1';
}

function extract_safe_host(raw_hdr) {
	if (!raw_hdr || type(raw_hdr) != 'string') return '';
	let h = trim(raw_hdr);
	if (match(h, /[\r\n\/\\@ \t]/)) return '';
	if (substr(h, 0, 1) == '[') {
		let end_br = index(h, ']');
		if (end_br <= 1) return '';
		let v6 = substr(h, 0, end_br + 1);
		return match(v6, /^\[[0-9a-fA-F:]+\]$/) ? v6 : '';
	}
	let host_only = split(h, ':')[0];
	if ( length(host_only) == 0 || length(host_only) > 253 ) return '';
	if (match(host_only, /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/)) return host_only;
	if (match(host_only, /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/)) return host_only;
	return '';
}

let https_port = +(getenv('NOC_HTTPS_PORT') || 8743);
let host = extract_safe_host(getenv('HTTP_HOST') || '');
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
