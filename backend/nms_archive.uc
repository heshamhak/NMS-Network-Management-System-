// Shared production ucode module for archive & sysupgrade.conf security validation.
// Imported by /usr/libexec/noc-helperd and directly executable by ucode test harnesses.

const ALLOWED_ARCHIVE_PREFIXES = ['etc/', 'root/', 'usr/local/', 'www/', 'lib/uci/'];

function oct_to_int(s) {
	let val = 0;
	let clean = trim(replace(s || '', /\0/g, ''));
	for (let i = 0; i < length(clean); i++) {
		let ch = ord(clean, i);
		if (ch >= 48 && ch <= 55) val = (val * 8) + (ch - 48);
	}
	return val;
}

function cstr(buf, off, maxlen) {
	let s = substr(buf, off, maxlen);
	let z = index(s, '\0');
	return z >= 0 ? substr(s, 0, z) : s;
}

function has_unsafe_chars(p) {
	if (type(p) != 'string' || p == '') return true;
	for (let i = 0; i < length(p); i++) {
		let c = ord(p, i);
		if (c < 32 || c == 127 || c == 92) return true; // control chars, NUL, newline, CR, backslash
	}
	return false;
}

export function normalize_archive_rel_path(raw_path) {
	if (has_unsafe_chars(raw_path)) return null;
	if (substr(raw_path, 0, 1) == '/') return null;
	let p = raw_path;
	while (index(p, './') == 0) p = substr(p, 2);
	if (p == '' || p == '.') return '.';
	let parts = split(p, '/');
	let out = [];
	for (let seg in parts) {
		if (seg == '' || seg == '.') continue;
		if (seg == '..') return null; // Never allow '..' in archive entry or hard-link path
		push(out, seg);
	}
	return length(out) > 0 ? join('/', out) : '.';
};

export function resolve_symlink_target(entry_path, link_target) {
	if (has_unsafe_chars(link_target)) return null;
	if (substr(link_target, 0, 1) == '/') return null; // Reject every absolute symlink target
	let parts = split(entry_path, '/');
	pop(parts); // parent directory of entry_path
	for (let seg in split(link_target, '/')) {
		if (seg == '' || seg == '.') continue;
		if (seg == '..') {
			if (length(parts) == 0) return null; // Escaped archive root
			pop(parts);
		} else {
			push(parts, seg);
		}
	}
	return length(parts) > 0 ? join('/', parts) : null;
};

function is_in_allowed_prefix(p) {
	for (let ap in ALLOWED_ARCHIVE_PREFIXES) {
		if (index(p, ap) == 0 || p + '/' == ap) return true;
	}
	return false;
}

function parse_pax_records(pax_data) {
	let res = {};
	let pos = 0;
	let total = length(pax_data);
	while (pos < total) {
		let sp = index(pax_data, ' ', pos);
		if (sp <= pos) break;
		let rec_len = +substr(pax_data, pos, sp - pos);
		if (rec_len <= 0 || pos + rec_len > total) break;
		let rec = substr(pax_data, sp + 1, pos + rec_len - sp - 2); // strip trailing \n
		let eq = index(rec, '=');
		if (eq > 0) {
			res[substr(rec, 0, eq)] = substr(rec, eq + 1);
		}
		pos += rec_len;
	}
	return res;
}

export function validate_tar_stream(tar_bytes) {
	let entries = [];
	let errors = [];
	if (type(tar_bytes) != 'string' || length(tar_bytes) < 512) {
		push(errors, 'أرشيف tar غير صالح أو قصير جداً');
		return { valid: false, entries: entries, errors: errors };
	}
	let total = length(tar_bytes);
	let offset = 0;
	let pax_next = {};
	let gnu_longname = null;
	let gnu_longlink = null;
	let zero_blocks = 0;

	while (offset + 512 <= total) {
		let hdr = substr(tar_bytes, offset, 512);
		offset += 512;

		let is_zero = true;
		for (let i = 0; i < 512; i++) {
			if (ord(hdr, i) != 0) { is_zero = false; break; }
		}
		if (is_zero) {
			zero_blocks++;
			continue;
		}
		zero_blocks = 0;

		let name = cstr(hdr, 0, 100);
		let prefix = cstr(hdr, 345, 155);
		let raw_path = (prefix != '' ? (prefix + '/' + name) : name);
		let size = oct_to_int(substr(hdr, 124, 12));
		let tflag = substr(hdr, 156, 1);
		if (tflag == '\0') tflag = '0';
		let linkname = cstr(hdr, 157, 100);

		let data_blocks = int((size + 511) / 512) * 512;
		if (offset + data_blocks > total) {
			push(errors, 'أرشيف مقطوع أو تالف أثناء قراءة الكتل');
			break;
		}
		let payload = size > 0 ? substr(tar_bytes, offset, size) : '';
		offset += data_blocks;

		if (tflag == 'x') {
			let recs = parse_pax_records(payload);
			for (let k in keys(recs)) pax_next[k] = recs[k];
			continue;
		}
		if (tflag == 'g') continue; // global pax header
		if (tflag == 'L') { gnu_longname = replace(payload, /\0+$/, ''); continue; }
		if (tflag == 'K') { gnu_longlink = replace(payload, /\0+$/, ''); continue; }

		if (pax_next.path != null) raw_path = pax_next.path;
		else if (gnu_longname != null) raw_path = gnu_longname;
		if (pax_next.linkpath != null) linkname = pax_next.linkpath;
		else if (gnu_longlink != null) linkname = gnu_longlink;
		pax_next = {};
		gnu_longname = null;
		gnu_longlink = null;

		if (tflag == '3' || tflag == '4' || tflag == '6') {
			push(errors, 'نوع ملف غير آمن في الأرشيف (device/fifo): ' + tflag);
			continue;
		}
		if (tflag != '0' && tflag != '1' && tflag != '2' && tflag != '5') {
			push(errors, 'نوع إدخال غير مدعوم في الأرشيف: ' + tflag);
			continue;
		}

		let norm_path = normalize_archive_rel_path(raw_path);
		if (norm_path == null) {
			push(errors, 'مسار غير آمن أو محاولة اجتياز داخل الأرشيف: ' + raw_path);
			continue;
		}
		if (norm_path == '.') continue;
		if (!is_in_allowed_prefix(norm_path)) {
			push(errors, 'مسار خارج نطاق الإعدادات المصرح به: ' + norm_path);
			continue;
		}

		if (tflag == '1') {
			// Hard link targets are relative to archive root; reject absolute or escaping targets
			let norm_hl = normalize_archive_rel_path(linkname);
			if (norm_hl == null || norm_hl == '.' || !is_in_allowed_prefix(norm_hl)) {
				push(errors, 'هدف رابط صلب (hard link) غير آمن: ' + norm_path + ' -> ' + linkname);
				continue;
			}
		} else if (tflag == '2') {
			// Symbolic link targets are resolved relative to entry's parent directory
			let resolved_sl = resolve_symlink_target(norm_path, linkname);
			if (resolved_sl == null || !is_in_allowed_prefix(resolved_sl)) {
				push(errors, 'هدف رابط رمزي (symlink) غير آمن أو يتجاوز النطاق: ' + norm_path + ' -> ' + linkname);
				continue;
			}
		}

		push(entries, norm_path);
	}

	if (length(entries) == 0 && length(errors) == 0) {
		push(errors, 'الأرشيف فارغ ولا يحتوي على ملفات صالحة');
	}
	return { valid: length(errors) == 0 && length(entries) > 0, entries: entries, errors: errors };
};

export function is_safe_sysupgrade_path(p) {
	if (type(p) != 'string') return false;
	if (length(p) < 2 || length(p) > 256) return false;
	if (!match(p, /^\/[a-zA-Z0-9._\/-]+$/)) return false;
	if (index(p, '..') >= 0 || index(p, '//') >= 0) return false;
	let forbidden = ['/proc', '/sys', '/dev', '/tmp', '/run', '/var/run'];
	for (let fb in forbidden) {
		if (p == fb || index(p, fb + '/') == 0) return false;
	}
	let allowed = ['/etc/', '/root/', '/usr/local/', '/www/'];
	for (let al in allowed) {
		if (index(p, al) == 0) return true;
	}
	return false;
};

export function merge_sysupgrade_conf(existing_raw, new_paths) {
	let comments = [];
	if (type(existing_raw) == 'string' && existing_raw != '') {
		for (let line in split(existing_raw, '\n')) {
			let lt = trim(line);
			if (substr(lt, 0, 1) == '#') push(comments, line);
		}
	}
	if (length(comments) == 0) push(comments, '# Managed safely by NMS');
	return join('\n', comments) + '\n' + join('\n', new_paths) + (length(new_paths) > 0 ? '\n' : '');
};
