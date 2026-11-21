// Shared production ucode module for archive & sysupgrade.conf security validation.
// Imported by /usr/libexec/noc-helperd and directly executable by ucode test harnesses.

const ALLOWED_ARCHIVE_PREFIXES = ['etc/', 'root/', 'usr/local/', 'www/', 'lib/uci/'];

function parse_octal_strict(s) {
	if (type(s) != 'string' || length(s) == 0) return null;
	let val = 0;
	let seen_digit = false;
	let ended = false;
	for (let i = 0; i < length(s); i++) {
		let ch = ord(s, i);
		if (ch == 0 || ch == 32) {
			if (seen_digit) ended = true;
			continue;
		}
		if (ended) return null; // non-whitespace after trailing space/NUL
		if (ch < 48 || ch > 55) return null; // invalid octal char (including '-' or base-256 0x80)
		seen_digit = true;
		val = (val * 8) + (ch - 48);
	}
	return seen_digit ? val : null;
}

function verify_tar_header_checksum(hdr) {
	if (length(hdr) != 512) return false;
	let hdr_sum = parse_octal_strict(substr(hdr, 148, 8));
	if (hdr_sum == null) return false;
	let calc = 256; // 8 * 0x20 for bytes 148..155
	for (let i = 0; i < 148; i++) calc += ord(hdr, i);
	for (let i = 156; i < 512; i++) calc += ord(hdr, i);
	return calc == hdr_sum;
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
	let seen = {};
	let pos = 0;
	let total = length(pax_data);
	if (total == 0) return { ok: false, error: 'سجل PAX فارغ', records: res };
	while (pos < total) {
		let sp = index(pax_data, ' ', pos);
		if (sp <= pos) return { ok: false, error: 'تنسيق طول سجل PAX غير صالح', records: res };
		let len_str = substr(pax_data, pos, sp - pos);
		if (!match(len_str, /^[0-9]+$/)) return { ok: false, error: 'طول سجل PAX غير رقمي', records: res };
		let rec_len = +len_str;
		if (rec_len < 5 || pos + rec_len > total) return { ok: false, error: 'طول سجل PAX خارج الحدود', records: res };
		if (substr(pax_data, pos + rec_len - 1, 1) != '\n') return { ok: false, error: 'سجل PAX لا ينتهي بسطر جديد', records: res };
		let rec = substr(pax_data, sp + 1, pos + rec_len - sp - 2);
		let eq = index(rec, '=');
		if (eq <= 0) return { ok: false, error: 'سجل PAX يفتقد =' , records: res };
		let k = substr(rec, 0, eq);
		let v = substr(rec, eq + 1);
		if (seen[k]) return { ok: false, error: 'سجل PAX مكرر أو متعارض للمفتاح: ' + k, records: res };
		seen[k] = true;
		res[k] = v;
		pos += rec_len;
	}
	return { ok: true, error: '', records: res };
}

export function validate_tar_stream(tar_bytes) {
	let entries = [];
	let errors = [];
	if (type(tar_bytes) != 'string' || length(tar_bytes) < 1024 || (length(tar_bytes) % 512) != 0) {
		push(errors, 'أرشيف tar غير صالح أو مقطوع (الطول ليس من مضاعفات 512)');
		return { valid: false, entries: entries, errors: errors };
	}
	let total = length(tar_bytes);
	let offset = 0;
	let pax_next = {};
	let gnu_longname = null;
	let gnu_longlink = null;
	let zero_blocks = 0;
	let ended_archive = false;

	while (offset + 512 <= total) {
		let hdr = substr(tar_bytes, offset, 512);
		offset += 512;

		let is_zero = true;
		for (let i = 0; i < 512; i++) {
			if (ord(hdr, i) != 0) { is_zero = false; break; }
		}
		if (is_zero) {
			zero_blocks++;
			if (zero_blocks >= 2) ended_archive = true;
			continue;
		}
		if (ended_archive) {
			push(errors, 'بيانات غير متوقعة بعد علامة نهاية أرشيف tar');
			break;
		}
		if (zero_blocks > 0) {
			push(errors, 'كتلة صفرية مفردة غير صالحة قبل نهاية الأرشيف');
			break;
		}

		if (!verify_tar_header_checksum(hdr)) {
			push(errors, 'فشل التحقق من Checksum لترويسة tar');
			break;
		}

		let size = parse_octal_strict(substr(hdr, 124, 12));
		if (size == null) {
			push(errors, 'حقل حجم (octal size) غير صالح في ترويسة tar');
			break;
		}

		let name = cstr(hdr, 0, 100);
		let prefix = cstr(hdr, 345, 155);
		let raw_path = (prefix != '' ? (prefix + '/' + name) : name);
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
			let pr = parse_pax_records(payload);
			if (!pr.ok) {
				push(errors, pr.error);
				break;
			}
			for (let k in keys(pr.records)) {
				if (pax_next[k] != null) {
					push(errors, 'تعارض في سجلات PAX الممتدة للمفتاح: ' + k);
					break;
				}
				pax_next[k] = pr.records[k];
			}
			continue;
		}
		if (tflag == 'g') {
			let pg = parse_pax_records(payload);
			if (!pg.ok) {
				push(errors, 'سجل PAX عام (g) تالف: ' + pg.error);
				break;
			}
			if (pg.records.path != null || pg.records.linkpath != null) {
				push(errors, 'سجل PAX عام (g) يحاول تجاوز path أو linkpath');
				break;
			}
			continue;
		}
		if (tflag == 'L') {
			if (gnu_longname != null || size == 0) {
				push(errors, 'ترويسة GNU longname مكررة أو فارغة');
				break;
			}
			let cleaned = replace(payload, /\0+$/, '');
			if (index(cleaned, '\0') >= 0) {
				push(errors, 'بايت NUL غير قانوني داخل GNU longname');
				break;
			}
			gnu_longname = cleaned;
			continue;
		}
		if (tflag == 'K') {
			if (gnu_longlink != null || size == 0) {
				push(errors, 'ترويسة GNU longlink مكررة أو فارغة');
				break;
			}
			let cleaned = replace(payload, /\0+$/, '');
			if (index(cleaned, '\0') >= 0) {
				push(errors, 'بايت NUL غير قانوني داخل GNU longlink');
				break;
			}
			gnu_longlink = cleaned;
			continue;
		}

		if (pax_next.path != null && gnu_longname != null && pax_next.path != gnu_longname) {
			push(errors, 'تعارض بين PAX path و GNU longname');
			break;
		}
		if (pax_next.linkpath != null && gnu_longlink != null && pax_next.linkpath != gnu_longlink) {
			push(errors, 'تعارض بين PAX linkpath و GNU longlink');
			break;
		}

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
			let norm_hl = normalize_archive_rel_path(linkname);
			if (norm_hl == null || norm_hl == '.' || !is_in_allowed_prefix(norm_hl)) {
				push(errors, 'هدف رابط صلب (hard link) غير آمن: ' + norm_path + ' -> ' + linkname);
				continue;
			}
		} else if (tflag == '2') {
			let resolved_sl = resolve_symlink_target(norm_path, linkname);
			if (resolved_sl == null || !is_in_allowed_prefix(resolved_sl)) {
				push(errors, 'هدف رابط رمزي (symlink) غير آمن أو يتجاوز النطاق: ' + norm_path + ' -> ' + linkname);
				continue;
			}
		}

		push(entries, norm_path);
	}

	if (length(keys(pax_next)) > 0 || gnu_longname != null || gnu_longlink != null) {
		push(errors, 'ترويسة PAX أو GNU ممتدة يتيمة دون ملف لاحق');
	}
	if (!ended_archive && length(errors) == 0) {
		push(errors, 'علامة نهاية أرشيف tar (كتلتان صفريتان) مفقودة أو غير مكتملة');
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

export function atomic_write_checked(path, content, mode, uid, gid, ops) {
	let tmp = path + '.tmp.' + ops.suffix();
	let cleanup = function() {
		if (ops.stat(tmp)) ops.unlink(tmp);
	};
	let w = ops.writefile(tmp, content);
	if (w == null || w != length(content)) {
		cleanup();
		return { ok: false, error: 'write_failed', tmp_path: tmp };
	}
	if (uid != null && gid != null) {
		if (!ops.chown(tmp, uid, gid)) {
			cleanup();
			return { ok: false, error: 'chown_failed', tmp_path: tmp };
		}
	}
	if (!ops.chmod(tmp, mode || 0o600)) {
		cleanup();
		return { ok: false, error: 'chmod_failed', tmp_path: tmp };
	}
	if (!ops.rename(tmp, path)) {
		cleanup();
		return { ok: false, error: 'rename_failed', tmp_path: tmp };
	}
	return { ok: true, error: '', tmp_path: tmp };
};
