(function () {
  'use strict';

  function isPrivateIpv4(h) {
    var m = /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/.exec(h);
    if (!m) return false;
    var a = +m[1], b = +m[2], c = +m[3], d = +m[4];
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    if (a === 10 || a === 127) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }

  function isValidIpv6Groups(addr) {
    if (!addr || /:::/.test(addr) || /^:[^:]/.test(addr) || /[^:]:$/.test(addr)) return false;
    var dbl = addr.split('::');
    if (dbl.length > 2) return false;
    if (dbl.length === 2) {
      var left = dbl[0] ? dbl[0].split(':') : [];
      var right = dbl[1] ? dbl[1].split(':') : [];
      if (left.length + right.length >= 8) return false;
      var all = left.concat(right);
      for (var i = 0; i < all.length; i++) {
        if (!/^[0-9a-f]{1,4}$/.test(all[i])) return false;
      }
      return true;
    }
    var groups = addr.split(':');
    if (groups.length !== 8) return false;
    for (var j = 0; j < 8; j++) {
      if (!/^[0-9a-f]{1,4}$/.test(groups[j])) return false;
    }
    return true;
  }

  function isLocalIpv6(h) {
    if (!/^\[[0-9a-fA-F:]+\]$/.test(h)) return false;
    var inner = h.slice(1, -1).toLowerCase();
    if (!isValidIpv6Groups(inner)) return false;
    if (inner === '::1') return true;
    if (/^fe[89ab][0-9a-f]:/.test(inner)) return true;
    if (/^f[cd][0-9a-f]{2}:/.test(inner)) return true;
    return false;
  }

  var APPROVED_BASE_NAMES = ['localhost', 'router', 'gateway', 'nms'];

  function isApprovedLocalHostname(lower) {
    for (var i = 0; i < APPROVED_BASE_NAMES.length; i++) {
      var b = APPROVED_BASE_NAMES[i];
      if (lower === b) return true;
      if (b !== 'localhost' && (lower === b + '.lan' || lower === b + '.local' || lower === b + '.home.arpa')) {
        return true;
      }
    }
    return false;
  }

  function isTrustedLocalHost(h) {
    if (!h || typeof h !== 'string' || h.length > 253) return false;
    if (/[\r\n\/\\@ \t]/.test(h)) return false;
    if (isLocalIpv6(h)) return true;
    if (/^[0-9.]+$/.test(h)) return isPrivateIpv4(h);
    var lower = h.toLowerCase();
    return isApprovedLocalHostname(lower);
  }

  var loc = window.location;
  var portStr = loc.port ? String(loc.port) : '';
  if (portStr !== '' && (!/^[0-9]{1,5}$/.test(portStr) || +portStr < 1 || +portStr > 65535)) {
    return;
  }
  var rawHost = loc.hostname || (loc.host ? loc.host.split(':')[0] : '');
  if (!isTrustedLocalHost(rawHost)) return;

  var target = 'https:' + '//' + rawHost + ':8743/';
  var link = document.getElementById('manualLink');
  if (link) {
    link.setAttribute('href', target);
  }

  if (loc.port === '8743' && loc.protocol === 'https:') {
    return;
  }
  loc.replace(target);
})();
