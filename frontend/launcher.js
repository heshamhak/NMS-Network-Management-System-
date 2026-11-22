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

  function isLocalIpv6(h) {
    if (!/^\[[0-9a-fA-F:]+\]$/.test(h)) return false;
    var inner = h.slice(1, -1).toLowerCase();
    if (inner === '::1') return true;
    if (/^fe[89ab][0-9a-f]:/.test(inner)) return true;
    if (/^f[cd][0-9a-f]{2}:/.test(inner)) return true;
    return false;
  }

  function isTrustedLocalHost(h) {
    if (!h || typeof h !== 'string' || h.length > 253) return false;
    if (/[\r\n\/\\@ \t]/.test(h)) return false;
    if (isLocalIpv6(h)) return true;
    if (/^[0-9.]+$/.test(h)) return isPrivateIpv4(h);
    var lower = h.toLowerCase();
    if (/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(lower)) return true;
    if (/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.(?:lan|local|home\.arpa)$/.test(lower)) return true;
    return false;
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
