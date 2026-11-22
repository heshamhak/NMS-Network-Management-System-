(function () {
  'use strict';

  function isValidHost(h) {
    if (!h || typeof h !== 'string' || h.length > 253) return false;
    if (/^\[[0-9a-fA-F:]+\]$/.test(h)) return true;
    if (/^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$/.test(h)) return true;
    return /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(h);
  }

  var loc = window.location;
  var rawHost = loc.hostname || (loc.host ? loc.host.split(':')[0] : '');
  if (!isValidHost(rawHost)) return;

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
