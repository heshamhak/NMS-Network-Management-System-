/*!
 * noc-search.js: بحث شامل Ctrl+K (صفحات + إعدادات + إجراءات + أجهزة + قواعد)
 * يُحمَّل بعد app.js (يحتاج window.NOC). لا يستخدم innerHTML ولا معالجات inline (متوافق مع CSP).
 * قاعدة صارمة: لوحة البحث لا تنفّذ أي إجراء تعديلي أبداً، بل تنقلك إلى العنصر وتضيئه فقط.
 */
(function (root) {
  'use strict';

  /* ---------- أدوات نقية (قابلة للاختبار في Node) ---------- */
  var DIG = '٠١٢٣٤٥٦٧٨٩';
  function norm(s) {
    s = String(s == null ? '' : s).toLowerCase();
    s = s.replace(/[\u064B-\u065F\u0670\u0640]/g, '');
    s = s.replace(/[أإآٱ]/g, 'ا').replace(/ى/g, 'ي').replace(/ة/g, 'ه').replace(/ؤ/g, 'و').replace(/ئ/g, 'ي');
    s = s.replace(/[٠-٩]/g, function (d) { return String(DIG.indexOf(d)); });
    s = s.replace(/[^\p{L}\p{N}\s.:_\/-]/gu, ' ');
    return s.replace(/\s+/g, ' ').trim();
  }

  var SYN_RAW = [
    ['جدار', 'ناري', 'firewall', 'nftables', 'nft', 'fw4'],
    ['حجز', 'ثابت', 'static', 'lease', 'reservation'],
    ['جهاز', 'اجهزه', 'client', 'clients', 'device', 'devices'],
    ['حجب', 'حظر', 'block', 'deny', 'drop', 'ban'],
    ['سرعه', 'speed', 'rate', 'limit', 'throttle', 'kbps'],
    ['كلمه', 'مرور', 'password', 'passwd', 'pass'],
    ['تحويل', 'forward', 'redirect', 'dnat'],
    ['توقيت', 'وقت', 'ntp', 'time', 'timezone'],
    ['حاويه', 'حاويات', 'docker', 'container'],
    ['اعلانات', 'ads', 'adblock', 'adguard', 'agh'],
    ['مفتاح', 'مفاتيح', 'key', 'keys', 'ssh'],
    ['نسخ', 'احتياطي', 'backup', 'export'],
    ['اعاده', 'restart', 'reboot', 'reload'],
    ['مسار', 'توجيه', 'route', 'routing', 'gateway']
  ];
  var SYN = SYN_RAW.map(function (g) { return g.map(norm); });

  function variants(tok) {
    var out = [tok];
    for (var i = 0; i < SYN.length; i++) {
      if (SYN[i].indexOf(tok) >= 0) {
        for (var j = 0; j < SYN[i].length; j++) if (out.indexOf(SYN[i][j]) < 0) out.push(SYN[i][j]);
      }
    }
    return out;
  }
  function prepare(query) {
    var toks = norm(query).split(' ').filter(Boolean);
    return toks.map(variants);
  }
  function wordStart(h, v) { return (' ' + h).indexOf(' ' + v) >= 0; }
  function subseq(h, v) {
    var i = 0;
    for (var k = 0; k < h.length && i < v.length; k++) if (h.charAt(k) === v.charAt(i)) i++;
    return i === v.length;
  }
  var KIND_BONUS = { page: 12, setting: 8, action: 4, device: 10, rule: 6, item: 6 };

  function score(e, qt) {
    var total = 0;
    for (var i = 0; i < qt.length; i++) {
      var best = 0;
      for (var j = 0; j < qt[i].length; j++) {
        var v = qt[i][j], s = 0;
        if (e.labelN === v) s = 120;
        else if (e.labelN.indexOf(v) === 0) s = 100;
        else if (wordStart(e.labelN, v)) s = 80;
        else if (e.labelN.indexOf(v) >= 0) s = 60;
        else if (wordStart(e.hay, v)) s = 40;
        else if (e.hay.indexOf(v) >= 0) s = 25;
        else if (v.length >= 3 && subseq(e.labelN, v)) s = 10;
        if (s > best) best = s;
      }
      if (best === 0) return 0;
      total += best;
    }
    return total + (KIND_BONUS[e.kind] || 0) + (e.tabLevel ? 20 : 0);
  }
  function rank(pool, query, kinds, limit) {
    var qt = prepare(query), res = [];
    for (var i = 0; i < pool.length; i++) {
      var e = pool[i];
      if (kinds && kinds.indexOf(e.kind) < 0) continue;
      var s = qt.length ? score(e, qt) : 1;
      if (s > 0) res.push({ e: e, s: s });
    }
    res.sort(function (a, b) { return (b.s - a.s) || (a.e.label < b.e.label ? -1 : 1); });
    return res.slice(0, limit || 40).map(function (r) { return r.e; });
  }
  function mk(o) {
    o.sub = o.sub || '';
    o.crumbs = (o.crumbs || []).filter(Boolean);
    o.labelN = norm(o.label);
    o.hay = norm([o.label, o.sub, o.crumbs.join(' '), o.kw || ''].join(' '));
    o.key = o.kind + '|' + (o.tab || '') + '|' + o.label;
    return o;
  }

  if (typeof document === 'undefined') {
    if (typeof module !== 'undefined') module.exports = { norm: norm, prepare: prepare, score: score, rank: rank, mk: mk };
    return;
  }

  /* ---------- جزء المتصفح ---------- */
  var NOC = root.NOC;
  if (!NOC) { if (root.console) root.console.warn('noc-search: window.NOC غير معرّف (حمّل app.js أولاً)'); return; }

  var KIND_LBL = { page: 'قسم', setting: 'إعداد', action: 'إجراء', device: 'جهاز', rule: 'قاعدة', item: 'عنصر' };
  var PREFIX = { '/': ['page', 'setting'], '>': ['action'], '@': ['device'], '#': ['rule', 'item'] };

  var TAB_KEYS = {
    dashboard: 'dashboard performance cpu memory ram storage disk ports wan lan traffic chart throughput المعالج الذاكره المنافذ',
    adguard: 'adguard agh dns filter block ads rewrite querylog blocklist حجب اعلانات خصوصيه',
    clients: 'clients devices dhcp lease static mac arp inspect conntrack اجهزه حجز',
    network: 'network routing wan lan pppoe wifi wlan route dhcp dnsmasq mtu ssid uci',
    sqm: 'sqm cake qos shaping bufferbloat fq_codel تدفق',
    firewall: 'firewall nftables fw4 nat port forward redirect banip upnp natpmp rule جدار',
    docker: 'docker container image volume network حاويات',
    tailscale: 'tailscale vpn tailnet exit node serve peers',
    services: 'services procd cron ssh dropbear keys packages apk users totp 2fa alerts telegram ntfy ntp timezone hostname backup reboot quota schedule',
    diagnostics: 'ping traceroute nslookup tcp probe logs syslog dmesg audit security تشخيص'
  };
  var ID_KEYS = {
    netDhcpStart: 'dhcp.lan.start', netDhcpLimit: 'dhcp.lan.limit pool', netDhcpLease: 'dhcp.lan.leasetime leasetime',
    netDhcpCacheSize: 'cachesize dnsmasq', netDhcpRebindChk: 'rebind_protection dnsmasq',
    netWanUser: 'network.wan.username pppoe', netWanPass: 'network.wan.password pppoe', netWanMtu: 'network.wan.mtu',
    netWanMetric: 'network.wan.metric', netWanAutoChk: 'network.wan.auto', netPacketSteeringChk: 'packet_steering network.globals',
    wifiUplinkSsid: 'wpa_supplicant uplink sta', wifiApSsid: 'wireless.default_radio0.ssid', wifiApKey: 'wireless.default_radio0.key wpa',
    wifiApEnc: 'wireless.default_radio0.encryption sae psk2', wifiApChannel: 'wireless.radio0.channel', wifiApHtmode: 'wireless.radio0.htmode',
    sqmDownInput: 'sqm download', sqmUpInput: 'sqm upload', sqmOverheadInput: 'sqm overhead', sqmQdiscSelect: 'cake fq_codel qdisc',
    sqmScriptSelect: 'piece_of_cake layer_cake simple.qos', sqmLinklayerSelect: 'linklayer atm ethernet',
    fwSynFloodChk: 'syn_flood firewall.defaults', fwDropInvalidChk: 'drop_invalid', fwWanMasqChk: 'masq nat', fwWanMtuFixChk: 'mtu_fix mss clamping',
    banipEnableChk: 'ban_enabled banip', banipIcmpInput: 'ban_icmplimit', banipSynInput: 'ban_synlimit', banipUdpInput: 'ban_udplimit',
    upnpEnableChk: 'upnpd miniupnpd', upnpStunHostInput: 'stun', sysHostnameInput: 'system.hostname', sysZonenameSelect: 'timezone zonename',
    sysLogSizeInput: 'log_size', sysNtpServersInput: 'ntp server', sysConntrackMaxInput: 'nf_conntrack_max',
    sshPassAuthChk: 'dropbear PasswordAuth', sshRootPassAuthChk: 'RootPasswordAuth', sshNewKeyInput: 'authorized_keys',
    aghUpstreamModeSelect: 'upstream mode parallel load_balance fastest', aghCacheSizeInput: 'cache_size', aghRatelimitInput: 'ratelimit',
    clientEditRateKbps: 'rate limit throttle kbps', quotaMbInput: 'quota', alertsTgToken: 'telegram bot token', alertsNtfyUrl: 'ntfy',
    btnSysReboot: 'reboot restart gateway', btnExportSysBackup: 'backup export json', btnQuickFlushDns: 'flush dns cache',
    btnQuickSyncTime: 'ntp sync time', btnPkgUpdateRepos: 'apk update'
  };

  function el(tag, cls, text, attrs) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = String(text);
    if (attrs) for (var k in attrs) if (attrs[k] != null) n.setAttribute(k, String(attrs[k]));
    return n;
  }
  function textOf(n) { return n ? n.textContent.replace(/\s+/g, ' ').trim() : ''; }
  function motion() { return (root.matchMedia && root.matchMedia('(prefers-reduced-motion: reduce)').matches) ? 'auto' : 'smooth'; }
  function expand(card) {
    if (!card) return;
    card.classList.remove('is-collapsed');
    var b = card.querySelector('.card-collapse-btn');
    if (b) b.setAttribute('aria-expanded', 'true');
  }
  function flash(n) {
    if (!n) return;
    n.classList.add('noc-flash');
    setTimeout(function () { n.classList.remove('noc-flash'); }, 1600);
  }

  /* ---------- فهرس الإعدادات من الـ DOM (يُعاد بناؤه عند كل فتح) ---------- */
  function buildPages() {
    var out = [], seen = [], titles = NOC.TAB_TITLES || {};
    function once(n) { if (seen.indexOf(n) >= 0) return false; seen.push(n); return true; }
    document.querySelectorAll('.tab-view').forEach(function (view) {
      var tab = view.id.replace(/^view-/, ''), tabTitle = titles[tab] || tab;
      out.push(mk({ kind: 'page', tab: tab, label: tabTitle, crumbs: [], kw: TAB_KEYS[tab] || '', el: view, tabLevel: true }));
      view.querySelectorAll('article.card').forEach(function (card) {
        if (card.classList.contains('mini-stat') || card.closest('.admin-only.hidden')) return;
        var cardTitle = textOf(card.querySelector('.card-head h3'));
        var cardKw = (card.getAttribute('data-kw') || '') + ' ' + (TAB_KEYS[tab] || '');
        if (cardTitle) out.push(mk({ kind: 'page', tab: tab, label: cardTitle, crumbs: [tabTitle], kw: cardKw, el: card, cardEl: card }));
        function add(kind, label, sub, node, extraKw) {
          label = (label || '').trim();
          if (!label || !node || !once(node)) return;
          var panel = node.closest ? node.closest('.inset-panel') : null;
          var pTitle = panel ? textOf(panel.querySelector('h4')) : '';
          out.push(mk({
            kind: kind, tab: tab, label: label, sub: sub || '',
            crumbs: [tabTitle, cardTitle, pTitle && pTitle !== label ? pTitle : ''],
            kw: [extraKw || '', node.getAttribute && node.getAttribute('data-kw') || '', card.getAttribute('data-kw') || '', cardTitle].join(' '),
            el: node, cardEl: card
          }));
        }
        card.querySelectorAll('.toggle-item').forEach(function (t) {
          var inp = t.querySelector('input,select');
          add('setting', textOf(t.querySelector('.toggle-title')), textOf(t.querySelector('.toggle-sub')), inp || t, inp ? ID_KEYS[inp.id] : '');
        });
        card.querySelectorAll('.form-group').forEach(function (g) {
          var inp = g.querySelector('input,select,textarea');
          if (!inp) return;
          add('setting', textOf(g.querySelector('label')), '', inp, ID_KEYS[inp.id]);
        });
        card.querySelectorAll('.inline-form > input, .inline-form > select, .filter-bar > input, .filter-bar > select, .diag-bar > input').forEach(function (inp) {
          var lbl = inp.getAttribute('placeholder') || inp.getAttribute('aria-label') || '';
          add('setting', lbl, '', inp, ID_KEYS[inp.id]);
        });
        card.querySelectorAll('h4').forEach(function (h) { add('setting', textOf(h), '', h, ''); });
        card.querySelectorAll('button.btn[id]').forEach(function (b) {
          add('action', textOf(b), '', b, ID_KEYS[b.id]);
        });
      });
    });
    return out;
  }

  /* ---------- كيانات حيّة من حالة التطبيق (للمدير فقط) ---------- */
  function goTab(tab) { NOC.switchTab(tab); }
  function reveal(id) {
    var n = document.getElementById(id);
    if (!n) return;
    var card = n.closest('article.card') || n;
    expand(card);
    setTimeout(function () { card.scrollIntoView({ block: 'start', behavior: motion() }); flash(card); }, 80);
  }
  function viaTable(tab, bodyId, text) {
    return function () {
      goTab(tab);
      if (root.NOCTools && root.NOCTools.setFilter) root.NOCTools.setFilter(bodyId, text);
      reveal(bodyId);
    };
  }
  function entities() {
    var S = NOC.state || {}, out = [], TT = NOC.TAB_TITLES || {};
    if (S.role !== 'admin') return out;
    function add(kind, label, sub, tab, crumb, run, kw) {
      if (!label) return;
      out.push(mk({ kind: kind, tab: tab, label: String(label), sub: sub || '', crumbs: [TT[tab] || tab, crumb], kw: kw || '', run: run }));
    }
    function safe(fn) { try { fn(); } catch (e) {} }
    safe(function () {
      ((S.lastClients && S.lastClients.clients) || []).forEach(function (c) {
        if (!c.mac || c.mac === 'HIDDEN') return;
        add('device', c.display_name, ((c.ips && c.ips.length ? c.ips.join(' ') : c.ip) || '') + ' ' + c.mac, 'clients', 'الأجهزة المتصلة', function () {
          goTab('clients');
          if (root.NOCTools && root.NOCTools.setFilter) root.NOCTools.setFilter('clientsTableBody', c.mac);
          if (NOC.openClientInspector) NOC.openClientInspector(c);
        }, c.hostname || '');
      });
      ((S.lastClients && S.lastClients.static_leases_list) || []).forEach(function (l) {
        add('rule', l.name || l.mac, l.ip + ' ' + l.mac, 'clients', 'الحجوزات الثابتة', viaTable('clients', 'clientsStaticLeasesBody', l.mac), 'static lease dhcp');
      });
      ((S.lastClients && S.lastClients.local_domains) || []).forEach(function (d) {
        add('rule', d.name, d.ip, 'clients', 'النطاقات المحلية', viaTable('clients', 'clientsDomainsBody', d.name), 'local domain');
      });
    });
    safe(function () {
      var fw = S.lastFirewall || {};
      (fw.rules || []).forEach(function (r) {
        add('rule', r.name || r.id, (r.src || '*') + ' ' + (r.dest || '*') + ' ' + (r.proto || '') + ' ' + (r.dest_port || '') + ' ' + (r.target || ''), 'firewall', 'قواعد المرور', viaTable('firewall', 'fwRulesBody', r.name || r.id), r.id);
      });
      (fw.redirects || []).forEach(function (r) {
        add('rule', r.name || r.id, (r.src_dport || '') + ' ' + (r.dest_ip || '') + ':' + (r.dest_port || ''), 'firewall', 'تحويل المنافذ', viaTable('firewall', 'fwRedirectsBody', r.name || r.id), 'port forward redirect');
      });
    });
    safe(function () {
      var ag = S.lastAdGuard || {};
      (ag.rewrites || []).forEach(function (r) { add('rule', r.domain, r.answer, 'adguard', 'DNS Rewrites', viaTable('adguard', 'aghRewritesBody', r.domain), 'rewrite'); });
      (ag.filters || []).forEach(function (f) { add('rule', f.name || f.url, f.url || '', 'adguard', 'قوائم الفلاتر', viaTable('adguard', 'aghFiltersBody', f.name || f.url), 'filter blocklist'); });
      (ag.user_rules || []).forEach(function (r) {
        if (!r || r === '! [NOC-CONSOLE]') return;
        add('rule', r, '', 'adguard', 'القواعد المخصصة', function () { goTab('adguard'); reveal('aghCustomRulesList'); }, 'custom rule');
      });
    });
    safe(function () {
      ((S.lastNetwork && S.lastNetwork.static_routes) || []).forEach(function (r) {
        add('rule', r.target + '/' + r.netmask, r.gateway || '', 'network', 'المسارات الثابتة', viaTable('network', 'staticRoutesBody', r.target), 'static route');
      });
    });
    safe(function () {
      ((S.lastDocker && S.lastDocker.containers) || []).forEach(function (c) {
        add('item', c.name, c.image + ' ' + c.state, 'docker', 'الحاويات', viaTable('docker', 'dockerContainersBody', c.name), 'docker container');
      });
      ((S.lastTailscale && S.lastTailscale.peers) || []).forEach(function (p) {
        add('item', p.hostname || p.dns_name, (p.ips || []).join(' '), 'tailscale', 'الأقران', viaTable('tailscale', 'tsPeersBody', p.hostname || p.dns_name), 'peer tailscale');
      });
      var sv = S.lastServices || {};
      (sv.services || []).forEach(function (s) {
        if (s.exists === false) return;
        add('item', s.name, s.running ? 'running' : 'stopped', 'services', 'الخدمات النظامية', function () { goTab('services'); reveal('servicesGrid'); }, 'service procd init');
      });
      ((sv.ssh_settings && sv.ssh_settings.keys) || []).forEach(function (k) {
        add('item', k.comment || k.prefix, k.key_type + ' ' + k.prefix, 'services', 'مفاتيح SSH', viaTable('services', 'sshKeysBody', k.comment || k.prefix), 'ssh key');
      });
      (sv.cron_jobs || []).forEach(function (j) {
        add('item', j.line, '', 'services', 'المهام المجدولة', viaTable('services', 'cronJobsBody', j.line), 'cron');
      });
    });
    return out;
  }

  /* ---------- الآخِرات (recent) ---------- */
  var RK = 'noc.recent.v1';
  function getRecent() { try { return JSON.parse(root.localStorage.getItem(RK) || '[]'); } catch (e) { return []; } }
  function pushRecent(key) {
    try {
      var r = getRecent().filter(function (k) { return k !== key; });
      r.unshift(key);
      root.localStorage.setItem(RK, JSON.stringify(r.slice(0, 8)));
    } catch (e) {}
  }

  /* ---------- الانتقال إلى عنصر ---------- */
  function goTo(e) {
    goTab(e.tab);
    var card = e.cardEl || (e.el && e.el.closest ? e.el.closest('article.card') : null);
    expand(card);
    setTimeout(function () {
      var target = (e.el && e.el.offsetParent !== null) ? e.el : (card || e.el);
      if (!target) return;
      target.scrollIntoView({ block: e.tabLevel ? 'start' : 'center', behavior: motion() });
      if (!e.tabLevel) {
        flash(target);
        if (/^(INPUT|SELECT|TEXTAREA|BUTTON)$/.test(target.tagName)) { try { target.focus({ preventScroll: true }); } catch (x) {} }
      }
    }, 90);
  }

  /* ---------- الواجهة ---------- */
  var modal, input, box, hint, pool = [], items = [], sel = 0, lastFocus = null;

  function isOpen() { return modal && !modal.classList.contains('hidden'); }
  function runItem(e) {
    if (!e) return;
    pushRecent(e.key);
    close();
    if (e.run) e.run(); else goTo(e);
  }
  function renderList() {
    while (box.firstChild) box.removeChild(box.firstChild);
    items.forEach(function (e, i) {
      var b = el('button', 'cmd-palette-item', null, { type: 'button', role: 'option', id: 'cp-opt-' + i, 'aria-selected': i === sel ? 'true' : 'false' });
      var main = el('span', 'cp-main');
      main.appendChild(el('span', 'cp-title', e.label.length > 90 ? e.label.slice(0, 90) + '…' : e.label));
      var crumb = e.crumbs.join(' › ') + (e.sub ? (e.crumbs.length ? ' · ' : '') + e.sub : '');
      if (crumb) main.appendChild(el('span', 'cp-crumbs', crumb.length > 120 ? crumb.slice(0, 120) + '…' : crumb));
      b.appendChild(main);
      b.appendChild(el('span', 'status-pill pill-neutral', KIND_LBL[e.kind] || ''));
      b.addEventListener('click', function () { runItem(e); });
      b.addEventListener('mousemove', function () { if (sel !== i) { sel = i; mark(); } });
      box.appendChild(b);
    });
    if (!items.length) box.appendChild(el('div', 'sub-label', 'لا توجد نتائج مطابقة. جرّب كلمة أخرى أو اسم إعداد UCI (مثل network.wan.mtu).'));
    input.setAttribute('aria-activedescendant', items.length ? 'cp-opt-' + sel : '');
  }
  function mark() {
    var kids = box.querySelectorAll('.cmd-palette-item');
    kids.forEach(function (k, i) { k.setAttribute('aria-selected', i === sel ? 'true' : 'false'); });
    if (kids[sel]) { kids[sel].scrollIntoView({ block: 'nearest' }); input.setAttribute('aria-activedescendant', kids[sel].id); }
  }
  function update() {
    var raw = input.value, q = raw.trim(), kinds = null;
    if (q && PREFIX[q.charAt(0)]) { kinds = PREFIX[q.charAt(0)]; q = q.slice(1).trim(); }
    if (!q && !kinds) {
      var byKey = {};
      pool.forEach(function (e) { byKey[e.key] = e; });
      var rec = getRecent().map(function (k) { return byKey[k]; }).filter(Boolean);
      var tabs = pool.filter(function (e) { return e.tabLevel; });
      items = rec.concat(tabs.filter(function (t) { return rec.indexOf(t) < 0; }));
    } else {
      items = rank(pool, q, kinds, 40);
    }
    sel = 0;
    renderList();
  }
  function open() {
    if (!modal) return;
    lastFocus = document.activeElement;
    pool = buildPages().concat(entities());
    modal.classList.remove('hidden');
    input.value = '';
    update();
    input.focus();
  }
  function close() {
    if (!modal) return;
    modal.classList.add('hidden');
    if (lastFocus && lastFocus.focus) { try { lastFocus.focus(); } catch (e) {} }
  }

  function init() {
    modal = document.getElementById('cmdPaletteModal');
    input = document.getElementById('cmdPaletteInput');
    box = document.getElementById('cmdPaletteResults');
    if (!modal || !input || !box) return;
    box.setAttribute('role', 'listbox');
    input.setAttribute('role', 'combobox');
    input.setAttribute('aria-controls', 'cmdPaletteResults');
    input.setAttribute('aria-expanded', 'true');
    input.setAttribute('placeholder', 'ابحث عن إعداد أو جهاز أو قاعدة... (مثل: mtu، جدار، حجز، network.wan.mtu)');
    hint = el('div', 'cp-hint sub-label', '/ إعدادات   @ أجهزة   # قواعد وعناصر   > إجراءات   |   ↑↓ للتنقل، Enter للانتقال، Esc للإغلاق. البحث لا ينفّذ أي تعديل.');
    box.parentNode.appendChild(hint);

    var btn = document.getElementById('btnCmdPalette');
    if (btn) btn.addEventListener('click', open);
    var cls = document.getElementById('btnCloseCmdPalette');
    if (cls) cls.addEventListener('click', close);
    modal.addEventListener('click', function (ev) { if (ev.target === modal) close(); });
    input.addEventListener('input', update);
    input.addEventListener('keydown', function (ev) {
      if (ev.key === 'ArrowDown') { ev.preventDefault(); if (items.length) { sel = (sel + 1) % items.length; mark(); } }
      else if (ev.key === 'ArrowUp') { ev.preventDefault(); if (items.length) { sel = (sel - 1 + items.length) % items.length; mark(); } }
      else if (ev.key === 'Enter') { ev.preventDefault(); runItem(items[sel]); }
    });
    document.addEventListener('keydown', function (ev) {
      if ((ev.ctrlKey || ev.metaKey) && String(ev.key).toLowerCase() === 'k') { ev.preventDefault(); if (isOpen()) close(); else open(); }
      else if (ev.key === 'Escape' && isOpen()) { ev.preventDefault(); close(); }
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})(typeof window !== 'undefined' ? window : globalThis);
