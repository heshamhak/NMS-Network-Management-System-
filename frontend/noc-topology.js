/* Integrated Interactive Network Tree Topology (Live Router Telemetry + Simulation Mode, CSP-safe, zero innerHTML) */
(function () {
  'use strict';

  var mode = 'live';
  var zoom = 1;
  var panX = 0;
  var panY = 0;
  var hasFitted = false;
  var selectedNodeId = null;
  var pollTimer = null;
  var currentConnections = [];
  var nodeRegistry = {};
  var prevClientBytes = {};
  var deviceInstantBps = {};
  var nodeOffsets = {};
  try {
    var savedOff = localStorage.getItem('noc_topo_offsets');
    if (savedOff) nodeOffsets = JSON.parse(savedOff) || {};
  } catch (e) {}

  function saveOffsets() {
    try { localStorage.setItem('noc_topo_offsets', JSON.stringify(nodeOffsets)); } catch (e) {}
  }

  function applyNodeOffset(card, id) {
    var off = nodeOffsets[id];
    if (off && (off.dx || off.dy)) {
      card.style.transform = 'translate(' + off.dx + 'px, ' + off.dy + 'px)';
    }
  }

  function enableNodeDrag(card, id, cfg) {
    var moved = false;
    card.addEventListener('mousedown', function (ev) {
      if (ev.button !== 0 || ev.target.closest('input, button, select, label')) return;
      ev.stopPropagation();
      moved = false;
      var sx = ev.clientX, sy = ev.clientY;
      var base = nodeOffsets[id] || { dx: 0, dy: 0 };
      var dx0 = base.dx, dy0 = base.dy;
      card.classList.add('is-dragging');

      function onMove(mv) {
        var ddx = (mv.clientX - sx) / zoom;
        var ddy = (mv.clientY - sy) / zoom;
        if (Math.abs(ddx) > 3 || Math.abs(ddy) > 3) moved = true;
        if (!moved) return;
        var nx = Math.round(dx0 + ddx);
        var ny = Math.round(dy0 + ddy);
        nodeOffsets[id] = { dx: nx, dy: ny };
        card.style.transform = 'translate(' + nx + 'px, ' + ny + 'px)';
        drawConnections();
      }

      function onUp() {
        card.classList.remove('is-dragging');
        window.removeEventListener('mousemove', onMove);
        window.removeEventListener('mouseup', onUp);
        if (moved) saveOffsets();
      }

      window.addEventListener('mousemove', onMove);
      window.addEventListener('mouseup', onUp);
    });

    card.addEventListener('click', function () {
      if (moved) { moved = false; return; }
      selectedNodeId = id;
      var root = qs('view-topology');
      if (root) root.querySelectorAll('.node.selected').forEach(function (n) { n.classList.remove('selected'); });
      card.classList.add('selected');
      renderInspector(cfg);
      drawConnections();
    });
  }
  var simState = {
    wan: true, router: true, adguard: true, sqm: true, vpn: true,
    ap: true, ha: true, srv: true
  };
  var simSpeeds = {
    '192.168.1.50': 14500000,
    '192.168.1.51': 4200000,
    '192.168.1.52': 350000,
    '192.168.1.90': 0
  };
  var HEAT_MAX_BPS = 20000000;

  function qs(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function clearEl(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function fmtBps(bps) {
    var v = Math.max(0, Number(bps) || 0);
    if (v >= 1e6) return (v / 1e6).toFixed(2) + ' Mbps';
    if (v >= 1e3) return (v / 1e3).toFixed(1) + ' Kbps';
    return Math.round(v) + ' bps';
  }

  function fmtBytes(b) {
    var u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'], i = 0;
    var val = Math.max(0, Number(b) || 0);
    while (val >= 1024 && i < u.length - 1) { val /= 1024; i++; }
    return val.toFixed(i === 0 ? 0 : 1) + ' ' + u[i];
  }

  function speedToHeatColor(bps) {
    var ratio = Math.min(1, Math.max(0, (Number(bps) || 0) / HEAT_MAX_BPS));
    var hue = Math.round(142 * (1 - ratio));
    return 'hsl(' + hue + ', 82%, 50%)';
  }

  function log(msg) {
    var box = qs('topo-log-box');
    if (!box) return;
    var t = new Date().toLocaleTimeString('en-GB', { hour12: false });
    box.appendChild(el('div', null, '[' + t + '] ' + msg));
    while (box.children.length > 60) box.removeChild(box.firstChild);
    box.scrollTop = box.scrollHeight;
  }

  function makeIcon(kind) {
    var wrap = el('span', 'node-icon');
    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', '16');
    svg.setAttribute('height', '16');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');

    function add(tag, attrs) {
      var p = document.createElementNS('http://www.w3.org/2000/svg', tag);
      Object.keys(attrs).forEach(function (k) { p.setAttribute(k, attrs[k]); });
      svg.appendChild(p);
    }

    if (kind === 'ap') {
      add('circle', { cx: '12', cy: '13', r: '1.5' });
      add('path', { d: 'M8.5 9.5a5 5 0 0 1 7 0' });
      add('path', { d: 'M5.5 6.5a9 9 0 0 1 13 0' });
      add('path', { d: 'M12 14.5V20M8 20h8' });
    } else if (kind === 'ha') {
      add('path', { d: 'M3 10.5L12 3l9 7.5V20a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z' });
      add('circle', { cx: '12', cy: '14', r: '2' });
      add('path', { d: 'M12 10v2M9 17h6' });
    } else if (kind === 'srv') {
      add('rect', { x: '3', y: '4', width: '18', height: '7', rx: '1.5' });
      add('rect', { x: '3', y: '13', width: '18', height: '7', rx: '1.5' });
      add('line', { x1: '7', y1: '7.5', x2: '7.01', y2: '7.5' });
      add('line', { x1: '7', y1: '16.5', x2: '7.01', y2: '16.5' });
      add('line', { x1: '12', y1: '7.5', x2: '17', y2: '7.5' });
      add('line', { x1: '12', y1: '16.5', x2: '17', y2: '16.5' });
    } else if (kind === 'wan') {
      add('circle', { cx: '12', cy: '12', r: '9' });
      add('path', { d: 'M2 12h20M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18' });
    } else if (kind === 'router') {
      add('rect', { x: '3', y: '11', width: '18', height: '8', rx: '2' });
      add('path', { d: 'M7 11V6M17 11V6M7 15h2M12 15h5' });
    } else {
      add('rect', { x: '3', y: '4', width: '18', height: '12', rx: '2' });
      add('path', { d: 'M8 20h8M12 16v4' });
    }

    wrap.appendChild(svg);
    return wrap;
  }

  function makeNode(cfg) {
    nodeRegistry[cfg.id] = cfg;
    var card = el('div', 'node ' + cfg.stateClass + (selectedNodeId === cfg.id ? ' selected' : ''));
    card.id = cfg.id;
    card.setAttribute('data-type', cfg.type);
    if (cfg.role) card.setAttribute('data-role', cfg.role);

    var hdr = el('div', 'node-header');
    var tg = el('div', 'node-title-group');
    tg.appendChild(makeIcon(cfg.icon || cfg.role || cfg.type));
    tg.appendChild(el('span', 'node-title', cfg.title));
    hdr.appendChild(tg);
    hdr.appendChild(el('span', 'node-badge', cfg.badge));
    card.appendChild(hdr);

    var info = el('div', 'node-info');
    (cfg.lines || []).forEach(function (ln, idx) {
      if (idx > 0) info.appendChild(document.createElement('br'));
      info.appendChild(el('span', ln.mono ? 'mono' : null, ln.text));
    });
    card.appendChild(info);

    var ctrl = el('div', 'node-ctrl');
    ctrl.appendChild(el('span', null, cfg.footLabel || 'المسار'));
    if (mode === 'sim' && cfg.simKey) {
      var sw = el('label', 'switch');
      var chk = el('input');
      chk.type = 'checkbox';
      chk.checked = !!simState[cfg.simKey];
      chk.addEventListener('click', function (ev) { ev.stopPropagation(); });
      chk.addEventListener('change', function (ev) {
        simState[cfg.simKey] = ev.target.checked;
        log((ev.target.checked ? 'محاكاة تشغيل: ' : 'محاكاة إيقاف: ') + cfg.title);
        renderTree();
      });
      sw.appendChild(chk);
      sw.appendChild(el('span', 'switch-slider'));
      ctrl.appendChild(sw);
    } else {
      ctrl.appendChild(el('span', 'mono', cfg.footVal || '--'));
    }
    card.appendChild(ctrl);

    applyNodeOffset(card, cfg.id);
    enableNodeDrag(card, cfg.id, cfg);
    return card;
  }

  function makeRouterChassis(opts) {
    nodeRegistry[opts.id] = opts;
    var card = el('div', 'node router-chassis ' + opts.stateClass + (selectedNodeId === opts.id ? ' selected' : ''));
    card.id = opts.id;
    card.setAttribute('data-type', 'router');

    var hdr = el('div', 'node-header');
    hdr.appendChild(el('span', 'node-title', opts.title));
    hdr.appendChild(el('span', 'node-badge', opts.badge));
    card.appendChild(hdr);

    var core = el('div', 'router-core-bar');
    (opts.coreItems || []).forEach(function (it) {
      core.appendChild(el('span', 'sub-label mono', it));
    });
    if (mode === 'sim') {
      var sw = el('label', 'switch');
      var chk = el('input');
      chk.type = 'checkbox';
      chk.checked = !!simState.router;
      chk.addEventListener('click', function (ev) { ev.stopPropagation(); });
      chk.addEventListener('change', function (ev) {
        simState.router = ev.target.checked;
        log((ev.target.checked ? 'محاكاة تشغيل: ' : 'محاكاة إيقاف: ') + opts.title);
        renderTree();
      });
      sw.appendChild(chk);
      sw.appendChild(el('span', 'switch-slider'));
      core.appendChild(sw);
    }
    card.appendChild(core);

    var grid = el('div', 'router-edge-grid');
    (opts.modules || []).forEach(function (m) {
      var mod = el('div', 'router-module ' + (m.on ? 'is-on' : 'is-off'));
      mod.setAttribute('data-mod', m.key);
      var mh = el('div', 'router-mod-head');
      mh.appendChild(el('span', null, m.title));
      if (mode === 'sim' && m.simKey) {
        var msw = el('label', 'switch');
        var mchk = el('input');
        mchk.type = 'checkbox';
        mchk.checked = !!simState[m.simKey];
        mchk.addEventListener('click', function (ev) { ev.stopPropagation(); });
        mchk.addEventListener('change', function (ev) {
          simState[m.simKey] = ev.target.checked;
          log((ev.target.checked ? 'محاكاة تشغيل: ' : 'محاكاة إيقاف: ') + m.title);
          renderTree();
        });
        msw.appendChild(mchk);
        msw.appendChild(el('span', 'switch-slider'));
        mh.appendChild(msw);
      } else {
        mh.appendChild(el('span', 'node-badge', m.on ? 'نشط' : 'متوقف'));
      }
      mod.appendChild(mh);
      mod.appendChild(el('div', 'router-mod-sub mono', m.sub));
      grid.appendChild(mod);
    });
    card.appendChild(grid);

    applyNodeOffset(card, opts.id);
    enableNodeDrag(card, opts.id, opts);
    return card;
  }

  function renderInspector(cfg) {
    var box = qs('topoInspectorBox');
    if (!box || !cfg) return;
    clearEl(box);
    box.appendChild(el('strong', null, cfg.title));
    (cfg.details || []).forEach(function (pair) {
      var row = el('div', 'kv-row');
      row.appendChild(el('span', null, pair[0]));
      row.appendChild(el('strong', 'mono', pair[1]));
      box.appendChild(row);
    });

    if (mode === 'live' && cfg.deviceIp && window.NOC && window.NOC.apiCall) {
      var pingResEl = el('div', 'sub-label mono', '');
      var pingBtn = el('button', 'btn btn-primary btn-sm', 'فحص Ping (' + cfg.deviceIp + ')');
      pingBtn.type = 'button';
      pingBtn.addEventListener('click', async function () {
        pingResEl.textContent = 'جارٍ فحص الاتصال...';
        log('جارٍ فحص Ping للعنوان ' + cfg.deviceIp + '...');
        var r = await window.NOC.apiCall('diagnostics', { method: 'POST', body: { tool: 'ping', target: cfg.deviceIp } });
        if (r && r.ok && r.data && r.data.output) {
          var lines = r.data.output.trim().split('\n');
          var summary = lines.slice(-2).join(' | ');
          pingResEl.textContent = summary;
          log('Ping ' + cfg.deviceIp + ': ' + summary);
        } else {
          var errMsg = (r && r.errors && r.errors[0] && r.errors[0].message_ar) || 'تعذر الفحص';
          pingResEl.textContent = errMsg;
          log('Ping ' + cfg.deviceIp + ': ' + errMsg);
        }
      });
      box.appendChild(pingBtn);
      box.appendChild(pingResEl);
    }

    if (mode === 'sim' && cfg.deviceIp) {
      var simWrap = el('div', 'form-group');
      var curMbps = Math.round((simSpeeds[cfg.deviceIp] || 0) / 100000) / 10;
      var lbl = el('label', 'sub-label', 'سرعة المحاكاة اللحظية: ' + curMbps + ' Mbps');
      var rng = el('input');
      rng.type = 'range'; rng.min = '0'; rng.max = '25'; rng.step = '0.5'; rng.value = String(curMbps);
      rng.addEventListener('input', function (ev) {
        var mbps = Number(ev.target.value) || 0;
        simSpeeds[cfg.deviceIp] = mbps * 1000000;
        lbl.textContent = 'سرعة المحاكاة اللحظية: ' + mbps + ' Mbps';
        renderTree();
      });
      simWrap.appendChild(lbl);
      simWrap.appendChild(rng);
      box.appendChild(simWrap);
    }
  }

  function drawConnections() {
    var svg = qs('topo-svg');
    var stage = qs('topo-stage');
    if (!svg || !stage || stage.offsetParent === null) return;

    svg.setAttribute('width', String(stage.scrollWidth));
    svg.setAttribute('height', String(stage.scrollHeight));
    clearEl(svg);
    var sRect = stage.getBoundingClientRect();

    currentConnections.forEach(function (conn) {
      var fEl = qs(conn.from);
      var tEl = qs(conn.to);
      if (!fEl || !tEl) return;

      var fRect = fEl.getBoundingClientRect();
      var tRect = tEl.getBoundingClientRect();
      var x1 = (fRect.left + fRect.width / 2 - sRect.left) / zoom;
      var y1 = (fRect.bottom - sRect.top) / zoom;
      var x2 = (tRect.left + tRect.width / 2 - sRect.left) / zoom;
      var y2 = (tRect.top - sRect.top) / zoom;

      var fActive = fEl.classList.contains('active') && !fEl.classList.contains('disabled');
      var tActive = tEl.classList.contains('active') && !tEl.classList.contains('disabled');
      var tBroken = tEl.classList.contains('broken');
      var isActive = fActive && tActive;

      var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      var cy = y1 + (y2 - y1) / 2;
      path.setAttribute('d', 'M ' + x1 + ' ' + y1 + ' C ' + x1 + ' ' + cy + ', ' + x2 + ' ' + cy + ', ' + x2 + ' ' + y2);

      var cls = 'network-line';
      if (tBroken) cls += ' broken';
      else if (isActive) cls += ' active';
      if (selectedNodeId && (conn.from === selectedNodeId || conn.to === selectedNodeId)) cls += ' highlighted';
      path.setAttribute('class', cls);
      path.setAttribute('data-type', conn.type);
      if (isActive && conn.bps != null) {
        var ratio = Math.min(1, Math.max(0, conn.bps / HEAT_MAX_BPS));
        path.style.stroke = speedToHeatColor(conn.bps);
        path.style.strokeWidth = (2.2 + 2.6 * ratio).toFixed(1) + 'px';
        path.style.animationDuration = Math.max(8, Math.round(34 - 24 * ratio)) + 's';
      }
      if (!isActive && !tBroken) path.style.opacity = '0.18';
      svg.appendChild(path);
    });
  }

  function renderTree() {
    var colWan = qs('topo-col-wan');
    var colRouter = qs('topo-col-router');
    var colPorts = qs('topo-col-ports');
    var colDevices = qs('topo-col-devices');
    if (!colWan || !colRouter || !colPorts || !colDevices) return;
    clearEl(colWan); clearEl(colRouter); clearEl(colPorts); clearEl(colDevices);
    currentConnections = [];
    nodeRegistry = {};

    var st = (window.NOC && window.NOC.state) ? window.NOC.state : {};
    var ov = st.lastOverview;
    var cl = st.lastClients;
    var isLive = (mode === 'live' && ov && ov.system);

    var wanUp = isLive ? !!(ov.wan && ov.wan.up) : simState.wan;
    var sqmUp = isLive ? (ov.dependencies && ov.dependencies.sqm === 'ready') : (simState.sqm && wanUp);
    var routerUp = isLive ? true : (simState.router && wanUp);
    var aghUp = isLive ? (ov.dependencies && ov.dependencies.adguard === 'ready') : (simState.adguard && routerUp);
    var vpnUp = isLive ? (ov.dependencies && ov.dependencies.tailscale === 'ready') : (simState.vpn && routerUp);
    var lanUp = isLive ? !!(ov.lan && ov.lan.up) : routerUp;
    var apUp = isLive ? lanUp : (simState.ap && lanUp);
    var haUp = isLive ? lanUp : (simState.ha && lanUp);
    var srvUp = isLive ? lanUp : (simState.srv && lanUp);

    var activeDevName = (isLive && ov.wan && ov.wan.active_device) ? ov.wan.active_device : 'wlan0';
    var ifaces = (isLive && ov.interfaces) ? ov.interfaces : {};
    var wanIf = ifaces[activeDevName] || {};
    var wanSpeed = (Number(wanIf.rx_bps) || 0) + (Number(wanIf.tx_bps) || 0);
    var eth0Speed = ifaces.eth0 ? ((Number(ifaces.eth0.rx_bps) || 0) + (Number(ifaces.eth0.tx_bps) || 0)) : wanSpeed;
    var eth1Speed = ifaces.eth1 ? ((Number(ifaces.eth1.rx_bps) || 0) + (Number(ifaces.eth1.tx_bps) || 0)) : 0;
    var eth3Speed = ifaces.eth3 ? ((Number(ifaces.eth3.rx_bps) || 0) + (Number(ifaces.eth3.tx_bps) || 0)) : 0;

    colWan.appendChild(makeNode({
      id: 'topo-wan',
      type: 'wan',
      simKey: 'wan',
      title: 'مدخل الإنترنت النشط (' + activeDevName + ')',
      badge: wanUp ? 'متصل' : 'منقطع',
      stateClass: wanUp ? 'active' : 'broken',
      lines: [
        { text: 'منفذ الاتصال الخارجي | ' + ((isLive && ov.wan && ov.wan.ipv4) ? ov.wan.ipv4 : '203.0.113.10'), mono: true },
        { text: 'التدفق: ' + fmtBps(wanSpeed), mono: true }
      ],
      footLabel: 'المسار النشط',
      footVal: 'WWAN نشط',
      details: [
        ['الواجهة النشطة', activeDevName],
        ['العنوان', (isLive && ov.wan && ov.wan.ipv4) ? ov.wan.ipv4 : '203.0.113.10'],
        ['تنزيل فوري', fmtBps(wanIf.rx_bps || 0)],
        ['رفع فوري', fmtBps(wanIf.tx_bps || 0)]
      ]
    }));

    colWan.appendChild(makeNode({
      id: 'topo-wan-pppoe',
      type: 'wan',
      title: 'مدخل احتياطي: PPPoE',
      badge: 'متوقف',
      stateClass: 'disabled',
      lines: [{ text: 'اشتراك المزود الرئيسي' }, { text: 'متوقف حالياً (احتياطي)' }],
      footLabel: 'الحالة',
      footVal: 'غير نشط',
      details: [['الحالة', 'متوقف حالياً (الإنترنت يعمل عبر wlan0)']]
    }));

    var cpuPct = isLive && ov.cpu ? Math.round(ov.cpu.total_pct || 0) : 12;
    var memPct = isLive && ov.memory ? Math.round(ov.memory.used_pct || 0) : 28;
    var conns = (isLive && ov.conntrack && ov.conntrack.active) || 0;
    colRouter.appendChild(makeRouterChassis({
      id: 'topo-router',
      title: ((isLive && ov.system.hostname) ? ov.system.hostname : 'الراوتر الرئيسي') + ' (192.168.1.1) — نواة التوجيه والجدار fw4',
      badge: routerUp ? 'نشط' : 'متوقف',
      stateClass: routerUp ? 'active' : 'disabled',
      coreItems: [
        'LAN: ' + ((isLive && ov.lan && ov.lan.ipv4) ? ov.lan.ipv4 : '192.168.1.1') + '/24',
        'CPU: ' + cpuPct + '%',
        'RAM: ' + memPct + '%',
        'الاتصالات: ' + conns
      ],
      modules: [
        { key: 'sqm', simKey: 'sqm', title: '1. SQM / CAKE (عند المدخل)', on: sqmUp, sub: activeDevName + ' | 2000/4000 Kbps' },
        { key: 'adguard', simKey: 'adguard', title: '2. AdGuard DNS (:53)', on: aghUp, sub: 'تصفية الإعلانات والنطاقات' },
        { key: 'vpn', simKey: 'vpn', title: '3. Tailscale VPN', on: vpnUp, sub: 'tailscale0 | وصول مشفّر' }
      ],
      details: [
        ['المعالج', cpuPct + '%'],
        ['الذاكرة', memPct + '%'],
        ['الجلسات الحية', String(conns)],
        ['SQM/CAKE', sqmUp ? 'نشط' : 'متوقف'],
        ['AdGuard DNS', aghUp ? 'مفعّل' : 'متوقف'],
        ['Tailscale VPN', vpnUp ? 'متصل' : 'مغلق']
      ]
    }));
    currentConnections.push({ from: 'topo-wan', to: 'topo-router', type: 'primary', bps: wanSpeed });
    currentConnections.push({ from: 'topo-wan-pppoe', to: 'topo-router', type: 'primary' });

    colPorts.appendChild(makeNode({
      id: 'topo-ap',
      type: 'router',
      role: 'ap',
      icon: 'ap',
      simKey: 'ap',
      deviceIp: isLive ? '' : '192.168.1.10',
      title: 'منفذ eth0: نقطة الوصول (AP)',
      badge: apUp ? fmtBps(eth0Speed) : 'مغلق',
      stateClass: apUp ? 'active' : 'disabled',
      lines: [
        { text: isLive ? ('LAN Bridge | ' + ((ov.lan && ov.lan.device) || 'br-lan')) : 'Access-Point | 192.168.1.10', mono: true },
        { text: 'الموزع الرئيسي لأجهزة الشبكة اللاسلكية' }
      ],
      footLabel: 'التدفق',
      footVal: fmtBps(eth0Speed),
      details: isLive
        ? [['الواجهة', (ov.lan && ov.lan.device) || 'br-lan'], ['التدفق على المنفذ', fmtBps(eth0Speed)]]
        : [['الجهاز', 'Access Point (Demo)'], ['IP', '192.168.1.10'], ['MAC', '02:00:00:00:00:10'], ['التدفق على المنفذ', fmtBps(eth0Speed)]]
    }));
    currentConnections.push({ from: 'topo-router', to: 'topo-ap', type: 'success', bps: eth0Speed });

    if (!isLive) {
      colPorts.appendChild(makeNode({
        id: 'topo-ha',
        type: 'device',
        role: 'ha',
        icon: 'ha',
        simKey: 'ha',
        deviceIp: '192.168.1.20',
        title: 'منفذ eth1: عقدة خدمات ذكية',
        badge: haUp ? fmtBps(eth1Speed) : 'مغلق',
        stateClass: haUp ? 'active' : 'disabled',
        lines: [
          { text: '192.168.1.20 | :8123', mono: true },
          { text: 'عقدة أتمتة (مثال محاكاة)' }
        ],
        footLabel: 'التدفق',
        footVal: fmtBps(eth1Speed),
        details: [['IP', '192.168.1.20'], ['MAC', '02:00:00:00:00:20'], ['التدفق على المنفذ', fmtBps(eth1Speed)]]
      }));
      currentConnections.push({ from: 'topo-router', to: 'topo-ha', type: 'success', bps: eth1Speed });

      colPorts.appendChild(makeNode({
        id: 'topo-srv',
        type: 'device',
        role: 'srv',
        icon: 'srv',
        simKey: 'srv',
        deviceIp: '192.168.1.30',
        title: 'منفذ eth3: خادم محلي',
        badge: srvUp ? fmtBps(eth3Speed) : 'مغلق',
        stateClass: srvUp ? 'active' : 'disabled',
        lines: [
          { text: '192.168.1.30 | Server', mono: true },
          { text: 'خادم تطبيقات (مثال محاكاة)' }
        ],
        footLabel: 'التدفق',
        footVal: fmtBps(eth3Speed),
        details: [['IP', '192.168.1.30'], ['MAC', '02:00:00:00:00:30'], ['التدفق على المنفذ', fmtBps(eth3Speed)]]
      }));
      currentConnections.push({ from: 'topo-router', to: 'topo-srv', type: 'success', bps: eth3Speed });
    }

    var search = (qs('topoDeviceSearch') ? qs('topoDeviceSearch').value : '').toLowerCase().trim();
    var filter = qs('topoDeviceFilter') ? qs('topoDeviceFilter').value : 'online';
    var rawClients = [];
    if (isLive && cl && cl.clients) {
      rawClients = cl.clients.slice();
    } else {
      rawClients = [
        { display_name: 'Workstation-01', ip: '192.168.1.50', mac: '02:00:00:00:00:50', online: true, blocked: false, rate_limit_kbps: 0, total_rx_bytes: 250000000, total_tx_bytes: 40000000 },
        { display_name: 'Mobile-Device', ip: '192.168.1.51', mac: '02:00:00:00:00:51', online: true, blocked: false, rate_limit_kbps: 0, total_rx_bytes: 95000000, total_tx_bytes: 15000000 },
        { display_name: 'IoT-Sensor', ip: '192.168.1.52', mac: '02:00:00:00:00:52', online: true, blocked: false, rate_limit_kbps: 0, total_rx_bytes: 2200000, total_tx_bytes: 800000 }
      ];
    }

    var filtered = rawClients.filter(function (c) {
      var hay = ((c.display_name || '') + ' ' + (c.ip || '') + ' ' + (c.mac || '')).toLowerCase();
      if (search && hay.indexOf(search) < 0) return false;
      if (filter === 'online' && !c.online) return false;
      if (filter === 'blocked' && !c.blocked) return false;
      if (filter === 'limited' && !(c.rate_limit_kbps > 0)) return false;
      return true;
    }).slice(0, 12);

    var onlineTotal = 0;
    var simTotalBps = 0;
    filtered.forEach(function (c, idx) {
      var devUp = apUp && c.online && !c.blocked;
      if (devUp) onlineTotal++;
      var nid = 'topo-dev-' + idx;
      var stCls = c.blocked ? 'broken' : (devUp ? 'active' : 'disabled');
      var badge = c.blocked ? 'محجوب' : (devUp ? 'متصل' : 'غير متصل');
      var dKey = c.mac || c.ip || nid;
      var instBps = devUp ? (isLive ? (deviceInstantBps[dKey] || 0) : (simSpeeds[c.ip] || 0)) : 0;
      if (devUp && !isLive) simTotalBps += instBps;

      colDevices.appendChild(makeNode({
        id: nid,
        type: 'device',
        deviceIp: c.ip || '',
        title: c.display_name || c.ip || 'جهاز',
        badge: devUp ? fmtBps(instBps) : badge,
        stateClass: stCls,
        lines: [
          { text: (c.ip || '--') + ' | ' + (c.mac || '--'), mono: true },
          { text: fmtBytes(c.total_rx_bytes || 0) + ' / ' + fmtBytes(c.total_tx_bytes || 0), mono: true }
        ],
        footLabel: c.rate_limit_kbps > 0 ? ('محدود ' + c.rate_limit_kbps + ' Kbps') : 'السرعة اللحظية',
        footVal: devUp ? fmtBps(instBps) : badge,
        details: [
          ['الاسم', c.display_name || '--'],
          ['IP', c.ip || '--'],
          ['MAC', c.mac || '--'],
          ['السرعة اللحظية', fmtBps(instBps)],
          ['التنزيل الكلي', fmtBytes(c.total_rx_bytes || 0)],
          ['الرفع الكلي', fmtBytes(c.total_tx_bytes || 0)],
          ['الحد', c.rate_limit_kbps > 0 ? (c.rate_limit_kbps + ' Kbps') : 'غير مقيد']
        ]
      }));
      currentConnections.push({ from: 'topo-ap', to: nid, type: c.rate_limit_kbps > 0 ? 'warn' : 'success', bps: instBps });
    });

    if (filtered.length === 0) {
      colDevices.appendChild(el('div', 'node disabled', 'لا توجد أجهزة مطابقة للتصفية الحالية.'));
    }

    if (qs('topoTotalSpeed')) qs('topoTotalSpeed').textContent = isLive ? fmtBps(wanSpeed) : (wanUp && routerUp ? fmtBps(simTotalBps) : '0 bps');
    if (qs('topoActiveDevices')) qs('topoActiveDevices').textContent = onlineTotal + '/' + rawClients.length;
    if (selectedNodeId && nodeRegistry[selectedNodeId]) renderInspector(nodeRegistry[selectedNodeId]);
    requestAnimationFrame(drawConnections);
  }

  function updateClientSpeeds(clData) {
    if (!clData || !clData.clients) return;
    var nowMs = Date.now();
    clData.clients.forEach(function (c) {
      var k = c.mac || c.ip;
      if (!k) return;
      var rx = Number(c.total_rx_bytes) || 0;
      var tx = Number(c.total_tx_bytes) || 0;
      var prev = prevClientBytes[k];
      if (prev && nowMs > prev.ts) {
        var dtSec = (nowMs - prev.ts) / 1000;
        var dBytes = Math.max(0, rx - prev.rx) + Math.max(0, tx - prev.tx);
        var rawBps = (dBytes * 8) / dtSec;
        deviceInstantBps[k] = (deviceInstantBps[k] || 0) * 0.35 + rawBps * 0.65;
      }
      prevClientBytes[k] = { rx: rx, tx: tx, ts: nowMs };
    });
  }

  async function pollTopologyClients() {
    if (mode !== 'live' || document.hidden) return;
    if (!window.NOC || !window.NOC.state || window.NOC.state.activeTab !== 'topology') return;
    if (!window.NOC.state.authenticated || !window.NOC.apiCall) return;
    try {
      var r = await window.NOC.apiCall('clients', { skipSeqCheck: true, keepInFlight: true });
      if (r && r.ok && r.data) {
        window.NOC.state.lastClients = r.data;
        updateClientSpeeds(r.data);
        renderTree();
      }
    } catch (e) {}
  }

  function setMode(next) {
    mode = next;
    var isLive = mode === 'live';
    if (qs('btnTopoLive')) qs('btnTopoLive').className = 'btn btn-sm ' + (isLive ? 'btn-primary' : 'btn-secondary');
    if (qs('btnTopoSim')) qs('btnTopoSim').className = 'btn btn-sm ' + (!isLive ? 'btn-primary' : 'btn-secondary');
    if (qs('topoModeBadge')) {
      qs('topoModeBadge').textContent = isLive ? 'وضع المراقبة الحية' : 'وضع المحاكاة التفاعلية';
      qs('topoModeBadge').className = 'status-pill ' + (isLive ? 'pill-success' : 'pill-warning');
    }
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    if (isLive) {
      log('تفعيل المراقبة الحية من بيانات الراوتر الفعلية.');
      pollTopologyClients();
      pollTimer = setInterval(pollTopologyClients, 2500);
    } else {
      log('تفعيل وضع المحاكاة — اختبر المسارات دون التأثير على الراوتر.');
    }
    renderTree();
  }

  function applyTransform() {
    var stage = qs('topo-stage');
    if (stage) stage.style.transform = 'translate(' + Math.round(panX) + 'px, ' + Math.round(panY) + 'px) scale(' + zoom.toFixed(3) + ')';
    if (qs('topoZoomLabel')) qs('topoZoomLabel').textContent = Math.round(zoom * 100) + '%';
    drawConnections();
  }

  function fitToScreen() {
    var canvasEl = qs('topo-canvas');
    var treeEl = qs('topo-network-tree');
    if (!canvasEl || !treeEl || canvasEl.clientWidth === 0) return;
    var cw = canvasEl.clientWidth;
    var ch = canvasEl.clientHeight;
    var tw = Math.max(treeEl.scrollWidth, 720);
    var th = Math.max(treeEl.scrollHeight, 480);
    var pad = 32;
    zoom = Math.min(1.0, Math.max(0.35, Math.min((cw - pad) / tw, (ch - pad) / th)));
    panX = Math.round((cw - tw * zoom) / 2);
    panY = Math.max(12, Math.round((ch - th * zoom) / 2));
    hasFitted = true;
    applyTransform();
  }

  document.addEventListener('DOMContentLoaded', function () {
    if (!qs('view-topology')) return;
    if (qs('btnTopoLive')) qs('btnTopoLive').addEventListener('click', function () { setMode('live'); });
    if (qs('btnTopoSim')) qs('btnTopoSim').addEventListener('click', function () { setMode('sim'); });
    if (qs('btnTopoRefresh')) qs('btnTopoRefresh').addEventListener('click', pollTopologyClients);
    if (qs('topoDeviceSearch')) qs('topoDeviceSearch').addEventListener('input', renderTree);
    if (qs('topoDeviceFilter')) qs('topoDeviceFilter').addEventListener('change', renderTree);
    if (qs('btnTopoZoomIn')) qs('btnTopoZoomIn').addEventListener('click', function () {
      var c = qs('topo-canvas');
      var cx = c ? c.clientWidth / 2 : 300;
      var cy = c ? c.clientHeight / 2 : 250;
      var nz = Math.min(2.5, +(zoom * 1.15).toFixed(3));
      panX = cx - (cx - panX) * (nz / zoom);
      panY = cy - (cy - panY) * (nz / zoom);
      zoom = nz;
      applyTransform();
    });
    if (qs('btnTopoZoomOut')) qs('btnTopoZoomOut').addEventListener('click', function () {
      var c = qs('topo-canvas');
      var cx = c ? c.clientWidth / 2 : 300;
      var cy = c ? c.clientHeight / 2 : 250;
      var nz = Math.max(0.25, +(zoom / 1.15).toFixed(3));
      panX = cx - (cx - panX) * (nz / zoom);
      panY = cy - (cy - panY) * (nz / zoom);
      zoom = nz;
      applyTransform();
    });
    if (qs('btnTopoZoomReset')) qs('btnTopoZoomReset').addEventListener('click', fitToScreen);
    if (qs('btnTopoResetLayout')) qs('btnTopoResetLayout').addEventListener('click', function () {
      nodeOffsets = {};
      saveOffsets();
      renderTree();
      setTimeout(fitToScreen, 60);
      log('تم إرجاع جميع البطاقات إلى مواضعها الافتراضية.');
    });

    var canvasEl = qs('topo-canvas');
    if (canvasEl) {
      canvasEl.addEventListener('wheel', function (ev) {
        ev.preventDefault();
        var rect = canvasEl.getBoundingClientRect();
        var mx = ev.clientX - rect.left;
        var my = ev.clientY - rect.top;
        var factor = ev.deltaY < 0 ? 1.12 : (1 / 1.12);
        var nz = Math.min(2.5, Math.max(0.25, +(zoom * factor).toFixed(3)));
        if (nz !== zoom) {
          panX = mx - (mx - panX) * (nz / zoom);
          panY = my - (my - panY) * (nz / zoom);
          zoom = nz;
          applyTransform();
        }
      }, { passive: false });

      var panning = false, startX = 0, startY = 0, pX0 = 0, pY0 = 0;
      canvasEl.addEventListener('mousedown', function (ev) {
        if (ev.button !== 0 || ev.target.closest('.node, button, input, select, label')) return;
        panning = true;
        canvasEl.classList.add('is-panning');
        startX = ev.clientX; startY = ev.clientY;
        pX0 = panX; pY0 = panY;
      });
      window.addEventListener('mousemove', function (ev) {
        if (!panning) return;
        panX = pX0 + (ev.clientX - startX);
        panY = pY0 + (ev.clientY - startY);
        applyTransform();
      });
      window.addEventListener('mouseup', function () {
        if (!panning) return;
        panning = false;
        canvasEl.classList.remove('is-panning');
      });
    }

    document.addEventListener('noc:tab', function (ev) {
      if (ev && ev.detail && ev.detail.tab === 'topology') {
        if (mode === 'live') pollTopologyClients();
        renderTree();
        if (!hasFitted) setTimeout(fitToScreen, 120);
      }
    });
    document.addEventListener('noc:overview', function () {
      if (window.NOC && window.NOC.state && window.NOC.state.activeTab === 'topology' && mode === 'live') {
        renderTree();
      }
    });
    document.addEventListener('noc:clients', function () {
      if (window.NOC && window.NOC.state && window.NOC.state.lastClients) {
        updateClientSpeeds(window.NOC.state.lastClients);
        if (window.NOC.state.activeTab === 'topology' && mode === 'live') renderTree();
      }
    });
    window.addEventListener('resize', drawConnections);
    setMode('live');
  });
})();
