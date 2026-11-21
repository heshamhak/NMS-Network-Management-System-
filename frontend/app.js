/* NOC Operations Console Frontend Controller (CSP strict 'self', zero innerHTML, P13 epoch/seq sync) */
(function() {
  'use strict';

  const nfLatn = new Intl.NumberFormat('ar', { numberingSystem: 'latn', maximumFractionDigits: 1 });
  const nfInt = new Intl.NumberFormat('ar', { numberingSystem: 'latn', maximumFractionDigits: 0 });
  const REDUCED_MOTION = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const CIRCUMFERENCE = 2 * Math.PI * 50; // 314.159

  const state = {
    authenticated: false,
    initialized: true,
    bootstrapActive: false,
    role: 'readonly',
    username: '',
    csrfToken: '',
    activeTab: 'dashboard',
    bootId: null,
    epoch: 0,
    cursors: {},
    inFlight: {},
    lastOverview: null,
    lastOverviewTs: 0,
    lastAdGuard: null,
    lastClients: null,
    lastNetwork: null,
    lastSqm: null,
    lastFirewall: null,
    lastDocker: null,
    lastTailscale: null,
    lastServices: null,
    logsSinceSeq: 0,
    sse: null,
    pollTimer: null,
    ageTimer: null,
    rxHist: [],
    txHist: [],
    selectedIface: 'wlan0',
    tweenVals: {},
    inspectedClient: null,
    lastClientInspect: null,
    rateUnitMode: 'auto_bits',
    dataUnitMode: 'iec_auto',
    sampleSpeedMs: 1000,
    lastRenderPerfMs: 0,
    lastTrafficWindow: null,
    stopwatch: null
  };

  // --- Safe DOM Helpers (Zero innerHTML) ---
  function qs(id) { return document.getElementById(id); }

  function clearEl(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function el(tag, cls, text, attrs) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (attrs) {
      for (const k of Object.keys(attrs)) {
        if (attrs[k] !== undefined && attrs[k] !== null) node.setAttribute(k, String(attrs[k]));
      }
    }
    return node;
  }

  function showToast(msg, kind) {
    const c = qs('toastContainer');
    if (!c) return;
    const t = el('div', 'toast ' + (kind || ''), msg);
    c.appendChild(t);
    setTimeout(() => {
      if (t.parentNode) t.parentNode.removeChild(t);
    }, 4200);
  }

  const nfDec2 = new Intl.NumberFormat('ar', { numberingSystem: 'latn', minimumFractionDigits: 2, maximumFractionDigits: 2 });

  function formatBytes(b) {
    const v = Math.max(0, Number(b) || 0);
    const mode = state.dataUnitMode || 'iec_auto';
    if (mode === 'mib') return nfDec2.format(v / (1024 * 1024)) + ' MiB';
    if (mode === 'gib') return nfDec2.format(v / (1024 * 1024 * 1024)) + ' GiB';
    if (mode === 'si_auto') {
      if (v < 1000) return nfInt.format(v) + ' B';
      if (v < 1000000) return nfLatn.format(v / 1000) + ' KB';
      if (v < 1000000000) return nfDec2.format(v / 1000000) + ' MB';
      return nfDec2.format(v / 1000000000) + ' GB';
    }
    if (v < 1024) return nfInt.format(v) + ' B';
    if (v < 1024 * 1024) return nfLatn.format(v / 1024) + ' KiB';
    if (v < 1024 * 1024 * 1024) return nfDec2.format(v / (1024 * 1024)) + ' MiB';
    return nfDec2.format(v / (1024 * 1024 * 1024)) + ' GiB';
  }

  function formatBps(bps) {
    const v = Math.max(0, Number(bps) || 0);
    const mode = state.rateUnitMode || 'auto_bits';
    if (mode === 'mbps') return nfDec2.format(v / 1000000) + ' Mbps';
    if (mode === 'kbps') return nfLatn.format(v / 1000) + ' Kbps';
    if (mode === 'mbs') return nfDec2.format(v / 8000000) + ' MB/s';
    if (mode === 'kbs') return nfLatn.format(v / 8000) + ' KB/s';
    if (mode === 'auto_bytes') {
      const bSec = v / 8;
      if (bSec < 1000) return nfInt.format(bSec) + ' B/s';
      if (bSec < 1000000) return nfLatn.format(bSec / 1000) + ' KB/s';
      return nfDec2.format(bSec / 1000000) + ' MB/s';
    }
    if (v < 1000) return nfInt.format(v) + ' bps';
    if (v < 1000000) return nfLatn.format(v / 1000) + ' Kbps';
    return nfDec2.format(v / 1000000) + ' Mbps';
  }

  function formatDurationAr(sec) {
    const s = Math.max(0, Math.floor(Number(sec) || 0));
    if (s < 60) return nfInt.format(s) + ' ثانية';
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    const remS = s % 60;
    if (d > 0) return nfInt.format(d) + ' يوم و ' + nfInt.format(h) + ' س';
    if (h > 0) return nfInt.format(h) + ' ساعة و ' + nfInt.format(m) + ' د';
    return nfInt.format(m) + ' دقيقة و ' + nfInt.format(remS) + ' ث';
  }

  function formatUptime(sec) {
    const s = Math.max(0, Math.floor(Number(sec) || 0));
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d > 0) return nfInt.format(d) + ' يوم ' + nfInt.format(h) + ' س';
    return nfInt.format(h) + ' س ' + nfInt.format(m) + ' د';
  }

  // --- Tween Animated Numeric Value ---
  function setAnimatedText(id, targetVal, fmtFn) {
    const node = qs(id);
    if (!node) return;
    if (REDUCED_MOTION) {
      state.tweenVals[id] = targetVal;
      node.textContent = fmtFn(targetVal);
      return;
    }
    const startVal = (state.tweenVals[id] !== undefined) ? state.tweenVals[id] : targetVal;
    const startTime = performance.now();
    const dur = 240;
    function step(now) {
      const p = Math.min(1, (now - startTime) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      const cur = startVal + (targetVal - startVal) * eased;
      state.tweenVals[id] = cur;
      node.textContent = fmtFn(cur);
      if (p < 1) requestAnimationFrame(step);
      else state.tweenVals[id] = targetVal;
    }
    requestAnimationFrame(step);
  }

  function setGauge(arcId, meterBoxId, pctVal, warnAt, dangerAt) {
    const pct = Math.max(0, Math.min(100, Number(pctVal) || 0));
    const arc = qs(arcId);
    const box = qs(meterBoxId);
    if (arc) {
      const offset = CIRCUMFERENCE * (1 - pct / 100);
      arc.setAttribute('stroke-dashoffset', offset.toFixed(2));
      arc.classList.remove('arc-emerald', 'arc-amber', 'arc-danger');
      if (pct >= dangerAt) arc.classList.add('arc-danger');
      else if (pct >= warnAt) arc.classList.add('arc-amber');
      else arc.classList.add('arc-emerald');
    }
    if (box) box.setAttribute('aria-valuenow', String(Math.round(pct)));
  }

  // --- Fritsch-Carlson Monotone Cubic Spline (Strict Non-Negative, Zero Overshoot) ---
  function buildMonotoneSplinePath(values, width, baselineY, maxVal) {
    const n = values.length;
    if (n === 0) return { line: '', area: '', lastX: -10, lastY: baselineY };
    const topPad = 14;
    const usableH = baselineY - topPad;
    const scaleMax = Math.max(1, maxVal);
    const pts = [];
    for (let i = 0; i < n; i++) {
      const x = n === 1 ? width : (i / (n - 1)) * width;
      const ratio = Math.max(0, Math.min(1, (Number(values[i]) || 0) / scaleMax));
      const y = baselineY - ratio * usableH;
      pts.push({ x, y });
    }
    if (n === 1) {
      return {
        line: 'M ' + pts[0].x.toFixed(1) + ' ' + pts[0].y.toFixed(1),
        area: '',
        lastX: pts[0].x,
        lastY: pts[0].y
      };
    }

    const dx = [];
    const dy = [];
    const m = [];
    for (let i = 0; i < n - 1; i++) {
      dx[i] = pts[i + 1].x - pts[i].x;
      dy[i] = pts[i + 1].y - pts[i].y;
      m[i] = dx[i] !== 0 ? dy[i] / dx[i] : 0;
    }

    const tangents = new Array(n).fill(0);
    tangents[0] = m[0];
    tangents[n - 1] = m[n - 2];
    for (let i = 1; i < n - 1; i++) {
      if (m[i - 1] * m[i] <= 0) {
        tangents[i] = 0;
      } else {
        tangents[i] = (m[i - 1] + m[i]) / 2;
      }
    }
    // Enforce Fritsch-Carlson monotonicity ratio constraint
    for (let i = 0; i < n - 1; i++) {
      if (m[i] === 0) {
        tangents[i] = 0;
        tangents[i + 1] = 0;
      } else {
        const a = tangents[i] / m[i];
        const b = tangents[i + 1] / m[i];
        const hyp = Math.hypot(a, b);
        if (hyp > 3) {
          const tau = 3 / hyp;
          tangents[i] = tau * a * m[i];
          tangents[i + 1] = tau * b * m[i];
        }
      }
    }

    let d = 'M ' + pts[0].x.toFixed(1) + ' ' + pts[0].y.toFixed(1);
    for (let i = 0; i < n - 1; i++) {
      const segDx = dx[i] / 3;
      const cx1 = pts[i].x + segDx;
      const cy1 = Math.min(baselineY, Math.max(topPad, pts[i].y + segDx * tangents[i]));
      const cx2 = pts[i + 1].x - segDx;
      const cy2 = Math.min(baselineY, Math.max(topPad, pts[i + 1].y - segDx * tangents[i + 1]));
      d += ' C ' + cx1.toFixed(1) + ' ' + cy1.toFixed(1) + ', ' + cx2.toFixed(1) + ' ' + cy2.toFixed(1) + ', ' + pts[i + 1].x.toFixed(1) + ' ' + pts[i + 1].y.toFixed(1);
    }
    const area = d + ' L ' + pts[n - 1].x.toFixed(1) + ' ' + baselineY + ' L ' + pts[0].x.toFixed(1) + ' ' + baselineY + ' Z';
    return { line: d, area, lastX: pts[n - 1].x, lastY: pts[n - 1].y };
  }

  // --- P13 Consistent Epoch / Seq-Ordered HTTP Client ---
  async function apiCall(action, opts) {
    const options = opts || {};
    const method = options.method || 'GET';
    const resource = options.resource || action;
    const isMut = method === 'POST';

    if (isMut) state.epoch++;
    const reqEpoch = state.epoch;

    if (!options.keepInFlight && state.inFlight[resource]) {
      try { state.inFlight[resource].abort(); } catch (e) {}
    }
    const ctrl = new AbortController();
    state.inFlight[resource] = ctrl;

    let url = '/api?action=' + encodeURIComponent(action);
    if (options.query) {
      for (const k of Object.keys(options.query)) {
        url += '&' + encodeURIComponent(k) + '=' + encodeURIComponent(options.query[k]);
      }
    }

    const fetchOpts = {
      method,
      credentials: 'same-origin',
      signal: ctrl.signal,
      headers: {}
    };
    if (isMut) {
      fetchOpts.headers['Content-Type'] = 'application/json';
      if (state.csrfToken) fetchOpts.headers['X-CSRF-Token'] = state.csrfToken;
      fetchOpts.body = JSON.stringify(options.body || {});
    }

    let resp;
    try {
      resp = await fetch(url, fetchOpts);
    } catch (err) {
      if (err && err.name === 'AbortError') return { aborted: true };
      throw err;
    } finally {
      if (state.inFlight[resource] === ctrl) delete state.inFlight[resource];
    }

    const env = await resp.json();
    if (resp.status === 401 && action !== 'auth_login' && action !== 'auth_bootstrap' && action !== 'auth_status' && action !== 'auth_session') {
      state.authenticated = false;
      stopLiveLoop();
      checkAuthState();
      return { unauthenticated: true, env };
    }

    if (env && env.boot_id) {
      if (state.bootId && state.bootId !== env.boot_id) {
        state.cursors = {};
      }
      state.bootId = env.boot_id;
    }

    if (!isMut && !options.skipSeqCheck && env && env.resource) {
      if (reqEpoch !== state.epoch) return { stale: true, env };
      const prev = state.cursors[env.resource];
      if (prev && prev.boot_id === env.boot_id && env.seq <= prev.seq) {
        return { stale: true, env };
      }
      state.cursors[env.resource] = { boot_id: env.boot_id, seq: env.seq, at: Date.now() };
    }

    if (isMut && resp.ok && env && env.data && env.data.rollback_token) {
      showRollbackBanner(env.data.rollback_token, env.data.rollback_ttl || 60);
    }

    return { ok: resp.ok, status: resp.status, env, data: env ? env.data : {}, errors: env ? (env.errors || []) : [] };
  }

  // --- Confirmation Dialog Helper ---
  function confirmAction(title, desc) {
    return new Promise((resolve) => {
      const modal = qs('confirmModal');
      qs('confirmTitle').textContent = title;
      qs('confirmBody').textContent = desc;
      modal.classList.remove('hidden');

      function cleanup(res) {
        modal.classList.add('hidden');
        qs('confirmCancelBtn').removeEventListener('click', onCancel);
        qs('confirmProceedBtn').removeEventListener('click', onOk);
        resolve(res);
      }
      function onCancel() { cleanup(false); }
      function onOk() { cleanup(true); }
      qs('confirmCancelBtn').addEventListener('click', onCancel);
      qs('confirmProceedBtn').addEventListener('click', onOk);
    });
  }

  // --- Auth & Bootstrap State Machine ---
  let authChecking = false;
  async function checkAuthState() {
    if (authChecking) return;
    authChecking = true;
    try {
      const stRes = await apiCall('auth_status', { skipSeqCheck: true });
      const st = stRes.data || {};
      state.initialized = !!st.initialized;
      state.bootstrapActive = !!st.bootstrap_active;
      renderFreezeBanner(st.freeze || {});

      if (!state.initialized) {
        showAuthModal(true);
        return;
      }

      if (st.authenticated) {
        state.authenticated = true;
        state.role = st.role || 'readonly';
        state.username = st.username || 'user';
        state.csrfToken = st.csrf_token || '';
        qs('authOverlay').classList.add('hidden');
        applyRoleVisibility();
        startLiveLoop();
      } else {
        showAuthModal(false);
      }
    } catch (e) {
      showAuthModal(false);
    } finally {
      authChecking = false;
    }
  }

  function showAuthModal(isBootstrap) {
    qs('authOverlay').classList.remove('hidden');
    qs('authErrorBox').classList.add('hidden');
    if (isBootstrap) {
      qs('authModeTitle').textContent = 'التهيئة الأولية لحساب المدير';
      qs('authModeDesc').textContent = 'أدخل رمز التهيئة الأولية وحدد كلمة مرور قوية (12 حرفاً على الأقل).';
      qs('bootstrapTokenGroup').classList.remove('hidden');
      qs('authUserGroup').classList.add('hidden');
      qs('authPassLabel').textContent = 'كلمة المرور الجديدة للمدير';
      qs('authSubmitBtn').textContent = 'تفعيل حساب المدير';
    } else {
      qs('authModeTitle').textContent = 'تسجيل الدخول إلى نظام إدارة الشبكة NMS';
      qs('authModeDesc').textContent = 'يرجى المصادقة للوصول إلى بيانات البوابة والتحكم الشبكي.';
      qs('bootstrapTokenGroup').classList.add('hidden');
      qs('authUserGroup').classList.remove('hidden');
      qs('authPassLabel').textContent = 'كلمة المرور';
      qs('authSubmitBtn').textContent = 'دخول';
    }
  }

  function applyRoleVisibility() {
    const rb = qs('roleBadge');
    const ub = qs('cmdUserBadge');
    const isAdmin = state.role === 'admin';
    if (rb) rb.textContent = isAdmin ? 'صلاحية: مدير كامل' : 'صلاحية: مراقب (قراءة فقط)';
    if (ub) ub.textContent = (state.username || 'مستخدم') + (isAdmin ? ' (مدير)' : ' (مراقب)');
    document.querySelectorAll('.admin-only').forEach((node) => {
      if (isAdmin) node.classList.remove('hidden');
      else node.classList.add('hidden');
    });
    if (!isAdmin && qs('clientEditPanel')) qs('clientEditPanel').classList.add('hidden');
    if (!isAdmin && qs('clientDeepInspectPanel')) qs('clientDeepInspectPanel').classList.add('hidden');
    document.dispatchEvent(new CustomEvent('noc:auth'));
  }

  async function handleAuthSubmit(ev) {
    ev.preventDefault();
    const errBox = qs('authErrorBox');
    errBox.classList.add('hidden');
    const pw = qs('authPassInput').value || '';

    if (!state.initialized) {
      const tok = (qs('bootstrapTokenInput').value || '').trim();
      if (pw.length < 12) {
        errBox.textContent = 'يجب أن لا يقل طول كلمة المرور عن 12 حرفاً.';
        errBox.classList.remove('hidden');
        return;
      }
      const res = await apiCall('auth_bootstrap', { method: 'POST', body: { token: tok, password: pw } });
      if (res.ok && res.data && res.data.authenticated) {
        qs('authPassInput').value = '';
        qs('bootstrapTokenInput').value = '';
        await checkAuthState();
        showToast('تم تفعيل حساب المدير بنجاح', 'success');
      } else {
        errBox.textContent = (res.errors && res.errors[0] && res.errors[0].message_ar) || 'فشل إتمام التهيئة الأولية.';
        errBox.classList.remove('hidden');
      }
      return;
    }

    const user = (qs('authUserInput').value || 'admin').trim();
    const totpCode = qs('authTotpInput') ? (qs('authTotpInput').value || '').trim() : '';
    const res = await apiCall('auth_login', { method: 'POST', body: { username: user, password: pw, totp_code: totpCode } });
    if (res.ok && res.data && res.data.authenticated) {
      qs('authPassInput').value = '';
      if (qs('authTotpInput')) qs('authTotpInput').value = '';
      if (qs('authTotpGroup')) qs('authTotpGroup').classList.add('hidden');
      state.authenticated = true;
      state.role = res.data.role || 'readonly';
      state.username = res.data.username || user;
      state.csrfToken = res.data.csrf_token || '';
      qs('authOverlay').classList.add('hidden');
      applyRoleVisibility();
      startLiveLoop();
      showToast('تم تسجيل الدخول بنجاح', 'success');
    } else {
      if (res.data && res.data.totp_required && qs('authTotpGroup')) {
        qs('authTotpGroup').classList.remove('hidden');
        if (qs('authTotpInput')) qs('authTotpInput').focus();
      }
      errBox.textContent = (res.errors && res.errors[0] && res.errors[0].message_ar) || 'بيانات الدخول غير صحيحة.';
      errBox.classList.remove('hidden');
    }
  }

  function renderFreezeBanner(freeze) {
    const b = qs('globalFreezeBanner');
    if (!b) return;
    if (freeze && freeze.frozen) {
      b.classList.remove('hidden');
      qs('freezeReasonText').textContent = (freeze.reason || 'فشل تراجع آلي سابق') + (freeze.ts ? ' (' + freeze.ts + ')' : '');
    } else {
      b.classList.add('hidden');
    }
  }

  // --- Navigation ---
  const TAB_TITLES = {
    dashboard: 'الأداء العام والمنافذ',
    topology: 'شجرة المسارات الحية',
    adguard: 'الحجب والخصوصية (AdGuard)',
    clients: 'الأجهزة المتصلة',
    network: 'الشبكة والتوجيه',
    sqm: 'إدارة التدفق SQM',
    firewall: 'الجدار الناري',
    docker: 'الحاويات البرمجية',
    tailscale: 'الشبكة الخاصة VPN',
    services: 'الخدمات والصلاحيات',
    diagnostics: 'التشخيص والتدقيق'
  };

  function switchTab(tab) {
    state.activeTab = tab;
    document.querySelectorAll('.sidebar-btn').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.tab === tab);
    });
    document.querySelectorAll('.tab-view').forEach((sec) => {
      sec.classList.toggle('active', sec.id === 'view-' + tab);
    });
    const titleNode = qs('activePageTitle');
    if (titleNode) titleNode.textContent = TAB_TITLES[tab] || 'نظام إدارة الشبكة NMS';
    closeMobileDrawer();
    refreshActiveTab();
    document.dispatchEvent(new CustomEvent('noc:tab', { detail: { tab: tab } }));
  }

  function closeMobileDrawer() {
    qs('mainSidebar').classList.remove('open');
    qs('mobileNavBackdrop').classList.add('hidden');
    qs('mobileNavBtn').setAttribute('aria-expanded', 'false');
  }

  // --- Render Overview (Dashboard) ---
  function renderOverview(data) {
    if (!data || !data.system) return;
    state.lastOverview = data;
    state.lastOverviewTs = Date.now();
    document.dispatchEvent(new CustomEvent('noc:overview'));

    const badge = qs('cmdConnBadge');
    badge.textContent = 'متصل مباشرة';
    badge.className = 'status-pill pill-success';

    qs('sidebarHostname').textContent = data.system.hostname || 'Network Management System';
    qs('cmdGwName').textContent = (data.lan && data.lan.ipv4) ? data.lan.ipv4 : '192.168.1.1';
    qs('sysReleaseText').textContent = data.system.model || '--';
    qs('sysKernelText').textContent = 'Kernel ' + (data.system.kernel || '--') + ' | ' + (data.system.arch || 'x86_64');
    qs('uptimeBadge').textContent = formatUptime(data.system.uptime);

    // Health Strip
    const strip = qs('cmdHealthStrip');
    clearEl(strip);
    const deps = data.dependencies || {};
    const depLabels = {
      adguard: 'الحجب', firewall: 'الجدار', sqm: 'SQM', docker: 'الحاويات',
      tailscale: 'VPN', ntp: 'التوقيت', helper: 'المساعد', storage: 'التخزين'
    };
    for (const k of Object.keys(depLabels)) {
      const st = deps[k] || 'unavailable';
      const pill = el('span', 'health-pill');
      pill.appendChild(el('span', 'health-dot ' + st));
      pill.appendChild(document.createTextNode(depLabels[k]));
      strip.appendChild(pill);
    }

    // Drift Banners (P3 storage + P6 route drift + P7 SQM standby drift)
    const driftMsgs = [];
    if (data.wan && !data.wan.up) {
      driftMsgs.push('تنبيه المسار: لا يوجد منفذ اتصال خارجي نشط حالياً.');
    } else if (data.wan && data.wan.route_drift) {
      driftMsgs.push('تنبيه المسار: المنفذ الافتراضي pppoe-wan متوقف حالياً، وتعمل البوابة عبر ' + (data.wan.active_device || 'wlan0') + ' (' + (data.wan.wwan_ipv4 || '--') + ').');
    }
    if (data.wan && data.wan.sqm_standby_drift) {
      driftMsgs.push('انحراف SQM: تشكيل التدفق مربوط بواجهة pppoe-wan بينما الحركة الفعلية تمر عبر ' + data.wan.active_device + '.');
    }
    const storSum = data.storage_summary || {};
    if (storSum.low_space_warning) {
      driftMsgs.push('تنبيه المساحة: نظام الجذر (/) يستخدم ' + nfLatn.format((data.disks && data.disks[0] && data.disks[0].pct) || 88) + '% من أصل ' + formatBytes(storSum.filesystem_bytes) + ' (متبقٍ ' + nfInt.format(storSum.free_mib || 0) + ' MiB).');
    }
    const driftBox = qs('globalDriftBanner');
    if (qs('cmdAlertBadge')) {
      qs('cmdAlertBadge').textContent = 'التنبيهات: ' + nfInt.format(driftMsgs.length);
      qs('cmdAlertBadge').className = 'status-pill ' + (driftMsgs.length > 0 ? 'pill-warning' : 'pill-success');
    }
    if (data.platform_health && qs('platformHealthList')) {
      const ph = data.platform_health;
      const phEl = qs('platformHealthList');
      clearEl(phEl);
      const rows = [
        ['طلبات API', nfInt.format(ph.api_requests || 0)],
        ['اتصالات البث الحي (SSE)', nfInt.format(ph.sse_clients || 0)],
        ['ذاكرة الخادم (RSS)', nfInt.format(Math.round((ph.apid_rss_kb || 0) / 1024)) + ' MiB']
      ];
      for (const [lbl, val] of rows) {
        const r = el('div', 'kv-row');
        r.appendChild(el('span', null, lbl));
        r.appendChild(el('strong', 'mono', val));
        phEl.appendChild(r);
      }
    }
    if (driftMsgs.length > 0) {
      qs('driftBannerText').textContent = driftMsgs.join(' — ');
      driftBox.classList.remove('hidden');
    } else {
      driftBox.classList.add('hidden');
    }

    // CPU
    const cpuPct = Number(data.cpu && data.cpu.total_pct) || 0;
    setGauge('cpuGaugeArc', 'cpuMeterBox', cpuPct, 70, 90);
    setAnimatedText('cpuTotalPct', cpuPct, (v) => nfLatn.format(v) + '%');
    qs('cpuTotalBar').style.width = Math.min(100, cpuPct) + '%';
    qs('cpuModelText').textContent = data.system.cpu_model || '--';
    const ld = data.system.load || [0, 0, 0];
    qs('loadAvgText').textContent = ld.map((x) => Number(x).toFixed(2)).join(' / ');
    if (data.temps && data.temps.length > 0) {
      qs('cpuTempBadge').textContent = nfLatn.format(data.temps[0].temp_c) + ' °C';
    }
    const coresGrid = qs('cpuCoresGrid');
    clearEl(coresGrid);
    for (const c of (data.cpu && data.cpu.cores) || []) {
      const chip = el('div', 'core-chip');
      chip.appendChild(el('span', 'sub-label mono', c.name));
      chip.appendChild(el('strong', 'mono', c.pct !== null ? nfInt.format(c.pct) + '%' : '--'));
      coresGrid.appendChild(chip);
    }

    // RAM + Conntrack
    const mem = data.memory || {};
    const ramPct = Number(mem.used_pct) || 0;
    setGauge('ramGaugeArc', 'ramMeterBox', ramPct, 75, 90);
    setAnimatedText('ramGaugePct', ramPct, (v) => nfLatn.format(v) + '%');
    qs('ramPctBadge').textContent = nfLatn.format(ramPct) + '%';
    qs('ramUsedText').textContent = formatBytes(mem.used) + ' / ' + formatBytes(mem.total);
    qs('ramAvailText').textContent = formatBytes(mem.available);
    qs('ramBar').style.width = Math.min(100, ramPct) + '%';

    const ct = data.conntrack || {};
    if (ct.supported) {
      qs('conntrackText').textContent = nfInt.format(ct.active) + ' / ' + nfInt.format(ct.max);
      qs('conntrackBar').style.width = Math.min(100, Number(ct.pct) || 0) + '%';
    } else {
      qs('conntrackText').textContent = 'غير مدعوم على النواة';
      qs('conntrackBar').style.width = '0%';
    }

    // Storage (Honest Rootfs vs NVMe Partition)
    const rootFs = (data.disks && data.disks.find((d) => d.mount === '/')) || (data.disks && data.disks[0]);
    if (rootFs) {
      setGauge('diskGaugeArc', 'diskMeterBox', rootFs.pct, 90, 95);
      setAnimatedText('diskGaugePct', rootFs.pct, (v) => nfLatn.format(v) + '%');
      qs('diskUsedText').textContent = formatBytes(rootFs.used) + ' / ' + formatBytes(rootFs.total);
      qs('diskAvailText').textContent = formatBytes(rootFs.avail);
    }
    qs('nvmeSummaryText').textContent = formatBytes(storSum.partition_bytes || 0);
    const disksStrip = qs('disksContainer');
    clearEl(disksStrip);
    for (const d of (data.disks || [])) {
      const pill = el('div', 'disk-pill');
      pill.appendChild(el('span', 'mono', d.mount));
      pill.appendChild(el('strong', 'mono', nfLatn.format(d.pct) + '% (' + formatBytes(d.avail) + ' حر)'));
      disksStrip.appendChild(pill);
    }

    // Physical Ports Section (Split into 1. Internet Ingress WAN/WWAN vs 2. Internet Egress LAN/Distribution)
    const ingressStrip = qs('portsIngressStrip');
    const egressStrip = qs('portsEgressStrip');
    clearEl(ingressStrip);
    clearEl(egressStrip);
    const ifaces = data.interfaces || {};
    const wanData = data.wan || {};
    const lanData = data.lan || {};

    const PORT_ROLES = {
      'wlan0': 'بوابة الإنترنت اللاسلكية النشطة (WWAN)',
      'eth0': 'منفذ الإنترنت السلكي الرئيسي (WAN)',
      'pppoe-wan': 'نفق اشتراك المزود (PPPoE WAN)',
      'ifb4wlan0': 'قناة تشكيل التدفق الوارد (SQM IFB)',
      'ifb4pppoe-wan': 'قناة تشكيل التدفق الوارد (SQM IFB)',
      'br-lan': 'الجسر المحلي الرئيسي لتوزيع الإنترنت (LAN)',
      'eth1': 'منفذ خروج محلي LAN 1 (2.5 GbE)',
      'eth2': 'منفذ خروج محلي LAN 2 (2.5 GbE)',
      'eth3': 'منفذ خروج محلي LAN 3 (2.5 GbE)',
      'tailscale0': 'منفذ خروج الشبكة الخاصة المشفرة (VPN)',
      'docker0': 'جسر خروج الحاويات البرمجية (Docker)'
    };

    const ingressNames = ['wlan0', 'eth0', 'pppoe-wan', 'ifb4wlan0', 'ifb4pppoe-wan'].filter((n) => ifaces[n]);
    const ingressSet = new Set(ingressNames);
    const egressOrder = ['br-lan', 'eth1', 'eth2', 'eth3', 'tailscale0', 'docker0'];
    const egressNames = egressOrder.filter((n) => ifaces[n]).concat(
      Object.keys(ifaces).filter((n) => !ingressSet.has(n) && egressOrder.indexOf(n) < 0)
    );

    if (qs('portsIngressBadge')) {
      qs('portsIngressBadge').textContent = 'المسار النشط: ' + (wanData.active_device || 'wlan0') + (wanData.ipv4 ? (' (' + wanData.ipv4 + ')') : '');
      qs('portsIngressBadge').className = 'status-pill mono ' + (wanData.up ? 'pill-success' : 'pill-danger');
    }
    if (qs('portsEgressBadge')) {
      qs('portsEgressBadge').textContent = 'بوابة الخروج: ' + (lanData.device || 'br-lan') + ' (' + (lanData.ipv4 || '192.168.1.1') + '/' + (lanData.mask || 24) + ')';
    }

    function appendPortTile(container, name, isIngress) {
      if (!container || !ifaces[name]) return;
      const inf = ifaces[name];
      const up = inf.carrier || inf.operstate === 'up';
      const isPrimaryActive = isIngress && wanData.active_device === name;
      const tile = el('div', 'port-tile ' + (up ? 'up' : 'down'));
      const top = el('div', 'port-top');
      top.appendChild(el('span', 'port-name mono', name));
      top.appendChild(
        el(
          'span',
          'status-pill ' + (isPrimaryActive ? 'pill-success' : (up ? 'pill-success' : 'pill-neutral')),
          isPrimaryActive ? 'البوابة النشطة' : (up ? 'متصل' : 'غير متصل')
        )
      );
      tile.appendChild(top);
      const roleDesc = PORT_ROLES[name] || (isIngress ? 'منفذ دخول إنترنت' : 'منفذ خروج وتوزيع محلي');
      tile.appendChild(el('div', 'port-role', roleDesc));
      let ipInfo = '';
      if (name === 'wlan0' && wanData.wwan_ipv4) ipInfo = ' | IP: ' + wanData.wwan_ipv4;
      else if (name === 'pppoe-wan' && wanData.pppoe_ipv4) ipInfo = ' | IP: ' + wanData.pppoe_ipv4;
      else if (name === 'br-lan' && lanData.ipv4) ipInfo = ' | IP: ' + lanData.ipv4;
      const spdStr = (inf.speed ? (nfInt.format(inf.speed) + ' Mbps' + (inf.duplex ? ' (' + inf.duplex + ')' : '')) : (up ? 'نشط' : '--')) + ipInfo;
      tile.appendChild(el('div', 'port-speed mono', spdStr));
      tile.appendChild(el('div', 'port-bytes mono', 'RX ' + formatBytes(inf.rx_bytes) + ' | TX ' + formatBytes(inf.tx_bytes)));
      container.appendChild(tile);
    }

    for (const name of ingressNames) appendPortTile(ingressStrip, name, true);
    for (const name of egressNames.slice(0, 10)) appendPortTile(egressStrip, name, false);

    // Live Throughput Chart
    const wanInfo = data.wan || {};
    qs('wanBadge').textContent = (wanInfo.up ? ('نشط: ' + wanInfo.active_device + ' (' + (wanInfo.ipv4 || '--') + ')') : 'غير متصل');
    qs('wanBadge').className = 'status-pill ' + (wanInfo.up ? 'pill-success' : 'pill-danger');

    const sel = ifaces[state.selectedIface] || ifaces[wanInfo.active_device] || ifaces['br-lan'];
    if (sel) {
      const nowPerf = performance.now();
      if (state.lastRenderPerfMs > 0 && qs('actualSampleDtText')) {
        const dtSec = Math.max(0.2, (nowPerf - state.lastRenderPerfMs) / 1000);
        qs('actualSampleDtText').textContent = nfDec2.format(dtSec) + ' ث';
      }
      state.lastRenderPerfMs = nowPerf;

      const rxBps = Number(sel.rx_bps) || 0;
      const txBps = Number(sel.tx_bps) || 0;
      setAnimatedText('liveRxSpeed', rxBps, formatBps);
      setAnimatedText('liveTxSpeed', txBps, formatBps);
      qs('totalRxBytes').textContent = 'المجموع: ' + formatBytes(sel.rx_bytes);
      qs('totalTxBytes').textContent = 'المجموع: ' + formatBytes(sel.tx_bytes);

      state.rxHist.push(rxBps);
      state.txHist.push(txBps);
      if (state.rxHist.length > 36) state.rxHist.shift();
      if (state.txHist.length > 36) state.txHist.shift();

      const peak = Math.max(100000, ...state.rxHist, ...state.txHist);
      qs('chartPeakLabel').textContent = 'سقف القياس: ' + formatBps(peak);

      if (!state.netChart && window.NetChart && qs('net-chart-root')) {
        state.netChart = window.NetChart.mount(qs('net-chart-root'), {
          title: state.selectedIface || 'wlan0',
          unit: state.rateUnitMode || 'auto_bits',
          range: 300
        });
      }
      if (state.netChart) {
        state.netChart.push(rxBps, txBps, Date.now());
      }

      if (state.stopwatch && state.stopwatch.active) {
        updateStopwatchDisplay(sel);
      } else if (!state.lastTrafficWindow) {
        fetchTrafficWindow();
      }
    }
  }

  function getSelectedWindowSeconds() {
    const preset = qs('trafficWindowPresetSelect') ? qs('trafficWindowPresetSelect').value : '300';
    if (preset === 'custom') {
      const n = Math.max(1, Number(qs('trafficCustomDurationInput') ? qs('trafficCustomDurationInput').value : 10) || 10);
      const u = Math.max(60, Number(qs('trafficCustomUnitSelect') ? qs('trafficCustomUnitSelect').value : 60) || 60);
      return n * u;
    }
    return Number(preset);
  }

  async function fetchTrafficWindow() {
    if (state.stopwatch && state.stopwatch.active) return;
    const iface = state.selectedIface || 'wlan0';
    const sec = getSelectedWindowSeconds();
    const r = await apiCall('traffic_window', { query: { iface, seconds: sec }, skipSeqCheck: true, keepInFlight: true });
    if (r && r.ok && r.data && r.data.window) {
      state.lastTrafficWindow = r.data.window;
      renderTrafficWindowCard(r.data.window);
    }
  }

  function renderTrafficWindowCard(w) {
    if (!w || !qs('winRxBytesText')) return;
    const srcLabels = {
      high_res_1s_ring: 'قياس حلقي عالي الدقة (عينة/ثانية)',
      rrd_archive: 'سجل الأرشيف الزمني (RRD 30s)',
      active_session_ring: 'المتوفر منذ بدء جلسة الرصد الحالية',
      kernel_total_since_boot: 'إجمالي عداد النواة منذ إقلاع النظام'
    };
    if (qs('winPeriodLabel')) {
      qs('winPeriodLabel').textContent = 'المدة المحسوبة (' + (w.interface || state.selectedIface) + ')';
    }
    qs('winCoveredText').textContent = formatDurationAr(w.covered_sec || 0);
    qs('winSourceText').textContent = srcLabels[w.source] || w.source || '--';
    qs('winRxBytesText').textContent = formatBytes(w.rx_bytes || 0);
    qs('winAvgRxRateText').textContent = 'المتوسط: ' + formatBps(w.avg_rx_bps || 0);
    qs('winTxBytesText').textContent = formatBytes(w.tx_bytes || 0);
    qs('winAvgTxRateText').textContent = 'المتوسط: ' + formatBps(w.avg_tx_bps || 0);
    qs('winTotalBytesText').textContent = formatBytes(w.total_bytes || ((w.rx_bytes || 0) + (w.tx_bytes || 0)));
    qs('winPeakRateText').textContent = 'الذروة: ' + formatBps(Math.max(w.peak_rx_bps || 0, w.peak_tx_bps || 0));
  }

  function toggleTrafficStopwatch() {
    const btn = qs('btnToggleTrafficStopwatch');
    if (state.stopwatch && state.stopwatch.active) {
      state.stopwatch.active = false;
      if (btn) {
        btn.textContent = 'بدء عداد قياس مباشر';
        btn.className = 'btn btn-primary btn-sm';
      }
      showToast('تم إيقاف عداد القياس المباشر وتثبيت القراءة', 'success');
      return;
    }
    const ifaces = (state.lastOverview && state.lastOverview.interfaces) || {};
    const sel = ifaces[state.selectedIface] || ifaces['wlan0'] || { rx_bytes: 0, tx_bytes: 0, rx_bps: 0, tx_bps: 0 };
    state.stopwatch = {
      active: true,
      iface: state.selectedIface || 'wlan0',
      startMs: Date.now(),
      baseRx: Number(sel.rx_bytes) || 0,
      baseTx: Number(sel.tx_bytes) || 0,
      peakBps: Math.max(Number(sel.rx_bps) || 0, Number(sel.tx_bps) || 0)
    };
    if (btn) {
      btn.textContent = 'إيقاف عداد القياس المباشر';
      btn.className = 'btn btn-danger btn-sm';
    }
    updateStopwatchDisplay(sel);
    showToast('بدأ عداد قياس الاستهلاك المباشر للواجهة ' + state.stopwatch.iface, 'success');
  }

  function updateStopwatchDisplay(sel) {
    if (!state.stopwatch || !state.stopwatch.active || !sel) return;
    const elapsedSec = Math.max(1, (Date.now() - state.stopwatch.startMs) / 1000);
    const drx = Math.max(0, (Number(sel.rx_bytes) || 0) - state.stopwatch.baseRx);
    const dtx = Math.max(0, (Number(sel.tx_bytes) || 0) - state.stopwatch.baseTx);
    const curPeak = Math.max(state.stopwatch.peakBps, Number(sel.rx_bps) || 0, Number(sel.tx_bps) || 0);
    state.stopwatch.peakBps = curPeak;

    if (qs('winPeriodLabel')) qs('winPeriodLabel').textContent = 'عداد القياس المباشر (' + state.stopwatch.iface + ')';
    qs('winCoveredText').textContent = formatDurationAr(elapsedSec);
    qs('winSourceText').textContent = 'عداد مباشر حي من عدادات النواة';
    qs('winRxBytesText').textContent = formatBytes(drx);
    qs('winAvgRxRateText').textContent = 'المتوسط: ' + formatBps((drx * 8) / elapsedSec);
    qs('winTxBytesText').textContent = formatBytes(dtx);
    qs('winAvgTxRateText').textContent = 'المتوسط: ' + formatBps((dtx * 8) / elapsedSec);
    qs('winTotalBytesText').textContent = formatBytes(drx + dtx);
    qs('winPeakRateText').textContent = 'الذروة: ' + formatBps(curPeak);
  }

  // --- Render AdGuard Home ---
  const SERVICE_LABELS = {
    youtube: 'YouTube', tiktok: 'TikTok', instagram: 'Instagram', facebook: 'Facebook',
    whatsapp: 'WhatsApp', telegram: 'Telegram', discord: 'Discord', netflix: 'Netflix',
    snapchat: 'Snapchat', roblox: 'Roblox', steam: 'Steam', twitch: 'Twitch',
    twitter: 'X / Twitter', reddit: 'Reddit'
  };

  function isFocusedWithin(containerId) {
    const c = qs(containerId);
    return !!(c && document.activeElement && c.contains(document.activeElement));
  }

  function renderAdGuard(data) {
    state.lastAdGuard = data;
    if (!data) return;
    const stats = data.stats || {};
    qs('aghTotalQueries').textContent = nfInt.format(stats.sampled_queries || 0);
    qs('aghAllowedQueries').textContent = nfInt.format(stats.allowed_queries || 0);
    qs('aghBlockedQueries').textContent = nfInt.format(stats.blocked_queries || 0);
    qs('aghAllowPct').textContent = nfLatn.format(stats.allowed_pct || 0) + '%';
    qs('aghBlockPct').textContent = nfLatn.format(stats.blocked_pct || 0) + '%';
    qs('aghActiveClientsCount').textContent = nfInt.format((data.client_stats || []).length);
    qs('aghAvgMs').textContent = (stats.avg_ms !== null && stats.avg_ms !== undefined) ? nfLatn.format(stats.avg_ms) : '--';
    qs('aghFiltersCount').textContent = nfInt.format((data.filters || []).length);
    qs('aghStatusText').textContent = data.api_connected ? (data.protection_enabled ? 'الحماية مفعلة' : 'الحماية متوقفة مؤقتاً') : (data.api_error || 'اتصال API غير مهيأ');

    qs('aghProtToggle').checked = !!data.protection_enabled;
    qs('aghSafeToggle').checked = !!data.safebrowsing_enabled;
    qs('aghParentalToggle').checked = !!data.parental_enabled;
    qs('aghSafeSearchToggle').checked = !!data.safesearch_enabled;
    if (qs('aghDnssecToggle')) qs('aghDnssecToggle').checked = !!data.enable_dnssec;
    if (qs('aghCacheToggle')) qs('aghCacheToggle').checked = data.cache_enabled !== false;
    if (qs('aghIpv6BlockToggle')) qs('aghIpv6BlockToggle').checked = !!data.aaaa_disabled;

    const dinfo = data.dns_info || {};
    if (qs('aghUpstreamModeSelect') && document.activeElement !== qs('aghUpstreamModeSelect')) {
      qs('aghUpstreamModeSelect').value = dinfo.upstream_mode || 'parallel';
    }
    if (qs('aghCacheSizeInput') && document.activeElement !== qs('aghCacheSizeInput')) {
      qs('aghCacheSizeInput').value = String(dinfo.cache_size !== undefined ? dinfo.cache_size : 67108864);
    }
    if (qs('aghRatelimitInput') && document.activeElement !== qs('aghRatelimitInput')) {
      qs('aghRatelimitInput').value = String(dinfo.ratelimit || 0);
    }

    if (!data.api_connected && state.role === 'admin') {
      qs('aghCredsSetupBox').classList.remove('hidden');
    }

    // Blocked Services Grid
    const bsGrid = qs('aghBlockedServicesGrid');
    if (bsGrid && !isFocusedWithin('aghBlockedServicesGrid')) {
      clearEl(bsGrid);
      const blockedSet = new Set(data.blocked_services || []);
      const avail = data.available_services || Object.keys(SERVICE_LABELS);
      for (const sid of avail) {
        const item = el('div', 'toggle-item');
        item.appendChild(el('span', 'toggle-title mono', SERVICE_LABELS[sid] || sid));
        const lbl = el('label', 'switch');
        const chk = el('input', 'agh-srv-chk', null, { type: 'checkbox', 'data-service': sid });
        chk.checked = blockedSet.has(sid);
        lbl.appendChild(chk);
        lbl.appendChild(el('span', 'switch-slider'));
        item.appendChild(lbl);
        bsGrid.appendChild(item);
      }
    }

    // DNS Rewrites Table
    const rwBody = qs('aghRewritesBody');
    if (rwBody) {
      clearEl(rwBody);
      for (const rw of (data.rewrites || [])) {
        const tr = el('tr');
        tr.appendChild(el('td', 'mono', rw.domain || ''));
        tr.appendChild(el('td', 'mono', rw.answer || ''));
        const ac = el('td');
        const delBtn = el('button', 'btn btn-danger btn-sm', 'حذف', { type: 'button' });
        delBtn.addEventListener('click', async () => {
          const r = await apiCall('adguard_control', { method: 'POST', body: { subaction: 'rewrite_delete', domain: rw.domain, answer: rw.answer } });
          if (r.ok) { showToast('تم حذف التوجيه بنجاح', 'success'); refreshActiveTab(); }
          else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل الحذف', 'error');
        });
        ac.appendChild(delBtn);
        tr.appendChild(ac);
        rwBody.appendChild(tr);
      }
    }

    // Filter Subscriptions Table
    const flBody = qs('aghFiltersBody');
    if (flBody) {
      clearEl(flBody);
      for (const f of (data.filters || [])) {
        const tr = el('tr');
        tr.appendChild(el('td', '', f.name || f.url));
        tr.appendChild(el('td', 'mono', nfInt.format(f.rules_count || 0)));
        const stTd = el('td');
        stTd.appendChild(el('span', 'status-pill ' + (f.enabled ? 'pill-success' : 'pill-neutral'), f.enabled ? 'مفعلة' : 'معطلة'));
        tr.appendChild(stTd);
        const ac = el('td');
        const wrap = el('div', 'cell-actions');
        const tgBtn = el('button', 'btn btn-secondary btn-sm', f.enabled ? 'تعطيل' : 'تفعيل', { type: 'button' });
        tgBtn.addEventListener('click', async () => {
          const r = await apiCall('adguard_control', { method: 'POST', body: { subaction: 'filter_toggle', url: f.url, name: f.name, enabled: !f.enabled } });
          if (r.ok) { showToast('تم تحديث القائمة', 'success'); refreshActiveTab(); }
          else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل التحديث', 'error');
        });
        wrap.appendChild(tgBtn);
        const delBtn = el('button', 'btn btn-danger btn-sm', 'حذف', { type: 'button' });
        delBtn.addEventListener('click', async () => {
          const ok = await confirmAction('حذف قائمة فلترة', 'هل تريد حذف القائمة: ' + (f.name || f.url) + '؟');
          if (!ok) return;
          const r = await apiCall('adguard_control', { method: 'POST', body: { subaction: 'filter_delete', url: f.url } });
          if (r.ok) { showToast('تم حذف القائمة بنجاح', 'success'); refreshActiveTab(); }
          else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل الحذف', 'error');
        });
        wrap.appendChild(delBtn);
        ac.appendChild(wrap);
        tr.appendChild(ac);
        flBody.appendChild(tr);
      }
    }

    // Custom Rules
    const rList = qs('aghCustomRulesList');
    clearEl(rList);
    for (const rule of (data.user_rules || [])) {
      if (!rule || rule === '! [NOC-CONSOLE]') continue;
      const row = el('div', 'rule-row');
      row.appendChild(el('span', 'mono', rule));
      if (state.role === 'admin') {
        const delBtn = el('button', 'btn btn-danger btn-sm', 'حذف', { type: 'button', 'data-rule': rule });
        delBtn.addEventListener('click', () => removeDnsRule(rule));
        row.appendChild(delBtn);
      }
      rList.appendChild(row);
    }

    // Per-Client Stats Grid
    const cGrid = qs('aghClientsStatsGrid');
    const cFilt = qs('aghClientFilter');
    const prevFilter = cFilt.value;
    clearEl(cGrid);
    clearEl(cFilt);
    cFilt.appendChild(el('option', '', 'جميع الأجهزة', { value: '' }));

    for (const c of (data.client_stats || [])) {
      cFilt.appendChild(el('option', '', c.name + ' (' + c.ip + ')', { value: c.ip }));
      const card = el('div', 'client-stat-card');
      const head = el('div', 'kv-row');
      head.appendChild(el('strong', '', c.name));
      head.appendChild(el('span', 'status-pill ' + (c.online ? 'pill-success' : 'pill-neutral'), c.online ? 'نشط' : 'خامل'));
      card.appendChild(head);
      card.appendChild(el('div', 'meta-line mono', c.ip + (c.mac ? ' | ' + c.mac : '')));
      const rowNums = el('div', 'kv-row');
      rowNums.appendChild(el('span', 'val-success mono', 'مسموح: ' + nfInt.format(c.allowed)));
      rowNums.appendChild(el('span', 'val-danger mono', 'مرفوض: ' + nfInt.format(c.blocked) + ' (' + nfLatn.format(c.block_pct) + '%)'));
      card.appendChild(rowNums);
      if (c.last_domain) {
        card.appendChild(el('div', 'meta-line mono', (c.last_time ? c.last_time + ' ' : '') + c.last_domain));
      }
      cGrid.appendChild(card);
    }
    if (prevFilter) cFilt.value = prevFilter;

    filterAdGuardQueries();
  }

  function filterAdGuardQueries() {
    const tbody = qs('aghQueriesContainer');
    clearEl(tbody);
    const data = state.lastAdGuard;
    if (!data || !data.recent_queries) return;
    const qTerm = (qs('aghQuerySearch').value || '').toLowerCase().trim();
    const cIp = qs('aghClientFilter').value || '';
    const mode = qs('aghFilterModeSelect').value || 'all';

    for (const q of data.recent_queries) {
      if (qTerm && (q.domain || '').toLowerCase().indexOf(qTerm) < 0) continue;
      if (cIp && q.client !== cIp) continue;
      if (mode === 'blocked' && !q.blocked) continue;
      if (mode === 'allowed' && q.blocked) continue;

      const tr = el('tr');
      tr.appendChild(el('td', 'mono', q.time || '--'));
      tr.appendChild(el('td', '', (q.client_name || q.client)));
      tr.appendChild(el('td', 'mono', q.domain));
      tr.appendChild(el('td', 'mono', q.type));
      tr.appendChild(el('td', 'mono', nfLatn.format(q.elapsed_ms || 0) + ' ms'));
      const statusCell = el('td');
      statusCell.appendChild(el('span', 'status-pill ' + (q.blocked ? 'pill-danger' : 'pill-success'), q.reason_text));
      tr.appendChild(statusCell);

      const actCell = el('td');
      if (state.role === 'admin' && q.domain) {
        const ruleStr = q.blocked ? ('@@||' + q.domain + '^') : ('||' + q.domain + '^');
        const btn = el('button', 'btn btn-secondary btn-sm', q.blocked ? 'سماح' : 'حظر النطاق', { type: 'button' });
        btn.addEventListener('click', () => addDnsRule(ruleStr));
        actCell.appendChild(btn);
      }
      tr.appendChild(actCell);
      tbody.appendChild(tr);
    }
  }

  // --- Render Clients ---
  function renderClients(data) {
    state.lastClients = data;
    if (!data) return;
    const note = qs('clientsCapabilityNote');
    if (data.flow_offloading) {
      note.textContent = 'تنبيه دقة القياس: تسريع التدفق (Flow Offloading) مفعل في الجدار الناري مما يعطل عدادات البايت لكل عميل بدقة، لذا تُعرض حالة الاتصال والمنع المباشر.';
      note.classList.remove('hidden');
    } else {
      note.classList.add('hidden');
    }
    filterClientsTable();

    const slBody = qs('clientsStaticLeasesBody');
    if (slBody) {
      clearEl(slBody);
      for (const l of (data.static_leases_list || [])) {
        const tr = el('tr');
        tr.appendChild(el('td', '', l.name || '--'));
        tr.appendChild(el('td', 'mono', l.mac || ''));
        tr.appendChild(el('td', 'mono', l.ip || ''));
        tr.appendChild(el('td', 'mono', l.leasetime || 'infinite'));
        const ac = el('td');
        if (l.id) {
          const delBtn = el('button', 'btn btn-danger btn-sm', 'حذف', { type: 'button' });
          delBtn.addEventListener('click', async () => {
            const ok = await confirmAction('حذف حجز DHCP الثابت', 'هل تريد حذف الحجز للجهاز ' + (l.name || l.mac) + '؟');
            if (!ok) return;
            const r = await apiCall('client_control', { method: 'POST', body: { subaction: 'lease_delete', id: l.id } });
            if (r.ok) { showToast('تم حذف الحجز الثابت', 'success'); refreshActiveTab(); }
            else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل الحذف', 'error');
          });
          ac.appendChild(delBtn);
        }
        tr.appendChild(ac);
        slBody.appendChild(tr);
      }
    }

    const dmBody = qs('clientsDomainsBody');
    if (dmBody) {
      clearEl(dmBody);
      for (const d of (data.local_domains || [])) {
        const tr = el('tr');
        tr.appendChild(el('td', 'mono', d.name || ''));
        tr.appendChild(el('td', 'mono', d.ip || ''));
        const ac = el('td');
        if (d.id) {
          const delBtn = el('button', 'btn btn-danger btn-sm', 'حذف', { type: 'button' });
          delBtn.addEventListener('click', async () => {
            const r = await apiCall('client_control', { method: 'POST', body: { subaction: 'domain_delete', id: d.id } });
            if (r.ok) { showToast('تم حذف النطاق المحلي', 'success'); refreshActiveTab(); }
            else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل الحذف', 'error');
          });
          ac.appendChild(delBtn);
        }
        tr.appendChild(ac);
        dmBody.appendChild(tr);
      }
    }
  }

  function openClientEditor(c, isNewDevice) {
    const macInput = qs('clientEditMac');
    macInput.value = (c && c.mac) ? c.mac : '';
    if (isNewDevice) {
      macInput.removeAttribute('readonly');
      if (qs('clientEditPanelTitle')) qs('clientEditPanelTitle').textContent = 'إضافة جهاز جديد إلى الشبكة وتثبيت DHCP أو تقييد سرعته';
    } else {
      macInput.setAttribute('readonly', 'readonly');
      if (qs('clientEditPanelTitle')) qs('clientEditPanelTitle').textContent = 'تعديل بيانات الجهاز وتقييد السرعة وتثبيت DHCP';
    }
    qs('clientEditIp').value = (c && c.ip) ? c.ip : '192.168.1.';
    qs('clientEditName').value = (c && (c.nickname || c.hostname)) ? (c.nickname || c.hostname) : '';
    qs('clientEditRateKbps').value = String((c && c.rate_limit_kbps) || 0);
    qs('clientEditStaticChk').checked = isNewDevice ? true : !!(c && c.static_lease);
    qs('clientEditPanel').classList.remove('hidden');
  }

  async function openClientInspector(c) {
    if (!c) return;
    state.inspectedClient = c;
    const panel = qs('clientDeepInspectPanel');
    if (!panel) return;
    panel.classList.remove('hidden');
    if (qs('clientInspectTitle')) {
      qs('clientInspectTitle').textContent = 'الفحص التفصيلي لنشاط الجهاز وسجل الحجب: ' + (c.display_name || c.ip || c.mac);
    }
    const idGrid = qs('clientInspectIdentityGrid');
    if (idGrid) {
      clearEl(idGrid);
      const items = [
        ['الاسم والحالة', (c.display_name || 'جهاز') + ' (' + (c.blocked ? 'محظور' : (c.online ? 'متصل' : 'خامل')) + ')', c.arp_state || '--'],
        ['عنوان IPv4 / الحجز', c.ip || '--', c.static_lease ? 'حجز DHCP ثابت مفعل' : 'تعيين DHCP ديناميكي'],
        ['عنوان MAC الفيزيائي', c.mac || '--', c.rate_limit_kbps > 0 ? ('مقيد السرعة: ' + nfInt.format(c.rate_limit_kbps) + ' Kbps') : 'السرعة غير مقيدة'],
        ['إجمالي الاستهلاك والجلسات', formatBytes(c.total_rx_bytes || 0) + ' تنزيل / ' + formatBytes(c.total_tx_bytes || 0) + ' رفع', nfInt.format(c.total_conns || 0) + ' جلسة مسجلة']
      ];
      for (const [lbl, val, sub] of items) {
        const box = el('div', 'inset-panel mini-stat');
        box.appendChild(el('span', 'mini-lbl', lbl));
        box.appendChild(el('strong', 'mono', val));
        box.appendChild(el('span', 'mini-sub mono', sub));
        idGrid.appendChild(box);
      }
    }
    const r = await apiCall('client_inspect', { query: { ip: c.ip || '', mac: c.mac || '' }, skipSeqCheck: true });
    if (r && r.ok && r.data) {
      state.lastClientInspect = r.data;
      renderClientInspectData();
    } else {
      showToast((r && r.errors && r.errors[0] && r.errors[0].message_ar) || 'تعذر جلب تفاصيل نشاط الجهاز', 'error');
    }
  }

  function renderClientInspectData() {
    const d = state.lastClientInspect;
    if (!d) return;
    const term = ((qs('clientInspectSearchInput') && qs('clientInspectSearchInput').value) || '').toLowerCase().trim();

    // Top queried domains chips
    const topBox = qs('clientInspectTopDomains');
    if (topBox) {
      clearEl(topBox);
      topBox.appendChild(el('span', 'sub-label', 'أكثر النطاقات طلباً من هذا الجهاز:'));
      const list = d.top_domains || [];
      if (!list.length) {
        topBox.appendChild(el('span', 'sub-label', 'لا توجد نطاقات مسجلة في النافذة الحالية'));
      } else {
        for (const td of list) {
          if (term && td.domain.toLowerCase().indexOf(term) < 0) continue;
          const chip = el('span', 'list-chip mono');
          chip.appendChild(el('span', '', td.domain + ' (' + nfInt.format(td.count) + ')'));
          topBox.appendChild(chip);
        }
      }
    }

    // 1. Live Conntrack Flows
    const fBody = qs('clientInspectFlowsBody');
    if (fBody) {
      clearEl(fBody);
      let count = 0;
      for (const f of (d.active_flows || [])) {
        const hay = (f.proto + ' ' + f.state + ' ' + f.src + ' ' + f.dst).toLowerCase();
        if (term && hay.indexOf(term) < 0) continue;
        count++;
        const tr = el('tr');
        tr.appendChild(el('td', 'mono', f.proto));
        tr.appendChild(el('td', 'mono', f.state));
        tr.appendChild(el('td', 'mono', f.src));
        tr.appendChild(el('td', 'mono', f.dst));
        tr.appendChild(el('td', 'mono', formatBytes(f.bytes || 0)));
        fBody.appendChild(tr);
      }
      if (count === 0) {
        const tr = el('tr');
        tr.appendChild(el('td', 'sub-label', 'لا توجد جلسات اتصال مطابقة حالياً', { colspan: '5' }));
        fBody.appendChild(tr);
      }
    }

    // 2. Live DNS Queries
    const qBody = qs('clientInspectDnsBody');
    if (qBody) {
      clearEl(qBody);
      let count = 0;
      for (const q of (d.dns_queries || [])) {
        const hay = ((q.domain || '') + ' ' + (q.type || '') + ' ' + (q.rule || '')).toLowerCase();
        if (term && hay.indexOf(term) < 0) continue;
        count++;
        const tr = el('tr');
        tr.appendChild(el('td', 'mono', q.time || '--'));
        tr.appendChild(el('td', 'mono', q.domain));
        tr.appendChild(el('td', 'mono', q.type));
        const stTd = el('td');
        stTd.appendChild(el('span', 'status-pill ' + (q.blocked ? 'pill-danger' : 'pill-success'), q.blocked ? 'محجوب' : 'مسموح'));
        tr.appendChild(stTd);
        const ac = el('td');
        if (state.role === 'admin' && q.domain) {
          const ruleStr = q.blocked ? ('@@||' + q.domain + '^') : ('||' + q.domain + '^');
          const b = el('button', 'btn btn-primary btn-sm', q.blocked ? 'فك الحجب' : 'حظر النطاق', { type: 'button' });
          b.addEventListener('click', () => addDnsRule(ruleStr));
          ac.appendChild(b);
        }
        tr.appendChild(ac);
        qBody.appendChild(tr);
      }
      if (count === 0) {
        const tr = el('tr');
        tr.appendChild(el('td', 'sub-label', 'لا توجد استعلامات DNS مطابقة', { colspan: '5' }));
        qBody.appendChild(tr);
      }
    }

    // 3. DNS Block History for this device
    const bBody = qs('clientInspectBlockedBody');
    if (bBody) {
      clearEl(bBody);
      let count = 0;
      for (const bq of (d.blocked_queries || [])) {
        const hay = ((bq.domain || '') + ' ' + (bq.rule || '')).toLowerCase();
        if (term && hay.indexOf(term) < 0) continue;
        count++;
        const tr = el('tr');
        tr.appendChild(el('td', 'mono', bq.time || '--'));
        tr.appendChild(el('td', 'mono', bq.domain));
        tr.appendChild(el('td', 'mono', bq.rule || 'قائمة التصفية'));
        const ac = el('td');
        if (state.role === 'admin' && bq.domain) {
          const allowBtn = el('button', 'btn btn-primary btn-sm', 'سماح استثنائي', { type: 'button' });
          allowBtn.addEventListener('click', () => addDnsRule('@@||' + bq.domain + '^'));
          ac.appendChild(allowBtn);
        }
        tr.appendChild(ac);
        bBody.appendChild(tr);
      }
      if (count === 0) {
        const tr = el('tr');
        tr.appendChild(el('td', 'sub-label', 'لا توجد سجلات حجب DNS على هذا الجهاز في النافذة الحالية', { colspan: '4' }));
        bBody.appendChild(tr);
      }
    }

    // 4. Administrative Block / Rate-Limit Audit History
    const aBody = qs('clientInspectAuditBody');
    if (aBody) {
      clearEl(aBody);
      let count = 0;
      for (const ae of (d.audit_history || []).slice().reverse()) {
        const hay = ((ae.action || '') + ' ' + (ae.target || '') + ' ' + (ae.details || '')).toLowerCase();
        if (term && hay.indexOf(term) < 0) continue;
        count++;
        const tr = el('tr');
        tr.appendChild(el('td', 'mono', ae.ts || '--'));
        tr.appendChild(el('td', 'mono', ae.action || '--'));
        tr.appendChild(el('td', 'mono', ae.target || '--'));
        tr.appendChild(el('td', '', ae.result || '--'));
        tr.appendChild(el('td', 'mono', ae.details || ''));
        aBody.appendChild(tr);
      }
      if (count === 0) {
        const tr = el('tr');
        tr.appendChild(el('td', 'sub-label', 'لا توجد عمليات حظر أو تقييد إدارية سابقة مسجلة لهذا الجهاز', { colspan: '5' }));
        aBody.appendChild(tr);
      }
    }
  }

  function filterClientsTable() {
    const tbody = qs('clientsTableBody');
    clearEl(tbody);
    const data = state.lastClients;
    if (!data || !data.clients) return;
    const term = (qs('clientsSearchInput').value || '').toLowerCase().trim();
    const filt = qs('clientsFilterSelect').value || 'all';

    for (const c of data.clients) {
      const hay = ((c.display_name || '') + ' ' + (c.ip || '') + ' ' + (c.mac || '')).toLowerCase();
      if (term && hay.indexOf(term) < 0) continue;
      if (filt === 'online' && !c.online) continue;
      if (filt === 'blocked' && !c.blocked) continue;

      const tr = el('tr');
      tr.appendChild(el('td', '', c.display_name || 'جهاز'));
      tr.appendChild(el('td', 'mono', (c.ips && c.ips.length) ? c.ips.join(', ') : (c.ip || '--')));
      tr.appendChild(el('td', 'mono', c.mac || '--'));
      const stCell = el('td');
      const badges = el('div', 'meta-badges');
      badges.appendChild(el('span', 'status-pill ' + (c.blocked ? 'pill-danger' : (c.online ? 'pill-success' : 'pill-neutral')), c.blocked ? 'محظور' : (c.online ? 'متصل' : 'خامل')));
      if (c.static_lease) badges.appendChild(el('span', 'status-pill pill-neutral', 'IP ثابت'));
      if (c.rate_limit_kbps > 0) badges.appendChild(el('span', 'status-pill pill-warning mono', '<= ' + nfInt.format(c.rate_limit_kbps) + ' Kbps'));
      stCell.appendChild(badges);
      tr.appendChild(stCell);

      const trafficStr = formatBytes(c.total_rx_bytes || 0) + ' / ' + formatBytes(c.total_tx_bytes || 0) + (c.total_conns ? (' (' + nfInt.format(c.total_conns) + ' جلسة)') : '');
      tr.appendChild(el('td', 'mono', trafficStr));
      tr.appendChild(el('td', 'mono', c.arp_state || '--'));

      const actCell = el('td');
      if (state.role === 'admin' && c.mac && c.mac !== 'HIDDEN') {
        const wrap = el('div', 'td-actions');
        const inspectBtn = el('button', 'btn btn-primary btn-sm', 'فحص وتفاصيل', { type: 'button' });
        inspectBtn.addEventListener('click', () => openClientInspector(c));
        wrap.appendChild(inspectBtn);

        const editBtn = el('button', 'btn btn-secondary btn-sm', 'تعديل / سرعة', { type: 'button' });
        editBtn.addEventListener('click', () => openClientEditor(c, false));
        wrap.appendChild(editBtn);

        if (c.ip) {
          const pingBtn = el('button', 'btn btn-secondary btn-sm', 'Ping', { type: 'button' });
          pingBtn.addEventListener('click', () => pingClient(c.ip));
          wrap.appendChild(pingBtn);
        }

        const btn = el('button', 'btn btn-sm ' + (c.blocked ? 'btn-primary' : 'btn-danger'), c.blocked ? 'رفع الحظر' : 'حظر', { type: 'button' });
        btn.addEventListener('click', () => toggleClientBlock(c));
        wrap.appendChild(btn);
        actCell.appendChild(wrap);
      }
      tr.appendChild(actCell);
      tbody.appendChild(tr);
    }
  }

  // --- Render Secondary Views (Network, SQM, Firewall, Docker, Tailscale, Services, Diagnostics/Logs) ---
  function renderKvRows(containerId, rows) {
    const c = qs(containerId);
    clearEl(c);
    for (const [lbl, val] of rows) {
      const row = el('div', 'kv-row');
      row.appendChild(el('span', '', lbl));
      row.appendChild(el('strong', 'mono', val));
      c.appendChild(row);
    }
  }

  function renderNetwork(data) {
    state.lastNetwork = data;
    if (!data) return;
    const wan = data.wan || {};
    const lan = data.lan || {};
    renderKvRows('netWanDetails', [
      ['المنفذ النشط للإنترنت', wan.active_device || '--'],
      ['عنوان البوابة الخارجية', wan.ipv4 || '--'],
      ['حالة PPPoE (eth0)', wan.pppoe_up ? ('متصل (' + wan.pppoe_ipv4 + ')') : 'متوقف / احتياطي'],
      ['حالة الارتباط اللاسلكي (wwan)', wan.wwan_up ? ('متصل (' + wan.wwan_ipv4 + ')') : 'غير متصل']
    ]);
    renderKvRows('netLanDetails', [
      ['واجهة الجسر المحلي', lan.device || 'br-lan'],
      ['عنوان LAN', (lan.ipv4 || '192.168.1.1') + '/' + (lan.mask || 24)],
      ['حالة الجسر', lan.up ? 'نشط' : 'غير متصل']
    ]);

    const dp = data.dhcp_pool || {};
    if (qs('netDhcpStart') && document.activeElement !== qs('netDhcpStart')) qs('netDhcpStart').value = String(dp.start || 5);
    if (qs('netDhcpLimit') && document.activeElement !== qs('netDhcpLimit')) qs('netDhcpLimit').value = String(dp.limit || 31);
    if (qs('netDhcpLease') && document.activeElement !== qs('netDhcpLease')) qs('netDhcpLease').value = dp.leasetime || '1h';
    if (qs('netDhcpCacheSize') && document.activeElement !== qs('netDhcpCacheSize')) qs('netDhcpCacheSize').value = String(dp.cachesize !== undefined ? dp.cachesize : 1000);
    if (qs('netDhcpRebindChk')) qs('netDhcpRebindChk').checked = dp.rebind_protection !== false;

    const ws = data.wan_settings || {};
    if (qs('netWanUser') && document.activeElement !== qs('netWanUser')) qs('netWanUser').value = ws.username || '';
    if (qs('netWanMtu') && document.activeElement !== qs('netWanMtu')) qs('netWanMtu').value = String(ws.mtu || 1492);
    if (qs('netWanMetric') && document.activeElement !== qs('netWanMetric')) qs('netWanMetric').value = String(ws.metric || 10);
    if (qs('netWanAutoChk')) qs('netWanAutoChk').checked = !!ws.auto;
    if (qs('netPacketSteeringChk')) qs('netPacketSteeringChk').checked = ws.packet_steering !== false;

    const wifi = data.wireless_settings || {};
    if (qs('wifiUplinkSsid') && document.activeElement !== qs('wifiUplinkSsid')) qs('wifiUplinkSsid').value = wifi.uplink_ssid || '';
    if (qs('wifiApEnableChk')) qs('wifiApEnableChk').checked = !wifi.ap_disabled;
    if (qs('wifiApSsid') && document.activeElement !== qs('wifiApSsid')) qs('wifiApSsid').value = wifi.ap_ssid || 'Gateway-AP';
    if (qs('wifiApEnc') && document.activeElement !== qs('wifiApEnc')) qs('wifiApEnc').value = (wifi.ap_encryption && wifi.ap_encryption !== 'none') ? wifi.ap_encryption : 'psk2';
    if (qs('wifiApChannel') && document.activeElement !== qs('wifiApChannel')) qs('wifiApChannel').value = wifi.ap_channel || '36';
    if (qs('wifiApHtmode') && document.activeElement !== qs('wifiApHtmode')) qs('wifiApHtmode').value = wifi.ap_htmode || 'HT40';

    renderWifiScanList(data.wifi_scan || []);

    const rtBody = qs('staticRoutesBody');
    if (rtBody) {
      clearEl(rtBody);
      for (const r of (data.static_routes || [])) {
        const tr = el('tr');
        tr.appendChild(el('td', 'mono', r.interface || ''));
        tr.appendChild(el('td', 'mono', r.target || ''));
        tr.appendChild(el('td', 'mono', r.netmask || ''));
        tr.appendChild(el('td', 'mono', r.gateway || '--'));
        tr.appendChild(el('td', 'mono', String(r.metric || 0)));
        const ac = el('td');
        if (r.id) {
          const delBtn = el('button', 'btn btn-danger btn-sm', 'حذف', { type: 'button' });
          delBtn.addEventListener('click', async () => {
            const ok = await confirmAction('حذف مسار ثابت', 'هل تريد حذف المسار نحو ' + r.target + '؟');
            if (!ok) return;
            const res = await apiCall('network_control', { method: 'POST', body: { subaction: 'route_delete', id: r.id } });
            if (res.ok) { showToast('تم حذف المسار الثابت', 'success'); refreshActiveTab(); }
            else showToast((res.errors && res.errors[0] && res.errors[0].message_ar) || 'فشل الحذف', 'error');
          });
          ac.appendChild(delBtn);
        }
        tr.appendChild(ac);
        rtBody.appendChild(tr);
      }
    }

    const uciIfBody = qs('uciInterfacesBody');
    if (uciIfBody) {
      clearEl(uciIfBody);
      for (const ui of (data.uci_interfaces || [])) {
        const tr = el('tr');
        tr.appendChild(el('td', 'mono', ui.name || ''));
        tr.appendChild(el('td', 'mono', ui.proto || '--'));
        tr.appendChild(el('td', 'mono', ui.device || '--'));
        tr.appendChild(el('td', 'mono', ui.ipaddr || '--'));
        tr.appendChild(el('td', 'mono', ui.ip6addr || (ui.ip6assign != null ? ('/' + ui.ip6assign) : '--')));
        const ac = el('td');
        if (!ui.protected && ui.name) {
          const delBtn = el('button', 'btn btn-danger btn-sm', 'حذف', { type: 'button' });
          delBtn.addEventListener('click', async () => {
            const ok = await confirmAction('حذف واجهة شبكة', 'هل تريد حذف الواجهة ' + ui.name + '؟');
            if (!ok) return;
            const res = await apiCall('network_control', { method: 'POST', body: { subaction: 'interface_delete', name: ui.name } });
            if (res.ok) { showToast('تم حذف الواجهة بنجاح', 'success'); refreshActiveTab(); }
            else showToast((res.errors && res.errors[0] && res.errors[0].message_ar) || 'فشل الحذف', 'error');
          });
          ac.appendChild(delBtn);
        } else {
          ac.appendChild(el('span', 'status-pill pill-neutral', 'محمي'));
        }
        tr.appendChild(ac);
        uciIfBody.appendChild(tr);
      }
    }

    const bvBody = qs('bridgeVlansBody');
    if (bvBody) {
      clearEl(bvBody);
      for (const bv of (data.bridge_vlans || [])) {
        const tr = el('tr');
        tr.appendChild(el('td', 'mono', bv.device || 'br-lan'));
        tr.appendChild(el('td', 'mono', String(bv.vlan || '')));
        tr.appendChild(el('td', 'mono', (bv.ports || []).join(', ')));
        const ac = el('td');
        if (bv.id) {
          const delBtn = el('button', 'btn btn-danger btn-sm', 'حذف', { type: 'button' });
          delBtn.addEventListener('click', async () => {
            const ok = await confirmAction('حذف Bridge-VLAN', 'هل تريد حذف VLAN ' + bv.vlan + '؟');
            if (!ok) return;
            const res = await apiCall('network_control', { method: 'POST', body: { subaction: 'bridge_vlan_delete', id: bv.id } });
            if (res.ok) { showToast('تم حذف Bridge-VLAN', 'success'); refreshActiveTab(); }
            else showToast((res.errors && res.errors[0] && res.errors[0].message_ar) || 'فشل الحذف', 'error');
          });
          ac.appendChild(delBtn);
        }
        tr.appendChild(ac);
        bvBody.appendChild(tr);
      }
    }

    const v6 = data.ipv6_settings || {};
    if (qs('ipv6UlaInput') && document.activeElement !== qs('ipv6UlaInput')) qs('ipv6UlaInput').value = v6.ula_prefix || '';
    if (qs('ipv6RaSelect')) qs('ipv6RaSelect').value = v6.ra || 'disabled';
    if (qs('ipv6Dhcpv6Select')) qs('ipv6Dhcpv6Select').value = v6.dhcpv6 || 'disabled';
    if (qs('ipv6NdpSelect')) qs('ipv6NdpSelect').value = v6.ndp || 'disabled';
    if (qs('ipv6SlaacChk')) qs('ipv6SlaacChk').checked = v6.ra_slaac !== false;

    const tbody = qs('netInterfacesTableBody');
    clearEl(tbody);
    const ifaces = data.interfaces || {};
    for (const name of Object.keys(ifaces).sort()) {
      const i = ifaces[name];
      const tr = el('tr');
      tr.appendChild(el('td', 'mono', i.name));
      tr.appendChild(el('td', '', (i.carrier || i.operstate === 'up') ? 'نشط' : 'متوقف'));
      tr.appendChild(el('td', 'mono', i.speed ? (nfInt.format(i.speed) + ' Mbps') : '--'));
      tr.appendChild(el('td', 'mono', nfInt.format(i.mtu || 1500)));
      tr.appendChild(el('td', 'mono', i.mac || '--'));
      tr.appendChild(el('td', 'mono', formatBytes(i.rx_bytes)));
      tr.appendChild(el('td', 'mono', formatBytes(i.tx_bytes)));
      tr.appendChild(el('td', 'mono', nfInt.format((i.rx_errors || 0) + (i.tx_errors || 0)) + ' / ' + nfInt.format(i.rx_dropped || 0)));
      tbody.appendChild(tr);
    }
  }

  function renderWifiScanList(list) {
    const tbody = qs('wifiScanBody');
    if (!tbody) return;
    clearEl(tbody);
    for (const s of (list || [])) {
      const tr = el('tr');
      tr.appendChild(el('td', 'mono', s.ssid || '--'));
      tr.appendChild(el('td', 'mono', String(s.signal_dbm || -99) + ' dBm'));
      tr.appendChild(el('td', 'mono', String(s.freq_mhz || 0) + ' MHz'));
      tr.appendChild(el('td', 'mono', s.security || 'Open'));
      const ac = el('td');
      const selBtn = el('button', 'btn btn-secondary btn-sm', 'اختيار', { type: 'button' });
      selBtn.addEventListener('click', () => {
        if (qs('wifiUplinkSsid')) qs('wifiUplinkSsid').value = s.ssid || '';
        showToast('تم اختيار الشبكة ' + (s.ssid || ''), 'success');
      });
      ac.appendChild(selBtn);
      tr.appendChild(ac);
      tbody.appendChild(tr);
    }
  }

  function renderSqm(data) {
    state.lastSqm = data;
    if (!data || !data.config) return;
    const cfg = data.config;
    qs('sqmStatusBadge').textContent = cfg.enabled ? 'مفعل' : 'متوقف';
    qs('sqmStatusBadge').className = 'status-pill ' + (cfg.enabled ? 'pill-success' : 'pill-neutral');
    const ovWan = state.lastOverview && state.lastOverview.wan;
    const alertBox = qs('sqmDriftAlert');
    if (cfg.enabled && ovWan && ovWan.active_device && cfg.interface !== ovWan.active_device) {
      alertBox.textContent = 'تنبيه: تم ضبط SQM على الواجهة (' + cfg.interface + ') في وضع الاستعداد بينما تمر الحركة الحالية عبر (' + ovWan.active_device + ').';
      alertBox.classList.remove('hidden');
    } else {
      alertBox.classList.add('hidden');
    }
    renderKvRows('sqmConfigGrid', [
      ['الواجهة المستهدفة', cfg.interface],
      ['سرعة التنزيل المحددة', nfInt.format(cfg.download_kbps) + ' Kbps'],
      ['سرعة الرفع المحددة', nfInt.format(cfg.upload_kbps) + ' Kbps'],
      ['خوارزمية الطابور', cfg.qdisc + ' (' + cfg.script + ')'],
      ['طبقة الارتباط والحمل الإضافي', (cfg.linklayer || 'ethernet') + ' / ' + nfInt.format(cfg.overhead) + ' bytes']
    ]);
    const ed = qs('sqmEditorCard');
    if (ed && !ed.contains(document.activeElement)) {
      qs('sqmEnableToggle').checked = !!cfg.enabled;
      qs('sqmIfaceSelect').value = cfg.interface || 'pppoe-wan';
      qs('sqmQdiscSelect').value = cfg.qdisc || 'cake';
      qs('sqmScriptSelect').value = cfg.script || 'piece_of_cake.qos';
      qs('sqmDownInput').value = String(cfg.download_kbps || 0);
      qs('sqmUpInput').value = String(cfg.upload_kbps || 0);
      qs('sqmOverheadInput').value = String(cfg.overhead || 44);
      if (qs('sqmLinklayerSelect')) qs('sqmLinklayerSelect').value = cfg.linklayer || 'ethernet';
      if (qs('sqmIngressEcnSelect')) qs('sqmIngressEcnSelect').value = cfg.ingress_ecn || 'ECN';
      if (qs('sqmEgressEcnSelect')) qs('sqmEgressEcnSelect').value = cfg.egress_ecn || 'ECN';
      if (qs('sqmVerbosityInput')) qs('sqmVerbosityInput').value = String(cfg.verbosity !== undefined ? cfg.verbosity : 5);
      if (qs('sqmSquashDscpChk')) qs('sqmSquashDscpChk').checked = cfg.squash_dscp !== false;
      if (qs('sqmSquashIngressChk')) qs('sqmSquashIngressChk').checked = cfg.squash_ingress !== false;
    }
    qs('sqmTcStatsPre').textContent = data.tc_stats || 'لا توجد بيانات طابور متاحة.';
  }

  function renderFirewall(data) {
    state.lastFirewall = data;
    if (!data) return;
    qs('fwBanipBadge').textContent = data.banip_running ? 'خدمة banIP: نشطة' : 'خدمة banIP: متوقفة';
    qs('fwBanipBadge').className = 'status-pill ' + (data.banip_running ? 'pill-success' : 'pill-neutral');

    const defs = data.defaults || {};
    if (qs('fwSynFloodChk')) qs('fwSynFloodChk').checked = defs.syn_flood !== false;
    if (qs('fwDropInvalidChk')) qs('fwDropInvalidChk').checked = !!defs.drop_invalid;
    if (qs('fwWanMasqChk')) qs('fwWanMasqChk').checked = defs.wan_masq !== false;
    if (qs('fwWanMtuFixChk')) qs('fwWanMtuFixChk').checked = defs.wan_mtu_fix !== false;

    const zGrid = qs('fwZonesGrid');
    clearEl(zGrid);
    for (const z of (data.zones || [])) {
      const card = el('div', 'zone-card');
      card.appendChild(el('strong', 'mono', z.name || z['.name'] || 'zone'));
      card.appendChild(el('span', 'sub-label mono', 'IN:' + (z.input || '-') + ' OUT:' + (z.output || '-') + ' FWD:' + (z.forward || '-')));
      zGrid.appendChild(card);
    }

    const protectedFw = new Set(['noc_console_lan', 'Allow-NOC-Console-LAN', 'Allow-DHCP-Renew', 'Allow-Ping', 'Allow-DHCPv6']);
    const rBody = qs('fwRulesBody');
    clearEl(rBody);
    for (const r of (data.rules || [])) {
      const tr = el('tr');
      tr.appendChild(el('td', '', r.name || r.id));
      tr.appendChild(el('td', 'mono', r.src || '*'));
      tr.appendChild(el('td', 'mono', r.dest || '*'));
      tr.appendChild(el('td', 'mono', r.proto || 'all'));
      tr.appendChild(el('td', 'mono', r.dest_port || '*'));
      tr.appendChild(el('td', 'mono', r.target));
      tr.appendChild(el('td', '', r.enabled ? 'مفعلة' : 'معطلة'));
      const tCell = el('td');
      if (state.role === 'admin' && r.id) {
        const wrap = el('div', 'cell-actions');
        const isProt = protectedFw.has(r.id) || protectedFw.has(r.name);
        const btn = el('button', 'btn btn-secondary btn-sm', r.enabled ? 'تعطيل' : 'تفعيل', { type: 'button' });
        if (isProt && r.enabled) {
          btn.disabled = true;
          btn.textContent = 'محمية';
        } else {
          btn.addEventListener('click', () => toggleFwRule(r.id, !r.enabled));
        }
        wrap.appendChild(btn);
        if (!isProt && r.id.indexOf('noc_rule_') === 0) {
          const delBtn = el('button', 'btn btn-danger btn-sm', 'حذف', { type: 'button' });
          delBtn.addEventListener('click', async () => {
            const ok = await confirmAction('حذف قاعدة جدار ناري', 'هل تريد حذف القاعدة ' + (r.name || r.id) + '؟');
            if (!ok) return;
            const res = await apiCall('firewall_control', { method: 'POST', body: { subaction: 'delete_rule', id: r.id } });
            if (res.ok) { showToast('تم حذف القاعدة بنجاح', 'success'); refreshActiveTab(); }
            else showToast((res.errors && res.errors[0] && res.errors[0].message_ar) || 'مرفوض', 'error');
          });
          wrap.appendChild(delBtn);
        }
        tCell.appendChild(wrap);
      }
      tr.appendChild(tCell);
      rBody.appendChild(tr);
    }

    const rdBody = qs('fwRedirectsBody');
    clearEl(rdBody);
    for (const r of (data.redirects || [])) {
      const tr = el('tr');
      tr.appendChild(el('td', '', r.name || r.id));
      tr.appendChild(el('td', 'mono', (r.src || 'wan') + ' / ' + (r.proto || 'tcp')));
      tr.appendChild(el('td', 'mono', r.src_dport || '*'));
      tr.appendChild(el('td', 'mono', (r.dest_ip || '') + ':' + (r.dest_port || '')));
      tr.appendChild(el('td', '', r.enabled ? 'مفعلة' : 'معطلة'));
      const aCell = el('td');
      if (state.role === 'admin' && r.id) {
        const delBtn = el('button', 'btn btn-danger btn-sm', 'حذف', { type: 'button' });
        delBtn.addEventListener('click', () => deleteFwRedirect(r.id));
        aCell.appendChild(delBtn);
      }
      tr.appendChild(aCell);
      rdBody.appendChild(tr);
    }
    for (const u of (data.upnp_rules || [])) {
      const tr = el('tr');
      tr.appendChild(el('td', '', 'UPnP: ' + (u.descr || 'خدمة تلقائية')));
      tr.appendChild(el('td', 'mono', u.proto || 'TCP'));
      tr.appendChild(el('td', 'mono', String(u.ext_port || '')));
      tr.appendChild(el('td', 'mono', (u.int_addr || '') + ':' + (u.int_port || '')));
      tr.appendChild(el('td', '', 'تلقائي UPnP'));
      tr.appendChild(el('td', '', '--'));
      rdBody.appendChild(tr);
    }

    const bp = data.banip_detail || {};
    if (qs('banipEnableChk')) qs('banipEnableChk').checked = !!bp.enabled;
    if (qs('banipAutoBlockChk')) qs('banipAutoBlockChk').checked = bp.autoblocklist !== false;
    if (qs('banipAutoAllowChk')) qs('banipAutoAllowChk').checked = bp.autoallowlist !== false;
    if (qs('banipIcmpInput') && document.activeElement !== qs('banipIcmpInput')) qs('banipIcmpInput').value = String(bp.icmplimit || 25);
    if (qs('banipSynInput') && document.activeElement !== qs('banipSynInput')) qs('banipSynInput').value = String(bp.synlimit || 10);
    if (qs('banipUdpInput') && document.activeElement !== qs('banipUdpInput')) qs('banipUdpInput').value = String(bp.udplimit || 100);
    renderBanipChips('banipBlocklistContainer', 'blocklist', bp.blocklist || []);
    renderBanipChips('banipAllowlistContainer', 'allowlist', bp.allowlist || []);

    const up = data.upnp_detail || {};
    if (qs('upnpEnableChk')) qs('upnpEnableChk').checked = up.enabled !== false;
    if (qs('upnpNatpmpChk')) qs('upnpNatpmpChk').checked = up.enable_natpmp !== false;
    if (qs('upnpSecureChk')) qs('upnpSecureChk').checked = up.secure_mode !== false;
    if (qs('upnpExtIfaceSelect') && document.activeElement !== qs('upnpExtIfaceSelect')) qs('upnpExtIfaceSelect').value = up.external_iface || 'wwan';
    if (qs('upnpStunChk')) qs('upnpStunChk').checked = !!up.use_stun;
    if (qs('upnpStunHostInput') && document.activeElement !== qs('upnpStunHostInput')) qs('upnpStunHostInput').value = up.stun_host || 'stun.cloudflare.com';
    if (qs('upnpStunPortInput') && document.activeElement !== qs('upnpStunPortInput')) qs('upnpStunPortInput').value = String(up.stun_port || 3478);
  }

  function renderBanipChips(containerId, listType, entries) {
    const c = qs(containerId);
    if (!c) return;
    clearEl(c);
    if (!entries.length) {
      c.appendChild(el('span', 'sub-label', 'لا توجد عناوين مدرجة'));
      return;
    }
    for (const ip of entries) {
      const chip = el('span', 'list-chip mono');
      chip.appendChild(el('span', '', ip));
      const del = el('button', 'chip-del', 'x', { type: 'button', title: 'إزالة' });
      del.addEventListener('click', async () => {
        const r = await apiCall('firewall_control', { method: 'POST', body: { subaction: 'banip_list', list_type: listType, op: 'remove', entry: ip } });
        if (r.ok) { showToast('تمت إزالة العنوان', 'success'); refreshActiveTab(); }
        else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل الحذف', 'error');
      });
      chip.appendChild(del);
      c.appendChild(chip);
    }
  }

  function renderDocker(data) {
    state.lastDocker = data;
    if (!data) return;
    const st = data.state || 'unprovisioned';
    const badge = qs('dockerStateBadge');
    const banner = qs('dockerStateBanner');
    if (st === 'unprovisioned') {
      badge.textContent = 'غير مهيأ (0 حاويات)';
      badge.className = 'status-pill pill-neutral';
      banner.textContent = 'محرك الحاويات يعمل لكنه غير مهيأ بأي حاوية نشطة حالياً (0 حاويات).';
      banner.className = 'alert-box alert-neutral';
    } else if (st === 'unavailable') {
      badge.textContent = 'غير متاح';
      badge.className = 'status-pill pill-danger';
      banner.textContent = data.message_ar || 'تعذر الوصول إلى محرك الحاويات.';
      banner.className = 'alert-box alert-danger';
    } else {
      badge.textContent = 'نشط (' + nfInt.format((data.containers || []).length) + ')';
      badge.className = 'status-pill pill-success';
      banner.textContent = 'جميع الحاويات المرصودة جاهزة للإدارة.';
      banner.className = 'alert-box alert-neutral';
    }

    const tbody = qs('dockerContainersBody');
    clearEl(tbody);
    for (const c of (data.containers || [])) {
      const tr = el('tr');
      tr.appendChild(el('td', 'mono', c.id));
      tr.appendChild(el('td', 'mono', c.name));
      tr.appendChild(el('td', 'mono', c.image));
      tr.appendChild(el('td', 'mono', c.state));
      tr.appendChild(el('td', '', c.status));
      tr.appendChild(el('td', 'mono', c.ports || '--'));
      const aCell = el('td');
      if (state.role === 'admin' && c.name) {
        const w = el('div', 'cell-actions');
        const isUp = (c.state || '').toLowerCase() === 'running';
        const toggleBtn = el('button', 'btn btn-sm ' + (isUp ? 'btn-danger' : 'btn-primary'), isUp ? 'إيقاف' : 'تشغيل', { type: 'button' });
        toggleBtn.addEventListener('click', () => runDockerAction(isUp ? 'stop' : 'start', c.name));
        w.appendChild(toggleBtn);
        const rBtn = el('button', 'btn btn-secondary btn-sm', 'إعادة تشغيل', { type: 'button' });
        rBtn.addEventListener('click', () => runDockerAction('restart', c.name));
        w.appendChild(rBtn);
        const lBtn = el('button', 'btn btn-secondary btn-sm', 'السجل', { type: 'button' });
        lBtn.addEventListener('click', () => runDockerAction('logs', c.name));
        w.appendChild(lBtn);

        const polSel = el('select', 'form-select form-select-sm mono');
        for (const pOpt of ['unless-stopped', 'always', 'no']) {
          polSel.appendChild(el('option', '', pOpt, { value: pOpt }));
        }
        const polBtn = el('button', 'btn btn-secondary btn-sm', 'تطبيق سياسة', { type: 'button' });
        polBtn.addEventListener('click', async () => {
          const r = await apiCall('docker_control', { method: 'POST', body: { subaction: 'set_restart', container: c.name, policy: polSel.value } });
          if (r.ok) showToast('تم تحديث سياسة إعادة التشغيل للحاوية', 'success');
          else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل التحديث', 'error');
        });
        w.appendChild(polSel);
        w.appendChild(polBtn);
        aCell.appendChild(w);
      }
      tr.appendChild(aCell);
      tbody.appendChild(tr);
    }

    const imBody = qs('dockerImagesBody');
    clearEl(imBody);
    for (const im of (data.images || [])) {
      const tr = el('tr');
      tr.appendChild(el('td', 'mono', im.repo_tag));
      tr.appendChild(el('td', 'mono', im.id));
      tr.appendChild(el('td', 'mono', im.size));
      imBody.appendChild(tr);
    }

    const nwBody = qs('dockerNetworksBody');
    if (nwBody) {
      clearEl(nwBody);
      for (const n of (data.networks || [])) {
        const tr = el('tr');
        tr.appendChild(el('td', 'mono', n.name));
        tr.appendChild(el('td', 'mono', n.driver));
        tr.appendChild(el('td', 'mono', n.scope));
        nwBody.appendChild(tr);
      }
    }

    const vlBody = qs('dockerVolumesBody');
    if (vlBody) {
      clearEl(vlBody);
      for (const v of (data.volumes || [])) {
        const tr = el('tr');
        tr.appendChild(el('td', 'mono', v.name));
        tr.appendChild(el('td', 'mono', v.driver));
        vlBody.appendChild(tr);
      }
    }
  }

  function renderTailscale(data) {
    state.lastTailscale = data;
    if (!data) return;
    const running = data.backend_state === 'Running';
    qs('tsStateBadge').textContent = running ? 'متصل (Running)' : (data.backend_state || 'غير متاح');
    qs('tsStateBadge').className = 'status-pill ' + (running ? 'pill-success' : 'pill-warning');
    const s = data.self || {};
    renderKvRows('tsSelfCard', [
      ['اسم العقدة', s.hostname || '--'],
      ['اسم النطاق', s.dns_name || '--'],
      ['عناوين VPN', (s.ips || []).join(', ') || '--'],
      ['الإصدار', data.version || '--']
    ]);

    const pr = data.prefs || {};
    if (qs('tsAcceptRoutesChk')) qs('tsAcceptRoutesChk').checked = !!pr.accept_routes;
    if (qs('tsAcceptDnsChk')) qs('tsAcceptDnsChk').checked = !!pr.accept_dns;
    if (qs('tsShieldsUpChk')) qs('tsShieldsUpChk').checked = !!pr.shields_up;
    if (qs('tsAdvLanChk')) qs('tsAdvLanChk').checked = (pr.advertise_routes || []).indexOf('192.168.1.0/24') >= 0;
    if (qs('tsServeStatusPre')) qs('tsServeStatusPre').textContent = data.serve_status || 'لا توجد خدمات Serve نشطة';

    const tbody = qs('tsPeersBody');
    clearEl(tbody);
    for (const p of (data.peers || [])) {
      const tr = el('tr');
      tr.appendChild(el('td', '', p.hostname || p.dns_name || p.id));
      tr.appendChild(el('td', 'mono', p.os || '--'));
      tr.appendChild(el('td', 'mono', (p.ips || []).join(', ')));
      tr.appendChild(el('td', '', p.online ? 'متصل' : 'غير متصل'));
      tr.appendChild(el('td', 'mono', formatBytes(p.rx_bytes) + ' / ' + formatBytes(p.tx_bytes)));
      tr.appendChild(el('td', '', p.exit_node ? 'نعم' : 'لا'));
      const pCell = el('td');
      const target = (p.ips && p.ips[0]) || p.hostname;
      if (state.role === 'admin' && target) {
        const pBtn = el('button', 'btn btn-secondary btn-sm', 'فحص Ping', { type: 'button' });
        pBtn.addEventListener('click', () => runTailscaleAction('ping', target));
        pCell.appendChild(pBtn);
      }
      tr.appendChild(pCell);
      tbody.appendChild(tr);
    }
  }

  function renderServices(data) {
    state.lastServices = data;
    if (!data) return;
    const grid = qs('servicesGrid');
    clearEl(grid);
    for (const s of (data.services || [])) {
      if (s.exists === false) continue;
      const card = el('div', 'service-card');
      const head = el('div', 'svc-head');
      head.appendChild(el('strong', 'mono', s.name));
      const bWrap = el('div', 'meta-badges');
      bWrap.appendChild(el('span', 'status-pill ' + (s.running ? 'pill-success' : 'pill-danger'), s.running ? 'تعمل' : 'متوقفة'));
      bWrap.appendChild(el('span', 'status-pill ' + (s.enabled ? 'pill-neutral' : 'pill-warning'), s.enabled ? 'تلقائي' : 'يدوي'));
      head.appendChild(bWrap);
      card.appendChild(head);

      if (state.role === 'admin') {
        const acts = el('div', 'svc-actions');
        if (s.restartable) {
          const rBtn = el('button', 'btn btn-secondary btn-sm', 'إعادة تشغيل', { type: 'button' });
          rBtn.addEventListener('click', () => runServiceOp(s.name, 'restart'));
          acts.appendChild(rBtn);
        }
        if (s.stoppable) {
          const stBtn = el('button', 'btn btn-sm ' + (s.running ? 'btn-danger' : 'btn-primary'), s.running ? 'إيقاف' : 'تشغيل', { type: 'button' });
          stBtn.addEventListener('click', () => runServiceOp(s.name, s.running ? 'stop' : 'start'));
          acts.appendChild(stBtn);

          const btBtn = el('button', 'btn btn-secondary btn-sm', s.enabled ? 'تعطيل الإقلاع' : 'تفعيل الإقلاع', { type: 'button' });
          btBtn.addEventListener('click', () => runServiceOp(s.name, s.enabled ? 'disable' : 'enable'));
          acts.appendChild(btBtn);
        }
        card.appendChild(acts);
      }
      grid.appendChild(card);
    }

    const sys = data.system_settings || {};
    if (qs('sysHostnameInput') && document.activeElement !== qs('sysHostnameInput')) qs('sysHostnameInput').value = sys.hostname || 'Gateway';
    if (qs('sysLogSizeInput') && document.activeElement !== qs('sysLogSizeInput')) qs('sysLogSizeInput').value = String(sys.log_size || 128);
    if (qs('sysNtpEnableChk')) qs('sysNtpEnableChk').checked = sys.ntp_enabled !== false;
    if (qs('sysNtpServerChk')) qs('sysNtpServerChk').checked = !!sys.ntp_server_enabled;
    if (qs('sysNtpServersInput') && document.activeElement !== qs('sysNtpServersInput') && sys.ntp_servers && sys.ntp_servers.length) {
      qs('sysNtpServersInput').value = sys.ntp_servers.join(', ');
    }
    if (qs('sysZonenameSelect') && document.activeElement !== qs('sysZonenameSelect')) {
      const zTarget = (sys.zonename || 'UTC') + '|' + (sys.timezone || 'GMT0');
      const opts = Array.from(qs('sysZonenameSelect').options);
      const matchOpt = opts.find((o) => o.value === zTarget || o.value.indexOf((sys.zonename || 'UTC') + '|') === 0);
      if (matchOpt) qs('sysZonenameSelect').value = matchOpt.value;
    }
    if (qs('sysConntrackMaxInput') && document.activeElement !== qs('sysConntrackMaxInput')) qs('sysConntrackMaxInput').value = String(sys.conntrack_max || 262144);
    if (qs('sysPacketSteeringChk')) qs('sysPacketSteeringChk').checked = sys.packet_steering !== false;

    const tplSel = qs('cronTemplateSelect');
    if (tplSel && tplSel.options.length === 0) {
      for (const t of (data.cron_templates || [])) {
        tplSel.appendChild(el('option', '', t.label, { value: t.id }));
      }
    }
    const cjBody = qs('cronJobsBody');
    if (cjBody) {
      clearEl(cjBody);
      for (const cj of (data.cron_jobs || [])) {
        const tr = el('tr');
        tr.appendChild(el('td', 'mono', String(cj.index)));
        tr.appendChild(el('td', 'mono', cj.line));
        const ac = el('td');
        const delBtn = el('button', 'btn btn-danger btn-sm', 'حذف', { type: 'button' });
        delBtn.addEventListener('click', async () => {
          const r = await apiCall('system_control', { method: 'POST', body: { subaction: 'cron_delete', index: cj.index } });
          if (r.ok) { showToast('تم حذف المهمة المجدولة', 'success'); refreshActiveTab(); }
          else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل الحذف', 'error');
        });
        ac.appendChild(delBtn);
        tr.appendChild(ac);
        cjBody.appendChild(tr);
      }
    }

    const ssh = data.ssh_settings || {};
    if (qs('sshPassAuthChk')) qs('sshPassAuthChk').checked = ssh.password_auth !== false;
    if (qs('sshRootPassAuthChk')) qs('sshRootPassAuthChk').checked = ssh.root_password_auth !== false;
    const skBody = qs('sshKeysBody');
    if (skBody) {
      clearEl(skBody);
      for (const k of (ssh.keys || [])) {
        const tr = el('tr');
        tr.appendChild(el('td', 'mono', k.key_type));
        tr.appendChild(el('td', 'mono', k.prefix));
        tr.appendChild(el('td', 'mono', k.comment || '--'));
        const ac = el('td');
        const delBtn = el('button', 'btn btn-danger btn-sm', 'حذف', { type: 'button' });
        delBtn.addEventListener('click', async () => {
          const ok = await confirmAction('حذف مفتاح SSH مصرح به', 'هل تريد حذف المفتاح (' + (k.comment || k.prefix) + ')؟');
          if (!ok) return;
          const r = await apiCall('system_control', { method: 'POST', body: { subaction: 'ssh_key_delete', index: k.index } });
          if (r.ok) { showToast('تم حذف المفتاح العام', 'success'); refreshActiveTab(); }
          else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'مرفوض', 'error');
        });
        ac.appendChild(delBtn);
        tr.appendChild(ac);
        skBody.appendChild(tr);
      }
    }

    if (state.role === 'admin' && qs('packagesListGrid') && qs('packagesListGrid').childNodes.length === 0) {
      loadPackagesList('');
    }
  }

  async function loadPackagesList(q) {
    const r = await apiCall('packages', { query: { q: q || '' }, skipSeqCheck: true });
    if (!r || !r.ok || !r.data) return;
    const d = r.data;
    if (qs('pkgManagerBadge')) qs('pkgManagerBadge').textContent = String(d.pkg_manager || 'unknown').toUpperCase();
    if (qs('pkgCountBadge')) qs('pkgCountBadge').textContent = nfInt.format(d.filtered_count || 0) + ' / ' + nfInt.format(d.total_count || 0) + ' حزمة';
    if (qs('sysPkgVersionText') && d.system_version) {
      qs('sysPkgVersionText').textContent = 'System OS ' + d.system_version + ' | Kernel ' + (d.kernel_version || '6.12.112');
    }
    const grid = qs('packagesListGrid');
    if (!grid) return;
    clearEl(grid);
    for (const p of (d.packages || [])) {
      const chip = el('span', 'pkg-chip mono');
      chip.appendChild(el('span', '', p));
      const basePkg = String(p).replace(/-[0-9][^-]*(-r[0-9]+)?$/, '');
      const upBtn = el('button', 'pkg-chip-action', 'تحديث', { type: 'button', title: 'تحديث الحزمة ' + basePkg });
      upBtn.addEventListener('click', () => {
        if (qs('pkgActionNameInput')) qs('pkgActionNameInput').value = basePkg;
        runPkgAction('upgrade', basePkg);
      });
      chip.appendChild(upBtn);
      grid.appendChild(chip);
    }
  }

  async function runPkgAction(op, pkgName) {
    const labels = {
      update: 'تحديث فهرس مستودعات النظام (apk update)',
      check_upgrades: 'فحص ترقيات النظام والحزم المتاحة (apk upgrade -s)',
      install: 'تنزيل وتثبيت البرنامج (' + pkgName + ')',
      upgrade: 'تحديث البرنامج (' + pkgName + ')',
      del: 'حذف الحزمة (' + pkgName + ')'
    };
    if (op === 'install' || op === 'upgrade' || op === 'del') {
      if (!pkgName) {
        showToast('يرجى إدخال اسم البرنامج أو الحزمة أولاً', 'error');
        return;
      }
      const ok = await confirmAction('تأكيد عملية الحزم البرمجية', 'سيتم تنفيذ: ' + (labels[op] || op));
      if (!ok) return;
    }
    const pre = qs('pkgActionOutputPre');
    if (pre) {
      pre.textContent = 'جاري تنفيذ (' + (labels[op] || op) + ')...';
      pre.classList.remove('hidden');
    }
    const r = await apiCall('system_control', { method: 'POST', body: { subaction: 'pkg_action', op, package: pkgName || '' } });
    if (r && r.data && pre) {
      pre.textContent = r.data.output || r.data.message_ar || 'اكتملت العملية.';
    }
    if (r && r.ok) {
      showToast((r.data && r.data.message_ar) || 'تم التنفيذ بنجاح', 'success');
      loadPackagesList(qs('pkgSearchInput') ? qs('pkgSearchInput').value.trim() : '');
    } else {
      const errMsg = (r && r.errors && r.errors[0] && r.errors[0].message_ar) || 'تعذر إتمام عملية الحزمة';
      if (pre && (!r || !r.data || !r.data.output)) pre.textContent = errMsg;
      showToast(errMsg, 'error');
    }
  }

  function renderAuthUsers(users) {
    const tbody = qs('roUsersList');
    if (!tbody) return;
    clearEl(tbody);
    for (const u of (users || [])) {
      const tr = el('tr');
      tr.appendChild(el('td', 'mono', u.username));
      tr.appendChild(el('td', '', u.role === 'admin' ? 'مدير النظام' : 'مراقب (قراءة فقط)'));
      const ac = el('td');
      if (u.username !== 'admin') {
        const del = el('button', 'btn btn-danger btn-sm', 'حذف', { type: 'button' });
        del.addEventListener('click', () => deleteOperatorUser(u.username));
        ac.appendChild(del);
      } else {
        ac.appendChild(el('span', 'sub-label', 'محمي'));
      }
      tr.appendChild(ac);
      tbody.appendChild(tr);
    }
  }

  function renderLogsAndAudit(data) {
    if (!data) return;
    if (data.next_seq !== undefined) state.logsSinceSeq = Number(data.next_seq) || 0;
    qs('syslogPre').textContent = data.syslog || '';
    qs('dmesgPre').textContent = data.dmesg || '';
    const tbody = qs('auditEntriesBody');
    clearEl(tbody);
    const list = (data.audit_entries || []).slice().reverse();
    state.lastAuditEntries = list;
    for (const e of list) {
      const tr = el('tr');
      tr.appendChild(el('td', 'mono', e.ts || '--'));
      tr.appendChild(el('td', 'mono', e.actor || '--'));
      tr.appendChild(el('td', 'mono', e.action || '--'));
      tr.appendChild(el('td', 'mono', e.target || '--'));
      tr.appendChild(el('td', '', e.result || '--'));
      tr.appendChild(el('td', 'mono', e.details || ''));
      tbody.appendChild(tr);
    }
  }

  // --- Mutations ---
  async function addDnsRule(rule) {
    if (!rule) return;
    const ok = await confirmAction('إضافة قاعدة تصفية DNS', 'سيتم إضافة القاعدة: ' + rule);
    if (!ok) return;
    const res = await apiCall('adguard_control', { method: 'POST', body: { subaction: 'add_rule', rule } });
    if (res.ok) {
      showToast((res.data && res.data.message) || 'تمت إضافة القاعدة بنجاح', 'success');
      qs('customDnsRuleInput').value = '';
      refreshActiveTab();
    } else {
      showToast((res.errors && res.errors[0] && res.errors[0].message_ar) || 'فشل إضافة القاعدة', 'error');
    }
  }

  async function removeDnsRule(rule) {
    const ok = await confirmAction('حذف قاعدة DNS مدارة', 'هل تريد حذف القاعدة: ' + rule + '؟');
    if (!ok) return;
    const res = await apiCall('adguard_control', { method: 'POST', body: { subaction: 'remove_rule', rule } });
    if (res.ok) {
      showToast('تمت إزالة القاعدة بنجاح', 'success');
      refreshActiveTab();
    } else {
      showToast((res.errors && res.errors[0] && res.errors[0].message_ar) || 'تعذر حذف القاعدة', 'error');
    }
  }

  async function toggleAghFlag(flag, enabled, duration_s) {
    const res = await apiCall('adguard_control', {
      method: 'POST',
      body: { subaction: 'toggle_flag', flag, enabled: !!enabled, duration_s: duration_s || 0 }
    });
    if (res.ok) {
      showToast('تم تحديث إعداد الحماية بنجاح', 'success');
      refreshActiveTab();
    } else {
      showToast((res.errors && res.errors[0] && res.errors[0].message_ar) || 'تعذر تحديث الحماية', 'error');
      refreshActiveTab();
    }
  }

  async function toggleClientBlock(client) {
    const sub = client.blocked ? 'unblock' : 'block';
    const ok = await confirmAction(
      client.blocked ? 'رفع حظر الجهاز' : 'حظر الجهاز عبر الجسر والجدار',
      (client.blocked ? 'رفع الحظر عن: ' : 'منع مرور البيانات للجهاز: ') + client.display_name + ' (' + client.mac + ')'
    );
    if (!ok) return;
    const res = await apiCall('client_control', {
      method: 'POST',
      body: { subaction: sub, mac: client.mac, ip: client.ip }
    });
    if (res.ok) {
      showToast((res.data && res.data.message_ar) || 'تم تنفيذ الإجراء بنجاح', 'success');
      refreshActiveTab();
    } else {
      showToast((res.errors && res.errors[0] && res.errors[0].message_ar) || 'رفض تنفيذ الحظر', 'error');
    }
  }

  async function runServiceOp(name, subaction) {
    const labelMap = { start: 'تشغيل', stop: 'إيقاف', restart: 'إعادة تشغيل', enable: 'تفعيل الإقلاع التلقائي', disable: 'تعطيل الإقلاع التلقائي' };
    const ok = await confirmAction((labelMap[subaction] || subaction) + ' الخدمة', 'سيتم تنفيذ (' + (labelMap[subaction] || subaction) + ') على الخدمة ' + name);
    if (!ok) return;
    const res = await apiCall('service_control', { method: 'POST', body: { subaction, name } });
    if (res.ok) {
      showToast((res.data && res.data.message_ar) || 'تم التنفيذ بنجاح', 'success');
      refreshActiveTab();
    } else {
      showToast((res.errors && res.errors[0] && res.errors[0].message_ar) || 'تعذر تنفيذ العملية', 'error');
    }
  }

  async function pingClient(ip) {
    const box = qs('clientPingResult');
    box.textContent = 'جاري فحص الاستجابة للعنوان ' + ip + '...';
    box.classList.remove('hidden');
    const res = await apiCall('client_control', { method: 'POST', body: { subaction: 'ping', ip } });
    if (res.ok && res.data) {
      box.textContent = res.data.output || 'اكتمل الفحص.';
    } else {
      box.textContent = (res.errors && res.errors[0] && res.errors[0].message_ar) || 'تعذر فحص الجهاز.';
    }
  }

  async function runNetAction(subaction, confirmTitle) {
    if (confirmTitle) {
      const ok = await confirmAction(confirmTitle, 'هل تريد المتابعة في تنفيذ إجراء الشبكة؟');
      if (!ok) return;
    }
    const res = await apiCall('network_control', { method: 'POST', body: { subaction } });
    if (res.ok) {
      showToast((res.data && res.data.message_ar) || 'تم تنفيذ الإجراء بنجاح', 'success');
      refreshOverview();
      if (state.activeTab === 'network') refreshActiveTab();
    } else {
      showToast((res.errors && res.errors[0] && res.errors[0].message_ar) || 'فشل إجراء الشبكة', 'error');
    }
  }

  async function toggleFwRule(id, enabled) {
    const ok = await confirmAction('تحديث قاعدة الجدار الناري', 'هل تريد ' + (enabled ? 'تفعيل' : 'تعطيل') + ' القاعدة ' + id + '؟');
    if (!ok) return;
    const res = await apiCall('firewall_control', { method: 'POST', body: { subaction: 'toggle_rule', id, enabled } });
    if (res.ok) {
      showToast((res.data && res.data.message_ar) || 'تم التحديث بنجاح', 'success');
      refreshActiveTab();
    } else {
      showToast((res.errors && res.errors[0] && res.errors[0].message_ar) || 'مرفوض', 'error');
    }
  }

  async function deleteFwRedirect(id) {
    const ok = await confirmAction('حذف قاعدة تحويل المنفذ', 'هل تريد حذف القاعدة ' + id + ' وإعادة تحميل الجدار؟');
    if (!ok) return;
    const res = await apiCall('firewall_control', { method: 'POST', body: { subaction: 'delete_redirect', id } });
    if (res.ok) {
      showToast('تم حذف القاعدة بنجاح', 'success');
      refreshActiveTab();
    } else {
      showToast((res.errors && res.errors[0] && res.errors[0].message_ar) || 'تعذر حذف القاعدة', 'error');
    }
  }

  async function runDockerAction(subaction, container) {
    if (subaction !== 'logs') {
      const ok = await confirmAction('التحكم بالحاوية', 'تنفيذ (' + subaction + ') على الحاوية ' + container + '؟');
      if (!ok) return;
    }
    const res = await apiCall('docker_control', { method: 'POST', body: { subaction, container } });
    if (res.ok) {
      if (subaction === 'logs' && res.data) {
        qs('dockerLogsPre').textContent = res.data.output || 'لا توجد سجلات.';
        qs('dockerLogsPre').classList.remove('hidden');
      } else {
        showToast((res.data && res.data.message_ar) || 'تم التنفيذ بنجاح', 'success');
        refreshActiveTab();
      }
    } else {
      showToast((res.errors && res.errors[0] && res.errors[0].message_ar) || 'فشل تنفيذ أمر الحاوية', 'error');
    }
  }

  async function runTailscaleAction(subaction, target) {
    if (subaction === 'reconnect') {
      const ok = await confirmAction('إعادة تشغيل اتصال VPN', 'قد يتطلب إعادة المصافحة بضع ثوانٍ.');
      if (!ok) return;
    }
    const res = await apiCall('tailscale_control', { method: 'POST', body: { subaction, target: target || '' } });
    if (res.ok) {
      if (res.data && res.data.output) {
        qs('tsDiagPre').textContent = res.data.output;
        qs('tsDiagPre').classList.remove('hidden');
      }
      showToast((res.data && res.data.message_ar) || 'تم التنفيذ بنجاح', 'success');
      if (subaction === 'reconnect') refreshActiveTab();
    } else {
      showToast((res.errors && res.errors[0] && res.errors[0].message_ar) || 'تعذر تنفيذ العملية', 'error');
    }
  }

  async function deleteOperatorUser(username) {
    const ok = await confirmAction('حذف حساب مراقب', 'هل تريد حذف الحساب ' + username + ' نهائياً؟');
    if (!ok) return;
    const res = await apiCall('auth_admin', { method: 'POST', body: { subaction: 'delete_user', username } });
    if (res.ok) {
      showToast('تم حذف الحساب بنجاح', 'success');
      refreshActiveTab();
    } else {
      showToast((res.errors && res.errors[0] && res.errors[0].message_ar) || 'تعذر حذف الحساب', 'error');
    }
  }

  async function runDiag(tool) {
    const target = (qs('diagTargetInput').value || '').trim();
    const qtype = qs('diagQtypeSelect').value || 'A';
    const port = Number(qs('diagPortInput').value) || 80;
    qs('diagOutputPre').textContent = 'جاري تنفيذ الفحص...';
    const res = await apiCall('diagnostics', {
      method: 'POST',
      body: { tool, target, qtype, port }
    });
    if (res.ok && res.data) {
      qs('diagOutputPre').textContent = res.data.output || 'اكتمل الفحص دون مخرجات نصية.';
      fetchLogs();
    } else {
      qs('diagOutputPre').textContent = (res.errors && res.errors[0] && res.errors[0].message_ar) || 'تعذر تنفيذ الفحص.';
    }
  }

  // --- Refresh & Streaming Loop ---
  async function refreshOverview() {
    try {
      const r = await apiCall('overview');
      if (r && r.ok && r.data) renderOverview(r.data);
    } catch (e) {}
  }

  async function fetchLogs() {
    if (state.role !== 'admin') return;
    try {
      const r = await apiCall('logs', { query: { since_seq: state.logsSinceSeq } });
      if (r && r.ok && r.data) renderLogsAndAudit(r.data);
    } catch (e) {}
  }

  async function refreshActiveTab() {
    if (!state.authenticated) return;
    const tab = state.activeTab;
    try {
      if (tab === 'dashboard') {
        await refreshOverview();
      } else if (tab === 'topology') {
        await refreshOverview();
        const r = await apiCall('clients', { skipSeqCheck: true, keepInFlight: true });
        if (r && r.ok && r.data) {
          state.lastClients = r.data;
          document.dispatchEvent(new CustomEvent('noc:clients'));
        }
      } else if (tab === 'adguard') {
        const r = await apiCall('adguard');
        if (r && r.ok && r.data) renderAdGuard(r.data);
      } else if (tab === 'clients') {
        const r = await apiCall('clients');
        if (r && r.ok && r.data) renderClients(r.data);
      } else if (tab === 'network') {
        const r = await apiCall('network');
        if (r && r.ok && r.data) renderNetwork(r.data);
      } else if (tab === 'sqm') {
        const r = await apiCall('sqm');
        if (r && r.ok && r.data) renderSqm(r.data);
      } else if (tab === 'firewall') {
        const r = await apiCall('firewall');
        if (r && r.ok && r.data) renderFirewall(r.data);
      } else if (tab === 'docker') {
        const r = await apiCall('docker');
        if (r && r.ok && r.data) renderDocker(r.data);
      } else if (tab === 'tailscale') {
        const r = await apiCall('tailscale');
        if (r && r.ok && r.data) renderTailscale(r.data);
      } else if (tab === 'services') {
        const r = await apiCall('services');
        if (r && r.ok && r.data) renderServices(r.data);
        if (state.role === 'admin') {
          const ru = await apiCall('auth_users', { skipSeqCheck: true });
          if (ru && ru.ok && ru.data) renderAuthUsers(ru.data.users || []);
          loadAdminExtras();
        }
      } else if (tab === 'diagnostics') {
        await fetchLogs();
        loadReportAndAudit();
      }
    } catch (e) {}
  }

  function startSSE() {
    if (state.sse) return;
    try {
      const es = new EventSource('/api?action=stream');
      es.addEventListener('overview', (ev) => {
        try {
          const nowMs = Date.now();
          if (state.sampleSpeedMs > 1000 && state.lastOverviewTs && (nowMs - state.lastOverviewTs) < (state.sampleSpeedMs - 150)) {
            return;
          }
          const env = JSON.parse(ev.data);
          if (env && env.boot_id && state.bootId && state.bootId !== env.boot_id) {
            state.cursors = {};
          }
          if (env && env.boot_id) state.bootId = env.boot_id;
          const prev = state.cursors['overview'];
          if (!prev || env.seq > prev.seq || env.boot_id !== prev.boot_id) {
            state.cursors['overview'] = { boot_id: env.boot_id, seq: env.seq, at: nowMs };
            if (env.data) renderOverview(env.data);
          }
        } catch (err) {}
      });
      es.addEventListener('expire', () => {
        stopSSE();
        setTimeout(() => { if (state.authenticated) startSSE(); }, 1000);
      });
      es.onerror = () => {
        stopSSE();
        if (qs('cmdConnBadge') && state.authenticated) {
          qs('cmdConnBadge').textContent = 'البث منقطع (إعادة المحاولة)';
          qs('cmdConnBadge').className = 'status-pill pill-warning';
        }
      };
      state.sse = es;
    } catch (e) {}
  }

  function stopSSE() {
    if (state.sse) {
      try { state.sse.close(); } catch (e) {}
      state.sse = null;
    }
  }

  async function sequentialPollTick() {
    if (!state.authenticated) return;
    if (!state.sse) await refreshOverview();
    if (state.activeTab !== 'dashboard') await refreshActiveTab();
    state.pollTimer = setTimeout(sequentialPollTick, 3500);
  }

  function startLiveLoop() {
    stopLiveLoop();
    startSSE();
    refreshActiveTab();
    state.pollTimer = setTimeout(sequentialPollTick, 3500);
    state.ageTimer = setInterval(() => {
      const ageNode = qs('cmdSampleAge');
      if (!ageNode || !state.lastOverviewTs) return;
      const ageSec = Math.max(0, Math.floor((Date.now() - state.lastOverviewTs) / 1000));
      ageNode.textContent = nfInt.format(ageSec) + ' ث';
      if (ageSec > 10) {
        qs('cmdConnBadge').textContent = 'متأخر (' + nfInt.format(ageSec) + ' ث)';
        qs('cmdConnBadge').className = 'status-pill pill-warning';
      }
    }, 1000);
  }

  function stopLiveLoop() {
    stopSSE();
    if (state.pollTimer) { clearTimeout(state.pollTimer); state.pollTimer = null; }
    if (state.ageTimer) { clearInterval(state.ageTimer); state.ageTimer = null; }
  }

  // --- Event Listener Wiring (Zero Inline Attributes) ---
  function initListeners() {
    qs('authForm').addEventListener('submit', handleAuthSubmit);

    qs('btnLogout').addEventListener('click', async () => {
      await apiCall('auth_logout', { method: 'POST', body: {} });
      state.authenticated = false;
      state.csrfToken = '';
      stopLiveLoop();
      checkAuthState();
    });

    qs('btnRefreshNow').addEventListener('click', () => {
      refreshOverview();
      refreshActiveTab();
    });

    qs('mobileNavBtn').addEventListener('click', () => {
      const sb = qs('mainSidebar');
      const open = sb.classList.toggle('open');
      qs('mobileNavBackdrop').classList.toggle('hidden', !open);
      qs('mobileNavBtn').setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    qs('mobileNavBackdrop').addEventListener('click', closeMobileDrawer);

    document.querySelectorAll('.sidebar-btn').forEach((btn) => {
      btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });

    qs('wanIfaceSelect').addEventListener('change', (ev) => {
      state.selectedIface = ev.target.value;
      state.rxHist = [];
      state.txHist = [];
      if (state.netChart) {
        state.netChart.setTitle(state.selectedIface);
        state.netChart.clear();
      }
      if (state.stopwatch && state.stopwatch.active) {
        state.stopwatch.active = false;
        if (qs('btnToggleTrafficStopwatch')) {
          qs('btnToggleTrafficStopwatch').textContent = 'بدء عداد قياس مباشر';
          qs('btnToggleTrafficStopwatch').className = 'btn btn-primary btn-sm';
        }
      }
      if (state.lastOverview) renderOverview(state.lastOverview);
      fetchTrafficWindow();
    });

    if (qs('rateUnitSelect')) {
      qs('rateUnitSelect').addEventListener('change', (ev) => {
        state.rateUnitMode = ev.target.value || 'auto_bits';
        if (state.netChart) state.netChart.setUnit(state.rateUnitMode);
        if (state.lastOverview) renderOverview(state.lastOverview);
        if (state.lastTrafficWindow) renderTrafficWindowCard(state.lastTrafficWindow);
      });
    }

    if (qs('dataUnitSelect')) {
      qs('dataUnitSelect').addEventListener('change', (ev) => {
        state.dataUnitMode = ev.target.value || 'iec_auto';
        if (state.lastOverview) renderOverview(state.lastOverview);
        if (state.lastClients) renderClients(state.lastClients);
        if (state.lastNetwork) renderNetwork(state.lastNetwork);
        if (state.lastTrafficWindow) renderTrafficWindowCard(state.lastTrafficWindow);
      });
    }

    if (qs('sampleSpeedSelect')) {
      qs('sampleSpeedSelect').addEventListener('change', (ev) => {
        state.sampleSpeedMs = Number(ev.target.value) || 1000;
        showToast('تم ضبط سرعة القياس على عينة كل ' + (state.sampleSpeedMs / 1000) + ' ثانية', 'success');
      });
    }

    if (qs('trafficWindowPresetSelect')) {
      qs('trafficWindowPresetSelect').addEventListener('change', (ev) => {
        const isCustom = ev.target.value === 'custom';
        if (qs('trafficCustomDurationInput')) qs('trafficCustomDurationInput').classList.toggle('hidden', !isCustom);
        if (qs('trafficCustomUnitSelect')) qs('trafficCustomUnitSelect').classList.toggle('hidden', !isCustom);
        if (!isCustom) fetchTrafficWindow();
      });
    }
    if (qs('btnCalcTrafficWindow')) {
      qs('btnCalcTrafficWindow').addEventListener('click', () => {
        if (state.stopwatch && state.stopwatch.active) toggleTrafficStopwatch();
        fetchTrafficWindow();
      });
    }
    if (qs('btnToggleTrafficStopwatch')) {
      qs('btnToggleTrafficStopwatch').addEventListener('click', toggleTrafficStopwatch);
    }

    qs('btnClearFreeze').addEventListener('click', async () => {
      const ok = await confirmAction('رفع حالة التجميد الأمني', 'هل تم التحقق من استقرار قواعد الجدار الناري وتريد إعادة تفعيل التعديلات؟');
      if (!ok) return;
      const r = await apiCall('freeze_clear', { method: 'POST', body: { confirm_reconciled: true } });
      if (r.ok) {
        renderFreezeBanner({ frozen: false });
        showToast('تم رفع حالة التجميد بنجاح', 'success');
      }
    });

    // Quick Operations on Dashboard
    qs('btnQuickFlushDns').addEventListener('click', () => runNetAction('flush_dns', null));
    qs('btnQuickSyncTime').addEventListener('click', () => runNetAction('sync_time', null));
    qs('btnQuickRecheckWan').addEventListener('click', () => { refreshOverview(); showToast('تم تحديث المسارات والمقاييس', 'success'); });

    // AdGuard Controls
    qs('aghProtToggle').addEventListener('change', (ev) => toggleAghFlag('protection_enabled', ev.target.checked, 0));
    qs('btnAghApplyPause').addEventListener('click', () => {
      const sec = Number(qs('aghPauseSelect').value) || 300;
      toggleAghFlag('protection_enabled', false, sec);
    });
    qs('aghSafeToggle').addEventListener('change', (ev) => toggleAghFlag('safebrowsing_enabled', ev.target.checked, 0));
    qs('aghParentalToggle').addEventListener('change', (ev) => toggleAghFlag('parental_enabled', ev.target.checked, 0));
    qs('aghSafeSearchToggle').addEventListener('change', (ev) => toggleAghFlag('safesearch_enabled', ev.target.checked, 0));
    qs('aghDnssecToggle').addEventListener('change', (ev) => toggleAghFlag('enable_dnssec', ev.target.checked, 0));
    qs('aghCacheToggle').addEventListener('change', (ev) => toggleAghFlag('cache_enabled', ev.target.checked, 0));
    qs('aghIpv6BlockToggle').addEventListener('change', (ev) => toggleAghFlag('aaaa_disabled', ev.target.checked, 0));

    qs('btnAghRefreshFilters').addEventListener('click', async () => {
      const r = await apiCall('adguard_control', { method: 'POST', body: { subaction: 'refresh_filters' } });
      if (r.ok) { showToast('تم تحديث قوائم الفلترة بنجاح', 'success'); refreshActiveTab(); }
      else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'تعذر التحديث', 'error');
    });
    qs('btnAghClearCache').addEventListener('click', async () => {
      const r = await apiCall('adguard_control', { method: 'POST', body: { subaction: 'clear_cache' } });
      if (r.ok) { showToast('تم مسح كاش DNS بنجاح', 'success'); refreshActiveTab(); }
      else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'تعذر المسح', 'error');
    });
    qs('btnAghClearLog').addEventListener('click', async () => {
      const ok = await confirmAction('مسح سجل الاستعلامات', 'سيتم حذف سجل استعلامات DNS من ذاكرة المحرك. هل أنت متأكد؟');
      if (!ok) return;
      const r = await apiCall('adguard_control', { method: 'POST', body: { subaction: 'clear_querylog' } });
      if (r.ok) { showToast('تم مسح السجل بنجاح', 'success'); refreshActiveTab(); }
      else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'تعذر المسح', 'error');
    });

    qs('btnSaveAghDnsConfig').addEventListener('click', async () => {
      const r = await apiCall('adguard_control', {
        method: 'POST',
        body: {
          subaction: 'dns_config',
          upstream_mode: qs('aghUpstreamModeSelect').value,
          cache_size: Number(qs('aghCacheSizeInput').value) || 0,
          ratelimit: Number(qs('aghRatelimitInput').value) || 0
        }
      });
      if (r.ok) { showToast('تم حفظ إعدادات خادم DNS', 'success'); refreshActiveTab(); }
      else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل الحفظ', 'error');
    });

    qs('btnSaveAghBlockedServices').addEventListener('click', async () => {
      const ids = [];
      document.querySelectorAll('#aghBlockedServicesGrid .agh-srv-chk').forEach((chk) => {
        if (chk.checked && chk.dataset.service) ids.push(chk.dataset.service);
      });
      const r = await apiCall('adguard_control', { method: 'POST', body: { subaction: 'set_blocked_services', ids } });
      if (r.ok) { showToast('تم تحديث قائمة التطبيقات المحجوبة بنجاح', 'success'); refreshActiveTab(); }
      else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل التحديث', 'error');
    });

    qs('btnAddAghRewrite').addEventListener('click', async () => {
      const domain = qs('aghRewriteDomainInput').value.trim();
      const answer = qs('aghRewriteAnswerInput').value.trim();
      const r = await apiCall('adguard_control', { method: 'POST', body: { subaction: 'rewrite_add', domain, answer } });
      if (r.ok) {
        qs('aghRewriteDomainInput').value = ''; qs('aghRewriteAnswerInput').value = '';
        showToast('تمت إضافة سجل التوجيه بنجاح', 'success');
        refreshActiveTab();
      } else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'بيانات غير صالحة', 'error');
    });

    qs('btnAddAghFilter').addEventListener('click', async () => {
      const name = qs('aghFilterNameInput').value.trim();
      const url = qs('aghFilterUrlInput').value.trim();
      const r = await apiCall('adguard_control', { method: 'POST', body: { subaction: 'filter_add', name, url } });
      if (r.ok) {
        qs('aghFilterNameInput').value = ''; qs('aghFilterUrlInput').value = '';
        showToast('تمت إضافة قائمة الفلتر بنجاح', 'success');
        refreshActiveTab();
      } else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'رابط غير صالح', 'error');
    });

    if (qs('btnApplyFilterPreset')) {
      qs('btnApplyFilterPreset').addEventListener('click', async () => {
        const val = qs('aghFilterPresetSelect').value;
        if (!val) {
          showToast('يرجى اختيار قائمة حجب جاهزة من القائمة المنسدلة أولاً', 'error');
          return;
        }
        const parts = val.split('|');
        const name = parts[0];
        const url = 'https://' + parts[1];
        qs('aghFilterNameInput').value = name;
        qs('aghFilterUrlInput').value = url;
        const r = await apiCall('adguard_control', { method: 'POST', body: { subaction: 'filter_add', name, url } });
        if (r.ok) {
          qs('aghFilterPresetSelect').value = '';
          qs('aghFilterNameInput').value = '';
          qs('aghFilterUrlInput').value = '';
          showToast('تم تنزيل وتفعيل قائمة الحجب (' + name + ') بنجاح', 'success');
          refreshActiveTab();
        } else {
          showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'تعذر تنزيل القائمة أو أنها مضافة مسبقاً', 'error');
        }
      });
    }

    qs('btnToggleAghCreds').addEventListener('click', () => {
      qs('aghCredsSetupBox').classList.toggle('hidden');
    });
    qs('btnSaveAghCreds').addEventListener('click', async () => {
      const u = (qs('aghCredUser').value || '').trim();
      const p = qs('aghCredPass').value || '';
      const r = await apiCall('adguard_control', { method: 'POST', body: { subaction: 'set_creds', username: u, password: p } });
      if (r.ok) {
        qs('aghCredPass').value = '';
        qs('aghCredsSetupBox').classList.add('hidden');
        showToast('تم ربط حساب AdGuard بنجاح', 'success');
        refreshActiveTab();
      } else {
        showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل التحقق من البيانات', 'error');
      }
    });

    qs('btnAddDnsRule').addEventListener('click', () => addDnsRule((qs('customDnsRuleInput').value || '').trim()));
    qs('aghQuerySearch').addEventListener('input', filterAdGuardQueries);
    qs('aghClientFilter').addEventListener('change', filterAdGuardQueries);
    qs('aghFilterModeSelect').addEventListener('change', filterAdGuardQueries);

    // Clients Filter & Meta Editor & Domains & Deep Inspector
    qs('clientsSearchInput').addEventListener('input', filterClientsTable);
    qs('clientsFilterSelect').addEventListener('change', filterClientsTable);
    if (qs('btnOpenAddDevice')) {
      qs('btnOpenAddDevice').addEventListener('click', () => openClientEditor(null, true));
    }
    if (qs('btnAddStaticLease')) {
      qs('btnAddStaticLease').addEventListener('click', async () => {
        const hostname = (qs('staticLeaseNameInput').value || '').trim().replace(/[^a-zA-Z0-9_-]/g, '');
        const mac = (qs('staticLeaseMacInput').value || '').trim().toLowerCase();
        const ip = (qs('staticLeaseIpInput').value || '').trim();
        const r = await apiCall('client_control', { method: 'POST', body: { subaction: 'static_lease', mac, ip, hostname, enable: true } });
        if (r.ok) {
          if (hostname) await apiCall('client_control', { method: 'POST', body: { subaction: 'set_meta', mac, ip, nickname: hostname, rate_limit_kbps: 0 } });
          qs('staticLeaseNameInput').value = ''; qs('staticLeaseMacInput').value = ''; qs('staticLeaseIpInput').value = '';
          showToast('تمت إضافة الجهاز وتثبيت عنوان IP الثابت بنجاح', 'success');
          refreshActiveTab();
        } else {
          showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'بيانات MAC أو IP غير صالحة', 'error');
        }
      });
    }
    if (qs('clientInspectSearchInput')) {
      qs('clientInspectSearchInput').addEventListener('input', renderClientInspectData);
    }
    if (qs('btnRefreshClientInspect')) {
      qs('btnRefreshClientInspect').addEventListener('click', () => {
        if (state.inspectedClient) openClientInspector(state.inspectedClient);
      });
    }
    if (qs('btnCloseClientInspect')) {
      qs('btnCloseClientInspect').addEventListener('click', () => qs('clientDeepInspectPanel').classList.add('hidden'));
    }
    qs('btnCancelClientMeta').addEventListener('click', () => qs('clientEditPanel').classList.add('hidden'));
    qs('btnSaveClientMeta').addEventListener('click', async () => {
      const mac = qs('clientEditMac').value.trim();
      const ip = qs('clientEditIp').value.trim();
      const nickname = qs('clientEditName').value.trim();
      const rate_limit_kbps = Number(qs('clientEditRateKbps').value) || 0;
      const enableStatic = qs('clientEditStaticChk').checked;
      const r1 = await apiCall('client_control', { method: 'POST', body: { subaction: 'set_meta', mac, ip, nickname, rate_limit_kbps } });
      if (!r1.ok) {
        showToast((r1.errors && r1.errors[0] && r1.errors[0].message_ar) || 'فشل حفظ البيانات', 'error');
        return;
      }
      const r2 = await apiCall('client_control', { method: 'POST', body: { subaction: 'static_lease', mac, ip, hostname: nickname.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 24), enable: enableStatic } });
      qs('clientEditPanel').classList.add('hidden');
      showToast(r2.ok ? 'تم حفظ تعديلات الجهاز وتثبيت DHCP بنجاح' : 'تم حفظ التقييد والاسم', 'success');
      refreshActiveTab();
    });

    qs('btnAddClientDomain').addEventListener('click', async () => {
      const name = qs('clientDomainNameInput').value.trim();
      const ip = qs('clientDomainIpInput').value.trim();
      const r = await apiCall('client_control', { method: 'POST', body: { subaction: 'domain_add', name, ip } });
      if (r.ok) {
        qs('clientDomainNameInput').value = ''; qs('clientDomainIpInput').value = '';
        showToast('تمت إضافة النطاق المحلي بنجاح', 'success');
        refreshActiveTab();
      } else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'بيانات غير صالحة', 'error');
    });

    // Network Controls
    qs('btnNetReconnectWan').addEventListener('click', () => runNetAction('reconnect_wan', 'إعادة ربط منفذ WAN'));
    qs('btnNetReconnectWwan').addEventListener('click', () => runNetAction('reconnect_wwan', 'إعادة ربط الوصلة اللاسلكية'));
    qs('btnNetFlushDns').addEventListener('click', () => runNetAction('flush_dns', null));

    qs('btnSaveNetDhcp').addEventListener('click', async () => {
      const r = await apiCall('network_control', {
        method: 'POST',
        body: {
          subaction: 'save_dhcp',
          start: Number(qs('netDhcpStart').value) || 5,
          limit: Number(qs('netDhcpLimit').value) || 31,
          leasetime: qs('netDhcpLease').value.trim() || '1h',
          cachesize: Number(qs('netDhcpCacheSize').value) || 1000,
          rebind_protection: qs('netDhcpRebindChk').checked
        }
      });
      if (r.ok) { showToast('تم حفظ وتطبيق إعدادات DHCP', 'success'); refreshActiveTab(); }
      else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل الحفظ', 'error');
    });

    qs('btnSaveNetWan').addEventListener('click', async () => {
      const r = await apiCall('network_control', {
        method: 'POST',
        body: {
          subaction: 'save_wan',
          username: qs('netWanUser').value.trim(),
          password: qs('netWanPass').value,
          mtu: Number(qs('netWanMtu').value) || 1492,
          metric: Number(qs('netWanMetric').value) || 10,
          auto: qs('netWanAutoChk').checked,
          packet_steering: qs('netPacketSteeringChk').checked
        }
      });
      if (r.ok) {
        qs('netWanPass').value = '';
        showToast('تم حفظ إعدادات WAN PPPoE', 'success');
        refreshActiveTab();
      } else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل الحفظ', 'error');
    });

    qs('btnWifiScan').addEventListener('click', async () => {
      showToast('جاري مسح الشبكات اللاسلكية المجاورة...', 'success');
      const r = await apiCall('network_control', { method: 'POST', body: { subaction: 'wifi_scan' } });
      if (r.ok && r.data) {
        renderWifiScanList(r.data.results || []);
        showToast('اكتمل مسح الشبكات اللاسلكية', 'success');
      } else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'تعذر المسح', 'error');
    });

    qs('btnSaveWifiUplink').addEventListener('click', async () => {
      const ssid = qs('wifiUplinkSsid').value.trim();
      const psk = qs('wifiUplinkPsk').value;
      const ok = await confirmAction('تحديث شبكة الارتباط الصاعدة', 'سيتم ربط wlan0 بالشبكة: ' + ssid);
      if (!ok) return;
      const r = await apiCall('network_control', { method: 'POST', body: { subaction: 'wifi_save_uplink', ssid, psk } });
      if (r.ok) {
        qs('wifiUplinkPsk').value = '';
        showToast('تم حفظ وربط الشبكة اللاسلكية', 'success');
        refreshActiveTab();
      } else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل التحديث', 'error');
    });

    qs('btnSaveWifiAp').addEventListener('click', async () => {
      const r = await apiCall('network_control', {
        method: 'POST',
        body: {
          subaction: 'wifi_save_ap',
          disabled: !qs('wifiApEnableChk').checked,
          ssid: qs('wifiApSsid').value.trim(),
          key: qs('wifiApKey').value,
          encryption: qs('wifiApEnc').value,
          channel: qs('wifiApChannel').value,
          htmode: qs('wifiApHtmode').value
        }
      });
      if (r.ok) {
        qs('wifiApKey').value = '';
        showToast('تم حفظ إعدادات نقطة الوصول 5GHz', 'success');
        refreshActiveTab();
      } else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل الحفظ', 'error');
    });

    qs('btnAddStaticRoute').addEventListener('click', async () => {
      const r = await apiCall('network_control', {
        method: 'POST',
        body: {
          subaction: 'route_add',
          interface: qs('routeIfaceSelect').value,
          target: qs('routeTargetInput').value.trim(),
          netmask: qs('routeMaskInput').value.trim(),
          gateway: qs('routeGwInput').value.trim(),
          metric: Number(qs('routeMetricInput').value) || 0
        }
      });
      if (r.ok) {
        qs('routeTargetInput').value = ''; qs('routeGwInput').value = '';
        showToast('تمت إضافة المسار الثابت بنجاح', 'success');
        refreshActiveTab();
      } else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'بيانات غير صالحة', 'error');
    });

    if (qs('btnSaveUciIface')) {
      qs('btnSaveUciIface').addEventListener('click', async () => {
        const r = await apiCall('network_control', {
          method: 'POST',
          body: {
            subaction: 'interface_save',
            name: qs('uciIfaceNameInput').value.trim(),
            proto: qs('uciIfaceProtoSelect').value,
            device: qs('uciIfaceDevInput').value.trim(),
            ipaddr: qs('uciIfaceIpInput').value.trim(),
            netmask: qs('uciIfaceMaskInput').value.trim()
          }
        });
        if (r.ok) { showToast('تم حفظ الواجهة بنجاح', 'success'); refreshActiveTab(); }
        else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل حفظ الواجهة', 'error');
      });
    }

    if (qs('btnSaveBridgeVlan')) {
      qs('btnSaveBridgeVlan').addEventListener('click', async () => {
        const ports = (qs('bvPortsInput').value || '').split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
        const r = await apiCall('network_control', {
          method: 'POST',
          body: {
            subaction: 'bridge_vlan_save',
            device: qs('bvDeviceInput').value.trim(),
            vlan: Number(qs('bvVlanInput').value),
            ports
          }
        });
        if (r.ok) { showToast('تم حفظ Bridge-VLAN بنجاح', 'success'); refreshActiveTab(); }
        else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل حفظ Bridge-VLAN', 'error');
      });
    }

    if (qs('btnSaveIpv6')) {
      qs('btnSaveIpv6').addEventListener('click', async () => {
        const r = await apiCall('network_control', {
          method: 'POST',
          body: {
            subaction: 'ipv6_save',
            interface: 'lan',
            ula_prefix: qs('ipv6UlaInput').value.trim(),
            ra: qs('ipv6RaSelect').value,
            dhcpv6: qs('ipv6Dhcpv6Select').value,
            ndp: qs('ipv6NdpSelect').value,
            ra_slaac: qs('ipv6SlaacChk').checked
          }
        });
        if (r.ok) { showToast('تم حفظ إعدادات IPv6 بنجاح', 'success'); refreshActiveTab(); }
        else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل حفظ إعدادات IPv6', 'error');
      });
    }

    // SQM Editor Controls
    qs('btnSqmBindActive').addEventListener('click', () => {
      const act = (state.lastOverview && state.lastOverview.wan && state.lastOverview.wan.active_device) || 'wlan0';
      qs('sqmIfaceSelect').value = act;
      showToast('تم اختيار المنفذ النشط (' + act + ')، اضغط حفظ وتطبيق', 'success');
    });
    qs('btnSaveSqm').addEventListener('click', async () => {
      const ok = await confirmAction('تحديث إعدادات SQM', 'سيتم تحديث تشكيل التدفق وإعادة تحميل SQM.');
      if (!ok) return;
      const r = await apiCall('sqm_control', {
        method: 'POST',
        body: {
          enabled: qs('sqmEnableToggle').checked,
          interface: qs('sqmIfaceSelect').value,
          qdisc: qs('sqmQdiscSelect').value,
          script: qs('sqmScriptSelect').value,
          download_kbps: Number(qs('sqmDownInput').value) || 0,
          upload_kbps: Number(qs('sqmUpInput').value) || 0,
          overhead: Number(qs('sqmOverheadInput').value) || 44,
          linklayer: qs('sqmLinklayerSelect').value,
          ingress_ecn: qs('sqmIngressEcnSelect').value,
          egress_ecn: qs('sqmEgressEcnSelect').value,
          verbosity: Number(qs('sqmVerbosityInput').value) || 5,
          squash_dscp: qs('sqmSquashDscpChk').checked,
          squash_ingress: qs('sqmSquashIngressChk').checked
        }
      });
      if (r.ok) { showToast('تم حفظ وتطبيق SQM بنجاح', 'success'); refreshActiveTab(); }
      else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل تطبيق SQM', 'error');
    });

    // Firewall Defaults, Rules, Redirects, banIP & UPnP
    qs('btnSaveFwDefaults').addEventListener('click', async () => {
      const r = await apiCall('firewall_control', {
        method: 'POST',
        body: {
          subaction: 'save_defaults',
          syn_flood: qs('fwSynFloodChk').checked,
          drop_invalid: qs('fwDropInvalidChk').checked,
          wan_masq: qs('fwWanMasqChk').checked,
          wan_mtu_fix: qs('fwWanMtuFixChk').checked
        }
      });
      if (r.ok) { showToast('تم حفظ الخيارات العامة للجدار الناري', 'success'); refreshActiveTab(); }
      else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل الحفظ', 'error');
    });

    qs('btnAddFwRule').addEventListener('click', async () => {
      const r = await apiCall('firewall_control', {
        method: 'POST',
        body: {
          subaction: 'add_rule',
          name: qs('fwRuleName').value.trim() || 'CustomRule',
          src: qs('fwRuleSrc').value,
          dest: qs('fwRuleDest').value,
          proto: qs('fwRuleProto').value,
          src_ip: qs('fwRuleSrcIp').value.trim(),
          dest_port: qs('fwRulePort').value.trim(),
          target: qs('fwRuleTarget').value
        }
      });
      if (r.ok) {
        qs('fwRuleName').value = ''; qs('fwRuleSrcIp').value = ''; qs('fwRulePort').value = '';
        showToast('تمت إضافة قاعدة الجدار الناري بنجاح', 'success');
        refreshActiveTab();
      } else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'مرفوض أو غير صالح', 'error');
    });

    qs('btnAddFwRedirect').addEventListener('click', async () => {
      const r = await apiCall('firewall_control', {
        method: 'POST',
        body: {
          subaction: 'add_redirect',
          name: qs('fwFwdName').value.trim() || 'Rule',
          proto: qs('fwFwdProto').value,
          src_dport: Number(qs('fwFwdExtPort').value) || 0,
          dest_ip: qs('fwFwdIntIp').value.trim(),
          dest_port: Number(qs('fwFwdIntPort').value) || 0
        }
      });
      if (r.ok) {
        qs('fwFwdName').value = ''; qs('fwFwdExtPort').value = ''; qs('fwFwdIntIp').value = ''; qs('fwFwdIntPort').value = '';
        showToast('تمت إضافة قاعدة التحويل بنجاح', 'success');
        refreshActiveTab();
      } else {
        showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'مرفوض أو غير صالح', 'error');
      }
    });

    qs('btnSaveBanip').addEventListener('click', async () => {
      const r = await apiCall('firewall_control', {
        method: 'POST',
        body: {
          subaction: 'banip_save',
          enabled: qs('banipEnableChk').checked,
          autoblocklist: qs('banipAutoBlockChk').checked,
          autoallowlist: qs('banipAutoAllowChk').checked,
          icmplimit: Number(qs('banipIcmpInput').value) || 25,
          synlimit: Number(qs('banipSynInput').value) || 10,
          udplimit: Number(qs('banipUdpInput').value) || 100
        }
      });
      if (r.ok) { showToast('تم حفظ إعدادات banIP بنجاح', 'success'); refreshActiveTab(); }
      else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل الحفظ', 'error');
    });

    qs('btnAddBanipEntry').addEventListener('click', async () => {
      const entry = qs('banipEntryInput').value.trim();
      const list_type = qs('banipListTypeSelect').value;
      const r = await apiCall('firewall_control', { method: 'POST', body: { subaction: 'banip_list', list_type, op: 'add', entry } });
      if (r.ok) {
        qs('banipEntryInput').value = '';
        showToast('تمت إضافة العنوان إلى القائمة', 'success');
        refreshActiveTab();
      } else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'مرفوض أو غير صالح', 'error');
    });

    qs('btnSaveUpnp').addEventListener('click', async () => {
      const r = await apiCall('firewall_control', {
        method: 'POST',
        body: {
          subaction: 'upnp_save',
          enabled: qs('upnpEnableChk').checked,
          enable_upnp: qs('upnpEnableChk').checked,
          enable_natpmp: qs('upnpNatpmpChk').checked,
          secure_mode: qs('upnpSecureChk').checked,
          external_iface: qs('upnpExtIfaceSelect').value,
          use_stun: qs('upnpStunChk').checked,
          stun_host: qs('upnpStunHostInput').value.trim(),
          stun_port: Number(qs('upnpStunPortInput').value) || 3478
        }
      });
      if (r.ok) { showToast('تم حفظ إعدادات UPnP بنجاح', 'success'); refreshActiveTab(); }
      else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل الحفظ', 'error');
    });

    // Docker Extended Controls
    qs('btnDockerPruneImages').addEventListener('click', async () => {
      const ok = await confirmAction('تنظيف الصور اليتيمة (Dangling Images)', 'سيتم حذف الصور غير المرتبطة بأي وسم أو حاوية فقط.');
      if (!ok) return;
      const r = await apiCall('docker_control', { method: 'POST', body: { subaction: 'prune_images' } });
      if (r.ok) { showToast('تم تنظيف الصور اليتيمة بنجاح', 'success'); refreshActiveTab(); }
      else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'تعذر التنظيف', 'error');
    });

    // Tailscale Controls
    qs('btnTsNetcheck').addEventListener('click', () => runTailscaleAction('netcheck'));
    qs('btnTsReconnect').addEventListener('click', () => runTailscaleAction('reconnect'));
    qs('btnSaveTsFlags').addEventListener('click', async () => {
      const r = await apiCall('tailscale_control', {
        method: 'POST',
        body: {
          subaction: 'set_flags',
          accept_routes: qs('tsAcceptRoutesChk').checked,
          accept_dns: qs('tsAcceptDnsChk').checked,
          shields_up: qs('tsShieldsUpChk').checked,
          advertise_routes: qs('tsAdvLanChk').checked ? '192.168.1.0/24' : ''
        }
      });
      if (r.ok) { showToast('تم حفظ خصائص Tailscale بنجاح', 'success'); refreshActiveTab(); }
      else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'مرفوض', 'error');
    });

    // System, Cron, SSH, Packages, Backup & Reboot Controls
    qs('btnSaveSysGeneral').addEventListener('click', async () => {
      const zParts = (qs('sysZonenameSelect').value || 'UTC|GMT0').split('|');
      const ntpArr = (qs('sysNtpServersInput').value || '').split(',').map((s) => s.trim()).filter(Boolean);
      const r = await apiCall('system_control', {
        method: 'POST',
        body: {
          subaction: 'save_general',
          hostname: qs('sysHostnameInput').value.trim(),
          zonename: zParts[0] || 'UTC',
          timezone: zParts[1] || 'GMT0',
          log_size: Number(qs('sysLogSizeInput').value) || 128,
          ntp_enabled: qs('sysNtpEnableChk').checked,
          ntp_server_enabled: qs('sysNtpServerChk').checked,
          ntp_servers: ntpArr
        }
      });
      if (r.ok) { showToast('تم حفظ إعدادات النظام والتوقيت', 'success'); refreshActiveTab(); }
      else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'بيانات غير صالحة', 'error');
    });

    qs('btnSaveSysTuning').addEventListener('click', async () => {
      const r = await apiCall('system_control', {
        method: 'POST',
        body: {
          subaction: 'save_tuning',
          conntrack_max: Number(qs('sysConntrackMaxInput').value) || 262144,
          packet_steering: qs('sysPacketSteeringChk').checked
        }
      });
      if (r.ok) { showToast('تم تحديث معايير النواة بنجاح', 'success'); refreshActiveTab(); }
      else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل التحديث', 'error');
    });

    qs('btnExportSysBackup').addEventListener('click', async () => {
      const r = await apiCall('backup_export', { skipSeqCheck: true });
      if (!r.ok || !r.data) {
        showToast('تعذر تصدير النسخة الاحتياطية', 'error');
        return;
      }
      const dataStr = JSON.stringify(r.data, null, 2);
      const blob = new Blob([dataStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'gateway_config_backup.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast('تم تصدير النسخة الاحتياطية للإعدادات بنجاح', 'success');
    });

    if (qs('btnExportSysupgradeBackup')) {
      qs('btnExportSysupgradeBackup').addEventListener('click', async () => {
        const r = await apiCall('backup_export', { method: 'POST', body: { mode: 'sysupgrade' }, skipSeqCheck: true });
        if (!r.ok || !r.data || !r.data.archive_b64) {
          showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'تعذر تصدير أرشيف sysupgrade -b', 'error');
          return;
        }
        const binStr = atob(r.data.archive_b64);
        const bytes = new Uint8Array(binStr.length);
        for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
        const blob = new Blob([bytes], { type: 'application/gzip' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = r.data.filename || 'sysupgrade-backup.tar.gz';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        if (qs('sysBackupStatusPre')) {
          qs('sysBackupStatusPre').classList.remove('hidden');
          qs('sysBackupStatusPre').textContent = 'SHA-256: ' + (r.data.sha256 || '') + '\nالملفات: ' + (r.data.entries_count || 0);
        }
        showToast('تم تصدير أرشيف sysupgrade -b والتحقق من سلامته', 'success');
      });
    }

    if (qs('btnValidateSysBackup')) {
      qs('btnValidateSysBackup').addEventListener('click', async () => {
        const fInput = qs('sysBackupValidateFile');
        const file = fInput && fInput.files ? fInput.files[0] : null;
        if (!file) {
          showToast('اختر ملف أرشيف (.tar.gz) أولاً للتحقق من سلامته', 'warning');
          return;
        }
        const buf = await file.arrayBuffer();
        const bytes = new Uint8Array(buf);
        let binStr = '';
        for (let i = 0; i < bytes.length; i++) binStr += String.fromCharCode(bytes[i]);
        const r = await apiCall('backup_validate', { method: 'POST', body: { archive_b64: btoa(binStr) }, skipSeqCheck: true });
        if (qs('sysBackupStatusPre')) {
          qs('sysBackupStatusPre').classList.remove('hidden');
          const d = r.data || {};
          qs('sysBackupStatusPre').textContent = (r.ok && d.valid ? 'VALID' : 'INVALID') + '\nSHA-256: ' + (d.sha256 || '--') + '\nEntries: ' + (d.entries_count || 0) + ((d.errors && d.errors.length) ? '\nErrors: ' + d.errors.join('; ') : '');
        }
        showToast(r.ok ? 'الأرشيف سليم واجتاز فحص المسارات' : 'الأرشيف غير صالح أو يحتوي مسارات مرفوضة', r.ok ? 'success' : 'error');
      });
    }

    if (qs('btnLoadSysupgradeConf')) {
      qs('btnLoadSysupgradeConf').addEventListener('click', async () => {
        const r = await apiCall('system_control', { method: 'POST', body: { subaction: 'sysupgrade_conf_get' }, skipSeqCheck: true });
        if (r.ok && r.data && qs('sysupgradeConfTextarea')) {
          qs('sysupgradeConfTextarea').value = (r.data.entries || []).join('\n');
          showToast('تم تحميل مسارات sysupgrade.conf', 'success');
        } else {
          showToast('تعذر قراءة sysupgrade.conf', 'error');
        }
      });
    }

    if (qs('btnSaveSysupgradeConf')) {
      qs('btnSaveSysupgradeConf').addEventListener('click', async () => {
        const raw = qs('sysupgradeConfTextarea') ? qs('sysupgradeConfTextarea').value : '';
        const paths = raw.split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith('#'));
        const r = await apiCall('system_control', { method: 'POST', body: { subaction: 'sysupgrade_conf_save', paths } });
        if (r.ok) showToast('تم حفظ sysupgrade.conf بأمان', 'success');
        else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل حفظ sysupgrade.conf', 'error');
      });
    }

    qs('btnSysReboot').addEventListener('click', async () => {
      const ch = await apiCall('system_control', { method: 'POST', body: { subaction: 'reboot_challenge' } });
      if (!ch.ok || !ch.data || !ch.data.nonce) {
        showToast('تعذر إصدار رمز تحدي إعادة التشغيل', 'error');
        return;
      }
      const ok = await confirmAction('تأكيد إعادة تشغيل البوابة الشبكية', 'سيتم قطع الاتصال مؤقتاً وإعادة إقلاع النظام بالكامل (رمز التحدي مفعل لمدة 60 ثانية).');
      if (!ok) return;
      const r = await apiCall('system_control', { method: 'POST', body: { subaction: 'reboot', nonce: ch.data.nonce, confirm: 'CONFIRM_REBOOT' } });
      if (r.ok) showToast('جاري إعادة تشغيل البوابة...', 'success');
      else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'تم رفض إعادة التشغيل', 'error');
    });

    qs('btnAddCronJob').addEventListener('click', async () => {
      const template_id = qs('cronTemplateSelect').value;
      const schedule = qs('cronScheduleInput').value.trim();
      const r = await apiCall('system_control', { method: 'POST', body: { subaction: 'cron_add', template_id, schedule } });
      if (r.ok) { showToast('تمت إضافة المهمة المجدولة بنجاح', 'success'); refreshActiveTab(); }
      else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'توقيت غير صالح', 'error');
    });

    qs('btnSaveSshConfig').addEventListener('click', async () => {
      const r = await apiCall('system_control', {
        method: 'POST',
        body: {
          subaction: 'ssh_save',
          password_auth: qs('sshPassAuthChk').checked,
          root_password_auth: qs('sshRootPassAuthChk').checked
        }
      });
      if (r.ok) { showToast('تم تحديث إعدادات SSH بنجاح', 'success'); refreshActiveTab(); }
      else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'مرفوض لمنع القفل', 'error');
    });

    qs('btnAddSshKey').addEventListener('click', async () => {
      const public_key = qs('sshNewKeyInput').value.trim();
      const r = await apiCall('system_control', { method: 'POST', body: { subaction: 'ssh_key_add', public_key } });
      if (r.ok) {
        qs('sshNewKeyInput').value = '';
        showToast('تمت إضافة المفتاح العام بنجاح', 'success');
        refreshActiveTab();
      } else showToast((r.errors && r.errors[0] && r.errors[0].message_ar) || 'مفتاح غير صالح', 'error');
    });

    qs('btnSearchPackages').addEventListener('click', () => loadPackagesList(qs('pkgSearchInput').value.trim()));
    qs('pkgSearchInput').addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter') { ev.preventDefault(); loadPackagesList(qs('pkgSearchInput').value.trim()); }
    });
    if (qs('btnPkgUpdateRepos')) {
      qs('btnPkgUpdateRepos').addEventListener('click', () => runPkgAction('update', ''));
    }
    if (qs('btnPkgCheckUpgrades')) {
      qs('btnPkgCheckUpgrades').addEventListener('click', () => runPkgAction('check_upgrades', ''));
    }
    if (qs('btnPkgInstall')) {
      qs('btnPkgInstall').addEventListener('click', () => runPkgAction('install', (qs('pkgActionNameInput').value || '').trim()));
    }
    if (qs('btnPkgUpgradeOne')) {
      qs('btnPkgUpgradeOne').addEventListener('click', () => runPkgAction('upgrade', (qs('pkgActionNameInput').value || '').trim()));
    }

    // Diagnostics, Audit Export & Users
    qs('btnDiagPing').addEventListener('click', () => runDiag('ping'));
    qs('btnDiagTrace').addEventListener('click', () => runDiag('traceroute'));
    qs('btnDiagNslookup').addEventListener('click', () => runDiag('nslookup'));
    qs('btnDiagTcpProbe').addEventListener('click', () => runDiag('tcp_probe'));
    qs('btnDiagRoutes').addEventListener('click', () => runDiag('routes'));
    qs('btnRefreshLogs').addEventListener('click', fetchLogs);
    qs('btnExportAuditJson').addEventListener('click', () => {
      const dataStr = JSON.stringify(state.lastAuditEntries || [], null, 2);
      const blob = new Blob([dataStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'gateway_audit_log.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });

    qs('btnCreateReadonly').addEventListener('click', async () => {
      const u = (qs('roUsernameInput').value || '').trim();
      const p = qs('roPasswordInput').value || '';
      const r = await apiCall('auth_set_readonly', { method: 'POST', body: { username: u, password: p } });
      if (r.ok) {
        qs('roPasswordInput').value = '';
        qs('roStatusMsg').textContent = (r.data && r.data.message_ar) || 'تم الحفظ بنجاح';
        showToast('تم إعداد حساب المراقب بنجاح', 'success');
        refreshActiveTab();
      } else {
        qs('roStatusMsg').textContent = (r.errors && r.errors[0] && r.errors[0].message_ar) || 'فشل إعداد الحساب';
        showToast(qs('roStatusMsg').textContent, 'error');
      }
    });

    qs('btnChangeAdminPass').addEventListener('click', async () => {
      const p = qs('adminNewPassInput').value || '';
      if (p.length < 12) {
        qs('adminPassStatusMsg').textContent = 'يجب أن لا يقل طول كلمة المرور الجديدة عن 12 حرفاً.';
        return;
      }
      const ok = await confirmAction('تحديث كلمة مرور المدير', 'سيتم تغيير كلمة مرور حساب المدير فوراً.');
      if (!ok) return;
      const r = await apiCall('auth_admin', { method: 'POST', body: { subaction: 'change_password', password: p } });
      if (r.ok) {
        qs('adminNewPassInput').value = '';
        qs('adminPassStatusMsg').textContent = 'تم تحديث كلمة مرور المدير بنجاح';
        showToast('تم تحديث كلمة مرور المدير', 'success');
      } else {
        qs('adminPassStatusMsg').textContent = (r.errors && r.errors[0] && r.errors[0].message_ar) || 'تعذر التحديث';
        showToast(qs('adminPassStatusMsg').textContent, 'error');
      }
    });

    document.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape') closeMobileDrawer();
    });
  }

  function initCollapsibleCards() {
    document.querySelectorAll('.tab-view').forEach((sec) => {
      const cards = Array.from(sec.querySelectorAll('article.card:not(.mini-stat)'));
      if (cards.length > 1 && !sec.querySelector('.section-collapse-bar')) {
        const bar = el('div', 'section-collapse-bar');
        const btnExpandAll = el('button', 'btn btn-secondary btn-sm', 'توسيع جميع الأقسام', { type: 'button' });
        const btnCollapseAll = el('button', 'btn btn-secondary btn-sm', 'طي جميع الأقسام', { type: 'button' });
        btnExpandAll.addEventListener('click', () => {
          cards.forEach((c) => {
            c.classList.remove('is-collapsed');
            const b = c.querySelector('.card-collapse-btn');
            if (b) b.setAttribute('aria-expanded', 'true');
          });
        });
        btnCollapseAll.addEventListener('click', () => {
          cards.forEach((c) => {
            c.classList.add('is-collapsed');
            const b = c.querySelector('.card-collapse-btn');
            if (b) b.setAttribute('aria-expanded', 'false');
          });
        });
        bar.appendChild(btnExpandAll);
        bar.appendChild(btnCollapseAll);
        sec.insertBefore(bar, sec.firstChild);
      }
      cards.forEach((card) => {
        const head = card.querySelector('.card-head');
        if (!head || head.querySelector('.card-collapse-btn')) return;
        card.classList.add('card-collapsible');
        const btn = el('button', 'card-collapse-btn', null, {
          type: 'button',
          'aria-expanded': 'true',
          'aria-label': 'طي أو توسيع القسم',
          title: 'طي أو توسيع القسم'
        });
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', '0 0 24 24');
        svg.setAttribute('width', '16');
        svg.setAttribute('height', '16');
        svg.setAttribute('fill', 'none');
        svg.setAttribute('stroke', 'currentColor');
        svg.setAttribute('stroke-width', '2.2');
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', 'M6 9l6 6 6-6');
        svg.appendChild(path);
        btn.appendChild(svg);

        function toggleCard(ev) {
          if (ev) ev.stopPropagation();
          const collapsed = card.classList.toggle('is-collapsed');
          btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
        }
        btn.addEventListener('click', toggleCard);
        head.addEventListener('click', (ev) => {
          if (ev.target.closest('button, input, select, a, label')) return;
          toggleCard(ev);
        });
        head.appendChild(btn);
      });
    });
  }

  let rollbackTimerId = null;
  let activeRollbackToken = '';

  function showRollbackBanner(token, ttlSec) {
    const b = qs('rollbackBanner');
    if (!b || !token) return;
    activeRollbackToken = token;
    let left = ttlSec || 60;
    b.classList.remove('hidden');
    if (rollbackTimerId) clearInterval(rollbackTimerId);
    const upd = () => {
      if (qs('rollbackCountdownText')) qs('rollbackCountdownText').textContent = 'متبقي ' + nfInt.format(left) + ' ثانية';
    };
    upd();
    rollbackTimerId = setInterval(() => {
      left--;
      if (left <= 0) {
        clearInterval(rollbackTimerId);
        rollbackTimerId = null;
        activeRollbackToken = '';
        b.classList.add('hidden');
      } else {
        upd();
      }
    }, 1000);
  }

  async function loadAdminExtras() {
    try {
      const [ra, rt, rq] = await Promise.all([
        apiCall('alerts', { skipSeqCheck: true }),
        apiCall('totp_status', { skipSeqCheck: true }),
        apiCall('device_quotas', { skipSeqCheck: true })
      ]);
      if (ra && ra.ok && ra.data && ra.data.config) {
        const c = ra.data.config;
        if (qs('alertsTgEnabled')) qs('alertsTgEnabled').checked = !!c.telegram_enabled;
        if (qs('alertsTgChatId')) qs('alertsTgChatId').value = c.telegram_chat_id || '';
        if (qs('alertsNtfyEnabled')) qs('alertsNtfyEnabled').checked = !!c.ntfy_enabled;
        if (qs('alertsNtfyUrl')) qs('alertsNtfyUrl').value = c.ntfy_url || '';
        if (qs('alertsCpuMax')) qs('alertsCpuMax').value = c.cpu_temp_max || 78;
        if (qs('alertsRamMax')) qs('alertsRamMax').value = c.ram_pct_max || 90;
        const tb = qs('alertsHistoryBody');
        if (tb) {
          clearEl(tb);
          for (const h of (ra.data.history || []).slice().reverse()) {
            const tr = el('tr');
            tr.appendChild(el('td', 'mono', h.ts || '--'));
            tr.appendChild(el('td', null, h.level || 'info'));
            tr.appendChild(el('td', null, h.title || '--'));
            tr.appendChild(el('td', null, h.message || '--'));
            tb.appendChild(tr);
          }
        }
      }
      if (rt && rt.ok && rt.data && qs('totpStatusBadge')) {
        qs('totpStatusBadge').textContent = rt.data.enabled ? 'مفعّلة' : 'غير مفعّلة';
        qs('totpStatusBadge').className = 'status-pill ' + (rt.data.enabled ? 'pill-success' : 'pill-neutral');
      }
      if (rq && rq.ok && rq.data) {
        if (qs('quotasListText')) {
          const qk = Object.keys(rq.data.quotas || {});
          qs('quotasListText').textContent = qk.length ? qk.map((m) => m + ': ' + rq.data.quotas[m].quota_mb + ' MiB').join(' | ') : 'لا توجد حصص مسجلة.';
        }
        if (qs('schedListText')) {
          const sc = rq.data.schedules || [];
          qs('schedListText').textContent = sc.length ? sc.map((s) => s.mac + ' (' + s.action_type + ' ' + s.start_time + '-' + s.end_time + ')').join(' | ') : 'لا توجد جداول مسجلة.';
        }
      }
    } catch (e) {}
  }

  async function loadReportAndAudit() {
    try {
      const [rr, rs] = await Promise.all([
        apiCall('weekly_report', { skipSeqCheck: true }),
        apiCall('security_audit', { skipSeqCheck: true })
      ]);
      if (rr && rr.ok && rr.data && rr.data.report && qs('weeklyReportList')) {
        const rep = rr.data.report;
        const box = qs('weeklyReportList');
        clearEl(box);
        const items = [
          ['استعلامات DNS (عينة)', nfInt.format(rep.dns_queries_sampled || 0)],
          ['المحجوب (عينة)', nfInt.format(rep.dns_blocked_sampled || 0) + ' (' + nfLatn.format(rep.block_rate_pct || 0) + '%)'],
          ['أجهزة DHCP النشطة', nfInt.format(rep.active_leases || 0)],
          ['سجلات التدقيق المسجلة', nfInt.format(rep.audit_events_count || 0)]
        ];
        for (const [k, v] of items) {
          const r = el('div', 'kv-row');
          r.appendChild(el('span', null, k));
          r.appendChild(el('strong', 'mono', v));
          box.appendChild(r);
        }
      }
      if (rs && rs.ok && rs.data && qs('securityAuditList')) {
        const box = qs('securityAuditList');
        clearEl(box);
        for (const chk of (rs.data.checks || [])) {
          const r = el('div', 'kv-row');
          r.appendChild(el('span', null, chk.label));
          const st = el('strong', chk.ok ? 'pill-success status-pill' : 'pill-warning status-pill', chk.detail);
          r.appendChild(st);
          box.appendChild(r);
        }
      }
    } catch (e) {}
  }

  function initPlatformExtras() {
    if (qs('btnConfirmRollback')) {
      qs('btnConfirmRollback').addEventListener('click', async () => {
        if (!activeRollbackToken) return;
        const r = await apiCall('rollback_control', { method: 'POST', body: { subaction: 'confirm', token: activeRollbackToken } });
        if (rollbackTimerId) clearInterval(rollbackTimerId);
        activeRollbackToken = '';
        if (qs('rollbackBanner')) qs('rollbackBanner').classList.add('hidden');
        showToast((r && r.data && r.data.message_ar) || 'تم تأكيد التعديل', r && r.ok ? 'success' : 'error');
      });
    }
    if (qs('btnRevertRollback')) {
      qs('btnRevertRollback').addEventListener('click', async () => {
        if (!activeRollbackToken) return;
        const r = await apiCall('rollback_control', { method: 'POST', body: { subaction: 'revert', token: activeRollbackToken } });
        if (rollbackTimerId) clearInterval(rollbackTimerId);
        activeRollbackToken = '';
        if (qs('rollbackBanner')) qs('rollbackBanner').classList.add('hidden');
        showToast((r && r.data && r.data.message_ar) || 'تم التراجع الفوري', r && r.ok ? 'success' : 'error');
        refreshActiveTab();
      });
    }
    if (qs('btnTotpSetup')) {
      qs('btnTotpSetup').addEventListener('click', async () => {
        const r = await apiCall('auth_admin', { method: 'POST', body: { subaction: 'totp_setup' } });
        if (r && r.ok && r.data && qs('totpSetupPanel')) {
          qs('totpSetupPanel').classList.remove('hidden');
          if (qs('totpSecretDisplay')) qs('totpSecretDisplay').textContent = r.data.secret || '--';
        }
      });
    }
    if (qs('btnTotpEnable')) {
      qs('btnTotpEnable').addEventListener('click', async () => {
        const code = qs('totpVerifyInput') ? qs('totpVerifyInput').value.trim() : '';
        const sec = qs('totpSecretDisplay') ? qs('totpSecretDisplay').textContent.trim() : '';
        const r = await apiCall('auth_admin', { method: 'POST', body: { subaction: 'totp_enable', code, secret: sec } });
        showToast((r && r.data && r.data.message_ar) || 'تم التحديث', r && r.ok ? 'success' : 'error');
        if (r && r.ok && qs('totpSetupPanel')) qs('totpSetupPanel').classList.add('hidden');
        loadAdminExtras();
      });
    }
    if (qs('btnTotpDisable')) {
      qs('btnTotpDisable').addEventListener('click', async () => {
        const r = await apiCall('auth_admin', { method: 'POST', body: { subaction: 'totp_disable' } });
        showToast((r && r.data && r.data.message_ar) || 'تم التعطيل', r && r.ok ? 'success' : 'error');
        loadAdminExtras();
      });
    }
    if (qs('btnSaveAlerts')) {
      qs('btnSaveAlerts').addEventListener('click', async () => {
        const r = await apiCall('alerts_control', {
          method: 'POST',
          body: {
            subaction: 'set',
            telegram_enabled: !!(qs('alertsTgEnabled') && qs('alertsTgEnabled').checked),
            telegram_bot_token: qs('alertsTgToken') ? qs('alertsTgToken').value.trim() : '',
            telegram_chat_id: qs('alertsTgChatId') ? qs('alertsTgChatId').value.trim() : '',
            ntfy_enabled: !!(qs('alertsNtfyEnabled') && qs('alertsNtfyEnabled').checked),
            ntfy_url: qs('alertsNtfyUrl') ? qs('alertsNtfyUrl').value.trim() : '',
            cpu_temp_max: Number(qs('alertsCpuMax') ? qs('alertsCpuMax').value : 78) || 78,
            ram_pct_max: Number(qs('alertsRamMax') ? qs('alertsRamMax').value : 90) || 90
          }
        });
        showToast((r && r.data && r.data.message_ar) || 'تم الحفظ', r && r.ok ? 'success' : 'error');
        loadAdminExtras();
      });
    }
    if (qs('btnTestAlerts')) {
      qs('btnTestAlerts').addEventListener('click', async () => {
        const r = await apiCall('alerts_control', { method: 'POST', body: { subaction: 'test' } });
        showToast((r && r.data && r.data.message_ar) || 'تم الإرسال', r && r.ok ? 'success' : 'error');
        loadAdminExtras();
      });
    }
    if (qs('btnSaveQuota')) {
      qs('btnSaveQuota').addEventListener('click', async () => {
        const r = await apiCall('client_quota_set', {
          method: 'POST',
          body: {
            mac: qs('quotaMacInput') ? qs('quotaMacInput').value.trim() : '',
            quota_mb: Number(qs('quotaMbInput') ? qs('quotaMbInput').value : 0) || 0,
            throttle_kbps: Number(qs('quotaThrottleInput') ? qs('quotaThrottleInput').value : 0) || 0
          }
        });
        showToast((r && r.data && r.data.message_ar) || 'تم الحفظ', r && r.ok ? 'success' : 'error');
        loadAdminExtras();
      });
    }
    if (qs('btnSaveSchedule')) {
      qs('btnSaveSchedule').addEventListener('click', async () => {
        const r = await apiCall('schedule_action_set', {
          method: 'POST',
          body: {
            mac: qs('schedMacInput') ? qs('schedMacInput').value.trim() : '',
            action_type: qs('schedActionSelect') ? qs('schedActionSelect').value : 'block',
            start_time: qs('schedStartInput') ? qs('schedStartInput').value.trim() : '23:00',
            end_time: qs('schedEndInput') ? qs('schedEndInput').value.trim() : '07:00'
          }
        });
        showToast((r && r.data && r.data.message_ar) || 'تمت الجدولة', r && r.ok ? 'success' : 'error');
        loadAdminExtras();
      });
    }
    if (qs('btnRefreshReport')) qs('btnRefreshReport').addEventListener('click', loadReportAndAudit);
    if (qs('btnRunSecurityAudit')) qs('btnRunSecurityAudit').addEventListener('click', loadReportAndAudit);

    // Background tab SSE / chart pause
    document.addEventListener('visibilitychange', () => {
      if (!state.authenticated) return;
      if (document.hidden) {
        if (state.netChart) state.netChart.paused = true;
        stopSSE();
      } else {
        if (state.netChart) { state.netChart.paused = false; state.netChart.render(); }
        startSSE();
        refreshOverview();
      }
    });

    // Register PWA Service Worker
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('/pro/sw.js').catch(() => {});
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    initCollapsibleCards();
    initListeners();
    initPlatformExtras();
    if (window.NetChart && qs('net-chart-root')) {
      state.netChart = window.NetChart.mount(qs('net-chart-root'), {
        title: state.selectedIface || 'wlan0',
        unit: state.rateUnitMode || 'auto_bits',
        range: 300
      });
    }
    checkAuthState();
  });

  window.NOC = {
    state: state,
    apiCall: apiCall,
    switchTab: switchTab,
    openClientInspector: openClientInspector,
    refreshActiveTab: refreshActiveTab,
    showToast: showToast,
    TAB_TITLES: TAB_TITLES
  };
})();
