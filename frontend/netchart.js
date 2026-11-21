/*!
 * netchart.js: مراقب تدفق الإنترنت (بطاقات + رسم مرآوي)
 * يحتاج Chart.js v4 محلياً (window.Chart). لا يحتاج أي شيء آخر.
 *
 * الاستخدام:
 *   var nc = NetChart.mount(document.getElementById('net-chart-root'), { title: 'wlan0', unit: 'auto', range: 300 });
 *   nc.push(rxBitsPerSec, txBitsPerSec, Date.now());   // عند كل عيّنة
 *   nc.setUnit('auto'|'auto_bits'|'auto_bytes'|'bps'|'kbps'|'mbps'|'kbs'|'mbs');
 *   nc.setTitle('eth0');
 *   nc.clear();      // عند تغيير الواجهة
 *   nc.destroy();
 */
(function (global) {
  'use strict';

  var COL = { rx: '#22c55e', tx: '#f59e0b', grid: 'rgba(128,128,128,.18)', tick: '#8b93a1', zero: 'rgba(128,128,128,.7)' };
  var UNITS = { bps: 1, kbps: 1e3, mbps: 1e6, kbs: 8e3, mbs: 8e6 };
  var UNIT_LBL = {
    auto: 'تلقائي (bps/Kbps/Mbps)',
    auto_bits: 'تلقائي (bps/Kbps/Mbps)',
    auto_bytes: 'تلقائي (B/s/KB/s/MB/s)',
    bps: 'bps',
    kbps: 'Kbps',
    mbps: 'Mbps',
    kbs: 'KB/s',
    mbs: 'MB/s'
  };

  var CSS = [
    '.nc{font-family:inherit;color:inherit;max-width:100%;min-width:0}',
    '.nc button{font:inherit;font-size:13px;color:inherit;background:transparent;border:1px solid rgba(128,128,128,.4);padding:4px 12px;cursor:pointer;border-radius:8px}',
    '.nc button:hover{border-color:rgba(128,128,128,.8)}',
    '.nc-bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:0 0 12px}',
    '.nc-sp{flex:1}',
    '.nc-meta{font-size:12px;opacity:.7}',
    '.nc-seg{display:inline-flex;border-radius:8px;overflow:hidden}',
    '.nc-seg button{border-radius:0;margin-inline-start:-1px}',
    '.nc-seg button.on{background:rgba(59,130,246,.2);border-color:#3b82f6;color:#60a5fa}',
    '.nc-tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:0 0 14px}',
    '.nc-tile{background:rgba(128,128,128,.12);border-radius:8px;padding:10px 12px;min-width:0;max-width:100%}',
    '.nc-tile small{font-size:12px;opacity:.7}',
    '.nc-tile b{display:block;font-size:20px;font-weight:500;margin:2px 0 4px;direction:ltr;text-align:right;font-variant-numeric:tabular-nums}',
    '.nc-tile canvas{display:block;width:100%;height:34px}',
    '.nc-lg{display:flex;gap:16px;font-size:12px;opacity:.8;margin:0 0 6px;flex-wrap:wrap}',
    '.nc-lg i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-inline-end:4px;vertical-align:-1px}',
    '.nc-cv{position:relative;width:100%;height:280px;min-width:0}'
  ].join('');

  function injectCss() {
    if (document.getElementById('nc-style')) return;
    var s = document.createElement('style');
    s.id = 'nc-style';
    s.textContent = CSS;
    document.head.appendChild(s);
  }

  function fmtRate(bps, unit) {
    var a = Math.abs(bps);
    if (unit === 'auto_bytes') {
      var bytesPerSec = a / 8;
      if (bytesPerSec >= 1e6) return (bytesPerSec / 1e6).toFixed(2) + ' MB/s';
      if (bytesPerSec >= 1e3) return (bytesPerSec / 1e3).toFixed(1) + ' KB/s';
      return Math.round(bytesPerSec) + ' B/s';
    }
    if (!UNITS[unit]) {
      if (a >= 1e6) return (a / 1e6).toFixed(2) + ' Mbps';
      if (a >= 1e3) return (a / 1e3).toFixed(1) + ' Kbps';
      return Math.round(a) + ' bps';
    }
    return (a / UNITS[unit]).toFixed(unit === 'bps' ? 0 : 2) + ' ' + UNIT_LBL[unit];
  }

  function fmtBytes(b) {
    var u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'], i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return b.toFixed(i === 0 ? 0 : 2) + ' ' + u[i];
  }

  function fmtAgo(sec) {
    sec = Math.max(0, Math.round(sec));
    if (sec === 0) return 'الآن';
    if (sec >= 60) return Math.floor(sec / 60) + ' د ' + (sec % 60) + ' ث';
    return sec + ' ث';
  }

  function drawSpark(cv, data, color) {
    var dpr = global.devicePixelRatio || 1;
    var w = cv.clientWidth, h = cv.clientHeight;
    if (!w || !h) return;
    if (cv.width !== w * dpr) { cv.width = w * dpr; cv.height = h * dpr; }
    var g = cv.getContext('2d');
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.clearRect(0, 0, w, h);
    if (data.length < 2) return;
    var mx = Math.max.apply(null, data) || 1;
    g.beginPath();
    for (var i = 0; i < data.length; i++) {
      var x = (i / (data.length - 1)) * w;
      var y = h - 2 - (data[i] / mx) * (h - 4);
      if (i === 0) g.moveTo(x, y); else g.lineTo(x, y);
    }
    g.strokeStyle = color;
    g.lineWidth = 1.5;
    g.lineJoin = 'round';
    g.stroke();
  }

  function tile(k, label) {
    return '<div class="nc-tile"><small>' + label + '</small><b data-k="' + k + '">-</b><canvas data-s="' + k + '"></canvas></div>';
  }

  function NetChart(root, opts) {
    if (!global.Chart) throw new Error('NetChart: Chart.js غير محمّل');
    opts = opts || {};
    this.root = root;
    this.maxSamples = opts.maxSamples || 5400;
    this.range = opts.range || 300;
    this.unit = opts.unit || 'auto';
    this.rx = []; this.tx = []; this.ts = [];
    this.paused = false;
    this._raf = 0;
    this._viewTs = [];
    this._build(opts.title || '');
    this.render();
  }

  NetChart.prototype._build = function (title) {
    var self = this;
    injectCss();
    this.root.innerHTML =
      '<div class="nc">' +
        '<div class="nc-bar">' +
          '<div class="nc-seg"><button type="button" data-r="60">1 د</button><button type="button" data-r="300">5 د</button><button type="button" data-r="900">15 د</button></div>' +
          '<button type="button" class="nc-pause">إيقاف مؤقت</button>' +
          '<span class="nc-sp"></span><span class="nc-meta"></span>' +
        '</div>' +
        '<div class="nc-tiles">' +
          tile('rx', 'التنزيل الآن') + tile('tx', 'الرفع الآن') + tile('pk', 'الذروة في المدى') + tile('tt', 'الإجمالي في المدى') +
        '</div>' +
        '<div class="nc-lg"><span><i style="background:' + COL.rx + '"></i>تنزيل RX (فوق الصفر)</span><span><i style="background:' + COL.tx + '"></i>رفع TX (تحت الصفر)</span><span>- - المتوسط</span></div>' +
        '<div class="nc-cv" dir="ltr"><canvas></canvas></div>' +
      '</div>';

    this.elMeta = this.root.querySelector('.nc-meta');
    this.elPause = this.root.querySelector('.nc-pause');
    this.segBtns = this.root.querySelectorAll('.nc-seg button');
    this.setTitle(title);

    Array.prototype.forEach.call(this.segBtns, function (b) {
      b.addEventListener('click', function () { self.setRange(parseInt(b.getAttribute('data-r'), 10)); });
    });
    this.elPause.addEventListener('click', function () {
      self.paused = !self.paused;
      self.elPause.textContent = self.paused ? 'استئناف' : 'إيقاف مؤقت';
      if (!self.paused) self.render();
    });
    this._markRange();

    var self2 = this;
    function ds(label, color, fill) {
      return { label: label, data: [], borderColor: color, backgroundColor: fill, fill: fill ? 'origin' : false, borderWidth: 2, pointRadius: 0, tension: 0.12 };
    }
    var avgRx = ds('متوسط التنزيل', COL.rx, null); avgRx.borderDash = [5, 4]; avgRx.borderWidth = 1;
    var avgTx = ds('متوسط الرفع', COL.tx, null); avgTx.borderDash = [5, 4]; avgTx.borderWidth = 1;
    var peak = { label: 'ذروة', data: [], borderColor: COL.rx, backgroundColor: COL.rx, pointRadius: 5, pointBorderWidth: 2, pointBorderColor: '#fff', showLine: false };

    this.chart = new global.Chart(this.root.querySelector('.nc-cv canvas'), {
      type: 'line',
      data: { labels: [], datasets: [ds('تنزيل', COL.rx, 'rgba(34,197,94,.14)'), ds('رفع', COL.tx, 'rgba(245,158,11,.14)'), avgRx, avgTx, peak] },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            rtl: true,
            filter: function (c) { return c.datasetIndex < 2; },
            callbacks: {
              title: function (it) {
                var t = self2._viewTs, i = it[0].dataIndex;
                return 'قبل ' + fmtAgo((t[t.length - 1] - t[i]) / 1000);
              },
              label: function (c) { return c.dataset.label + ': ' + fmtRate(c.parsed.y, self2.unit); }
            }
          }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: {
              color: COL.tick, font: { size: 11 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 6,
              callback: function (v) {
                var t = self2._viewTs;
                return t.length ? fmtAgo((t[t.length - 1] - t[v]) / 1000) : '';
              }
            }
          },
          y: {
            border: { display: false },
            grid: { color: function (c) { return c.tick.value === 0 ? COL.zero : COL.grid; } },
            ticks: { color: COL.tick, font: { size: 11 }, maxTicksLimit: 7, callback: function (v) { return fmtRate(v, self2.unit); } }
          }
        }
      }
    });
  };

  NetChart.prototype._markRange = function () {
    var r = String(this.range);
    Array.prototype.forEach.call(this.segBtns, function (b) {
      b.classList.toggle('on', b.getAttribute('data-r') === r);
    });
  };

  NetChart.prototype.setTitle = function (t) { this._title = t; this._updateMeta(); };
  NetChart.prototype._updateMeta = function () {
    var u = (this.unit === 'auto' || this.unit === 'auto_bits' || !UNIT_LBL[this.unit])
      ? 'الوحدة تلقائية'
      : 'الوحدة: ' + UNIT_LBL[this.unit];
    this.elMeta.textContent = (this._title ? this._title + ' · ' : '') + u;
  };
  NetChart.prototype.setUnit = function (u) {
    this.unit = (UNITS[u] || u === 'auto_bytes' || u === 'auto_bits') ? u : 'auto';
    this._updateMeta();
    this.render();
  };
  NetChart.prototype.setRange = function (sec) { this.range = sec; this._markRange(); this.render(); };
  NetChart.prototype.clear = function () { this.rx = []; this.tx = []; this.ts = []; this.render(); };

  NetChart.prototype.push = function (rxBps, txBps, tMs) {
    this.rx.push(+rxBps || 0);
    this.tx.push(+txBps || 0);
    this.ts.push(tMs || Date.now());
    if (this.rx.length > this.maxSamples + 300) {
      this.rx.splice(0, 300); this.tx.splice(0, 300); this.ts.splice(0, 300);
    }
    if (this.paused || this._raf) return;
    var self = this;
    this._raf = global.requestAnimationFrame(function () { self._raf = 0; self.render(); });
  };

  NetChart.prototype.render = function () {
    var n = this.ts.length;
    var q = function (k) { return this.root.querySelector('[data-k="' + k + '"]'); }.bind(this);
    if (!n) {
      this.chart.data.labels = [];
      this.chart.data.datasets.forEach(function (d) { d.data = []; });
      this.chart.update('none');
      ['rx', 'tx', 'pk', 'tt'].forEach(function (k) { q(k).textContent = '-'; });
      return;
    }
    var cutoff = this.ts[n - 1] - this.range * 1000, s = n - 1;
    while (s > 0 && this.ts[s - 1] >= cutoff) s--;

    var rx = this.rx.slice(s), tx = this.tx.slice(s), ts = this.ts.slice(s), m = rx.length, i;
    this._viewTs = ts;

    var pk = 0, pi = 0, sa = 0, sb = 0, bytes = 0;
    for (i = 0; i < m; i++) {
      if (rx[i] > pk) { pk = rx[i]; pi = i; }
      sa += rx[i]; sb += tx[i];
      if (i > 0) bytes += (rx[i] + tx[i]) * Math.min(10, (ts[i] - ts[i - 1]) / 1000) / 8;
    }
    var ax = sa / m, bx = sb / m, d = this.chart.data;
    d.labels = rx.map(function (_, j) { return j; });
    d.datasets[0].data = rx;
    d.datasets[1].data = tx.map(function (v) { return -v; });
    d.datasets[2].data = rx.map(function () { return ax; });
    d.datasets[3].data = tx.map(function () { return -bx; });
    d.datasets[4].data = rx.map(function (v, j) { return j === pi ? v : null; });
    this.chart.update('none');

    q('rx').textContent = fmtRate(rx[m - 1], this.unit);
    q('tx').textContent = fmtRate(tx[m - 1], this.unit);
    q('pk').textContent = fmtRate(pk, this.unit);
    q('tt').textContent = fmtBytes(bytes);

    var w = Math.min(60, m), sr = rx.slice(-w), st = tx.slice(-w);
    var spk = sr.map(function (_, j) { return Math.max.apply(null, sr.slice(Math.max(0, j - 30), j + 1)); });
    var tot = sr.map(function (v, j) { return v + st[j]; });
    var sp = function (k) { return this.root.querySelector('[data-s="' + k + '"]'); }.bind(this);
    drawSpark(sp('rx'), sr, COL.rx);
    drawSpark(sp('tx'), st, COL.tx);
    drawSpark(sp('pk'), spk, COL.rx);
    drawSpark(sp('tt'), tot, COL.tick);
  };

  NetChart.prototype.destroy = function () {
    if (this._raf) global.cancelAnimationFrame(this._raf);
    this.chart.destroy();
    this.root.innerHTML = '';
  };

  NetChart.mount = function (root, opts) { return new NetChart(root, opts); };
  global.NetChart = NetChart;
})(window);
