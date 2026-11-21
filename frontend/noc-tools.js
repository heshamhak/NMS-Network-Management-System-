/*!
 * noc-tools.js: أدوات تنسيق الصفحات الطويلة
 *  1) فهرس صفحة لاصق (chips) يقفز إلى أي بطاقة ويفتحها.
 *  2) تصفية فورية لكل جدول (+ سقف 200 صف مع "عرض المزيد") بلا تعديل أي دالة رسم في app.js.
 * يُحمَّل بعد app.js. متوافق مع CSP (لا innerHTML ولا inline handlers).
 */
(function (root) {
  'use strict';

  var DIG = '٠١٢٣٤٥٦٧٨٩';
  function norm(s) {
    s = String(s == null ? '' : s).toLowerCase();
    s = s.replace(/[\u064B-\u065F\u0670\u0640]/g, '');
    s = s.replace(/[أإآٱ]/g, 'ا').replace(/ى/g, 'ي').replace(/ة/g, 'ه').replace(/ؤ/g, 'و').replace(/ئ/g, 'ي');
    s = s.replace(/[٠-٩]/g, function (d) { return String(DIG.indexOf(d)); });
    s = s.replace(/[^\p{L}\p{N}\s.:_\/-]/gu, ' ');
    return s.replace(/\s+/g, ' ').trim();
  }
  if (typeof document === 'undefined') {
    if (typeof module !== 'undefined') module.exports = { norm: norm };
    return;
  }

  var LIMIT = 200, reg = {};

  function el(tag, cls, text, attrs) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = String(text);
    if (attrs) for (var k in attrs) if (attrs[k] != null) n.setAttribute(k, String(attrs[k]));
    return n;
  }
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

  /* ---------- تصفية الجداول ---------- */
  function enhanceTable(wrap) {
    if (wrap.getAttribute('data-tt') || wrap.classList.contains('table-scroll-bounded')) return;
    var table = wrap.querySelector('table.data-table');
    if (!table || !table.tBodies[0]) return;
    var tbody = table.tBodies[0];
    wrap.setAttribute('data-tt', '1');

    var bar = el('div', 'tt-bar');
    bar.hidden = true;
    var inp = el('input', 'form-input form-input-sm', null, { type: 'search', placeholder: 'تصفية الجدول...', 'aria-label': 'تصفية الجدول' });
    var cnt = el('span', 'tt-count');
    var more = el('button', 'btn btn-secondary btn-sm', 'عرض المزيد', { type: 'button' });
    more.hidden = true;
    bar.appendChild(inp); bar.appendChild(cnt); bar.appendChild(more);
    wrap.parentNode.insertBefore(bar, wrap);

    var limit = LIMIT, raf = 0;
    function apply() {
      raf = 0;
      var rows = tbody.rows, total = rows.length, matched = 0, shown = 0;
      var terms = norm(inp.value).split(' ').filter(Boolean);
      for (var i = 0; i < total; i++) {
        var r = rows[i];
        var txt = r._n || (r._n = norm(r.textContent));
        var ok = true;
        for (var t = 0; t < terms.length; t++) if (txt.indexOf(terms[t]) < 0) { ok = false; break; }
        if (ok) { matched++; if (shown < limit) { r.hidden = false; shown++; } else r.hidden = true; }
        else r.hidden = true;
      }
      bar.hidden = total <= 8 && !inp.value;
      cnt.textContent = (inp.value ? matched + ' من ' + total : total) + ' صف';
      more.hidden = matched <= shown;
      if (!more.hidden) more.textContent = 'عرض المزيد (' + (matched - shown) + ')';
      wrap.classList.toggle('tt-tall', total > 12);
    }
    function schedule() { if (!raf) raf = root.requestAnimationFrame(apply); }
    inp.addEventListener('input', function () { limit = LIMIT; apply(); });
    more.addEventListener('click', function () { limit += LIMIT; apply(); });
    new root.MutationObserver(schedule).observe(tbody, { childList: true });
    if (tbody.id) reg[tbody.id] = { input: inp, apply: function () { limit = LIMIT; apply(); } };
    apply();
  }
  function setFilter(bodyId, text) {
    var r = reg[bodyId];
    if (!r) return;
    r.input.value = text || '';
    r.apply();
  }

  /* ---------- فهرس الصفحة ---------- */
  function buildPageIndex(view) {
    var old = view.querySelector(':scope > .page-index');
    if (old) old.remove();
    var cards = [].slice.call(view.querySelectorAll('article.card')).filter(function (c) {
      return !c.classList.contains('mini-stat') && !c.closest('.admin-only.hidden') && c.querySelector('.card-head h3');
    });
    if (cards.length < 3) return;
    var nav = el('nav', 'page-index', null, { 'aria-label': 'فهرس الصفحة' });
    cards.forEach(function (c) {
      var t = c.querySelector('.card-head h3').textContent.trim();
      var b = el('button', 'pi-chip', t, { type: 'button', title: t });
      b.addEventListener('click', function () {
        expand(c);
        c.scrollIntoView({ block: 'start', behavior: motion() });
        flash(c);
      });
      nav.appendChild(b);
    });
    view.insertBefore(nav, view.firstChild);
  }
  function refreshIndexes() { document.querySelectorAll('.tab-view').forEach(buildPageIndex); }

  function syncCmdH() {
    var b = document.getElementById('opsCommandBar');
    if (!b) return;
    var sticky = root.getComputedStyle(b).position === 'sticky';
    document.documentElement.style.setProperty('--cmd-h', (sticky ? b.offsetHeight : 0) + 'px');
  }

  function init() {
    document.querySelectorAll('.table-scroll').forEach(enhanceTable);
    refreshIndexes();
    syncCmdH();
    root.addEventListener('resize', syncCmdH);
    if (root.ResizeObserver) { var b = document.getElementById('opsCommandBar'); if (b) new root.ResizeObserver(syncCmdH).observe(b); }
    document.addEventListener('noc:auth', refreshIndexes);
    document.addEventListener('noc:tab', function () { refreshIndexes(); syncCmdH(); });
  }
  root.NOCTools = { setFilter: setFilter, refreshIndexes: refreshIndexes, norm: norm };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})(typeof window !== 'undefined' ? window : globalThis);
