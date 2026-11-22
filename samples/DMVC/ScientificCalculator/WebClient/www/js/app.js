// Page behaviour of the web client. No inline script anywhere (CSP): everything is wired here,
// on document, so it keeps working after htmx swaps the body (hx-boost) or a fragment.
(function () {
  'use strict';

  // ---- Texts: the "js" section of i18n\<lang>.json, in a meta of the layout ----
  var texts = {};
  try { texts = JSON.parse(document.querySelector('meta[name="app-texts"]').content); } catch (e) { /* no texts */ }
  var locale = document.documentElement.lang || undefined;

  function text(key, args) {
    var s = texts[key] || key;
    Object.keys(args || {}).forEach(function (name) { s = s.split('{' + name + '}').join(args[name]); });
    return s;
  }

  // ---- Theme toggle ----
  function updateThemeIcon() {
    var btn = document.getElementById('themeToggle');
    if (!btn) return;
    var dark = document.documentElement.getAttribute('data-bs-theme') === 'dark';
    btn.querySelector('i').className = dark ? 'bi bi-sun' : 'bi bi-moon-stars';
    btn.title = dark ? text('theme_light') : text('theme_dark');
    btn.setAttribute('aria-label', btn.title);
  }

  document.addEventListener('click', function (evt) {
    if (!evt.target.closest('#themeToggle')) return;
    var next = document.documentElement.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-bs-theme', next);
    try { localStorage.setItem('calcweb-theme', next); } catch (e) { /* storage blocked */ }
    updateThemeIcon();
    refreshCharts(document.body);
  });

  // ---- Toasts: text only (textContent), never HTML ----
  function showToast(message, type) {
    var container = document.getElementById('toastContainer');
    if (!container || !window.bootstrap) return;
    var el = document.createElement('div');
    el.className = 'toast align-items-center border-0 text-bg-' + (type || 'info');
    el.setAttribute('role', 'alert');
    var row = document.createElement('div');
    row.className = 'd-flex';
    var body = document.createElement('div');
    body.className = 'toast-body';
    body.textContent = message;
    var close = document.createElement('button');
    close.type = 'button';
    close.className = 'btn-close btn-close-white me-2 m-auto';
    close.setAttribute('data-bs-dismiss', 'toast');
    close.setAttribute('aria-label', text('close'));
    row.appendChild(body);
    row.appendChild(close);
    el.appendChild(row);
    container.appendChild(el);
    el.addEventListener('hidden.bs.toast', function () { el.remove(); });
    new bootstrap.Toast(el, { delay: 4000 }).show();
  }

  document.body.addEventListener('showMessage', function (evt) {
    showToast(evt.detail.value, 'success');
  });
  document.addEventListener('htmx:responseError', function (evt) {
    var xhr = evt.detail.xhr;
    showToast(text('request_failed', { status: xhr.status }) + (xhr.status === 403 ? text('request_forbidden') : ''), 'danger');
  });
  document.addEventListener('htmx:sendError', function () {
    showToast(text('send_error'), 'danger');
  });

  // ---- Times: ISO 8601 UTC from the server, shown in the browser's time zone ----
  var relative = window.Intl && Intl.RelativeTimeFormat ? new Intl.RelativeTimeFormat(locale, { numeric: 'auto' }) : null;

  function relativeText(date) {
    var seconds = Math.round((date.getTime() - Date.now()) / 1000);
    if (!relative) return date.toLocaleString(locale);
    if (Math.abs(seconds) < 60) return relative.format(seconds, 'second');
    if (Math.abs(seconds) < 3600) return relative.format(Math.round(seconds / 60), 'minute');
    if (Math.abs(seconds) < 86400) return relative.format(Math.round(seconds / 3600), 'hour');
    return date.toLocaleString(locale);
  }

  function formatTimes(root) {
    root.querySelectorAll('time[datetime]').forEach(function (el) {
      var date = new Date(el.getAttribute('datetime'));
      if (isNaN(date)) return;
      el.title = date.toISOString();
      el.textContent = el.hasAttribute('data-relative') ? relativeText(date) : date.toLocaleString(locale);
    });
  }

  function updateCountdowns() {
    document.querySelectorAll('[data-countdown]').forEach(function (el) {
      var left = Math.round((new Date(el.getAttribute('data-countdown')).getTime() - Date.now()) / 1000);
      if (isNaN(left)) return;
      if (left <= 0) {
        el.textContent = text('token_expired');
        el.className = 'text-warning';
      } else {
        el.textContent = text('token_left', { time: Math.floor(left / 60) + ':' + String(left % 60).padStart(2, '0') });
        el.className = 'text-secondary';
      }
    });
  }
  setInterval(updateCountdowns, 1000);

  // ---- Constants into the last number field used ----
  var lastNumberField = null;
  document.addEventListener('focusin', function (evt) {
    if (evt.target.matches && evt.target.matches('input[data-number]')) lastNumberField = evt.target;
  });
  document.addEventListener('click', function (evt) {
    var btn = evt.target.closest('[data-insert]');
    if (!btn) return;
    var field = lastNumberField && document.body.contains(lastNumberField)
      ? lastNumberField
      : document.querySelector('.tab-pane.active input[data-number]');
    if (!field) return;
    field.value = btn.getAttribute('data-insert');
    field.focus();
  });

  // ---- Keypad: the keys write into the display, at the caret ----
  var lastAnswer = null;
  var finePointer = window.matchMedia ? window.matchMedia('(pointer: fine)').matches : true;

  function insertAtCaret(field, s) {
    var start = field.selectionStart === null ? field.value.length : field.selectionStart;
    var end = field.selectionEnd === null ? start : field.selectionEnd;
    field.value = field.value.slice(0, start) + s + field.value.slice(end);
    field.setSelectionRange(start + s.length, start + s.length);
  }

  function deleteBeforeCaret(field) {
    var start = field.selectionStart === null ? field.value.length : field.selectionStart;
    var end = field.selectionEnd === null ? start : field.selectionEnd;
    if (start === end) {
      if (start === 0) return;
      // An operator key wrote " x ": delete it whole
      start = / . $/.test(field.value.slice(Math.max(0, start - 3), start)) ? start - 3 : start - 1;
    }
    field.value = field.value.slice(0, start) + field.value.slice(end);
    field.setSelectionRange(start, start);
  }

  document.addEventListener('click', function (evt) {
    var key = evt.target.closest('[data-key], [data-key-action]');
    var field = document.getElementById('keypad-display');
    if (!key || !field || key.disabled) return;
    var action = key.getAttribute('data-key-action');
    if (action === 'clear') field.value = '';
    else if (action === 'backspace') deleteBeforeCaret(field);
    else if (action === 'answer') {
      if (lastAnswer === null) return;
      insertAtCaret(field, lastAnswer.charAt(0) === '-' ? '(' + lastAnswer + ')' : lastAnswer);
    }
    else insertAtCaret(field, key.getAttribute('data-key'));
    // A touch screen would open its keyboard on the display
    if (finePointer) field.focus();
  });

  document.addEventListener('keydown', function (evt) {
    if (evt.key === 'Escape' && evt.target.id === 'keypad-display') evt.target.value = '';
  });

  // Ans: the value of the last result card of the keypad
  document.addEventListener('htmx:afterSwap', function (evt) {
    if (!document.getElementById('keypad-display') || evt.detail.target.id !== 'result') return;
    var value = evt.detail.target.querySelector('[data-copy]');
    if (value) lastAnswer = value.getAttribute('data-copy');
  });

  // ---- Charts (Chart.js), built from the data-* attributes of the result cards ----
  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function chartTheme() {
    return {
      accent: cssVar('--brand-accent') || '#fbbf24',
      text: cssVar('--bs-secondary-color') || '#888',
      grid: cssVar('--bs-border-color-translucent') || 'rgba(128,128,128,.2)',
      info: cssVar('--bs-info') || '#0dcaf0',
      success: cssVar('--bs-success') || '#198754'
    };
  }

  function baseOptions(theme) {
    return {
      responsive: true,
      maintainAspectRatio: false,
      animation: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? false : { duration: 400 },
      plugins: { legend: { labels: { color: theme.text } } },
      scales: {
        x: { ticks: { color: theme.text }, grid: { color: theme.grid } },
        y: { ticks: { color: theme.text }, grid: { color: theme.grid } }
      }
    };
  }

  function statisticsChart(canvas, theme) {
    var values = JSON.parse(canvas.getAttribute('data-values') || '[]');
    var mean = parseFloat(canvas.getAttribute('data-mean'));
    var median = parseFloat(canvas.getAttribute('data-median'));
    var labels = values.map(function (_, i) { return '#' + (i + 1); });
    return new Chart(canvas, {
      data: {
        labels: labels,
        datasets: [
          { type: 'bar', label: text('values'), data: values, backgroundColor: theme.accent, borderRadius: 4 },
          { type: 'line', label: text('mean'), data: values.map(function () { return mean; }), borderColor: theme.info, borderDash: [6, 4], pointRadius: 0 },
          { type: 'line', label: text('median'), data: values.map(function () { return median; }), borderColor: theme.success, borderDash: [2, 3], pointRadius: 0 }
        ]
      },
      options: baseOptions(theme)
    });
  }

  function quadraticChart(canvas, theme) {
    var a = parseFloat(canvas.getAttribute('data-a'));
    var b = parseFloat(canvas.getAttribute('data-b'));
    var c = parseFloat(canvas.getAttribute('data-c'));
    var roots = (canvas.getAttribute('data-roots') || '').split(' ').filter(Boolean).map(parseFloat);
    var vertex = -b / (2 * a);
    var spread = 4;
    roots.forEach(function (r) { spread = Math.max(spread, Math.abs(r - vertex) * 1.6); });
    var points = [];
    for (var i = 0; i <= 120; i++) {
      var x = vertex - spread + (2 * spread * i) / 120;
      points.push({ x: x, y: a * x * x + b * x + c });
    }
    var options = baseOptions(theme);
    options.scales.x.type = 'linear';
    options.plugins.tooltip = { callbacks: { label: function (ctx) { return '(' + ctx.parsed.x.toPrecision(4) + ', ' + ctx.parsed.y.toPrecision(4) + ')'; } } };
    return new Chart(canvas, {
      type: 'scatter',
      data: {
        datasets: [
          { label: 'y = ax\u00B2 + bx + c', data: points, showLine: true, pointRadius: 0, borderColor: theme.accent, borderWidth: 2 },
          { label: text('real_roots'), data: roots.map(function (r) { return { x: r, y: 0 }; }), pointRadius: 6, pointBackgroundColor: theme.info, borderColor: theme.info },
          { label: text('vertex'), data: [{ x: vertex, y: a * vertex * vertex + b * vertex + c }], pointRadius: 5, pointStyle: 'rectRot', pointBackgroundColor: theme.success, borderColor: theme.success }
        ]
      },
      options: options
    });
  }

  function buildCharts(root) {
    if (!window.Chart) return;
    var theme = chartTheme();
    root.querySelectorAll('canvas[data-chart]').forEach(function (canvas) {
      var existing = Chart.getChart(canvas);
      if (existing) existing.destroy();
      if (canvas.getAttribute('data-chart') === 'statistics') statisticsChart(canvas, theme);
      else if (canvas.getAttribute('data-chart') === 'quadratic') quadraticChart(canvas, theme);
    });
  }

  function refreshCharts(root) { buildCharts(root); }

  document.addEventListener('htmx:beforeCleanupElement', function (evt) {
    if (!window.Chart || !evt.target.querySelectorAll) return;
    evt.target.querySelectorAll('canvas[data-chart]').forEach(function (canvas) {
      var chart = Chart.getChart(canvas);
      if (chart) chart.destroy();
    });
  });

  // ---- New content: the first page and every swap ----
  function processContent(root) {
    formatTimes(root);
    buildCharts(root);
    updateThemeIcon();
    updateCountdowns();
  }

  document.addEventListener('htmx:load', function (evt) { processContent(evt.detail.elt); });
  processContent(document.body);
})();
