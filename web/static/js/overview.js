/* Nexara Nexus overview: the processes toggle, reloads after host or connection changes, and error toasts
   for the restart action. Host switching with Q / E lives in nexus.js. No inline handlers (strict CSP). */
(function () {
  'use strict';

  var PROCS_KEY = 'nexus.overview.procs';
  var RELOAD_DELAY_MS = 400;

  function store(fn) {
    try { return fn(window.sessionStorage); } catch (e) { return null; }
  }

  // --- cores / processes toggle: the state sits on the card, which the SSE swaps never replace ---
  function cpuCard() { return document.querySelector('.ov-cpu'); }

  function setProcs(on) {
    var card = cpuCard();
    if (!card) { return; }
    card.classList.toggle('is-procs', on);
    var btn = card.querySelector('[data-ov-procs]');
    if (btn) { btn.setAttribute('aria-pressed', on ? 'true' : 'false'); }
  }

  document.addEventListener('click', function (e) {
    var t = e.target;
    if (!(t instanceof Element) || !t.closest('[data-ov-procs]')) { return; }
    var card = cpuCard();
    if (!card) { return; }
    var on = !card.classList.contains('is-procs');
    setProcs(on);
    store(function (s) { s.setItem(PROCS_KEY, on ? '1' : '0'); });
  });

  // The CPU body is replaced on every sample; keep the button state in step with the card.
  document.addEventListener('htmx:afterSwap', function (e) {
    var card = cpuCard();
    if (card && e.target instanceof Element && card.contains(e.target)) {
      setProcs(card.classList.contains('is-procs'));
    }
  });

  // --- reload when the server state may have changed behind our back ---
  var reloadTimer = null;
  function reloadSoon() {
    if (reloadTimer) { return; }
    reloadTimer = setTimeout(function () { window.location.reload(); }, RELOAD_DELAY_MS);
  }

  // A host went online or offline: tabs, pill, sidebar and the card set all change.
  document.addEventListener('htmx:sseMessage', function (e) {
    if (e.detail && e.detail.type === 'ov-state') { reloadSoon(); }
  });

  // Events are only change hints: after the stream dropped and came back, read the state again.
  var dropped = false;
  document.addEventListener('htmx:sseError', function () { dropped = true; });
  document.addEventListener('htmx:sseOpen', function () {
    if (dropped) { dropped = false; reloadSoon(); }
  });

  // --- toast for failed actions (nexus.js arms and removes it like a server-rendered one) ---
  function span(cls) {
    var el = document.createElement('span');
    el.className = cls;
    el.setAttribute('aria-hidden', 'true');
    return el;
  }

  function showToast(title, sub) {
    var host = document.getElementById('toasts');
    if (!host) { return; }
    var toast = document.createElement('div');
    toast.className = 'toast';
    toast.setAttribute('role', 'status');
    ['tl', 'tr', 'bl', 'br'].forEach(function (c) { toast.appendChild(span('corner corner-' + c)); });
    var main = document.createElement('div');
    main.className = 'toast-main';
    var name = document.createElement('span');
    name.className = 'toast-title t-serif';
    name.textContent = title;
    main.appendChild(span('crosshair-mark'));
    main.appendChild(name);
    main.appendChild(span('crosshair-mark'));
    toast.appendChild(main);
    if (sub) {
      var line = document.createElement('div');
      line.className = 'toast-sub t-display';
      line.textContent = sub;
      toast.appendChild(line);
    }
    host.appendChild(toast);
  }

  function failed(e) {
    var elt = e.detail && e.detail.elt;
    if (!(elt instanceof Element) || !elt.closest('[data-ov-restart]')) { return; }
    var xhr = e.detail.xhr;
    var text = xhr && xhr.responseText ? xhr.responseText.trim().slice(0, 120) : '';
    showToast('Failed', text || 'Request failed');
  }
  document.addEventListener('htmx:responseError', failed);
  document.addEventListener('htmx:sendError', failed);
  document.addEventListener('htmx:timeout', failed);

  function init() {
    if (store(function (s) { return s.getItem(PROCS_KEY); }) === '1') { setProcs(true); }
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
