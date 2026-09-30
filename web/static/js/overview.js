/* Nexara Nexus overview: the processes toggle and reloads after host or connection changes. Error toasts
   live in nexus.js. Host switching with Q / E lives in nexus.js. No inline handlers (strict CSP). */
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

  function init() {
    if (store(function (s) { return s.getItem(PROCS_KEY); }) === '1') { setProcs(true); }
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
