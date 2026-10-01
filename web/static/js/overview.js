/* Nexara Nexus overview: the processes toggle. Live values arrive through the event stream (sse-swap on the cards);
   a host going online or offline, a dropped stream and the like are handled in place by nexus.js, there is no page
   reload anywhere. Error toasts and host switching with Q / E live in nexus.js. No inline handlers (strict CSP). */
(function () {
  'use strict';

  // The app layout loads this file on every page; the page template of the overview may load it again.
  if (window.__nxOverview) { return; }
  window.__nxOverview = true;

  var PROCS_KEY = 'nexus.overview.procs';

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

  // The card is new on every visit of the view (navigation, refresh after a host went online): apply the
  // remembered state to it. htmx fires htmx:load for the swapped-in element and once for the whole page.
  function restore(root) {
    if (!(root instanceof Element)) { return; }
    var card = root.matches('.ov-cpu') ? root : root.querySelector('.ov-cpu');
    if (card && store(function (s) { return s.getItem(PROCS_KEY); }) === '1') { setProcs(true); }
  }
  if (window.htmx && htmx.onLoad) {
    htmx.onLoad(restore);
  } else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { restore(document.body); });
  } else {
    restore(document.body);
  }
})();
