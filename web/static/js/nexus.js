/* Nexara Nexus UI glue. No framework, no inline handlers (strict CSP): everything is delegated from document. */
(function () {
  'use strict';

  var TOAST_MS = 2600;

  // --- CSRF: every htmx request carries the token from <meta name="csrf-token"> ---
  document.addEventListener('htmx:configRequest', function (e) {
    var meta = document.querySelector('meta[name="csrf-token"]');
    if (meta && meta.content) {
      e.detail.headers['X-CSRF-Token'] = meta.content;
    }
  });

  // --- connection state: the body class drives the pink "reconnecting" band and live square ---
  function setLost(lost) {
    document.body.classList.toggle('is-lost', lost);
  }
  document.addEventListener('htmx:sseError', function () { setLost(true); });
  document.addEventListener('htmx:sseOpen', function () { setLost(false); });
  document.addEventListener('htmx:sendError', function () { setLost(true); });
  document.addEventListener('htmx:afterRequest', function (e) {
    if (e.detail && e.detail.successful) { setLost(false); }
  });

  // --- host tabs: Q / E (and the key buttons) switch to the previous / next host ---
  function stepHost(delta) {
    var tabs = Array.prototype.slice.call(document.querySelectorAll('[data-host-tabs] a.tab'));
    if (tabs.length < 2) { return; }
    var cur = tabs.findIndex(function (t) { return t.classList.contains('on') || t.hasAttribute('aria-current'); });
    var next = tabs[(Math.max(cur, 0) + delta + tabs.length) % tabs.length];
    next.click();
  }

  function isTyping(el) {
    if (!el) { return false; }
    var tag = el.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable;
  }

  document.addEventListener('keydown', function (e) {
    if (e.defaultPrevented) { return; }
    if (e.key === 'Escape') {
      if (closeTopModal()) { e.preventDefault(); }
      return;
    }
    if (e.ctrlKey || e.metaKey || e.altKey || isTyping(e.target) || document.querySelector('[data-modal]')) { return; }
    var k = e.key.toLowerCase();
    if (k === 'q') { stepHost(-1); } else if (k === 'e') { stepHost(1); }
  });

  // --- toasts: hide 2.6 s after they appear (server-rendered or swapped in by htmx) ---
  function armToast(el) {
    if (el.__armed) { return; }
    el.__armed = true;
    setTimeout(function () {
      el.classList.add('is-leaving');
      setTimeout(function () { if (el.parentNode) { el.parentNode.removeChild(el); } }, 250);
    }, TOAST_MS);
  }
  function armToasts(root) {
    Array.prototype.forEach.call(root.querySelectorAll('.toast'), armToast);
  }

  // --- modals: Esc or the close button remove the dialog; focus moves into a new one ---
  var lastFocus = null;
  function closeTopModal() {
    var all = document.querySelectorAll('[data-modal]');
    if (!all.length) { return false; }
    var top = all[all.length - 1];
    top.parentNode.removeChild(top);
    if (lastFocus && document.contains(lastFocus)) { lastFocus.focus(); }
    lastFocus = null;
    return true;
  }
  function focusModal(modal) {
    var target = modal.querySelector('input, select, textarea, button:not([data-modal-close])') ||
      modal.querySelector('[data-modal-close]');
    if (target) { target.focus(); }
  }

  // --- small helpers driven by data attributes ---
  document.addEventListener('click', function (e) {
    var t = e.target;
    if (!(t instanceof Element)) { return; }

    var step = t.closest('[data-host-step]');
    if (step) { stepHost(parseInt(step.getAttribute('data-host-step'), 10) || 0); return; }

    if (t.closest('[data-modal-close]')) { closeTopModal(); return; }

    var toggle = t.closest('[data-toggle-password]');
    if (toggle) {
      var input = document.getElementById(toggle.getAttribute('data-toggle-password'));
      if (input) {
        var show = input.type === 'password';
        input.type = show ? 'text' : 'password';
        toggle.setAttribute('aria-pressed', show ? 'true' : 'false');
      }
      return;
    }

    var copy = t.closest('[data-copy]');
    if (copy && navigator.clipboard) {
      var src = document.querySelector(copy.getAttribute('data-copy'));
      if (src) {
        navigator.clipboard.writeText(src.textContent.trim()).then(function () {
          var old = copy.textContent;
          copy.textContent = copy.getAttribute('data-copied') || 'Copied';
          setTimeout(function () { copy.textContent = old; }, 1500);
        });
      }
    }
  });

  // --- observe toast and modal roots so fragments swapped in by htmx behave like server-rendered ones ---
  function init() {
    armToasts(document);
    var toasts = document.getElementById('toasts');
    if (toasts) {
      new MutationObserver(function () { armToasts(toasts); }).observe(toasts, { childList: true, subtree: true });
    }
    var modals = document.getElementById('modal-root');
    if (modals) {
      var first = modals.querySelector('[data-modal]');
      if (first) { focusModal(first); }
      new MutationObserver(function (records) {
        records.forEach(function (r) {
          Array.prototype.forEach.call(r.addedNodes, function (n) {
            if (n.nodeType === 1 && n.matches('[data-modal]')) {
              lastFocus = document.activeElement;
              focusModal(n);
            }
          });
        });
      }).observe(modals, { childList: true });
    }
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
