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

  // An expired session answers the event stream with 401, which EventSource cannot tell apart from a hub that is
  // away: it would retry forever and the "reconnecting" band would never end. After a stream error ask a small
  // authenticated endpoint; a 401 or a redirect to the login page means the session is over.
  var pinging = false;
  function checkSession() {
    if (pinging || !window.fetch) { return; }
    pinging = true;
    fetch('/events/ping', { credentials: 'same-origin', cache: 'no-store', redirect: 'manual' })
      .then(function (res) {
        pinging = false;
        if (res.status === 401 || res.type === 'opaqueredirect') { window.location.assign('/login'); }
      })
      .catch(function () { pinging = false; }); // hub unreachable: keep reconnecting
  }
  document.addEventListener('htmx:sseError', function () { setLost(true); checkSession(); });

  // Leaving the page aborts the stream, which the browser reports as an error event that htmx logs to the console.
  // Close the streams first (the SSE extension does this on htmx:beforeCleanupElement).
  function closeStreams() {
    Array.prototype.forEach.call(document.querySelectorAll('[sse-connect]'), function (el) {
      htmx.trigger(el, 'htmx:beforeCleanupElement');
    });
  }
  window.addEventListener('beforeunload', closeStreams);
  window.addEventListener('pagehide', closeStreams);
  document.addEventListener('htmx:sseOpen', function () { setLost(false); });
  document.addEventListener('htmx:sendError', function () { setLost(true); });
  document.addEventListener('htmx:afterRequest', function (e) {
    if (e.detail && e.detail.successful) { setLost(false); }
  });

  // --- error responses: views answer with real status codes (404, 409, 422, 429, ...) and an HTML fragment
  // (a toast for #toasts via HX-Retarget, a form with its error row). htmx does not swap 4xx/5xx by default;
  // swap the ones that carry HTML. Plain-text errors (CSRF, stubs) are not swapped, see below. ---
  document.addEventListener('htmx:beforeSwap', function (e) {
    var xhr = e.detail && e.detail.xhr;
    if (!xhr || xhr.status < 400) { return; }
    var type = xhr.getResponseHeader('Content-Type') || '';
    if (type.indexOf('text/html') === 0 && xhr.responseText.trim() !== '') {
      e.detail.shouldSwap = true;
      e.detail.isError = false;
    }
  });

  // A failed action that returned no fragment still tells the operator. Polls and fragment loads (GET) stay quiet.
  function failedAction(e) {
    var cfg = e.detail && e.detail.requestConfig;
    if (!cfg || !cfg.verb || cfg.verb === 'get') { return; }
    var xhr = e.detail.xhr;
    var text = xhr && xhr.responseText ? xhr.responseText.trim().slice(0, 120) : '';
    showToast('Failed', text || 'Request failed');
  }
  document.addEventListener('htmx:responseError', failedAction);
  document.addEventListener('htmx:sendError', failedAction);
  document.addEventListener('htmx:timeout', failedAction);

  // --- out-of-band sinks: the event stream sends sets of hx-swap-oob elements (live pills, job chip, job dialog).
  // Elements whose target is not on this page are dropped, so htmx does not log an error for each of them. ---
  function oobTarget(el) {
    var v = el.getAttribute('hx-swap-oob') || '';
    var i = v.indexOf(':');
    if (i >= 0) {
      try { return document.querySelector(v.slice(i + 1)); } catch (err) { return null; }
    }
    return el.id ? document.getElementById(el.id) : null;
  }
  document.addEventListener('htmx:sseBeforeMessage', function (e) {
    var sink = e.target;
    if (!(sink instanceof Element) || !sink.hasAttribute('data-oob-sink')) { return; }
    e.preventDefault();
    var t = document.createElement('template');
    t.innerHTML = e.detail.data;
    var keep = '';
    Array.prototype.forEach.call(t.content.children, function (el) {
      if (oobTarget(el)) { keep += el.outerHTML; }
    });
    if (keep) { htmx.swap(sink, keep, { swapStyle: 'none' }); }
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
      if (closeTopModal() || closeSheets()) { e.preventDefault(); }
      return;
    }
    if (e.ctrlKey || e.metaKey || e.altKey || isTyping(e.target) || document.querySelector('[data-modal]')) { return; }
    var k = e.key.toLowerCase();
    if (k === 'q') { stepHost(-1); } else if (k === 'e') { stepHost(1); }
  });

  // --- toasts: hide 2.6 s after they appear (server-rendered, swapped in by htmx or built by showToast) ---
  function span(cls) {
    var el = document.createElement('span');
    el.className = cls;
    el.setAttribute('aria-hidden', 'true');
    return el;
  }

  // Same markup as the "toast" template.
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
  window.nexusToast = showToast;

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

  // --- "More" sheet of the phone layout ---
  var sheetOpener = null;
  function setSheet(sheet, open) {
    sheet.hidden = !open;
    Array.prototype.forEach.call(document.querySelectorAll('[data-sheet-open="' + sheet.id + '"]'), function (b) {
      b.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    if (open) {
      sheetOpener = document.activeElement;
      var target = sheet.querySelector('[data-sheet-close]:not(.sheet-backdrop)') || sheet;
      target.focus();
    } else if (sheetOpener && document.contains(sheetOpener)) {
      sheetOpener.focus();
      sheetOpener = null;
    }
  }
  function closeSheets() {
    var closed = false;
    Array.prototype.forEach.call(document.querySelectorAll('.sheet:not([hidden])'), function (s) {
      setSheet(s, false);
      closed = true;
    });
    return closed;
  }

  // --- small helpers driven by data attributes ---
  document.addEventListener('click', function (e) {
    var t = e.target;
    if (!(t instanceof Element)) { return; }

    var opener = t.closest('[data-sheet-open]');
    if (opener) {
      var sheet = document.getElementById(opener.getAttribute('data-sheet-open'));
      if (sheet) { setSheet(sheet, sheet.hidden); }
      return;
    }
    if (t.closest('[data-sheet-close]')) { closeSheets(); return; }

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

  // --- job terminal: stay at the bottom while output arrives, unless the user scrolled up ---
  var following = new WeakMap();

  document.addEventListener('scroll', function (e) {
    var t = e.target;
    if (t instanceof Element && t.classList.contains('job-terminal')) {
      following.set(t, t.scrollHeight - t.scrollTop - t.clientHeight < 24);
    }
  }, true);

  function toBottom(t) {
    if (following.get(t) !== false) { t.scrollTop = t.scrollHeight; }
  }

  function terminalOf(node) {
    var el = node.nodeType === 1 ? node : node.parentElement;
    return el ? el.closest('.job-terminal') : null;
  }

  function watchTerminals() {
    var root = document.getElementById('modal-root');
    if (!root) { return; }
    new MutationObserver(function (records) {
      records.forEach(function (r) {
        var t = terminalOf(r.target);
        if (t) { toBottom(t); }
        Array.prototype.forEach.call(r.addedNodes, function (n) {
          if (n.nodeType !== 1) { return; }
          var own = terminalOf(n);
          if (own) { toBottom(own); }
          Array.prototype.forEach.call(n.querySelectorAll('.job-terminal'), toBottom);
        });
      });
    }).observe(root, { childList: true, subtree: true });
  }

  // --- observe the page so fragments swapped in by htmx behave like server-rendered ones ---
  function init() {
    armToasts(document);
    watchTerminals();
    // The whole body, not #toasts: an out-of-band swap may replace the #toasts element itself.
    new MutationObserver(function (records) {
      records.forEach(function (r) {
        Array.prototype.forEach.call(r.addedNodes, function (n) {
          if (n.nodeType !== 1) { return; }
          if (n.classList.contains('toast')) { armToast(n); } else { armToasts(n); }
        });
      });
    }).observe(document.body, { childList: true, subtree: true });
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
