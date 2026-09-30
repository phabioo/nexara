/* Packages view glue: error toasts for failed actions and the job terminal's follow-the-tail scrolling. */
(function () {
  'use strict';

  // The server answers a refused action (offline host, job already queued, ...) with a toast fragment and a
  // 4xx/5xx status, retargeted to #toasts. htmx does not swap error responses by default; allow it for these.
  document.addEventListener('htmx:beforeSwap', function (e) {
    var xhr = e.detail && e.detail.xhr;
    if (xhr && xhr.status >= 400 && xhr.getResponseHeader('X-Nexus-Toast') === '1') {
      e.detail.shouldSwap = true;
      e.detail.isError = false;
    }
  });

  // The event stream carries out-of-band updates for the job dialog and the status-bar chip. Most of the
  // time there is nothing to update (dialog closed, no chip); htmx would log an error for each missing
  // target. Keep only the elements that have one and swap those ourselves.
  function oobTarget(el) {
    var v = el.getAttribute('hx-swap-oob') || '';
    if (v === 'true' || v === 'outerHTML') { return el.id ? document.getElementById(el.id) : null; }
    var i = v.indexOf(':');
    if (i < 0) { return null; }
    try { return document.querySelector(v.slice(i + 1)); } catch (err) { return null; }
  }

  document.addEventListener('htmx:sseBeforeMessage', function (e) {
    var sink = e.target;
    if (!(sink instanceof Element) || !sink.classList.contains('pkg-sink')) { return; }
    e.preventDefault();
    var t = document.createElement('template');
    t.innerHTML = e.detail.data;
    var keep = '';
    Array.prototype.forEach.call(t.content.children, function (el) {
      if (oobTarget(el)) { keep += el.outerHTML; }
    });
    if (keep) { htmx.swap(sink, keep, { swapStyle: 'none' }); }
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

  function watch() {
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

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', watch);
  } else {
    watch();
  }
})();
