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

  // --- what is on screen: <main id="main" data-host data-view> is replaced by every navigation, so it always
  // names the host and the view of the current page ---
  function mainEl() { return document.getElementById('main'); }
  function curHost() { var m = mainEl(); return m ? m.getAttribute('data-host') || '' : ''; }
  function curView() { var m = mainEl(); return m ? m.getAttribute('data-view') || '' : ''; }
  function regions() { return document.body.getAttribute('data-regions') || ''; }
  // A shell session that is open keeps its main area; refreshing it would end the session.
  function shellLive() {
    var m = mainEl();
    var sh = m && m.querySelector('[data-shell]');
    return !!sh && sh.getAttribute('data-state') === 'ready';
  }
  function currentPath() { return window.location.pathname + window.location.search; }

  // The request for the main area in flight: a navigation (boosted link, HX-Location, goHome) or a refresh. htmx
  // syncs them on <body> (hx-sync on the links), so a second one would abort the first - and htmx reports every
  // abort as an error in the console. Links therefore wait for the one in flight (see "Navigation queue" below),
  // and everything that changes the page on its own (refreshes, goHome) waits for a navigation: a request that
  // started for the old page must not land after the new one.
  var mainXhr = null;
  var mainPath = '';
  var mainIsNav = false;
  var supersededXhr = null; // a navigation nobody wants any more: it finishes, its page is not swapped in
  function inFlight(x) { return !!x && x.readyState > 0 && x.readyState < 4; }
  function busy() { return inFlight(mainXhr); }
  function navInFlight() { return inFlight(mainXhr) && mainIsNav; }
  document.addEventListener('htmx:beforeRequest', function (e) {
    var d = e.detail;
    if (!d || !d.xhr || !d.target || d.target.id !== 'main') { return; }
    mainXhr = d.xhr;
    mainIsNav = !isRefresh(d);
    mainPath = (d.pathInfo && d.pathInfo.requestPath) || '';
  }, true);

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
  // Events are only change hints: after the stream dropped and came back, read the page again (once, in place).
  var dropped = false;
  document.addEventListener('htmx:sseError', function () { dropped = true; setLost(true); checkSession(); });
  document.addEventListener('htmx:sseOpen', function () {
    setLost(false);
    if (dropped) { dropped = false; scheduleRefresh(!shellLive()); }
  });

  // Leaving the page aborts the stream, which the browser reports as an error event that htmx logs to the console.
  // Close the streams first (the SSE extension does this on htmx:beforeCleanupElement).
  function closeStreams() {
    Array.prototype.forEach.call(document.querySelectorAll('[sse-connect]'), function (el) {
      htmx.trigger(el, 'htmx:beforeCleanupElement');
    });
  }
  window.addEventListener('beforeunload', closeStreams);
  window.addEventListener('pagehide', closeStreams);
  document.addEventListener('htmx:sendError', function () { setLost(true); });
  document.addEventListener('htmx:afterRequest', function (e) {
    if (e.detail && e.detail.successful) { setLost(false); }
  });

  // --- navigation without page loads -------------------------------------------------------------------------
  // Links marked with "nx-boost" (partials/components.html) and HX-Location answers load the target URL with htmx.
  // The server answers with the complete page; htmx takes #main from it and swaps the shell regions (tabs, pills,
  // nav, node card, status bar) out of band. Everything else in the shell, notably the top bar's animations and
  // the single event stream, stays untouched. A reload of any URL still renders the complete page.

  // A background refresh of the current page (same URL, no history entry). The requests carry X-Nx-Refresh so
  // the handlers below can tell them from navigation.
  var REFRESH_HEADER = 'X-Nx-Refresh';
  var REFRESH_MS = 150;
  var refreshTimer = null;
  var refreshMain = false;

  function refresh(withMain) {
    if (!window.htmx) { return; }
    var spec = {
      target: '#main',
      swap: withMain ? 'outerHTML' : 'none',
      selectOOB: regions(),
      headers: {}
    };
    spec.headers[REFRESH_HEADER] = '1';
    if (withMain) { spec.select = '#main'; }
    var p = htmx.ajax('GET', currentPath(), spec);
    if (p && p.catch) { p.catch(function () { /* the hub is away: the stream shows it */ }); }
  }

  // Events come in bursts (a host going online also moves its packages and jobs): one refresh serves them all.
  function scheduleRefresh(withMain) {
    refreshMain = refreshMain || withMain;
    if (refreshTimer) { return; }
    refreshTimer = setTimeout(runRefresh, REFRESH_MS);
  }

  function runRefresh() {
    // htmx queues a request that starts while a navigation is in flight and sends it afterwards, aimed at the
    // main area and the regions of the page that is gone by then. The navigation brings everything up to date
    // anyway, so wait for it.
    if (navInFlight()) { refreshTimer = setTimeout(runRefresh, REFRESH_MS); return; }
    var m = refreshMain;
    refreshTimer = null;
    refreshMain = false;
    refresh(m && !shellLive());
  }

  // Leave a page whose host is gone (removed from another browser or by this one): continue at the overview.
  function goHome(host) {
    setTimeout(function again() {
      // The remover's own browser already moved on with HX-Location; do not navigate twice.
      if (curHost() !== host || !window.htmx) { return; }
      if (navInFlight()) { setTimeout(again, REFRESH_MS); return; }
      htmx.ajax('GET', '/', { target: '#main', select: '#main', swap: 'outerHTML', selectOOB: regions(), replace: 'true' });
    }, 400);
  }

  // The host list changed (payload of the "nx-hosts" event, see httpserver/sse.go).
  function onHostsEvent(raw) {
    var ev;
    try { ev = JSON.parse(raw); } catch (err) { return; }
    if (!ev || typeof ev.host !== 'string') { return; }
    var mine = ev.host === curHost();
    switch (ev.kind) {
      case 'removed':
        if (mine) { goHome(ev.host); } else { scheduleRefresh(false); }
        return;
      case 'added':
        scheduleRefresh(curHost() === ''); // the empty state turns into the first host
        return;
      case 'online':
      case 'offline':
        // The packages view reloads itself on these events (pkg-changed); the others swap their main area.
        scheduleRefresh(mine && curView() !== 'packages');
        return;
      default:
        scheduleRefresh(false); // counts and flags of the tabs and the nav
    }
  }

  function isRefresh(detail) {
    var cfg = detail && detail.requestConfig;
    return !!(cfg && cfg.headers && cfg.headers[REFRESH_HEADER]);
  }

  // A response for #main that is not a page of the app (sign-in after the session ended, an error page, a
  // plain-text 404): leave the single-page flow and let the browser load the URL, which shows it properly.
  // A refresh whose page is no longer the current one (the operator navigated meanwhile) is dropped.
  document.addEventListener('htmx:beforeSwap', function (e) {
    var d = e.detail;
    var target = d && d.target;
    if (!target || target.id !== 'main' || !d.xhr) { return; }
    var path = (d.pathInfo && d.pathInfo.requestPath) || '';
    if (d.xhr === supersededXhr) {
      d.shouldSwap = false;
      d.isError = false;
      return;
    }
    if (isRefresh(d) && path !== currentPath()) {
      d.shouldSwap = false;
      return;
    }
    // A host tab whose host was removed a moment ago: stay where we are and let the refresh drop the tab, instead of
    // loading the plain "Not found" page over the whole app.
    if (!isRefresh(d) && d.xhr.status === 404 && /^\/hosts\//.test(path)) {
      d.shouldSwap = false;
      d.isError = false;
      showToast('Not found', 'This host is no longer linked');
      scheduleRefresh(false);
      return;
    }
    var type = d.xhr.getResponseHeader('Content-Type') || '';
    var isPage = d.xhr.status < 400 && type.indexOf('text/html') === 0 && /\sid=["']?main["'\s>]/.test(d.xhr.responseText);
    if (isPage || d.xhr.status === 204) { return; }
    d.shouldSwap = false;
    d.isError = false;
    if (!isRefresh(d) || d.xhr.status === 401 || /^\/login\b/.test(new URL(d.xhr.responseURL || path, window.location.href).pathname)) {
      window.location.assign(d.xhr.status >= 400 ? path : (d.xhr.responseURL || path));
    }
  });

  // The answer to a GET for another host than the one on screen is a late one: the operator moved on while it was
  // on its way (a dialog, a page of the package list, a fragment of the old view). Its target may still exist
  // (#modal-root, #toasts), so it would put the old host's content into the new host's view. Actions (POST) are
  // different: their answer is the operator's feedback and names its host.
  var HOST_PATH = /^\/hosts\/([^/?#]+)\//;
  function requestHost(path) {
    var m = HOST_PATH.exec(path || '');
    if (!m) { return ''; }
    try { return decodeURIComponent(m[1]); } catch (err) { return m[1]; }
  }
  document.addEventListener('htmx:beforeSwap', function (e) {
    var d = e.detail;
    var cfg = d && d.requestConfig;
    if (!d || !d.target || d.target.id === 'main' || !cfg || cfg.verb !== 'get') { return; }
    var host = requestHost(d.pathInfo && d.pathInfo.requestPath);
    if (host && host !== 'new' && curHost() && host !== curHost()) {
      d.shouldSwap = false;
      d.isError = false;
    }
  });

  // After a navigation (not after a refresh): drop dialogs of the old page, scroll to the top, put the focus on
  // the new view's heading and announce it. A refresh keeps everything as it is.
  var announceTimer = null;
  // The title is the same for every host of a view; name the host so that a switch is heard as one.
  function announcement() { return document.title + (curHost() ? ' · ' + curHost() : ''); }
  function announce(text) {
    var live = document.getElementById('nx-announce');
    if (!live) { return; }
    live.textContent = '';
    clearTimeout(announceTimer);
    announceTimer = setTimeout(function () { live.textContent = text; }, 60);
  }
  function dropDialogs() {
    Array.prototype.forEach.call(document.querySelectorAll('[data-modal]'), function (m) {
      if (m.parentNode) { m.parentNode.removeChild(m); }
    });
    closeSheets();
  }
  document.addEventListener('htmx:afterSwap', function (e) {
    var main = e.target;
    if (!(main instanceof Element) || main.id !== 'main' || isRefresh(e.detail)) { return; }
    dropDialogs();
    main.scrollTop = 0;
    window.scrollTo(0, 0);
    var heading = main.querySelector('.view-title, .view-heading-title') || main;
    if (!heading.hasAttribute('tabindex')) { heading.setAttribute('tabindex', '-1'); }
    heading.focus({ preventScroll: true });
    announce(announcement());
  });

  // Back and forward: htmx loads the page again (the history cache is off, the content is live) and swaps the
  // main area only. The regions and the attributes of <main> come out of the same response.
  document.addEventListener('htmx:historyRestore', function (e) {
    var html = e.detail && e.detail.serverResponse;
    if (typeof html !== 'string') { refresh(true); return; }
    var doc = new DOMParser().parseFromString(html, 'text/html');
    var fresh = doc.getElementById('main');
    var main = mainEl();
    if (fresh && main) {
      ['data-host', 'data-view'].forEach(function (a) { main.setAttribute(a, fresh.getAttribute(a) || ''); });
    }
    htmx.swap(main || 'body', html, { swapStyle: 'none' }, { selectOOB: regions() });
    // Same as after a navigation: nothing of the page we came from stays open.
    dropDialogs();
    if (main) { main.scrollTop = 0; }
    window.scrollTo(0, 0);
    announce(announcement());
  });
  // A navigation that is still on its way must not land on top of the page the operator just went back to.
  window.addEventListener('popstate', cancelWanted);

  // --- events of the stream ---------------------------------------------------------------------------------
  // The stream is not filtered by host: it stays open while the operator moves between hosts. Events about one
  // host carry its short name as the SSE id; they only reach the page while that host is on screen.
  function foreign(msg) {
    return !!(msg && msg.lastEventId && msg.lastEventId !== curHost());
  }

  // Elements with their own sse-swap (the overview cards) and the live sink below share this check.
  document.addEventListener('htmx:sseBeforeMessage', function (e) {
    if (foreign(e.detail)) { e.preventDefault(); }
  }, true);

  // The packages view reloads its list on "pkg-changed" (hx-trigger="sse:pkg-changed"); the extension triggers
  // that event on the element without asking, so it is stopped here before htmx's own listener sees it.
  document.addEventListener('sse:pkg-changed', function (e) {
    if (foreign(e.detail)) { e.stopImmediatePropagation(); }
  }, true);

  // --- error responses: views answer with real status codes (404, 409, 422, 429, ...) and an HTML fragment
  // (a toast for #toasts via HX-Retarget, a form with its error row). htmx does not swap 4xx/5xx by default;
  // swap the ones that carry HTML. Plain-text errors (CSRF, stubs) are not swapped, see below. ---
  document.addEventListener('htmx:beforeSwap', function (e) {
    var xhr = e.detail && e.detail.xhr;
    if (!xhr || xhr.status < 400) { return; }
    if (e.detail.target && e.detail.target.id === 'main') { return; } // handled above
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
    if (e.defaultPrevented || !(sink instanceof Element) || !sink.hasAttribute('data-oob-sink')) { return; }
    e.preventDefault();
    if (e.detail.type === 'nx-hosts') { onHostsEvent(e.detail.data); return; }
    var t = document.createElement('template');
    t.innerHTML = e.detail.data;
    var keep = '';
    Array.prototype.forEach.call(t.content.children, function (el) {
      if (oobTarget(el)) { keep += el.outerHTML; }
    });
    if (keep) { htmx.swap(sink, keep, { swapStyle: 'none' }); }
  });

  // --- Navigation queue and host tabs. Q / E (and the key buttons) do exactly what a click on the neighbouring tab
  // does: the tab links point at the same view of the other host (httpserver/layout.go). A click on a link while
  // another request for the main area is on its way (a held key, quick clicks, a slow Pi) does not start a second
  // request: it becomes "the page I want", the one in flight is dropped when it arrives (nobody sees a terminal open
  // for a host that was only passed on the way), and the wanted page is requested right after. Presses of Q / E
  // add up: the base of a press is the page asked for last, not the one still on screen. ---
  var STEP_GAP_MS = 120;
  var wantHref = '';  // the page the operator asked for last, until it has been requested
  var wantTimer = null;
  var wantAt = 0;
  var passing = false; // our own click on the wanted link must reach htmx

  function hostTabs() { return Array.prototype.slice.call(document.querySelectorAll('[data-host-tabs] a.tab')); }
  function isOn(tab) { return tab.classList.contains('on') || tab.hasAttribute('aria-current'); }
  function linkTo(href) {
    return Array.prototype.find.call(document.querySelectorAll('a[hx-boost]'), function (a) { return a.getAttribute('href') === href; });
  }

  function supersedeNav() { if (navInFlight()) { supersededXhr = mainXhr; } }

  function cancelWanted() {
    clearTimeout(wantTimer);
    wantTimer = null;
    wantHref = '';
    supersedeNav();
  }

  function wantPage(href) {
    wantHref = href;
    supersedeNav();
    if (wantTimer) { return; }
    wantTimer = setTimeout(runWant, Math.max(0, wantAt + STEP_GAP_MS - Date.now()));
  }

  function runWant() {
    wantTimer = null;
    if (!wantHref) { return; }
    if (busy()) { wantTimer = setTimeout(runWant, 30); return; }
    var href = wantHref;
    wantHref = '';
    var link = linkTo(href);
    if (!link || (link.closest('[data-host-tabs]') && isOn(link))) { return; } // already there
    wantAt = Date.now();
    passing = true;
    try { link.click(); } finally { passing = false; }
  }

  // While the operator is stepping through the hosts the next view must not take the keyboard: a terminal that
  // grabs the focus on open would swallow the following presses (and the held key would type "eeee" into the
  // shell of the host just reached). <body data-stepping> tells shell.js to leave the focus alone; when the
  // presses stop, "nx:stepend" lets it focus the terminal after all.
  var STEP_IDLE_MS = 700;
  var stepIdle = null;
  function touchStepping() {
    document.body.setAttribute('data-stepping', '');
    clearTimeout(stepIdle);
    stepIdle = setTimeout(function () {
      document.body.removeAttribute('data-stepping');
      document.dispatchEvent(new CustomEvent('nx:stepend'));
    }, STEP_IDLE_MS);
  }

  function stepHost(delta) {
    var tabs = hostTabs();
    if (tabs.length < 2) { return; }
    touchStepping();
    var base = wantHref || (navInFlight() && mainXhr !== supersededXhr ? mainPath : '');
    var cur = base ? tabs.findIndex(function (t) { return t.getAttribute('href') === base; }) : -1;
    if (cur < 0) { cur = tabs.findIndex(isOn); }
    wantPage(tabs[(Math.max(cur, 0) + delta + tabs.length) % tabs.length].getAttribute('href'));
  }

  document.addEventListener('click', function (e) {
    if (passing || e.defaultPrevented || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) { return; }
    var link = e.target instanceof Element ? e.target.closest('a[hx-boost]') : null;
    if (!link) { return; }
    // The tab of the host on screen is not a link to anywhere: following it would reload the view the operator is
    // in (a terminal session would start over, the package list back at the top). It still cancels a switch that
    // is on its way, so a click on it means "stay here".
    var onTab = !!link.closest('[data-host-tabs]') && isOn(link);
    if (!onTab && !busy() && !wantTimer && !wantHref) { return; } // nothing in the way: htmx follows the link
    e.preventDefault();
    e.stopPropagation();
    if (onTab) { cancelWanted(); } else { wantPage(link.getAttribute('href')); }
  }, true);

  // The tab row is replaced by every switch and every refresh. A replacement starts scrolled to the left, which on a
  // phone can hide the tab of the host on screen: keep the position and bring that tab into view.
  var tabsScroll = 0;
  function fitTabs(row) {
    if (!row) { return; }
    row.scrollLeft = tabsScroll;
    var on = row.querySelector('.tab.on');
    if (!on) { return; }
    var a = on.getBoundingClientRect();
    var r = row.getBoundingClientRect();
    if (a.left < r.left) { row.scrollLeft -= r.left - a.left + 8; } else if (a.right > r.right) { row.scrollLeft += a.right - r.right + 8; }
    tabsScroll = row.scrollLeft;
  }
  document.addEventListener('scroll', function (e) {
    if (e.target instanceof Element && e.target.id === 'nx-tabs') { tabsScroll = e.target.scrollLeft; }
  }, true);

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

  // --- tickers: a CSS animation starts over when its element is replaced (a packages refresh, a navigation).
  // Every ticker gets the phase of the shared document timeline, so a replacement carries on where the old one
  // was instead of jumping back to the start. (Style properties set through the CSSOM are fine under the CSP.) ---
  function syncTickers(root) {
    if (!(root instanceof Element) || !document.timeline) { return; }
    var runs = root.matches('.ticker-run') ? [root] : root.querySelectorAll('.ticker-run');
    Array.prototype.forEach.call(runs, function (run) {
      var ms = parseFloat(window.getComputedStyle(run).animationDuration) * 1000;
      if (ms > 0) { run.style.animationDelay = '-' + (document.timeline.currentTime % ms) + 'ms'; }
    });
  }
  if (window.htmx && htmx.onLoad) { htmx.onLoad(syncTickers); }

  // --- observe the page so fragments swapped in by htmx behave like server-rendered ones ---
  function init() {
    armToasts(document);
    var bar = document.querySelector('.topbar');
    if (bar) {
      fitTabs(document.getElementById('nx-tabs'));
      new MutationObserver(function (records) {
        records.forEach(function (r) {
          Array.prototype.forEach.call(r.addedNodes, function (n) {
            if (n.nodeType === 1 && n.id === 'nx-tabs') { fitTabs(n); }
          });
        });
      }).observe(bar, { childList: true });
    }
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
