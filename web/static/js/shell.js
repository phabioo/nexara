/* Nexara Shell: xterm.js on the hub's shell WebSocket (/hosts/{host}/shell/ws).
   Protocol (internal/hub/httpserver/shellws.go): binary frames carry terminal bytes in both
   directions, the browser sends {"type":"resize","cols":N,"rows":M} as a text frame.
   No inline scripts or styles (strict CSP).

   The page is part of an app that navigates without page loads (nexus.js), so the terminal has a life cycle:
   it is set up when the shell view appears (htmx:load) and torn down when the view is replaced or the page is
   left (htmx:beforeCleanupElement, pagehide): WebSocket closed, terminal disposed, observers and listeners
   removed. There is at most one session at a time. The xterm files are loaded on first use, so the other views
   do not carry them. */
(function () {
  'use strict';

  // The app layout loads this file on every page.
  if (window.__nxShell) { return; }
  window.__nxShell = true;

  var session = null; // the mounted terminal, if any
  var adopted = [];   // stylesheets xterm created for the DOM renderer (see withAdoptedStyles)

  function logLine(text) {
    var el = document.getElementById('statusbar-log');
    if (el) { el.textContent = text; }
  }

  // --- loading xterm on first use ------------------------------------------------------------
  function loadScript(src) {
    return new Promise(function (resolve, reject) {
      var el = document.createElement('script');
      el.src = src;
      el.onload = resolve;
      el.onerror = function () { reject(new Error('could not load ' + src)); };
      document.head.appendChild(el);
    });
  }

  function hasLink(href) {
    var path = new URL(href, location.href).pathname;
    return Array.prototype.some.call(document.querySelectorAll('link[rel="stylesheet"]'), function (l) {
      return new URL(l.href, location.href).pathname === path;
    });
  }

  function ctors() {
    return {
      Terminal: window.Terminal && (window.Terminal.Terminal || window.Terminal),
      Fit: window.FitAddon && (window.FitAddon.FitAddon || window.FitAddon)
    };
  }

  var libs = null; // Promise, shared by every mount
  function loadLibs(root) {
    var c = ctors();
    if (typeof c.Terminal === 'function' && typeof c.Fit === 'function') { return Promise.resolve(c); }
    if (!libs) {
      var css = root.getAttribute('data-xterm-css');
      var js = root.getAttribute('data-xterm-js');
      var fit = root.getAttribute('data-xterm-fit');
      if (!js || !fit) { return Promise.reject(new Error('no xterm files')); }
      if (css && !hasLink(css)) {
        var link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = css;
        document.head.appendChild(link);
      }
      libs = loadScript(js).then(function () { return loadScript(fit); }).then(ctors, function (err) {
        libs = null;
        throw err;
      });
    }
    return libs;
  }

  // xterm's DOM renderer injects <style> elements, which the CSP (style-src 'self') blocks. While the
  // terminal opens, createElement('style') hands out a hidden stand-in that xterm fills as usual; its
  // text is applied through constructable stylesheets, which the CSP allows. The sheets are collected in
  // `adopted` and removed again when the session ends.
  function withAdoptedStyles(fn) {
    var canAdopt = 'adoptedStyleSheets' in document && typeof CSSStyleSheet === 'function';
    if (!canAdopt) { fn(); return; }
    var original = document.createElement;
    function adopt(el) {
      var sheet = new CSSStyleSheet();
      document.adoptedStyleSheets = document.adoptedStyleSheets.concat([sheet]);
      function sync() {
        try { sheet.replaceSync(el.textContent || ''); } catch (err) { /* invalid CSS: keep the old rules */ }
      }
      var watch = new MutationObserver(sync);
      watch.observe(el, { childList: true, characterData: true, subtree: true });
      adopted.push({ sheet: sheet, watch: watch });
      sync();
    }
    document.createElement = function (name, options) {
      if (typeof name === 'string' && name.toLowerCase() === 'style') {
        var stand = original.call(document, 'span');
        stand.hidden = true;
        stand.setAttribute('data-xterm-style', '');
        adopt(stand);
        return stand;
      }
      return original.call(document, name, options);
    };
    try { fn(); } finally { document.createElement = original; }
  }

  function dropAdopted() {
    if (!adopted.length) { return; }
    var gone = adopted.map(function (a) { a.watch.disconnect(); return a.sheet; });
    adopted = [];
    if ('adoptedStyleSheets' in document) {
      document.adoptedStyleSheets = document.adoptedStyleSheets.filter(function (s) { return gone.indexOf(s) < 0; });
    }
  }

  // --- the view -------------------------------------------------------------------------------
  function mount(root) {
    if (root.getAttribute('data-state') !== 'ready') { return; } // offline and disabled have no terminal
    if (session && session.root === root) { return; }
    unmount();

    var hostName = root.getAttribute('data-host') || '';
    var hostLabel = root.getAttribute('data-label') || hostName;
    var host = root.querySelector('[data-shell-term]');
    var statusBar = root.querySelector('[data-shell-status]');
    var statusText = root.querySelector('[data-shell-status-text]');
    var cleanups = [];
    var me = { root: root, dead: false, dispose: null };
    session = me;

    function fail(text) {
      if (statusBar) { statusBar.hidden = false; }
      if (statusText) { statusText.textContent = text; }
    }
    if (!host) { return; }

    loadLibs(root).then(function (c) {
      if (me.dead) { return; }
      run(c.Terminal, c.Fit);
    }, function () {
      if (!me.dead) { fail('The terminal could not be loaded.'); }
    });

    me.dispose = function () {
      cleanups.splice(0).forEach(function (fn) { try { fn(); } catch (err) { /* already gone */ } });
    };

    function run(TerminalCtor, FitCtor) {
      var narrow = window.matchMedia('(max-width: 767.98px)').matches;
      var term = new TerminalCtor({
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: narrow ? 12 : 13,
        lineHeight: 1.45,
        cursorBlink: true,
        scrollback: 5000,
        allowProposedApi: false,
        theme: {
          background: '#0b0c0d',
          foreground: '#35e36a',
          cursor: '#c6f500',
          cursorAccent: '#0b0c0d',
          selectionBackground: 'rgba(198,245,0,.28)',
          black: '#0b0c0d', red: '#ff3f74', green: '#35e36a', yellow: '#c6f500',
          blue: '#2f9bff', magenta: '#b04dff', cyan: '#22e0c8', white: '#c9cacc',
          brightBlack: '#5b5e62', brightRed: '#ff6d95', brightGreen: '#7dff9e', brightYellow: '#dcff4d',
          brightBlue: '#6cb8ff', brightMagenta: '#cb85ff', brightCyan: '#6ff0de', brightWhite: '#f2f3ef'
        }
      });
      var fit = new FitCtor();
      term.loadAddon(fit);
      cleanups.push(function () { term.dispose(); dropAdopted(); });

      // --- connection -----------------------------------------------------------------------
      var ws = null;
      var ended = false;     // the last session is over (shows the status bar)
      var everOpened = false;
      var encoder = new TextEncoder();

      function setStatus(text) {
        if (!statusBar) { return; }
        statusBar.hidden = !text;
        if (text && statusText) { statusText.textContent = text; }
      }

      function wsURL() {
        var u = new URL(root.getAttribute('data-ws'), location.href);
        u.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        u.searchParams.set('cols', String(term.cols));
        u.searchParams.set('rows', String(term.rows));
        return u.href;
      }

      function sendBytes(text) {
        if (ws && ws.readyState === WebSocket.OPEN && text) { ws.send(encoder.encode(text)); }
      }

      function sendResize() {
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
        }
      }

      // closeInfo maps a WebSocket close to the message shown to the operator.
      function closeInfo(code, reason) {
        if (!everOpened) {
          return 'Could not open the shell. The session may have expired: reload the page and try again.';
        }
        switch (code) {
          case 1000: return reason === 'shell exited' ? 'Session ended. The shell exited.' : 'Session closed.';
          case 1001: return 'The hub is restarting. Reconnect in a moment.';
          case 1008:
            return reason === 'session ended' ? 'Your session has ended. Redirecting to sign in.' : 'The shell is switched off for this host.';
          case 1013: return 'The host is offline.';
          case 1011: return reason === 'shell connection lost' ? 'Connection to the host lost.' : 'The shell could not be started.';
          default: return 'Connection lost.';
        }
      }

      function connect() {
        if (me.dead || (ws && ws.readyState <= WebSocket.OPEN)) { return; }
        ended = false;
        everOpened = false;
        setStatus('');
        term.reset();
        var sock = new WebSocket(wsURL());
        sock.binaryType = 'arraybuffer';
        ws = sock;
        sock.onopen = function () {
          everOpened = true;
          logLine('Shell session opened on ' + hostLabel);
          sendResize();
          // Not while the operator steps through the hosts with Q / E (nexus.js): the next press must still
          // reach the page, not this terminal. "nx:stepend" below focuses it once the presses stop.
          if (!document.body.hasAttribute('data-stepping')) { term.focus(); }
        };
        sock.onmessage = function (e) {
          if (e.data instanceof ArrayBuffer) { term.write(new Uint8Array(e.data)); }
        };
        sock.onclose = function (e) {
          if (ws !== sock) { return; }
          ended = true;
          var info = closeInfo(e.code, e.reason);
          if (everOpened) { term.write('\r\n\x1b[2m[session ended]\x1b[0m\r\n'); }
          logLine('Shell session closed on ' + hostLabel);
          setStatus(info);
          // The hub ends open shells when the operator's session ends (sign-out elsewhere, expiry, reset).
          if (everOpened && e.code === 1008 && e.reason === 'session ended') {
            window.setTimeout(function () { window.location.assign('/login'); }, 1500);
          }
        };
      }

      // Leaving the view closes the socket first and detaches the handlers, so nothing writes into a
      // disposed terminal and the hub sees the session end at once.
      cleanups.unshift(function () {
        var sock = ws;
        ws = null;
        if (sock) {
          sock.onopen = sock.onmessage = sock.onclose = null;
          if (sock.readyState <= WebSocket.OPEN) { sock.close(1000, 'left the view'); }
        }
      });

      // --- input: soft modifiers of the key bar ----------------------------------------------------
      var mods = { ctrl: false, alt: false };

      function releaseMods() {
        mods.ctrl = mods.alt = false;
        Array.prototype.forEach.call(root.querySelectorAll('[data-mod]'), function (b) {
          b.setAttribute('aria-pressed', 'false');
        });
      }

      function ctrlChar(ch) {
        var c = ch.charCodeAt(0);
        if (c >= 97 && c <= 122) { return String.fromCharCode(c - 96); }
        if (c >= 65 && c <= 90) { return String.fromCharCode(c - 64); }
        switch (ch) {
          case '@': case ' ': return '\x00';
          case '[': return '\x1b';
          case '\\': return '\x1c';
          case ']': return '\x1d';
          case '^': return '\x1e';
          case '_': return '\x1f';
          case '?': return '\x7f';
          default: return ch;
        }
      }

      function withMods(data) {
        if (!mods.ctrl && !mods.alt) { return data; }
        var out = data;
        if (mods.ctrl && data.length === 1) { out = ctrlChar(data); }
        if (mods.alt) { out = '\x1b' + out; }
        releaseMods();
        return out;
      }

      me.focus = function () { term.focus(); };

      term.onData(function (data) {
        if (!ws || ws.readyState !== WebSocket.OPEN) {
          if (ended && data === '\r') { connect(); }
          return;
        }
        sendBytes(withMods(data));
      });
      term.onResize(sendResize);

      var ARROWS = { up: 'A', down: 'B', right: 'C', left: 'D' };

      function keySequence(name) {
        if (name === 'esc') { return '\x1b'; }
        if (name === 'tab') { return '\t'; }
        var letter = ARROWS[name];
        if (!letter) { return ''; }
        var m = 1 + (mods.alt ? 2 : 0) + (mods.ctrl ? 4 : 0);
        if (m > 1) { releaseMods(); return '\x1b[1;' + m + letter; }
        var app = term.modes && term.modes.applicationCursorKeysMode;
        return (app ? '\x1bO' : '\x1b[') + letter;
      }

      // The key bar, Clear and Reconnect sit inside the view, which goes away together with the session.
      var keys = root.querySelector('[data-shell-keys]');
      if (keys) {
        // Keep the focus (and the soft keyboard) in the terminal while tapping keys.
        keys.addEventListener('mousedown', function (e) { e.preventDefault(); });
        keys.addEventListener('click', function (e) {
          var btn = e.target instanceof Element ? e.target.closest('[data-key]') : null;
          if (!btn) { return; }
          var name = btn.getAttribute('data-key');
          if (btn.hasAttribute('data-mod')) {
            var on = btn.getAttribute('aria-pressed') !== 'true';
            btn.setAttribute('aria-pressed', on ? 'true' : 'false');
            mods[name] = on;
          } else if (ws && ws.readyState === WebSocket.OPEN) {
            var text = btn.getAttribute('data-text');
            sendBytes(text ? withMods(text) : keySequence(name));
          }
          term.focus();
        });
      }

      var clear = root.querySelector('[data-shell-clear]');
      if (clear) {
        clear.addEventListener('click', function () { term.clear(); term.focus(); });
      }
      var reconnect = root.querySelector('[data-shell-reconnect]');
      if (reconnect) {
        reconnect.addEventListener('click', function () { connect(); });
      }

      // --- layout: fit the terminal to its box ---------------------------------------------------
      var fitQueued = false;
      function queueFit() {
        if (fitQueued || me.dead) { return; }
        fitQueued = true;
        requestAnimationFrame(function () {
          fitQueued = false;
          if (me.dead) { return; }
          try { fit.fit(); } catch (err) { /* not measurable yet */ }
        });
      }
      if (typeof ResizeObserver === 'function') {
        var ro = new ResizeObserver(queueFit);
        ro.observe(host);
        cleanups.push(function () { ro.disconnect(); });
      }
      window.addEventListener('resize', queueFit);
      cleanups.push(function () { window.removeEventListener('resize', queueFit); });

      var started = false;
      function start() {
        if (started || me.dead) { return; }
        started = true;
        withAdoptedStyles(function () { term.open(host); });
        try { fit.fit(); } catch (err) { /* keep the default size */ }
        connect();
      }

      // The first measurement needs the terminal font; fall back after a short wait.
      var fonts = document.fonts && document.fonts.load ? document.fonts.load("13px 'JetBrains Mono'") : null;
      if (fonts && typeof fonts.then === 'function') {
        fonts.then(start, start);
        var fallback = setTimeout(start, 1500);
        cleanups.push(function () { clearTimeout(fallback); });
      } else {
        start();
      }
    }
  }

  function unmount() {
    var me = session;
    if (!me) { return; }
    session = null;
    me.dead = true;
    if (me.dispose) { me.dispose(); }
  }

  // The view appears: on the first load of the page, after navigation, after a refresh of the main area.
  function onLoad(elt) {
    if (!(elt instanceof Element)) { return; }
    var root = elt.matches('[data-shell]') ? elt : elt.querySelector('[data-shell]');
    if (root) { mount(root); }
  }
  if (window.htmx && htmx.onLoad) {
    htmx.onLoad(onLoad);
  } else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { onLoad(document.body); });
  } else {
    onLoad(document.body);
  }

  // The presses of Q / E stopped: the terminal that was left alone meanwhile takes the keyboard, unless the
  // operator put it somewhere else (a field, a button) in the meantime.
  document.addEventListener('nx:stepend', function () {
    var me = session;
    var active = document.activeElement;
    if (!me || !me.focus || !me.root.isConnected) { return; }
    // The page puts the focus on the view's heading (or <main>) after a navigation: that is "nowhere".
    if (active && active !== document.body && active.id !== 'main' && !active.classList.contains('view-title')) { return; }
    me.focus();
  });

  // The view is replaced (navigation, history, refresh) ...
  document.addEventListener('htmx:beforeCleanupElement', function (e) {
    if (session && e.target === session.root) { unmount(); }
  });
  // ... or the page is left. pagehide also fires when the page goes into the back/forward cache.
  window.addEventListener('pagehide', unmount);
  window.addEventListener('pageshow', function (e) {
    if (e.persisted) { onLoad(document.body); } // back from the back/forward cache: the session is new
  });
})();
