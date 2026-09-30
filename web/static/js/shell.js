/* Nexara Shell: xterm.js on the hub's shell WebSocket (/hosts/{host}/shell/ws).
   Protocol (internal/hub/httpserver/shellws.go): binary frames carry terminal bytes in both
   directions, the browser sends {"type":"resize","cols":N,"rows":M} as a text frame.
   No inline scripts or styles (strict CSP). */
(function () {
  'use strict';

  var root = document.querySelector('[data-shell]');
  if (!root) { return; }

  var state = root.getAttribute('data-state');
  var hostName = root.getAttribute('data-host') || '';
  var hostLabel = root.getAttribute('data-label') || hostName;

  function logLine(text) {
    var el = document.getElementById('statusbar-log');
    if (el) { el.textContent = text; }
  }

  // --- offline: no connection attempt; reload when the agent comes back -----------------------
  if (state === 'offline') {
    document.addEventListener('htmx:sseMessage', function (e) {
      var data = (e.detail && e.detail.data) || '';
      var host = /data-host="([^"]*)"/.exec(data);
      var online = /data-online="([^"]*)"/.exec(data);
      if (host && online && host[1] === hostName && online[1] === 'true') { location.reload(); }
    });
    return;
  }
  if (state !== 'ready') { return; }

  // --- xterm setup ------------------------------------------------------------------------
  var TerminalCtor = window.Terminal && (window.Terminal.Terminal || window.Terminal);
  var FitCtor = window.FitAddon && (window.FitAddon.FitAddon || window.FitAddon);
  var host = document.querySelector('[data-shell-term]');
  var statusBar = document.querySelector('[data-shell-status]');
  var statusText = document.querySelector('[data-shell-status-text]');
  if (typeof TerminalCtor !== 'function' || typeof FitCtor !== 'function' || !host) {
    if (statusBar) { statusBar.hidden = false; }
    if (statusText) { statusText.textContent = 'The terminal could not be loaded.'; }
    return;
  }

  // xterm's DOM renderer injects <style> elements, which the CSP (style-src 'self') blocks. While the
  // terminal opens, createElement('style') hands out a hidden stand-in that xterm fills as usual; its
  // text is applied through constructable stylesheets, which the CSP allows.
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
      new MutationObserver(sync).observe(el, { childList: true, characterData: true, subtree: true });
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

  // --- connection ---------------------------------------------------------------------------
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
      case 1008: return 'The shell is switched off for this host.';
      case 1013: return 'The host is offline.';
      case 1011: return reason === 'shell connection lost' ? 'Connection to the host lost.' : 'The shell could not be started.';
      default: return 'Connection lost.';
    }
  }

  function connect() {
    if (ws && ws.readyState <= WebSocket.OPEN) { return; }
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
      term.focus();
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
    };
  }

  // --- input: soft modifiers of the key bar ---------------------------------------------------
  var mods = { ctrl: false, alt: false };

  function releaseMods() {
    mods.ctrl = mods.alt = false;
    Array.prototype.forEach.call(document.querySelectorAll('[data-mod]'), function (b) {
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

  var keys = document.querySelector('[data-shell-keys]');
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

  var clear = document.querySelector('[data-shell-clear]');
  if (clear) {
    clear.addEventListener('click', function () { term.clear(); term.focus(); });
  }
  var reconnect = document.querySelector('[data-shell-reconnect]');
  if (reconnect) {
    reconnect.addEventListener('click', function () { connect(); });
  }

  // --- layout: fit the terminal to its box -----------------------------------------------------
  var fitQueued = false;
  function queueFit() {
    if (fitQueued) { return; }
    fitQueued = true;
    requestAnimationFrame(function () {
      fitQueued = false;
      try { fit.fit(); } catch (err) { /* not measurable yet */ }
    });
  }
  if (typeof ResizeObserver === 'function') {
    new ResizeObserver(queueFit).observe(host);
  }
  window.addEventListener('resize', queueFit);

  function start() {
    withAdoptedStyles(function () { term.open(host); });
    try { fit.fit(); } catch (err) { /* keep the default size */ }
    connect();
  }

  // The first measurement needs the terminal font; fall back after a short wait.
  var fonts = document.fonts && document.fonts.load ? document.fonts.load("13px 'JetBrains Mono'") : null;
  if (fonts && typeof fonts.then === 'function') {
    var started = false;
    var go = function () { if (!started) { started = true; start(); } };
    fonts.then(go, go);
    setTimeout(go, 1500);
  } else {
    start();
  }
})();
