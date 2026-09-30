/* Setup wizard helpers: live passphrase strength and download feedback on the Trust step.
   No framework, no inline handlers (strict CSP); everything is delegated from document. */
(function () {
  'use strict';

  var LABELS = ['Too weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very strong'];

  // Same scoring as the design mockup; the server enforces the real policy.
  function score(pw) {
    var s = 0;
    if (pw.length >= 8) { s++; }
    if (pw.length >= 12) { s++; }
    if (pw.length >= 16) { s++; }
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) { s++; }
    if (/[0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw)) { s++; }
    return s;
  }

  function showStrength(input) {
    var form = input.form || document;
    var bar = form.querySelector('[data-strength]');
    var text = form.querySelector('[data-strength-text]');
    if (!bar || !text) { return; }
    var n = input.value ? score(input.value) : 0;
    Array.prototype.forEach.call(bar.children, function (seg, i) {
      seg.classList.toggle('on', i < n);
    });
    text.textContent = input.value ? LABELS[n] : '—';
  }

  document.addEventListener('input', function (e) {
    var t = e.target;
    if (t instanceof HTMLInputElement && t.hasAttribute('data-strength-input')) { showStrength(t); }
  });

  // The download itself is a normal link; mark it so the operator sees what was fetched.
  document.addEventListener('click', function (e) {
    var t = e.target;
    if (!(t instanceof Element)) { return; }
    var link = t.closest('[data-trust-download]');
    if (!link) { return; }
    link.classList.add('is-done');
    var state = link.querySelector('[data-state]');
    if (state) { state.textContent = 'Downloaded ✓'; }
    var next = document.querySelector('[data-trust-next] span');
    if (next) { next.textContent = 'Continue'; }
  });
})();
