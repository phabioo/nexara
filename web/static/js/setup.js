/* Setup wizard helpers: live passphrase strength and download feedback on the Trust step.
   No framework, no inline handlers (strict CSP); everything is delegated from document. */
(function () {
  'use strict';

  var LABELS = ['Too weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very strong'];

  // Port of auth.Strength (internal/hub/auth/password.go): the same 0-5 score the server documents
  // for this meter. Advisory only; the server enforces the length policy.
  function score(pw) {
    var chars = Array.from(pw);
    var n = chars.length;
    if (n === 0) { return 0; }
    var s = n >= 24 ? 4 : n >= 16 ? 3 : n >= 12 ? 2 : n >= 8 ? 1 : 0;
    var lower = false, upper = false, digit = false, other = false;
    var distinct = {};
    var distinctCount = 0;
    chars.forEach(function (c) {
      if (!distinct[c]) { distinct[c] = true; distinctCount++; }
      if (c >= 'a' && c <= 'z') { lower = true; }
      else if (c >= 'A' && c <= 'Z') { upper = true; }
      else if (c >= '0' && c <= '9') { digit = true; }
      else if (!/\p{Cc}/u.test(c)) { other = true; }
    });
    var classes = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (other ? 1 : 0);
    if (classes >= 3) { s++; }
    if (distinctCount < 5 && s > 1) { s = 1; }
    return Math.min(s, 5);
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
    if (!(t instanceof HTMLInputElement)) { return; }
    if (t.hasAttribute('data-strength-input')) { showStrength(t); }
    // Like the mockup: editing a field withdraws the messages of the previous submit.
    var form = t.form;
    if (form) {
      Array.prototype.forEach.call(form.querySelectorAll('.form-error'), function (el) { el.remove(); });
      Array.prototype.forEach.call(form.querySelectorAll('[aria-invalid]'), function (el) { el.removeAttribute('aria-invalid'); });
    }
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
