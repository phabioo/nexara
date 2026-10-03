/* Setup restore: after "Restored" the hub restarts. This page waits until the sign-in page answers again
   (the old process redirects every path to /setup, the restarted hub serves /login) and then goes there.
   No inline code (strict CSP); without script the "Go to sign-in" link does the same by hand. */
(function () {
  'use strict';

  var root = document.querySelector('[data-restore-auto]');
  if (!root || !window.fetch) { return; }
  var status = root.querySelector('[data-restore-status]');
  var started = Date.now();
  var GIVE_UP = 3 * 60 * 1000;

  function ready(res) {
    return res.ok && new URL(res.url).pathname === '/login';
  }

  function probe() {
    fetch('/login', { cache: 'no-store', credentials: 'same-origin' }).then(function (res) {
      if (ready(res)) {
        if (status) { status.textContent = 'Nexus is back. Opening the sign-in page…'; }
        window.location.assign('/login');
        return;
      }
      again();
    }).catch(again);
  }

  function again() {
    if (Date.now() - started > GIVE_UP) {
      if (status) { status.textContent = 'Nexus did not come back within 3 minutes. Check the service on the host, then open the sign-in page.'; }
      return;
    }
    window.setTimeout(probe, 1500);
  }

  // Give the hub a moment to go down first.
  window.setTimeout(probe, 2000);
})();
