# Harpo end-to-end tests

Four scripts, all driving the live two-site demo with a real headless Chrome.
Each creates its own throwaway entries (and groups) and deletes them
afterwards.

- **`offline-vault.e2e.js`** — the PWA offline vault. Registers the service
  worker, syncs an encrypted snapshot, then *stops the Harpo container* and
  proves the vault still unlocks, decrypts, reveals the right password and
  generates 2FA codes offline. It also proves that another account signing in
  to the same browser cannot take the vault over, and that a refresh still in
  flight when the vault is locked cannot undo the lock.
- **`offline-disable.e2e.js`** — what a device does when the administrator
  turns offline access off. Not part of `test:all`: the script cannot change
  the container's environment, so you give it `HARPO_RESTART_CMD`, a shell
  command that restarts the server with `Harpo__Offline__Enabled=false`
  (for example a `docker compose ... up -d --force-recreate` with the offline
  switch set to false). It syncs a copy, leaves the vault unlocked, runs the
  command, clicks Refresh, and expects the disabled message, an empty entry
  list, a deleted IndexedDB record, and an offline reload (network cut) that
  offers no unlock. It leaves the stack with offline access disabled; restore
  it yourself. Run it on a throwaway stack, never the demo:
  `HARPO_RESTART_CMD='...' npm run test:disable` — expect 10/10 checks passed.
  (Headless Chrome keeps `navigator.onLine` true while its network is cut, so
  the page shows the setup screen rather than the "no offline data" message;
  the script accepts either, since neither offers an unlock.)
- **`session.e2e.js`** — signing out ends the session on the server. One tab
  opens the vault and reveals a password; a second tab of the same browser
  signs out; the first tab, whose live connection still holds the signed-in
  user, clicks Reveal and Copy again and must be told the session has ended
  without being shown the password, then must move to the sign-in page by
  itself within 30 seconds. The cookie, copied before the sign-out, is then
  replayed: it must get neither a page, nor an offline snapshot, nor a live
  connection. Needs only a single site with offline access on; it adds one
  entry to the first account's personal vault and deletes it. A disabled
  directory account is not covered here (Development-mode users cannot be
  disabled without a restart): the unit tests cover it with a controllable
  clock, and it was checked by hand against the Samba AD lab.
- **`ui.e2e.js`** — the interactive UI: dialog keyboard behaviour (focus moves
  in, Tab stays in, Escape closes, focus returns), validation shown at the
  field it concerns, the password and 2FA controls, notes through the editor,
  copying from history, the entry details dialog as a Viewer on a 390px touch
  screen (notes as selectable text with a copy button, a notes indicator on
  the row, "No notes" when empty), the entries layout at seven widths (nothing may
  overflow or sit under another element, at rest or with secrets revealed),
  links from the health report, the Administration page's navigation and
  audit-log filters, and personal vaults as two accounts see them: one each,
  closed to the other (the site administrator included), described in the
  audit log without entry names, and taken over from the Administration page
  — after which the second account gets a fresh one — plus a site admin who
  is given an explicit Viewer membership keeping the edit controls. It also holds the
  content security policy to its word:
  every page must be served with it, nothing the app does may be blocked by
  it, and an injected inline script or style must have no effect — so a
  change that quietly needs something the policy forbids fails here.

## Prerequisites

- The two-site demo running: `docker compose -f docker-compose.multisite.yml up -d`
  (from the repo root)
- Node 20+ and the `docker` CLI on PATH
- Note: the offline suite **stops and restarts `harpo-alpha`** mid-run.

## Run

```bash
npm install
npm test          # offline vault — expect 22/22 checks passed
npm run test:ui   # interactive UI — expect 45/45 checks passed
npm run test:session  # sign-out ends open tabs and copied cookies — expect 9/9 checks passed
npm run test:all  # all three
```

Environment overrides: `HARPO_BASE_URL`, `HARPO_CONTAINER`, `HARPO_USER`
(a site administrator), `HARPO_PASSWORD`, and `HARPO_OTHER_USER` /
`HARPO_OTHER_PASSWORD` (a second account that is not a site administrator,
used by both suites). The UI suite takes over the second account's personal
vault, so point it at a throwaway stack, not at one whose second account
keeps real passwords there.

Re-running the offline suite within 30 seconds hits the per-user snapshot
cooldown; the script waits it out automatically once.

## Things headless Chrome does differently

Worth knowing before changing these scripts — each cost an afternoon once.

- **Use synthetic events.** Interactions with Blazor pages use `el.click()` and
  value-set + `input`/`change` dispatch rather than trusted CDP input: headless
  Chrome's trusted events stop reaching pages once a Blazor Server circuit has
  attached in the session. Forms are submitted with `form.requestSubmit()`.
- **Stub `confirm()`.** Native `confirm()` dialogs opened without user
  activation (all our clicks are synthetic) are auto-cancelled before a CDP
  dialog handler can answer them — stub `window.confirm` via
  `evaluateOnNewDocument` instead of using `page.on("dialog")`.
- **Bring a tab to the front before waiting on it.** A background tab gets no
  animation frames, which is what `waitForFunction` polls on.
- **One browser context per site.** Both demo sites are on `localhost`, and
  cookies ignore the port: signing in to `:8082` replaces the `:8081` session
  in the same context.
