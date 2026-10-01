# Harpo end-to-end tests

Two suites, both driving the live two-site demo with a real headless Chrome.
Each creates its own throwaway group and entries and deletes the group
afterwards.

- **`offline-vault.e2e.js`** — the PWA offline vault. Registers the service
  worker, syncs an encrypted snapshot, then *stops the Harpo container* and
  proves the vault still unlocks, decrypts, reveals the right password and
  generates 2FA codes offline. It also proves that another account signing in
  to the same browser cannot take the vault over, and that a refresh still in
  flight when the vault is locked cannot undo the lock.
- **`ui.e2e.js`** — the interactive UI: dialog keyboard behaviour (focus moves
  in, Tab stays in, Escape closes, focus returns), validation shown at the
  field it concerns, the password and 2FA controls, copying from history, the
  entries layout at seven widths (nothing may overflow or sit under another
  element, at rest or with secrets revealed), links from the health report,
  and the Administration page's navigation and audit-log filters.

## Prerequisites

- The two-site demo running: `docker compose -f docker-compose.multisite.yml up -d`
  (from the repo root)
- Node 20+ and the `docker` CLI on PATH
- Note: the offline suite **stops and restarts `harpo-alpha`** mid-run.

## Run

```bash
npm install
npm test          # offline vault — expect 22/22 checks passed
npm run test:ui   # interactive UI — expect 25/25 checks passed
npm run test:all  # both
```

Environment overrides: `HARPO_BASE_URL`, `HARPO_CONTAINER`, `HARPO_USER`
(a site administrator), `HARPO_PASSWORD`, and `HARPO_OTHER_USER` /
`HARPO_OTHER_PASSWORD` (a second account, used by the offline suite).

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
