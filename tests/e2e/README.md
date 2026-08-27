# Harpo end-to-end tests

Tests the PWA **offline vault** with a real headless Chrome — it registers the
service worker, syncs an encrypted snapshot, then *stops the Harpo container*
and proves the vault still unlocks, decrypts, and reveals the right password
offline. Creates its own throwaway group/entry and deletes it afterwards.

## Prerequisites

- The two-site demo running: `docker compose -f docker-compose.multisite.yml up -d`
  (from the repo root)
- Node 20+ and the `docker` CLI on PATH
- Note: the test **stops and restarts `harpo-alpha`** mid-run.

## Run

```bash
npm install
npm test
```

Expect `17/17 checks passed`.

One more headless gotcha: native `confirm()` dialogs opened without user
activation (all our clicks are synthetic) are auto-cancelled by headless
Chrome before a CDP dialog handler can answer them — stub `window.confirm`
via `evaluateOnNewDocument` instead of using `page.on("dialog")`. Environment overrides: `HARPO_BASE_URL`,
`HARPO_CONTAINER`, `HARPO_USER`, `HARPO_PASSWORD`.

Implementation note: interactions with Blazor pages use synthetic DOM events
(`el.click()`, value-set + `input`/`change` dispatch) rather than trusted CDP
input — headless Chrome's trusted events stop reaching pages once a Blazor
Server circuit has attached in the session.

Re-running within 30 seconds hits the per-user snapshot cooldown; the script
waits it out automatically once.
