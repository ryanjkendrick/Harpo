// End-to-end test of what the offline vault does when an administrator turns
// offline access off (Harpo__Offline__Enabled=false) while a device holds a copy.
//
// What it does:
//   1. signs in, opens the offline vault, syncs a copy and leaves it unlocked
//   2. runs HARPO_RESTART_CMD — a shell command YOU supply that restarts the
//      server with offline access disabled (this script cannot change the
//      container's environment itself)
//   3. clicks Refresh in the still-unlocked vault, so the server answers 404
//   4. verifies: the "Offline access is disabled" message, the entry list is
//      empty, the IndexedDB record is deleted, and an offline reload (network
//      cut, served by the service worker) offers no way to unlock the old copy
//
// The stack is left running with offline access DISABLED. Restore it yourself.
//
// Example (throwaway compose project, see README.md in this directory):
//   HARPO_RESTART_CMD='HARPO_OFFLINE=false docker compose -p harpo-e2e up -d --force-recreate harpo' \
//   HARPO_BASE_URL=http://localhost:8091 node offline-disable.e2e.js
// The command must leave the server healthy and answering at HARPO_BASE_URL
// with offline access turned off.
const puppeteer = require("puppeteer");
const { execSync } = require("child_process");

const BASE = process.env.HARPO_BASE_URL || "http://localhost:8081";
const USER = process.env.HARPO_USER || "alice";
const USER_PASSWORD = process.env.HARPO_PASSWORD || "alice";
const RESTART_CMD = process.env.HARPO_RESTART_CMD;
const PASSPHRASE = "correct-horse-battery";

const results = [];
function check(name, ok, detail = "") {
    results.push({ name, ok });
    console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  [" + detail + "]" : ""}`);
}

// Fully synthetic input: trusted CDP input stops reaching Blazor pages once a
// circuit has attached in headless Chrome (see README.md, "Things headless
// Chrome does differently").
async function typeInto(page, selector, text) {
    await page.waitForSelector(selector, { timeout: 10000 });
    await page.evaluate((sel, value) => {
        const el = document.querySelector(sel);
        el.focus();
        el.value = value;
        el.dispatchEvent(new Event("input", { bubbles: true }));
        el.dispatchEvent(new Event("change", { bubbles: true }));
    }, selector, text);
}

async function jsClick(page, selector) {
    await page.evaluate((sel) => {
        const el = document.querySelector(sel);
        if (!el) {
            throw new Error("missing " + sel);
        }
        el.click();
    }, selector);
}

// What the device actually has stored — independent of what the page shows.
function storedVaultOwner(page) {
    return page.evaluate(() => new Promise((resolve) => {
        const open = indexedDB.open("harpo-offline", 1);
        open.onsuccess = () => {
            const req = open.result.transaction("vault").objectStore("vault").get("current");
            req.onsuccess = () => resolve(req.result ? req.result.username : null);
        };
    }));
}

async function waitHealthy() {
    for (let i = 0; i < 90; i++) {
        try {
            const res = await fetch(`${BASE}/healthz`, { signal: AbortSignal.timeout(1000) });
            if (res.ok) {
                return;
            }
        } catch { }
        await new Promise((r) => setTimeout(r, 1000));
    }
    throw new Error("the server did not come back healthy");
}

(async () => {
    if (!RESTART_CMD) {
        console.error("Set HARPO_RESTART_CMD to a shell command that restarts the server with " +
            "Harpo__Offline__Enabled=false (see the header of this file).");
        process.exit(2);
    }
    const browser = await puppeteer.launch({ headless: "new", args: ["--no-first-run"] });
    const page = await browser.newPage();
    await page.evaluateOnNewDocument(() => { window.confirm = () => true; });
    await page.setViewport({ width: 1100, height: 750 });

    try {
        // ---- 1. Sign in, sync a copy, stay unlocked ----
        await page.goto(`${BASE}/login`, { waitUntil: "networkidle2" });
        await page.type('input[name="Model.Username"]', USER);
        await page.type('input[name="Model.Password"]', USER_PASSWORD);
        await Promise.all([
            page.waitForNavigation({ waitUntil: "networkidle2" }),
            page.click('button[type="submit"]'),
        ]);
        check("sign in", page.url() === `${BASE}/`, page.url());

        await page.goto(`${BASE}/offline.html`, { waitUntil: "networkidle2" });
        await page.evaluate(() => navigator.serviceWorker.ready);
        await page.waitForSelector("#state-setup:not(.hidden)", { timeout: 10000 });
        await typeInto(page, "#setupPass", PASSPHRASE);
        await typeInto(page, "#setupPass2", PASSPHRASE);
        await jsClick(page, "#setupBtn");
        await page.waitForSelector("#state-vault:not(.hidden)", { timeout: 40000 });
        check("copy synced and unlocked", (await storedVaultOwner(page)) === USER);

        // ---- 2. Admin disables offline access; the server restarts ----
        execSync(RESTART_CMD, { stdio: "inherit", shell: "/bin/sh" });
        await waitHealthy();
        // The snapshot endpoint needs the browser's session; the anonymous
        // feature probe says what the restarted server will tell it.
        const probe = await (await fetch(`${BASE}/api/offline/enabled`)).json();
        check("server now reports offline access disabled", probe.enabled === false, JSON.stringify(probe));

        // ---- 3. Refresh the still-unlocked vault ----
        await page.bringToFront();
        await jsClick(page, "#refreshBtn");
        await page.waitForSelector("#state-message:not(.hidden)", { timeout: 15000 });
        const title = await page.$eval("#messageTitle", (el) => el.textContent);
        check("refresh shows the disabled message", title === "Offline access is disabled", title);
        check("rendered entries are gone", await page.$eval("#entryList", (el) => el.children.length === 0));
        check("vault view is hidden",
            await page.$eval("#state-vault", (el) => el.classList.contains("hidden")));
        check("stored copy is deleted", (await storedVaultOwner(page)) === null);

        // ---- 4. Cut the network and reload: nothing may unlock ----
        await page.setOfflineMode(true);
        await page.reload({ waitUntil: "load" });
        // With no copy left, the page explains there is nothing on this device
        // (offline) or offers setup (online) — either way, never an unlock.
        try {
            await page.waitForSelector("#state-message:not(.hidden), #state-setup:not(.hidden), #state-unlock:not(.hidden)", { timeout: 10000 });
        } catch {
            const visible = await page.evaluate(() => [...document.querySelectorAll("section[id^=state-]")].filter((s) => !s.classList.contains("hidden")).map((s) => s.id));
            throw new Error("no final state after the offline reload; visible: " + JSON.stringify(visible) + " title: " + document.title);
        }
        check("offline reload is served by the service worker", (await page.title()) === "Offline vault · Harpo");
        const after = await page.evaluate(() => ({
            visible: [...document.querySelectorAll("section[id^=state-]")].filter((s) => !s.classList.contains("hidden")).map((s) => s.id),
            title: document.getElementById("messageTitle")?.textContent ?? "",
            online: navigator.onLine,
        }));
        check("offline reload offers no unlock",
            !after.visible.includes("state-unlock") && !after.visible.includes("state-vault")
            && (after.visible.includes("state-setup") || after.title === "No offline data on this device"),
            JSON.stringify(after));
        check("still no stored copy after the reload", (await storedVaultOwner(page)) === null);
        await page.setOfflineMode(false);
    } catch (e) {
        check("script completed", false, e.message.slice(0, 200));
    } finally {
        await browser.close();
    }

    const failed = results.filter((r) => !r.ok).length;
    console.log(`\n${results.length - failed}/${results.length} checks passed`);
    process.exit(failed === 0 ? 0 : 1);
})();
