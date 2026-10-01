// End-to-end test of Harpo's PWA offline vault, run against the live multisite
// demo stack with a real headless Chrome (service workers don't run in every
// embedded browser, so this is the honest way to test offline behaviour).
//
// What it does:
//   1. signs in to site alpha, creates its own throwaway group + password entry
//   2. sets up the offline vault (passphrase + sync)
//   3. STOPS the harpo-alpha container
//   4. verifies: page loads from the service worker, badge shows "server
//      unreachable", wrong passphrase is rejected, the vault decrypts offline,
//      the revealed password matches, and navigation falls back to the vault
//   5. restarts the container and deletes the throwaway group
// Along the way it also proves two things that were once broken: signing in
// as someone else in the same browser cannot replace the vault's contents, and
// a refresh still in flight when the vault is locked cannot undo the lock.
//
// Prerequisites: `docker compose -f docker-compose.multisite.yml up -d` and the
// docker CLI on PATH. Run with: npm test (see README.md in this directory).
const puppeteer = require("puppeteer");
const { execSync } = require("child_process");

const BASE = process.env.HARPO_BASE_URL || "http://localhost:8081";
const CONTAINER = process.env.HARPO_CONTAINER || "harpo-alpha";
const USER = process.env.HARPO_USER || "alice";
const USER_PASSWORD = process.env.HARPO_PASSWORD || "alice";
// A second account, to prove one user's offline vault can't be taken over by another.
const OTHER_USER = process.env.HARPO_OTHER_USER || "bob";
const OTHER_PASSWORD = process.env.HARPO_OTHER_PASSWORD || "bob";

const RUN_ID = Date.now();
const GROUP_NAME = `E2E Offline ${RUN_ID}`;
const ENTRY_NAME = `E2E Entry ${RUN_ID}`;
const ENTRY_PASSWORD = `E2e-Secret-${RUN_ID}!x`;
const PASSPHRASE = "correct-horse-battery";
const TOTP_SECRET = "JBSWY3DPEHPK3PXP"; // so the offline copy has a 2FA code to generate

const results = [];
function check(name, ok, detail = "") {
    results.push({ name, ok });
    console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  [" + detail + "]" : ""}`);
}

async function clickByText(page, selector, text) {
    const clicked = await page.evaluate((sel, needle) => {
        const el = [...document.querySelectorAll(sel)].find((e) => e.textContent.includes(needle));
        if (el) {
            el.click();
            return true;
        }
        return false;
    }, selector, text);
    if (!clicked) {
        throw new Error(`No "${selector}" containing "${text}"`);
    }
}

// Blazor pages in headless Chrome respond to JS-dispatched clicks more reliably
// than CDP mouse events (Blazor does not require isTrusted), so use el.click().
async function jsClick(page, selector) {
    await page.evaluate((sel) => {
        const el = document.querySelector(sel);
        if (!el) {
            throw new Error("missing " + sel);
        }
        el.click();
    }, selector);
}

// Fully synthetic typing: on circuit-attached Blazor pages, CDP's trusted input
// events fail to even focus elements in headless Chrome, so set the value
// directly and dispatch input+change (covers both @bind flavours).
async function typeInto(page, selector, text) {
    await page.waitForSelector(selector, { timeout: 10000 });
    await page.evaluate((sel, value) => {
        const el = document.querySelector(sel);
        if (!el) {
            throw new Error("missing " + sel);
        }
        el.focus();
        el.value = value;
        el.dispatchEvent(new Event("input", { bubbles: true }));
        el.dispatchEvent(new Event("change", { bubbles: true }));
    }, selector, text);
}

async function waitForText(page, selector, text, timeout = 15000) {
    await page.waitForFunction(
        (sel, needle) => [...document.querySelectorAll(sel)].some((e) => e.textContent.includes(needle)),
        { timeout }, selector, text);
}

// Signs in on a page of its own. Fully synthetic, because by the time a second
// sign-in is needed a Blazor circuit has attached and trusted input is dead.
async function signIn(page, user, password) {
    await page.goto(`${BASE}/login`, { waitUntil: "networkidle2" });
    await typeInto(page, 'input[name="Model.Username"]', user);
    await typeInto(page, 'input[name="Model.Password"]', password);
    await Promise.all([
        page.waitForNavigation({ waitUntil: "networkidle2" }),
        jsClick(page, 'button[type="submit"]'),
    ]);
    if (page.url() !== `${BASE}/`) {
        throw new Error(`sign-in as ${user} failed: ${page.url()}`);
    }
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

// Outcome-first retry: succeed fast if `probe` already holds, otherwise run the
// (idempotent) `action` and re-check. Prevents duplicate creates on retries.
async function ensure(probe, action, tries = 6) {
    for (let i = 0; i < tries; i++) {
        try {
            await probe();
            return;
        } catch { }
        try { await action(); } catch { }
    }
    await probe();
}

// Blazor interactive pages ignore clicks until the SignalR circuit attaches, so
// keep clicking until the expected effect shows up.
async function retryUntil(action, probe, tries = 15) {
    let lastErr;
    for (let i = 0; i < tries; i++) {
        try { await action(); } catch (e) { lastErr = e; }
        try {
            await probe();
            return;
        } catch (e) { lastErr = e; }
    }
    throw lastErr ?? new Error("retryUntil exhausted");
}

(async () => {
    const browser = await puppeteer.launch({ headless: "new", args: ["--no-first-run"] });
    const page = await browser.newPage();
    // Destructive actions use native confirm() dialogs. Headless Chrome
    // auto-cancels dialogs opened without user activation (our clicks are
    // synthetic), so stub confirm to accept instead of relying on CDP dialogs.
    await page.evaluateOnNewDocument(() => { window.confirm = () => true; });
    await page.setViewport({ width: 1100, height: 750 });

    try {
        // ---- 1. Sign in ----
        await page.goto(`${BASE}/login`, { waitUntil: "networkidle2" });
        await page.type('input[name="Model.Username"]', USER);
        await page.type('input[name="Model.Password"]', USER_PASSWORD);
        await Promise.all([
            page.waitForNavigation({ waitUntil: "networkidle2" }),
            page.click('button[type="submit"]'),
        ]);
        check("sign in", page.url() === `${BASE}/`, page.url());

        // ---- 2. Create a throwaway group ----
        await page.goto(`${BASE}/groups`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".page-header .btn-primary");
        await ensure(
            () => waitForText(page, ".group-card", GROUP_NAME, 4000),
            async () => {
                await jsClick(page, ".page-header .btn-primary");
                await page.waitForSelector(".modal-panel .form-grid label:nth-of-type(1) input", { visible: true, timeout: 4000 });
                await typeInto(page, ".modal-panel .form-grid label:nth-of-type(1) input", GROUP_NAME);
                await jsClick(page, ".modal-actions .btn-primary");
            });
        check("create test group", true);

        // ---- 3. Create a password entry in it ----
        await page.goto(`${BASE}/`, { waitUntil: "networkidle2" });
        await waitForText(page, ".group-item", GROUP_NAME);
        await ensure(
            () => page.waitForFunction(
                (name) => document.querySelector(".vault-toolbar h1")?.textContent === name,
                { timeout: 4000 }, GROUP_NAME),
            () => clickByText(page, ".group-item", GROUP_NAME));
        await ensure(
            () => waitForText(page, ".entries-table", ENTRY_NAME, 4000),
            async () => {
                await jsClick(page, ".vault-toolbar .btn-primary");
                await page.waitForSelector(".modal-panel .password-row input", { visible: true, timeout: 4000 });
                await typeInto(page, ".modal-panel .form-grid > label:nth-of-type(1) input", ENTRY_NAME);
                await typeInto(page, ".modal-panel .password-row input", ENTRY_PASSWORD);
                await typeInto(page, '.modal-panel input[placeholder^="base32"]', TOTP_SECRET);
                await jsClick(page, ".modal-actions .btn-primary");
            });
        check("create test entry", true);

        // ---- 4. Offline vault: set up & sync (retry once if throttled) ----
        await page.goto(`${BASE}/offline.html`, { waitUntil: "networkidle2" });
        const swState = await page.evaluate(async () => {
            const reg = await navigator.serviceWorker.ready;
            const keys = await caches.keys();
            const cache = await caches.open(keys[0]);
            const cached = (await cache.keys()).map((r) => new URL(r.url).pathname);
            return { active: reg.active?.state, cached };
        });
        check("service worker active", swState.active === "activated", swState.active);
        check("offline shell precached",
            ["/offline.html", "/offline.js", "/manifest.webmanifest"].every((p) => swState.cached.includes(p)));

        await page.waitForSelector("#state-setup:not(.hidden)", { timeout: 10000 });
        await typeInto(page, "#setupPass", PASSPHRASE);
        await typeInto(page, "#setupPass2", PASSPHRASE);
        for (let attempt = 0; ; attempt++) {
            await jsClick(page, "#setupBtn");
            try {
                await page.waitForSelector("#state-vault:not(.hidden)", { timeout: 40000 });
                break;
            } catch (e) {
                // Another sync within the per-user cooldown window → wait it out once.
                const throttled = await page.$eval("#setupError", (el) => el.textContent).catch(() => "");
                if (attempt === 0 && throttled.includes("slow down")) {
                    await new Promise((r) => setTimeout(r, 31000));
                    continue;
                }
                throw e;
            }
        }
        const synced = await page.$eval("#entryList", (el) => el.textContent);
        check("sync contains test entry", synced.includes(ENTRY_NAME));

        await page.waitForFunction(
            () => !document.getElementById("backLink").classList.contains("hidden"),
            { timeout: 10000 });
        check("back-to-Harpo link shown while reachable", true);

        // ---- 4b. Someone else signs in to Harpo in this browser ----
        // The vault tab is still unlocked. A refresh now would be answered for the
        // OTHER account and re-encrypted under this vault's key — it must be refused.
        const other = await browser.newPage();
        const cookies = await other.createCDPSession();
        try {
            await cookies.send("Network.clearBrowserCookies");
            await signIn(other, OTHER_USER, OTHER_PASSWORD);
            // Back to the vault tab: a background tab gets no animation frames,
            // which is what waitForFunction polls on.
            await page.bringToFront();
            await jsClick(page, "#refreshBtn");
            await page.waitForFunction(
                () => !document.getElementById("vaultError").classList.contains("hidden"),
                { timeout: 15000 });
            const refusal = await page.$eval("#vaultError", (el) => el.textContent);
            const stillShown = await page.$eval("#entryList", (el) => el.textContent);
            check("refresh as another account is refused",
                refusal.includes(`belongs to "${USER}"`) && stillShown.includes(ENTRY_NAME)
                    && (await storedVaultOwner(page)) === USER,
                refusal.slice(0, 80));
        } finally {
            // Put the original session back for the rest of the run.
            await cookies.send("Network.clearBrowserCookies");
            await signIn(other, USER, USER_PASSWORD);
            await other.close();
            await page.bringToFront();
        }

        // ---- 5. Take the server down ----
        execSync(`docker stop ${CONTAINER}`, { stdio: "ignore" });
        let serverDown = false;
        try {
            await fetch(`${BASE}/healthz`, { signal: AbortSignal.timeout(2000) });
        } catch {
            serverDown = true;
        }
        check("server is stopped", serverDown);

        // ---- 6. Offline behaviour ----
        await page.goto(`${BASE}/offline.html`, { waitUntil: "load" });
        await page.waitForSelector("#state-unlock:not(.hidden)", { timeout: 10000 });
        check("offline page served by service worker", (await page.title()) === "Offline vault · Harpo");

        await page.waitForFunction(
            () => document.getElementById("netBadge").textContent === "server unreachable",
            { timeout: 10000 });
        check("badge shows server unreachable", true);
        check("back-to-Harpo link hidden while unreachable",
            await page.$eval("#backLink", (el) => el.classList.contains("hidden")));

        await typeInto(page, "#unlockPass", "totally-wrong-pass");
        await jsClick(page, "#unlockBtn");
        await page.waitForSelector("#unlockError:not(.hidden)", { timeout: 30000 });
        check("wrong passphrase rejected",
            (await page.$eval("#unlockError", (el) => el.textContent)).includes("Wrong passphrase"));

        await typeInto(page, "#unlockPass", PASSPHRASE);
        await jsClick(page, "#unlockBtn");
        await page.waitForSelector("#state-vault:not(.hidden)", { timeout: 30000 });
        check("vault decrypts offline",
            (await page.$eval("#entryList", (el) => el.textContent)).includes(ENTRY_NAME));

        await clickByText(page, ".entry", ENTRY_NAME); // arm auto-lock reset; then reveal:
        await page.evaluate((name) => {
            const entry = [...document.querySelectorAll(".entry")].find((e) => e.textContent.includes(name));
            entry.querySelector('button[title="Reveal"]').click();
        }, ENTRY_NAME);
        const revealed = await page.evaluate((name) => {
            const entry = [...document.querySelectorAll(".entry")].find((e) => e.textContent.includes(name));
            return entry.querySelector(".pw").textContent;
        }, ENTRY_NAME);
        check("revealed password matches", revealed === ENTRY_PASSWORD, revealed);

        // The 2FA control is a labelled chip (not a second "eye" beside the
        // password's), and the code is generated on the device, offline.
        const totp = await page.evaluate(async (name) => {
            const entry = [...document.querySelectorAll(".entry")].find((e) => e.textContent.includes(name));
            const chip = entry.querySelector(".btn-chip");
            const before = chip.textContent.trim();
            chip.click();
            await new Promise((r) => setTimeout(r, 1500));
            const code = [...entry.querySelectorAll(".pw.shown")].map((e) => e.textContent)
                .find((t) => /^\d{3} \d{3} · \d+s$/.test(t)) ?? null;
            return { before, after: chip.textContent.trim(), code };
        }, ENTRY_NAME);
        check("2FA code is generated offline behind a labelled control",
            totp.before === "2FA" && totp.after === "Hide 2FA" && totp.code !== null, JSON.stringify(totp));

        await page.goto(`${BASE}/`, { waitUntil: "load" });
        check("navigation fallback to offline vault", (await page.title()) === "Offline vault · Harpo");

        // ---- 7. Server returns: the offline page must offer a way back ----
        execSync(`docker start ${CONTAINER}`, { stdio: "ignore" });
        for (let i = 0; i < 60; i++) {
            try {
                const res = await fetch(`${BASE}/healthz`, { signal: AbortSignal.timeout(1000) });
                if (res.ok) {
                    break;
                }
            } catch { }
            await new Promise((r) => setTimeout(r, 1000));
        }
        await page.goto(`${BASE}/offline.html`, { waitUntil: "networkidle2" });
        await page.waitForFunction(
            () => !document.getElementById("backLink").classList.contains("hidden"),
            { timeout: 15000 });

        // ---- 7b. Lock the vault while a refresh is still in flight ----
        // (The restart reset the per-user snapshot throttle, so a refresh is allowed.)
        const unlockWith = async (passphrase) => {
            await page.waitForSelector("#state-unlock:not(.hidden)", { timeout: 10000 });
            await typeInto(page, "#unlockPass", passphrase);
            await jsClick(page, "#unlockBtn");
            await page.waitForFunction(() => !document.getElementById("unlockBtn").disabled, { timeout: 60000 });
            return page.evaluate(() => !document.getElementById("state-vault").classList.contains("hidden"));
        };
        check("unlocks online after the outage", await unlockWith(PASSPHRASE));
        let held = null;
        const hold = (req) => {
            if (held === null && req.url().includes("/api/offline/snapshot")) {
                held = req; // keep the response from arriving until after the lock
                return;
            }
            req.continue();
        };
        await page.setRequestInterception(true);
        page.on("request", hold);
        await jsClick(page, "#refreshBtn");
        for (let i = 0; i < 100 && held === null; i++) {
            await new Promise((r) => setTimeout(r, 100));
        }
        if (held === null) {
            throw new Error("the refresh request was never issued");
        }
        await jsClick(page, "#lockBtn");
        await held.continue();
        await new Promise((r) => setTimeout(r, 3000));
        const lockHeld = await page.evaluate(() =>
            !document.getElementById("state-unlock").classList.contains("hidden")
            && document.getElementById("state-vault").classList.contains("hidden")
            && document.getElementById("entryList").children.length === 0);
        check("in-flight refresh cannot undo a lock", lockHeld);
        page.off("request", hold);
        await page.setRequestInterception(false);

        // The same race used to re-encrypt the stored vault under the passphrase
        // "null"; after a reload the real passphrase must still be the only key.
        await page.reload({ waitUntil: "networkidle2" });
        const nullOpens = await unlockWith("null");
        const realOpens = !nullOpens && await unlockWith(PASSPHRASE);
        check("stored vault still opens only with the real passphrase", realOpens && !nullOpens,
            `real=${realOpens} null=${nullOpens}`);

        await Promise.all([
            page.waitForNavigation({ waitUntil: "networkidle2" }),
            jsClick(page, "#backLink"),
        ]);
        check("back link returns to the main app", page.url() === `${BASE}/`, page.url());
    } catch (e) {
        check("script completed", false, e.message.slice(0, 200));
    } finally {
        // ---- 8. Restore the server (if a failure skipped 7) and clean up ----
        try {
            execSync(`docker start ${CONTAINER}`, { stdio: "ignore" });
            for (let i = 0; i < 60; i++) {
                try {
                    const res = await fetch(`${BASE}/healthz`, { signal: AbortSignal.timeout(1000) });
                    if (res.ok) {
                        break;
                    }
                } catch { }
                await new Promise((r) => setTimeout(r, 1000));
            }
            // Whatever happened above, clean up as the user who owns the test data.
            await (await page.createCDPSession()).send("Network.clearBrowserCookies");
            await signIn(page, USER, USER_PASSWORD);
            await page.goto(`${BASE}/groups`, { waitUntil: "networkidle2" });
            await waitForText(page, ".group-card", GROUP_NAME);
            await clickByText(page, ".group-card", GROUP_NAME);
            await page.waitForSelector(".panel-danger .btn-danger", { timeout: 15000 });
            await retryUntil(
                () => jsClick(page, ".panel-danger .btn-danger"),
                () => page.waitForFunction(() => location.pathname === "/groups", { timeout: 1500 }));
            check("test group cleaned up", true);
        } catch (e) {
            check("test group cleaned up", false, e.message.slice(0, 120));
        }
        await browser.close();
    }

    const failed = results.filter((r) => !r.ok).length;
    console.log(`\n${results.length - failed}/${results.length} checks passed`);
    process.exit(failed === 0 ? 0 : 1);
})();
