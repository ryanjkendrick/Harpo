// End-to-end check that signing out ends the session on the server, for pages
// that are already open and for cookies that are replayed — the two ways the
// review (F2) got at a password after sign-out:
//
//  1. Tab A opens the vault and reveals a password. Tab B (same browser, same
//     cookie) signs out. Tab A — whose live connection still holds the user it
//     signed in with — clicks Reveal again: it must be told the session has
//     ended, and must not be shown the password. Within 30 s it must move to
//     the sign-in page by itself.
//  2. The cookie, copied before the sign-out and replayed afterwards, gets
//     neither a page nor an offline snapshot.
//
// Disabled accounts and changed admin roles are covered by the unit tests
// (SessionTests) and, against a real directory, by hand — see README.md here.
//
// Runs against any single Harpo site with a site-admin account; it creates one
// entry in that account's personal vault and deletes it again.
// Run with: npm run test:session (see README.md in this directory).
const puppeteer = require("puppeteer");

const BASE = process.env.HARPO_BASE_URL || "http://localhost:8081";
const USER = process.env.HARPO_USER || "alice";
const USER_PASSWORD = process.env.HARPO_PASSWORD || "alice";

const RUN_ID = Date.now();
const ENTRY = `E2E Session ${RUN_ID}`;
const SECRET = `Sx9!session-${RUN_ID}`;
const ENDED = "Your session has ended";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
function check(name, ok, detail = "") {
    results.push({ name, ok });
    console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  [" + detail + "]" : ""}`);
}

// Synthetic interaction only: see "Things headless Chrome does differently".
const setValue = (page, selector, value) => page.evaluate((sel, val) => {
    const el = document.querySelector(sel);
    if (!el) {
        throw new Error("missing " + sel);
    }
    el.focus();
    el.value = val;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
}, selector, value);

const clickText = (page, selector, text) => page.evaluate((sel, needle) => {
    const el = [...document.querySelectorAll(sel)].find((e) => e.textContent.includes(needle));
    if (!el) {
        throw new Error(`no "${sel}" containing "${needle}"`);
    }
    el.click();
}, selector, text);

const rowAction = (page, entryName, label) => page.evaluate((name, l) => {
    const row = [...document.querySelectorAll(".entries-table tbody tr")].find((r) => r.textContent.includes(name));
    const button = row?.querySelector(`button[aria-label="${l}"], button[title="${l}"]`);
    if (!button) {
        return false;
    }
    button.click();
    return true;
}, entryName, label);

async function signIn(page) {
    await page.goto(`${BASE}/login`, { waitUntil: "networkidle2" });
    await setValue(page, 'input[name="Model.Username"]', USER);
    await setValue(page, 'input[name="Model.Password"]', USER_PASSWORD);
    await Promise.all([
        page.waitForNavigation({ waitUntil: "networkidle2" }),
        page.evaluate(() => document.querySelector('button[type="submit"]').click()),
    ]);
    if (page.url() !== `${BASE}/`) {
        throw new Error(`sign-in as ${USER} failed: ` + page.url());
    }
}

async function openPersonalVault(page) {
    await page.goto(`${BASE}/`, { waitUntil: "networkidle2" });
    await page.waitForSelector(".personal-list .group-item", { timeout: 15000 });
    const id = await page.evaluate(() =>
        document.querySelector(".personal-list .group-item").getAttribute("href").split("/").pop());
    await page.goto(`${BASE}/vault/${id}`, { waitUntil: "networkidle2" });
    await page.waitForSelector(".vault-toolbar", { timeout: 15000 });
    return id;
}

// Interactive pages ignore clicks until the circuit attaches: click until the dialog shows.
async function createEntry(page) {
    for (let i = 0; i < 12; i++) {
        await clickText(page, ".vault-toolbar .btn-primary", "New password");
        try {
            await page.waitForSelector(".modal-panel", { timeout: 2500 });
            break;
        } catch { /* not attached yet */ }
    }
    await sleep(500);
    await setValue(page, ".modal-panel form > label:nth-of-type(1) input", ENTRY);
    await setValue(page, ".modal-panel .password-row input", SECRET);
    await sleep(500);
    await page.evaluate(() => document.querySelector(".modal-panel form").requestSubmit());
    await page.waitForFunction(
        (n) => !document.querySelector(".modal-panel") && document.querySelector(".entries-table")?.textContent.includes(n),
        { timeout: 15000 }, ENTRY);
}

// What the server does with a bare cookie, redirects not followed.
async function replay(cookie, path, headers = {}, method = "GET") {
    const res = await fetch(`${BASE}${path}`, { method, headers: { cookie, ...headers }, redirect: "manual" });
    return { status: res.status, location: res.headers.get("location") ?? "" };
}

const bouncedToSignIn = (r) => (r.status === 302 && /\/login/.test(r.location)) || r.status === 401;

(async () => {
    const browser = await puppeteer.launch({ headless: "new", args: ["--no-first-run"] });
    // Both tabs in one context: one cookie jar, one session — as two tabs of one browser.
    const context = await browser.createBrowserContext();
    const tabA = await context.newPage();
    await tabA.evaluateOnNewDocument(() => { window.confirm = () => true; });
    await tabA.setViewport({ width: 1280, height: 860 });
    let cleanup = null;

    try {
        // ---- 1. an open tab, after a sign-out in another ----
        await signIn(tabA);
        await openPersonalVault(tabA);
        await createEntry(tabA);
        cleanup = async () => {
            await signIn(tabA);
            await openPersonalVault(tabA);
            await tabA.waitForFunction((n) => document.querySelector(".entries-table")?.textContent.includes(n), { timeout: 15000 }, ENTRY);
            await sleep(800);
            await rowAction(tabA, ENTRY, "Delete");
            await tabA.waitForFunction((n) => !document.querySelector(".entries-table")?.textContent.includes(n), { timeout: 15000 }, ENTRY);
        };

        await rowAction(tabA, ENTRY, "Reveal");
        await tabA.waitForFunction((s) => document.querySelector(".entries-table .revealed")?.textContent === s, { timeout: 10000 }, SECRET);
        await rowAction(tabA, ENTRY, "Hide password");
        await tabA.waitForFunction(() => !document.querySelector(".entries-table .revealed"), { timeout: 10000 });
        check("before signing out, the open tab reveals the password", true);

        const cdp = await tabA.createCDPSession();
        const { cookies } = await cdp.send("Network.getAllCookies");
        const auth = cookies.find((c) => c.name === ".harpo.auth");
        const cookie = auth ? `${auth.name}=${auth.value}` : "";
        const offlineHeaders = { "X-Harpo-Offline": "1" };
        const before = await replay(cookie, "/api/offline/snapshot", offlineHeaders);
        check("before signing out, the copied cookie gets an offline snapshot", before.status === 200, JSON.stringify(before));

        // Tab B signs out with the sign-out button.
        const tabB = await context.newPage();
        await tabB.goto(`${BASE}/`, { waitUntil: "networkidle2" });
        await tabB.waitForSelector(".logout-form", { timeout: 15000 });
        await Promise.all([
            tabB.waitForNavigation({ waitUntil: "networkidle2" }),
            tabB.evaluate(() => document.querySelector(".logout-form").requestSubmit()),
        ]);
        check("tab B signs out", new URL(tabB.url()).pathname === "/login", tabB.url());

        // Straight back to tab A (well inside its 30 s page check), and Reveal again.
        await tabA.bringToFront();
        const clicked = await rowAction(tabA, ENTRY, "Reveal");
        let toast = "";
        try {
            await tabA.waitForFunction((t) => document.querySelector(".toast")?.textContent.includes(t), { timeout: 10000 }, ENDED);
            toast = await tabA.evaluate(() => document.querySelector(".toast").textContent.trim());
        } catch { /* reported below */ }
        const leaked = await tabA.evaluate((s) => document.body.innerText.includes(s) || !!document.querySelector(".revealed"), SECRET);
        check("a fresh Reveal in the still-open tab is refused with the session-ended message",
            clicked && toast.includes(ENDED) && !leaked, `clicked=${clicked} toast="${toast}" leaked=${leaked}`);

        const copied = await rowAction(tabA, ENTRY, "Copy password");
        await sleep(1500);
        const copyToast = await tabA.evaluate(() => document.querySelector(".toast")?.textContent.trim() ?? "");
        check("Copy is refused the same way", copied && copyToast.includes(ENDED), copyToast);

        // The page's own check moves it to the sign-in page, clearing the screen.
        const t0 = Date.now();
        let moved = false;
        try {
            await tabA.waitForFunction(() => location.pathname === "/login", { timeout: 45000 });
            moved = true;
        } catch { /* reported below */ }
        const seconds = Math.round((Date.now() - t0) / 1000);
        check("the open tab moves to the sign-in page within 30 seconds", moved && seconds <= 35, `${seconds}s, at ${tabA.url()}`);

        // ---- 2. the copied cookie, replayed after the sign-out ----
        const page = await replay(cookie, "/");
        check("the copied cookie no longer opens a page (sent to sign in)", bouncedToSignIn(page), JSON.stringify(page));
        const snapshot = await replay(cookie, "/api/offline/snapshot", offlineHeaders);
        check("the copied cookie no longer gets an offline snapshot", bouncedToSignIn(snapshot), JSON.stringify(snapshot));
        const circuit = await replay(cookie, "/_blazor/negotiate?negotiateVersion=1", {}, "POST");
        check("the copied cookie cannot open a live connection", circuit.status === 401 || bouncedToSignIn(circuit), JSON.stringify(circuit));
    } catch (err) {
        check("suite ran to completion", false, err.message);
    } finally {
        if (cleanup) {
            try {
                await cleanup();
            } catch (err) {
                console.log(`(cleanup failed: ${err.message} — delete "${ENTRY}" by hand)`);
            }
        }
        await browser.close();
    }

    const failed = results.filter((r) => !r.ok).length;
    console.log(`\n${results.length - failed}/${results.length} checks passed`);
    process.exit(failed ? 1 : 0);
})();
