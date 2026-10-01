// End-to-end checks of Harpo's interactive UI against the live multisite demo
// stack: dialog keyboard behaviour and validation, the vault's password and
// 2FA controls, the entries layout at a range of widths, the links between
// pages, and the Administration page.
//
// These are the things unit tests cannot see — a control that ends up hidden
// under another, focus left behind a dialog, an error shown far from its field.
// The suite creates its own throwaway group and entries and deletes the group
// when it is done.
//
// Prerequisites: `docker compose -f docker-compose.multisite.yml up -d`.
// Run with: npm run test:ui (see README.md in this directory).
const puppeteer = require("puppeteer");

const BASE = process.env.HARPO_BASE_URL || "http://localhost:8081";
const USER = process.env.HARPO_USER || "alice"; // must be a site administrator
const USER_PASSWORD = process.env.HARPO_PASSWORD || "alice";

const RUN_ID = Date.now();
const GROUP = `E2E UI ${RUN_ID}`;
const ENTRY = `E2E Router ${RUN_ID}`;
const WEAK_ENTRY = `E2E Weak ${RUN_ID}`;
const TOTP_SECRET = "JBSWY3DPEHPK3PXP";
const WIDTHS = [1920, 1600, 1440, 1280, 1024, 768, 390];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
function check(name, ok, detail = "") {
    results.push({ name, ok });
    console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  [" + detail + "]" : ""}`);
}

// All interaction is synthetic (el.click(), value + input/change events): once a
// Blazor circuit has attached, headless Chrome's trusted input stops arriving.
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

const submitDialog = (page) => page.evaluate(() => document.querySelector(".modal-panel form").requestSubmit());

// What has keyboard focus, described well enough to assert on.
const focused = (page) => page.evaluate(() => {
    const a = document.activeElement;
    return a ? `${a.tagName.toLowerCase()}:${(a.getAttribute("aria-label") || a.placeholder || a.textContent || "").trim().slice(0, 40)}` : "(nothing)";
});

async function signIn(page) {
    await page.goto(`${BASE}/login`, { waitUntil: "networkidle2" });
    await setValue(page, 'input[name="Model.Username"]', USER);
    await setValue(page, 'input[name="Model.Password"]', USER_PASSWORD);
    await Promise.all([
        page.waitForNavigation({ waitUntil: "networkidle2" }),
        page.evaluate(() => document.querySelector('button[type="submit"]').click()),
    ]);
    if (page.url() !== `${BASE}/`) {
        throw new Error("sign-in failed: " + page.url());
    }
}

// Interactive pages ignore clicks until the circuit attaches: click until the dialog shows.
async function openDialog(page, buttonSelector, buttonText) {
    for (let i = 0; i < 12; i++) {
        await clickText(page, buttonSelector, buttonText);
        try {
            await page.waitForSelector(".modal-panel", { timeout: 2500 });
            await sleep(500);
            return;
        } catch { /* not attached yet */ }
    }
    throw new Error(`the "${buttonText}" dialog did not open`);
}

async function createEntry(page, name, password, totp = "") {
    await openDialog(page, ".vault-toolbar .btn-primary", "New password");
    await setValue(page, ".modal-panel form > label:nth-of-type(1) input", name);
    await setValue(page, ".modal-panel .password-row input", password);
    if (totp) {
        await setValue(page, '.modal-panel input[placeholder^="base32"]', totp);
    }
    await sleep(500);
    await submitDialog(page);
    await page.waitForFunction(
        (n) => !document.querySelector(".modal-panel") && document.querySelector(".entries-table")?.textContent.includes(n),
        { timeout: 15000 }, name);
}

const rowAction = (page, entryName, ariaLabel) => page.evaluate((name, label) => {
    const row = [...document.querySelectorAll(".entries-table tbody tr")].find((r) => r.textContent.includes(name));
    const button = row?.querySelector(`button[aria-label="${label}"], button[title="${label}"]`);
    if (!button) {
        throw new Error(`no "${label}" control on the row for ${name}`);
    }
    button.click();
}, entryName, ariaLabel);

async function groupId(page) {
    for (let i = 0; i < 15; i++) {
        await page.goto(`${BASE}/groups`, { waitUntil: "networkidle2" });
        await sleep(800);
        const href = await page.evaluate((g) =>
            [...document.querySelectorAll('a[href^="/groups/"]')].find((a) => a.textContent.includes(g))?.getAttribute("href"), GROUP);
        if (href) {
            return href.split("/").pop();
        }
    }
    throw new Error("the test group never appeared");
}

(async () => {
    const browser = await puppeteer.launch({ headless: "new", args: ["--no-first-run"] });
    const page = await browser.newPage();
    // Headless Chrome cancels confirm() dialogs opened without user activation.
    await page.evaluateOnNewDocument(() => { window.confirm = () => true; });
    await page.setViewport({ width: 1280, height: 860 });
    let id = null;

    try {
        await signIn(page);

        // ---- 1. New-group dialog: validation at the field ----
        await page.goto(`${BASE}/groups`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".page-header .btn-primary");
        await openDialog(page, ".page-header .btn-primary", "New group");
        await submitDialog(page);
        await sleep(900);
        check("new-group dialog reports a missing name at the field",
            (await page.evaluate(() => document.getElementById("error-group-name")?.textContent)) === "Give the group a name."
            && (await focused(page)).startsWith("input:"), await focused(page));
        await setValue(page, ".modal-panel form > label:nth-of-type(1) input", GROUP);
        await sleep(400);
        await submitDialog(page);
        await page.waitForFunction(() => !document.querySelector(".modal-panel"), { timeout: 15000 });
        id = await groupId(page);
        check("submitting the form creates the group", true);

        // ---- 2. Entry editor: focus, semantics, validation, keyboard ----
        await page.goto(`${BASE}/vault/${id}`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".vault-toolbar .btn-primary");
        await page.evaluate(() => document.querySelector(".vault-toolbar .btn-primary").focus());
        await openDialog(page, ".vault-toolbar .btn-primary", "New password");
        check("dialog opens with focus in its first field", (await focused(page)).startsWith("input:e.g."), await focused(page));
        const dialog = await page.evaluate(() => {
            const panel = document.querySelector(".modal-panel");
            return {
                role: panel.getAttribute("role"),
                title: document.getElementById(panel.getAttribute("aria-labelledby"))?.textContent,
                form: !!panel.querySelector("form"),
                iconField: panel.querySelector("#icon-field-label")?.parentElement.tagName,
                emojiLabel: panel.querySelector(".icon-free-label span")?.textContent,
                uploadNote: panel.querySelector(".icon-picker-extra .muted")?.textContent.includes("shared by everyone"),
            };
        });
        check("dialog is a labelled dialog holding a real form",
            dialog.role === "dialog" && dialog.title === "New password" && dialog.form, JSON.stringify(dialog));
        check("icon picker: not a label around buttons, emoji field and upload scope are labelled",
            dialog.iconField === "DIV" && dialog.emojiLabel === "Or type any emoji" && dialog.uploadNote === true);

        await submitDialog(page);
        await sleep(900);
        const empty = await page.evaluate(() => ({
            name: document.getElementById("error-name")?.textContent,
            password: document.getElementById("error-password")?.textContent,
            invalid: document.querySelector(".modal-panel form input").getAttribute("aria-invalid"),
            footerOnScreen: document.querySelector(".modal-footer").getBoundingClientRect().bottom <= window.innerHeight,
        }));
        check("empty submit reports at each field, footer stays on screen",
            empty.name === "Give this password a name." && empty.password === "Enter a password, or generate one."
            && empty.invalid === "true" && empty.footerOnScreen, JSON.stringify(empty));
        check("focus moves to the first invalid field", (await focused(page)).startsWith("input:e.g."), await focused(page));

        await setValue(page, ".modal-panel form > label:nth-of-type(1) input", ENTRY);
        await setValue(page, ".modal-panel .password-row input", "Xk9#mQ2$vL7!pR4&");
        await setValue(page, '.modal-panel input[placeholder^="base32"]', "not base32!");
        await sleep(500);
        await submitDialog(page);
        await sleep(1100);
        check("a server-side validation error lands at its field",
            (await page.evaluate(() => document.getElementById("error-totp")?.textContent ?? "")).includes("base32")
            && (await focused(page)).includes("base32"), await focused(page));

        const keys = await page.evaluate(() => {
            const panel = document.querySelector(".modal-panel");
            const items = [...panel.querySelectorAll(
                'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select, textarea')]
                .filter((e) => e.getClientRects().length > 0);
            const first = items[0];
            const last = items[items.length - 1];
            const tab = (target, shiftKey = false) =>
                target.dispatchEvent(new KeyboardEvent("keydown", { key: "Tab", shiftKey, bubbles: true, cancelable: true }));
            last.focus();
            tab(last);
            const forward = document.activeElement === first;
            tab(first, true);
            const backward = document.activeElement === last;
            document.querySelector(".modal-backdrop").dispatchEvent(new MouseEvent("click", { bubbles: true }));
            return { forward, backward, upload: items.some((e) => e.type === "file") };
        });
        await sleep(600);
        check("Tab wraps at both ends of the dialog; upload is reachable by keyboard",
            keys.forward && keys.backward && keys.upload, JSON.stringify(keys));
        check("a click on the backdrop does not discard the form", await page.evaluate(() => !!document.querySelector(".modal-panel")));

        await page.evaluate(() => document.body.dispatchEvent(
            new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true })));
        await page.waitForFunction(() => !document.querySelector(".modal-panel"), { timeout: 8000 });
        await sleep(400);
        check("Escape closes the dialog and focus returns to its opener",
            (await focused(page)).includes("New password"), await focused(page));

        await createEntry(page, ENTRY, "Xk9#mQ2$vL7!pR4&", TOTP_SECRET);
        await createEntry(page, WEAK_ENTRY, "password");
        check("entries are created by submitting the form", true);

        // ---- 3. Vault row: 2FA control, trash, history ----
        const row = await page.evaluate(() => ({
            chip: document.querySelector(".totp-chip")?.textContent.trim(),
            trash: document.querySelector("details.trash summary")?.textContent.trim(),
            note: document.querySelector(".trash-note")?.textContent.replace(/\s+/g, " ").trim(),
        }));
        check("2FA control is labelled", row.chip === "2FA", String(row.chip));
        check("trash is shown before anything is deleted, and says how long things stay",
            row.trash === "Recently deleted (0)" && (row.note || "").includes("nothing is purged automatically"), String(row.trash));

        await page.evaluate(() => document.querySelector(".totp-chip").click());
        await page.waitForSelector(".totp-group", { timeout: 10000 });
        await sleep(1200);
        const totp = await page.evaluate(() => {
            const g = document.querySelector(".totp-group");
            return { label: g.querySelector(".totp-label")?.textContent, code: g.querySelector("code")?.textContent,
                     ring: !!g.querySelector(".totp-ring-fill"), seconds: g.querySelector(".totp-remaining")?.textContent };
        });
        check("2FA code shows with its label, a countdown ring and the seconds left",
            totp.label === "2FA" && /^\d{3} \d{3}$/.test(totp.code) && totp.ring && /^\d+s$/.test(totp.seconds), JSON.stringify(totp));

        await rowAction(page, ENTRY, "Password history");
        await page.waitForSelector(".history-table", { timeout: 10000 });
        await sleep(500);
        await page.evaluate(() => document.querySelector('.history-table button[aria-label="Copy this password"]').click());
        await page.waitForFunction(() => /copied|Copy failed/.test(document.querySelector(".toast")?.textContent ?? ""), { timeout: 8000 });
        check("a past password can be copied from history", true);
        await page.evaluate(() => document.querySelector(".modal-close").click());
        await page.waitForFunction(() => !document.querySelector(".modal-panel"), { timeout: 8000 });

        // ---- 4. Layout: nothing overflows or hides, at any width, at rest or revealed ----
        const problems = [];
        const modes = [];
        for (const width of WIDTHS) {
            await page.setViewport({ width, height: 860, isMobile: width < 500 });
            await page.goto(`${BASE}/vault/${id}`, { waitUntil: "networkidle2" });
            await page.waitForSelector(".entries-table");
            await sleep(900);
            for (const state of ["at rest", "revealed"]) {
                if (state === "revealed") {
                    await rowAction(page, ENTRY, "Reveal");
                    await page.evaluate(() => document.querySelector(".totp-chip").click());
                    await page.waitForSelector(".totp-group", { timeout: 10000 });
                    await sleep(900);
                }
                const m = await page.evaluate((name) => {
                    const panel = document.querySelector(".vault-entries").getBoundingClientRect();
                    const scroll = document.querySelector(".table-scroll");
                    const row = [...document.querySelectorAll(".entries-table tbody tr")].find((r) => r.textContent.includes(name));
                    const actions = row.querySelector(".cell-actions").getBoundingClientRect();
                    const hidden = [];
                    for (const el of row.querySelectorAll("button, code, a, .mask, .entry-name, .cell-updated span")) {
                        const r = el.getBoundingClientRect();
                        if (r.width === 0 || el.closest(".cell-actions")) {
                            continue;
                        }
                        const outside = r.right > panel.right + 1 || r.left < panel.left - 1;
                        const under = r.right > actions.left + 1 && r.left < actions.right - 1
                            && r.bottom > actions.top + 1 && r.top < actions.bottom - 1;
                        if (outside || under) {
                            hidden.push(el.getAttribute("aria-label") || el.className || el.tagName);
                        }
                    }
                    const updated = row.querySelector(".cell-updated").getBoundingClientRect();
                    return {
                        mode: getComputedStyle(row).display === "grid" ? "cards" : "table",
                        overflow: scroll.scrollWidth - scroll.clientWidth,
                        pageFits: document.documentElement.scrollWidth <= window.innerWidth + 1,
                        updatedShown: updated.width > 20 && updated.right <= panel.right + 1,
                        hidden,
                    };
                }, ENTRY);
                if (state === "at rest") {
                    modes.push(`${width}:${m.mode}`);
                }
                if (m.overflow > 1 || !m.pageFits || !m.updatedShown || m.hidden.length > 0) {
                    problems.push(`${width}px ${state}: ${JSON.stringify(m)}`);
                }
            }
        }
        check("entries layout: nothing overflows or is hidden at any width", problems.length === 0,
            problems.length === 0 ? modes.join(" ") : problems.join(" | "));
        check("wide panels get the table, narrow ones get cards",
            modes[0].endsWith("table") && modes[modes.length - 1].endsWith("cards"), modes.join(" "));
        await page.setViewport({ width: 1280, height: 860 });

        // ---- 5. Health report links to the entry ----
        await page.goto(`${BASE}/health`, { waitUntil: "networkidle2" });
        await page.waitForFunction((n) => document.body.textContent.includes(n), { timeout: 15000 }, WEAK_ENTRY);
        const link = await page.evaluate((n) =>
            [...document.querySelectorAll('a[href*="?q="]')].find((a) => a.textContent.trim() === n)?.getAttribute("href"), WEAK_ENTRY);
        await page.goto(`${BASE}${link}`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".vault-toolbar .search");
        await sleep(1200);
        const landed = await page.evaluate(() => ({
            search: document.querySelector(".vault-toolbar .search").value,
            names: [...document.querySelectorAll(".entries-table tbody .entry-name")].map((e) => e.textContent),
        }));
        check("a health finding opens the vault filtered to that entry",
            landed.search === WEAK_ENTRY && landed.names.length === 1 && landed.names[0] === WEAK_ENTRY, JSON.stringify(landed));

        // ---- 6. Administration ----
        await page.goto(`${BASE}/admin`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".audit-table", { timeout: 15000 });
        await sleep(1200);
        const admin = await page.evaluate(() => ({
            nav: [...document.querySelectorAll(".section-nav a")].map((a) => a.getAttribute("href").split("#")[1]),
            sticky: getComputedStyle(document.querySelector(".section-nav")).position,
            offline: document.querySelector("#site .stat:last-child")?.textContent.replace(/\s+/g, " ").trim(),
            chips: [...document.querySelectorAll(".filter-chips .chip")].map((c) => c.textContent.trim()).join(","),
            folded: document.querySelectorAll(".audit-repeat").length,
            deletedShown: [...document.querySelectorAll("section.panel")]
                .find((s) => s.querySelector("h2")?.textContent === "Deleted groups")?.querySelectorAll(".group-card").length ?? 0,
        }));
        check("administration has jump links to every section",
            admin.nav.length === 5 && admin.sticky === "sticky"
            && await page.evaluate((ids) => ids.every((i) => document.getElementById(i)), admin.nav), admin.nav.join(","));
        check("offline stat is spelled out", /^(Allowed offline copies · expire after \d+ days|Off offline copies)$/.test(admin.offline || ""), String(admin.offline));
        check("audit log folds repeated events and offers categories",
            admin.chips === "All,Reveals,Changes,Deletions,Background" && admin.folded > 0, `${admin.chips}; folded rows: ${admin.folded}`);
        check("deleted groups list is capped", admin.deletedShown <= 5, `shown: ${admin.deletedShown}`);
        await clickText(page, ".filter-chips .chip", "Reveals");
        await sleep(1500);
        const reveals = await page.evaluate(() =>
            [...document.querySelectorAll(".audit-table tbody tr td:nth-child(3)")].map((td) => td.textContent.trim()));
        check("the Reveals category shows only reveals and copies, including copies from history",
            reveals.length > 0 && reveals.includes("revision.copy")
            && reveals.every((a) => /^(password\.(reveal|copy)|revision\.(reveal|copy)|totp\.reveal)$/.test(a)),
            [...new Set(reveals)].join(","));
    } catch (e) {
        check("script completed", false, e.message.slice(0, 200));
    } finally {
        // ---- 7. Remove the throwaway group ----
        try {
            await page.setViewport({ width: 1280, height: 860 });
            id ??= await groupId(page);
            await page.goto(`${BASE}/groups/${id}`, { waitUntil: "networkidle2" });
            await page.waitForSelector(".panel-danger .btn-danger", { timeout: 15000 });
            for (let i = 0; i < 12; i++) {
                await page.evaluate(() => document.querySelector(".panel-danger .btn-danger")?.click());
                try {
                    await page.waitForFunction(() => location.pathname === "/groups", { timeout: 1500 });
                    break;
                } catch { /* circuit not attached yet */ }
            }
            check("test group cleaned up", await page.evaluate(() => location.pathname === "/groups"));
        } catch (e) {
            check("test group cleaned up", false, e.message.slice(0, 120));
        }
        await browser.close();
    }

    const failed = results.filter((r) => !r.ok).length;
    console.log(`\n${results.length - failed}/${results.length} checks passed`);
    process.exit(failed === 0 ? 0 : 1);
})();
