// End-to-end checks of Harpo's interactive UI against the live multisite demo
// stack: dialog keyboard behaviour and validation, the vault's password and
// 2FA controls, the entries layout at a range of widths, the links between
// pages, the Administration page, and personal vaults as two accounts see them.
//
// These are the things unit tests cannot see — a control that ends up hidden
// under another, focus left behind a dialog, an error shown far from its field.
// The suite creates its own throwaway group and entries and deletes the group
// when it is done. The personal-vault section takes over the second account's
// vault (that account gets a fresh one on its next visit) and deletes the
// resulting group; run it against a throwaway stack rather than one whose
// second account keeps real passwords in its personal vault.
//
// Prerequisites: `docker compose -f docker-compose.multisite.yml up -d`.
// Run with: npm run test:ui (see README.md in this directory).
const puppeteer = require("puppeteer");

const BASE = process.env.HARPO_BASE_URL || "http://localhost:8081";
const USER = process.env.HARPO_USER || "alice"; // must be a site administrator
const USER_PASSWORD = process.env.HARPO_PASSWORD || "alice";
const OTHER_USER = process.env.HARPO_OTHER_USER || "bob"; // not a site administrator
const OTHER_PASSWORD = process.env.HARPO_OTHER_PASSWORD || "bob";

const RUN_ID = Date.now();
const GROUP = `E2E UI ${RUN_ID}`;
const ENTRY = `E2E Router ${RUN_ID}`;
const WEAK_ENTRY = `E2E Weak ${RUN_ID}`;
const PERSONAL_ENTRY = `E2E Personal ${RUN_ID}`;
const OTHER_PERSONAL_ENTRY = `E2E Other Personal ${RUN_ID}`;
const TOTP_SECRET = "JBSWY3DPEHPK3PXP";
const NOTES = `recovery codes 4F9K-22QX (run ${RUN_ID})`;
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

async function signIn(page, user = USER, password = USER_PASSWORD) {
    await page.goto(`${BASE}/login`, { waitUntil: "networkidle2" });
    await setValue(page, 'input[name="Model.Username"]', user);
    await setValue(page, 'input[name="Model.Password"]', password);
    await Promise.all([
        page.waitForNavigation({ waitUntil: "networkidle2" }),
        page.evaluate(() => document.querySelector('button[type="submit"]').click()),
    ]);
    if (page.url() !== `${BASE}/`) {
        throw new Error(`sign-in as ${user} failed: ` + page.url());
    }
}

// The vault page's sidebar, once it has rendered: section headings, the
// personal vault's link, and the shared groups listed.
async function sidebar(page) {
    await page.goto(`${BASE}/`, { waitUntil: "networkidle2" });
    await page.waitForSelector(".vault-groups .group-list", { timeout: 15000 });
    await sleep(600);
    return page.evaluate(() => ({
        headings: [...document.querySelectorAll(".vault-groups-header h2")].map((h) => h.textContent.trim()),
        personal: document.querySelector(".personal-list .group-item")?.getAttribute("href")?.split("/").pop() ?? null,
        personalName: document.querySelector(".personal-list .group-item-name")?.textContent.trim(),
        personalBadge: document.querySelector(".personal-list .badge")?.textContent.trim(),
        groups: [...document.querySelectorAll(".group-list:not(.personal-list) .group-item-name")].map((e) => e.textContent.trim()),
    }));
}

// What a visitor finds at a vault URL: the entries shown, the toolbar, and any toast.
async function visitVault(page, vaultId) {
    await page.goto(`${BASE}/vault/${vaultId}`, { waitUntil: "networkidle2" });
    await page.waitForSelector(".vault-toolbar", { timeout: 15000 });
    await sleep(1500);
    return page.evaluate(() => ({
        title: document.querySelector(".vault-toolbar h1")?.textContent.trim(),
        privateBadge: document.querySelector(".vault-private-badge")?.textContent.trim() ?? null,
        canAdd: !!document.querySelector(".vault-toolbar .btn-primary"),
        entries: [...document.querySelectorAll(".entries-table tbody .entry-name")].map((e) => e.textContent.trim()),
        toast: document.querySelector(".toast")?.textContent.trim() ?? "",
    }));
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
    // Chrome reports whatever the content security policy blocked as a console
    // error, so a page that needs something the policy forbids shows up here.
    const blocked = [];
    let expectingBlocks = false;
    page.on("console", (message) => {
        if (!expectingBlocks && /Content Security Policy/i.test(message.text())) {
            blocked.push(`${new URL(page.url()).pathname}: ${message.text().slice(0, 160)}`);
        }
    });
    const policies = new Map(); // page path -> the policy it was served with
    page.on("response", (response) => {
        if (response.request().resourceType() === "document") {
            policies.set(new URL(response.url()).pathname.replace(/[0-9a-f-]{36}/, "{id}"),
                response.headers()["content-security-policy"] ?? "");
        }
    });
    let id = null;
    let takenOverId = null;
    let personalId = null;
    let otherContext = null;

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

        // Notes: typed into the editor, shown on the entry, and offered back next time.
        await rowAction(page, ENTRY, "Edit");
        await page.waitForSelector(".modal-panel textarea", { timeout: 10000 });
        await sleep(500);
        await setValue(page, ".modal-panel textarea", NOTES);
        await sleep(300);
        await submitDialog(page);
        await page.waitForFunction(() => !document.querySelector(".modal-panel"), { timeout: 15000 });
        await sleep(600);
        const notesOnRow = await page.evaluate((name) =>
            [...document.querySelectorAll(".entries-table tbody tr")].find((r) => r.textContent.includes(name))
                ?.querySelector(".cell-name")?.getAttribute("title"), ENTRY);
        await rowAction(page, ENTRY, "Edit");
        await page.waitForSelector(".modal-panel textarea", { timeout: 10000 });
        await sleep(500);
        const notesInEditor = await page.evaluate(() => document.querySelector(".modal-panel textarea").value);
        await page.evaluate(() => document.querySelector(".modal-close").click());
        await page.waitForFunction(() => !document.querySelector(".modal-panel"), { timeout: 8000 });
        check("notes are saved, shown on the entry and offered back for editing",
            notesOnRow === NOTES && notesInEditor === NOTES, JSON.stringify({ notesOnRow, notesInEditor }));

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

        // ---- 7. Personal vaults: one each, owner-only, taken over on departure ----
        const mine = await sidebar(page);
        personalId = mine.personal;
        check("the vault lists a personal vault above the groups, marked as only yours",
            mine.headings.join(",") === "Personal,Groups" && !!personalId && mine.personalName === "Personal"
            && mine.personalBadge === "only you" && !mine.groups.includes("Personal"), JSON.stringify(mine));

        let vault = await visitVault(page, personalId);
        check("the personal vault opens for its owner with the private marker", vault.privateBadge === "only you" && vault.canAdd, JSON.stringify(vault));
        await createEntry(page, PERSONAL_ENTRY, "Pv7$kq2!Lm9#xW4e");
        await rowAction(page, PERSONAL_ENTRY, "Reveal");
        await page.waitForSelector(".entries-table .revealed", { timeout: 10000 });
        check("a personal entry is created and revealed like any other", true);

        await page.goto(`${BASE}/groups`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".card-list, .empty-state", { timeout: 15000 });
        await sleep(600);
        const groupsPage = await page.evaluate((pid) => ({
            names: [...document.querySelectorAll(".group-card-name")].map((e) => e.textContent.trim()),
            linksToPersonal: !!document.querySelector(`a[href="/groups/${pid}"]`),
        }), personalId);
        await page.goto(`${BASE}/groups/${personalId}`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".page-narrow .panel, .alert-error", { timeout: 15000 });
        await sleep(600);
        const personalDetail = await page.evaluate(() => ({
            heading: document.querySelector(".panel h2")?.textContent.trim(),
            members: !!document.querySelector(".members-table"),
            danger: !!document.querySelector(".panel-danger"),
            settings: [...document.querySelectorAll(".panel h2")].some((h) => h.textContent === "Group settings"),
        }));
        check("the personal vault is not a group: absent from the groups list, nothing to manage",
            !groupsPage.names.includes("Personal") && !groupsPage.linksToPersonal
            && personalDetail.heading === "Your personal vault" && !personalDetail.members && !personalDetail.danger && !personalDetail.settings,
            JSON.stringify({ groupsPage, personalDetail }));

        // The second account, in its own browser context (cookies ignore the port).
        otherContext = await browser.createBrowserContext();
        const other = await otherContext.newPage();
        await other.evaluateOnNewDocument(() => { window.confirm = () => true; });
        await other.setViewport({ width: 1280, height: 860 });
        await signIn(other, OTHER_USER, OTHER_PASSWORD);
        const theirs = await sidebar(other);
        const otherPersonalId = theirs.personal;
        await visitVault(other, otherPersonalId);
        await createEntry(other, OTHER_PERSONAL_ENTRY, "Qz3!vb8#Nt5$yR2p");
        const theirView = await visitVault(other, personalId);
        await page.bringToFront();
        const myView = await visitVault(page, otherPersonalId);
        check("each account has its own vault and neither can open the other's — the site admin included",
            !!otherPersonalId && otherPersonalId !== personalId
            && theirView.entries.length === 0 && !theirView.canAdd && theirView.toast.includes("Only its owner")
            && myView.entries.length === 0 && !myView.canAdd && myView.toast.includes("Only its owner"),
            JSON.stringify({ theirView, myView }));

        await page.goto(`${BASE}/admin`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".personal-vaults-table, #personal-vaults .muted", { timeout: 15000 });
        await sleep(1200);
        const adminBefore = await page.evaluate((otherUser) => {
            const row = [...document.querySelectorAll(".personal-vaults-table tbody tr")]
                .find((r) => r.querySelector(".mono")?.textContent.trim() === otherUser);
            return {
                otherListed: !!row,
                otherCount: row?.querySelector("td:nth-child(2)")?.textContent.trim(),
                allGroups: [...document.querySelectorAll("section.panel")]
                    .find((s) => s.querySelector("h2")?.textContent === "All groups")
                    ?.querySelectorAll(".group-card-name").length ?? 0,
                personalInAllGroups: [...document.querySelectorAll(".group-card-name")].some((e) => e.textContent.trim() === "Personal"),
                auditWhat: [...document.querySelectorAll(".audit-table tbody tr td:nth-child(4)")].map((td) => td.textContent.trim()),
            };
        }, OTHER_USER);
        check("administration lists personal vaults by owner and size only, and keeps them out of the group list",
            adminBefore.otherListed && adminBefore.otherCount === "1" && adminBefore.allGroups > 0 && !adminBefore.personalInAllGroups,
            JSON.stringify({ ...adminBefore, auditWhat: undefined }));
        check("the audit log records the personal reveal without the entry's name",
            adminBefore.auditWhat.some((w) => w.startsWith("an entry in a personal vault"))
            && !adminBefore.auditWhat.some((w) => w.includes(PERSONAL_ENTRY)),
            adminBefore.auditWhat.slice(0, 3).join(" | "));

        // Take the other account's vault over.
        await page.evaluate((otherUser) => {
            const row = [...document.querySelectorAll(".personal-vaults-table tbody tr")]
                .find((r) => r.querySelector(".mono")?.textContent.trim() === otherUser);
            row.querySelector("button").click();
        }, OTHER_USER);
        await page.waitForSelector(".modal-panel form", { timeout: 10000 });
        await sleep(500);
        const takeoverDialog = await page.evaluate(() => ({
            title: document.querySelector(".modal-panel h2")?.textContent.trim(),
            name: document.querySelector(".modal-panel input")?.value,
        }));
        await submitDialog(page);
        await page.waitForFunction(() => !document.querySelector(".modal-panel"), { timeout: 15000 });
        await sleep(1200);
        const adminAfter = await page.evaluate((otherUser) => ({
            otherStillListed: [...document.querySelectorAll(".personal-vaults-table tbody tr")]
                .some((r) => r.querySelector(".mono")?.textContent.trim() === otherUser),
            groupNames: [...document.querySelectorAll(".group-card-name")].map((e) => e.textContent.trim()),
            takeoverLogged: [...document.querySelectorAll(".audit-table tbody tr")]
                .some((r) => r.textContent.includes("personal.takeover") && r.textContent.includes(`was the personal vault of ${otherUser}`)),
        }), OTHER_USER);
        takenOverId = otherPersonalId;
        const takenOver = await visitVault(page, otherPersonalId);
        check("a takeover turns the vault into a group the admin can open, named after its owner and audited",
            takeoverDialog.title === "Take over a personal vault" && takeoverDialog.name === `${OTHER_USER}'s personal vault`
            && !adminAfter.otherStillListed && adminAfter.groupNames.includes(`${OTHER_USER}'s personal vault`) && adminAfter.takeoverLogged
            && takenOver.entries.includes(OTHER_PERSONAL_ENTRY) && takenOver.privateBadge === null,
            JSON.stringify({ takeoverDialog, adminAfter, takenOver: takenOver.entries }));

        await other.bringToFront();
        const theirsAfter = await sidebar(other);
        await page.bringToFront();
        check("the former owner sees the group they lost, and gets a fresh personal vault",
            theirsAfter.groups.includes(`${OTHER_USER}'s personal vault`)
            && !!theirsAfter.personal && theirsAfter.personal !== otherPersonalId,
            JSON.stringify(theirsAfter));
        await other.close();

        // ---- 8. Content security policy: on every page, in nobody's way, and enforced ----
        const unprotected = [...policies].filter(([, policy]) =>
            !/script-src 'self';/.test(policy) || !/style-src 'self';/.test(policy) || !/frame-ancestors 'none'/.test(policy));
        check("every page is served with the content security policy", policies.size >= 6 && unprotected.length === 0,
            unprotected.length === 0 ? [...policies.keys()].join(" ") : `missing or weaker on: ${unprotected.map(([path]) => path).join(", ")}`);
        check("nothing the app does is blocked by it", blocked.length === 0, blocked.slice(0, 3).join(" | "));
        expectingBlocks = true;
        const injected = await page.evaluate(() => {
            const script = document.createElement("script");
            script.textContent = "window.__injected = true;";
            document.body.appendChild(script);
            const probe = document.createElement("div");
            probe.setAttribute("style", "color: rgb(1, 2, 3)");
            document.body.appendChild(probe);
            const result = { scriptRan: window.__injected === true, styleApplied: getComputedStyle(probe).color === "rgb(1, 2, 3)" };
            script.remove();
            probe.remove();
            return result;
        });
        check("an injected inline script does not run and an injected inline style does not apply",
            !injected.scriptRan && !injected.styleApplied, JSON.stringify(injected));
    } catch (e) {
        check("script completed", false, e.message.slice(0, 200));
    } finally {
        // ---- 9. Remove the throwaway groups and the personal entry ----
        const deleteGroup = async (groupToDelete) => {
            await page.goto(`${BASE}/groups/${groupToDelete}`, { waitUntil: "networkidle2" });
            await page.waitForSelector(".panel-danger .btn-danger", { timeout: 15000 });
            for (let i = 0; i < 12; i++) {
                await page.evaluate(() => document.querySelector(".panel-danger .btn-danger")?.click());
                try {
                    await page.waitForFunction(() => location.pathname === "/groups", { timeout: 1500 });
                    break;
                } catch { /* circuit not attached yet */ }
            }
            return page.evaluate(() => location.pathname === "/groups");
        };
        try {
            await page.setViewport({ width: 1280, height: 860 });
            id ??= await groupId(page);
            let cleaned = await deleteGroup(id);
            if (takenOverId) {
                cleaned = (await deleteGroup(takenOverId)) && cleaned;
            }
            if (personalId) {
                await visitVault(page, personalId);
                await rowAction(page, PERSONAL_ENTRY, "Delete");
                await page.waitForFunction((n) => !document.querySelector(".entries-table")?.textContent.includes(n),
                    { timeout: 10000 }, PERSONAL_ENTRY);
            }
            check("test groups and the personal entry cleaned up", cleaned);
        } catch (e) {
            check("test groups and the personal entry cleaned up", false, e.message.slice(0, 120));
        }
        try {
            await otherContext?.close();
        } catch { /* already gone with the browser */ }
        await browser.close();
    }

    const failed = results.filter((r) => !r.ok).length;
    console.log(`\n${results.length - failed}/${results.length} checks passed`);
    process.exit(failed === 0 ? 0 : 1);
})();
