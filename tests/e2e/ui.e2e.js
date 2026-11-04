// End-to-end checks of Harpo's interactive UI against the live multisite demo
// stack: dialog keyboard behaviour and validation, the vault's password and
// 2FA controls, the entries layout at a range of widths, the links between
// pages, the Administration page (its all-groups export included: the demo
// and CI stacks switch it on), personal vaults as two accounts see them, and
// purging deleted passwords and a deleted group.
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
const fs = require("fs");
const os = require("os");
const path = require("path");
const puppeteer = require("puppeteer");

const BASE = process.env.HARPO_BASE_URL || "http://localhost:8081";
const USER = process.env.HARPO_USER || "alice"; // must be a site administrator
const USER_PASSWORD = process.env.HARPO_PASSWORD || "alice";
const OTHER_USER = process.env.HARPO_OTHER_USER || "bob"; // not a site administrator
const OTHER_PASSWORD = process.env.HARPO_OTHER_PASSWORD || "bob";
const DB_ENCRYPTED = process.env.HARPO_DB_ENCRYPTED; // "true" or "false" when the stack's state is known

const RUN_ID = Date.now();
const GROUP = `E2E UI ${RUN_ID}`;
const ENTRY = `E2E Router ${RUN_ID}`;
const WEAK_ENTRY = `E2E Weak ${RUN_ID}`;
const PERSONAL_ENTRY = `E2E Personal ${RUN_ID}`;
const OTHER_PERSONAL_ENTRY = `E2E Other Personal ${RUN_ID}`;
const OTHER_GROUP = `E2E Other Group ${RUN_ID}`;
const PURGE_GROUP = `E2E Purge ${RUN_ID}`;
const PURGE_ENTRIES = [`E2E Purge One ${RUN_ID}`, `E2E Purge Two ${RUN_ID}`, `E2E Purge Three ${RUN_ID}`];
const TOTP_SECRET = "JBSWY3DPEHPK3PXP";
const NOTES = `recovery codes 4F9K-22QX (run ${RUN_ID})`;
const WIDTHS = [1920, 1600, 1440, 1280, 1024, 768, 390];
const IMPORTED = `E2E Imported ${RUN_ID}`;
const IMPORTED_PASSWORD = "Imp0rt!Pass#1";
// A name a spreadsheet would run as a formula: the CSV export must neutralise it.
const INJECTED = `=HYPERLINK("http://example.invalid","x") ${RUN_ID}`;
const CSV_HEADER = "name,login_uri,login_username,login_password,notes,login_totp";
// A Bitwarden export: its folder column, a note spanning two lines, a row
// matching an entry the vault already has (ENTRY, no username) and a secure
// note without a password, which must be reported as failed (it starts on line 6).
const BITWARDEN_CSV = [
    "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp",
    `Network,,login,${IMPORTED},"first line`,
    `second, with ""quotes""",,0,https://imported.example.com,imp-admin,${IMPORTED_PASSWORD},${TOTP_SECRET}`,
    `,,login,"${INJECTED.replace(/"/g, '""')}",,,0,,@evil,Imp0rt!Pass#2,`,
    `,,login,${ENTRY},,,0,,,dup-password,`,
    `,,note,E2E Note only ${RUN_ID},just a note,,0,,,,`,
    "",
].join("\r\n");

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

// The export endpoint, fetched from the page so its cookies apply. One export
// every 10 seconds per user: a 429 is waited out (twice at most).
async function fetchExport(page, url) {
    for (let attempt = 0; ; attempt++) {
        const r = await page.evaluate(async (u) => {
            const response = await fetch(u, { credentials: "same-origin" });
            const bytes = new Uint8Array(await response.arrayBuffer());
            return {
                status: response.status,
                retryAfter: response.headers.get("retry-after"),
                disposition: response.headers.get("content-disposition") ?? "",
                cache: response.headers.get("cache-control") ?? "",
                bom: bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF,
                text: new TextDecoder().decode(bytes), // drops the byte order mark
            };
        }, url);
        if (r.status !== 429 || attempt >= 2) {
            return r;
        }
        await sleep((Number(r.retryAfter) || 10) * 1000 + 500);
    }
}

// The all-groups archive, fetched from the page like fetchExport. The zip is
// read in the page: its central directory gives the file names, and each file
// is inflated with the browser's own DecompressionStream so the test can look
// inside. One archive a minute per user: a 429 is waited out once.
async function fetchArchive(page, url) {
    for (let attempt = 0; ; attempt++) {
        const r = await page.evaluate(async (u) => {
            const response = await fetch(u, { credentials: "same-origin" });
            const bytes = new Uint8Array(await response.arrayBuffer());
            const result = {
                status: response.status,
                retryAfter: response.headers.get("retry-after"),
                type: response.headers.get("content-type") ?? "",
                disposition: response.headers.get("content-disposition") ?? "",
                cache: response.headers.get("cache-control") ?? "",
                pk: bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04,
                files: {},
                text: response.status === 200 ? "" : new TextDecoder().decode(bytes),
            };
            if (!result.pk) {
                return result;
            }
            const view = new DataView(bytes.buffer);
            let end = bytes.length - 22; // the end-of-central-directory record, found from the back
            while (end >= 0 && view.getUint32(end, true) !== 0x06054b50) {
                end--;
            }
            const count = view.getUint16(end + 10, true);
            let at = view.getUint32(end + 16, true);
            const utf8 = new TextDecoder();
            for (let i = 0; i < count && view.getUint32(at, true) === 0x02014b50; i++) {
                const method = view.getUint16(at + 10, true);
                const size = view.getUint32(at + 20, true);
                const nameLength = view.getUint16(at + 28, true);
                const extraLength = view.getUint16(at + 30, true);
                const commentLength = view.getUint16(at + 32, true);
                const local = view.getUint32(at + 42, true);
                const name = utf8.decode(bytes.subarray(at + 46, at + 46 + nameLength));
                const start = local + 30 + view.getUint16(local + 26, true) + view.getUint16(local + 28, true);
                let content = bytes.subarray(start, start + size);
                if (method === 8) {
                    const inflated = new Blob([content]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
                    content = new Uint8Array(await new Response(inflated).arrayBuffer());
                }
                result.files[name] = utf8.decode(content);
                at += 46 + nameLength + extraLength + commentLength;
            }
            return result;
        }, url);
        if (r.status !== 429 || attempt >= 1) {
            return r;
        }
        await sleep((Number(r.retryAfter) || 60) * 1000 + 500);
    }
}

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
    let otherGroupId = null;
    let purgeGroupId = null;
    let purgeGroupDeleted = false;
    const csvPath = path.join(os.tmpdir(), `harpo-e2e-import-${RUN_ID}.csv`);

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

        // ---- 3a. Import a Bitwarden export into the group, then export the group ----
        const toolbar = await page.evaluate(() =>
            [...document.querySelectorAll(".vault-toolbar .btn")].map((b) => b.textContent.trim()));
        check("a group admin's toolbar offers Import… and Export… beside New password",
            toolbar.join(",") === "Import…,Export…,New password", toolbar.join(","));

        fs.writeFileSync(csvPath, BITWARDEN_CSV);
        await openDialog(page, ".vault-toolbar .vault-import", "Import");
        await (await page.$('.modal-panel input[type="file"]')).uploadFile(csvPath);
        await page.waitForSelector(".modal-panel .import-preview", { timeout: 15000 });
        await sleep(400);
        const preview = await page.evaluate(() => ({
            mapping: Object.fromEntries([...document.querySelectorAll(".import-preview thead th")]
                .map((th) => [th.querySelector(".import-column-name").textContent.trim(), th.querySelector("select").value])),
            firstRow: [...document.querySelectorAll(".import-preview tbody tr:first-child td")].map((td) => td.textContent.trim()),
            folderNote: document.querySelector(".import-folder-note")?.textContent.replace(/\s+/g, " ").trim() ?? "",
            text: document.querySelector(".modal-panel").textContent,
            confirm: document.querySelector(".modal-panel .import-confirm")?.textContent.trim(),
        }));
        const m = preview.mapping;
        check("a Bitwarden file is mapped without a click; its folder column is shown but not used",
            m.name === "Name" && m.login_username === "Username" && m.login_password === "Password" && m.login_uri === "Url"
            && m.notes === "Notes" && m.login_totp === "Totp" && m.folder === "Ignore" && m.type === "Ignore"
            && preview.folderNote.includes("“folder”") && preview.confirm === "Import 4 rows", JSON.stringify(preview.mapping));
        check("the preview shows the rows but hides passwords and 2FA secrets",
            preview.firstRow.includes(IMPORTED) && preview.firstRow.includes("••••••••")
            && !preview.text.includes(IMPORTED_PASSWORD) && !preview.text.includes(TOTP_SECRET), preview.firstRow.join(" | "));

        await page.evaluate(() => document.querySelector(".modal-panel .import-confirm").click());
        await page.waitForSelector(".modal-panel .import-summary", { timeout: 15000 });
        const summary = await page.evaluate(() => ({
            created: document.querySelector(".import-count-created strong")?.textContent.trim(),
            skipped: document.querySelector(".import-count-skipped strong")?.textContent.trim(),
            failed: document.querySelector(".import-count-failed strong")?.textContent.trim(),
            failures: [...document.querySelectorAll(".import-failures tbody tr")]
                .map((r) => [...r.querySelectorAll("td")].map((td) => td.textContent.trim()).join(" / ")),
        }));
        check("the summary counts what was created, skipped as a duplicate, and failed with its row and reason",
            summary.created === "2" && summary.skipped === "1" && summary.failed === "1"
            && summary.failures.length === 1 && summary.failures[0] === `6 / E2E Note only ${RUN_ID} / Password is required.`,
            JSON.stringify(summary));
        await clickText(page, ".modal-panel .btn-primary", "Done");
        await page.waitForFunction(() => !document.querySelector(".modal-panel"), { timeout: 8000 });
        await page.waitForFunction((a, b) => {
            const names = [...document.querySelectorAll(".entries-table tbody .entry-name")].map((e) => e.textContent.trim());
            return names.includes(a) && names.includes(b);
        }, { timeout: 15000 }, IMPORTED, INJECTED);
        check("the imported entries are in the list", true);

        await openDialog(page, ".vault-toolbar .vault-export", "Export");
        const exportDialog = await page.evaluate(() => ({
            warning: document.querySelector(".modal-panel .export-warning")?.textContent.replace(/\s+/g, " ").trim() ?? "",
            facts: document.querySelector(".modal-panel .export-facts")?.textContent.replace(/\s+/g, " ").trim() ?? "",
            href: document.querySelector(".modal-panel a.export-download")?.getAttribute("href"),
            download: document.querySelector(".modal-panel a.export-download")?.hasAttribute("download"),
        }));
        await page.evaluate(() => document.querySelector('.modal-panel input[value="json"]').click());
        let jsonHref = null;
        try {
            await page.waitForFunction(() => document.querySelector("a.export-download")?.getAttribute("href").endsWith("format=json"), { timeout: 5000 });
            jsonHref = await page.evaluate(() => document.querySelector("a.export-download").getAttribute("href"));
        } catch { /* stays null */ }
        check("the export dialog says the file is plain text, audited and to be deleted, and links to the download",
            exportDialog.warning.includes("not encrypted") && exportDialog.warning.includes("every current password")
            && exportDialog.facts.includes("audit log") && exportDialog.facts.includes("Delete the file")
            && exportDialog.href === `/api/vault/${id}/export?format=csv` && exportDialog.download
            && jsonHref === `/api/vault/${id}/export?format=json`, JSON.stringify({ ...exportDialog, jsonHref }));
        await page.evaluate(() => document.querySelector(".modal-close").click());
        await page.waitForFunction(() => !document.querySelector(".modal-panel"), { timeout: 8000 });

        const csv = await fetchExport(page, `/api/vault/${id}/export?format=csv`);
        const csvLines = csv.text.split("\r\n");
        check("the CSV export is a UTF-8 attachment with a byte order mark, not cached, under the Bitwarden header",
            csv.status === 200 && csv.bom && csvLines[0] === CSV_HEADER
            && csv.disposition.startsWith("attachment") && csv.cache.includes("no-store"),
            JSON.stringify({ status: csv.status, bom: csv.bom, header: csvLines[0], disposition: csv.disposition, cache: csv.cache }));
        const injectedLine = csvLines.find((l) => l.includes(String(RUN_ID)) && l.includes("HYPERLINK")) ?? "";
        check("a value a spreadsheet would run as a formula is exported with a leading apostrophe, quoted",
            injectedLine.startsWith(`"'=HYPERLINK(""http://example.invalid"",""x"") ${RUN_ID}",,"'@evil",`), injectedLine);

        const json = await fetchExport(page, `/api/vault/${id}/export?format=json`);
        let exported = null;
        try {
            exported = JSON.parse(json.text);
        } catch { /* reported below */ }
        const byName = (n) => exported?.entries?.find((e) => e.name === n);
        check("the JSON export holds the 2FA secrets and notes, the imported entry's included",
            json.status === 200 && exported?.format === "harpo-vault-export" && exported?.vault?.name === GROUP
            && byName(ENTRY)?.totp === TOTP_SECRET && byName(ENTRY)?.notes === NOTES
            && byName(IMPORTED)?.totp === TOTP_SECRET && byName(IMPORTED)?.password === IMPORTED_PASSWORD
            && byName(IMPORTED)?.notes === 'first line\r\nsecond, with "quotes"',
            JSON.stringify({ status: json.status, format: exported?.format, entry: byName(ENTRY)?.totp, imported: byName(IMPORTED)?.notes }));

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
            dbFile: [...document.querySelectorAll("#site .stat")].map((s) => s.textContent.replace(/\s+/g, " ").trim())
                .find((t) => t.includes("database file")),
            chips: [...document.querySelectorAll(".filter-chips .chip")].map((c) => c.textContent.trim()).join(","),
            folded: document.querySelectorAll(".audit-repeat").length,
            deletedShown: [...document.querySelectorAll("section.panel")]
                .find((s) => s.querySelector("h2")?.textContent === "Deleted groups")?.querySelectorAll(".group-card").length ?? 0,
        }));
        check("administration has jump links to every section",
            admin.nav.length === 6 && admin.nav.includes("export") && admin.sticky === "sticky"
            && await page.evaluate((ids) => ids.every((i) => document.getElementById(i)), admin.nav), admin.nav.join(","));
        check("offline stat is spelled out", /^(Allowed offline copies · expire after \d+ days|Off offline copies)$/.test(admin.offline || ""), String(admin.offline));
        // Say which it should be with HARPO_DB_ENCRYPTED=true|false; otherwise either passes.
        check("database file encryption is shown",
            new RegExp(`^(${[DB_ENCRYPTED !== "false" && "Encrypted database file", DB_ENCRYPTED !== "true" && "Not encrypted database file · passwords are still encrypted"].filter(Boolean).join("|")})$`).test(admin.dbFile || ""),
            String(admin.dbFile));
        check("audit log folds repeated events and offers categories",
            admin.chips === "All,Reveals,Changes,Deletions,Background" && admin.folded > 0, `${admin.chips}; folded rows: ${admin.folded}`);
        check("deleted groups list is capped", admin.deletedShown <= 5, `shown: ${admin.deletedShown}`);

        // ---- 6a. Export all groups (switched on in the demo and CI stacks) ----
        await openDialog(page, "#export .export-all-open", "Export all groups");
        await page.waitForSelector(".modal-panel .export-all-groups", { timeout: 10000 });
        const allGroupsDialog = await page.evaluate(() => ({
            off: !!document.querySelector("#export .export-all-off"),
            title: document.querySelector(".modal-panel h2")?.textContent.trim(),
            warning: document.querySelector(".modal-panel .export-warning")?.textContent.replace(/\s+/g, " ").trim() ?? "",
            facts: document.querySelector(".modal-panel .export-facts")?.textContent.replace(/\s+/g, " ").trim() ?? "",
            groups: parseInt(document.querySelector(".modal-panel .export-all-groups")?.textContent ?? "", 10),
            entries: parseInt(document.querySelector(".modal-panel .export-all-entries")?.textContent ?? "", 10),
            href: document.querySelector(".modal-panel a.export-download")?.getAttribute("href"),
            download: document.querySelector(".modal-panel a.export-download")?.hasAttribute("download"),
        }));
        let allGroupsJsonHref = null;
        for (let i = 0; i < 8 && allGroupsJsonHref !== "/api/admin/export?format=json"; i++) {
            await page.evaluate(() => document.querySelector('.modal-panel input[value="json"]').click());
            await sleep(400);
            allGroupsJsonHref = await page.evaluate(() => document.querySelector(".modal-panel a.export-download").getAttribute("href"));
        }
        check("the Administration page's Export section opens a dialog that warns, counts the groups and links to the archive",
            !allGroupsDialog.off && allGroupsDialog.title === "Export all groups"
            && allGroupsDialog.warning.includes("not encrypted") && allGroupsDialog.warning.includes("every shared password")
            && allGroupsDialog.facts.includes("audit log") && allGroupsDialog.facts.includes("Delete the archive")
            && allGroupsDialog.facts.includes("Personal vaults are not included")
            && allGroupsDialog.groups >= 1 && allGroupsDialog.entries >= 3
            && allGroupsDialog.href === "/api/admin/export?format=csv" && allGroupsDialog.download
            && allGroupsJsonHref === "/api/admin/export?format=json", JSON.stringify({ ...allGroupsDialog, allGroupsJsonHref }));
        await clickText(page, ".modal-panel .modal-actions button", "Cancel");
        await page.waitForFunction(() => !document.querySelector(".modal-panel"), { timeout: 8000 });

        await clickText(page, ".filter-chips .chip", "Reveals");
        await sleep(1500);
        const reveals = await page.evaluate(() =>
            [...document.querySelectorAll(".audit-table tbody tr td:nth-child(3)")].map((td) => td.textContent.trim()));
        check("the Reveals category shows only reveals and copies, including copies from history",
            reveals.length > 0 && reveals.includes("revision.copy") && reveals.includes("vault.export")
            && reveals.every((a) => /^(password\.(reveal|copy)|revision\.(reveal|copy)|totp\.reveal|vault\.export|site\.export)$/.test(a)),
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
        // Its owner may export it; the audit log must not name what is in it (checked in the admin view below).
        const personalExport = await fetchExport(page, `/api/vault/${personalId}/export?format=csv`);
        check("the owner can export their personal vault",
            !!(await page.$(".vault-toolbar .vault-export")) && personalExport.status === 200
            && personalExport.text.includes(PERSONAL_ENTRY) && /harpo-personal-/.test(personalExport.disposition),
            JSON.stringify({ status: personalExport.status, disposition: personalExport.disposition }));

        // The site admin's all-groups archive, now that their personal vault holds
        // something: the shared test group is in it, the personal vault never is.
        const archive = await fetchArchive(page, "/api/admin/export?format=csv");
        const archived = Object.keys(archive.files);
        const groupFile = archive.files[`${GROUP}.csv`] ?? "";
        check("the all-groups download is an uncached zip with a file per group, the test group's included",
            archive.status === 200 && archive.pk && archive.type === "application/zip" && archive.cache.includes("no-store")
            && /attachment;.*harpo-[a-z0-9-]+-all-groups-\d{4}-\d{2}-\d{2}\.zip/.test(archive.disposition)
            && archived.includes("README.txt") && groupFile.startsWith(CSV_HEADER)
            && groupFile.includes(ENTRY) && groupFile.includes(IMPORTED_PASSWORD),
            JSON.stringify({ status: archive.status, type: archive.type, disposition: archive.disposition, files: archived.length }));
        check("the archive's README says it is unencrypted and lists the groups, and no personal vault is in it",
            archive.files["README.txt"]?.includes("NOT ENCRYPTED") && archive.files["README.txt"].includes(`${GROUP}  ->  ${GROUP}.csv`)
            && archive.files["README.txt"].includes("personal vaults")
            && !archived.some((n) => /^Personal( \(\d+\))?\.csv$/.test(n))
            && !Object.values(archive.files).some((text) => text.includes(PERSONAL_ENTRY)),
            archived.join(", ").slice(0, 200));

        // ---- 7a. Global search: an entry in another vault is found from this one ----
        // The shared test group is open and holds nothing called PERSONAL_ENTRY;
        // the personal vault does. Typing keeps retrying until the circuit has
        // attached, since an input event sent before that is lost.
        await page.setViewport({ width: 1280, height: 860 });
        await page.goto(`${BASE}/vault/${id}`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".vault-toolbar .search");
        const typeSearch = async (text, waitFor) => {
            for (let i = 0; i < 12; i++) {
                await setValue(page, ".vault-toolbar .search", text);
                try {
                    await page.waitForFunction(waitFor, { timeout: 2500 });
                    return true;
                } catch { /* not attached yet */ }
            }
            return false;
        };
        const found = await typeSearch(PERSONAL_ENTRY, () => !!document.querySelector(".search-others .search-hit"));
        const searchHit = await page.evaluate((name) => {
            const hit = [...document.querySelectorAll(".search-others .search-hit")].find((h) => h.textContent.includes(name));
            const link = hit?.querySelector("a.search-hit-vault");
            return {
                heading: document.querySelector(".search-others-title")?.textContent.trim(),
                hit: !!hit,
                vault: link?.textContent.trim(),
                href: link?.getAttribute("href") ?? "",
                buttons: hit ? hit.querySelectorAll("button").length : -1,
                text: document.querySelector(".search-others")?.textContent ?? "",
                // The open group's own results are untouched: nothing matches here.
                openGroupSays: document.querySelector(".vault-entries .empty-state")?.textContent.trim() ?? "",
            };
        }, PERSONAL_ENTRY);
        check("searching from a shared group lists a match in the personal vault under 'Also in other vaults', named Personal",
            found && searchHit.heading === "Also in other vaults" && searchHit.hit && searchHit.vault === "Personal"
            && searchHit.href === `/vault/${personalId}?q=${encodeURIComponent(PERSONAL_ENTRY)}`
            && searchHit.openGroupSays.includes("Nothing matches your search."), JSON.stringify(searchHit));
        check("a search result shows no password and offers no reveal",
            !searchHit.text.includes("Pv7$kq2!Lm9#xW4e") && searchHit.buttons === 0 && !(await page.$(".search-others .revealed, .search-others .mask")));

        // One character is not enough to search elsewhere; the section goes away.
        await setValue(page, ".vault-toolbar .search", "E");
        await page.waitForFunction(() => !document.querySelector(".search-others"), { timeout: 5000 });
        check("a single character does not search other vaults", true);

        const none = await typeSearch(`zz-no-such-entry-${RUN_ID}`,
            () => document.querySelector(".search-others .search-none"));
        check("a term nothing else matches says so quietly instead of listing", none
            && (await page.evaluate(() => document.querySelectorAll(".search-others .search-hit").length)) === 0);

        // The result card fits a phone and the wide layout alike.
        await typeSearch(PERSONAL_ENTRY, () => !!document.querySelector(".search-others .search-hit"));
        const fits = [];
        for (const width of [1280, 390]) {
            // Width alone: toggling isMobile reloads the page, which would drop the typed search.
            await page.setViewport({ width, height: 860 });
            await sleep(500);
            fits.push(await page.evaluate((w) => {
                const root = document.documentElement;
                const hit = document.querySelector(".search-others .search-hit");
                const link = hit?.querySelector("a.search-hit-vault");
                if (!hit || !link) {
                    return `${w}: missing`;
                }
                const h = hit.getBoundingClientRect();
                const l = link.getBoundingClientRect();
                const inside = h.left >= 0 && h.right <= root.clientWidth + 1 && l.left >= h.left - 1 && l.right <= h.right + 1;
                return inside && root.scrollWidth <= root.clientWidth + 1
                    ? "ok" : `${w}: overflow ${JSON.stringify({ hl: h.left, hr: h.right, ll: l.left, lr: l.right, sw: root.scrollWidth, cw: root.clientWidth })}`;
            }, width));
        }
        await page.setViewport({ width: 1280, height: 860 });
        check("the other-vaults result fits at 1280px and at 390px with no sideways scroll", fits.every((f) => f === "ok"), fits.join(" | "));

        // Clicking the vault name opens it already filtered to the entry.
        await page.evaluate(() => document.querySelector(".search-others a.search-hit-vault").click());
        await page.waitForFunction((pid) => location.pathname === `/vault/${pid}`, { timeout: 15000 }, personalId);
        await page.waitForFunction(
            (n) => document.querySelector(".vault-toolbar h1")?.textContent.trim() === "Personal"
                && document.querySelector(".vault-toolbar .search")?.value === n
                && document.querySelectorAll(".entries-table tbody .entry-name").length === 1,
            { timeout: 15000 }, PERSONAL_ENTRY);
        check("clicking the vault name opens the personal vault filtered to that entry",
            await page.evaluate((n) => document.querySelector(".entries-table tbody .entry-name").textContent.trim() === n, PERSONAL_ENTRY));
        // The vault we landed in is the match's own, so nothing is "elsewhere".
        await sleep(800);
        check("the vault the result led to does not list its own entry again under 'Also in other vaults'",
            !(await page.evaluate((n) => [...document.querySelectorAll(".search-others .search-hit")].some((h) => h.textContent.includes(n)), PERSONAL_ENTRY)));

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
        const adminBefore = await page.evaluate((otherUser, me) => {
            const rowOf = (user) => [...document.querySelectorAll(".personal-vaults-table tbody tr")]
                .find((r) => r.querySelector(".mono")?.textContent.trim() === user);
            const row = rowOf(otherUser);
            const mine = rowOf(me);
            return {
                otherListed: !!row,
                otherCount: row?.querySelector("td:nth-child(2)")?.textContent.trim(),
                otherCanBeTakenOver: !!row?.querySelector("button"),
                mineListed: !!mine,
                mineCanBeTakenOver: !!mine?.querySelector("button"),
                mineBadge: mine?.querySelector(".cell-actions .badge")?.textContent.trim() ?? null,
                allGroups: [...document.querySelectorAll("section.panel")]
                    .find((s) => s.querySelector("h2")?.textContent === "All groups")
                    ?.querySelectorAll(".group-card-name").length ?? 0,
                personalInAllGroups: [...document.querySelectorAll(".group-card-name")].some((e) => e.textContent.trim() === "Personal"),
                auditWhat: [...document.querySelectorAll(".audit-table tbody tr td:nth-child(4)")].map((td) => td.textContent.trim()),
                personalExport: [...document.querySelectorAll(".audit-table tbody tr")]
                    .find((r) => r.querySelector("td:nth-child(3)")?.textContent.trim() === "vault.export")
                    ?.querySelector("td:nth-child(4)")?.textContent.replace(/\s+/g, " ").trim() ?? "",
                siteExport: [...document.querySelectorAll(".audit-table tbody tr")]
                    .find((r) => r.querySelector("td:nth-child(3)")?.textContent.trim() === "site.export")
                    ?.textContent.replace(/\s+/g, " ").trim() ?? "",
            };
        }, OTHER_USER, USER);
        check("administration lists personal vaults by owner and size only, offers no takeover of the admin's own, and keeps them out of the group list",
            adminBefore.otherListed && adminBefore.otherCount === "1" && adminBefore.otherCanBeTakenOver
            && adminBefore.mineListed && !adminBefore.mineCanBeTakenOver && adminBefore.mineBadge === "you"
            && adminBefore.allGroups > 0 && !adminBefore.personalInAllGroups,
            JSON.stringify({ ...adminBefore, auditWhat: undefined }));
        check("the audit log records the personal reveal without the entry's name",
            adminBefore.auditWhat.some((w) => w.startsWith("an entry in a personal vault"))
            && !adminBefore.auditWhat.some((w) => w.includes(PERSONAL_ENTRY)),
            adminBefore.auditWhat.slice(0, 3).join(" | "));
        check("the audit log records the personal vault's export as \"a personal vault\", with the count and no names",
            /^a personal vault · CSV, \d+ entr(y|ies)$/.test(adminBefore.personalExport), adminBefore.personalExport);
        check("the audit log records the all-groups download once, as site.export of \"all groups\" with counts and no names",
            new RegExp(`${USER} site\\.export all groups · CSV, \\d+ groups?, \\d+ entr(y|ies) `).test(adminBefore.siteExport)
            && !adminBefore.siteExport.includes(GROUP) && !adminBefore.siteExport.includes("Personal"), adminBefore.siteExport);

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
        // A site admin given an explicit Viewer membership keeps the edit
        // controls: the service lets site admins write to any shared group,
        // and the page must not hide what the service allows (this regressed once).
        await other.goto(`${BASE}/groups`, { waitUntil: "networkidle2" });
        await other.waitForSelector(".page-header .btn-primary");
        await openDialog(other, ".page-header .btn-primary", "New group");
        await setValue(other, ".modal-panel form > label:nth-of-type(1) input", OTHER_GROUP);
        await sleep(300);
        await submitDialog(other);
        await other.waitForFunction(() => !document.querySelector(".modal-panel"), { timeout: 15000 });
        for (let i = 0; i < 15 && !otherGroupId; i++) {
            await other.goto(`${BASE}/groups`, { waitUntil: "networkidle2" });
            await sleep(800);
            otherGroupId = await other.evaluate((g) =>
                [...document.querySelectorAll('a[href^="/groups/"]')].find((a) => a.textContent.includes(g))?.getAttribute("href").split("/").pop() ?? null, OTHER_GROUP);
        }
        await other.goto(`${BASE}/groups/${otherGroupId}`, { waitUntil: "networkidle2" });
        await other.waitForSelector(".add-member-row", { timeout: 15000 });
        await sleep(600);
        await setValue(other, ".add-member-row input:nth-of-type(1), .add-member-row label:nth-of-type(1) input", USER);
        await other.evaluate(() => { const s = document.querySelector(".add-member-row select"); s.value = "Viewer"; s.dispatchEvent(new Event("change", { bubbles: true })); });
        await sleep(300);
        await clickText(other, ".add-member-row button", "Add member");
        await other.waitForFunction((u) => [...document.querySelectorAll(".members-table .mono")].some((e) => e.textContent.trim() === u), { timeout: 15000 }, USER);
        const membership = await other.evaluate((u) => {
            const row = [...document.querySelectorAll(".members-table tbody tr")].find((r) => r.querySelector(".mono")?.textContent.trim() === u);
            return row?.querySelector("select")?.value ?? row?.querySelector(".badge")?.textContent.trim();
        }, USER);
        // The second account administers a group of its own now, and still may not take every group away.
        const otherArchive = await fetchArchive(other, "/api/admin/export?format=csv");
        check("a group admin who is not a site administrator is refused the all-groups archive with 403",
            otherArchive.status === 403 && !otherArchive.pk && otherArchive.text.includes("Only site administrators"),
            JSON.stringify({ status: otherArchive.status, text: otherArchive.text.slice(0, 80) }));
        await other.close();
        await page.bringToFront();
        const asViewerAdmin = await visitVault(page, otherGroupId);
        check("a site admin with an explicit Viewer membership keeps the edit controls",
            membership === "Viewer" && asViewerAdmin.canAdd && asViewerAdmin.toast === "",
            JSON.stringify({ membership, asViewerAdmin }));

        // ---- 7b. Entry details: a Viewer can read, select and copy the notes, on a phone ----
        // The notes used to live only in a hover tooltip on the name cell, so a
        // read-only member on a touch device could not reach them at all.
        await page.goto(`${BASE}/groups/${id}`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".add-member-row", { timeout: 15000 });
        await sleep(600);
        await setValue(page, ".add-member-row input:nth-of-type(1), .add-member-row label:nth-of-type(1) input", OTHER_USER);
        await page.evaluate(() => { const s = document.querySelector(".add-member-row select"); s.value = "Viewer"; s.dispatchEvent(new Event("change", { bubbles: true })); });
        await sleep(300);
        await clickText(page, ".add-member-row button", "Add member");
        await page.waitForFunction((u) => [...document.querySelectorAll(".members-table .mono")].some((e) => e.textContent.trim() === u), { timeout: 15000 }, OTHER_USER);

        const viewer = await otherContext.newPage();
        await viewer.evaluateOnNewDocument(() => { window.confirm = () => true; });
        await viewer.setViewport({ width: 390, height: 860, isMobile: true, hasTouch: true });
        // Bob is still signed in: his context kept the cookie from section 7.
        await viewer.goto(`${BASE}/vault/${id}`, { waitUntil: "networkidle2" });
        await viewer.waitForSelector(".entries-table", { timeout: 15000 });
        await sleep(1200);
        const viewerRow = await viewer.evaluate((name) => {
            const row = [...document.querySelectorAll(".entries-table tbody tr")].find((r) => r.textContent.includes(name));
            const button = row.querySelector('button[aria-label="Details and notes"]');
            // The imported entries sort above this one, so its card may start below the fold.
            button?.scrollIntoView({ block: "center" });
            const r = button?.getBoundingClientRect();
            const hit = r ? document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2) : null;
            return {
                cards: getComputedStyle(row).display === "grid",
                canEdit: !!row.querySelector('button[aria-label="Edit"]'),
                indicator: row.querySelector(".notes-indicator")?.getAttribute("aria-label") ?? null,
                detailsButton: !!button,
                visible: !!r && r.width > 0 && r.left >= 0 && r.right <= window.innerWidth,
                clickable: !!button && !!hit && button.contains(hit),
                pageFits: document.documentElement.scrollWidth <= window.innerWidth + 1,
            };
        }, ENTRY);
        const viewerTools = await viewer.evaluate(() => ({
            importButton: !!document.querySelector(".vault-toolbar .vault-import"),
            exportButton: !!document.querySelector(".vault-toolbar .vault-export"),
        }));
        const viewerExport = await fetchExport(viewer, `/api/vault/${id}/export?format=csv`);
        check("a Viewer is offered neither Import nor Export, and the export endpoint refuses them with 403",
            !viewerTools.importButton && !viewerTools.exportButton && viewerExport.status === 403
            && !viewerExport.text.includes(IMPORTED_PASSWORD), JSON.stringify({ ...viewerTools, status: viewerExport.status }));
        check("a Viewer on a 390px touch screen sees a card with a notes indicator and a visible, unobstructed Details button",
            viewerRow.cards && !viewerRow.canEdit && viewerRow.indicator === "Has notes" && viewerRow.detailsButton
            && viewerRow.visible && viewerRow.clickable && viewerRow.pageFits, JSON.stringify(viewerRow));

        await viewer.evaluate((name) => [...document.querySelectorAll(".entries-table tbody tr")].find((r) => r.textContent.includes(name))
            .querySelector('button[aria-label="Details and notes"]').focus(), ENTRY);
        for (let i = 0; i < 12 && !(await viewer.$(".modal-panel")); i++) {
            await rowAction(viewer, ENTRY, "Details and notes");
            await sleep(1500);
        }
        await viewer.waitForSelector(".modal-panel .details-notes", { timeout: 8000 });
        await sleep(500);
        const details = await viewer.evaluate(() => {
            const panel = document.querySelector(".modal-panel");
            const notes = panel.querySelector(".details-notes");
            const box = notes.getBoundingClientRect();
            const style = getComputedStyle(notes);
            return {
                role: panel.getAttribute("role"),
                title: document.getElementById(panel.getAttribute("aria-labelledby"))?.textContent,
                notes: notes.textContent,
                tag: notes.tagName,
                preWrap: style.whiteSpace === "pre-wrap",
                selectable: style.userSelect !== "none",
                notInTitleOnly: !notes.closest("[title]"),
                shown: box.width > 0 && box.left >= 0 && box.right <= window.innerWidth,
                copyNotes: !!panel.querySelector('button[aria-label="Copy notes"]'),
                labels: [...panel.querySelectorAll("dt")].map((e) => e.textContent).join(","),
                twoFa: [...panel.querySelectorAll("dt")].find((e) => e.textContent === "2FA")?.nextElementSibling.textContent.trim(),
                updatedBy: panel.querySelector(".details-list dd .mono:not(.details-username)")?.textContent.trim(),
                insideDialog: panel.contains(document.activeElement),
            };
        });
        check("the Viewer's details dialog is a labelled dialog showing the notes as selectable text, with a copy button",
            details.role === "dialog" && details.title === `Details · ${ENTRY}` && details.notes === NOTES
            && details.tag === "PRE" && details.preWrap && details.selectable && details.notInTitleOnly
            && details.shown && details.copyNotes && details.insideDialog, JSON.stringify(details));
        check("the details also give the password's last editor, 2FA state and the other fields",
            details.labels === "Name,URL,Username,Password last changed,2FA"
            && details.updatedBy === USER && details.twoFa === "Configured", JSON.stringify(details));

        await viewer.evaluate(() => document.querySelector('.modal-panel button[aria-label="Copy notes"]').click());
        await viewer.waitForFunction(() => /copied|Copy failed/.test(document.querySelector(".toast")?.textContent ?? ""), { timeout: 8000 });
        check("Copy notes answers with a toast", true);

        await viewer.evaluate(() => document.body.dispatchEvent(
            new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true })));
        await viewer.waitForFunction(() => !document.querySelector(".modal-panel"), { timeout: 8000 });
        await sleep(400);
        check("Escape closes the details and focus returns to the Details button",
            (await focused(viewer)) === "button:Details and notes", await focused(viewer));

        // An entry without notes says so, and its row carries no indicator.
        const weakIndicator = await viewer.evaluate((name) =>
            !![...document.querySelectorAll(".entries-table tbody tr")].find((r) => r.textContent.includes(name)).querySelector(".notes-indicator"), WEAK_ENTRY);
        for (let i = 0; i < 12 && !(await viewer.$(".modal-panel")); i++) {
            await rowAction(viewer, WEAK_ENTRY, "Details and notes");
            await sleep(1500);
        }
        await viewer.waitForSelector(".modal-panel .details-notes-state", { timeout: 8000 });
        const noNotes = await viewer.evaluate(() => document.querySelector(".modal-panel .details-notes-state").textContent.trim());
        check("an entry without notes shows no indicator and the details say \"No notes\"",
            !weakIndicator && noNotes === "No notes", JSON.stringify({ weakIndicator, noNotes }));
        await viewer.evaluate(() => document.querySelector(".modal-close").click());
        await viewer.waitForFunction(() => !document.querySelector(".modal-panel"), { timeout: 8000 });
        await viewer.close();

        // ---- 7c. Purge: not for members, for the group's admins, and a deleted group from Administration ----
        // Its own group: the admin creates it, the second account joins as a
        // Member, three entries are created and deleted.
        await page.goto(`${BASE}/groups`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".page-header .btn-primary");
        await openDialog(page, ".page-header .btn-primary", "New group");
        await setValue(page, ".modal-panel form > label:nth-of-type(1) input", PURGE_GROUP);
        await sleep(300);
        await submitDialog(page);
        await page.waitForFunction(() => !document.querySelector(".modal-panel"), { timeout: 15000 });
        for (let i = 0; i < 15 && !purgeGroupId; i++) {
            await page.goto(`${BASE}/groups`, { waitUntil: "networkidle2" });
            await sleep(800);
            purgeGroupId = await page.evaluate((g) =>
                [...document.querySelectorAll('a[href^="/groups/"]')].find((a) => a.textContent.includes(g))?.getAttribute("href").split("/").pop() ?? null, PURGE_GROUP);
        }
        await page.goto(`${BASE}/groups/${purgeGroupId}`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".add-member-row", { timeout: 15000 });
        await sleep(600);
        await setValue(page, ".add-member-row input:nth-of-type(1), .add-member-row label:nth-of-type(1) input", OTHER_USER);
        await page.evaluate(() => { const s = document.querySelector(".add-member-row select"); s.value = "Member"; s.dispatchEvent(new Event("change", { bubbles: true })); });
        await sleep(300);
        await clickText(page, ".add-member-row button", "Add member");
        await page.waitForFunction((u) => [...document.querySelectorAll(".members-table .mono")].some((e) => e.textContent.trim() === u), { timeout: 15000 }, OTHER_USER);
        await visitVault(page, purgeGroupId);
        for (const name of PURGE_ENTRIES) {
            await createEntry(page, name, "Purge-Me!2468");
        }
        for (const name of PURGE_ENTRIES) {
            await rowAction(page, name, "Delete");
            await page.waitForFunction((n) => !document.querySelector(".entries-table")?.textContent.includes(n), { timeout: 10000 }, name);
        }

        // What the trash offers whoever is looking at it.
        const trashState = (p) => p.evaluate(() => ({
            summary: document.querySelector("details.trash summary")?.textContent.trim(),
            rows: [...document.querySelectorAll(".trash tbody tr")].map((r) => r.querySelector(".entry-name")?.textContent.trim()),
            restore: [...document.querySelectorAll(".trash .cell-actions button")].filter((b) => b.textContent.trim() === "Restore").length,
            purge: document.querySelectorAll(".trash .purge-entry").length,
            emptyBin: !!document.querySelector(".trash .empty-bin"),
        }));
        // Click a control until its confirmation shows (the circuit may not be attached yet), and read it.
        const openConfirm = async (p, click, arg = null) => {
            for (let i = 0; i < 12 && !(await p.$(".modal-panel .purge-confirm")); i++) {
                await p.evaluate(click, arg);
                await sleep(700);
            }
            return p.evaluate(() => ({
                title: document.querySelector(".modal-panel h2")?.textContent.trim(),
                text: document.querySelector(".modal-panel .purge-confirm")?.textContent.replace(/\s+/g, " ").trim() ?? "",
                confirm: document.querySelector(".modal-panel .purge-confirm-button")?.textContent.trim(),
            }));
        };
        const confirmPurge = async (p) => {
            await p.evaluate(() => document.querySelector(".modal-panel .purge-confirm-button").click());
            await p.waitForFunction(() => !document.querySelector(".modal-panel"), { timeout: 30000 });
            await sleep(800);
        };

        const member = await otherContext.newPage();
        await member.evaluateOnNewDocument(() => { window.confirm = () => true; });
        await member.setViewport({ width: 1280, height: 860 });
        await visitVault(member, purgeGroupId);
        const asMember = await trashState(member);
        check("a member sees Restore on every deleted entry but neither Purge nor Empty recycle bin",
            asMember.restore === 3 && asMember.purge === 0 && !asMember.emptyBin, JSON.stringify(asMember));

        // Promote the member to the group's admin: a group admin who is not a site administrator purges.
        await page.goto(`${BASE}/groups/${purgeGroupId}`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".members-table", { timeout: 15000 });
        await sleep(600);
        await page.evaluate((u) => {
            const row = [...document.querySelectorAll(".members-table tbody tr")].find((r) => r.querySelector(".mono")?.textContent.trim() === u);
            const select = row.querySelector("select");
            select.value = "Admin";
            select.dispatchEvent(new Event("change", { bubbles: true }));
        }, OTHER_USER);
        await sleep(1500);
        await visitVault(member, purgeGroupId);
        const asAdmin = await trashState(member);
        const purgeDialog = await openConfirm(member, (name) => [...document.querySelectorAll(".trash tbody tr")]
            .find((r) => r.textContent.includes(name))?.querySelector(".purge-entry")?.click(), PURGE_ENTRIES[0]);
        check("the group admin's Purge asks first: it names the entry and says it cannot be undone and leaves every site",
            asAdmin.purge === 3 && asAdmin.emptyBin && purgeDialog.title === "Purge password"
            && purgeDialog.text.includes(PURGE_ENTRIES[0]) && purgeDialog.text.includes("cannot be undone")
            && purgeDialog.text.includes("every site") && purgeDialog.confirm === "Purge",
            JSON.stringify({ asAdmin: { purge: asAdmin.purge, emptyBin: asAdmin.emptyBin }, purgeDialog }));
        await confirmPurge(member);
        const afterPurge = await trashState(member);
        await visitVault(member, purgeGroupId);
        const afterReload = await trashState(member);
        check("the purged entry is gone from the recycle bin, with no Restore for it, the others still restorable",
            !afterPurge.rows.includes(PURGE_ENTRIES[0]) && afterReload.summary === "Recently deleted (2)"
            && !afterReload.rows.includes(PURGE_ENTRIES[0]) && afterReload.restore === 2,
            JSON.stringify(afterReload));

        const emptyDialog = await openConfirm(member, () => document.querySelector(".trash .empty-bin")?.click());
        await confirmPurge(member);
        await visitVault(member, purgeGroupId);
        const emptied = await trashState(member);
        check("Empty recycle bin asks first with the count, then purges every deleted entry",
            emptyDialog.title === "Empty recycle bin" && emptyDialog.text.includes("2 deleted passwords")
            && emptyDialog.text.includes("cannot be undone") && emptyDialog.text.includes("every site")
            && emptied.summary === "Recently deleted (0)" && emptied.rows.length === 0 && !emptied.emptyBin,
            JSON.stringify({ emptyDialog, emptied }));
        await member.close();
        await page.bringToFront();

        // Delete the group, then purge it from Administration.
        await page.goto(`${BASE}/groups/${purgeGroupId}`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".panel-danger .btn-danger", { timeout: 15000 });
        for (let i = 0; i < 12 && !purgeGroupDeleted; i++) {
            await page.evaluate(() => document.querySelector(".panel-danger .btn-danger")?.click());
            try {
                await page.waitForFunction(() => location.pathname === "/groups", { timeout: 1500 });
                purgeGroupDeleted = true;
            } catch { /* circuit not attached yet */ }
        }
        await page.goto(`${BASE}/admin`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".audit-table", { timeout: 15000 });
        await sleep(1200);
        const groupDialog = await openConfirm(page, (g) => [...document.querySelectorAll(".group-card")]
            .find((c) => c.querySelector(".group-card-name")?.textContent.trim() === g)?.querySelector(".purge-group")?.click(), PURGE_GROUP);
        await confirmPurge(page);
        await page.goto(`${BASE}/admin`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".audit-table", { timeout: 15000 });
        await sleep(1200);
        const adminAfterPurge = await page.evaluate((g) => ({
            deletedListed: [...document.querySelectorAll(".group-card-name")].some((n) => n.textContent.trim() === g),
            audit: [...document.querySelectorAll(".audit-table tbody tr")].slice(0, 40).map((r) => ({
                action: r.querySelector("td:nth-child(3)")?.textContent.trim(),
                what: r.querySelector("td:nth-child(4)")?.textContent.replace(/\s+/g, " ").trim(),
            })),
        }), PURGE_GROUP);
        check("a deleted group is purged from Administration after a confirmation, and is no longer listed",
            groupDialog.title === "Purge a deleted group" && groupDialog.text.includes(PURGE_GROUP)
            && groupDialog.text.includes("cannot be undone") && groupDialog.confirm === "Purge group"
            && !adminAfterPurge.deletedListed, JSON.stringify({ groupDialog, deletedListed: adminAfterPurge.deletedListed }));
        const logged = (action, what) => adminAfterPurge.audit.some((e) => e.action === action && what(e.what || ""));
        check("the audit log shows entry.purge, bin.empty (with the count) and group.purge",
            logged("entry.purge", (w) => w.includes(PURGE_ENTRIES[0]) && w.includes(PURGE_GROUP))
            && logged("bin.empty", (w) => w.startsWith(PURGE_GROUP) && w.includes("2 entries"))
            && logged("group.purge", (w) => w.startsWith(PURGE_GROUP) && w.includes("0 entries")),
            JSON.stringify(adminAfterPurge.audit.filter((e) => /purge|bin/.test(e.action || ""))));

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
            if (otherGroupId) {
                cleaned = (await deleteGroup(otherGroupId)) && cleaned;
            }
            if (purgeGroupId && !purgeGroupDeleted) {
                cleaned = (await deleteGroup(purgeGroupId)) && cleaned;
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
        fs.rmSync(csvPath, { force: true });
        await browser.close();
    }

    const failed = results.filter((r) => !r.ok).length;
    console.log(`\n${results.length - failed}/${results.length} checks passed`);
    process.exit(failed === 0 ? 0 : 1);
})();
