// Captures the screenshots used by docs/user-manual.md.
//
// Run it against a THROWAWAY stack (never the demo): it signs in as the three
// Development-mode accounts, fills the site with example groups, passwords,
// members and an offline copy, and leaves all of it behind. Expects alice (a
// site administrator), bob and carol, offline access enabled, and ideally a
// replication peer so the Administration page has something to show.
//
//   HARPO_BASE_URL=http://localhost:8091 node manual-screenshots.js
//
// Images land in docs/manual (override with HARPO_SHOTS_DIR). Full pages are
// captured at 1x and dialogs at 2x, so the text in a clipped dialog stays
// readable when the manual scales it down.
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const puppeteer = require("puppeteer");

const BASE = process.env.HARPO_BASE_URL || "http://localhost:8091";
const OUT = process.env.HARPO_SHOTS_DIR || path.join(__dirname, "..", "..", "docs", "manual");
const PASSPHRASE = "correct horse battery staple";
const TOTP = "JBSWY3DPEHPK3PXP";
const FULL = { width: 1440, height: 900, deviceScaleFactor: 1 };
// Tall enough for the longest dialog to show whole instead of scrolling inside itself.
const TALL = { width: 1440, height: 1500, deviceScaleFactor: 2 };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Synthetic input throughout: once a Blazor circuit is attached, headless
// Chrome's trusted input no longer reaches the page (see ui.e2e.js).
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

const click = (page, selector) => page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) {
        throw new Error("missing " + sel);
    }
    el.click();
}, selector);

const submitDialog = (page) => page.evaluate(() => document.querySelector(".modal-panel form").requestSubmit());
const noDialog = (page) => page.waitForFunction(() => !document.querySelector(".modal-panel"), { timeout: 15000 });

async function signIn(page, user, password) {
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

async function openDialog(page, buttonSelector, buttonText) {
    for (let i = 0; i < 12; i++) {
        await clickText(page, buttonSelector, buttonText);
        try {
            await page.waitForSelector(".modal-panel", { timeout: 2500 });
            await sleep(500);
            return;
        } catch { /* circuit not attached yet */ }
    }
    throw new Error(`the "${buttonText}" dialog did not open`);
}

async function openVault(page, id) {
    await page.goto(`${BASE}/vault/${id}`, { waitUntil: "networkidle2" });
    await page.waitForSelector(".vault-toolbar", { timeout: 15000 });
    await sleep(1200);
}

async function createGroup(page, name, description) {
    await page.goto(`${BASE}/groups`, { waitUntil: "networkidle2" });
    await page.waitForSelector(".page-header .btn-primary");
    await openDialog(page, ".page-header .btn-primary", "New group");
    await setValue(page, ".modal-panel form > label:nth-of-type(1) input", name);
    await setValue(page, ".modal-panel form > label:nth-of-type(2) input", description);
    await sleep(300);
    await submitDialog(page);
    await noDialog(page);
    for (let i = 0; i < 15; i++) {
        await page.goto(`${BASE}/groups`, { waitUntil: "networkidle2" });
        await sleep(700);
        const href = await page.evaluate((g) =>
            [...document.querySelectorAll('a[href^="/groups/"]')].find((a) => a.textContent.includes(g))?.getAttribute("href"), name);
        if (href) {
            return href.split("/").pop();
        }
    }
    throw new Error(`group ${name} never appeared`);
}

// Fills the "New password" dialog on the open vault. `icon` is one of the
// picker's preset emoji; left out, the URL may pick a catalogue icon by itself.
async function createEntry(page, { name, icon, url = "", username = "", password, totp = "", notes = "" }) {
    await openDialog(page, ".vault-toolbar .btn-primary", "New password");
    await setValue(page, ".modal-panel form > label:nth-of-type(1) input", name);
    if (icon) {
        await clickText(page, ".modal-panel .icon-option", icon);
    }
    if (url) {
        await setValue(page, '.modal-panel input[placeholder="https://…"]', url);
    }
    if (username) {
        await setValue(page, '.modal-panel input[placeholder^="Account this"]', username);
    }
    await setValue(page, ".modal-panel .password-row input", password);
    if (totp) {
        await setValue(page, '.modal-panel input[placeholder^="base32"]', totp);
    }
    if (notes) {
        await setValue(page, ".modal-panel textarea", notes);
    }
    await sleep(500);
    await submitDialog(page);
    await page.waitForFunction(
        (n) => !document.querySelector(".modal-panel") && document.querySelector(".entries-table")?.textContent.includes(n),
        { timeout: 15000 }, name);
    await sleep(300);
}

const rowAction = (page, entryName, label) => page.evaluate((name, lbl) => {
    const row = [...document.querySelectorAll(".entries-table tbody tr")].find((r) => r.textContent.includes(name));
    const button = row?.querySelector(`button[aria-label="${lbl}"], button[title="${lbl}"]`);
    if (!button) {
        throw new Error(`no "${lbl}" control on the row for ${name}`);
    }
    button.click();
}, entryName, label);

async function changePassword(page, entryName, newPassword) {
    await rowAction(page, entryName, "Edit");
    await page.waitForSelector(".modal-panel .password-row input", { timeout: 10000 });
    await sleep(400);
    await setValue(page, ".modal-panel .password-row input", newPassword);
    await sleep(300);
    await submitDialog(page);
    await noDialog(page);
    await sleep(500);
}

async function addMember(page, username, role) {
    await setValue(page, "#new-member-username", username);
    await sleep(900); // suggestions
    await page.evaluate((r) => {
        const s = document.querySelector(".add-member-row select");
        s.value = r;
        s.dispatchEvent(new Event("change", { bubbles: true }));
    }, role);
    await clickText(page, ".add-member-row button", "Add member");
    await page.waitForFunction((u) => [...document.querySelectorAll(".members-table tbody tr")].some((r) => r.textContent.includes(u)),
        { timeout: 15000 }, username);
    await sleep(400);
}

async function dialogShot(page, file) {
    await page.setViewport(TALL);
    await sleep(700);
    const panel = await page.$(".modal-panel");
    await panel.screenshot({ path: path.join(OUT, file) });
    await page.setViewport(FULL);
    await sleep(400);
    console.log("shot", file);
}

async function elementShot(page, selector, file, scale = 2) {
    await page.setViewport({ ...FULL, deviceScaleFactor: scale });
    await sleep(600);
    const el = await page.$(selector);
    await el.screenshot({ path: path.join(OUT, file) });
    await page.setViewport(FULL);
    await sleep(400);
    console.log("shot", file);
}

// The smallest rectangle holding every element the selectors match, at 2x.
async function regionShot(page, selectors, file) {
    const box = await page.evaluate((sels) => {
        const rects = sels.flatMap((s) => [...document.querySelectorAll(s)]).map((e) => e.getBoundingClientRect());
        const left = Math.min(...rects.map((r) => r.left)) - 8;
        const top = Math.min(...rects.map((r) => r.top)) - 8;
        const right = Math.max(...rects.map((r) => r.right)) + 8;
        const bottom = Math.max(...rects.map((r) => r.bottom)) + 8;
        return { x: left + window.scrollX, y: top + window.scrollY, width: right - left, height: bottom - top };
    }, selectors);
    await page.screenshot({ path: path.join(OUT, file), clip: box });
    console.log("shot", file);
}

async function pageShot(page, file, fullPage = false) {
    await sleep(500);
    await page.screenshot({ path: path.join(OUT, file), fullPage });
    console.log("shot", file);
}

(async () => {
    fs.mkdirSync(OUT, { recursive: true });
    const browser = await puppeteer.launch({ headless: "new", args: ["--no-first-run"] });
    const page = await browser.newPage();
    await page.evaluateOnNewDocument(() => { window.confirm = () => true; });
    await page.setViewport(FULL);

    try {
        // ---- Sign-in page ----
        await page.goto(`${BASE}/login`, { waitUntil: "networkidle2" });
        await pageShot(page, "sign-in.png");
        await signIn(page, "alice", "alice");

        // ---- Groups ----
        const infra = await createGroup(page, "Infrastructure", "Servers, network gear and cloud consoles");
        const marketing = await createGroup(page, "Marketing", "Social accounts and agency portals");
        const finance = await createGroup(page, "Finance", "Banking and payroll");

        // ---- Infrastructure entries ----
        await openVault(page, infra);
        await createEntry(page, { name: "Core router", icon: "🛠️", url: "https://10.0.0.1", username: "admin",
            password: "Rk7#vq2Lm9!xPz4W",
            notes: "Serial console: 115200 8N1 on the second port.\nConfig backups land on the NAS every night at 02:00." });
        await createEntry(page, { name: "AWS root account", icon: "☁️", url: "https://console.aws.amazon.com",
            username: "ops@example.com", password: "Tq8$wn3Hc6!zYv2M", totp: TOTP,
            notes: "Recovery codes (each works once):\n4F9K-22QX\n8HTR-01MZ\nQ2PL-77AB\n\nBilling alerts go to ops@example.com." });
        await createEntry(page, { name: "Backup NAS", icon: "🗄️", url: "https://nas.office.example.com", username: "backup",
            password: "Summer2019!" });
        await createEntry(page, { name: "Office Wi-Fi", icon: "🌐", username: "", password: "Summer2019!" });
        await createEntry(page, { name: "Printer admin", icon: "🖥️", url: "http://print.office.example.com", username: "admin",
            password: "admin1234" });
        await createEntry(page, { name: "Harpo demo", url: "https://harpo.example.com", username: "alice",
            password: "Vb4!mk8Qz2#rLp7X" });
        await createEntry(page, { name: "Legacy VPN", icon: "🔑", url: "https://vpn-old.example.com", username: "vpnadmin",
            password: "Gh5@kd9Wq1!sNx3C" });
        await changePassword(page, "Core router", "Jm3!xw7Rp2#qBv9Z");
        await changePassword(page, "Core router", "Zt6#hn4Kc8!wQy1L");
        await rowAction(page, "Legacy VPN", "Delete");
        await page.waitForFunction(() => !document.querySelector(".entries-table")?.textContent.includes("Legacy VPN"), { timeout: 15000 });

        // ---- Marketing entries ----
        await openVault(page, marketing);
        await createEntry(page, { name: "Corporate Twitter", icon: "💬", url: "https://x.com", username: "@example_corp",
            password: "Pw9!zx3Mn7#kQr5T", totp: TOTP });
        await createEntry(page, { name: "Mailchimp", icon: "📧", url: "https://mailchimp.com", username: "admin@example.com",
            password: "Ld2#vb8Yq4!nHx6W" });
        await createEntry(page, { name: "Agency portal", icon: "🎫", url: "https://portal.agency.example", username: "example-corp",
            password: "Xc7!qp2Zr9#mKt4V" });

        // ---- Finance entries ----
        await openVault(page, finance);
        await createEntry(page, { name: "Online banking", icon: "🏦", url: "https://business.bank.example", username: "00412345",
            password: "Nr5#kz8Wq2!xVb7M", totp: TOTP });
        await createEntry(page, { name: "Payroll provider", icon: "💳", url: "https://payroll.example.com", username: "finance@example.com",
            password: "Qw3!hs9Lp6#zTn2R" });

        // ---- Alice's personal vault ----
        await page.goto(`${BASE}/`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".personal-list .group-item", { timeout: 15000 });
        const personal = await page.evaluate(() => document.querySelector(".personal-list .group-item").getAttribute("href").split("/").pop());
        await openVault(page, personal);
        await createEntry(page, { name: "My GitHub", icon: "📦", url: "https://github.com", username: "alice-liddell",
            password: "Hy8!tn2Qw6#rKz4P", totp: TOTP });
        await createEntry(page, { name: "Pension portal", icon: "📊", url: "https://pension.example.org", username: "AL123456",
            password: "Bv2#qm7Zx9!wLs5N" });
        await pageShot(page, "personal-vault.png");

        // ---- Members ----
        await page.goto(`${BASE}/groups/${infra}`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".add-member-row", { timeout: 15000 });
        await sleep(800);
        await addMember(page, "bob", "Member");
        await page.setViewport({ ...FULL, deviceScaleFactor: 2 });
        await sleep(600);
        await setValue(page, "#new-member-username", "car");
        await page.waitForSelector(".member-suggestions", { timeout: 10000 });
        await sleep(500);
        await regionShot(page, [".add-member-row", ".member-suggestions"], "member-suggestions.png");
        await click(page, ".member-suggestion");
        await page.setViewport(FULL);
        await sleep(600);
        await page.evaluate(() => {
            const s = document.querySelector(".add-member-row select");
            s.value = "Viewer";
            s.dispatchEvent(new Event("change", { bubbles: true }));
        });
        await clickText(page, ".add-member-row button", "Add member");
        await page.waitForFunction(() => [...document.querySelectorAll(".members-table tbody tr")].some((r) => r.textContent.includes("carol")),
            { timeout: 15000 });
        await sleep(800);
        await pageShot(page, "group-detail.png", true);

        await page.goto(`${BASE}/groups/${marketing}`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".add-member-row", { timeout: 15000 });
        await sleep(800);
        await addMember(page, "bob", "Admin");
        await addMember(page, "carol", "Member");
        await page.goto(`${BASE}/groups/${finance}`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".add-member-row", { timeout: 15000 });
        await sleep(800);
        await addMember(page, "carol", "Viewer");

        await page.goto(`${BASE}/groups`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".card-list", { timeout: 15000 });
        await pageShot(page, "groups.png");

        // ---- The vault page ----
        await openVault(page, infra);
        await rowAction(page, "Core router", "Reveal password");
        await page.evaluate(() => document.querySelector(".totp-chip").click());
        await page.waitForSelector(".totp-group", { timeout: 10000 });
        await sleep(800);
        await pageShot(page, "vault.png");

        await openDialog(page, ".vault-toolbar .btn-primary", "New password");
        await setValue(page, ".modal-panel form > label:nth-of-type(1) input", "Monitoring (Grafana)");
        await clickText(page, ".modal-panel .icon-option", "📊");
        await setValue(page, '.modal-panel input[placeholder="https://…"]', "https://grafana.example.com");
        await setValue(page, '.modal-panel input[placeholder^="Account this"]', "admin");
        await clickText(page, ".modal-panel .password-row button", "Generate");
        await sleep(400);
        await page.evaluate(() => document.querySelector('.modal-panel .password-row button[title="Generator options"]').click());
        await sleep(600);
        await dialogShot(page, "new-password.png");
        await page.evaluate(() => document.querySelector(".modal-close").click());
        await noDialog(page);

        await rowAction(page, "AWS root account", "Details and notes");
        await page.waitForSelector(".details-list", { timeout: 10000 });
        await dialogShot(page, "details.png");
        await page.evaluate(() => document.querySelector(".modal-close").click());
        await noDialog(page);

        await rowAction(page, "Core router", "Password history");
        await page.waitForSelector(".history-table", { timeout: 10000 });
        await sleep(400);
        await page.evaluate(() => document.querySelectorAll(".history-table tbody tr")[1].querySelector('button[aria-label="Reveal this password"]').click());
        await sleep(800);
        await dialogShot(page, "history.png");
        await page.evaluate(() => document.querySelector(".modal-close").click());
        await noDialog(page);

        await setValue(page, ".vault-toolbar .search", "admin");
        await page.waitForSelector(".search-hits", { timeout: 10000 });
        await sleep(600);
        await pageShot(page, "search.png");
        await setValue(page, ".vault-toolbar .search", "");
        await sleep(600);

        await page.evaluate(() => { document.querySelector("details.trash").open = true; });
        await sleep(600);
        await elementShot(page, "details.trash", "trash.png");

        // ---- Import and export: the dialogs only; nothing is imported or downloaded ----
        // A KeePassXC export, cut to the columns that fit the dialog; the file name shows in the shot.
        const importDir = fs.mkdtempSync(path.join(os.tmpdir(), "harpo-manual-"));
        const importFile = path.join(importDir, "keepass-export.csv");
        fs.writeFileSync(importFile, [
            "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\"",
            "\"Network\",\"Firewall\",\"admin\",\"Fw3!kq8Zr2#mLx6T\",\"https://fw.office.example.com\"",
            "\"Network\",\"Switch stack\",\"admin\",\"Sw5#np2Vq8!tKz4R\",\"https://10.0.0.2\"",
            "\"Cloud\",\"DNS provider\",\"ops@example.com\",\"Dn7!wx3Lq9#bRt2M\",\"https://dns.example.net\"",
            "",
        ].join("\r\n"));
        await openDialog(page, ".vault-toolbar .vault-import", "Import");
        await (await page.$('.modal-panel input[type="file"]')).uploadFile(importFile);
        await page.waitForSelector(".modal-panel .import-preview", { timeout: 15000 });
        await sleep(500);
        await dialogShot(page, "import.png");
        await page.evaluate(() => document.querySelector(".modal-close").click());
        await noDialog(page);
        fs.rmSync(importDir, { recursive: true, force: true });

        await openDialog(page, ".vault-toolbar .vault-export", "Export");
        await dialogShot(page, "export.png");
        await page.evaluate(() => document.querySelector(".modal-close").click());
        await noDialog(page);

        // ---- Vault health ----
        await page.goto(`${BASE}/health`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".stat-row", { timeout: 20000 });
        await sleep(800);
        await pageShot(page, "health.png", true);

        // ---- Offline vault ----
        await page.goto(`${BASE}/offline.html`, { waitUntil: "networkidle2" });
        await page.waitForSelector("#state-setup:not(.hidden)", { timeout: 15000 });
        await pageShot(page, "offline-setup.png");
        await setValue(page, "#setupPass", PASSPHRASE);
        await setValue(page, "#setupPass2", PASSPHRASE);
        await click(page, "#setupBtn");
        await page.waitForSelector("#state-vault:not(.hidden)", { timeout: 40000 });
        await page.waitForFunction(() => document.getElementById("toast").classList.contains("hidden"), { timeout: 20000 });
        await sleep(500);
        await pageShot(page, "offline-vault.png", true);

        // ---- Bob gets a personal vault too, so the admin table shows more than one ----
        const bobContext = await browser.createBrowserContext();
        const bob = await bobContext.newPage();
        await bob.setViewport(FULL);
        await signIn(bob, "bob", "bob");
        await bob.waitForSelector(".personal-list .group-item", { timeout: 15000 });
        const bobPersonal = await bob.evaluate(() => document.querySelector(".personal-list .group-item").getAttribute("href").split("/").pop());
        await openVault(bob, bobPersonal);
        await createEntry(bob, { name: "Train season ticket", icon: "🎫", url: "https://tickets.example", username: "bob.loblaw",
            password: "Fk6!pw3Nz8#qXt2V" });
        await bobContext.close();

        // ---- Carol as a Viewer ----
        const carolContext = await browser.createBrowserContext();
        const carol = await carolContext.newPage();
        await carol.setViewport(FULL);
        await signIn(carol, "carol", "carol");
        await openVault(carol, infra);
        await pageShot(carol, "viewer.png");
        await carol.setViewport({ width: 390, height: 844, deviceScaleFactor: 2 });
        await openVault(carol, infra);
        await rowAction(carol, "AWS root account", "Details and notes");
        await carol.waitForSelector(".details-list", { timeout: 10000 });
        await sleep(600);
        await pageShot(carol, "mobile-details.png");
        await carolContext.close();

        // ---- Administration ----
        await page.goto(`${BASE}/admin`, { waitUntil: "networkidle2" });
        await page.waitForSelector(".peers-table, #replication", { timeout: 15000 });
        await page.waitForFunction(() => document.querySelector(".audit-table"), { timeout: 20000 });
        await sleep(1200);
        await pageShot(page, "admin.png");
        await elementShot(page, "#audit", "admin-audit.png", 1);
        await elementShot(page, "#personal-vaults", "admin-personal-vaults.png", 1);
        await clickText(page, "#personal-vaults button", "Take over");
        await page.waitForSelector(".modal-panel", { timeout: 10000 });
        await sleep(500);
        await dialogShot(page, "takeover.png");
        await page.evaluate(() => document.querySelector(".modal-close").click());
        await noDialog(page);

        // ---- A vault long enough to page: last, so the shots above keep their small example data ----
        const archive = await createGroup(page, "Archive", "Retired systems, kept for reference");
        const archiveDir = fs.mkdtempSync(path.join(os.tmpdir(), "harpo-manual-"));
        const archiveFile = path.join(archiveDir, "archive.csv");
        const letters = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        fs.writeFileSync(archiveFile, ["Title,Username,Password,URL", ...Array.from({ length: 60 }, (_, i) => {
            const n = String(i + 1).padStart(2, "0");
            const password = Array.from({ length: 16 }, (_, j) => letters[(i * 31 + j * 17 + 7) % letters.length]).join("") + "!";
            return `Retired server ${n},admin,${password},https://srv${n}.old.example.com`;
        }), ""].join("\r\n"));
        await openVault(page, archive);
        await openDialog(page, ".vault-toolbar .vault-import", "Import");
        await (await page.$('.modal-panel input[type="file"]')).uploadFile(archiveFile);
        await page.waitForSelector(".modal-panel .import-confirm", { timeout: 15000 });
        await page.evaluate(() => document.querySelector(".modal-panel .import-confirm").click());
        await page.waitForSelector(".modal-panel .import-summary", { timeout: 30000 });
        await clickText(page, ".modal-panel .btn-primary", "Done");
        await noDialog(page);
        fs.rmSync(archiveDir, { recursive: true, force: true });
        await page.waitForSelector(".pager", { timeout: 15000 });
        await sleep(600);
        await regionShot(page, [".entries-table tbody tr:nth-last-child(-n+3)", ".pager"], "vault-pager.png");

        console.log("done");
    } finally {
        await browser.close();
    }
})().catch((e) => {
    console.error(e);
    process.exit(1);
});
