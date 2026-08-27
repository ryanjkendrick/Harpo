// Harpo offline vault.
//
// While online and signed in, this page downloads the user's accessible entries
// from /api/offline/snapshot and stores them on the device encrypted under an
// offline passphrase the user chooses:
//
//   KEK = PBKDF2-SHA256(passphrase, salt, 600k iterations)
//   DEK = random AES-256-GCM key, stored wrapped by the KEK
//   vault blob = AES-256-GCM(DEK, snapshot JSON)  → IndexedDB
//
// Offline, the passphrase unwraps the DEK and decrypts the blob — read-only.
// The server master key is never on the device; the server re-encrypts nothing
// here — it hands the snapshot to *this authenticated user*, and the device
// protects it locally. All rendering uses textContent (never innerHTML).
"use strict";

const DB_NAME = "harpo-offline";
const STORE = "vault";
const RECORD_KEY = "current";
const PBKDF2_ITERATIONS = 600000;
const AUTO_LOCK_MS = 10 * 60 * 1000;

let dek = null;          // in-memory only while unlocked
let vaultData = null;    // decrypted snapshot while unlocked
let record = null;       // encrypted record from IndexedDB
let idleTimer = null;

// ---------- tiny helpers ----------

const $ = (id) => document.getElementById(id);
function b64(buf) {
    // Chunked to keep large vault blobs from overflowing the argument stack.
    const bytes = new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
        s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(s);
}
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const utf8 = (s) => new TextEncoder().encode(s);

function show(stateId) {
    for (const sec of document.querySelectorAll("section")) {
        sec.classList.toggle("hidden", sec.id !== stateId);
    }
}

function showMessage(title, body, { loginLink = false, wipe = false } = {}) {
    $("messageTitle").textContent = title;
    $("messageBody").textContent = body;
    $("messageLoginLink").classList.toggle("hidden", !loginLink);
    $("wipeBtn3").classList.toggle("hidden", !wipe);
    show("state-message");
}

let toastTimer = null;
function toast(text) {
    const el = $("toast");
    el.textContent = text;
    el.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.add("hidden"), 2500);
}

function setError(id, text) {
    const el = $(id);
    if (text) {
        el.textContent = text;
        el.classList.remove("hidden");
    } else {
        el.classList.add("hidden");
    }
}

// navigator.onLine only knows about the network; the case this page exists for
// is "network up, Harpo server down" — so track actual server reachability too.
let serverReachable = null;

function noteServer(ok) {
    serverReachable = ok;
    updateNetBadge();
}

function updateNetBadge() {
    const el = $("netBadge");
    el.classList.remove("online", "warn");
    if (!navigator.onLine) {
        el.textContent = "offline";
    } else if (serverReachable === false) {
        el.textContent = "server unreachable";
        el.classList.add("warn");
    } else {
        el.textContent = "online";
        el.classList.add("online");
    }
    // The way back to the main app — crucial in the installed PWA, which has no
    // address bar. Shown only while Harpo is reachable; while it isn't, the
    // link would just bounce off the service worker back to this page.
    $("backLink").classList.toggle("hidden", !navigator.onLine || serverReachable === false);
}

// ---------- IndexedDB ----------

function openDb() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, 1);
        req.onupgradeneeded = () => req.result.createObjectStore(STORE);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function idbGet() {
    const db = await openDb();
    return new Promise((resolve, reject) => {
        const req = db.transaction(STORE).objectStore(STORE).get(RECORD_KEY);
        req.onsuccess = () => { resolve(req.result || null); db.close(); };
        req.onerror = () => { reject(req.error); db.close(); };
    });
}

async function idbPut(value) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, "readwrite");
        tx.objectStore(STORE).put(value, RECORD_KEY);
        tx.oncomplete = () => { resolve(); db.close(); };
        tx.onerror = () => { reject(tx.error); db.close(); };
    });
}

async function idbWipe() {
    const db = await openDb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, "readwrite");
        tx.objectStore(STORE).delete(RECORD_KEY);
        tx.oncomplete = () => { resolve(); db.close(); };
        tx.onerror = () => { reject(tx.error); db.close(); };
    });
}

// ---------- crypto ----------

async function deriveKek(passphrase, salt, iterations) {
    const material = await crypto.subtle.importKey("raw", utf8(passphrase), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
        material,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]);
}

async function encryptWithKey(key, bytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
    return { iv: b64(iv), ct: b64(ct) };
}

async function decryptWithKey(key, ivB64, ctB64) {
    return crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(ivB64) }, key, unb64(ctB64));
}

async function encryptVaultRecord(passphraseOrNull, snapshot) {
    // Reuse the unlocked DEK when we have one; otherwise mint everything fresh.
    let salt, iterations, wrapped;
    if (dek === null) {
        salt = crypto.getRandomValues(new Uint8Array(16));
        iterations = PBKDF2_ITERATIONS;
        const kek = await deriveKek(passphraseOrNull, salt, iterations);
        dek = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
        const rawDek = await crypto.subtle.exportKey("raw", dek);
        wrapped = await encryptWithKey(kek, rawDek);
    } else {
        salt = unb64(record.salt);
        iterations = record.iterations;
        wrapped = { iv: record.wrapIv, ct: record.wrappedDek };
    }
    const blob = await encryptWithKey(dek, utf8(JSON.stringify(snapshot)));
    return {
        salt: b64(salt.buffer ? salt : new Uint8Array(salt)),
        iterations,
        wrapIv: wrapped.iv,
        wrappedDek: wrapped.ct,
        vaultIv: blob.iv,
        vaultCt: blob.ct,
        syncedAt: Date.now(),
        maxAgeDays: snapshot.maxAgeDays,
        username: snapshot.username,
        displayName: snapshot.displayName,
        siteId: snapshot.siteId,
    };
}

// ---------- server ----------

async function fetchSnapshot() {
    let res;
    try {
        res = await fetch("/api/offline/snapshot", {
            headers: { "X-Harpo-Offline": "1" },
            credentials: "same-origin",
            cache: "no-store",
        });
    } catch {
        noteServer(false);
        throw new Error("The server is unreachable — connect to the network and try again.");
    }
    noteServer(true);
    if (res.redirected || res.status === 401) {
        throw new Error("SIGN_IN");
    }
    if (res.status === 404) {
        throw new Error("DISABLED");
    }
    if (res.status === 429) {
        throw new Error("The server asked us to slow down — try again in a moment.");
    }
    if (!res.ok) {
        throw new Error("The server rejected the request (" + res.status + ").");
    }
    return res.json();
}

async function probeEnabled() {
    try {
        const res = await fetch("/api/offline/enabled", { credentials: "same-origin", cache: "no-store" });
        if (!res.ok) {
            noteServer(false);
            return null;
        }
        noteServer(true);
        return (await res.json()).enabled === true;
    } catch {
        noteServer(false);
        return null; // server unreachable — can't tell
    }
}

// ---------- expiry / lock ----------

const isExpired = (rec) => Date.now() - rec.syncedAt > rec.maxAgeDays * 86400000;

function expiresText(rec) {
    const left = rec.syncedAt + rec.maxAgeDays * 86400000 - Date.now();
    if (left <= 0) {
        return "expired";
    }
    const days = Math.floor(left / 86400000);
    return days >= 1 ? `expires in ${days}d` : `expires in ${Math.max(1, Math.floor(left / 3600000))}h`;
}

function lock() {
    dek = null;
    vaultData = null;
    clearTimeout(idleTimer);
    $("entryList").replaceChildren();
    $("unlockPass").value = "";
    enterUnlockState();
}

function armAutoLock() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
        if (vaultData !== null) {
            lock();
            toast("Locked after inactivity");
        }
    }, AUTO_LOCK_MS);
}

for (const evt of ["click", "keydown", "input"]) {
    document.addEventListener(evt, () => {
        if (vaultData !== null) {
            armAutoLock();
        }
    });
}

// ---------- rendering ----------

function renderVault() {
    const filter = $("search").value.trim().toLowerCase();
    const groups = new Map(vaultData.groups.map((g) => [g.id, g]));
    const byGroup = new Map();
    for (const entry of vaultData.entries) {
        const hit = !filter
            || entry.name.toLowerCase().includes(filter)
            || (entry.url || "").toLowerCase().includes(filter)
            || (entry.username || "").toLowerCase().includes(filter);
        if (!hit) {
            continue;
        }
        if (!byGroup.has(entry.groupId)) {
            byGroup.set(entry.groupId, []);
        }
        byGroup.get(entry.groupId).push(entry);
    }

    const list = $("entryList");
    list.replaceChildren();
    if (byGroup.size === 0) {
        const p = document.createElement("p");
        p.className = "muted small";
        p.textContent = vaultData.entries.length === 0
            ? "Your snapshot has no passwords (you may not belong to any group)."
            : "Nothing matches your search.";
        list.appendChild(p);
        return;
    }

    for (const [groupId, entries] of byGroup) {
        const block = document.createElement("div");
        block.className = "group-block";
        const heading = document.createElement("div");
        heading.className = "group-name";
        heading.textContent = groups.get(groupId)?.name ?? "Unknown group";
        block.appendChild(heading);

        for (const entry of entries) {
            block.appendChild(renderEntry(entry));
        }
        list.appendChild(block);
    }
}

function renderEntry(entry) {
    const row = document.createElement("div");
    row.className = "entry";

    const icon = document.createElement("span");
    icon.className = "icon";
    // Catalogue icons ("icon:{id}") live on the server; offline we show the default glyph.
    icon.textContent = !entry.icon || entry.icon.startsWith("icon:") ? "🔐" : entry.icon;
    row.appendChild(icon);

    const who = document.createElement("div");
    who.className = "who";
    const name = document.createElement("div");
    name.className = "name";
    name.textContent = entry.name;
    who.appendChild(name);
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = [entry.username, entry.url].filter(Boolean).join(" · ");
    if (entry.notes) {
        meta.title = entry.notes;
    }
    who.appendChild(meta);
    row.appendChild(who);

    const pw = document.createElement("span");
    pw.className = "pw";
    pw.textContent = "••••••••";
    row.appendChild(pw);

    let shown = false;
    let hideTimer = null;
    const reveal = document.createElement("button");
    reveal.className = "btn-icon";
    reveal.title = "Reveal";
    reveal.innerHTML = lucide("eye");
    const setShown = (value) => {
        shown = value;
        pw.textContent = shown ? (entry.password ?? "(no password)") : "••••••••";
        pw.classList.toggle("shown", shown);
        reveal.innerHTML = lucide(shown ? "eye-off" : "eye");
        clearTimeout(hideTimer);
        if (shown) {
            hideTimer = setTimeout(() => setShown(false), 30000); // auto-hide
        }
    };
    reveal.addEventListener("click", () => setShown(!shown));
    row.appendChild(reveal);

    if (entry.totp) {
        const totpBtn = document.createElement("button");
        totpBtn.className = "btn-icon";
        totpBtn.title = "Show 2FA code";
        totpBtn.innerHTML = lucide("timer");
        const codeEl = document.createElement("span");
        codeEl.className = "pw shown";
        codeEl.style.display = "none";
        let totpTimer = null;
        const stopTotp = () => {
            clearInterval(totpTimer);
            totpTimer = null;
            codeEl.style.display = "none";
            totpBtn.innerHTML = lucide("timer");
        };
        const renderCode = async () => {
            try {
                const { code, remaining } = await totpNow(entry.totp);
                codeEl.textContent = `${code.slice(0, 3)} ${code.slice(3)} · ${remaining}s`;
            } catch {
                codeEl.textContent = "2FA error";
                stopTotp();
            }
        };
        totpBtn.addEventListener("click", async () => {
            if (totpTimer) {
                stopTotp();
                return;
            }
            codeEl.style.display = "";
            totpBtn.innerHTML = lucide("eye-off");
            await renderCode();
            const startedAt = Date.now();
            totpTimer = setInterval(() => {
                if (Date.now() - startedAt > 120000) {
                    stopTotp(); // same hygiene as revealed passwords
                    return;
                }
                renderCode();
            }, 1000);
        });
        row.appendChild(codeEl);
        row.appendChild(totpBtn);
    }

    const copy = document.createElement("button");
    copy.className = "btn-icon";
    copy.title = "Copy password";
    copy.innerHTML = lucide("copy");
    copy.addEventListener("click", async () => {
        if (entry.password == null) {
            toast("This entry has no password");
            return;
        }
        toast(await copyText(entry.password, 60000)
            ? "Password copied — clipboard clears in 60s"
            : "Copy failed");
    });
    row.appendChild(copy);

    return row;
}

let clipboardTimer = null;
// ---------- icons (vendored Lucide subset, ISC license — matches the app chrome) ----------

const LUCIDE = {
    "eye": '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8Z"/><circle cx="12" cy="12" r="3"/>',
    "eye-off": '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" x2="23" y1="1" y2="23"/>',
    "copy": '<rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
    "timer": '<line x1="10" x2="14" y1="2" y2="2"/><line x1="12" x2="15" y1="14" y2="11"/><circle cx="12" cy="14" r="8"/>',
};

function lucide(name, size = 16) {
    return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24"`
        + ` fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"`
        + ` stroke-linejoin="round" aria-hidden="true">${LUCIDE[name]}</svg>`;
}

// ---------- TOTP (RFC 6238 via WebCrypto) ----------

function base32Decode(input) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const cleaned = input.replace(/[\s-]/g, "").replace(/=+$/, "").toUpperCase();
    let bits = 0, value = 0;
    const out = [];
    for (const c of cleaned) {
        const idx = alphabet.indexOf(c);
        if (idx < 0) {
            throw new Error("bad base32");
        }
        value = (value << 5) | idx;
        bits += 5;
        if (bits >= 8) {
            out.push((value >> (bits - 8)) & 0xff);
            bits -= 8;
        }
    }
    return new Uint8Array(out);
}

function parseTotp(stored) {
    let secret = stored, digits = 6, period = 30, algorithm = "SHA-1";
    if (stored.toLowerCase().startsWith("otpauth://")) {
        const url = new URL(stored);
        const q = url.searchParams;
        secret = q.get("secret") || "";
        digits = parseInt(q.get("digits") || "6", 10);
        period = parseInt(q.get("period") || "30", 10);
        const algo = (q.get("algorithm") || "SHA1").toUpperCase();
        algorithm = algo === "SHA256" ? "SHA-256" : algo === "SHA512" ? "SHA-512" : "SHA-1";
    }
    return { key: base32Decode(secret), digits, period, algorithm };
}

async function totpNow(stored) {
    const p = parseTotp(stored);
    const counter = Math.floor(Date.now() / 1000 / p.period);
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, BigInt(counter));
    const key = await crypto.subtle.importKey("raw", p.key, { name: "HMAC", hash: { name: p.algorithm } }, false, ["sign"]);
    const hash = new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes));
    const offset = hash[hash.length - 1] & 0x0f;
    const binary = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
    const code = String(binary % 10 ** p.digits).padStart(p.digits, "0");
    const remaining = p.period - (Math.floor(Date.now() / 1000) % p.period);
    return { code, remaining };
}

async function copyText(text, clearAfterMs = 0) {
    const ok = await copyTextCore(text);
    if (ok && clearAfterMs > 0) {
        clearTimeout(clipboardTimer);
        clipboardTimer = setTimeout(() => {
            try {
                navigator.clipboard?.writeText(" ").catch(() => { });
            } catch { }
        }, clearAfterMs);
    }
    return ok;
}

async function copyTextCore(text) {
    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
            return true;
        }
    } catch { /* fall through */ }
    try {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand("copy");
        ta.remove();
        return ok;
    } catch {
        return false;
    }
}

// ---------- states / flows ----------

function enterVaultState() {
    $("syncInfo").textContent =
        `${record.username}@${record.siteId} · synced ${new Date(record.syncedAt).toLocaleString()} · ${expiresText(record)}`;
    $("refreshBtn").disabled = !navigator.onLine;
    renderVault();
    show("state-vault");
    armAutoLock();
}

function enterUnlockState() {
    $("unlockInfo").textContent =
        `Offline copy for ${record.displayName} (${record.username}) from site "${record.siteId}" · ${expiresText(record)}` +
        (isExpired(record) ? " — unlocking will refresh it from the server." : "");
    setError("unlockError", null);
    show("state-unlock");
}

async function doSetup() {
    const pass = $("setupPass").value;
    const pass2 = $("setupPass2").value;
    if (pass.length < 10) {
        setError("setupError", "The passphrase must be at least 10 characters.");
        return;
    }
    if (pass !== pass2) {
        setError("setupError", "The passphrases don't match.");
        return;
    }
    setError("setupError", null);
    const btn = $("setupBtn");
    btn.disabled = true;
    btn.textContent = "Syncing…";
    try {
        const snapshot = await fetchSnapshot();
        record = await encryptVaultRecord(pass, snapshot);
        await idbPut(record);
        if (navigator.storage?.persist) {
            navigator.storage.persist().catch(() => { });
        }
        vaultData = snapshot;
        toast(`Synced ${snapshot.entries.length} entries`);
        enterVaultState();
    } catch (err) {
        handleFlowError(err, "setupError");
    } finally {
        btn.disabled = false;
        btn.textContent = "Enable & sync now";
    }
}

async function doUnlock() {
    const btn = $("unlockBtn");
    btn.disabled = true;
    btn.textContent = "Deriving key…";
    try {
        const kek = await deriveKek($("unlockPass").value, unb64(record.salt), record.iterations);
        const rawDek = await decryptWithKey(kek, record.wrapIv, record.wrappedDek);
        dek = await crypto.subtle.importKey("raw", rawDek, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
        const json = await decryptWithKey(dek, record.vaultIv, record.vaultCt);
        vaultData = JSON.parse(new TextDecoder().decode(json));
    } catch {
        dek = null;
        setError("unlockError", "Wrong passphrase.");
        btn.disabled = false;
        btn.textContent = "Unlock";
        return;
    }
    btn.disabled = false;
    btn.textContent = "Unlock";

    if (isExpired(record)) {
        // Never show stale data: a successful refresh is required to proceed.
        const refreshed = await doRefresh({ quiet: true });
        if (!refreshed) {
            dek = null;
            vaultData = null;
            showMessage("Snapshot expired",
                "This offline copy is older than allowed. Sign in while online, then refresh it.",
                { loginLink: true, wipe: true });
            return;
        }
    }
    enterVaultState();
}

async function doRefresh({ quiet = false } = {}) {
    const btn = $("refreshBtn");
    btn.disabled = true;
    try {
        const snapshot = await fetchSnapshot();
        record = await encryptVaultRecord(null, snapshot);
        await idbPut(record);
        vaultData = snapshot;
        if (!quiet) {
            toast(`Refreshed — ${snapshot.entries.length} entries`);
            enterVaultState();
        }
        return true;
    } catch (err) {
        if (!quiet) {
            handleFlowError(err, null);
        }
        return false;
    } finally {
        btn.disabled = false;
    }
}

function handleFlowError(err, errorElementId) {
    if (err.message === "SIGN_IN") {
        showMessage("Sign in first",
            "You need to be signed in to Harpo (online) before syncing an offline copy.",
            { loginLink: true });
    } else if (err.message === "DISABLED") {
        showMessage("Offline access is disabled",
            "Your administrator has turned off offline password storage for this Harpo.");
    } else if (errorElementId) {
        setError(errorElementId, err.message);
    } else {
        toast(err.message);
    }
}

async function doWipe() {
    if (!confirm("Wipe the offline copy from this device? You can re-sync while online.")) {
        return;
    }
    await idbWipe();
    dek = null;
    vaultData = null;
    record = null;
    toast("Offline data wiped");
    init();
}

// ---------- boot ----------

async function init() {
    updateNetBadge();
    if (!window.isSecureContext || !crypto.subtle) {
        showMessage("Secure context required",
            "The offline vault needs HTTPS (or localhost) so the browser exposes its cryptography APIs.");
        return;
    }

    record = await idbGet().catch(() => null);

    if (navigator.onLine) {
        const enabled = await probeEnabled();
        if (enabled === false) {
            if (record) {
                // Admin turned the feature off: honour it on next contact.
                await idbWipe();
                record = null;
                showMessage("Offline access is disabled",
                    "Your administrator turned off offline password storage, so the local copy on this device has been removed.");
            } else {
                showMessage("Offline access is disabled",
                    "Your administrator has turned off offline password storage for this Harpo.");
            }
            return;
        }
    }

    if (!record) {
        if (!navigator.onLine) {
            showMessage("No offline data on this device",
                "Connect to the network, sign in to Harpo, and set up offline access first.");
            return;
        }
        show("state-setup");
        return;
    }

    if (isExpired(record) && !navigator.onLine) {
        showMessage("Snapshot expired",
            "This offline copy is older than allowed and can't be shown. Connect to the network to refresh it.",
            { wipe: true });
        return;
    }

    enterUnlockState();
}

$("setupBtn").addEventListener("click", doSetup);
$("unlockBtn").addEventListener("click", doUnlock);
$("unlockPass").addEventListener("keydown", (e) => { if (e.key === "Enter") doUnlock(); });
$("refreshBtn").addEventListener("click", () => doRefresh());
$("lockBtn").addEventListener("click", () => { lock(); toast("Locked"); });
$("search").addEventListener("input", renderVault);
for (const id of ["wipeBtn1", "wipeBtn2", "wipeBtn3"]) {
    $(id).addEventListener("click", doWipe);
}
window.addEventListener("online", () => {
    updateNetBadge();
    if (vaultData === null) {
        init(); // don't yank an unlocked vault out from under the user
    } else {
        $("refreshBtn").disabled = false;
    }
});
window.addEventListener("offline", () => {
    updateNetBadge();
    if (vaultData !== null) {
        $("refreshBtn").disabled = true;
    }
});

if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js", { updateViaCache: "none" }).catch(() => { });
}

init();
