// PWA: the service worker only caches the static offline-vault shell (see sw.js).
if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js", { updateViaCache: "none" }).catch(() => { });
}

// Small per-browser preference store (e.g. password generator settings).
window.harpoPrefsGet = (key) => {
    try { return localStorage.getItem(key); } catch { return null; }
};
window.harpoPrefsSet = (key, value) => {
    try { localStorage.setItem(key, value); } catch { }
};

// Copies text to the clipboard; returns true on success.
// navigator.clipboard needs a secure context (HTTPS or localhost), so fall back
// to the legacy execCommand path for plain-HTTP deployments behind a proxy.
let harpoClipboardTimer = null;
window.harpoCopy = async function (text, clearAfterMs = 0) {
    const ok = await harpoCopyCore(text);
    if (ok && clearAfterMs > 0) {
        // Overwrite the clipboard after a delay so a copied password doesn't
        // linger. Browsers refuse clipboard writes from unfocused pages; if the
        // user has moved on, the overwrite silently doesn't happen.
        clearTimeout(harpoClipboardTimer);
        harpoClipboardTimer = setTimeout(() => {
            try {
                navigator.clipboard?.writeText(" ").catch(() => { });
            } catch { }
        }, clearAfterMs);
    }
    return ok;
};

async function harpoCopyCore(text) {
    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
            return true;
        }
    } catch {
        // fall through to the legacy path
    }
    try {
        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        const ok = document.execCommand("copy");
        document.body.removeChild(textarea);
        return ok;
    } catch {
        return false;
    }
};

// Keyboard focus for <Modal>. Blazor renders the dialog; this keeps focus honest
// around it: remember what had focus, move focus into the dialog, keep Tab
// inside it, close on Escape wherever focus happens to be, and put focus back
// where it was when the dialog closes.
window.harpoModal = (() => {
    const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), ' +
        'select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
    let panel = null;
    let returnTo = null;

    const rendered = (el) => el.getClientRects().length > 0;
    const focusables = () => [...panel.querySelectorAll(FOCUSABLE)].filter(rendered);

    function onKeyDown(e) {
        if (panel === null || !document.contains(panel)) {
            return;
        }
        if (e.key === "Escape") {
            e.preventDefault();
            panel.querySelector(".modal-close")?.click();
            return;
        }
        if (e.key !== "Tab") {
            return;
        }
        const items = focusables();
        if (items.length === 0) {
            e.preventDefault();
            panel.focus();
            return;
        }
        const first = items[0];
        const last = items[items.length - 1];
        const active = document.activeElement;
        if (!panel.contains(active)) {
            e.preventDefault(); // focus escaped (a click on the backdrop, say): bring it back
            first.focus();
        } else if (e.shiftKey && (active === first || active === panel)) {
            e.preventDefault();
            last.focus();
        } else if (!e.shiftKey && active === last) {
            e.preventDefault();
            first.focus();
        }
    }

    return {
        open(element) {
            if (panel === null) {
                returnTo = document.activeElement;
                document.addEventListener("keydown", onKeyDown, true);
            }
            panel = element;
            // Start in the first field when there is one, so typing can begin at once.
            const field = element.querySelector(
                'input:not([type="hidden"]):not([type="file"]):not([disabled]), textarea, select');
            (field ?? element).focus();
        },
        close() {
            if (panel === null) {
                return;
            }
            document.removeEventListener("keydown", onKeyDown, true);
            panel = null;
            const target = returnTo;
            returnTo = null;
            if (target && document.contains(target) && typeof target.focus === "function") {
                target.focus();
            }
        },
    };
})();
