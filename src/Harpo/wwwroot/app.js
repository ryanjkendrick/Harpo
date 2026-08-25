// PWA: the service worker only caches the static offline-vault shell (see sw.js).
if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js", { updateViaCache: "none" }).catch(() => { });
}

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
