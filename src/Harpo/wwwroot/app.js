// PWA: the service worker only caches the static offline-vault shell (see sw.js).
if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js", { updateViaCache: "none" }).catch(() => { });
}

// Copies text to the clipboard; returns true on success.
// navigator.clipboard needs a secure context (HTTPS or localhost), so fall back
// to the legacy execCommand path for plain-HTTP deployments behind a proxy.
window.harpoCopy = async function (text) {
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
