export async function sha256Hex(str) {
    if (!window.crypto || !crypto.subtle) {
        throw new Error("Web Crypto API not available (requires HTTPS / secure context).");
    }
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function initLogin(ids = {}) {
    const formEl = document.getElementById(ids.formId || 'loginForm');
    if (!formEl) return;

    const userEl = formEl.querySelector(`#${ids.userId || 'userInput'}`);
    const pwdEl = formEl.querySelector(`#${ids.passwordId || 'passwordInput'}`);
    const btn = formEl.querySelector(`#${ids.buttonId || 'loginBtn'}`);
    const msg = document.getElementById(ids.messageId || 'loginMsg');

    if (!userEl || !pwdEl || !btn || !msg) return;

    // disable if Web Crypto not available (prevents runtime errors / console noise)
    if (!window.crypto || !crypto.subtle) {
        btn.disabled = true;
        msg.textContent = "Browser does not support secure hashing (Web Crypto). Use HTTPS or a modern browser.";
        return;
    }

    btn.addEventListener('click', async () => {
        msg.textContent = '';
        btn.disabled = true;
        try {
            const identifier = userEl.value.trim();
            const password = pwdEl.value;
            if (!identifier || !password) throw new Error('All fields required');

            const hashed = await sha256Hex(password);

            const res = await fetch('/auth/login', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username_or_email: identifier, password: hashed })
            });

            const contentType = res.headers.get('content-type') || '';
            const data = contentType.includes('application/json') ? await res.json().catch(() => null) : await res.text().catch(() => null);

            if (res.ok) {
                if (data && data.id) localStorage.setItem('userId', data.id);
                msg.textContent = 'Signed in';
                try { const mod = await import('./auth.js'); await mod.renderAuthArea(); } catch (_) {}
            } else {
                if (res.status === 401) {
                    msg.textContent = 'Invalid username or password.';
                } else if (res.status === 400) {
                    msg.textContent = data && data.detail ? String(data.detail) : 'Bad request';
                } else {
                    const err = data && (data.detail || data.error) ? (data.detail || data.error) : (typeof data === 'string' ? data : JSON.stringify(data));
                    msg.textContent = 'Error: ' + (err || ('HTTP ' + res.status));
                }
            }
        } catch (e) {
            msg.textContent = 'Error: ' + (e.message || String(e));
        } finally {
            btn.disabled = false;
        }
    });
}
