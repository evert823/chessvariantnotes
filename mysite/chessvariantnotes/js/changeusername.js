import { sha256Hex } from './register.js';

export function initChangeUsername(ids = {}) {
  const form = document.getElementById(ids.formId || 'changeUsernameForm');
  const newUsernameEl = document.getElementById(ids.newUsernameId || 'newUsernameInput');
  const passwordEl = document.getElementById(ids.passwordId || 'currentPasswordInput');

  // prefer button inside the form to avoid duplicate-id collisions with auth area
  let btn = null;
  if (form) {
    try {
      btn = ids.buttonId ? form.querySelector(`#${CSS.escape(ids.buttonId)}`) : null;
    } catch (e) {
      btn = ids.buttonId ? form.querySelector(`[id="${ids.buttonId}"]`) : null;
    }
    if (!btn) btn = form.querySelector('button[type="button"], button[type="submit"], button, input[type="button"], input[type="submit"]');
  }
  if (!btn) btn = document.getElementById(ids.buttonId || 'changeUsernameBtn');

  const msg = document.getElementById(ids.messageId || 'changeUsernameMsg');
  const onSuccess = ids.onSuccess; // optional callback

  if (!form || !newUsernameEl || !passwordEl || !btn || !msg) return;

  btn.addEventListener('click', async () => {
    msg.textContent = '';
    btn.disabled = true;
    try {
      const new_username = (newUsernameEl.value || '').trim();
      const password = passwordEl.value;
      if (!new_username || !password) throw new Error('All fields required');

      const hashed = await sha256Hex(password);

      const res = await fetch('/auth/changeusername', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ new_username, password: hashed })
      });

      const contentType = res.headers.get('content-type') || '';
      const data = contentType.includes('application/json') ? await res.json().catch(() => null) : await res.text().catch(() => null);

      if (res.ok) {
        msg.textContent = 'Username changed.';
        form.reset();
        if (typeof onSuccess === 'function') await onSuccess();
      } else {
        const err = data && (data.detail || data.error) ? (data.detail || data.error) : (typeof data === 'string' ? data : JSON.stringify(data));
        msg.textContent = 'Error: ' + (err || ('HTTP ' + res.status));
      }
    } catch (e) {
      msg.textContent = 'Error: ' + e.message;
    } finally {
      btn.disabled = false;
    }
  });
}