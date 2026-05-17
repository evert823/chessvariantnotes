export async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function initRegister(ids = {}) {
  const form = document.getElementById(ids.formId || 'registerForm');
  const emailEl = document.getElementById(ids.emailId || 'emailInput');
  const usernameEl = document.getElementById(ids.usernameId || 'usernameInput');
  const passwordEl = document.getElementById(ids.passwordId || 'passwordInput');
  const btn = document.getElementById(ids.buttonId || 'registerBtn');
  const msg = document.getElementById(ids.messageId || 'registerMsg');

  if (!form || !emailEl || !usernameEl || !passwordEl || !btn || !msg) return;

  btn.addEventListener('click', async () => {
    msg.textContent = '';
    btn.disabled = true;
    try {
      const email = emailEl.value.trim();
      const username = usernameEl.value.trim();
      const password = passwordEl.value;
      if (!email || !username || !password) throw new Error('All fields required');

      // client-side hash (you said hashed password will be sent)
      const hashed = await sha256Hex(password);

      const res = await fetch('/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, username, password: hashed })
      });

      const contentType = res.headers.get('content-type') || '';
      const data = contentType.includes('application/json') ? await res.json().catch(() => null) : await res.text().catch(() => null);

      if (res.status === 201) {
        msg.textContent = 'Account created. Check your email for a confirmation link.';
        if (data && data.confirm_url_for_dev) {
          const a = document.createElement('a');
          a.href = data.confirm_url_for_dev;
          a.textContent = 'Dev confirmation link';
          a.target = '_blank';
          msg.appendChild(document.createElement('br'));
          msg.appendChild(a);
        }
        form.reset();
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
