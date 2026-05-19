export async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function initResetPassword({ formId, passwordId, buttonId, messageId }) {
  const form = document.getElementById(formId);
  const passwordInput = document.getElementById(passwordId);
  const button = document.getElementById(buttonId);
  const msg = document.getElementById(messageId);
  if (!form || !passwordInput || !button || !msg) return;

  msg.setAttribute('aria-live', 'polite');

  // parse token & username from URL query params
  const params = new URLSearchParams(window.location.search);
  const token = params.get('token') || '';
  const username = params.get('username') || '';

  if (!token || !username) {
    msg.textContent = 'Invalid reset link (missing token/username).';
    button.disabled = true;
    return;
  }

  passwordInput.focus();

  async function doRequest() {
    const password = passwordInput.value || '';
    if (password.length < 8) {
      msg.textContent = 'Password must be at least 8 characters.';
      return;
    }

    button.disabled = true;
    msg.textContent = 'Setting password...';

    try {
      // first (client-side) hash
      const firstHash = await sha256Hex(password);

      const res = await fetch('/auth/resetpassword', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token,
          username,
          password: firstHash
        })
      });

      const ct = res.headers.get('content-type') || '';
      const data = ct.includes('application/json') ? await res.json().catch(() => null) : await res.text().catch(() => null);

      if (res.ok) {
        msg.textContent = 'Password updated. You can now log in.';
        form.reset();
      } else {
        console.error('resetpassword failed', res.status, data);
        msg.textContent = 'Failed to reset password. If this persists, contact support.';
      }
    } catch (e) {
      console.error('resetpassword error', e);
      msg.textContent = 'Failed to reset password. If this persists, contact support.';
    } finally {
      button.disabled = false;
    }
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    doRequest();
  });

  button.addEventListener('click', doRequest);
}
