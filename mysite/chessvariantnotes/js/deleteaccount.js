export function initDeleteAccount({ formId, emailId, buttonId, messageId }) {
  const form = document.getElementById(formId);
  const emailInput = document.getElementById(emailId);
  const button = document.getElementById(buttonId);
  const msg = document.getElementById(messageId);
  if (!form || !emailInput || !button || !msg) return;

  msg.setAttribute('aria-live', 'polite');

  // parse token & username from URL query params
  const params = new URLSearchParams(window.location.search);
  const token = params.get('token') || '';
  const username = params.get('username') || '';

  const userEl = document.getElementById('deleteUser');
  if (userEl) userEl.textContent = username;

  if (!token || !username) {
    msg.textContent = 'Invalid deletion link (missing token/username).';
    button.disabled = true;
    return;
  }

  emailInput.focus();

  async function doRequest() {
    const email = emailInput.value?.trim();
    if (!email) {
      msg.textContent = 'Please enter your email';
      return;
    }

    button.disabled = true;
    msg.textContent = 'Deleting account...';

    try {
      const res = await fetch('/auth/deleteaccount', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, email }),
      });

      if (res.ok) {
        const data = await res.json().catch(() => null);
        if (data && data.status === 'deleted') {
          msg.textContent = 'Account deleted. An email has been sent.';
          form.reset();
          return;
        }
        msg.textContent = 'Account deletion completed.';
      } else {
        msg.textContent = 'Failed to delete account. If this persists, contact support.';
      }
    } catch (e) {
      console.error('deleteaccount error', e);
      msg.textContent = 'Failed to delete account. If this persists, contact support.';
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