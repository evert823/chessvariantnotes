export function initRequestResetPassword({ formId, emailId, buttonId, messageId }) {
  const form = document.getElementById(formId);
  const emailInput = document.getElementById(emailId);
  const button = document.getElementById(buttonId);
  const msg = document.getElementById(messageId);

  if (!form || !emailInput || !button || !msg) return;

  const GENERIC_TEXT = "If an account exists, you'll receive an email";

  // ensure assistive tech reads updates
  msg.setAttribute("aria-live", "polite");

  async function doRequest() {
    const email = emailInput.value?.trim();
    if (!email) {
      msg.textContent = "Please enter your email";
      return;
    }

    button.disabled = true;
    msg.textContent = "Sending...";

    try {
      await fetch('/auth/requestresetpassword', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      // Always show the generic message to avoid account enumeration
      msg.textContent = GENERIC_TEXT;
    } catch (err) {
      // Network/error: still show generic message
      msg.textContent = GENERIC_TEXT;
    } finally {
      button.disabled = false;
    }
  }

  button.addEventListener('click', doRequest);
  // handle Enter key / form submit
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    doRequest();
  });
}
