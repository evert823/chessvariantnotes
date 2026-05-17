export async function getCurrentUser() {
  const headers = {};
  const storedUser = localStorage.getItem('userId');
  if (storedUser) headers['X-User-Id'] = storedUser;
  try {
    const res = await fetch('/auth/me', { method: 'GET', headers, credentials: 'include' });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function escapeHtml(s) {
  return (s || '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}

export async function logout() {
  localStorage.removeItem('userId');
  try { await fetch('/auth/logout', { method: 'POST', credentials: 'include' }); } catch {}
}

export async function renderAuthArea(containerId = 'authArea') {
  const container = document.getElementById(containerId);
  if (!container) return;
  const statusEl = document.createElement('span');
  statusEl.id = 'authStatus';
  const actionsEl = document.createElement('span');
  actionsEl.id = 'authActions';
  actionsEl.style.marginLeft = '10px';
  container.innerHTML = '';
  container.appendChild(statusEl);
  container.appendChild(actionsEl);

  const user = await getCurrentUser();
  if (user) {
    statusEl.textContent = `Logged in as ${escapeHtml(user.username || user.email || user.id)}`;
    actionsEl.innerHTML = `<button id="logoutBtn">Logout</button>`;
    document.getElementById('logoutBtn').addEventListener('click', async () => {
      await logout();
      await renderAuthArea(containerId);
    });
  } else {
    statusEl.textContent = 'Not logged in';
    actionsEl.innerHTML = `<button id="loginBtn">Login</button> <button id="signupBtn" style="margin-left:6px">Sign up</button>`;
    document.getElementById('loginBtn').addEventListener('click', () => { window.location.href = '/chessvariantnotes/login.html'; });
    document.getElementById('signupBtn').addEventListener('click', () => { window.location.href = '/chessvariantnotes/register.html'; });
  }
}
