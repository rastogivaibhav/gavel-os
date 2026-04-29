/**
 * Authentication handler — Windows AD + JWT integration
 */

async function getAuthToken() {
  try {
    let token = sessionStorage.getItem('gavel_token');
    const expiry = sessionStorage.getItem('gavel_token_expiry');
    if (token && expiry && new Date(expiry) > new Date()) return token;

    const response = await fetch('/api/auth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ windows_user: 'AD\\user', clearance_level: 2 })
    });

    if (!response.ok) throw new Error('Token request failed');
    const data = await response.json();
    token = data.access_token;

    sessionStorage.setItem('gavel_token', token);
    sessionStorage.setItem('gavel_token_expiry', new Date(Date.now() + 3600000).toISOString());
    return token;
  } catch (error) {
    console.error('Auth error:', error);
    return null;
  }
}

function logout() {
  sessionStorage.removeItem('gavel_token');
  sessionStorage.removeItem('gavel_token_expiry');
  window.location.href = '/auth/login';
}

document.addEventListener('DOMContentLoaded', async () => {
  const userDisplay = document.getElementById('user-display');
  if (userDisplay) {
    userDisplay.textContent = '👤 AD\\user';
  }
});
