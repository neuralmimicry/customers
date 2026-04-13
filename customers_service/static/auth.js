(() => {
  const form = document.getElementById('authForm');
  if (!form) return;

  const authType = form.dataset.auth;
  if (!authType) return;
  const nextPath = (form.dataset.next || '/').trim() || '/';

  const errorEl = document.getElementById('authError');
  const submitBtn = form.querySelector('button[type="submit"]');
  const usernameEl = document.getElementById('username');
  const emailEl = document.getElementById('email');
  const passwordEl = document.getElementById('password');
  const confirmEl = document.getElementById('confirm');

  const apiBase = (() => {
    if (typeof window !== 'undefined' && typeof window.__RAG_API_BASE === 'string' && window.__RAG_API_BASE.trim()) {
      return window.__RAG_API_BASE.trim().replace(/\/+$/, '');
    }
    const meta = document.querySelector('meta[name="rag-api-base"]');
    if (meta && meta.content) {
      const value = meta.content.trim();
      if (value && !value.includes('{{')) {
        return value.replace(/\/+$/, '');
      }
    }
    return '';
  })();

  const apiUrl = (path) => {
    const suffix = path.startsWith('/') ? path : `/${path}`;
    return `${apiBase}${suffix}`;
  };

  const redirectViaSso = (token) => {
    const cleaned = String(token || '').trim();
    if (!cleaned) return false;
    const ssoUrl = new URL(apiUrl('/sso') || '/sso', window.location.href);
    ssoUrl.searchParams.set('token', cleaned);
    ssoUrl.searchParams.set('next', nextPath);
    window.location.href = ssoUrl.toString();
    return true;
  };

  const setError = (message) => {
    if (!errorEl) return;
    errorEl.textContent = message || '';
    errorEl.hidden = !message;
  };

  const errorMessage = (payload) => {
    if (payload && payload.details) return payload.details;
    const code = payload?.error;
    const map = {
      invalid_credentials: 'Invalid username or password.',
      setup_required: 'Setup is required before you can sign in.',
      setup_not_allowed: 'Setup has already been completed.',
      username_and_password_required: 'Username and password are required.',
      invalid_username: 'Username must be 3-32 chars (letters, numbers, underscore, dash).',
      password_too_short: 'Password must be at least 8 characters.',
      password_mismatch: 'Passwords do not match.',
      invalid_email: 'Please enter a valid email address.',
    };
    return map[code] || 'Request failed. Please try again.';
  };

  const endpoint = authType === 'setup' ? '/api/setup' : '/api/login';

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    setError('');
    if (submitBtn) submitBtn.disabled = true;

    const payload = {
      username: (usernameEl?.value || '').trim(),
      password: passwordEl?.value || '',
    };
    if (authType === 'setup') {
      payload.confirm = confirmEl?.value || '';
      payload.email = (emailEl?.value || '').trim();
    }

    try {
      const res = await fetch(apiUrl(endpoint), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(payload),
      });
      let data = {};
      try {
        data = await res.json();
      } catch (err) {
        data = {};
      }
      if (!res.ok) {
        if (data.error === 'setup_required' && authType === 'login') {
          window.location.href = '/setup';
          return;
        }
        if (data.error === 'setup_not_allowed' && authType === 'setup') {
          window.location.href = '/login';
          return;
        }
        setError(errorMessage(data));
        return;
      }
      if (redirectViaSso(data?.sso_token || data?.token)) {
        return;
      }
      window.location.href = nextPath;
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      if (submitBtn) submitBtn.disabled = false;
    }
  });
})();
