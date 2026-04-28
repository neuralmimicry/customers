(() => {
  const form = document.getElementById('authForm');
  if (!form) return;

  const authType = form.dataset.auth;
  if (!authType) return;

  const nextPath = (form.dataset.next || '/').trim() || '/';
  const passwordMinLength = Number.parseInt(form.dataset.passwordMinLength || '8', 10) || 8;

  const errorEl = document.getElementById('authError');
  const usernameEl = document.getElementById('username');
  const emailEl = document.getElementById('email');
  const passwordEl = document.getElementById('password');
  const confirmEl = document.getElementById('confirm');
  const workspaceNameEl = document.getElementById('workspaceName');
  const enableTotpEl = document.getElementById('enableTotp');
  const registerPasskeyEl = document.getElementById('registerPasskey');

  const passwordStepEl = document.getElementById('passwordStep');
  const totpStepEl = document.getElementById('totpStep');
  const totpCodeEl = document.getElementById('totpCode');
  const backToPasswordBtn = document.getElementById('backToPasswordBtn');
  const passkeySignInBtn = document.getElementById('passkeySignInBtn');

  const securitySetupEl = document.getElementById('securitySetup');
  const securitySetupStatusEl = document.getElementById('securitySetupStatus');
  const totpSetupPanelEl = document.getElementById('totpSetupPanel');
  const passkeySetupPanelEl = document.getElementById('passkeySetupPanel');
  const totpSecretEl = document.getElementById('totpSecret');
  const totpProvisioningUriEl = document.getElementById('totpProvisioningUri');
  const totpVerifyCodeEl = document.getElementById('totpVerifyCode');
  const totpVerifyBtn = document.getElementById('totpVerifyBtn');
  const totpSkipBtn = document.getElementById('totpSkipBtn');
  const passkeyRegisterBtn = document.getElementById('passkeyRegisterBtn');
  const passkeySkipBtn = document.getElementById('passkeySkipBtn');

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

  const supportsPasskeys = Boolean(
    form.dataset.passkeysSupported === 'true' &&
    typeof window !== 'undefined' &&
    window.PublicKeyCredential &&
    navigator?.credentials,
  );

  const requestJson = async (path, options = {}) => {
    const res = await fetch(apiUrl(path), {
      credentials: 'include',
      ...options,
    });
    let data = {};
    try {
      data = await res.json();
    } catch (err) {
      data = {};
    }
    return { res, data };
  };

  const setError = (message) => {
    if (!errorEl) return;
    errorEl.textContent = message || '';
    errorEl.hidden = !message;
  };

  const setSecurityStatus = (message, isError = false) => {
    if (!securitySetupStatusEl) return;
    securitySetupStatusEl.textContent = message || '';
    securitySetupStatusEl.hidden = !message;
    securitySetupStatusEl.classList.toggle('auth-error', Boolean(isError));
  };

  const errorMessage = (payload, fallback = 'Request failed. Please try again.') => {
    if (payload && payload.details) return payload.details;
    const code = payload?.error;
    const map = {
      email_required: 'Email is required.',
      invalid_credentials: 'Invalid username or password.',
      invalid_email: 'Enter a valid email address.',
      invalid_mfa_code: 'Enter a valid six-digit authenticator code.',
      invalid_username: 'Username must be 3-32 chars (letters, numbers, underscore, dash).',
      local_auth_unavailable: 'This account does not support local sign-in.',
      mfa_challenge_missing: 'The sign-in check has expired. Please start again.',
      passkey_challenge_missing: 'The passkey prompt has expired. Please start again.',
      passkey_exists: 'That passkey is already registered to this account.',
      passkey_invalid: 'The passkey could not be verified.',
      passkey_registration_failed: 'The passkey could not be registered.',
      passkey_sign_in_unavailable: 'Passkey sign-in is not available for that account.',
      password_mismatch: 'Passwords do not match.',
      password_too_short: `Password must be at least ${passwordMinLength} characters.`,
      registration_not_allowed: 'Self-registration is not available.',
      reserved_username: 'That username is reserved.',
      setup_not_allowed: 'Setup has already been completed.',
      setup_required: 'Setup is required before you can sign in.',
      too_many_attempts: 'Too many attempts. Please try again later.',
      totp_not_enabled: 'Authenticator-app sign-in is not enabled for this account.',
      user_exists: 'That username is already in use.',
      username_and_password_required: 'Username and password are required.',
      username_required: 'Enter your username first.',
    };
    return map[code] || fallback;
  };

  const setButtonsDisabled = (disabled) => {
    form.querySelectorAll('button').forEach((button) => {
      button.disabled = Boolean(disabled);
    });
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

  const finishAuth = (payload) => {
    if (redirectViaSso(payload?.sso_token || payload?.token)) {
      return;
    }
    window.location.href = nextPath;
  };

  const showPasswordStage = () => {
    if (passwordStepEl) passwordStepEl.hidden = false;
    if (totpStepEl) totpStepEl.hidden = true;
    if (totpCodeEl) totpCodeEl.value = '';
  };

  const showTotpStage = () => {
    if (passwordStepEl) passwordStepEl.hidden = true;
    if (totpStepEl) totpStepEl.hidden = false;
    if (totpCodeEl) {
      totpCodeEl.focus();
      totpCodeEl.select?.();
    }
  };

  const base64UrlToBytes = (value) => {
    const normalised = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - (normalised.length % 4)) % 4);
    const binary = window.atob(normalised + padding);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  };

  const bytesToBase64Url = (value) => {
    const bytes = value instanceof Uint8Array ? value : new Uint8Array(value || []);
    let binary = '';
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  };

  const preparePublicKey = (payload) => {
    const publicKey = JSON.parse(JSON.stringify(payload || {}));
    if (publicKey.challenge) {
      publicKey.challenge = base64UrlToBytes(publicKey.challenge);
    }
    if (publicKey.user?.id) {
      publicKey.user.id = base64UrlToBytes(publicKey.user.id);
    }
    ['allowCredentials', 'excludeCredentials'].forEach((key) => {
      if (!Array.isArray(publicKey[key])) return;
      publicKey[key] = publicKey[key].map((item) => ({
        ...item,
        id: base64UrlToBytes(item.id),
      }));
    });
    return publicKey;
  };

  const serialiseCredential = (credential) => {
    if (!credential) return null;
    const response = credential.response || {};
    const payload = {
      id: credential.id,
      rawId: bytesToBase64Url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment || null,
      clientExtensionResults: typeof credential.getClientExtensionResults === 'function'
        ? credential.getClientExtensionResults()
        : {},
      response: {
        clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      },
    };
    if (response.attestationObject) {
      payload.response.attestationObject = bytesToBase64Url(response.attestationObject);
    }
    if (response.authenticatorData) {
      payload.response.authenticatorData = bytesToBase64Url(response.authenticatorData);
    }
    if (response.signature) {
      payload.response.signature = bytesToBase64Url(response.signature);
    }
    if (response.userHandle) {
      payload.response.userHandle = bytesToBase64Url(response.userHandle);
    }
    if (typeof response.getTransports === 'function') {
      payload.transports = response.getTransports();
    }
    return payload;
  };

  let completedAuthPayload = null;
  const securityQueue = [];

  const hideSecurityPanels = () => {
    if (totpSetupPanelEl) totpSetupPanelEl.hidden = true;
    if (passkeySetupPanelEl) passkeySetupPanelEl.hidden = true;
  };

  const continueSecurityFlow = async () => {
    hideSecurityPanels();
    if (!securityQueue.length) {
      setSecurityStatus('Security setup complete. Redirecting.');
      finishAuth(completedAuthPayload || {});
      return;
    }

    const currentStep = securityQueue[0];
    if (currentStep === 'totp') {
      setSecurityStatus('Preparing authenticator-app setup.');
      if (totpSetupPanelEl) totpSetupPanelEl.hidden = false;
      const { res, data } = await requestJson('/api/profile/mfa/totp/start', {
        method: 'POST',
      });
      if (!res.ok) {
        setSecurityStatus(errorMessage(data, 'Authenticator-app setup could not be started.'), true);
        return;
      }
      if (totpSecretEl) totpSecretEl.value = data?.totp?.secret || '';
      if (totpProvisioningUriEl) totpProvisioningUriEl.value = data?.totp?.provisioning_uri || '';
      if (totpVerifyCodeEl) {
        totpVerifyCodeEl.value = '';
        totpVerifyCodeEl.focus();
      }
      setSecurityStatus('Add the key to your authenticator app, then enter the current code.');
      return;
    }

    if (currentStep === 'passkey') {
      if (!supportsPasskeys) {
        securityQueue.shift();
        setSecurityStatus('This browser does not support passkeys, so setup will continue without one.');
        await continueSecurityFlow();
        return;
      }
      if (passkeySetupPanelEl) passkeySetupPanelEl.hidden = false;
      setSecurityStatus('Register a passkey on this device, or skip and continue.');
    }
  };

  const startPasskeyRegistration = async () => {
    setSecurityStatus('Preparing passkey registration.');
    const { res: optionsRes, data: optionsData } = await requestJson('/api/profile/passkeys/register/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    if (!optionsRes.ok) {
      setSecurityStatus(errorMessage(optionsData, 'Passkey registration could not be started.'), true);
      return;
    }

    let credential;
    try {
      credential = await navigator.credentials.create({
        publicKey: preparePublicKey(optionsData?.public_key),
      });
    } catch (err) {
      if (err?.name === 'NotAllowedError') {
        setSecurityStatus('Passkey registration was cancelled.');
        return;
      }
      setSecurityStatus('Passkey registration failed.', true);
      return;
    }

    const { res: verifyRes, data: verifyData } = await requestJson('/api/profile/passkeys/register/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential: serialiseCredential(credential) }),
    });
    if (!verifyRes.ok) {
      setSecurityStatus(errorMessage(verifyData, 'Passkey registration failed.'), true);
      return;
    }

    securityQueue.shift();
    await continueSecurityFlow();
  };

  const verifyTotpSetup = async () => {
    const code = (totpVerifyCodeEl?.value || '').trim();
    if (!code) {
      setSecurityStatus('Enter the six-digit code from your authenticator app.', true);
      return;
    }
    const { res, data } = await requestJson('/api/profile/mfa/totp/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    if (!res.ok) {
      setSecurityStatus(errorMessage(data, 'Authenticator-app setup could not be verified.'), true);
      return;
    }
    securityQueue.shift();
    await continueSecurityFlow();
  };

  const handleAccountSetupSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setButtonsDisabled(true);

    const endpoint = authType === 'setup' ? '/api/setup' : '/api/register';
    const payload = {
      username: (usernameEl?.value || '').trim(),
      password: passwordEl?.value || '',
      confirm: confirmEl?.value || '',
      email: (emailEl?.value || '').trim(),
    };
    if (workspaceNameEl && workspaceNameEl.value.trim()) {
      payload.workspace_name = workspaceNameEl.value.trim();
      payload.create_team = true;
    }

    try {
      const { res, data } = await requestJson(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        if (data.error === 'setup_not_allowed' && authType === 'setup') {
          window.location.href = '/login';
          return;
        }
        if (data.error === 'setup_required' && authType === 'register') {
          window.location.href = '/setup';
          return;
        }
        setError(errorMessage(data));
        return;
      }

      completedAuthPayload = data;
      securityQueue.length = 0;
      if (enableTotpEl?.checked) securityQueue.push('totp');
      if (registerPasskeyEl?.checked) securityQueue.push('passkey');

      if (!securityQueue.length) {
        finishAuth(data);
        return;
      }

      form.hidden = true;
      if (securitySetupEl) securitySetupEl.hidden = false;
      await continueSecurityFlow();
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setButtonsDisabled(false);
    }
  };

  const handleLoginSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setButtonsDisabled(true);

    const inTotpStage = Boolean(totpStepEl && !totpStepEl.hidden);
    try {
      if (inTotpStage) {
        const { res, data } = await requestJson('/api/login/mfa/totp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code: (totpCodeEl?.value || '').trim() }),
        });
        if (!res.ok) {
          setError(errorMessage(data, 'Authenticator-app verification failed.'));
          showTotpStage();
          return;
        }
        finishAuth(data);
        return;
      }

      const { res, data } = await requestJson('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: (usernameEl?.value || '').trim(),
          password: passwordEl?.value || '',
        }),
      });
      if (res.status === 202 || data?.status === 'mfa_required') {
        showTotpStage();
        return;
      }
      if (!res.ok) {
        if (data.error === 'setup_required') {
          window.location.href = '/setup';
          return;
        }
        setError(errorMessage(data));
        return;
      }
      finishAuth(data);
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setButtonsDisabled(false);
    }
  };

  const handlePasskeySignIn = async () => {
    setError('');
    if (!supportsPasskeys) {
      setError('Passkeys are not available in this browser.');
      return;
    }
    const username = (usernameEl?.value || '').trim();
    if (!username) {
      setError('Enter your username first.');
      usernameEl?.focus();
      return;
    }

    setButtonsDisabled(true);
    try {
      const { res: optionsRes, data: optionsData } = await requestJson('/api/passkeys/authenticate/options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });
      if (!optionsRes.ok) {
        setError(errorMessage(optionsData, 'Passkey sign-in is not available.'));
        return;
      }

      let credential;
      try {
        credential = await navigator.credentials.get({
          publicKey: preparePublicKey(optionsData?.public_key),
        });
      } catch (err) {
        if (err?.name === 'NotAllowedError') {
          setError('Passkey sign-in was cancelled.');
          return;
        }
        setError('Passkey sign-in failed.');
        return;
      }

      const { res: verifyRes, data: verifyData } = await requestJson('/api/passkeys/authenticate/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: serialiseCredential(credential) }),
      });
      if (!verifyRes.ok) {
        setError(errorMessage(verifyData, 'Passkey sign-in failed.'));
        return;
      }
      finishAuth(verifyData);
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setButtonsDisabled(false);
    }
  };

  if (registerPasskeyEl && !supportsPasskeys) {
    registerPasskeyEl.checked = false;
    registerPasskeyEl.disabled = true;
  }
  if (passkeySignInBtn && !supportsPasskeys) {
    passkeySignInBtn.hidden = true;
  }

  if (backToPasswordBtn) {
    backToPasswordBtn.addEventListener('click', () => {
      setError('');
      showPasswordStage();
    });
  }

  if (totpVerifyBtn) {
    totpVerifyBtn.addEventListener('click', async () => {
      await verifyTotpSetup();
    });
  }

  if (totpSkipBtn) {
    totpSkipBtn.addEventListener('click', async () => {
      securityQueue.shift();
      await continueSecurityFlow();
    });
  }

  if (passkeyRegisterBtn) {
    passkeyRegisterBtn.addEventListener('click', async () => {
      await startPasskeyRegistration();
    });
  }

  if (passkeySkipBtn) {
    passkeySkipBtn.addEventListener('click', async () => {
      securityQueue.shift();
      await continueSecurityFlow();
    });
  }

  if (passkeySignInBtn) {
    passkeySignInBtn.addEventListener('click', async () => {
      await handlePasskeySignIn();
    });
  }

  form.addEventListener('submit', async (event) => {
    if (authType === 'login') {
      await handleLoginSubmit(event);
      return;
    }
    await handleAccountSetupSubmit(event);
  });

  if (totpStepEl && !totpStepEl.hidden) {
    showTotpStage();
  }
})();
