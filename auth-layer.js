/**
 * Wilbanks Company — Auth Layer
 * Injected into both apps via index.html before React loads.
 * - JWT token stored in memory only (window.__WC_TOKEN)
 * - Username saved to localStorage for "remember me"
 * - Face ID / WebAuthn: optional after first login
 * - Monkey-patches fetch to inject Authorization headers on Railway calls
 */
(function () {
  const API = "https://wilbanks-server-production.up.railway.app";
  const TOKEN_KEY = "wc_auth_token"; // sessionStorage — clears when tab closes... we use memory
  const USERNAME_KEY = "wc_saved_username";
  const WEBAUTHN_PROMPT_KEY = "wc_webauthn_prompted"; // so we only ask once
  const WEBAUTHN_VALID_KEY = "wc_webauthn_valid"; // set after a successful Face ID login

  // ── Token storage ────────────────────────────────────────────────────────
  // Field tech app is a PWA installed on iPhone home screen — standalone windows
  // have isolated sessionStorage that clears on every cold launch, so we use
  // localStorage for the field app so the session survives PWA restarts.
  // Dashboard uses sessionStorage (clears when tab closes, more secure on shared desktops).
  // The 30-day JWT + inactivity timeout are the security boundaries in both cases.
  let _token = null;

  function isFieldApp() {
    return window.location.pathname.includes('fieldtech') ||
           window.location.href.includes('wilbanks-fieldtech');
  }

  function saveToken(token) {
    _token = token;
    try {
      if (isFieldApp()) {
        // Field tech app — PWA, single-tenant, single-user-per-device. localStorage
        // primary so the session survives iOS Safari tab suspension + home-screen relaunch.
        localStorage.setItem(TOKEN_KEY, token);
      } else {
        // Dashboard (wc-v224b: FULLY STRICT per-tab login).
        //   sessionStorage only — each tab is its own session, no inheritance.
        //   Every new tab forces a fresh login. Hard refresh keeps the session
        //   (sessionStorage survives reloads). Closing the tab ends the session.
        sessionStorage.setItem(TOKEN_KEY, token);
        // Defensive: nuke any stale localStorage seed from a prior wc-v224 boot.
        try { localStorage.removeItem(TOKEN_KEY); } catch {}
      }
    } catch {}
  }
  function loadToken() {
    if (_token) return _token;
    try {
      if (isFieldApp()) {
        _token = localStorage.getItem(TOKEN_KEY) || sessionStorage.getItem(TOKEN_KEY) || null;
      } else {
        // Dashboard: sessionStorage only. No localStorage fallback — strict per-tab.
        _token = sessionStorage.getItem(TOKEN_KEY) || null;
        // Defensive: if a stale localStorage seed survived from an earlier
        // wc-v224 build, drop it. We do NOT use it.
        try { if (localStorage.getItem(TOKEN_KEY)) localStorage.removeItem(TOKEN_KEY); } catch {}
      }
    } catch {}
    return _token;
  }
  function clearToken() {
    _token = null;
    try { sessionStorage.removeItem(TOKEN_KEY); } catch {}
    try { localStorage.removeItem(TOKEN_KEY); } catch {}
  }

  // ── Startup guard removed ──────────────────────────────────────────────────
  // Previously purged any stored admin token on startup to prevent hardcoded
  // dev tokens from persisting. The root cause (hardcoded token in index.html)
  // has been fixed, so this guard is no longer needed and was causing real
  // admin logins to be cleared on every hard refresh.

  // Expose token globally for React app to use
  Object.defineProperty(window, "__WC_TOKEN", {
    get: () => _token,
    set: (v) => { _token = v; },
    configurable: true,
  });

  // ── Fetch interceptor — inject Authorization on all Railway calls ──────────
  const _origFetch = window.fetch.bind(window);
  window.fetch = function (input, init = {}) {
    const url = typeof input === "string" ? input : (input?.url || "");
    if (url.includes("wilbanks-server-production.up.railway.app") && _token) {
      init = {
        ...init,
        headers: {
          ...(init.headers || {}),
          Authorization: "Bearer " + _token,
        },
      };
    }
    return _origFetch(input, init);
  };

  // ── Auth state ─────────────────────────────────────────────────────────────
  let currentUser = null;

  // wc-v205: expose the logged-in role to the React app so Settings can gate the
  // admin-only "Admin Tools" tab. Persist to localStorage (synchronous read on
  // mount) and dispatch an event (live update if role resolves after mount).
  function publishUserRole(u) {
    try {
      var r = (u && u.role) ? String(u.role) : '';
      if (r) localStorage.setItem('wc_user_role', r);
      else localStorage.removeItem('wc_user_role');
      window.dispatchEvent(new CustomEvent('wc:user-role', { detail: r }));
    } catch (e) {}
  }

  function getSavedUsername() {
    try { return localStorage.getItem(USERNAME_KEY) || ""; } catch { return ""; }
  }
  function setSavedUsername(u) {
    try { localStorage.setItem(USERNAME_KEY, u); } catch {}
  }

  function hasPromptedWebAuthn() {
    try { return localStorage.getItem(WEBAUTHN_PROMPT_KEY) === "1"; } catch { return false; }
  }
  function markWebAuthnPrompted() {
    try { localStorage.setItem(WEBAUTHN_PROMPT_KEY, "1"); } catch {}
  }

  // ── WebAuthn helpers ───────────────────────────────────────────────────────
  function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = "";
    for (const b of bytes) str += String.fromCharCode(b);
    return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }
  function base64urlToBuffer(b64) {
    const b = b64.replace(/-/g, "+").replace(/_/g, "/");
    const str = atob(b);
    const buf = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i);
    return buf.buffer;
  }

  async function tryWebAuthnLogin(username) {
    try {
      const optRes = await _origFetch(API + "/api/auth/webauthn/authenticate/options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
      });
      if (!optRes.ok) return { error: "no_credential" };
      const options = await optRes.json();

      // Convert base64url fields
      options.challenge = base64urlToBuffer(options.challenge);
      if (options.allowCredentials) {
        options.allowCredentials = options.allowCredentials.map(c => ({
          ...c,
          id: base64urlToBuffer(c.id),
        }));
      }

      const credential = await navigator.credentials.get({ publicKey: options });
      if (!credential) return null;

      const assertionBody = {
        userId: options.userId,
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
          authenticatorData: bufferToBase64url(credential.response.authenticatorData),
          signature: bufferToBase64url(credential.response.signature),
          userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null,
        },
      };

      const verifyRes = await _origFetch(API + "/api/auth/webauthn/authenticate/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(assertionBody),
      });
      if (!verifyRes.ok) return null;
      return await verifyRes.json();
    } catch (e) {
      console.warn("[auth] WebAuthn failed:", e.message);
      return null;
    }
  }

  async function registerWebAuthn() {
    try {
      const optRes = await _origFetch(API + "/api/auth/webauthn/register/options", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + _token },
      });
      if (!optRes.ok) return false;
      const options = await optRes.json();

      options.challenge = base64urlToBuffer(options.challenge);
      options.user.id = base64urlToBuffer(options.user.id);
      if (options.excludeCredentials) {
        options.excludeCredentials = options.excludeCredentials.map(c => ({
          ...c,
          id: base64urlToBuffer(c.id),
        }));
      }

      const credential = await navigator.credentials.create({ publicKey: options });
      if (!credential) return false;

      const regBody = {
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
          attestationObject: bufferToBase64url(credential.response.attestationObject),
          transports: credential.response.getTransports ? credential.response.getTransports() : [],
        },
      };

      const verifyRes = await _origFetch(API + "/api/auth/webauthn/register/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + _token },
        body: JSON.stringify(regBody),
      });
      return verifyRes.ok;
    } catch (e) {
      console.warn("[auth] WebAuthn register failed:", e.message);
      return false;
    }
  }

  // ── UI rendering ───────────────────────────────────────────────────────────
  const CSS = `
    #wc-auth-overlay {
      position: fixed; inset: 0; z-index: 99999;
      background: #09090b;
      display: flex; align-items: center; justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      transition: opacity 0.35s ease;
    }
    #wc-auth-overlay.wc-fade-out { opacity: 0; pointer-events: none; }
    .wc-card {
      background: #18181b;
      border: 1px solid #27272a;
      border-radius: 16px;
      padding: 36px 32px;
      width: 100%;
      max-width: 380px;
      margin: 0 16px;
      box-shadow: 0 24px 80px rgba(0,0,0,0.6);
    }
    .wc-logo {
      display: flex; align-items: center; gap: 12px;
      margin-bottom: 28px;
    }
    .wc-logo img { width: 48px; height: 48px; border-radius: 10px; object-fit: cover; }
    .wc-logo-text { line-height: 1.2; }
    .wc-logo-text h1 { margin:0; font-size: 17px; font-weight: 700; color: #fafafa; }
    .wc-logo-text p { margin:0; font-size: 12px; color: #71717a; }
    .wc-title { font-size: 22px; font-weight: 700; color: #fafafa; margin: 0 0 6px; }
    .wc-subtitle { font-size: 14px; color: #71717a; margin: 0 0 24px; }
    .wc-field { margin-bottom: 16px; }
    .wc-label { display: block; font-size: 12px; font-weight: 500; color: #a1a1aa; margin-bottom: 6px; letter-spacing: 0.02em; text-transform: uppercase; }
    .wc-input {
      width: 100%; box-sizing: border-box;
      background: #09090b; border: 1px solid #3f3f46;
      border-radius: 8px; padding: 11px 14px;
      font-size: 15px; color: #fafafa; outline: none;
      transition: border-color 0.15s;
    }
    .wc-input:focus { border-color: #3b82f6; }
    .wc-input::placeholder { color: #52525b; }
    .wc-btn {
      width: 100%; padding: 12px;
      border: none; border-radius: 8px;
      font-size: 15px; font-weight: 600; cursor: pointer;
      transition: background 0.15s, opacity 0.15s;
      margin-bottom: 10px;
    }
    .wc-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .wc-btn-primary { background: #3b82f6; color: #fff; }
    .wc-btn-primary:hover:not(:disabled) { background: #2563eb; }
    .wc-btn-faceid {
      background: #18181b; color: #fafafa;
      border: 1px solid #3f3f46;
      display: flex; align-items: center; justify-content: center; gap: 10px;
    }
    .wc-btn-faceid:hover:not(:disabled) { background: #27272a; }
    .wc-error {
      background: #3f1212; border: 1px solid #7f1d1d;
      color: #fca5a5; border-radius: 8px;
      padding: 10px 14px; font-size: 13px;
      margin-bottom: 14px; display: none;
    }
    .wc-error.visible { display: block; }
    .wc-divider {
      display: flex; align-items: center; gap: 10px;
      margin: 14px 0; color: #3f3f46; font-size: 12px;
    }
    .wc-divider::before, .wc-divider::after {
      content: ''; flex: 1; height: 1px; background: #27272a;
    }
    .wc-spinner {
      width: 18px; height: 18px;
      border: 2px solid rgba(255,255,255,0.2);
      border-top-color: #fff;
      border-radius: 50%;
      animation: wc-spin 0.7s linear infinite;
      display: inline-block;
    }
    @keyframes wc-spin { to { transform: rotate(360deg); } }
    /* Password show/hide toggle */
    .wc-pw-wrap { position: relative; }
    .wc-pw-wrap .wc-input { padding-right: 42px; }
    .wc-eye-btn {
      position: absolute; right: 12px; top: 50%; transform: translateY(-50%);
      background: none; border: none; cursor: pointer; padding: 4px;
      color: #71717a; display: flex; align-items: center; justify-content: center;
      -webkit-tap-highlight-color: transparent; min-width: 32px; min-height: 32px;
    }
    .wc-eye-btn:hover { color: #a1a1aa; }

    /* Change password screen */
    .wc-change-pw-hint { font-size: 13px; color: #71717a; margin: 0 0 20px; }

    /* Face ID prompt */
    .wc-faceid-icon { font-size: 48px; text-align: center; margin-bottom: 12px; }
    .wc-faceid-desc { font-size: 14px; color: #a1a1aa; text-align: center; margin: 0 0 24px; line-height: 1.5; }
    .wc-btn-skip { background: transparent; color: #71717a; font-size: 14px; border: none; cursor: pointer; width: 100%; padding: 8px; text-decoration: underline; }
    .wc-btn-skip:hover { color: #a1a1aa; }
    /* ── Month Calendar Mobile Optimization ─────────────────────────── */
    /* Reduce cell height on mobile so days aren't elongated */
    @media (max-width: 640px) {
      /* Day cells: reduce minHeight override */
      [data-datestr] {
        min-height: 64px !important;
        padding-top: 24px !important;
      }
      /* Day number badge: slightly smaller */
      [data-datestr] .text-xs.font-semibold.w-6.h-6 {
        width: 20px !important;
        height: 20px !important;
        font-size: 10px !important;
      }
      /* Day-of-week header: compact */
      .grid.grid-cols-7 > div.text-\[11px\] {
        padding-top: 4px !important;
        padding-bottom: 4px !important;
        font-size: 10px !important;
      }
      /* Event chips inside cells: tighter */
      [data-datestr] .rounded-sm,
      [data-datestr] [class*="rounded"] {
        padding: 1px 3px !important;
        font-size: 9px !important;
        line-height: 1.2 !important;
      }
    }
    @media (max-width: 390px) {
      [data-datestr] {
        min-height: 54px !important;
        padding-top: 22px !important;
      }
    }
  `;

  function injectStyles() {
    if (document.getElementById("wc-auth-styles")) return;
    const el = document.createElement("style");
    el.id = "wc-auth-styles";
    el.textContent = CSS;
    document.head.appendChild(el);
  }

  function showOverlay(html) {
    injectStyles();
    let overlay = document.getElementById("wc-auth-overlay");
    if (!overlay) {
      overlay = document.createElement("div");
      overlay.id = "wc-auth-overlay";
      document.body.appendChild(overlay);
    }
    overlay.innerHTML = `<div class="wc-card">${html}</div>`;
    overlay.classList.remove("wc-fade-out");
    return overlay;
  }

  function dismissOverlay() {
    const overlay = document.getElementById("wc-auth-overlay");
    if (overlay) {
      overlay.classList.add("wc-fade-out");
      setTimeout(() => overlay.remove(), 400);
    }
    // Unhide root
    const root = document.getElementById("root");
    if (root) root.style.display = "";
    // Signal React app that auth is complete so it re-fires all queries
    window.__WC_AUTH_READY = true;
    try { window.dispatchEvent(new CustomEvent("wc:auth-ready")); } catch {}
  }

  // ── Login screen ──────────────────────────────────────────────────────────
  function renderLogin(errorMsg = "") {
    const savedUsername = getSavedUsername();
    const faceIdAvailable = window.PublicKeyCredential && typeof navigator.credentials?.get === "function";

    const faceIdHtml = faceIdAvailable && savedUsername ? `
      <div class="wc-divider">or</div>
      <button class="wc-btn wc-btn-faceid" id="wc-faceid-btn">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round">
          <circle cx="12" cy="12" r="9"/>
          <circle cx="9" cy="10.5" r="1" fill="currentColor" stroke="none"/>
          <circle cx="15" cy="10.5" r="1" fill="currentColor" stroke="none"/>
          <path d="M8.5 14.5 Q12 17.5 15.5 14.5"/>
        </svg>
        Sign in with Face ID
      </button>
    ` : "";

    const overlay = showOverlay(`
      <div class="wc-logo">
        <img src="./assets/logo-DmC-dsba.jpg" alt="Wilbanks" />
        <div class="wc-logo-text">
          <h1>Wilbanks Company</h1>
          <p>Cooling &bull; Heating &bull; Plumbing</p>
        </div>
      </div>
      <h2 class="wc-title">Sign In</h2>
      <p class="wc-subtitle">Enter your credentials to continue</p>
      <div class="wc-error${errorMsg ? " visible" : ""}" id="wc-error">${errorMsg}</div>
      <div class="wc-field">
        <label class="wc-label" for="wc-username">Username</label>
        <input class="wc-input" id="wc-username" type="text" placeholder="username" autocomplete="username" autocapitalize="none" value="${savedUsername}" />
      </div>
      <div class="wc-field">
        <label class="wc-label" for="wc-password">Password</label>
        <div class="wc-pw-wrap"><input class="wc-input" id="wc-password" type="password" placeholder="••••••••" autocomplete="current-password" /><button type="button" class="wc-eye-btn" id="wc-eye-login" aria-label="Show password" tabindex="-1"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button></div>
      </div>
      <button class="wc-btn wc-btn-primary" id="wc-login-btn">Sign In</button>
      ${faceIdHtml}
    `);

    const usernameInput = overlay.querySelector("#wc-username");
    const passwordInput = overlay.querySelector("#wc-password");
    const loginBtn = overlay.querySelector("#wc-login-btn");
    const errorEl = overlay.querySelector("#wc-error");
    const faceIdBtn = overlay.querySelector("#wc-faceid-btn");

    // Focus
    setTimeout(() => {
      if (savedUsername) passwordInput?.focus();
      else usernameInput?.focus();
    }, 100);

    const eyeLoginBtn = overlay.querySelector("#wc-eye-login");
    if (eyeLoginBtn) {
      eyeLoginBtn.addEventListener("click", () => {
        const show = passwordInput.type === "password";
        passwordInput.type = show ? "text" : "password";
        eyeLoginBtn.innerHTML = show ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>` : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
      });
    }

    function showError(msg) {
      errorEl.textContent = msg;
      errorEl.classList.add("visible");
    }

    async function doLogin() {
      const username = usernameInput.value.trim();
      const password = passwordInput.value;
      if (!username || !password) { showError("Please enter your username and password."); return; }
      loginBtn.disabled = true;
      loginBtn.innerHTML = '<span class="wc-spinner"></span>';
      errorEl.classList.remove("visible");

      try {
        const res = await _origFetch(API + "/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }),
        });
        const data = await res.json();
        if (!res.ok) { showError(data.error || "Login failed"); loginBtn.disabled = false; loginBtn.textContent = "Sign In"; return; }
        setSavedUsername(username);
        onLoginSuccess(data.token, data.user);
      } catch (e) {
        showError("Connection error. Please try again.");
        loginBtn.disabled = false;
        loginBtn.textContent = "Sign In";
      }
    }

    loginBtn.addEventListener("click", doLogin);
    passwordInput.addEventListener("keydown", e => { if (e.key === "Enter") doLogin(); });
    usernameInput.addEventListener("keydown", e => { if (e.key === "Enter") passwordInput.focus(); });

    if (faceIdBtn) {
      faceIdBtn.addEventListener("click", async () => {
        const username = usernameInput.value.trim() || savedUsername;
        if (!username) { showError("Enter your username first, then try Face ID."); return; }
        faceIdBtn.disabled = true;
        faceIdBtn.innerHTML = '<span class="wc-spinner"></span> Checking Face ID...';
        const result = await tryWebAuthnLogin(username);
        if (result?.token) {
          try { localStorage.setItem(WEBAUTHN_VALID_KEY, '1'); } catch {}
          setSavedUsername(username);
          onLoginSuccess(result.token, result.user);
        } else {
          try {
            localStorage.removeItem(WEBAUTHN_PROMPT_KEY);
            localStorage.removeItem(WEBAUTHN_VALID_KEY);
          } catch {}
          faceIdBtn.disabled = false;
          faceIdBtn.innerHTML = `
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round">
              <circle cx="12" cy="12" r="9"/>
              <circle cx="9" cy="10.5" r="1" fill="currentColor" stroke="none"/>
              <circle cx="15" cy="10.5" r="1" fill="currentColor" stroke="none"/>
              <path d="M8.5 14.5 Q12 17.5 15.5 14.5"/>
            </svg>
            Sign in with Face ID`;
          if (result?.error === 'no_credential') {
            showError("Face ID isn't set up yet. Sign in with your password below — you'll be prompted to enable Face ID right after.");
          } else {
            showError("Face ID failed. Sign in with your password — you'll be prompted to re-enable Face ID after logging in.");
          }
        }
      });
    }
  }

  // ── Change Password screen ────────────────────────────────────────────────
  function renderChangePassword() {
    const overlay = showOverlay(`
      <div class="wc-logo">
        <img src="./assets/logo-DmC-dsba.jpg" alt="Wilbanks" />
        <div class="wc-logo-text">
          <h1>Wilbanks Company</h1>
          <p>Cooling &bull; Heating &bull; Plumbing</p>
        </div>
      </div>
      <h2 class="wc-title">Set Your Password</h2>
      <p class="wc-change-pw-hint">This is your first login. Please create a new password to continue.</p>
      <div class="wc-error" id="wc-error"></div>
      <div class="wc-field">
        <label class="wc-label" for="wc-newpw">New Password</label>
        <div class="wc-pw-wrap"><input class="wc-input" id="wc-newpw" type="password" placeholder="At least 6 characters" autocomplete="new-password" /><button type="button" class="wc-eye-btn" id="wc-eye-newpw" aria-label="Show password" tabindex="-1"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button></div>
      </div>
      <div class="wc-field">
        <label class="wc-label" for="wc-confirmpw">Confirm Password</label>
        <div class="wc-pw-wrap"><input class="wc-input" id="wc-confirmpw" type="password" placeholder="Re-enter password" autocomplete="new-password" /><button type="button" class="wc-eye-btn" id="wc-eye-confirmpw" aria-label="Show password" tabindex="-1"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button></div>
      </div>
      <button class="wc-btn wc-btn-primary" id="wc-setpw-btn">Set Password & Continue</button>
    `);

    const newPw = overlay.querySelector("#wc-newpw");
    const confirmPw = overlay.querySelector("#wc-confirmpw");
    const btn = overlay.querySelector("#wc-setpw-btn");
    const errorEl = overlay.querySelector("#wc-error");

    setTimeout(() => newPw?.focus(), 100);

    const eyeNewBtn = overlay.querySelector("#wc-eye-newpw");
    const eyeConfBtn = overlay.querySelector("#wc-eye-confirmpw");
    if (eyeNewBtn) {
      eyeNewBtn.addEventListener("click", () => {
        const show = newPw.type === "password";
        newPw.type = show ? "text" : "password";
        eyeNewBtn.innerHTML = show ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>` : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
      });
    }
    if (eyeConfBtn) {
      eyeConfBtn.addEventListener("click", () => {
        const show = confirmPw.type === "password";
        confirmPw.type = show ? "text" : "password";
        eyeConfBtn.innerHTML = show ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>` : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
      });
    }

    async function doChange() {
      const pw = newPw.value;
      const cpw = confirmPw.value;
      if (pw.length < 6) { errorEl.textContent = "Password must be at least 6 characters."; errorEl.classList.add("visible"); return; }
      if (pw !== cpw) { errorEl.textContent = "Passwords don't match."; errorEl.classList.add("visible"); return; }
      btn.disabled = true;
      btn.innerHTML = '<span class="wc-spinner"></span>';
      try {
        const res = await _origFetch(API + "/api/auth/change-password", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: "Bearer " + _token },
          body: JSON.stringify({ newPassword: pw }),
        });
        const data = await res.json();
        if (!res.ok) { errorEl.textContent = data.error || "Error setting password"; errorEl.classList.add("visible"); btn.disabled = false; btn.textContent = "Set Password & Continue"; return; }
        // Update token
        saveToken(data.token);
        currentUser = { ...currentUser, mustChangePassword: false };
        // Proceed to Face ID prompt or app
        afterPasswordSet();
      } catch {
        errorEl.textContent = "Connection error.";
        errorEl.classList.add("visible");
        btn.disabled = false;
        btn.textContent = "Set Password & Continue";
      }
    }

    btn.addEventListener("click", doChange);
    confirmPw.addEventListener("keydown", e => { if (e.key === "Enter") doChange(); });
  }

  // ── Face ID prompt ─────────────────────────────────────────────────────────
  function renderFaceIdPrompt() {
    const overlay = showOverlay(`
      <div class="wc-faceid-icon">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="1.5" stroke-linecap="round">
          <circle cx="12" cy="12" r="9"/>
          <circle cx="9" cy="10.5" r="1" fill="#3b82f6" stroke="none"/>
          <circle cx="15" cy="10.5" r="1" fill="#3b82f6" stroke="none"/>
          <path d="M8.5 14.5 Q12 17.5 15.5 14.5"/>
        </svg>
      </div>
      <h2 class="wc-title" style="text-align:center">Enable Face ID?</h2>
      <p class="wc-faceid-desc">Skip the password next time. Sign in instantly with your face using Face ID.</p>
      <div class="wc-error" id="wc-error"></div>
      <button class="wc-btn wc-btn-primary" id="wc-enable-faceid">Enable Face ID</button>
      <button class="wc-btn-skip" id="wc-skip-faceid">Not now</button>
    `);

    const enableBtn = overlay.querySelector("#wc-enable-faceid");
    const skipBtn = overlay.querySelector("#wc-skip-faceid");
    const errorEl = overlay.querySelector("#wc-error");

    enableBtn.addEventListener("click", async () => {
      enableBtn.disabled = true;
      enableBtn.innerHTML = '<span class="wc-spinner"></span> Setting up...';
      const ok = await registerWebAuthn();
      if (ok) {
        markWebAuthnPrompted();
        try { localStorage.setItem(WEBAUTHN_VALID_KEY, '1'); } catch {}
        launchApp();
      } else {
        errorEl.textContent = "Face ID setup failed. You can enable it later in settings.";
        errorEl.classList.add("visible");
        enableBtn.disabled = false;
        enableBtn.textContent = "Try Again";
      }
    });

    skipBtn.addEventListener("click", () => {
      markWebAuthnPrompted();
      launchApp();
    });
  }

  // ── Flow control ──────────────────────────────────────────────────────────
  function onLoginSuccess(token, user) {
    saveToken(token);
    currentUser = user;
    window.__WC_USER = user;
    publishUserRole(user);

    // Determine which app we're on
    const isDashboard = !window.location.pathname.includes('fieldtech') &&
                        !window.location.href.includes('wilbanks-fieldtech');
    // 'tech' can only access field tech app
    if (user.role === 'tech' && isDashboard) {
      clearToken();
      renderLogin('Field Tech accounts can only access the Field Tech app, not the dashboard.');
      return;
    }
    // 'dispatcher' can only access dashboard (admin can access both)
    if (user.role === 'dispatcher' && !isDashboard) {
      clearToken();
      renderLogin('Dashboard accounts cannot access the Field Tech app.');
      return;
    }
    // 'both' role can access either app — no block needed

    if (user.mustChangePassword) {
      renderChangePassword();
    } else {
      afterPasswordSet();
    }
  }

  function afterPasswordSet() {
    const faceIdAvailable = window.PublicKeyCredential && typeof navigator.credentials?.get === "function";
    const alreadyPrompted = hasPromptedWebAuthn();
    const hasWebAuthn = currentUser?.hasWebAuthn;
    const credentialValid = localStorage.getItem(WEBAUTHN_VALID_KEY) === '1';
    // Only offer Face ID to field tech users (tech/both) — not dashboard-only roles
    const isTechRole = true; // All roles can use Face ID

    if (faceIdAvailable && isTechRole) {
      // Credentials are stale if server has them but they've never successfully
      // authenticated (WEBAUTHN_VALID_KEY not set) — wipe and re-prompt
      const stale = (hasWebAuthn || alreadyPrompted) && !credentialValid;
      if (stale) {
        // wc-v224: prefer in-memory; fall back to either storage tier.
        const tok = _token || sessionStorage.getItem(TOKEN_KEY) || localStorage.getItem(TOKEN_KEY) || '';
        const wipe = tok
          ? _origFetch(API + '/api/auth/webauthn', { method: 'DELETE', headers: { 'Authorization': 'Bearer ' + tok } }).catch(() => {})
          : Promise.resolve();
        wipe.then(() => {
          try {
            localStorage.removeItem(WEBAUTHN_PROMPT_KEY);
            localStorage.removeItem(WEBAUTHN_VALID_KEY);
          } catch {}
          currentUser.hasWebAuthn = false;
          renderFaceIdPrompt();
        });
        return;
      }
      // Already set up and working — skip prompt
      if (alreadyPrompted && credentialValid) { launchApp(); return; }
      // Fresh user — never prompted yet
      renderFaceIdPrompt();
    } else {
      launchApp();
    }
  }

  // wc-v245: Reset Dashboard view + filters on FRESH login.
  // These prefs are server-stored (per-user) so the logout localStorage/
  // sessionStorage sweep alone is not enough — without this, login restores
  // the prior session's view mode (list) and filters (e.g. "Dexter Tanner").
  // Resets: wc_dash_view→"calendar", wc_dash_tab→"active", all four
  // wc_dash_*_filter keys cleared. wc_default_cal_view (the user's chosen
  // calendar mode: month/week/day/tech) is NOT touched — the calendar still
  // opens in their default mode. This runs ONLY in launchApp(), so existing-
  // session refreshes (bootstrap path) preserve in-tab state as before.
  async function resetDashStateOnFreshLogin() {
    if (!_token) return;
    try {
      await _origFetch(API + "/api/user/preferences", {
        method: "PUT",
        headers: {
          "Authorization": "Bearer " + _token,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          prefs: {
            wc_dash_view: "calendar",
            wc_dash_tab: "active",
            wc_dash_status_filter: null,
            wc_dash_service_filter: null,
            wc_dash_date_filter: null,
            wc_dash_tech_filter: "all",
          },
        }),
      });
    } catch (e) {
      // Best-effort — never block login if this fails. Server stays at prior
      // values; user can clear filters manually.
    }
    // Also clear the wc-v222 pre-paint cache for THIS user so the next boot
    // does not paint a stale dashboard view from cache before hydration.
    try {
      var uid = currentUser && (currentUser.id || currentUser.user_id);
      if (uid != null) {
        var cacheKey = "wc_prefs_cache_" + uid;
        var raw = localStorage.getItem(cacheKey);
        if (raw) {
          try {
            var c = JSON.parse(raw);
            if (c && typeof c === "object") {
              c.wc_dash_view = "calendar";
              c.wc_dash_tab = "active";
              delete c.wc_dash_status_filter;
              delete c.wc_dash_service_filter;
              delete c.wc_dash_date_filter;
              c.wc_dash_tech_filter = "all";
              localStorage.setItem(cacheKey, JSON.stringify(c));
            }
          } catch (e2) { /* ignore */ }
        }
      }
    } catch (e3) { /* ignore */ }
  }

  async function launchApp() {
    window.__WC_USER = currentUser;
    publishUserRole(currentUser);
    window.__WC_LOGOUT = logout;
    // wc-v245: Reset dashboard view + filters BEFORE dismissOverlay so that
    // when React hydrates prefs (triggered by wc:auth-ready fired inside
    // dismissOverlay), the GET /preferences returns the already-reset state.
    // We await so React never sees the stale values, even briefly.
    await resetDashStateOnFreshLogin();
    dismissOverlay();
    // wc-v243: A FRESH LOGIN must land on the default route. Do NOT restore
    // wc_last_hash here — that key is for the existing-session refresh path in
    // bootstrap() (same tab, same session, page reloaded). If it's still in
    // sessionStorage at this point, it's stale (e.g. the prior session's
    // logout sweep raced with the pagehide listener that re-wrote it). Wipe
    // it defensively and ensure the URL hash is clean so wouter renders the
    // default landing screen.
    try { sessionStorage.removeItem('wc_last_hash'); } catch {}
    try {
      if (window.location.hash && window.location.hash !== '#/' && window.location.hash !== '#') {
        // Clear the hash without triggering a navigation/scroll — use replaceState.
        history.replaceState(null, '', window.location.pathname + window.location.search);
      }
    } catch {}
    // Sync display name into the field tech app's localStorage key
    // so the top-left header always shows the logged-in user's name
    syncFieldTechName(currentUser);
    // Inject the sidebar Sign Out button + Admin Tools nav after a FRESH login.
    // The React app does NOT render these natively, so they must be injected
    // here just like bootstrap() does for a token-already-present page load.
    // Multiple intervals survive React re-renders during initial mount.
    setTimeout(function() { injectAdminToolsNav(); injectRecordPaymentButtons(); injectRecordPaymentDetailPage(); }, 300);
    setTimeout(function() { injectAdminToolsNav(); injectRecordPaymentButtons(); injectRecordPaymentDetailPage(); }, 800);
    setTimeout(function() { injectAdminToolsNav(); injectRecordPaymentButtons(); injectRecordPaymentDetailPage(); }, 1600);
    setTimeout(function() { injectLogoutButton(); }, 1500);
    // Start inactivity timer
    startInactivityTimer();
  }

  // ── Inactivity timeout ─────────────────────────────────────────────────────
  // Dashboard: 30 minutes. Field app: 24 hours.
  const LAST_ACTIVE_KEY = 'wc_last_active';
  let _inactivityInterval = null;

  function getInactivityLimit() {
    const isDashboard = !window.location.pathname.includes('fieldtech') &&
                        !window.location.href.includes('wilbanks-fieldtech');
    return isDashboard ? 30 * 60 * 1000 : 24 * 60 * 60 * 1000; // 30min or 24hr in ms
  }

  function touchActivity() {
    try { localStorage.setItem(LAST_ACTIVE_KEY, Date.now().toString()); } catch {}
  }

  function startInactivityTimer() {
    // Record activity now
    touchActivity();
    // Listen for any user interaction
    ['mousemove','mousedown','keydown','touchstart','scroll','click'].forEach(evt => {
      window.addEventListener(evt, touchActivity, { passive: true });
    });
    // Check every minute
    if (_inactivityInterval) clearInterval(_inactivityInterval);
    _inactivityInterval = setInterval(() => {
      try {
        const last = parseInt(localStorage.getItem(LAST_ACTIVE_KEY) || '0', 10);
        if (last && Date.now() - last > getInactivityLimit()) {
          clearInterval(_inactivityInterval);
          _inactivityInterval = null;
          logout();
          setTimeout(() => {
            const err = document.getElementById('wc-error');
            if (err) {
              err.textContent = 'You were logged out due to inactivity.';
              err.classList.add('visible');
            }
          }, 300);
        }
      } catch {}
    }, 60 * 1000); // check every 60 seconds
  }

  function syncFieldTechName(user) {
    if (!user) return;
    const isDashboard = !window.location.pathname.includes('fieldtech') &&
                        !window.location.href.includes('wilbanks-fieldtech') &&
                        !window.location.href.includes('fieldtech');
    if (isDashboard) return; // only needed on field tech app
    try {
      const name = user.displayName || user.username || '';
      localStorage.setItem('wc_tech_name', name);
      // Dispatch storage event so React state in hb() picks up the new value
      // even though it was set in the same window (storage event normally only
      // fires in OTHER windows, so we dispatch it manually)
      window.dispatchEvent(new StorageEvent('storage', {
        key: 'wc_tech_name',
        newValue: name,
        storageArea: localStorage
      }));
    } catch {}
  }


  // ── User Management ────────────────────────────────────────────────────────
  function injectAdminToolsNav() {
    // wc-v203: Admin Tools folder retired from the left sidebar. All four items
    // (Settings, Users & Roles, Audit Log, Deleted Jobs) now live as tabs inside
    // the React Settings page. Also clean up any previously-injected group that a
    // stale cached build may have left in the DOM.
    document.getElementById('wc-admin-tools-group')?.remove();
    return;
    /* eslint-disable no-unreachable */
    const role = currentUser?.role;
    if (role !== 'admin') return;
    const isAdmin = true;

    // Track collapsed state across re-injections; auto-open when on an admin page
    if (typeof window._wcAdminOpen === 'undefined') window._wcAdminOpen = false;
    const _curHash = window.location.hash;
    if (_curHash.includes('audit-log') || _curHash.includes('deleted-jobs') || _curHash.includes('/settings')) window._wcAdminOpen = true;

    function buildGroup(refLink) {
      // Remove old group if present
      const old = document.getElementById('wc-admin-tools-group');
      if (old) old.remove();

      const isDark = document.documentElement.classList.contains('dark');
      const open = window._wcAdminOpen;
      const hash = window.location.hash;
      const isActive = hash.includes('audit-log') || hash.includes('deleted-jobs') || hash.includes('/settings');

      const group = document.createElement('div');
      group.id = 'wc-admin-tools-group';
      group.style.cssText = 'margin-bottom:2px;';

      // Folder toggle button
      const toggle = document.createElement('button');
      toggle.style.cssText = `
        display:flex; align-items:center; gap:10px;
        width:100%; padding:8px 12px;
        background:${isActive ? 'hsl(var(--primary))' : 'transparent'};
        color:${isActive ? 'hsl(var(--primary-foreground))' : 'hsl(var(--muted-foreground))'};
        border:none; border-radius:6px; cursor:pointer;
        font-size:14px; font-weight:500; font-family:inherit;
        text-align:left; transition:background 0.15s;
      `;
      toggle.onmouseenter = () => { if (!isActive) toggle.style.background = 'hsl(var(--muted))'; toggle.style.color = 'hsl(var(--foreground))'; };
      toggle.onmouseleave = () => { if (!isActive) { toggle.style.background = 'transparent'; toggle.style.color = 'hsl(var(--muted-foreground))'; } };
      toggle.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0">
          <rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/>
        </svg>
        <span style="flex:1">Admin Tools</span>
        <svg id="wc-admin-chevron" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"
          style="flex-shrink:0;transition:transform 0.2s;transform:rotate(${open ? 180 : 0}deg)">
          <polyline points="6 9 12 15 18 9"/>
        </svg>
      `;

      // Sub-items container
      const sub = document.createElement('div');
      sub.id = 'wc-admin-sub';
      sub.style.cssText = `overflow:hidden; max-height:${open ? '200px' : '0'}; transition:max-height 0.2s ease;`;

      function makeSubItem({ label, href, onClick, svgPath, active }) {
        const el = document.createElement(href ? 'a' : 'button');
        if (href) el.href = href;
        el.style.cssText = `
          display:flex; align-items:center; gap:10px;
          width:100%; padding:6px 12px 6px 36px;
          background:${active ? 'hsl(var(--primary)/0.15)' : 'transparent'};
          color:${active ? 'hsl(var(--primary))' : 'hsl(var(--muted-foreground))'};
          border:none; border-radius:6px; cursor:pointer;
          font-size:13px; font-weight:500; font-family:inherit;
          text-decoration:none; text-align:left; transition:background 0.15s;
          margin-bottom:1px;
        `;
        el.onmouseenter = () => { if (!active) { el.style.background = 'hsl(var(--muted))'; el.style.color = 'hsl(var(--foreground))'; } };
        el.onmouseleave = () => { if (!active) { el.style.background = 'transparent'; el.style.color = 'hsl(var(--muted-foreground))'; } };
        el.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0">${svgPath}</svg><span>${label}</span>`;
        if (onClick) el.addEventListener('click', onClick);
        return el;
      }

      const items = [];
      items.push(makeSubItem({
        label: 'Settings', href: '#/settings', active: hash.includes('/settings'),
        svgPath: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
        onClick: null,
      }));
      if (isAdmin) {
        items.push(makeSubItem({
          label: 'Users', href: '#/users', active: hash.includes('/users'),
          svgPath: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
          onClick: null,
        }));
      }
      items.push(makeSubItem({
        label: 'Audit Log', href: '#/audit-log', active: hash.includes('audit-log'),
        svgPath: '<path d="M3 3v5h5"/><path d="M3.05 13A9 9 0 1 0 6 5.3L3 8"/><path d="M12 7v5l4 2"/>',
        onClick: null,
      }));
      items.push(makeSubItem({
        label: 'Deleted Jobs', href: '#/deleted-jobs', active: hash.includes('deleted-jobs'),
        svgPath: '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>',
        onClick: null,
      }));

      items.forEach(item => sub.appendChild(item));

      toggle.addEventListener('click', () => {
        window._wcAdminOpen = !window._wcAdminOpen;
        const chevron = toggle.querySelector('#wc-admin-chevron');
        if (window._wcAdminOpen) {
          sub.style.maxHeight = '200px';
          if (chevron) chevron.style.transform = 'rotate(180deg)';
        } else {
          sub.style.maxHeight = '0';
          if (chevron) chevron.style.transform = 'rotate(0deg)';
        }
      });

      group.appendChild(toggle);
      group.appendChild(sub);
      return group;
    }

    function tryInjectDesktop() {
      // Anchor to the <nav> inside the sidebar <aside>
      const nav = document.querySelector('aside nav');
      if (!nav) return false;
      if (document.getElementById('wc-admin-tools-group')) return true;

      const group = buildGroup(nav);
      nav.appendChild(group);
      return true;
    }

    if (!tryInjectDesktop()) {
      const obs = new MutationObserver(() => { if (tryInjectDesktop()) obs.disconnect(); });
      obs.observe(document.body, { childList: true, subtree: true });
      setTimeout(() => obs.disconnect(), 10000);
    }

    // Re-inject on navigation (React wipes injected DOM on route changes)
    // Guard: only register this listener once even if injectAdminToolsNav is called multiple times
    if (!window._wcNavHashListenerAdded) {
      window._wcNavHashListenerAdded = true;
      window.addEventListener('hashchange', (e) => {
        // Clear detail injection lock only when navigating AWAY from an appointment page.
        // If navigating TO #/appointment/id, do NOT reset — a concurrent MO call may have
        // already set the lock and we must not race-reset it before the 300ms callback fires.
        var prevHash = (e && e.oldURL ? e.oldURL.split('#')[1] : '') || '';
        var prevMatch = prevHash.match(/^\/appointment\/(\d+)/);
        if (prevMatch) {
          // Only clear the lock for the appointment we just left
          delete _wcDetailInjectLock[parseInt(prevMatch[1])];
        }
        setTimeout(() => {
          document.getElementById('wc-admin-tools-group')?.remove();
          tryInjectDesktop();
          injectRecordPaymentDetailPage();
        }, 300);
      });
    }

    // Watch for React wiping the nav (e.g. on refresh) and re-inject immediately
    const _wcNavObserver = new MutationObserver(function() {
      if (!document.getElementById('wc-admin-tools-group')) {
        const nav = document.querySelector('aside nav');
        if (nav) { buildGroup(nav); nav.appendChild(document.getElementById('wc-admin-tools-group') || buildGroup(nav)); }
        tryInjectDesktop();
      }
    });
    const _wcNavEl = document.querySelector('aside nav');
    if (_wcNavEl) _wcNavObserver.observe(_wcNavEl.parentElement || document.body, { childList: true, subtree: true });
    else {
      // Nav not mounted yet — observe body until it appears then attach
      const _wcBodyObs = new MutationObserver(function() {
        const nav = document.querySelector('aside nav');
        if (nav) {
          _wcBodyObs.disconnect();
          _wcNavObserver.observe(nav.parentElement || document.body, { childList: true, subtree: true });
        }
      });
      _wcBodyObs.observe(document.body, { childList: true, subtree: true });
    }
  }

  function openUsersPanel() {
    if (document.getElementById('wc-users-panel')) return;
    injectStyles();

    const panel = document.createElement('div');
    panel.id = 'wc-users-panel';
    Object.assign(panel.style, {
      position: 'fixed', inset: '0', zIndex: '99990',
      background: 'rgba(0,0,0,0.7)', display: 'flex',
      alignItems: 'center', justifyContent: 'center',
      fontFamily: '-apple-system, BlinkMacSystemFont, sans-serif',
    });
    panel.innerHTML = `
      <div style="background:#18181b;border:1px solid #27272a;border-radius:16px;width:100%;max-width:560px;margin:16px;max-height:90vh;display:flex;flex-direction:column;box-shadow:0 24px 80px rgba(0,0,0,0.6)">
        <div style="padding:20px 24px 16px;border-bottom:1px solid #27272a;display:flex;align-items:center;justify-content:space-between;flex-shrink:0">
          <div>
            <h2 style="margin:0;font-size:18px;font-weight:700;color:#fafafa">User Management</h2>
            <p style="margin:4px 0 0;font-size:13px;color:#71717a">Manage who can access the apps</p>
          </div>
          <button id="wc-users-close" style="background:transparent;border:none;color:#71717a;cursor:pointer;font-size:20px;padding:4px 8px;line-height:1">&times;</button>
        </div>
        <div style="padding:20px 24px;border-bottom:1px solid #27272a;flex-shrink:0">
          <h3 style="margin:0 0 14px;font-size:14px;font-weight:600;color:#a1a1aa;text-transform:uppercase;letter-spacing:0.05em">Add New User</h3>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
            <div>
              <label style="display:block;font-size:12px;color:#71717a;margin-bottom:5px">USERNAME</label>
              <input id="wc-new-username" placeholder="e.g. john" style="width:100%;box-sizing:border-box;background:#09090b;border:1px solid #3f3f46;border-radius:8px;padding:9px 12px;font-size:14px;color:#fafafa;outline:none" />
            </div>
            <div>
              <label style="display:block;font-size:12px;color:#71717a;margin-bottom:5px">ROLE</label>
              <select id="wc-new-role" style="width:100%;box-sizing:border-box;background:#09090b;border:1px solid #3f3f46;border-radius:8px;padding:9px 12px;font-size:14px;color:#fafafa;outline:none">
                <option value="tech">Field Tech Only</option>
                <option value="dispatcher">Dashboard Only</option>
                <option value="both">Dashboard + Field Tech</option>
                <option value="admin">Admin (Dashboard + Users)</option>
              </select>
            </div>
          </div>
          <div style="margin-bottom:12px">
            <label style="display:block;font-size:12px;color:#71717a;margin-bottom:5px">DISPLAY NAME (optional)</label>
            <input id="wc-new-displayname" placeholder="Full name shown in app" style="width:100%;box-sizing:border-box;background:#09090b;border:1px solid #3f3f46;border-radius:8px;padding:9px 12px;font-size:14px;color:#fafafa;outline:none" />
          </div>
          <div style="display:flex;align-items:center;gap:10px">
            <div style="flex:1">
              <label style="display:block;font-size:12px;color:#71717a;margin-bottom:5px">TEMP PASSWORD</label>
              <input id="wc-new-password" type="text" value="Wilbanks1!" style="width:100%;box-sizing:border-box;background:#09090b;border:1px solid #3f3f46;border-radius:8px;padding:9px 12px;font-size:14px;color:#fafafa;outline:none" />
            </div>
            <button id="wc-add-user-btn" style="background:#3b82f6;border:none;color:#fff;border-radius:8px;padding:9px 20px;font-size:14px;font-weight:600;cursor:pointer;white-space:nowrap;margin-top:18px">Add User</button>
          </div>
          <div id="wc-add-error" style="display:none;margin-top:8px;background:#3f1212;border:1px solid #7f1d1d;color:#fca5a5;border-radius:6px;padding:8px 12px;font-size:13px"></div>
          <div id="wc-add-success" style="display:none;margin-top:8px;background:#14532d;border:1px solid #166534;color:#86efac;border-radius:6px;padding:8px 12px;font-size:13px"></div>
        </div>
        <div style="flex:1;overflow-y:auto;padding:16px 24px" id="wc-user-list-container">
          <h3 style="margin:0 0 14px;font-size:14px;font-weight:600;color:#a1a1aa;text-transform:uppercase;letter-spacing:0.05em">Existing Users</h3>
          <div id="wc-user-list"><div style="color:#52525b;font-size:14px">Loading...</div></div>
        </div>
      </div>
    `;

    document.body.appendChild(panel);
    document.getElementById('wc-users-close').addEventListener('click', () => panel.remove());
    panel.addEventListener('click', e => { if (e.target === panel) panel.remove(); });

    loadUserList();

    document.getElementById('wc-add-user-btn').addEventListener('click', async () => {
      const username = document.getElementById('wc-new-username').value.trim().toLowerCase();
      const role = document.getElementById('wc-new-role').value;
      const displayName = document.getElementById('wc-new-displayname').value.trim();
      const password = document.getElementById('wc-new-password').value.trim();
      const errEl = document.getElementById('wc-add-error');
      const okEl = document.getElementById('wc-add-success');
      errEl.style.display = 'none';
      okEl.style.display = 'none';

      if (!username) { errEl.textContent = 'Username is required.'; errEl.style.display = 'block'; return; }
      if (!password || password.length < 6) { errEl.textContent = 'Password must be at least 6 characters.'; errEl.style.display = 'block'; return; }

      const btn = document.getElementById('wc-add-user-btn');
      btn.disabled = true; btn.textContent = 'Adding...';

      try {
        const res = await fetch(API + '/api/auth/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + _token },
          body: JSON.stringify({ username, password, role, displayName: displayName || undefined }),
        });
        const data = await res.json();
        if (!res.ok) { errEl.textContent = data.error || 'Failed to create user'; errEl.style.display = 'block'; }
        else {
          okEl.textContent = `User "${username}" created. Temp password: ${password} (they will be asked to change it on first login)`;
          okEl.style.display = 'block';
          document.getElementById('wc-new-username').value = '';
          document.getElementById('wc-new-displayname').value = '';
          document.getElementById('wc-new-password').value = 'Wilbanks1!';
          loadUserList();
        }
      } catch { errEl.textContent = 'Connection error.'; errEl.style.display = 'block'; }
      btn.disabled = false; btn.textContent = 'Add User';
    });
  }

  async function loadUserList() {
    const container = document.getElementById('wc-user-list');
    if (!container) return;
    container.innerHTML = '<div style="color:#52525b;font-size:14px">Loading...</div>';
    try {
      const res = await fetch(API + '/api/auth/users', {
        headers: { Authorization: 'Bearer ' + _token },
      });
      const users = await res.json();
      if (!users.length) { container.innerHTML = '<div style="color:#52525b;font-size:14px">No users yet.</div>'; return; }

      container.innerHTML = users.map(u => `
        <div id="wc-user-row-${u.id}" style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:#09090b;border:1px solid #27272a;border-radius:8px;margin-bottom:8px">
          <div>
            <div style="font-size:14px;font-weight:600;color:#fafafa">${u.display_name || u.username} <span style="font-size:12px;color:#52525b;font-weight:400">@${u.username}</span></div>
            <div style="font-size:12px;color:#71717a;margin-top:2px">${u.role === 'admin' ? '🔑 Admin (Dashboard + Users)' : u.role === 'dispatcher' ? '🖥️ Dashboard Only' : u.role === 'both' ? '🖥️🔧 Dashboard + Field Tech' : '🔧 Field Tech Only'}</div>
          </div>
          <div style="display:flex;gap:6px;flex-shrink:0">
            <button onclick="window.__wcResetPw(${u.id}, '${u.username}')" style="background:#27272a;border:none;color:#a1a1aa;border-radius:6px;padding:6px 10px;font-size:12px;cursor:pointer">Reset PW</button>
            ${u.id !== currentUser?.id ? `<button onclick="window.__wcDeleteUser(${u.id}, '${u.username}')" style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:#ef4444;border-radius:6px;padding:6px 10px;font-size:12px;cursor:pointer">Remove</button>` : '<span style="font-size:12px;color:#52525b;padding:6px 10px">(you)</span>'}
          </div>
        </div>
      `).join('');

      window.__wcResetPw = async (id, username) => {
        if (!confirm(`Reset password for "${username}" to Wilbanks1!?`)) return;
        const res = await fetch(API + '/api/auth/users/' + id + '/reset-password', {
          method: 'POST', headers: { Authorization: 'Bearer ' + _token },
        });
        if (res.ok) alert(`Password reset. "${username}" will be asked to set a new password on next login.`);
        else alert('Reset failed.');
      };

      window.__wcDeleteUser = async (id, username) => {
        if (!confirm(`Remove user "${username}"? This cannot be undone.`)) return;
        const res = await fetch(API + '/api/auth/users/' + id, {
          method: 'DELETE', headers: { Authorization: 'Bearer ' + _token },
        });
        if (res.ok) { document.getElementById('wc-user-row-' + id)?.remove(); }
        else alert('Delete failed.');
      };

    } catch { container.innerHTML = '<div style="color:#ef4444;font-size:14px">Failed to load users.</div>'; }
  }

  // ── Record Payment Injection ──────────────────────────────────────────────
  // Injects "Record Payment" buttons on sent-invoice rows in the list view.
  // Renders a modal dialog; calls /api/qb-record-payment on the server.
  var _wcApptCache = null; // cached appointments
  var _wcApptCacheTs = 0;

  async function fetchApptCache() {
    const now = Date.now();
    if (_wcApptCache && (now - _wcApptCacheTs) < 30000) return _wcApptCache;
    try {
      const tok = loadToken();
      if (!tok) return null;
      const res = await _origFetch(API + '/api/appointments', {
        headers: { Authorization: 'Bearer ' + tok }
      });
      if (!res.ok) return null;
      _wcApptCache = await res.json();
      _wcApptCacheTs = now;
      return _wcApptCache;
    } catch { return null; }
  }

  function showRecordPaymentDialog(appt) {
    document.getElementById('wc-rp-overlay')?.remove();

    const overlay = document.createElement('div');
    overlay.id = 'wc-rp-overlay';
    overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;padding:16px;';

    const methodColors = { PayPal: '#003087', Venmo: '#3D95CE', Check: '#6b7280', Cash: '#166534', Other: '#4b5563' };
    const methods = ['PayPal', 'Venmo', 'Check', 'Cash', 'Other'];
    let selectedMethod = 'PayPal';
    let amount = appt.invoiceAmount ? parseFloat(appt.invoiceAmount).toFixed(2) : '';
    let submitting = false;

    const card = document.createElement('div');
    card.style.cssText = 'background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:12px;padding:24px;width:100%;max-width:440px;font-family:inherit;';

    function getMethodBtnsHTML() {
      return methods.map(function(m) {
        var sel = selectedMethod === m;
        return '<button data-wc-rp-m="' + m + '" style="padding:10px 4px;border-radius:8px;font-size:12px;font-weight:600;border:1px solid;cursor:pointer;transition:all 0.15s;' +
          'background:' + (sel ? methodColors[m] : 'transparent') + ';' +
          'color:' + (sel ? '#fff' : 'hsl(var(--muted-foreground))') + ';' +
          'border-color:' + (sel ? methodColors[m] : 'hsl(var(--border))') + ';font-family:inherit;">' + m + '</button>';
      }).join('');
    }

    function buildHTML() {
      var amtDisplay = amount || '';
      var invoiceAmt = appt.invoiceAmount ? parseFloat(appt.invoiceAmount).toLocaleString('en-US', { minimumFractionDigits: 2 }) : '';
      return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:16px;">' +
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>' +
        '<span style="font-size:16px;font-weight:600;color:hsl(var(--foreground))">Record Payment Received</span>' +
        '</div>' +
        '<div style="background:hsl(var(--muted)/0.4);border-radius:8px;padding:12px;margin-bottom:16px;font-size:14px;">' +
        '<div style="font-weight:500;color:hsl(var(--foreground));margin-bottom:2px;">' + (appt.customerName || '') + '</div>' +
        '<div style="color:hsl(var(--muted-foreground));">Invoice #' + (appt.qbInvoiceNum || '') + '</div>' +
        (invoiceAmt ? '<div style="color:hsl(var(--muted-foreground));">Total: $' + invoiceAmt + '</div>' : '') +
        '</div>' +
        '<div style="margin-bottom:16px;">' +
        '<div style="font-size:13px;font-weight:500;color:hsl(var(--foreground));margin-bottom:8px;">Payment Method</div>' +
        '<div data-wc-rp-methods style="display:grid;grid-template-columns:repeat(5,1fr);gap:8px;">' + getMethodBtnsHTML() + '</div>' +
        '</div>' +
        '<div style="margin-bottom:20px;">' +
        '<div style="font-size:13px;font-weight:500;color:hsl(var(--foreground));margin-bottom:8px;">Amount Received ($)</div>' +
        '<div style="position:relative;">' +
        '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="hsl(var(--muted-foreground))" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="position:absolute;left:12px;top:50%;transform:translateY(-50%);"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>' +
        '<input data-wc-rp-input="amount" type="number" min="0" step="0.01" placeholder="0.00" value="' + amtDisplay + '"' +
        ' style="width:100%;padding:10px 12px 10px 36px;border-radius:8px;border:1px solid hsl(var(--border));background:hsl(var(--muted)/0.5);color:hsl(var(--foreground));font-size:14px;font-family:inherit;box-sizing:border-box;outline:none;" />' +
        '</div>' +
        '</div>' +
        '<div style="display:flex;gap:8px;justify-content:flex-end;">' +
        '<button data-wc-rp-action="cancel" style="padding:9px 16px;border-radius:8px;border:1px solid hsl(var(--border));background:transparent;color:hsl(var(--foreground));font-size:14px;font-weight:500;cursor:pointer;font-family:inherit;">Cancel</button>' +
        '<button data-wc-rp-action="submit" style="padding:9px 20px;border-radius:8px;border:none;background:#059669;color:#fff;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit;display:inline-flex;align-items:center;gap:6px;">' +
        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>' +
        'Record Payment</button>' +
        '</div>' +
        '<div data-wc-rp-status style="margin-top:12px;font-size:13px;text-align:center;"></div>';
    }

    function rerenderMethods() {
      var grid = card.querySelector('[data-wc-rp-methods]');
      if (grid) grid.innerHTML = getMethodBtnsHTML();
    }

    // Single event-delegated click handler on the card — no getElementById needed
    card.addEventListener('click', async function(e) {
      var target = e.target.closest('[data-wc-rp-m],[data-wc-rp-action]');
      if (!target) return;
      e.stopPropagation();

      var m = target.getAttribute('data-wc-rp-m');
      if (m) {
        selectedMethod = m;
        rerenderMethods();
        var ai = card.querySelector('[data-wc-rp-input="amount"]');
        if (ai) ai.focus();
        return;
      }

      var action = target.getAttribute('data-wc-rp-action');

      if (action === 'cancel') {
        overlay.remove();
        return;
      }

      if (action === 'submit') {
        if (submitting) return;
        var amtEl = card.querySelector('[data-wc-rp-input="amount"]');
        var amtVal = amtEl ? amtEl.value : amount;
        var statusEl = card.querySelector('[data-wc-rp-status]');
        var submitBtn = card.querySelector('[data-wc-rp-action="submit"]');
        if (!amtVal || parseFloat(amtVal) <= 0) {
          if (statusEl) statusEl.innerHTML = '<span style="color:#ef4444">Please enter a valid amount.</span>';
          return;
        }
        submitting = true;
        if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Saving...'; }
        try {
          var tok = loadToken();
          var res = await _origFetch(API + '/api/qb-record-payment', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + tok },
            body: JSON.stringify({
              appointmentId: appt.id,
              qbInvoiceId: appt.qbInvoiceId,
              amount: amtVal,
              paymentMethod: selectedMethod
            })
          });
          var data = await res.json();
          if (!res.ok) throw new Error(data.detail || data.error || 'Failed');
          var msg = data.paid
            ? 'Paid in full via ' + selectedMethod + '.'
            : '$' + parseFloat(amtVal).toFixed(2) + ' recorded. $' + parseFloat(data.balance).toFixed(2) + ' still due.';
          if (statusEl) statusEl.innerHTML = '<span style="color:#34d399">' + msg + '</span>';
          _wcApptCache = null;
          var rpCardBtn = document.querySelector('[data-wc-rp-id="' + appt.id + '"]');
          if (rpCardBtn) rpCardBtn.remove();
          var rpDetailCard = document.querySelector('[data-wc-rp-detail-id="' + appt.id + '"]');
          if (rpDetailCard) rpDetailCard.remove();
          setTimeout(function() { overlay.remove(); }, 2500);
        } catch(err) {
          if (statusEl) statusEl.innerHTML = '<span style="color:#ef4444">' + (err.message || 'Error') + '</span>';
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> Record Payment';
          }
          submitting = false;
        }
      }
    });

    // Track amount changes
    card.addEventListener('input', function(e) {
      if (e.target.getAttribute('data-wc-rp-input') === 'amount') {
        amount = e.target.value;
      }
    });

    // Build HTML and mount (card is in DOM before any querySelector calls)
    card.innerHTML = buildHTML();
    overlay.appendChild(card);
    overlay.addEventListener('click', function(e) { if (e.target === overlay) overlay.remove(); });
    document.body.appendChild(overlay);

    setTimeout(function() {
      var ai = card.querySelector('[data-wc-rp-input="amount"]');
      if (ai) ai.focus();
    }, 50);
  }


  async function injectRecordPaymentButtons() {
    // Only in list view (not calendar)
    const cards = document.querySelectorAll('[data-testid^="card-appointment-"]');
    if (!cards.length) return;

    const appts = await fetchApptCache();
    if (!appts) return;

    const apptMap = {};
    appts.forEach(a => { apptMap[a.id] = a; });

    cards.forEach(card => {
      const testId = card.getAttribute('data-testid') || '';
      const id = parseInt(testId.replace('card-appointment-', ''));
      if (!id) return;
      const appt = apptMap[id];
      if (!appt) return;
      if ((appt.invoiceStatus !== 'sent' && appt.invoiceStatus !== 'paid') || !appt.qbInvoiceId) return;
      // Only inject once per card
      if (card.querySelector('[data-wc-rp-id]')) return;

      const btn = document.createElement('button');
      btn.setAttribute('data-wc-rp-id', String(id));
      btn.style.cssText = 'display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:6px;border:none;background:#059669;color:#fff;font-size:12px;font-weight:600;cursor:pointer;font-family:inherit;margin-top:6px;flex-shrink:0;';
      btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg> Record Payment';
      btn.addEventListener('click', function(e) {
        e.stopPropagation();
        showRecordPaymentDialog(appt);
      });

      // Find the bottom info row of the card and append the button there
      const lastDiv = card.lastElementChild;
      if (lastDiv) lastDiv.appendChild(btn);
      else card.appendChild(btn);
    });
  }

  var _wcDetailInjectLock = {};  // synchronous lock per appointment id
  async function injectRecordPaymentDetailPage() {
    // Only run when the hash is #/appointment/{id}
    const hash = window.location.hash;
    const match = hash.match(/^#\/appointment\/(\d+)/);
    if (!match) return;
    const id = parseInt(match[1]);
    if (!id) return;

    // Guard: already injected? (covers re-nav away and back)
    if (document.querySelector('[data-wc-rp-detail-id="' + id + '"]')) return;
    // Synchronous lock — set BEFORE the async fetch to prevent MutationObserver from
    // firing concurrent calls while the fetch is in-flight (race condition fix)
    if (_wcDetailInjectLock[id]) return;
    _wcDetailInjectLock[id] = true;

    // Need the space-y-4 container to be present (page has loaded)
    const container = document.querySelector('.space-y-4');
    if (!container) {
      // DOM not ready yet — release lock and let MO retry naturally
      _wcDetailInjectLock[id] = false;
      return;
    }

    // Need at least the Tech Notes h2 to be present before we inject
    var hasDetail = false;
    var h2s = document.querySelectorAll('h2');
    for (var j = 0; j < h2s.length; j++) {
      if (h2s[j].textContent && h2s[j].textContent.trim() === 'Tech Notes') { hasDetail = true; break; }
      if (h2s[j].textContent && h2s[j].textContent.trim() === 'Customer') { hasDetail = true; break; }
    }
    if (!hasDetail) {
      // DOM not fully rendered yet — hold the lock and retry in 200ms
      setTimeout(function() { _wcDetailInjectLock[id] = false; injectRecordPaymentDetailPage(); }, 200);
      return;
    }

    // Fetch this specific appointment directly (list endpoint excludes completed jobs)
    var appt = null;
    try {
      var tok = loadToken();
      if (!tok) { _wcDetailInjectLock[id] = false; return; }
      var apptRes = await _origFetch(API + '/api/appointments/' + id, {
        headers: { 'Authorization': 'Bearer ' + tok }
      });
      if (!apptRes.ok) { _wcDetailInjectLock[id] = false; return; }
      appt = await apptRes.json();
    } catch(e) { _wcDetailInjectLock[id] = false; return; }
    if (!appt) { _wcDetailInjectLock[id] = false; return; }
    if ((appt.invoiceStatus !== 'sent' && appt.invoiceStatus !== 'paid') || !appt.qbInvoiceId) { _wcDetailInjectLock[id] = false; return; }

    // Build a full invoice card matching the other cards on the detail page
    var card = document.createElement('div');
    card.setAttribute('data-wc-rp-detail-id', String(id));
    card.className = 'bg-card border border-border rounded-lg p-5';

    // Card header row
    var header = document.createElement('h2');
    header.style.cssText = 'font-size:14px;font-weight:600;color:hsl(var(--foreground));margin-bottom:12px;display:flex;align-items:center;gap:8px;';
    header.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="hsl(var(--primary))" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>Invoice';
    card.appendChild(header);

    // Info rows
    var info = document.createElement('div');
    info.style.cssText = 'display:flex;flex-direction:column;gap:6px;font-size:14px;';

    if (appt.qbInvoiceNum) {
      var numRow = document.createElement('div');
      numRow.style.cssText = 'display:flex;align-items:center;gap:8px;';
      numRow.innerHTML = '<span style="color:hsl(var(--muted-foreground))">Invoice #:</span>' +
        '<span style="color:hsl(var(--foreground));font-weight:500">' + appt.qbInvoiceNum + '</span>' +
        (appt.qbInvoiceId ? '<a href="https://wilbanks-server-production.up.railway.app/api/qb-invoice-pdf/' + id + '" target="_blank" style="color:hsl(var(--primary));font-size:12px;text-decoration:none;margin-left:6px;">View Invoice</a>' : '');
      info.appendChild(numRow);
    }

    if (appt.invoiceAmount) {
      var amtRow = document.createElement('div');
      amtRow.style.cssText = 'display:flex;align-items:center;gap:8px;';
      var amt = parseFloat(appt.invoiceAmount).toLocaleString('en-US', { minimumFractionDigits: 2 });
      amtRow.innerHTML = '<span style="color:hsl(var(--muted-foreground))">Amount:</span>' +
        '<span style="color:#34d399;font-weight:600">$' + amt + '</span>';
      info.appendChild(amtRow);
    }

    // Record Payment button (only if invoice is still unpaid)
    var btnWrap = document.createElement('div');
    btnWrap.style.cssText = 'padding-top:8px;';
    if (appt.invoiceStatus === 'sent') {
      var btn = document.createElement('button');
      btn.style.cssText = 'display:flex;align-items:center;justify-content:center;gap:6px;width:100%;padding:8px 14px;border-radius:7px;border:none;background:#059669;color:#fff;font-size:13px;font-weight:600;cursor:pointer;font-family:inherit;transition:background 0.15s;';
      btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Record Payment';
      btn.addEventListener('mouseenter', function() { btn.style.background = '#047857'; });
      btn.addEventListener('mouseleave', function() { btn.style.background = '#059669'; });
      btn.addEventListener('click', function(e) {
        e.stopPropagation();
        showRecordPaymentDialog(appt);
      });
      btnWrap.appendChild(btn);
    } else {
      var paidBadge = document.createElement('div');
      paidBadge.style.cssText = 'display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:7px;background:rgba(52,211,153,0.15);color:#34d399;font-size:13px;font-weight:600;font-family:inherit;';
      paidBadge.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Paid';
      btnWrap.appendChild(paidBadge);
    }
    info.appendChild(btnWrap);

    card.appendChild(info);

    // Insert before the "Send Notifications" card, or append to container
    var sendNotifCard = null;
    var allH2s = container.querySelectorAll('h2');
    for (var k = 0; k < allH2s.length; k++) {
      if (allH2s[k].textContent && allH2s[k].textContent.includes('Send Notifications')) {
        sendNotifCard = allH2s[k].closest('.bg-card') || allH2s[k].closest('[class*="rounded-lg"]') || allH2s[k].parentElement;
        break;
      }
    }
    if (sendNotifCard && sendNotifCard.parentElement === container) {
      container.insertBefore(card, sendNotifCard);
    } else {
      container.appendChild(card);
    }
  }

  function injectLogoutButton() {
    document.getElementById('wc-logout-btn')?.remove();

    // Build a sidebar-style logout button (dashboard desktop).
    // wc-v204: compact rail style — icon stacked above a small label — to match
    // the 104px icon rail (Dashboard/Techs/Settings/etc.).
    function buildSidebarBtn() {
      const btn = document.createElement('button');
      btn.id = 'wc-logout-btn';
      btn.title = 'Sign Out';
      btn.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0">
          <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
          <polyline points="16,17 21,12 16,7"/>
          <line x1="21" y1="12" x2="9" y2="12"/>
        </svg>
        <span style="line-height:1.1;text-align:center">Sign Out</span>
      `;
      Object.assign(btn.style, {
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: '2px',
        width: '100%', padding: '4px',
        background: 'transparent', border: 'none',
        borderRadius: '8px', cursor: 'pointer',
        fontSize: '10px', fontWeight: '600',
        color: '#ef4444',
        fontFamily: 'inherit',
        transition: 'background 0.15s',
      });
      btn.addEventListener('mouseenter', () => btn.style.background = 'rgba(239,68,68,0.1)');
      btn.addEventListener('mouseleave', () => btn.style.background = 'transparent');
      btn.addEventListener('click', doLogout);
      return btn;
    }



    function doLogout() {
      if (confirm('Sign out of Wilbanks Company?')) logout();
    }

    // Strategy 1a: Dashboard desktop sidebar — inject into the dedicated
    // #wc-sidebar-footer slot the React rail renders at the bottom of <nav>.
    // wc-v204: the old anchor ([data-testid="button-toggle-theme"]) was removed
    // from the rail in v197 (theme moved into Settings), which silently dropped
    // the desktop Sign Out button. Anchor to the footer slot instead.
    function tryInjectSidebar() {
      const footer = document.getElementById('wc-sidebar-footer');
      if (footer) {
        if (!footer.querySelector('#wc-logout-btn')) {
          footer.appendChild(buildSidebarBtn());
        }
        return true;
      }
      return false;
    }

    // Strategy 1b: Dashboard mobile menu — inject Admin Tools + Sign Out
    function tryInjectMobileMenu() {
      // The mobile dropdown has class 'md:hidden fixed top-[57px]'.
      // IMPORTANT: require `.md:hidden` so we never match the AI full-page
      // results overlay, which also uses `fixed top-[57px]` (but is NOT
      // md:hidden — it's z-[90] md:top-0 md:left-64). Matching the overlay
      // injected Admin Tools + Sign Out into the AI results panel, leaking
      // them above the AI bar on mobile.
      const mobileMenu = document.querySelector('.md\\:hidden.fixed.top-\\[57px\\]');
      if (!mobileMenu) return;

      // wc-v203: mobile Admin Tools section retired — items now live as Settings tabs.
      // Clean up any stale injected section, then skip rebuilding it.
      mobileMenu.querySelector('#wc-mobile-admin-section')?.remove();
      // Inject collapsible Admin Tools section for admin/both roles
      const role = currentUser?.role;
      if (false && (role === 'admin' || role === 'both')) {
        // Only rebuild if not already present — avoid clobbering open/close state
        if (mobileMenu.querySelector('#wc-mobile-admin-section')) return;

        const hash = window.location.hash;
        if (typeof window._wcAdminOpen === 'undefined') window._wcAdminOpen = false;
        if (hash.includes('audit-log') || hash.includes('deleted-jobs') || hash.includes('/settings') || hash.includes('/users')) window._wcAdminOpen = true;
        const open = window._wcAdminOpen;

        const section = document.createElement('div');
        section.id = 'wc-mobile-admin-section';
        section.style.cssText = 'border-top:1px solid hsl(var(--border));padding:4px 8px;';

        // Collapsible toggle header
        const toggle = document.createElement('button');
        toggle.style.cssText = 'display:flex;align-items:center;gap:10px;width:100%;padding:8px 12px;background:transparent;border:none;border-radius:6px;cursor:pointer;font-size:14px;font-weight:600;font-family:inherit;color:hsl(var(--muted-foreground));text-transform:uppercase;letter-spacing:0.05em;';
        toggle.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/></svg><span style="flex:1;font-size:11px">Admin Tools</span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;transition:transform 0.2s;transform:rotate(${open ? 180 : 0}deg)" id="wc-mobile-admin-chevron"><polyline points="6 9 12 15 18 9"/></svg>`;

        const sub = document.createElement('div');
        sub.id = 'wc-mobile-admin-sub';
        sub.style.cssText = `overflow:hidden;max-height:${open ? '300px' : '0'};transition:max-height 0.2s ease;`;

        toggle.addEventListener('click', function() {
          window._wcAdminOpen = !window._wcAdminOpen;
          sub.style.maxHeight = window._wcAdminOpen ? '300px' : '0';
          const chev = document.getElementById('wc-mobile-admin-chevron');
          if (chev) chev.style.transform = `rotate(${window._wcAdminOpen ? 180 : 0}deg)`;
        });

        const adminLinks = [
          { label: 'Settings', href: '#/settings', svg: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>' },
          { label: 'Users', href: '#/users', svg: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>' },
          { label: 'Audit Log', href: '#/audit-log', svg: '<path d="M3 3v5h5"/><path d="M3.05 13A9 9 0 1 0 6 5.3L3 8"/><path d="M12 7v5l4 2"/>' },
          { label: 'Deleted Jobs', href: '#/deleted-jobs', svg: '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>' },
        ];

        adminLinks.forEach(({ label: lbl, href, svg }) => {
          const active = hash === href;
          const a = document.createElement('a');
          a.href = href;
          a.style.cssText = `display:flex;align-items:center;gap:10px;padding:8px 12px 8px 28px;border-radius:6px;font-size:14px;font-weight:500;font-family:inherit;text-decoration:none;color:${active ? 'hsl(var(--primary))' : 'hsl(var(--muted-foreground))'};background:${active ? 'hsl(var(--primary)/0.1)' : 'transparent'};transition:background 0.15s;margin-bottom:1px;`;
          a.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0">${svg}</svg><span>${lbl}</span>`;
          a.addEventListener('click', () => { setTimeout(() => { mobileMenu.style.display = 'none'; }, 100); });
          sub.appendChild(a);
        });

        section.appendChild(toggle);
        section.appendChild(sub);
        mobileMenu.appendChild(section);
      }

      // Inject Sign Out button
      if (!mobileMenu.querySelector('#wc-logout-mobile')) {
        const btn = buildSidebarBtn();
        btn.id = 'wc-logout-mobile';
        btn.style.marginTop = '4px';
        btn.style.marginBottom = '4px';
        mobileMenu.appendChild(btn);
      }
    }

    // Strategy 2: Field tech — hijack the existing LogOut icon button in the header
    // The compiled app already has a LogOut SVG button — rewire it
    function tryHijackLogoutBtn() {
      const existing = document.getElementById('wc-logout-btn');
      if (existing && document.body.contains(existing)) return true;
      if (existing) existing.remove(); // stale — clean up
      // Find button containing LogOut SVG path (M9 21H5)
      const buttons = document.querySelectorAll('button');
      for (const btn of buttons) {
        const svg = btn.querySelector('svg');
        if (!svg) continue;
        const paths = btn.querySelectorAll('path, polyline, line');
        for (const p of paths) {
          const d = p.getAttribute('d') || p.getAttribute('points') || '';
          if (d.includes('M9 21H5') || d.includes('16 17 21 12')) {
            // This is the LogOut button — rewire it
            btn.id = 'wc-logout-btn';
            // Clone to remove old listeners
            const newBtn = btn.cloneNode(true);
            newBtn.id = 'wc-logout-btn';
            // Style it red to indicate logout
            newBtn.style.color = '#ef4444';
            newBtn.addEventListener('click', doLogout);
            btn.parentNode?.replaceChild(newBtn, btn);
            return true;
          }
        }
      }
      return false;
    }



    function tryInject() {
      if (tryInjectSidebar()) return true;
      if (tryHijackLogoutBtn()) return true;
      return false;
    }

    tryInject();

    // Guard: only register the MutationObserver once across all injectLogoutButton() calls
    if (!window._wcMutObsAdded) {
      window._wcMutObsAdded = true;
      let attempts = 0;
      // Keep observer running permanently — re-wires logout btn after every React navigation
      const observer = new MutationObserver(() => {
        attempts++;
        tryInject();
        tryInjectMobileMenu();
        injectRecordPaymentButtons();
        injectRecordPaymentDetailPage();
        if (attempts > 2000) observer.disconnect();
      });
      observer.observe(document.body, { childList: true, subtree: true });
    }

    // Poll for mobile menu visibility and inject QB link + admin items when open
    var _lastMenuChildCount = 0;
    setInterval(function() {
      var menu = document.querySelector('.md\\:hidden.fixed.top-\\[57px\\]');
      if (!menu) return;
      var visible = menu.offsetHeight > 0 && getComputedStyle(menu).display !== 'none';
      if (!visible) return;
      tryInjectMobileMenu();
    }, 300);


  }

  function logout() {
    // wc-v219: full cleanup so next user lands fresh on default route
    // wc-v222: also clears wc_prefs_cache_* (per-user pre-paint cache) and
    //         the legacy hyphenated wc-theme key.
    // wc-v224: parallel sweep of sessionStorage wc_* keys (Phase 1 per-tab
    //         session isolation — sessionStorage is now the source of truth
    //         for the dashboard's active session).
    // wc-v243: latch a flag so the pagehide/beforeunload _saveHash() listener
    // (which fires during the reload at the end of this function) cannot
    // race and re-write wc_last_hash after we've cleared it. Without the
    // latch, _saveHash() would persist the current hash one last time and
    // the NEXT login would restore the prior session's route — the exact
    // regression we're fixing here.
    window.__WC_LOGGING_OUT = true;
    // Clear hash + saved hash so we don't restore prior admin's last screen
    try { sessionStorage.removeItem('wc_last_hash'); } catch (e) {}
    try { window.location.hash = ''; } catch (e) {}
    // Sweep all wc_* localStorage keys EXCEPT wc_saved_username (remember me).
    // Also catch the hyphenated legacy `wc-theme` key (does not match wc_*).
    try {
      var preserve = { 'wc_saved_username': 1 };
      var toRemove = [];
      for (var i = 0; i < localStorage.length; i++) {
        var k = localStorage.key(i);
        if (!k) continue;
        // wc_* (underscore) — original sweep
        if (k.indexOf('wc_') === 0 && !preserve[k]) { toRemove.push(k); continue; }
        // wc-theme (hyphen) — legacy per-device theme key; safe to drop, the
        // pre-paint inline script now reads from wc_prefs_cache_<uid>.
        if (k === 'wc-theme') { toRemove.push(k); continue; }
      }
      for (var j = 0; j < toRemove.length; j++) localStorage.removeItem(toRemove[j]);
    } catch (e) {}
    // wc-v224: parallel sessionStorage sweep — wc_* keys in this tab only.
    // Other tabs are unaffected; their sessionStorage is isolated.
    try {
      var ssRemove = [];
      for (var si = 0; si < sessionStorage.length; si++) {
        var sk = sessionStorage.key(si);
        if (!sk) continue;
        if (sk.indexOf('wc_') === 0) ssRemove.push(sk);
      }
      for (var sj = 0; sj < ssRemove.length; sj++) sessionStorage.removeItem(ssRemove[sj]);
    } catch (e) {}
    // Clear field-tech session marker as well
    try { sessionStorage.removeItem('techName'); } catch (e) {}
    clearToken();
    // wc-v244: FORCE a real navigation by appending a cache-bust query param.
    // iOS PWA / Safari was treating location.replace(pathname + search) as a
    // no-op when the only delta vs. the current URL was the hash, so the page
    // never actually reloaded — the React app kept rendering the prior route
    // (e.g. /finance), the login form was shown on top of it, and after
    // launchApp() the user landed back on /finance. Appending `?lo=<ts>`
    // changes the search string and guarantees a fresh page load.
    // Also explicitly drop the hash via the URL we navigate to.
    var target = window.location.pathname + '?lo=' + Date.now();
    try { window.location.replace(target); } catch (e) { window.location.href = target; }
  }

  // Expose logout globally
  window.__WC_LOGOUT = logout;

  // ── Bootstrap ─────────────────────────────────────────────────────────────
  async function bootstrap() {
    // Hide root until auth is confirmed
    const root = document.getElementById("root");
    if (root) root.style.display = "none";

    injectStyles();

    // Try existing token
    const token = loadToken();
    if (token) {
      try {
        const res = await _origFetch(API + "/api/auth/me", {
          headers: { Authorization: "Bearer " + token },
        });
        if (res.ok) {
          const user = await res.json();
          saveToken(token);
          currentUser = user;
          window.__WC_USER = user;
          publishUserRole(user);
          window.__WC_LOGOUT = logout;
          // wc-v224 fix: fire the auth-ready signal on existing-session boot
          // too (previously only fired from launchApp() on fresh login). The
          // useCurrentUser hook depends on this; without it, the user badge
          // stays blank on any tab that boots via seed-hop or hard refresh.
          window.__WC_AUTH_READY = true;
          try { window.dispatchEvent(new CustomEvent("wc:auth-ready")); } catch {}
          // Token valid — show app and inject UI elements
          if (root) root.style.display = "";
          // Restore the hash route from before the refresh
          try {
            const savedHash = sessionStorage.getItem('wc_last_hash');
            if (savedHash && savedHash !== '#/' && savedHash !== '#') {
              sessionStorage.removeItem('wc_last_hash');
              const _applyHash = () => {
                try { window.location.hash = savedHash.replace(/^#/, ''); } catch {}
              };
              _applyHash();
              setTimeout(_applyHash, 150);
              setTimeout(_applyHash, 500);
            }
          } catch {}
          // Sync display name into field tech app header
          syncFieldTechName(user);
          // Inject Admin Tools nav for admin role only
          // Run at multiple intervals to survive React re-renders from hash restoration
          setTimeout(function() { injectAdminToolsNav(); injectRecordPaymentButtons(); injectRecordPaymentDetailPage(); }, 300);
          setTimeout(function() { injectAdminToolsNav(); injectRecordPaymentButtons(); injectRecordPaymentDetailPage(); }, 800);
          setTimeout(function() { injectAdminToolsNav(); injectRecordPaymentButtons(); injectRecordPaymentDetailPage(); }, 1600);
          // Start inactivity timer
          startInactivityTimer();
          // Wait for React to mount then inject
          setTimeout(() => {
            injectLogoutButton();
          }, 1500);
          // Block field techs from accessing the dashboard URL
          if (user.role === 'tech') {
            const isDashboard = !window.location.pathname.includes('fieldtech') &&
                                !window.location.href.includes('wilbanks-fieldtech');
            if (isDashboard) {
              if (root) root.style.display = 'none';
              renderLogin('Field Tech accounts cannot access the dashboard.');
              clearToken();
              return;
            }
          }
          // Block dispatcher-only role from field tech app (admin can access both)
          if (user.role === 'dispatcher') {
            const isDashboard = !window.location.pathname.includes('fieldtech') &&
                                !window.location.href.includes('wilbanks-fieldtech');
            if (!isDashboard) {
              if (root) root.style.display = 'none';
              renderLogin('Dashboard accounts cannot access the Field Tech app.');
              clearToken();
              return;
            }
          }
          return;
        }
      } catch {
        // Network error (server cold start, offline, etc.) — token may still be valid.
        // Don't clear it; show the app optimistically so a hard refresh doesn't log the user out.
        if (root) root.style.display = "";
        startInactivityTimer();
        setTimeout(() => { injectLogoutButton(); }, 1500);
        setTimeout(function() { injectAdminToolsNav(); injectRecordPaymentButtons(); injectRecordPaymentDetailPage(); }, 800);
        return;
      }
      // Token returned a non-2xx (401/403) — genuinely invalid, clear it
      clearToken();
    }

    renderLogin();
  }

  // ── Hash persistence on refresh ────────────────────────────────────────────
  // Save the current hash route continuously so a refresh (or iOS PWA relaunch)
  // lands back on the same screen. iOS Safari does NOT reliably fire beforeunload,
  // so we save on hashchange and visibilitychange instead.
  const HASH_KEY = 'wc_last_hash';
  function _saveHash() {
    // wc-v243: never write wc_last_hash during a logout teardown. The logout
    // function sets __WC_LOGGING_OUT, then clears the hash and removes this
    // key, then triggers a full reload. The pagehide / beforeunload events
    // fire mid-teardown and would otherwise re-persist a stale route.
    if (window.__WC_LOGGING_OUT) return;
    try {
      const h = window.location.hash;
      if (h && h !== '#/' && h !== '#') {
        sessionStorage.setItem(HASH_KEY, h);
      } else {
        sessionStorage.removeItem(HASH_KEY);
      }
    } catch {}
  }
  window.addEventListener('hashchange', _saveHash);
  document.addEventListener('visibilitychange', _saveHash);
  window.addEventListener('pagehide', _saveHash);
  window.addEventListener('beforeunload', _saveHash);

  // ── bfcache guard ─────────────────────────────────────────────────────────
  // If Safari restores this page from bfcache after a logout navigation,
  // _token is still set in memory but localStorage is cleared.
  // Force a full reload so bootstrap runs fresh and shows the login screen.
  window.addEventListener('pageshow', function(e) {
    if (e.persisted) {
      // Page was restored from bfcache — check if token is gone from storage
      const stored = (function() {
        // wc-v224b: dashboard is sessionStorage-only; field-tech keeps localStorage.
        try {
          if (isFieldApp()) {
            return localStorage.getItem('wc_auth_token') || sessionStorage.getItem('wc_auth_token');
          }
          return sessionStorage.getItem('wc_auth_token');
        } catch { return null; }
      })();
      if (!stored) {
        // Token gone but bfcache restored old state — force fresh load
        _token = null;
        window.location.replace(window.location.pathname + '?lo=' + Date.now());
      }
    }
  });

  // ── QB Login Nav Link (removed per user request) ─────────────────────────

  function canUseQBLogin() { return false; }
  function injectQBLoginLink() { return; }
  function showQBToast() { return; }
  function checkQBSessionOnLogin() { return; }
  function startQBSessionPoll() { return; }
  function renderQBLoginPage() { return; }

  /* DEAD CODE BELOW — kept for reference, never executes */
  function _injectQBLoginLink_unused() {
    if (!canUseQBLogin()) return;
    const hash = window.location.hash;
    const isActive = hash.includes('/qb-login');
    const color = _qbSessionValid === false ? '#ef4444' : _qbSessionValid === true ? '#22c55e' : 'hsl(var(--muted-foreground))';
    const dot = _qbSessionValid === false ? ' <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#ef4444;margin-left:auto;animation:wc-pulse 1.5s infinite"></span>'
      : _qbSessionValid === true ? ' <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#22c55e;margin-left:auto"></span>' : '';
    const svgIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/><path d="M9 21V9"/></svg>';

    // Mobile menu link — always inject regardless of sidebar presence.
    // Require `.md:hidden` so the AI full-page results overlay (also
    // `fixed top-[57px]`, but z-[90]/md:top-0) is never matched.
    const mobileMenu = document.querySelector('.md\\:hidden.fixed.top-\\[57px\\]');
    if (mobileMenu) {
      let mobileLink = document.getElementById('wc-qb-login-mobile');
      if (!mobileLink) {
        const qbSection = document.createElement('div');
        qbSection.id = 'wc-qb-login-mobile-section';
        qbSection.style.cssText = 'border-top:1px solid hsl(var(--border));padding:4px 8px;';
        const lbl = document.createElement('p');
        lbl.textContent = 'Reports';
        lbl.style.cssText = 'font-size:11px;font-weight:600;color:hsl(var(--muted-foreground));text-transform:uppercase;letter-spacing:0.05em;padding:6px 4px 2px;margin:0;';
        qbSection.appendChild(lbl);
        mobileLink = document.createElement('a');
        mobileLink.id = 'wc-qb-login-mobile';
        mobileLink.href = '#/qb-login';
        mobileLink.style.cssText = 'display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:6px;font-size:14px;font-weight:500;font-family:inherit;text-decoration:none;transition:background 0.15s;margin-bottom:1px;';
        mobileLink.addEventListener('click', function(e) {
          // Close hamburger menu via React's own button before navigating
          var xBtn = Array.from(document.querySelectorAll('.md\\:hidden button')).find(function(b) {
            return Array.from(b.querySelectorAll('path')).some(function(p) { return (p.getAttribute('d') || '').includes('18 6 6 18'); });
          });
          if (xBtn) xBtn.click();
        });
        qbSection.appendChild(mobileLink);
        const signOut = mobileMenu.querySelector('#wc-logout-mobile');
        if (signOut) mobileMenu.insertBefore(qbSection, signOut);
        else mobileMenu.appendChild(qbSection);
      }
      mobileLink.style.color = color;
      mobileLink.innerHTML = svgIcon + '<span>QuickBooks Login</span>' + dot;
    }

    const nav = document.querySelector('aside nav');
    if (!nav) return;

    if (!document.getElementById('wc-qb-login-link')) {
      const link = document.createElement('a');
      link.id = 'wc-qb-login-link';
      link.href = '#/qb-login';
      link.style.cssText = 'display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:6px;font-size:14px;font-weight:500;font-family:inherit;text-decoration:none;color:' + (isActive ? 'hsl(var(--primary-foreground))' : color) + ';background:' + (isActive ? 'hsl(var(--primary))' : 'transparent') + ';transition:background 0.15s;margin-bottom:2px;';
      link.onmouseenter = function() { if (!link.dataset.active) { link.style.background = 'hsl(var(--muted))'; } };
      link.onmouseleave = function() { if (!link.dataset.active) { link.style.background = 'transparent'; link.style.color = color; } };
      if (isActive) link.dataset.active = '1';
      link.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/><path d="M9 21V9"/></svg><span>QuickBooks Login</span>' + dot;
      // Insert after Reports link if present, otherwise append
      nav.appendChild(link);
    } else {
      // Update existing link color and active state
      const link = document.getElementById('wc-qb-login-link');
      link.style.color = isActive ? 'hsl(var(--primary-foreground))' : color;
      link.style.background = isActive ? 'hsl(var(--primary))' : 'transparent';
      if (isActive) link.dataset.active = '1'; else delete link.dataset.active;
      link.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/><path d="M9 21V9"/></svg><span>QuickBooks Login</span>' + dot;
    }


    // Render QB Login page when hash matches
    window.addEventListener('hashchange', function() {
      if (window.location.hash === '#/qb-login') renderQBLoginPage();
      injectQBLoginLink();
    }, { once: true });
    if (isActive) renderQBLoginPage();
  }

  // ── QB Session Toast ───────────────────────────────────────────────────────
  var _qbToast = null;

  function showQBToast(valid) {
    if (_qbToast) { _qbToast.remove(); _qbToast = null; }
    const toast = document.createElement('div');
    _qbToast = toast;
    toast.id = 'wc-qb-toast';
    const bg = valid ? '#14532d' : '#450a0a';
    const border = valid ? '#16a34a' : '#dc2626';
    const textColor = valid ? '#86efac' : '#fca5a5';
    toast.style.cssText = `position:fixed;bottom:24px;right:24px;z-index:9999;background:${bg};border:1px solid ${border};border-radius:10px;padding:14px 18px;max-width:340px;box-shadow:0 4px 24px rgba(0,0,0,0.4);font-family:inherit;animation:wc-toast-in 0.3s ease;`;
    if (!valid) {
      toast.innerHTML = `
        <div style="display:flex;align-items:flex-start;gap:12px">
          <div style="font-size:18px;margin-top:1px">&#128274;</div>
          <div>
            <div style="font-size:14px;font-weight:600;color:#fef2f2;margin-bottom:4px">QuickBooks Session Expired</div>
            <div style="font-size:13px;color:${textColor};line-height:1.4">Click <a href="#/qb-login" onclick="document.getElementById('wc-qb-toast').style.display='none'" style="color:#f87171;font-weight:600;text-decoration:underline">QuickBooks Login</a> in the sidebar to reconnect.</div>
          </div>
          <button onclick="this.closest('#wc-qb-toast').style.display='none'" style="background:none;border:none;color:#f87171;cursor:pointer;font-size:18px;padding:0;margin-left:auto;line-height:1">&times;</button>
        </div>`;
    } else {
      toast.innerHTML = `
        <div style="display:flex;align-items:center;gap:12px">
          <div style="font-size:18px">&#9989;</div>
          <div style="font-size:13px;font-weight:500;color:${textColor}">QuickBooks session is active</div>
          <button onclick="this.closest('#wc-qb-toast').style.display='none'" style="background:none;border:none;color:#86efac;cursor:pointer;font-size:18px;padding:0;margin-left:auto;line-height:1">&times;</button>
        </div>`;
      // Auto-dismiss green toast after 5 seconds
      setTimeout(function() { if (toast.parentNode) toast.remove(); _qbToast = null; }, 5000);
    }
    // Add keyframe animation if not present
    if (!document.getElementById('wc-qb-styles')) {
      const style = document.createElement('style');
      style.id = 'wc-qb-styles';
      style.textContent = '@keyframes wc-toast-in{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}} @keyframes wc-pulse{0%,100%{opacity:1}50%{opacity:0.4}}';
      document.head.appendChild(style);
    }
    document.body.appendChild(toast);
  }

  function checkQBSessionOnLogin() {
    if (!canUseQBLogin()) return;
    const token = loadToken();
    if (!token) return;
    fetch(API + '/api/qb-session/status', {
      headers: { 'Authorization': 'Bearer ' + token }
    }).then(function(r) { return r.json(); }).then(function(d) {
      _qbSessionValid = d.playwrightSessionValid !== undefined ? !!d.playwrightSessionValid : !!d.valid;
      injectQBLoginLink();
      showQBToast(_qbSessionValid);
    }).catch(function() { _qbSessionValid = null; });
  }

  // ── QB Session Background Poll (every 10 min) ──────────────────────────────
  var _qbPollInterval = null;

  function startQBSessionPoll() {
    if (!canUseQBLogin()) return;
    if (_qbPollInterval) clearInterval(_qbPollInterval);
    _qbPollInterval = setInterval(function() {
      const token = loadToken();
      if (!token) return;
      fetch(API + '/api/qb-session/status', {
        headers: { 'Authorization': 'Bearer ' + token }
      }).then(function(r) { return r.json(); }).then(function(d) {
        const wasValid = _qbSessionValid;
        _qbSessionValid = d.playwrightSessionValid !== undefined ? !!d.playwrightSessionValid : !!d.valid;
        injectQBLoginLink();
        // Show toast only if session just dropped (was valid, now expired)
        if (wasValid === true && _qbSessionValid === false) {
          showQBToast(false);
        }
      }).catch(function() {});
    }, 10 * 60 * 1000); // 10 minutes
  }

  // ── QB Login Page ──────────────────────────────────────────────────────────
  var _qbPageRendered = false;

  function renderQBLoginPage() {
    // Only render on dashboard, not field app
    if (window.location.href.includes('fieldtech')) return;

    // Make React container invisible and show our page
    const main = document.querySelector('main');
    const root = document.getElementById('root');

    // Remove old page if present
    const old = document.getElementById('wc-qb-login-page');
    if (old) old.remove();

    const page = document.createElement('div');
    page.id = 'wc-qb-login-page';
    page.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:hsl(var(--background));overflow-y:auto;padding:16px;z-index:9999;display:flex;flex-direction:column;align-items:center;';
    // Shift right of sidebar on desktop via JS after paint
    requestAnimationFrame(function() {
      const sidebar = document.querySelector('nav.fixed, aside.fixed, [class*="sidebar"]');
      const sidebarWidth = sidebar ? sidebar.offsetWidth : (window.innerWidth >= 768 ? 256 : 0);
      if (sidebarWidth > 0 && window.innerWidth >= 768) {
        page.style.left = sidebarWidth + 'px';
        page.style.padding = '32px';
      }
    });

    const token = loadToken();
    const lastRefreshed = _qbLastRefreshed ? new Date(_qbLastRefreshed).toLocaleString() : 'Unknown';
    const statusColor = _qbSessionValid === true ? '#22c55e' : _qbSessionValid === false ? '#ef4444' : '#f59e0b';
    const statusText = _qbSessionValid === true ? 'Active' : _qbSessionValid === false ? 'Expired' : 'Unknown';
    const statusDot = `<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${statusColor};margin-right:8px"></span>`;

    page.innerHTML = `
      <div style="max-width:560px;width:100%;">
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:28px">
          <button onclick="history.back();setTimeout(function(){var p=document.getElementById('wc-qb-login-page');if(p)p.remove();var bd=document.querySelector('.fixed.inset-0.z-10');if(bd)bd.style.display='none';},150);" style="display:flex;align-items:center;justify-content:center;width:32px;height:32px;border-radius:8px;border:1px solid hsl(var(--border));background:hsl(var(--card));cursor:pointer;flex-shrink:0;" title="Back">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="hsl(var(--foreground))" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5"/><path d="M12 19l-7-7 7-7"/></svg>
          </button>
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="hsl(var(--foreground))" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/><path d="M9 21V9"/></svg>
          <h1 style="font-size:22px;font-weight:700;color:hsl(var(--foreground));margin:0">QuickBooks Login</h1>
        </div>

        <div style="background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:12px;padding:24px;margin-bottom:20px">
          <div style="font-size:13px;color:hsl(var(--muted-foreground));margin-bottom:8px">Session Status</div>
          <div style="display:flex;align-items:center;font-size:16px;font-weight:600;color:${statusColor};margin-bottom:12px">${statusDot}${statusText}</div>
          <div style="font-size:12px;color:hsl(var(--muted-foreground))">Last refreshed: ${lastRefreshed}</div>
        </div>

        <div style="background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:12px;padding:24px;margin-bottom:20px">
          <div style="font-size:14px;font-weight:600;color:hsl(var(--foreground));margin-bottom:12px">How to Refresh</div>
          <ol style="font-size:13px;color:hsl(var(--muted-foreground));margin:0;padding-left:20px;line-height:1.8">
            <li style="margin-bottom:6px">Click <strong style="color:hsl(var(--foreground))">Open QuickBooks Login</strong> below — a new tab will open.</li>
            <li style="margin-bottom:6px">When prompted, enter:<br>
              <span style="display:inline-block;margin-top:4px;padding:6px 10px;background:hsl(var(--muted));border-radius:6px;font-family:monospace;font-size:12px;color:hsl(var(--foreground))">
                Username: <strong>wilbanks</strong> &nbsp;|&nbsp; Password: <strong>WilbanksQB2026!</strong>
              </span><br>
              <span style="font-size:12px">Then click <strong style="color:hsl(var(--foreground))">Connect</strong>.</span>
            </li>
            <li style="margin-bottom:6px">A Chrome browser window will appear. Log into QuickBooks using the Wilbanks Company QB credentials.</li>
            <li style="margin-bottom:6px">If QuickBooks asks for a verification code, check the business phone for a text and enter the code.</li>
            <li style="margin-bottom:6px">Wait until you can see the <strong style="color:hsl(var(--foreground))">QuickBooks home page</strong> — do not close the tab early.</li>
            <li style="margin-bottom:6px">Switch back to this tab and click <strong style="color:hsl(var(--foreground))">Check Session Status</strong> below.</li>
            <li>The status should update to <strong style="color:#22c55e">Active</strong> and the sidebar will turn green.</li>
          </ol>
        </div>

        <button id="wc-qb-open-btn" style="width:100%;padding:14px;background:#3b82f6;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;font-family:inherit;margin-bottom:12px;transition:background 0.15s"
          onmouseenter="this.style.background='#2563eb'" onmouseleave="this.style.background='#3b82f6'">
          Open QuickBooks Login
        </button>

        <button id="wc-qb-check-btn" style="width:100%;padding:12px;background:hsl(var(--muted));color:hsl(var(--foreground));border:1px solid hsl(var(--border));border-radius:8px;font-size:14px;font-weight:500;cursor:pointer;font-family:inherit;transition:background 0.15s"
          onmouseenter="this.style.background='hsl(var(--accent))'" onmouseleave="this.style.background='hsl(var(--muted))'">
          Check Session Status
        </button>

        <div id="wc-qb-page-status" style="margin-top:16px;font-size:13px;text-align:center;min-height:20px"></div>
      </div>`;

    // Hide React's main content
    if (main) main.style.display = 'none';
    document.body.appendChild(page);

    // Open QB Login button handler — opens VPS browser session
    document.getElementById('wc-qb-open-btn').addEventListener('click', function() {
      window.open('http://138.197.76.170', '_blank', 'width=1280,height=900,resizable=yes,scrollbars=yes');
    });

    // Check status button handler
    document.getElementById('wc-qb-check-btn').addEventListener('click', function() {
      const btn = this;
      const statusDiv = document.getElementById('wc-qb-page-status');
      btn.disabled = true;
      btn.textContent = 'Checking...';
      statusDiv.style.color = 'hsl(var(--muted-foreground))';
      statusDiv.textContent = 'Checking session with QuickBooks...';
      fetch(API + '/api/qb-session/status', {
        headers: { 'Authorization': 'Bearer ' + token }
      }).then(function(r) { return r.json(); }).then(function(d) {
        _qbSessionValid = d.playwrightSessionValid !== undefined ? !!d.playwrightSessionValid : !!d.valid;
        _qbLastRefreshed = d.lastRefreshed;
        btn.disabled = false;
        btn.textContent = 'Check Session Status';
        injectQBLoginLink();
        // Refresh the page
        setTimeout(function() { renderQBLoginPage(); }, 300);
      }).catch(function() {
        btn.disabled = false;
        btn.textContent = 'Check Session Status';
        statusDiv.style.color = '#ef4444';
        statusDiv.textContent = 'Could not reach server. Try again.';
      });
    });

    // Listen for hash changes away from qb-login to restore main
    function onHashChange() {
      if (!window.location.hash.includes('/qb-login')) {
        const p = document.getElementById('wc-qb-login-page');
        if (p) p.remove();
        if (main) main.style.display = '';
        window.removeEventListener('hashchange', onHashChange);
      }
    }
    window.addEventListener('hashchange', onHashChange);
  }

  var _qbLastRefreshed = null;

  // QB Login page/nav removed per user request

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootstrap);
  } else {
    bootstrap();
  }
})();
