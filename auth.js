'use strict';
// OpenID Connect login (Authorization Code + PKCE) against your Secure Auth server. No dependencies.
// State is kept in signed, HttpOnly cookies, so it survives Render restarts and needs no database.
const crypto = require('crypto');

const PENDING = 'tg_oauth';     // short-lived: state, nonce, PKCE verifier
const SESSION = 'tg_session';   // signed session: who is signed in

const b64u = (b) => Buffer.from(b).toString('base64url');
const nowSec = () => Math.floor(Date.now() / 1000);

function safeEqual(a, b) {
  const x = Buffer.from(String(a ?? '')), y = Buffer.from(String(b ?? ''));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

class LoginError extends Error {
  constructor(code, detail) { super(detail || code); this.code = code; this.detail = detail || code; }
}

function loadConfig(env = process.env) {
  const need = (k) => { const v = env[k]; if (!v) throw new Error(`Missing environment variable: ${k}`); return v; };
  const local = (u) => /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/.test(u);
  const issuer = need('OIDC_ISSUER').replace(/\/+$/, '');
  const publicUrl = need('PUBLIC_URL').replace(/\/+$/, '');
  for (const [name, u] of [['OIDC_ISSUER', issuer], ['PUBLIC_URL', publicUrl]]) {
    if (!u.startsWith('https://') && !local(u)) throw new Error(`${name} must start with https:// (http is allowed only for localhost)`);
  }
  const secret = need('SESSION_SECRET');
  if (secret.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters');
  const signup = env.ACCOUNT_SIGNUP_URL || '';
  if (signup && !/^https:\/\/[^\s"'<>]+$/.test(signup)) throw new Error('ACCOUNT_SIGNUP_URL must be an https:// URL');
  return {
    issuer, publicUrl, secret,
    clientId: need('OIDC_CLIENT_ID'),
    clientSecret: need('OIDC_CLIENT_SECRET'),
    redirectUri: env.OIDC_REDIRECT_URI || `${publicUrl}/`,     // must match the redirect URI registered in the portal EXACTLY
    scope: env.OIDC_SCOPE || 'openid profile',
    secure: publicUrl.startsWith('https://'),
    sessionDays: Number(env.SESSION_DAYS || 7),
    signupUrl: signup,
    provider: env.AUTH_PROVIDER_NAME || 'Secure Auth',
    trustProxy: env.TRUST_PROXY !== '0',
  };
}

// ---- signed cookies ----
function seal(payload, secret) {
  const body = b64u(JSON.stringify(payload));
  return `${body}.${crypto.createHmac('sha256', secret).update(body).digest('base64url')}`;
}
function unseal(token, secret) {
  try {
    const [body, mac] = String(token || '').split('.');
    if (!body || !mac) return null;
    const good = crypto.createHmac('sha256', secret).update(body).digest('base64url');
    if (!safeEqual(mac, good)) return null;
    const data = JSON.parse(Buffer.from(body, 'base64url').toString());
    return data && data.exp > nowSec() ? data : null;
  } catch { return null; }
}
function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
const cookie = (name, value, maxAge, secure) =>
  `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;

// ---- ID token verification (RS256 against the server's JWKS) ----
function verifyIdToken(token, { keys, issuer, clientId, nonce, skew = 60, now = nowSec() }) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new Error('Malformed ID token');
  const [h, p, s] = parts;
  const header = JSON.parse(Buffer.from(h, 'base64url').toString());
  const claims = JSON.parse(Buffer.from(p, 'base64url').toString());
  if (header.alg !== 'RS256') throw new Error('Unexpected signing algorithm');
  const jwk = header.kid ? keys.find((k) => k.kid === header.kid) : (keys.length === 1 ? keys[0] : null);
  if (!jwk || jwk.kty !== 'RSA') { const e = new Error('Signing key not found'); e.code = 'NO_KEY'; throw e; }
  const ok = crypto.verify('RSA-SHA256', Buffer.from(`${h}.${p}`),
    crypto.createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(s, 'base64url'));
  if (!ok) throw new Error('Invalid ID token signature');
  if (claims.iss !== issuer) throw new Error('Wrong issuer');
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(clientId) || (aud.length > 1 && claims.azp !== clientId)) throw new Error('Wrong audience');
  if (typeof claims.exp !== 'number' || claims.exp < now - skew) throw new Error('ID token expired');
  if (typeof claims.iat === 'number' && claims.iat > now + skew) throw new Error('ID token issued in the future');
  if (!claims.sub) throw new Error('Missing subject');
  if (nonce !== undefined && !safeEqual(claims.nonce, nonce)) throw new Error('Nonce mismatch');
  return claims;
}

function createAuth(cfg, fetchImpl = fetch) {
  const timeout = () => AbortSignal.timeout(60000);   // generous: a sleeping free-tier server can take ~1 min to wake
  let meta = null, metaAt = 0, jwksCache = null, jwksAt = 0;

  async function metadata() {
    if (meta && Date.now() - metaAt < 3600e3) return meta;
    const r = await fetchImpl(`${cfg.issuer}/.well-known/openid-configuration`, { signal: timeout() });
    if (!r.ok) throw new Error(`OIDC discovery failed (${r.status})`);
    const m = await r.json();
    if (m.issuer !== cfg.issuer) throw new Error(`Issuer mismatch: server says ${m.issuer}, OIDC_ISSUER is ${cfg.issuer}`);
    for (const k of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) if (!m[k]) throw new Error(`Discovery is missing ${k}`);
    meta = m; metaAt = Date.now();
    return m;
  }
  async function keys(force = false) {
    if (!force && jwksCache && Date.now() - jwksAt < 3600e3) return jwksCache;
    const r = await fetchImpl((await metadata()).jwks_uri, { signal: timeout() });
    if (!r.ok) throw new Error(`JWKS fetch failed (${r.status})`);
    jwksCache = (await r.json()).keys || []; jwksAt = Date.now();
    return jwksCache;
  }
  const basic = () => 'Basic ' + Buffer.from(`${encodeURIComponent(cfg.clientId)}:${encodeURIComponent(cfg.clientSecret)}`).toString('base64');

  async function startLogin() {
    const m = await metadata();
    const state = b64u(crypto.randomBytes(18)), nonce = b64u(crypto.randomBytes(18));
    const verifier = b64u(crypto.randomBytes(48));
    const url = new URL(m.authorization_endpoint);
    url.search = new URLSearchParams({
      response_type: 'code', client_id: cfg.clientId, redirect_uri: cfg.redirectUri, scope: cfg.scope,
      state, nonce, code_challenge: b64u(crypto.createHash('sha256').update(verifier).digest()), code_challenge_method: 'S256',
    }).toString();
    const pending = seal({ state, nonce, verifier, exp: nowSec() + 600 }, cfg.secret);
    return { url: url.toString(), pendingCookie: cookie(PENDING, pending, 600, cfg.secure) };
  }

  async function finishLogin(query, pendingToken) {
    const pending = unseal(pendingToken, cfg.secret);
    if (!pending) throw new LoginError('expired', 'no valid login in progress (cookie missing or expired)');
    if (!safeEqual(query.state, pending.state)) throw new LoginError('login_failed', 'state mismatch');
    if (query.error) throw new LoginError(query.error === 'access_denied' ? 'access_denied' : 'login_failed', `${query.error} ${query.error_description || ''}`);
    if (!query.code) throw new LoginError('login_failed', 'no code returned');

    const m = await metadata();
    const r = await fetchImpl(m.token_endpoint, {
      method: 'POST', signal: timeout(),
      headers: { Authorization: basic(), 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: query.code, redirect_uri: cfg.redirectUri, code_verifier: pending.verifier }),
    });
    const tok = await r.json().catch(() => ({}));
    if (!r.ok || !tok.id_token) throw new LoginError('login_failed', `token endpoint ${r.status} ${tok.error || ''} ${tok.error_description || ''}`);

    const check = (k) => verifyIdToken(tok.id_token, { keys: k, issuer: cfg.issuer, clientId: cfg.clientId, nonce: pending.nonce });
    let claims;
    try { claims = check(await keys()); }
    catch (e) {
      if (e.code !== 'NO_KEY') throw new LoginError('login_failed', e.message);
      try { claims = check(await keys(true)); } catch (e2) { throw new LoginError('login_failed', e2.message); }   // key rotated
    }
    // We only needed the identity: revoke the access/refresh tokens right away (best effort).
    if (m.revocation_endpoint) {
      for (const t of [tok.refresh_token, tok.access_token].filter(Boolean)) {
        fetchImpl(m.revocation_endpoint, { method: 'POST', signal: timeout(),
          headers: { Authorization: basic(), 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ token: t }) }).catch(() => {});
      }
    }
    return claims;
  }

  const maxAge = () => Math.round(cfg.sessionDays * 86400);
  return {
    startLogin, finishLogin, metadata,
    sessionCookie(claims) {
      const picture = typeof claims.picture === 'string' && /^https?:\/\//.test(claims.picture) ? claims.picture : null;
      const data = { sub: String(claims.sub), name: String(claims.name || 'Friend').slice(0, 80), picture, exp: nowSec() + maxAge() };
      return cookie(SESSION, seal(data, cfg.secret), maxAge(), cfg.secure);
    },
    getSession(req) { return unseal(parseCookies(req.headers.cookie)[SESSION], cfg.secret); },
    pendingFrom(req) { return parseCookies(req.headers.cookie)[PENDING]; },
    clearCookies() { return [cookie(SESSION, '', 0, cfg.secure), cookie(PENDING, '', 0, cfg.secure)]; },
  };
}

module.exports = { loadConfig, createAuth, verifyIdToken, LoginError, seal, unseal, parseCookies, PENDING, SESSION };
