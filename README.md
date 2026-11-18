# Together (with sign-in)

Your couple-sync app, now behind your Secure Auth login. Visitors see a login page; only signed-in people get the app
or the WebSocket signaling server. `public/app.js` is exactly your original.

```
server.js           HTTP + WebSocket server (sign-in routes, protected static files, protected signaling)
auth.js             OpenID Connect login (Authorization Code + PKCE), no extra dependencies
views/login.html    the login page (your dark/rose theme)
public/index.html   your page + a name chip and "Sign out"
public/user.js      fills in the signed-in name
public/app.js       unchanged
tests/              unit tests (npm test)
```

## Set up
1. In the developer portal, open **Edit** on Together and add **test users**: the email of each person's *user account*
   (created on your user site). While the app is in `draft`, only these people can sign in, which is perfect for a
   private couple app. Without test users nobody can sign in, not even you.
2. **Rotate the client secret** ("New secret"): the old one was visible in a screenshot. Never commit it.
3. On Render (Web Service, Node): build `npm install`, start `npm start`, and set the environment variables below.

| Variable | Value |
|---|---|
| `OIDC_ISSUER` | `https://app.najibur.me` (exactly the auth server's `ISSUER`) |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | from the developer portal |
| `PUBLIC_URL` | `https://together-4546.onrender.com` |
| `SESSION_SECRET` | 32+ random characters: `python -c "import secrets;print(secrets.token_hex(32))"` |

The redirect URI is `PUBLIC_URL` + `/`, which is what you registered. If you ever register `/auth/callback` instead,
that route works too (set `OIDC_REDIRECT_URI`). Optional: `OIDC_SCOPE` (default `openid profile`; add `birthdate`
only if you use it and it is registered), `SESSION_DAYS` (default 7), `ACCOUNT_SIGNUP_URL` (adds a "Create one" link on the
login page), `AUTH_PROVIDER_NAME`.

## How it behaves
- `/` without a session redirects to `/login`; `/auth/start` sends the browser to your auth server; the callback checks
  `state`, exchanges the code with PKCE and your client secret, verifies the ID token signature, issuer, audience and
  nonce, then sets a signed HttpOnly session cookie. The access/refresh tokens are revoked immediately (only the identity is needed).
- Sessions are stateless signed cookies, so Render restarts don't sign anyone out. Sign-out clears the cookie; a
  session lasts up to `SESSION_DAYS` even if the person's central account is later disabled.
- WebSocket: requires the session cookie **and** a same-origin page, messages are capped at 64 KB, peers can only relay
  `signal` messages (not forge `peer-left` etc.), and dead connections are dropped so rooms don't stay "full".
  `joined` / `peer-joined` now also carry the person's name (`you` / `name`); `app.js` ignores extra fields.
- Free Render instances sleep; if the auth server is asleep the first sign-in can take about a minute.

## Tests
`npm test` runs the unit tests (token verification, cookie signing, config checks). I also ran the full flow against
the real auth backend: login redirect with PKCE, consent, code exchange, replay/forgery attempts, Deny, WebSocket gating,
rooms, and sign-out.
