'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');
const { loadConfig, createAuth, LoginError } = require('./auth');

const PORT = process.env.PORT || 3000;
const MAX_PEERS = 2; // a couple
const PUBLIC_DIR = path.join(__dirname, 'public');
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon',
};

const cfg = loadConfig();
const auth = createAuth(cfg);

// ---- login page (served without a session; messages come from a fixed list, never from the URL) ----
const MESSAGES = {
  access_denied: 'You chose not to share your account with Together.',
  expired: 'Your sign-in took too long or was started in another browser. Please try again.',
  unavailable: "The sign-in service isn't reachable right now. Please try again in a minute.",
  login_failed: "We couldn't sign you in. Please try again.",
};
const loginTemplate = fs.readFileSync(path.join(__dirname, 'views', 'login.html'), 'utf8');
function renderLogin(errorCode) {
  const msg = MESSAGES[errorCode] || '';
  const signup = cfg.signupUrl ? `<p class="small">No account yet? <a href="${cfg.signupUrl}" rel="noopener">Create one</a></p>` : '';
  return loginTemplate
    .replace('{{ERROR}}', msg ? `<p class="error" role="alert">${msg}</p>` : '')
    .replace('{{SIGNUP}}', signup)
    .replace(/\{\{PROVIDER\}\}/g, cfg.provider.replace(/[<>&"']/g, ''));
}

// ---- tiny in-memory rate limiter (per client IP) ----
const hits = new Map();
function limited(req, key, max, windowMs = 60000) {
  const xff = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
  const ip = (cfg.trustProxy && xff.length ? xff[xff.length - 1] : req.socket.remoteAddress) || 'unknown';
  const k = `${key}|${ip}`, now = Date.now();
  const h = (hits.get(k) || []).filter((t) => now - t < windowMs);
  h.push(now); hits.set(k, h);
  return h.length > max;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some((t) => now - t < 60000)) hits.delete(k); }, 60000).unref();

// ---- HTTP ----
function redirect(res, location, status = 302) { res.writeHead(status, { Location: location }); res.end(); }
function text(res, status, body, type = 'text/plain; charset=utf-8') { res.writeHead(status, { 'Content-Type': type }); res.end(body); }

function serveStatic(req, res, pathname) {
  let rel;
  try { rel = decodeURIComponent(pathname); } catch { return text(res, 400, 'Bad request'); }
  if (rel.includes('\0')) return text(res, 400, 'Bad request');
  const file = path.resolve(PUBLIC_DIR, '.' + (rel === '/' ? '/index.html' : rel));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return text(res, 403, 'Forbidden');
  fs.readFile(file, (err, data) => {
    if (err) return text(res, 404, 'Not found');
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(req.method === 'HEAD' ? undefined : data);
  });
}

async function handleCallback(req, res, url) {
  const clear = auth.clearCookies()[1];   // always drop the one-time login cookie
  try {
    const claims = await auth.finishLogin(Object.fromEntries(url.searchParams), auth.pendingFrom(req));
    res.setHeader('Set-Cookie', [clear, auth.sessionCookie(claims)]);
    redirect(res, '/');
  } catch (err) {
    const code = err instanceof LoginError ? err.code : 'unavailable';
    console.warn('login failed:', code, '-', err.detail || err.message);
    res.setHeader('Set-Cookie', clear);
    redirect(res, `/login?error=${code}`);
  }
}

async function route(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', "frame-ancestors 'none'; base-uri 'none'; object-src 'none'");
  if (cfg.secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

  if (p === '/healthz') return text(res, 200, 'ok');

  // sign-in: start, and the callback (your registered redirect URI is the site root "/")
  if (req.method === 'GET' && p === '/auth/start') {
    if (limited(req, 'auth', 20)) return text(res, 429, 'Too many attempts. Please wait a minute.');
    try {
      const { url: authUrl, pendingCookie } = await auth.startLogin();
      res.setHeader('Set-Cookie', pendingCookie);
      return redirect(res, authUrl);
    } catch (err) {
      console.error('could not start login:', err.message);
      return redirect(res, '/login?error=unavailable');
    }
  }
  if (req.method === 'GET' && (p === '/auth/callback' || (p === '/' && (url.searchParams.has('code') || url.searchParams.has('error'))))) {
    if (limited(req, 'auth', 20)) return text(res, 429, 'Too many attempts. Please wait a minute.');
    return handleCallback(req, res, url);
  }

  const session = auth.getSession(req);

  if (p === '/login') {
    if (session) return redirect(res, '/');
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(renderLogin(url.searchParams.get('error')));
  }
  if (p === '/logout' && req.method === 'POST') {
    res.setHeader('Set-Cookie', auth.clearCookies());
    return redirect(res, '/login', 303);
  }
  if (p === '/api/me') {
    if (!session) return text(res, 401, JSON.stringify({ error: 'not signed in' }), 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    return text(res, 200, JSON.stringify({ name: session.name, picture: session.picture }), 'application/json');
  }

  // everything else needs a session
  if (!session) return req.method === 'GET' && (p === '/' || p.endsWith('.html')) ? redirect(res, '/login') : text(res, 401, 'Sign in required');
  if (req.method !== 'GET' && req.method !== 'HEAD') return text(res, 405, 'Method not allowed');
  return serveStatic(req, res, p);
}

const server = http.createServer((req, res) => {
  route(req, res).catch((err) => {
    console.error(err);
    if (!res.headersSent) text(res, 500, 'Server error'); else res.end();
  });
});

// ---- WebSocket signaling (only for signed-in people) ----
const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });
wss.on('error', (err) => console.error('websocket server error:', err.message));
const rooms = new Map();

server.on('upgrade', (req, socket, head) => {
  const reject = (line) => { socket.write(`HTTP/1.1 ${line}\r\nConnection: close\r\n\r\n`); socket.destroy(); };
  if (limited(req, 'ws', 30)) return reject('429 Too Many Requests');
  const session = auth.getSession(req);
  if (!session) return reject('401 Unauthorized');
  // The cookie is sent automatically, so make sure the page that opened the socket is ours (blocks cross-site hijacking).
  try { if (new URL(req.headers.origin || '').host !== req.headers.host) return reject('403 Forbidden'); }
  catch { return reject('403 Forbidden'); }
  wss.handleUpgrade(req, socket, head, (ws) => { ws.user = session; wss.emit('connection', ws, req); });
});

function send(ws, obj) { if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj)); }
function broadcast(room, sender, obj) { for (const peer of room) if (peer !== sender) send(peer, obj); }
function leave(ws) {
  const room = rooms.get(ws.roomCode);
  if (!room) return;
  room.delete(ws);
  broadcast(room, ws, { type: 'peer-left' });
  if (room.size === 0) rooms.delete(ws.roomCode);
  ws.roomCode = null;
}

wss.on('connection', (ws) => {
  ws.roomCode = null;
  ws.alive = true;
  ws.on('pong', () => { ws.alive = true; });
  // Without this, one oversized or malformed frame emits an unhandled 'error' and crashes the whole server.
  ws.on('error', (err) => console.warn('websocket error:', err.code || err.message));

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (!msg || typeof msg !== 'object') return;

    if (msg.type === 'join') {
      const code = String(msg.room || '').trim().toUpperCase();
      if (!/^[A-Z0-9]{4,12}$/.test(code)) {
        return send(ws, { type: 'error', message: 'Room code must be 4-12 letters or digits.' });
      }
      if (ws.roomCode) leave(ws);
      const room = rooms.get(code) || new Set();
      if (room.size >= MAX_PEERS) {
        return send(ws, { type: 'error', message: 'This room is already full.' });
      }
      rooms.set(code, room);
      room.add(ws);
      ws.roomCode = code;
      send(ws, { type: 'joined', room: code, others: room.size - 1, you: ws.user.name });
      broadcast(room, ws, { type: 'peer-joined', name: ws.user.name });
      return;
    }

    if (msg.type !== 'signal') return;   // the only thing peers may relay to each other
    const room = rooms.get(ws.roomCode);
    if (room) broadcast(room, ws, msg);
  });

  ws.on('close', () => leave(ws));
});

// drop dead connections (phones that lost signal) so rooms don't stay "full"
const heartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.alive) { ws.terminate(); continue; }
    ws.alive = false; ws.ping();
  }
}, 30000);
wss.on('close', () => clearInterval(heartbeat));

server.listen(PORT, () => console.log(`Together on http://localhost:${PORT} (sign-in via ${cfg.issuer})`));
