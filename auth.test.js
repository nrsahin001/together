'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { verifyIdToken, seal, unseal, loadConfig } = require('../auth');

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig', alg: 'RS256' };
const b64u = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
const ISS = 'https://auth.example.com', CID = 'client-123';
const now = Math.floor(Date.now() / 1000);
const claims = (over = {}) => ({ iss: ISS, aud: [CID], sub: '7', exp: now + 3600, iat: now, nonce: 'n1', name: 'Ada', ...over });

function token(payload, { header = { alg: 'RS256', kid: 'k1' }, key = privateKey } = {}) {
  const data = `${b64u(header)}.${b64u(payload)}`;
  const sig = header.alg === 'RS256' ? crypto.sign('RSA-SHA256', Buffer.from(data), key).toString('base64url') : '';
  return `${data}.${sig}`;
}
const opts = { keys: [jwk], issuer: ISS, clientId: CID, nonce: 'n1' };

test('accepts a valid ID token', () => {
  assert.equal(verifyIdToken(token(claims()), opts).name, 'Ada');
});
test('rejects wrong issuer, audience, nonce, expiry', () => {
  assert.throws(() => verifyIdToken(token(claims({ iss: 'https://evil.example' })), opts), /issuer/);
  assert.throws(() => verifyIdToken(token(claims({ aud: ['other'] })), opts), /audience/);
  assert.throws(() => verifyIdToken(token(claims({ aud: [CID, 'x'], azp: 'x' })), opts), /audience/);
  assert.throws(() => verifyIdToken(token(claims({ nonce: 'zzz' })), opts), /Nonce/);
  assert.throws(() => verifyIdToken(token(claims({ exp: now - 3600 })), opts), /expired/);
  assert.throws(() => verifyIdToken(token(claims({ iat: now + 3600 })), opts), /future/);
});
test('rejects tampered payload, foreign key and alg=none', () => {
  const t = token(claims()).split('.');
  t[1] = b64u(claims({ sub: '1' }));
  assert.throws(() => verifyIdToken(t.join('.'), opts), /signature/);
  const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  assert.throws(() => verifyIdToken(token(claims(), { key: other }), opts), /signature/);
  assert.throws(() => verifyIdToken(token(claims(), { header: { alg: 'none' } }), opts), /algorithm/);
  assert.throws(() => verifyIdToken(token(claims(), { header: { alg: 'HS256', kid: 'k1' } }), opts), /algorithm/);
  assert.throws(() => verifyIdToken('a.b', opts), /Malformed/);
});
test('unknown kid signals a key refresh', () => {
  assert.throws(() => verifyIdToken(token(claims(), { header: { alg: 'RS256', kid: 'rotated' } }), opts), (e) => e.code === 'NO_KEY');
});

test('signed cookies: tamper, wrong secret and expiry are rejected', () => {
  const secret = 's'.repeat(40), exp = now + 60;
  const c = seal({ sub: '7', exp }, secret);
  assert.equal(unseal(c, secret).sub, '7');
  assert.equal(unseal(c, 'x'.repeat(40)), null);
  const [body, mac] = c.split('.');
  assert.equal(unseal(`${b64u({ sub: '1', exp })}.${mac}`, secret), null);
  assert.equal(unseal(seal({ sub: '7', exp: now - 1 }, secret), secret), null);
  assert.equal(unseal(undefined, secret), null);
});

test('config refuses unsafe settings', () => {
  const ok = { OIDC_ISSUER: 'https://a.example', PUBLIC_URL: 'https://b.example', OIDC_CLIENT_ID: 'i', OIDC_CLIENT_SECRET: 's', SESSION_SECRET: 'z'.repeat(32) };
  assert.equal(loadConfig(ok).redirectUri, 'https://b.example/');
  assert.throws(() => loadConfig({ ...ok, OIDC_ISSUER: 'http://a.example' }), /https/);
  assert.throws(() => loadConfig({ ...ok, SESSION_SECRET: 'short' }), /32/);
  assert.throws(() => loadConfig({ ...ok, OIDC_CLIENT_ID: '' }), /OIDC_CLIENT_ID/);
  assert.doesNotThrow(() => loadConfig({ ...ok, OIDC_ISSUER: 'http://localhost:5000', PUBLIC_URL: 'http://localhost:3000' }));
});
