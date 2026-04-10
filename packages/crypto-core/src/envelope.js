'use strict';

const crypto = require('crypto');
const { AES_ALGO, AES_IV_BYTES, HMAC_ALGO, TOKEN_VERSION } = require('./constants');

function b64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function b64urlToBuffer(text) {
  const normalized = String(text || '').replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + pad, 'base64');
}

function canonicalizeEnvelopePayload(payload) {
  return Buffer.from(JSON.stringify(payload));
}

function encryptPayload(payload, aesKey, aad = '') {
  const iv = crypto.randomBytes(AES_IV_BYTES);
  const cipher = crypto.createCipheriv(AES_ALGO, aesKey, iv, { authTagLength: 16 });
  if (aad) cipher.setAAD(Buffer.from(aad));

  const plaintext = canonicalizeEnvelopePayload(payload);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    iv: b64url(iv),
    ciphertext: b64url(ciphertext),
    tag: b64url(tag),
    v: TOKEN_VERSION,
    aad: b64url(Buffer.from(aad || ''))
  };
}

function decryptPayload(encrypted, aesKey, aad = '') {
  const decipher = crypto.createDecipheriv(AES_ALGO, aesKey, b64urlToBuffer(encrypted.iv), { authTagLength: 16 });
  const expectedAad = aad || b64urlToBuffer(encrypted.aad || '').toString('utf8');
  if (expectedAad) decipher.setAAD(Buffer.from(expectedAad));

  decipher.setAuthTag(b64urlToBuffer(encrypted.tag));
  const pt = Buffer.concat([decipher.update(b64urlToBuffer(encrypted.ciphertext)), decipher.final()]);
  return JSON.parse(pt.toString('utf8'));
}

function signEnvelope(encrypted, hmacKey) {
  const body = JSON.stringify(encrypted);
  const sig = crypto.createHmac(HMAC_ALGO, hmacKey).update(body).digest('base64url');
  return `${b64url(body)}.${sig}`;
}

function verifyAndParseEnvelope(token, hmacKey) {
  const [bodyB64, sig] = String(token || '').split('.');
  if (!bodyB64 || !sig) throw new Error('malformed token');

  const body = b64urlToBuffer(bodyB64).toString('utf8');
  const expected = crypto.createHmac(HMAC_ALGO, hmacKey).update(body).digest();
  const actual = Buffer.from(sig, 'base64url');
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    throw new Error('bad token signature');
  }

  const parsed = JSON.parse(body);
  if (parsed.v !== TOKEN_VERSION) {
    throw new Error('unsupported token version');
  }
  return parsed;
}

module.exports = {
  b64url,
  b64urlToBuffer,
  encryptPayload,
  decryptPayload,
  signEnvelope,
  verifyAndParseEnvelope
};
