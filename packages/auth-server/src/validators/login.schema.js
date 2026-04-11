'use strict';

// Allowed username characters: alphanumeric, hyphens, underscores, dots
const USERNAME_RE = /^[a-zA-Z0-9._-]+$/;

// clientPreHash is a base64-encoded 32-byte SHA-256/PBKDF2 output (~44 chars)
// Accept anything >= 32 chars that looks like base64 (strict enough to reject empty/garbage)
const BASE64_RE = /^[A-Za-z0-9+/=_-]+$/;

/**
 * Validate the body of a POST /auth/login request.
 *
 * @param {object} body
 * @returns {{ valid: boolean, errors: string[] }}
 */
function validateLogin(body = {}) {
  const errors = [];

  const username = String(body.username || '').trim();
  const clientPreHash = String(body.clientPreHash || '').trim();

  if (!username) {
    errors.push('username: required');
  } else if (username.length < 3) {
    errors.push('username: must be at least 3 characters');
  } else if (username.length > 64) {
    errors.push('username: must not exceed 64 characters');
  } else if (!USERNAME_RE.test(username)) {
    errors.push('username: contains invalid characters (allowed: a-z 0-9 . _ -)');
  }

  if (!clientPreHash) {
    errors.push('clientPreHash: required');
  } else if (clientPreHash.length < 32) {
    errors.push('clientPreHash: too short — must be a PBKDF2 base64 output (>= 32 chars)');
  } else if (clientPreHash.length > 256) {
    errors.push('clientPreHash: exceeds maximum length');
  } else if (!BASE64_RE.test(clientPreHash)) {
    errors.push('clientPreHash: invalid encoding — must be base64 or base64url');
  }

  return { valid: errors.length === 0, errors };
}

module.exports = { validateLogin };
