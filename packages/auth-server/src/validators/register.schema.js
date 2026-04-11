'use strict';

// Allowed username characters: alphanumeric, hyphens, underscores, dots
const USERNAME_RE = /^[a-zA-Z0-9._-]+$/;

// Password complexity: at least one letter AND one digit or special char
const PASSWORD_COMPLEXITY_RE = /^(?=.*[a-zA-Z])(?=.*[\d\W]).+$/;

// Common/breached passwords blocklist (minimal subset — extend in production
// by checking against HIBP or loading a full dictionary at startup)
const BLOCKLISTED_PASSWORDS = new Set([
  'password123',
  'password1234',
  'qwerty12345',
  '123456789012',
  'letmein12345',
  'welcome12345',
  'admin1234567',
  'iloveyou1234',
  'monkey123456',
  'dragon123456'
]);

/**
 * Validate the body of a POST /auth/register request.
 *
 * @param {object} body
 * @returns {{ valid: boolean, errors: string[] }}
 */
function validateRegister(body = {}) {
  const errors = [];

  const username = String(body.username || '').trim();
  const password = String(body.password || '');

  // --- Username ---
  if (!username) {
    errors.push('username: required');
  } else if (username.length < 3) {
    errors.push('username: must be at least 3 characters');
  } else if (username.length > 64) {
    errors.push('username: must not exceed 64 characters');
  } else if (!USERNAME_RE.test(username)) {
    errors.push('username: contains invalid characters (allowed: a-z 0-9 . _ -)');
  }

  // --- Password ---
  if (!password) {
    errors.push('password: required');
  } else if (password.length < 10) {
    errors.push('password: must be at least 10 characters');
  } else if (password.length > 128) {
    errors.push('password: must not exceed 128 characters');
  } else if (!PASSWORD_COMPLEXITY_RE.test(password)) {
    errors.push('password: must contain at least one letter and one digit or special character');
  } else if (BLOCKLISTED_PASSWORDS.has(password.toLowerCase())) {
    errors.push('password: this password is too common — please choose a stronger one');
  }

  return { valid: errors.length === 0, errors };
}

module.exports = { validateRegister };
