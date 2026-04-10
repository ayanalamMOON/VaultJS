'use strict';

function validateRegister(body = {}) {
  const errors = [];
  if (!body.username || body.username.length < 3) errors.push('username must be at least 3 chars');
  if (!body.password || body.password.length < 10) errors.push('password must be at least 10 chars');
  return { valid: errors.length === 0, errors };
}

module.exports = { validateRegister };
