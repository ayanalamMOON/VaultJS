'use strict';

function validateLogin(body = {}) {
  const errors = [];
  if (!body.username) errors.push('username required');
  if (!body.clientPreHash) errors.push('clientPreHash required');
  return { valid: errors.length === 0, errors };
}

module.exports = { validateLogin };
