'use strict';

const { hashPassword, verifyPassword } = require('../../crypto-core/src/kdf');
const { upsertUser, getUserByUsername } = require('../../../infra/db/user.model');

async function registerUser({ username, password }) {
  const passwordHash = await hashPassword(password);
  return upsertUser({ id: username, username, passwordHash });
}

async function verifyLogin({ username, clientPreHash }) {
  const user = getUserByUsername(username);
  if (!user) return null;

  const ok = await verifyPassword(user.passwordHash, clientPreHash);
  return ok ? user : null;
}

module.exports = { registerUser, verifyLogin };
