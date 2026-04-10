'use strict';

const crypto = require('crypto');
const constants = require('./constants');

let argon2;
try {
  argon2 = require('argon2');
} catch {
  argon2 = null;
}

function normalizePreHashInput(input) {
  if (typeof input !== 'string' || input.length < 16) {
    throw new Error('invalid pre-hash input');
  }
  return input.trim();
}

function pbkdf2PreHash(password, username, domain = 'domain.com') {
  if (!password || !username) throw new Error('password and username are required');
  const salt = `${username}::${domain}`;
  return crypto
    .pbkdf2Sync(password, salt, constants.PBKDF2_ITERATIONS, constants.PBKDF2_BYTES, constants.PBKDF2_DIGEST)
    .toString('base64');
}

function peppered(value, pepper = process.env.PASSWORD_PEPPER || '') {
  return `${value}::${pepper}`;
}

async function hashPassword(clientPreHash) {
  const normalized = normalizePreHashInput(clientPreHash);
  const input = peppered(normalized);

  if (argon2) {
    return argon2.hash(input, {
      type: argon2.argon2id,
      memoryCost: constants.ARGON2_MEMORY_KIB,
      timeCost: constants.ARGON2_TIME_COST,
      parallelism: constants.ARGON2_PARALLELISM,
      hashLength: 32
    });
  }

  const salt = crypto.randomBytes(constants.SALT_BYTES);
  const digest = crypto.scryptSync(input, salt, 64, { N: 2 ** 15, r: 8, p: 1 }).toString('base64');
  return `scryptv2$${salt.toString('base64')}$${digest}`;
}

async function verifyPassword(hash, clientPreHash) {
  const normalized = normalizePreHashInput(clientPreHash);
  const input = peppered(normalized);

  if (argon2 && hash.startsWith('$argon2')) {
    return argon2.verify(hash, input);
  }

  if (!hash.startsWith('scryptv2$')) {
    return false;
  }

  const [, saltB64, digestB64] = hash.split('$');
  const actual = crypto.scryptSync(input, Buffer.from(saltB64, 'base64'), 64, { N: 2 ** 15, r: 8, p: 1 });
  const expected = Buffer.from(digestB64, 'base64');

  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

module.exports = {
  pbkdf2PreHash,
  hashPassword,
  verifyPassword,
  normalizePreHashInput
};
