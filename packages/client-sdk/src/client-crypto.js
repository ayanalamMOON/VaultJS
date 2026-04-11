'use strict';

const { pbkdf2PreHash } = require('../../crypto-core/src/kdf');

/**
 * Derive a client-side PBKDF2 pre-hash of the user's password.
 *
 * This is the first layer of the "Length" dimension: the raw password never
 * leaves the client. Instead a 150 000-iteration PBKDF2-SHA256 hash with a
 * username::domain salt is sent to the server, where a second memory-hard
 * KDF (argon2id or scrypt) is applied on top.
 *
 * @param {string} password  - User's raw plaintext password
 * @param {string} username  - Username (used as salt component)
 * @param {string} [domain='domain.com'] - Domain (used as salt component)
 * @returns {string}  Base64-encoded 32-byte pre-hash
 * @throws {Error}    If password or username is missing / too short
 */
function clientPreHash(password, username, domain = 'domain.com') {
  if (!password || typeof password !== 'string') throw new Error('password is required');
  if (!username || typeof username !== 'string') throw new Error('username is required');
  if (password.length < 1) throw new Error('password must not be empty');
  return pbkdf2PreHash(password, username, domain);
}

module.exports = { clientPreHash };
