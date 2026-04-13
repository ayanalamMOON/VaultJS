'use strict';

const { hashPassword, verifyPassword } = require('../../crypto-core/src/kdf');
const { upsertUser, getUserByUsername } = require('../../../infra/db/user.model');

/**
 * Register a new user. Hashes the client-pre-hashed password using the
 * server-side KDF (argon2id when available, scryptv2 otherwise) before storage.
 *
 * Note: `password` here is already the PBKDF2 pre-hash from the client,
 * NOT the raw plaintext. The server performs a second, memory-hard hash on top.
 *
 * @param {object} opts
 * @param {string} opts.username    - Validated username
 * @param {string} opts.password    - Client-side pre-hashed password
 * @returns {Promise<object>}       - The stored user record (no passwordHash exposed)
 */
async function registerUser({ username, password }) {
    if (!username) throw new Error('username is required');
    if (!password) throw new Error('password is required');

    // Reject duplicate usernames before hashing to avoid wasting CPU
    const existing = await getUserByUsername(username);
    if (existing) {
        const err = new Error('username already taken');
        err.code = 'DUPLICATE_USER';
        throw err;
    }

    const passwordHash = await hashPassword(password);
    await upsertUser({ username, password: passwordHash });

    // Return canonical app-level identity shape
    return { id: username, username };
}

/**
 * Verify a login attempt. Returns the user record (without passwordHash) on
 * success, or null if the credentials are incorrect.
 *
 * Timing: `verifyPassword` always runs a full KDF iteration even when the user
 * does not exist, preventing user-enumeration via timing side-channels.
 *
 * @param {object} opts
 * @param {string} opts.username       - Username from login request
 * @param {string} opts.clientPreHash  - Client-side pre-hashed password
 * @returns {Promise<object|null>}
 */
async function verifyLogin({ username, clientPreHash }) {
    if (!username || !clientPreHash) return null;

    const user = await getUserByUsername(username);

    // Run the full KDF even for unknown users to maintain constant timing
    // Use a deterministic dummy hash so the cost is identical
    const hashToCheck = user?.password ?? 'scryptv2$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==';
    const ok = await verifyPassword(hashToCheck, clientPreHash).catch(() => false);

    if (!user || !ok) return null;

    return { id: user.username, username: user.username };
}

module.exports = { registerUser, verifyLogin };
