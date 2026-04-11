'use strict';

const crypto = require('crypto');
const {
  POW_DEFAULT_DIFFICULTY,
  POW_MIN_DIFFICULTY,
  POW_MAX_DIFFICULTY,
  POW_EXPIRES_MS,
  POW_CHALLENGE_BYTES,
  POW_MAX_NONCE
} = require('../../crypto-core/src/constants');

/**
 * Outstanding challenge store. In production with multiple server instances
 * this should be backed by Redis (SET NX EX pattern). The in-process Map
 * works for single-instance deploys and tests.
 *
 * key → { id, prefix, difficulty, expiresAt, maxNonce }
 */
const outstanding = new Map();

// Evict expired challenges every 60 seconds to prevent unbounded growth
const EVICT_INTERVAL_MS = 60_000;
const evictTimer = setInterval(() => {
  const now = Date.now();
  for (const [k, v] of outstanding) {
    if (v.expiresAt <= now) outstanding.delete(k);
  }
}, EVICT_INTERVAL_MS);
if (evictTimer.unref) evictTimer.unref();

/**
 * Count the number of leading zero bits in a buffer.
 * Used both server-side (to verify solutions) and client-side (to solve).
 *
 * @param {Buffer} buffer
 * @returns {number}
 */
function countLeadingZeroBits(buffer) {
  let bits = 0;
  for (const byte of buffer) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

/**
 * Compute the challenge difficulty based on consecutive failure count.
 * Ramps up linearly from POW_DEFAULT_DIFFICULTY, clamped to [min, max].
 *
 * @param {number} failures - Consecutive login failures for this user+ip
 * @returns {number}
 */
function computeDifficulty(failures = 0) {
  // Start ramping at 3 failures. Each additional failure adds 1 bit.
  const raw = POW_DEFAULT_DIFFICULTY + Math.max(0, failures - 3);
  return Math.min(POW_MAX_DIFFICULTY, Math.max(POW_MIN_DIFFICULTY, raw));
}

/**
 * Issue a new PoW challenge for a user key.
 * Replaces any previously outstanding challenge for the same key.
 *
 * @param {string} userKey   - Composite key e.g. "username:ip"
 * @param {number} failures  - Consecutive failure count
 * @returns {{ id: string, prefix: string, difficulty: number, expiresAt: number, maxNonce: number }}
 */
function issueChallenge(userKey, failures = 3) {
  if (!userKey) throw new Error('userKey is required');

  const challenge = {
    id: crypto.randomUUID(),
    prefix: crypto.randomBytes(POW_CHALLENGE_BYTES).toString('hex'),
    difficulty: computeDifficulty(failures),
    expiresAt: Date.now() + POW_EXPIRES_MS,
    maxNonce: POW_MAX_NONCE
  };

  outstanding.set(userKey, challenge);
  return challenge;
}

/**
 * Verify a PoW solution against the outstanding challenge for a user key.
 *
 * Verification is a single SHA-256 hash — effectively free compared to the
 * cost the client paid to find the nonce.
 *
 * Once verified the challenge is consumed (deleted) so it cannot be replayed.
 *
 * @param {string}       userKey - Same key used in issueChallenge
 * @param {string|number} nonce  - Client's solution nonce
 * @returns {boolean}
 */
function verifyChallenge(userKey, nonce) {
  const challenge = outstanding.get(userKey);
  if (!challenge) return false;

  // Expired?
  if (challenge.expiresAt < Date.now()) {
    outstanding.delete(userKey);
    return false;
  }

  // Validate nonce bounds
  const parsed = Number(nonce);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > challenge.maxNonce) {
    return false;
  }

  // Verify the solution
  const digest = crypto.createHash('sha256').update(`${challenge.prefix}${parsed}`).digest();
  const ok = countLeadingZeroBits(digest) >= challenge.difficulty;

  // Consume the challenge regardless of outcome to prevent brute-force of nonces
  outstanding.delete(userKey);
  return ok;
}

module.exports = { issueChallenge, verifyChallenge, countLeadingZeroBits, computeDifficulty };
