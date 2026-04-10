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

const outstanding = new Map();

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

function computeDifficulty(failures = 0) {
  return Math.min(POW_MAX_DIFFICULTY, Math.max(POW_MIN_DIFFICULTY, POW_DEFAULT_DIFFICULTY + failures - 3));
}

function issueChallenge(userKey, failures = 3) {
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

function verifyChallenge(userKey, nonce) {
  const challenge = outstanding.get(userKey);
  if (!challenge || challenge.expiresAt < Date.now()) return false;

  const parsed = Number(nonce);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > challenge.maxNonce) return false;

  const digest = crypto.createHash('sha256').update(`${challenge.prefix}${parsed}`).digest();
  const ok = countLeadingZeroBits(digest) >= challenge.difficulty;
  if (ok) outstanding.delete(userKey);
  return ok;
}

module.exports = { issueChallenge, verifyChallenge, countLeadingZeroBits, computeDifficulty };
