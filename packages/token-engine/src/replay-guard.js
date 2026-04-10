'use strict';

const crypto = require('crypto');
const { hasSeenRotation, recordRotation } = require('../../../infra/redis/rotation-store');

const jtiCache = new Map();

function hashJti(jti) {
  return crypto.createHash('sha256').update(String(jti)).digest('hex');
}

async function assertFreshRotation(sessionId, rotation, redis = null) {
  const replayed = await hasSeenRotation(sessionId, rotation, redis);
  if (replayed) throw new Error('replay detected: rotation');
  await recordRotation(sessionId, rotation, redis);
}

async function assertFreshJti(sessionId, jti, ttlMs = 10 * 60 * 1000) {
  const key = `${sessionId}:${hashJti(jti)}`;
  const current = jtiCache.get(key);
  if (current && current > Date.now()) {
    throw new Error('replay detected: jti');
  }
  jtiCache.set(key, Date.now() + ttlMs);
}

module.exports = {
  assertFreshRotation,
  assertFreshJti
};
