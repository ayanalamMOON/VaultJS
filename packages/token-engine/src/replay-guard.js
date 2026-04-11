'use strict';

const crypto = require('crypto');
const { hasSeenRotation, recordRotation } = require('../../../infra/redis/rotation-store');

// In-memory JTI store: key -> expiry timestamp (ms)
const jtiCache = new Map();

// Evict expired entries every 5 minutes to prevent unbounded growth
const JTI_EVICT_INTERVAL_MS = 5 * 60 * 1000;
let evictTimer = null;

function scheduleEviction() {
  if (evictTimer) return;
  evictTimer = setInterval(() => {
    const now = Date.now();
    for (const [key, expiry] of jtiCache) {
      if (expiry <= now) jtiCache.delete(key);
    }
  }, JTI_EVICT_INTERVAL_MS);
  // Let the timer be unref'd so it doesn't hold the event loop open in tests
  if (evictTimer.unref) evictTimer.unref();
}

scheduleEviction();

function hashJti(jti) {
  return crypto.createHash('sha256').update(String(jti)).digest('hex');
}

/**
 * Assert that a session rotation number has not been seen before.
 * First-use is recorded so any re-use (replay) is rejected.
 *
 * @param {string} sessionId
 * @param {number} rotation
 * @param {import('ioredis').Redis|null} redis
 */
async function assertFreshRotation(sessionId, rotation, redis = null) {
  const replayed = await hasSeenRotation(sessionId, rotation, redis);
  if (replayed) throw new Error('replay detected: rotation');
  await recordRotation(sessionId, rotation, redis);
}

/**
 * Assert that a JWT ID (jti) has not been seen before within its TTL.
 * Uses Redis SETNX when available; falls back to in-process Map.
 *
 * @param {string} sessionId
 * @param {string} jti
 * @param {import('ioredis').Redis|null} redis
 * @param {number} ttlMs
 */
async function assertFreshJti(sessionId, jti, redis = null, ttlMs = 10 * 60 * 1000) {
  const hash = hashJti(jti);

  if (redis) {
    const redisKey = `vault:jti:${sessionId}:${hash}`;
    const ttlSec = Math.ceil(ttlMs / 1000);
    // SET NX EX is atomic: returns 'OK' if key was absent, null if already exists
    const result = await redis.set(redisKey, '1', 'EX', ttlSec, 'NX');
    if (result === null) throw new Error('replay detected: jti');
    return;
  }

  // In-memory fallback
  const key = `${sessionId}:${hash}`;
  const existing = jtiCache.get(key);
  if (existing && existing > Date.now()) {
    throw new Error('replay detected: jti');
  }
  jtiCache.set(key, Date.now() + ttlMs);
}

module.exports = {
  assertFreshRotation,
  assertFreshJti,
  // Exposed for testing only
  _jtiCache: jtiCache
};
