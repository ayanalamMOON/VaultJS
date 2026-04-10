'use strict';

const lastSeen = new Map();

async function hasSeenRotation(sessionId, rot, redis = null) {
  const key = `vault:rot:${sessionId}`;
  if (redis) {
    const previous = Number(await redis.get(key) || 0);
    return rot <= previous;
  }
  return rot <= (lastSeen.get(sessionId) || 0);
}

async function recordRotation(sessionId, rot, redis = null, ttlSeconds = 900) {
  const key = `vault:rot:${sessionId}`;
  if (redis) {
    await redis.set(key, String(rot), 'EX', ttlSeconds);
    return;
  }
  lastSeen.set(sessionId, rot);
}

module.exports = {
  hasSeenRotation,
  recordRotation
};
