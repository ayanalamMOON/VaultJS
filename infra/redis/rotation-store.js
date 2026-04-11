'use strict';

const lastSeen = new Map();

// Atomic LUA script to check AND set rotation value safely against double-spent tickets
// KEYS[1] = rotation key, ARGV[1] = rotation number, ARGV[2] = TTL
const ROTATION_LUA = `
  local previous = tonumber(redis.call('get', KEYS[1]) or 0)
  local current = tonumber(ARGV[1])
  if current <= previous then
    return 1 -- replay detected
  else
    redis.call('set', KEYS[1], current, 'EX', ARGV[2])
    return 0 -- OK
  end
`;

async function hasSeenRotation(sessionId, rot, redis = null) {
  if (!redis) {
    return rot <= (lastSeen.get(sessionId) || 0);
  }
  // With LUA script, hasSeenRotation is handled atomically inside recordRotation 
  // to avoid Race Conditions. We return false here and enforce inside recordRotation.
  return false;
}

async function recordRotation(sessionId, rot, redis = null, ttlSeconds = 900) {
  if (redis) {
    const key = `vault:rot:${sessionId}`;
    let isReplay = 0;
    try {
      isReplay = await redis.eval(ROTATION_LUA, 1, key, rot, ttlSeconds);
    } catch (e) {
      console.error('[Redis LUA] Fail', e);
      throw new Error('redis logic failure');
    }
    if (isReplay === 1) {
      throw new Error('replay detected: rotation');
    }
    return;
  }
  
  if (rot <= (lastSeen.get(sessionId) || 0)) {
    throw new Error('replay detected: rotation');
  }
  lastSeen.set(sessionId, rot);
}

module.exports = {
  hasSeenRotation,
  recordRotation
};
