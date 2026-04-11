'use strict';

const store = new Map();

async function setTokenState(sessionId, value, ttlSeconds = 600, redis = null) {
  if (redis) {
    try {
      await redis.set(`vault:session:${sessionId}`, JSON.stringify(value), 'EX', ttlSeconds);
    } catch(e) {
      console.error('[Redis] setTokenState failure', e.message);
    }
    return;
  }
  store.set(sessionId, { value, exp: Date.now() + ttlSeconds * 1000 });
}

async function getTokenState(sessionId, redis = null) {
  if (redis) {
    try {
      const raw = await redis.get(`vault:session:${sessionId}`);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      console.error('[Redis] getTokenState parse/fetch failure', e.message);
      return null;
    }
  }
  const item = store.get(sessionId);
  if (!item || item.exp < Date.now()) return null;
  return item.value;
}

module.exports = { setTokenState, getTokenState };
