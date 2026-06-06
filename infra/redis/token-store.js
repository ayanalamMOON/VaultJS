'use strict';

const store = new Map();
let promMetrics = null;
try {
    promMetrics = require('../../packages/auth-server/src/prom-metrics');
} catch (e) {
    promMetrics = null;
}

async function setTokenState(sessionId, value, ttlSeconds = 600, redis = null) {
    if (redis) {
        try {
            await redis.set(`vault:session:${sessionId}`, JSON.stringify(value), 'EX', ttlSeconds);
            try { promMetrics?.recordRedisEvent('set', 1); } catch (e) { }
        } catch (e) {
            console.error('[Redis] setTokenState failure', e.message);
            try { promMetrics?.recordRedisEvent('error', 1); } catch (err) { }
        }
        return;
    }
    store.set(sessionId, { value, exp: Date.now() + ttlSeconds * 1000 });
}

async function getTokenState(sessionId, redis = null) {
    if (redis) {
        try {
            const raw = await redis.get(`vault:session:${sessionId}`);
            const parsed = raw ? JSON.parse(raw) : null;
            try { promMetrics?.recordRedisEvent(parsed ? 'hit' : 'miss', 1); } catch (e) { }
            return parsed;
        } catch (e) {
            console.error('[Redis] getTokenState parse/fetch failure', e.message);
            try { promMetrics?.recordRedisEvent('error', 1); } catch (err) { }
            return null;
        }
    }
    const item = store.get(sessionId);
    if (!item || item.exp < Date.now()) {
        try { promMetrics?.recordRedisEvent('miss', 1); } catch (e) { }
        return null;
    }
    try { promMetrics?.recordRedisEvent('hit', 1); } catch (e) { }
    return item.value;
}

module.exports = { setTokenState, getTokenState };
