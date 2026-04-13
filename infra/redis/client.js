'use strict';

const Redis = require('ioredis');

let singleton;
let redisDisabledLogged = false;

function isTruthy(value) {
    return ['1', 'true', 'yes', 'on'].includes(String(value || '').toLowerCase());
}

function normalizeRedisUrl(value) {
    const raw = String(value || '').trim();
    if (!raw) return null;
    if (/^rediss?:\/\//i.test(raw)) return raw;
    return `redis://${raw}`;
}

function isRedisEnabled() {
    const raw = process.env.REDIS_ENABLED;
    if (raw === undefined || raw === null || String(raw).trim() === '') {
        if (process.env.NODE_ENV === 'test') {
            return false;
        }
        return true;
    }
    return isTruthy(raw);
}

function createRedisClient(url = process.env.REDIS_URL || null) {
    if (!isRedisEnabled()) {
        if (!redisDisabledLogged) {
            console.log('[Redis] Disabled via REDIS_ENABLED=false. Using non-Redis fallbacks.');
            redisDisabledLogged = true;
        }
        return null;
    }

    if (!singleton) {
        const redisTls = isTruthy(process.env.REDIS_TLS);
        const baseOptions = {
            lazyConnect: true,
            maxRetriesPerRequest: 1,
            enableOfflineQueue: false
        };

        if (redisTls) {
            baseOptions.tls = {};
        }

        const normalizedUrl = normalizeRedisUrl(url);

        if (normalizedUrl) {
            singleton = new Redis(normalizedUrl, baseOptions);
        } else {
            singleton = new Redis({
                host: process.env.REDIS_HOST || '127.0.0.1',
                port: Number(process.env.REDIS_PORT || 6379),
                username: process.env.REDIS_USERNAME,
                password: process.env.REDIS_PASSWORD,
                ...baseOptions
            });
        }

        singleton.on('error', (err) => {
            console.error('[Redis CircuitBreaker] Error:', err.message);
        });

        singleton.on('ready', () => {
            console.log('[Redis] Connected and ready');
        });

        singleton.on('reconnecting', () => {
            console.warn('[Redis] Reconnecting...');
        });
    }
    return singleton;
}

module.exports = {
    createRedisClient
};
