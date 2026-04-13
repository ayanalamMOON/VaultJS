'use strict';

const { getAnomalyPressure } = require('../anomaly-detector');

// Per-IP token buckets stored in process memory.
// For multi-instance deployments wire in the Redis leaky-bucket implementation below.
const buckets = new Map();

// Evict stale buckets periodically so memory doesn't grow without bound.
const EVICT_INTERVAL_MS = 5 * 60 * 1000;
const evictTimer = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of buckets) {
        if (v.resetAt <= now) buckets.delete(k);
    }
}, EVICT_INTERVAL_MS);
if (evictTimer.unref) evictTimer.unref();

const REDIS_WINDOW_LUA = `
  local count = redis.call('INCR', KEYS[1])
  if count == 1 then
    redis.call('PEXPIRE', KEYS[1], ARGV[1])
  end
  local pttl = redis.call('PTTL', KEYS[1])
  return {count, pttl}
`;

function setRateHeaders(res, { limit, remaining, resetSec }) {
    const safeRemaining = Math.max(0, remaining);
    const safeReset = Math.max(0, Math.ceil(resetSec));
    res.set('X-RateLimit-Limit', String(limit));
    res.set('X-RateLimit-Remaining', String(safeRemaining));
    res.set('X-RateLimit-Reset', String(safeReset));
    // IETF draft-compatible aliases
    res.set('RateLimit-Limit', String(limit));
    res.set('RateLimit-Remaining', String(safeRemaining));
    res.set('RateLimit-Reset', String(safeReset));
}

function readNumberEnv(name, fallback) {
    const raw = Number(process.env[name]);
    return Number.isFinite(raw) ? raw : fallback;
}

function computeEffectiveLimit(req, baseLimit, adaptive) {
    if (!adaptive) {
        return { limit: baseLimit, profile: 'static' };
    }

    let limit = Number(baseLimit);
    const riskScore = Number(req.security?.ipRiskScore || 0);
    const ua = String(req.headers['user-agent'] || '').toLowerCase();
    const pressure = getAnomalyPressure().score;

    if (riskScore >= 40) limit *= 0.55;
    else if (riskScore >= 25) limit *= 0.8;

    if (/bot|crawler|spider|headless|selenium|puppeteer|playwright|webdriver/.test(ua)) {
        limit *= 0.7;
    }

    const pressureThreshold = readNumberEnv('VAULT_ANOMALY_PRESSURE_THRESHOLD', 140);
    if (pressure > pressureThreshold) {
        limit *= 0.85;
    }

    return {
        limit: Math.max(5, Math.floor(limit)),
        profile: 'adaptive'
    };
}

/**
 * Factory that returns an Express middleware implementing a fixed-window rate limiter.
 *
 * When Redis is provided the limit is enforced using INCR + EXPIRE so it works
 * across multiple server instances. Falls back to the in-process Map otherwise.
 *
 * @param {object} opts
 * @param {number} [opts.limit=30]          - Max requests allowed per window
 * @param {number} [opts.windowMs=60000]    - Window length in milliseconds
 * @param {string} [opts.keyPrefix='rl']    - Redis key namespace
 * @param {import('ioredis').Redis|null} [opts.redis=null]
 * @returns {import('express').RequestHandler}
 */
function rateLimiter({ limit = 30, windowMs = 60_000, keyPrefix = 'rl', redis = null, includeRoute = false, adaptive = true } = {}) {
    const windowSec = Math.ceil(windowMs / 1000);

    return async (req, res, next) => {
        // Use the real client IP enriched by the ipIntel middleware when available
        const ip = req.security?.clientIp || req.ip || '0.0.0.0';
        const routePart = includeRoute ? `:${req.method}:${req.baseUrl || req.path || '/'}` : '';
        const scopedIp = `${ip}${routePart}`;
        const effective = computeEffectiveLimit(req, limit, adaptive);

        res.set('X-RateLimit-Effective-Limit', String(effective.limit));
        res.set('X-RateLimit-Policy', effective.profile);

        try {
            if (redis) {
                return await redisRateLimit(req, res, next, {
                    ip: scopedIp,
                    redis,
                    keyPrefix,
                    windowSec,
                    windowMs,
                    limit: effective.limit
                });
            }
            return memoryRateLimit(req, res, next, { ip: scopedIp, limit: effective.limit, windowMs });
        } catch {
            // On any limiter error, let the request through rather than DoSing ourselves
            return next();
        }
    };
}

async function redisRateLimit(req, res, next, { ip, redis, keyPrefix, windowSec, windowMs, limit }) {
    const key = `${keyPrefix}:${ip}`;
    const raw = await redis.eval(REDIS_WINDOW_LUA, 1, key, windowMs);
    const count = Number(raw?.[0] || 0);
    const pttl = Number(raw?.[1] || 0);
    const resetSec = pttl > 0 ? pttl / 1000 : windowSec;

    if (count > limit) {
        setRateHeaders(res, { limit, remaining: 0, resetSec });
        res.set('Retry-After', String(Math.ceil(resetSec)));
        return res.status(429).json({ error: 'rate limit exceeded' });
    }
    setRateHeaders(res, { limit, remaining: limit - count, resetSec });
    return next();
}

function memoryRateLimit(req, res, next, { ip, limit, windowMs }) {
    const now = Date.now();
    const item = buckets.get(ip) || { count: 0, resetAt: now + windowMs };

    if (item.resetAt <= now) {
        item.count = 0;
        item.resetAt = now + windowMs;
    }

    item.count += 1;
    buckets.set(ip, item);

    const remaining = Math.max(0, limit - item.count);
    const resetSec = Math.ceil((item.resetAt - now) / 1000);
    setRateHeaders(res, { limit, remaining, resetSec });

    if (item.count > limit) {
        res.set('Retry-After', String(resetSec));
        return res.status(429).json({ error: 'rate limit exceeded' });
    }
    return next();
}

module.exports = { rateLimiter };
