'use strict';

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
function rateLimiter({ limit = 30, windowMs = 60_000, keyPrefix = 'rl', redis = null } = {}) {
  const windowSec = Math.ceil(windowMs / 1000);

  return async (req, res, next) => {
    // Use the real client IP enriched by the ipIntel middleware when available
    const ip = req.security?.clientIp || req.ip || '0.0.0.0';

    try {
      if (redis) {
        return await redisRateLimit(req, res, next, { ip, redis, keyPrefix, windowSec, limit });
      }
      return memoryRateLimit(req, res, next, { ip, limit, windowMs });
    } catch {
      // On any limiter error, let the request through rather than DoSing ourselves
      return next();
    }
  };
}

async function redisRateLimit(req, res, next, { ip, redis, keyPrefix, windowSec, limit }) {
  const key = `${keyPrefix}:${ip}`;
  const count = await redis.incr(key);
  if (count === 1) {
    // Set expiry only on the first increment to preserve the window start
    await redis.expire(key, windowSec);
  }
  if (count > limit) {
    res.set('Retry-After', String(windowSec));
    return res.status(429).json({ error: 'rate limit exceeded' });
  }
  res.set('X-RateLimit-Limit', String(limit));
  res.set('X-RateLimit-Remaining', String(Math.max(0, limit - count)));
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
  res.set('X-RateLimit-Limit', String(limit));
  res.set('X-RateLimit-Remaining', String(remaining));

  if (item.count > limit) {
    const retryAfterSec = Math.ceil((item.resetAt - now) / 1000);
    res.set('Retry-After', String(retryAfterSec));
    return res.status(429).json({ error: 'rate limit exceeded' });
  }
  return next();
}

module.exports = { rateLimiter };
