'use strict';

const buckets = new Map();

function rateLimiter({ limit = 30, windowMs = 60_000 } = {}) {
  return (req, res, next) => {
    const key = req.ip;
    const item = buckets.get(key) || { count: 0, resetAt: Date.now() + windowMs };
    if (item.resetAt <= Date.now()) {
      item.count = 0;
      item.resetAt = Date.now() + windowMs;
    }
    item.count += 1;
    buckets.set(key, item);

    if (item.count > limit) {
      return res.status(429).json({ error: 'rate limit exceeded' });
    }

    return next();
  };
}

module.exports = { rateLimiter };
