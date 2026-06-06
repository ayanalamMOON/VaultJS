'use strict';

// Lightweight per-IP rate limiter for admin endpoints. In-memory and simple.
const WINDOW_MS = Number(process.env.ADMIN_RATE_LIMIT_WINDOW_MS || 60_000);
const MAX_PER_WINDOW = Number(process.env.ADMIN_RATE_LIMIT_MAX || 60);

const store = new Map();

function cleanupWindow() {
    const now = Date.now();
    for (const [k, v] of store.entries()) {
        if (v.start + WINDOW_MS < now) store.delete(k);
    }
}

function rateLimitMiddleware(req, res, next) {
    const ip = req.security?.clientIp || req.ip || 'unknown';
    const now = Date.now();
    const entry = store.get(ip) || { start: now, count: 0 };
    if (entry.start + WINDOW_MS < now) {
        entry.start = now;
        entry.count = 0;
    }
    entry.count += 1;
    store.set(ip, entry);
    res.setHeader('x-admin-rate-limit-limit', String(MAX_PER_WINDOW));
    res.setHeader('x-admin-rate-limit-remaining', String(Math.max(0, MAX_PER_WINDOW - entry.count)));
    if (entry.count > MAX_PER_WINDOW) {
        return res.status(429).json({ ok: false, error: 'rate_limited' });
    }
    // occasional cleanup
    if (Math.random() < 0.01) cleanupWindow();
    return next();
}

module.exports = rateLimitMiddleware;
