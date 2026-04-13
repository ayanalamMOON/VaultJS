'use strict';

const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const { createRedisClient } = require('../../../infra/redis/client');
const { getDb } = require('../../../infra/db/connection');
const { authRoutes } = require('./routes/auth.routes');
const { sessionRoutes } = require('./routes/session.routes');
const { adminRoutes } = require('./routes/admin.routes');
const { rateLimiter } = require('./middleware/rate-limiter');
const { ipIntel } = require('./middleware/ip-intel');
const { validateTokenMiddleware } = require('./middleware/validate-token');
const { getAnomalyStats } = require('./anomaly-detector');

const app = express();
const port = Number(process.env.PORT || 3001);
const masterSecret = process.env.MASTER_SECRET || 'dev_master_secret_change_me';
const hmacKey = process.env.HMAC_KEY || 'dev_hmac_key_change_me';
const redis = createRedisClient();

// ── Global middleware ────────────────────────────────────────────────────────
app.set('trust proxy', 1); // Trust first proxy (nginx / load balancer)
app.use(express.json({ limit: '64kb' }));
app.use(cookieParser());

app.use((req, res, next) => {
    const requestId = String(req.headers['x-request-id'] || crypto.randomUUID());
    const started = process.hrtime.bigint();

    req.requestId = requestId;
    res.setHeader('x-request-id', requestId);

    res.on('finish', () => {
        const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
        if (elapsedMs > 2000) {
            console.warn(`[auth-server] slow request ${req.method} ${req.originalUrl} ${elapsedMs.toFixed(1)}ms reqId=${requestId}`);
        }
    });

    next();
});

app.use(ipIntel);
app.use(rateLimiter({ limit: 60, windowMs: 60_000, redis }));

// Remove fingerprinting headers
app.disable('x-powered-by');
app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
});

// ── Routes ───────────────────────────────────────────────────────────────────

// Auth routes (register, login, logout) — public; login has its own PoW/rate-limit
app.use('/auth', authRoutes({ masterSecret, hmacKey, redis }));

// Session routes — require a valid token
const tokenMiddleware = validateTokenMiddleware({ masterSecret, hmacKey, redis });
app.use('/session', tokenMiddleware, sessionRoutes({ masterSecret, hmacKey, redis }));

// Admin routes — API token protected, no session token required
app.use('/admin', adminRoutes());

// Health check — no auth required
app.get('/healthz', (_req, res) => res.json({ ok: true, ts: Date.now() }));

app.get('/healthz/deep', async (_req, res) => {
    const checks = {
        sqlite: { ok: false },
        redis: { ok: false }
    };

    try {
        await getDb();
        checks.sqlite = { ok: true };
    } catch (err) {
        checks.sqlite = { ok: false, error: err.message };
    }

    if (!redis) {
        checks.redis = { ok: true, skipped: true, reason: 'disabled' };
    } else {
        try {
            const pong = await Promise.race([
                redis.ping(),
                new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 750))
            ]);
            checks.redis = { ok: pong === 'PONG' };
        } catch (err) {
            checks.redis = { ok: false, error: err.message };
        }
    }

    const ok = checks.sqlite.ok && checks.redis.ok;
    const body = {
        ok,
        ts: Date.now(),
        uptimeSec: Math.floor(process.uptime()),
        checks,
        anomalies: getAnomalyStats()
    };

    return res.status(ok ? 200 : 503).json(body);
});

// 404 handler
app.use((_req, res) => res.status(404).json({ error: 'not found' }));

// Global error handler — never leak stack traces
app.use((err, _req, res, _next) => {
    console.error('[auth-server] unhandled error:', err.message);
    res.status(500).json({ error: 'internal server error' });
});

if (require.main === module) {
    const server = app.listen(port, () => {
        console.log(`auth-server listening on :${port}`);
    });

    const shutdown = (signal) => {
        console.log(`[auth-server] graceful shutdown on ${signal}`);

        if (redis && typeof redis.disconnect === 'function') {
            try { redis.disconnect(false); } catch { /* noop */ }
        }

        server.close(() => {
            console.log('[auth-server] server closed');
            process.exit(0);
        });

        const killTimer = setTimeout(() => process.exit(1), 5000);
        if (killTimer.unref) killTimer.unref();
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
}

module.exports = { app };
