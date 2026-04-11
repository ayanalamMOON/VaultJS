'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');
const { createRedisClient } = require('../../../infra/redis/client');
const { authRoutes } = require('./routes/auth.routes');
const { sessionRoutes } = require('./routes/session.routes');
const { rateLimiter } = require('./middleware/rate-limiter');
const { ipIntel } = require('./middleware/ip-intel');
const { validateTokenMiddleware } = require('./middleware/validate-token');

const app = express();
const port = Number(process.env.PORT || 3001);
const masterSecret = process.env.MASTER_SECRET || 'dev_master_secret_change_me';
const hmacKey = process.env.HMAC_KEY || 'dev_hmac_key_change_me';
const redis = createRedisClient();

// ── Global middleware ────────────────────────────────────────────────────────
app.set('trust proxy', 1); // Trust first proxy (nginx / load balancer)
app.use(express.json({ limit: '64kb' }));
app.use(cookieParser());
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

// Health check — no auth required
app.get('/healthz', (_req, res) => res.json({ ok: true, ts: Date.now() }));

// 404 handler
app.use((_req, res) => res.status(404).json({ error: 'not found' }));

// Global error handler — never leak stack traces
app.use((err, _req, res, _next) => {
  console.error('[auth-server] unhandled error:', err.message);
  res.status(500).json({ error: 'internal server error' });
});

if (require.main === module) {
  app.listen(port, () => {
    console.log(`auth-server listening on :${port}`);
  });
}

module.exports = { app };
