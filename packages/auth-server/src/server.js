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

app.use(express.json());
app.use(cookieParser());
app.use(rateLimiter());
app.use(ipIntel);

app.use('/auth', authRoutes({ masterSecret, hmacKey, redis }));
app.use('/session', validateTokenMiddleware({ masterSecret, hmacKey, redis }), sessionRoutes());

app.get('/healthz', (_req, res) => res.json({ ok: true }));

if (require.main === module) {
  app.listen(port, () => {
    console.log(`auth-server listening on :${port}`);
  });
}

module.exports = { app };
