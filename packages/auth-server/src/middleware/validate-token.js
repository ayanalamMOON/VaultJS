'use strict';

const { validateSession, refreshSession, COOKIE_NAME } = require('../session-manager');
const { logAnomaly } = require('../anomaly-detector');

function buildContext(req) {
  return {
    userAgent: req.headers['user-agent'],
    timeZone: req.headers['x-timezone'],
    colorDepth: req.headers['x-color-depth'],
    pixelDepth: req.headers['x-pixel-depth'],
    webglRenderer: req.headers['x-webgl-renderer'],
    ip: req.security?.clientIp || req.ip
  };
}

function shouldRefreshToken(payload, nowSec = Math.floor(Date.now() / 1000)) {
  const remaining = (payload.exp || 0) - nowSec;
  return remaining < 240;
}

function validateTokenMiddleware({ masterSecret, hmacKey, redis = null }) {
  return async (req, res, next) => {
    try {
      const token = req.cookies[COOKIE_NAME] || req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: 'missing token' });

      const context = buildContext(req);
      const validated = await validateSession({ token, context, masterSecret, hmacKey, redis });
      req.auth = validated;

      if (shouldRefreshToken(validated)) {
        const refreshed = await refreshSession({
          validatedPayload: validated,
          context,
          masterSecret,
          hmacKey
        });
        res.cookie(COOKIE_NAME, refreshed.token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict'
        });
      }

      res.setHeader('x-vault-rotation', String(validated.rot));
      return next();
    } catch (err) {
      logAnomaly('token_validation_failure', { message: err.message, ip: req.security?.clientIp || req.ip });
      return res.status(401).json({ error: 'invalid session' });
    }
  };
}

module.exports = { validateTokenMiddleware, buildContext, shouldRefreshToken };
