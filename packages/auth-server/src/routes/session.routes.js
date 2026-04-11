'use strict';

const express = require('express');
const { validateTokenMiddleware } = require('../middleware/validate-token');
const { revokeSession, COOKIE_NAME } = require('../session-manager');
const { logAnomaly } = require('../anomaly-detector');

/**
 * Session routes — all require a valid VaultJS token (enforced by
 * validateTokenMiddleware mounted in server.js before this router).
 *
 * @returns {import('express').Router}
 */
function sessionRoutes({ masterSecret, hmacKey, redis = null } = {}) {
  const router = express.Router();

  // ── GET /session/me ──────────────────────────────────────────────────────
  // Return the public fields from the validated session payload.
  router.get('/me', (req, res) => {
    const { uid, sid, rot, epoch, risk, iat, exp } = req.auth;
    return res.json({
      userId: uid,
      sessionId: sid,
      rotation: rot,
      epoch,
      risk,
      issuedAt: iat,
      expiresAt: exp
    });
  });

  // ── DELETE /session ──────────────────────────────────────────────────────
  // Revoke the current session. Mirrors POST /auth/logout for REST clients
  // that prefer a DELETE verb.
  router.delete('/', async (req, res) => {
    try {
      await revokeSession(req.auth.sid, req.auth.uid, redis);
    } catch (err) {
      logAnomaly('session_delete_error', {
        ip: req.security?.clientIp || req.ip,
        uid: req.auth?.uid,
        message: err.message
      });
    }
    res.clearCookie(COOKIE_NAME, {
      httpOnly: true,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production'
    });
    return res.json({ ok: true });
  });

  // ── GET /session/status ──────────────────────────────────────────────────
  // Lightweight liveness check for authenticated clients. Returns the token
  // TTL remaining in seconds so the client-sdk can calibrate its refresh timer.
  router.get('/status', (req, res) => {
    const nowSec = Math.floor(Date.now() / 1000);
    const ttlRemaining = Math.max(0, (req.auth.exp || 0) - nowSec);
    return res.json({
      ok: true,
      ttlRemaining,
      rotation: req.auth.rot
    });
  });

  return router;
}

module.exports = { sessionRoutes };
