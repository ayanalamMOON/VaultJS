'use strict';

const express = require('express');
const { validateRegister } = require('../validators/register.schema');
const { validateLogin } = require('../validators/login.schema');
const { registerUser, verifyLogin } = require('../password-manager');
const { createSession, revokeSession, revokeAllUserSessions, COOKIE_NAME } = require('../session-manager');
const { issueChallenge, verifyChallenge } = require('../pow-challenge');
const { buildContext } = require('../middleware/validate-token');
const { logAnomaly } = require('../anomaly-detector');

// Number of failed attempts before PoW is required
const POW_THRESHOLD = 3;
// Lock out repeated failures beyond this count (PoW must succeed every time)
const HARD_LIMIT = 20;
// TTL for the in-process failure counter (10 min sliding window)
const FAILURE_WINDOW_MS = 10 * 60 * 1000;

/**
 * Set the vault session cookie with consistent secure defaults.
 * @param {import('express').Response} res
 * @param {string} token
 */
function setSessionCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 720 * 1000 // slightly longer than TOKEN_TTL_SECONDS to support silent refresh
  });
}

/**
 * Build auth routes factory. Injects masterSecret, hmacKey and optionally redis
 * so routes are fully testable without relying on process.env at call time.
 *
 * @param {object} opts
 * @param {string} opts.masterSecret
 * @param {string} opts.hmacKey
 * @param {import('ioredis').Redis|null} [opts.redis]
 * @returns {import('express').Router}
 */
function authRoutes({ masterSecret, hmacKey, redis = null }) {
  const router = express.Router();

  // Sliding-window failure counters: key -> { count, windowEnd }
  const failures = new Map();

  // Evict stale failure windows every 5 minutes
  const evictTimer = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of failures) {
      if (v.windowEnd <= now) failures.delete(k);
    }
  }, 5 * 60 * 1000);
  if (evictTimer.unref) evictTimer.unref();

  /**
   * Get the current failure count for a key, resetting it if the window has passed.
   */
  function getFailCount(key) {
    const now = Date.now();
    const item = failures.get(key);
    if (!item || item.windowEnd <= now) return 0;
    return item.count;
  }

  function incFailCount(key) {
    const now = Date.now();
    const item = failures.get(key);
    if (!item || item.windowEnd <= now) {
      failures.set(key, { count: 1, windowEnd: now + FAILURE_WINDOW_MS });
    } else {
      item.count += 1;
    }
  }

  function resetFailCount(key) {
    failures.delete(key);
  }

  // ── POST /auth/register ──────────────────────────────────────────────────
  router.post('/register', async (req, res) => {
    const { valid, errors } = validateRegister(req.body);
    if (!valid) return res.status(400).json({ errors });

    try {
      const user = await registerUser({
        username: req.body.username,
        password: req.body.password
      });
      return res.status(201).json({ ok: true, username: user.username });
    } catch (err) {
      if (err.code === 'DUPLICATE_USER') {
        // Return 409 but do NOT confirm whether the username exists to
        // external observers — use a generic message on purpose
        return res.status(409).json({ error: 'registration failed' });
      }
      logAnomaly('register_error', { ip: req.security?.clientIp || req.ip, message: err.message });
      return res.status(500).json({ error: 'registration failed' });
    }
  });

  // ── POST /auth/login ─────────────────────────────────────────────────────
  router.post('/login', async (req, res) => {
    const { valid, errors } = validateLogin(req.body);
    if (!valid) return res.status(400).json({ errors });

    const ip = req.security?.clientIp || req.ip || 'unknown';
    const key = `${String(req.body.username).toLowerCase()}:${ip}`;
    const failCount = getFailCount(key);

    // Hard ceiling — return 429 to slow down sustained brute-force even if PoW passes
    if (failCount >= HARD_LIMIT) {
      logAnomaly('login_hard_limit', { ip, uid: req.body.username, count: failCount });
      return res.status(429).json({ error: 'too many failed attempts — try again later' });
    }

    // Require PoW after POW_THRESHOLD consecutive failures
    if (failCount >= POW_THRESHOLD) {
      const nonce = req.body.powNonce;
      if (!verifyChallenge(key, nonce)) {
        const challenge = issueChallenge(key, failCount);
        logAnomaly('login_pow_required', { ip, uid: req.body.username, count: failCount });
        return res.status(403).json({ error: 'pow_required', challenge });
      }
    }

    try {
      const user = await verifyLogin({
        username: req.body.username,
        clientPreHash: req.body.clientPreHash
      });

      if (!user) {
        incFailCount(key);
        logAnomaly('login_failed', { ip, uid: req.body.username, count: getFailCount(key) });
        // Constant response regardless of whether user exists
        return res.status(401).json({ error: 'invalid credentials' });
      }

      resetFailCount(key);
      const context = buildContext(req);
      const issued = await createSession({ uid: user.id, context, masterSecret, hmacKey, redis });
      setSessionCookie(res, issued.token);
      return res.json({ ok: true, token: issued.token });
    } catch (err) {
      logAnomaly('login_error', { ip, message: err.message });
      return res.status(500).json({ error: 'login failed' });
    }
  });

  // ── POST /auth/logout ────────────────────────────────────────────────────
  router.post('/logout', async (req, res) => {
    // Best-effort revocation — even if the cookie is missing we clear it
    const token = req.cookies?.[COOKIE_NAME];
    if (token && req.auth) {
      try {
        await revokeSession(req.auth.sid, req.auth.uid, redis);
      } catch {
        // Non-fatal — cookie will expire naturally
      }
    }
    res.clearCookie(COOKIE_NAME, { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' });
    return res.json({ ok: true });
  });

  // ── POST /auth/logout-all ────────────────────────────────────────────────
  // Revoke every active session for the authenticated user (requires a valid token)
  router.post('/logout-all', async (req, res) => {
    if (!req.auth?.uid) return res.status(401).json({ error: 'not authenticated' });
    try {
      await revokeAllUserSessions(req.auth.uid, redis);
    } catch (err) {
      logAnomaly('logout_all_error', { ip: req.security?.clientIp || req.ip, uid: req.auth.uid, message: err.message });
    }
    res.clearCookie(COOKIE_NAME, { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' });
    return res.json({ ok: true });
  });

  return router;
}

module.exports = { authRoutes };
