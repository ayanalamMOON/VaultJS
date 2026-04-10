'use strict';

const express = require('express');
const { validateRegister } = require('../validators/register.schema');
const { validateLogin } = require('../validators/login.schema');
const { registerUser, verifyLogin } = require('../password-manager');
const { createSession, COOKIE_NAME } = require('../session-manager');
const { issueChallenge, verifyChallenge } = require('../pow-challenge');
const { buildContext } = require('../middleware/validate-token');

function authRoutes({ masterSecret, hmacKey, redis = null }) {
  const router = express.Router();
  const failures = new Map();

  router.post('/register', async (req, res) => {
    const { valid, errors } = validateRegister(req.body);
    if (!valid) return res.status(400).json({ errors });

    await registerUser({ username: req.body.username, password: req.body.password });
    return res.status(201).json({ ok: true });
  });

  router.post('/login', async (req, res) => {
    const { valid, errors } = validateLogin(req.body);
    if (!valid) return res.status(400).json({ errors });

    const key = `${req.body.username}:${req.ip}`;
    const failCount = failures.get(key) || 0;

    if (failCount >= 3) {
      const nonce = req.body.powNonce;
      if (!verifyChallenge(key, nonce)) {
        return res.status(403).json({ error: 'pow required', challenge: issueChallenge(key, failCount) });
      }
    }

    const user = await verifyLogin({ username: req.body.username, clientPreHash: req.body.clientPreHash });
    if (!user) {
      failures.set(key, failCount + 1);
      return res.status(401).json({ error: 'invalid credentials' });
    }

    failures.delete(key);
    const issued = await createSession({ uid: user.id, context: buildContext(req), masterSecret, hmacKey, redis });
    res.cookie(COOKIE_NAME, issued.token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' });
    return res.json({ ok: true, token: issued.token });
  });

  return router;
}

module.exports = { authRoutes };
