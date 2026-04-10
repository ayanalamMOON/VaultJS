'use strict';

const express = require('express');

function sessionRoutes() {
  const router = express.Router();

  router.get('/me', (req, res) => {
    return res.json({ userId: req.auth.uid, sessionId: req.auth.sid, rotation: req.auth.rot });
  });

  return router;
}

module.exports = { sessionRoutes };
