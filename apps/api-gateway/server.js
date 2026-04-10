'use strict';

const express = require('express');
const { validateTokenMiddleware } = require('../../packages/auth-server/src/middleware/validate-token');

const app = express();
const port = Number(process.env.GATEWAY_PORT || 4000);

app.use(express.json());
app.use(validateTokenMiddleware({
  masterSecret: process.env.MASTER_SECRET || 'dev_master_secret_change_me',
  hmacKey: process.env.HMAC_KEY || 'dev_hmac_key_change_me'
}));

app.get('/api/data', (req, res) => {
  res.json({ message: 'secure data', user: req.auth.uid });
});

if (require.main === module) {
  app.listen(port, () => console.log(`api-gateway listening on ${port}`));
}

module.exports = { app };
