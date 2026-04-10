'use strict';

const express = require('express');

const app = express();
const port = Number(process.env.DEMO_PORT || 4100);

app.get('/', (_req, res) => {
  res.send('VaultJS demo app running. Use client-sdk to authenticate against auth-server.');
});

if (require.main === module) {
  app.listen(port, () => console.log(`demo-app listening on ${port}`));
}

module.exports = { app };
