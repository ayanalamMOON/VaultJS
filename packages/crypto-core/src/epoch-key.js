'use strict';

const crypto = require('crypto');
const { EPOCH_SECONDS } = require('./constants');

function currentEpoch(unixSeconds = Math.floor(Date.now() / 1000), windowSeconds = EPOCH_SECONDS) {
  return Math.floor(unixSeconds / windowSeconds);
}

function deriveEpochKey(masterSecret, epoch, info = 'session-aes-key') {
  if (!masterSecret) throw new Error('masterSecret is required');
  return crypto.hkdfSync('sha256', Buffer.from(masterSecret), Buffer.from(String(epoch)), Buffer.from(info), 32);
}

function deriveEpochKeyring(masterSecret, epoch, lookback = 1, lookahead = 0) {
  const ring = [];
  for (let e = epoch - lookback; e <= epoch + lookahead; e += 1) {
    ring.push({ epoch: e, key: deriveEpochKey(masterSecret, e) });
  }
  return ring;
}

module.exports = {
  currentEpoch,
  deriveEpochKey,
  deriveEpochKeyring
};
