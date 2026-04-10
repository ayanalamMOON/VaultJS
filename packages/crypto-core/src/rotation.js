'use strict';

const crypto = require('crypto');
const { NONCE_BYTES } = require('./constants');

function nextRotation(previous = 0) {
  return Number.isFinite(previous) ? previous + 1 : 1;
}

function randomNonce() {
  return crypto.randomBytes(NONCE_BYTES).toString('hex');
}

module.exports = {
  nextRotation,
  randomNonce
};
