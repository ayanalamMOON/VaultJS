'use strict';

const { buildFingerprint } = require('../../crypto-core/src/fingerprint');

function buildClientFingerprint(ctx = {}) {
  return buildFingerprint(ctx);
}

module.exports = { buildClientFingerprint };
