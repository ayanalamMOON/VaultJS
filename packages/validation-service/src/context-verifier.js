'use strict';

const { buildFingerprint } = require('../../crypto-core/src/fingerprint');

function verifyContext(innerPayload, requestContext) {
  const expected = buildFingerprint(requestContext);
  return expected === innerPayload.fp;
}

module.exports = { verifyContext };
