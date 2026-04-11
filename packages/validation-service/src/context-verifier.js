'use strict';

const { buildFingerprint, normalizeIpPrefix } = require('../../crypto-core/src/fingerprint');
const { hashContextSummary } = require('../../token-engine/src/token-factory');

/**
 * Verify that the runtime request context matches the context that was bound
 * into the token at mint time. This is the "Width" dimension — a stolen token
 * used from a different browser, device, or network will fail here.
 *
 * @param {object} innerPayload    - Decrypted inner token payload
 * @param {object} requestContext  - Runtime request context
 * @returns {boolean}
 */
function verifyContext(innerPayload, requestContext) {
  const expected = buildFingerprint(requestContext);
  return expected === innerPayload.fp;
}

/**
 * Verify the context summary hash (ua + ip + tz + webgl composite).
 * This is a second, independent check on top of the fingerprint.
 *
 * @param {object} innerPayload
 * @param {object} requestContext
 * @returns {boolean}
 */
function verifyContextSummary(innerPayload, requestContext) {
  const expected = hashContextSummary(requestContext);
  return expected === innerPayload.ctx;
}

/**
 * Verify that the IP prefix (first two octets for IPv4, first four groups for
 * IPv6) has not changed since the token was minted. This catches cross-network
 * token theft while tolerating natural IP changes within the same /16.
 *
 * @param {string} mintIp    - IP at token mint time
 * @param {string} currentIp - IP on the current request
 * @returns {boolean}
 */
function verifyIpPrefix(mintIp, currentIp) {
  return normalizeIpPrefix(mintIp) === normalizeIpPrefix(currentIp);
}

module.exports = { verifyContext, verifyContextSummary, verifyIpPrefix };
