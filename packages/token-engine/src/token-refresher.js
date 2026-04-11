'use strict';

const { issueToken } = require('./token-factory');

/**
 * Issue a fresh token from an already-validated payload.
 * Increments the rotation counter; all other context bindings are re-derived
 * from the live request context so fingerprint/risk claims stay current.
 *
 * @param {object}  opts
 * @param {object}  opts.validatedPayload  - Output of validateToken()
 * @param {object}  opts.context           - Live request context
 * @param {string}  opts.masterSecret
 * @param {string}  opts.hmacKey
 * @returns {{ token: string, inner: object, aad: string }}
 */
function refreshToken({ validatedPayload, context, masterSecret, hmacKey }) {
  if (!validatedPayload?.uid) throw new Error('validatedPayload.uid is required');
  if (!validatedPayload?.sid) throw new Error('validatedPayload.sid is required');

  return issueToken({
    uid: validatedPayload.uid,
    sessionId: validatedPayload.sid,
    context,
    previousRotation: validatedPayload.rot,
    masterSecret,
    hmacKey
  });
}

module.exports = { refreshToken };
