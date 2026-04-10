'use strict';

const { issueToken } = require('./token-factory');

function refreshToken({ validatedPayload, context, masterSecret, hmacKey }) {
  return issueToken({
    uid: validatedPayload.uid,
    sessionId: validatedPayload.sid,
    context,
    previousRotation: validatedPayload.rot,
    masterSecret,
    hmacKey
  });
}

module.exports = {
  refreshToken
};
