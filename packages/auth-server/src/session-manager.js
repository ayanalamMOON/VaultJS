'use strict';

const crypto = require('crypto');
const { setSession, getSession, deleteSession } = require('../../../infra/db/session.model');
const { setTokenState, getTokenState } = require('../../../infra/redis/token-store');
const { issueToken, validateToken, refreshToken } = require('../../token-engine/src');
const { COOKIE_NAME } = require('../../crypto-core/src/constants');

function newSessionId() {
  return crypto.randomUUID();
}

async function createSession({ uid, context, masterSecret, hmacKey, redis = null }) {
  const sessionId = newSessionId();
  const issued = issueToken({ uid, sessionId, context, masterSecret, hmacKey });
  setSession(sessionId, { uid, rot: issued.inner.rot, createdAt: Date.now() });
  await setTokenState(sessionId, { rot: issued.inner.rot, jti: issued.inner.jti }, 600, redis);
  return issued;
}

async function validateSession({ token, context, masterSecret, hmacKey, redis = null }) {
  const validated = await validateToken({ token, context, masterSecret, hmacKey, redis });
  const session = getSession(validated.sid);
  if (!session) throw new Error('session not found');

  const state = await getTokenState(validated.sid, redis);
  if (!state) throw new Error('session state missing');
  if (validated.rot < state.rot) throw new Error('stale rotation');

  return validated;
}

async function refreshSession({ validatedPayload, context, masterSecret, hmacKey, redis = null }) {
  const refreshed = refreshToken({ validatedPayload, context, masterSecret, hmacKey });
  setSession(validatedPayload.sid, { uid: validatedPayload.uid, rot: refreshed.inner.rot });
  await setTokenState(validatedPayload.sid, { rot: refreshed.inner.rot, jti: refreshed.inner.jti }, 600, redis);
  return refreshed;
}

function revokeSession(sessionId) {
  deleteSession(sessionId);
}

module.exports = { COOKIE_NAME, createSession, validateSession, refreshSession, revokeSession };
