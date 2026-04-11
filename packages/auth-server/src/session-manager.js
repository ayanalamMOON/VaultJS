'use strict';

const crypto = require('crypto');
const { setSession, getSession, deleteSession } = require('../../../infra/db/session.model');
const { setTokenState, getTokenState } = require('../../../infra/redis/token-store');
const { issueToken, validateToken, refreshToken } = require('../../token-engine/src');
const { COOKIE_NAME } = require('../../crypto-core/src/constants');
const { logAnomaly } = require('./anomaly-detector');

/** Hard ceiling on how many concurrent sessions a single user may hold. */
const MAX_SESSIONS_PER_USER = 10;

// Track active sessionIds per userId for the in-process store
// uid -> Set<sessionId>
const userSessions = new Map();

function newSessionId() {
  return crypto.randomUUID();
}

/**
 * Enforce the per-user session ceiling. Evicts the oldest session when the
 * limit is reached (LRU eviction by createdAt).
 *
 * @param {string} uid
 */
function enforceSessionCeiling(uid) {
  const set = userSessions.get(uid);
  if (!set || set.size < MAX_SESSIONS_PER_USER) return;

  // Find the oldest session for this user and evict it
  let oldestId = null;
  let oldestTs = Infinity;
  for (const sid of set) {
    const s = getSession(sid);
    if (s && s.createdAt < oldestTs) {
      oldestTs = s.createdAt;
      oldestId = sid;
    }
  }
  if (oldestId) {
    deleteSession(oldestId);
    set.delete(oldestId);
    logAnomaly('session_ceiling_eviction', { uid, evictedSid: oldestId });
  }
}

/**
 * Register a sessionId under the user's active-session index.
 *
 * @param {string} uid
 * @param {string} sessionId
 */
function trackSession(uid, sessionId) {
  if (!userSessions.has(uid)) userSessions.set(uid, new Set());
  userSessions.get(uid).add(sessionId);
}

/**
 * Create a new session for an authenticated user. Issues a new token, stores
 * session state in the DB and in Redis (if available), and enforces the
 * per-user session ceiling.
 *
 * @param {object} opts
 * @param {string} opts.uid
 * @param {object} opts.context
 * @param {string} opts.masterSecret
 * @param {string} opts.hmacKey
 * @param {import('ioredis').Redis|null} [opts.redis]
 * @returns {Promise<{ token: string, inner: object, aad: string }>}
 */
async function createSession({ uid, context, masterSecret, hmacKey, redis = null }) {
  enforceSessionCeiling(uid);

  const sessionId = newSessionId();
  const issued = issueToken({ uid, sessionId, context, masterSecret, hmacKey });

  setSession(sessionId, {
    uid,
    rot: issued.inner.rot,
    createdAt: Date.now()
  });
  await setTokenState(
    sessionId,
    { rot: issued.inner.rot, jti: issued.inner.jti },
    600,
    redis
  );

  trackSession(uid, sessionId);
  return issued;
}

/**
 * Validate an incoming token against its stored session state.
 *
 * @param {object} opts
 * @param {string} opts.token
 * @param {object} opts.context
 * @param {string} opts.masterSecret
 * @param {string} opts.hmacKey
 * @param {import('ioredis').Redis|null} [opts.redis]
 * @returns {Promise<object>} Validated inner payload
 */
async function validateSession({ token, context, masterSecret, hmacKey, redis = null }) {
  const validated = await validateToken({ token, context, masterSecret, hmacKey, redis });

  const session = getSession(validated.sid);
  if (!session) throw new Error('session not found');

  const state = await getTokenState(validated.sid, redis);
  if (!state) throw new Error('session state missing');
  if (validated.rot < state.rot) throw new Error('stale rotation');

  return validated;
}

/**
 * Issue a refreshed token and update stored session state.
 *
 * @param {object} opts
 * @param {object} opts.validatedPayload
 * @param {object} opts.context
 * @param {string} opts.masterSecret
 * @param {string} opts.hmacKey
 * @param {import('ioredis').Redis|null} [opts.redis]
 * @returns {Promise<{ token: string, inner: object, aad: string }>}
 */
async function refreshSession({ validatedPayload, context, masterSecret, hmacKey, redis = null }) {
  const refreshed = refreshToken({ validatedPayload, context, masterSecret, hmacKey });
  setSession(validatedPayload.sid, {
    uid: validatedPayload.uid,
    rot: refreshed.inner.rot,
    updatedAt: Date.now()
  });
  await setTokenState(
    validatedPayload.sid,
    { rot: refreshed.inner.rot, jti: refreshed.inner.jti },
    600,
    redis
  );
  return refreshed;
}

/**
 * Revoke a session by sessionId, cleaning up in-process and Redis state.
 *
 * @param {string} sessionId
 * @param {string} [uid]
 * @param {import('ioredis').Redis|null} [redis]
 */
async function revokeSession(sessionId, uid = null, redis = null) {
  deleteSession(sessionId);

  if (uid) {
    const set = userSessions.get(uid);
    if (set) set.delete(sessionId);
  }

  // Best-effort Redis cleanup — a failure here is non-fatal
  if (redis) {
    try {
      await Promise.all([
        redis.del(`vault:session:${sessionId}`),
        redis.del(`vault:rot:${sessionId}`)
      ]);
    } catch {
      // Non-fatal: key will expire naturally
    }
  }
}

/**
 * Revoke ALL sessions belonging to a user (useful for password change / account compromise).
 *
 * @param {string} uid
 * @param {import('ioredis').Redis|null} [redis]
 */
async function revokeAllUserSessions(uid, redis = null) {
  const set = userSessions.get(uid);
  if (!set) return;
  const ids = [...set];
  await Promise.all(ids.map((sid) => revokeSession(sid, uid, redis)));
  userSessions.delete(uid);
}

module.exports = {
  COOKIE_NAME,
  createSession,
  validateSession,
  refreshSession,
  revokeSession,
  revokeAllUserSessions
};
