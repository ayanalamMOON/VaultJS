'use strict';

const crypto = require('crypto');
const { setSession, getSession, deleteSession, listSessions, revokeSession: dbRevokeSession } = require('../../../infra/db/session.model');
const { setTokenState, getTokenState } = require('../../../infra/redis/token-store');
const { issueToken, validateToken, refreshToken } = require('../../token-engine/src');
const { COOKIE_NAME } = require('../../crypto-core/src/constants');
const { logAnomaly } = require('./anomaly-detector');
const promMetrics = require('./prom-metrics');

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
async function enforceSessionCeiling(uid) {
    const set = userSessions.get(uid);
    if (!set || set.size < MAX_SESSIONS_PER_USER) return;

    // Find the oldest session for this user and evict it
    let oldestId = null;
    let oldestTs = Infinity;
    for (const sid of set) {
        const s = await getSession(sid);
        const created = s?.payload?.createdAt || s?.payload?.created || null;
        const ts = typeof created === 'number' ? created : Number(created) || Infinity;
        if (ts && ts < oldestTs) {
            oldestTs = ts;
            oldestId = sid;
        }
    }
    if (oldestId) {
        // Prefer revoking to ensure durable state
        try {
            await dbRevokeSession(oldestId, new Date().toISOString());
        } catch (e) { }
        set.delete(oldestId);
        try { promMetrics.incSession('evicted', 1); } catch (e) { }
        logAnomaly('session_ceiling_eviction', { uid, evictedSid: oldestId });
        try { promMetrics.setActiveSessions([...userSessions.values()].reduce((acc, s) => acc + s.size, 0)); } catch (e) { }
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
    try { promMetrics.setActiveSessions([...userSessions.values()].reduce((acc, s) => acc + s.size, 0)); } catch (e) { }
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
    await enforceSessionCeiling(uid);

    const sessionId = newSessionId();
    const issued = issueToken({ uid, sessionId, context, masterSecret, hmacKey });

    await setSession(sessionId, {
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
    try { promMetrics.incSession('created', 1); } catch (e) { }
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

    const session = await getSession(validated.sid);
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
    await setSession(validatedPayload.sid, {
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
    try { promMetrics.incSession('refreshed', 1); } catch (e) { }
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
    // Mark durable revocation in DB
    try {
        await dbRevokeSession(sessionId, new Date().toISOString());
    } catch (e) { }

    try { promMetrics.incSession('revoked', 1); } catch (e) { }

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
    try { promMetrics.setActiveSessions([...userSessions.values()].reduce((acc, s) => acc + s.size, 0)); } catch (e) { }
}

/**
 * Revoke ALL sessions belonging to a user (useful for password change / account compromise).
 *
 * @param {string} uid
 * @param {import('ioredis').Redis|null} [redis]
 */
async function revokeAllUserSessions(uid, redis = null) {
    // Try durable path first: revoke all sessions stored for this uid
    try {
        const rows = await listSessions({ uid, limit: 10000, offset: 0, activeOnly: false });
        for (const r of rows) {
            try { await dbRevokeSession(r.sessionId, new Date().toISOString()); } catch (e) { }
            try { await revokeSession(r.sessionId, uid, redis); } catch (e) { }
        }
    } catch (e) {
        // Fallback to in-memory eviction
        const set = userSessions.get(uid);
        if (set) {
            const ids = [...set];
            await Promise.all(ids.map((sid) => revokeSession(sid, uid, redis)));
        }
    }
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
