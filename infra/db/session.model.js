'use strict';

const { runAsync, getAsync, allAsync } = require('./connection');

async function setSession(sessionId, payload) {
    const json = JSON.stringify(payload);
    const uid = (payload && payload.uid) ? payload.uid : null;
    const revokedAt = (payload && payload.revokedAt) ? payload.revokedAt : null;

    await runAsync(`
        INSERT INTO sessions (sessionId, payload, uid, revokedAt, updatedAt)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(sessionId) DO UPDATE SET
            payload=excluded.payload,
            uid=excluded.uid,
            revokedAt=excluded.revokedAt,
            updatedAt=CURRENT_TIMESTAMP
    `, [sessionId, json, uid, revokedAt]);
}

async function getSession(sessionId) {
    const row = await getAsync('SELECT payload FROM sessions WHERE sessionId = ?', [sessionId]);
    if (!row) return null;

    try {
        return JSON.parse(row.payload);
    } catch (e) {
        return null;
    }
}

async function deleteSession(sessionId) {
    await runAsync('DELETE FROM sessions WHERE sessionId = ?', [sessionId]);
}

/**
 * List sessions for a given user id. Returns array of { sessionId, payload }
 * If uid is falsy, returns all sessions.
 */
/**
 * List sessions for a given user id. Supports pagination and active-only filter.
 * @param {object} opts
 * @param {string|null} [opts.uid]
 * @param {number} [opts.limit]
 * @param {number} [opts.offset]
 * @param {boolean} [opts.activeOnly]
 * @returns {Promise<Array<{sessionId:string,payload:object}>>}
 */
async function listSessions({ uid = null, limit = 1000, offset = 0, activeOnly = false } = {}) {
    // Build WHERE clause using indexed columns for efficient filtering.
    const where = [];
    const params = [];
    if (uid) {
        where.push('uid = ?');
        params.push(uid);
    }
    if (activeOnly) {
        where.push('revokedAt IS NULL');
    }
    const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const rows = await allAsync(`SELECT sessionId, payload FROM sessions ${whereClause} ORDER BY updatedAt DESC LIMIT ? OFFSET ?`, [...params, limit, offset]);
    const out = [];
    for (const row of rows || []) {
        try {
            out.push({ sessionId: row.sessionId, payload: JSON.parse(row.payload) });
        } catch {
            // skip malformed
        }
    }
    return out;
}

/**
 * Count sessions matching optional filters. This performs the same filtering
 * as listSessions but returns only the total matching count (useful for
 * pagination metadata).
 *
 * Note: payload is stored as TEXT; we currently load rows and filter in JS to
 * maintain compatibility with plain SQLite builds.
 */
async function countSessions({ uid = null, activeOnly = false } = {}) {
    const where = [];
    const params = [];
    if (uid) {
        where.push('uid = ?');
        params.push(uid);
    }
    if (activeOnly) {
        where.push('revokedAt IS NULL');
    }
    const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const row = await getAsync(`SELECT COUNT(*) as cnt FROM sessions ${whereClause}`, params);
    return row && row.cnt ? Number(row.cnt) : 0;
}

module.exports = { setSession, getSession, deleteSession, listSessions, countSessions };
