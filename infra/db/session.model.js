'use strict';

const { runAsync, getAsync, allAsync } = require('./connection');

async function setSession(sessionId, payload = {}) {
    const uid = payload.uid == null ? null : String(payload.uid).slice(0, 128);
    const revokedAt = payload.revokedAt == null ? null : String(payload.revokedAt);
    const json = JSON.stringify(payload || {});

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
    const row = await getAsync('SELECT sessionId, payload, uid, revokedAt, updatedAt, expiresAt FROM sessions WHERE sessionId = ? LIMIT 1', [sessionId]);
    if (!row) return null;

    let parsed = null;
    try {
        parsed = JSON.parse(row.payload || '{}');
    } catch (e) {
        parsed = {};
    }

    return {
        sessionId: row.sessionId,
        uid: row.uid || parsed.uid || null,
        revokedAt: row.revokedAt || parsed.revokedAt || null,
        updatedAt: row.updatedAt || null,
        expiresAt: row.expiresAt || null,
        payload: parsed
    };
}

async function deleteSession(sessionId) {
    await runAsync('DELETE FROM sessions WHERE sessionId = ?', [sessionId]);
}

async function listSessions({ uid = null, limit = 100, offset = 0, activeOnly = false } = {}) {
    const clauses = [];
    const params = [];

    if (uid) {
        clauses.push('uid = ?');
        params.push(String(uid));
    }

    if (activeOnly) {
        clauses.push('revokedAt IS NULL');
    }

    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = await allAsync(`SELECT sessionId, payload, uid, revokedAt, updatedAt, expiresAt FROM sessions ${where} ORDER BY updatedAt DESC LIMIT ? OFFSET ?`, [...params, Math.max(1, Number(limit) || 100), Math.max(0, Number(offset) || 0)]);

    return rows.map((row) => {
        let parsed = {};
        try { parsed = JSON.parse(row.payload || '{}'); } catch (e) { parsed = {}; }
        return {
            sessionId: row.sessionId,
            uid: row.uid || parsed.uid || null,
            revokedAt: row.revokedAt || parsed.revokedAt || null,
            updatedAt: row.updatedAt || null,
            expiresAt: row.expiresAt || null,
            payload: parsed
        };
    });
}

async function countSessions({ uid = null, activeOnly = false } = {}) {
    const clauses = [];
    const params = [];
    if (uid) { clauses.push('uid = ?'); params.push(String(uid)); }
    if (activeOnly) { clauses.push('revokedAt IS NULL'); }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const row = await getAsync(`SELECT COUNT(*) AS total FROM sessions ${where}`, params);
    return Number(row?.total || 0);
}

async function revokeSession(sessionId, revokedAt = null) {
    const when = revokedAt || new Date().toISOString();
    const existing = await getSession(sessionId);
    if (!existing) return false;
    const payload = existing.payload || {};
    payload.revokedAt = when;
    await runAsync('UPDATE sessions SET payload = ?, revokedAt = ?, updatedAt = CURRENT_TIMESTAMP WHERE sessionId = ?', [JSON.stringify(payload), when, sessionId]);
    return true;
}

module.exports = { setSession, getSession, deleteSession, listSessions, countSessions, revokeSession };
