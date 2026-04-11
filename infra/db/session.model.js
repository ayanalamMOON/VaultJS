'use strict';

const { runAsync, getAsync } = require('./connection');

async function setSession(sessionId, payload) {
  await runAsync(`
    INSERT INTO sessions (sessionId, payload, updatedAt)
    VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(sessionId) DO UPDATE SET 
      payload=excluded.payload,
      updatedAt=CURRENT_TIMESTAMP
  `, [sessionId, JSON.stringify(payload)]);
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

module.exports = { setSession, getSession, deleteSession };
