'use strict';

const sessions = new Map();

function setSession(sessionId, payload) {
  sessions.set(sessionId, { ...payload, updatedAt: Date.now() });
}

function getSession(sessionId) {
  return sessions.get(sessionId) || null;
}

function deleteSession(sessionId) {
  sessions.delete(sessionId);
}

module.exports = { setSession, getSession, deleteSession };
