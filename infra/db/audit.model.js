'use strict';

const logs = [];

function addAuditEvent(event) {
  logs.push({ id: logs.length + 1, at: new Date().toISOString(), ...event });
}

function listAuditEvents(limit = 100) {
  return logs.slice(-limit).reverse();
}

module.exports = { addAuditEvent, listAuditEvents };
