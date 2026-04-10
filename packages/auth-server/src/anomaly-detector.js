'use strict';

const EventEmitter = require('events');
const { addAuditEvent } = require('../../../infra/db/audit.model');

const anomalyBus = new EventEmitter();
const counters = new Map();

function keyFor(type, details) {
  return `${type}:${details?.ip || 'unknown'}:${details?.uid || 'anon'}`;
}

function severityFromCount(count) {
  if (count >= 10) return 'critical';
  if (count >= 5) return 'high';
  if (count >= 2) return 'medium';
  return 'low';
}

function logAnomaly(type, details = {}) {
  const key = keyFor(type, details);
  const count = (counters.get(key) || 0) + 1;
  counters.set(key, count);
  const severity = severityFromCount(count);

  const event = { type, details: { ...details, count }, severity };
  addAuditEvent(event);
  anomalyBus.emit('anomaly', event);
  return event;
}

function onAnomaly(listener) {
  anomalyBus.on('anomaly', listener);
  return () => anomalyBus.off('anomaly', listener);
}

module.exports = { logAnomaly, onAnomaly };
