'use strict';

const EventEmitter = require('events');
const { addAuditEvent } = require('../../../infra/db/audit.model');

// Event bus for real-time anomaly subscribers (e.g. SIEM adapters)
const anomalyBus = new EventEmitter();
anomalyBus.setMaxListeners(20);

// Per-key occurrence counters with TTL-based expiry windows
// Structure: key -> { count: number, windowEnd: number }
const counters = new Map();

// Sliding window duration: anomalies counted within this window
const WINDOW_MS = 10 * 60 * 1000; // 10 minutes

// Evict expired counter windows every 5 minutes
const EVICT_INTERVAL_MS = 5 * 60 * 1000;
const evictTimer = setInterval(() => {
  const now = Date.now();
  for (const [k, v] of counters) {
    if (v.windowEnd <= now) counters.delete(k);
  }
}, EVICT_INTERVAL_MS);
if (evictTimer.unref) evictTimer.unref();

/**
 * Build a composite key for tracking anomalies per (type, ip, uid) tuple.
 * @param {string} type
 * @param {object} details
 * @returns {string}
 */
function keyFor(type, details) {
  return `${type}:${details?.ip || 'unknown'}:${details?.uid || 'anon'}`;
}

/**
 * Map an occurrence count to a severity label.
 * @param {number} count
 * @returns {'low'|'medium'|'high'|'critical'}
 */
function severityFromCount(count) {
  if (count >= 10) return 'critical';
  if (count >= 5) return 'high';
  if (count >= 2) return 'medium';
  return 'low';
}

/**
 * Record an anomaly event. Increments the counter for the (type, ip, uid) tuple,
 * persists it to the audit log, and emits to any registered anomaly listeners.
 *
 * @param {string} type     - Machine-readable anomaly type, e.g. 'token_validation_failure'
 * @param {object} details  - Extra context: { ip, uid, message, ... }
 * @returns {object}        - The anomaly event that was recorded
 */
function logAnomaly(type, details = {}) {
  const key = keyFor(type, details);
  const now = Date.now();
  const existing = counters.get(key);

  let count;
  if (!existing || existing.windowEnd <= now) {
    count = 1;
    counters.set(key, { count, windowEnd: now + WINDOW_MS });
  } else {
    count = existing.count + 1;
    counters.set(key, { count, windowEnd: existing.windowEnd });
  }

  const severity = severityFromCount(count);
  const event = {
    type,
    details: { ...details, count },
    severity,
    at: new Date().toISOString()
  };

  // Persist to audit log (non-blocking, fire-and-forget)
  try {
    addAuditEvent(event);
  } catch {
    // Never let audit logging crash the request path
  }

  anomalyBus.emit('anomaly', event);
  return event;
}

/**
 * Subscribe to anomaly events.
 * Returns an unsubscribe function for clean teardown.
 *
 * @param {function} listener
 * @returns {function} unsubscribe
 */
function onAnomaly(listener) {
  anomalyBus.on('anomaly', listener);
  return () => anomalyBus.off('anomaly', listener);
}

module.exports = { logAnomaly, onAnomaly };
