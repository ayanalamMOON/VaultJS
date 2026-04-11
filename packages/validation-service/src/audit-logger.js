'use strict';

const { addAuditEvent } = require('../../../infra/db/audit.model');

/**
 * Severity levels ordered by urgency, used for downstream log routing
 * (e.g. 'critical' events → real-time PagerDuty alert).
 */
const SEVERITY = Object.freeze({
  INFO: 'info',
  WARN: 'warn',
  DENY: 'deny',
  CRITICAL: 'critical'
});

/**
 * Log a validation event to the audit trail.
 *
 * Every token validation — pass or fail — is recorded. This provides the
 * forensic timeline needed for incident response without impacting request
 * latency (the write to the in-process audit store is synchronous and O(1)).
 *
 * @param {object}  event
 * @param {boolean} event.allow   - Whether the token was accepted
 * @param {string}  event.reason  - Machine-readable reason code
 * @param {number}  [event.score] - Decision engine score (0–100)
 * @param {string}  [event.sid]   - Session ID (if decryption succeeded)
 * @param {string}  [event.uid]   - User ID (if known)
 * @param {object}  [event.context] - Request context snapshot
 */
function auditValidation(event) {
  const severity = !event.allow
    ? (event.reason === 'bad_signature' || event.reason === 'replay_detected'
      ? SEVERITY.CRITICAL
      : SEVERITY.DENY)
    : SEVERITY.INFO;

  const record = {
    type: 'validation',
    severity,
    ...event
  };

  try {
    addAuditEvent(record);
  } catch {
    // Never let audit logging crash the validation pipeline
  }
}

/**
 * Log an access-granted event distinct from the validation decision.
 * Called after the decision engine allows the request, recording the
 * resource that was accessed.
 *
 * @param {object}  event
 * @param {string}  event.uid
 * @param {string}  event.sid
 * @param {string}  event.resource - e.g. 'GET /api/data'
 */
function auditAccess(event) {
  try {
    addAuditEvent({ type: 'access', severity: SEVERITY.INFO, ...event });
  } catch {
    // Non-fatal
  }
}

module.exports = { auditValidation, auditAccess, SEVERITY };
