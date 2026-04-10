'use strict';

const { addAuditEvent } = require('../../../infra/db/audit.model');

function auditValidation(event) {
  addAuditEvent({ type: 'validation', ...event });
}

module.exports = { auditValidation };
