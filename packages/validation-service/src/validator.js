'use strict';

const { validateToken } = require('../../token-engine/src/token-validator');
const { verifyContext } = require('./context-verifier');
const { decideValidation } = require('./decision-engine');
const { auditValidation } = require('./audit-logger');

async function runValidation({ token, requestContext, masterSecret, hmacKey, redis = null }) {
  let validated;
  try {
    validated = await validateToken({ token, context: requestContext, masterSecret, hmacKey, redis });
  } catch (err) {
    const denied = decideValidation({ signatureValid: false, decryptionValid: false, contextValid: false, replayValid: false });
    auditValidation({ allow: denied.allow, reason: err.message, context: requestContext });
    return { ...denied, payload: null };
  }

  const contextValid = verifyContext(validated, requestContext);
  const decision = decideValidation({
    signatureValid: true,
    decryptionValid: true,
    contextValid,
    replayValid: true
  });

  auditValidation({ allow: decision.allow, reason: decision.reason, score: decision.score, sid: validated.sid });
  return { ...decision, payload: decision.allow ? validated : null };
}

module.exports = { runValidation };
