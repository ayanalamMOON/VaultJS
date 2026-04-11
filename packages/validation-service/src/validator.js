'use strict';

const { validateToken } = require('../../token-engine/src/token-validator');
const { verifyContext, verifyContextSummary } = require('./context-verifier');
const { decideValidation } = require('./decision-engine');
const { auditValidation } = require('./audit-logger');

let _wasmEnginePromise = null;

async function getWasmEngine() {
  if (_wasmEnginePromise) return _wasmEnginePromise;

  _wasmEnginePromise = (async () => {
    try {
      const fs = require('fs');
      const path = require('path');
      const wasmPath = path.join(__dirname, 'validation-engine.wasm');
      
      // Async stat check
      await fs.promises.access(wasmPath, fs.constants.R_OK);
      
      const wasmBuffer = await fs.promises.readFile(wasmPath);
      // For Node < 16 WebAssembly.instantiate is preferred over new Module
      const { instance } = await WebAssembly.instantiate(wasmBuffer, {});
      return instance.exports;
    } catch (e) {
      // Silently fallback to pure NodeJS crypto algorithms
      return null;
    }
  })();

  return _wasmEnginePromise;
}

/**
 * Run the full validation pipeline — the isolated validation service described
 * in the 4D architecture. This module has NO direct DB access; it operates
 * purely on the token + request context and produces a structured verdict.
 *
 * Pipeline:
 *   1. HMAC envelope verification
 *   2. Epoch-keyed AES-GCM decryption (tries current + grace epochs)
 *   3. Temporal claims validation
 *   4. Risk-score drift check
 *   5. Fingerprint binding (Width dimension)
 *   6. Context summary binding
 *   7. Rotation anti-replay
 *   8. JTI anti-replay
 *   9. Decision engine scoring (40/30/20/10 weighted signals)
 *   10. Audit trail recording
 *
 * @param {object}  opts
 * @param {string}  opts.token           - Raw vault token string
 * @param {object}  opts.requestContext  - Runtime request context
 * @param {string}  opts.masterSecret    - Master key material
 * @param {string}  opts.hmacKey         - HMAC signing key
 * @param {import('ioredis').Redis|null} [opts.redis]
 * @returns {Promise<{ allow: boolean, reason: string, score: number, payload: object|null }>}
 */
async function runValidation({ token, requestContext, masterSecret, hmacKey, redis = null }) {
  let validated;

  // Steps 1–8 are performed by validateToken. If any step throws, the token
  // is rejected. We catch the error to produce a structured denial.
  try {
    // Route to WASM if available, else fallback to JS
    const wasmEngine = await getWasmEngine();
    if (wasmEngine && typeof wasmEngine.validateToken === 'function') {
      // Stub for future Rust WASM payload interop
      // validated = wasmEngine.validateToken({ token, context: requestContext, masterSecret, hmacKey });
    }

    if (!validated) {
      validated = await validateToken({
        token,
        context: requestContext,
        masterSecret,
        hmacKey,
        redis
      });
    }
  } catch (err) {
    // Classify which signal failed based on the error message
    const signals = classifyError(err.message);
    const denied = decideValidation(signals);

    auditValidation({
      allow: false,
      reason: err.message,
      score: denied.score,
      context: requestContext
    });

    return { ...denied, payload: null };
  }

  // Steps 9–10: run the decision engine on the successfully-validated payload.
  // We re-verify context here as an independent second check.
  const contextValid = verifyContext(validated, requestContext);
  const contextSummaryValid = verifyContextSummary(validated, requestContext);

  const decision = decideValidation({
    signatureValid: true,
    decryptionValid: true,
    contextValid: contextValid && contextSummaryValid,
    replayValid: true
  });

  auditValidation({
    allow: decision.allow,
    reason: decision.reason,
    score: decision.score,
    sid: validated.sid,
    uid: validated.uid
  });

  return {
    ...decision,
    payload: decision.allow ? validated : null
  };
}

/**
 * Map a validateToken error message to the set of signals that failed.
 * This allows the decision engine to produce accurate scoring even on errors.
 *
 * @param {string} message
 * @returns {object} signals
 */
function classifyError(message) {
  const msg = String(message).toLowerCase();

  if (msg.includes('signature') || msg.includes('malformed')) {
    return { signatureValid: false, decryptionValid: false, contextValid: false, replayValid: false };
  }
  if (msg.includes('decrypt')) {
    return { signatureValid: true, decryptionValid: false, contextValid: false, replayValid: false };
  }
  if (msg.includes('fingerprint') || msg.includes('context')) {
    return { signatureValid: true, decryptionValid: true, contextValid: false, replayValid: true };
  }
  if (msg.includes('replay') || msg.includes('rotation') || msg.includes('stale') || msg.includes('jti')) {
    return { signatureValid: true, decryptionValid: true, contextValid: true, replayValid: false };
  }
  if (msg.includes('expired') || msg.includes('future') || msg.includes('temporal')) {
    return { signatureValid: true, decryptionValid: true, contextValid: false, replayValid: false };
  }
  if (msg.includes('risk') || msg.includes('risky') || msg.includes('drift')) {
    return { signatureValid: true, decryptionValid: true, contextValid: false, replayValid: true };
  }

  // Unknown error — assume total failure
  return { signatureValid: false, decryptionValid: false, contextValid: false, replayValid: false };
}

module.exports = { runValidation, classifyError };
