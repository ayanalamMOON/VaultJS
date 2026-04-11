'use strict';

/**
 * Weight each validation signal. The total adds up to 100.
 *
 *   Signature (HMAC)   40  — outer tamper detection
 *   Decryption (AES)   30  — inner confidentiality + epoch binding
 *   Context (fp + ctx) 20  — width-dimension environment binding
 *   Replay (rot + jti) 10  — time-dimension freshness
 */
const WEIGHTS = Object.freeze({
  signature:  40,
  decryption: 30,
  context:    20,
  replay:     10
});

/** Minimum combined score to accept a request. */
const ACCEPT_THRESHOLD = 90;

/**
 * Score the four validation signals into a 0–100 integer.
 *
 * @param {object}  signals
 * @param {boolean} signals.signatureValid
 * @param {boolean} signals.decryptionValid
 * @param {boolean} signals.contextValid
 * @param {boolean} signals.replayValid
 * @returns {number} 0–100
 */
function scoreSignals({ signatureValid, decryptionValid, contextValid, replayValid }) {
  let score = 0;
  if (signatureValid)  score += WEIGHTS.signature;
  if (decryptionValid) score += WEIGHTS.decryption;
  if (contextValid)    score += WEIGHTS.context;
  if (replayValid)     score += WEIGHTS.replay;
  return score;
}

/**
 * Produce a machine-readable reason code for the first failing signal.
 *
 * @param {object} signals
 * @returns {string}
 */
function failureReason(signals) {
  if (!signals.signatureValid)  return 'bad_signature';
  if (!signals.decryptionValid) return 'decrypt_fail';
  if (!signals.contextValid)    return 'context_mismatch';
  if (!signals.replayValid)     return 'replay_detected';
  return 'ok';
}

/**
 * Run the decision engine: score all signals, compare against the acceptance
 * threshold, and return a structured verdict.
 *
 * @param {object} signals - { signatureValid, decryptionValid, contextValid, replayValid }
 * @returns {{ allow: boolean, reason: string, score: number }}
 */
function decideValidation(signals) {
  const score = scoreSignals(signals);
  const allow = score >= ACCEPT_THRESHOLD;
  const reason = allow ? 'ok' : failureReason(signals);
  return { allow, reason, score };
}

module.exports = { decideValidation, scoreSignals, failureReason, WEIGHTS, ACCEPT_THRESHOLD };
