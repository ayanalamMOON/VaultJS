'use strict';

function scoreSignals({ signatureValid, decryptionValid, contextValid, replayValid }) {
  let score = 0;
  if (signatureValid) score += 40;
  if (decryptionValid) score += 30;
  if (contextValid) score += 20;
  if (replayValid) score += 10;
  return score;
}

function decideValidation(signals) {
  const score = scoreSignals(signals);
  const allow = score >= 90;

  const reason = allow
    ? 'ok'
    : !signals.signatureValid
      ? 'bad_signature'
      : !signals.decryptionValid
        ? 'decrypt_fail'
        : !signals.contextValid
          ? 'context_mismatch'
          : 'replay_detected';

  return { allow, reason, score };
}

module.exports = { decideValidation, scoreSignals };
