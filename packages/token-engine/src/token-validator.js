'use strict';

const {
  currentEpoch,
  EPOCH_GRACE_WINDOWS,
  CLOCK_SKEW_SECONDS,
  deriveEpochKeyring,
  decryptPayload,
  verifyAndParseEnvelope,
  buildFingerprint
} = require('../../crypto-core/src');
const { assertFreshRotation, assertFreshJti } = require('./replay-guard');
const { hashContextSummary } = require('./token-factory');
const { trustScore } = require('./security-context');

function assertTemporalClaims(inner, nowSec = Math.floor(Date.now() / 1000)) {
  if (!inner.iat || !inner.exp) throw new Error('temporal claims missing');
  if (inner.iat > nowSec + CLOCK_SKEW_SECONDS) throw new Error('token issued in future');
  if (inner.exp < nowSec - CLOCK_SKEW_SECONDS) throw new Error('token expired');
}

function assertRiskClaims(inner, context) {
  const runtimeScore = trustScore(context);
  const mintedScore = inner?.risk?.ts ?? 0;
  if (runtimeScore < 30) throw new Error('runtime context too risky');
  if (mintedScore - runtimeScore > 35) throw new Error('risk profile drift too high');
}

async function decryptWithKeyring(encrypted, keyring) {
  for (const candidate of keyring) {
    try {
      const inner = decryptPayload(encrypted, candidate.key);
      return { inner, epoch: candidate.epoch };
    } catch {
      // continue
    }
  }
  return null;
}

async function validateToken({ token, context, masterSecret, hmacKey, redis }) {
  const encrypted = verifyAndParseEnvelope(token, hmacKey);
  const now = currentEpoch();
  const keyring = deriveEpochKeyring(masterSecret, now, EPOCH_GRACE_WINDOWS, 0);

  const decrypted = await decryptWithKeyring(encrypted, keyring);
  if (!decrypted) throw new Error('token decryption failed');

  const inner = decrypted.inner;
  assertTemporalClaims(inner);
  assertRiskClaims(inner, context);

  const expectedFp = buildFingerprint(context);
  if (expectedFp !== inner.fp) throw new Error('fingerprint mismatch');

  const expectedCtx = hashContextSummary(context);
  if (expectedCtx !== inner.ctx) throw new Error('context summary mismatch');

  await assertFreshRotation(inner.sid, inner.rot, redis);
  await assertFreshJti(inner.sid, inner.jti);

  return { ...inner, matchedEpoch: decrypted.epoch };
}

module.exports = {
  validateToken,
  assertTemporalClaims,
  assertRiskClaims,
  decryptWithKeyring
};
