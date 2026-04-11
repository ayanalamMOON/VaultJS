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

/**
 * Verify that temporal claims (iat / exp) are within acceptable bounds.
 * Allows CLOCK_SKEW_SECONDS drift in both directions.
 *
 * @param {object} inner   - Decrypted token payload
 * @param {number} nowSec  - Current unix seconds (injectable for testing)
 */
function assertTemporalClaims(inner, nowSec = Math.floor(Date.now() / 1000)) {
  if (!inner || typeof inner.iat !== 'number' || typeof inner.exp !== 'number') {
    throw new Error('temporal claims missing');
  }
  if (inner.iat > nowSec + CLOCK_SKEW_SECONDS) {
    throw new Error('token issued in future');
  }
  if (inner.exp < nowSec - CLOCK_SKEW_SECONDS) {
    throw new Error('token expired');
  }
}

/**
 * Verify that the runtime trust score has not degraded catastrophically
 * from the score recorded at mint time.
 *
 * @param {object} inner    - Decrypted token payload
 * @param {object} context  - Runtime request context
 */
function assertRiskClaims(inner, context) {
  const runtimeScore = trustScore(context);
  const mintedScore = inner?.risk?.ts ?? 0;

  if (runtimeScore < 30) {
    throw new Error('runtime context too risky');
  }
  if (mintedScore - runtimeScore > 35) {
    throw new Error('risk profile drift too high');
  }
  if (inner?.risk?.wa === 1 && !context.webauthnCredentialId) {
    throw new Error('hardware token bound but no credential provided');
  }
}

/**
 * Try to decrypt an envelope with each key in the keyring.
 * Returns the first successful decryption result, or null.
 *
 * @param {object}   encrypted - Parsed envelope (iv, ciphertext, tag, aad, v)
 * @param {Array<{epoch:number, key:Buffer}>} keyring
 * @returns {Promise<{inner:object, epoch:number}|null>}
 */
async function decryptWithKeyring(encrypted, keyring) {
  for (const candidate of keyring) {
    try {
      const inner = decryptPayload(encrypted, candidate.key);
      return { inner, epoch: candidate.epoch };
    } catch {
      // Try next key in ring
    }
  }
  return null;
}

/**
 * Fully validate a VaultJS token:
 *   1. HMAC signature verification
 *   2. AES-GCM decryption via epoch keyring (supports epoch grace windows)
 *   3. Temporal claims
 *   4. Risk/trust-score drift
 *   5. Browser fingerprint binding
 *   6. Context summary binding
 *   7. Rotation anti-replay
 *   8. JTI anti-replay
 *
 * @param {object}                    opts
 * @param {string}                    opts.token          - Raw vault token string
 * @param {object}                    opts.context        - Runtime request context
 * @param {string}                    opts.masterSecret   - Master key material
 * @param {string}                    opts.hmacKey        - HMAC signing key
 * @param {import('ioredis').Redis|null} [opts.redis]     - Optional Redis client
 * @returns {Promise<object>}         Validated inner payload + matchedEpoch
 */
async function validateToken({ token, context, masterSecret, hmacKey, redis = null }) {
  // Step 1: verify HMAC, parse envelope
  const encrypted = verifyAndParseEnvelope(token, hmacKey);

  // Step 2: try to decrypt using current epoch + grace windows
  const nowEpoch = currentEpoch();
  const keyring = deriveEpochKeyring(masterSecret, nowEpoch, EPOCH_GRACE_WINDOWS, 0);
  const decrypted = await decryptWithKeyring(encrypted, keyring);
  if (!decrypted) throw new Error('token decryption failed');

  const inner = decrypted.inner;

  // Step 3: temporal claims
  assertTemporalClaims(inner);

  // Step 4: risk/trust-score drift
  assertRiskClaims(inner, context);

  // Step 5: browser fingerprint binding
  const expectedFp = buildFingerprint(context);
  if (expectedFp !== inner.fp) {
    throw new Error('fingerprint mismatch');
  }

  // Step 6: context summary binding
  const expectedCtx = hashContextSummary(context);
  if (expectedCtx !== inner.ctx) {
    throw new Error('context summary mismatch');
  }

  // Step 7: rotation anti-replay
  await assertFreshRotation(inner.sid, inner.rot, redis);

  // Step 8: JTI anti-replay (threaded through redis for distributed deploys)
  await assertFreshJti(inner.sid, inner.jti, redis);

  return { ...inner, matchedEpoch: decrypted.epoch };
}

module.exports = {
  validateToken,
  assertTemporalClaims,
  assertRiskClaims,
  decryptWithKeyring
};
