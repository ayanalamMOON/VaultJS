'use strict';

const {
    currentEpoch,
    EPOCH_GRACE_WINDOWS,
    CLOCK_SKEW_SECONDS,
    MAX_TOKEN_BYTES,
    MAX_TOKEN_LIFETIME_SECONDS,
    MIN_RUNTIME_TRUST_SCORE,
    MAX_CONTEXT_DRIFT_SCORE,
    deriveEpochKeyring,
    decryptPayload,
    verifyAndParseEnvelope,
    buildFingerprint,
    fingerprintDriftScore
} = require('../../crypto-core/src');
const { assertFreshRotation, assertFreshJti } = require('./replay-guard');
const { hashContextSummary } = require('./token-factory');
const { evaluateContext } = require('./security-context');

function readNumberEnv(name, fallback) {
    const value = Number(process.env[name]);
    return Number.isFinite(value) ? value : fallback;
}

function readStringListEnv(name) {
    const raw = String(process.env[name] || '').trim();
    if (!raw) return [];
    return raw.split(',').map((x) => x.trim()).filter(Boolean);
}

function assertClaimShape(inner) {
    if (!inner || typeof inner !== 'object') throw new Error('token payload invalid');
    if (!inner.uid || typeof inner.uid !== 'string') throw new Error('uid claim missing');
    if (!inner.sid || typeof inner.sid !== 'string') throw new Error('sid claim missing');
    if (!Number.isInteger(inner.rot) || inner.rot < 1) throw new Error('rotation claim invalid');
    if (!inner.jti || typeof inner.jti !== 'string') throw new Error('jti claim missing');
    if (!inner.fp || typeof inner.fp !== 'string') throw new Error('fingerprint claim missing');
    if (!inner.ctx || typeof inner.ctx !== 'string') throw new Error('context summary claim missing');
    if (!Number.isInteger(inner.epoch) || inner.epoch < 0) throw new Error('epoch claim invalid');
}

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

    const maxLifetime = readNumberEnv('VAULT_MAX_TOKEN_LIFETIME_SECONDS', MAX_TOKEN_LIFETIME_SECONDS);
    if ((inner.exp - inner.iat) > (maxLifetime + CLOCK_SKEW_SECONDS)) {
        throw new Error('token lifetime exceeds policy');
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
    const runtime = evaluateContext(context);
    const runtimeScore = runtime.score;
    const mintedScore = inner?.risk?.ts ?? 0;
    const minRuntimeScore = readNumberEnv('VAULT_MIN_RUNTIME_TRUST', MIN_RUNTIME_TRUST_SCORE);
    const maxRiskDrift = readNumberEnv('VAULT_MAX_RISK_DRIFT', 35);
    const mintedFlags = Array.isArray(inner?.risk?.fl)
        ? inner.risk.fl.map((f) => String(f).trim()).filter(Boolean)
        : [];

    const blockedFlags = new Set(readStringListEnv('VAULT_BLOCKED_RISK_FLAGS'));
    if (blockedFlags.size > 0) {
        for (const flag of mintedFlags) {
            if (blockedFlags.has(flag)) {
                throw new Error(`token blocked by risk flag: ${flag}`);
            }
        }
    }

    if (runtimeScore < minRuntimeScore) {
        throw new Error('runtime context too risky');
    }
    if (mintedScore - runtimeScore > maxRiskDrift) {
        throw new Error('risk profile drift too high');
    }
    if (inner?.risk?.wa === 1 && !context.webauthnCredentialId) {
        throw new Error('hardware token bound but no credential provided');
    }
    if (inner?.risk?.wa === 1 && inner?.risk?.bf && runtime?.ua?.browserFamily && inner.risk.bf !== runtime.ua.browserFamily) {
        throw new Error('hardware token bound but browser family changed');
    }

    return runtime;
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
    if (!token || typeof token !== 'string') throw new Error('token missing');
    if (Buffer.byteLength(token, 'utf8') > MAX_TOKEN_BYTES) {
        throw new Error('token exceeds maximum size');
    }

    // Step 1: verify HMAC, parse envelope
    const encrypted = verifyAndParseEnvelope(token, hmacKey);

    // Step 2: try to decrypt using current epoch + grace windows
    const nowEpoch = currentEpoch();
    const keyring = deriveEpochKeyring(masterSecret, nowEpoch, EPOCH_GRACE_WINDOWS, 0);
    const decrypted = await decryptWithKeyring(encrypted, keyring);
    if (!decrypted) throw new Error('token decryption failed');

    const inner = decrypted.inner;

    // Step 2.5: shape validation
    assertClaimShape(inner);

    // Step 3: temporal claims
    assertTemporalClaims(inner);

    // Step 4: risk/trust-score drift
    const runtimeRisk = assertRiskClaims(inner, context);

    // Step 5: browser fingerprint binding
    const expectedFp = buildFingerprint(context);
    const contextDrift = fingerprintDriftScore(inner.fp, expectedFp);
    if (expectedFp !== inner.fp) {
        throw new Error(`fingerprint mismatch (drift=${contextDrift})`);
    }

    if ((inner?.risk?.nw || '') === 'private' && runtimeRisk.network === 'public') {
        throw new Error('network trust degraded');
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

    const maxContextDrift = readNumberEnv('VAULT_MAX_CONTEXT_DRIFT', MAX_CONTEXT_DRIFT_SCORE);
    if (contextDrift > maxContextDrift) {
        throw new Error('context drift too high');
    }

    return {
        ...inner,
        matchedEpoch: decrypted.epoch,
        runtimeRiskScore: runtimeRisk.score,
        runtimeRiskFlags: runtimeRisk.flags,
        contextDrift
    };
}

module.exports = {
    validateToken,
    assertTemporalClaims,
    assertRiskClaims,
    decryptWithKeyring
};
