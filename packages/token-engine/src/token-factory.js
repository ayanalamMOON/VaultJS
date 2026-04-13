'use strict';

const crypto = require('crypto');
const {
    currentEpoch,
    deriveEpochKey,
    encryptPayload,
    signEnvelope,
    buildFingerprint,
    nextRotation,
    randomNonce,
    TOKEN_TTL_SECONDS
} = require('../../crypto-core/src');
const { parseUserAgent, evaluateContext } = require('./security-context');

/**
 * Produce a 24-char hex summary of the request context (ua + ip + tz + webgl).
 * Used as AAD binding so the ciphertext is tied to the client context at mint time.
 *
 * @param {object} context
 * @returns {string}
 */
function hashContextSummary(context = {}) {
    const summary = [
        context.userAgent || '',
        context.ip || '',
        context.timeZone || '',
        context.webglRenderer || '',
        context.webauthnCredentialId || ''
    ].join('|');
    return crypto.createHash('sha256').update(summary).digest('hex').slice(0, 24);
}

/**
 * Build risk claims embedded in every token:
 *   ts  - server-computed trust score at mint time
 *   bf  - browser family (chrome | firefox | edge | safari | unknown)
 *   mb  - is mobile (1 | 0)
 *
 * @param {object} context
 * @returns {{ ts: number, bf: string, mb: 0|1 }}
 */
function buildRiskClaims(context = {}) {
    const assessment = evaluateContext(context);
    const ua = parseUserAgent(context.userAgent);
    return {
        ts: assessment.score,
        bf: ua.browserFamily,
        mb: ua.isMobile ? 1 : 0,
        wa: context.webauthnCredentialId ? 1 : 0,
        nw: assessment.network,
        fl: assessment.flags.slice(0, 8)
    };
}

/**
 * Mint a fully signed, AES-GCM encrypted VaultJS token.
 *
 * Token structure (layered):
 *  outer: base64url(JSON(encryptedEnvelope)).hmacSig
 *  envelope fields: iv, ciphertext, tag, aad, v
 *  inner (plaintext after decrypt): uid, sid, epoch, fp, rot, nonce, jti, iat, exp, ctx, risk
 *
 * @param {object}  opts
 * @param {string}  opts.uid              - User identifier
 * @param {string}  opts.sessionId        - Session UUID
 * @param {object}  opts.context          - Request context (ua, ip, tz, webgl, etc.)
 * @param {number}  [opts.previousRotation=0] - Previous rotation counter value
 * @param {string}  opts.masterSecret     - Master key material for HKDF epoch derivation
 * @param {string}  opts.hmacKey          - Key for outer HMAC signature
 * @param {number}  [opts.now=Date.now()] - Inject current time for testing
 * @returns {{ token: string, inner: object, aad: string }}
 */
function issueToken({ uid, sessionId, context, previousRotation = 0, masterSecret, hmacKey, now = Date.now() }) {
    if (!uid) throw new Error('uid is required');
    if (!sessionId) throw new Error('sessionId is required');
    if (!masterSecret) throw new Error('masterSecret is required');
    if (!hmacKey) throw new Error('hmacKey is required');

    const nowSec = Math.floor(now / 1000);
    const epoch = currentEpoch(nowSec);
    const fp = buildFingerprint(context);
    const risk = buildRiskClaims(context);
    const rot = nextRotation(previousRotation);

    const inner = {
        uid,
        sid: sessionId,
        epoch,
        fp,
        rot,
        nonce: randomNonce(),
        jti: crypto.randomUUID(),
        iat: nowSec,
        exp: nowSec + TOKEN_TTL_SECONDS,
        ctx: hashContextSummary(context),
        risk
    };

    // AAD = uid.sid.rotation.browserFamily.webauthn — ties ciphertext to these values
    const aad = `${uid}.${sessionId}.${rot}.${risk.bf}.${risk.wa}`;
    const aesKey = deriveEpochKey(masterSecret, epoch);
    const encrypted = encryptPayload(inner, aesKey, aad);
    const token = signEnvelope(encrypted, hmacKey);

    return { token, inner, aad };
}

module.exports = {
    issueToken,
    hashContextSummary,
    buildRiskClaims
};
