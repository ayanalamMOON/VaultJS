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
const { trustScore, parseUserAgent } = require('./security-context');

function hashContextSummary(context = {}) {
  const summary = `${context.userAgent || ''}|${context.ip || ''}|${context.timeZone || ''}|${context.webglRenderer || ''}`;
  return crypto.createHash('sha256').update(summary).digest('hex').slice(0, 24);
}

function buildRiskClaims(context = {}) {
  const ua = parseUserAgent(context.userAgent);
  return {
    ts: trustScore(context),
    bf: ua.browserFamily,
    mb: ua.isMobile ? 1 : 0
  };
}

function issueToken({ uid, sessionId, context, previousRotation = 0, masterSecret, hmacKey, now = Date.now() }) {
  const nowSec = Math.floor(now / 1000);
  const epoch = currentEpoch(nowSec);
  const fp = buildFingerprint(context);
  const risk = buildRiskClaims(context);

  const inner = {
    uid,
    sid: sessionId,
    epoch,
    fp,
    rot: nextRotation(previousRotation),
    nonce: randomNonce(),
    jti: crypto.randomUUID(),
    iat: nowSec,
    exp: nowSec + TOKEN_TTL_SECONDS,
    ctx: hashContextSummary(context),
    risk
  };

  const aad = `${uid}.${sessionId}.${inner.rot}.${risk.bf}`;
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
