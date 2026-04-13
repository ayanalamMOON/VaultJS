'use strict';

const { validateSession, refreshSession, revokeSession, COOKIE_NAME } = require('../session-manager');
const { logAnomaly } = require('../anomaly-detector');

/**
 * Build a request-context object from Express request headers + security metadata.
 * The context is used both for token validation and for binding new tokens.
 *
 * @param {import('express').Request} req
 * @returns {object}
 */
function buildContext(req) {
    return {
        userAgent: req.headers['user-agent'] || '',
        timeZone: req.headers['x-timezone'] || '',
        colorDepth: req.headers['x-color-depth'] || '',
        pixelDepth: req.headers['x-pixel-depth'] || '',
        webglRenderer: req.headers['x-webgl-renderer'] || '',
        webauthnCredentialId: req.headers['x-webauthn-credential-id'] || '',
        ip: req.security?.clientIp || req.ip || ''
    };
}

/**
 * Determine whether the token is close enough to expiry that it should be
 * silently refreshed on this response. Threshold: < 240 s remaining.
 *
 * @param {object} payload  - Validated token payload
 * @param {number} nowSec   - Current unix seconds (injectable for testing)
 * @returns {boolean}
 */
function shouldRefreshToken(payload, nowSec = Math.floor(Date.now() / 1000)) {
    const remaining = (payload.exp || 0) - nowSec;
    return remaining < 240;
}

/**
 * Set the vault session cookie with consistent, secure defaults.
 *
 * @param {import('express').Response} res
 * @param {string} token
 */
function setSessionCookie(res, token) {
    res.cookie(COOKIE_NAME, token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        // Max-age mirrors the token TTL + a small buffer so the browser
        // doesn't drop the cookie before the silent-refresh fires
        maxAge: 720 * 1000
    });
}

/**
 * Express middleware that validates the VaultJS session token on every
 * protected route. On success it:
 *   - Attaches the validated payload to req.auth
 *   - Silently refreshes the token if it is close to expiry
 *   - Sets X-Vault-Rotation for downstream correlation
 * On failure it:
 *   - Logs an anomaly event
 *   - Returns 401 with a generic error message (no internals leaked)
 *
 * @param {object} opts
 * @param {string} opts.masterSecret
 * @param {string} opts.hmacKey
 * @param {import('ioredis').Redis|null} [opts.redis]
 * @returns {import('express').RequestHandler}
 */
function validateTokenMiddleware({ masterSecret, hmacKey, redis = null }) {
    return async (req, res, next) => {
        // Accept token from HttpOnly cookie or Authorization header
        const token =
            req.cookies?.[COOKIE_NAME] ||
            (req.headers.authorization?.startsWith('Bearer ')
                ? req.headers.authorization.slice(7)
                : null);

        if (!token) {
            return res.status(401).json({ error: 'missing token' });
        }

        try {
            const context = buildContext(req);
            const validated = await validateSession({ token, context, masterSecret, hmacKey, redis });
            req.auth = validated;

            // Silent refresh — rotates the token before it expires
            if (shouldRefreshToken(validated)) {
                try {
                    const refreshed = await refreshSession({
                        validatedPayload: validated,
                        context,
                        masterSecret,
                        hmacKey,
                        redis
                    });
                    setSessionCookie(res, refreshed.token);
                } catch (refreshErr) {
                    // A failed refresh is non-fatal: the current validated token is still good
                    logAnomaly('token_refresh_failure', {
                        ip: context.ip,
                        uid: validated.uid,
                        message: refreshErr.message
                    });
                }
            }

            res.setHeader('x-vault-rotation', String(validated.rot));
            res.setHeader('x-vault-risk-score', String(validated.runtimeRiskScore ?? validated?.risk?.ts ?? 0));
            res.setHeader('x-vault-context-drift', String(validated.contextDrift ?? 0));
            return next();
        } catch (err) {
            logAnomaly('token_validation_failure', {
                message: err.message,
                ip: req.security?.clientIp || req.ip || 'unknown'
            });
            return res.status(401).json({ error: 'invalid session' });
        }
    };
}

module.exports = { validateTokenMiddleware, buildContext, shouldRefreshToken };
