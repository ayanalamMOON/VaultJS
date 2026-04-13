'use strict';

const { clientPreHash: deriveClientPreHash } = require('./client-crypto');
const { buildClientFingerprint } = require('./client-fingerprint');
const { solvePow } = require('./pow-solver');
const { startSilentRefresh } = require('./silent-refresh');
const {
    registerPasskey: performPasskeyRegistration,
    loginWithPasskey: performPasskeyLogin
} = require('./client-webauthn');

/**
 * VaultClient — the browser-side entry point for authenticating with a VaultJS
 * auth-server. Handles:
 *   - Client-side PBKDF2 pre-hashing before credentials are sent
 *   - Browser fingerprint / context headers on every request
 *   - Automatic PoW resolution when the server challenges a login
 *   - Silent token refresh loop
 *   - Registration and logout
 *
 * @example
 * const client = new VaultClient({
 *   baseUrl: 'https://auth.example.com',
 *   domain: 'example.com',
 *   contextProvider: () => ({
 *     timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
 *     colorDepth: screen.colorDepth,
 *     pixelDepth: screen.pixelDepth,
 *     webglRenderer: getWebGLRenderer()
 *   })
 * });
 * await client.login('alice', 'mypassword');
 */
class VaultClient {
    /**
     * @param {object}   opts
     * @param {string}   opts.baseUrl                     - Auth-server origin (no trailing slash)
     * @param {string}   [opts.domain='domain.com']       - Domain for PBKDF2 salt
     * @param {function} [opts.fetchImpl=fetch]           - Fetch implementation (injectable)
     * @param {function} [opts.contextProvider=()=>({})]  - Returns browser context signals
     * @param {object}   [opts.refresh]                   - Options forwarded to startSilentRefresh
     * @param {object}   [opts.network]                   - Network resiliency options
     * @param {function} [opts.onSecuritySignals]         - Callback for x-vault-* response telemetry
     */
    constructor({
        baseUrl,
        domain = 'domain.com',
        fetchImpl = (typeof fetch !== 'undefined' ? fetch : null),
        contextProvider = () => ({}),
        refresh = {},
        network = {},
        onSecuritySignals = null
    }) {
        if (!baseUrl) throw new Error('VaultClient: baseUrl is required');
        if (!fetchImpl) throw new Error('VaultClient: fetchImpl is required (provide a fetch implementation)');

        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.domain = domain;
        this.fetch = fetchImpl;
        this.contextProvider = contextProvider;
        this.refreshOpts = refresh;
        this.networkOpts = {
            timeoutMs: Number(network.timeoutMs) > 0 ? Number(network.timeoutMs) : 10_000,
            retries: Number(network.retries) >= 0 ? Number(network.retries) : 1,
            retryDelayMs: Number(network.retryDelayMs) > 0 ? Number(network.retryDelayMs) : 250,
            maxRetryDelayMs: Number(network.maxRetryDelayMs) > 0 ? Number(network.maxRetryDelayMs) : 2_000
        };
        this._stopRefresh = null;
        this._authenticated = false;
        this._webauthnCredentialId = null;
        this._lastSecuritySignals = null;
        this.onSecuritySignals = typeof onSecuritySignals === 'function' ? onSecuritySignals : null;
    }

    /**
     * Build request headers including all browser context signals.
     * @returns {object}
     */
    _headers() {
        const ctx = this.contextProvider();
        const headers = {
            'content-type': 'application/json',
            'x-timezone': String(ctx.timeZone || ''),
            'x-color-depth': String(ctx.colorDepth || ''),
            'x-pixel-depth': String(ctx.pixelDepth || ''),
            'x-webgl-renderer': String(ctx.webglRenderer || ''),
            'x-client-fp': buildClientFingerprint(ctx)
        };
        if (this._webauthnCredentialId || ctx.webauthnCredentialId) {
            headers['x-webauthn-credential-id'] = String(this._webauthnCredentialId || ctx.webauthnCredentialId);
        }
        return headers;
    }

    _sleep(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }

    _isRetryableResponse(res) {
        return res.status === 408 || res.status === 425 || res.status === 429 || (res.status >= 500 && res.status <= 599);
    }

    _retryDelay(attempt) {
        const base = this.networkOpts.retryDelayMs * (2 ** Math.max(0, attempt - 1));
        const jitter = Math.floor(Math.random() * 150);
        return Math.min(this.networkOpts.maxRetryDelayMs, base + jitter);
    }

    _extractSecuritySignals(res) {
        try {
            if (!res || !res.headers || typeof res.headers.get !== 'function') return null;
            const riskRaw = res.headers.get('x-vault-risk-score');
            const driftRaw = res.headers.get('x-vault-context-drift');
            const rotationRaw = res.headers.get('x-vault-rotation');

            if (riskRaw === null && driftRaw === null && rotationRaw === null) return null;

            return {
                riskScore: Number(riskRaw ?? 0),
                contextDrift: Number(driftRaw ?? 0),
                rotation: Number(rotationRaw ?? 0),
                at: new Date().toISOString()
            };
        } catch {
            return null;
        }
    }

    /**
     * Internal resilient request helper with timeout + retries.
     *
     * @param {string} path
     * @param {object} opts
     * @returns {Promise<Response>}
     */
    async _request(path, {
        method = 'GET',
        body,
        signal,
        headers = {},
        retries = this.networkOpts.retries,
        timeoutMs = this.networkOpts.timeoutMs
    } = {}) {
        const url = /^https?:\/\//i.test(path) ? path : `${this.baseUrl}${path}`;
        const maxAttempts = Math.max(1, retries + 1);

        let lastError;

        for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
            if (signal?.aborted) {
                const err = new Error('request aborted');
                err.name = 'AbortError';
                throw err;
            }

            const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
            const onAbort = () => controller?.abort();
            if (signal && controller) signal.addEventListener('abort', onAbort, { once: true });

            const timeoutId = controller
                ? setTimeout(() => controller.abort(), timeoutMs)
                : null;

            try {
                const res = await this.fetch(url, {
                    method,
                    credentials: 'include',
                    headers: {
                        ...this._headers(),
                        ...headers
                    },
                    body: body === undefined ? undefined : JSON.stringify(body),
                    signal: controller?.signal
                });

                const signals = this._extractSecuritySignals(res);
                if (signals) {
                    this._lastSecuritySignals = signals;
                    if (this.onSecuritySignals) {
                        try { this.onSecuritySignals(signals); } catch { /* consumer callback must not break flow */ }
                    }
                }

                if (attempt < maxAttempts && this._isRetryableResponse(res)) {
                    await this._sleep(this._retryDelay(attempt));
                    continue;
                }

                return res;
            } catch (err) {
                lastError = err;
                if (attempt >= maxAttempts) throw err;
                await this._sleep(this._retryDelay(attempt));
            } finally {
                if (timeoutId) clearTimeout(timeoutId);
                if (signal && controller) signal.removeEventListener('abort', onAbort);
            }
        }

        throw lastError || new Error('request failed');
    }

    /**
     * Internal POST helper.
     * @param {string} path
     * @param {object} body
     * @param {object} [opts] Options for fetch
     * @returns {Promise<Response>}
     */
    async _post(path, body, opts = {}) {
        return this._request(path, {
            method: 'POST',
            body,
            signal: opts.signal,
            retries: Number.isFinite(opts.retries) ? opts.retries : this.networkOpts.retries,
            timeoutMs: Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : this.networkOpts.timeoutMs
        });
    }

    /**
     * Internal GET helper.
     * @param {string} path
     * @returns {Promise<Response>}
     */
    async _get(path) {
        return this._request(path, { method: 'GET' });
    }

    /**
     * Register a new user account.
     * Sends the raw credentials; the server runs its own validation.
     * Note: unlike login, registration does NOT pre-hash on the client because
     * the server needs the actual password for KDF parameter negotiation in the
     * registration path. If you want client-side pre-hash on registration too,
     * set `preHashRegistration: true` in opts.
     *
     * @param {string}  username
     * @param {string}  password
     * @param {object}  [opts]
     * @param {boolean} [opts.preHashRegistration=false]
     * @returns {Promise<void>}
     */
    async register(username, password, { preHashRegistration = false } = {}) {
        if (!username || !password) throw new Error('username and password are required');

        const payload = preHashRegistration
            ? { username, password: deriveClientPreHash(password, username, this.domain) }
            : { username, password };

        const res = await this._post('/auth/register', payload);
        if (res.status === 409) throw new Error('username already taken');
        if (!res.ok) {
            const body = await res.json().catch(() => ({}));
            throw new Error(`registration failed (${res.status}): ${(body.errors || []).join(', ') || body.error || 'unknown'}`);
        }
    }

    /**
     * Authenticate with the server. Sends the PBKDF2 pre-hash of the password
     * so the raw password never leaves the client. Automatically resolves PoW
     * challenges and starts the silent-refresh loop on success.
     *
     * @param {string} username
     * @param {string} password   - Raw password (pre-hashed internally before sending)
     * @returns {Promise<void>}
     */
    async login(username, password, { maxPowAttempts = 2 } = {}) {
        if (!username || !password) throw new Error('username and password are required');

        const preHash = deriveClientPreHash(password, username, this.domain);
        const body = { username, clientPreHash: preHash };

        let res = await this._post('/auth/login', body);

        // Server requires PoW — solve and retry with bounded attempts
        for (let attempt = 0; res.status === 403 && attempt < maxPowAttempts; attempt += 1) {
            const payload = await res.json().catch(() => ({}));
            if (!payload.challenge) throw new Error('login failed: unexpected 403 without challenge');

            let powNonce;
            try {
                powNonce = solvePow(payload.challenge);
            } catch {
                throw new Error('login failed: could not solve PoW challenge');
            }

            res = await this._post('/auth/login', { ...body, powNonce });
        }

        if (!res.ok) {
            const errBody = await res.json().catch(() => ({}));
            throw new Error(`login failed (${res.status}): ${errBody.error || 'invalid credentials'}`);
        }

        this._authenticated = true;

        // Start the silent-refresh loop if not already running
        if (!this._stopRefresh) {
            this._stopRefresh = startSilentRefresh(
                (path, init) => this.fetch(`${this.baseUrl}${path}`, { ...init, headers: this._headers() }),
                this.refreshOpts
            );
        }
    }

    /**
     * Register a new hardware passkey.
     * Robust flow handles signals for graceful cancellation and complex error wrapping.
     *
     * @param {string} username
     * @param {object} [opts]
     * @param {AbortSignal} [opts.signal]
     * @returns {Promise<void>}
     */
    async registerWithPasskey(username, { signal } = {}) {
        if (!username) throw new Error('username is required');

        try {
            // 1. Get challenge from server
            const challengeRes = await this._post('/auth/webauthn/register-challenge', { username }, { signal });
            if (!challengeRes.ok) throw new Error('Failed to get passkey challenge from server');
            const options = await challengeRes.json();

            // 2. Prompt user hardware safely
            const credential = await performPasskeyRegistration(options, signal);

            // 3. Send physical attestation
            const verifyRes = await this._post('/auth/webauthn/register-verify', { username, credential }, { signal });
            if (!verifyRes.ok) throw new Error('Passkey registration validation failed at server layer');

            // Auto login
            this._webauthnCredentialId = credential.id;
            this._authenticated = true;

            if (!this._stopRefresh) {
                this._stopRefresh = startSilentRefresh(
                    (path, init) => this.fetch(`${this.baseUrl}${path}`, { ...init, headers: this._headers() }),
                    this.refreshOpts
                );
            }
        } catch (err) {
            if (err.name === 'AbortError') throw err;
            throw new Error(`VaultJS Passkey Registration Failed: ${err.message}`);
        }
    }

    /**
     * Authenticate via hardware passkey.
     * Robust flow handles signals for graceful cancellation and complex error wrapping.
     *
     * @param {string} username
     * @param {object} [opts]
     * @param {AbortSignal} [opts.signal]
     * @returns {Promise<void>}
     */
    async loginWithPasskey(username, { signal } = {}) {
        if (!username) throw new Error('username is required');

        try {
            // 1. Get challenge from server
            const challengeRes = await this._post('/auth/webauthn/login-challenge', { username }, { signal });
            if (!challengeRes.ok) throw new Error('Failed to fetch passkey challenge');
            const options = await challengeRes.json();

            // 2. Prompt user hardware safely
            const assertion = await performPasskeyLogin(options, signal);

            // 3. Send physical assertion
            const verifyRes = await this._post('/auth/webauthn/login-verify', { username, assertion }, { signal });
            if (!verifyRes.ok) throw new Error('Passkey login assertion rejected by server');

            this._webauthnCredentialId = assertion.id;
            this._authenticated = true;

            if (!this._stopRefresh) {
                this._stopRefresh = startSilentRefresh(
                    (path, init) => this.fetch(`${this.baseUrl}${path}`, { ...init, headers: this._headers() }),
                    this.refreshOpts
                );
            }
        } catch (err) {
            if (err.name === 'AbortError') throw err;
            throw new Error(`VaultJS Passkey Login Failed: ${err.message}`);
        }
    }

    /**
     * Log out from the server and stop the silent-refresh loop.
     *
     * @returns {Promise<void>}
     */
    async logout() {
        this._authenticated = false;

        if (this._stopRefresh) {
            this._stopRefresh();
            this._stopRefresh = null;
        }

        try {
            await this._post('/auth/logout', {});
        } catch {
            // Non-fatal — the server cookie will expire naturally
        }
    }

    /**
     * Log out from ALL devices (revokes every session for the current user).
     * Requires a currently valid session.
     *
     * @returns {Promise<void>}
     */
    async logoutAll() {
        this._authenticated = false;

        if (this._stopRefresh) {
            this._stopRefresh();
            this._stopRefresh = null;
        }

        try {
            await this._post('/auth/logout-all', {});
        } catch {
            // Non-fatal
        }
    }

    /**
     * Check whether the client currently believes it is authenticated.
     * Does NOT make a network call — use GET /session/status for that.
     *
     * @returns {boolean}
     */
    get isAuthenticated() {
        return this._authenticated;
    }

    /**
     * Verify the session is still valid server-side and return the TTL remaining.
     *
     * @returns {Promise<{ok: boolean, ttlRemaining: number, rotation: number}>}
     */
    async sessionStatus() {
        const res = await this._get('/session/status');
        if (res.status === 401) {
            this._authenticated = false;
            if (this._stopRefresh) { this._stopRefresh(); this._stopRefresh = null; }
            throw new Error('session expired');
        }
        if (!res.ok) throw new Error(`session status check failed (${res.status})`);
        return res.json();
    }

    /**
     * Fetch server-evaluated security posture for the current authenticated session.
     *
     * @returns {Promise<object>}
     */
    async securityPosture() {
        const res = await this._get('/session/security-posture');
        if (res.status === 401) {
            this._authenticated = false;
            if (this._stopRefresh) {
                this._stopRefresh();
                this._stopRefresh = null;
            }
            throw new Error('session expired');
        }
        if (!res.ok) throw new Error(`security posture check failed (${res.status})`);
        return res.json();
    }

    /**
     * Return latest security telemetry observed in response headers.
     *
     * @returns {object|null}
     */
    get lastSecuritySignals() {
        return this._lastSecuritySignals;
    }

    /**
     * Perform an authenticated request with Vault context headers attached.
     * Useful for custom app endpoints while reusing VaultClient resilience.
     *
     * @param {string} path
     * @param {object} [opts]
     * @returns {Promise<Response>}
     */
    async request(path, opts = {}) {
        const res = await this._request(path, opts);
        if (res.status === 401) {
            this._authenticated = false;
            if (this._stopRefresh) {
                this._stopRefresh();
                this._stopRefresh = null;
            }
        }
        return res;
    }
}

module.exports = { VaultClient };
