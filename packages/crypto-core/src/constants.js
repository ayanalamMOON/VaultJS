'use strict';

/**
 * VaultJS cryptographic constants.
 *
 * All security-critical tunables are centralized here so they can be
 * audited and adjusted in one place. Values follow OWASP / NIST
 * recommendations where applicable.
 */

module.exports = {
    // ── PBKDF2 (client-side pre-hash) ────────────────────────────────────────
    /** PBKDF2 iteration count — OWASP 2024 recommends ≥ 600 000 for SHA-256. */
    PBKDF2_ITERATIONS: 150_000,
    PBKDF2_DIGEST: 'sha256',
    PBKDF2_BYTES: 32,

    // ── Argon2id (server-side password hashing) ──────────────────────────────
    /** Memory cost in KiB. 96 MiB makes GPU-parallel cracking extremely expensive. */
    ARGON2_MEMORY_KIB: 96 * 1024,
    /** Time cost — number of passes over memory. */
    ARGON2_TIME_COST: 3,
    /** Parallelism — number of threads. Must not exceed available CPU cores. */
    ARGON2_PARALLELISM: 4,

    // ── Epoch key rotation (Time dimension) ──────────────────────────────────
    /** Epoch window in seconds. 300 s = 5-minute token epochs. */
    EPOCH_SECONDS: 300,
    /** Number of previous epochs accepted during validation (grace windows). */
    EPOCH_GRACE_WINDOWS: 1,
    /** Clock skew tolerance for iat/exp temporal claims. */
    CLOCK_SKEW_SECONDS: 30,

    // ── Token envelope cryptography (Depth dimension) ────────────────────────
    HMAC_ALGO: 'sha256',
    AES_ALGO: 'aes-256-gcm',
    /** AES-GCM recommended IV length (NIST SP 800-38D). */
    AES_IV_BYTES: 12,
    /** Random salt length for password hashing (scrypt fallback). */
    SALT_BYTES: 32,
    /** Random nonce length embedded in every inner token. */
    NONCE_BYTES: 16,

    // ── Session cookie ───────────────────────────────────────────────────────
    COOKIE_NAME: 'vault_session',
    /** Token envelope version. Increment on breaking format changes. */
    TOKEN_VERSION: 2,
    /** Default token TTL in seconds. Client must refresh before this expires. */
    TOKEN_TTL_SECONDS: 600,
    /** Hard maximum accepted exp-iat window to reject suspiciously long-lived tokens. */
    MAX_TOKEN_LIFETIME_SECONDS: 900,
    /** Maximum accepted raw token length (bytes/chars) before early rejection. */
    MAX_TOKEN_BYTES: 8192,

    // ── Runtime security policy defaults ─────────────────────────────────────
    /** Minimum runtime trust score accepted by validators unless overridden. */
    MIN_RUNTIME_TRUST_SCORE: 30,
    /** Maximum tolerated fingerprint drift (0-100) for diagnostics/policy engines. */
    MAX_CONTEXT_DRIFT_SCORE: 45,
    /** Global anomaly pressure threshold used by adaptive protections. */
    MAX_ANOMALY_PRESSURE: 140,

    // ── Proof-of-Work challenge parameters ───────────────────────────────────
    /** Default PoW difficulty in leading-zero-bits. */
    POW_DEFAULT_DIFFICULTY: 20,
    /** Minimum difficulty floor (even for 0 failures). */
    POW_MIN_DIFFICULTY: 18,
    /** Maximum difficulty ceiling (prevents impossible challenges). */
    POW_MAX_DIFFICULTY: 24,
    /** Maximum time (ms) a challenge is valid before it expires. */
    POW_EXPIRES_MS: 30_000,
    /** Byte length of the random challenge prefix. */
    POW_CHALLENGE_BYTES: 12,
    /** Maximum nonce value the client is expected to search. */
    POW_MAX_NONCE: 25_000_000
};
