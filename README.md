# VaultJS - 4D Web Security System

VaultJS is a novel 4D web security reference implementation designed to provide a highly resilient, denuvo-inspired token architecture.

## The Core Concept: What "4D" Means Cryptographically

| Dimension | Metaphor | Cryptographic Mapping |
|---|---|---|
| **Length** | Key entropy / space | 256-bit+ token entropy, Argon2id tuning |
| **Width** | Context binding | Multi-factor environmental fingerprint |
| **Depth** | Layered obfuscation | Nested encryption envelope (like Denuvo's VM layers) |
| **Time** | Temporal validity | Epoch-locked key derivation + silent rotation |

---

## Module 1 — Password Protection (Anti-Cracking)

### Client-Side Pre-Hashing
Most systems hash only server-side. VaultJS adds a client-side layer first. The browser pre-hashes the password before transmission:
- Derives 256 bits via PBKDF2 with 150,000 iterations.
- Uses a `username::domain.com` salt.

**Why this matters:** Even if your TLS is MITMed, the attacker gets a PBKDF2 digest, not the raw password. Cracking that digest to recover the original password is a second hard problem.

### Server-Side: Argon2id as the Second Layer
The server takes the client pre-hash and applies Argon2id:
- Tuned to 96MB memory cost, 3 time cost, 4 parallelism.
- This creates two sequential hard problems for any attacker. GPU farms that crack bcrypt in hours would take months here.

### Proof-of-Work Gate on Failed Attempts
Inspired by Hashcash — after N failures, the server issues a PoW challenge:
- The client must find a SHA256(prefix + nonce) with 20 leading zero bits.
- CPU-bound on the attacker, essentially free for a real user.

---

## Module 2 — Session Token Architecture (Anti-Hijacking)

### The 3-Layer Token Envelope (Depth Dimension)
The token is a layered cryptographic envelope:
1. **Outer:** HMAC-SHA256 signed envelope for tamper detection.
2. **Middle:** AES-256-GCM encrypted payload for confidentiality.
3. **Inner:** Rotating sub-token with short TTL and context fingerprint.

### Width Dimension — Context Fingerprint
Tokens are strictly bound to the environment they were issued in:
- The context fingerprint (`fp` field) includes `userAgent`, screen bits, `timeZone`, and the hardware `webglRenderer` string.
- If a token is stolen and used from a different browser or device, the fingerprint validation fails. The token is useless outside its origin environment.

### Time Dimension — Epoch Key Rotation
The server derives the AES-GCM encryption key from a **time-based master key**, not a static one:
- 5-minute time buckets (epochs).
- `epoch_key = HKDF(masterSecret, salt=epoch)`
- Captured tokens are cryptographically invalid after the epoch ends. The client SDK silently refreshes tokens in the background via a background fetch (zero UX impact).

---

## Module 3 — Validation Service (Denuvo-Inspired)

Moving validation logic into an opaque, isolated execution environment (akin to Denuvo's VM layer).
Our validation runs a strict 10-step pipeline to re-verify context, verify signatures, decrypt the envelope, check epochs, and look for replay attacks.

## Packages
- `packages/crypto-core`: Stateless crypto utilities (Constants, HKDF, PBKDF2, Token Envelopes).
- `packages/token-engine`: Token factory and validation orchestrator, Replay Guards.
- `packages/auth-server`: Express endpoints, Anomaly Detection, PoW Challenges, IP Intelligence, Rate Limiting.
- `packages/client-sdk`: Browser helpers for pre-hashing, PoW solving, fingerprinting, and a robust `VaultClient` with silent-refresh.
- `packages/validation-service`: Isolated decision engine and context verifier.

## Quick start
```bash
npm install
npm test
npm run start:auth
```
