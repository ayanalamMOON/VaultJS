# Copilot Instructions for VaultJS

## Build, test, and lint commands

Run commands from the repository root.

- Install dependencies: `npm install`
- Lint: `npm run lint` (current script is a no-op check)
- Build/smoke check: `npm run build` (runs `scripts/benchmark.js --smoke`)
- Full test suite: `npm test`
- Single test file: `npm test -- tests/integration/auth-flow.test.js`
- Single test by name: `npm test -- -t "replay attempt is rejected"`

## High-level architecture

VaultJS is a CommonJS monorepo (single root `package.json`, workspaces under `packages/*` and `apps/*`) with security flows centered in `packages/auth-server`.

1. `packages/client-sdk` prepares client-side signals (PBKDF2 pre-hash, fingerprint/context headers, PoW solving, silent refresh loop) and talks to auth endpoints.
2. `packages/auth-server` is the main Express service. It composes:
   - login/register/session/admin routes
   - context/risk middleware (`ip-intel`, adaptive `rate-limiter`, token validation)
   - session lifecycle management (`session-manager`)
3. `packages/token-engine` mints/validates/refreshes tokens and enforces replay protections (`rot` + `jti`) using optional Redis-backed state.
4. `packages/crypto-core` contains primitives and token format internals (HKDF epoch keys, AES-GCM envelope, HMAC signing, fingerprint hashing, KDF logic).
5. `packages/validation-service` adds decision scoring/policy profiles and SIEM export + containment workflows; auth-server admin routes expose these capabilities.
6. `infra/db` provides SQLite-backed models (users/sessions/audits/policy history/export jobs/containments); `infra/redis` is optional and has in-memory fallbacks when disabled.
7. `apps/api-gateway` demonstrates protected resource access via shared token middleware; `apps/demo-app` is a minimal demo server.

## Key codebase conventions

- **Cross-package imports are source-relative** (for example, `require('../../packages/.../src/...')`), not package-published imports.
- **Client context header contract is explicit** and used throughout token validation:
  - `x-timezone`, `x-color-depth`, `x-pixel-depth`, `x-webgl-renderer`, optional `x-webauthn-credential-id`
- **Token transport convention:** read from `vault_session` cookie first, then `Authorization: Bearer ...`.
- **Session/token lifecycle defaults:** token TTL is 600s with middleware-driven silent refresh near expiry; cookie maxAge is slightly longer (720s).
- **Replay prevention is dual-layered:** rotation counter and JTI uniqueness are both enforced; Redis is used when available, otherwise process memory fallback is expected.
- **Admin routes are hard-gated by API token:** endpoints under `/admin` require `ADMIN_API_TOKEN` (via `x-admin-token` or Bearer token).
- **Policy profile model is built-in and mutable at runtime:** `strict`, `balanced`, `compat` via admin endpoints and decision engine helpers.
- **SIEM/export artifacts are persisted to disk and DB snapshots:** default manifest directory `infra/db/export-manifests`; containment evidence directory `infra/db/siem-containments` (overridable via env vars).
- **Tests target exported Express apps directly** (`supertest` against `app`) rather than launching standalone processes.
- **In test environments Redis is off by default** unless explicitly enabled (`REDIS_ENABLED`), so tests rely on in-memory fallback behavior.
