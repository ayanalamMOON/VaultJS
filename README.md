# VaultJS

VaultJS is a 4D web security reference implementation:

- **Length:** high entropy and memory-hard KDFs.
- **Width:** context-bound tokens (fingerprint + IP prefix checks).
- **Depth:** layered token envelope (HMAC + AES-GCM + rotating payload).
- **Time:** epoch-keyed derivation with silent refresh.

## Packages
- `packages/crypto-core`: stateless crypto utilities.
- `packages/token-engine`: token mint/validate/refresh orchestration.
- `packages/auth-server`: Express auth + session endpoints.
- `packages/client-sdk`: browser-side pre-hash/fingerprint/PoW helpers.
- `packages/validation-service`: isolated validation pipeline.

## Quick start
```bash
npm install
npm test
npm run start:auth
```

## Security notes
This is a strong baseline, but production deployments should add:
- dedicated secret management (KMS/HSM),
- hardened logging + SIEM,
- WebAuthn hardware binding for high-assurance environments.
