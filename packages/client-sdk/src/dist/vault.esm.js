'use strict';

/**
 * ESM-compatible entry point for the VaultJS client SDK.
 *
 * Re-exports the full public API surface:
 *   - VaultClient        — main client class
 *   - clientPreHash      — PBKDF2 pre-hash helper
 *   - buildClientFingerprint / collectBrowserContext — fingerprint helpers
 *   - solvePow / solvePowAsync — PoW solvers
 *   - startSilentRefresh — background token refresh loop
 */

const { VaultClient } = require('../vault-client');
const { clientPreHash } = require('../client-crypto');
const { buildClientFingerprint, collectBrowserContext, getWebGLRenderer } = require('../client-fingerprint');
const { solvePow, solvePowAsync } = require('../pow-solver');
const { startSilentRefresh } = require('../silent-refresh');

module.exports = {
  VaultClient,
  clientPreHash,
  buildClientFingerprint,
  collectBrowserContext,
  getWebGLRenderer,
  solvePow,
  solvePowAsync,
  startSilentRefresh
};
