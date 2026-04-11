'use strict';

const { buildFingerprint } = require('../../crypto-core/src/fingerprint');

/**
 * Collect browser context signals and produce a 32-char hex fingerprint.
 *
 * In a real browser environment the `ctx` object should be populated by
 * calling native APIs:
 *
 *   {
 *     userAgent:      navigator.userAgent,
 *     timeZone:       Intl.DateTimeFormat().resolvedOptions().timeZone,
 *     colorDepth:     screen.colorDepth,
 *     pixelDepth:     screen.pixelDepth,
 *     webglRenderer:  getWebGLRenderer(),  // WEBGL_debug_renderer_info
 *     ip:             ''   // not available client-side; server injects this
 *   }
 *
 * This module intentionally does NOT access `window` / `navigator` directly
 * so it can run in Node.js test environments without mocking.
 *
 * @param {object} ctx - Browser context signals (see above)
 * @returns {string}   32-char hex fingerprint
 */
function buildClientFingerprint(ctx = {}) {
  return buildFingerprint(ctx);
}

/**
 * Helper: extract the WebGL renderer string from the current browser context.
 * Safe to call in Node.js (returns 'unknown').
 *
 * @returns {string}
 */
function getWebGLRenderer() {
  try {
    if (typeof document === 'undefined') return 'unknown';
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return 'unknown';
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    if (!ext) return 'unknown';
    return gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || 'unknown';
  } catch {
    return 'unknown';
  }
}

/**
 * Helper: collect all available context signals from the browser.
 * Returns a plain object ready to be passed to `buildClientFingerprint()`.
 *
 * Safe to call in Node.js — returns sensible defaults.
 *
 * @returns {object}
 */
function collectBrowserContext() {
  const ctx = {
    userAgent: '',
    timeZone: '',
    colorDepth: '',
    pixelDepth: '',
    webglRenderer: 'unknown',
    ip: '' // Not available client-side; server fills this in
  };

  try {
    if (typeof navigator !== 'undefined') ctx.userAgent = navigator.userAgent || '';
    if (typeof Intl !== 'undefined') {
      ctx.timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    }
    if (typeof screen !== 'undefined') {
      ctx.colorDepth = String(screen.colorDepth || '');
      ctx.pixelDepth = String(screen.pixelDepth || '');
    }
    ctx.webglRenderer = getWebGLRenderer();
  } catch {
    // Non-fatal — return whatever we collected
  }

  return ctx;
}

module.exports = { buildClientFingerprint, getWebGLRenderer, collectBrowserContext };
