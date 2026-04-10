'use strict';

const { trustScore } = require('../../packages/token-engine/src/security-context');
const { shouldRefreshToken } = require('../../packages/auth-server/src/middleware/validate-token');

test('trustScore penalizes bot-like contexts', () => {
  const good = trustScore({ userAgent: 'Mozilla/5.0 Chrome/123', webglRenderer: 'ANGLE', timeZone: 'UTC', ip: '10.1.1.1' });
  const bad = trustScore({ userAgent: 'HeadlessBot', webglRenderer: 'unknown', ip: '8.8.8.8' });
  expect(good).toBeGreaterThan(bad);
});

test('shouldRefreshToken triggers near expiry', () => {
  const now = Math.floor(Date.now() / 1000);
  expect(shouldRefreshToken({ exp: now + 120 }, now)).toBe(true);
  expect(shouldRefreshToken({ exp: now + 900 }, now)).toBe(false);
});
