'use strict';

const { computeDifficulty } = require('../../packages/auth-server/src/pow-challenge');

test('pow difficulty increases with repeated failures', () => {
  expect(computeDifficulty(3)).toBeGreaterThanOrEqual(18);
  expect(computeDifficulty(8)).toBeGreaterThan(computeDifficulty(4));
});
