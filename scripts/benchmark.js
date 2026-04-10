'use strict';

const { pbkdf2PreHash } = require('../packages/crypto-core/src/kdf');

const t0 = Date.now();
pbkdf2PreHash('correct horse battery staple', 'bench-user');
const ms = Date.now() - t0;

if (process.argv.includes('--smoke')) {
  console.log(`smoke benchmark pbkdf2: ${ms}ms`);
} else {
  console.log(JSON.stringify({ pbkdf2Ms: ms }));
}
