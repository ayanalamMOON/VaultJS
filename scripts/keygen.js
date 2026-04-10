'use strict';

const crypto = require('crypto');

function key(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

console.log('MASTER_SECRET=' + key(32));
console.log('HMAC_KEY=' + key(32));
