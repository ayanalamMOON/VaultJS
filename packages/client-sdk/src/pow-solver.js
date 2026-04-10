'use strict';

const crypto = require('crypto');

function countLeadingZeroBits(buffer) {
  let bits = 0;
  for (const byte of buffer) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

function solvePow({ prefix, difficulty, maxNonce = 5_000_000 }) {
  for (let nonce = 0; nonce <= maxNonce; nonce += 1) {
    const digest = crypto.createHash('sha256').update(`${prefix}${nonce}`).digest();
    if (countLeadingZeroBits(digest) >= difficulty) {
      return String(nonce);
    }
  }
  throw new Error('pow solution not found');
}

module.exports = { solvePow, countLeadingZeroBits };
