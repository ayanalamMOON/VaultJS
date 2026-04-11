'use strict';

const crypto = require('crypto');

/**
 * Count the number of leading zero bits in a SHA-256 digest buffer.
 *
 * @param {Buffer} buffer
 * @returns {number}
 */
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

/**
 * Solve a Proof-of-Work challenge issued by the server.
 *
 * Iterates through nonce values 0..maxNonce looking for one that, when
 * concatenated with the challenge prefix and SHA-256 hashed, produces
 * a digest with at least `difficulty` leading zero bits.
 *
 * @param {object} challenge
 * @param {string} challenge.prefix     - Random hex prefix from the server
 * @param {number} challenge.difficulty - Minimum leading zero bits required
 * @param {number} [challenge.maxNonce=25000000] - Upper bound for nonce search
 * @returns {string} The nonce that solves the challenge
 * @throws {Error}   If no solution is found within the nonce range
 */
function solvePow({ prefix, difficulty, maxNonce = 25_000_000 }) {
  if (!prefix) throw new Error('pow: prefix is required');
  if (typeof difficulty !== 'number' || difficulty < 1) throw new Error('pow: difficulty must be a positive integer');

  for (let nonce = 0; nonce <= maxNonce; nonce += 1) {
    const digest = crypto.createHash('sha256').update(`${prefix}${nonce}`).digest();
    if (countLeadingZeroBits(digest) >= difficulty) {
      return String(nonce);
    }
  }

  throw new Error(`pow: no solution found within nonce range 0..${maxNonce} for difficulty ${difficulty}`);
}

/**
 * Async/chunked PoW solver suitable for browser main threads.
 * Yields control back to the event loop every `chunkSize` iterations to avoid
 * blocking UI. Returns a Promise that resolves with the nonce string.
 *
 * @param {object}  challenge
 * @param {string}  challenge.prefix
 * @param {number}  challenge.difficulty
 * @param {number}  [challenge.maxNonce=25000000]
 * @param {number}  [chunkSize=50000]
 * @returns {Promise<string>}
 */
function solvePowAsync({ prefix, difficulty, maxNonce = 25_000_000 }, chunkSize = 50_000) {
  if (!prefix) return Promise.reject(new Error('pow: prefix is required'));
  if (typeof difficulty !== 'number' || difficulty < 1) {
    return Promise.reject(new Error('pow: difficulty must be a positive integer'));
  }

  return new Promise((resolve, reject) => {
    let nonce = 0;

    function processChunk() {
      const end = Math.min(nonce + chunkSize, maxNonce + 1);
      for (; nonce < end; nonce += 1) {
        const digest = crypto.createHash('sha256').update(`${prefix}${nonce}`).digest();
        if (countLeadingZeroBits(digest) >= difficulty) {
          return resolve(String(nonce));
        }
      }
      if (nonce > maxNonce) {
        return reject(new Error(`pow: no solution found within nonce range 0..${maxNonce} for difficulty ${difficulty}`));
      }
      // Yield to event loop before next chunk
      setTimeout(processChunk, 0);
    }

    processChunk();
  });
}

module.exports = { solvePow, solvePowAsync, countLeadingZeroBits };
