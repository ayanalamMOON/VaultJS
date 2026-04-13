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
 * Verify a PoW solution locally.
 *
 * @param {object} challenge
 * @param {string} challenge.prefix
 * @param {number} challenge.difficulty
 * @param {string|number} nonce
 * @returns {boolean}
 */
function verifyPowSolution({ prefix, difficulty }, nonce) {
    if (!prefix || typeof difficulty !== 'number') return false;
    const parsed = Number(nonce);
    if (!Number.isInteger(parsed) || parsed < 0) return false;
    const digest = crypto.createHash('sha256').update(`${prefix}${parsed}`).digest();
    return countLeadingZeroBits(digest) >= difficulty;
}

function normalizeAsyncOptions(chunkSizeOrOptions) {
    if (typeof chunkSizeOrOptions === 'number') {
        return { chunkSize: chunkSizeOrOptions };
    }
    if (chunkSizeOrOptions && typeof chunkSizeOrOptions === 'object') {
        return chunkSizeOrOptions;
    }
    return {};
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
function solvePowAsync({ prefix, difficulty, maxNonce = 25_000_000 }, chunkSizeOrOptions = 50_000) {
    if (!prefix) return Promise.reject(new Error('pow: prefix is required'));
    if (typeof difficulty !== 'number' || difficulty < 1) {
        return Promise.reject(new Error('pow: difficulty must be a positive integer'));
    }

    const opts = normalizeAsyncOptions(chunkSizeOrOptions);
    const chunkSize = Number(opts.chunkSize) > 0 ? Number(opts.chunkSize) : 50_000;
    const signal = opts.signal || null;
    const onProgress = typeof opts.onProgress === 'function' ? opts.onProgress : null;
    const yieldMs = Number(opts.yieldMs) >= 0 ? Number(opts.yieldMs) : 0;

    return new Promise((resolve, reject) => {
        let nonce = 0;
        const startedAt = Date.now();

        function abortError() {
            const err = new Error('pow: aborted');
            err.name = 'AbortError';
            return err;
        }

        if (signal?.aborted) {
            reject(abortError());
            return;
        }

        function processChunk() {
            if (signal?.aborted) {
                reject(abortError());
                return;
            }

            const end = Math.min(nonce + chunkSize, maxNonce + 1);
            for (; nonce < end; nonce += 1) {
                const digest = crypto.createHash('sha256').update(`${prefix}${nonce}`).digest();
                if (countLeadingZeroBits(digest) >= difficulty) {
                    onProgress?.({
                        nonce,
                        maxNonce,
                        progress: 1,
                        elapsedMs: Date.now() - startedAt,
                        solved: true
                    });
                    return resolve(String(nonce));
                }
            }

            onProgress?.({
                nonce,
                maxNonce,
                progress: Math.min(1, nonce / (maxNonce || 1)),
                elapsedMs: Date.now() - startedAt,
                solved: false
            });

            if (nonce > maxNonce) {
                return reject(new Error(`pow: no solution found within nonce range 0..${maxNonce} for difficulty ${difficulty}`));
            }
            // Yield to event loop before next chunk
            setTimeout(processChunk, yieldMs);
        }

        processChunk();
    });
}

module.exports = { solvePow, solvePowAsync, verifyPowSolution, countLeadingZeroBits };
