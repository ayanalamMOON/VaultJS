'use strict';

const crypto = require('crypto');

const HEX_RE = /^[a-f0-9]+$/i;

function normalizeIpPrefix(ip = '') {
    if (!ip) return '0.0';
    if (ip.includes(':')) {
        return ip.split(':').slice(0, 4).join(':');
    }
    const [a = '0', b = '0'] = ip.split('.');
    return `${a}.${b}`;
}

function buildFingerprint(input = {}) {
    const factors = [
        input.userAgent || 'unknown-ua',
        input.timeZone || 'UTC',
        input.colorDepth || 'na',
        input.pixelDepth || 'na',
        input.webglRenderer || 'na',
        normalizeIpPrefix(input.ip)
    ];

    return crypto.createHash('sha256').update(factors.join('|')).digest('hex').slice(0, 32);
}

/**
 * Compute Hamming distance (bit-level) between two equal-length hex strings.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function hammingDistanceHex(a, b) {
    const left = String(a || '').toLowerCase();
    const right = String(b || '').toLowerCase();

    if (!left || !right || left.length !== right.length || !HEX_RE.test(left) || !HEX_RE.test(right)) {
        return Number.POSITIVE_INFINITY;
    }

    let bits = 0;
    for (let i = 0; i < left.length; i += 1) {
        const x = parseInt(left[i], 16) ^ parseInt(right[i], 16);
        // popcount of a nibble (0..15)
        bits += (x & 1) + ((x >> 1) & 1) + ((x >> 2) & 1) + ((x >> 3) & 1);
    }
    return bits;
}

/**
 * Convert two fingerprint hashes into a normalized drift score in [0, 100].
 * 0   => identical
 * 100 => completely different / invalid input
 *
 * @param {string} mintedFp
 * @param {string} runtimeFp
 * @returns {number}
 */
function fingerprintDriftScore(mintedFp, runtimeFp) {
    const bits = hammingDistanceHex(mintedFp, runtimeFp);
    if (!Number.isFinite(bits)) return 100;
    const totalBits = String(mintedFp).length * 4;
    return Math.round((bits / totalBits) * 100);
}

module.exports = {
    buildFingerprint,
    normalizeIpPrefix,
    hammingDistanceHex,
    fingerprintDriftScore
};
