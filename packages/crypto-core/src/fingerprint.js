'use strict';

const crypto = require('crypto');

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

module.exports = {
  buildFingerprint,
  normalizeIpPrefix
};
