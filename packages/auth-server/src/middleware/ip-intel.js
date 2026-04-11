'use strict';

/**
 * IP Intelligence middleware — extracts the real client IP from proxy headers,
 * classifies it into a risk tier, and attaches `req.security` metadata for
 * downstream middleware and route handlers.
 *
 * Supports:
 *   - X-Forwarded-For (first entry = original client)
 *   - X-Real-IP (nginx convention)
 *   - CF-Connecting-IP (Cloudflare)
 *   - Falls back to req.ip (Express trust-proxy aware)
 */

// RFC 1918 / RFC 4193 / RFC 6598 private/reserved ranges
const PRIVATE_V4 = [
  /^10\./,                          // 10.0.0.0/8
  /^172\.(1[6-9]|2\d|3[01])\./,    // 172.16.0.0/12
  /^192\.168\./,                    // 192.168.0.0/16
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, // 100.64.0.0/10 (CGN)
];

const LOOPBACK_V4 = /^127\./;
const LOOPBACK_V6 = /^::1$/;
const PRIVATE_V6 = /^f[cd]/i; // fc00::/7 ULA

/**
 * Extract the most likely real client IP from request headers.
 *
 * @param {import('express').Request} req
 * @returns {string}
 */
function extractClientIp(req) {
  // Cloudflare
  const cfIp = req.headers['cf-connecting-ip'];
  if (cfIp) return String(cfIp).trim();

  // Standard proxy header
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return String(forwarded).split(',')[0].trim();

  // Nginx
  const realIp = req.headers['x-real-ip'];
  if (realIp) return String(realIp).trim();

  return req.ip || '';
}

/**
 * Classify an IP into a risk tier.
 *
 * Risk scores (lower = more trusted):
 *   loopback   →  0  (local dev)
 *   internal   →  5  (private network)
 *   cgn        → 10  (carrier-grade NAT — slightly less trustworthy)
 *   ipv6       → 15  (public but harder to geo-locate)
 *   public     → 25  (normal internet)
 *   unknown    → 40  (no IP at all — highly suspicious)
 *
 * @param {string} ip
 * @returns {{ label: string, score: number }}
 */
function computeIpRisk(ip) {
  if (!ip) return { label: 'unknown', score: 40 };
  const addr = String(ip).trim();

  if (LOOPBACK_V4.test(addr) || LOOPBACK_V6.test(addr)) {
    return { label: 'loopback', score: 0 };
  }

  // CGN range (100.64/10) — check before generic private
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(addr)) {
    return { label: 'cgn', score: 10 };
  }

  for (const re of PRIVATE_V4) {
    if (re.test(addr)) return { label: 'internal', score: 5 };
  }
  if (PRIVATE_V6.test(addr)) return { label: 'internal', score: 5 };
  if (addr.includes(':')) return { label: 'ipv6', score: 15 };

  return { label: 'public', score: 25 };
}

/**
 * Express middleware that enriches `req.security` with IP intelligence.
 */
function ipIntel(req, _res, next) {
  const clientIp = extractClientIp(req);
  const risk = computeIpRisk(clientIp);

  req.security = req.security || {};
  req.security.clientIp = clientIp;
  req.security.ipRisk = risk.label;
  req.security.ipRiskScore = risk.score;
  next();
}

module.exports = { ipIntel, extractClientIp, computeIpRisk };
