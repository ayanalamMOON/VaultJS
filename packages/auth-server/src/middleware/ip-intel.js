'use strict';

function extractClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return String(forwarded).split(',')[0].trim();
  return req.ip;
}

function computeIpRisk(ip) {
  if (!ip) return { label: 'unknown', score: 40 };
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.')) return { label: 'internal', score: 5 };
  if (ip.includes(':')) return { label: 'ipv6', score: 15 };
  return { label: 'public', score: 25 };
}

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
