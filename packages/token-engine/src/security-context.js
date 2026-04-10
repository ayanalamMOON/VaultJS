'use strict';

function parseUserAgent(ua = '') {
  const value = String(ua).toLowerCase();
  return {
    isMobile: /mobile|android|iphone|ipad/.test(value),
    isBotLike: /bot|crawler|spider|headless/.test(value),
    browserFamily: value.includes('firefox')
      ? 'firefox'
      : value.includes('edg')
        ? 'edge'
        : value.includes('chrome')
          ? 'chrome'
          : value.includes('safari')
            ? 'safari'
            : 'unknown'
  };
}

function classifyNetwork(ip = '') {
  const addr = String(ip);
  if (addr.startsWith('10.') || addr.startsWith('192.168.') || addr.startsWith('172.16.')) {
    return 'private';
  }
  if (addr.includes(':')) return 'ipv6';
  return 'public';
}

function trustScore(context = {}) {
  const ua = parseUserAgent(context.userAgent);
  const network = classifyNetwork(context.ip);
  let score = 100;

  if (!context.webglRenderer || context.webglRenderer === 'unknown') score -= 10;
  if (!context.timeZone) score -= 5;
  if (ua.isBotLike) score -= 50;
  if (network === 'public') score -= 5;
  if (String(context.userAgent || '').length < 20) score -= 10;

  return Math.max(0, Math.min(100, score));
}

module.exports = {
  parseUserAgent,
  classifyNetwork,
  trustScore
};
