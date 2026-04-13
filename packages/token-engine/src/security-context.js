'use strict';

/**
 * Classify a User-Agent string into a set of signals used for risk scoring
 * and browser-family AAD binding.
 *
 * @param {string} ua
 * @returns {{ isMobile: boolean, isBotLike: boolean, browserFamily: string }}
 */
function parseUserAgent(ua = '') {
    const value = String(ua).toLowerCase();
    return {
        isMobile: /mobile|android|iphone|ipad|ipod/.test(value),
        isBotLike: /bot|crawler|spider|headless|phantom|selenium|puppeteer|playwright/.test(value),
        isAutomated: /headless|phantom|selenium|puppeteer|playwright|webdriver/.test(value),
        browserFamily: value.includes('firefox')
            ? 'firefox'
            : value.includes('edg/')
                ? 'edge'
                : value.includes('chrome')
                    ? 'chrome'
                    : value.includes('safari')
                        ? 'safari'
                        : 'unknown'
    };
}

/**
 * Classify an IP address into a network type for risk scoring.
 *
 * Ranges treated as internal/private:
 *   10.0.0.0/8  192.168.0.0/16  172.16.0.0/12
 *   127.0.0.0/8  ::1  fc00::/7
 *
 * @param {string} ip
 * @returns {'loopback'|'private'|'ipv6'|'public'|'unknown'}
 */
function classifyNetwork(ip = '') {
    const addr = String(ip).trim();
    if (!addr) return 'unknown';
    if (addr === '127.0.0.1' || addr === '::1') return 'loopback';
    if (
        addr.startsWith('10.') ||
        addr.startsWith('192.168.') ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(addr) ||
        addr.startsWith('fc') ||
        addr.startsWith('fd')
    ) {
        return 'private';
    }
    if (addr.includes(':')) return 'ipv6';
    return 'public';
}

/**
 * Compute a 0-100 integer trust score from a request context object.
 *
 * Deductions:
 *   -50  bot-like UA
 *   -10  missing / very short user-agent (< 20 chars)
 *   -10  missing WebGL renderer
 *   - 5  missing time-zone
 *   - 5  public IP (normal internet clients are slightly less trusted than private)
 *   -15  unknown IP (no IP at all)
 *
 * @param {object} context
 * @param {string} [context.userAgent]
 * @param {string} [context.ip]
 * @param {string} [context.timeZone]
 * @param {string} [context.webglRenderer]
 * @returns {number} 0–100
 */
function trustScore(context = {}) {
    return evaluateContext(context).score;
}

/**
 * Rich trust evaluation that returns both score and contributing factors.
 * This enables downstream policy engines to reason about *why* trust changed.
 *
 * @param {object} context
 * @returns {{ score: number, network: string, ua: object, flags: string[] }}
 */
function evaluateContext(context = {}) {
    const ua = parseUserAgent(context.userAgent);
    const network = classifyNetwork(context.ip);
    const flags = [];
    let score = 100;

    if (ua.isBotLike) {
        score -= 50;
        flags.push('bot_like_ua');
    }
    if (ua.isAutomated) {
        score -= 15;
        flags.push('automation_framework');
    }
    if (!context.userAgent || String(context.userAgent).length < 20) {
        score -= 10;
        flags.push('weak_user_agent');
    }
    if (!context.webglRenderer || context.webglRenderer === 'unknown') {
        score -= 10;
        flags.push('missing_webgl');
    }
    if (!context.timeZone) {
        score -= 5;
        flags.push('missing_timezone');
    }

    if (network === 'public') {
        score -= 5;
        flags.push('public_network');
    }
    if (network === 'unknown') {
        score -= 15;
        flags.push('unknown_network');
    }

    if (context.webauthnCredentialId) {
        score += 50;
        flags.push('hardware_bound');
    }

    return {
        score: Math.max(0, Math.min(100, score)),
        network,
        ua,
        flags
    };
}

module.exports = {
    parseUserAgent,
    classifyNetwork,
    trustScore,
    evaluateContext
};
