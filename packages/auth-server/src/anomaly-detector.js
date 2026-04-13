'use strict';

const EventEmitter = require('events');
const { addAuditEvent } = require('../../../infra/db/audit.model');

// Event bus for real-time anomaly subscribers (e.g. SIEM adapters)
const anomalyBus = new EventEmitter();
anomalyBus.setMaxListeners(20);

// Per-key occurrence counters with TTL-based expiry windows
// Structure: key -> { count: number, windowEnd: number }
const counters = new Map();
const recent = [];
const MAX_RECENT_EVENTS = 500;
const escalations = new Map();
const recentEscalations = [];
const MAX_RECENT_ESCALATIONS = 300;
const MAX_INSIGHT_WINDOW_MS = 24 * 60 * 60 * 1000;
const DEFAULT_INSIGHT_WINDOW_MS = 15 * 60 * 1000;

// Sliding window duration: anomalies counted within this window
const WINDOW_MS = 10 * 60 * 1000; // 10 minutes

// Evict expired counter windows every 5 minutes
const EVICT_INTERVAL_MS = 5 * 60 * 1000;
const evictTimer = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of counters) {
        if (v.windowEnd <= now) counters.delete(k);
    }
}, EVICT_INTERVAL_MS);
if (evictTimer.unref) evictTimer.unref();

/**
 * Build a composite key for tracking anomalies per (type, ip, uid) tuple.
 * @param {string} type
 * @param {object} details
 * @returns {string}
 */
function keyFor(type, details) {
    return `${type}:${details?.ip || 'unknown'}:${details?.uid || 'anon'}`;
}

/**
 * Map an occurrence count to a severity label.
 * @param {number} count
 * @returns {'low'|'medium'|'high'|'critical'}
 */
function severityFromCount(count) {
    if (count >= 10) return 'critical';
    if (count >= 5) return 'high';
    if (count >= 2) return 'medium';
    return 'low';
}

function escalationLevelFromCount(count) {
    if (count >= 10) return 3;
    if (count >= 5) return 2;
    if (count >= 2) return 1;
    return 0;
}

function severityWeight(severity) {
    if (severity === 'critical') return 5;
    if (severity === 'high') return 3;
    if (severity === 'medium') return 2;
    return 1;
}

/**
 * Record an anomaly event. Increments the counter for the (type, ip, uid) tuple,
 * persists it to the audit log, and emits to any registered anomaly listeners.
 *
 * @param {string} type     - Machine-readable anomaly type, e.g. 'token_validation_failure'
 * @param {object} details  - Extra context: { ip, uid, message, ... }
 * @returns {object}        - The anomaly event that was recorded
 */
function logAnomaly(type, details = {}) {
    const key = keyFor(type, details);
    const now = Date.now();
    const existing = counters.get(key);

    let count;
    if (!existing || existing.windowEnd <= now) {
        count = 1;
        counters.set(key, { count, windowEnd: now + WINDOW_MS });
    } else {
        count = existing.count + 1;
        counters.set(key, { count, windowEnd: existing.windowEnd });
    }

    const severity = severityFromCount(count);
    const event = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
        type,
        details: { ...details, count },
        severity,
        at: new Date().toISOString()
    };

    recent.push(event);
    if (recent.length > MAX_RECENT_EVENTS) {
        recent.splice(0, recent.length - MAX_RECENT_EVENTS);
    }

    // Persist to audit log (non-blocking, fire-and-forget)
    try {
        addAuditEvent(event);
    } catch {
        // Never let audit logging crash the request path
    }

    anomalyBus.emit('anomaly', event);

    const level = escalationLevelFromCount(count);
    const previousLevel = escalations.get(key) || 0;
    if (level > previousLevel) {
        escalations.set(key, level);
        const escalationEvent = {
            id: `${event.id}-lvl${level}`,
            key,
            level,
            previousLevel,
            event,
            at: new Date().toISOString()
        };

        recentEscalations.push(escalationEvent);
        if (recentEscalations.length > MAX_RECENT_ESCALATIONS) {
            recentEscalations.splice(0, recentEscalations.length - MAX_RECENT_ESCALATIONS);
        }

        anomalyBus.emit('escalation', escalationEvent);
    }

    return event;
}

/**
 * Subscribe to anomaly events.
 * Returns an unsubscribe function for clean teardown.
 *
 * @param {function} listener
 * @returns {function} unsubscribe
 */
function onAnomaly(listener) {
    anomalyBus.on('anomaly', listener);
    return () => anomalyBus.off('anomaly', listener);
}

/**
 * Subscribe to anomaly escalation events (threshold crossings).
 *
 * @param {function} listener
 * @returns {function}
 */
function onEscalation(listener) {
    anomalyBus.on('escalation', listener);
    return () => anomalyBus.off('escalation', listener);
}

/**
 * Compute weighted anomaly pressure from recent events in a rolling window.
 *
 * @param {number} [windowMs=WINDOW_MS]
 * @returns {{ score: number, total: number, bySeverity: object }}
 */
function getAnomalyPressure(windowMs = WINDOW_MS) {
    const now = Date.now();
    const floor = now - Math.max(1, Number(windowMs) || WINDOW_MS);
    const bucket = { low: 0, medium: 0, high: 0, critical: 0 };

    for (const event of recent) {
        const ts = new Date(event.at).getTime();
        if (!Number.isFinite(ts) || ts < floor) continue;
        bucket[event.severity] = (bucket[event.severity] || 0) + 1;
    }

    const score =
        (bucket.low * severityWeight('low')) +
        (bucket.medium * severityWeight('medium')) +
        (bucket.high * severityWeight('high')) +
        (bucket.critical * severityWeight('critical'));

    return {
        score,
        total: bucket.low + bucket.medium + bucket.high + bucket.critical,
        bySeverity: bucket
    };
}

/**
 * Read lightweight in-memory anomaly stats for diagnostics dashboards.
 *
 * @returns {{ uniqueKeys: number, recentEvents: number, top: Array<{key:string,count:number}> }}
 */
function getAnomalyStats() {
    const top = [...counters.entries()]
        .map(([key, value]) => ({ key, count: value.count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);

    return {
        uniqueKeys: counters.size,
        recentEvents: recent.length,
        recentEscalations: recentEscalations.length,
        pressure: getAnomalyPressure(),
        top
    };
}

/**
 * Return recent anomaly events newest-first.
 *
 * @param {number} [limit=50]
 * @returns {Array<object>}
 */
function getRecentAnomalies(limit = 50) {
    const n = Math.max(1, Math.min(500, Number(limit) || 50));
    return recent.slice(-n).reverse();
}

/**
 * Return recent anomaly escalations newest-first.
 *
 * @param {number} [limit=50]
 * @returns {Array<object>}
 */
function getRecentEscalations(limit = 50) {
    const n = Math.max(1, Math.min(300, Number(limit) || 50));
    return recentEscalations.slice(-n).reverse();
}

function safeTs(value) {
    const ts = new Date(value).getTime();
    return Number.isFinite(ts) ? ts : null;
}

function toMinuteBucket(ts) {
    const d = new Date(ts);
    d.setSeconds(0, 0);
    return d.toISOString();
}

function trendDirection(firstHalf, secondHalf) {
    if (secondHalf > firstHalf * 1.2) return 'rising';
    if (secondHalf < firstHalf * 0.8) return 'falling';
    return 'stable';
}

function buildInsightRecommendations({ pressure, totalEvents, escalationCounts, topTypes }) {
    const recommendations = [];

    if (totalEvents === 0) {
        recommendations.push({
            priority: 'low',
            code: 'stable_baseline',
            message: 'No anomaly events observed in the requested window.'
        });
        return recommendations;
    }

    if (escalationCounts.level3 > 0) {
        recommendations.push({
            priority: 'critical',
            code: 'critical_escalation_detected',
            message: 'Level 3 escalations detected. Trigger incident response and key/session review.'
        });
    }

    if (pressure.score >= 140) {
        recommendations.push({
            priority: 'high',
            code: 'high_anomaly_pressure',
            message: 'Anomaly pressure exceeded safe threshold. Tighten adaptive limits and require step-up auth.'
        });
    }

    if ((topTypes[0]?.count || 0) >= Math.ceil(totalEvents * 0.5)) {
        recommendations.push({
            priority: 'medium',
            code: 'single_type_hotspot',
            message: `A single anomaly type dominates recent traffic (${topTypes[0].type}); prioritize targeted mitigations.`
        });
    }

    if (recommendations.length === 0) {
        recommendations.push({
            priority: 'low',
            code: 'monitoring_recommended',
            message: 'Anomaly activity is present but controlled. Continue monitoring and periodic policy simulation.'
        });
    }

    return recommendations;
}

/**
 * Build high-signal anomaly analytics for admin dashboards and automated policy decisions.
 *
 * @param {object} [options]
 * @param {number} [options.windowMs]
 * @param {number} [options.topN]
 * @returns {{
 *   windowMs:number,
 *   totals:{events:number,escalations:number},
 *   pressure:{score:number,total:number,bySeverity:object},
 *   distributions:{severity:object,escalationLevels:object,topTypes:Array<object>},
 *   trend:{firstHalf:number,secondHalf:number,direction:string,perMinute:Array<object>},
 *   recommendations:Array<object>
 * }}
 */
function getAnomalyInsights(options = {}) {
    const windowMs = Math.max(60_000, Math.min(MAX_INSIGHT_WINDOW_MS, Number(options.windowMs) || DEFAULT_INSIGHT_WINDOW_MS));
    const topN = Math.max(3, Math.min(20, Number(options.topN) || 8));
    const now = Date.now();
    const floor = now - windowMs;
    const middle = floor + Math.floor(windowMs / 2);

    const severity = { low: 0, medium: 0, high: 0, critical: 0 };
    const perMinuteMap = new Map();
    const byType = new Map();
    let firstHalf = 0;
    let secondHalf = 0;

    for (const event of recent) {
        const ts = safeTs(event.at);
        if (ts === null || ts < floor) continue;

        severity[event.severity] = (severity[event.severity] || 0) + 1;

        if (ts <= middle) firstHalf += 1;
        else secondHalf += 1;

        const minute = toMinuteBucket(ts);
        const currentMinute = perMinuteMap.get(minute) || { minute, count: 0, critical: 0 };
        currentMinute.count += 1;
        if (event.severity === 'critical') currentMinute.critical += 1;
        perMinuteMap.set(minute, currentMinute);

        const type = String(event.type || 'unknown');
        const currentType = byType.get(type) || {
            type,
            count: 0,
            severity: { low: 0, medium: 0, high: 0, critical: 0 },
            lastSeen: null
        };
        currentType.count += 1;
        currentType.severity[event.severity] = (currentType.severity[event.severity] || 0) + 1;
        currentType.lastSeen = event.at || currentType.lastSeen;
        byType.set(type, currentType);
    }

    const escalationLevels = { level1: 0, level2: 0, level3: 0 };
    let escalationTotal = 0;
    for (const escalation of recentEscalations) {
        const ts = safeTs(escalation.at);
        if (ts === null || ts < floor) continue;

        escalationTotal += 1;
        if (escalation.level >= 3) escalationLevels.level3 += 1;
        else if (escalation.level === 2) escalationLevels.level2 += 1;
        else if (escalation.level === 1) escalationLevels.level1 += 1;
    }

    const topTypes = [...byType.values()]
        .sort((a, b) => b.count - a.count)
        .slice(0, topN);

    const perMinute = [...perMinuteMap.values()]
        .sort((a, b) => new Date(a.minute).getTime() - new Date(b.minute).getTime());

    const pressure = getAnomalyPressure(windowMs);
    const totalEvents = severity.low + severity.medium + severity.high + severity.critical;

    return {
        windowMs,
        totals: {
            events: totalEvents,
            escalations: escalationTotal
        },
        pressure,
        distributions: {
            severity,
            escalationLevels,
            topTypes
        },
        trend: {
            firstHalf,
            secondHalf,
            direction: trendDirection(firstHalf, secondHalf),
            perMinute
        },
        recommendations: buildInsightRecommendations({
            pressure,
            totalEvents,
            escalationCounts: escalationLevels,
            topTypes
        })
    };
}

module.exports = {
    logAnomaly,
    onAnomaly,
    onEscalation,
    getAnomalyPressure,
    getAnomalyStats,
    getRecentAnomalies,
    getRecentEscalations,
    getAnomalyInsights
};
