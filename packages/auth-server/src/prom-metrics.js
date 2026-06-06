'use strict';

let prom = null;
try {
    // prefer installed prom-client
    // eslint-disable-next-line global-require
    prom = require('prom-client');
} catch (e) {
    prom = null;
}

if (!prom) {
    module.exports = {
        middleware: (_req, _res, next) => next(),
        incAdmin: async () => { },
        observeRequest: () => { }
    };
} else {
    const collectDefault = prom.collectDefaultMetrics;
    collectDefault({ timeout: 5000 });

    const httpDuration = new prom.Histogram({
        name: 'http_request_duration_seconds',
        help: 'HTTP request duration in seconds',
        labelNames: ['method', 'route', 'status'],
        buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5]
    });

    const adminCounter = new prom.Counter({
        name: 'admin_actions_total',
        help: 'Total admin actions performed',
        labelNames: ['action']
    });

    const tokenCounter = new prom.Counter({
        name: 'vault_token_events_total',
        help: 'Token lifecycle events',
        labelNames: ['event']
    });

    const tokenValidationDuration = new prom.Histogram({
        name: 'vault_token_validation_seconds',
        help: 'Duration of token validation in seconds',
        labelNames: ['outcome'],
        buckets: [0.0005, 0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1]
    });

    const sessionCounter = new prom.Counter({
        name: 'vault_sessions_total',
        help: 'Session lifecycle events',
        labelNames: ['event']
    });

    const replayCounter = new prom.Counter({
        name: 'vault_replay_detections_total',
        help: 'Replay detections for rotation and JTI checks',
        labelNames: ['kind']
    });

    const redisCacheCounter = new prom.Counter({
        name: 'vault_redis_cache_events_total',
        help: 'Redis cache access outcomes',
        labelNames: ['kind']
    });

    const redisCacheHitRateGauge = new prom.Gauge({
        name: 'vault_redis_cache_hit_rate',
        help: 'Observed Redis token-cache hit rate'
    });

    const redisCacheMissRateGauge = new prom.Gauge({
        name: 'vault_redis_cache_miss_rate',
        help: 'Observed Redis token-cache miss rate'
    });

    const tokenMintDuration = new prom.Histogram({
        name: 'vault_token_mint_seconds',
        help: 'Duration of token minting in seconds',
        labelNames: ['operation'],
        buckets: [0.0005, 0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1]
    });

    const activeSessionsGauge = new prom.Gauge({
        name: 'vault_active_sessions',
        help: 'Number of active sessions tracked in-process'
    });

    let redisLookupHits = 0;
    let redisLookupMisses = 0;

    function middleware(req, res, next) {
        const end = httpDuration.startTimer({ method: req.method, route: req.path });
        res.on('finish', () => {
            end({ status: String(res.statusCode) });
        });
        next();
    }

    async function incAdmin(action, value = 1) {
        adminCounter.inc({ action: String(action) }, Number(value || 1));
    }

    function incToken(event, value = 1) {
        tokenCounter.inc({ event: String(event) }, Number(value || 1));
    }

    function observeTokenValidation(durationSeconds, outcome = 'success') {
        try { tokenValidationDuration.observe({ outcome: String(outcome) }, Number(durationSeconds)); } catch (e) { }
    }

    function incSession(event, value = 1) {
        sessionCounter.inc({ event: String(event) }, Number(value || 1));
    }

    function incReplay(kind, value = 1) {
        replayCounter.inc({ kind: String(kind) }, Number(value || 1));
    }

    function recordRedisEvent(kind, value = 1) {
        const safeKind = String(kind);
        const safeValue = Number(value || 1);
        redisCacheCounter.inc({ kind: safeKind }, safeValue);
        if (safeKind === 'hit') redisLookupHits += safeValue;
        if (safeKind === 'miss') redisLookupMisses += safeValue;
        const total = redisLookupHits + redisLookupMisses;
        if (total > 0) {
            redisCacheHitRateGauge.set(redisLookupHits / total);
            redisCacheMissRateGauge.set(redisLookupMisses / total);
        }
    }

    function observeTokenMint(durationSeconds, operation = 'issue') {
        try { tokenMintDuration.observe({ operation: String(operation) }, Number(durationSeconds)); } catch (e) { }
    }

    function setActiveSessions(value) {
        try { activeSessionsGauge.set(Number(value || 0)); } catch (e) { }
    }

    module.exports = {
        middleware,
        incAdmin,
        observeRequest: httpDuration.observe,
        register: prom.register,
        // token/session helpers
        incToken,
        observeTokenValidation,
        incSession,
        setActiveSessions,
        incReplay,
        recordRedisEvent,
        observeTokenMint
    };
}
