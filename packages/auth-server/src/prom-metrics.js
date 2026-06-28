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

    const authOutcomeCounter = new prom.Counter({
        name: 'vault_auth_outcomes_total',
        help: 'Authentication outcomes',
        labelNames: ['outcome']
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

    const middlewareLatency = new prom.Histogram({
        name: 'vault_middleware_latency_seconds',
        help: 'Latency of critical middleware/components',
        labelNames: ['component', 'outcome'],
        buckets: [0.0005, 0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1, 2, 5]
    });

    let redisLookupHits = 0;
    let redisLookupMisses = 0;

    function normalizeRouteLabel(req) {
        // Avoid high-cardinality labels: NEVER use req.path directly.
        // Prefer Express route template (bounded set).
        const routeTemplate = req?.route?.path;
        if (typeof routeTemplate === 'string' && routeTemplate.length > 0) {
            return routeTemplate;
        }

        // If route template is missing, use baseUrl + template/path if any.
        const baseUrl = typeof req?.baseUrl === 'string' ? req.baseUrl : '';
        const pathFromRoute = typeof req?.route?.path === 'string' ? req.route.path : '';
        if (baseUrl && pathFromRoute) return `${baseUrl}${pathFromRoute}`;

        // Fallback: keep it bounded-ish by only using the first path segment.
        const originalUrl = typeof req?.originalUrl === 'string' ? req.originalUrl : '';
        if (!originalUrl) return '/unknown';

        const urlPath = originalUrl.split('?')[0] || '';
        const seg = urlPath.split('/').filter(Boolean)[0];
        return seg ? `/${seg}` : '/unknown';
    }

    function middleware(req, res, next) {
        const route = normalizeRouteLabel(req);
        const end = httpDuration.startTimer({ method: req.method, route, status: '0' });
        res.on('finish', () => {
            end({ status: String(res.statusCode) });
        });
        next();
    }

    async function incAdmin(action, value = 1) {
        adminCounter.inc({ action: String(action) }, Number(value || 1));
    }

    function incAuthOutcome(outcome, value = 1) {
        const safe = String(outcome || '').trim().toLowerCase();
        // bounded label values
        const allowed = new Set(['success', 'failure', 'replay_detected', 'pow_failed']);
        const label = allowed.has(safe) ? safe : 'failure';
        authOutcomeCounter.inc({ outcome: label }, Number(value || 1));
    }

    function incToken(event, value = 1) {
        tokenCounter.inc({ event: String(event) }, Number(value || 1));
    }

    function observeTokenValidation(durationSeconds, outcome = 'success') {
        try { tokenValidationDuration.observe({ outcome: String(outcome) }, Number(durationSeconds)); } catch (e) { }
    }

    function observeMiddlewareLatency(component, outcome, durationSeconds) {
        try {
            middlewareLatency.observe({
                component: String(component),
                outcome: String(outcome)
            }, Number(durationSeconds));
        } catch (e) { }
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

        // auth outcomes
        incAuthOutcome,

        // token/session helpers
        incToken,
        observeTokenValidation,
        incSession,
        setActiveSessions,
        incReplay,
        recordRedisEvent,
        observeTokenMint,

        // middleware instrumentation
        observeMiddlewareLatency
    };
}
