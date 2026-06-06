'use strict';

// Metrics wrapper: prefer persistent DB-backed metrics, fall back to in-memory.
let backend = null;
try {
    backend = require('../../../infra/db/metrics.model');
} catch (e) {
    backend = null;
}

const memory = new Map();

async function incr(name, delta = 1) {
    if (backend && backend.incrMetric) {
        try { await backend.incrMetric(name, delta); return; } catch (e) { /* fallback */ }
    }
    const v = Number(memory.get(name) || 0) + Number(delta || 1);
    memory.set(name, v);
}

async function getCounter(name) {
    if (backend && backend.getMetric) {
        try { return await backend.getMetric(name); } catch (e) { /* fallback */ }
    }
    return Number(memory.get(name) || 0);
}

async function getAll() {
    if (backend && backend.getAllMetrics) {
        try { return await backend.getAllMetrics(); } catch (e) { /* fallback */ }
    }
    const out = {};
    for (const [k, v] of memory.entries()) out[k] = Number(v || 0);
    return out;
}

module.exports = { incr, getCounter, getAll };
