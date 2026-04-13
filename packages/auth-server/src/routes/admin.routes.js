'use strict';

const crypto = require('crypto');
const path = require('path');
const express = require('express');
const {
    listAuditEventsAdvanced,
    getAuditEventStats,
    addPolicyChangeHistory,
    listPolicyChangeHistory,
    createExportJobSnapshot,
    getExportJobSnapshot,
    listExportJobSnapshots,
    getLatestExportJobSnapshot,
    getExportJobByManifestHash
} = require('../../../../infra/db/audit.model');
const {
    logAnomaly,
    getAnomalyStats,
    getAnomalyPressure,
    getRecentAnomalies,
    getRecentEscalations,
    getAnomalyInsights
} = require('../anomaly-detector');
const {
    getPolicyProfile,
    setPolicyProfile,
    POLICY_PROFILES,
    simulatePolicyProfiles,
    recommendPolicyProfile
} = require('../../../validation-service/src/decision-engine');
const {
    SCHEMA_VERSION,
    exportSiemRecords,
    normalizeExportFilters,
    buildIntegrityMetadata,
    signExportPayload,
    createBatchId,
    buildSignedManifest,
    persistSignedManifestFile,
    loadSignedManifestFile,
    verifySignedManifest
} = require('../../../validation-service/src/siem-exporter');

function parseLimit(raw, { fallback = 100, min = 1, max = 1000 } = {}) {
    const value = Number(raw);
    if (!Number.isFinite(value)) return fallback;
    return Math.max(min, Math.min(max, Math.floor(value)));
}

function parseOptionalPositiveInt(raw) {
    const value = Number(raw);
    if (!Number.isFinite(value) || value <= 0) return null;
    return Math.floor(value);
}

function parseBoolean(raw) {
    if (typeof raw === 'boolean') return raw;
    if (raw === 'true') return true;
    if (raw === 'false') return false;
    return null;
}

function nextCursor(events = []) {
    if (!Array.isArray(events) || events.length === 0) return null;
    const id = Number(events[events.length - 1]?.id);
    return Number.isFinite(id) && id > 0 ? id : null;
}

function manifestDirectory() {
    return String(process.env.SIEM_MANIFEST_DIR || '').trim()
        || path.join(process.cwd(), 'infra', 'db', 'export-manifests');
}

function configuredAdminToken() {
    return String(process.env.ADMIN_API_TOKEN || '').trim();
}

function extractAdminToken(req) {
    const direct = req.headers['x-admin-token'];
    if (direct) return String(direct).trim();

    const auth = String(req.headers.authorization || '');
    if (auth.toLowerCase().startsWith('bearer ')) {
        return auth.slice(7).trim();
    }

    return '';
}

function safeTokenEqual(left, right) {
    const a = Buffer.from(String(left || ''));
    const b = Buffer.from(String(right || ''));
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}

function requireAdminAuth(req, res, next) {
    const expected = configuredAdminToken();
    if (!expected) {
        return res.status(503).json({
            ok: false,
            error: 'admin_api_disabled',
            message: 'set ADMIN_API_TOKEN to enable admin endpoints'
        });
    }

    const provided = extractAdminToken(req);
    if (!provided || !safeTokenEqual(provided, expected)) {
        logAnomaly('admin_auth_failed', {
            ip: req.security?.clientIp || req.ip || 'unknown',
            path: req.originalUrl
        });
        return res.status(401).json({ ok: false, error: 'unauthorized' });
    }

    return next();
}

function adminRoutes() {
    const router = express.Router();

    router.use(requireAdminAuth);

    router.get('/policy/profile', (req, res) => {
        return res.json({
            ok: true,
            active: getPolicyProfile(),
            available: Object.keys(POLICY_PROFILES)
        });
    });

    router.post('/policy/profile', async (req, res) => {
        const requested = String(req.body?.profile || '').trim().toLowerCase();
        if (!requested || !POLICY_PROFILES[requested]) {
            return res.status(400).json({
                ok: false,
                error: 'invalid_profile',
                available: Object.keys(POLICY_PROFILES)
            });
        }

        const previous = getPolicyProfile();
        const active = setPolicyProfile(requested);
        const actor = String(req.headers['x-admin-actor'] || 'admin').slice(0, 128);
        const ip = req.security?.clientIp || req.ip || 'unknown';

        logAnomaly('admin_policy_profile_changed', {
            ip,
            previous,
            active
        });

        try {
            const history = await addPolicyChangeHistory({
                previousProfile: previous,
                activeProfile: active,
                actor,
                ip,
                requestId: req.requestId || null,
                rationale: req.body?.rationale || null
            });

            return res.json({
                ok: true,
                previous,
                active,
                history,
                available: Object.keys(POLICY_PROFILES)
            });
        } catch (err) {
            logAnomaly('admin_policy_profile_persist_error', {
                ip,
                previous,
                active,
                message: err.message
            });
            return res.status(500).json({ ok: false, error: 'policy_history_persist_failed' });
        }
    });

    router.get('/policy/history', async (req, res) => {
        const limit = parseLimit(req.query.limit, { fallback: 100, max: 1000 });
        const beforeId = parseOptionalPositiveInt(req.query.beforeId);
        const afterId = parseOptionalPositiveInt(req.query.afterId);

        const rows = await listPolicyChangeHistory({ limit, beforeId, afterId });
        return res.json({
            ok: true,
            count: rows.length,
            items: rows
        });
    });

    router.get('/anomalies/stats', (req, res) => {
        return res.json({
            ok: true,
            policyProfile: getPolicyProfile(),
            pressure: getAnomalyPressure(),
            anomalies: getAnomalyStats()
        });
    });

    router.get('/anomalies/recent', (req, res) => {
        const limit = parseLimit(req.query.limit, { fallback: 100, max: 500 });
        const severity = String(req.query.severity || '').trim().toLowerCase();
        const type = String(req.query.type || '').trim().toLowerCase();

        const rows = getRecentAnomalies(limit * 3)
            .filter((item) => !severity || String(item.severity || '').toLowerCase() === severity)
            .filter((item) => !type || String(item.type || '').toLowerCase().includes(type))
            .slice(0, limit);

        return res.json({
            ok: true,
            count: rows.length,
            items: rows
        });
    });

    router.get('/anomalies/escalations', (req, res) => {
        const limit = parseLimit(req.query.limit, { fallback: 100, max: 300 });
        const minLevel = parseLimit(req.query.minLevel, { fallback: 1, min: 1, max: 3 });

        const rows = getRecentEscalations(limit * 3)
            .filter((item) => Number(item.level || 0) >= minLevel)
            .slice(0, limit);

        return res.json({
            ok: true,
            count: rows.length,
            items: rows
        });
    });

    router.get('/anomalies/insights', (req, res) => {
        const windowMs = parseLimit(req.query.windowMs, {
            fallback: 15 * 60 * 1000,
            min: 60_000,
            max: 24 * 60 * 60 * 1000
        });
        const topN = parseLimit(req.query.topN, { fallback: 8, min: 3, max: 20 });

        return res.json({
            ok: true,
            policyProfile: getPolicyProfile(),
            insights: getAnomalyInsights({ windowMs, topN })
        });
    });

    router.post('/policy/simulate', (req, res) => {
        const raw = req.body?.signals || {};
        const signals = {
            signatureValid: parseBoolean(raw.signatureValid),
            decryptionValid: parseBoolean(raw.decryptionValid),
            contextValid: parseBoolean(raw.contextValid),
            replayValid: parseBoolean(raw.replayValid),
            riskScore: raw.riskScore,
            contextDrift: raw.contextDrift
        };

        const missing = Object.entries(signals)
            .filter(([k, v]) => ['signatureValid', 'decryptionValid', 'contextValid', 'replayValid'].includes(k) && v === null)
            .map(([k]) => k);

        if (missing.length > 0) {
            return res.status(400).json({
                ok: false,
                error: 'invalid_signals',
                message: 'signatureValid, decryptionValid, contextValid and replayValid must be boolean',
                fields: missing
            });
        }

        const profiles = req.body?.profiles;
        const simulation = simulatePolicyProfiles(signals, profiles);
        const recommendation = recommendPolicyProfile(signals, profiles);

        return res.json({
            ok: true,
            simulation,
            recommendation: {
                profile: recommendation.recommended,
                rationale: recommendation.rationale
            }
        });
    });

    router.get('/audit/export/meta', async (_req, res) => {
        const latestJob = await getLatestExportJobSnapshot({ includeSnapshot: false });
        const stats = await getAuditEventStats();
        return res.json({
            ok: true,
            schema: SCHEMA_VERSION,
            generatedAt: new Date().toISOString(),
            stats,
            latestJob: latestJob
                ? {
                    batchId: latestJob.batchId,
                    createdAt: latestJob.createdAt,
                    recordCount: latestJob.recordCount,
                    manifestHash: latestJob.manifestHash
                }
                : null
        });
    });

    router.get('/audit/export/jobs', async (req, res) => {
        const limit = parseLimit(req.query.limit, { fallback: 100, max: 1000 });
        const beforeId = parseOptionalPositiveInt(req.query.beforeId);
        const afterId = parseOptionalPositiveInt(req.query.afterId);

        const jobs = await listExportJobSnapshots({
            limit,
            beforeId,
            afterId,
            includeSnapshot: false
        });

        return res.json({
            ok: true,
            count: jobs.length,
            items: jobs
        });
    });

    router.get('/audit/export/jobs/:batchId', async (req, res) => {
        const includeSnapshot = parseBoolean(String(req.query.includeSnapshot || 'false')) === true;
        const job = await getExportJobSnapshot(req.params.batchId, { includeSnapshot });
        if (!job) {
            return res.status(404).json({ ok: false, error: 'export_job_not_found' });
        }

        return res.json({ ok: true, job });
    });

    router.get('/audit/export/jobs/:batchId/manifest', async (req, res) => {
        const job = await getExportJobSnapshot(req.params.batchId, { includeSnapshot: false });
        if (!job) {
            return res.status(404).json({ ok: false, error: 'export_job_not_found' });
        }

        let manifest = job.manifest || null;
        if (!manifest && job.manifestPath) {
            try {
                manifest = loadSignedManifestFile(job.manifestPath);
            } catch {
                manifest = null;
            }
        }

        if (!manifest) {
            return res.status(404).json({ ok: false, error: 'manifest_not_found' });
        }

        return res.json({
            ok: true,
            batchId: job.batchId,
            manifest
        });
    });

    router.get('/audit/export/jobs/:batchId/verify', async (req, res) => {
        const job = await getExportJobSnapshot(req.params.batchId, { includeSnapshot: false });
        if (!job) {
            return res.status(404).json({ ok: false, error: 'export_job_not_found' });
        }

        let manifest = job.manifest || null;
        if (!manifest && job.manifestPath) {
            try {
                manifest = loadSignedManifestFile(job.manifestPath);
            } catch {
                manifest = null;
            }
        }

        const signingKey = process.env.SIEM_MANIFEST_SIGNING_KEY || process.env.SIEM_EXPORT_SIGNING_KEY || '';
        const verification = verifySignedManifest(manifest, { signingKey });

        let chainValid = true;
        const previousManifestHash = manifest?.replayProtection?.previousManifestHash || null;
        if (previousManifestHash) {
            const prev = await getExportJobByManifestHash(previousManifestHash, { includeSnapshot: false });
            chainValid = Boolean(prev);
        }

        return res.json({
            ok: true,
            batchId: job.batchId,
            manifestHash: job.manifestHash,
            chainValid,
            replayProtected: verification.ok && chainValid,
            verification
        });
    });

    router.get('/audit/export', async (req, res) => {
        const limit = parseLimit(req.query.limit, { fallback: 250, max: 5000 });
        const format = String(req.query.format || 'json').trim().toLowerCase();
        const cursor = parseOptionalPositiveInt(req.query.cursor);
        const sinceId = parseOptionalPositiveInt(req.query.sinceId);
        const filters = normalizeExportFilters({
            severity: req.query.severity,
            type: req.query.type,
            outcome: req.query.outcome,
            from: req.query.from,
            to: req.query.to
        });

        if (format !== 'json' && format !== 'ndjson') {
            return res.status(400).json({ ok: false, error: 'invalid_format', supported: ['json', 'ndjson'] });
        }

        const events = await listAuditEventsAdvanced({
            limit,
            beforeId: cursor,
            afterId: sinceId,
            sort: 'desc'
        });
        const policyProfile = getPolicyProfile();
        const records = exportSiemRecords(events, {
            format: 'json',
            policyProfile,
            serviceName: 'vaultjs-auth-server',
            filters
        });

        const serializedRecords = JSON.stringify(records);
        const integrity = buildIntegrityMetadata(records, serializedRecords);
        const pageCursor = nextCursor(events);
        const signingKey = process.env.SIEM_EXPORT_SIGNING_KEY;
        const manifestSigningKey = process.env.SIEM_MANIFEST_SIGNING_KEY || signingKey;

        const batchId = createBatchId('siem');
        const latestJob = await getLatestExportJobSnapshot({ includeSnapshot: false });
        const manifest = buildSignedManifest({
            batchId,
            createdAt: new Date().toISOString(),
            exportSchema: SCHEMA_VERSION,
            format,
            policyProfile,
            filters,
            recordCount: records.length,
            checksumSha256: integrity.checksumSha256,
            chainSha256: integrity.chainSha256,
            snapshotChecksumSha256: integrity.checksumSha256,
            previousManifestHash: latestJob?.manifestHash || null,
            serviceName: 'vaultjs-auth-server'
        }, {
            signingKey: manifestSigningKey
        });

        const manifestPath = persistSignedManifestFile(manifest, {
            directory: manifestDirectory()
        });

        const exportJob = await createExportJobSnapshot({
            batchId,
            createdAt: manifest.createdAt,
            format,
            policyProfile,
            filters,
            recordCount: records.length,
            checksumSha256: integrity.checksumSha256,
            chainSha256: integrity.chainSha256,
            signatureSha256: signExportPayload(serializedRecords, signingKey),
            manifestPath,
            manifestHash: manifest.manifestHash,
            previousManifestHash: manifest.replayProtection?.previousManifestHash || null,
            snapshot: records,
            manifest
        });

        if (format === 'ndjson') {
            const payload = records.map((record) => JSON.stringify(record)).join('\n');
            const signature = signExportPayload(payload, signingKey);

            res.setHeader('content-type', 'application/x-ndjson; charset=utf-8');
            res.setHeader('x-vault-export-batch-id', batchId);
            res.setHeader('x-vault-export-manifest-hash', manifest.manifestHash);
            res.setHeader('x-vault-export-checksum-sha256', integrity.checksumSha256);
            res.setHeader('x-vault-export-chain-sha256', integrity.chainSha256);
            res.setHeader('x-vault-export-schema', SCHEMA_VERSION);
            if (pageCursor !== null) res.setHeader('x-vault-export-next-cursor', String(pageCursor));
            if (signature) res.setHeader('x-vault-export-signature', signature);
            return res.send(payload ? `${payload}\n` : '');
        }

        const signature = signExportPayload(serializedRecords, signingKey);

        return res.json({
            ok: true,
            schema: SCHEMA_VERSION,
            generatedAt: new Date().toISOString(),
            policyProfile,
            format: 'json',
            batchId,
            exportJobId: exportJob?.id || null,
            cursor: pageCursor,
            count: records.length,
            manifestHash: manifest.manifestHash,
            manifestPath,
            checksumSha256: integrity.checksumSha256,
            chainSha256: integrity.chainSha256,
            signatureSha256: signature,
            filters,
            records
        });
    });

    return router;
}

module.exports = { adminRoutes };
