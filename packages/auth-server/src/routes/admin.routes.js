'use strict';

const crypto = require('crypto');
const path = require('path');
const express = require('express');
const {
    listAuditEventsAdvanced,
    getAuditEventStats,
    addAuditEvent,
    addPolicyChangeHistory,
    listPolicyChangeHistory,
    createExportJobSnapshot,
    getExportJobSnapshot,
    listExportJobSnapshots,
    getLatestExportJobSnapshot,
    getExportJobByManifestHash,
    getSIEMContainmentSummary
} = require('../../../../infra/db/audit.model');
const { listSessions, getSession: getSessionModel, revokeSession: modelRevokeSession, countSessions } = require('../../../../infra/db/session.model');
const { getTokenState } = require('../../../../infra/redis/token-store');
const sessionManager = require('../session-manager');
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
const {
    containSIEMBatch,
    getContainmentStatus,
    listContainmentStatuses,
    listContainmentHistory,
    acknowledgeSIEMContainment,
    resumeSIEMContainment,
    resolveSIEMContainment
} = require('../../../validation-service/src/siem-containment');
const { getSession } = require('../../../../infra/db/session.model');
const { revokeSession: revokeSessionFromManager } = require('../session-manager');

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

function loadJobManifest(job) {
    if (job?.manifest && typeof job.manifest === 'object') {
        return job.manifest;
    }

    if (job?.manifestPath) {
        try {
            return loadSignedManifestFile(job.manifestPath);
        } catch {
            return null;
        }
    }

    return null;
}

function buildExportIssues({ manifest, verification, chainValid }) {
    const issues = new Set();

    if (!manifest) {
        issues.add('manifest_missing');
    }
    if (verification.hashValid === false) {
        issues.add('manifest_hash_mismatch');
    }
    if (verification.signatureValid === false) {
        issues.add('manifest_signature_invalid');
    }
    if (!chainValid) {
        issues.add('manifest_chain_broken');
    }

    return [...issues];
}

async function evaluateExportJob(job, {
    signingKey,
    jobLookup = null,
    includeContainment = false
} = {}) {
    const manifest = loadJobManifest(job);
    const verification = verifySignedManifest(manifest, { signingKey });
    const previousManifestHash = manifest?.replayProtection?.previousManifestHash || null;
    const previousJob = previousManifestHash && typeof jobLookup === 'function'
        ? await Promise.resolve(jobLookup(previousManifestHash))
        : null;
    const chainValid = !previousManifestHash || Boolean(previousJob);
    const issues = buildExportIssues({ manifest, verification, chainValid });
    const replayProtected = Boolean(verification.ok && chainValid);
    const containment = includeContainment ? await getContainmentStatus(job.batchId) : null;

    return {
        job,
        manifest,
        verification,
        previousManifestHash,
        previousJob,
        chainValid,
        replayProtected,
        issues,
        containment
    };
}

function resolveReplayChainAnchor(assessment, assessmentsByManifestHash) {
    let current = assessment;
    const visited = new Set();
    let brokenAt = null;

    while (current?.previousManifestHash) {
        if (visited.has(current.job.manifestHash)) {
            brokenAt = `cycle:${current.job.manifestHash}`;
            break;
        }

        visited.add(current.job.manifestHash);

        const previous = assessmentsByManifestHash.get(current.previousManifestHash);
        if (!previous) {
            brokenAt = current.previousManifestHash;
            break;
        }

        current = previous;
    }

    return {
        chainKey: brokenAt ? `broken:${brokenAt}` : `root:${current.job.manifestHash}`,
        root: current,
        brokenAt
    };
}

function summarizeReplayChains(assessments) {
    const assessmentsByManifestHash = new Map();
    for (const assessment of assessments) {
        assessmentsByManifestHash.set(assessment.job.manifestHash, assessment);
    }

    const groups = new Map();

    for (const assessment of assessments) {
        const anchor = resolveReplayChainAnchor(assessment, assessmentsByManifestHash);
        const chainKey = anchor.chainKey;
        const group = groups.get(chainKey) || {
            chainKey,
            rootBatchId: anchor.root.job.batchId,
            rootManifestHash: anchor.root.job.manifestHash,
            latestId: Number(anchor.root.job.id || 0),
            latestBatchId: anchor.root.job.batchId,
            latestManifestHash: anchor.root.job.manifestHash,
            latestCreatedAt: anchor.root.job.createdAt,
            batchCount: 0,
            health: 'healthy',
            issueCounts: {
                manifest_missing: 0,
                manifest_hash_mismatch: 0,
                manifest_signature_invalid: 0,
                manifest_chain_broken: 0
            },
            batches: []
        };

        group.batchCount += 1;
        group.batches.push({
            id: assessment.job.id,
            batchId: assessment.job.batchId,
            createdAt: assessment.job.createdAt,
            manifestHash: assessment.job.manifestHash,
            previousManifestHash: assessment.previousManifestHash,
            status: assessment.replayProtected ? 'healthy' : 'degraded',
            replayProtected: assessment.replayProtected,
            chainValid: assessment.chainValid,
            issues: assessment.issues
        });

        const currentCreatedAt = Date.parse(assessment.job.createdAt) || 0;
        const latestCreatedAt = Date.parse(group.latestCreatedAt) || 0;
        if (currentCreatedAt > latestCreatedAt || (
            currentCreatedAt === latestCreatedAt
            && Number(assessment.job.id || 0) > Number(group.latestId || 0)
        )) {
            group.latestId = Number(assessment.job.id || 0);
            group.latestBatchId = assessment.job.batchId;
            group.latestManifestHash = assessment.job.manifestHash;
            group.latestCreatedAt = assessment.job.createdAt;
        }

        for (const issue of assessment.issues) {
            if (Object.prototype.hasOwnProperty.call(group.issueCounts, issue)) {
                group.issueCounts[issue] += 1;
            }
        }

        if (assessment.issues.includes('manifest_chain_broken') || assessment.issues.includes('manifest_missing')) {
            group.health = 'broken';
        } else if (assessment.issues.length > 0 && group.health !== 'broken') {
            group.health = 'degraded';
        }

        groups.set(chainKey, group);
    }

    return [...groups.values()]
        .sort((a, b) => {
            const left = Date.parse(b.latestCreatedAt) || 0;
            const right = Date.parse(a.latestCreatedAt) || 0;
            if (left !== right) return left - right;
            return Number(b.latestId || 0) - Number(a.latestId || 0);
        })
        .map((group) => ({
            ...group,
            batches: group.batches.sort((a, b) => {
                const left = Date.parse(a.createdAt) || 0;
                const right = Date.parse(b.createdAt) || 0;
                if (left !== right) return left - right;
                return Number(a.id || 0) - Number(b.id || 0);
            })
        }));
}

function deriveIncidentSeverity(assessment) {
    if (!assessment?.replayProtected) {
        return 'critical';
    }

    if (assessment.issues?.includes('manifest_chain_broken') || assessment.issues?.includes('manifest_missing')) {
        return 'critical';
    }

    if ((assessment.issues?.length || 0) > 0 || assessment.containment) {
        return 'high';
    }

    return 'info';
}

function buildRootCauseHypothesis(assessment) {
    if (assessment?.issues?.includes('manifest_hash_mismatch')) {
        return 'Manifest checksum changed after export; inspect the manifest file and storage path for tampering or corruption.';
    }

    if (assessment?.issues?.includes('manifest_signature_invalid')) {
        return 'Manifest signature verification failed; confirm the active signing key and any recent key rotation.';
    }

    if (assessment?.issues?.includes('manifest_chain_broken')) {
        return 'Manifest lineage is broken; the previous manifest hash cannot be resolved to a known batch.';
    }

    if (assessment?.issues?.includes('manifest_missing')) {
        return 'The manifest could not be loaded from disk or the database snapshot.';
    }

    if (assessment?.containment?.status) {
        return `Containment is ${assessment.containment.status}; follow the operator workflow to acknowledge or resolve the batch.`;
    }

    return 'No active replay issue detected; continue routine monitoring.';
}

function buildSuggestedActions(job, assessment) {
    const batchId = job.batchId;
    const actions = [];

    if (assessment?.containment?.status === 'paused') {
        actions.push({
            rank: 1,
            action: 'acknowledge_containment',
            description: 'Assign an owner and acknowledge the containment record.',
            riskLevel: 'low',
            request: {
                method: 'POST',
                path: `/admin/audit/export/jobs/${batchId}/containment/acknowledge`,
                body: { note: 'acknowledged from quick-response payload' }
            }
        });
        actions.push({
            rank: 2,
            action: 'resolve_containment',
            description: 'Resolve the paused containment once the batch has been reviewed.',
            riskLevel: 'medium',
            request: {
                method: 'POST',
                path: `/admin/audit/export/jobs/${batchId}/containment/resolve`,
                body: { note: 'resolve after review' }
            }
        });
    }

    if (assessment?.issues?.includes('manifest_hash_mismatch') || assessment?.issues?.includes('manifest_signature_invalid')) {
        actions.push({
            rank: actions.length + 1,
            action: 'review_manifest',
            description: 'Inspect the manifest file and signing key history for drift or tampering.',
            riskLevel: 'low',
            request: {
                method: 'GET',
                path: `/admin/audit/export/jobs/${batchId}/manifest`,
                body: null
            }
        });
    }

    if (assessment?.issues?.includes('manifest_chain_broken')) {
        actions.push({
            rank: actions.length + 1,
            action: 'inspect_lineage',
            description: 'Use the replay-chain summary to identify the missing predecessor batch.',
            riskLevel: 'low',
            request: {
                method: 'GET',
                path: `/admin/audit/export/replay-chains?limit=10`,
                body: null
            }
        });
    }

    if (actions.length === 0) {
        actions.push({
            rank: 1,
            action: 'monitor',
            description: 'No active remediation is required; continue monitoring the batch health.',
            riskLevel: 'none',
            request: {
                method: 'GET',
                path: `/admin/audit/export/jobs/${batchId}/health`,
                body: null
            }
        });
    }

    return actions;
}

function buildQuickResponsePayload(job, assessment) {
    const severity = deriveIncidentSeverity(assessment);
    const incidentId = `inc-${job.batchId}`;
    const payload = {
        incidentId,
        severity,
        timestamp: new Date().toISOString(),
        batchSummary: {
            batchId: job.batchId,
            manifestHash: job.manifestHash,
            chainSha256: job.chainSha256,
            recordCount: job.recordCount,
            policyProfile: job.policyProfile,
            manifestPath: job.manifestPath,
            evidencePath: assessment.containment?.evidencePath || null,
            containmentStatus: assessment.containment?.status || null
        },
        verification: {
            hashValid: assessment.verification.hashValid,
            signatureValid: assessment.verification.signatureValid,
            chainValid: assessment.chainValid,
            replayProtected: assessment.replayProtected,
            issues: assessment.issues
        },
        rootCauseHypothesis: buildRootCauseHypothesis(assessment),
        suggestedActions: buildSuggestedActions(job, assessment)
    };

    payload.markdownSummary = renderIncidentMarkdown(payload);
    payload.plainTextSummary = renderIncidentPlainText(payload);
    payload.acknowledgmentRequest = {
        method: 'POST',
        path: `/admin/audit/export/jobs/${job.batchId}/containment/acknowledge`,
        body: { note: `acknowledged from ${incidentId}` }
    };

    return payload;
}

function renderIncidentMarkdown(payload) {
    const lines = [
        `# Incident ${payload.incidentId}`,
        `**Severity:** ${String(payload.severity).toUpperCase()}`,
        `**Batch:** ${payload.batchSummary.batchId}`,
        `**Manifest Hash:** ${payload.batchSummary.manifestHash}`,
        `**Chain SHA-256:** ${payload.batchSummary.chainSha256}`,
        '',
        `**Replay Protected:** ${payload.verification.replayProtected ? 'yes' : 'no'}`,
        `**Root Cause:** ${payload.rootCauseHypothesis}`,
        '',
        '## Suggested Actions'
    ];

    for (const action of payload.suggestedActions) {
        lines.push(`- [${action.rank}] **${action.action}** — ${action.description}`);
    }

    return lines.join('\n');
}

function renderIncidentPlainText(payload) {
    const lines = [
        `INCIDENT ${payload.incidentId}`,
        `Severity: ${String(payload.severity).toUpperCase()}`,
        `Batch: ${payload.batchSummary.batchId}`,
        `Manifest Hash: ${payload.batchSummary.manifestHash}`,
        `Chain SHA-256: ${payload.batchSummary.chainSha256}`,
        `Replay Protected: ${payload.verification.replayProtected ? 'yes' : 'no'}`,
        `Root Cause: ${payload.rootCauseHypothesis}`
    ];

    for (const action of payload.suggestedActions) {
        lines.push(`Action ${action.rank}: ${action.action} - ${action.description}`);
    }

    return lines.join('\n');
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

    // Admin auth, basic rate limiting, and lightweight metrics
    const rateLimit = require('../admin-rate-limit');
    const metrics = require('../metrics');
    const promMetrics = require('../prom-metrics');

    router.use(requireAdminAuth);
    router.use(rateLimit);

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
        const pausedContainments = await listContainmentStatuses({ limit: 50, status: 'paused' });
        const containmentSummary = await getSIEMContainmentSummary();
        return res.json({
            ok: true,
            schema: SCHEMA_VERSION,
            generatedAt: new Date().toISOString(),
            stats,
            containmentSummary,
            containments: {
                pausedCount: pausedContainments.length,
                latestPaused: pausedContainments[0] || null
            },
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

        const containments = await listContainmentStatuses({ limit: 1000 });
        const containmentMap = new Map(containments.map((row) => [row.batchId, row]));
        const items = jobs.map((job) => {
            const containment = containmentMap.get(job.batchId) || null;
            return {
                ...job,
                containment,
                ingestionPaused: Boolean(containment)
            };
        });

        return res.json({
            ok: true,
            count: items.length,
            items
        });
    });

    // Admin: bulk revoke all sessions for a user
    router.post('/sessions/revoke', async (req, res) => {
        const uid = String(req.query.uid || req.body?.uid || '').trim();
        if (!uid) return res.status(400).json({ ok: false, error: 'missing_uid' });

        const actor = String(req.headers['x-admin-actor'] || 'admin').slice(0, 128);
        const ip = req.security?.clientIp || req.ip || 'unknown';

        try {
            const rows = await listSessions({ uid, limit: 10000, offset: 0, activeOnly: false });
            let count = 0;
            for (const r of rows) {
                try {
                    await modelRevokeSession(r.sessionId, new Date().toISOString());
                    await sessionManager.revokeSession(r.sessionId, uid, null);
                    count++;
                } catch (e) {
                    // continue revoking others
                }
            }

            addAuditEvent({
                type: 'admin_bulk_revoke_sessions',
                severity: 'critical',
                allow: true,
                uid,
                count,
                actor,
                ip,
                at: new Date().toISOString(),
                details: { reason: req.body?.reason || null }
            });

            try { metrics.incr('admin.bulk_revoke.count', count); } catch (e) { }
            try { promMetrics.incAdmin('bulk_revoke', count); } catch (e) { }

            return res.json({ ok: true, uid, count });
        } catch (err) {
            logAnomaly('admin_bulk_revoke_failed', { ip, uid, message: err.message });
            return res.status(500).json({ ok: false, error: 'bulk_revoke_failed' });
        }
    });

    // Admin: list sessions with pagination and filters
    router.get('/sessions', async (req, res) => {
        const limit = parseLimit(req.query.limit, { fallback: 50, max: 1000 });
        const offset = Math.max(0, Number(req.query.offset || 0));
        const uid = req.query.uid ? String(req.query.uid).trim() : null;
        const activeOnly = parseBoolean(req.query.activeOnly) === true;

        try {
            const total = await countSessions({ uid, activeOnly });
            const items = await listSessions({ uid, limit, offset, activeOnly });

            addAuditEvent({
                type: 'admin_list_sessions',
                severity: 'info',
                allow: true,
                actor: String(req.headers['x-admin-actor'] || 'admin').slice(0, 128),
                ip: req.security?.clientIp || req.ip || 'unknown',
                at: new Date().toISOString(),
                details: { uid, limit, offset, activeOnly }
            });

            try { metrics.incr('admin.list_sessions.count', items.length); } catch (e) { }
            try { promMetrics.incAdmin('list_sessions', items.length); } catch (e) { }

            return res.json({ ok: true, total, count: items.length, limit, offset, items });
        } catch (err) {
            logAnomaly('admin_list_sessions_failed', { message: err.message });
            return res.status(500).json({ ok: false, error: 'list_failed' });
        }
    });

    // Admin: get details for a specific session
    router.get('/sessions/:sid', async (req, res) => {
        const sid = String(req.params.sid || '').trim();
        if (!sid) return res.status(400).json({ ok: false, error: 'missing_sid' });

        try {
            const row = await getSessionModel(sid);
            if (!row) return res.status(404).json({ ok: false, error: 'session_not_found' });

            const state = await getTokenState(sid, null);
            const actor = String(req.headers['x-admin-actor'] || 'admin').slice(0, 128);
            const ip = req.security?.clientIp || req.ip || 'unknown';

            addAuditEvent({
                type: 'admin_view_session',
                severity: 'info',
                allow: true,
                sessionId: sid,
                actor,
                ip,
                at: new Date().toISOString()
            });

            try { metrics.incr('admin.view_session.count'); } catch (e) { }
            try { promMetrics.incAdmin('view_session', 1); } catch (e) { }

            return res.json({ ok: true, session: row, state: state || null });
        } catch (err) {
            return res.status(500).json({ ok: false, error: 'session_lookup_failed' });
        }
    });

    router.get('/audit/export/jobs/:batchId', async (req, res) => {
        const includeSnapshot = parseBoolean(String(req.query.includeSnapshot || 'false')) === true;
        const job = await getExportJobSnapshot(req.params.batchId, { includeSnapshot });
        if (!job) {
            return res.status(404).json({ ok: false, error: 'export_job_not_found' });
        }

        const containment = await getContainmentStatus(req.params.batchId);

        return res.json({
            ok: true,
            job,
            containment: containment || null,
            ingestionPaused: Boolean(containment)
        });
    });

    router.get('/audit/export/jobs/:batchId/containment', async (req, res) => {
        const containment = await getContainmentStatus(req.params.batchId);
        if (!containment) {
            return res.status(404).json({ ok: false, error: 'containment_not_found' });
        }

        return res.json({
            ok: true,
            ingestionPaused: containment.status === 'paused',
            containment
        });
    });

    router.get('/audit/export/jobs/:batchId/containment/history', async (req, res) => {
        const limit = parseLimit(req.query.limit, { fallback: 100, max: 1000 });
        const beforeId = parseOptionalPositiveInt(req.query.beforeId);
        const afterId = parseOptionalPositiveInt(req.query.afterId);

        const history = await listContainmentHistory(req.params.batchId, { limit, beforeId, afterId });
        return res.json({ ok: true, count: history.length, items: history });
    });

    router.post('/audit/export/jobs/:batchId/containment', async (req, res) => {
        const job = await getExportJobSnapshot(req.params.batchId, { includeSnapshot: true });
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

        const containment = await containSIEMBatch({
            batchId: req.params.batchId,
            owner: String(req.body?.owner || req.headers['x-admin-actor'] || 'admin').slice(0, 128),
            severity: String(req.body?.severity || 'high').toLowerCase(),
            reason: String(req.body?.reason || 'manual_pause').slice(0, 2048),
            verification: req.body?.verification || null,
            exportJob: job,
            manifest,
            actor: String(req.headers['x-admin-actor'] || 'admin').slice(0, 128)
        });

        return res.status(201).json({
            ok: true,
            ingestionPaused: true,
            containment
        });
    });

    router.post('/audit/export/jobs/:batchId/containment/acknowledge', async (req, res) => {
        const actor = String(req.headers['x-admin-actor'] || 'admin').slice(0, 128);
        const note = String(req.body?.note || '').slice(0, 2048) || null;

        try {
            const containment = await acknowledgeSIEMContainment({
                batchId: req.params.batchId,
                actor,
                note
            });

            return res.json({ ok: true, containment });
        } catch (err) {
            return res.status(404).json({ ok: false, error: err.message });
        }
    });

    router.post('/audit/export/jobs/:batchId/containment/resume', async (req, res) => {
        const actor = String(req.headers['x-admin-actor'] || 'admin').slice(0, 128);
        const note = String(req.body?.note || '').slice(0, 2048) || null;

        try {
            const containment = await resumeSIEMContainment({
                batchId: req.params.batchId,
                actor,
                note
            });

            return res.json({ ok: true, containment });
        } catch (err) {
            return res.status(404).json({ ok: false, error: err.message });
        }
    });

    router.post('/audit/export/jobs/:batchId/containment/resolve', async (req, res) => {
        const actor = String(req.headers['x-admin-actor'] || 'admin').slice(0, 128);
        const note = String(req.body?.note || '').slice(0, 2048) || null;

        try {
            const containment = await resolveSIEMContainment({
                batchId: req.params.batchId,
                actor,
                note
            });

            return res.json({ ok: true, containment });
        } catch (err) {
            return res.status(404).json({ ok: false, error: err.message });
        }
    });

    router.get('/audit/export/containments', async (req, res) => {
        const limit = parseLimit(req.query.limit, { fallback: 100, max: 1000 });
        const beforeId = parseOptionalPositiveInt(req.query.beforeId);
        const afterId = parseOptionalPositiveInt(req.query.afterId);
        const status = req.query.status ? String(req.query.status) : null;

        const rows = await listContainmentStatuses({ limit, beforeId, afterId, status });
        return res.json({ ok: true, count: rows.length, items: rows });
    });

    // Administrative session controls
    router.post('/sessions/:sid/revoke', async (req, res) => {
        const sid = String(req.params.sid || '').trim();
        if (!sid) return res.status(400).json({ ok: false, error: 'missing_session_id' });

        const session = await getSession(sid);
        const actor = String(req.headers['x-admin-actor'] || 'admin').slice(0, 128);
        try {
            await revokeSessionFromManager(sid, session ? session.uid : null, null);

            // Audit/anomaly log
            logAnomaly('admin_session_revoked', {
                actor,
                sid,
                uid: session ? session.uid : null,
                ip: req.security?.clientIp || req.ip || 'unknown'
            });

            return res.json({ ok: true, sessionId: sid, uid: session ? session.uid : null, existed: Boolean(session) });
        } catch (err) {
            logAnomaly('admin_session_revoke_failed', {
                actor,
                sid,
                uid: session ? session.uid : null,
                message: err.message
            });
            return res.status(500).json({ ok: false, error: 'revoke_failed' });
        }
    });

    // GET /admin/sessions?uid=<userId> — list sessions for a user (or all if omitted)
    router.get('/sessions', async (req, res) => {
        const uid = req.query.uid ? String(req.query.uid) : null;
        const limit = Number(req.query.limit || 100);
        const offset = Number(req.query.offset || 0);
        const activeOnly = typeof req.query.activeOnly !== 'undefined' ? String(req.query.activeOnly) === 'true' : false;
        try {
            const { listSessions, countSessions } = require('../../../../infra/db/session.model');
            const limitVal = Math.max(1, Math.min(1000, limit));
            const offsetVal = Math.max(0, offset);
            const items = await listSessions({ uid, limit: limitVal, offset: offsetVal, activeOnly });
            const total = await countSessions({ uid, activeOnly });
            return res.json({ ok: true, total, count: items.length, limit: limitVal, offset: offsetVal, items });
        } catch (err) {
            logAnomaly('admin_session_list_failed', { message: err.message });
            return res.status(500).json({ ok: false, error: 'list_failed' });
        }
    });

    router.get('/audit/export/containments/summary', async (_req, res) => {
        const summary = await getSIEMContainmentSummary();
        return res.json({
            ok: true,
            generatedAt: new Date().toISOString(),
            summary
        });
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

        const verificationOk = verification.ok && chainValid;
        let containment = await getContainmentStatus(req.params.batchId);

        if (!verificationOk) {
            const actor = String(req.headers['x-admin-actor'] || 'admin').slice(0, 128);
            const reason = !verification.hashValid
                ? 'manifest_hash_mismatch'
                : verification.signatureValid === false
                    ? 'manifest_signature_invalid'
                    : !chainValid
                        ? 'manifest_chain_broken'
                        : 'verification_failed';

            addAuditEvent({
                type: 'siem_export_verification_failed',
                severity: 'critical',
                allow: false,
                reason,
                batchId: job.batchId,
                manifestHash: job.manifestHash,
                chainValid,
                verification,
                at: new Date().toISOString(),
                details: {
                    manifestPath: job.manifestPath
                }
            });

            containment = await containSIEMBatch({
                batchId: req.params.batchId,
                owner: actor,
                severity: 'critical',
                reason,
                verification: {
                    ...verification,
                    chainValid,
                    replayProtected: false
                },
                exportJob: job,
                manifest,
                actor
            });
        }

        return res.json({
            ok: true,
            batchId: job.batchId,
            manifestHash: job.manifestHash,
            chainValid,
            replayProtected: verificationOk,
            ingestionPaused: Boolean(containment),
            containment: containment || null,
            verification: {
                ...verification,
                chainValid,
                replayProtected: verificationOk
            }
        });
    });

    router.get('/audit/export/jobs/:batchId/health', async (req, res) => {
        const job = await getExportJobSnapshot(req.params.batchId, { includeSnapshot: false });
        if (!job) {
            return res.status(404).json({ ok: false, error: 'export_job_not_found' });
        }

        const signingKey = process.env.SIEM_MANIFEST_SIGNING_KEY || process.env.SIEM_EXPORT_SIGNING_KEY || '';
        const assessment = await evaluateExportJob(job, {
            signingKey,
            jobLookup: (manifestHash) => getExportJobByManifestHash(manifestHash, { includeSnapshot: false }),
            includeContainment: true
        });

        return res.json({
            ok: true,
            batchId: job.batchId,
            status: assessment.replayProtected ? 'healthy' : 'degraded',
            replayProtected: assessment.replayProtected,
            chainValid: assessment.chainValid,
            issues: assessment.issues,
            job: {
                id: job.id,
                createdAt: job.createdAt,
                format: job.format,
                policyProfile: job.policyProfile,
                recordCount: job.recordCount,
                manifestHash: job.manifestHash,
                previousManifestHash: assessment.previousManifestHash,
                manifestPath: job.manifestPath
            },
            verification: {
                ...assessment.verification,
                chainValid: assessment.chainValid,
                replayProtected: assessment.replayProtected
            },
            lineage: {
                previousBatchId: assessment.previousJob?.batchId || null,
                previousManifestHash: assessment.previousManifestHash,
                currentManifestHash: job.manifestHash
            },
            containment: assessment.containment
                ? {
                    batchId: assessment.containment.batchId,
                    status: assessment.containment.status,
                    owner: assessment.containment.owner,
                    severity: assessment.containment.severity,
                    reason: assessment.containment.reason,
                    lastStatusAt: assessment.containment.lastStatusAt
                }
                : null
        });
    });

    router.get('/audit/export/jobs/:batchId/quick-response', async (req, res) => {
        const job = await getExportJobSnapshot(req.params.batchId, { includeSnapshot: false });
        if (!job) {
            return res.status(404).json({ ok: false, error: 'export_job_not_found' });
        }

        const format = String(req.query.format || 'json').trim().toLowerCase();
        if (!['json', 'markdown', 'text'].includes(format)) {
            return res.status(400).json({
                ok: false,
                error: 'invalid_format',
                supported: ['json', 'markdown', 'text']
            });
        }

        const signingKey = process.env.SIEM_MANIFEST_SIGNING_KEY || process.env.SIEM_EXPORT_SIGNING_KEY || '';
        const assessment = await evaluateExportJob(job, {
            signingKey,
            jobLookup: (manifestHash) => getExportJobByManifestHash(manifestHash, { includeSnapshot: false }),
            includeContainment: true
        });

        const payload = buildQuickResponsePayload(job, assessment);

        addAuditEvent({
            type: 'siem_export_quick_response_generated',
            severity: assessment.replayProtected ? 'info' : 'warn',
            allow: true,
            batchId: job.batchId,
            manifestHash: job.manifestHash,
            at: payload.timestamp,
            details: {
                format,
                incidentId: payload.incidentId
            }
        });

        if (format === 'markdown') {
            res.setHeader('content-type', 'text/markdown; charset=utf-8');
            res.setHeader('x-vault-incident-id', payload.incidentId);
            return res.send(payload.markdownSummary);
        }

        if (format === 'text') {
            res.setHeader('content-type', 'text/plain; charset=utf-8');
            res.setHeader('x-vault-incident-id', payload.incidentId);
            return res.send(payload.plainTextSummary);
        }

        return res.json({
            ok: true,
            ...payload
        });
    });

    router.get('/audit/export/replay-chains', async (req, res) => {
        const limit = parseLimit(req.query.limit, { fallback: 50, max: 100 });
        const signingKey = process.env.SIEM_MANIFEST_SIGNING_KEY || process.env.SIEM_EXPORT_SIGNING_KEY || '';
        const jobs = await listExportJobSnapshots({ limit: 1000, includeSnapshot: false });
        const jobMap = new Map(jobs.map((job) => [job.manifestHash, job]));
        const assessments = [];

        for (const job of jobs) {
            assessments.push(await evaluateExportJob(job, {
                signingKey,
                jobLookup: (manifestHash) => jobMap.get(manifestHash) || null,
                includeContainment: false
            }));
        }

        const chains = summarizeReplayChains(assessments);
        const visibleChains = chains.slice(0, limit);
        const totals = chains.reduce((acc, chain) => {
            acc.batches += chain.batchCount;
            acc.chains += 1;
            if (chain.health === 'healthy') acc.healthyChains += 1;
            if (chain.health === 'degraded') acc.degradedChains += 1;
            if (chain.health === 'broken') acc.brokenChains += 1;
            return acc;
        }, { chains: 0, batches: 0, healthyChains: 0, degradedChains: 0, brokenChains: 0 });

        return res.json({
            ok: true,
            count: visibleChains.length,
            totals,
            chains: visibleChains
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

        // fetch a larger window from the DB and apply export filters in-memory so
        // pagination/limit applies to the filtered results rather than the raw DB page
        const sourceLimit = 5000; // upper bound to allow filtering by type/outcome
        const events = await listAuditEventsAdvanced({
            limit: sourceLimit,
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

        addAuditEvent({
            type: 'siem_export_created',
            severity: 'info',
            allow: true,
            batchId,
            manifestHash: manifest.manifestHash,
            recordCount: records.length,
            format,
            policyProfile,
            manifestPath,
            at: new Date().toISOString(),
            details: {
                exportJobId: exportJob?.id || null,
                nextCursor: pageCursor
            }
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
