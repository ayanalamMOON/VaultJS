'use strict';

const crypto = require('crypto');
const { runAsync, allAsync, getAsync } = require('./connection');

// Queue memory buffer for write-behind
let auditQueue = [];
let batchProcessing = false;

const BATCH_SIZE = 50;

async function processQueue() {
    if (batchProcessing || auditQueue.length === 0) return;
    batchProcessing = true;

    const batch = auditQueue.splice(0, BATCH_SIZE);

    try {
        for (const event of batch) {
            await runAsync(
                'INSERT INTO audits (event_data) VALUES (?)',
                [JSON.stringify(event)]
            );
        }
    } catch (err) {
        console.error('Audit Batch Sync Failed', err);
    }

    batchProcessing = false;

    if (auditQueue.length > 0) {
        setImmediate(processQueue);
    }
}

function addAuditEvent(event) {
    auditQueue.push(event);
    setImmediate(processQueue);
}

function parseAuditRow(row) {
    return {
        id: row.id,
        createdAt: row.createdAt,
        ...JSON.parse(row.event_data || '{}')
    };
}

function parseJson(value, fallback = null) {
    if (value === undefined || value === null || value === '') return fallback;
    try {
        return JSON.parse(value);
    } catch {
        return fallback;
    }
}

function clampLimit(limit, min = 1, max = 5000, fallback = 100) {
    const value = Number(limit);
    if (!Number.isFinite(value)) return fallback;
    return Math.max(min, Math.min(max, Math.floor(value)));
}

function parsePolicyChangeRow(row) {
    return {
        id: Number(row.id),
        changedAt: row.changedAt,
        previousProfile: row.previousProfile,
        activeProfile: row.activeProfile,
        actor: row.actor,
        ip: row.ip,
        requestId: row.requestId,
        rationale: row.rationale,
        changeHash: row.changeHash
    };
}

function parseExportJobRow(row, { includeSnapshot = false } = {}) {
    if (!row) return null;

    const base = {
        id: Number(row.id),
        batchId: row.batchId,
        createdAt: row.createdAt,
        format: row.format,
        policyProfile: row.policyProfile,
        filters: parseJson(row.filtersJson, {}),
        recordCount: Number(row.recordCount || 0),
        checksumSha256: row.checksumSha256,
        chainSha256: row.chainSha256,
        signatureSha256: row.signatureSha256,
        manifestPath: row.manifestPath,
        manifestHash: row.manifestHash,
        previousManifestHash: row.previousManifestHash,
        manifest: parseJson(row.manifestJson, null)
    };

    if (includeSnapshot) {
        base.snapshot = parseJson(row.snapshotJson, []);
    }

    return base;
}

async function listAuditEventsAdvanced({
    limit = 100,
    beforeId = null,
    afterId = null,
    sort = 'desc'
} = {}) {
    const safeLimit = Math.max(1, Math.min(5000, Number(limit) || 100));
    const safeBeforeId = Number(beforeId);
    const safeAfterId = Number(afterId);
    const order = String(sort || '').toLowerCase() === 'asc' ? 'ASC' : 'DESC';

    const clauses = [];
    const params = [];

    if (Number.isFinite(safeBeforeId) && safeBeforeId > 0) {
        clauses.push('id < ?');
        params.push(safeBeforeId);
    }

    if (Number.isFinite(safeAfterId) && safeAfterId > 0) {
        clauses.push('id > ?');
        params.push(safeAfterId);
    }

    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const query = `SELECT * FROM audits ${where} ORDER BY id ${order} LIMIT ?`;
    params.push(safeLimit);

    const rows = await allAsync(query, params);
    return rows.map(parseAuditRow);
}

async function listAuditEvents(limit = 100) {
    const rows = await listAuditEventsAdvanced({ limit, sort: 'desc' });
    return rows;
}

async function getAuditEventStats() {
    const row = await getAsync('SELECT COUNT(*) AS total, MIN(id) AS oldestId, MAX(id) AS newestId FROM audits');
    return {
        total: Number(row?.total || 0),
        oldestId: row?.oldestId == null ? null : Number(row.oldestId),
        newestId: row?.newestId == null ? null : Number(row.newestId)
    };
}

async function addPolicyChangeHistory({
    previousProfile,
    activeProfile,
    actor = 'admin',
    ip = 'unknown',
    requestId = null,
    rationale = null,
    changedAt = new Date().toISOString()
}) {
    const prev = String(previousProfile || '').trim();
    const next = String(activeProfile || '').trim();
    if (!prev || !next) throw new Error('policy profiles are required');

    const safeActor = String(actor || 'admin').slice(0, 128);
    const safeIp = String(ip || 'unknown').slice(0, 128);
    const safeRequestId = requestId == null ? null : String(requestId).slice(0, 128);
    const safeRationale = rationale == null ? null : String(rationale).slice(0, 2048);

    const changeHash = crypto
        .createHash('sha256')
        .update(`${changedAt}:${prev}:${next}:${safeActor}:${safeIp}:${safeRequestId || ''}:${safeRationale || ''}`)
        .digest('hex');

    const result = await runAsync(`
        INSERT INTO policy_changes (
            changedAt, previousProfile, activeProfile, actor, ip, requestId, rationale, changeHash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [changedAt, prev, next, safeActor, safeIp, safeRequestId, safeRationale, changeHash]);

    return {
        id: result.lastID,
        changedAt,
        previousProfile: prev,
        activeProfile: next,
        actor: safeActor,
        ip: safeIp,
        requestId: safeRequestId,
        rationale: safeRationale,
        changeHash
    };
}

async function listPolicyChangeHistory({
    limit = 100,
    beforeId = null,
    afterId = null
} = {}) {
    const safeLimit = clampLimit(limit, 1, 1000, 100);
    const before = Number(beforeId);
    const after = Number(afterId);

    const clauses = [];
    const params = [];

    if (Number.isFinite(before) && before > 0) {
        clauses.push('id < ?');
        params.push(before);
    }
    if (Number.isFinite(after) && after > 0) {
        clauses.push('id > ?');
        params.push(after);
    }

    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = await allAsync(
        `SELECT * FROM policy_changes ${where} ORDER BY id DESC LIMIT ?`,
        [...params, safeLimit]
    );

    return rows.map(parsePolicyChangeRow);
}

async function createExportJobSnapshot({
    batchId,
    createdAt = new Date().toISOString(),
    format,
    policyProfile,
    filters = {},
    recordCount = 0,
    checksumSha256,
    chainSha256,
    signatureSha256 = null,
    manifestPath = null,
    manifestHash = null,
    previousManifestHash = null,
    snapshot = [],
    manifest = null
}) {
    const safeBatchId = String(batchId || '').trim();
    if (!safeBatchId) throw new Error('batchId is required');

    const safeFormat = String(format || '').trim().toLowerCase();
    const safePolicyProfile = String(policyProfile || '').trim().toLowerCase();
    const safeRecordCount = Math.max(0, Number(recordCount) || 0);
    const safeChecksum = String(checksumSha256 || '').trim();
    const safeChain = String(chainSha256 || '').trim();

    if (!safeFormat) throw new Error('format is required');
    if (!safePolicyProfile) throw new Error('policyProfile is required');
    if (!safeChecksum) throw new Error('checksumSha256 is required');
    if (!safeChain) throw new Error('chainSha256 is required');

    await runAsync(`
        INSERT INTO export_jobs (
            batchId, createdAt, format, policyProfile, filtersJson, recordCount,
            checksumSha256, chainSha256, signatureSha256, manifestPath,
            manifestHash, previousManifestHash, snapshotJson, manifestJson
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
        safeBatchId,
        createdAt,
        safeFormat,
        safePolicyProfile,
        JSON.stringify(filters || {}),
        safeRecordCount,
        safeChecksum,
        safeChain,
        signatureSha256 == null ? null : String(signatureSha256),
        manifestPath == null ? null : String(manifestPath),
        manifestHash == null ? null : String(manifestHash),
        previousManifestHash == null ? null : String(previousManifestHash),
        JSON.stringify(snapshot || []),
        manifest == null ? null : JSON.stringify(manifest)
    ]);

    return getExportJobSnapshot(safeBatchId, { includeSnapshot: true });
}

async function getExportJobSnapshot(batchId, { includeSnapshot = true } = {}) {
    const safeBatchId = String(batchId || '').trim();
    if (!safeBatchId) return null;

    const row = await getAsync('SELECT * FROM export_jobs WHERE batchId = ? LIMIT 1', [safeBatchId]);
    return parseExportJobRow(row, { includeSnapshot });
}

async function getExportJobByManifestHash(manifestHash, { includeSnapshot = false } = {}) {
    const safeHash = String(manifestHash || '').trim();
    if (!safeHash) return null;
    const row = await getAsync('SELECT * FROM export_jobs WHERE manifestHash = ? LIMIT 1', [safeHash]);
    return parseExportJobRow(row, { includeSnapshot });
}

async function getLatestExportJobSnapshot({ includeSnapshot = false } = {}) {
    const row = await getAsync('SELECT * FROM export_jobs ORDER BY id DESC LIMIT 1');
    return parseExportJobRow(row, { includeSnapshot });
}

async function listExportJobSnapshots({
    limit = 100,
    beforeId = null,
    afterId = null,
    includeSnapshot = false
} = {}) {
    const safeLimit = clampLimit(limit, 1, 1000, 100);
    const before = Number(beforeId);
    const after = Number(afterId);

    const clauses = [];
    const params = [];

    if (Number.isFinite(before) && before > 0) {
        clauses.push('id < ?');
        params.push(before);
    }
    if (Number.isFinite(after) && after > 0) {
        clauses.push('id > ?');
        params.push(after);
    }

    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = await allAsync(
        `SELECT * FROM export_jobs ${where} ORDER BY id DESC LIMIT ?`,
        [...params, safeLimit]
    );

    return rows.map((row) => parseExportJobRow(row, { includeSnapshot }));
}

module.exports = {
    addAuditEvent,
    listAuditEvents,
    listAuditEventsAdvanced,
    getAuditEventStats,
    addPolicyChangeHistory,
    listPolicyChangeHistory,
    createExportJobSnapshot,
    getExportJobSnapshot,
    listExportJobSnapshots,
    getLatestExportJobSnapshot,
    getExportJobByManifestHash
};
