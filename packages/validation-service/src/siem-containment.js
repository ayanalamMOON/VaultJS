'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const {
    addAuditEvent,
    listAuditEventsByText,
    createSIEMContainmentRecord,
    getSIEMContainmentByBatchId,
    listSIEMContainments,
    updateSIEMContainmentStatus,
    addSIEMContainmentHistory,
    listSIEMContainmentHistory
} = require('../../../infra/db/audit.model');
const { stableStringify } = require('./siem-exporter');

function sha256(value) {
    return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function getContainmentDirectory() {
    return String(process.env.SIEM_CONTAINMENT_DIR || '').trim()
        || path.join(process.cwd(), 'infra', 'db', 'siem-containments');
}

function getDefaultManifestPath(batchId) {
    const manifestDir = String(process.env.SIEM_MANIFEST_DIR || '').trim()
        || path.join(process.cwd(), 'infra', 'db', 'export-manifests');
    return path.join(manifestDir, `${batchId}.manifest.json`);
}

function ensureDir(dirPath) {
    fs.mkdirSync(dirPath, { recursive: true });
}

async function captureRelevantAuditEvents(batchId, { limit = 50 } = {}) {
    return listAuditEventsByText(batchId, { limit });
}

function buildContainmentEvidence({
    batchId,
    owner,
    severity,
    reason,
    verification,
    exportJob,
    manifest,
    auditEvents,
    manifestPath,
    manifestCopyPath,
    evidencePath
}) {
    const createdAt = new Date().toISOString();
    const bundle = {
        schema: 'vaultjs-siem-containment.v1',
        batchId,
        createdAt,
        owner,
        severity,
        reason,
        state: 'paused',
        pausedAt: createdAt,
        manifestPath,
        manifestCopyPath,
        evidencePath,
        verification,
        exportJob,
        manifest,
        auditEvents
    };

    return {
        ...bundle,
        evidenceHash: sha256(stableStringify(bundle))
    };
}

function persistManifestCopy({ batchId, manifest, sourcePath, directory }) {
    ensureDir(directory);
    const targetPath = path.join(directory, `${batchId}.manifest.json`);
    if (fs.existsSync(targetPath)) return targetPath;

    if (sourcePath && fs.existsSync(sourcePath)) {
        fs.copyFileSync(sourcePath, targetPath);
        return targetPath;
    }

    fs.writeFileSync(targetPath, JSON.stringify(manifest, null, 2), 'utf8');
    return targetPath;
}

async function containSIEMBatch({
    batchId,
    owner = 'admin',
    severity = 'high',
    reason = 'verification_failed',
    verification = null,
    exportJob = null,
    manifest = null,
    actor = 'admin'
}) {
    const safeBatchId = String(batchId || '').trim();
    if (!safeBatchId) throw new Error('batchId is required');

    const existing = await getSIEMContainmentByBatchId(safeBatchId);
    if (existing) return existing;

    const containmentDirectory = getContainmentDirectory();
    const evidenceFilePath = path.join(containmentDirectory, `${safeBatchId}.containment.json`);
    const manifestSourcePath = exportJob?.manifestPath || getDefaultManifestPath(safeBatchId);
    const manifestCopyPath = persistManifestCopy({
        batchId: safeBatchId,
        manifest,
        sourcePath: manifestSourcePath,
        directory: containmentDirectory
    });

    const auditEvents = await captureRelevantAuditEvents(safeBatchId, { limit: 50 });
    const evidence = buildContainmentEvidence({
        batchId: safeBatchId,
        owner,
        severity,
        reason,
        verification,
        exportJob,
        manifest,
        auditEvents,
        manifestPath: manifestSourcePath,
        manifestCopyPath,
        evidencePath: evidenceFilePath
    });

    ensureDir(containmentDirectory);
    fs.writeFileSync(evidenceFilePath, JSON.stringify(evidence, null, 2), 'utf8');

    const record = await createSIEMContainmentRecord({
        batchId: safeBatchId,
        status: 'paused',
        owner,
        severity,
        reason,
        lastStatusAt: evidence.createdAt,
        verification,
        exportJob,
        manifest,
        evidencePath: evidenceFilePath,
        manifestCopyPath,
        auditEvents
    });

    addAuditEvent({
        type: 'siem_export_contained',
        severity: 'critical',
        allow: false,
        reason,
        batchId: safeBatchId,
        owner,
        actor,
        verification,
        at: evidence.createdAt,
        details: {
            evidencePath: evidenceFilePath,
            manifestCopyPath
        }
    });

    await addSIEMContainmentHistory({
        batchId: safeBatchId,
        fromStatus: null,
        toStatus: 'paused',
        actor,
        note: reason,
        details: {
            evidencePath: evidenceFilePath,
            manifestCopyPath
        }
    });

    return {
        ...record,
        paused: true,
        evidencePath: evidenceFilePath,
        manifestCopyPath,
        auditEvents
    };
}

async function transitionContainment({
    batchId,
    toStatus,
    actor = 'admin',
    note = null,
    updates = {},
    auditType = 'siem_containment_status_changed'
}) {
    const safeBatchId = String(batchId || '').trim();
    if (!safeBatchId) throw new Error('batchId is required');

    const current = await getSIEMContainmentByBatchId(safeBatchId);
    if (!current) throw new Error('containment not found');

    const normalizedTo = String(toStatus || '').trim().toLowerCase();
    if (!normalizedTo) throw new Error('toStatus is required');

    const now = new Date().toISOString();
    const next = await updateSIEMContainmentStatus(safeBatchId, {
        status: normalizedTo,
        lastStatusAt: now,
        ...updates
    });

    await addSIEMContainmentHistory({
        batchId: safeBatchId,
        fromStatus: current.status,
        toStatus: normalizedTo,
        actor,
        note,
        details: updates
    });

    addAuditEvent({
        type: auditType,
        severity: 'warn',
        allow: false,
        batchId: safeBatchId,
        reason: normalizedTo,
        at: now,
        details: {
            fromStatus: current.status,
            toStatus: normalizedTo,
            note
        }
    });

    return next;
}

async function acknowledgeSIEMContainment({
    batchId,
    actor = 'admin',
    note = null
}) {
    const now = new Date().toISOString();
    return transitionContainment({
        batchId,
        toStatus: 'acknowledged',
        actor,
        note,
        updates: {
            acknowledgedAt: now,
            acknowledgedBy: actor
        },
        auditType: 'siem_containment_acknowledged'
    });
}

async function resumeSIEMContainment({
    batchId,
    actor = 'admin',
    note = null
}) {
    const now = new Date().toISOString();
    return transitionContainment({
        batchId,
        toStatus: 'acknowledged',
        actor,
        note: note || 'resumed',
        updates: {
            resumedAt: now,
            resumedBy: actor
        },
        auditType: 'siem_containment_resumed'
    });
}

async function resolveSIEMContainment({
    batchId,
    actor = 'admin',
    note = null
}) {
    const now = new Date().toISOString();
    return transitionContainment({
        batchId,
        toStatus: 'resolved',
        actor,
        note,
        updates: {
            resolvedAt: now,
            resolvedBy: actor
        },
        auditType: 'siem_containment_resolved'
    });
}

async function getContainmentStatus(batchId) {
    return getSIEMContainmentByBatchId(batchId);
}

async function listContainmentStatuses(options = {}) {
    return listSIEMContainments(options);
}

async function listContainmentHistory(batchId, options = {}) {
    return listSIEMContainmentHistory({ batchId, ...options });
}

module.exports = {
    getContainmentDirectory,
    buildContainmentEvidence,
    containSIEMBatch,
    acknowledgeSIEMContainment,
    resumeSIEMContainment,
    resolveSIEMContainment,
    getContainmentStatus,
    listContainmentStatuses,
    listContainmentHistory
};
