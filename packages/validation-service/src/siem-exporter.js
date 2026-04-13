'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SCHEMA_VERSION = 'vaultjs-siem.v1';
const MANIFEST_SCHEMA_VERSION = 'vaultjs-siem-manifest.v1';

function sha256(value) {
    return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function parseCsvOrArray(value) {
    if (Array.isArray(value)) {
        return value.map((item) => String(item).trim().toLowerCase()).filter(Boolean);
    }
    return String(value || '')
        .split(',')
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean);
}

function safeTs(value) {
    const ts = new Date(value).getTime();
    return Number.isFinite(ts) ? ts : null;
}

function severityToNumber(severity) {
    const value = String(severity || '').toLowerCase();
    if (value === 'critical') return 9;
    if (value === 'high') return 8;
    if (value === 'deny') return 7;
    if (value === 'warn') return 5;
    if (value === 'medium') return 4;
    if (value === 'info') return 3;
    if (value === 'low') return 2;
    return 1;
}

function normalizeCategory(event = {}) {
    const type = String(event.type || '').toLowerCase();
    if (type.includes('validation')) return 'authentication';
    if (type.includes('access')) return 'access';
    if (type.includes('anomaly')) return 'intrusion_detection';
    return 'security';
}

function normalizeOutcome(event = {}) {
    if (event.allow === true) return 'success';
    if (event.allow === false) return 'failure';

    const severity = String(event.severity || '').toLowerCase();
    if (severity === 'critical' || severity === 'deny' || severity === 'high') return 'failure';
    return 'unknown';
}

function normalizeExportFilters(filters = {}) {
    const severity = parseCsvOrArray(filters.severity);
    const outcomes = parseCsvOrArray(filters.outcome);
    const typeContains = String(filters.type || '').trim().toLowerCase();
    const fromTs = safeTs(filters.from);
    const toTs = safeTs(filters.to);

    return {
        severity,
        outcomes,
        typeContains,
        fromTs,
        toTs
    };
}

function filterAuditEvents(events = [], filters = {}) {
    const normalized = normalizeExportFilters(filters);

    return events.filter((event) => {
        const eventSeverity = String(event.severity || '').toLowerCase();
        if (normalized.severity.length > 0 && !normalized.severity.includes(eventSeverity)) {
            return false;
        }

        const eventType = String(event.type || '').toLowerCase();
        if (normalized.typeContains && !eventType.includes(normalized.typeContains)) {
            return false;
        }

        if (normalized.outcomes.length > 0) {
            const eventOutcome = normalizeOutcome(event);
            if (!normalized.outcomes.includes(eventOutcome)) {
                return false;
            }
        }

        const ts = safeTs(event.at || event.createdAt);
        if (normalized.fromTs !== null && (ts === null || ts < normalized.fromTs)) {
            return false;
        }
        if (normalized.toTs !== null && (ts === null || ts > normalized.toTs)) {
            return false;
        }

        return true;
    });
}

function sanitizeDetails(details) {
    if (!details || typeof details !== 'object') return undefined;

    const blockedKeys = ['token', 'password', 'secret', 'cookie', 'authorization'];
    const safe = {};

    for (const [key, value] of Object.entries(details)) {
        const lower = key.toLowerCase();
        if (blockedKeys.some((k) => lower.includes(k))) {
            continue;
        }

        if (typeof value === 'string' && value.length > 512) {
            safe[key] = `${value.slice(0, 509)}...`;
            continue;
        }

        safe[key] = value;
    }

    return Object.keys(safe).length > 0 ? safe : undefined;
}

function toSiemRecord(event = {}, { policyProfile = 'balanced', serviceName = 'vaultjs-auth-server' } = {}) {
    const ts = event.at || event.createdAt || new Date().toISOString();
    const eventId = event.id || crypto.randomUUID();
    const reasons = Array.isArray(event.reasons) ? event.reasons : (event.reason ? [event.reason] : []);

    return {
        schema: SCHEMA_VERSION,
        '@timestamp': ts,
        event: {
            id: eventId,
            kind: 'event',
            category: [normalizeCategory(event)],
            type: [String(event.type || 'security_event')],
            outcome: normalizeOutcome(event),
            severity: severityToNumber(event.severity),
            reason: event.reason || null,
            action: event.action || null
        },
        service: {
            name: serviceName
        },
        labels: {
            policy_profile: policyProfile
        },
        user: event.uid ? { id: String(event.uid) } : undefined,
        session: event.sid ? { id: String(event.sid) } : undefined,
        source: event?.context?.ipPrefix ? { ip_prefix: event.context.ipPrefix } : undefined,
        vaultjs: {
            score: Number.isFinite(event.score) ? event.score : null,
            threshold: Number.isFinite(event.threshold) ? event.threshold : null,
            confidence: Number.isFinite(event.confidence) ? event.confidence : null,
            tier: event.tier || null,
            drift: Number.isFinite(event.drift) ? event.drift : null,
            reasons,
            details: sanitizeDetails(event.details)
        }
    };
}

function computeChainHash(records = []) {
    let rolling = '0'.repeat(64);
    for (const record of records) {
        rolling = sha256(`${rolling}:${JSON.stringify(record)}`);
    }
    return rolling;
}

function buildIntegrityMetadata(records = [], serializedPayload = null) {
    const payload = serializedPayload === null ? JSON.stringify(records) : String(serializedPayload);
    return {
        checksumSha256: sha256(payload),
        chainSha256: computeChainHash(records),
        count: records.length
    };
}

function signExportPayload(payload, signingKey) {
    const key = String(signingKey || '').trim();
    if (!key) return null;
    return crypto.createHmac('sha256', key).update(String(payload)).digest('hex');
}

function stableSortObject(value) {
    if (Array.isArray(value)) {
        return value.map((item) => stableSortObject(item));
    }
    if (value && typeof value === 'object') {
        const out = {};
        for (const key of Object.keys(value).sort()) {
            out[key] = stableSortObject(value[key]);
        }
        return out;
    }
    return value;
}

function stableStringify(value) {
    return JSON.stringify(stableSortObject(value));
}

function createBatchId(prefix = 'batch') {
    const ts = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
    const suffix = crypto.randomBytes(8).toString('hex');
    return `${prefix}_${ts}_${suffix}`;
}

function unsignedManifestPayload(manifest = {}) {
    const {
        manifestHash: _manifestHash,
        signature: _signature,
        ...rest
    } = manifest;
    return rest;
}

function buildSignedManifest({
    batchId,
    createdAt = new Date().toISOString(),
    exportSchema = SCHEMA_VERSION,
    format = 'json',
    policyProfile = 'balanced',
    filters = {},
    recordCount = 0,
    checksumSha256,
    chainSha256,
    snapshotChecksumSha256 = null,
    previousManifestHash = null,
    serviceName = 'vaultjs-auth-server'
} = {}, { signingKey } = {}) {
    const safeBatchId = String(batchId || '').trim();
    if (!safeBatchId) throw new Error('batchId is required for manifest');

    const unsigned = {
        schema: MANIFEST_SCHEMA_VERSION,
        batchId: safeBatchId,
        createdAt,
        service: { name: serviceName },
        export: {
            schema: exportSchema,
            format: String(format || 'json').toLowerCase(),
            policyProfile: String(policyProfile || 'balanced').toLowerCase(),
            filters: normalizeExportFilters(filters || {}),
            recordCount: Math.max(0, Number(recordCount) || 0),
            checksumSha256: String(checksumSha256 || ''),
            chainSha256: String(chainSha256 || ''),
            snapshotChecksumSha256: snapshotChecksumSha256 ? String(snapshotChecksumSha256) : null
        },
        replayProtection: {
            nonce: crypto.randomBytes(16).toString('hex'),
            previousManifestHash: previousManifestHash ? String(previousManifestHash) : null
        }
    };

    const canonical = stableStringify(unsigned);
    const manifestHash = sha256(canonical);
    const signatureValue = signExportPayload(canonical, signingKey);

    return {
        ...unsigned,
        manifestHash,
        signature: signatureValue
            ? {
                algorithm: 'hmac-sha256',
                value: signatureValue
            }
            : null
    };
}

function verifySignedManifest(manifest, { signingKey } = {}) {
    if (!manifest || typeof manifest !== 'object') {
        return {
            ok: false,
            hashValid: false,
            signatureValid: false,
            reason: 'manifest_missing'
        };
    }

    const unsigned = unsignedManifestPayload(manifest);
    const canonical = stableStringify(unsigned);
    const expectedHash = sha256(canonical);
    const hashValid = expectedHash === String(manifest.manifestHash || '');

    let signatureValid = null;
    if (manifest.signature?.value) {
        const expectedSignature = signExportPayload(canonical, signingKey);
        signatureValid = Boolean(expectedSignature) && expectedSignature === String(manifest.signature.value);
    }

    return {
        ok: hashValid && signatureValid !== false,
        hashValid,
        signatureValid,
        expectedHash,
        providedHash: manifest.manifestHash || null
    };
}

function persistSignedManifestFile(manifest, { directory } = {}) {
    const safeBatchId = String(manifest?.batchId || '').trim();
    if (!safeBatchId) throw new Error('manifest.batchId is required');

    const targetDir = directory || path.join(process.cwd(), 'infra', 'db', 'export-manifests');
    fs.mkdirSync(targetDir, { recursive: true });

    const filePath = path.join(targetDir, `${safeBatchId}.manifest.json`);
    if (fs.existsSync(filePath)) {
        throw new Error(`manifest file already exists for batchId ${safeBatchId}`);
    }

    fs.writeFileSync(filePath, JSON.stringify(manifest, null, 2), 'utf8');
    return filePath;
}

function loadSignedManifestFile(filePath) {
    const absolutePath = path.resolve(String(filePath || ''));
    const text = fs.readFileSync(absolutePath, 'utf8');
    return JSON.parse(text);
}

function exportSiemRecords(events = [], {
    format = 'json',
    policyProfile = 'balanced',
    serviceName = 'vaultjs-auth-server',
    filters = {}
} = {}) {
    const filteredEvents = filterAuditEvents(events, filters);
    const records = filteredEvents.map((event) => toSiemRecord(event, { policyProfile, serviceName }));

    if (String(format).toLowerCase() === 'ndjson') {
        return records.map((r) => JSON.stringify(r)).join('\n');
    }

    return records;
}

module.exports = {
    SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION,
    toSiemRecord,
    exportSiemRecords,
    severityToNumber,
    normalizeExportFilters,
    filterAuditEvents,
    computeChainHash,
    buildIntegrityMetadata,
    signExportPayload,
    stableStringify,
    createBatchId,
    buildSignedManifest,
    verifySignedManifest,
    persistSignedManifestFile,
    loadSignedManifestFile
};
