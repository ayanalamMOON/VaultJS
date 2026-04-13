'use strict';

const {
    exportSiemRecords,
    filterAuditEvents,
    buildIntegrityMetadata,
    signExportPayload,
    computeChainHash,
    buildSignedManifest,
    verifySignedManifest,
    createBatchId
} = require('../../packages/validation-service/src/siem-exporter');

test('filters audit events by severity, type and outcome', () => {
    const events = [
        {
            id: '1',
            type: 'validation',
            severity: 'info',
            allow: true,
            at: '2026-01-01T10:00:00.000Z'
        },
        {
            id: '2',
            type: 'anomaly_login_failed',
            severity: 'critical',
            allow: false,
            at: '2026-01-01T10:01:00.000Z'
        },
        {
            id: '3',
            type: 'anomaly_token',
            severity: 'high',
            allow: false,
            at: '2026-01-01T10:02:00.000Z'
        }
    ];

    const filtered = filterAuditEvents(events, {
        severity: 'critical,high',
        type: 'anomaly',
        outcome: 'failure',
        from: '2026-01-01T10:00:30.000Z',
        to: '2026-01-01T10:02:30.000Z'
    });

    expect(filtered.length).toBe(2);
    expect(filtered.every((e) => e.type.includes('anomaly'))).toBe(true);
});

test('exportSiemRecords respects filters and supports NDJSON', () => {
    const events = [
        { id: '1', type: 'validation', severity: 'info', allow: true, at: '2026-01-01T10:00:00.000Z' },
        { id: '2', type: 'anomaly_x', severity: 'critical', allow: false, at: '2026-01-01T10:01:00.000Z' }
    ];

    const jsonRecords = exportSiemRecords(events, {
        format: 'json',
        filters: { severity: 'critical' }
    });

    const ndjson = exportSiemRecords(events, {
        format: 'ndjson',
        filters: { severity: 'critical' }
    });

    expect(jsonRecords.length).toBe(1);
    expect(typeof ndjson).toBe('string');
    expect(ndjson.split('\n').length).toBe(1);
});

test('integrity metadata and signatures are deterministic for same payload', () => {
    const records = [
        { id: 'a', event: { id: 'a' } },
        { id: 'b', event: { id: 'b' } }
    ];

    const serialized = JSON.stringify(records);
    const integrityA = buildIntegrityMetadata(records, serialized);
    const integrityB = buildIntegrityMetadata(records, serialized);

    expect(integrityA.checksumSha256).toBe(integrityB.checksumSha256);
    expect(integrityA.chainSha256).toBe(integrityB.chainSha256);
    expect(integrityA.chainSha256).toBe(computeChainHash(records));

    const signatureA = signExportPayload(serialized, 'signing-key');
    const signatureB = signExportPayload(serialized, 'signing-key');
    const signatureNone = signExportPayload(serialized, '');

    expect(signatureA).toBe(signatureB);
    expect(signatureNone).toBeNull();
});

test('buildSignedManifest and verifySignedManifest provide tamper evidence', () => {
    const batchId = createBatchId('unit');
    const manifest = buildSignedManifest({
        batchId,
        format: 'json',
        policyProfile: 'balanced',
        filters: { severity: 'critical' },
        recordCount: 2,
        checksumSha256: 'a'.repeat(64),
        chainSha256: 'b'.repeat(64),
        previousManifestHash: 'c'.repeat(64)
    }, {
        signingKey: 'manifest-key'
    });

    const verified = verifySignedManifest(manifest, { signingKey: 'manifest-key' });
    expect(verified.ok).toBe(true);
    expect(verified.hashValid).toBe(true);
    expect(verified.signatureValid).toBe(true);

    const tampered = {
        ...manifest,
        export: {
            ...manifest.export,
            recordCount: 3
        }
    };
    const tamperedResult = verifySignedManifest(tampered, { signingKey: 'manifest-key' });
    expect(tamperedResult.ok).toBe(false);
    expect(tamperedResult.hashValid).toBe(false);
});
