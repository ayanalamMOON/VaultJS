'use strict';

const crypto = require('crypto');
const request = require('supertest');
const { app } = require('../../packages/auth-server/src/server');
const { runAsync } = require('../../infra/db/connection');
const { logAnomaly } = require('../../packages/auth-server/src/anomaly-detector');
const {
    getPolicyProfile,
    setPolicyProfile,
    clearPolicyProfileOverride
} = require('../../packages/validation-service/src/decision-engine');

const ADMIN_TOKEN = 'test-admin-token';
const SIGNING_KEY = 'test-siem-signing-key';

describe('admin routes', () => {
    beforeAll(() => {
        process.env.ADMIN_API_TOKEN = ADMIN_TOKEN;
        process.env.SIEM_EXPORT_SIGNING_KEY = SIGNING_KEY;
        process.env.SIEM_MANIFEST_SIGNING_KEY = SIGNING_KEY;
    });

    afterEach(() => {
        clearPolicyProfileOverride();
    });

    afterAll(() => {
        delete process.env.ADMIN_API_TOKEN;
        delete process.env.SIEM_EXPORT_SIGNING_KEY;
        delete process.env.SIEM_MANIFEST_SIGNING_KEY;
    });

    test('rejects requests without admin token', async () => {
        await request(app).get('/admin/anomalies/stats').expect(401);
    });

    test('allows reading and switching policy profile with admin token', async () => {
        const initial = await request(app)
            .get('/admin/policy/profile')
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        expect(initial.body.ok).toBe(true);
        expect(initial.body.active).toBe(getPolicyProfile());

        const changed = await request(app)
            .post('/admin/policy/profile')
            .set('x-admin-token', ADMIN_TOKEN)
            .set('x-admin-actor', 'security-admin')
            .send({ profile: 'strict' })
            .expect(200);

        expect(changed.body.ok).toBe(true);
        expect(changed.body.active).toBe('strict');
        expect(changed.body.history).toBeDefined();
        expect(changed.body.history.actor).toBe('security-admin');
        expect(getPolicyProfile()).toBe('strict');

        await request(app)
            .post('/admin/policy/profile')
            .set('x-admin-token', ADMIN_TOKEN)
            .send({ profile: 'not-a-profile' })
            .expect(400);

        setPolicyProfile('balanced');

        const history = await request(app)
            .get('/admin/policy/history?limit=20')
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        expect(history.body.ok).toBe(true);
        expect(history.body.count).toBeGreaterThan(0);
        expect(history.body.items.some((item) => item.activeProfile === 'strict')).toBe(true);
    });

    test('returns anomaly summaries and escalation feeds', async () => {
        const uid = `admin-test-${Date.now()}`;
        logAnomaly('phase3_test_event', { ip: '127.0.0.1', uid });
        logAnomaly('phase3_test_event', { ip: '127.0.0.1', uid });
        logAnomaly('phase3_test_event', { ip: '127.0.0.1', uid });

        const stats = await request(app)
            .get('/admin/anomalies/stats')
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        expect(stats.body.ok).toBe(true);
        expect(stats.body.anomalies).toBeDefined();
        expect(stats.body.pressure.score).toBeGreaterThanOrEqual(0);

        const recent = await request(app)
            .get('/admin/anomalies/recent?type=phase3_test_event&limit=5')
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        expect(recent.body.ok).toBe(true);
        expect(recent.body.items.length).toBeGreaterThanOrEqual(1);

        const escalations = await request(app)
            .get('/admin/anomalies/escalations?minLevel=1&limit=5')
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        expect(escalations.body.ok).toBe(true);
        expect(Array.isArray(escalations.body.items)).toBe(true);
        expect(escalations.body.items.some((item) => String(item.key).includes('phase3_test_event'))).toBe(true);

        const insights = await request(app)
            .get('/admin/anomalies/insights?windowMs=600000&topN=5')
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        expect(insights.body.ok).toBe(true);
        expect(insights.body.insights).toBeDefined();
        expect(insights.body.insights.distributions).toBeDefined();
        expect(Array.isArray(insights.body.insights.recommendations)).toBe(true);
    });

    test('simulates policy decisions across profiles and returns recommendation', async () => {
        const simulated = await request(app)
            .post('/admin/policy/simulate')
            .set('x-admin-token', ADMIN_TOKEN)
            .send({
                signals: {
                    signatureValid: true,
                    decryptionValid: true,
                    contextValid: false,
                    replayValid: true,
                    riskScore: 60,
                    contextDrift: 25
                }
            })
            .expect(200);

        expect(simulated.body.ok).toBe(true);
        expect(simulated.body.simulation).toBeDefined();
        expect(simulated.body.simulation.matrix.strict).toBeDefined();
        expect(simulated.body.simulation.matrix.balanced).toBeDefined();
        expect(simulated.body.simulation.matrix.compat).toBeDefined();
        expect(['strict', 'balanced', 'compat']).toContain(simulated.body.recommendation.profile);
    });

    test('exports SIEM records in JSON and NDJSON formats with cursor and signing', async () => {
        const exportType = `anomaly_admin_export_test_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
        const eventId = crypto.randomUUID();
        const eventId2 = crypto.randomUUID();
        await runAsync(
            'INSERT INTO audits (event_data) VALUES (?)',
            [JSON.stringify({
                id: eventId,
                type: exportType,
                severity: 'critical',
                reason: 'security_check',
                uid: 'admin-export-user',
                details: {
                    token: 'should-be-redacted',
                    password: 'should-be-redacted',
                    safeField: 'kept'
                },
                at: new Date().toISOString()
            })]
        );

        await runAsync(
            'INSERT INTO audits (event_data) VALUES (?)',
            [JSON.stringify({
                id: eventId2,
                type: exportType,
                severity: 'high',
                reason: 'security_check_2',
                uid: 'admin-export-user-2',
                details: {
                    authorization: 'should-be-redacted',
                    safeField: 'kept-2'
                },
                at: new Date().toISOString()
            })]
        );

        const meta = await request(app)
            .get('/admin/audit/export/meta')
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        expect(meta.body.ok).toBe(true);
        expect(meta.body.stats).toBeDefined();
        expect(meta.body.stats.total).toBeGreaterThan(0);

        const exportedJson = await request(app)
            .get(`/admin/audit/export?format=json&limit=1&type=${encodeURIComponent(exportType)}`)
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        expect(exportedJson.body.ok).toBe(true);
        expect(exportedJson.body.format).toBe('json');
        expect(exportedJson.body.count).toBeGreaterThan(0);
        expect(exportedJson.body.cursor).toBeDefined();
        expect(exportedJson.body.batchId).toBeDefined();
        expect(exportedJson.body.manifestHash).toBeDefined();
        expect(exportedJson.body.signatureSha256).toBeDefined();
        expect(exportedJson.body.chainSha256).toBeDefined();

        const batchId = exportedJson.body.batchId;

        const record = exportedJson.body.records[0];
        expect(record).toBeDefined();
        expect(record.event.type[0]).toContain(exportType);
        expect(record.vaultjs.details.safeField.startsWith('kept')).toBe(true);
        expect(record.vaultjs.details.token).toBeUndefined();
        expect(record.vaultjs.details.password).toBeUndefined();

        const secondPage = await request(app)
            .get(`/admin/audit/export?format=json&limit=5&type=${encodeURIComponent(exportType)}&cursor=${exportedJson.body.cursor}`)
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        expect(secondPage.body.ok).toBe(true);
        expect(secondPage.body.records.length).toBeGreaterThanOrEqual(0);

        const exportedNdjson = await request(app)
            .get(`/admin/audit/export?format=ndjson&limit=25&type=${encodeURIComponent(exportType)}`)
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        expect(exportedNdjson.headers['x-vault-export-batch-id']).toBeDefined();
        expect(exportedNdjson.headers['x-vault-export-manifest-hash']).toBeDefined();
        expect(exportedNdjson.headers['x-vault-export-schema']).toBeDefined();
        expect(exportedNdjson.headers['x-vault-export-checksum-sha256']).toBeDefined();
        expect(exportedNdjson.headers['x-vault-export-chain-sha256']).toBeDefined();
        expect(exportedNdjson.headers['x-vault-export-signature']).toBeDefined();
        expect(exportedNdjson.text.trim().length).toBeGreaterThan(0);

        const firstLine = exportedNdjson.text.trim().split('\n')[0];
        const parsed = JSON.parse(firstLine);
        expect(parsed.schema).toBeDefined();
        expect(parsed.event).toBeDefined();

        const jobs = await request(app)
            .get('/admin/audit/export/jobs?limit=20')
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        expect(jobs.body.ok).toBe(true);
        expect(jobs.body.items.some((item) => item.batchId === batchId)).toBe(true);

        const jobDetail = await request(app)
            .get(`/admin/audit/export/jobs/${encodeURIComponent(batchId)}?includeSnapshot=true`)
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        expect(jobDetail.body.ok).toBe(true);
        expect(jobDetail.body.job.batchId).toBe(batchId);
        expect(Array.isArray(jobDetail.body.job.snapshot)).toBe(true);

        const manifest = await request(app)
            .get(`/admin/audit/export/jobs/${encodeURIComponent(batchId)}/manifest`)
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        expect(manifest.body.ok).toBe(true);
        expect(manifest.body.manifest.batchId).toBe(batchId);
        expect(manifest.body.manifest.signature).toBeDefined();

        const verify = await request(app)
            .get(`/admin/audit/export/jobs/${encodeURIComponent(batchId)}/verify`)
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        expect(verify.body.ok).toBe(true);
        expect(verify.body.batchId).toBe(batchId);
        expect(verify.body.chainValid).toBe(true);
        expect(verify.body.replayProtected).toBe(true);
    });
});
