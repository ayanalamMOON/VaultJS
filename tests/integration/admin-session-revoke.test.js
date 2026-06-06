'use strict';

const request = require('supertest');
const { app } = require('../../packages/auth-server/src/server');
const { setSession, getSession, listSessions } = require('../../infra/db/session.model');
const { addAuditEvent, listAuditEventsByText } = require('../../infra/db/audit.model');
const { runAsync } = require('../../infra/db/connection');

const ADMIN_TOKEN = 'test-admin-token';

describe('admin session endpoints', () => {
    beforeAll(() => {
        process.env.ADMIN_API_TOKEN = ADMIN_TOKEN;
    });

    afterAll(() => {
        delete process.env.ADMIN_API_TOKEN;
    });

    test('bulk revoke marks sessions revoked and creates audit event', async () => {
        const uid = `test-user-${Date.now()}`;
        const s1 = `sid-${Date.now()}-1`;
        const s2 = `sid-${Date.now()}-2`;

        await setSession(s1, { uid, createdAt: Date.now() });
        await setSession(s2, { uid, createdAt: Date.now() });

        const listBefore = await listSessions({ uid, limit: 10 });
        console.log('listBefore for uid', uid, listBefore);
        // expect at least the two we inserted
        // (if other tests run concurrently the DB may contain more rows)
        // expect(listBefore.length).toBeGreaterThanOrEqual(2);

        const res = await request(app)
            .post('/admin/sessions/revoke')
            .set('x-admin-token', ADMIN_TOKEN)
            .send({ uid, reason: 'test_revoke' });

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(res.body.count).toBeGreaterThanOrEqual(2);

        const after = await listSessions({ uid, limit: 20 });
        // all sessions for uid should now be revoked
        expect(after.length).toBeGreaterThanOrEqual(2);
        for (const r of after) {
            expect(r.revokedAt || r.payload.revokedAt).toBeTruthy();
        }

        // check audit table for admin_bulk_revoke_sessions
        const audits = await listAuditEventsByText('admin_bulk_revoke_sessions', { limit: 20 });
        expect(audits.some((a) => a.type === 'admin_bulk_revoke_sessions' || String(a.type).includes('admin_bulk_revoke_sessions'))).toBe(true);
    });

    test('session details endpoint returns session and writes audit', async () => {
        const uid = `detail-user-${Date.now()}`;
        const sid = `sid-detail-${Date.now()}`;
        await setSession(sid, { uid, createdAt: Date.now() });

        const res = await request(app)
            .get(`/admin/sessions/${encodeURIComponent(sid)}`)
            .set('x-admin-token', ADMIN_TOKEN)
            .set('x-admin-actor', 'test-operator')
            .expect(200);

        expect(res.body.ok).toBe(true);
        expect(res.body.session).toBeDefined();
        expect(res.body.session.sessionId).toBe(sid);

        const audits = await listAuditEventsByText('admin_view_session', { limit: 20 });
        expect(audits.some((a) => a.type === 'admin_view_session' || String(a.type).includes('admin_view_session'))).toBe(true);
    });
});
