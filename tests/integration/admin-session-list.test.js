'use strict';

const request = require('supertest');
const { app } = require('../../packages/auth-server/src/server');
const { createSession } = require('../../packages/auth-server/src/session-manager');

const ADMIN_TOKEN = 'test-admin-token';

describe('admin session listing', () => {
    beforeAll(() => {
        process.env.ADMIN_API_TOKEN = ADMIN_TOKEN;
    });

    afterAll(() => {
        delete process.env.ADMIN_API_TOKEN;
    });

    test('lists sessions for a user', async () => {
        const uid = `list-test-${Date.now()}`;
        const ctx = { userAgent: 'list-agent', timeZone: 'UTC', ip: '127.0.0.1' };

        const s1 = await createSession({ uid, context: ctx, masterSecret: process.env.MASTER_SECRET || 'dev_master_secret_change_me', hmacKey: process.env.HMAC_KEY || 'dev_hmac_key_change_me' });
        const s2 = await createSession({ uid, context: ctx, masterSecret: process.env.MASTER_SECRET || 'dev_master_secret_change_me', hmacKey: process.env.HMAC_KEY || 'dev_hmac_key_change_me' });

        const resp = await request(app)
            .get(`/admin/sessions?uid=${encodeURIComponent(uid)}`)
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        // debug output on failure
        // eslint-disable-next-line no-console
        console.log('created sids:', s1.inner.sid, s2.inner.sid);
        // eslint-disable-next-line no-console
        console.log('resp items (by uid):', resp.body.items.map((i) => i.sessionId));

        const respAll = await request(app)
            .get(`/admin/sessions`)
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);
        // eslint-disable-next-line no-console
        console.log('resp items (all):', respAll.body.items.map((i) => i.sessionId));

        expect(resp.body.ok).toBe(true);
        expect(Array.isArray(resp.body.items)).toBe(true);
        const ids = resp.body.items.map((i) => i.sessionId);
        expect(ids).toContain(s1.inner.sid);
        expect(ids).toContain(s2.inner.sid);
    });
});
