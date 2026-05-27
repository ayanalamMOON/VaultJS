'use strict';

const request = require('supertest');
const { app } = require('../../packages/auth-server/src/server');
const { createSession } = require('../../packages/auth-server/src/session-manager');

const ADMIN_TOKEN = 'test-admin-token';

describe('admin session revocation', () => {
    beforeAll(() => {
        process.env.ADMIN_API_TOKEN = ADMIN_TOKEN;
    });

    afterAll(() => {
        delete process.env.ADMIN_API_TOKEN;
    });

    test('admin can revoke a session and token becomes invalid', async () => {
        const uid = `revoke-test-${Date.now()}`;
        // Create a fresh session/token
        const context = {
            userAgent: 'test-agent',
            timeZone: 'UTC',
            webglRenderer: '',
            webauthnCredentialId: '',
            ip: '127.0.0.1'
        };

        const issued = await createSession({
            uid,
            context,
            masterSecret: process.env.MASTER_SECRET || 'dev_master_secret_change_me',
            hmacKey: process.env.HMAC_KEY || 'dev_hmac_key_change_me',
            redis: null
        });

        const token = issued.token;
        const sid = issued.inner.sid;

        // Token should initially be accepted for protected endpoint
        const first = await request(app)
            .get('/session/me')
            .set('Authorization', `Bearer ${token}`)
            .set('user-agent', 'test-agent')
            .set('x-forwarded-for', '127.0.0.1')
            .set('x-timezone', 'UTC');
        if (first.status !== 200) {
            // Log body for debugging
            // eslint-disable-next-line no-console
            console.error('initial /session/me failed:', first.status, first.body || first.text);
        }
        expect(first.status).toBe(200);

        // sanity check: admin routes are reachable with token
        await request(app)
            .get('/admin/policy/profile')
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        // Admin revokes the session
        const revokeResp = await request(app)
            .post(`/admin/sessions/${encodeURIComponent(sid)}/revoke`)
            .set('x-admin-token', ADMIN_TOKEN);
        if (revokeResp.status !== 200) {
            // eslint-disable-next-line no-console
            console.error('revoke response:', revokeResp.status, revokeResp.body || revokeResp.text);
        }
        expect(revokeResp.status).toBe(200);

        // Token must now be rejected
        await request(app)
            .get('/session/me')
            .set('Authorization', `Bearer ${token}`)
            .set('user-agent', 'test-agent')
            .set('x-forwarded-for', '127.0.0.1')
            .set('x-timezone', 'UTC')
            .expect(401);
    });
});
