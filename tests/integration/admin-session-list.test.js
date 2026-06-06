'use strict';

const request = require('supertest');
const { app } = require('../../packages/auth-server/src/server');
const { setSession, listSessions, countSessions } = require('../../infra/db/session.model');

const ADMIN_TOKEN = 'test-admin-token';

describe('admin sessions listing', () => {
    beforeAll(() => {
        process.env.ADMIN_API_TOKEN = ADMIN_TOKEN;
    });
    afterAll(() => {
        delete process.env.ADMIN_API_TOKEN;
    });

    test('lists sessions with pagination and returns total count', async () => {
        const uid = `list-user-${Date.now()}`;
        // create 7 sessions
        for (let i = 0; i < 7; i++) {
            await setSession(`sid-list-${uid}-${i}-${Date.now()}`, { uid, createdAt: Date.now() + i });
        }

        const total = await countSessions({ uid });
        expect(total).toBeGreaterThanOrEqual(7);

        const res = await request(app)
            .get(`/admin/sessions?uid=${encodeURIComponent(uid)}&limit=5&offset=0`)
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        expect(res.body.ok).toBe(true);
        expect(res.body.total).toBeGreaterThanOrEqual(7);
        expect(res.body.count).toBe(5);
        expect(Array.isArray(res.body.items)).toBe(true);

        const res2 = await request(app)
            .get(`/admin/sessions?uid=${encodeURIComponent(uid)}&limit=5&offset=5`)
            .set('x-admin-token', ADMIN_TOKEN)
            .expect(200);

        expect(res2.body.ok).toBe(true);
        expect(res2.body.offset).toBe(5);
        expect(res2.body.items.length).toBeGreaterThanOrEqual(2);
    });
});
