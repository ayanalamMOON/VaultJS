'use strict';

const { createSession, revokeAllUserSessions, COOKIE_NAME } = require('../../packages/auth-server/src/session-manager');
const { listSessions } = require('../../infra/db/session.model');

describe('session-manager unit', () => {
    test('enforceSessionCeiling evicts oldest when exceeding MAX_SESSIONS_PER_USER', async () => {
        const uid = `ceiling-test-${Date.now()}`;
        const created = [];
        for (let i = 0; i < 11; i++) {
            const s = await createSession({ uid, context: { userAgent: 'uagent', ip: '127.0.0.1' }, masterSecret: process.env.MASTER_SECRET || 'dev_master_secret_change_me', hmacKey: process.env.HMAC_KEY || 'dev_hmac_key_change_me' });
            created.push(s.inner.sid);
        }

        const items = await listSessions({ uid });
        // enforceSessionCeiling should evict oldest so only 10 remain
        expect(items.length).toBe(10);
        const ids = items.map((i) => i.sessionId);
        expect(ids).not.toContain(created[0]);
    });

    test('revokeAllUserSessions marks all sessions revoked', async () => {
        const uid = `revokeall-test-${Date.now()}`;
        const sids = [];
        for (let i = 0; i < 3; i++) {
            const s = await createSession({ uid, context: { userAgent: 'uagent', ip: '127.0.0.1' }, masterSecret: process.env.MASTER_SECRET || 'dev_master_secret_change_me', hmacKey: process.env.HMAC_KEY || 'dev_hmac_key_change_me' });
            sids.push(s.inner.sid);
        }

        await revokeAllUserSessions(uid);

        const items = await listSessions({ uid });
        expect(items.length).toBeGreaterThanOrEqual(3);
        for (const it of items) {
            expect(it.payload.revokedAt).toBeDefined();
        }
    });
});
