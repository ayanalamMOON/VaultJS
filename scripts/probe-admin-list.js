(async () => {
    const request = require('supertest');
    const { app } = require('../packages/auth-server/src/server');
    const { createSession } = require('../packages/auth-server/src/session-manager');
    process.env.ADMIN_API_TOKEN = 'test-admin-token';
    process.env.REDIS_ENABLED = 'false';
    const uid = 'list-test-' + Date.now();
    const ctx = { userAgent: 'list-agent', timeZone: 'UTC', ip: '127.0.0.1' };
    const s1 = await createSession({ uid, context: ctx, masterSecret: 'dev_master_secret_change_me', hmacKey: 'dev_hmac_key_change_me' });
    const s2 = await createSession({ uid, context: ctx, masterSecret: 'dev_master_secret_change_me', hmacKey: 'dev_hmac_key_change_me' });
    console.log('created sids:', s1.inner.sid, s2.inner.sid);
    const resp = await request(app)
        .get(`/admin/sessions?uid=${encodeURIComponent(uid)}`)
        .set('x-admin-token', 'test-admin-token');
    console.log('resp.body.items by uid:', resp.body.items.map(i => i.sessionId));
    const respAll = await request(app)
        .get('/admin/sessions')
        .set('x-admin-token', 'test-admin-token');
    console.log('respAll count', respAll.body.items.length);
})();
