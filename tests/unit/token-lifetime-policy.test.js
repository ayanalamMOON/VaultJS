'use strict';

const { issueToken } = require('../../packages/token-engine/src/token-factory');
const { validateToken } = require('../../packages/token-engine/src/token-validator');

test('token lifetime policy rejects overlong token windows', async () => {
    const previous = process.env.VAULT_MAX_TOKEN_LIFETIME_SECONDS;
    process.env.VAULT_MAX_TOKEN_LIFETIME_SECONDS = '120';

    const context = {
        userAgent: 'Mozilla/5.0 Chrome/123',
        webglRenderer: 'ANGLE',
        timeZone: 'UTC',
        ip: '10.1.1.1'
    };

    const issued = issueToken({
        uid: 'u-lifetime',
        sessionId: 's-lifetime',
        context,
        masterSecret: 'ms-lifetime',
        hmacKey: 'hk-lifetime'
    });

    await expect(validateToken({
        token: issued.token,
        context,
        masterSecret: 'ms-lifetime',
        hmacKey: 'hk-lifetime'
    })).rejects.toThrow('token lifetime exceeds policy');

    if (previous === undefined) delete process.env.VAULT_MAX_TOKEN_LIFETIME_SECONDS;
    else process.env.VAULT_MAX_TOKEN_LIFETIME_SECONDS = previous;
});
