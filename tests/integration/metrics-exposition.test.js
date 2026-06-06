'use strict';

const request = require('supertest');
const { app } = require('../../packages/auth-server/src/server');
const { issueToken, validateToken } = require('../../packages/token-engine/src');
const { setTokenState, getTokenState } = require('../../infra/redis/token-store');

const MASTER_SECRET = 'metrics-test-master-secret';
const HMAC_KEY = 'metrics-test-hmac-key';

function buildContext() {
    return {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36',
        timeZone: 'UTC',
        colorDepth: '24',
        pixelDepth: '24',
        webglRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3080, Direct3D11)',
        webauthnCredentialId: '',
        ip: '127.0.0.1'
    };
}

describe('Prometheus metrics exposition', () => {
    test('exposes token, redis, and replay metrics after domain activity', async () => {
        const context = buildContext();
        const issued = issueToken({
            uid: 'metrics-user',
            sessionId: `metrics-session-${Date.now()}`,
            context,
            masterSecret: MASTER_SECRET,
            hmacKey: HMAC_KEY
        });

        await setTokenState('metrics-cache', { rot: 1, jti: 'jti-1' }, 60, null);
        await getTokenState('metrics-cache-miss', null);
        await getTokenState('metrics-cache', null);

        await validateToken({
            token: issued.token,
            context,
            masterSecret: MASTER_SECRET,
            hmacKey: HMAC_KEY
        });

        await expect(validateToken({
            token: issued.token,
            context,
            masterSecret: MASTER_SECRET,
            hmacKey: HMAC_KEY
        })).rejects.toThrow(/replay detected/);

        const response = await request(app)
            .get('/metrics')
            .expect(200);

        expect(response.text).toContain('vault_token_events_total');
        expect(response.text).toContain('vault_token_mint_seconds');
        expect(response.text).toContain('vault_replay_detections_total');
        expect(response.text).toContain('vault_redis_cache_events_total');
        expect(response.text).toContain('vault_redis_cache_hit_rate');
        expect(response.text).toContain('vault_redis_cache_miss_rate');
        expect(response.text).toContain('vault_token_validation_seconds');
    });
});
