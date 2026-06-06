'use strict';

const { encryptPayload, decryptPayload, signEnvelope, verifyAndParseEnvelope } = require('../../packages/crypto-core/src/envelope');

test('envelope encryption and signature round-trip', () => {
    const aesKey = Buffer.alloc(32, 7);
    const hmacKey = 'test-hmac-key';
    const payload = { uid: 'u1', rot: 1 };

    const encrypted = encryptPayload(payload, aesKey);
    expect(encrypted.suite).toBeDefined();
    expect(encrypted.alg).toBe('aes-256-gcm');
    const token = signEnvelope(encrypted, hmacKey);
    const parsed = verifyAndParseEnvelope(token, hmacKey);
    expect(parsed.suite).toBe(encrypted.suite);
    expect(parsed.alg).toBe('aes-256-gcm');
    const decrypted = decryptPayload(parsed, aesKey);

    expect(decrypted).toEqual(payload);
});
