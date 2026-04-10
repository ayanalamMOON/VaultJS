'use strict';

const { encryptPayload, decryptPayload, signEnvelope, verifyAndParseEnvelope } = require('../../packages/crypto-core/src/envelope');

test('envelope encryption and signature round-trip', () => {
  const aesKey = Buffer.alloc(32, 7);
  const hmacKey = 'test-hmac-key';
  const payload = { uid: 'u1', rot: 1 };

  const encrypted = encryptPayload(payload, aesKey);
  const token = signEnvelope(encrypted, hmacKey);
  const parsed = verifyAndParseEnvelope(token, hmacKey);
  const decrypted = decryptPayload(parsed, aesKey);

  expect(decrypted).toEqual(payload);
});
