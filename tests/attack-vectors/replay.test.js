'use strict';

const { issueToken } = require('../../packages/token-engine/src/token-factory');
const { validateToken } = require('../../packages/token-engine/src/token-validator');

test('replay attempt is rejected', async () => {
  const context = { userAgent: 'ua', ip: '1.2.3.4' };
  const params = { uid: 'u1', sessionId: 's1', context, masterSecret: 'ms', hmacKey: 'hk' };
  const issued = issueToken(params);

  await expect(validateToken({ token: issued.token, context, masterSecret: 'ms', hmacKey: 'hk' })).resolves.toBeTruthy();
  await expect(validateToken({ token: issued.token, context, masterSecret: 'ms', hmacKey: 'hk' })).rejects.toThrow('replay detected: rotation');
});
