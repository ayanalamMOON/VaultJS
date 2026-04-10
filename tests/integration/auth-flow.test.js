'use strict';

const request = require('supertest');
const { app } = require('../../packages/auth-server/src/server');
const { pbkdf2PreHash } = require('../../packages/crypto-core/src/kdf');

test('register and login returns ok', async () => {
  await request(app).post('/auth/register').send({ username: 'alice', password: 'very-strong-password' }).expect(201);
  const clientPreHash = pbkdf2PreHash('very-strong-password', 'alice');
  const response = await request(app).post('/auth/login').send({ username: 'alice', clientPreHash }).expect(200);
  expect(response.body.ok).toBe(true);
});
