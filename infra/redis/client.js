'use strict';

const Redis = require('ioredis');

let singleton;

function createRedisClient(url = process.env.REDIS_URL) {
  if (!url) {
    return null;
  }
  if (!singleton) {
    singleton = new Redis(url, { lazyConnect: true, maxRetriesPerRequest: 1 });
  }
  return singleton;
}

module.exports = {
  createRedisClient
};
