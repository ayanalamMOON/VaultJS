'use strict';

const Redis = require('ioredis');

let singleton;

function createRedisClient(url = process.env.REDIS_URL || 'redis://localhost:6379') {
  if (!singleton) {
    singleton = new Redis(url, { 
      lazyConnect: true, 
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false
    });

    singleton.on('error', (err) => {
      console.error('[Redis CircuitBreaker] Error:', err.message);
    });

    singleton.on('ready', () => {
      console.log('[Redis] Connected and ready');
    });

    singleton.on('reconnecting', () => {
      console.warn('[Redis] Reconnecting...');
    });
  }
  return singleton;
}

module.exports = {
  createRedisClient
};
