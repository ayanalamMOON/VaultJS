'use strict';

const crypto = require('crypto');

const nextKey = crypto.randomBytes(32).toString('base64url');
console.log(JSON.stringify({ rotatedAt: new Date().toISOString(), nextMasterSecret: nextKey }, null, 2));
