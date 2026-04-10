'use strict';

const { pbkdf2PreHash } = require('../../crypto-core/src/kdf');

function clientPreHash(password, username, domain = 'domain.com') {
  return pbkdf2PreHash(password, username, domain);
}

module.exports = { clientPreHash };
