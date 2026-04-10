'use strict';

const { clientPreHash: deriveClientPreHash } = require('./client-crypto');
const { buildClientFingerprint } = require('./client-fingerprint');
const { solvePow } = require('./pow-solver');
const { startSilentRefresh } = require('./silent-refresh');

class VaultClient {
  constructor({ baseUrl, fetchImpl = fetch, contextProvider = () => ({}) }) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.fetch = fetchImpl;
    this.contextProvider = contextProvider;
    this.stopRefresh = null;
  }

  headers() {
    const ctx = this.contextProvider();
    return {
      'content-type': 'application/json',
      'x-timezone': ctx.timeZone || 'UTC',
      'x-color-depth': String(ctx.colorDepth || '24'),
      'x-pixel-depth': String(ctx.pixelDepth || '24'),
      'x-webgl-renderer': ctx.webglRenderer || 'unknown',
      'x-client-fp': buildClientFingerprint(ctx)
    };
  }

  async #post(path, body) {
    return this.fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      credentials: 'include',
      headers: this.headers(),
      body: JSON.stringify(body)
    });
  }

  async login(username, password, domain = 'domain.com') {
    const preHash = deriveClientPreHash(password, username, domain);
    const body = { username, clientPreHash: preHash };
    const res = await this.#post('/auth/login', body);

    if (res.status === 403) {
      const payload = await res.json();
      const powNonce = solvePow(payload.challenge);
      const retry = await this.#post('/auth/login', { ...body, powNonce });
      if (!retry.ok) throw new Error(`login failed after pow (${retry.status})`);
    } else if (!res.ok) {
      throw new Error(`login failed (${res.status})`);
    }

    if (!this.stopRefresh) {
      this.stopRefresh = startSilentRefresh((path, init) => this.fetch(`${this.baseUrl}${path}`, init));
    }
  }

  logout() {
    if (this.stopRefresh) {
      this.stopRefresh();
      this.stopRefresh = null;
    }
  }
}

module.exports = { VaultClient };
