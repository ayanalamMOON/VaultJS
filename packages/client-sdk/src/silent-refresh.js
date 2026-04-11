'use strict';

/**
 * Start a silent-refresh loop that keeps the server-side session alive by
 * periodically hitting a lightweight authenticated endpoint. The server will
 * issue a fresh cookie on every response when the token is near expiry.
 *
 * Features:
 *   - Random jitter on every interval to prevent thundering-herd from many
 *     clients all refreshing at exactly the same moment
 *   - Exponential backoff with cap on consecutive network errors
 *   - Stops automatically when the page becomes hidden (Page Visibility API)
 *   - Returns a clean teardown function
 *
 * @param {function} fetcher          - fetch-compatible function (path, init) => Promise<Response>
 * @param {object}   [opts]
 * @param {number}   [opts.intervalMs=240000]   - Base refresh interval (4 min default)
 * @param {number}   [opts.jitterMs=30000]      - Max random jitter added to each interval
 * @param {number}   [opts.maxBackoffMs=300000] - Maximum backoff after repeated errors
 * @param {string}   [opts.path='/session/status'] - Endpoint to hit
 * @returns {function} stop — call to cancel all timers
 */
function startSilentRefresh(fetcher, {
  intervalMs = 240_000,
  jitterMs = 30_000,
  maxBackoffMs = 300_000,
  path = '/session/status'
} = {}) {
  let timerId = null;
  let stopped = false;
  let consecutiveErrors = 0;

  function jitter() {
    return Math.floor(Math.random() * jitterMs);
  }

  function backoff() {
    // Exponential backoff: 0s, 5s, 10s, 20s, 40s … capped at maxBackoffMs
    if (consecutiveErrors === 0) return 0;
    const exp = Math.min(consecutiveErrors - 1, 5);
    return Math.min((2 ** exp) * 5_000, maxBackoffMs);
  }

  async function doRefresh() {
    if (stopped) return;

    try {
      const res = await fetcher(path, { method: 'GET', credentials: 'include' });
      if (res.ok) {
        consecutiveErrors = 0;
      } else if (res.status === 401) {
        // Session is gone — stop refreshing, no point retrying
        stop();
        return;
      } else {
        consecutiveErrors += 1;
      }
    } catch {
      // Network error
      consecutiveErrors += 1;
    }

    if (!stopped) {
      const delay = intervalMs + jitter() + backoff();
      timerId = setTimeout(doRefresh, delay);
    }
  }

  // Handle page visibility: pause when hidden, resume when visible
  function onVisibilityChange() {
    if (document.visibilityState === 'visible' && !stopped) {
      if (timerId) clearTimeout(timerId);
      timerId = setTimeout(doRefresh, jitter());
    } else if (document.visibilityState === 'hidden') {
      if (timerId) clearTimeout(timerId);
    }
  }

  if (typeof document !== 'undefined' && document.addEventListener) {
    document.addEventListener('visibilitychange', onVisibilityChange);
  }

  // Kick off the first refresh after a jittered delay
  timerId = setTimeout(doRefresh, intervalMs + jitter());

  function stop() {
    stopped = true;
    if (timerId) {
      clearTimeout(timerId);
      timerId = null;
    }
    if (typeof document !== 'undefined' && document.removeEventListener) {
      document.removeEventListener('visibilitychange', onVisibilityChange);
    }
  }

  return stop;
}

module.exports = { startSilentRefresh };
