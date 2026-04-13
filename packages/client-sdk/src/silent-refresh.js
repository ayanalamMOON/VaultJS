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
    minIntervalMs = 30_000,
    jitterMs = 30_000,
    maxBackoffMs = 300_000,
    path = '/session/status',
    onHeartbeat = () => { },
    onError = () => { },
    pauseWhenOffline = true
} = {}) {
    let timerId = null;
    let stopped = false;
    let consecutiveErrors = 0;
    let dynamicIntervalMs = intervalMs;

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

        if (pauseWhenOffline && typeof navigator !== 'undefined' && navigator.onLine === false) {
            timerId = setTimeout(doRefresh, Math.min(dynamicIntervalMs, 60_000));
            return;
        }

        try {
            const res = await fetcher(path, { method: 'GET', credentials: 'include' });
            if (res.ok) {
                consecutiveErrors = 0;
                const body = await res.json().catch(() => ({}));
                if (Number.isFinite(body.ttlRemaining) && body.ttlRemaining > 0) {
                    // Refresh at ~60% of remaining TTL to maintain healthy margin
                    dynamicIntervalMs = Math.max(minIntervalMs, Math.min(intervalMs, Math.floor(body.ttlRemaining * 1000 * 0.6)));
                }
                onHeartbeat({ ok: true, status: res.status, body });
            } else if (res.status === 401) {
                // Session is gone — stop refreshing, no point retrying
                onHeartbeat({ ok: false, status: 401, body: null });
                stop();
                return;
            } else {
                consecutiveErrors += 1;
                onHeartbeat({ ok: false, status: res.status, body: null });
            }
        } catch {
            // Network error
            consecutiveErrors += 1;
            onError({ consecutiveErrors });
        }

        if (!stopped) {
            const delay = dynamicIntervalMs + jitter() + backoff();
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

    function onOnline() {
        if (!stopped && !timerId) {
            timerId = setTimeout(doRefresh, jitter());
        }
    }

    if (pauseWhenOffline && typeof window !== 'undefined' && window.addEventListener) {
        window.addEventListener('online', onOnline);
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
        if (pauseWhenOffline && typeof window !== 'undefined' && window.removeEventListener) {
            window.removeEventListener('online', onOnline);
        }
    }

    return stop;
}

module.exports = { startSilentRefresh };
