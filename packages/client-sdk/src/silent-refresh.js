'use strict';

function startSilentRefresh(fetcher, intervalMs = 240_000) {
  const timer = setInterval(async () => {
    try {
      await fetcher('/session/me', { method: 'GET', credentials: 'include' });
    } catch {
      // silent by design
    }
  }, intervalMs);

  return () => clearInterval(timer);
}

module.exports = { startSilentRefresh };
