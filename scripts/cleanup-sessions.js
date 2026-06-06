'use strict';

const { runAsync } = require('../infra/db/connection');

async function cleanupSessions({ purgeDays = Number(process.env.SESS_PURGE_DAYS || 30), expiredOnly = process.env.SESS_PURGE_EXPIRED_ONLY === 'true' } = {}) {
    const now = new Date();
    const revokedThreshold = new Date(now.getTime() - purgeDays * 24 * 60 * 60 * 1000).toISOString();

    console.log('cleanup-sessions: purgeDays=', purgeDays, 'revokedThreshold=', revokedThreshold);

    // purge expired sessions with expiresAt set
    const res1 = await runAsync('DELETE FROM sessions WHERE expiresAt IS NOT NULL AND expiresAt < ?', [new Date().toISOString()]);
    console.log('deleted expired sessions:', res1.changes || 0);

    if (!expiredOnly) {
        const res2 = await runAsync('DELETE FROM sessions WHERE revokedAt IS NOT NULL AND revokedAt < ?', [revokedThreshold]);
        console.log('deleted old revoked sessions:', res2.changes || 0);
    }

    console.log('cleanup complete');
    return true;
}

if (require.main === module) {
    cleanupSessions().catch((err) => {
        console.error('cleanup-sessions failed', err);
        process.exit(1);
    });
}

module.exports = { cleanupSessions };
