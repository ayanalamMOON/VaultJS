#!/usr/bin/env node
'use strict';

// One-time migration: populate `uid` and `revokedAt` columns from JSON payload
// into the dedicated columns added to the sessions table.

const { allAsync, runAsync } = require('../infra/db/connection');
const fs = require('fs');
const path = require('path');

async function migrate() {
    console.log('Starting sessions payload -> columns migration');
    const rows = await allAsync('SELECT sessionId, payload, uid, revokedAt FROM sessions', []);
    if (!rows || rows.length === 0) {
        console.log('No sessions found, nothing to do.');
        return;
    }

    // Backup current sessions table to a JSON file before making updates.
    try {
        const backupDir = path.join(process.cwd(), 'infra', 'db', 'session-backups');
        if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        const backupPath = path.join(backupDir, `sessions-backup-${ts}.json`);
        fs.writeFileSync(backupPath, JSON.stringify(rows, null, 2), { encoding: 'utf8' });
        console.log('Sessions backup written to', backupPath);
    } catch (e) {
        console.warn('Failed to write sessions backup; aborting migration to avoid data loss:', e && e.message ? e.message : e);
        throw e;
    }

    let updated = 0;
    let skipped = 0;
    let malformed = 0;

    for (const row of rows) {
        const sid = row.sessionId;
        let payload = null;
        try {
            payload = JSON.parse(row.payload || '{}');
        } catch (e) {
            malformed += 1;
            console.warn('Skipping malformed payload for session', sid);
            continue;
        }

        const payloadUid = payload && payload.uid ? String(payload.uid) : null;
        const payloadRevoked = payload && payload.revokedAt ? Number(payload.revokedAt) : null;

        const currentUid = row.uid != null ? String(row.uid) : null;
        const currentRevoked = row.revokedAt != null ? Number(row.revokedAt) : null;

        const wantUid = currentUid || payloadUid;
        const wantRevoked = (currentRevoked != null) ? currentRevoked : payloadRevoked;

        const needUpdate = (wantUid !== currentUid) || (wantRevoked !== currentRevoked);
        if (!needUpdate) {
            skipped += 1;
            continue;
        }

        await runAsync('UPDATE sessions SET uid = ?, revokedAt = ? WHERE sessionId = ?', [wantUid, wantRevoked, sid]);
        updated += 1;
    }

    console.log(`Migration complete. rows=${rows.length} updated=${updated} skipped=${skipped} malformed=${malformed}`);
}

migrate().catch((err) => {
    console.error('Migration failed:', err && err.message ? err.message : err);
    process.exit(2);
});
