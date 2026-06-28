#!/usr/bin/env node
'use strict';

// Dump sessions table to a SQL file as INSERT statements. This is intended as
// a human-readable, restorable pre-migration backup.

const { allAsync } = require('../infra/db/connection');
const fs = require('fs');
const path = require('path');

function escSql(val) {
    if (val === null || typeof val === 'undefined') return 'NULL';
    // Numbers should not be quoted
    if (typeof val === 'number') return String(val);
    // Escape single quotes for SQL
    return `'${String(val).replace(/'/g, "''")}'`;
}

async function dump() {
    console.log('Dumping sessions table to SQL file');
    const rows = await allAsync('SELECT sessionId, payload, uid, revokedAt, updatedAt, expiresAt FROM sessions', []);

    const backupDir = path.join(process.cwd(), 'infra', 'db', 'session-backups');
    if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    const outPath = path.join(backupDir, `sessions-sql-backup-${ts}.sql`);

    const stream = fs.createWriteStream(outPath, { encoding: 'utf8' });
    stream.write('PRAGMA foreign_keys=OFF;\n');
    stream.write('BEGIN TRANSACTION;\n');

    for (const r of rows || []) {
        const sid = escSql(r.sessionId);
        const payload = escSql(r.payload);
        const uid = escSql(r.uid);
        const revoked = r.revokedAt === null || typeof r.revokedAt === 'undefined' ? 'NULL' : String(r.revokedAt);
        const updatedAt = escSql(r.updatedAt);
        const expiresAt = escSql(r.expiresAt);

        const stmt = `INSERT OR REPLACE INTO sessions (sessionId, payload, uid, revokedAt, updatedAt, expiresAt) VALUES (${sid}, ${payload}, ${uid}, ${revoked}, ${updatedAt}, ${expiresAt});\n`;
        stream.write(stmt);
    }

    stream.write('COMMIT;\n');
    stream.end();
    console.log('Sessions SQL backup written to', outPath);
}

dump().catch((err) => {
    console.error('Dump failed:', err && err.message ? err.message : err);
    process.exit(2);
});
