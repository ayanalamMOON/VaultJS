#!/usr/bin/env node
'use strict';

// Restore sessions table from a SQL backup file produced by dump-sessions-sql.js
// Usage: BACKUP_PATH=infra/db/session-backups/sessions-sql-backup-...sql node scripts/restore-sessions-sql.js

const fs = require('fs');
const path = require('path');
const { runAsync } = require('../infra/db/connection');

async function restore(backupPath) {
    if (!backupPath) {
        // find latest backup
        const dir = path.join(process.cwd(), 'infra', 'db', 'session-backups');
        if (!fs.existsSync(dir)) throw new Error('Backup directory not found: ' + dir);
        const files = fs.readdirSync(dir)
            .filter((f) => f.startsWith('sessions-sql-backup-') && f.endsWith('.sql'))
            .map((f) => ({ f, m: fs.statSync(path.join(dir, f)).mtime.getTime() }))
            .sort((a, b) => b.m - a.m);
        if (!files.length) throw new Error('No SQL backup files found in ' + dir);
        backupPath = path.join(dir, files[0].f);
    }

    if (!fs.existsSync(backupPath)) throw new Error('Backup file not found: ' + backupPath);

    console.log('Restoring sessions from', backupPath);
    const sql = fs.readFileSync(backupPath, 'utf8');

    // Split by semicolon newline which we used when writing file.
    const stmts = sql.split(/;\s*\n/).map(s => s.trim()).filter(Boolean);

    for (const stmt of stmts) {
        try {
            await runAsync(stmt);
        } catch (e) {
            console.warn('Failed to run statement (continuing):', stmt.slice(0, 120), e && e.message ? e.message : e);
        }
    }

    console.log('Restore complete.');
}

const backupPath = process.env.BACKUP_PATH || process.argv[2] || null;
restore(backupPath).catch(err => {
    console.error('Restore failed:', err && err.message ? err.message : err);
    process.exit(2);
});
