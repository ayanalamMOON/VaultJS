'use strict';

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

let db = null;

/**
 * Get or initialize the SQLite database connection.
 * @returns {Promise<sqlite3.Database>}
 */
async function getDb() {
    if (db) return db;

    const dbPath = path.join(__dirname, 'vault.db');

    return new Promise((resolve, reject) => {
        db = new sqlite3.Database(dbPath, async (err) => {
            if (err) {
                console.error('Failed to connect to SQLite DB', err);
                return reject(err);
            }

            try {
                await initSchema(db);
                resolve(db);
            } catch (e) {
                reject(e);
            }
        });
    });
}

function runAsync(query, params = []) {
    return new Promise(async (resolve, reject) => {
        const database = await getDb();
        database.run(query, params, function (err) {
            if (err) return reject(err);
            resolve({ lastID: this.lastID, changes: this.changes });
        });
    });
}

function getAsync(query, params = []) {
    return new Promise(async (resolve, reject) => {
        const database = await getDb();
        database.get(query, params, (err, row) => {
            if (err) return reject(err);
            resolve(row);
        });
    });
}

function allAsync(query, params = []) {
    return new Promise(async (resolve, reject) => {
        const database = await getDb();
        database.all(query, params, (err, rows) => {
            if (err) return reject(err);
            resolve(rows);
        });
    });
}

/**
 * Initialize the schema tables if they don't exist.
 */
async function initSchema(database) {
    return new Promise((resolve, reject) => {
        database.serialize(() => {
            database.run(`
        CREATE TABLE IF NOT EXISTS users (
          username TEXT PRIMARY KEY,
          password TEXT,
          createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

            database.run(`
        CREATE TABLE IF NOT EXISTS sessions (
          sessionId TEXT PRIMARY KEY,
          payload TEXT,
                    uid TEXT,
                    revokedAt DATETIME,
          updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
          expiresAt DATETIME
        )
      `);

            // Add uid and revokedAt columns for efficient queries/pagination. Use
            // ALTER TABLE guarded by duplicate-column checks to be safe on
            // existing DBs.
            database.run('ALTER TABLE sessions ADD COLUMN uid TEXT', (addUidErr) => {
                if (addUidErr && !/duplicate column name/i.test(addUidErr.message)) {
                    // propagate as fatal
                    return reject(addUidErr);
                }

                database.run('ALTER TABLE sessions ADD COLUMN revokedAt INTEGER', (addRevokedErr) => {
                    if (addRevokedErr && !/duplicate column name/i.test(addRevokedErr.message)) {
                        return reject(addRevokedErr);
                    }

                    // Create indexes to make filtering/counting fast on large tables.
                    database.run('CREATE INDEX IF NOT EXISTS idx_sessions_uid ON sessions(uid)');
                    database.run('CREATE INDEX IF NOT EXISTS idx_sessions_revokedAt ON sessions(revokedAt)');
                });
            });

            database.run(`
        CREATE TABLE IF NOT EXISTS audits (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
          event_data TEXT
        )
      `);

            database.run(`
        CREATE TABLE IF NOT EXISTS policy_changes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          changedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
          previousProfile TEXT NOT NULL,
          activeProfile TEXT NOT NULL,
          actor TEXT,
          ip TEXT,
          requestId TEXT,
          rationale TEXT,
          changeHash TEXT UNIQUE
        )
      `);

            database.run(`
        CREATE TABLE IF NOT EXISTS export_jobs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          batchId TEXT NOT NULL UNIQUE,
          createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
          format TEXT NOT NULL,
          policyProfile TEXT NOT NULL,
          filtersJson TEXT,
          recordCount INTEGER NOT NULL,
          checksumSha256 TEXT NOT NULL,
          chainSha256 TEXT NOT NULL,
          signatureSha256 TEXT,
          manifestPath TEXT,
          manifestHash TEXT,
          previousManifestHash TEXT,
          snapshotJson TEXT,
          manifestJson TEXT
        )
      `);

            database.run(`
                CREATE TABLE IF NOT EXISTS siem_containments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batchId TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL DEFAULT 'paused',
                    owner TEXT,
                    severity TEXT NOT NULL DEFAULT 'high',
                    reason TEXT,
                    pausedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                    acknowledgedAt DATETIME,
                    acknowledgedBy TEXT,
                    resumedAt DATETIME,
                    resumedBy TEXT,
                    resolvedAt DATETIME,
                    resolvedBy TEXT,
                    lastStatusAt DATETIME,
                    notes TEXT,
                    verificationJson TEXT,
                    exportJobJson TEXT,
                    manifestJson TEXT,
                    evidencePath TEXT,
                    manifestCopyPath TEXT,
                    auditEventsJson TEXT
                )
            `);

            database.run(`
                CREATE TABLE IF NOT EXISTS siem_containment_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batchId TEXT NOT NULL,
                    fromStatus TEXT,
                    toStatus TEXT NOT NULL,
                    actor TEXT,
                    note TEXT,
                    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                    detailsJson TEXT
                )
            `);

            database.run('CREATE INDEX IF NOT EXISTS idx_policy_changes_changedAt ON policy_changes(changedAt DESC)');
            database.run('CREATE INDEX IF NOT EXISTS idx_export_jobs_createdAt ON export_jobs(createdAt DESC)');
            database.run('CREATE INDEX IF NOT EXISTS idx_export_jobs_manifestHash ON export_jobs(manifestHash)');

            database.run('CREATE INDEX IF NOT EXISTS idx_export_jobs_batchId ON export_jobs(batchId)', (err) => {
                if (err) return reject(err);
                database.run('CREATE INDEX IF NOT EXISTS idx_siem_containments_createdAt ON siem_containments(pausedAt DESC)');
                database.run('CREATE INDEX IF NOT EXISTS idx_siem_containments_status ON siem_containments(status)');
                database.run('CREATE INDEX IF NOT EXISTS idx_siem_containments_batchId ON siem_containments(batchId)', (containmentErr) => {
                    if (containmentErr) return reject(containmentErr);
                    database.run('CREATE INDEX IF NOT EXISTS idx_siem_containment_history_batchId ON siem_containment_history(batchId)');
                    database.run('CREATE INDEX IF NOT EXISTS idx_siem_containment_history_createdAt ON siem_containment_history(createdAt DESC)');
                    database.run('CREATE INDEX IF NOT EXISTS idx_audits_createdAt ON audits(createdAt DESC)');
                    try {
                        database.run("CREATE INDEX IF NOT EXISTS idx_audits_event_type ON audits(json_extract(event_data, '$.type'))");
                    } catch (e) {
                        // Older SQLite may not support expression indexes — ignore
                    }

                    const ignoreDuplicate = (err) => err && !/duplicate column name/i.test(err.message);

                    // Ensure sessions table has uid and revokedAt columns for efficient queries
                    database.run('ALTER TABLE sessions ADD COLUMN uid TEXT', (sessErr) => {
                        if (ignoreDuplicate(sessErr)) return reject(sessErr);
                        database.run('ALTER TABLE sessions ADD COLUMN revokedAt DATETIME', (sessErr2) => {
                            if (ignoreDuplicate(sessErr2)) return reject(sessErr2);
                            database.run('CREATE INDEX IF NOT EXISTS idx_sessions_uid ON sessions(uid)', (idxErr) => {
                                if (idxErr) return reject(idxErr);
                                database.run('CREATE INDEX IF NOT EXISTS idx_sessions_revokedAt ON sessions(revokedAt)', (idxErr2) => {
                                    if (idxErr2) return reject(idxErr2);

                                    // Continue with existing siem_containments migrations
                                    database.run('ALTER TABLE siem_containments ADD COLUMN acknowledgedAt DATETIME', (err) => {
                                        if (ignoreDuplicate(err)) return reject(err);
                                        database.run('ALTER TABLE siem_containments ADD COLUMN acknowledgedBy TEXT', (err2) => {
                                            if (ignoreDuplicate(err2)) return reject(err2);
                                            database.run('ALTER TABLE siem_containments ADD COLUMN resumedAt DATETIME', (err3) => {
                                                if (ignoreDuplicate(err3)) return reject(err3);
                                                database.run('ALTER TABLE siem_containments ADD COLUMN resumedBy TEXT', (err4) => {
                                                    if (ignoreDuplicate(err4)) return reject(err4);
                                                    database.run('ALTER TABLE siem_containments ADD COLUMN resolvedBy TEXT', (err5) => {
                                                        if (ignoreDuplicate(err5)) return reject(err5);
                                                        database.run('ALTER TABLE siem_containments ADD COLUMN lastStatusAt DATETIME', (err6) => {
                                                            if (ignoreDuplicate(err6)) return reject(err6);
                                                            database.run('ALTER TABLE siem_containments ADD COLUMN notes TEXT', (err7) => {
                                                                if (ignoreDuplicate(err7)) return reject(err7);
                                                                resolve();
                                                            });
                                                        });
                                                    });
                                                });
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
}

module.exports = {
    getDb,
    runAsync,
    getAsync,
    allAsync
};
