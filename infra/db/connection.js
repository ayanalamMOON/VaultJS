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
          updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
          expiresAt DATETIME
        )
      `);

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

            database.run('CREATE INDEX IF NOT EXISTS idx_policy_changes_changedAt ON policy_changes(changedAt DESC)');
            database.run('CREATE INDEX IF NOT EXISTS idx_export_jobs_createdAt ON export_jobs(createdAt DESC)');
            database.run('CREATE INDEX IF NOT EXISTS idx_export_jobs_manifestHash ON export_jobs(manifestHash)');

            database.run('CREATE INDEX IF NOT EXISTS idx_export_jobs_batchId ON export_jobs(batchId)', (err) => {
                if (err) return reject(err);
                resolve();
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
