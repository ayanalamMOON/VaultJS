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
    database.run(query, params, function(err) {
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
      `, (err) => {
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
