'use strict';

const { runAsync, getAsync, allAsync } = require('./connection');

async function ensureTable() {
    await runAsync(`
    CREATE TABLE IF NOT EXISTS metrics (
      name TEXT PRIMARY KEY,
      value INTEGER DEFAULT 0,
      updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

async function incrMetric(name, delta = 1) {
    if (!name) throw new Error('name required');
    await ensureTable();
    const safeName = String(name).slice(0, 256);
    const d = Number(delta) || 1;
    // Try update first
    const res = await runAsync('UPDATE metrics SET value = value + ?, updatedAt = CURRENT_TIMESTAMP WHERE name = ?', [d, safeName]);
    if (res.changes === 0) {
        await runAsync('INSERT INTO metrics (name, value) VALUES (?, ?)', [safeName, d]);
    }
}

async function getMetric(name) {
    await ensureTable();
    const row = await getAsync('SELECT value FROM metrics WHERE name = ? LIMIT 1', [String(name)]);
    return Number(row?.value || 0);
}

async function getAllMetrics() {
    await ensureTable();
    const rows = await allAsync('SELECT name, value FROM metrics');
    const out = {};
    for (const r of rows) out[r.name] = Number(r.value || 0);
    return out;
}

module.exports = { incrMetric, getMetric, getAllMetrics };
