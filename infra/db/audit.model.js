'use strict';

const { runAsync, allAsync } = require('./connection');

// Queue memory buffer for write-behind
let auditQueue = [];
let batchProcessing = false;

const BATCH_SIZE = 50;

async function processQueue() {
  if (batchProcessing || auditQueue.length === 0) return;
  batchProcessing = true;

  const batch = auditQueue.splice(0, BATCH_SIZE);
  
  try {
    for (const event of batch) {
      await runAsync(
        'INSERT INTO audits (event_data) VALUES (?)',
        [JSON.stringify(event)]
      );
    }
  } catch (err) {
    console.error('Audit Batch Sync Failed', err);
  }

  batchProcessing = false;
  
  if (auditQueue.length > 0) {
    setImmediate(processQueue);
  }
}

function addAuditEvent(event) {
  auditQueue.push(event);
  setImmediate(processQueue);
}

async function listAuditEvents(limit = 100) {
  const rows = await allAsync('SELECT * FROM audits ORDER BY id DESC LIMIT ?', [limit]);
  return rows.map(r => ({
    id: r.id,
    createdAt: r.createdAt,
    ...JSON.parse(r.event_data || '{}')
  }));
}

module.exports = { addAuditEvent, listAuditEvents };
