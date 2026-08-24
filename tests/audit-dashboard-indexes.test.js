const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Database = require('better-sqlite3');

const { AuditLogger } = require('../dist/audit');

test('audit migration creates covering indexes for synchronous dashboard queries', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clawguard-audit-index-'));
  const dbPath = path.join(dir, 'audit.db');
  try {
    const audit = new AuditLogger(dbPath);
    audit.logRequest({
      timestamp: new Date().toISOString(),
      service: 'github',
      method: 'GET',
      path: '/',
      approved: true,
      responseStatus: 200,
      agentIp: '127.0.0.1',
    });
    audit.close();

    const db = new Database(dbPath, { readonly: true });
    try {
      const indexes = db.prepare(`
        SELECT name FROM sqlite_master
        WHERE type = 'index' AND tbl_name = 'requests'
      `).all().map((row) => row.name);
      assert.ok(indexes.includes('idx_requests_timestamp_service_method_approved'));
      assert.ok(indexes.includes('idx_requests_service_timestamp_method_approved'));

      const sincePlan = db.prepare(`
        EXPLAIN QUERY PLAN SELECT COUNT(*) FROM requests WHERE timestamp >= ?
      `).all('2000-01-01T00:00:00.000Z').map((row) => row.detail).join(' ');
      assert.match(sincePlan, /idx_requests_timestamp_service_method_approved/);

      const servicePlan = db.prepare(`
        EXPLAIN QUERY PLAN SELECT COUNT(*) FROM requests WHERE service = ? AND timestamp >= ?
      `).all('github', '2000-01-01T00:00:00.000Z').map((row) => row.detail).join(' ');
      assert.match(servicePlan, /idx_requests_service_timestamp_method_approved/);
    } finally {
      db.close();
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
