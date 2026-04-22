const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { AuditLogger } = require('../dist/audit');
const { ApprovalManager } = require('../dist/approval');

function tmpDb() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-approval-'));
  return path.join(dir, 'test.db');
}

function makeServiceConfig(defaultAction) {
  return {
    upstream: 'https://api.example.com',
    auth: { type: 'bearer', token: 'x' },
    policy: { default: defaultAction, rules: [] },
  };
}

function fakeTelegram() {
  const calls = { notifyAutoApproved: [], requestApproval: [], clearPendingRequest: [] };
  let nextApproval = null; // { approved, ttlSeconds, approvedBy, pathScoped }
  return {
    setNext(a) { nextApproval = a; },
    calls,
    notifyAutoApproved(service, method, p, agentIp, reason) {
      calls.notifyAutoApproved.push({ service, method, path: p, agentIp, reason });
    },
    async requestApproval(requestId, service, method, p, agentIp) {
      calls.requestApproval.push({ requestId, service, method, path: p, agentIp });
      return nextApproval || { approved: false, ttlSeconds: 0, approvedBy: 'timeout', pathScoped: false };
    },
    clearPendingRequest(id) { calls.clearPendingRequest.push(id); },
  };
}

test('policy auto_approve skips lookup and notifies showlog hook', async () => {
  const audit = new AuditLogger(tmpDb());
  const tg = fakeTelegram();
  const mgr = new ApprovalManager(tg, audit, 1000);

  const ok = await mgr.checkApproval('svc', makeServiceConfig('auto_approve'), 'GET', '/anything?x=1', '1.2.3.4');
  assert.equal(ok, true);
  assert.equal(tg.calls.notifyAutoApproved.length, 1);
  assert.equal(tg.calls.notifyAutoApproved[0].reason, 'policy:auto_approve');
});

test('method-wide approval covers any path for same service+method', async () => {
  const dbPath = tmpDb();
  const audit = new AuditLogger(dbPath);
  audit.logApproval('svc', 'POST', 'alice', 3600, null); // method-wide
  const tg = fakeTelegram();
  const mgr = new ApprovalManager(tg, audit, 1000);

  const ok1 = await mgr.checkApproval('svc', makeServiceConfig('require_approval'), 'POST', '/foo?a=1', '1.2.3.4');
  const ok2 = await mgr.checkApproval('svc', makeServiceConfig('require_approval'), 'POST', '/bar', '1.2.3.4');
  assert.equal(ok1, true);
  assert.equal(ok2, true);
  assert.equal(tg.calls.requestApproval.length, 0, 'no telegram prompt should be sent');
  assert.equal(tg.calls.notifyAutoApproved.length, 2);
});

test('path-scoped approval matches exact path with querystring, not others', async () => {
  const dbPath = tmpDb();
  const audit = new AuditLogger(dbPath);
  const exactPath = '/logotel_spa/repo.git/git-upload-pack?service=git-upload-pack';
  audit.logApproval('bitbucket', 'POST', 'alice', 86400, exactPath);

  const tg = fakeTelegram();
  const mgr = new ApprovalManager(tg, audit, 1000);

  // exact match (path + querystring) → approved silently
  const ok = await mgr.checkApproval('bitbucket', makeServiceConfig('require_approval'), 'POST', exactPath, '1.2.3.4');
  assert.equal(ok, true);
  assert.equal(tg.calls.requestApproval.length, 0);

  // different querystring → telegram is asked
  tg.setNext({ approved: false, ttlSeconds: 0, approvedBy: 'denied', pathScoped: false });
  const ok2 = await mgr.checkApproval('bitbucket', makeServiceConfig('require_approval'), 'POST', '/logotel_spa/repo.git/git-upload-pack?service=git-receive-pack', '1.2.3.4');
  assert.equal(ok2, false);
  assert.equal(tg.calls.requestApproval.length, 1);
});

test('path-scoped approval does not cover other paths even on same service+method', async () => {
  const dbPath = tmpDb();
  const audit = new AuditLogger(dbPath);
  audit.logApproval('svc', 'GET', 'alice', 3600, '/a');
  const tg = fakeTelegram();
  const mgr = new ApprovalManager(tg, audit, 1000);

  const ok1 = await mgr.checkApproval('svc', makeServiceConfig('require_approval'), 'GET', '/a', '1.2.3.4');
  assert.equal(ok1, true);
  assert.equal(tg.calls.requestApproval.length, 0);

  tg.setNext({ approved: false, ttlSeconds: 0, approvedBy: 'timeout', pathScoped: false });
  const ok2 = await mgr.checkApproval('svc', makeServiceConfig('require_approval'), 'GET', '/b', '1.2.3.4');
  assert.equal(ok2, false);
  assert.equal(tg.calls.requestApproval.length, 1);
});

test('method-wide approval takes over when path-scoped is absent', async () => {
  const dbPath = tmpDb();
  const audit = new AuditLogger(dbPath);
  audit.logApproval('svc', 'GET', 'alice', 3600, '/known');
  audit.logApproval('svc', 'GET', 'bob', 3600, null); // wide too
  const tg = fakeTelegram();
  const mgr = new ApprovalManager(tg, audit, 1000);

  // path-specific hit
  const ok1 = await mgr.checkApproval('svc', makeServiceConfig('require_approval'), 'GET', '/known', '1.2.3.4');
  assert.equal(ok1, true);
  assert.equal(tg.calls.notifyAutoApproved[0].reason.startsWith('approval:path'), true);

  // different path → fall back to method-wide
  const ok2 = await mgr.checkApproval('svc', makeServiceConfig('require_approval'), 'GET', '/other', '1.2.3.4');
  assert.equal(ok2, true);
  assert.equal(tg.calls.requestApproval.length, 0);
  assert.equal(tg.calls.notifyAutoApproved[1].reason.startsWith('approval:method-wide'), true);
});

test('telegram approve stores path-scoped when pathScoped=true', async () => {
  const dbPath = tmpDb();
  const audit = new AuditLogger(dbPath);
  const tg = fakeTelegram();
  tg.setNext({ approved: true, ttlSeconds: 3600, approvedBy: 'alice', pathScoped: true });
  const mgr = new ApprovalManager(tg, audit, 1000);

  const p = '/api/resource?uuid=123';
  const ok = await mgr.checkApproval('svc', makeServiceConfig('require_approval'), 'GET', p, '1.2.3.4');
  assert.equal(ok, true);

  // Second call on same path: should hit cache (no telegram)
  const ok2 = await mgr.checkApproval('svc', makeServiceConfig('require_approval'), 'GET', p, '1.2.3.4');
  assert.equal(ok2, true);
  assert.equal(tg.calls.requestApproval.length, 1);

  // Third call on different path: must prompt again
  tg.setNext({ approved: false, ttlSeconds: 0, approvedBy: 'timeout', pathScoped: false });
  const ok3 = await mgr.checkApproval('svc', makeServiceConfig('require_approval'), 'GET', '/api/other', '1.2.3.4');
  assert.equal(ok3, false);
  assert.equal(tg.calls.requestApproval.length, 2);
});

test('revokeApproval targets exact path when given', async () => {
  const dbPath = tmpDb();
  const audit = new AuditLogger(dbPath);
  audit.logApproval('svc', 'GET', 'alice', 3600, '/a');
  audit.logApproval('svc', 'GET', 'bob', 3600, null);
  const tg = fakeTelegram();
  const mgr = new ApprovalManager(tg, audit, 1000);

  assert.equal(mgr.hasActiveApproval('svc', 'GET', '/a'), true);
  // revoke only the path-scoped
  const revoked = mgr.revokeApproval('svc', 'GET', '/a');
  assert.equal(revoked, true);

  // path-scoped gone; method-wide still present → any path still allowed via wide
  assert.equal(mgr.hasActiveApproval('svc', 'GET', '/a'), true);
  assert.equal(mgr.hasActiveApproval('svc', 'GET'), true);

  // revoke method-wide
  const r2 = mgr.revokeApproval('svc', 'GET', null);
  assert.equal(r2, true);
  assert.equal(mgr.hasActiveApproval('svc', 'GET'), false);
});
