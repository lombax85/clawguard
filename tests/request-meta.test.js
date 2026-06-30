const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { extractRequestMeta, META_HEADER_USER, META_HEADER_REASON } = require('../dist/request-meta');
const { AuditLogger } = require('../dist/audit');
const { ApprovalManager } = require('../dist/approval');

function tmpDb() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-meta-'));
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
  const calls = { notifyAutoApproved: [], requestApproval: [] };
  let nextApproval = null;
  return {
    setNext(a) { nextApproval = a; },
    calls,
    notifyAutoApproved(service, method, p, agentIp, reason, meta) {
      calls.notifyAutoApproved.push({ service, method, path: p, agentIp, reason, meta });
    },
    async requestApproval(requestId, service, method, p, agentIp, meta) {
      calls.requestApproval.push({ requestId, service, method, path: p, agentIp, meta });
      return nextApproval || { approved: false, ttlSeconds: 0, approvedBy: 'timeout', pathScoped: false };
    },
    clearPendingRequest() {},
  };
}

test('extractRequestMeta reads user and reason headers', () => {
  const meta = extractRequestMeta({
    [META_HEADER_USER]: 'alice@logotel.it',
    [META_HEADER_REASON]: 'Creating a task in Todoist',
    'content-type': 'application/json',
  });
  assert.equal(meta.user, 'alice@logotel.it');
  assert.equal(meta.reason, 'Creating a task in Todoist');
});

test('extractRequestMeta yields undefined when headers absent or blank', () => {
  assert.deepEqual(extractRequestMeta({}), { user: undefined, reason: undefined });
  assert.deepEqual(
    extractRequestMeta({ [META_HEADER_USER]: '   ', [META_HEADER_REASON]: '' }),
    { user: undefined, reason: undefined },
  );
});

test('extractRequestMeta handles array header values and trims', () => {
  const meta = extractRequestMeta({ [META_HEADER_USER]: ['  bob  ', 'ignored'] });
  assert.equal(meta.user, 'bob');
});

test('extractRequestMeta caps overly long values', () => {
  const long = 'x'.repeat(900);
  const meta = extractRequestMeta({ [META_HEADER_REASON]: long });
  assert.ok(meta.reason.length <= 501);
  assert.ok(meta.reason.endsWith('…'));
});

test('checkApproval forwards meta to telegram requestApproval', async () => {
  const audit = new AuditLogger(tmpDb());
  const tg = fakeTelegram();
  tg.setNext({ approved: true, ttlSeconds: 60, approvedBy: 'alice', pathScoped: false });
  const mgr = new ApprovalManager(tg, audit, 1000);

  const meta = { user: 'alice@logotel.it', reason: 'push commit' };
  const ok = await mgr.checkApproval('svc', makeServiceConfig('require_approval'), 'POST', '/x', '1.2.3.4', meta);
  assert.equal(ok, true);
  assert.equal(tg.calls.requestApproval.length, 1);
  assert.deepEqual(tg.calls.requestApproval[0].meta, meta);
});

test('checkApproval forwards meta to notifyAutoApproved on policy auto-approve', async () => {
  const audit = new AuditLogger(tmpDb());
  const tg = fakeTelegram();
  const mgr = new ApprovalManager(tg, audit, 1000);

  const meta = { user: 'bob', reason: 'read profile' };
  await mgr.checkApproval('svc', makeServiceConfig('auto_approve'), 'GET', '/me', '1.2.3.4', meta);
  assert.equal(tg.calls.notifyAutoApproved.length, 1);
  assert.deepEqual(tg.calls.notifyAutoApproved[0].meta, meta);
});

test('audit.logRequest persists request_user and request_reason', () => {
  const audit = new AuditLogger(tmpDb());
  audit.logRequest({
    timestamp: new Date().toISOString(),
    service: 'svc', method: 'POST', path: '/x', approved: true,
    responseStatus: 200, agentIp: '1.2.3.4',
    requestUser: 'alice@logotel.it', requestReason: 'creating task',
  });
  const rows = audit.getRecentRequests(1);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].request_user, 'alice@logotel.it');
  assert.equal(rows[0].request_reason, 'creating task');
});

test('audit.logRequest stores null provenance when meta absent', () => {
  const audit = new AuditLogger(tmpDb());
  audit.logRequest({
    timestamp: new Date().toISOString(),
    service: 'svc', method: 'GET', path: '/y', approved: true,
    responseStatus: 200, agentIp: '1.2.3.4',
  });
  const rows = audit.getRecentRequests(1);
  assert.equal(rows[0].request_user, null);
  assert.equal(rows[0].request_reason, null);
});
