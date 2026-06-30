const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { PairThrottle } = require('../dist/pair-throttle');
const { AuditLogger } = require('../dist/audit');

function tmpDb() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-throttle-'));
  return path.join(dir, 'test.db');
}

test('PairThrottle: not throttled under the cap, throttled at the cap', () => {
  let now = 1000;
  const t = new PairThrottle(3, 10000, () => now);
  t.registerFailure('a');
  t.registerFailure('a');
  assert.equal(t.isThrottled('a'), false); // 2 < 3
  t.registerFailure('a');
  assert.equal(t.isThrottled('a'), true);  // 3 >= 3
});

test('PairThrottle: window expiry resets attempts', () => {
  let now = 1000;
  const t = new PairThrottle(2, 5000, () => now);
  t.registerFailure('a');
  t.registerFailure('a');
  assert.equal(t.isThrottled('a'), true);
  now += 6000; // beyond the window
  assert.equal(t.isThrottled('a'), false);
});

test('PairThrottle: reset clears attempts (successful pair)', () => {
  let now = 1000;
  const t = new PairThrottle(2, 5000, () => now);
  t.registerFailure('a');
  t.registerFailure('a');
  assert.equal(t.isThrottled('a'), true);
  t.reset('a');
  assert.equal(t.isThrottled('a'), false);
});

test('PairThrottle: per-key isolation', () => {
  let now = 1000;
  const t = new PairThrottle(1, 5000, () => now);
  t.registerFailure('a');
  assert.equal(t.isThrottled('a'), true);
  assert.equal(t.isThrottled('b'), false);
});

test('pairing is per-chat: unpairing one chat does not affect another', () => {
  const audit = new AuditLogger(tmpDb());
  audit.pairUser('-1001234567890', 'group');
  audit.pairUser('999', 'dm');
  assert.equal(audit.isPairedUser('-1001234567890'), true);

  // Unpairing a different chat must not disturb the group pairing
  // (this is what guarantees a stray /unpair can't disable approvals).
  audit.unpairUser('999');
  assert.equal(audit.isPairedUser('-1001234567890'), true);
  assert.equal(audit.isPairedUser('999'), false);
});
