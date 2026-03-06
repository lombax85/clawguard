const test = require('node:test');
const assert = require('node:assert/strict');

const {
  getPassthroughHosts,
  __resetDiscoveredHostsForTests,
  __trackDiscoveredHostForTests,
} = require('../dist/mitm-proxy');

test('discovered hosts list is capped to prevent unbounded memory growth', () => {
  __resetDiscoveredHostsForTests();

  for (let i = 0; i < 1105; i++) {
    __trackDiscoveredHostForTests(`host-${i}.example.com`, 'GET', '/v1/test');
  }

  const hosts = getPassthroughHosts();
  assert.equal(hosts.length, 1000);
  // oldest entries should be evicted
  assert.equal(hosts.some((h) => h.hostname === 'host-0.example.com'), false);
  assert.equal(hosts.some((h) => h.hostname === 'host-1104.example.com'), true);
});

test('tracking same host updates counter without increasing total entries', () => {
  __resetDiscoveredHostsForTests();

  __trackDiscoveredHostForTests('api.example.com', 'GET', '/a');
  __trackDiscoveredHostForTests('api.example.com', 'POST', '/b');

  const hosts = getPassthroughHosts();
  assert.equal(hosts.length, 1);
  assert.equal(hosts[0].hostname, 'api.example.com');
  assert.equal(hosts[0].count, 2);
  assert.deepEqual(new Set(hosts[0].methods), new Set(['GET', 'POST']));
});
