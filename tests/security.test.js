const test = require('node:test');
const assert = require('node:assert/strict');

const {
  isPrivateIP,
  isAllowedUpstream,
  validateUpstreamUrl,
  validateRuntimeUrl,
} = require('../dist/security');

const baseSecurity = {
  allowedUpstreams: ['api.github.com', 'todoist.com'],
  blockPrivateIPs: true,
  enforceHostnameMatch: true,
};

test('isPrivateIP recognizes common private and public IPv4', () => {
  assert.equal(isPrivateIP('127.0.0.1'), true);
  assert.equal(isPrivateIP('10.0.0.1'), true);
  assert.equal(isPrivateIP('192.168.1.50'), true);
  assert.equal(isPrivateIP('8.8.8.8'), false);
});

test('isPrivateIP blocks IPv4-mapped IPv6 addresses', () => {
  assert.equal(isPrivateIP('::ffff:127.0.0.1'), true);
  assert.equal(isPrivateIP('::ffff:7f00:1'), true);
  // Mapped public addresses are rejected conservatively instead of being
  // reinterpreted inconsistently by downstream networking APIs.
  assert.equal(isPrivateIP('::ffff:8.8.8.8'), true);
});

test('isAllowedUpstream supports exact domain and subdomain', () => {
  assert.equal(isAllowedUpstream('api.github.com', ['api.github.com']), true);
  assert.equal(isAllowedUpstream('sub.todoist.com', ['todoist.com']), true);
  assert.equal(isAllowedUpstream('evil.com', ['todoist.com']), false);
});

test('validateUpstreamUrl rejects unsupported protocol', () => {
  const result = validateUpstreamUrl('ftp://api.github.com/resource', baseSecurity);
  assert.equal(result.valid, false);
  assert.match(result.reason || '', /Unsupported protocol/);
});

test('validateUpstreamUrl rejects allowlist miss', () => {
  const result = validateUpstreamUrl('https://example.org/path', baseSecurity);
  assert.equal(result.valid, false);
  assert.match(result.reason || '', /allowed upstreams/i);
});

test('validateUpstreamUrl rejects private IP when blockPrivateIPs=true', () => {
  const result = validateUpstreamUrl('https://127.0.0.1/internal', {
    ...baseSecurity,
    allowedUpstreams: ['127.0.0.1'],
  });
  assert.equal(result.valid, false);
  assert.match(result.reason || '', /private IP/i);
});

test('validateUpstreamUrl allows one explicitly opted-in private HTTP target', () => {
  const result = validateUpstreamUrl('https://192.168.88.3/sdk', {
    ...baseSecurity,
    allowedUpstreams: ['192.168.88.3'],
  }, true);
  assert.equal(result.valid, true);
});

test('validateRuntimeUrl keeps private-target opt-in pinned to configured host', () => {
  const security = { ...baseSecurity, allowedUpstreams: ['192.168.88.3', '192.168.88.4'] };
  assert.equal(validateRuntimeUrl(
    'https://192.168.88.3/sdk', 'https://192.168.88.3', security, true
  ).valid, true);
  const mismatch = validateRuntimeUrl(
    'https://192.168.88.4/sdk', 'https://192.168.88.3', security, true
  );
  assert.equal(mismatch.valid, false);
  assert.match(mismatch.reason || '', /Path traversal detected/);
});

test('validateRuntimeUrl rejects host mismatch (path traversal protection)', () => {
  const result = validateRuntimeUrl(
    'https://evil.com/api',
    'https://api.github.com',
    baseSecurity
  );
  assert.equal(result.valid, false);
  assert.match(result.reason || '', /Path traversal detected/);
});

test('validateRuntimeUrl accepts same host and allowed policy', () => {
  const result = validateRuntimeUrl(
    'https://api.github.com/repos/lombax85/clawguard',
    'https://api.github.com',
    baseSecurity
  );
  assert.equal(result.valid, true);
});
