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
