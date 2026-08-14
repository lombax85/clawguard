const test = require('node:test');
const assert = require('node:assert/strict');

const { validateHttpConfiguration } = require('../dist/config');

function config(service) {
  return { services: { target: service } };
}

test('HTTP private target and self-signed TLS require explicit booleans', () => {
  const errors = validateHttpConfiguration(config({
    upstream: 'https://192.168.88.3',
    auth: { type: 'plugin', token: 'unused' },
    policy: { default: 'require_approval' },
    http: { allowPrivateTarget: true, noCheckCertificate: true },
  }));
  assert.deepEqual(errors, []);
});

test('HTTP TLS bypass is rejected for plaintext upstream', () => {
  const errors = validateHttpConfiguration(config({
    upstream: 'http://192.168.88.3',
    auth: { type: 'plugin', token: 'unused' },
    policy: { default: 'require_approval' },
    http: { allowPrivateTarget: true, noCheckCertificate: true },
  }));
  assert.equal(errors.some((error) => error.includes('only for an HTTPS upstream')), true);
});

test('non-HTTP services cannot define HTTP target exceptions', () => {
  const errors = validateHttpConfiguration(config({
    protocol: 'ssh',
    upstream: 'ssh://192.168.88.3:22',
    auth: { type: 'plugin', token: 'unused' },
    policy: { default: 'require_approval' },
    http: { allowPrivateTarget: true },
  }));
  assert.equal(errors.some((error) => error.includes('must not define service.http')), true);
});
