const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

const { createAdminRouter } = require('../dist/admin');

function makeConfig(strictMode) {
  return {
    admin: {
      enabled: true,
      pin: '1234',
      strictMode,
      allowedIPs: ['127.0.0.1', '::1', '::ffff:127.0.0.1'],
    },
    services: {
      existing: {
        upstream: 'https://api.example.com',
        auth: { type: 'bearer', token: 'secret' },
        policy: { default: 'require_approval' },
      },
    },
    security: {
      allowedUpstreams: ['api.example.com'],
      blockPrivateIPs: true,
      followRedirects: false,
      maxPayloadLogSize: 10240,
    },
  };
}

function fakeApprovalManager() {
  return {
    getActiveCount: () => 0,
    getStatus: () => ({}),
    revokeApproval: () => true,
    revokeAll: () => 0,
  };
}

function fakeAudit() {
  const calls = { saveServiceOverride: [] };
  return {
    calls,
    getDashboardStats: () => ({
      totalRequestsToday: 0,
      totalRequestsWeek: 0,
      activeApprovals: 0,
      configuredServices: 0,
      requestsByService: [],
      requestsByHour: [],
      approvalStats: { approved: 0, denied: 0, timeout: 0 },
      methodBreakdown: [],
      availableServices: [],
    }),
    saveServiceOverride: (name, config) => calls.saveServiceOverride.push({ name, config }),
    deleteServiceOverride: () => {},
    getRecentApprovals: () => [],
    getRecentRequests: () => [],
    getPairedUsers: () => [],
  };
}

async function withAdminServer(config, fn) {
  const app = express();
  app.use(express.raw({ type: '*/*', limit: '1mb' }));
  const audit = fakeAudit();
  app.use('/__admin', createAdminRouter(config, fakeApprovalManager(), audit));
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await fn(`http://127.0.0.1:${port}/__admin`, audit);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('admin strict mode blocks service override writes', async () => {
  const config = makeConfig(true);
  await withAdminServer(config, async (base, audit) => {
    const res = await fetch(`${base}/api/services`, {
      method: 'POST',
      headers: { 'x-clawguard-pin': '1234', 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'newsvc',
        config: {
          upstream: 'https://api.example.com',
          auth: { type: 'bearer', token: 'secret' },
          policy: { default: 'require_approval' },
        },
      }),
    });

    assert.equal(res.status, 403);
    assert.equal(audit.calls.saveServiceOverride.length, 0);
    assert.equal(config.services.newsvc, undefined);
  });
});

test('admin editable mode persists service overrides and updates runtime config', async () => {
  const config = makeConfig(false);
  await withAdminServer(config, async (base, audit) => {
    const serviceConfig = {
      upstream: 'https://api.example.com',
      auth: { type: 'bearer', token: 'secret' },
      policy: { default: 'require_approval' },
    };

    const res = await fetch(`${base}/api/services`, {
      method: 'POST',
      headers: { 'x-clawguard-pin': '1234', 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'newsvc', config: serviceConfig }),
    });

    assert.equal(res.status, 200);
    assert.equal(audit.calls.saveServiceOverride.length, 1);
    assert.deepEqual(config.services.newsvc, serviceConfig);
  });
});
