'use strict';

const dns = require('node:dns').promises;
const fs = require('node:fs');
const path = require('node:path');

const { SshBroker } = require('/app/dist/ssh-broker');
const { SshAgentLeaseManager } = require('/app/dist/ssh-agent-lease');

const resultsDir = '/e2e-results';
const eventsPath = path.join(resultsDir, 'events.ndjson');
const readyPath = path.join(resultsDir, 'broker.ready');
const upstreamPrivateKeyPath = '/e2e-secrets/upstream_identity';
const upstreamHostPublicKeyPath = '/e2e-config/upstream_host.pub';

function readOpenSshPublicKey(filePath) {
  const fields = fs.readFileSync(filePath, 'utf8').trim().split(/\s+/);
  if (fields.length < 2 || !/^ssh-[A-Za-z0-9@._+-]+$/.test(fields[0])) {
    throw new Error(`invalid OpenSSH public key fixture: ${filePath}`);
  }
  return `${fields[0]} ${fields[1]}`;
}

function record(type, id, payload) {
  fs.appendFileSync(eventsPath, `${JSON.stringify({ type, id, ...payload })}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  });
}

async function main() {
  fs.mkdirSync(resultsDir, { recursive: true, mode: 0o700 });
  try { fs.unlinkSync(readyPath); } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const retainedPrivateKey = fs.readFileSync(upstreamPrivateKeyPath);
  const knownHostKey = readOpenSshPublicKey(upstreamHostPublicKeyPath);
  const leaseTtlSecondsText = process.env.E2E_LEASE_TTL_SECONDS || '30';
  if (!/^[1-9][0-9]*$/.test(leaseTtlSecondsText)) {
    throw new Error('E2E_LEASE_TTL_SECONDS must be a positive integer');
  }
  const leaseTtlSeconds = Number(leaseTtlSecondsText);
  const maxConcurrentLeasesText = process.env.E2E_MAX_CONCURRENT_LEASES || '4';
  if (!/^[1-9][0-9]*$/.test(maxConcurrentLeasesText)) {
    throw new Error('E2E_MAX_CONCURRENT_LEASES must be a positive integer');
  }
  const maxConcurrentLeases = Number(maxConcurrentLeasesText);
  const runtimeDir = '/run/clawguard-ssh';
  const socketPath = path.join(runtimeDir, 'broker.sock');

  const config = {
    server: { port: 9090, agentKey: 'e2e-unused' },
    services: {
      production: {
        protocol: 'ssh',
        upstream: 'ssh://upstream:2222',
        auth: {
          type: 'plugin',
          token: 'unused',
          pluginPath: 'e2e-memory-key',
          pluginConfig: {},
        },
        policy: { default: 'require_approval' },
        ssh: { knownHostKey, allowPrivateTarget: true },
      },
    },
    security: {
      allowedUpstreams: ['upstream'],
      blockPrivateIPs: true,
      followRedirects: false,
      maxPayloadLogSize: 1024,
    },
    admin: { enabled: false, pin: '', allowedIPs: [], strictMode: true },
    proxy: { enabled: false, caDir: '/tmp/e2e-ca', discovery: false, discoveryPolicy: 'block' },
    transparentProxy: { enabled: false, httpPort: 8080, httpsPort: 8443 },
    audit: { type: 'sqlite', path: '/tmp/e2e-unused.db', logPayload: false },
    sshBroker: {
      enabled: true,
      runtimeDir,
      socketPath,
      gatewayUid: 10001,
      gatewayGid: 10001,
      approvalTimeoutMs: 5000,
      credentialTimeoutMs: 5000,
      leaseTtlSeconds,
      maxSessionSeconds: 30,
      sshAgentPath: '/usr/bin/ssh-agent',
      sshAddPath: '/usr/bin/ssh-add',
      maxConcurrentLeases,
    },
  };

  const leaseManager = new SshAgentLeaseManager(config.sshBroker);
  const audit = {
    startSshSession(entry) {
      record('start', entry.id, entry);
    },
    updateSshSession(id, update) {
      record('update', id, update);
      return true;
    },
    finalizeSshSession(id, final) {
      record('final', id, final);
      return true;
    },
  };
  const approvalManager = {
    async checkSshSessionApproval() {
      return true;
    },
  };
  const credentialPlugin = {
    name: 'e2e-memory-key',
    async getCredentials(context) {
      if (context.serviceName !== 'production') {
        throw new Error('unexpected E2E SSH service');
      }
      return { username: 'deploy', privateKey: Buffer.from(retainedPrivateKey) };
    },
  };

  const broker = new SshBroker(config, {
    approvalManager,
    audit,
    leaseManager,
    credentialPluginForService(serviceName) {
      return serviceName === 'production' ? credentialPlugin : undefined;
    },
    async validateTarget() {
      const result = await dns.lookup('upstream', { family: 4 });
      return { valid: true, resolvedAddresses: [result.address] };
    },
  });

  let stopping = false;
  async function stop(signal) {
    if (stopping) return;
    stopping = true;
    record('process', 'broker', { outcome: 'stopping', signal });
    try {
      await broker.close();
      await leaseManager.close();
      retainedPrivateKey.fill(0);
      process.exit(0);
    } catch (error) {
      console.error(error);
      retainedPrivateKey.fill(0);
      process.exit(1);
    }
  }

  process.on('SIGTERM', () => { void stop('SIGTERM'); });
  process.on('SIGINT', () => { void stop('SIGINT'); });

  await broker.start();
  fs.writeFileSync(readyPath, 'ready\n', { encoding: 'utf8', mode: 0o600 });
  record('process', 'broker', { outcome: 'ready' });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
