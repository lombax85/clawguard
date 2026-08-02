import path from 'path';
import https from 'https';
import express from 'express';
import { loadConfig } from './config';
import { AuditLogger } from './audit';
import { TelegramNotifier } from './telegram';
import { WebhookNotifier } from './webhook';
import { ApprovalManager } from './approval';
import { createProxy } from './proxy';
import { validateAllUpstreams, validateSshTargetRuntime, validateUpstreamUrl } from './security';
import { CertManager } from './cert-manager';
import { attachMitmProxy } from './mitm-proxy';
import { startTransparentProxy } from './transparent-proxy';
import { loadPlugin } from './auth-plugins/loader';
import { createAdminRouter } from './admin';
import { loadSshCredentialPlugin } from './ssh-credential-plugins/loader';
import { SshAgentLeaseManager } from './ssh-agent-lease';
import { SshBroker } from './ssh-broker';

const CONFIG_PATH = process.env['CLAWGUARD_CONFIG'] || process.env['AGENTGATE_CONFIG'] || path.join(process.cwd(), 'clawguard.yaml');

async function main() {
  console.log(`
╔══════════════════════════════════════════╗
║   🛡️  ClawGuard v0.2.0                  ║
║   Security gateway for OpenClaw agents   ║
╚══════════════════════════════════════════╝
`);

  // Load config
  console.log(`📄 Loading config from: ${CONFIG_PATH}`);
  const config = await loadConfig(CONFIG_PATH);

  // Validate upstream security
  console.log(`🔒 Validating upstream security:`);
  validateAllUpstreams(config);

  // Init audit
  const auditPath = path.resolve(config.audit.path);
  console.log(`📊 Audit log: ${auditPath}`);
  const audit = new AuditLogger(auditPath);

  // Apply service overrides from admin panel (SQLite)
  if (config.admin.strictMode) {
    console.log('   🔒 Admin strict mode enabled: service overrides are ignored; YAML is the source of truth');
  } else {
    const overrides = audit.getServiceOverrides();
    for (const [name, svcConfig] of Object.entries(overrides)) {
      // SSH services are always sourced from YAML. A stale HTTP override may
      // not shadow one, and an override may never introduce SSH dynamically.
      if (config.services[name]?.protocol === 'ssh'
        || svcConfig.protocol === 'ssh'
        || svcConfig.ssh !== undefined) {
        console.warn(`   ⚠️  SSH service override ignored: ${name} (SSH is YAML-only)`);
        continue;
      }
      if (svcConfig.protocol !== undefined && svcConfig.protocol !== 'http') {
        console.warn(`   ⚠️  Service override skipped: ${name} — unsupported protocol`);
        continue;
      }
      // Validate override against current allowlist
      const validation = validateUpstreamUrl(svcConfig.upstream, config.security);
      if (!validation.valid) {
        console.warn(`   ⚠️  Service override skipped: ${name} — ${validation.reason}`);
        console.warn(`      Add "${new URL(svcConfig.upstream).hostname}" to security.allowedUpstreams in clawguard.yaml to enable it`);
        continue;
      }
      svcConfig.protocol = 'http';
      config.services[name] = svcConfig;
      console.log(`   ↻ Service override loaded: ${name}`);
    }
  }

  // Init Telegram (optional — if not configured, approvals are auto-approved)
  let telegram: TelegramNotifier | undefined;
  if (config.notifications?.telegram?.botToken) {
    telegram = new TelegramNotifier(config.notifications.telegram, audit);
  } else {
    console.log('📱 Telegram: disabled (not configured)');
  }

  // Init Webhook (optional informational side channel — fire-and-forget)
  let webhookNotifier: WebhookNotifier | undefined;
  if (config.notifications?.webhook?.enabled) {
    webhookNotifier = new WebhookNotifier(config.notifications.webhook);
  } else {
    console.log('🪝 Webhook: disabled (not configured)');
  }

  // Init approval manager (restores active approvals from SQLite)
  console.log(`🔑 Restoring approvals:`);
  const approvalManager = new ApprovalManager(telegram, audit, undefined, webhookNotifier);

  // Create and start proxy
  const app = createProxy(config, approvalManager, audit, telegram);
  const port = config.server.port;

  // Load auth plugins BEFORE accepting requests
  const PLUGIN_DATA_DIR = path.resolve('data/plugins');
  const SSH_PLUGIN_DATA_DIR = path.resolve('data/ssh-credential-plugins');
  for (const [name, svc] of Object.entries(config.services)) {
    if (svc.auth.type === 'plugin' && svc.auth.pluginPath) {
      try {
        if (svc.protocol === 'ssh') {
          await loadSshCredentialPlugin(
            name,
            svc.auth.pluginPath,
            svc.auth.pluginConfig || {},
            SSH_PLUGIN_DATA_DIR
          );
        } else {
          await loadPlugin(name, svc.auth.pluginPath, svc.auth.pluginConfig || {}, PLUGIN_DATA_DIR);
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        console.error(`❌ Failed to load plugin for ${name}: ${message}`);
        process.exit(1);
      }
    }
  }

  // Resolve SSH targets before accepting sessions. The broker repeats this on
  // every request and gives the sidecar the validated IP, avoiding a second
  // untrusted DNS lookup between policy evaluation and connection.
  for (const [name, svc] of Object.entries(config.services)) {
    if (svc.protocol !== 'ssh') continue;
    const validation = await validateSshTargetRuntime(svc, config.security);
    if (!validation.valid) {
      throw new Error(`SSH target validation failed for ${name}: ${validation.reason}`);
    }
    console.log(`   ✓ SSH target resolved and validated: ${name}`);
  }

  let sshLeaseManager: SshAgentLeaseManager | undefined;
  let sshBroker: SshBroker | undefined;
  if (config.sshBroker.enabled) {
    sshLeaseManager = new SshAgentLeaseManager({
      runtimeDir: config.sshBroker.runtimeDir,
      gatewayUid: config.sshBroker.gatewayUid,
      gatewayGid: config.sshBroker.gatewayGid,
      leaseTtlSeconds: config.sshBroker.leaseTtlSeconds,
      maxConcurrentLeases: config.sshBroker.maxConcurrentLeases,
      sshAgentPath: config.sshBroker.sshAgentPath,
      sshAddPath: config.sshBroker.sshAddPath,
    });
    sshBroker = new SshBroker(config, {
      approvalManager,
      audit,
      leaseManager: sshLeaseManager,
    });
    await sshBroker.start();
    console.log(`🔐 Experimental SSH broker: ${config.sshBroker.socketPath}`);
  }

  const server = app.listen(port, () => {
    console.log(`\n🚀 ClawGuard proxy running on http://localhost:${port}`);
    console.log(`📡 Configured services:`);
    for (const [name, svc] of Object.entries(config.services)) {
      const detail = svc.protocol === 'ssh' ? 'one-time SSH approval' : svc.policy.default;
      console.log(`   → ${name}: ${svc.upstream} (${detail})`);
    }
    console.log(`\n🔑 Agent key header: X-ClawGuard-Key`);
    console.log(`📊 Status:    http://localhost:${port}/__status`);
    console.log(`📋 Audit:     http://localhost:${port}/__audit`);
    if (config.admin.enabled) {
      console.log(`🖥️  Dashboard: http://localhost:${port}/__admin`);
    }
    if (config.audit.logPayload) {
      console.log(`📦 Payload logging: ENABLED`);
    }
    console.log(`\n⏳ Waiting for requests...\n`);
  });

  // ─── Cert Manager ──────────────────────────────────────────────

  let certManager: CertManager | undefined;
  if (config.proxy.enabled || config.transparentProxy.enabled || config.admin.https?.enabled) {
    const caDir = path.resolve(config.proxy.caDir);
    certManager = new CertManager(caDir);
  }

  // ─── Admin HTTPS listener ────────────────────────────────────
  // A second listener that serves only the admin dashboard over TLS.
  // Required to enable Web Push / Service Workers in the browser
  // (those APIs are gated to secure contexts: https or http://localhost).

  let httpsServer: https.Server | undefined;
  if (config.admin.enabled && config.admin.https?.enabled && certManager) {
    const httpsCfg = config.admin.https;
    const userHostnames = httpsCfg.hostnames || [];
    const dnsNames = ['localhost', ...userHostnames.filter((h) => !/^\d+\.\d+\.\d+\.\d+$/.test(h) && h !== 'localhost')];
    const ips = ['127.0.0.1', ...userHostnames.filter((h) => /^\d+\.\d+\.\d+\.\d+$/.test(h) && h !== '127.0.0.1')];

    const pair = certManager.getServerCert('admin', dnsNames, ips);

    const adminApp = express();
    adminApp.use(express.raw({ type: '*/*', limit: '10mb' }));
    adminApp.use('/__admin', createAdminRouter(config, approvalManager, audit, telegram));

    httpsServer = https.createServer({ cert: pair.cert, key: pair.key }, adminApp);
    httpsServer.listen(httpsCfg.port, () => {
      console.log(`\n🔐 Admin HTTPS listener: https://localhost:${httpsCfg.port}/__admin`);
      console.log(`   Certificate SAN: DNS=[${dnsNames.join(', ')}] IP=[${ips.join(', ')}]`);
      console.log(`   Trust this CA in your browser/Keychain: ${certManager!.getCaCertPath()}`);
    });
  }

  // ─── HTTPS_PROXY MITM mode ───────────────────────────────────

  if (config.proxy.enabled && certManager) {
    console.log(`🔀 HTTPS_PROXY mode: ENABLED`);
    attachMitmProxy(server, config, approvalManager, audit, certManager, telegram);
    console.log(`   CA cert: ${certManager.getCaCertPath()}`);
    console.log(`   Usage:   export HTTPS_PROXY=http://AGENT_KEY:x@CLAWGUARD_HOST:${port}`);
    console.log(`   Trust:   NODE_EXTRA_CA_CERTS=${certManager.getCaCertPath()}`);
  }

  // ─── Transparent Proxy sidecar mode ──────────────────────────

  if (config.transparentProxy.enabled && certManager) {
    console.log(`🔀 Transparent Proxy mode: ENABLED`);
    startTransparentProxy(config, approvalManager, audit, certManager);
  }

  // Graceful shutdown
  let shuttingDown = false;
  async function shutdown(): Promise<void> {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log('\n🛑 Shutting down ClawGuard...');
    telegram?.stop();
    await sshBroker?.close();
    await sshLeaseManager?.close();
    await Promise.all([
      new Promise<void>((resolve) => server.close(() => resolve())),
      new Promise<void>((resolve) => {
        if (!httpsServer) {
          resolve();
          return;
        }
        httpsServer.close(() => resolve());
      }),
    ]);
    audit.close();
    process.exit(0);
  }

  process.on('SIGINT', () => { void shutdown(); });
  process.on('SIGTERM', () => { void shutdown(); });
}

main().catch((err) => {
  console.error('❌ Fatal error during startup:', err.message || err);
  process.exit(1);
});
