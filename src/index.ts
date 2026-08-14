import path from 'path';
import https from 'https';
import express from 'express';
import { loadConfig } from './config';
import { AuditLogger } from './audit';
import { TelegramNotifier } from './telegram';
import { WebhookNotifier } from './webhook';
import { ApprovalManager } from './approval';
import { createProxy } from './proxy';
import {
  validateAllUpstreams,
  validateFtpTargetRuntime,
  validateSshTargetRuntime,
  validateUpstreamUrl,
} from './security';
import { CertManager } from './cert-manager';
import { attachMitmProxy } from './mitm-proxy';
import { startTransparentProxy } from './transparent-proxy';
import { loadPlugin } from './auth-plugins/loader';
import { createAdminRouter } from './admin';
import { loadSshCredentialPlugin } from './ssh-credential-plugins/loader';
import { SshAgentLeaseManager } from './ssh-agent-lease';
import { SshBroker } from './ssh-broker';
import { loadFtpCredentialPlugin } from './ftp-credential-plugins/loader';
import { FtpGatewayClient } from './ftp-gateway-client';
import { FtpBroker } from './ftp-broker';
import { createFtpRouter } from './ftp-router';

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
      // Protocol gateways are always sourced from YAML. A stale HTTP override
      // may neither shadow nor dynamically introduce one.
      if ((config.services[name]?.protocol ?? 'http') !== 'http'
        || (svcConfig.protocol ?? 'http') !== 'http'
        || svcConfig.ssh !== undefined
        || svcConfig.ftp !== undefined
        || config.services[name]?.http?.allowPrivateTarget === true
        || config.services[name]?.http?.noCheckCertificate === true
        || svcConfig.http?.allowPrivateTarget === true
        || svcConfig.http?.noCheckCertificate === true) {
        console.warn(`   ⚠️  Service override ignored: ${name} (protocol gateways are YAML-only)`);
        continue;
      }
      if (svcConfig.protocol !== undefined && svcConfig.protocol !== 'http') {
        console.warn(`   ⚠️  Service override skipped: ${name} — unsupported protocol`);
        continue;
      }
      // Validate override against current allowlist
      const validation = validateUpstreamUrl(
        svcConfig.upstream,
        config.security,
        false
      );
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

  const port = config.server.port;

  // Load auth plugins BEFORE accepting requests
  const PLUGIN_DATA_DIR = path.resolve('data/plugins');
  const SSH_PLUGIN_DATA_DIR = path.resolve('data/ssh-credential-plugins');
  const FTP_PLUGIN_DATA_DIR = path.resolve('data/ftp-credential-plugins');
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
        } else if (svc.protocol === 'ftp' || svc.protocol === 'ftps') {
          await loadFtpCredentialPlugin(
            name,
            svc.auth.pluginPath,
            svc.auth.pluginConfig || {},
            FTP_PLUGIN_DATA_DIR
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

  // Resolve protocol targets before accepting sessions. Brokers repeat this
  // on every request and pin the validated address set in their sidecars.
  for (const [name, svc] of Object.entries(config.services)) {
    if (svc.protocol !== 'ssh' && svc.protocol !== 'ftp' && svc.protocol !== 'ftps') continue;
    const validation = svc.protocol === 'ssh'
      ? await validateSshTargetRuntime(svc, config.security)
      : await validateFtpTargetRuntime(svc, config.security);
    if (!validation.valid) {
      throw new Error(`${svc.protocol.toUpperCase()} target validation failed for ${name}: ${validation.reason}`);
    }
    console.log(`   ✓ ${svc.protocol.toUpperCase()} target resolved and validated: ${name}`);
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

  let ftpBroker: FtpBroker | undefined;
  if (config.ftpGateway.enabled) {
    const gateway = new FtpGatewayClient(
      config.ftpGateway.socketPath,
      config.ftpGateway.gatewayTimeoutMs
    );
    ftpBroker = new FtpBroker(config, { approvalManager, audit, gateway });
    console.log(`🔐 Experimental FTP/FTPS gateway: ${config.ftpGateway.socketPath}`);
  }

  // Construct the HTTP app only after all credential plugins and protocol
  // brokers are ready, so no request can race startup initialization.
  const app = createProxy(config, approvalManager, audit, telegram, ftpBroker);

  const server = app.listen(port, () => {
    console.log(`\n🚀 ClawGuard proxy running on http://localhost:${port}`);
    console.log(`📡 Configured services:`);
    for (const [name, svc] of Object.entries(config.services)) {
      const detail = svc.protocol === 'ssh'
        ? 'one-time SSH approval'
        : svc.protocol === 'ftp' || svc.protocol === 'ftps'
          ? 'bounded FTP lease approval'
          : svc.policy.default;
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
  // A second listener for the admin dashboard and authenticated FTP lease API.
  // It also keeps browser features that require a secure context available.

  let httpsServer: https.Server | undefined;
  if (config.admin.enabled && config.admin.https?.enabled && certManager) {
    const httpsCfg = config.admin.https;
    const userHostnames = httpsCfg.hostnames || [];
    const dnsNames = ['localhost', ...userHostnames.filter((h) => !/^\d+\.\d+\.\d+\.\d+$/.test(h) && h !== 'localhost')];
    const ips = ['127.0.0.1', ...userHostnames.filter((h) => /^\d+\.\d+\.\d+\.\d+$/.test(h) && h !== '127.0.0.1')];

    const pair = certManager.getServerCert('admin', dnsNames, ips);

    const adminApp = express();
    adminApp.use(express.raw({ type: '*/*', limit: '10mb' }));
    // Lease responses contain an ephemeral gateway password. Expose the same
    // authenticated API on the optional TLS listener so remote agents need
    // not mint leases over the plaintext HTTP proxy port.
    if (ftpBroker) adminApp.use('/__ftp', createFtpRouter(config, ftpBroker));
    adminApp.use('/__admin', createAdminRouter(config, approvalManager, audit, telegram));

    httpsServer = https.createServer({ cert: pair.cert, key: pair.key }, adminApp);
    httpsServer.listen(httpsCfg.port, () => {
      console.log(`\n🔐 Admin HTTPS listener: https://localhost:${httpsCfg.port}/__admin`);
      console.log(`   Certificate SAN: DNS=[${dnsNames.join(', ')}] IP=[${ips.join(', ')}]`);
      console.log(`   Trust this CA in your browser/Keychain: ${certManager!.getCaCertPath()}`);
      if (ftpBroker) console.log(`   FTP lease API: https://localhost:${httpsCfg.port}/__ftp/session`);
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
    // Stop accepting new requests before waiting for protocol brokers and
    // Telegram's active long poll to finish.
    await Promise.all([
      new Promise<void>((resolve) => server.close(() => resolve())),
      new Promise<void>((resolve) => {
        if (!httpsServer) {
          resolve();
          return;
        }
        httpsServer.close(() => resolve());
      }),
      telegram?.stop(),
      ftpBroker?.close(),
      sshBroker?.close(),
      sshLeaseManager?.close(),
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
