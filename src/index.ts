import path from 'path';
import { loadConfig } from './config';
import { AuditLogger } from './audit';
import { TelegramNotifier } from './telegram';
import { ApprovalManager } from './approval';
import { createProxy } from './proxy';
import { validateAllUpstreams, validateUpstreamUrl } from './security';

const CONFIG_PATH = process.env['CLAWGUARD_CONFIG'] || process.env['AGENTGATE_CONFIG'] || path.join(process.cwd(), 'clawguard.yaml');

console.log(`
╔══════════════════════════════════════════╗
║   🛡️  ClawGuard v0.2.0                  ║
║   Security gateway for OpenClaw agents   ║
╚══════════════════════════════════════════╝
`);

// Load config
console.log(`📄 Loading config from: ${CONFIG_PATH}`);
const config = loadConfig(CONFIG_PATH);

// Validate upstream security
console.log(`🔒 Validating upstream security:`);
validateAllUpstreams(config);

// Init audit
const auditPath = path.resolve(config.audit.path);
console.log(`📊 Audit log: ${auditPath}`);
const audit = new AuditLogger(auditPath);

// Apply service overrides from admin panel (SQLite)
const overrides = audit.getServiceOverrides();
for (const [name, svcConfig] of Object.entries(overrides)) {
  // Validate override against current allowlist
  const validation = validateUpstreamUrl(svcConfig.upstream, config.security);
  if (!validation.valid) {
    console.warn(`   ⚠️  Service override skipped: ${name} — ${validation.reason}`);
    console.warn(`      Add "${new URL(svcConfig.upstream).hostname}" to security.allowedUpstreams in clawguard.yaml to enable it`);
    continue;
  }
  config.services[name] = svcConfig;
  console.log(`   ↻ Service override loaded: ${name}`);
}

// Init Telegram
const telegram = new TelegramNotifier(config.notifications.telegram, audit);

// Init approval manager (restores active approvals from SQLite)
console.log(`🔑 Restoring approvals:`);
const approvalManager = new ApprovalManager(telegram, audit);

// Create and start proxy
const app = createProxy(config, approvalManager, audit);
const port = config.server.port;

const server = app.listen(port, () => {
  console.log(`\n🚀 ClawGuard proxy running on http://localhost:${port}`);
  console.log(`📡 Configured services:`);
  for (const [name, svc] of Object.entries(config.services)) {
    console.log(`   → ${name}: ${svc.upstream} (${svc.policy.default})`);
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

// Graceful shutdown
function shutdown(): void {
  console.log('\n🛑 Shutting down ClawGuard...');
  telegram.stop();
  audit.close();
  server.close();
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
