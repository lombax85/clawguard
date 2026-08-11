import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';
import { Config, FtpGatewayConfig, ServiceConfig, SshBrokerConfig } from './types';
import { createSecretProviders, resolveSecretValue, SecretProvider } from './secrets/provider';
import { validateFtpService, validateSshService } from './security';

function substituteEnvVars(str: string): string {
  return str.replace(/\$\{(\w+)\}/g, (match, varName) => {
    const val = process.env[varName];
    if (!val) {
      console.error(`❌ Required environment variable ${varName} is not set`);
      process.exit(1);
    }
    return val;
  });
}

function deepSubstitute(obj: unknown): unknown {
  if (typeof obj === 'string') {
    // Only substitute if the string contains ${...} pattern
    if (obj.includes('${')) {
      return substituteEnvVars(obj);
    }
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(deepSubstitute);
  }
  if (obj && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = deepSubstitute(value);
    }
    return result;
  }
  return obj;
}

const DEFAULT_SECURITY = {
  allowedUpstreams: [],
  blockPrivateIPs: true,
  followRedirects: false,
  maxPayloadLogSize: 10240, // 10KB
};

const DEFAULT_ADMIN = {
  enabled: true,
  pin: '',
  allowedIPs: ['127.0.0.1', '::1', '::ffff:127.0.0.1', '172.16.0.0/12'],
  strictMode: true,
};

const DEFAULT_ADMIN_HTTPS = {
  enabled: false,
  port: 9443,
  hostnames: [] as string[],
};

const DEFAULT_AUDIT = {
  type: 'sqlite' as const,
  path: './clawguard.db',
  logPayload: false,
};

const DEFAULT_PROXY = {
  enabled: false,
  caDir: './data/ca',
  discovery: false,
  discoveryPolicy: 'block' as const,
};

const DEFAULT_TRANSPARENT_PROXY = {
  enabled: false,
  httpPort: 8080,
  httpsPort: 8443,
};

export const DEFAULT_SSH_BROKER: SshBrokerConfig = {
  enabled: false,
  socketPath: '/run/clawguard-ssh/broker.sock',
  runtimeDir: '/run/clawguard-ssh',
  gatewayUid: 10001,
  gatewayGid: 10001,
  approvalTimeoutMs: 90000,
  credentialTimeoutMs: 30000,
  leaseTtlSeconds: 120,
  maxSessionSeconds: 3600,
  sshAgentPath: '/usr/bin/ssh-agent',
  sshAddPath: '/usr/bin/ssh-add',
  maxConcurrentLeases: 10,
};

export const DEFAULT_FTP_GATEWAY: FtpGatewayConfig = {
  enabled: false,
  socketPath: '/run/clawguard-ftp/gateway.sock',
  publicHost: 'localhost',
  allowInsecureHttpApi: false,
  approvalTimeoutMs: 90000,
  credentialTimeoutMs: 30000,
  gatewayTimeoutMs: 10000,
  sessionTtlSeconds: 3600,
  maxConcurrentSessions: 10,
  controlPortStart: 21210,
  controlPortEnd: 21219,
  passivePortStart: 30000,
  passivePortsPerSession: 10,
};

const DEFAULT_TELEGRAM_PAIRING = {
  enabled: true,
  secret: '',
};

/** Applies SSH-related defaults without making invalid input silently safe. */
export function normalizeSshConfiguration(config: Config): void {
  config.sshBroker = { ...DEFAULT_SSH_BROKER, ...(config.sshBroker || {}) };
  for (const service of Object.values(config.services || {})) {
    service.protocol = service.protocol ?? 'http';
  }
}

/** Applies FTP/FTPS gateway defaults without enabling the experimental path. */
export function normalizeFtpConfiguration(config: Config): void {
  config.ftpGateway = { ...DEFAULT_FTP_GATEWAY, ...(config.ftpGateway || {}) };
}

export function validateFtpConfiguration(config: Config): string[] {
  const errors: string[] = [];
  const services = Object.entries(config.services || {});
  const ftpServices = services.filter(([, service]) => service.protocol === 'ftp' || service.protocol === 'ftps');

  for (const [name, service] of services) {
    const protocol = service.protocol ?? 'http';
    if (protocol !== 'ftp' && protocol !== 'ftps') {
      if (service.ftp !== undefined) {
        errors.push(`${protocol.toUpperCase()} service "${name}" must not define service.ftp`);
      }
      continue;
    }

    if (name.length > 64 || !/^[A-Za-z0-9_-]+$/.test(name)) {
      errors.push(`FTP service alias "${name}" must be 1-64 letters, digits, hyphens, or underscores`);
    }
    if (service.auth?.type !== 'plugin') {
      errors.push(`FTP service "${name}" must use auth.type: plugin`);
    }
    if (typeof service.auth?.pluginPath !== 'string' || service.auth.pluginPath.trim().length === 0) {
      errors.push(`FTP service "${name}" must define auth.pluginPath`);
    }
    if (service.hostnames !== undefined) {
      errors.push(`FTP service "${name}" must not define HTTP hostnames`);
    }

    const validation = validateFtpService(service, config.security);
    if (!validation.valid) errors.push(`FTP service "${name}": ${validation.reason}`);
  }

  const gateway = config.ftpGateway;
  if (ftpServices.length > 0 && !gateway?.enabled) {
    errors.push('ftpGateway.enabled must be true when FTP/FTPS services are configured');
  }
  if (!gateway?.enabled) return errors;

  if (!path.isAbsolute(gateway.socketPath || '')) {
    errors.push('ftpGateway.socketPath must be an absolute path');
  }
  if (typeof gateway.publicHost !== 'string'
    || gateway.publicHost.length === 0
    || gateway.publicHost.length > 253
    || /[\s/:]/.test(gateway.publicHost)) {
    errors.push('ftpGateway.publicHost must be a hostname or IPv4 address without scheme or port');
  }
  if (typeof gateway.allowInsecureHttpApi !== 'boolean') {
    errors.push('ftpGateway.allowInsecureHttpApi must be true or false');
  } else if (!gateway.allowInsecureHttpApi
    && (!config.admin?.enabled || !config.admin.https?.enabled)) {
    errors.push('FTP lease credentials require admin.https.enabled or explicit ftpGateway.allowInsecureHttpApi: true');
  }
  for (const [field, value] of [
    ['approvalTimeoutMs', gateway.approvalTimeoutMs],
    ['credentialTimeoutMs', gateway.credentialTimeoutMs],
    ['gatewayTimeoutMs', gateway.gatewayTimeoutMs],
  ] as const) {
    if (!Number.isInteger(value) || value < 1000 || value > 300000) {
      errors.push(`ftpGateway.${field} must be an integer between 1000 and 300000`);
    }
  }
  if (!Number.isInteger(gateway.sessionTtlSeconds)
    || gateway.sessionTtlSeconds < 10
    || gateway.sessionTtlSeconds > 86400) {
    errors.push('ftpGateway.sessionTtlSeconds must be an integer between 10 and 86400');
  }
  if (!Number.isInteger(gateway.maxConcurrentSessions)
    || gateway.maxConcurrentSessions < 1
    || gateway.maxConcurrentSessions > 100) {
    errors.push('ftpGateway.maxConcurrentSessions must be an integer between 1 and 100');
  }
  for (const field of ['controlPortStart', 'controlPortEnd', 'passivePortStart'] as const) {
    const value = gateway[field];
    if (!Number.isInteger(value) || value < 1024 || value > 65535) {
      errors.push(`ftpGateway.${field} must be an integer between 1024 and 65535`);
    }
  }
  if (Number.isInteger(gateway.controlPortStart)
    && Number.isInteger(gateway.controlPortEnd)
    && gateway.controlPortEnd - gateway.controlPortStart + 1 < gateway.maxConcurrentSessions) {
    errors.push('ftpGateway control-port range must contain at least maxConcurrentSessions ports');
  }
  if (!Number.isInteger(gateway.passivePortsPerSession)
    || gateway.passivePortsPerSession < 1
    || gateway.passivePortsPerSession > 100) {
    errors.push('ftpGateway.passivePortsPerSession must be an integer between 1 and 100');
  } else if (Number.isInteger(gateway.passivePortStart)
    && gateway.passivePortStart + gateway.passivePortsPerSession * gateway.maxConcurrentSessions - 1 > 65535) {
    errors.push('ftpGateway passive-port allocation exceeds port 65535');
  }
  const controlEnd = gateway.controlPortEnd;
  const passiveEnd = gateway.passivePortStart
    + gateway.passivePortsPerSession * gateway.maxConcurrentSessions - 1;
  if (gateway.controlPortStart <= passiveEnd && gateway.passivePortStart <= controlEnd) {
    errors.push('ftpGateway control and passive port ranges must not overlap');
  }
  return errors;
}

/**
 * Returns every SSH/broker configuration error so callers and tests can fail
 * closed without depending on process.exit.
 */
export function validateSshConfiguration(config: Config): string[] {
  const errors: string[] = [];
  const services = Object.entries(config.services || {});
  const sshServices = services.filter(([, service]) => service.protocol === 'ssh');

  for (const [name, service] of services) {
    const protocol = service.protocol ?? 'http';
    if (!['http', 'ssh', 'ftp', 'ftps'].includes(protocol)) {
      errors.push(`service "${name}" has unsupported protocol "${String(service.protocol)}"`);
      continue;
    }

    if (protocol !== 'ssh') {
      if (service.ssh !== undefined) {
        errors.push(`${protocol.toUpperCase()} service "${name}" must not define service.ssh`);
      }
      continue;
    }

    if (name.length > 64 || !/^[A-Za-z0-9_-]+$/.test(name)) {
      errors.push(`SSH service alias "${name}" must be 1-64 letters, digits, hyphens, or underscores`);
    }

    if (service.auth?.type !== 'plugin') {
      errors.push(`SSH service "${name}" must use auth.type: plugin`);
    }
    if (typeof service.auth?.pluginPath !== 'string' || service.auth.pluginPath.trim().length === 0) {
      errors.push(`SSH service "${name}" must define auth.pluginPath`);
    }
    if (service.hostnames !== undefined) {
      errors.push(`SSH service "${name}" must not define HTTP hostnames`);
    }
    if (!service.ssh || typeof service.ssh.allowPrivateTarget !== 'boolean') {
      errors.push(`SSH service "${name}" must explicitly set ssh.allowPrivateTarget`);
    }

    const validation = validateSshService(service, config.security);
    if (!validation.valid) {
      errors.push(`SSH service "${name}": ${validation.reason}`);
    }
  }

  const broker = config.sshBroker;
  if (sshServices.length > 0 && !broker?.enabled) {
    errors.push('sshBroker.enabled must be true when SSH services are configured');
  }

  if (broker?.enabled) {
    if (!path.isAbsolute(broker.runtimeDir || '')) {
      errors.push('sshBroker.runtimeDir must be an absolute path');
    }
    if (!path.isAbsolute(broker.socketPath || '')) {
      errors.push('sshBroker.socketPath must be an absolute path');
    } else if (path.isAbsolute(broker.runtimeDir || '')) {
      const runtimeDir = path.resolve(broker.runtimeDir);
      const socketPath = path.resolve(broker.socketPath);
      if (socketPath !== path.join(runtimeDir, path.basename(socketPath))) {
        errors.push('sshBroker.socketPath must be directly inside sshBroker.runtimeDir');
      }
    }
    if (!Number.isInteger(broker.gatewayUid) || broker.gatewayUid <= 0 || broker.gatewayUid > 2147483647) {
      errors.push('sshBroker.gatewayUid must be a positive non-root integer');
    }
    if (!Number.isInteger(broker.gatewayGid) || broker.gatewayGid <= 0 || broker.gatewayGid > 2147483647) {
      errors.push('sshBroker.gatewayGid must be a positive non-root integer');
    }
    if (!Number.isInteger(broker.approvalTimeoutMs) || broker.approvalTimeoutMs <= 0) {
      errors.push('sshBroker.approvalTimeoutMs must be greater than zero');
    }
    if (!Number.isInteger(broker.credentialTimeoutMs)
      || broker.credentialTimeoutMs < 1000
      || broker.credentialTimeoutMs > 300000) {
      errors.push('sshBroker.credentialTimeoutMs must be an integer between 1000 and 300000');
    }
    if (!Number.isInteger(broker.leaseTtlSeconds) || broker.leaseTtlSeconds <= 0) {
      errors.push('sshBroker.leaseTtlSeconds must be greater than zero');
    }
    if (!Number.isInteger(broker.maxSessionSeconds)
      || broker.maxSessionSeconds < 10
      || broker.maxSessionSeconds > 86400) {
      errors.push('sshBroker.maxSessionSeconds must be an integer between 10 and 86400');
    }
    if (!path.isAbsolute(broker.sshAgentPath || '')) {
      errors.push('sshBroker.sshAgentPath must be an absolute path');
    }
    if (!path.isAbsolute(broker.sshAddPath || '')) {
      errors.push('sshBroker.sshAddPath must be an absolute path');
    }
    if (!Number.isInteger(broker.maxConcurrentLeases) || broker.maxConcurrentLeases <= 0) {
      errors.push('sshBroker.maxConcurrentLeases must be a positive integer');
    }
  }

  return errors;
}

export async function loadConfig(configPath: string): Promise<Config> {
  if (!fs.existsSync(configPath)) {
    console.error(`❌ Config file not found: ${configPath}`);
    console.error(`   Create one from clawguard.yaml.example`);
    process.exit(1);
  }

  const raw = fs.readFileSync(configPath, 'utf-8');
  const parsed = yaml.load(raw) as Record<string, unknown>;
  const config = deepSubstitute(parsed) as Config;

  // ─── Validate required fields ──────────────────────────────

  if (!config.server?.port || !config.server?.agentKey) {
    console.error('❌ Missing server.port or server.agentKey in config');
    process.exit(1);
  }

  if (!config.services || Object.keys(config.services).length === 0) {
    console.error('❌ No services configured');
    process.exit(1);
  }

  if (config.notifications?.telegram) {
    if (!config.notifications.telegram.botToken) {
      console.error('❌ Missing notifications.telegram.botToken');
      process.exit(1);
    }
    if (!config.notifications.telegram.chatId) {
      console.error('❌ Missing notifications.telegram.chatId');
      process.exit(1);
    }
  } else {
    console.log('⚠️  Telegram not configured — HTTP approvals auto-approve; SSH/FTP sessions remain fail-closed');
  }

  // ─── Apply defaults ────────────────────────────────────────

  config.security = { ...DEFAULT_SECURITY, ...(config.security || {}) };
  config.admin = { ...DEFAULT_ADMIN, ...(config.admin || {}) };
  if (config.admin.https) {
    config.admin.https = { ...DEFAULT_ADMIN_HTTPS, ...config.admin.https };
  }
  config.audit = { ...DEFAULT_AUDIT, ...(config.audit || {}) };
  config.proxy = { ...DEFAULT_PROXY, ...(config.proxy || {}) };
  config.transparentProxy = { ...DEFAULT_TRANSPARENT_PROXY, ...(config.transparentProxy || {}) };
  normalizeSshConfiguration(config);
  normalizeFtpConfiguration(config);

  const sshErrors = validateSshConfiguration(config);
  if (sshErrors.length > 0) {
    for (const error of sshErrors) console.error(`❌ ${error}`);
    process.exit(1);
  }
  const ftpErrors = validateFtpConfiguration(config);
  if (ftpErrors.length > 0) {
    for (const error of ftpErrors) console.error(`❌ ${error}`);
    process.exit(1);
  }

  if (!['block', 'silent_allow'].includes(config.proxy.discoveryPolicy)) {
    console.error('❌ Invalid proxy.discoveryPolicy. Allowed values: block, silent_allow');
    process.exit(1);
  }

  if (config.notifications?.telegram) {
    if (!config.notifications.telegram.pairing) {
      config.notifications.telegram.pairing = { ...DEFAULT_TELEGRAM_PAIRING };
    }

    // ─── Validate Telegram pairing ─────────────────────────────

    if (config.notifications.telegram.pairing.enabled && !config.notifications.telegram.pairing.secret) {
      console.error('❌ Telegram pairing is enabled but no secret is set.');
      console.error('   Set notifications.telegram.pairing.secret in config');
      process.exit(1);
    }

    // ─── Normalize group/multi-user fields ─────────────────────

    const tg = config.notifications.telegram;
    if (tg.allowedApprovers !== undefined) {
      if (!Array.isArray(tg.allowedApprovers)) {
        console.error('❌ notifications.telegram.allowedApprovers must be a list of @usernames or numeric user ids');
        process.exit(1);
      }
      tg.allowedApprovers = tg.allowedApprovers.map((a) => String(a).trim()).filter((a) => a.length > 0);
    }
    if (tg.messageThreadId !== undefined) {
      const threadId = Number(tg.messageThreadId);
      if (!Number.isInteger(threadId)) {
        console.error('❌ notifications.telegram.messageThreadId must be an integer (forum topic id)');
        process.exit(1);
      }
      tg.messageThreadId = threadId;
    }
  }

  // ─── Outbound webhook ──────────────────────────────────────

  if (config.notifications?.webhook?.enabled) {
    const wh = config.notifications.webhook;
    if (!wh.url) {
      console.error('❌ notifications.webhook.enabled is true but notifications.webhook.url is missing.');
      process.exit(1);
    }
    try {
      const u = new URL(wh.url);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        throw new Error(`unsupported protocol: ${u.protocol}`);
      }
    } catch (err) {
      console.error(`❌ notifications.webhook.url is not a valid URL: ${err instanceof Error ? err.message : err}`);
      process.exit(1);
    }
    wh.method = wh.method ?? 'POST';
    wh.timeoutMs = wh.timeoutMs ?? 5000;
    wh.cancelOnResolve = wh.cancelOnResolve ?? true;
    wh.escalateAfterSeconds = wh.escalateAfterSeconds ?? 0;
    if (wh.escalateAfterSeconds < 0) {
      console.error('❌ notifications.webhook.escalateAfterSeconds must be >= 0');
      process.exit(1);
    }
  }

  // ─── Validate admin PIN ────────────────────────────────────

  if (config.admin.enabled && !config.admin.pin) {
    console.error('❌ Admin panel is enabled but no PIN is set.');
    console.error('   Set admin.pin in config or disable with admin.enabled: false');
    process.exit(1);
  }

  // ─── Resolve secret references ───────────────────────────────

  await resolveServiceSecrets(config);

  return config;
}

/**
 * Resolves secret references (e.g. "vault:secret/data/github#token")
 * in all service auth fields.
 */
async function resolveServiceSecrets(config: Config): Promise<void> {
  const providers = await createSecretProviders(config.secrets);

  if (providers.size <= 1) {
    // Only static provider — no secret backends configured, skip resolution
    // unless some token values actually use a provider prefix
    const hasRefs = Object.values(config.services).some(svc => hasSecretRef(svc));
    if (!hasRefs) return;
  }

  console.log('🔐 Resolving secret references...');

  for (const [name, svc] of Object.entries(config.services)) {
    try {
      if (typeof svc.auth.token === 'string') {
        svc.auth.token = await resolveSecretValue(svc.auth.token, providers);
      }
      if (svc.auth.clientId) {
        svc.auth.clientId = await resolveSecretValue(svc.auth.clientId, providers);
      }
      if (svc.auth.clientSecret) {
        svc.auth.clientSecret = await resolveSecretValue(svc.auth.clientSecret, providers);
      }
      if (svc.auth.password) {
        svc.auth.password = await resolveSecretValue(svc.auth.password, providers);
      }
      if (svc.auth.pluginConfig) {
        svc.auth.pluginConfig = await resolvePluginConfigSecrets(svc.auth.pluginConfig, providers);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`❌ Failed to resolve secrets for service "${name}": ${message}`);
      process.exit(1);
    }
  }
}

async function resolvePluginConfigSecrets(
  value: Record<string, unknown>,
  providers: Map<string, SecretProvider>
): Promise<Record<string, unknown>> {
  const resolved: Record<string, unknown> = {};

  for (const [key, item] of Object.entries(value)) {
    if (typeof item === 'string') {
      resolved[key] = await resolveSecretValue(item, providers);
    } else if (item && typeof item === 'object' && !Array.isArray(item)) {
      resolved[key] = await resolvePluginConfigSecrets(item as Record<string, unknown>, providers);
    } else {
      resolved[key] = item;
    }
  }

  return resolved;
}

function objectHasSecretRef(value: Record<string, unknown>, refPattern: RegExp): boolean {
  return Object.values(value).some((item) => {
    if (typeof item === 'string') return refPattern.test(item);
    if (item && typeof item === 'object' && !Array.isArray(item)) {
      return objectHasSecretRef(item as Record<string, unknown>, refPattern);
    }
    return false;
  });
}

function hasSecretRef(svc: ServiceConfig): boolean {
  const refPattern = /^\w+:.+#\w+$/;
  const pluginConfigHasRef = svc.auth.pluginConfig
    ? objectHasSecretRef(svc.auth.pluginConfig, refPattern)
    : false;

  return (typeof svc.auth.token === 'string' && refPattern.test(svc.auth.token))
    || (!!svc.auth.clientId && refPattern.test(svc.auth.clientId))
    || (!!svc.auth.clientSecret && refPattern.test(svc.auth.clientSecret))
    || (!!svc.auth.password && refPattern.test(svc.auth.password))
    || pluginConfigHasRef;
}

/**
 * Save config back to YAML (used by admin API for service updates).
 * Preserves env var references by re-reading the original file.
 */
export function saveConfig(configPath: string, config: Config): void {
  const yamlStr = yaml.dump(config, { indent: 2, lineWidth: 120, noRefs: true });
  fs.writeFileSync(configPath, yamlStr, 'utf-8');
}
