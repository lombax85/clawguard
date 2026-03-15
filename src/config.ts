import fs from 'fs';
import yaml from 'js-yaml';
import { Config, ServiceConfig } from './types';
import { createSecretProviders, resolveSecretValue, SecretProvider } from './secrets/provider';

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

const DEFAULT_TELEGRAM_PAIRING = {
  enabled: true,
  secret: '',
};

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
    console.log('⚠️  Telegram not configured — approval requests will be auto-approved');
  }

  // ─── Apply defaults ────────────────────────────────────────

  config.security = { ...DEFAULT_SECURITY, ...(config.security || {}) };
  config.admin = { ...DEFAULT_ADMIN, ...(config.admin || {}) };
  config.audit = { ...DEFAULT_AUDIT, ...(config.audit || {}) };
  config.proxy = { ...DEFAULT_PROXY, ...(config.proxy || {}) };
  config.transparentProxy = { ...DEFAULT_TRANSPARENT_PROXY, ...(config.transparentProxy || {}) };

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
      svc.auth.token = await resolveSecretValue(svc.auth.token, providers);
      if (svc.auth.clientId) {
        svc.auth.clientId = await resolveSecretValue(svc.auth.clientId, providers);
      }
      if (svc.auth.clientSecret) {
        svc.auth.clientSecret = await resolveSecretValue(svc.auth.clientSecret, providers);
      }
      if (svc.auth.password) {
        svc.auth.password = await resolveSecretValue(svc.auth.password, providers);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`❌ Failed to resolve secrets for service "${name}": ${message}`);
      process.exit(1);
    }
  }
}

function hasSecretRef(svc: ServiceConfig): boolean {
  const refPattern = /^\w+:.+#\w+$/;
  return refPattern.test(svc.auth.token)
    || (!!svc.auth.clientId && refPattern.test(svc.auth.clientId))
    || (!!svc.auth.clientSecret && refPattern.test(svc.auth.clientSecret))
    || (!!svc.auth.password && refPattern.test(svc.auth.password));
}

/**
 * Save config back to YAML (used by admin API for service updates).
 * Preserves env var references by re-reading the original file.
 */
export function saveConfig(configPath: string, config: Config): void {
  const yamlStr = yaml.dump(config, { indent: 2, lineWidth: 120, noRefs: true });
  fs.writeFileSync(configPath, yamlStr, 'utf-8');
}
