import fs from 'fs';
import path from 'path';
import {
  ISshCredentialPlugin,
  SshCredentialContext,
  SshCredentials,
} from './ISshCredentialPlugin';

/** Kept separate from the HTTP auth-plugin registry by design. */
const sshCredentialPluginRegistry = new Map<string, ISshCredentialPlugin>();

const BUILTIN_PLUGINS = new Set(['ssh-agent-key']);
const ALLOWED_CREDENTIAL_FIELDS = new Set(['username', 'privateKey']);
const MAX_PRIVATE_KEY_BYTES = 1024 * 1024;

function sanitizePluginName(name: string): string {
  if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
    throw new Error(
      `Invalid SSH credential plugin name "${name}": must contain only alphanumeric characters, hyphens, and underscores`
    );
  }
  return name;
}

function resolvePluginPath(pluginPath: string): string {
  if (typeof pluginPath !== 'string' || pluginPath.length === 0) {
    throw new Error('SSH credential plugin path must be a non-empty string');
  }
  if (BUILTIN_PLUGINS.has(pluginPath)) {
    return path.join(__dirname, pluginPath);
  }
  return path.isAbsolute(pluginPath)
    ? pluginPath
    : path.resolve(process.cwd(), pluginPath);
}

function isWithin(baseDir: string, candidate: string): boolean {
  const relative = path.relative(baseDir, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

/** Return a traversal-safe data path beneath the caller-provided SSH plugin base. */
export function getSshCredentialPluginDataDir(
  pluginName: string,
  dataBaseDir: string
): string {
  sanitizePluginName(pluginName);
  const base = path.resolve(dataBaseDir);
  const candidate = path.resolve(base, pluginName);
  if (!isWithin(base, candidate)) {
    throw new Error('SSH credential plugin data directory escapes its configured base');
  }
  return candidate;
}

function createSafeDataDir(pluginName: string, dataBaseDir: string): string {
  const requestedBase = path.resolve(dataBaseDir);
  fs.mkdirSync(requestedBase, { recursive: true, mode: 0o700 });
  const realBase = fs.realpathSync(requestedBase);
  const dataDir = getSshCredentialPluginDataDir(pluginName, realBase);

  if (fs.existsSync(dataDir)) {
    const stat = fs.lstatSync(dataDir);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error(
        `Unsafe data directory for SSH credential plugin "${pluginName}"`
      );
    }
  } else {
    fs.mkdirSync(dataDir, { mode: 0o700 });
  }

  const realDataDir = fs.realpathSync(dataDir);
  if (!isWithin(realBase, realDataDir)) {
    throw new Error(
      `Data directory for SSH credential plugin "${pluginName}" escapes its configured base`
    );
  }
  return realDataDir;
}

function validateCredentials(value: unknown, pluginName: string): SshCredentials {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`SSH credential plugin "${pluginName}" returned invalid credentials`);
  }

  const ownKeys = Reflect.ownKeys(value);
  const unexpected = ownKeys.filter(
    (key) => typeof key !== 'string' || !ALLOWED_CREDENTIAL_FIELDS.has(key)
  );
  if (unexpected.length > 0) {
    const fields = unexpected.map((key) =>
      typeof key === 'symbol' ? key.toString() : key
    );
    throw new Error(
      `SSH credential plugin "${pluginName}" returned unexpected credential field(s): ${fields.join(', ')}`
    );
  }

  const raw = value as Record<string, unknown>;
  if (typeof raw.username !== 'string'
    || !/^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$/.test(raw.username)) {
    throw new Error(`SSH credential plugin "${pluginName}" returned an invalid username`);
  }

  let privateKey: string | Buffer;
  if (typeof raw.privateKey === 'string') {
    if (raw.privateKey.trim().length === 0) {
      throw new Error(`SSH credential plugin "${pluginName}" returned an empty privateKey`);
    }
    if (Buffer.byteLength(raw.privateKey, 'utf8') > MAX_PRIVATE_KEY_BYTES) {
      throw new Error(`SSH credential plugin "${pluginName}" returned an oversized privateKey`);
    }
    privateKey = raw.privateKey;
  } else if (Buffer.isBuffer(raw.privateKey)) {
    if (raw.privateKey.length === 0) {
      throw new Error(`SSH credential plugin "${pluginName}" returned an empty privateKey`);
    }
    if (raw.privateKey.length > MAX_PRIVATE_KEY_BYTES) {
      throw new Error(`SSH credential plugin "${pluginName}" returned an oversized privateKey`);
    }
    privateKey = Buffer.from(raw.privateKey);
  } else {
    throw new Error(`SSH credential plugin "${pluginName}" returned an invalid privateKey`);
  }

  return Object.freeze({ username: raw.username, privateKey });
}

function wrapPlugin(plugin: ISshCredentialPlugin): ISshCredentialPlugin {
  return Object.freeze({
    name: plugin.name,
    async getCredentials(ctx: SshCredentialContext): Promise<SshCredentials> {
      return validateCredentials(await plugin.getCredentials(ctx), plugin.name);
    },
  });
}

/**
 * Load and initialize a plugin. Registration happens last; a failed reload
 * removes the previous entry so subsequent credential lookup fails closed.
 */
export async function loadSshCredentialPlugin(
  serviceName: string,
  pluginPath: string,
  pluginConfig: Record<string, unknown>,
  dataBaseDir: string
): Promise<ISshCredentialPlugin> {
  sshCredentialPluginRegistry.delete(serviceName);

  if (pluginConfig === null || typeof pluginConfig !== 'object' || Array.isArray(pluginConfig)) {
    throw new Error('SSH credential plugin config must be an object');
  }

  const resolved = resolvePluginPath(pluginPath);
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const mod = require(resolved);
  if (typeof mod.createPlugin !== 'function') {
    throw new Error(
      `SSH credential plugin "${pluginPath}" does not export a createPlugin() function`
    );
  }

  const candidate: unknown = mod.createPlugin();
  if (candidate === null || typeof candidate !== 'object') {
    throw new Error(
      `SSH credential plugin "${pluginPath}" createPlugin() did not return an object`
    );
  }

  const plugin = candidate as ISshCredentialPlugin;
  if (typeof plugin.name !== 'string' || plugin.name.length === 0) {
    throw new Error(
      `SSH credential plugin "${pluginPath}" returned an object without a valid 'name' string`
    );
  }
  sanitizePluginName(plugin.name);
  if (typeof plugin.getCredentials !== 'function') {
    throw new Error(
      `SSH credential plugin "${pluginPath}" returned an object without a getCredentials() method`
    );
  }
  if (plugin.init !== undefined && typeof plugin.init !== 'function') {
    throw new Error(
      `SSH credential plugin "${pluginPath}" returned an object with an invalid init property`
    );
  }

  const dataDir = createSafeDataDir(plugin.name, dataBaseDir);
  if (plugin.init) {
    await plugin.init(dataDir, pluginConfig);
  }

  const wrapped = wrapPlugin(plugin);
  sshCredentialPluginRegistry.set(serviceName, wrapped);
  console.log(`   SSH credential plugin loaded: ${plugin.name} (service: ${serviceName})`);
  return wrapped;
}

/** Return the initialized SSH credential plugin for a service, if present. */
export function getSshCredentialPlugin(
  serviceName: string
): ISshCredentialPlugin | undefined {
  return sshCredentialPluginRegistry.get(serviceName);
}
