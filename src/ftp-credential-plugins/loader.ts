import fs from 'fs';
import path from 'path';
import {
  FtpCredentialContext,
  FtpCredentials,
  IFtpCredentialPlugin,
} from './IFtpCredentialPlugin';

const registry = new Map<string, IFtpCredentialPlugin>();
const BUILTIN_PLUGINS = new Set(['ftp-password']);
const ALLOWED_CREDENTIAL_FIELDS = new Set(['username', 'password']);
const MAX_PASSWORD_BYTES = 16 * 1024;

function sanitizePluginName(name: string): string {
  if (!/^[A-Za-z0-9_-]+$/.test(name)) {
    throw new Error(`Invalid FTP credential plugin name "${name}"`);
  }
  return name;
}

function resolvePluginPath(pluginPath: string): string {
  if (typeof pluginPath !== 'string' || pluginPath.length === 0) {
    throw new Error('FTP credential plugin path must be a non-empty string');
  }
  return BUILTIN_PLUGINS.has(pluginPath)
    ? path.join(__dirname, pluginPath)
    : path.isAbsolute(pluginPath) ? pluginPath : path.resolve(process.cwd(), pluginPath);
}

function isWithin(baseDir: string, candidate: string): boolean {
  const relative = path.relative(baseDir, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

export function getFtpCredentialPluginDataDir(pluginName: string, dataBaseDir: string): string {
  sanitizePluginName(pluginName);
  const base = path.resolve(dataBaseDir);
  const candidate = path.resolve(base, pluginName);
  if (!isWithin(base, candidate)) throw new Error('FTP credential plugin data directory escapes its base');
  return candidate;
}

function createSafeDataDir(pluginName: string, dataBaseDir: string): string {
  const requestedBase = path.resolve(dataBaseDir);
  fs.mkdirSync(requestedBase, { recursive: true, mode: 0o700 });
  const realBase = fs.realpathSync(requestedBase);
  const dataDir = getFtpCredentialPluginDataDir(pluginName, realBase);
  if (fs.existsSync(dataDir)) {
    const stat = fs.lstatSync(dataDir);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error(`Unsafe data directory for FTP credential plugin "${pluginName}"`);
    }
  } else {
    fs.mkdirSync(dataDir, { mode: 0o700 });
  }
  const realDataDir = fs.realpathSync(dataDir);
  if (!isWithin(realBase, realDataDir)) {
    throw new Error(`Data directory for FTP credential plugin "${pluginName}" escapes its base`);
  }
  return realDataDir;
}

function validateCredentials(value: unknown, pluginName: string): FtpCredentials {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`FTP credential plugin "${pluginName}" returned invalid credentials`);
  }
  const ownKeys = Reflect.ownKeys(value);
  const unexpected = ownKeys.filter((key) => typeof key !== 'string' || !ALLOWED_CREDENTIAL_FIELDS.has(key));
  if (unexpected.length > 0) {
    throw new Error(`FTP credential plugin "${pluginName}" returned unexpected credential fields`);
  }

  const raw = value as Record<string, unknown>;
  if (typeof raw.username !== 'string' || !/^[^\0\r\n]{1,255}$/.test(raw.username)) {
    throw new Error(`FTP credential plugin "${pluginName}" returned an invalid username`);
  }
  const source = raw.password;
  if (typeof source !== 'string' && !Buffer.isBuffer(source)) {
    throw new Error(`FTP credential plugin "${pluginName}" returned an invalid password`);
  }
  const password = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source, 'utf8');
  if (password.length === 0 || password.length > MAX_PASSWORD_BYTES
    || password.includes(0x00) || password.includes(0x0a) || password.includes(0x0d)) {
    password.fill(0);
    throw new Error(`FTP credential plugin "${pluginName}" returned an invalid password`);
  }
  return Object.freeze({ username: raw.username, password });
}

function wrapPlugin(plugin: IFtpCredentialPlugin): IFtpCredentialPlugin {
  return Object.freeze({
    name: plugin.name,
    async getCredentials(ctx: FtpCredentialContext): Promise<FtpCredentials> {
      return validateCredentials(await plugin.getCredentials(ctx), plugin.name);
    },
  });
}

export async function loadFtpCredentialPlugin(
  serviceName: string,
  pluginPath: string,
  pluginConfig: Record<string, unknown>,
  dataBaseDir: string
): Promise<IFtpCredentialPlugin> {
  registry.delete(serviceName);
  if (pluginConfig === null || typeof pluginConfig !== 'object' || Array.isArray(pluginConfig)) {
    throw new Error('FTP credential plugin config must be an object');
  }

  const resolved = resolvePluginPath(pluginPath);
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const mod = require(resolved);
  if (typeof mod.createPlugin !== 'function') {
    throw new Error(`FTP credential plugin "${pluginPath}" does not export createPlugin()`);
  }
  const candidate: unknown = mod.createPlugin();
  if (candidate === null || typeof candidate !== 'object') {
    throw new Error(`FTP credential plugin "${pluginPath}" did not return an object`);
  }
  const plugin = candidate as IFtpCredentialPlugin;
  if (typeof plugin.name !== 'string' || plugin.name.length === 0) {
    throw new Error(`FTP credential plugin "${pluginPath}" returned an invalid name`);
  }
  sanitizePluginName(plugin.name);
  if (typeof plugin.getCredentials !== 'function') {
    throw new Error(`FTP credential plugin "${pluginPath}" has no getCredentials()`);
  }
  if (plugin.init !== undefined && typeof plugin.init !== 'function') {
    throw new Error(`FTP credential plugin "${pluginPath}" has an invalid init property`);
  }

  const dataDir = createSafeDataDir(plugin.name, dataBaseDir);
  if (plugin.init) await plugin.init(dataDir, pluginConfig);
  const wrapped = wrapPlugin(plugin);
  registry.set(serviceName, wrapped);
  console.log(`   FTP credential plugin loaded: ${plugin.name} (service: ${serviceName})`);
  return wrapped;
}

export function getFtpCredentialPlugin(serviceName: string): IFtpCredentialPlugin | undefined {
  return registry.get(serviceName);
}
