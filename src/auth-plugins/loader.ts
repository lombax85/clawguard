import path from 'path';
import fs from 'fs';
import { IAuthPlugin } from './IAuthPlugin';

/** Registry of loaded plugin instances, keyed by service name */
const pluginRegistry = new Map<string, IAuthPlugin>();

/**
 * Validates a plugin name contains no path traversal characters.
 * Only allows alphanumeric, hyphens, and underscores.
 */
function sanitizePluginName(name: string): string {
  if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
    throw new Error(
      `Invalid plugin name "${name}": must contain only alphanumeric characters, hyphens, and underscores`
    );
  }
  return name;
}

/** Built-in plugin names that ship with ClawGuard */
const BUILTIN_PLUGINS = new Set(['echo', 'oauth2-authcode', 'aws-sigv4']);

/**
 * Resolves a plugin module path.
 * - Built-in plugins: resolved from src/auth-plugins/<name>.ts (or dist/)
 * - Absolute paths: used as-is
 * - Relative paths: resolved from cwd
 */
function resolvePluginPath(pluginPath: string): string {
  if (BUILTIN_PLUGINS.has(pluginPath)) {
    // Built-in: resolve relative to this file's directory
    return path.join(__dirname, pluginPath);
  }
  if (path.isAbsolute(pluginPath)) {
    return pluginPath;
  }
  return path.resolve(process.cwd(), pluginPath);
}

/**
 * Loads and initializes a plugin for a given service.
 * The plugin module must export a `createPlugin` function that returns an IAuthPlugin.
 */
export async function loadPlugin(
  serviceName: string,
  pluginPath: string,
  pluginConfig: Record<string, unknown>,
  dataBaseDir: string
): Promise<IAuthPlugin> {
  const resolved = resolvePluginPath(pluginPath);

  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const mod = require(resolved);

  if (typeof mod.createPlugin !== 'function') {
    throw new Error(
      `Plugin "${pluginPath}" does not export a createPlugin() function`
    );
  }

  const plugin: IAuthPlugin = mod.createPlugin();

  // Validate plugin implements required interface
  if (typeof plugin.name !== 'string' || !plugin.name) {
    throw new Error(`Plugin "${pluginPath}" returned an object without a valid 'name' string`);
  }
  if (typeof plugin.rewriteRequest !== 'function') {
    throw new Error(`Plugin "${pluginPath}" returned an object without a rewriteRequest() method`);
  }

  // Sanitize plugin name to prevent path traversal in data directory
  sanitizePluginName(plugin.name);

  // Ensure data directory exists for this plugin
  const dataDir = path.join(dataBaseDir, plugin.name);
  fs.mkdirSync(dataDir, { recursive: true });

  // Initialize plugin
  if (plugin.init) {
    await plugin.init(dataDir, pluginConfig);
  }

  pluginRegistry.set(serviceName, plugin);
  console.log(`   🔌 Plugin loaded: ${plugin.name} (service: ${serviceName})`);

  return plugin;
}

/** Returns the loaded plugin for a service, or undefined */
export function getPlugin(serviceName: string): IAuthPlugin | undefined {
  return pluginRegistry.get(serviceName);
}

/** Returns the data directory path for a plugin */
export function getPluginDataDir(pluginName: string, dataBaseDir: string): string {
  return path.join(dataBaseDir, pluginName);
}
