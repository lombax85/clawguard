import nodePath from 'path';
import { URL } from 'url';
import { ServiceConfig, SecurityConfig } from '../types';
import { validateRuntimeUrl } from '../security';
import { getPlugin, getPluginDataDir } from './loader';

export interface PluginApplyResult {
  headers: Record<string, string>;
  body: Buffer;
  upstreamUrl: URL;
}

/**
 * Applies a plugin's rewriteRequest to the current request.
 * - Throws if the plugin is not loaded (prevents unauthenticated forwarding).
 * - Re-validates the upstream URL after plugin override (prevents SSRF bypass).
 */
export async function applyPlugin(
  serviceName: string,
  serviceConfig: ServiceConfig,
  forwardHeaders: Record<string, string>,
  requestBody: Buffer,
  upstreamUrl: URL,
  method: string,
  path: string,
  security: SecurityConfig,
  configuredUpstream: string
): Promise<PluginApplyResult> {
  const plugin = getPlugin(serviceName);
  if (!plugin) {
    throw new Error(`Plugin not loaded for service "${serviceName}". Cannot forward without auth.`);
  }

  const pluginDataDir = getPluginDataDir(plugin.name, nodePath.resolve('data/plugins'));
  const result = await plugin.rewriteRequest({
    serviceName,
    method,
    path,
    headers: { ...forwardHeaders },  // defensive copy — plugin cannot mutate caller's headers
    body: requestBody,
    upstreamUrl: upstreamUrl.toString(),
    dataDir: pluginDataDir,
    config: serviceConfig.auth.pluginConfig || {},
  });

  Object.assign(forwardHeaders, result.headers);
  requestBody = result.body;

  if (result.upstreamUrl) {
    let newUrl: URL;
    try {
      newUrl = new URL(result.upstreamUrl);
    } catch {
      throw new Error(`Plugin "${plugin.name}" returned an invalid upstream URL: "${result.upstreamUrl}"`);
    }
    upstreamUrl.protocol = newUrl.protocol;
    upstreamUrl.host = newUrl.host;
    upstreamUrl.pathname = newUrl.pathname;
    upstreamUrl.search = newUrl.search;
    // Clear any stale credentials from the original URL when host changes
    upstreamUrl.username = '';
    upstreamUrl.password = '';

    // Re-validate after plugin override to prevent SSRF bypass
    const recheck = validateRuntimeUrl(upstreamUrl.toString(), configuredUpstream, security);
    if (!recheck.valid) {
      throw new Error(`Plugin URL override blocked by security policy: ${recheck.reason}`);
    }
  }

  console.log(`   🔌 Plugin "${plugin.name}" applied for ${serviceName}`);

  return { headers: forwardHeaders, body: requestBody, upstreamUrl };
}
