import nodePath from 'path';
import { URL } from 'url';
import { RequestApprovalInfo, ServiceConfig, SecurityConfig } from '../types';
import { validateRuntimeUrl } from '../security';
import { getPlugin, getPluginDataDir } from './loader';

export interface PluginApplyResult {
  headers: Record<string, string>;
  body: Buffer;
  upstreamUrl: URL;
  requestState?: unknown;
  auditRequestBody?: string | null;
}

export interface PluginResponseHeadersResult {
  headers: Record<string, string | string[] | undefined>;
  auditResponseBody?: string | null;
}

function pluginContext(
  serviceName: string,
  serviceConfig: ServiceConfig,
  headers: Record<string, string>,
  body: Buffer,
  upstreamUrl: URL,
  method: string,
  path: string
) {
  const plugin = getPlugin(serviceName);
  if (!plugin) {
    throw new Error(`Plugin not loaded for service "${serviceName}". Cannot forward without auth.`);
  }
  return {
    plugin,
    context: {
      serviceName,
      method,
      path,
      headers: { ...headers },
      body,
      upstreamUrl: upstreamUrl.toString(),
      dataDir: getPluginDataDir(plugin.name, nodePath.resolve('data/plugins')),
      config: serviceConfig.auth.pluginConfig || {},
    },
  };
}

export async function describePluginRequest(
  serviceName: string,
  serviceConfig: ServiceConfig,
  headers: Record<string, string>,
  body: Buffer,
  upstreamUrl: URL,
  method: string,
  path: string
): Promise<RequestApprovalInfo | undefined> {
  const { plugin, context } = pluginContext(
    serviceName, serviceConfig, headers, body, upstreamUrl, method, path
  );
  if (!plugin.describeRequest) return undefined;
  return plugin.describeRequest(context);
}

export async function applyPluginResponseHeaders(
  serviceName: string,
  serviceConfig: ServiceConfig,
  method: string,
  path: string,
  statusCode: number,
  headers: Record<string, string | string[] | undefined>,
  requestState?: unknown
): Promise<PluginResponseHeadersResult> {
  const plugin = getPlugin(serviceName);
  if (!plugin) {
    throw new Error(`Plugin not loaded for service "${serviceName}". Cannot forward without auth.`);
  }
  if (!plugin.rewriteResponseHeaders) return { headers };
  return plugin.rewriteResponseHeaders({
    serviceName,
    method,
    path,
    statusCode,
    headers: { ...headers },
    requestState,
    dataDir: getPluginDataDir(plugin.name, nodePath.resolve('data/plugins')),
    config: serviceConfig.auth.pluginConfig || {},
  });
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
  const { plugin, context } = pluginContext(
    serviceName, serviceConfig, forwardHeaders, requestBody, upstreamUrl, method, path
  );
  const result = await plugin.rewriteRequest(context);

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
    const recheck = validateRuntimeUrl(
      upstreamUrl.toString(), configuredUpstream, security,
      serviceConfig.http?.allowPrivateTarget === true
    );
    if (!recheck.valid) {
      throw new Error(`Plugin URL override blocked by security policy: ${recheck.reason}`);
    }
  }

  console.log(`   🔌 Plugin "${plugin.name}" applied for ${serviceName}`);

  return {
    headers: forwardHeaders,
    body: requestBody,
    upstreamUrl,
    requestState: result.requestState,
    auditRequestBody: result.auditRequestBody,
  };
}
