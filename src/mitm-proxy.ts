import http from 'http';
import https from 'https';
import tls from 'tls';
import net from 'net';
import { URL } from 'url';
import { Config, ServiceConfig } from './types';
import { ApprovalManager } from './approval';
import { AuditLogger } from './audit';
import { CertManager } from './cert-manager';
import { validateRuntimeUrl, validateUpstreamUrl, resolveAndCheckPrivateIP } from './security';
import { rewriteRequestAuth } from './auth-rewrite';

// ─── Discovery host tracking ─────────────────────────────────

interface DiscoveredHost {
  count: number;
  firstSeen: string;
  lastSeen: string;
  authHeader: string | null;   // e.g. "Bearer sk-****", "Key ****", "Basic ****"
  authType: string | null;     // e.g. "bearer", "key", "basic", "custom-header"
  authHeaderName: string | null; // e.g. "authorization", "x-api-key"
  methods: Set<string>;
  paths: string[];             // last N unique paths seen
}

const discoveredHosts: Map<string, DiscoveredHost> = new Map();
const MAX_PATHS = 10;
const MAX_DISCOVERED_HOSTS = 1000;

function detectAuth(
  headers: Record<string, string | string[] | undefined>,
  url?: string
): { authHeader: string | null; authType: string | null; authHeaderName: string | null } {
  // Check Authorization header
  const authVal = headers['authorization'] as string | undefined;
  if (authVal) {
    const masked = maskDiscoveredToken(authVal);
    if (/^Bearer /i.test(authVal)) return { authHeader: masked, authType: 'bearer', authHeaderName: 'authorization' };
    if (/^Key /i.test(authVal)) return { authHeader: masked, authType: 'key', authHeaderName: 'authorization' };
    if (/^Basic /i.test(authVal)) return { authHeader: masked, authType: 'basic', authHeaderName: 'authorization' };
    return { authHeader: masked, authType: 'custom', authHeaderName: 'authorization' };
  }

  // Check common API key headers
  for (const h of ['x-api-key', 'x-auth-token', 'api-key', 'apikey', 'x-subscription-token']) {
    const val = headers[h] as string | undefined;
    if (val) return { authHeader: maskDiscoveredToken(val), authType: 'header', authHeaderName: h };
  }

  // Check common auth query parameters
  if (url) {
    try {
      const params = new URL(url, 'https://placeholder').searchParams;
      for (const p of ['access_token', 'api_key', 'apikey', 'key', 'token', 'auth_token']) {
        const val = params.get(p);
        if (val) return { authHeader: maskDiscoveredToken(val), authType: 'query', authHeaderName: p };
      }
    } catch { /* ignore parse errors */ }
  }

  return { authHeader: null, authType: null, authHeaderName: null };
}

function maskDiscoveredToken(value: string): string {
  // Show prefix (Bearer/Key/etc) and first+last 4 chars of the actual token
  const parts = value.split(' ');
  if (parts.length >= 2) {
    const prefix = parts[0];
    const token = parts.slice(1).join(' ');
    if (token.length <= 8) return `${prefix} ****`;
    return `${prefix} ${token.substring(0, 4)}****${token.substring(token.length - 4)}`;
  }
  if (value.length <= 8) return '****';
  return `${value.substring(0, 4)}****${value.substring(value.length - 4)}`;
}

function trackDiscoveredHost(hostname: string, method?: string, path?: string, headers?: Record<string, string | string[] | undefined>, url?: string): void {
  const now = new Date().toISOString();
  const entry = discoveredHosts.get(hostname);

  if (entry) {
    entry.count++;
    entry.lastSeen = now;
    if (method) entry.methods.add(method);
    if (path && !entry.paths.includes(path)) {
      entry.paths.push(path);
      if (entry.paths.length > MAX_PATHS) entry.paths.shift();
    }
    // Update auth if we didn't have it before
    if (!entry.authType && headers) {
      const auth = detectAuth(headers, url);
      entry.authHeader = auth.authHeader;
      entry.authType = auth.authType;
      entry.authHeaderName = auth.authHeaderName;
    }
    // refresh insertion order for LRU-like eviction
    discoveredHosts.delete(hostname);
    discoveredHosts.set(hostname, entry);
    return;
  }

  // Evict oldest discovered host when over cap
  if (discoveredHosts.size >= MAX_DISCOVERED_HOSTS) {
    const oldestKey = discoveredHosts.keys().next().value as string | undefined;
    if (oldestKey) discoveredHosts.delete(oldestKey);
  }

  const auth = headers ? detectAuth(headers, url) : { authHeader: null, authType: null, authHeaderName: null };
  discoveredHosts.set(hostname, {
    count: 1,
    firstSeen: now,
    lastSeen: now,
    authHeader: auth.authHeader,
    authType: auth.authType,
    authHeaderName: auth.authHeaderName,
    methods: new Set(method ? [method] : []),
    paths: path ? [path] : [],
  });
  console.log(`🔍 New unconfigured host discovered: ${hostname}${auth.authType ? ` (auth: ${auth.authType})` : ''}`);
}

export function getPassthroughHosts(): {
  hostname: string; count: number; firstSeen: string; lastSeen: string;
  authHeader: string | null; authType: string | null; authHeaderName: string | null;
  methods: string[]; paths: string[];
}[] {
  return [...discoveredHosts.entries()]
    .map(([hostname, info]) => ({
      hostname, count: info.count, firstSeen: info.firstSeen, lastSeen: info.lastSeen,
      authHeader: info.authHeader, authType: info.authType, authHeaderName: info.authHeaderName,
      methods: [...info.methods], paths: info.paths,
    }))
    .sort((a, b) => b.count - a.count);
}

// Test helpers (no runtime side effects)
export function __resetDiscoveredHostsForTests(): void {
  discoveredHosts.clear();
}

export function __trackDiscoveredHostForTests(hostname: string, method?: string, path?: string): void {
  trackDiscoveredHost(hostname, method, path);
}

/**
 * Resolves a hostname to a configured service.
 * Checks both the `hostnames` array and the upstream URL hostname.
 */
function resolveServiceByHostname(
  hostname: string,
  services: Record<string, ServiceConfig>
): { name: string; config: ServiceConfig } | null {
  for (const [name, svc] of Object.entries(services)) {
    // Check explicit hostnames
    if (svc.hostnames?.some((h) => h === hostname)) {
      return { name, config: svc };
    }
    // Check upstream hostname
    try {
      const upstreamHost = new URL(svc.upstream).hostname;
      if (upstreamHost === hostname) {
        return { name, config: svc };
      }
    } catch {
      // skip invalid upstream URLs
    }
  }
  return null;
}

/**
 * Extracts the agent key from Proxy-Authorization header.
 * Supports: Basic base64(agentKey:) or Basic base64(:agentKey)
 * The agent key can be the username or the password.
 */
function extractAgentKey(proxyAuth: string | undefined): string | null {
  if (!proxyAuth) return null;

  const match = proxyAuth.match(/^Basic\s+(.+)$/i);
  if (!match) return null;

  try {
    const decoded = Buffer.from(match[1], 'base64').toString('utf-8');
    const colonIndex = decoded.indexOf(':');
    if (colonIndex === -1) return decoded;

    const username = decoded.substring(0, colonIndex);
    const password = decoded.substring(colonIndex + 1);

    // Agent key can be in username or password position
    // HTTPS_PROXY=http://agentkey:x@host  → username = agentkey
    // HTTPS_PROXY=http://x:agentkey@host  → password = agentkey
    return username || password || null;
  } catch {
    return null;
  }
}

/**
 * Attaches CONNECT handler to an HTTP server for HTTPS_PROXY mode.
 * Performs MITM to inspect, approve, and inject auth into requests.
 */
export function attachMitmProxy(
  server: http.Server,
  config: Config,
  approvalManager: ApprovalManager,
  audit: AuditLogger,
  certManager: CertManager
): void {
  server.on('connect', (req: http.IncomingMessage, clientSocket: net.Socket, head: Buffer) => {
    const target = req.url || '';
    const [hostname, portStr] = target.split(':');
    const port = parseInt(portStr) || 443;

    const clientIp = clientSocket.remoteAddress || 'unknown';

    // Validate agent key from Proxy-Authorization
    const agentKey = extractAgentKey(req.headers['proxy-authorization']);
    if (agentKey !== config.server.agentKey) {
      console.error(`🚫 MITM proxy: invalid agent key from ${clientIp} for ${hostname}`);
      clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="ClawGuard"\r\n\r\n');
      clientSocket.end();
      return;
    }

    // Resolve hostname to a configured service
    const match = resolveServiceByHostname(hostname, config.services);
    if (!match) {
      // Always track unknown hosts for discovery suggestions
      trackDiscoveredHost(hostname);

      if (!config.proxy.discovery || config.proxy.discoveryPolicy === 'block') {
        // Default-safe behavior: block unknown services unless explicitly allowed.
        clientSocket.write('HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{"error":"Unknown service blocked by policy. Add service config or set proxy.discoveryPolicy=silent_allow."}');
        clientSocket.end();
        return;
      }

      // discovery + silent_allow: MITM unknown hosts, inspect, and forward safely.
      handleDiscoveryMitm(hostname, port, clientSocket, head, certManager, config, audit, clientIp);
      return;
    }

    // Respond 200 to establish the tunnel
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    // Generate a cert for this hostname and start TLS
    const certPair = certManager.getCertForHost(hostname);

    const tlsSocket = new tls.TLSSocket(clientSocket, {
      isServer: true,
      cert: certPair.cert,
      key: certPair.key,
    });

    // Use a temporary HTTP server to parse the decrypted HTTP stream
    const innerServer = http.createServer();

    innerServer.on('request', (innerReq: http.IncomingMessage, innerRes: http.ServerResponse) => {
      handleMitmRequest(
        innerReq, innerRes,
        match.name, match.config,
        config, approvalManager, audit, clientIp
      );
    });

    // Feed the TLS socket into the HTTP parser
    innerServer.emit('connection', tlsSocket);

    // Forward any buffered data from the CONNECT request
    if (head && head.length > 0) {
      tlsSocket.unshift(head);
    }

    tlsSocket.on('error', (err) => {
      if ((err as NodeJS.ErrnoException).code !== 'ECONNRESET') {
        console.error(`❌ MITM TLS error for ${hostname}: ${err.message}`);
      }
    });

    clientSocket.on('error', (err) => {
      if ((err as NodeJS.ErrnoException).code !== 'ECONNRESET') {
        console.error(`❌ MITM client socket error: ${err.message}`);
      }
    });
  });
}

function handleMitmRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  serviceName: string,
  serviceConfig: ServiceConfig,
  config: Config,
  approvalManager: ApprovalManager,
  audit: AuditLogger,
  clientIp: string
): void {
  // Collect request body
  const bodyChunks: Buffer[] = [];
  req.on('data', (chunk: Buffer) => bodyChunks.push(chunk));
  req.on('end', async () => {
    const body = Buffer.concat(bodyChunks);
    const method = req.method || 'GET';
    const requestPath = req.url || '/';

    // Build upstream URL
    const upstreamUrl = new URL(requestPath, serviceConfig.upstream);

    // SSRF check
    const runtimeCheck = validateRuntimeUrl(upstreamUrl.toString(), serviceConfig.upstream, config.security);
    if (!runtimeCheck.valid) {
      console.error(`🚫 SSRF blocked (MITM): ${runtimeCheck.reason}`);
      audit.logRequest({
        timestamp: new Date().toISOString(), service: serviceName,
        method, path: requestPath, approved: false,
        responseStatus: 403, agentIp: clientIp,
      });
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Request blocked by security policy' }));
      return;
    }

    // Check approval
    const approved = await approvalManager.checkApproval(
      serviceName, serviceConfig, method, requestPath, clientIp
    );

    if (!approved) {
      audit.logRequest({
        timestamp: new Date().toISOString(), service: serviceName,
        method, path: requestPath, approved: false,
        responseStatus: 403, agentIp: clientIp,
      });
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Approval denied or timed out' }));
      return;
    }

    // Build forward headers
    const forwardHeaders: Record<string, string> = {};
    for (const [key, value] of Object.entries(req.headers)) {
      const lower = key.toLowerCase();
      if (lower === 'host') continue;
      if (lower === 'proxy-authorization') continue;
      if (lower === 'proxy-connection') continue;
      if (typeof value === 'string') forwardHeaders[key] = value;
      else if (Array.isArray(value)) forwardHeaders[key] = value.join(', ');
    }

    // Rewrite body for oauth2_client_credentials
    let requestBody: Buffer = body;
    const rewritten = rewriteRequestAuth(serviceConfig, method, requestPath, requestBody, forwardHeaders);
    requestBody = rewritten.body as Buffer;
    Object.assign(forwardHeaders, rewritten.headers);

    // Inject auth (skipped for oauth2_client_credentials)
    if (!rewritten.skipAuthInjection) {
      if (serviceConfig.auth.type === 'bearer') {
        forwardHeaders['authorization'] = `Bearer ${serviceConfig.auth.token}`;
      } else if (serviceConfig.auth.type === 'header' && serviceConfig.auth.headerName) {
        forwardHeaders[serviceConfig.auth.headerName] = serviceConfig.auth.token;
      } else if (serviceConfig.auth.type === 'query' && serviceConfig.auth.paramName) {
        upstreamUrl.searchParams.set(serviceConfig.auth.paramName, serviceConfig.auth.token);
      }
    }

    forwardHeaders['host'] = upstreamUrl.host;

    // Audit: capture request body
    let requestBodyLog: string | null = null;
    if (config.audit.logPayload && requestBody.length > 0) {
      const maxSize = config.security.maxPayloadLogSize || 10240;
      const bodyStr = requestBody.toString('utf-8');
      requestBodyLog = bodyStr.length > maxSize
        ? bodyStr.substring(0, maxSize) + '... [truncated]' : bodyStr;
    }

    // Forward to upstream
    const isHttps = upstreamUrl.protocol === 'https:';
    const transport = isHttps ? https : http;

    const proxyReq = transport.request(upstreamUrl.toString(), {
      method,
      headers: forwardHeaders,
    }, (proxyRes) => {
      // Capture response for audit
      const responseChunks: Buffer[] = [];
      if (config.audit.logPayload) {
        proxyRes.on('data', (chunk: Buffer) => responseChunks.push(chunk));
      }

      proxyRes.on('end', () => {
        let responseBodyLog: string | null = null;
        if (config.audit.logPayload && responseChunks.length > 0) {
          const maxSize = config.security.maxPayloadLogSize || 10240;
          const bodyStr = Buffer.concat(responseChunks).toString('utf-8');
          responseBodyLog = bodyStr.length > maxSize
            ? bodyStr.substring(0, maxSize) + '... [truncated]' : bodyStr;
        }
        audit.logRequest({
          timestamp: new Date().toISOString(), service: serviceName,
          method, path: requestPath, approved: true,
          responseStatus: proxyRes.statusCode || 0, agentIp: clientIp,
          requestBody: requestBodyLog, responseBody: responseBodyLog,
        });
      });

      // Forward response headers and body
      const resHeaders: Record<string, string | string[]> = {};
      for (const [key, value] of Object.entries(proxyRes.headers)) {
        if (value) resHeaders[key] = value;
      }
      res.writeHead(proxyRes.statusCode || 502, resHeaders);
      proxyRes.pipe(res);
    });

    proxyReq.on('error', (err) => {
      console.error(`❌ Upstream error (MITM) for ${serviceName}: ${err.message}`);
      audit.logRequest({
        timestamp: new Date().toISOString(), service: serviceName,
        method, path: requestPath, approved: true,
        responseStatus: 502, agentIp: clientIp,
        requestBody: requestBodyLog,
      });
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Upstream error: ${err.message}` }));
    });

    if (requestBody.length > 0) {
      proxyReq.write(requestBody);
    }
    proxyReq.end();

    console.log(`🔀 MITM: ${method} ${serviceName}${requestPath} → ${upstreamUrl.host}`);
  });
}

/**
 * Discovery MITM: intercept TLS to inspect headers, then forward as-is to the real upstream.
 * No approval, no auth injection — just logging for service discovery.
 */
function handleDiscoveryMitm(
  hostname: string,
  port: number,
  clientSocket: net.Socket,
  head: Buffer,
  certManager: CertManager,
  config: Config,
  audit: AuditLogger,
  clientIp: string
): void {
  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

  const certPair = certManager.getCertForHost(hostname);

  const tlsSocket = new tls.TLSSocket(clientSocket, {
    isServer: true,
    cert: certPair.cert,
    key: certPair.key,
  });

  const innerServer = http.createServer();

  innerServer.on('request', (req: http.IncomingMessage, res: http.ServerResponse) => {
    const method = req.method || 'GET';
    const requestPath = req.url || '/';

    // Track with full header + query param inspection
    trackDiscoveredHost(hostname, method, requestPath, req.headers as Record<string, string | string[] | undefined>, requestPath);

    // Forward as-is to the real upstream
    const upstreamUrl = new URL(requestPath, `https://${hostname}`);

    // Discovery SSRF/runtime safety checks:
    // 1) allowlist + protocol checks
    const upstreamCheck = validateUpstreamUrl(upstreamUrl.toString(), config.security);
    if (!upstreamCheck.valid) {
      audit.logRequest({
        timestamp: new Date().toISOString(),
        service: `discovery:${hostname}`,
        method,
        path: requestPath,
        approved: false,
        responseStatus: 403,
        agentIp: clientIp,
      });
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Request blocked by security policy: ${upstreamCheck.reason}` }));
      return;
    }

    const forwardHeaders: Record<string, string> = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (key.toLowerCase() === 'host') continue;
      if (typeof value === 'string') forwardHeaders[key] = value;
      else if (Array.isArray(value)) forwardHeaders[key] = value.join(', ');
    }
    forwardHeaders['host'] = hostname;

    // Collect body
    const bodyChunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => bodyChunks.push(chunk));
    req.on('end', async () => {
      // 2) DNS resolution check against private IPs (defense against SSRF/rebinding)
      if (config.security.blockPrivateIPs) {
        const isPrivate = await resolveAndCheckPrivateIP(hostname);
        if (isPrivate) {
          audit.logRequest({
            timestamp: new Date().toISOString(),
            service: `discovery:${hostname}`,
            method,
            path: requestPath,
            approved: false,
            responseStatus: 403,
            agentIp: clientIp,
          });
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Request blocked by security policy: private IP target' }));
          return;
        }
      }

      const body = Buffer.concat(bodyChunks);

      const proxyReq = https.request(upstreamUrl.toString(), {
        method,
        headers: forwardHeaders,
      }, (proxyRes) => {
        const resHeaders: Record<string, string | string[]> = {};
        for (const [key, value] of Object.entries(proxyRes.headers)) {
          if (value) resHeaders[key] = value;
        }
        res.writeHead(proxyRes.statusCode || 502, resHeaders);
        proxyRes.pipe(res);

        audit.logRequest({
          timestamp: new Date().toISOString(),
          service: `discovery:${hostname}`,
          method,
          path: requestPath,
          approved: true,
          responseStatus: proxyRes.statusCode || 0,
          agentIp: clientIp,
        });
      });

      proxyReq.on('error', (err) => {
        audit.logRequest({
          timestamp: new Date().toISOString(),
          service: `discovery:${hostname}`,
          method,
          path: requestPath,
          approved: true,
          responseStatus: 502,
          agentIp: clientIp,
        });
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Upstream error: ${err.message}` }));
      });

      if (body.length > 0) proxyReq.write(body);
      proxyReq.end();
    });
  });

  innerServer.emit('connection', tlsSocket);
  if (head && head.length > 0) tlsSocket.unshift(head);

  tlsSocket.on('error', (err) => {
    if ((err as NodeJS.ErrnoException).code !== 'ECONNRESET') {
      console.error(`❌ Discovery TLS error for ${hostname}: ${err.message}`);
    }
  });
  clientSocket.on('error', () => { /* ignore */ });
}
