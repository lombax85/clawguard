import express, { Request, Response } from 'express';
import http from 'http';
import https from 'https';
import { URL } from 'url';
import { Config, ServiceConfig } from './types';
import { ApprovalManager } from './approval';
import { AuditLogger } from './audit';
import { createAdminRouter } from './admin';
import { validateRuntimeUrl } from './security';
import { rewriteRequestAuth } from './auth-rewrite';

/**
 * Validates that the client sent the correct dummy token.
 * If dummyToken is not configured, validation is skipped (backwards compatible).
 * Returns null if valid, or an error message if invalid.
 */
function validateDummyToken(req: Request, serviceConfig: ServiceConfig): string | null {
  const { auth } = serviceConfig;
  if (!auth.dummyToken) return null; // no dummy configured, skip validation

  switch (auth.type) {
    case 'bearer': {
      const authHeader = req.headers['authorization'] as string | undefined;
      const clientToken = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined;
      if (clientToken !== auth.dummyToken) {
        return 'Invalid or missing dummy token in Authorization header';
      }
      return null;
    }
    case 'header': {
      const headerName = auth.headerName;
      if (!headerName) return null;
      const clientToken = req.headers[headerName.toLowerCase()] as string | undefined;
      if (clientToken !== auth.dummyToken) {
        return `Invalid or missing dummy token in ${headerName} header`;
      }
      return null;
    }
    case 'query': {
      const paramName = auth.paramName;
      if (!paramName) return null;
      const url = new URL(req.originalUrl, `http://${req.headers.host}`);
      const clientToken = url.searchParams.get(paramName);
      if (clientToken !== auth.dummyToken) {
        return `Invalid or missing dummy token in ${paramName} query param`;
      }
      return null;
    }
    default:
      return null; // other auth types don't support dummy validation yet
  }
}

export function createProxy(
  config: Config,
  approvalManager: ApprovalManager,
  audit: AuditLogger
): express.Application {
  const app = express();

  // Parse raw body for forwarding
  app.use(express.raw({ type: '*/*', limit: '10mb' }));

  // ─── Admin panel ──────────────────────────────────────────

  if (config.admin.enabled) {
    const adminRouter = createAdminRouter(config, approvalManager, audit);
    app.use('/__admin', adminRouter);
  }

  // ─── Status endpoint (requires agent key) ─────────────────

  app.get('/__status', (req: Request, res: Response) => {
    const agentKey = req.headers['x-clawguard-key'] as string | undefined;
    if (agentKey !== config.server.agentKey) {
      res.status(401).json({ error: 'Invalid or missing X-ClawGuard-Key' });
      return;
    }
    res.json({
      status: 'running',
      version: '0.2.0',
      services: Object.keys(config.services),
      approvals: approvalManager.getStatus(),
    });
  });

  // ─── Audit endpoint (requires agent key) ──────────────────

  app.get('/__audit', (req: Request, res: Response) => {
    const agentKey = req.headers['x-clawguard-key'] as string | undefined;
    if (agentKey !== config.server.agentKey) {
      res.status(401).json({ error: 'Invalid or missing X-ClawGuard-Key' });
      return;
    }
    const limit = parseInt(req.query['limit'] as string) || 50;
    res.json(audit.getRecentRequests(limit));
  });

  // ─── Main proxy: /:service (root path) ────────────────────

  app.all('/:service', handleProxy(config, approvalManager, audit));

  // ─── Main proxy: /:service/* (subpaths) ───────────────────

  app.all('/:service/*', handleProxy(config, approvalManager, audit));

  // ─── Host-based routing (for /etc/hosts or forwarder mode) ──
  // When traffic arrives with Host: api.openai.com (no service prefix),
  // match it against configured hostnames and route accordingly.

  app.all('*', handleHostProxy(config, approvalManager, audit, { requireAgentKey: true }));

  return app;
}

/**
 * Resolves a service by matching the request Host header against
 * the `hostnames` array configured for each service.
 */
function resolveServiceByHost(
  host: string | undefined,
  services: Record<string, ServiceConfig>
): { name: string; config: ServiceConfig } | null {
  if (!host) return null;
  const hostname = host.split(':')[0]; // strip port
  for (const [name, svc] of Object.entries(services)) {
    if (svc.hostnames?.some((h) => h === hostname)) {
      return { name, config: svc };
    }
  }
  return null;
}

export function handleHostProxy(
  config: Config,
  approvalManager: ApprovalManager,
  audit: AuditLogger,
  options: { requireAgentKey: boolean; passthrough?: boolean } = { requireAgentKey: true }
) {
  return async (req: Request, res: Response): Promise<void> => {
    const match = resolveServiceByHost(req.headers.host, config.services);

    if (!match) {
      // In transparent proxy mode, forward unknown hosts directly (passthrough)
      if (options.passthrough) {
        const host = req.headers.host || '';
        const hostname = host.split(':')[0];
        const port = host.includes(':') ? parseInt(host.split(':')[1]) : 80;
        const upstreamPath = req.originalUrl || '/';
        const upstreamUrl = `http://${hostname}:${port}${upstreamPath}`;

        console.log(`🔀 Passthrough (no injection): ${req.method} ${upstreamUrl}`);

        try {
          const forwardHeaders: Record<string, string> = {};
          for (const [key, value] of Object.entries(req.headers)) {
            if (typeof value === 'string') forwardHeaders[key] = value;
            else if (Array.isArray(value)) forwardHeaders[key] = value.join(', ');
          }

          const requestBody = (req.body && Buffer.isBuffer(req.body)) ? req.body : Buffer.alloc(0);

          const proxyReq = http.request(upstreamUrl, {
            method: req.method,
            headers: forwardHeaders,
          }, (proxyRes) => {
            res.status(proxyRes.statusCode || 502);
            for (const [key, value] of Object.entries(proxyRes.headers)) {
              if (value) res.setHeader(key, value as string | string[]);
            }
            proxyRes.pipe(res);
          });

          proxyReq.on('error', (err) => {
            console.error(`❌ Passthrough error for ${hostname}: ${err.message}`);
            res.status(502).json({ error: `Upstream error: ${err.message}` });
          });

          if (requestBody.length > 0) proxyReq.write(requestBody);
          proxyReq.end();
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Unknown error';
          console.error(`❌ Passthrough error: ${message}`);
          res.status(500).json({ error: message });
        }
        return;
      }

      res.status(404).json({ error: 'Unknown host. Configure hostnames in service config for host-based routing.' });
      return;
    }

    const serviceName = match.name;
    const serviceConfig = match.config;

    // Validate agent key if required
    if (options.requireAgentKey) {
      const agentKey = (req.headers['x-clawguard-key'] || req.headers['x-agentgate-key']) as string | undefined;
      if (agentKey !== config.server.agentKey) {
        res.status(401).json({ error: 'Invalid or missing X-ClawGuard-Key' });
        return;
      }
    }

    // ─── Validate dummy token ─────────────────────────────────
    const dummyError = validateDummyToken(req, serviceConfig);
    if (dummyError) {
      console.error(`🚫 Dummy token validation failed for ${serviceName}: ${dummyError}`);
      audit.logRequest({
        timestamp: new Date().toISOString(), service: serviceName,
        method: req.method, path: req.originalUrl || '/', approved: false,
        responseStatus: 403, agentIp: (req.ip || req.socket.remoteAddress || 'unknown') as string,
      });
      res.status(403).json({ error: dummyError });
      return;
    }

    // In host-based mode, the entire path is the upstream path (no prefix to strip)
    const upstreamPath = req.originalUrl || '/';
    const agentIp = (req.ip || req.socket.remoteAddress || 'unknown') as string;

    // ─── SSRF check ──────────────────────────────────────────

    const upstreamUrl = new URL(upstreamPath, serviceConfig.upstream);
    const runtimeCheck = validateRuntimeUrl(upstreamUrl.toString(), serviceConfig.upstream, config.security);
    if (!runtimeCheck.valid) {
      console.error(`🚫 SSRF blocked (host-mode): ${runtimeCheck.reason}`);
      res.status(403).json({ error: 'Request blocked by security policy' });
      return;
    }

    // ─── Approval ────────────────────────────────────────────

    const approved = await approvalManager.checkApproval(
      serviceName, serviceConfig, req.method, upstreamPath, agentIp
    );

    if (!approved) {
      audit.logRequest({
        timestamp: new Date().toISOString(), service: serviceName,
        method: req.method, path: upstreamPath, approved: false,
        responseStatus: 403, agentIp,
      });
      res.status(403).json({ error: 'Approval denied or timed out' });
      return;
    }

    // ─── Forward ─────────────────────────────────────────────

    try {
      const isHttps = upstreamUrl.protocol === 'https:';
      const transport = isHttps ? https : http;

      const forwardHeaders: Record<string, string> = {};
      for (const [key, value] of Object.entries(req.headers)) {
        const lower = key.toLowerCase();
        if (lower.startsWith('x-clawguard')) continue;
        if (lower.startsWith('x-agentgate')) continue;
        if (lower === 'host') continue;
        if (typeof value === 'string') forwardHeaders[key] = value;
        else if (Array.isArray(value)) forwardHeaders[key] = value.join(', ');
      }

      // Rewrite body for oauth2_client_credentials
      let requestBody = (req.body && Buffer.isBuffer(req.body)) ? req.body : Buffer.alloc(0);
      const rewritten = rewriteRequestAuth(serviceConfig, req.method, upstreamPath, requestBody, forwardHeaders);
      requestBody = rewritten.body;
      Object.assign(forwardHeaders, rewritten.headers);

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

      let requestBodyLog: string | null = null;
      if (config.audit.logPayload && requestBody.length > 0) {
        const maxSize = config.security.maxPayloadLogSize || 10240;
        const bodyStr = requestBody.toString('utf-8');
        requestBodyLog = bodyStr.length > maxSize
          ? bodyStr.substring(0, maxSize) + `... [truncated]` : bodyStr;
      }

      const proxyReq = transport.request(upstreamUrl.toString(), {
        method: req.method, headers: forwardHeaders,
      }, (proxyRes) => {
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
              ? bodyStr.substring(0, maxSize) + `... [truncated]` : bodyStr;
          }
          audit.logRequest({
            timestamp: new Date().toISOString(), service: serviceName,
            method: req.method, path: upstreamPath, approved: true,
            responseStatus: proxyRes.statusCode || 0, agentIp,
            requestBody: requestBodyLog, responseBody: responseBodyLog,
          });
        });

        res.status(proxyRes.statusCode || 502);
        for (const [key, value] of Object.entries(proxyRes.headers)) {
          if (value) res.setHeader(key, value as string | string[]);
        }
        proxyRes.pipe(res);
      });

      proxyReq.on('error', (err) => {
        console.error(`❌ Upstream error (host-mode) for ${serviceName}: ${err.message}`);
        audit.logRequest({
          timestamp: new Date().toISOString(), service: serviceName,
          method: req.method, path: upstreamPath, approved: true,
          responseStatus: 502, agentIp, requestBody: requestBodyLog,
        });
        res.status(502).json({ error: `Upstream error: ${err.message}` });
      });

      if (requestBody.length > 0) {
        proxyReq.write(requestBody);
      }
      proxyReq.end();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      console.error(`❌ Proxy error (host-mode): ${message}`);
      res.status(500).json({ error: message });
    }
  };
}

function handleProxy(
  config: Config,
  approvalManager: ApprovalManager,
  audit: AuditLogger
) {
  return async (req: Request, res: Response): Promise<void> => {
    const serviceName = req.params['service'] as string;

    // Skip internal routes
    if (serviceName.startsWith('__')) {
      res.status(404).json({ error: 'Not found' });
      return;
    }

    const serviceConfig: ServiceConfig | undefined = config.services[serviceName];

    if (!serviceConfig) {
      res.status(404).json({ error: `Unknown service: ${serviceName}` });
      return;
    }

    // Validate agent key
    const agentKey = (req.headers['x-clawguard-key'] || req.headers['x-agentgate-key']) as string | undefined;
    if (agentKey !== config.server.agentKey) {
      res.status(401).json({ error: 'Invalid or missing X-ClawGuard-Key' });
      return;
    }

    // ─── Validate dummy token ─────────────────────────────────
    const dummyError = validateDummyToken(req, serviceConfig);
    if (dummyError) {
      console.error(`🚫 Dummy token validation failed for ${serviceName}: ${dummyError}`);
      audit.logRequest({
        timestamp: new Date().toISOString(), service: serviceName,
        method: req.method, path: req.originalUrl || '/', approved: false,
        responseStatus: 403, agentIp: (req.ip || req.socket.remoteAddress || 'unknown') as string,
      });
      res.status(403).json({ error: dummyError });
      return;
    }

    // Build upstream path — anchored removal of service prefix
    const prefixLen = `/${serviceName}`.length;
    const upstreamPath = req.originalUrl.substring(prefixLen) || '/';
    const agentIp = (req.ip || req.socket.remoteAddress || 'unknown') as string;

    // ─── SSRF check: validate constructed URL ───────────────

    const upstreamUrl = new URL(upstreamPath, serviceConfig.upstream);
    const runtimeCheck = validateRuntimeUrl(upstreamUrl.toString(), serviceConfig.upstream, config.security);
    if (!runtimeCheck.valid) {
      console.error(`🚫 SSRF blocked: ${runtimeCheck.reason}`);
      audit.logRequest({
        timestamp: new Date().toISOString(),
        service: serviceName,
        method: req.method,
        path: upstreamPath,
        approved: false,
        responseStatus: 403,
        agentIp,
      });
      res.status(403).json({ error: 'Request blocked by security policy' });
      return;
    }

    // ─── Check approval ─────────────────────────────────────

    const approved = await approvalManager.checkApproval(
      serviceName,
      serviceConfig,
      req.method,
      upstreamPath,
      agentIp
    );

    if (!approved) {
      audit.logRequest({
        timestamp: new Date().toISOString(),
        service: serviceName,
        method: req.method,
        path: upstreamPath,
        approved: false,
        responseStatus: 403,
        agentIp,
      });
      res.status(403).json({ error: 'Approval denied or timed out' });
      return;
    }

    // ─── Forward request to upstream ────────────────────────

    try {
      const isHttps = upstreamUrl.protocol === 'https:';
      const transport = isHttps ? https : http;

      // Build headers (forward original, inject auth, remove clawguard headers)
      const forwardHeaders: Record<string, string> = {};
      for (const [key, value] of Object.entries(req.headers)) {
        const lower = key.toLowerCase();
        if (lower.startsWith('x-clawguard')) continue;
        if (lower.startsWith('x-agentgate')) continue;
        if (lower === 'host') continue;
        if (typeof value === 'string') {
          forwardHeaders[key] = value;
        } else if (Array.isArray(value)) {
          forwardHeaders[key] = value.join(', ');
        }
      }

      // Rewrite body for oauth2_client_credentials (replaces dummy secrets with real ones)
      let requestBody = (req.body && Buffer.isBuffer(req.body)) ? req.body : Buffer.alloc(0);
      const rewritten = rewriteRequestAuth(serviceConfig, req.method, upstreamPath, requestBody, forwardHeaders);
      requestBody = rewritten.body;
      Object.assign(forwardHeaders, rewritten.headers);

      // Inject auth (skipped for oauth2_client_credentials — script manages its own Bearer token)
      if (!rewritten.skipAuthInjection) {
        if (serviceConfig.auth.type === 'bearer') {
          forwardHeaders['authorization'] = `Bearer ${serviceConfig.auth.token}`;
        } else if (serviceConfig.auth.type === 'basic' && serviceConfig.auth.username && serviceConfig.auth.password) {
          const basicAuth = Buffer.from(`${serviceConfig.auth.username}:${serviceConfig.auth.password}`).toString('base64');
          forwardHeaders['authorization'] = `Basic ${basicAuth}`;
        } else if (serviceConfig.auth.type === 'url' && serviceConfig.auth.username && serviceConfig.auth.password) {
          // Inject credentials into URL (for services like Bitbucket that require user:pass@host)
          upstreamUrl.username = serviceConfig.auth.username;
          upstreamUrl.password = serviceConfig.auth.password;
        } else if (serviceConfig.auth.type === 'header' && serviceConfig.auth.headerName) {
          forwardHeaders[serviceConfig.auth.headerName] = serviceConfig.auth.token;
        } else if (serviceConfig.auth.type === 'query' && serviceConfig.auth.paramName) {
          upstreamUrl.searchParams.set(serviceConfig.auth.paramName, serviceConfig.auth.token);
        }
      }

      forwardHeaders['host'] = upstreamUrl.host;

      // Capture request body for audit
      let requestBodyLog: string | null = null;
      if (config.audit.logPayload && requestBody.length > 0) {
        const maxSize = config.security.maxPayloadLogSize || 10240;
        const bodyStr = requestBody.toString('utf-8');
        requestBodyLog = bodyStr.length > maxSize
          ? bodyStr.substring(0, maxSize) + `... [truncated, ${requestBody.length} bytes total]`
          : bodyStr;
      }

      const proxyReq = transport.request(
        upstreamUrl.toString(),
        {
          method: req.method,
          headers: forwardHeaders,
        },
        (proxyRes) => {
          // Don't follow redirects if disabled
          if (!config.security.followRedirects && proxyRes.statusCode && proxyRes.statusCode >= 300 && proxyRes.statusCode < 400) {
            const location = proxyRes.headers['location'];
            if (location) {
              const redirectCheck = validateRuntimeUrl(
                new URL(location, upstreamUrl.toString()).toString(),
                serviceConfig.upstream,
                config.security
              );
              if (!redirectCheck.valid) {
                console.error(`🚫 Redirect blocked: ${redirectCheck.reason}`);
                audit.logRequest({
                  timestamp: new Date().toISOString(),
                  service: serviceName,
                  method: req.method,
                  path: upstreamPath,
                  approved: true,
                  responseStatus: 403,
                  agentIp,
                  requestBody: requestBodyLog,
                });
                res.status(403).json({ error: 'Redirect blocked by security policy' });
                return;
              }
            }
          }

          // Capture response body for audit
          const responseChunks: Buffer[] = [];
          if (config.audit.logPayload) {
            proxyRes.on('data', (chunk: Buffer) => {
              responseChunks.push(chunk);
            });
          }

          proxyRes.on('end', () => {
            let responseBodyLog: string | null = null;
            if (config.audit.logPayload && responseChunks.length > 0) {
              const maxSize = config.security.maxPayloadLogSize || 10240;
              const bodyStr = Buffer.concat(responseChunks).toString('utf-8');
              responseBodyLog = bodyStr.length > maxSize
                ? bodyStr.substring(0, maxSize) + `... [truncated, ${bodyStr.length} bytes total]`
                : bodyStr;
            }

            audit.logRequest({
              timestamp: new Date().toISOString(),
              service: serviceName,
              method: req.method,
              path: upstreamPath,
              approved: true,
              responseStatus: proxyRes.statusCode || 0,
              agentIp,
              requestBody: requestBodyLog,
              responseBody: responseBodyLog,
            });
          });

          // Forward response
          res.status(proxyRes.statusCode || 502);
          for (const [key, value] of Object.entries(proxyRes.headers)) {
            if (value) res.setHeader(key, value as string | string[]);
          }
          proxyRes.pipe(res);
        }
      );

      proxyReq.on('error', (err) => {
        console.error(`❌ Upstream error for ${serviceName}: ${err.message}`);
        audit.logRequest({
          timestamp: new Date().toISOString(),
          service: serviceName,
          method: req.method,
          path: upstreamPath,
          approved: true,
          responseStatus: 502,
          agentIp,
          requestBody: requestBodyLog,
        });
        res.status(502).json({ error: `Upstream error: ${err.message}` });
      });

      // Forward body
      if (requestBody.length > 0) {
        proxyReq.write(requestBody);
      }
      proxyReq.end();

    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      console.error(`❌ Proxy error: ${message}`);
      res.status(500).json({ error: message });
    }
  };
}
