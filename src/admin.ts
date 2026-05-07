import { Router, Request, Response, NextFunction } from 'express';
import path from 'path';
import net from 'net';
import { Config, ServiceConfig } from './types';
import { ApprovalManager } from './approval';
import { AuditLogger } from './audit';
import { validateUpstreamUrl } from './security';
import { getPassthroughHosts } from './mitm-proxy';
import { WebPushNotifier } from './webpush';

/**
 * Check if an IP matches an allowed entry.
 * Supports exact IPs ("192.168.1.50") and CIDR notation ("192.168.1.0/24").
 */
function ipMatchesEntry(clientIp: string, entry: string): boolean {
  // Strip IPv6-mapped-IPv4 prefix for comparison
  const normalizedClient = clientIp.replace(/^::ffff:/, '');

  if (entry.includes('/')) {
    // CIDR notation
    return isIpInCidr(normalizedClient, entry);
  }

  // Exact match (check both raw and normalized)
  return clientIp === entry || normalizedClient === entry || clientIp === `::ffff:${entry}`;
}

function isIpInCidr(ip: string, cidr: string): boolean {
  const [network, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);

  if (!net.isIPv4(ip) || !net.isIPv4(network)) return false;
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;

  const ipNum = ipv4ToInt(ip);
  const netNum = ipv4ToInt(network);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;

  return (ipNum & mask) === (netNum & mask);
}

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function createAdminRouter(
  config: Config,
  approvalManager: ApprovalManager,
  audit: AuditLogger,
  webpushNotifier?: WebPushNotifier
): Router {
  const router = Router();

  // ─── Middleware: IP allowlist ──────────────────────────────

  router.use((req: Request, res: Response, next: NextFunction) => {
    const clientIp = req.ip || req.socket.remoteAddress || '';
    const allowed = config.admin.allowedIPs;

    if (!allowed.some((entry) => ipMatchesEntry(clientIp, entry))) {
      console.warn(`⛔ Admin access denied for IP: ${clientIp} (allowed: ${allowed.join(', ')})`);
      res.status(403).json({
        error: 'Admin panel is not accessible from your IP',
        clientIp,
        hint: 'Add this IP/CIDR to admin.allowedIPs if expected',
      });
      return;
    }
    next();
  });

  // ─── Serve web UI ─────────────────────────────────────────

  router.get('/', (_req: Request, res: Response) => {
    res.sendFile(path.join(process.cwd(), 'public', 'index.html'));
  });

  // ─── Service worker (must be served at /__admin/ scope, no PIN) ──
  // The browser fetches this directly when registering the SW, so we
  // can't gate it on a PIN header. The IP allowlist (above) still applies.

  router.get('/sw.js', (_req: Request, res: Response) => {
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.setHeader('Service-Worker-Allowed', '/__admin/');
    res.setHeader('Cache-Control', 'no-cache');
    res.sendFile(path.join(process.cwd(), 'public', 'sw.js'));
  });

  // ─── Login (validate PIN) ─────────────────────────────────

  router.post('/api/login', (req: Request, res: Response) => {
    let body: { pin?: string };
    try {
      body = JSON.parse(req.body?.toString() || '{}');
    } catch {
      body = {};
    }

    if (body.pin === config.admin.pin) {
      res.json({ ok: true });
    } else {
      res.status(401).json({ error: 'Invalid PIN' });
    }
  });

  // ─── Middleware: PIN auth (for all api/ routes after login) ──

  const pinAuth = (req: Request, res: Response, next: NextFunction) => {
    const pin = req.headers['x-clawguard-pin'] as string | undefined;
    if (pin !== config.admin.pin) {
      res.status(401).json({ error: 'Invalid or missing X-ClawGuard-Pin header' });
      return;
    }
    next();
  };

  // ─── Dashboard stats ─────────────────────────────────────

  router.get('/api/stats', pinAuth, (req: Request, res: Response) => {
    const filterService = req.query['service'] as string | undefined;
    const stats = audit.getDashboardStats(
      approvalManager.getActiveCount(),
      Object.keys(config.services).length,
      filterService || undefined
    );
    res.json(stats);
  });

  // ─── Services CRUD ────────────────────────────────────────

  router.get('/api/services', pinAuth, (_req: Request, res: Response) => {
    const services: Record<string, unknown> = {};
    for (const [name, svc] of Object.entries(config.services)) {
      const authInfo: Record<string, unknown> = {
        type: svc.auth.type,
        token: maskToken(svc.auth.token),
        headerName: svc.auth.headerName,
        paramName: svc.auth.paramName,
      };
      if (svc.auth.type === 'oauth2_client_credentials') {
        authInfo.tokenPath = svc.auth.tokenPath;
        authInfo.clientId = svc.auth.clientId ? maskToken(svc.auth.clientId) : undefined;
        authInfo.clientSecret = svc.auth.clientSecret ? maskToken(svc.auth.clientSecret) : undefined;
      }
      if (svc.auth.type === 'body_json' && svc.auth.fields) {
        const maskedFields: Record<string, string> = {};
        for (const [key, value] of Object.entries(svc.auth.fields)) {
          maskedFields[key] = maskToken(value);
        }
        authInfo.fields = maskedFields;
      }
      services[name] = {
        upstream: svc.upstream,
        auth: authInfo,
        policy: svc.policy,
      };
    }
    res.json(services);
  });

  router.post('/api/services', pinAuth, (req: Request, res: Response) => {
    let body: { name?: string; config?: ServiceConfig };
    try {
      body = JSON.parse(req.body?.toString() || '{}');
    } catch {
      res.status(400).json({ error: 'Invalid JSON body' });
      return;
    }

    if (!body.name || !body.config) {
      res.status(400).json({ error: 'Missing name or config' });
      return;
    }

    if (config.services[body.name]) {
      res.status(409).json({ error: `Service "${body.name}" already exists` });
      return;
    }

    // Validate upstream
    const validation = validateUpstreamUrl(body.config.upstream, config.security);
    if (!validation.valid) {
      res.status(400).json({ error: validation.reason });
      return;
    }

    // Save to SQLite and update runtime config
    audit.saveServiceOverride(body.name, body.config);
    config.services[body.name] = body.config;
    console.log(`➕ Service added via admin: ${body.name} → ${body.config.upstream}`);
    res.json({ ok: true, service: body.name });
  });

  router.put('/api/services/:name', pinAuth, (req: Request, res: Response) => {
    const name = req.params['name'] as string;
    let body: { config?: Partial<ServiceConfig> };
    try {
      body = JSON.parse(req.body?.toString() || '{}');
    } catch {
      res.status(400).json({ error: 'Invalid JSON body' });
      return;
    }

    if (!config.services[name]) {
      res.status(404).json({ error: `Service "${name}" not found` });
      return;
    }

    // Merge with existing
    const updated: ServiceConfig = {
      ...config.services[name],
      ...body.config,
      auth: { ...config.services[name].auth, ...body.config?.auth },
      policy: { ...config.services[name].policy, ...body.config?.policy },
    };

    // Validate upstream if changed
    if (body.config?.upstream) {
      const validation = validateUpstreamUrl(body.config.upstream, config.security);
      if (!validation.valid) {
        res.status(400).json({ error: validation.reason });
        return;
      }
    }

    audit.saveServiceOverride(name, updated);
    config.services[name] = updated;
    console.log(`✏️  Service updated via admin: ${name}`);
    res.json({ ok: true, service: name });
  });

  router.delete('/api/services/:name', pinAuth, (req: Request, res: Response) => {
    const name = req.params['name'] as string;
    if (!config.services[name]) {
      res.status(404).json({ error: `Service "${name}" not found` });
      return;
    }

    audit.deleteServiceOverride(name);
    delete config.services[name];
    approvalManager.revokeApproval(name);
    console.log(`🗑️  Service deleted via admin: ${name}`);
    res.json({ ok: true });
  });

  // ─── Approvals ────────────────────────────────────────────

  router.get('/api/approvals', pinAuth, (_req: Request, res: Response) => {
    res.json({
      active: approvalManager.getStatus(),
      recent: audit.getRecentApprovals(20),
    });
  });

  router.post('/api/revoke/:service', pinAuth, (req: Request, res: Response) => {
    const service = req.params['service'] as string;
    const method = (req.query['method'] as string | undefined)?.toUpperCase();
    // path query param: omitted → any scope for that method; "" or "*" → method-wide; string → exact path
    const rawPath = req.query['path'] as string | undefined;
    let path: string | null | undefined;
    if (rawPath === undefined) path = undefined;
    else if (rawPath === '' || rawPath === '*') path = null;
    else path = rawPath;

    const revoked = approvalManager.revokeApproval(service, method, path);
    const describeScope = () => {
      if (!method) return service;
      if (path === undefined) return `${service} ${method}`;
      if (path === null) return `${service} ${method} (method-wide)`;
      return `${service} ${method} path=${path}`;
    };
    if (revoked) {
      res.json({ ok: true, message: `Approval for "${describeScope()}" revoked` });
    } else {
      res.status(404).json({ error: `No active approval for "${describeScope()}"` });
    }
  });

  router.post('/api/revoke-all', pinAuth, (_req: Request, res: Response) => {
    const count = approvalManager.revokeAll();
    res.json({ ok: true, revoked: count });
  });

  // ─── Audit log ────────────────────────────────────────────

  router.get('/api/requests', pinAuth, (req: Request, res: Response) => {
    const limit = parseInt(req.query['limit'] as string) || 100;
    res.json(audit.getRecentRequests(limit));
  });

  // ─── Allowed upstreams (for UI hints) ─────────────────────

  router.get('/api/allowed-upstreams', pinAuth, (_req: Request, res: Response) => {
    res.json({
      allowedUpstreams: config.security.allowedUpstreams,
      blockPrivateIPs: config.security.blockPrivateIPs,
    });
  });

  // ─── Discovered hosts (proxy passthrough) ────────────────

  router.get('/api/discovered-hosts', pinAuth, (_req: Request, res: Response) => {
    res.json(getPassthroughHosts());
  });

  // ─── Telegram pairing info ────────────────────────────────

  router.get('/api/telegram', pinAuth, (_req: Request, res: Response) => {
    res.json({
      pairedUsers: audit.getPairedUsers(),
      pairingEnabled: config.notifications?.telegram?.pairing?.enabled ?? false,
    });
  });

  // ─── Web Push ─────────────────────────────────────────────

  // Public — the SW fetches this before subscribing. Returns the VAPID public
  // key + a flag so the dashboard knows if pushes are enabled at all.
  router.get('/api/webpush/config', (_req: Request, res: Response) => {
    if (!webpushNotifier) {
      res.json({ enabled: false });
      return;
    }
    res.json({
      enabled: true,
      publicKey: webpushNotifier.getPublicKey(),
    });
  });

  router.post('/api/webpush/subscribe', pinAuth, (req: Request, res: Response) => {
    if (!webpushNotifier) {
      res.status(400).json({ error: 'Web Push is not enabled in config' });
      return;
    }
    let body: { endpoint?: string; keys?: { p256dh?: string; auth?: string } };
    try {
      body = JSON.parse(req.body?.toString() || '{}');
    } catch {
      res.status(400).json({ error: 'Invalid JSON body' });
      return;
    }
    if (!body.endpoint || !body.keys?.p256dh || !body.keys?.auth) {
      res.status(400).json({ error: 'Missing endpoint, keys.p256dh, or keys.auth' });
      return;
    }
    const userAgent = (req.headers['user-agent'] as string | undefined) || null;
    audit.saveWebPushSubscription(body.endpoint, body.keys.p256dh, body.keys.auth, userAgent);
    console.log(`🔔 Web Push subscription registered (${body.endpoint.slice(-12)})`);
    res.json({ ok: true });
  });

  router.post('/api/webpush/unsubscribe', pinAuth, (req: Request, res: Response) => {
    let body: { endpoint?: string };
    try {
      body = JSON.parse(req.body?.toString() || '{}');
    } catch {
      res.status(400).json({ error: 'Invalid JSON body' });
      return;
    }
    if (!body.endpoint) {
      res.status(400).json({ error: 'Missing endpoint' });
      return;
    }
    const removed = audit.deleteWebPushSubscription(body.endpoint);
    res.json({ ok: removed });
  });

  // Public — invoked by the service worker when the user taps an action button
  // on a Web Push notification. Authentication is via HMAC signature inside the
  // payload (signed by ClawGuard at push time using the VAPID private key).
  router.post('/api/webpush/respond', (req: Request, res: Response) => {
    if (!webpushNotifier) {
      res.status(400).json({ error: 'Web Push is not enabled' });
      return;
    }
    let body: { requestId?: string; action?: string; signature?: string };
    try {
      body = JSON.parse(req.body?.toString() || '{}');
    } catch {
      res.status(400).json({ error: 'Invalid JSON body' });
      return;
    }
    if (!body.requestId || !body.action || !body.signature) {
      res.status(400).json({ error: 'Missing requestId, action, or signature' });
      return;
    }
    const result = webpushNotifier.resolveRequest(body.requestId, body.action, body.signature);
    if (!result.ok) {
      res.status(409).json({ error: result.reason });
      return;
    }
    console.log(`📲 Web Push callback: action=${body.action} requestId=${body.requestId}`);
    res.json({ ok: true });
  });

  router.get('/api/webpush/subscriptions', pinAuth, (_req: Request, res: Response) => {
    const subs = audit.getWebPushSubscriptions().map((s) => ({
      id: s.id,
      endpointSuffix: s.endpoint.slice(-16),
      userAgent: s.userAgent,
      createdAt: s.createdAt,
    }));
    res.json({ subscriptions: subs, enabled: !!webpushNotifier });
  });

  return router;
}

// ─── Helpers ──────────────────────────────────────────────────

function maskToken(token: string): string {
  if (token.length <= 8) return '****';
  return token.substring(0, 4) + '****' + token.substring(token.length - 4);
}
