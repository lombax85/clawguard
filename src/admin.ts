import { Router, Request, Response, NextFunction } from 'express';
import path from 'path';
import net from 'net';
import { Config, ServiceConfig } from './types';
import { ApprovalManager } from './approval';
import { AuditLogger } from './audit';
import { validateUpstreamUrl } from './security';

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
  audit: AuditLogger
): Router {
  const router = Router();

  // ─── Middleware: IP allowlist ──────────────────────────────

  router.use((req: Request, res: Response, next: NextFunction) => {
    const clientIp = req.ip || req.socket.remoteAddress || '';
    const allowed = config.admin.allowedIPs;

    if (!allowed.some((entry) => ipMatchesEntry(clientIp, entry))) {
      res.status(403).json({ error: 'Admin panel is not accessible from your IP' });
      return;
    }
    next();
  });

  // ─── Serve web UI ─────────────────────────────────────────

  router.get('/', (_req: Request, res: Response) => {
    res.sendFile(path.join(process.cwd(), 'public', 'index.html'));
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

  router.get('/api/stats', pinAuth, (_req: Request, res: Response) => {
    const stats = audit.getDashboardStats(
      approvalManager.getActiveCount(),
      Object.keys(config.services).length
    );
    res.json(stats);
  });

  // ─── Services CRUD ────────────────────────────────────────

  router.get('/api/services', pinAuth, (_req: Request, res: Response) => {
    const services: Record<string, unknown> = {};
    for (const [name, svc] of Object.entries(config.services)) {
      services[name] = {
        upstream: svc.upstream,
        auth: {
          type: svc.auth.type,
          token: maskToken(svc.auth.token),
          headerName: svc.auth.headerName,
        },
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
    const revoked = approvalManager.revokeApproval(service);
    if (revoked) {
      res.json({ ok: true, message: `Approval for "${service}" revoked` });
    } else {
      res.status(404).json({ error: `No active approval for "${service}"` });
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

  // ─── Telegram pairing info ────────────────────────────────

  router.get('/api/telegram', pinAuth, (_req: Request, res: Response) => {
    res.json({
      pairedUsers: audit.getPairedUsers(),
      pairingEnabled: config.notifications.telegram.pairing.enabled,
    });
  });

  return router;
}

// ─── Helpers ──────────────────────────────────────────────────

function maskToken(token: string): string {
  if (token.length <= 8) return '****';
  return token.substring(0, 4) + '****' + token.substring(token.length - 4);
}
