import { Router, Request, Response, NextFunction } from 'express';
import path from 'path';
import net from 'net';
import { Config, ServiceConfig } from './types';
import { ApprovalManager } from './approval';
import { AuditLogger } from './audit';
import { TelegramNotifier } from './telegram';
import { getPassthroughHosts } from './mitm-proxy';
import { createAdminProposalRouter, isProposalApplying } from './service-proposals';
import {
  AdminServiceRuntime,
  createAdminServiceRuntime,
  hydrateAdminService,
  hydrateAdminServicePatch,
  redactServiceForAdmin,
  validateAdminService,
} from './admin-service';
import {
  AdminSshKeyTools,
  buildAdminSshService,
  createAdminSshKeyTools,
  discoverAdminSshHostKeys,
  getAdminSshWizardMetadata,
  listAdminSshKeySources,
} from './admin-ssh';

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

function rejectIfStrictMode(config: Config, res: Response): boolean {
  if (!config.admin.strictMode) return false;
  res.status(403).json({
    error: 'Admin service editing is disabled by admin.strictMode. Edit clawguard.yaml and restart ClawGuard, or set admin.strictMode: false.',
  });
  return true;
}

export function createAdminRouter(
  config: Config,
  approvalManager: ApprovalManager,
  audit: AuditLogger,
  telegram?: TelegramNotifier,
  serviceRuntime: AdminServiceRuntime = createAdminServiceRuntime(config),
  sshKeyTools: AdminSshKeyTools = createAdminSshKeyTools(
    config.sshBroker.sshAgentPath,
    config.sshBroker.sshAddPath,
    config.sshBroker.sshKeyscanPath
  )
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

  router.use('/api', pinAuth, createAdminProposalRouter(config, audit, serviceRuntime));
  // A proposal may be asynchronously initializing credentials on either the
  // HTTP or HTTPS listener. Reserve its alias across ordinary admin writes.
  router.use('/api', (req: Request, res: Response, next: NextFunction) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) { next(); return; }
    let name: unknown;
    try { name = JSON.parse(req.body?.toString() || '{}').name; } catch { /* handler reports malformed JSON */ }
    const pathName = /^\/(?:services|ssh-services)\/([^/]+)/.exec(req.path)?.[1];
    let decodedName: string | undefined;
    try { decodedName = pathName ? decodeURIComponent(pathName) : undefined; } catch { /* route reports invalid encoding */ }
    if ((typeof name === 'string' && isProposalApplying(config, name))
      || (decodedName && isProposalApplying(config, decodedName))) {
      res.status(409).json({ error: 'This service is being approved; wait for the proposal to finish' });
      return;
    }
    next();
  });

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

  router.get('/api/admin-config', pinAuth, (_req: Request, res: Response) => {
    res.json({
      strictMode: config.admin.strictMode,
      serviceEditingEnabled: !config.admin.strictMode,
    });
  });

  // ─── Services CRUD ────────────────────────────────────────

  router.get('/api/services', pinAuth, (_req: Request, res: Response) => {
    const services: Record<string, unknown> = {};
    for (const [name, svc] of Object.entries(config.services)) {
      const authInfo: Record<string, unknown> = {
        type: svc.auth.type,
        token: maskToken(svc.auth.token),
        dummyToken: svc.auth.dummyToken ? maskToken(svc.auth.dummyToken) : undefined,
        headerName: svc.auth.headerName,
        paramName: svc.auth.paramName,
        username: svc.auth.username,
        password: svc.auth.password ? maskToken(svc.auth.password) : undefined,
        pluginPath: svc.auth.pluginPath,
        pluginConfigPresent: svc.auth.pluginConfig !== undefined,
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
        protocol: svc.protocol ?? 'http',
        upstream: svc.upstream,
        auth: authInfo,
        policy: svc.policy,
        hostnames: svc.hostnames,
        ssh: svc.ssh,
        ftp: svc.ftp,
        sshWizard: getAdminSshWizardMetadata(svc),
        editableConfig: redactServiceForAdmin(svc),
      };
    }
    res.json(services);
  });

  router.get('/api/ssh-key-sources', pinAuth, (_req: Request, res: Response) => {
    res.json(listAdminSshKeySources(config));
  });

  router.post('/api/ssh-host-keys/scan', pinAuth, async (req: Request, res: Response) => {
    if (rejectIfStrictMode(config, res)) return;

    let body: unknown;
    try {
      body = JSON.parse(req.body?.toString() || '{}');
    } catch {
      res.status(400).json({ error: 'Invalid JSON body' });
      return;
    }

    try {
      const discovery = await discoverAdminSshHostKeys(body, config, sshKeyTools);
      res.json(discovery);
    } catch (err) {
      res.status(400).json({ error: errorMessage(err) });
    }
  });

  router.post('/api/ssh-services', pinAuth, async (req: Request, res: Response) => {
    if (rejectIfStrictMode(config, res)) return;

    let body: unknown;
    try {
      body = JSON.parse(req.body?.toString() || '{}');
    } catch {
      res.status(400).json({ error: 'Invalid JSON body' });
      return;
    }

    const requestedName = body !== null && typeof body === 'object' && !Array.isArray(body)
      ? (body as Record<string, unknown>)['name']
      : undefined;
    if (typeof requestedName === 'string' && config.services[requestedName]) {
      res.status(409).json({ error: `Service "${requestedName}" already exists` });
      return;
    }

    try {
      const wizard = await buildAdminSshService(body, config, sshKeyTools);
      const name = requestedName as string;
      const errors = validateAdminService(name, wizard.service, config);
      if (errors.length > 0) {
        res.status(400).json({ error: errors.join('; ') });
        return;
      }

      const activeService = await serviceRuntime.apply(name, wizard.service);
      audit.saveServiceOverride(name, wizard.service);
      config.services[name] = activeService;
      console.log(`🔐 SSH host added via admin wizard: ${name} → ${wizard.service.upstream}`);
      res.json({ ok: true, service: name, key: wizard.keyInfo });
    } catch (err) {
      res.status(400).json({ error: errorMessage(err) });
    }
  });

  router.put('/api/ssh-services/:name', pinAuth, async (req: Request, res: Response) => {
    if (rejectIfStrictMode(config, res)) return;

    const name = req.params['name'] as string;
    const existing = config.services[name];
    if (!existing || existing.protocol !== 'ssh') {
      res.status(404).json({ error: `SSH service "${name}" not found` });
      return;
    }

    let body: unknown;
    try {
      const parsed = JSON.parse(req.body?.toString() || '{}');
      body = { ...parsed, name };
    } catch {
      res.status(400).json({ error: 'Invalid JSON body' });
      return;
    }

    try {
      const wizard = await buildAdminSshService(body, config, sshKeyTools, existing);
      const errors = validateAdminService(name, wizard.service, config);
      if (errors.length > 0) {
        res.status(400).json({ error: errors.join('; ') });
        return;
      }

      const activeService = await serviceRuntime.apply(name, wizard.service);
      audit.saveServiceOverride(name, wizard.service);
      config.services[name] = activeService;
      console.log(`✏️  SSH host updated via admin wizard: ${name}`);
      res.json({ ok: true, service: name, key: wizard.keyInfo });
    } catch (err) {
      res.status(400).json({ error: errorMessage(err) });
    }
  });

  router.post('/api/services', pinAuth, async (req: Request, res: Response) => {
    if (rejectIfStrictMode(config, res)) return;

    let body: { name?: string; config?: unknown };
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

    let service: ServiceConfig;
    try {
      service = hydrateAdminService(body.config);
    } catch (err) {
      res.status(400).json({ error: errorMessage(err) });
      return;
    }
    const errors = validateAdminService(body.name, service, config);
    if (errors.length > 0) {
      res.status(400).json({ error: errors.join('; ') });
      return;
    }

    try {
      const activeService = await serviceRuntime.apply(body.name, service);
      audit.saveServiceOverride(body.name, service);
      config.services[body.name] = activeService;
      console.log(`➕ Service added via admin: ${body.name} → ${service.upstream}`);
      res.json({ ok: true, service: body.name });
    } catch (err) {
      res.status(400).json({ error: errorMessage(err) });
    }
  });

  router.post('/api/services/:source/duplicate', pinAuth, async (req: Request, res: Response) => {
    if (rejectIfStrictMode(config, res)) return;

    const sourceName = req.params['source'] as string;
    const source = config.services[sourceName];
    if (!source) {
      res.status(404).json({ error: `Service "${sourceName}" not found` });
      return;
    }
    let body: { name?: string; config?: unknown };
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

    let duplicate: ServiceConfig;
    try {
      duplicate = hydrateAdminService(body.config, source);
    } catch (err) {
      res.status(400).json({ error: errorMessage(err) });
      return;
    }
    const errors = validateAdminService(body.name, duplicate, config);
    if (errors.length > 0) {
      res.status(400).json({ error: errors.join('; ') });
      return;
    }

    try {
      const activeService = await serviceRuntime.apply(body.name, duplicate);
      audit.saveServiceOverride(body.name, duplicate);
      config.services[body.name] = activeService;
      console.log(`📋 Service duplicated via admin: ${sourceName} → ${body.name}`);
      res.json({ ok: true, service: body.name, source: sourceName });
    } catch (err) {
      res.status(400).json({ error: errorMessage(err) });
    }
  });

  router.put('/api/services/:name', pinAuth, async (req: Request, res: Response) => {
    if (rejectIfStrictMode(config, res)) return;

    const name = req.params['name'] as string;
    let body: { config?: unknown; replace?: boolean };
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

    if (!body.config) {
      res.status(400).json({ error: 'Missing config' });
      return;
    }

    let updated: ServiceConfig;
    try {
      updated = body.replace
        ? hydrateAdminService(body.config, config.services[name])
        : hydrateAdminServicePatch(body.config, config.services[name]);
    } catch (err) {
      res.status(400).json({ error: errorMessage(err) });
      return;
    }
    const errors = validateAdminService(name, updated, config);
    if (errors.length > 0) {
      res.status(400).json({ error: errors.join('; ') });
      return;
    }

    try {
      const activeService = await serviceRuntime.apply(name, updated);
      audit.saveServiceOverride(name, updated);
      config.services[name] = activeService;
      console.log(`✏️  Service updated via admin: ${name}`);
      res.json({ ok: true, service: name });
    } catch (err) {
      res.status(400).json({ error: errorMessage(err) });
    }
  });

  router.delete('/api/services/:name', pinAuth, (req: Request, res: Response) => {
    if (rejectIfStrictMode(config, res)) return;

    const name = req.params['name'] as string;
    if (!config.services[name]) {
      res.status(404).json({ error: `Service "${name}" not found` });
      return;
    }

    audit.deleteServiceOverride(name);
    delete config.services[name];
    serviceRuntime.remove(name);
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
      health: telegram?.getHealth() ?? null,
    });
  });

  router.get('/api/telegram-health', pinAuth, (_req: Request, res: Response) => {
    res.json(telegram?.getHealth() ?? { enabled: false });
  });

  return router;
}

// ─── Helpers ──────────────────────────────────────────────────

function maskToken(token: string): string;
function maskToken(token: undefined): undefined;
function maskToken(token: string | undefined): string | undefined {
  if (token === undefined) return undefined;
  if (token.length <= 8) return '****';
  return token.substring(0, 4) + '****' + token.substring(token.length - 4);
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
