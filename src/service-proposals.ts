import { randomUUID } from 'crypto';
import { Router, Request, Response } from 'express';
import { AuditLogger } from './audit';
import { AdminServiceRuntime, validateAdminService } from './admin-service';
import { extractRequestMeta } from './request-meta';
import { isAllowedUpstream } from './security';
import { parseSecretRef } from './secrets/provider';
import { Config, ServiceConfig, ServiceProposal } from './types';

type Obj = Record<string, unknown>;
const CREDENTIAL = 'credential';
const INPUT = 'input';
const MAX_PROPOSAL_BYTES = 64 * 1024;
const HOST_KEY_PROBE = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC';
const SERVICE_KEYS = new Set(['protocol', 'upstream', 'auth', 'policy', 'hostnames', 'http', 'ssh', 'ftp']);
const AUTH_KEYS = new Set(['type', 'token', 'dummyToken', 'headerName', 'paramName', 'username', 'password',
  'tokenPath', 'clientId', 'clientSecret', 'authorizeUrl', 'tokenUrl', 'redirectUri', 'scopes', 'usePkce',
  'fields', 'pluginPath', 'pluginConfig']);
const SECRET_KEYS = new Set(['token', 'password', 'clientSecret', 'clientId']);
const PLUGIN_PUBLIC_KEYS: Record<string, Set<string>> = {
  'ssh-agent-key': new Set(['username']),
  'ftp-password': new Set(['username']),
  'vmware-esxi': new Set(['username']),
  'aws-sigv4': new Set(['region', 'service', 'fixedDate', 'assumeRole']),
  'oauth2-authcode': new Set(['tokenUrl', 'authorizeUrl', 'redirectUri', 'scopes', 'usePkce']),
  'echo': new Set(),
};
const applyingServices = new WeakMap<Config, Set<string>>();

export function isProposalApplying(config: Config, name: string): boolean {
  return applyingServices.get(config)?.has(name) ?? false;
}

function object(value: unknown): value is Obj {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function marker(value: unknown, kind: string): boolean {
  return object(value) && Object.keys(value).length === 1 && value['$clawguard'] === kind;
}

function pointerPart(key: string): string { return key.replace(/~/g, '~0').replace(/\//g, '~1'); }

function walk(value: unknown, fn: (value: unknown, path: string) => void, path = '', depth = 0): void {
  if (depth > 20) throw new Error('Configuration nesting exceeds 20 levels');
  if ((object(value) && !('$clawguard' in value)) || Array.isArray(value)) {
    for (const [key, item] of Object.entries(value as Obj)) {
      if (['__proto__', 'constructor', 'prototype'].includes(key)) throw new Error('Unsafe configuration key');
      walk(item, fn, `${path}/${pointerPart(key)}`, depth + 1);
    }
  } else fn(value, path);
}

function get(value: unknown, pointer: string): unknown {
  let current = value;
  for (const key of pointer.slice(1).split('/').map((part) => part.replace(/~1/g, '/').replace(/~0/g, '~'))) {
    if (!object(current) && !Array.isArray(current)) return undefined;
    if (!Object.hasOwn(current, key)) return undefined;
    current = (current as Obj)[key];
  }
  return current;
}

function set(value: Obj, pointer: string, replacement: unknown): void {
  const keys = pointer.slice(1).split('/').map((part) => part.replace(/~1/g, '/').replace(/~0/g, '~'));
  let target = value;
  for (const key of keys.slice(0, -1)) target = target[key] as Obj;
  target[keys[keys.length - 1]] = replacement;
}

function isCredentialPath(doc: Obj, path: string): boolean {
  if (!object(doc.auth)) return false;
  if (SECRET_KEYS.has(path.slice('/auth/'.length)) && path.startsWith('/auth/')) return true;
  if (path.startsWith('/auth/fields/')) return true;
  if (path.startsWith('/auth/pluginConfig/')) {
    const relative = path.slice('/auth/pluginConfig/'.length);
    const publicKeys = PLUGIN_PUBLIC_KEYS[String(doc.auth.pluginPath)] ?? new Set(['username']);
    // Only explicitly known metadata can be supplied by an agent. Arbitrary
    // plugin configuration leaves are credentials until the owner supplies them.
    return !publicKeys.has(relative.split('/')[0]);
  }
  return false;
}

export function proposalRequirements(doc: Obj): Array<{ path: string; kind: 'credential' | 'input' }> {
  const requirements: Array<{ path: string; kind: 'credential' | 'input' }> = [];
  walk(doc, (value, path) => {
    if (marker(value, CREDENTIAL)) requirements.push({ path, kind: 'credential' });
    if (marker(value, INPUT)) requirements.push({ path, kind: 'input' });
  });
  return requirements;
}

export function listCredentialSources(config: Config): Array<{ service: string; path: string; label: string }> {
  const sources: Array<{ service: string; path: string; label: string }> = [];
  for (const [name, service] of Object.entries(config.services)) {
    const doc = service as unknown as Obj;
    walk(doc, (value, path) => {
      if (typeof value === 'string' && value.length > 0 && isCredentialPath(doc, path)) {
        sources.push({ service: name, path, label: `${name} — ${path}` });
      }
    });
  }
  return sources;
}

export function proposalUpstreams(doc: Obj, config: Config): string[] {
  const host = new URL(String(doc.upstream)).hostname.replace(/^\[|\]$/g, '');
  const hosts = [host, ...(Array.isArray(doc.hostnames) ? doc.hostnames as string[] : [])];
  return [...new Set(hosts)].filter((hostname) => !isAllowedUpstream(hostname, config.security.allowedUpstreams));
}

function withUpstreams(config: Config, upstreams: string[]): Config {
  return { ...config, security: { ...config.security, allowedUpstreams: [...config.security.allowedUpstreams, ...upstreams] } };
}

function normalizeProposal(name: unknown, input: unknown, config: Config): Obj {
  if (typeof name !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(name)
    || name.startsWith('__') || ['constructor', 'prototype'].includes(name)) throw new Error('Invalid service name');
  if (!object(input) || !object(input.auth)) throw new Error('config and config.auth must be objects');
  const doc = structuredClone(input);
  for (const key of Object.keys(doc)) if (!SERVICE_KEYS.has(key)) throw new Error(`Unsupported service field: ${key}`);
  const auth = doc.auth as Obj;
  for (const key of Object.keys(auth)) if (!AUTH_KEYS.has(key)) throw new Error(`Unsupported auth field: ${key}`);
  doc.protocol ??= 'http';
  for (const [section, allowed] of Object.entries({
    http: ['allowedMethods', 'allowPrivateTarget', 'noCheckCertificate'],
    ssh: ['knownHostKey', 'allowPrivateTarget'],
    ftp: ['allowPrivateTarget', 'tlsMode', 'root', 'noCheckCertificate'],
    policy: ['default', 'rules'],
  })) {
    if (doc[section] !== undefined && (!object(doc[section])
      || Object.keys(doc[section]).some((key) => !allowed.includes(key)))) {
      throw new Error(`Invalid or unsupported ${section} configuration field`);
    }
  }
  if (object(doc.policy) && Array.isArray(doc.policy.rules)) {
    for (const rule of doc.policy.rules) {
      if (!object(rule) || Object.keys(rule).some((key) => !['match', 'action'].includes(key))
        || !object(rule.match) || Object.keys(rule.match).some((key) => !['method', 'path'].includes(key))) {
        throw new Error('Policy rules support only match.method, match.path, and action');
      }
    }
  }
  const url = new URL(String(doc.upstream));
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('Proposal upstream must not contain credentials, query parameters, or fragments');
  }
  if (doc.hostnames !== undefined && (!Array.isArray(doc.hostnames) || doc.hostnames.some((host) => {
    if (typeof host !== 'string' || !/^[a-z0-9.-]+$/i.test(host)) return true;
    try { return new URL(`https://${host}`).hostname !== host; } catch { return true; }
  }))) throw new Error('hostnames must contain exact DNS names');
  if (auth.type === 'plugin') {
    const builtin = doc.protocol === 'ssh' ? ['ssh-agent-key']
      : doc.protocol === 'ftp' || doc.protocol === 'ftps' ? ['ftp-password']
        : ['echo', 'oauth2-authcode', 'aws-sigv4', 'vmware-esxi'];
    const trusted = Object.values(config.services).some((service) =>
      (service.protocol ?? 'http') === doc.protocol && service.auth.pluginPath === auth.pluginPath);
    if (!builtin.includes(String(auth.pluginPath)) && !trusted) {
      throw new Error('Agent proposals may only use built-in plugins or a plugin already configured by the owner');
    }
    const required: Record<string, string[]> = {
      'ssh-agent-key': ['username', 'privateKey'], 'ftp-password': ['username', 'password'],
      'vmware-esxi': ['username', 'password'], 'aws-sigv4': ['accessKeyId', 'secretAccessKey', 'region', 'service'],
    };
    for (const key of required[String(auth.pluginPath)] ?? []) {
      const value = object(auth.pluginConfig) ? auth.pluginConfig[key] : undefined;
      if (!marker(value, CREDENTIAL) && (typeof value !== 'string' || !value.trim())) {
        throw new Error(`auth.pluginConfig.${key} is required`);
      }
    }
  }
  walk(doc, (value, path) => {
    if (isCredentialPath(doc, path) && value !== '' && !marker(value, CREDENTIAL)) {
      throw new Error(`Use {"$clawguard":"credential"} at ${path}; credentials cannot be submitted by agents`);
    }
    if (object(value) && '$clawguard' in value) {
      const validCredential = marker(value, CREDENTIAL) && (isCredentialPath(doc, path)
        || path === '/auth/username' || path === '/auth/pluginConfig/username');
      const validInput = marker(value, INPUT) && path === '/ssh/knownHostKey';
      if (!validCredential && !validInput) throw new Error(`Invalid placeholder at ${path}`);
    }
    if (typeof value === 'string' && (parseSecretRef(value) || value.includes('${'))) {
      throw new Error('Agents cannot submit secret-provider references; select a managed credential in the dashboard');
    }
  });
  const probe = structuredClone(doc);
  for (const requirement of proposalRequirements(doc)) {
    set(probe, requirement.path, requirement.kind === 'input' ? HOST_KEY_PROBE : 'clawguard-validation-placeholder');
  }
  const errors = validateAdminService(name, probe as unknown as ServiceConfig, withUpstreams(config, proposalUpstreams(doc, config)));
  if (errors.length) throw new Error(errors.join('; '));
  return doc;
}

function parseBody(req: Request): Obj {
  const raw = req.body?.toString() || '{}';
  if (Buffer.byteLength(raw) > MAX_PROPOSAL_BYTES) throw new Error('Proposal payload exceeds 64 KiB');
  const body: unknown = JSON.parse(raw);
  if (!object(body)) throw new Error('Body must be a JSON object');
  return body;
}

function publicStatus(proposal: ServiceProposal): Obj {
  return { id: proposal.id, name: proposal.name, status: proposal.status,
    createdAt: proposal.createdAt, decidedAt: proposal.decidedAt };
}

function failure(res: Response, error: unknown): void {
  res.status(400).json({ error: error instanceof Error ? error.message : 'Invalid proposal' });
}

export function createServiceProposalRouter(config: Config, audit: AuditLogger): Router {
  const router = Router();
  router.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    if (!config.server.agentKey || req.headers['x-clawguard-key'] !== config.server.agentKey) {
      res.status(401).json({ error: 'Invalid or missing X-ClawGuard-Key' }); return;
    }
    if (!config.admin.enabled) { res.status(403).json({ error: 'Service proposals require the admin dashboard' }); return; }
    next();
  });
  router.post('/services', (req, res) => {
    try {
      const body = parseBody(req);
      if (Object.keys(body).some((key) => key !== 'name' && key !== 'config')) throw new Error('Only name and config are accepted');
      const doc = normalizeProposal(body.name, body.config, config);
      const name = body.name as string;
      if (Object.hasOwn(config.services, name)) { res.status(409).json({ error: 'Service already exists' }); return; }
      const existing = audit.getPendingServiceProposal(name);
      if (existing) {
        if (JSON.stringify(existing.config) === JSON.stringify(doc)) {
          res.status(200).json({ ...publicStatus(existing), activated: false }); return;
        }
        res.status(409).json({ error: 'A different proposal for this service is already pending' }); return;
      }
      const proposal: ServiceProposal = {
        id: randomUUID(), name, config: doc, status: 'pending', createdAt: new Date().toISOString(),
        decidedAt: null, clientIp: req.ip || req.socket.remoteAddress || 'unknown',
      };
      // RequestMeta uses shorter keys; persist the explicit audit field names.
      const meta = extractRequestMeta(req.headers);
      proposal.requestUser = meta.user;
      proposal.requestReason = meta.reason;
      audit.saveServiceProposal(proposal);
      res.status(202).json({ ...publicStatus(proposal), activated: false, validation: 'configuration',
        requirements: proposalRequirements(doc), requiredUpstreams: proposalUpstreams(doc, config) });
    } catch (error) { failure(res, error); }
  });
  router.get('/services/:id', (req, res) => {
    const proposal = audit.getServiceProposal(req.params['id'] as string);
    if (!proposal) { res.status(404).json({ error: 'Proposal not found' }); return; }
    res.json(publicStatus(proposal));
  });
  return router;
}

export function restoreProposalUpstreams(config: Config, audit: AuditLogger): void {
  if (!config.admin.strictMode) {
    config.security.allowedUpstreams = [...new Set([...config.security.allowedUpstreams, ...audit.getAdminUpstreams()])];
  }
  audit.recoverServiceProposals();
}

export function createAdminProposalRouter(config: Config, audit: AuditLogger, runtime: AdminServiceRuntime): Router {
  const router = Router();
  router.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
  router.get('/credential-sources', (_req, res) => res.json(listCredentialSources(config)));
  router.get('/service-proposals', (_req, res) => {
    res.json(audit.getServiceProposals().map((proposal) => ({ ...proposal,
      requirements: proposalRequirements(proposal.config), requiredUpstreams: proposalUpstreams(proposal.config, config) })));
  });
  router.post('/service-proposals/:id/reject', (req, res) => {
    const id = req.params['id'] as string;
    if (!audit.getServiceProposal(id)) { res.status(404).json({ error: 'Proposal not found' }); return; }
    if (!audit.rejectServiceProposal(id)) { res.status(409).json({ error: 'Proposal is no longer pending' }); return; }
    res.json({ ok: true });
  });
  router.post('/service-proposals/:id/approve', async (req, res) => {
    if (config.admin.strictMode) { res.status(403).json({ error: 'Approval is disabled by admin.strictMode' }); return; }
    const id = req.params['id'] as string;
    const proposal = audit.getServiceProposal(id);
    if (!proposal) { res.status(404).json({ error: 'Proposal not found' }); return; }
    if (Object.hasOwn(config.services, proposal.name)) { res.status(409).json({ error: 'Service already exists' }); return; }
    if (!audit.claimServiceProposal(id)) { res.status(409).json({ error: 'Proposal is no longer pending' }); return; }
    const applying = applyingServices.get(config) ?? new Set<string>();
    applyingServices.set(config, applying);
    applying.add(proposal.name);
    let applied = false;
    let sensitiveOperation = false;
    try {
      const body = parseBody(req);
      const doc = normalizeProposal(proposal.name, proposal.config, config);
      const upstreams = proposalUpstreams(doc, config);
      if (upstreams.length && body.allowUpstreams !== true) throw new Error('Explicit approval of the new upstream domains is required');
      const bindings = object(body.credentials) ? body.credentials : {};
      const inputs = object(body.inputs) ? body.inputs : {};
      const sources = listCredentialSources(config);
      for (const requirement of proposalRequirements(doc)) {
        let value: unknown;
        if (requirement.kind === 'input') value = inputs[requirement.path];
        else {
          const binding = bindings[requirement.path];
          if (!object(binding)) throw new Error(`Supply a credential for ${requirement.path}`);
          if (Object.hasOwn(binding, 'value')) value = binding.value;
          else {
            const source = sources.find((item) => item.service === binding.service && item.path === binding.path);
            if (!source || source.path.split('/').pop() !== requirement.path.split('/').pop()) {
              throw new Error(`Select a compatible managed credential for ${requirement.path}`);
            }
            value = get(config.services[source.service], source.path);
          }
        }
        if (typeof value !== 'string' || !value.trim()) throw new Error(`Required value missing for ${requirement.path}`);
        set(doc, requirement.path, value);
      }
      const service = doc as unknown as ServiceConfig;
      const errors = validateAdminService(proposal.name, service, withUpstreams(config, upstreams));
      if (errors.length) throw new Error(errors.join('; '));
      // Temporary runtime config: live allowlists and services are unchanged
      // until plugin initialization and the SQLite transaction both succeed.
      sensitiveOperation = true;
      const active = await runtime.apply(proposal.name, service, withUpstreams(config, upstreams));
      applied = true;
      if (Object.hasOwn(config.services, proposal.name)) throw new Error('Service was added while reviewing this proposal');
      audit.approveServiceProposal(id, proposal.name, service, upstreams);
      config.security.allowedUpstreams = [...new Set([...config.security.allowedUpstreams, ...upstreams])];
      config.services[proposal.name] = active;
      res.json({ ok: true, service: proposal.name });
    } catch (error) {
      if (sensitiveOperation) runtime.remove(proposal.name);
      audit.releaseServiceProposal(id);
      // Plugin/provider errors can contain credentials. Never echo those
      // errors to either the browser or the agent-facing status endpoint.
      res.status(400).json({ error: !sensitiveOperation && error instanceof Error ? error.message
        : applied ? 'Could not persist the service; the proposal remains pending'
          : 'Could not initialize the service. Check credentials, host identity, and protocol configuration; the proposal remains pending.' });
    } finally {
      applying.delete(proposal.name);
    }
  });
  return router;
}
