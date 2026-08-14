import crypto from 'crypto';
import {
  AuthPluginContext,
  AuthPluginRequestDescription,
  AuthPluginResponseHeadersContext,
  AuthPluginResponseHeadersResult,
  AuthPluginResult,
  IAuthPlugin,
} from './IAuthPlugin';

const CLIENT_COOKIE = 'clawguard_esxi_session';
const UPSTREAM_COOKIE = 'vmware_soap_session';
const MAX_INSPECT_BODY_BYTES = 2 * 1024 * 1024;
const DEFAULT_SESSION_TTL_SECONDS = 30 * 60;

interface EsxiSession {
  upstreamCookie: string;
  expiresAt: number;
}

interface EsxiRequestState {
  action: string;
  kind: 'login' | 'logout' | 'request';
  clientSession?: string;
}

const READ_ACTIONS = new Set([
  'CheckCompatibility_Task',
  'CheckCustomizationSpec',
  'ContinueRetrievePropertiesEx',
  'CreateContainerView',
  'CreateListView',
  'CreatePropertyCollector',
  'CurrentTime',
  'DestroyPropertyCollector',
  'DestroyView',
  'DoesCustomizationSpecExist',
  'FindAllByDnsName',
  'FindAllByIp',
  'FindByDatastorePath',
  'FindByDnsName',
  'FindByInventoryPath',
  'FindByIp',
  'FindByUuid',
  'HasPrivilegeOnEntity',
  'HasPrivilegeOnEntities',
  'ListViewFromView',
  'QueryAvailableDisksForVmfs',
  'QueryChangedDiskAreas',
  'QueryConfigOption',
  'QueryConfigOptionDescriptor',
  'QueryDatastorePerformanceSummary',
  'QueryMemoryOverhead',
  'QueryNetworkHint',
  'QueryOptions',
  'QueryUnownedFiles',
  'RetrieveOptions',
  'RetrieveProperties',
  'RetrievePropertiesEx',
  'RetrieveServiceContent',
  'SearchDatastore',
  'SearchDatastoreSubFolders',
  'SessionIsActive',
  'WaitForUpdates',
  'WaitForUpdatesEx',
]);

const SESSION_ACTIONS = new Set(['Login', 'Logout']);
const BLOCKED_SESSION_EXPORT_ACTIONS = new Set([
  'AcquireCloneTicket',
  'AcquireGenericServiceTicket',
  'AcquireLocalTicket',
  'CloneSession',
  'ImpersonateUser',
  'LoginBySSPI',
  'LoginByToken',
]);
const DESTRUCTIVE_ACTION = /^(?:Destroy|Remove|Delete|PowerOff|Reset|Shutdown|Terminate|Unregister)/i;

const SAFE_PARAMETER_TAGS: Array<[string, string]> = [
  ['name', 'Name'],
  ['description', 'Description'],
  ['newName', 'New name'],
  ['memory', 'Capture memory'],
  ['quiesce', 'Quiesce filesystem'],
  ['removeChildren', 'Remove children'],
  ['consolidate', 'Consolidate disks'],
  ['force', 'Force'],
  ['numCPUs', 'vCPU'],
  ['memoryMB', 'Memory MB'],
  ['guestId', 'Guest OS'],
  ['powerOn', 'Power on'],
  ['template', 'VM template'],
  ['state', 'Requested state'],
  ['priority', 'Migration priority'],
  ['diskMoveType', 'Disk move type'],
  ['transform', 'Disk transform'],
  ['thinProvisioned', 'Thin provisioned'],
  ['eagerlyScrub', 'Eagerly scrub'],
  ['pathSet', 'Requested property'],
  ['maxObjects', 'Maximum objects'],
];

function safeText(value: string, max = 240): string {
  return decodeXml(value).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

function decodeXml(value: string): string {
  return value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function escapeXml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function extractSoapAction(body: Buffer): { action: string; xml: string } {
  if (body.length === 0) return { action: 'EmptyRequest', xml: '' };
  if (body.length > MAX_INSPECT_BODY_BYTES) {
    return { action: 'OversizedSoapRequest', xml: '' };
  }
  const xml = body.toString('utf8');
  const bodyMatch = xml.match(/<(?:[\w.-]+:)?Body\b[^>]*>([\s\S]*?)<\/(?:[\w.-]+:)?Body\s*>/i);
  if (!bodyMatch) return { action: 'UnknownSoapRequest', xml };
  const operation = bodyMatch[1].match(/<(?:[\w.-]+:)?([A-Za-z_][\w.-]*)\b/);
  return { action: operation?.[1] || 'UnknownSoapRequest', xml };
}

function extractElements(xml: string, localName: string): string[] {
  if (!xml) return [];
  const escaped = localName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(
    `<(?:[\\w.-]+:)?${escaped}\\b[^>]*>([^<]{0,1000})<\\/(?:[\\w.-]+:)?${escaped}\\s*>`,
    'gi'
  );
  return [...xml.matchAll(pattern)].map((match) => safeText(match[1] || '')).filter(Boolean);
}

function extractManagedObjects(xml: string): Array<{ type: string; id: string }> {
  if (!xml) return [];
  const results: Array<{ type: string; id: string }> = [];
  const objectTag = '(?:_this|vm|host|datastore|snapshot|entity|folder|pool|resourcePool|network|computeResource|cluster)';
  const pattern = new RegExp(
    `<(?:[\\w.-]+:)?${objectTag}\\b([^>]*)>([^<]{1,240})<\\/(?:[\\w.-]+:)?${objectTag}\\s*>`,
    'gi'
  );
  for (const match of xml.matchAll(pattern)) {
    const attrs = match[1] || '';
    const type = attrs.match(/\btype\s*=\s*["']([^"']+)["']/i)?.[1] || 'ManagedObject';
    const id = safeText(match[2] || '', 160);
    if (!id) continue;
    const item = { type: safeText(type, 80), id };
    if (!results.some((existing) => existing.type === item.type && existing.id === item.id)) {
      results.push(item);
    }
  }
  return results.slice(0, 8);
}

function riskFor(action: string): AuthPluginRequestDescription['risk'] {
  if (BLOCKED_SESSION_EXPORT_ACTIONS.has(action)) return 'destructive';
  if (SESSION_ACTIONS.has(action)) return 'session';
  if (READ_ACTIONS.has(action)) return 'read';
  if (action === 'UnknownSoapRequest' || action === 'OversizedSoapRequest' || action === 'EmptyRequest') {
    return 'unknown';
  }
  return DESTRUCTIVE_ACTION.test(action) ? 'destructive' : 'write';
}

function friendlyAction(action: string): string {
  const known: Record<string, string> = {
    Login: 'Open VMware API session',
    Logout: 'Close VMware API session',
    PowerOnVM_Task: 'Power on virtual machine',
    PowerOffVM_Task: 'Power off virtual machine',
    ResetVM_Task: 'Hard reset virtual machine',
    SuspendVM_Task: 'Suspend virtual machine',
    ShutdownGuest: 'Graceful guest shutdown',
    RebootGuest: 'Graceful guest reboot',
    CreateSnapshot_Task: 'Create VM snapshot',
    RemoveSnapshot_Task: 'Remove VM snapshot',
    RemoveAllSnapshots_Task: 'Remove all VM snapshots',
    RevertToSnapshot_Task: 'Revert VM to snapshot',
    ReconfigVM_Task: 'Reconfigure virtual machine',
    CloneVM_Task: 'Clone virtual machine',
    CreateVM_Task: 'Create virtual machine',
    RegisterVM_Task: 'Register virtual machine',
    UnregisterVM: 'Unregister virtual machine',
    Rename_Task: 'Rename managed object',
    MigrateVM_Task: 'Migrate virtual machine',
    RelocateVM_Task: 'Relocate virtual machine',
    ConsolidateVMDisks_Task: 'Consolidate virtual machine disks',
    UpgradeTools_Task: 'Upgrade VMware Tools',
    EnterMaintenanceMode_Task: 'Enter host maintenance mode',
    ExitMaintenanceMode_Task: 'Exit host maintenance mode',
    DeleteDatastoreFile_Task: 'Delete datastore file',
    MoveDatastoreFile_Task: 'Move datastore file',
    CopyDatastoreFile_Task: 'Copy datastore file',
    Destroy_Task: 'Destroy managed object',
    RetrievePropertiesEx: 'Read VMware inventory properties',
    ContinueRetrievePropertiesEx: 'Continue VMware inventory read',
    RetrieveServiceContent: 'Read VMware service capabilities',
  };
  return known[action] || action;
}

function approvalDescription(method: string, path: string, body: Buffer): AuthPluginRequestDescription {
  if (method.toUpperCase() === 'GET' && path.endsWith('/vimService.wsdl')) {
    return {
      approvalPath: '/sdk/read/vimService.wsdl',
      action: 'Read VMware API schema',
      risk: 'read',
      details: [{ label: 'Endpoint', value: path }],
    };
  }

  const { action, xml } = extractSoapAction(body);
  const risk = riskFor(action);
  const objects = extractManagedObjects(xml);
  const target = objects.map((item) => `${item.type} ${item.id}`).join(', ') || undefined;
  const scopeParts = objects.slice(0, 3).map((item) => `${item.type}-${item.id}`);
  const approvalPath = [
    '/sdk',
    risk || 'unknown',
    action.replace(/[^A-Za-z0-9_.-]/g, '_'),
    ...scopeParts.map((part) => part.replace(/[^A-Za-z0-9_.-]/g, '_')),
  ].join('/');

  const details: Array<{ label: string; value: string }> = [
    { label: 'SOAP method', value: action },
    { label: 'Endpoint', value: path },
    { label: 'Payload', value: `${body.length} bytes` },
  ];
  for (const [tag, label] of SAFE_PARAMETER_TAGS) {
    for (const value of extractElements(xml, tag).slice(0, 3)) {
      details.push({ label, value });
    }
  }

  return {
    approvalPath,
    action: friendlyAction(action),
    risk,
    target,
    details: details.slice(0, 12),
    oneTime: risk === 'write' || risk === 'destructive' || risk === 'unknown',
  };
}

function replaceXmlElement(xml: string, localName: string, value: string): string {
  const escaped = localName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(
    `(<(?:[\\w.-]+:)?${escaped}\\b[^>]*>)[\\s\\S]*?(<\\/(?:[\\w.-]+:)?${escaped}\\s*>)`,
    'i'
  );
  if (!pattern.test(xml)) throw new Error(`VMware Login request is missing ${localName}`);
  return xml.replace(pattern, `$1${escapeXml(value)}$2`);
}

function parseCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator <= 0) continue;
    const key = part.slice(0, separator).trim();
    let value = part.slice(separator + 1).trim();
    if (key !== name) continue;
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    return value || undefined;
  }
  return undefined;
}

function removeSessionCookies(header: string | undefined): string[] {
  if (!header) return [];
  return header.split(';').map((part) => part.trim()).filter((part) => {
    const key = part.split('=', 1)[0]?.trim();
    return key !== CLIENT_COOKIE && key !== UPSTREAM_COOKIE;
  });
}

function upstreamCookieFromSetCookie(value: string | string[] | undefined): string | undefined {
  const values = Array.isArray(value) ? value : value ? [value] : [];
  for (const item of values) {
    const pair = item.split(';', 1)[0]?.trim();
    if (pair?.startsWith(`${UPSTREAM_COOKIE}=`)) return pair;
  }
  return undefined;
}

function syntheticCookie(token: string): string {
  return `${CLIENT_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

class VMwareEsxiPlugin implements IAuthPlugin {
  readonly name = 'vmware-esxi';
  private username = '';
  private password = '';
  private sessionTtlMs = DEFAULT_SESSION_TTL_SECONDS * 1000;
  private sessions = new Map<string, EsxiSession>();

  async init(_dataDir: string, config: Record<string, unknown>): Promise<void> {
    if (typeof config['username'] !== 'string' || !config['username']) {
      throw new Error('vmware-esxi pluginConfig.username is required');
    }
    if (typeof config['password'] !== 'string' || !config['password']) {
      throw new Error('vmware-esxi pluginConfig.password is required');
    }
    const ttlSeconds = config['sessionTtlSeconds'] === undefined
      ? DEFAULT_SESSION_TTL_SECONDS : Number(config['sessionTtlSeconds']);
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 86400) {
      throw new Error('vmware-esxi sessionTtlSeconds must be an integer between 60 and 86400');
    }
    this.username = config['username'];
    this.password = config['password'];
    this.sessionTtlMs = ttlSeconds * 1000;
  }

  async describeRequest(ctx: AuthPluginContext): Promise<AuthPluginRequestDescription> {
    return approvalDescription(ctx.method, ctx.path, ctx.body);
  }

  private pruneSessions(): void {
    const now = Date.now();
    for (const [token, session] of this.sessions) {
      if (session.expiresAt <= now) this.sessions.delete(token);
    }
  }

  async rewriteRequest(ctx: AuthPluginContext): Promise<AuthPluginResult> {
    this.pruneSessions();
    const { action } = extractSoapAction(ctx.body);
    if (BLOCKED_SESSION_EXPORT_ACTIONS.has(action)) {
      throw new Error(`VMware session-export operation ${action} is blocked by the vmware-esxi plugin`);
    }
    const headers = { ...ctx.headers };
    const cookieHeader = headers['cookie'] || headers['Cookie'];
    delete headers['Cookie'];
    const clientSession = parseCookie(cookieHeader, CLIENT_COOKIE);
    const remainingCookies = removeSessionCookies(cookieHeader);

    if (clientSession) {
      const session = this.sessions.get(clientSession);
      if (!session) throw new Error('Unknown or expired ClawGuard VMware session');
      session.expiresAt = Date.now() + this.sessionTtlMs;
      remainingCookies.push(session.upstreamCookie);
    }
    if (remainingCookies.length > 0) headers['cookie'] = remainingCookies.join('; ');
    else delete headers['cookie'];

    let body = ctx.body;
    if (action === 'Login') {
      let xml = ctx.body.toString('utf8');
      xml = replaceXmlElement(xml, 'userName', this.username);
      xml = replaceXmlElement(xml, 'password', this.password);
      body = Buffer.from(xml, 'utf8');
      delete headers['cookie'];
    }

    headers['content-length'] = String(body.length);
    const kind: EsxiRequestState['kind'] = action === 'Login'
      ? 'login' : action === 'Logout' ? 'logout' : 'request';
    return {
      headers,
      body,
      requestState: { action, kind, clientSession } satisfies EsxiRequestState,
      auditRequestBody: `[VMware SOAP ${action}: payload redacted by vmware-esxi plugin]`,
    };
  }

  async rewriteResponseHeaders(
    ctx: AuthPluginResponseHeadersContext
  ): Promise<AuthPluginResponseHeadersResult> {
    const state = ctx.requestState as EsxiRequestState | undefined;
    const headers = { ...ctx.headers };
    const upstreamCookie = upstreamCookieFromSetCookie(headers['set-cookie']);
    delete headers['set-cookie'];

    if (state?.kind === 'login') {
      if (ctx.statusCode < 200 || ctx.statusCode >= 300 || !upstreamCookie) {
        throw new Error('VMware Login did not return a usable upstream session cookie');
      }
      const token = crypto.randomBytes(32).toString('base64url');
      this.sessions.set(token, {
        upstreamCookie,
        expiresAt: Date.now() + this.sessionTtlMs,
      });
      headers['set-cookie'] = [syntheticCookie(token)];
    } else if (state?.kind === 'logout') {
      if (state.clientSession) this.sessions.delete(state.clientSession);
      headers['set-cookie'] = [
        `${CLIENT_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
      ];
    } else if (state?.clientSession && upstreamCookie) {
      const session = this.sessions.get(state.clientSession);
      if (session) {
        session.upstreamCookie = upstreamCookie;
        session.expiresAt = Date.now() + this.sessionTtlMs;
      }
      headers['set-cookie'] = [syntheticCookie(state.clientSession)];
    }

    return {
      headers,
      auditResponseBody: `[VMware SOAP ${state?.action || 'response'}: payload redacted by vmware-esxi plugin]`,
    };
  }
}

export function createPlugin(): IAuthPlugin {
  return new VMwareEsxiPlugin();
}

export const __test = {
  approvalDescription,
  extractManagedObjects,
  extractSoapAction,
  extractElements,
  CLIENT_COOKIE,
  UPSTREAM_COOKIE,
};
