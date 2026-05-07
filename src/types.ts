// ─── Policy & Service ────────────────────────────────────────

export interface PolicyRule {
  match: {
    method?: string;
    path?: string;
  };
  action: 'auto_approve' | 'require_approval';
}

export interface ServiceConfig {
  upstream: string;
  auth: {
    type: 'bearer' | 'header' | 'query' | 'basic' | 'url' | 'oauth2_client_credentials' | 'oauth2_authorization_code' | 'body_json' | 'plugin';
    token: string;
    dummyToken?: string;   // if set, client must send this dummy value; clawguard validates it before injecting the real token
    headerName?: string;   // for type: 'header'
    paramName?: string;    // for type: 'query' (e.g. 'appid' for OpenWeatherMap)
    username?: string;     // for type: 'basic'
    password?: string;     // for type: 'basic'
    // for type: 'oauth2_client_credentials'
    tokenPath?: string;    // e.g. '/token' — the path where client sends credentials
    clientId?: string;
    clientSecret?: string;
    // for type: 'oauth2_authorization_code'
    authorizeUrl?: string;   // e.g. 'https://login.microsoftonline.com/.../authorize'
    tokenUrl?: string;       // e.g. 'https://login.microsoftonline.com/.../token'
    redirectUri?: string;    // e.g. 'http://localhost:9999/callback'
    scopes?: string[];       // e.g. ['openid', 'profile', 'User.Read']
    usePkce?: boolean;       // enable PKCE for public clients (no clientSecret)
    // for type: 'body_json' — inject/overwrite fields in the JSON request body
    fields?: Record<string, string>;
    // for type: 'plugin' — delegate auth to a custom plugin
    pluginPath?: string;   // built-in name (e.g. 'echo') or path to plugin module
    pluginConfig?: Record<string, unknown>; // arbitrary config passed to the plugin
  };
  policy: {
    default: 'auto_approve' | 'require_approval';
    rules?: PolicyRule[];
  };
  hostnames?: string[]; // for host-based routing (forward proxy / /etc/hosts mode)
}

// ─── Security ────────────────────────────────────────────────

export interface SecurityConfig {
  allowedUpstreams: string[];
  blockPrivateIPs: boolean;
  followRedirects: boolean;
  maxPayloadLogSize: number; // bytes, 0 = no limit
}

// ─── Admin ───────────────────────────────────────────────────

export interface AdminConfig {
  enabled: boolean;
  pin: string;
  allowedIPs: string[];
}

// ─── Telegram ────────────────────────────────────────────────

export interface TelegramConfig {
  botToken: string;
  chatId: string;
  pairing: {
    enabled: boolean;
    secret: string; // user must send /pair <secret> to the bot
  };
}

// ─── Web Push (browser push notifications, e.g. macOS native banners) ──

export interface WebPushConfig {
  enabled: boolean;
  subject: string;             // mailto: or https URL — required by VAPID spec
  keysPath?: string;           // where to persist auto-generated VAPID keys
  vapidPublicKey?: string;     // optional: provide explicitly to skip auto-generation
  vapidPrivateKey?: string;
  ttl?: number;                // seconds the push service holds the message; default 120
  urgency?: 'very-low' | 'low' | 'normal' | 'high'; // default 'high'
  requireInteraction?: boolean; // notification stays visible until clicked; default true
}

export interface WebPushSubscriptionRecord {
  id: number;
  endpoint: string;
  p256dh: string;
  auth: string;
  userAgent: string | null;
  createdAt: string;
}

// ─── Audit ───────────────────────────────────────────────────

export interface AuditConfig {
  type: 'sqlite';
  path: string;
  logPayload: boolean;
}

// ─── Secrets ─────────────────────────────────────────────────

export interface VaultAuthConfig {
  method: 'token' | 'kubernetes';
  token?: string;           // for method: 'token'
  role?: string;            // for method: 'kubernetes'
  mountPath?: string;       // default: 'auth/kubernetes'
}

export interface VaultSecretsConfig {
  address: string;          // e.g. https://vault.example.com
  namespace?: string;       // Vault Enterprise namespace
  auth: VaultAuthConfig;
  tlsSkipVerify?: boolean;  // default: false
  cacheTTL?: number;        // seconds, default: 300
}

export interface SecretsConfig {
  vault?: VaultSecretsConfig;
  // future: aws?, gcp?, azure?
}

// ─── Proxy (HTTPS_PROXY MITM mode) ─────────────────────────

export interface ProxyConfig {
  enabled: boolean;
  caDir: string; // directory for CA cert/key
  discovery: boolean; // enable discovery flow for unknown hosts
  // behavior for unknown hosts in discovery mode:
  // - block (default): deny unknown services and only log suggestions
  // - silent_allow: transparently forward unknown services while tracking
  discoveryPolicy: 'block' | 'silent_allow';
}

// ─── Transparent Proxy (L7 proxy for sidecars) ───────────────

export interface TransparentProxyConfig {
  enabled: boolean;
  httpPort: number;
  httpsPort: number;
}

// ─── Config (root) ──────────────────────────────────────────

export interface Config {
  server: {
    port: number;
    agentKey: string;
  };
  services: Record<string, ServiceConfig>;
  notifications?: {
    telegram?: TelegramConfig;
    webpush?: WebPushConfig;
  };
  audit: AuditConfig;
  security: SecurityConfig;
  admin: AdminConfig;
  proxy: ProxyConfig;
  transparentProxy: TransparentProxyConfig;
  secrets?: SecretsConfig;
}

// ─── Runtime types ──────────────────────────────────────────

export interface Approval {
  service: string;
  method: string;
  // null/undefined = method-wide; non-empty string = path-scoped (exact match incl. querystring)
  path?: string | null;
  approvedAt: number;
  expiresAt: number;
  approvedBy: string;
}

export interface PendingRequest {
  id: string;
  service: string;
  method: string;
  path: string;
  resolve: (approved: boolean) => void;
  timeout: NodeJS.Timeout;
}

export interface AuditEntry {
  timestamp: string;
  service: string;
  method: string;
  path: string;
  approved: boolean;
  responseStatus: number | null;
  agentIp: string;
  requestBody?: string | null;
  responseBody?: string | null;
}

// ─── Dashboard ──────────────────────────────────────────────

export interface DashboardStats {
  totalRequestsToday: number;
  totalRequestsWeek: number;
  activeApprovals: number;
  configuredServices: number;
  requestsByService: { service: string; count: number }[];
  requestsByHour: { hour: number; count: number }[];
  approvalStats: { approved: number; denied: number; timeout: number };
  methodBreakdown: { method: string; count: number }[];
  availableServices?: string[];
}
