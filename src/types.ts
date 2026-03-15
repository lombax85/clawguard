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
    type: 'bearer' | 'header' | 'query' | 'basic' | 'url' | 'oauth2_client_credentials' | 'body_json';
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
    // for type: 'body_json' — inject/overwrite fields in the JSON request body
    fields?: Record<string, string>;
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
