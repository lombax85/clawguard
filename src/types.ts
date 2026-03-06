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
    type: 'bearer' | 'header' | 'query' | 'oauth2_client_credentials';
    token: string;
    headerName?: string;   // for type: 'header'
    paramName?: string;    // for type: 'query' (e.g. 'appid' for OpenWeatherMap)
    // for type: 'oauth2_client_credentials'
    tokenPath?: string;    // e.g. '/token' — the path where client sends credentials
    clientId?: string;
    clientSecret?: string;
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

// ─── Config (root) ──────────────────────────────────────────

export interface Config {
  server: {
    port: number;
    agentKey: string;
  };
  services: Record<string, ServiceConfig>;
  notifications: {
    telegram: TelegramConfig;
  };
  audit: AuditConfig;
  security: SecurityConfig;
  admin: AdminConfig;
  proxy: ProxyConfig;
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
