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
    type: 'bearer' | 'header' | 'query';
    token: string;
    headerName?: string;   // for type: 'header'
    paramName?: string;    // for type: 'query' (e.g. 'appid' for OpenWeatherMap)
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
}

// ─── Runtime types ──────────────────────────────────────────

export interface Approval {
  service: string;
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
