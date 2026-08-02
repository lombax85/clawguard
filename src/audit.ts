import Database from 'better-sqlite3';
import { AuditEntry, Approval, DashboardStats, ServiceConfig } from './types';

export type SshSessionAction = 'shell' | 'exec';

export interface SshSessionStart {
  id: string;
  startedAt?: string;
  service: string;
  clientIp: string;
  targetHost?: string | null;
  targetPort?: number | null;
  upstreamUser?: string | null;
  action: SshSessionAction;
  approved?: boolean;
  outcome?: string;
  leaseExpiresAt?: string | null;
}

export interface SshSessionUpdate {
  targetHost?: string | null;
  targetPort?: number | null;
  upstreamUser?: string | null;
  approved?: boolean;
  outcome?: string;
  leaseExpiresAt?: string | null;
  exitStatus?: number | null;
  closeReason?: string | null;
}

export interface SshSessionFinalize extends SshSessionUpdate {
  endedAt?: string;
  outcome: string;
}

export interface SshSessionRecord {
  id: string;
  startedAt: string;
  updatedAt: string;
  endedAt: string | null;
  durationMs: number | null;
  service: string;
  clientIp: string;
  targetHost: string | null;
  targetPort: number | null;
  upstreamUser: string | null;
  action: SshSessionAction;
  approved: boolean;
  outcome: string;
  leaseExpiresAt: string | null;
  exitStatus: number | null;
  closeReason: string | null;
}

function normalizeCloseReason(value: string | null | undefined): string | null | undefined {
  if (value === undefined || value === null) return value;
  // Close reasons are metadata, not a transcript. Keep them single-line and
  // bounded so accidental error dumps cannot turn the audit DB into a stream log.
  return value.replace(/\s+/g, ' ').trim().slice(0, 1024);
}

export class AuditLogger {
  private db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.init();
  }

  private init(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        service TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        approved INTEGER NOT NULL,
        response_status INTEGER,
        agent_ip TEXT,
        request_body TEXT,
        response_body TEXT
      );

      CREATE TABLE IF NOT EXISTS approvals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        service TEXT NOT NULL,
        method TEXT NOT NULL DEFAULT '*',
        approved_by TEXT NOT NULL,
        ttl_seconds INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS telegram_paired_users (
        chat_id TEXT PRIMARY KEY,
        user_name TEXT,
        paired_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS services_override (
        service_name TEXT PRIMARY KEY,
        config_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS ssh_sessions (
        id TEXT PRIMARY KEY,
        started_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        ended_at TEXT,
        service TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        target_host TEXT,
        target_port INTEGER,
        upstream_user TEXT,
        action TEXT NOT NULL CHECK (action IN ('shell', 'exec')),
        approved INTEGER NOT NULL DEFAULT 0,
        outcome TEXT NOT NULL,
        lease_expires_at TEXT,
        exit_status INTEGER,
        close_reason TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_ssh_sessions_started_at
      ON ssh_sessions(started_at DESC);

    `);

    // Add columns if they don't exist (migration for existing DBs)
    try { this.db.exec('ALTER TABLE requests ADD COLUMN request_body TEXT'); } catch { /* already exists */ }
    try { this.db.exec('ALTER TABLE requests ADD COLUMN response_body TEXT'); } catch { /* already exists */ }
    try { this.db.exec('ALTER TABLE approvals ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0'); } catch { /* already exists */ }
    try { this.db.exec("ALTER TABLE approvals ADD COLUMN method TEXT NOT NULL DEFAULT '*'"); } catch { /* already exists */ }
    // NULL path = method-wide approval; non-null = path-scoped (exact match on pathname + querystring)
    try { this.db.exec('ALTER TABLE approvals ADD COLUMN path TEXT'); } catch { /* already exists */ }
    try { this.db.exec('ALTER TABLE telegram_paired_users ADD COLUMN showlog INTEGER NOT NULL DEFAULT 0'); } catch { /* already exists */ }
    // Optional request provenance (multi-user): who triggered the call and why.
    try { this.db.exec('ALTER TABLE requests ADD COLUMN request_user TEXT'); } catch { /* already exists */ }
    try { this.db.exec('ALTER TABLE requests ADD COLUMN request_reason TEXT'); } catch { /* already exists */ }
  }

  // ─── Request logging ──────────────────────────────────────

  logRequest(entry: AuditEntry): void {
    this.db.prepare(`
      INSERT INTO requests (timestamp, service, method, path, approved, response_status, agent_ip, request_body, response_body, request_user, request_reason)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      entry.timestamp,
      entry.service,
      entry.method,
      entry.path,
      entry.approved ? 1 : 0,
      entry.responseStatus,
      entry.agentIp,
      entry.requestBody || null,
      entry.responseBody || null,
      entry.requestUser || null,
      entry.requestReason || null
    );
  }

  // ─── Approval logging ─────────────────────────────────────

  logApproval(service: string, method: string, approvedBy: string, ttlSeconds: number, path?: string | null): void {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);
    this.db.prepare(`
      INSERT INTO approvals (timestamp, service, method, path, approved_by, ttl_seconds, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(now.toISOString(), service, method.toUpperCase(), path ?? null, approvedBy, ttlSeconds, expiresAt.toISOString());
  }

  /**
   * Load approvals that haven't expired yet and haven't been revoked
   * (for restoring state after restart).
   */
  getActiveApprovals(): Approval[] {
    const now = new Date().toISOString();

    // Clean up expired approvals first
    this.db.prepare(`DELETE FROM approvals WHERE expires_at <= ?`).run(now);

    const rows = this.db.prepare(`
      SELECT service, method, path, approved_by, ttl_seconds, expires_at, timestamp
      FROM approvals
      WHERE expires_at > ? AND revoked = 0
      ORDER BY id DESC
    `).all(now) as { service: string; method: string; path: string | null; approved_by: string; ttl_seconds: number; expires_at: string; timestamp: string }[];

    // Deduplicate — keep only the latest approval per service+method+path
    const seen = new Set<string>();
    const approvals: Approval[] = [];
    for (const row of rows) {
      const method = (row.method || '*').toUpperCase();
      const key = `${row.service}::${method}::${row.path ?? '*'}`;
      if (seen.has(key)) continue;
      seen.add(key);
      approvals.push({
        service: row.service,
        method,
        path: row.path,
        approvedAt: new Date(row.timestamp).getTime(),
        expiresAt: new Date(row.expires_at).getTime(),
        approvedBy: row.approved_by,
      });
    }
    return approvals;
  }

  /**
   * Mark an approval as revoked in the database so it won't be restored on restart.
   * - path=undefined: revoke all approvals for service+method (both method-wide and path-scoped)
   * - path=null: revoke only the method-wide approval
   * - path=string: revoke only the exact path-scoped approval
   */
  revokeApprovalInDb(service: string, method?: string, path?: string | null): void {
    if (method && path === null) {
      this.db.prepare(`
        UPDATE approvals SET revoked = 1 WHERE service = ? AND method = ? AND path IS NULL AND revoked = 0
      `).run(service, method.toUpperCase());
      return;
    }
    if (method && typeof path === 'string') {
      this.db.prepare(`
        UPDATE approvals SET revoked = 1 WHERE service = ? AND method = ? AND path = ? AND revoked = 0
      `).run(service, method.toUpperCase(), path);
      return;
    }
    if (method) {
      this.db.prepare(`
        UPDATE approvals SET revoked = 1 WHERE service = ? AND method = ? AND revoked = 0
      `).run(service, method.toUpperCase());
      return;
    }
    this.db.prepare(`
      UPDATE approvals SET revoked = 1 WHERE service = ? AND revoked = 0
    `).run(service);
  }

  // ─── Telegram pairing ─────────────────────────────────────

  isPairedUser(chatId: string): boolean {
    const row = this.db.prepare('SELECT 1 FROM telegram_paired_users WHERE chat_id = ?').get(chatId);
    return !!row;
  }

  pairUser(chatId: string, userName: string): void {
    this.db.prepare(`
      INSERT OR REPLACE INTO telegram_paired_users (chat_id, user_name, paired_at)
      VALUES (?, ?, ?)
    `).run(chatId, userName, new Date().toISOString());
  }

  unpairUser(chatId: string): void {
    this.db.prepare('DELETE FROM telegram_paired_users WHERE chat_id = ?').run(chatId);
  }

  getPairedUsers(): { chatId: string; userName: string; pairedAt: string }[] {
    return this.db.prepare('SELECT chat_id as chatId, user_name as userName, paired_at as pairedAt FROM telegram_paired_users').all() as { chatId: string; userName: string; pairedAt: string }[];
  }

  setShowlog(chatId: string, enabled: boolean): void {
    this.db.prepare('UPDATE telegram_paired_users SET showlog = ? WHERE chat_id = ?')
      .run(enabled ? 1 : 0, chatId);
  }

  isShowlogEnabled(chatId: string): boolean {
    const row = this.db.prepare('SELECT showlog FROM telegram_paired_users WHERE chat_id = ?').get(chatId) as { showlog: number } | undefined;
    return !!row && row.showlog === 1;
  }

  getShowlogEnabledChatIds(): string[] {
    const rows = this.db.prepare('SELECT chat_id as chatId FROM telegram_paired_users WHERE showlog = 1').all() as { chatId: string }[];
    return rows.map(r => r.chatId);
  }

  // ─── Service overrides (admin API) ────────────────────────

  getServiceOverrides(): Record<string, ServiceConfig> {
    const rows = this.db.prepare('SELECT service_name, config_json FROM services_override').all() as { service_name: string; config_json: string }[];
    const result: Record<string, ServiceConfig> = {};
    for (const row of rows) {
      try {
        result[row.service_name] = JSON.parse(row.config_json);
      } catch { /* skip invalid */ }
    }
    return result;
  }

  saveServiceOverride(name: string, config: ServiceConfig): void {
    const now = new Date().toISOString();
    this.db.prepare(`
      INSERT INTO services_override (service_name, config_json, created_at, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(service_name) DO UPDATE SET config_json = ?, updated_at = ?
    `).run(name, JSON.stringify(config), now, now, JSON.stringify(config), now);
  }

  deleteServiceOverride(name: string): void {
    this.db.prepare('DELETE FROM services_override WHERE service_name = ?').run(name);
  }

  // ─── Queries ───────────────────────────────────────────────

  startSshSession(entry: SshSessionStart): void {
    if (!entry.id.trim()) throw new Error('SSH session id is required');
    if (entry.action !== 'shell' && entry.action !== 'exec') {
      throw new Error(`Invalid SSH session action: ${entry.action}`);
    }
    if (entry.targetPort !== undefined && entry.targetPort !== null
      && (!Number.isInteger(entry.targetPort) || entry.targetPort < 1 || entry.targetPort > 65535)) {
      throw new Error(`Invalid SSH target port: ${entry.targetPort}`);
    }

    const now = entry.startedAt ?? new Date().toISOString();
    this.db.prepare(`
      INSERT INTO ssh_sessions (
        id, started_at, updated_at, service, client_ip, target_host, target_port,
        upstream_user, action, approved, outcome, lease_expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      entry.id, now, now, entry.service, entry.clientIp, entry.targetHost ?? null,
      entry.targetPort ?? null, entry.upstreamUser ?? null, entry.action, entry.approved ? 1 : 0,
      entry.outcome ?? 'pending_approval', entry.leaseExpiresAt ?? null
    );
  }

  updateSshSession(id: string, update: SshSessionUpdate): boolean {
    return this.applySshSessionUpdate(id, update, undefined);
  }

  finalizeSshSession(id: string, final: SshSessionFinalize): boolean {
    return this.applySshSessionUpdate(id, final, final.endedAt ?? new Date().toISOString());
  }

  private applySshSessionUpdate(
    id: string,
    update: SshSessionUpdate,
    endedAt: string | undefined
  ): boolean {
    const assignments = ['updated_at = ?'];
    const values: unknown[] = [new Date().toISOString()];

    if (endedAt !== undefined) {
      assignments.push('ended_at = ?');
      values.push(endedAt);
    }
    if (update.approved !== undefined) {
      assignments.push('approved = ?');
      values.push(update.approved ? 1 : 0);
    }
    if (update.targetHost !== undefined) {
      assignments.push('target_host = ?');
      values.push(update.targetHost);
    }
    if (update.targetPort !== undefined) {
      if (update.targetPort !== null
        && (!Number.isInteger(update.targetPort) || update.targetPort < 1 || update.targetPort > 65535)) {
        throw new Error(`Invalid SSH target port: ${update.targetPort}`);
      }
      assignments.push('target_port = ?');
      values.push(update.targetPort);
    }
    if (update.upstreamUser !== undefined) {
      assignments.push('upstream_user = ?');
      values.push(update.upstreamUser);
    }
    if (update.outcome !== undefined) {
      assignments.push('outcome = ?');
      values.push(update.outcome);
    }
    if (update.leaseExpiresAt !== undefined) {
      assignments.push('lease_expires_at = ?');
      values.push(update.leaseExpiresAt);
    }
    if (update.exitStatus !== undefined) {
      assignments.push('exit_status = ?');
      values.push(update.exitStatus);
    }
    if (update.closeReason !== undefined) {
      assignments.push('close_reason = ?');
      values.push(normalizeCloseReason(update.closeReason));
    }

    values.push(id);
    const result = this.db.prepare(`
      UPDATE ssh_sessions SET ${assignments.join(', ')} WHERE id = ?
    `).run(...values);
    return result.changes > 0;
  }

  getRecentSshSessions(limit: number = 50): SshSessionRecord[] {
    const safeLimit = Math.max(1, Math.min(Math.trunc(limit) || 50, 1000));
    const rows = this.db.prepare(`
      SELECT
        id,
        started_at AS startedAt,
        updated_at AS updatedAt,
        ended_at AS endedAt,
        CASE
          WHEN ended_at IS NULL THEN NULL
          ELSE CAST(ROUND((julianday(ended_at) - julianday(started_at)) * 86400000) AS INTEGER)
        END AS durationMs,
        service,
        client_ip AS clientIp,
        target_host AS targetHost,
        target_port AS targetPort,
        upstream_user AS upstreamUser,
        action,
        approved,
        outcome,
        lease_expires_at AS leaseExpiresAt,
        exit_status AS exitStatus,
        close_reason AS closeReason
      FROM ssh_sessions
      ORDER BY started_at DESC
      LIMIT ?
    `).all(safeLimit) as Array<Omit<SshSessionRecord, 'approved'> & { approved: number }>;

    return rows.map((row) => ({ ...row, approved: row.approved === 1 }));
  }

  getRecentRequests(limit: number = 50): unknown[] {
    return this.db.prepare(`
      SELECT id, timestamp, service, method, path, approved, response_status, agent_ip, request_body, response_body, request_user, request_reason
      FROM requests ORDER BY id DESC LIMIT ?
    `).all(limit);
  }

  getRecentApprovals(limit: number = 20): unknown[] {
    return this.db.prepare(`
      SELECT * FROM approvals ORDER BY id DESC LIMIT ?
    `).all(limit);
  }

  // ─── Dashboard aggregations ───────────────────────────────

  getRequestCountByService(sinceISO: string): { service: string; count: number }[] {
    return this.db.prepare(`
      SELECT service, COUNT(*) as count
      FROM requests
      WHERE timestamp >= ?
      GROUP BY service
      ORDER BY count DESC
    `).all(sinceISO) as { service: string; count: number }[];
  }

  getRequestsByHour(sinceISO: string, service?: string): { hour: number; count: number }[] {
    if (service) {
      return this.db.prepare(`
        SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hour, COUNT(*) as count
        FROM requests
        WHERE timestamp >= ? AND service = ?
        GROUP BY hour
        ORDER BY hour
      `).all(sinceISO, service) as { hour: number; count: number }[];
    }
    return this.db.prepare(`
      SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hour, COUNT(*) as count
      FROM requests
      WHERE timestamp >= ?
      GROUP BY hour
      ORDER BY hour
    `).all(sinceISO) as { hour: number; count: number }[];
  }

  getApprovalStats(sinceISO: string, service?: string): { approved: number; denied: number } {
    const query = service
      ? `SELECT SUM(CASE WHEN approved = 1 THEN 1 ELSE 0 END) as approved, SUM(CASE WHEN approved = 0 THEN 1 ELSE 0 END) as denied FROM requests WHERE timestamp >= ? AND service = ?`
      : `SELECT SUM(CASE WHEN approved = 1 THEN 1 ELSE 0 END) as approved, SUM(CASE WHEN approved = 0 THEN 1 ELSE 0 END) as denied FROM requests WHERE timestamp >= ?`;
    const row = (service
      ? this.db.prepare(query).get(sinceISO, service)
      : this.db.prepare(query).get(sinceISO)
    ) as { approved: number; denied: number } | undefined;
    return { approved: row?.approved || 0, denied: row?.denied || 0 };
  }

  getMethodBreakdown(sinceISO: string, service?: string): { method: string; count: number }[] {
    if (service) {
      return this.db.prepare(`
        SELECT method, COUNT(*) as count
        FROM requests
        WHERE timestamp >= ? AND service = ?
        GROUP BY method
        ORDER BY count DESC
      `).all(sinceISO, service) as { method: string; count: number }[];
    }
    return this.db.prepare(`
      SELECT method, COUNT(*) as count
      FROM requests
      WHERE timestamp >= ?
      GROUP BY method
      ORDER BY count DESC
    `).all(sinceISO) as { method: string; count: number }[];
  }

  getTotalRequests(sinceISO: string, service?: string): number {
    if (service) {
      const row = this.db.prepare(`
        SELECT COUNT(*) as total FROM requests WHERE timestamp >= ? AND service = ?
      `).get(sinceISO, service) as { total: number };
      return row.total;
    }
    const row = this.db.prepare(`
      SELECT COUNT(*) as total FROM requests WHERE timestamp >= ?
    `).get(sinceISO) as { total: number };
    return row.total;
  }

  getDistinctServices(): string[] {
    return (this.db.prepare(`SELECT DISTINCT service FROM requests ORDER BY service`).all() as { service: string }[]).map(r => r.service);
  }

  getDashboardStats(activeApprovals: number, configuredServices: number, filterService?: string): DashboardStats {
    const now = new Date();
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
    const weekStart = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();

    const approvalStats = this.getApprovalStats(weekStart, filterService);

    return {
      totalRequestsToday: this.getTotalRequests(todayStart, filterService),
      totalRequestsWeek: this.getTotalRequests(weekStart, filterService),
      activeApprovals,
      configuredServices,
      requestsByService: this.getRequestCountByService(weekStart),
      requestsByHour: this.getRequestsByHour(weekStart, filterService),
      approvalStats: { ...approvalStats, timeout: 0 },
      methodBreakdown: this.getMethodBreakdown(weekStart, filterService),
      availableServices: this.getDistinctServices(),
    };
  }

  // ─── Lifecycle ─────────────────────────────────────────────

  close(): void {
    this.db.close();
  }
}
