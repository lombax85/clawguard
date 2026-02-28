import Database from 'better-sqlite3';
import { AuditEntry, Approval, DashboardStats, ServiceConfig } from './types';

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
    `);

    // Add columns if they don't exist (migration for existing DBs)
    try { this.db.exec('ALTER TABLE requests ADD COLUMN request_body TEXT'); } catch { /* already exists */ }
    try { this.db.exec('ALTER TABLE requests ADD COLUMN response_body TEXT'); } catch { /* already exists */ }
    try { this.db.exec('ALTER TABLE approvals ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0'); } catch { /* already exists */ }
  }

  // ─── Request logging ──────────────────────────────────────

  logRequest(entry: AuditEntry): void {
    this.db.prepare(`
      INSERT INTO requests (timestamp, service, method, path, approved, response_status, agent_ip, request_body, response_body)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      entry.timestamp,
      entry.service,
      entry.method,
      entry.path,
      entry.approved ? 1 : 0,
      entry.responseStatus,
      entry.agentIp,
      entry.requestBody || null,
      entry.responseBody || null
    );
  }

  // ─── Approval logging ─────────────────────────────────────

  logApproval(service: string, approvedBy: string, ttlSeconds: number): void {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);
    this.db.prepare(`
      INSERT INTO approvals (timestamp, service, approved_by, ttl_seconds, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(now.toISOString(), service, approvedBy, ttlSeconds, expiresAt.toISOString());
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
      SELECT service, approved_by, ttl_seconds, expires_at, timestamp
      FROM approvals
      WHERE expires_at > ? AND revoked = 0
      ORDER BY id DESC
    `).all(now) as { service: string; approved_by: string; ttl_seconds: number; expires_at: string; timestamp: string }[];

    // Deduplicate — keep only the latest approval per service
    const seen = new Set<string>();
    const approvals: Approval[] = [];
    for (const row of rows) {
      if (seen.has(row.service)) continue;
      seen.add(row.service);
      approvals.push({
        service: row.service,
        approvedAt: new Date(row.timestamp).getTime(),
        expiresAt: new Date(row.expires_at).getTime(),
        approvedBy: row.approved_by,
      });
    }
    return approvals;
  }

  /**
   * Mark an approval as revoked in the database so it won't be restored on restart.
   */
  revokeApprovalInDb(service: string): void {
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

  getRecentRequests(limit: number = 50): unknown[] {
    return this.db.prepare(`
      SELECT id, timestamp, service, method, path, approved, response_status, agent_ip, request_body, response_body
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

  getRequestsByHour(sinceISO: string): { hour: number; count: number }[] {
    return this.db.prepare(`
      SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hour, COUNT(*) as count
      FROM requests
      WHERE timestamp >= ?
      GROUP BY hour
      ORDER BY hour
    `).all(sinceISO) as { hour: number; count: number }[];
  }

  getApprovalStats(sinceISO: string): { approved: number; denied: number } {
    const row = this.db.prepare(`
      SELECT
        SUM(CASE WHEN approved = 1 THEN 1 ELSE 0 END) as approved,
        SUM(CASE WHEN approved = 0 THEN 1 ELSE 0 END) as denied
      FROM requests
      WHERE timestamp >= ?
    `).get(sinceISO) as { approved: number; denied: number } | undefined;
    return { approved: row?.approved || 0, denied: row?.denied || 0 };
  }

  getMethodBreakdown(sinceISO: string): { method: string; count: number }[] {
    return this.db.prepare(`
      SELECT method, COUNT(*) as count
      FROM requests
      WHERE timestamp >= ?
      GROUP BY method
      ORDER BY count DESC
    `).all(sinceISO) as { method: string; count: number }[];
  }

  getTotalRequests(sinceISO: string): number {
    const row = this.db.prepare(`
      SELECT COUNT(*) as total FROM requests WHERE timestamp >= ?
    `).get(sinceISO) as { total: number };
    return row.total;
  }

  getDashboardStats(activeApprovals: number, configuredServices: number): DashboardStats {
    const now = new Date();
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
    const weekStart = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();

    const approvalStats = this.getApprovalStats(weekStart);

    return {
      totalRequestsToday: this.getTotalRequests(todayStart),
      totalRequestsWeek: this.getTotalRequests(weekStart),
      activeApprovals,
      configuredServices,
      requestsByService: this.getRequestCountByService(weekStart),
      requestsByHour: this.getRequestsByHour(weekStart),
      approvalStats: { ...approvalStats, timeout: 0 },
      methodBreakdown: this.getMethodBreakdown(weekStart),
    };
  }

  // ─── Lifecycle ─────────────────────────────────────────────

  close(): void {
    this.db.close();
  }
}
