import {
  Approval,
  ServiceConfig,
  PolicyRule,
  RequestMeta,
  RequestApprovalInfo,
  FtpAccessMode,
  TemporaryServiceApproval,
  HttpApprovalScope,
} from './types';
import { randomUUID } from 'crypto';
import { scopeMatches, scopeLabel, SCOPE_DURATIONS, SCOPE_FOREVER } from './approval-scope';
import { MAX_TEMPORARY_APPROVAL_SECONDS, serviceApprovalHash } from './temporary-approval';
import { TelegramNotifier } from './telegram';
import { WebhookNotifier } from './webhook';
import { AuditLogger } from './audit';

let requestCounter = 0;
const SSH_SESSION_METHOD = 'SSH_SESSION';
const FTP_SESSION_METHOD = 'FTP_SESSION';

function generateRequestId(): string {
  return `req_${Date.now()}_${++requestCounter}`;
}

function withFallbackReason(meta: RequestMeta | undefined, fallback: string): RequestMeta {
  const suppliedReason = meta?.reason?.trim();
  return {
    ...meta,
    reason: suppliedReason || fallback,
  };
}

export class ApprovalManager {
  // Keyed by `${service}::${METHOD}::${path|*}` — `*` means method-wide
  private activeApprovals: Map<string, Approval> = new Map();

  private approvalKey(service: string, method: string, path?: string | null): string {
    const pathPart = (path === undefined || path === null) ? '*' : path;
    return `${service}::${method.toUpperCase()}::${pathPart}`;
  }
  private telegram: TelegramNotifier | undefined;
  private webhook: WebhookNotifier | undefined;
  private audit: AuditLogger;
  private approvalTimeout: number;

  grantTemporaryServiceApproval(service: string, config: ServiceConfig, ttlSeconds: number,
    approvedBy: string, chatId: string, accessMode?: FtpAccessMode): TemporaryServiceApproval {
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > MAX_TEMPORARY_APPROVAL_SECONDS) {
      throw new Error('Temporary approval duration must be from 1 minute to 24 hours');
    }
    const protocol = config.protocol ?? 'http';
    if ((protocol === 'ftp' || protocol === 'ftps')
      && accessMode !== 'read_only' && accessMode !== 'read_write') {
      throw new Error('FTP requires an explicit read_only or read_write access mode');
    }
    const now = Date.now();
    const approval: TemporaryServiceApproval = {
      service, protocol, configHash: serviceApprovalHash(config), approvedAt: now,
      expiresAt: now + ttlSeconds * 1000, approvedBy, chatId,
      ...((protocol === 'ftp' || protocol === 'ftps') ? { accessMode } : {}),
    };
    this.audit.saveTemporaryServiceApproval(approval);
    // Change memory only after the replacement was saved successfully.
    for (const [key, previous] of this.activeApprovals) {
      if (previous.service === service) this.activeApprovals.delete(key);
    }
    return approval;
  }

  getTemporaryServiceApprovals(): TemporaryServiceApproval[] {
    return this.audit.getTemporaryServiceApprovals?.() ?? [];
  }

  private temporaryApproval(service: string, config: ServiceConfig): TemporaryServiceApproval | undefined {
    const approval = this.getTemporaryServiceApprovals().find(item => item.service === service);
    if (!approval || !this.telegram?.canUseTemporaryApproval?.(approval.chatId)) return undefined;
    if (approval.configHash !== serviceApprovalHash(config)) {
      this.audit.revokeTemporaryServiceApprovals(service);
      return undefined;
    }
    return approval;
  }

  private notifyTemporary(approval: TemporaryServiceApproval, method: string, path: string,
    agentIp: string, meta?: RequestMeta, info?: RequestApprovalInfo): void {
    const mode = approval.accessMode ? `; ${approval.accessMode}` : '';
    this.telegram?.notifyAutoApproved(approval.service, method, path, agentIp,
      `temporary service approval until ${new Date(approval.expiresAt).toISOString()}${mode}`, meta, info,
      { silent: true });
  }

  constructor(
    telegram: TelegramNotifier | undefined,
    audit: AuditLogger,
    approvalTimeoutMs: number = 120000,
    webhook?: WebhookNotifier
  ) {
    this.telegram = telegram;
    this.webhook = webhook;
    this.audit = audit;
    this.approvalTimeout = approvalTimeoutMs;

    // Restore active approvals from SQLite (survive restarts)
    this.restoreApprovals();
  }

  private restoreApprovals(): void {
    const saved = this.audit.getActiveApprovals();
    let restoredCount = 0;
    for (const approval of saved) {
      // Protocol-gateway approvals are deliberately one-shot. Ignore any
      // legacy or accidentally persisted entry so it can never authorize a
      // new SSH session or FTP lease after a restart.
      if ([SSH_SESSION_METHOD, FTP_SESSION_METHOD].includes(approval.method.toUpperCase())) continue;

      const key = this.approvalKey(approval.service, approval.method, approval.path);
      this.activeApprovals.set(key, approval);
      restoredCount++;
      const remaining = Math.round((approval.expiresAt - Date.now()) / 1000 / 60);
      const scope = approval.path ? `path=${approval.path}` : 'method-wide';
      console.log(`   ↻ Restored approval for ${approval.service} ${approval.method} (${scope}, ${remaining}min remaining)`);
    }
    if (restoredCount > 0) {
      console.log(`   ✓ ${restoredCount} approval(s) restored from database`);
    }
  }

  private matchesRule(rule: PolicyRule, method: string, path: string): boolean {
    if (rule.match.method && rule.match.method.toUpperCase() !== method.toUpperCase()) {
      return false;
    }
    if (rule.match.path && !path.startsWith(rule.match.path)) {
      return false;
    }
    return true;
  }

  private getAction(serviceConfig: ServiceConfig, method: string, path: string): 'auto_approve' | 'require_approval' {
    if (serviceConfig.policy.rules) {
      for (const rule of serviceConfig.policy.rules) {
        if (this.matchesRule(rule, method, path)) {
          return rule.action;
        }
      }
    }
    return serviceConfig.policy.default;
  }

  /**
   * Returns the matching approval (exact path first, then method-wide) or null.
   * Removes it from the map if expired.
   */
  private findActiveApproval(service: string, method: string, path: string): Approval | null {
    const exactKey = this.approvalKey(service, method, path);
    const exact = this.activeApprovals.get(exactKey);
    if (exact) {
      if (Date.now() > exact.expiresAt) {
        this.activeApprovals.delete(exactKey);
        this.audit.revokeApprovalInDb(service, method, path);
        console.log(`⏰ Approval expired for ${service} ${method.toUpperCase()} path=${path}`);
      } else {
        return exact;
      }
    }

    const wideKey = this.approvalKey(service, method, null);
    const wide = this.activeApprovals.get(wideKey);
    if (wide) {
      if (Date.now() > wide.expiresAt) {
        this.activeApprovals.delete(wideKey);
        this.audit.revokeApprovalInDb(service, method, null);
        console.log(`⏰ Approval expired for ${service} ${method.toUpperCase()} (method-wide)`);
        return null;
      }
      return wide;
    }

    return null;
  }

  hasActiveApproval(service: string, method: string, path?: string): boolean {
    if (path === undefined) {
      const wide = this.activeApprovals.get(this.approvalKey(service, method, null));
      if (!wide) return false;
      if (Date.now() > wide.expiresAt) {
        this.activeApprovals.delete(this.approvalKey(service, method, null));
        this.audit.revokeApprovalInDb(service, method, null);
        return false;
      }
      return true;
    }
    return this.findActiveApproval(service, method, path) !== null
      || (this.audit.getScopedApprovals?.() ?? []).some(a => a.service === service && scopeMatches(a.scope, method, path));
  }

  async checkApproval(
    service: string,
    serviceConfig: ServiceConfig,
    method: string,
    path: string,
    agentIp: string,
    meta?: RequestMeta,
    approvalInfo?: RequestApprovalInfo
  ): Promise<boolean> {
    const approvalPath = approvalInfo?.approvalPath || path;
    const temporary = this.temporaryApproval(service, serviceConfig);
    if (temporary) {
      this.notifyTemporary(temporary, method, approvalPath, agentIp, meta, approvalInfo);
      return true;
    }
    const oneTime = approvalInfo?.oneTime === true;
    const action = oneTime
      ? 'require_approval'
      : this.getAction(serviceConfig, method, approvalPath);

    // Auto-approve based on policy
    if (action === 'auto_approve') {
      console.log(`✅ Auto-approved: ${method} ${service}${approvalPath}`);
      this.telegram?.notifyAutoApproved(
        service, method, approvalPath, agentIp, 'policy:auto_approve', meta, approvalInfo
      );
      return true;
    }

    // Check existing approval (exact path first, then method-wide)
    const existing = oneTime ? null : this.findActiveApproval(service, method, approvalPath);
    if (existing) {
      const remaining = Math.round((existing.expiresAt - Date.now()) / 1000 / 60);
      const scope = existing.path ? `path=${existing.path}` : 'method-wide';
      console.log(`✅ Active approval for ${service} ${method.toUpperCase()} (${scope}, ${remaining}min remaining)`);
      const reason = existing.path
        ? `approval:path (${remaining}min left)`
        : `approval:method-wide (${remaining}min left)`;
      this.telegram?.notifyAutoApproved(
        service, method, approvalPath, agentIp, reason, meta, approvalInfo
      );
      return true;
    }

    if (!oneTime) {
      for (const approval of this.audit.getScopedApprovals?.() ?? []) {
        if (approval.service !== service) continue;
        if (approval.configHash !== serviceApprovalHash(serviceConfig)) {
          this.audit.revokeScopedApprovals(service, approval.id);
          continue;
        }
        if (scopeMatches(approval.scope, method, approvalPath)) {
          this.telegram?.notifyAutoApproved(service, method, approvalPath, agentIp,
            approval.expiresAt === null ? 'approval:scope (until revoked)'
              : `approval:scope (${Math.ceil((approval.expiresAt - Date.now()) / 60000)}min left)`, meta, approvalInfo);
          return true;
        }
      }
    }

    // Request new approval
    console.log(`🔔 Requesting approval for: ${method} ${service}${approvalPath}`);

    // No notification channel configured — auto-approve (test/dev mode)
    // The webhook is informational-only and cannot approve, so it doesn't count here.
    if (!this.telegram) {
      if (oneTime) {
        console.log(`❌ One-time request denied for ${service}: Telegram is not configured`);
        return false;
      }
      console.log(`✅ Auto-approved (no notification channel): ${method} ${service}${path}`);
      const approval: Approval = {
        service,
        method: method.toUpperCase(),
        path: null,
        approvedAt: Date.now(),
        expiresAt: Date.now() + 3600 * 1000, // 1h default
        approvedBy: 'auto (no channel)',
      };
      this.activeApprovals.set(this.approvalKey(service, method, null), approval);
      this.audit.logApproval(service, method, 'auto (no channel)', 3600, null);
      return true;
    }

    const requestId = generateRequestId();

    // Fire-and-forget side notification (e.g. user-defined webhook integration)
    this.webhook?.notifyApprovalRequired(
      requestId, service, method, approvalPath, agentIp, meta, approvalInfo
    );

    const configHash = serviceApprovalHash(serviceConfig);
    const deadline = Date.now() + this.approvalTimeout;
    let timer: NodeJS.Timeout | undefined;
    const timeoutPromise = new Promise<{ approved: boolean; ttlSeconds: number; approvedBy: string; pathScoped: boolean; scope?: HttpApprovalScope }>((resolve) => {
      timer = setTimeout(() => {
        this.telegram?.clearPendingRequest(requestId);
        resolve({ approved: false, ttlSeconds: 0, approvedBy: 'timeout', pathScoped: false });
      }, this.approvalTimeout);
    });

    const result = await Promise.race([
      this.telegram.requestApproval(
        requestId, service, method, approvalPath, agentIp, meta, approvalInfo, deadline, serviceConfig.http?.allowedMethods
      ),
      timeoutPromise,
    ]).finally(() => { if (timer) clearTimeout(timer); this.telegram?.clearPendingRequest(requestId); });

    if (result.scope && (Date.now() >= deadline || configHash !== serviceApprovalHash(serviceConfig)
      || !scopeMatches(result.scope, method, approvalPath)
      || !Object.values(SCOPE_DURATIONS).includes(result.ttlSeconds)
      || result.scope.methods.some(m => serviceConfig.http?.allowedMethods && !serviceConfig.http.allowedMethods.includes(m)))) {
      result.approved = false;
      result.approvedBy = 'scope_no_longer_valid';
    }

    // Side-channel notification of resolution so external integrations can dismiss alerts
    this.webhook?.notifyApprovalResolved(requestId, result.approved, result.approvedBy);

    if (result.approved) {
      if (oneTime || result.ttlSeconds === 0) {
        console.log(`✅ One-time request approved by ${result.approvedBy} for ${service} ${approvalPath}`);
        return true;
      }
      if (result.scope) {
        const now = Date.now();
        this.audit.saveScopedApproval({ id: randomUUID(), service, configHash, scope: result.scope,
          approvedAt: now, expiresAt: result.ttlSeconds === SCOPE_FOREVER ? null : now + result.ttlSeconds * 1000,
          approvedBy: result.approvedBy });
        console.log(`✅ Scoped approval for ${service}: ${scopeLabel(result.scope)}`);
        return true;
      }
      const scopedPath = result.pathScoped ? approvalPath : null;
      const approval: Approval = {
        service,
        method: method.toUpperCase(),
        path: scopedPath,
        approvedAt: Date.now(),
        expiresAt: Date.now() + result.ttlSeconds * 1000,
        approvedBy: result.approvedBy,
      };
      this.activeApprovals.set(this.approvalKey(service, method, scopedPath), approval);
      this.audit.logApproval(service, method, result.approvedBy, result.ttlSeconds, scopedPath);
      const scope = scopedPath ? `path=${scopedPath}` : 'method-wide';
      console.log(`✅ Approved by ${result.approvedBy} for ${service} ${method.toUpperCase()} (${scope}, ${result.ttlSeconds / 3600}h)`);
      return true;
    }

    console.log(`❌ Denied or timed out for ${service} (by: ${result.approvedBy})`);
    return false;
  }

  /**
   * Requests approval for exactly one SSH session.
   *
   * Unlike HTTP approvals, this path is always fail-closed and deliberately
   * bypasses policy auto-approval, the HTTP approval cache, restored
   * approvals, and approval persistence. A successful decision authorizes
   * only the caller currently awaiting this promise. An explicit temporary
   * service grant is the only exception to the fresh-decision requirement.
   */
  async checkSshSessionApproval(
    service: string,
    serviceConfig: ServiceConfig,
    path: string,
    agentIp: string,
    meta?: RequestMeta,
    timeoutMs: number = this.approvalTimeout,
    signal?: AbortSignal
  ): Promise<boolean> {
    // Keep the public signature aligned with checkApproval while making it
    // explicit that SSH policy rules are not consulted.
    const temporary = signal?.aborted ? undefined : this.temporaryApproval(service, serviceConfig);
    if (temporary) {
      this.notifyTemporary(temporary, SSH_SESSION_METHOD, path, agentIp,
        withFallbackReason(meta, `Open SSH session (${path})`));
      return true;
    }

    const requestId = generateRequestId();
    const approvalMeta = withFallbackReason(
      meta,
      `Open one-time SSH session (${path})`
    );
    console.log(`🔔 Requesting one-time SSH session approval: ${service}${path}`);

    this.webhook?.notifyApprovalRequired(
      requestId,
      service,
      SSH_SESSION_METHOD,
      path,
      agentIp,
      approvalMeta
    );

    // SSH never inherits the HTTP development-mode fail-open behavior.
    if (!this.telegram) {
      console.log(`❌ SSH session denied for ${service}: Telegram is not configured`);
      this.webhook?.notifyApprovalResolved(requestId, false, 'no_telegram');
      return false;
    }

    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
      console.error(`❌ SSH session denied for ${service}: invalid approval timeout`);
      this.webhook?.notifyApprovalResolved(requestId, false, 'invalid_timeout');
      return false;
    }

    if (signal?.aborted) {
      this.webhook?.notifyApprovalResolved(requestId, false, 'gateway_shutdown');
      return false;
    }

    let timeout: NodeJS.Timeout | undefined;
    let abortHandler: (() => void) | undefined;
    const timeoutPromise = new Promise<{ approved: boolean; approvedBy: string }>((resolve) => {
      timeout = setTimeout(() => {
        this.telegram?.clearPendingRequest(requestId);
        resolve({ approved: false, approvedBy: 'timeout' });
      }, timeoutMs);
    });
    const abortPromise = new Promise<{ approved: boolean; approvedBy: string }>((resolve) => {
      if (!signal) return;
      abortHandler = () => {
        this.telegram?.clearPendingRequest(requestId);
        resolve({ approved: false, approvedBy: 'gateway_shutdown' });
      };
      signal.addEventListener('abort', abortHandler, { once: true });
    });

    let result: { approved: boolean; approvedBy: string };
    try {
      result = await Promise.race([
        this.telegram.requestSshSessionApproval(requestId, service, path, agentIp, approvalMeta),
        timeoutPromise,
        abortPromise,
      ]);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`❌ SSH approval request failed for ${service}: ${message}`);
      result = { approved: false, approvedBy: 'telegram_error' };
    } finally {
      if (timeout) clearTimeout(timeout);
      if (signal && abortHandler) signal.removeEventListener('abort', abortHandler);
      this.telegram.clearPendingRequest(requestId);
    }

    this.webhook?.notifyApprovalResolved(requestId, result.approved, result.approvedBy);

    if (result.approved) {
      console.log(`✅ One-time SSH session approved by ${result.approvedBy} for ${service}`);
      return true;
    }

    console.log(`❌ SSH session denied for ${service} (by: ${result.approvedBy})`);
    return false;
  }

  /**
   * Requests approval for one bounded FTP/FTPS lease. It is fail-closed and
   * never reads or writes the reusable HTTP approval cache.
   */
  async checkFtpSessionApproval(
    service: string,
    serviceConfig: ServiceConfig,
    path: string,
    agentIp: string,
    meta?: RequestMeta,
    timeoutMs: number = this.approvalTimeout,
    signal?: AbortSignal
  ): Promise<FtpAccessMode | false> {
    const temporary = signal?.aborted ? undefined : this.temporaryApproval(service, serviceConfig);
    if (temporary && temporary.accessMode) {
      this.notifyTemporary(temporary, FTP_SESSION_METHOD, path, agentIp,
        withFallbackReason(meta, `Open FTP/FTPS lease (${path})`));
      return temporary.accessMode;
    }
    const requestId = generateRequestId();
    const approvalMeta = withFallbackReason(
      meta,
      `Open one-time FTP/FTPS lease (${path})`
    );
    console.log(`🔔 Requesting FTP/FTPS lease approval: ${service}${path}`);
    this.webhook?.notifyApprovalRequired(
      requestId, service, FTP_SESSION_METHOD, path, agentIp, approvalMeta
    );

    if (!this.telegram) {
      console.log(`❌ FTP lease denied for ${service}: Telegram is not configured`);
      this.webhook?.notifyApprovalResolved(requestId, false, 'no_telegram');
      return false;
    }
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
      this.webhook?.notifyApprovalResolved(requestId, false, 'invalid_timeout');
      return false;
    }
    if (signal?.aborted) {
      this.webhook?.notifyApprovalResolved(requestId, false, 'gateway_shutdown');
      return false;
    }

    let timeout: NodeJS.Timeout | undefined;
    let abortHandler: (() => void) | undefined;
    const timeoutPromise = new Promise<{ approved: boolean; approvedBy: string; accessMode?: FtpAccessMode }>((resolve) => {
      timeout = setTimeout(() => {
        this.telegram?.clearPendingRequest(requestId);
        resolve({ approved: false, approvedBy: 'timeout' });
      }, timeoutMs);
    });
    const abortPromise = new Promise<{ approved: boolean; approvedBy: string; accessMode?: FtpAccessMode }>((resolve) => {
      if (!signal) return;
      abortHandler = () => {
        this.telegram?.clearPendingRequest(requestId);
        resolve({ approved: false, approvedBy: 'gateway_shutdown' });
      };
      signal.addEventListener('abort', abortHandler, { once: true });
    });

    let result: { approved: boolean; approvedBy: string; accessMode?: FtpAccessMode };
    try {
      result = await Promise.race([
        this.telegram.requestFtpSessionApproval(requestId, service, path, agentIp, approvalMeta),
        timeoutPromise,
        abortPromise,
      ]);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`❌ FTP approval request failed for ${service}: ${message}`);
      result = { approved: false, approvedBy: 'telegram_error' };
    } finally {
      if (timeout) clearTimeout(timeout);
      if (signal && abortHandler) signal.removeEventListener('abort', abortHandler);
      this.telegram.clearPendingRequest(requestId);
    }

    const effectiveApproval = result.approved
      && (result.accessMode === 'read_only' || result.accessMode === 'read_write');
    this.webhook?.notifyApprovalResolved(requestId, effectiveApproval, result.approvedBy);
    if (effectiveApproval) {
      console.log(`✅ FTP ${result.accessMode} lease approved by ${result.approvedBy} for ${service}`);
      return result.accessMode!;
    }
    console.log(`❌ FTP lease denied for ${service} (by: ${result.approvedBy})`);
    return false;
  }

  /**
   * Revoke approvals.
   * - method=undefined: revoke every approval for the service (all methods, all paths)
   * - method set, path=undefined: revoke every approval for service+method (wide + all paths)
   * - method set, path=null: revoke only the method-wide approval
   * - method set, path=string: revoke only the exact path-scoped approval
   */
  revokeApproval(service: string, method?: string, path?: string | null): boolean {
    let temporaryRevoked = (!method || method === '*')
      ? (this.audit.revokeTemporaryServiceApprovals?.(service) ?? 0) > 0 : false;
    if (!method) temporaryRevoked = (this.audit.revokeScopedApprovals?.(service) ?? 0) > 0 || temporaryRevoked;
    else if (path === undefined) {
      for (const a of this.audit.getScopedApprovals?.() ?? []) {
        if (a.service === service && a.scope.methods.includes(method.toUpperCase())) {
          temporaryRevoked = this.revokeScopedApproval(service, a.id) || temporaryRevoked;
        }
      }
    }
    if (method && path !== undefined) {
      const key = this.approvalKey(service, method, path);
      if (this.activeApprovals.has(key)) {
        this.activeApprovals.delete(key);
        this.audit.revokeApprovalInDb(service, method, path);
        const scope = path === null ? 'method-wide' : `path=${path}`;
        console.log(`🔒 Approval revoked for ${service} ${method.toUpperCase()} (${scope})`);
        return true;
      }
      return temporaryRevoked;
    }

    if (method) {
      const prefix = `${service}::${method.toUpperCase()}::`;
      const keysToDelete = [...this.activeApprovals.keys()].filter((k) => k.startsWith(prefix));
      if (keysToDelete.length === 0) return temporaryRevoked;
      for (const key of keysToDelete) {
        this.activeApprovals.delete(key);
      }
      this.audit.revokeApprovalInDb(service, method);
      console.log(`🔒 Approval revoked for service+method: ${service} ${method.toUpperCase()} (${keysToDelete.length} entr${keysToDelete.length === 1 ? 'y' : 'ies'})`);
      return true;
    }

    // Revoke all methods for this service
    const keysToDelete = [...this.activeApprovals.keys()].filter((k) => k.startsWith(`${service}::`));
    if (keysToDelete.length === 0) return temporaryRevoked;

    for (const key of keysToDelete) {
      this.activeApprovals.delete(key);
    }
    this.audit.revokeApprovalInDb(service);
    console.log(`🔒 Approval revoked for service: ${service} (${keysToDelete.length} entr${keysToDelete.length === 1 ? 'y' : 'ies'})`);
    return true;
  }

  revokeAll(): number {
    const count = this.activeApprovals.size + this.getTemporaryServiceApprovals().length + (this.audit.getScopedApprovals?.() ?? []).length;
    this.audit.revokeScopedApprovals?.();
    this.audit.revokeTemporaryServiceApprovals?.();
    const keys = [...this.activeApprovals.keys()];
    this.activeApprovals.clear();
    for (const key of keys) {
      const [service, method, pathPart] = key.split('::');
      const path = pathPart === '*' ? null : pathPart;
      this.audit.revokeApprovalInDb(service, method, path);
    }
    console.log(`🔒 All ${count} approvals revoked`);
    return count;
  }

  getActiveCount(): number {
    // Clean expired first
    for (const [key, approval] of this.activeApprovals) {
      if (Date.now() > approval.expiresAt) {
        this.activeApprovals.delete(key);
      }
    }
    return this.activeApprovals.size + this.getTemporaryServiceApprovals().length + (this.audit.getScopedApprovals?.() ?? []).length;
  }

  revokeScopedApproval(service: string, id: string): boolean {
    return (this.audit.revokeScopedApprovals?.(service, id) ?? 0) > 0;
  }

  getStatus(): Record<string, { service: string; method: string; path: string | null; expiresAt: string | null; approvedBy: string; remainingMinutes: number | null; scopeId?: string; scope?: HttpApprovalScope }> {
    const status: ReturnType<ApprovalManager['getStatus']> = {};
    for (const a of this.audit.getScopedApprovals?.() ?? []) {
      status[a.id] = { service: a.service, method: a.scope.methods.join(', '), path: a.scope.path,
        scopeId: a.id, scope: a.scope, expiresAt: a.expiresAt === null ? null : new Date(a.expiresAt).toISOString(), approvedBy: a.approvedBy,
        remainingMinutes: a.expiresAt === null ? null : Math.ceil((a.expiresAt - Date.now()) / 60000) };
    }
    for (const approval of this.getTemporaryServiceApprovals()) {
      status[`${approval.service}::*::*`] = {
        service: approval.service, method: '*', path: null,
        expiresAt: new Date(approval.expiresAt).toISOString(), approvedBy: approval.approvedBy,
        remainingMinutes: Math.ceil((approval.expiresAt - Date.now()) / 60000),
      };
    }
    for (const [key, approval] of this.activeApprovals) {
      if (Date.now() < approval.expiresAt) {
        status[key] = {
          service: approval.service,
          method: approval.method,
          path: approval.path ?? null,
          expiresAt: new Date(approval.expiresAt).toISOString(),
          approvedBy: approval.approvedBy,
          remainingMinutes: Math.round((approval.expiresAt - Date.now()) / 1000 / 60),
        };
      }
    }
    return status;
  }
}
