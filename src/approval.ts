import { Approval, ServiceConfig, PolicyRule } from './types';
import { TelegramNotifier } from './telegram';
import { WebPushNotifier } from './webpush';
import { AuditLogger } from './audit';

let requestCounter = 0;

function generateRequestId(): string {
  return `req_${Date.now()}_${++requestCounter}`;
}

export class ApprovalManager {
  // Keyed by `${service}::${METHOD}::${path|*}` — `*` means method-wide
  private activeApprovals: Map<string, Approval> = new Map();

  private approvalKey(service: string, method: string, path?: string | null): string {
    const pathPart = (path === undefined || path === null) ? '*' : path;
    return `${service}::${method.toUpperCase()}::${pathPart}`;
  }
  private telegram: TelegramNotifier | undefined;
  private webpush: WebPushNotifier | undefined;
  private audit: AuditLogger;
  private approvalTimeout: number;

  constructor(
    telegram: TelegramNotifier | undefined,
    audit: AuditLogger,
    approvalTimeoutMs: number = 120000,
    webpush?: WebPushNotifier
  ) {
    this.telegram = telegram;
    this.webpush = webpush;
    this.audit = audit;
    this.approvalTimeout = approvalTimeoutMs;

    // Restore active approvals from SQLite (survive restarts)
    this.restoreApprovals();
  }

  getWebPush(): WebPushNotifier | undefined {
    return this.webpush;
  }

  private restoreApprovals(): void {
    const saved = this.audit.getActiveApprovals();
    for (const approval of saved) {
      const key = this.approvalKey(approval.service, approval.method, approval.path);
      this.activeApprovals.set(key, approval);
      const remaining = Math.round((approval.expiresAt - Date.now()) / 1000 / 60);
      const scope = approval.path ? `path=${approval.path}` : 'method-wide';
      console.log(`   ↻ Restored approval for ${approval.service} ${approval.method} (${scope}, ${remaining}min remaining)`);
    }
    if (saved.length > 0) {
      console.log(`   ✓ ${saved.length} approval(s) restored from database`);
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
    return this.findActiveApproval(service, method, path) !== null;
  }

  async checkApproval(
    service: string,
    serviceConfig: ServiceConfig,
    method: string,
    path: string,
    agentIp: string
  ): Promise<boolean> {
    const action = this.getAction(serviceConfig, method, path);

    // Auto-approve based on policy
    if (action === 'auto_approve') {
      console.log(`✅ Auto-approved: ${method} ${service}${path}`);
      this.telegram?.notifyAutoApproved(service, method, path, agentIp, 'policy:auto_approve');
      return true;
    }

    // Check existing approval (exact path first, then method-wide)
    const existing = this.findActiveApproval(service, method, path);
    if (existing) {
      const remaining = Math.round((existing.expiresAt - Date.now()) / 1000 / 60);
      const scope = existing.path ? `path=${existing.path}` : 'method-wide';
      console.log(`✅ Active approval for ${service} ${method.toUpperCase()} (${scope}, ${remaining}min remaining)`);
      const reason = existing.path
        ? `approval:path (${remaining}min left)`
        : `approval:method-wide (${remaining}min left)`;
      this.telegram?.notifyAutoApproved(service, method, path, agentIp, reason);
      return true;
    }

    // Request new approval
    console.log(`🔔 Requesting approval for: ${method} ${service}${path}`);

    // No notification channel configured — auto-approve (test/dev mode)
    if (!this.telegram && !this.webpush) {
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

    const timeoutPromise = new Promise<{ approved: boolean; ttlSeconds: number; approvedBy: string; pathScoped: boolean }>((resolve) => {
      setTimeout(() => {
        this.telegram?.clearPendingRequest(requestId);
        this.webpush?.clearPendingRequest(requestId);
        resolve({ approved: false, ttlSeconds: 0, approvedBy: 'timeout', pathScoped: false });
      }, this.approvalTimeout);
    });

    const channelPromises: Promise<{ approved: boolean; ttlSeconds: number; approvedBy: string; pathScoped: boolean }>[] = [];
    if (this.telegram) {
      channelPromises.push(this.telegram.requestApproval(requestId, service, method, path, agentIp));
    }
    if (this.webpush) {
      channelPromises.push(this.webpush.requestApproval(requestId, service, method, path, agentIp));
    }

    const result = await Promise.race([...channelPromises, timeoutPromise]);

    // First channel won — clear the others so any later button click is a no-op
    this.telegram?.clearPendingRequest(requestId);
    this.webpush?.clearPendingRequest(requestId);

    if (result.approved) {
      const scopedPath = result.pathScoped ? path : null;
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
   * Revoke approvals.
   * - method=undefined: revoke every approval for the service (all methods, all paths)
   * - method set, path=undefined: revoke every approval for service+method (wide + all paths)
   * - method set, path=null: revoke only the method-wide approval
   * - method set, path=string: revoke only the exact path-scoped approval
   */
  revokeApproval(service: string, method?: string, path?: string | null): boolean {
    if (method && path !== undefined) {
      const key = this.approvalKey(service, method, path);
      if (this.activeApprovals.has(key)) {
        this.activeApprovals.delete(key);
        this.audit.revokeApprovalInDb(service, method, path);
        const scope = path === null ? 'method-wide' : `path=${path}`;
        console.log(`🔒 Approval revoked for ${service} ${method.toUpperCase()} (${scope})`);
        return true;
      }
      return false;
    }

    if (method) {
      const prefix = `${service}::${method.toUpperCase()}::`;
      const keysToDelete = [...this.activeApprovals.keys()].filter((k) => k.startsWith(prefix));
      if (keysToDelete.length === 0) return false;
      for (const key of keysToDelete) {
        this.activeApprovals.delete(key);
      }
      this.audit.revokeApprovalInDb(service, method);
      console.log(`🔒 Approval revoked for service+method: ${service} ${method.toUpperCase()} (${keysToDelete.length} entr${keysToDelete.length === 1 ? 'y' : 'ies'})`);
      return true;
    }

    // Revoke all methods for this service
    const keysToDelete = [...this.activeApprovals.keys()].filter((k) => k.startsWith(`${service}::`));
    if (keysToDelete.length === 0) return false;

    for (const key of keysToDelete) {
      this.activeApprovals.delete(key);
    }
    this.audit.revokeApprovalInDb(service);
    console.log(`🔒 Approval revoked for service: ${service} (${keysToDelete.length} entr${keysToDelete.length === 1 ? 'y' : 'ies'})`);
    return true;
  }

  revokeAll(): number {
    const count = this.activeApprovals.size;
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
    return this.activeApprovals.size;
  }

  getStatus(): Record<string, { service: string; method: string; path: string | null; expiresAt: string; approvedBy: string; remainingMinutes: number }> {
    const status: Record<string, { service: string; method: string; path: string | null; expiresAt: string; approvedBy: string; remainingMinutes: number }> = {};
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
