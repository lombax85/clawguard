import { Approval, ServiceConfig, PolicyRule } from './types';
import { TelegramNotifier } from './telegram';
import { AuditLogger } from './audit';

let requestCounter = 0;

function generateRequestId(): string {
  return `req_${Date.now()}_${++requestCounter}`;
}

export class ApprovalManager {
  private activeApprovals: Map<string, Approval> = new Map();

  private approvalKey(service: string, method: string): string {
    return `${service}::${method.toUpperCase()}`;
  }
  private telegram: TelegramNotifier;
  private audit: AuditLogger;
  private approvalTimeout: number;

  constructor(telegram: TelegramNotifier, audit: AuditLogger, approvalTimeoutMs: number = 120000) {
    this.telegram = telegram;
    this.audit = audit;
    this.approvalTimeout = approvalTimeoutMs;

    // Restore active approvals from SQLite (survive restarts)
    this.restoreApprovals();
  }

  private restoreApprovals(): void {
    const saved = this.audit.getActiveApprovals();
    for (const approval of saved) {
      const key = this.approvalKey(approval.service, approval.method);
      this.activeApprovals.set(key, approval);
      const remaining = Math.round((approval.expiresAt - Date.now()) / 1000 / 60);
      console.log(`   ↻ Restored approval for ${approval.service} ${approval.method} (${remaining}min remaining)`);
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

  hasActiveApproval(service: string, method: string): boolean {
    const key = this.approvalKey(service, method);
    const approval = this.activeApprovals.get(key);
    if (!approval) return false;

    if (Date.now() > approval.expiresAt) {
      this.activeApprovals.delete(key);
      this.audit.revokeApprovalInDb(service, method);
      console.log(`⏰ Approval expired for service+method: ${service} ${method.toUpperCase()}`);
      return false;
    }

    return true;
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
      return true;
    }

    // Check existing approval (scoped by service + HTTP method)
    if (this.hasActiveApproval(service, method)) {
      const key = this.approvalKey(service, method);
      const approval = this.activeApprovals.get(key)!;
      const remaining = Math.round((approval.expiresAt - Date.now()) / 1000 / 60);
      console.log(`✅ Active approval for ${service} ${method.toUpperCase()} (${remaining}min remaining)`);
      return true;
    }

    // Request new approval
    console.log(`🔔 Requesting approval for: ${method} ${service}${path}`);
    const requestId = generateRequestId();

    const timeoutPromise = new Promise<{ approved: boolean; ttlSeconds: number; approvedBy: string }>((resolve) => {
      setTimeout(() => {
        resolve({ approved: false, ttlSeconds: 0, approvedBy: 'timeout' });
      }, this.approvalTimeout);
    });

    const result = await Promise.race([
      this.telegram.requestApproval(requestId, service, method, path, agentIp),
      timeoutPromise,
    ]);

    if (result.approved) {
      const approval: Approval = {
        service,
        method: method.toUpperCase(),
        approvedAt: Date.now(),
        expiresAt: Date.now() + result.ttlSeconds * 1000,
        approvedBy: result.approvedBy,
      };
      const key = this.approvalKey(service, method);
      this.activeApprovals.set(key, approval);
      this.audit.logApproval(service, method, result.approvedBy, result.ttlSeconds);
      console.log(`✅ Approved by ${result.approvedBy} for ${service} ${method.toUpperCase()} (${result.ttlSeconds / 3600}h)`);
      return true;
    }

    console.log(`❌ Denied or timed out for ${service} (by: ${result.approvedBy})`);
    return false;
  }

  revokeApproval(service: string, method?: string): boolean {
    if (method) {
      const key = this.approvalKey(service, method);
      if (this.activeApprovals.has(key)) {
        this.activeApprovals.delete(key);
        this.audit.revokeApprovalInDb(service, method);
        console.log(`🔒 Approval revoked for service+method: ${service} ${method.toUpperCase()}`);
        return true;
      }
      return false;
    }

    // Revoke all methods for this service
    const keysToDelete = [...this.activeApprovals.keys()].filter((k) => k.startsWith(`${service}::`));
    if (keysToDelete.length === 0) return false;

    for (const key of keysToDelete) {
      this.activeApprovals.delete(key);
    }
    this.audit.revokeApprovalInDb(service);
    console.log(`🔒 Approval revoked for service: ${service} (${keysToDelete.length} method(s))`);
    return true;
  }

  revokeAll(): number {
    const count = this.activeApprovals.size;
    const keys = [...this.activeApprovals.keys()];
    this.activeApprovals.clear();
    for (const key of keys) {
      const [service, method] = key.split('::');
      this.audit.revokeApprovalInDb(service, method);
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

  getStatus(): Record<string, { service: string; method: string; expiresAt: string; approvedBy: string; remainingMinutes: number }> {
    const status: Record<string, { service: string; method: string; expiresAt: string; approvedBy: string; remainingMinutes: number }> = {};
    for (const [key, approval] of this.activeApprovals) {
      if (Date.now() < approval.expiresAt) {
        status[key] = {
          service: approval.service,
          method: approval.method,
          expiresAt: new Date(approval.expiresAt).toISOString(),
          approvedBy: approval.approvedBy,
          remainingMinutes: Math.round((approval.expiresAt - Date.now()) / 1000 / 60),
        };
      }
    }
    return status;
  }
}
