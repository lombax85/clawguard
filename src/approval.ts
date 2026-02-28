import { Approval, ServiceConfig, PolicyRule } from './types';
import { TelegramNotifier } from './telegram';
import { AuditLogger } from './audit';

let requestCounter = 0;

function generateRequestId(): string {
  return `req_${Date.now()}_${++requestCounter}`;
}

export class ApprovalManager {
  private activeApprovals: Map<string, Approval> = new Map();
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
      this.activeApprovals.set(approval.service, approval);
      const remaining = Math.round((approval.expiresAt - Date.now()) / 1000 / 60);
      console.log(`   ↻ Restored approval for ${approval.service} (${remaining}min remaining)`);
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

  hasActiveApproval(service: string): boolean {
    const approval = this.activeApprovals.get(service);
    if (!approval) return false;

    if (Date.now() > approval.expiresAt) {
      this.activeApprovals.delete(service);
      console.log(`⏰ Approval expired for service: ${service}`);
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

    // Check existing approval
    if (this.hasActiveApproval(service)) {
      const approval = this.activeApprovals.get(service)!;
      const remaining = Math.round((approval.expiresAt - Date.now()) / 1000 / 60);
      console.log(`✅ Active approval for ${service} (${remaining}min remaining)`);
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
        approvedAt: Date.now(),
        expiresAt: Date.now() + result.ttlSeconds * 1000,
        approvedBy: result.approvedBy,
      };
      this.activeApprovals.set(service, approval);
      this.audit.logApproval(service, result.approvedBy, result.ttlSeconds);
      console.log(`✅ Approved by ${result.approvedBy} for ${result.ttlSeconds / 3600}h`);
      return true;
    }

    console.log(`❌ Denied or timed out for ${service} (by: ${result.approvedBy})`);
    return false;
  }

  revokeApproval(service: string): boolean {
    if (this.activeApprovals.has(service)) {
      this.activeApprovals.delete(service);
      this.audit.revokeApprovalInDb(service);
      console.log(`🔒 Approval revoked for service: ${service}`);
      return true;
    }
    return false;
  }

  revokeAll(): number {
    const count = this.activeApprovals.size;
    const services = [...this.activeApprovals.keys()];
    this.activeApprovals.clear();
    for (const service of services) {
      this.audit.revokeApprovalInDb(service);
    }
    console.log(`🔒 All ${count} approvals revoked`);
    return count;
  }

  getActiveCount(): number {
    // Clean expired first
    for (const [service, approval] of this.activeApprovals) {
      if (Date.now() > approval.expiresAt) {
        this.activeApprovals.delete(service);
      }
    }
    return this.activeApprovals.size;
  }

  getStatus(): Record<string, { expiresAt: string; approvedBy: string; remainingMinutes: number }> {
    const status: Record<string, { expiresAt: string; approvedBy: string; remainingMinutes: number }> = {};
    for (const [service, approval] of this.activeApprovals) {
      if (Date.now() < approval.expiresAt) {
        status[service] = {
          expiresAt: new Date(approval.expiresAt).toISOString(),
          approvedBy: approval.approvedBy,
          remainingMinutes: Math.round((approval.expiresAt - Date.now()) / 1000 / 60),
        };
      }
    }
    return status;
  }
}
