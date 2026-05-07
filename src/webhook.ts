import { WebhookConfig } from './types';

/**
 * Outbound webhook notifier — fire-and-forget side channel.
 *
 * Posts a JSON payload to a user-configured URL whenever an approval is
 * requested, and (optionally) when it's resolved. Useful to integrate with
 * any external alerting/automation system that can ingest a webhook
 * (smart-home hub, paging service, internal bot, etc.).
 *
 * This channel does NOT participate in the approval decision — the user
 * still approves/denies via Telegram. The webhook is purely informational.
 *
 * Optional escalation: when `escalateAfterSeconds > 0`, the `approval_required`
 * event is delayed by that interval and only fires if the approval is still
 * pending. If Telegram resolves the request first, neither event is sent —
 * useful to reserve the webhook (and any urgent alerts it triggers) for
 * cases where the primary channel was missed.
 */
export class WebhookNotifier {
  private config: WebhookConfig;
  // requestId → timer for the deferred 'approval_required' send
  private pendingTimers: Map<string, NodeJS.Timeout> = new Map();
  // requestIds for which 'approval_required' was actually sent
  // (so we know whether to send the matching 'approval_resolved')
  private firedRequests: Set<string> = new Set();

  constructor(config: WebhookConfig) {
    this.config = config;
    const dest = new URL(config.url);
    const escalate = config.escalateAfterSeconds ?? 0;
    const escalateNote = escalate > 0 ? `, escalate after ${escalate}s` : '';
    console.log(`🪝 Webhook notifier started — ${config.method ?? 'POST'} ${dest.protocol}//${dest.host}${dest.pathname}${escalateNote}`);
  }

  notifyApprovalRequired(
    requestId: string,
    service: string,
    method: string,
    path: string,
    agentIp: string
  ): void {
    const payload = {
      event: 'approval_required',
      requestId,
      service,
      method,
      path,
      agentIp,
      timestamp: Date.now(),
      dashboardUrl: this.config.dashboardUrl,
    };

    const fire = () => {
      this.pendingTimers.delete(requestId);
      this.firedRequests.add(requestId);
      void this.send(payload);
    };

    const delay = this.config.escalateAfterSeconds ?? 0;
    if (delay > 0) {
      const timer = setTimeout(fire, delay * 1000);
      this.pendingTimers.set(requestId, timer);
    } else {
      fire();
    }
  }

  notifyApprovalResolved(requestId: string, approved: boolean, approvedBy: string): void {
    // If the escalation timer is still pending, the approval resolved before
    // the webhook fired — cancel it and skip the resolved event entirely.
    const pending = this.pendingTimers.get(requestId);
    if (pending) {
      clearTimeout(pending);
      this.pendingTimers.delete(requestId);
      return;
    }

    // Only send 'resolved' if 'required' actually fired for this requestId
    if (!this.firedRequests.delete(requestId)) return;

    if (!this.config.cancelOnResolve) return;
    void this.send({
      event: 'approval_resolved',
      requestId,
      approved,
      approvedBy,
      timestamp: Date.now(),
    });
  }

  private async send(payload: Record<string, unknown>): Promise<void> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeoutMs ?? 5000);
    try {
      const res = await fetch(this.config.url, {
        method: this.config.method ?? 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'clawguard-webhook',
          ...(this.config.headers ?? {}),
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      if (!res.ok) {
        console.warn(`⚠️ Webhook ${payload['event']} → HTTP ${res.status}`);
      } else {
        console.log(`📤 Webhook ${payload['event']} → HTTP ${res.status}`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.warn(`⚠️ Webhook ${payload['event']} failed: ${message}`);
    } finally {
      clearTimeout(timer);
    }
  }
}
