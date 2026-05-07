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
 */
export class WebhookNotifier {
  private config: WebhookConfig;

  constructor(config: WebhookConfig) {
    this.config = config;
    const dest = new URL(config.url);
    console.log(`🪝 Webhook notifier started — ${config.method ?? 'POST'} ${dest.protocol}//${dest.host}${dest.pathname}`);
  }

  notifyApprovalRequired(
    requestId: string,
    service: string,
    method: string,
    path: string,
    agentIp: string
  ): void {
    void this.send({
      event: 'approval_required',
      requestId,
      service,
      method,
      path,
      agentIp,
      timestamp: Date.now(),
      dashboardUrl: this.config.dashboardUrl,
    });
  }

  notifyApprovalResolved(requestId: string, approved: boolean, approvedBy: string): void {
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
