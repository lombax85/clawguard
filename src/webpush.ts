import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import webpush from 'web-push';
import { WebPushConfig } from './types';
import { AuditLogger } from './audit';

export type WebPushApprovalCallback = (approved: boolean, ttlSeconds: number, approvedBy: string, pathScoped: boolean) => void;

export interface VapidKeys {
  publicKey: string;
  privateKey: string;
}

const TTL_BY_ACTION: Record<string, number> = {
  approve_once: 1,
  approve_15m: 900,
  approve_1h: 3600,
  approve_8h: 28800,
  approve_24h: 86400,
  approve_1w: 604800,
  approve_forever: 315360000, // ≈10 years
  deny: 0,
};

const SIGNED_ACTIONS = Object.keys(TTL_BY_ACTION);

/**
 * Load VAPID keys from explicit config, fall back to a persistent file,
 * and finally generate-and-persist if neither exists.
 */
export function ensureVapidKeys(keysPath: string, providedPub?: string, providedPriv?: string): VapidKeys {
  if (providedPub && providedPriv) {
    return { publicKey: providedPub, privateKey: providedPriv };
  }
  if (fs.existsSync(keysPath)) {
    try {
      const data = JSON.parse(fs.readFileSync(keysPath, 'utf-8')) as Partial<VapidKeys>;
      if (data.publicKey && data.privateKey) {
        console.log(`🔑 Loaded VAPID keys from ${keysPath}`);
        return { publicKey: data.publicKey, privateKey: data.privateKey };
      }
    } catch (err) {
      console.warn(`⚠️ Could not parse VAPID keys at ${keysPath}, regenerating: ${err instanceof Error ? err.message : err}`);
    }
  }
  const keys = webpush.generateVAPIDKeys();
  fs.mkdirSync(path.dirname(keysPath), { recursive: true });
  fs.writeFileSync(keysPath, JSON.stringify(keys, null, 2), { mode: 0o600 });
  console.log(`🔑 Generated VAPID keys at ${keysPath}`);
  return keys;
}

export class WebPushNotifier {
  private config: WebPushConfig;
  private audit: AuditLogger;
  private hmacSecret: string;
  private pendingCallbacks = new Map<string, WebPushApprovalCallback>();

  constructor(config: WebPushConfig, audit: AuditLogger) {
    if (!config.vapidPublicKey || !config.vapidPrivateKey) {
      throw new Error('WebPushNotifier: VAPID keys not initialized — call ensureVapidKeys() first');
    }
    this.config = config;
    this.audit = audit;
    webpush.setVapidDetails(config.subject, config.vapidPublicKey, config.vapidPrivateKey);
    // HMAC secret derived from the VAPID private key (which never leaves the server).
    // Used to sign approval actions so the service worker can authenticate /respond callbacks
    // without needing the dashboard PIN.
    this.hmacSecret = crypto.createHash('sha256').update('clawguard-webpush:' + config.vapidPrivateKey).digest('hex');

    const subs = audit.getWebPushSubscriptions();
    console.log(`🔔 Web Push notifier started (${subs.length} subscription${subs.length === 1 ? '' : 's'}, urgency=${config.urgency})`);
  }

  getPublicKey(): string {
    return this.config.vapidPublicKey!;
  }

  // ─── Action signatures ─────────────────────────────────────

  signAction(requestId: string, action: string): string {
    return crypto.createHmac('sha256', this.hmacSecret).update(`${requestId}:${action}`).digest('hex');
  }

  private verifyAction(requestId: string, action: string, signature: string): boolean {
    const expected = this.signAction(requestId, action);
    if (expected.length !== signature.length) return false;
    try {
      return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
    } catch {
      return false;
    }
  }

  /**
   * Called by the /respond endpoint when the service worker reports a button click.
   * Validates the signature (so only the SW that received our push can resolve), then
   * fires the registered callback to unblock the approval flow.
   */
  resolveRequest(requestId: string, action: string, signature: string, approvedBy: string = 'web-push'): { ok: boolean; reason?: string } {
    if (!SIGNED_ACTIONS.includes(action)) {
      return { ok: false, reason: 'unknown action' };
    }
    if (!this.verifyAction(requestId, action, signature)) {
      return { ok: false, reason: 'invalid signature' };
    }
    const callback = this.pendingCallbacks.get(requestId);
    if (!callback) {
      return { ok: false, reason: 'unknown or expired request' };
    }
    const ttl = TTL_BY_ACTION[action];
    const approved = action !== 'deny';
    this.pendingCallbacks.delete(requestId);
    try {
      // pathScoped is always false from Web Push for now — the SW only offers
      // the two macOS-friendly buttons (Approve 1h / Deny). Method-wide is fine.
      callback(approved, approved ? ttl : 0, approvedBy, false);
    } catch (err) {
      console.error(`❌ Web Push approval resolve error: ${err instanceof Error ? err.stack || err.message : err}`);
    }
    return { ok: true };
  }

  clearPendingRequest(requestId: string): void {
    if (!this.pendingCallbacks.has(requestId)) return;
    this.pendingCallbacks.delete(requestId);
    // Best-effort: tell every SW to close the still-open notification for this request
    this.broadcastCancel(requestId).catch(() => { /* swallow */ });
  }

  // ─── Push send ─────────────────────────────────────────────

  private async sendToSubscription(
    endpoint: string,
    p256dh: string,
    auth: string,
    payload: string,
    urgency: 'very-low' | 'low' | 'normal' | 'high'
  ): Promise<void> {
    try {
      await webpush.sendNotification(
        { endpoint, keys: { p256dh, auth } },
        payload,
        {
          TTL: this.config.ttl ?? 120,
          urgency,
        }
      );
    } catch (err: unknown) {
      const status = (err as { statusCode?: number }).statusCode;
      if (status === 404 || status === 410) {
        // Push service told us the subscription is gone — drop it from the DB
        this.audit.deleteWebPushSubscription(endpoint);
        console.log(`🗑️  Removed expired Web Push subscription (status ${status})`);
        return;
      }
      console.error(`❌ Web Push send error: ${err instanceof Error ? err.message : err}`);
    }
  }

  private async broadcastCancel(requestId: string): Promise<void> {
    const subs = this.audit.getWebPushSubscriptions();
    if (subs.length === 0) return;
    const payload = JSON.stringify({ kind: 'cancel', requestId });
    await Promise.all(
      subs.map((s) => this.sendToSubscription(s.endpoint, s.p256dh, s.auth, payload, 'normal'))
    );
  }

  /**
   * Issues a Web Push approval request. Returns a promise that resolves only
   * when /respond is called with a valid signature. Caller is responsible for
   * setting an upstream timeout (already handled by ApprovalManager).
   */
  async requestApproval(
    requestId: string,
    service: string,
    method: string,
    requestPath: string,
    agentIp: string
  ): Promise<{ approved: boolean; ttlSeconds: number; approvedBy: string; pathScoped: boolean }> {
    const subs = this.audit.getWebPushSubscriptions();
    if (subs.length === 0) {
      // No subscribers — never resolve so the other notification channel (or timeout) wins
      return new Promise<{ approved: boolean; ttlSeconds: number; approvedBy: string; pathScoped: boolean }>(() => { /* never resolves */ });
    }

    return new Promise<{ approved: boolean; ttlSeconds: number; approvedBy: string; pathScoped: boolean }>((resolve) => {
      const callback: WebPushApprovalCallback = (approved, ttlSeconds, approvedBy, pathScoped) => {
        resolve({ approved, ttlSeconds, approvedBy, pathScoped });
      };
      this.pendingCallbacks.set(requestId, callback);

      // Sign every supported action so the SW can offer richer choices later
      const signedActions: Record<string, string> = {};
      for (const a of SIGNED_ACTIONS) {
        signedActions[a] = this.signAction(requestId, a);
      }

      const payload = JSON.stringify({
        kind: 'approval',
        requestId,
        service,
        method,
        path: requestPath,
        agentIp,
        timestamp: Date.now(),
        actions: signedActions,
        requireInteraction: this.config.requireInteraction !== false,
      });

      const urgency = this.config.urgency ?? 'high';
      Promise.all(
        subs.map((s) => this.sendToSubscription(s.endpoint, s.p256dh, s.auth, payload, urgency))
      ).then(() => {
        console.log(`📤 Web Push approval sent: requestId=${requestId} service=${service} (${subs.length} subscriber${subs.length === 1 ? '' : 's'})`);
      });
    });
  }
}
