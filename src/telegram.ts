import TelegramBot from 'node-telegram-bot-api';
import { TelegramConfig } from './types';
import { AuditLogger } from './audit';

export type ApprovalCallback = (approved: boolean, ttlSeconds: number, approvedBy: string) => void;

export class TelegramNotifier {
  private bot: TelegramBot;
  private config: TelegramConfig;
  private audit: AuditLogger;
  private pendingCallbacks: Map<string, ApprovalCallback> = new Map();
  private pendingTexts: Map<string, string> = new Map(); // requestId → original message text
  private paired: boolean = false;
  private restartingPolling = false;

  constructor(config: TelegramConfig, audit: AuditLogger) {
    this.config = config;
    this.audit = audit;
    this.bot = new TelegramBot(config.botToken, {
      polling: {
        autoStart: true,
        interval: 1000,
        params: { timeout: 10 },
      },
    });
    this.setupPollingDiagnostics();
    this.setupCallbackHandler();
    this.setupPairingHandler();
    this.startPollingWatchdog();

    // Check if the configured chatId is already paired
    if (config.pairing.enabled) {
      this.paired = audit.isPairedUser(config.chatId);
      if (this.paired) {
        console.log('📱 Telegram notifier started (paired)');
      } else {
        console.log('📱 Telegram notifier started — ⚠️  NOT PAIRED');
        console.log(`   Send /pair ${config.pairing.secret} to the bot from your Telegram account`);
      }
    } else {
      this.paired = true; // pairing disabled = always paired
      console.log('📱 Telegram notifier started (pairing disabled)');
    }
  }

  // ─── Polling diagnostics & watchdog ──────────────────────

  private setupPollingDiagnostics(): void {
    this.bot.on('polling_error', (err) => {
      console.error('❌ Telegram polling_error:', err instanceof Error ? err.stack || err.message : err);
    });
    this.bot.on('error', (err) => {
      console.error('❌ Telegram error:', err instanceof Error ? err.stack || err.message : err);
    });
    this.bot.on('webhook_error', (err) => {
      console.error('❌ Telegram webhook_error:', err instanceof Error ? err.stack || err.message : err);
    });
  }

  private startPollingWatchdog(): void {
    // Watchdog based on polling_error count, not idle time
    // Idle time is unreliable: no messages for 60s is perfectly normal
    let consecutiveErrors = 0;
    const MAX_CONSECUTIVE_ERRORS = 3;
    const RESET_AFTER_MS = 60_000;
    let lastErrorAt = 0;

    this.bot.on('polling_error', async () => {
      const now = Date.now();
      // Reset counter if last error was long ago
      if (now - lastErrorAt > RESET_AFTER_MS) {
        consecutiveErrors = 0;
      }
      lastErrorAt = now;
      consecutiveErrors++;

      if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS && !this.restartingPolling) {
        this.restartingPolling = true;
        console.warn(`⚠️ ${consecutiveErrors} consecutive polling errors — restarting polling`);

        try {
          await this.bot.stopPolling({ cancel: true });
        } catch (err) {
          console.error('❌ Telegram stopPolling error:', err instanceof Error ? err.stack || err.message : err);
        }

        try {
          await this.bot.startPolling({ restart: true });
          consecutiveErrors = 0;
          console.log('✅ Telegram polling restarted by watchdog');
        } catch (err) {
          console.error('❌ Telegram startPolling error:', err instanceof Error ? err.stack || err.message : err);
        } finally {
          this.restartingPolling = false;
        }
      }
    });
  }

  clearPendingRequest(requestId: string): void {
    this.pendingCallbacks.delete(requestId);
    this.pendingTexts.delete(requestId);
  }

  private formatCallbackError(err: unknown): string {
    const msg = err instanceof Error ? err.message : String(err);
    // Treat stale callback errors as benign (expected after restart or timeout)
    if (msg.includes('query is too old') || msg.includes('query ID is invalid')) {
      return `(stale callback, safe to ignore) ${msg}`;
    }
    return err instanceof Error ? err.stack || err.message : msg;
  }

  // ─── Pairing system ───────────────────────────────────────

  private setupPairingHandler(): void {
    this.bot.onText(/\/pair\s+(.+)/, async (msg, match) => {
      const chatId = msg.chat.id.toString();
      const providedSecret = match?.[1]?.trim();
      const userName = msg.from?.first_name || msg.from?.username || 'unknown';

      if (!this.config.pairing.enabled) {
        await this.safeSendMessage(chatId, '⚠️ Pairing is disabled in configuration.');
        return;
      }

      if (providedSecret === this.config.pairing.secret) {
        this.audit.pairUser(chatId, userName);
        this.paired = true;
        console.log(`✅ Telegram paired with user: ${userName} (chat: ${chatId})`);
        await this.safeSendMessage(chatId,
          `✅ *Paired successfully!*\n\nHi ${userName}, you are now authorized to approve/deny ClawGuard requests from this chat.`,
          { parse_mode: 'Markdown' }
        );
      } else {
        console.log(`❌ Failed pairing attempt from chat ${chatId} (wrong secret)`);
        await this.safeSendMessage(chatId, '❌ Wrong pairing secret. Check your clawguard.yaml config.');
      }
    });

    this.bot.onText(/\/unpair/, async (msg) => {
      const chatId = msg.chat.id.toString();
      this.audit.unpairUser(chatId);
      this.paired = false;
      console.log(`🔓 Telegram unpaired: chat ${chatId}`);
      await this.safeSendMessage(chatId, '🔓 Unpaired. You will no longer receive approval requests.');
    });

    this.bot.onText(/\/status/, async (msg) => {
      const chatId = msg.chat.id.toString();
      const isPaired = this.audit.isPairedUser(chatId);
      const status = isPaired ? '✅ Paired' : '❌ Not paired';
      await this.safeSendMessage(chatId, `🛡️ *ClawGuard Status*\n\nPairing: ${status}`, { parse_mode: 'Markdown' });
    });
  }

  // ─── Callback handler (approve/deny buttons) ─────────────

  private setupCallbackHandler(): void {
    this.bot.on('callback_query', async (query) => {
      if (!query.data || !query.message) return;

      const chatId = query.message.chat.id.toString();

      // Verify the user is paired
      if (this.config.pairing.enabled && !this.audit.isPairedUser(chatId)) {
        try {
          await this.bot.answerCallbackQuery(query.id, { text: '❌ Not paired. Send /pair <secret> first.' });
        } catch (err) {
          console.warn(`⚠️ Telegram callback ack error (not paired): ${this.formatCallbackError(err)}`);
        }
        return;
      }

      const [action, requestId] = query.data.split(':');
      const callback = this.pendingCallbacks.get(requestId);

      console.log(`📲 Telegram callback: action=${action} requestId=${requestId} chatId=${chatId}`);

      if (!callback) {
        try {
          await this.bot.answerCallbackQuery(query.id, { text: '⏰ Request expired' });
        } catch (err) {
          console.warn(`⚠️ Telegram callback ack error (expired): ${this.formatCallbackError(err)}`);
        }
        return;
      }

      const userName = query.from.first_name || query.from.username || 'unknown';
      const originalText = this.pendingTexts.get(requestId) || '';
      const editOpts = { chat_id: query.message.chat.id, message_id: query.message.message_id, parse_mode: 'Markdown' as const };
      let approved = false;
      let ttlSeconds = 0;
      let ackText = '⚠️ Unknown action';
      let finalText = `${originalText}\n\n⚠️ *Unknown action* by ${userName}`;

      switch (action) {
        case 'approve_once':
          approved = true;
          ttlSeconds = 1;
          ackText = '✅ Approved once';
          finalText = `${originalText}\n\n✅ *Approved once* by ${userName}`;
          break;
        case 'approve_15m':
          approved = true;
          ttlSeconds = 900;
          ackText = '✅ Approved for 15 minutes';
          finalText = `${originalText}\n\n✅ *Approved for 15min* by ${userName}`;
          break;
        case 'approve_1h':
          approved = true;
          ttlSeconds = 3600;
          ackText = '✅ Approved for 1 hour';
          finalText = `${originalText}\n\n✅ *Approved for 1h* by ${userName}`;
          break;
        case 'approve_8h':
          approved = true;
          ttlSeconds = 28800;
          ackText = '✅ Approved for 8 hours';
          finalText = `${originalText}\n\n✅ *Approved for 8h* by ${userName}`;
          break;
        case 'approve_24h':
          approved = true;
          ttlSeconds = 86400;
          ackText = '✅ Approved for 24 hours';
          finalText = `${originalText}\n\n✅ *Approved for 24h* by ${userName}`;
          break;
        case 'approve_1w':
          approved = true;
          ttlSeconds = 604800;
          ackText = '✅ Approved for 1 week';
          finalText = `${originalText}\n\n✅ *Approved for 1 week* by ${userName}`;
          break;
        case 'approve_forever':
          approved = true;
          ttlSeconds = 315360000; // 10 years ≈ forever
          ackText = '✅ Approved forever';
          finalText = `${originalText}\n\n✅ *Approved forever* by ${userName}`;
          break;
        case 'deny':
          ackText = '❌ Denied';
          finalText = `${originalText}\n\n❌ *Denied* by ${userName}`;
          break;
        default:
          break;
      }

      try {
        await this.bot.answerCallbackQuery(query.id, { text: ackText });
      } catch (err) {
        console.warn(`⚠️ Telegram callback ack error: ${this.formatCallbackError(err)}`);
      }

      try {
        callback(approved, ttlSeconds, userName);
      } catch (err) {
        console.error(`❌ Telegram approval resolve error: ${err instanceof Error ? err.stack || err.message : err}`);
      }

      try {
        await this.bot.editMessageText(finalText, editOpts);
      } catch (err) {
        console.error(`❌ Telegram callback edit error: ${err instanceof Error ? err.stack || err.message : err}`);
      } finally {
        this.clearPendingRequest(requestId);
      }
    });
  }

  // ─── Request approval ─────────────────────────────────────

  async requestApproval(
    requestId: string,
    service: string,
    method: string,
    path: string,
    agentIp: string
  ): Promise<{ approved: boolean; ttlSeconds: number; approvedBy: string }> {
    // If not paired, deny immediately
    if (this.config.pairing.enabled && !this.paired) {
      console.log('❌ Cannot request approval: Telegram bot is not paired');
      return { approved: false, ttlSeconds: 0, approvedBy: 'unpaired' };
    }

    return new Promise((resolve) => {
      const callback: ApprovalCallback = (approved, ttlSeconds, approvedBy) => {
        resolve({ approved, ttlSeconds, approvedBy });
      };

      this.pendingCallbacks.set(requestId, callback);

      const text: string = [
        `🛡️ *ClawGuard — Approval Request*`,
        ``,
        `🔹 Service: *${service}*`,
        `🔹 Method: \`${method}\``,
        `🔹 Path: \`${path}\``,
        `🔹 Agent IP: \`${agentIp}\``,
        `🔹 Time: ${new Date().toLocaleString('it-IT', { timeZone: 'Europe/Rome' })}`,
        `🔹 Request ID: \`${requestId}\``,
      ].join('\n');

      this.pendingTexts.set(requestId, text);

      (async () => {
        const sent = await this.safeSendMessage(this.config.chatId, text, {
          parse_mode: 'Markdown',
          reply_markup: {
            inline_keyboard: [
              [
                { text: '✅ Once', callback_data: `approve_once:${requestId}` },
                { text: '✅ 15m', callback_data: `approve_15m:${requestId}` },
                { text: '✅ 1h', callback_data: `approve_1h:${requestId}` },
              ],
              [
                { text: '✅ 8h', callback_data: `approve_8h:${requestId}` },
                { text: '✅ 24h', callback_data: `approve_24h:${requestId}` },
                { text: '✅ 1w', callback_data: `approve_1w:${requestId}` },
              ],
              [
                { text: '✅ Forever', callback_data: `approve_forever:${requestId}` },
                { text: '❌ Deny', callback_data: `deny:${requestId}` },
              ],
            ],
          },
        });

        if (!sent) {
          this.clearPendingRequest(requestId);
          resolve({ approved: false, ttlSeconds: 0, approvedBy: 'telegram_error' });
          return;
        }

        console.log(`📤 Telegram approval request sent: requestId=${requestId} service=${service} method=${method}`);
      })().catch((err) => {
        console.error(`❌ Telegram requestApproval error: ${err instanceof Error ? err.stack || err.message : err}`);
        this.clearPendingRequest(requestId);
        resolve({ approved: false, ttlSeconds: 0, approvedBy: 'telegram_error' });
      });
    });
  }

  // ─── Safe send (with error handling) ──────────────────────

  private async safeSendMessage(
    chatId: string,
    text: string,
    options?: TelegramBot.SendMessageOptions
  ): Promise<TelegramBot.Message | null> {
    try {
      return await this.bot.sendMessage(chatId, text, options);
    } catch (err) {
      console.error(`❌ Telegram send error: ${err instanceof Error ? err.message : err}`);
      return null;
    }
  }

  // ─── Info notifications ─────────────────────────────────────

  async notifyDiscoveryBlocked(hostname: string, clientIp: string): Promise<void> {
    if (this.config.pairing.enabled && !this.paired) return;

    const text = [
      `🔍 *Discovery: new host blocked*`,
      ``,
      `Host: \`${hostname}\``,
      `Agent IP: \`${clientIp}\``,
      `Time: ${new Date().toLocaleString('it-IT', { timeZone: 'Europe/Rome' })}`,
      ``,
      `Add to services config or set \`discoveryPolicy: silent_allow\``,
    ].join('\n');

    await this.safeSendMessage(this.config.chatId, text, { parse_mode: 'Markdown' });
  }

  // ─── Lifecycle ─────────────────────────────────────────────

  stop(): void {
    this.bot.stopPolling();
  }
}
