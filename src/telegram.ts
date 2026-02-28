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

  constructor(config: TelegramConfig, audit: AuditLogger) {
    this.config = config;
    this.audit = audit;
    this.bot = new TelegramBot(config.botToken, { polling: true });
    this.setupCallbackHandler();
    this.setupPairingHandler();

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
        await this.bot.answerCallbackQuery(query.id, { text: '❌ Not paired. Send /pair <secret> first.' });
        return;
      }

      const [action, requestId] = query.data.split(':');
      const callback = this.pendingCallbacks.get(requestId);

      if (!callback) {
        await this.bot.answerCallbackQuery(query.id, { text: '⏰ Request expired' });
        return;
      }

      const userName = query.from.first_name || query.from.username || 'unknown';
      const originalText = this.pendingTexts.get(requestId) || '';
      const editOpts = { chat_id: query.message.chat.id, message_id: query.message.message_id, parse_mode: 'Markdown' as const };

      try {
        switch (action) {
          case 'approve_once':
            callback(true, 1, userName);
            await this.bot.answerCallbackQuery(query.id, { text: '✅ Approved once' });
            await this.bot.editMessageText(`${originalText}\n\n✅ *Approved once* by ${userName}`, editOpts);
            break;

          case 'approve_15m':
            callback(true, 900, userName);
            await this.bot.answerCallbackQuery(query.id, { text: '✅ Approved for 15 minutes' });
            await this.bot.editMessageText(`${originalText}\n\n✅ *Approved for 15min* by ${userName}`, editOpts);
            break;

          case 'approve_1h':
            callback(true, 3600, userName);
            await this.bot.answerCallbackQuery(query.id, { text: '✅ Approved for 1 hour' });
            await this.bot.editMessageText(`${originalText}\n\n✅ *Approved for 1h* by ${userName}`, editOpts);
            break;

          case 'approve_8h':
            callback(true, 28800, userName);
            await this.bot.answerCallbackQuery(query.id, { text: '✅ Approved for 8 hours' });
            await this.bot.editMessageText(`${originalText}\n\n✅ *Approved for 8h* by ${userName}`, editOpts);
            break;

          case 'approve_24h':
            callback(true, 86400, userName);
            await this.bot.answerCallbackQuery(query.id, { text: '✅ Approved for 24 hours' });
            await this.bot.editMessageText(`${originalText}\n\n✅ *Approved for 24h* by ${userName}`, editOpts);
            break;

          case 'deny':
            callback(false, 0, userName);
            await this.bot.answerCallbackQuery(query.id, { text: '❌ Denied' });
            await this.bot.editMessageText(`${originalText}\n\n❌ *Denied* by ${userName}`, editOpts);
            break;
        }
      } catch (err) {
        console.error(`❌ Telegram callback error: ${err instanceof Error ? err.message : err}`);
      }

      this.pendingCallbacks.delete(requestId);
      this.pendingTexts.delete(requestId);
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

      this.safeSendMessage(this.config.chatId, text, {
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
              { text: '❌ Deny', callback_data: `deny:${requestId}` },
            ],
          ],
        },
      }).catch(() => {
        // If sending fails, deny the request
        this.pendingCallbacks.delete(requestId);
        this.pendingTexts.delete(requestId);
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

  // ─── Lifecycle ─────────────────────────────────────────────

  stop(): void {
    this.bot.stopPolling();
  }
}
