import TelegramBot, {
  type InlineKeyboardMarkup,
  type Message,
  type SendMessageParams,
  type User,
} from 'node-telegram-bot-api';
import { TelegramConfig, RequestMeta, RequestApprovalInfo, FtpAccessMode } from './types';
import { AuditLogger } from './audit';
import { PairThrottle } from './pair-throttle';
import {
  TelegramPollingRecovery,
  TelegramPollingRecoveryOptions,
} from './telegram-polling-recovery';

export type ApprovalCallback = (
  approved: boolean,
  ttlSeconds: number,
  approvedBy: string,
  pathScoped: boolean,
  ftpAccessMode?: FtpAccessMode
) => void;
type SendMessageOptions = Omit<SendMessageParams, 'chat_id' | 'text'>;

/**
 * Strips characters that would break Telegram's legacy Markdown parser
 * (which has no reliable escaping) out of free-text, client-supplied values
 * so a malformed user/reason can never make the approval message fail to send.
 */
function sanitizeForTelegram(value: string): string {
  return value.replace(/[`*_[\]]/g, '').replace(/\s+/g, ' ').trim();
}

/**
 * The SSH approval keyboard intentionally has no TTL or reusable-scope
 * choices: an approval is valid only for the session currently waiting.
 */
export function buildSshSessionApprovalKeyboard(requestId: string): InlineKeyboardMarkup {
  return {
    inline_keyboard: [
      [
        { text: '✅ Approve this session', callback_data: `approve_ssh_session:${requestId}` },
        { text: '❌ Deny', callback_data: `deny:${requestId}` },
      ],
    ],
  };
}

/** FTP/FTPS approvals authorize one bounded gateway lease, never a reusable HTTP scope. */
export function buildFtpSessionApprovalKeyboard(requestId: string): InlineKeyboardMarkup {
  return {
    inline_keyboard: [
      [
        { text: '👁 Read only', callback_data: `approve_ftp_read_only:${requestId}` },
        { text: '✍️ Read/write', callback_data: `approve_ftp_read_write:${requestId}` },
      ],
      [
        { text: '❌ Deny', callback_data: `deny:${requestId}` },
      ],
    ],
  };
}

/** Renders optional provenance (who/why) as Markdown lines, or [] if absent. */
function metaLines(meta?: RequestMeta): string[] {
  if (!meta) return [];
  const lines: string[] = [];
  if (meta.user) lines.push(`👤 User: *${sanitizeForTelegram(meta.user)}*`);
  if (meta.reason) lines.push(`📝 Reason: _${sanitizeForTelegram(meta.reason)}_`);
  return lines;
}

export function approvalInfoLines(info?: RequestApprovalInfo): string[] {
  if (!info) return [];
  const lines: string[] = [];
  if (info.action) lines.push(`⚙️ Action: *${sanitizeForTelegram(info.action).slice(0, 160)}*`);
  if (info.risk) {
    const riskIcon = info.risk === 'read' ? '👁'
      : info.risk === 'session' ? '🔐'
        : info.risk === 'destructive' ? '🧨'
          : info.risk === 'write' ? '✍️' : '❓';
    lines.push(`${riskIcon} Risk: *${sanitizeForTelegram(info.risk)}*`);
  }
  if (info.target) lines.push(`🎯 Target: *${sanitizeForTelegram(info.target).slice(0, 240)}*`);
  for (const item of (info.details || []).slice(0, 10)) {
    const label = sanitizeForTelegram(item.label).slice(0, 50);
    const value = sanitizeForTelegram(item.value).slice(0, 220);
    if (label && value) lines.push(`▫️ ${label}: ${value}`);
  }
  if (info.oneTime) lines.push('⏱ Scope: *this request only*');
  return lines;
}

export interface TelegramHealth {
  paired: boolean;
  polling: boolean;
  restartingPolling: boolean;
  pendingCallbacks: number;
  consecutivePollingErrors: number;
  lastUpdateAt: string | null;
  lastCallbackAt: string | null;
  lastPollingErrorAt: string | null;
  lastPollingError: string | null;
  lastPollingRestartAt: string | null;
  lastPollingRestartOkAt: string | null;
  lastPollingRestartErrorAt: string | null;
  pollingConflict: boolean;
  pollingCircuitOpen: boolean;
  nextPollingRetryAt: string | null;
}

export interface TelegramNotifierDependencies {
  /** Test seam; production always constructs the real Telegram client. */
  bot?: TelegramBot;
  pollingRecoveryOptions?: TelegramPollingRecoveryOptions;
}

export class TelegramNotifier {
  private bot: TelegramBot;
  private config: TelegramConfig;
  private audit: AuditLogger;
  private pendingCallbacks: Map<string, ApprovalCallback> = new Map();
  private pendingTexts: Map<string, string> = new Map(); // requestId → original message text
  // Per-chat `/pair` brute-force throttle.
  private pairThrottle = new PairThrottle();
  private pollingRecovery: TelegramPollingRecovery;
  private consecutivePollingErrors = 0;
  private lastPollingErrorAt: number | null = null;
  private lastPollingError: string | null = null;
  private lastUpdateAt: number | null = null;
  private lastCallbackAt: number | null = null;

  constructor(
    config: TelegramConfig,
    audit: AuditLogger,
    dependencies: TelegramNotifierDependencies = {}
  ) {
    this.config = config;
    this.audit = audit;
    this.bot = dependencies.bot ?? new TelegramBot(config.botToken, {
      polling: {
        autoStart: true,
        interval: 1000,
        params: { timeout: 5 },
      },
      // node-telegram-bot-api 1.2 does not currently wire stopPolling's
      // cancellation signal into getUpdates. Keep the request below Docker's
      // usual 10-second shutdown grace while allowing the 5-second long poll.
      request: { timeoutMs: 8_000 },
    });
    const recoveryOptions = dependencies.pollingRecoveryOptions ?? {};
    this.pollingRecovery = new TelegramPollingRecovery(this.bot, {
      ...recoveryOptions,
      log: (level, message) => {
        recoveryOptions.log?.(level, message);
        if (level === 'error') console.error(`❌ ${message}`);
        else if (level === 'warn') console.warn(`⚠️ ${message}`);
        else console.log(`✅ ${message}`);
      },
      onStable: () => {
        this.consecutivePollingErrors = 0;
        recoveryOptions.onStable?.();
      },
      onCircuitOpen: () => {
        this.failPendingApprovals('telegram_polling_unavailable');
        recoveryOptions.onCircuitOpen?.();
      },
    });
    this.setupPollingDiagnostics();
    this.setupCallbackHandler();
    this.setupPairingHandler();

    // Pairing status is derived live from the DB (per-chat), not a mutable flag.
    if (config.pairing.enabled) {
      if (this.isConfiguredChatPaired()) {
        console.log('📱 Telegram notifier started (paired)');
      } else {
        console.log('📱 Telegram notifier started — ⚠️  NOT PAIRED');
        console.log(`   Send /pair <secret> from the configured chat (chatId=${config.chatId})`);
      }
    } else {
      console.log('📱 Telegram notifier started (pairing disabled)');
    }
  }

  // ─── Pairing helpers ──────────────────────────────────────

  /** True only for the chat configured to receive approvals (1:1 or group). */
  private isConfiguredChat(chatId: string): boolean {
    return chatId === this.config.chatId;
  }

  /**
   * Whether approvals can be requested: the configured chat must be paired
   * (or pairing is disabled). Derived from the DB so it can't be flipped by
   * a stray command from another chat.
   */
  private isConfiguredChatPaired(): boolean {
    if (!this.config.pairing.enabled) return true;
    return this.audit.isPairedUser(this.config.chatId);
  }

  // ─── Polling diagnostics & watchdog ──────────────────────

  private setupPollingDiagnostics(): void {
    this.bot.on('message', () => {
      this.lastUpdateAt = Date.now();
      this.consecutivePollingErrors = 0;
      this.pollingRecovery.noteHealthy();
    });
    this.bot.on('polling_error', (err) => {
      const message = err instanceof Error ? err.stack || err.message : String(err);
      this.lastPollingErrorAt = Date.now();
      this.lastPollingError = message;
      this.consecutivePollingErrors++;
      if (this.isPollingConflict(err)) {
        if (this.pollingRecovery.handleConflict()) {
          console.error('❌ Telegram polling conflict (409): another getUpdates request is active');
        }
      } else {
        this.pollingRecovery.notePollingError();
        console.error('❌ Telegram polling_error:', message);
      }
    });
    this.bot.on('error', (err) => {
      console.error('❌ Telegram error:', err instanceof Error ? err.stack || err.message : err);
    });
    this.bot.on('webhook_error', (err) => {
      console.error('❌ Telegram webhook_error:', err instanceof Error ? err.stack || err.message : err);
    });
  }

  private iso(timestamp: number | null): string | null {
    return timestamp ? new Date(timestamp).toISOString() : null;
  }

  private isPollingConflict(err: unknown): boolean {
    const message = err instanceof Error ? err.message : String(err);
    const response = (err as {
      response?: { status?: number; statusCode?: number };
    } | null)?.response;
    return response?.status === 409
      || response?.statusCode === 409
      || message.includes('409 Conflict');
  }

  clearPendingRequest(requestId: string): void {
    this.pendingCallbacks.delete(requestId);
    this.pendingTexts.delete(requestId);
  }

  private failPendingApprovals(approvedBy: string): void {
    const pending = [...this.pendingCallbacks.values()];
    this.pendingCallbacks.clear();
    this.pendingTexts.clear();
    for (const callback of pending) {
      try {
        callback(false, 0, approvedBy, false);
      } catch (err) {
        console.error(`❌ Telegram pending approval reject error: ${err instanceof Error ? err.stack || err.message : err}`);
      }
    }
    if (pending.length > 0) {
      console.error(`❌ Denied ${pending.length} pending approval(s): Telegram polling is unavailable`);
    }
  }

  getHealth(): TelegramHealth {
    const recovery = this.pollingRecovery.getState();
    return {
      paired: this.isConfiguredChatPaired(),
      polling: this.bot.isPolling(),
      restartingPolling: recovery.recovering,
      pendingCallbacks: this.pendingCallbacks.size,
      consecutivePollingErrors: this.consecutivePollingErrors,
      lastUpdateAt: this.iso(this.lastUpdateAt),
      lastCallbackAt: this.iso(this.lastCallbackAt),
      lastPollingErrorAt: this.iso(this.lastPollingErrorAt),
      lastPollingError: this.lastPollingError,
      lastPollingRestartAt: this.iso(recovery.lastRecoveryAt),
      lastPollingRestartOkAt: this.iso(recovery.lastRecoveryOkAt),
      lastPollingRestartErrorAt: this.iso(recovery.lastRecoveryErrorAt),
      pollingConflict: recovery.conflictCount > 0,
      pollingCircuitOpen: recovery.circuitOpen,
      nextPollingRetryAt: this.iso(recovery.nextRetryAt),
    };
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

      // Only the configured chat may pair. Silently ignore everyone else so the
      // bot is not a brute-force / identity oracle for arbitrary chats.
      if (!this.isConfiguredChat(chatId)) {
        console.log(`🚫 Ignoring /pair from non-configured chat ${chatId}`);
        return;
      }

      if (!this.config.pairing.enabled) {
        await this.safeSendMessage(chatId, '⚠️ Pairing is disabled in configuration.');
        return;
      }

      // Throttle repeated wrong attempts from the configured chat.
      if (this.pairThrottle.isThrottled(chatId)) {
        console.log(`⛔ /pair throttled for chat ${chatId} (too many failed attempts)`);
        return;
      }

      const providedSecret = match?.[1]?.trim();
      const userName = msg.from?.first_name || msg.from?.username || 'unknown';

      if (providedSecret === this.config.pairing.secret) {
        this.pairThrottle.reset(chatId);
        this.audit.pairUser(chatId, userName);
        console.log(`✅ Telegram paired with user: ${userName} (chat: ${chatId})`);
        await this.safeSendMessage(chatId,
          `✅ *Paired successfully!*\n\nHi ${userName}, this chat is now authorized to approve/deny ClawGuard requests.`,
          { parse_mode: 'Markdown' }
        );
      } else {
        this.pairThrottle.registerFailure(chatId);
        console.log(`❌ Failed pairing attempt from chat ${chatId} (wrong secret)`);
        await this.safeSendMessage(chatId, '❌ Wrong pairing secret. Check your clawguard.yaml config.');
      }
    });

    this.bot.onText(/\/unpair/, async (msg) => {
      const chatId = msg.chat.id.toString();
      // Only the configured chat can unpair itself; ignore stray commands so a
      // third party can't disrupt the approval flow.
      if (!this.isConfiguredChat(chatId)) {
        console.log(`🚫 Ignoring /unpair from non-configured chat ${chatId}`);
        return;
      }
      this.audit.unpairUser(chatId);
      console.log(`🔓 Telegram unpaired: chat ${chatId}`);
      await this.safeSendMessage(chatId, '🔓 Unpaired. You will no longer receive approval requests.');
    });

    this.bot.onText(/\/status/, async (msg) => {
      const chatId = msg.chat.id.toString();
      if (!this.isConfiguredChat(chatId)) {
        console.log(`🚫 Ignoring /status from non-configured chat ${chatId}`);
        return;
      }
      const isPaired = this.isConfiguredChatPaired();
      const status = isPaired ? '✅ Paired' : '❌ Not paired';
      const showlog = isPaired && this.audit.isShowlogEnabled(chatId) ? 'on' : 'off';
      await this.safeSendMessage(
        chatId,
        `🛡️ *ClawGuard Status*\n\nPairing: ${status}\nShowlog: ${showlog}`,
        { parse_mode: 'Markdown' },
      );
    });

    this.bot.onText(/^\/showlog(?:\s+(on|off))?/i, async (msg, match) => {
      const chatId = msg.chat.id.toString();
      if (!this.isConfiguredChat(chatId)) {
        console.log(`🚫 Ignoring /showlog from non-configured chat ${chatId}`);
        return;
      }
      if (this.config.pairing.enabled && !this.audit.isPairedUser(chatId)) {
        await this.safeSendMessage(chatId, '❌ Not paired. Send /pair <secret> first.');
        return;
      }
      const arg = match?.[1]?.toLowerCase();
      if (arg !== 'on' && arg !== 'off') {
        const current = this.audit.isShowlogEnabled(chatId) ? 'on' : 'off';
        await this.safeSendMessage(
          chatId,
          `ℹ️ Showlog is currently *${current}*. Usage: \`/showlog on\` or \`/showlog off\`.`,
          { parse_mode: 'Markdown' },
        );
        return;
      }
      this.audit.setShowlog(chatId, arg === 'on');
      const icon = arg === 'on' ? '🔔' : '🔕';
      await this.safeSendMessage(
        chatId,
        `${icon} Showlog *${arg}* — you will ${arg === 'on' ? 'now' : 'no longer'} receive info-only notifications for auto-approved calls.`,
        { parse_mode: 'Markdown' },
      );
    });
  }

  /**
   * Returns true if the given Telegram user is allowed to approve/deny.
   * When `allowedApprovers` is unset/empty, anyone in the paired chat is allowed
   * (backwards-compatible). Entries may be numeric user ids or @usernames.
   */
  private isAllowedApprover(from: User | undefined): boolean {
    const list = this.config.allowedApprovers;
    if (!list || list.length === 0) return true;
    if (!from) return false;
    const username = from.username?.toLowerCase();
    const userId = String(from.id);
    return list.some((entry) => {
      const normalized = entry.trim().replace(/^@/, '').toLowerCase();
      return normalized === userId || (!!username && normalized === username);
    });
  }

  /** Send options shared by all approval-related messages (adds the group topic thread). */
  private sendOptions(extra?: SendMessageOptions): SendMessageOptions {
    const opts: SendMessageOptions = { parse_mode: 'Markdown', ...extra };
    if (this.config.messageThreadId !== undefined) {
      opts.message_thread_id = this.config.messageThreadId;
    }
    return opts;
  }

  // ─── Callback handler (approve/deny buttons) ─────────────

  private setupCallbackHandler(): void {
    this.bot.on('callback_query', async (query) => {
      if (!query.data || !query.message) return;
      this.lastCallbackAt = Date.now();
      this.lastUpdateAt = this.lastCallbackAt;
      this.consecutivePollingErrors = 0;
      this.pollingRecovery.noteHealthy();

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

      // In a shared group, optionally restrict who may approve/deny.
      if (!this.isAllowedApprover(query.from)) {
        const who = query.from.username ? `@${query.from.username}` : (query.from.first_name || 'this user');
        console.log(`🚫 Telegram approver not allowlisted: ${who} (id=${query.from.id})`);
        try {
          await this.bot.answerCallbackQuery(query.id, { text: '🚫 You are not authorized to approve ClawGuard requests.' });
        } catch (err) {
          console.warn(`⚠️ Telegram callback ack error (not allowlisted): ${this.formatCallbackError(err)}`);
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

      // Claim the decision synchronously, before the first await below. This
      // makes a received human decision atomic with respect to circuit-open
      // draining and ensures concurrent/double taps cannot resolve it twice.
      this.pendingCallbacks.delete(requestId);

      const userName = query.from.first_name || query.from.username || 'unknown';
      const originalText = this.pendingTexts.get(requestId) || '';
      const editOpts = { chat_id: query.message.chat.id, message_id: query.message.message_id, parse_mode: 'Markdown' as const };
      let approved = false;
      let ttlSeconds = 0;
      let pathScoped = false;
      let ftpAccessMode: FtpAccessMode | undefined;
      let ackText = '⚠️ Unknown action';
      let finalText = `${originalText}\n\n⚠️ *Unknown action* by ${userName}`;

      switch (action) {
        case 'approve_ssh_session':
          approved = true;
          // Deliberately zero: SSH decisions are consumed directly by the
          // waiting session and are never stored as TTL approvals.
          ttlSeconds = 0;
          ackText = '✅ Approved for this SSH session';
          finalText = `${originalText}\n\n✅ *Approved for this SSH session* by ${userName}`;
          break;
        case 'approve_ftp_read_only':
          approved = true;
          ttlSeconds = 0;
          ftpAccessMode = 'read_only';
          ackText = '✅ Approved read-only FTP lease';
          finalText = `${originalText}\n\n✅ *Approved read-only FTP lease* by ${userName}`;
          break;
        case 'approve_ftp_read_write':
          approved = true;
          ttlSeconds = 0;
          ftpAccessMode = 'read_write';
          ackText = '✅ Approved read/write FTP lease';
          finalText = `${originalText}\n\n✅ *Approved read/write FTP lease* by ${userName}`;
          break;
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
        case 'approve_1month':
          approved = true;
          ttlSeconds = 2592000; // 30 days
          ackText = '✅ Approved for 1 month';
          finalText = `${originalText}\n\n✅ *Approved for 1 month* by ${userName}`;
          break;
        case 'approve_15m_path':
          approved = true;
          pathScoped = true;
          ttlSeconds = 900;
          ackText = '✅ Approved for 15 minutes (this path only)';
          finalText = `${originalText}\n\n✅ *Approved for 15min (path-only)* by ${userName}`;
          break;
        case 'approve_24h_path':
          approved = true;
          pathScoped = true;
          ttlSeconds = 86400;
          ackText = '✅ Approved for 24 hours (this path only)';
          finalText = `${originalText}\n\n✅ *Approved for 24h (path-only)* by ${userName}`;
          break;
        case 'approve_forever_path':
          approved = true;
          pathScoped = true;
          ttlSeconds = 315360000; // 10 years ≈ forever
          ackText = '✅ Approved forever (this path only)';
          finalText = `${originalText}\n\n✅ *Approved forever (path-only)* by ${userName}`;
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
        callback(approved, ttlSeconds, userName, pathScoped, ftpAccessMode);
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
    agentIp: string,
    meta?: RequestMeta,
    approvalInfo?: RequestApprovalInfo
  ): Promise<{ approved: boolean; ttlSeconds: number; approvedBy: string; pathScoped: boolean }> {
    // If the configured chat isn't paired, deny immediately
    if (!this.isConfiguredChatPaired()) {
      console.log('❌ Cannot request approval: configured Telegram chat is not paired');
      return { approved: false, ttlSeconds: 0, approvedBy: 'unpaired', pathScoped: false };
    }

    if (this.pollingRecovery.getState().circuitOpen) {
      console.error('❌ Cannot request approval: Telegram polling is paused after repeated 409 conflicts');
      return {
        approved: false,
        ttlSeconds: 0,
        approvedBy: 'telegram_polling_unavailable',
        pathScoped: false,
      };
    }

    return new Promise((resolve) => {
      const callback: ApprovalCallback = (approved, ttlSeconds, approvedBy, pathScoped) => {
        resolve({ approved, ttlSeconds, approvedBy, pathScoped });
      };

      this.pendingCallbacks.set(requestId, callback);

      const text: string = [
        `🛡️ *ClawGuard — Approval Request*`,
        ``,
        `🔹 Service: *${service}*`,
        `🔹 Method: \`${method}\``,
        `🔹 Path: \`${path}\``,
        ...approvalInfoLines(approvalInfo),
        ...metaLines(meta),
        `🔹 Agent IP: \`${agentIp}\``,
        `🔹 Time: ${new Date().toLocaleString('it-IT', { timeZone: 'Europe/Rome' })}`,
        `🔹 Request ID: \`${requestId}\``,
      ].join('\n');

      this.pendingTexts.set(requestId, text);

      (async () => {
        const sent = await this.safeSendMessage(this.config.chatId, text, this.sendOptions({
          reply_markup: {
            inline_keyboard: approvalInfo?.oneTime ? [
              [
                { text: '✅ Approve this request', callback_data: `approve_once:${requestId}` },
                { text: '❌ Deny', callback_data: `deny:${requestId}` },
              ],
            ] : [
              [
                { text: '✅ Once', callback_data: `approve_once:${requestId}` },
                { text: '✅ 15m', callback_data: `approve_15m:${requestId}` },
                { text: '✅ 1h', callback_data: `approve_1h:${requestId}` },
              ],
              [
                { text: '✅ 24h', callback_data: `approve_24h:${requestId}` },
                { text: '✅ 1w', callback_data: `approve_1w:${requestId}` },
                { text: '✅ 1month', callback_data: `approve_1month:${requestId}` },
              ],
              [
                { text: '🎯 15m-path', callback_data: `approve_15m_path:${requestId}` },
                { text: '🎯 24h-path', callback_data: `approve_24h_path:${requestId}` },
                { text: '🎯 forever-path', callback_data: `approve_forever_path:${requestId}` },
              ],
              [
                { text: '❌ Deny', callback_data: `deny:${requestId}` },
              ],
            ],
          },
        }));

        if (!sent) {
          this.clearPendingRequest(requestId);
          resolve({ approved: false, ttlSeconds: 0, approvedBy: 'telegram_error', pathScoped: false });
          return;
        }

        console.log(`📤 Telegram approval request sent: requestId=${requestId} service=${service} method=${method}`);
      })().catch((err) => {
        console.error(`❌ Telegram requestApproval error: ${err instanceof Error ? err.stack || err.message : err}`);
        this.clearPendingRequest(requestId);
        resolve({ approved: false, ttlSeconds: 0, approvedBy: 'telegram_error', pathScoped: false });
      });
    });
  }

  /**
   * Request a one-time SSH session decision. This is separate from the HTTP
   * approval UI so reusable TTL buttons can never be presented for SSH.
   */
  async requestSshSessionApproval(
    requestId: string,
    service: string,
    path: string,
    agentIp: string,
    meta?: RequestMeta
  ): Promise<{ approved: boolean; approvedBy: string }> {
    if (!this.isConfiguredChatPaired()) {
      console.log('❌ Cannot request SSH approval: configured Telegram chat is not paired');
      return { approved: false, approvedBy: 'unpaired' };
    }
    if (this.pollingRecovery.getState().circuitOpen) {
      console.error('❌ Cannot request SSH approval: Telegram polling is unavailable');
      return { approved: false, approvedBy: 'telegram_polling_unavailable' };
    }

    return new Promise((resolve) => {
      const callback: ApprovalCallback = (approved, _ttlSeconds, approvedBy) => {
        resolve({ approved, approvedBy });
      };

      this.pendingCallbacks.set(requestId, callback);

      const text: string = [
        `🛡️ *ClawGuard — SSH Session Approval*`,
        ``,
        `🔹 Service: *${sanitizeForTelegram(service)}*`,
        `🔹 Session: \`${sanitizeForTelegram(path)}\``,
        ...metaLines(meta),
        `🔹 Agent IP: \`${sanitizeForTelegram(agentIp)}\``,
        `🔹 Time: ${new Date().toLocaleString('it-IT', { timeZone: 'Europe/Rome' })}`,
        `🔹 Request ID: \`${requestId}\``,
        ``,
        `This approval is valid for this SSH session only.`,
      ].join('\n');

      this.pendingTexts.set(requestId, text);

      (async () => {
        const sent = await this.safeSendMessage(this.config.chatId, text, this.sendOptions({
          reply_markup: buildSshSessionApprovalKeyboard(requestId),
        }));

        if (!sent) {
          this.clearPendingRequest(requestId);
          resolve({ approved: false, approvedBy: 'telegram_error' });
          return;
        }

        console.log(`📤 Telegram SSH approval request sent: requestId=${requestId} service=${service}`);
      })().catch((err) => {
        console.error(`❌ Telegram requestSshSessionApproval error: ${err instanceof Error ? err.stack || err.message : err}`);
        this.clearPendingRequest(requestId);
        resolve({ approved: false, approvedBy: 'telegram_error' });
      });
    });
  }

  /** Request a one-time decision for one bounded FTP/FTPS gateway lease. */
  async requestFtpSessionApproval(
    requestId: string,
    service: string,
    path: string,
    agentIp: string,
    meta?: RequestMeta
  ): Promise<{ approved: boolean; approvedBy: string; accessMode?: FtpAccessMode }> {
    if (!this.isConfiguredChatPaired()) {
      console.log('❌ Cannot request FTP approval: configured Telegram chat is not paired');
      return { approved: false, approvedBy: 'unpaired' };
    }
    if (this.pollingRecovery.getState().circuitOpen) {
      console.error('❌ Cannot request FTP approval: Telegram polling is unavailable');
      return { approved: false, approvedBy: 'telegram_polling_unavailable' };
    }

    return new Promise((resolve) => {
      const callback: ApprovalCallback = (approved, _ttlSeconds, approvedBy, _pathScoped, accessMode) => {
        resolve({ approved, approvedBy, accessMode });
      };
      this.pendingCallbacks.set(requestId, callback);

      const text: string = [
        `🛡️ *ClawGuard — FTP/FTPS Lease Approval*`,
        ``,
        `🔹 Service: *${sanitizeForTelegram(service)}*`,
        `🔹 Lease: \`${sanitizeForTelegram(path)}\``,
        ...metaLines(meta),
        `🔹 Agent IP: \`${sanitizeForTelegram(agentIp)}\``,
        `🔹 Time: ${new Date().toLocaleString('it-IT', { timeZone: 'Europe/Rome' })}`,
        `🔹 Request ID: \`${requestId}\``,
        ``,
        `Choose read-only or read/write access for this one time-bounded FTP gateway lease.`,
      ].join('\n');
      this.pendingTexts.set(requestId, text);

      (async () => {
        const sent = await this.safeSendMessage(this.config.chatId, text, this.sendOptions({
          reply_markup: buildFtpSessionApprovalKeyboard(requestId),
        }));
        if (!sent) {
          this.clearPendingRequest(requestId);
          resolve({ approved: false, approvedBy: 'telegram_error' });
          return;
        }
        console.log(`📤 Telegram FTP approval request sent: requestId=${requestId} service=${service}`);
      })().catch((err) => {
        console.error(`❌ Telegram requestFtpSessionApproval error: ${err instanceof Error ? err.stack || err.message : err}`);
        this.clearPendingRequest(requestId);
        resolve({ approved: false, approvedBy: 'telegram_error' });
      });
    });
  }

  /**
   * Emit an info-only notification for a call that was auto-approved
   * (by policy or an existing approval). Gated per-chat by /showlog.
   */
  notifyAutoApproved(
    service: string,
    method: string,
    path: string,
    agentIp: string,
    reason: string,
    meta?: RequestMeta,
    approvalInfo?: RequestApprovalInfo,
  ): void {
    const chatIds = this.audit.getShowlogEnabledChatIds();
    if (chatIds.length === 0) return;

    const text = [
      `ℹ️ *ClawGuard — Auto-approved call*`,
      ``,
      `🔹 Service: *${service}*`,
      `🔹 Method: \`${method}\``,
      `🔹 Path: \`${path}\``,
      ...approvalInfoLines(approvalInfo),
      ...metaLines(meta),
      `🔹 Agent IP: \`${agentIp}\``,
      `🔹 Time: ${new Date().toLocaleString('it-IT', { timeZone: 'Europe/Rome' })}`,
      `🔹 Auto-approve: _${reason}_`,
    ].join('\n');

    for (const chatId of chatIds) {
      // fire-and-forget; errors surface via safeSendMessage logging
      this.safeSendMessage(chatId, text, { parse_mode: 'Markdown' });
    }
  }

  // ─── Safe send (with error handling) ──────────────────────

  private async safeSendMessage(
    chatId: string,
    text: string,
    options?: SendMessageOptions
  ): Promise<Message | null> {
    try {
      return await this.bot.sendMessage(chatId, text, options);
    } catch (err) {
      console.error(`❌ Telegram send error: ${err instanceof Error ? err.message : err}`);
      return null;
    }
  }

  // ─── Info notifications ─────────────────────────────────────

  async notifyDiscoveryBlocked(hostname: string, clientIp: string): Promise<void> {
    if (!this.isConfiguredChatPaired()) return;

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

  async stop(): Promise<void> {
    await this.pollingRecovery.stop();
  }
}
