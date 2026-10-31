import { randomBytes } from 'crypto';
import { type CallbackQuery, type InlineKeyboardMarkup, type User } from 'node-telegram-bot-api';
import { FtpAccessMode, ServiceConfig, TemporaryServiceApproval } from './types';
import { serviceApprovalHash, TemporaryApprovalController, temporaryApprovalDuration } from './temporary-approval';

const PREFIX = 'cgsvc:';
const MENU_TTL_MS = 10 * 60 * 1000;
const PAGE_SIZE = 8;
const MAX_MENUS = 128;
const DURATIONS = ['15m', '30m', '1h', '4h', '8h', '24h'];

interface Menu {
  userId: number;
  messageId?: number;
  expiresAt: number;
  page?: number;
  names?: string[];
  service?: string;
  configHash?: string;
  accessMode?: FtpAccessMode;
  grant?: string;
  grants?: Record<string, string>;
  step: 'services' | 'mode' | 'duration' | 'revoke' | 'revoke-services';
}

export interface ServiceMenuOptions {
  chatId: string;
  services: () => Record<string, ServiceConfig>;
  controller: () => TemporaryApprovalController | undefined;
  allowed: (chatId: string, user: User) => boolean;
  send: (text: string, keyboard: InlineKeyboardMarkup) => Promise<{ message_id: number } | null>;
  edit: (messageId: number, text: string, keyboard: InlineKeyboardMarkup) => Promise<unknown>;
  answer: (queryId: string, text: string) => Promise<unknown>;
}

/** Short-lived, one-use buttons bound to a chat, user, message and reviewed service. */
export class TelegramServiceMenu {
  private readonly menus = new Map<string, Menu>();

  constructor(private readonly options: ServiceMenuOptions) {}

  clear(): void { this.menus.clear(); }
  owns(data: string): boolean { return data.startsWith(PREFIX); }

  private prune(): void {
    for (const [token, menu] of this.menus) {
      if (menu.expiresAt <= Date.now()) this.menus.delete(token);
    }
    while (this.menus.size >= MAX_MENUS) this.menus.delete(this.menus.keys().next().value!);
  }

  private target(service: ServiceConfig): string {
    // Never expose userinfo or query credentials through a button prompt.
    try {
      const url = new URL(service.upstream);
      return `${url.protocol}//${url.host}${url.pathname}`.slice(0, 400);
    } catch { return 'Configured target'; }
  }

  private async answer(id: string, text: string): Promise<void> {
    try { await this.options.answer(id, text); }
    catch { console.warn('⚠️ Telegram service menu acknowledgement failed'); }
  }

  private async display(menu: Menu, text: string,
    buttons: (token: string) => InlineKeyboardMarkup): Promise<void> {
    this.prune();
    const token = randomBytes(12).toString('base64url');
    const keyboard = buttons(token);
    // Register before editing. Each screen gets a new token, so previous
    // screens and concurrent taps cannot apply a later screen's operation.
    this.menus.set(token, menu);
    try {
      if (menu.messageId !== undefined) {
        try {
          await this.options.edit(menu.messageId, text, keyboard);
          return;
        } catch {
          // An inaccessible/deleted message must not lose the next step.
          menu.messageId = undefined;
        }
      }
      const sent = await this.options.send(text, keyboard);
      if (sent) menu.messageId = sent.message_id;
      else this.menus.delete(token);
    } catch {
      this.menus.delete(token);
      console.warn('⚠️ Telegram service menu could not be displayed');
    }
  }

  private async finish(menu: Menu, text: string): Promise<void> {
    if (menu.messageId === undefined) return;
    try { await this.options.edit(menu.messageId, text, { inline_keyboard: [] }); }
    catch { console.warn('⚠️ Telegram service menu could not be closed'); }
  }

  private async showServices(menu: Menu): Promise<void> {
    const names = menu.names!;
    const page = menu.page ?? 0;
    const pages = Math.max(1, Math.ceil(names.length / PAGE_SIZE));
    const text = menu.step === 'revoke-services'
      ? `Revoke service approvals\nChoose a service with an active /allow (${page + 1}/${pages}).\nThis revokes its temporary and cached approvals.`
      : `Temporary service approval\nChoose a service (${page + 1}/${pages}).\nYou will choose its duration next.`;
    await this.display(menu,
      text, token => {
        const rows = names.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((name, index) => [{
          text: name, callback_data: `${PREFIX}${token}:service:${page * PAGE_SIZE + index}`,
        }]);
        const navigation = [];
        if (page > 0) navigation.push({ text: '← Previous', callback_data: `${PREFIX}${token}:page:${page - 1}` });
        if (page + 1 < pages) navigation.push({ text: 'Next →', callback_data: `${PREFIX}${token}:page:${page + 1}` });
        if (navigation.length) rows.push(navigation);
        rows.push([{ text: 'Cancel', callback_data: `${PREFIX}${token}:cancel` }]);
        return { inline_keyboard: rows };
      });
  }

  private async showService(menu: Menu, service: ServiceConfig): Promise<void> {
    const header = `${menu.service} · ${(service.protocol ?? 'http').toUpperCase()}\nTarget: ${this.target(service)}\n`;
    await this.display(menu, header + (menu.step === 'mode'
      ? 'Choose access for new FTP/FTPS leases. You will choose the duration next.'
      : `${menu.accessMode ? `Access: ${menu.accessMode === 'read_only' ? 'Read only' : 'Read/write'}\n` : ''}`
        + 'Choose the duration to approve all requests for this service.\nThis replaces earlier approvals and enables silent logs. Use /showlog off to mute them.'), token => ({
      inline_keyboard: menu.step === 'mode'
        ? [[{ text: '👁 Read only', callback_data: `${PREFIX}${token}:mode:read_only` },
          { text: '✍️ Read/write', callback_data: `${PREFIX}${token}:mode:read_write` }],
        [{ text: '← Services', callback_data: `${PREFIX}${token}:back` },
          { text: 'Cancel', callback_data: `${PREFIX}${token}:cancel` }]]
        : [DURATIONS.slice(0, 3).map(duration => ({ text: duration, callback_data: `${PREFIX}${token}:duration:${duration}` })),
          DURATIONS.slice(3).map(duration => ({ text: duration, callback_data: `${PREFIX}${token}:duration:${duration}` })),
          [{ text: '← Services', callback_data: `${PREFIX}${token}:back` },
            { text: 'Cancel', callback_data: `${PREFIX}${token}:cancel` }]],
    }));
  }

  async openRevoke(user: User): Promise<void> {
    const approvals = this.options.controller()?.getTemporaryServiceApprovals() ?? [];
    if (!approvals.length) {
      await this.options.send('No active temporary approvals. Use /revoke <service> to revoke cached HTTP approvals.', { inline_keyboard: [] });
      return;
    }
    await this.showServices({
      userId: user.id, expiresAt: Date.now() + MENU_TTL_MS, step: 'revoke-services', page: 0,
      names: approvals.map(item => item.service).sort(),
      grants: Object.fromEntries(approvals.map(item => [item.service, JSON.stringify(item)])),
    });
  }

  async open(user: User, name?: string): Promise<void> {
    const services = this.options.services();
    const menu: Menu = { userId: user.id, expiresAt: Date.now() + MENU_TTL_MS, step: 'services',
      names: Object.keys(services).sort(), page: 0 };
    if (name !== undefined) {
      if (!Object.hasOwn(services, name)) throw new Error(`Unknown service: ${name}`);
      const service = services[name];
      menu.service = name;
      menu.configHash = serviceApprovalHash(service);
      menu.step = service.protocol === 'ftp' || service.protocol === 'ftps' ? 'mode' : 'duration';
      await this.showService(menu, service);
    } else {
      if (!menu.names!.length) throw new Error('No configured services.');
      await this.showServices(menu);
    }
  }

  async showGranted(approval: TemporaryServiceApproval, service: ServiceConfig, user: User, messageId?: number): Promise<void> {
    const menu: Menu = { userId: user.id, messageId, expiresAt: approval.expiresAt, step: 'revoke',
      service: approval.service, grant: JSON.stringify(approval) };
    await this.display(menu,
      `${approval.service}: temporary approval active until ${new Date(approval.expiresAt).toLocaleString('it-IT', { timeZone: 'Europe/Rome' })} (Europe/Rome).\n`
      + `Target: ${this.target(service)}\n${approval.accessMode ? `Access: ${approval.accessMode}\n` : ''}`
      + `Earlier approvals were replaced. Showlog is on; use /showlog off to mute logs.\nRevoke: /revoke ${approval.service}`,
      token => ({ inline_keyboard: [[{ text: '🔒 Revoke now', callback_data: `${PREFIX}${token}:revoke` }]] }));
  }

  /** Returns true when the callback belongs to this menu, including stale buttons. */
  async handle(query: CallbackQuery): Promise<boolean> {
    if (!query.data?.startsWith(PREFIX)) return false;
    const chatId = String(query.message?.chat.id ?? '');
    if (!query.message || chatId !== this.options.chatId || !this.options.allowed(chatId, query.from)) {
      await this.answer(query.id, 'Access denied. Use an allowed account in the paired chat.');
      return true;
    }
    const parts = query.data.split(':');
    const [, token, action, value] = parts;
    const menu = this.menus.get(token);
    if (!menu || menu.expiresAt <= Date.now() || parts.length > 4) {
      if (menu?.expiresAt && menu.expiresAt <= Date.now()) this.menus.delete(token);
      await this.answer(query.id, 'Menu expired. Send /allow or /revoke to open a new menu.');
      return true;
    }
    if (menu.userId !== query.from.id || menu.messageId !== query.message.message_id) {
      await this.answer(query.id, 'Open your own menu with /allow or /revoke.');
      return true;
    }
    const controller = this.options.controller();
    if (!controller) { await this.answer(query.id, 'Service commands are not ready.'); return true; }
    const number = value !== undefined && /^\d+$/.test(value) ? Number(value) : -1;
    const serviceList = menu.step === 'services' || menu.step === 'revoke-services';
    const valid = (action === 'cancel' && value === undefined && menu.step !== 'revoke')
      || (action === 'back' && value === undefined && (menu.step === 'mode' || menu.step === 'duration'))
      || (action === 'page' && serviceList && number >= 0 && number < Math.ceil(menu.names!.length / PAGE_SIZE))
      || (action === 'service' && serviceList && number >= (menu.page ?? 0) * PAGE_SIZE
        && number < Math.min(((menu.page ?? 0) + 1) * PAGE_SIZE, menu.names!.length))
      || (action === 'mode' && menu.step === 'mode' && ['read_only', 'read_write'].includes(value))
      || (action === 'duration' && menu.step === 'duration' && DURATIONS.includes(value))
      || (action === 'revoke' && menu.step === 'revoke' && value === undefined);
    if (!valid) { await this.answer(query.id, 'This choice is not available.'); return true; }

    // Claim before any await: a double tap can never grant twice or extend expiry.
    this.menus.delete(token);
    try {
      if (action === 'cancel') {
        await this.answer(query.id, 'Cancelled.');
        await this.finish(menu, menu.step === 'revoke-services' ? 'Revocation cancelled. Approvals unchanged.' : 'Temporary approval cancelled.');
        return true;
      }
      if (action === 'page') {
        await this.answer(query.id, 'Choose a service.');
        await this.showServices({ ...menu, page: number });
        return true;
      }
      if (action === 'back') {
        await this.answer(query.id, 'Choose a service.');
        await this.showServices({ ...menu, step: 'services', service: undefined, configHash: undefined, accessMode: undefined });
        return true;
      }
      if (action === 'revoke' || (action === 'service' && menu.step === 'revoke-services')) {
        const name = action === 'revoke' ? menu.service! : menu.names![number];
        const expected = action === 'revoke' ? menu.grant : menu.grants![name];
        const current = controller.getTemporaryServiceApprovals().find(item => item.service === name);
        if (!current || JSON.stringify(current) !== expected) {
          await this.answer(query.id, 'This approval expired or was replaced. Open /revoke again.');
          await this.finish(menu, 'This approval expired or was replaced. Open /revoke again.');
          return true;
        }
        controller.revokeApproval(name);
        await this.answer(query.id, 'Approval revoked.');
        await this.finish(menu, `Approvals revoked for ${name}. Existing sessions keep their normal lifetime.`);
        return true;
      }
      const name = action === 'service' ? menu.names![number] : menu.service!;
      const services = this.options.services();
      if (!Object.hasOwn(services, name) || (menu.configHash && serviceApprovalHash(services[name]) !== menu.configHash)) {
        await this.answer(query.id, 'Service changed. Send /allow to review it again.');
        await this.finish(menu, 'Service changed. Send /allow to review it again.');
        return true;
      }
      const service = services[name];
      if (action === 'duration') {
        const approval = controller.grantTemporaryServiceApproval(name, service, temporaryApprovalDuration(value),
          `${query.from.username || query.from.first_name || 'Telegram user'} (${query.from.id})`, chatId, menu.accessMode);
        await this.answer(query.id, `Approved for ${value}. Silent logs enabled.`);
        await this.showGranted(approval, service, query.from, menu.messageId);
      } else {
        const step = action === 'mode' ? 'duration'
          : service.protocol === 'ftp' || service.protocol === 'ftps' ? 'mode' : 'duration';
        const next: Menu = { ...menu, service: name, configHash: serviceApprovalHash(service), step,
          accessMode: action === 'mode' ? value as FtpAccessMode : undefined };
        await this.answer(query.id, step === 'mode' ? 'Choose the access mode.' : 'Choose the duration.');
        await this.showService(next, service);
      }
    } catch {
      await this.answer(query.id, 'Command failed. Check /status before trying again.');
      await this.finish(menu, 'Command failed. Check /status before trying again.');
    }
    return true;
  }
}
