import { randomBytes } from 'crypto';
import { CallbackQuery, InlineKeyboardMarkup, User } from 'node-telegram-bot-api';
import { HttpApprovalScope } from './types';
import { approvalTarget, pathChoices, queryLabel, scopeLabel, SCOPE_DURATIONS, SCOPE_FOREVER } from './approval-scope';

const PREFIX = 'cgs:';
const PAGE = 7;
interface Draft {
  requestId: string;
  service: string;
  method: string;
  scope: HttpApprovalScope;
  paths: string[];
  params: [string, string][];
  methods: string[];
  deadline: number;
  messageId?: number;
  userId?: number;
  mode: 'method' | 'path';
  view: 'start' | 'summary' | 'path' | 'query' | 'params' | 'methods' | 'advanced';
  page: number;
  actions: Set<string>;
}

interface Options {
  chatId: string;
  allowed: (user: User) => boolean;
  pending: (id: string) => boolean;
  resolve: (id: string, scope: HttpApprovalScope | undefined, seconds: number, user: User, approved: boolean) => boolean;
  edit: (messageId: number, text: string, keyboard: InlineKeyboardMarkup) => Promise<unknown>;
  answer: (id: string, text: string) => Promise<unknown>;
}

/** Server-owned drafts: callbacks contain only random tokens and offered choices. */
export class TelegramScopeMenu {
  private drafts = new Map<string, Draft>();
  constructor(private readonly options: Options) {}
  owns(data: string): boolean { return data.startsWith(PREFIX); }
  clear(requestId?: string): void {
    for (const [token, draft] of this.drafts) {
      if (requestId === undefined || draft.requestId === requestId) this.drafts.delete(token);
    }
  }
  register(requestId: string, service: string, method: string, target: string,
    deadline: number, allowedMethods?: string[]): { methodWide: string; pathBased: string } | undefined {
    for (const [token, d] of this.drafts) if (d.deadline <= Date.now()) this.drafts.delete(token);
    const parsed = approvalTarget(target);
    if (!parsed || target.length > 1800 || parsed.params.length > 100 || this.drafts.size >= 1024) return;
    const token = randomBytes(12).toString('base64url');
    this.drafts.set(token, { requestId, service, method, deadline,
      paths: pathChoices(parsed.path).filter(path => path !== '/' || parsed.path === '/'), params: parsed.params,
      methods: [...new Set(allowedMethods ?? [method, 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])],
      scope: { path: parsed.path, includeSubpaths: true, methods: [method], query: { mode: 'ignore', params: [] } },
      mode: 'path', view: 'start', page: 0, actions: new Set(['open-method', 'open-path']) });
    return { methodWide: `${PREFIX}${token}:open-method`, pathBased: `${PREFIX}${token}:open-path` };
  }
  attach(requestId: string, messageId: number): void {
    for (const draft of this.drafts.values()) if (draft.requestId === requestId) draft.messageId = messageId;
  }
  private async answer(id: string, text: string): Promise<void> {
    try { await this.options.answer(id, text); } catch { /* The decision does not depend on the acknowledgement. */ }
  }
  private async render(d: Draft): Promise<void> {
    if (!this.options.pending(d.requestId) || d.deadline <= Date.now()) return;
    const token = randomBytes(12).toString('base64url');
    d.actions = new Set();
    const button = (text: string, action: string) => {
      d.actions.add(action);
      return { text: text.length > 60 ? `${text.slice(0, 57)}…` : text, callback_data: `${PREFIX}${token}:${action}` };
    };
    let rows: InlineKeyboardMarkup['inline_keyboard'] = [];
    const keys = [...new Set(d.params.map(([name]) => name))];
    const queryReady = d.scope.query.mode !== 'selected' || d.scope.query.params.length > 0;
    if (d.view === 'start') {
      rows = [[button('✅ Only this request', 'once'), button('⚡ 1h method-wide', 'quick-1h')],
        [button('Method-wide', 'open-method'), button('Path-based', 'open-path')]];
    } else if (d.view === 'summary') {
      rows = queryReady ? [['15m', '30m', '1h'], ['4h', '24h', '1w'], ['1month', 'forever']]
        .map(list => list.map(value => button(value === 'forever' ? 'Forever' : value, `grant-${value}`))) : [];
      const options = [button(`Methods: ${d.scope.methods.join(', ')} ▾`, 'view-methods')];
      if (d.mode === 'path') options.push(button(`Query: ${d.scope.query.mode === 'ignore' ? 'ignored'
        : d.scope.query.mode === 'exact' ? 'same' : 'selected'} ▾`, 'view-query'));
      rows.push(options);
      if (d.mode === 'path' && d.scope.path === d.paths.at(-1)) rows.push([button('More options', 'view-advanced')]);
      rows.push([button(d.mode === 'path' ? '← Change path' : '← Back', d.mode === 'path' ? 'view-path' : 'view-start')]);
    } else if (d.view === 'query') {
      rows = [[button('Ignore query', 'query-ignore')], [button('Same parameters and values', 'query-exact')]];
      if (keys.length) rows.push([button('Choose parameters', 'view-params')]);
    } else if (d.view === 'advanced') {
      rows = [[button(`${d.scope.includeSubpaths ? '✓ ' : ''}Include subpaths`, 'subpaths-include')],
        [button(`${d.scope.includeSubpaths ? '' : '✓ '}Exact path only`, 'subpaths-exclude')]];
    } else {
      const list = d.view === 'path' ? d.paths : d.view === 'methods' ? d.methods : keys;
      rows = list.slice(d.page * PAGE, (d.page + 1) * PAGE).map((value, i) => {
        const index = d.page * PAGE + i;
        const checked = d.view === 'methods' ? d.scope.methods.includes(value)
          : d.view === 'params' && d.scope.query.params.some(([name]) => name === value);
        let label = d.view === 'path' ? `${value}${value.endsWith('/') ? '' : '/'}*` : value;
        // Keep the distinguishing segment visible when prefixes share a long start.
        if (d.view === 'path' && label.length > 60) label = `${index + 1}. …${label.slice(-50)}`;
        return [button(`${checked ? '✓ ' : ''}${label}`, `pick-${index}`)];
      });
      const nav = [];
      if (d.page > 0) nav.push(button('← Previous', `page-${d.page - 1}`));
      if ((d.page + 1) * PAGE < list.length) nav.push(button('Next →', `page-${d.page + 1}`));
      if (nav.length) rows.push(nav);
    }
    if (d.view === 'path') rows.push([button('← Back', 'view-start')]);
    else if (d.view !== 'summary' && d.view !== 'start') rows.push([button('Done', 'view-summary')]);
    rows.push([button('❌ Deny', 'deny')]);
    const description = d.view === 'start' || d.view === 'path'
      ? `Method: ${d.method}\nRequested path: ${d.paths.at(-1)}`
      : d.view === 'query'
        ? `Methods: ${d.scope.methods.join(', ')}\nPath: ${d.scope.path}\nQuery rule: ${d.scope.query.mode === 'ignore'
          ? 'ignored' : d.scope.query.mode === 'exact' ? 'same parameters and values' : 'selected parameters'}`
        : this.description(d);
    const text = `Approval · ${d.service}\n${description}\n\n`
      + (d.view === 'path' ? `Choose a path. Each choice includes that path and all subpaths.\nQuery: ${queryLabel(d.scope)}\n` : '')
      + (d.view === 'methods' ? `The original method (${d.method}) must stay selected.\n` : '')
      + (d.view === 'params' ? 'Select at least one parameter. Use Ignore query to remove all query constraints.\n' : '')
      + (d.view === 'query' ? `Request query: ${queryLabel({ ...d.scope, query: { mode: 'exact', params: d.params } })}\n` : '')
      + (d.view === 'summary' ? (queryReady ? 'Choose a duration to approve.\n'
        : 'Select a query parameter or choose Ignore query before approving.\n') : '')
      + `Request expires at ${new Date(d.deadline).toLocaleTimeString('it-IT', { timeZone: 'Europe/Rome' })} (Europe/Rome).`;
    this.drafts.set(token, d);
    try { await this.options.edit(d.messageId!, text, { inline_keyboard: rows }); }
    catch { this.drafts.delete(token); throw new Error('Could not update approval menu'); }
  }
  private description(d: Draft): string {
    return d.mode === 'method' ? `Methods: ${d.scope.methods.join(', ')}\nPath: all\nQuery: ignored` : scopeLabel(d.scope);
  }
  async handle(query: CallbackQuery): Promise<void> {
    const [, token, action, extra] = (query.data ?? '').split(':');
    const d = this.drafts.get(token);
    if (!query.message || String(query.message.chat.id) !== this.options.chatId || !this.options.allowed(query.from)) {
      await this.answer(query.id, 'Access denied.'); return;
    }
    if (!d || extra !== undefined || !this.options.pending(d.requestId) || d.deadline <= Date.now()) {
      if (d) this.clear(d.requestId);
      await this.answer(query.id, 'Request or menu expired.'); return;
    }
    if (d.messageId !== query.message.message_id || (d.userId !== undefined && d.userId !== query.from.id)) {
      await this.answer(query.id, 'This menu belongs to another request or approver.'); return;
    }
    if (!d.actions.has(action)) { await this.answer(query.id, 'Choice not available.'); return; }
    // Claim this revision before any await. A replay cannot change the draft.
    this.drafts.delete(token);
    d.userId = query.from.id;
    if (action.startsWith('grant-') || action === 'quick-1h' || action === 'once' || action === 'deny') {
      const seconds = action === 'quick-1h' ? 3600 : SCOPE_DURATIONS[action.slice(6) as keyof typeof SCOPE_DURATIONS] ?? 0;
      const approved = action !== 'deny';
      const applied = this.options.resolve(d.requestId, action.startsWith('grant-') ? d.scope : undefined, seconds, query.from, approved);
      this.clear(d.requestId);
      await this.answer(query.id, applied ? (approved ? 'Approved.' : 'Denied.') : 'Request expired.');
      if (applied) {
        const description = action === 'quick-1h' ? `Methods: ${d.method}\nPath: all\nQuery: ignored`
          : action.startsWith('grant-') ? this.description(d) : `Method: ${d.method}\nRequested path: ${d.paths.at(-1)}`;
        try { await this.options.edit(d.messageId!, `${d.service}\n${description}\n\n`
          + (approved ? (action === 'quick-1h' ? 'Approved for 1h (method-wide).'
            : seconds === SCOPE_FOREVER ? 'Approved until revoked.'
            : seconds ? `Approved for ${action.slice(6)}.` : 'Approved for this request only.') : 'Denied.'), { inline_keyboard: [] }); }
        catch { /* The decision has already been delivered. */ }
      }
      return;
    }
    if (action === 'open-method' || action === 'open-path') {
      d.mode = action === 'open-method' ? 'method' : 'path';
      d.scope = { path: d.mode === 'method' ? '/' : d.paths.at(-1)!, includeSubpaths: true,
        methods: [d.method], query: { mode: 'ignore', params: [] } };
      d.view = d.mode === 'method' ? 'summary' : 'path'; d.page = 0;
    } else if (action.startsWith('subpaths-')) {
      d.scope.includeSubpaths = action === 'subpaths-include'; d.view = 'summary';
    } else if (action.startsWith('view-')) {
      d.view = action.slice(5) as Draft['view']; d.page = 0;
      if (d.view === 'params') d.scope.query = { mode: 'selected', params: d.scope.query.mode === 'selected' ? [...d.scope.query.params] : [] };
    } else if (action.startsWith('query-')) {
      d.scope.query = { mode: action === 'query-ignore' ? 'ignore' : 'exact', params: action === 'query-ignore' ? [] : [...d.params] };
      d.view = 'summary';
    } else if (action.startsWith('page-')) d.page = Number(action.slice(5));
    else if (action.startsWith('pick-')) {
      const index = Number(action.slice(5));
      if (d.view === 'path') {
        d.scope.path = d.paths[index];
        d.scope.includeSubpaths = true;
        d.view = 'summary';
      } else if (d.view === 'methods') {
        const method = d.methods[index];
        if (method !== d.method) d.scope.methods = d.scope.methods.includes(method)
          ? d.scope.methods.filter(item => item !== method) : [...d.scope.methods, method];
      } else {
        const name = [...new Set(d.params.map(([key]) => key))][index];
        const selected = d.scope.query.params.some(([key]) => key === name);
        if (!selected) d.scope.query.params.push(...d.params.filter(([key]) => key === name));
        else d.scope.query.params = d.scope.query.params.filter(([key]) => key !== name);
      }
    }
    try { await this.render(d); await this.answer(query.id, 'Scope updated.'); }
    catch { await this.answer(query.id, 'Menu unavailable. Approve once or deny from the original request.'); }
  }
}
