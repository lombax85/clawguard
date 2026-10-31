import { HttpApprovalScope } from './types';

// Do not decode the path or collapse slashes. Ambiguous traversal/separator
// encodings cannot use a reusable scope; the request can still be approved once.
export function approvalTarget(target: string): { path: string; params: [string, string][] } | undefined {
  if (!target.startsWith('/') || /[\\#\x00-\x20\x7f]/.test(target) || /%(?![0-9a-f]{2})/i.test(target)) return;
  const at = target.indexOf('?');
  const path = at < 0 ? target : target.slice(0, at);
  try {
    // URLSearchParams replaces malformed UTF-8 with U+FFFD. Reject it before
    // parsing so distinct invalid byte sequences cannot share an approval.
    decodeURIComponent(at < 0 ? '' : target.slice(at + 1).replace(/\+/g, ' '));
    for (const part of path.split('/')) {
      const decoded = decodeURIComponent(part);
      if (decoded === '.' || decoded === '..' || /[/\\\x00-\x1f\x7f]|%[0-9a-f]{2}/i.test(decoded)) return;
    }
    return { path, params: [...new URLSearchParams(at < 0 ? '' : target.slice(at + 1))] };
  } catch { return; }
}

export function pathChoices(path: string): string[] {
  const choices = ['/'];
  for (let i = 1; i < path.length; i++) {
    if (path[i] === '/' && path[i - 1] !== '/') choices.push(path.slice(0, i));
  }
  if (path !== '/') choices.push(path);
  return [...new Set(choices)];
}

function queryValues(params: [string, string][]): string {
  // Reordering distinct keys is equivalent. Repeated values keep their order.
  const keys = [...new Set(params.map(([key]) => key))].sort();
  return JSON.stringify(keys.map(key => [key, params.filter(([name]) => name === key).map(([, value]) => value)]));
}

export function validScope(scope: HttpApprovalScope): boolean {
  return !!scope && typeof scope.path === 'string' && !scope.path.includes('?') && !!approvalTarget(scope.path)
    && typeof scope.includeSubpaths === 'boolean' && Array.isArray(scope.methods) && scope.methods.length > 0
    && scope.methods.every(method => typeof method === 'string' && /^[A-Z][A-Z0-9_-]*$/.test(method))
    && !!scope.query && ['exact', 'ignore', 'selected'].includes(scope.query.mode)
    && Array.isArray(scope.query.params) && scope.query.params.every(pair => Array.isArray(pair) && pair.length === 2 && pair.every(value => typeof value === 'string'))
    && (scope.query.mode !== 'selected' || scope.query.params.length > 0);
}

export function scopeMatches(scope: HttpApprovalScope, method: string, target: string): boolean {
  if (!validScope(scope) || !scope.methods.includes(method.toUpperCase())) return false;
  const parsed = approvalTarget(target);
  if (!parsed) return false;
  const prefix = scope.path.endsWith('/') ? scope.path : `${scope.path}/`;
  if (parsed.path !== scope.path && !(scope.includeSubpaths && parsed.path.startsWith(prefix))) return false;
  if (scope.query.mode === 'ignore') return true;
  const names = new Set(scope.query.params.map(([name]) => name));
  const actual = scope.query.mode === 'selected' ? parsed.params.filter(([name]) => names.has(name)) : parsed.params;
  return queryValues(actual) === queryValues(scope.query.params);
}

export function queryLabel(scope: HttpApprovalScope): string {
  if (scope.query.mode === 'ignore') return 'Ignored';
  const display = (value: string) => value.replace(/[\x00-\x1f\x7f]/g, char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
  const params = scope.query.params.map(([name, value]) =>
    `${display(name)}=${/token|secret|password|authorization|signature|api.?key|^key$|^code$/i.test(name) ? '[hidden]' : display(value)}`);
  return `${scope.query.mode === 'exact' ? 'All parameters' : 'Selected parameters'}: ${params.join('&') || '(none)'}`;
}

export function scopeLabel(scope: HttpApprovalScope): string {
  return `Methods: ${scope.methods.join(', ')}\nPath: ${scope.path}\nSubpaths: ${scope.includeSubpaths ? 'included' : 'excluded'}\nQuery: ${queryLabel(scope)}`;
}
