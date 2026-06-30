import { RequestMeta } from './types';

// Headers that OpenClaw (or any client) may optionally set to attach
// human-readable provenance to a request. Both are stripped before the
// request is forwarded upstream (they share the `x-clawguard` prefix, which
// every proxy path already removes), so they never leak to the real API.
export const META_HEADER_USER = 'x-clawguard-user';
export const META_HEADER_REASON = 'x-clawguard-reason';

const MAX_META_LEN = 500;

function readHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const raw = headers[name];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (value === undefined || value === null) return undefined;
  const trimmed = String(value).trim();
  if (trimmed.length === 0) return undefined;
  return trimmed.length > MAX_META_LEN ? trimmed.slice(0, MAX_META_LEN) + '…' : trimmed;
}

/**
 * Extracts optional request provenance (who/why) from the incoming headers.
 * Missing headers yield `undefined` fields — the feature is opt-in.
 */
export function extractRequestMeta(
  headers: Record<string, string | string[] | undefined>,
): RequestMeta {
  return {
    user: readHeader(headers, META_HEADER_USER),
    reason: readHeader(headers, META_HEADER_REASON),
  };
}
