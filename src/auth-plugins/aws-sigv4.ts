import crypto from 'crypto';
import { IAuthPlugin, AuthPluginContext, AuthPluginResult } from './IAuthPlugin';

interface AwsSigV4PluginConfig {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  region: string;
  service: string;
  /** Optional deterministic timestamp for tests, e.g. 2015-08-30T12:36:00Z */
  fixedDate?: string;
}

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

const UNSIGNED_HEADERS = new Set([
  'authorization',
  'content-length',
  'expect',
  'user-agent',
]);

function requireString(config: Record<string, unknown>, key: keyof AwsSigV4PluginConfig): string {
  const value = config[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`aws-sigv4 plugin requires config.${key} as a non-empty string`);
  }
  return value;
}

function optionalString(config: Record<string, unknown>, key: keyof AwsSigV4PluginConfig): string | undefined {
  const value = config[key];
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value !== 'string') {
    throw new Error(`aws-sigv4 plugin config.${key} must be a string when provided`);
  }
  return value;
}

function sha256Hex(data: crypto.BinaryLike): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function hmac(key: crypto.BinaryLike, data: string): Buffer {
  return crypto.createHmac('sha256', key).update(data, 'utf8').digest();
}

function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`);
}

function safeDecodeURIComponent(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function canonicalUri(url: URL): string {
  const pathname = url.pathname || '/';
  return pathname
    .split('/')
    .map((segment) => encodeRfc3986(safeDecodeURIComponent(segment)))
    .join('/') || '/';
}

function canonicalQueryString(url: URL): string {
  const pairs: Array<[string, string]> = [];
  url.searchParams.forEach((value, key) => {
    pairs.push([encodeRfc3986(key), encodeRfc3986(value)]);
  });
  pairs.sort(([ak, av], [bk, bv]) => (ak === bk ? av.localeCompare(bv) : ak.localeCompare(bk)));
  return pairs.map(([key, value]) => `${key}=${value}`).join('&');
}

function normalizeHeaderValue(value: string): string {
  return value.trim().replace(/\s+/g, ' ');
}

function deleteHeaderCaseInsensitive(headers: Record<string, string>, headerName: string): void {
  const lower = headerName.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) delete headers[key];
  }
}

function isSignableHeader(name: string): boolean {
  const lower = name.toLowerCase();
  if (HOP_BY_HOP_HEADERS.has(lower)) return false;
  if (UNSIGNED_HEADERS.has(lower)) return false;
  if (lower.startsWith('x-clawguard') || lower.startsWith('x-agentgate')) return false;
  return true;
}

function canonicalHeaders(headers: Record<string, string>): { canonical: string; signedHeaders: string } {
  const normalized = new Map<string, string[]>();

  for (const [rawName, rawValue] of Object.entries(headers)) {
    const name = rawName.toLowerCase();
    if (!isSignableHeader(name)) continue;
    const values = normalized.get(name) || [];
    values.push(normalizeHeaderValue(rawValue));
    normalized.set(name, values);
  }

  const names = Array.from(normalized.keys()).sort();
  const canonical = names
    .map((name) => `${name}:${(normalized.get(name) || []).join(',')}`)
    .join('\n') + '\n';

  return {
    canonical,
    signedHeaders: names.join(';'),
  };
}

function formatAmzDate(date: Date): { amzDate: string; dateStamp: string } {
  const iso = date.toISOString().replace(/[:-]|\.\d{3}/g, '');
  return {
    amzDate: iso,
    dateStamp: iso.slice(0, 8),
  };
}

function signingKey(secretAccessKey: string, dateStamp: string, region: string, service: string): Buffer {
  const kDate = hmac(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, 'aws4_request');
}

class AwsSigV4Plugin implements IAuthPlugin {
  readonly name = 'aws-sigv4';
  private config!: AwsSigV4PluginConfig;

  async init(_dataDir: string, config: Record<string, unknown>): Promise<void> {
    this.config = {
      accessKeyId: requireString(config, 'accessKeyId'),
      secretAccessKey: requireString(config, 'secretAccessKey'),
      sessionToken: optionalString(config, 'sessionToken'),
      region: requireString(config, 'region'),
      service: requireString(config, 'service'),
      fixedDate: optionalString(config, 'fixedDate'),
    };

    const suffix = this.config.accessKeyId.slice(-4).padStart(this.config.accessKeyId.length, '*');
    console.log(`   🔌 AWS SigV4 plugin initialized (service=${this.config.service}, region=${this.config.region}, accessKeyId=${suffix})`);
  }

  async rewriteRequest(ctx: AuthPluginContext): Promise<AuthPluginResult> {
    const url = new URL(ctx.upstreamUrl);
    const headers: Record<string, string> = { ...ctx.headers };

    deleteHeaderCaseInsensitive(headers, 'authorization');
    deleteHeaderCaseInsensitive(headers, 'x-amz-date');
    deleteHeaderCaseInsensitive(headers, 'x-amz-security-token');
    deleteHeaderCaseInsensitive(headers, 'x-amz-content-sha256');
    deleteHeaderCaseInsensitive(headers, 'host');

    const now = this.config.fixedDate ? new Date(this.config.fixedDate) : new Date();
    if (Number.isNaN(now.getTime())) {
      throw new Error('aws-sigv4 plugin config.fixedDate is not a valid date');
    }

    const { amzDate, dateStamp } = formatAmzDate(now);
    const payloadHash = sha256Hex(ctx.body);

    headers['host'] = url.host;
    headers['x-amz-date'] = amzDate;
    headers['x-amz-content-sha256'] = payloadHash;
    if (this.config.sessionToken) {
      headers['x-amz-security-token'] = this.config.sessionToken;
    }

    const { canonical, signedHeaders } = canonicalHeaders(headers);
    const canonicalRequest = [
      ctx.method.toUpperCase(),
      canonicalUri(url),
      canonicalQueryString(url),
      canonical,
      signedHeaders,
      payloadHash,
    ].join('\n');

    const credentialScope = `${dateStamp}/${this.config.region}/${this.config.service}/aws4_request`;
    const stringToSign = [
      'AWS4-HMAC-SHA256',
      amzDate,
      credentialScope,
      sha256Hex(canonicalRequest),
    ].join('\n');

    const signature = crypto
      .createHmac('sha256', signingKey(this.config.secretAccessKey, dateStamp, this.config.region, this.config.service))
      .update(stringToSign, 'utf8')
      .digest('hex');

    headers['authorization'] = [
      `AWS4-HMAC-SHA256 Credential=${this.config.accessKeyId}/${credentialScope}`,
      `SignedHeaders=${signedHeaders}`,
      `Signature=${signature}`,
    ].join(', ');

    return {
      headers,
      body: ctx.body,
    };
  }
}

/** Factory function — required by the plugin loader */
export function createPlugin(): IAuthPlugin {
  return new AwsSigV4Plugin();
}
