import crypto from 'crypto';
import http from 'http';
import https from 'https';
import { IAuthPlugin, AuthPluginContext, AuthPluginResult } from './IAuthPlugin';

interface AssumeRoleConfig {
  roleArn: string;
  sessionName: string;
  externalId?: string;
  stsRegion?: string;
  durationSeconds?: number;
  /** Optional override for tests/local mocks. Defaults to regional AWS STS endpoint. */
  stsEndpoint?: string;
  /** Refresh temporary credentials this many seconds before expiration. Defaults to 300. */
  refreshWindowSeconds?: number;
}

interface AwsSigV4PluginConfig {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  region: string;
  service: string;
  assumeRole?: AssumeRoleConfig;
  /** Optional deterministic timestamp for tests, e.g. 2015-08-30T12:36:00Z */
  fixedDate?: string;
}

interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  expiration?: Date;
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

function requireNestedString(config: Record<string, unknown>, key: string, label: string): string {
  const value = config[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`aws-sigv4 plugin requires ${label} as a non-empty string`);
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

function optionalNestedString(config: Record<string, unknown>, key: string, label: string): string | undefined {
  const value = config[key];
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value !== 'string') {
    throw new Error(`aws-sigv4 plugin ${label} must be a string when provided`);
  }
  return value;
}

function optionalNestedNumber(config: Record<string, unknown>, key: string, label: string): number | undefined {
  const value = config[key];
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`aws-sigv4 plugin ${label} must be a finite number when provided`);
  }
  return value;
}

function parseAssumeRoleConfig(config: Record<string, unknown>): AssumeRoleConfig | undefined {
  const raw = config['assumeRole'];
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('aws-sigv4 plugin config.assumeRole must be an object when provided');
  }

  const assumeRole = raw as Record<string, unknown>;
  return {
    roleArn: requireNestedString(assumeRole, 'roleArn', 'config.assumeRole.roleArn'),
    sessionName: requireNestedString(assumeRole, 'sessionName', 'config.assumeRole.sessionName'),
    externalId: optionalNestedString(assumeRole, 'externalId', 'config.assumeRole.externalId'),
    stsRegion: optionalNestedString(assumeRole, 'stsRegion', 'config.assumeRole.stsRegion'),
    durationSeconds: optionalNestedNumber(assumeRole, 'durationSeconds', 'config.assumeRole.durationSeconds'),
    stsEndpoint: optionalNestedString(assumeRole, 'stsEndpoint', 'config.assumeRole.stsEndpoint'),
    refreshWindowSeconds: optionalNestedNumber(assumeRole, 'refreshWindowSeconds', 'config.assumeRole.refreshWindowSeconds'),
  };
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

function signAwsRequest(params: {
  method: string;
  url: URL;
  headers: Record<string, string>;
  body: Buffer;
  credentials: AwsCredentials;
  region: string;
  service: string;
  date: Date;
}): Record<string, string> {
  const headers: Record<string, string> = { ...params.headers };

  deleteHeaderCaseInsensitive(headers, 'authorization');
  deleteHeaderCaseInsensitive(headers, 'x-amz-date');
  deleteHeaderCaseInsensitive(headers, 'x-amz-security-token');
  deleteHeaderCaseInsensitive(headers, 'x-amz-content-sha256');
  deleteHeaderCaseInsensitive(headers, 'host');

  const { amzDate, dateStamp } = formatAmzDate(params.date);
  const payloadHash = sha256Hex(params.body);

  headers['host'] = params.url.host;
  headers['x-amz-date'] = amzDate;
  headers['x-amz-content-sha256'] = payloadHash;
  if (params.credentials.sessionToken) {
    headers['x-amz-security-token'] = params.credentials.sessionToken;
  }

  const { canonical, signedHeaders } = canonicalHeaders(headers);
  const canonicalRequest = [
    params.method.toUpperCase(),
    canonicalUri(params.url),
    canonicalQueryString(params.url),
    canonical,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const credentialScope = `${dateStamp}/${params.region}/${params.service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join('\n');

  const signature = crypto
    .createHmac('sha256', signingKey(params.credentials.secretAccessKey, dateStamp, params.region, params.service))
    .update(stringToSign, 'utf8')
    .digest('hex');

  headers['authorization'] = [
    `AWS4-HMAC-SHA256 Credential=${params.credentials.accessKeyId}/${credentialScope}`,
    `SignedHeaders=${signedHeaders}`,
    `Signature=${signature}`,
  ].join(', ');

  return headers;
}

function xmlText(xml: string, tag: string): string | undefined {
  const match = xml.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`));
  return match?.[1]
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

function parseAssumeRoleCredentials(xml: string): AwsCredentials {
  const accessKeyId = xmlText(xml, 'AccessKeyId');
  const secretAccessKey = xmlText(xml, 'SecretAccessKey');
  const sessionToken = xmlText(xml, 'SessionToken');
  const expiration = xmlText(xml, 'Expiration');

  if (!accessKeyId || !secretAccessKey || !sessionToken || !expiration) {
    throw new Error('STS AssumeRole response did not contain complete temporary credentials');
  }

  const expirationDate = new Date(expiration);
  if (Number.isNaN(expirationDate.getTime())) {
    throw new Error('STS AssumeRole response contained an invalid Expiration timestamp');
  }

  return {
    accessKeyId,
    secretAccessKey,
    sessionToken,
    expiration: expirationDate,
  };
}

async function httpRequest(url: URL, method: string, headers: Record<string, string>, body: Buffer): Promise<{ statusCode: number; body: Buffer }> {
  const transport = url.protocol === 'https:' ? https : http;

  return new Promise((resolve, reject) => {
    const req = transport.request(url.toString(), { method, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => resolve({ statusCode: res.statusCode || 0, body: Buffer.concat(chunks) }));
    });

    req.on('error', reject);
    if (body.length > 0) req.write(body);
    req.end();
  });
}

class AwsSigV4Plugin implements IAuthPlugin {
  readonly name = 'aws-sigv4';
  private config!: AwsSigV4PluginConfig;
  private cachedAssumeRoleCredentials?: AwsCredentials;
  private assumeRolePromise?: Promise<AwsCredentials>;

  async init(_dataDir: string, config: Record<string, unknown>): Promise<void> {
    this.config = {
      accessKeyId: requireString(config, 'accessKeyId'),
      secretAccessKey: requireString(config, 'secretAccessKey'),
      sessionToken: optionalString(config, 'sessionToken'),
      region: requireString(config, 'region'),
      service: requireString(config, 'service'),
      assumeRole: parseAssumeRoleConfig(config),
      fixedDate: optionalString(config, 'fixedDate'),
    };

    const suffix = this.config.accessKeyId.slice(-4).padStart(this.config.accessKeyId.length, '*');
    const roleSuffix = this.config.assumeRole ? `, assumeRole=${this.config.assumeRole.roleArn}` : '';
    console.log(`   🔌 AWS SigV4 plugin initialized (service=${this.config.service}, region=${this.config.region}, accessKeyId=${suffix}${roleSuffix})`);
  }

  async rewriteRequest(ctx: AuthPluginContext): Promise<AuthPluginResult> {
    const url = new URL(ctx.upstreamUrl);
    const now = this.getNow();
    const credentials = await this.getSigningCredentials(now);
    const headers = signAwsRequest({
      method: ctx.method,
      url,
      headers: ctx.headers,
      body: ctx.body,
      credentials,
      region: this.config.region,
      service: this.config.service,
      date: now,
    });

    return {
      headers,
      body: ctx.body,
    };
  }

  private getBaseCredentials(): AwsCredentials {
    return {
      accessKeyId: this.config.accessKeyId,
      secretAccessKey: this.config.secretAccessKey,
      sessionToken: this.config.sessionToken,
    };
  }

  private getNow(): Date {
    const now = this.config.fixedDate ? new Date(this.config.fixedDate) : new Date();
    if (Number.isNaN(now.getTime())) {
      throw new Error('aws-sigv4 plugin config.fixedDate is not a valid date');
    }
    return now;
  }

  private async getSigningCredentials(now: Date): Promise<AwsCredentials> {
    if (!this.config.assumeRole) return this.getBaseCredentials();

    const refreshWindowMs = (this.config.assumeRole.refreshWindowSeconds ?? 300) * 1000;
    if (
      this.cachedAssumeRoleCredentials?.expiration &&
      this.cachedAssumeRoleCredentials.expiration.getTime() - now.getTime() > refreshWindowMs
    ) {
      return this.cachedAssumeRoleCredentials;
    }

    if (!this.assumeRolePromise) {
      this.assumeRolePromise = this.assumeRole(now)
        .then((credentials) => {
          this.cachedAssumeRoleCredentials = credentials;
          return credentials;
        })
        .finally(() => {
          this.assumeRolePromise = undefined;
        });
    }

    return this.assumeRolePromise;
  }

  private async assumeRole(now: Date): Promise<AwsCredentials> {
    const assumeRole = this.config.assumeRole;
    if (!assumeRole) return this.getBaseCredentials();

    const stsRegion = assumeRole.stsRegion || this.config.region;
    const stsEndpoint = assumeRole.stsEndpoint || `https://sts.${stsRegion}.amazonaws.com`;
    const stsUrl = new URL('/', stsEndpoint);

    const bodyParams = new URLSearchParams({
      Action: 'AssumeRole',
      Version: '2011-06-15',
      RoleArn: assumeRole.roleArn,
      RoleSessionName: assumeRole.sessionName,
    });

    if (assumeRole.externalId) bodyParams.set('ExternalId', assumeRole.externalId);
    if (assumeRole.durationSeconds !== undefined) {
      bodyParams.set('DurationSeconds', String(Math.trunc(assumeRole.durationSeconds)));
    }

    const body = Buffer.from(bodyParams.toString(), 'utf8');
    const headers = signAwsRequest({
      method: 'POST',
      url: stsUrl,
      headers: {
        'content-type': 'application/x-www-form-urlencoded; charset=utf-8',
        'content-length': String(body.length),
      },
      body,
      credentials: this.getBaseCredentials(),
      region: stsRegion,
      service: 'sts',
      date: now,
    });
    headers['content-length'] = String(body.length);

    const response = await httpRequest(stsUrl, 'POST', headers, body);
    const raw = response.body.toString('utf8');
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw new Error(`STS AssumeRole failed (HTTP ${response.statusCode}): ${raw}`);
    }

    const credentials = parseAssumeRoleCredentials(raw);
    const suffix = credentials.accessKeyId.slice(-4).padStart(credentials.accessKeyId.length, '*');
    console.log(`   🔌 [aws-sigv4] Assumed role ${assumeRole.roleArn} (temporaryAccessKeyId=${suffix}, expires=${credentials.expiration?.toISOString()})`);
    return credentials;
  }
}

/** Factory function — required by the plugin loader */
export function createPlugin(): IAuthPlugin {
  return new AwsSigV4Plugin();
}
