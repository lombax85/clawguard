import http from 'http';
import { FtpAccessMode } from './types';

const MAX_RESPONSE_BYTES = 64 * 1024;

export interface FtpGatewayOpenRequest {
  sessionId: string;
  service: string;
  protocol: 'ftp' | 'ftps';
  accessMode: FtpAccessMode;
  clientIp: string;
  expiresAt: string;
  upstream: {
    hostname: string;
    port: number;
    resolvedAddresses: string[];
    root: string;
    tlsMode: 'none' | 'explicit' | 'implicit';
    noCheckCertificate: boolean;
  };
  upstreamCredentials: {
    username: string;
    passwordBase64: string;
  };
  gatewayCredentials: {
    username: string;
    password: string;
  };
}

export interface FtpGatewayOpenResponse {
  sessionId: string;
  controlPort: number;
  passivePortStart: number;
  passivePortEnd: number;
}

export interface FtpGatewayContract {
  openSession(request: FtpGatewayOpenRequest, signal?: AbortSignal): Promise<FtpGatewayOpenResponse>;
  closeSession(sessionId: string, signal?: AbortSignal): Promise<boolean>;
}

export class FtpGatewayClientError extends Error {}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validateOpenResponse(value: unknown): FtpGatewayOpenResponse {
  if (!isObject(value)
    || Object.keys(value).sort().join(',') !== 'controlPort,passivePortEnd,passivePortStart,sessionId'
    || typeof value.sessionId !== 'string'
    || !Number.isInteger(value.controlPort)
    || !Number.isInteger(value.passivePortStart)
    || !Number.isInteger(value.passivePortEnd)
    || (value.controlPort as number) < 1 || (value.controlPort as number) > 65535
    || (value.passivePortStart as number) < 1 || (value.passivePortStart as number) > 65535
    || (value.passivePortEnd as number) < (value.passivePortStart as number)
    || (value.passivePortEnd as number) > 65535) {
    throw new FtpGatewayClientError('FTP sidecar returned an invalid response');
  }
  return value as unknown as FtpGatewayOpenResponse;
}

export class FtpGatewayClient implements FtpGatewayContract {
  constructor(
    private readonly socketPath: string,
    private readonly timeoutMs: number
  ) {}

  private request(method: string, requestPath: string, body: unknown, signal?: AbortSignal): Promise<{
    status: number;
    body: unknown;
  }> {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const operation = new Promise<{
      status: number;
      body: unknown;
    }>((resolve, reject) => {
      const req = http.request({
        socketPath: this.socketPath,
        path: requestPath,
        method,
        signal,
        headers: payload ? {
          'content-type': 'application/json',
          'content-length': String(payload.length),
        } : undefined,
      }, (res) => {
        const chunks: Buffer[] = [];
        let length = 0;
        res.on('data', (chunk: Buffer) => {
          length += chunk.length;
          if (length > MAX_RESPONSE_BYTES) {
            req.destroy(new FtpGatewayClientError('FTP sidecar response is too large'));
            return;
          }
          chunks.push(Buffer.from(chunk));
        });
        res.on('end', () => {
          let parsed: unknown = {};
          try {
            parsed = length === 0 ? {} : JSON.parse(Buffer.concat(chunks, length).toString('utf8'));
          } catch {
            reject(new FtpGatewayClientError('FTP sidecar returned invalid JSON'));
            return;
          }
          resolve({ status: res.statusCode ?? 500, body: parsed });
        });
      });
      req.setTimeout(this.timeoutMs, () => {
        req.destroy(new FtpGatewayClientError('FTP sidecar request timed out'));
      });
      req.once('error', (err) => {
        if (err instanceof FtpGatewayClientError) reject(err);
        else reject(new FtpGatewayClientError(`FTP sidecar unavailable: ${err.message}`));
      });
      if (payload) req.end(payload);
      else req.end();
    });
    // The serialized request contains the upstream password. Once the Unix
    // socket exchange settles, do not retain another Buffer copy in ClawGuard.
    return operation.finally(() => payload?.fill(0));
  }

  async openSession(request: FtpGatewayOpenRequest, signal?: AbortSignal): Promise<FtpGatewayOpenResponse> {
    const response = await this.request('POST', '/session', request, signal);
    if (response.status !== 201) throw new FtpGatewayClientError('FTP sidecar rejected the session');
    return validateOpenResponse(response.body);
  }

  async closeSession(sessionId: string, signal?: AbortSignal): Promise<boolean> {
    const response = await this.request('DELETE', `/session/${encodeURIComponent(sessionId)}`, undefined, signal);
    if (response.status === 404) return false;
    if (response.status !== 200) throw new FtpGatewayClientError('FTP sidecar failed to close the session');
    return true;
  }
}
