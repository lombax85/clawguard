import fs from 'fs';
import { SecretProvider } from './provider';
import { VaultSecretsConfig } from '../types';

const K8S_SA_TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token';
const DEFAULT_K8S_MOUNT = 'auth/kubernetes';
const DEFAULT_CACHE_TTL = 300; // 5 minutes

interface CacheEntry {
  data: Record<string, string>;
  expiresAt: number;
}

export class VaultSecretProvider implements SecretProvider {
  name = 'vault';

  private address: string;
  private namespace?: string;
  private authMethod: 'token' | 'kubernetes';
  private staticToken?: string;
  private k8sRole?: string;
  private k8sMountPath: string;
  private tlsSkipVerify: boolean;
  private cacheTTL: number;

  private clientToken: string = '';
  private cache = new Map<string, CacheEntry>();

  constructor(config: VaultSecretsConfig) {
    // Env vars take precedence, then config values
    this.address = (process.env['VAULT_ADDR'] || config.address).replace(/\/+$/, '');
    this.namespace = process.env['VAULT_NAMESPACE'] || config.namespace;
    this.tlsSkipVerify = process.env['VAULT_SKIP_VERIFY'] === 'true' || config.tlsSkipVerify || false;
    this.cacheTTL = config.cacheTTL ?? DEFAULT_CACHE_TTL;

    // Auth method: env var VAULT_TOKEN implies token auth
    const envToken = process.env['VAULT_TOKEN'];
    if (envToken) {
      this.authMethod = 'token';
      this.staticToken = envToken;
    } else {
      this.authMethod = config.auth.method;
      this.staticToken = config.auth.token;
    }

    this.k8sRole = process.env['VAULT_K8S_ROLE'] || config.auth.role;
    this.k8sMountPath = process.env['VAULT_K8S_MOUNT_PATH'] || config.auth.mountPath || DEFAULT_K8S_MOUNT;
  }

  async init(): Promise<void> {
    if (this.authMethod === 'token') {
      if (!this.staticToken) {
        throw new Error('Vault token auth requires a token (set VAULT_TOKEN or secrets.vault.auth.token)');
      }
      this.clientToken = this.staticToken;
      console.log(`   Vault: authenticated with static token at ${this.address}`);
    } else if (this.authMethod === 'kubernetes') {
      await this.loginKubernetes();
    }
  }

  async resolve(ref: string): Promise<string> {
    // ref format: "path#field"
    const hashIdx = ref.indexOf('#');
    if (hashIdx === -1) {
      throw new Error(`Invalid Vault secret ref: "${ref}" — expected "path#field"`);
    }

    const path = ref.substring(0, hashIdx);
    const field = ref.substring(hashIdx + 1);

    const data = await this.readSecret(path);
    if (!(field in data)) {
      throw new Error(`Field "${field}" not found in Vault secret at "${path}". Available: ${Object.keys(data).join(', ')}`);
    }

    return data[field];
  }

  private async readSecret(path: string): Promise<Record<string, string>> {
    // Check cache
    const cached = this.cache.get(path);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.data;
    }

    const url = `${this.address}/v1/${path}`;
    const headers: Record<string, string> = {
      'X-Vault-Token': this.clientToken,
    };
    if (this.namespace) {
      headers['X-Vault-Namespace'] = this.namespace;
    }

    const resp = await this.vaultFetch(url, { method: 'GET', headers });

    if (resp.status === 403) {
      // Token may have expired (k8s auth), try re-login once
      if (this.authMethod === 'kubernetes') {
        console.log('   Vault: token expired, re-authenticating with Kubernetes...');
        await this.loginKubernetes();
        headers['X-Vault-Token'] = this.clientToken;
        const retry = await this.vaultFetch(url, { method: 'GET', headers });
        if (!retry.ok) {
          throw new Error(`Vault read failed after re-auth: ${retry.status} ${await retry.text()}`);
        }
        return this.parseAndCache(path, await retry.json());
      }
      throw new Error(`Vault read forbidden for "${path}": check token permissions`);
    }

    if (!resp.ok) {
      throw new Error(`Vault read failed for "${path}": ${resp.status} ${await resp.text()}`);
    }

    return this.parseAndCache(path, await resp.json());
  }

  private parseAndCache(path: string, body: unknown): Record<string, string> {
    const json = body as { data?: { data?: Record<string, string>; [key: string]: unknown } };

    // KV v2: data is nested under data.data
    // KV v1: data is directly under data
    let data: Record<string, string>;
    if (json.data?.data && typeof json.data.data === 'object') {
      data = json.data.data as Record<string, string>;
    } else if (json.data) {
      const { metadata: _m, ...rest } = json.data as Record<string, unknown>;
      data = rest as Record<string, string>;
    } else {
      throw new Error(`Unexpected Vault response structure for "${path}"`);
    }

    this.cache.set(path, {
      data,
      expiresAt: Date.now() + this.cacheTTL * 1000,
    });

    return data;
  }

  private async loginKubernetes(): Promise<void> {
    if (!this.k8sRole) {
      throw new Error('Vault Kubernetes auth requires a role (set VAULT_K8S_ROLE or secrets.vault.auth.role)');
    }

    let jwt: string;
    try {
      jwt = fs.readFileSync(K8S_SA_TOKEN_PATH, 'utf-8').trim();
    } catch {
      throw new Error(`Cannot read Kubernetes SA token from ${K8S_SA_TOKEN_PATH} — are you running inside a pod?`);
    }

    const url = `${this.address}/v1/${this.k8sMountPath}/login`;
    const resp = await this.vaultFetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: this.k8sRole, jwt }),
    });

    if (!resp.ok) {
      throw new Error(`Vault Kubernetes login failed: ${resp.status} ${await resp.text()}`);
    }

    const body = await resp.json() as { auth?: { client_token?: string } };
    if (!body.auth?.client_token) {
      throw new Error('Vault Kubernetes login response missing auth.client_token');
    }

    this.clientToken = body.auth.client_token;
    console.log(`   Vault: authenticated via Kubernetes (role: ${this.k8sRole}) at ${this.address}`);
  }

  private async vaultFetch(url: string, init: RequestInit): Promise<Response> {
    // Node 18+ has global fetch; for older versions undici is available
    if (this.tlsSkipVerify) {
      // Use undici for TLS skip verify
      const { request } = await import('undici');
      const resp = await request(url, {
        method: init.method as 'GET' | 'POST',
        headers: init.headers as Record<string, string>,
        body: init.body as string | undefined,
        dispatcher: undefined, // undici handles TLS options differently
      });
      return {
        ok: resp.statusCode >= 200 && resp.statusCode < 300,
        status: resp.statusCode,
        text: () => resp.body.text(),
        json: () => resp.body.json(),
      } as unknown as Response;
    }

    return fetch(url, init);
  }
}
