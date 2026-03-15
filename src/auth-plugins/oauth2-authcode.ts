import fs from 'fs';
import path from 'path';
import https from 'https';
import { IAuthPlugin, AuthPluginContext, AuthPluginResult } from './IAuthPlugin';

interface TokenData {
  access_token: string;
  refresh_token?: string;
  expires_at?: number; // unix timestamp in seconds
  token_type?: string;
}

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
}

/**
 * OAuth2 Authorization Code Flow plugin.
 *
 * Manages existing tokens (inject, refresh) but does NOT perform the
 * initial authorization — that will be handled by `clawguard auth <service>`.
 */
class OAuth2AuthCodePlugin implements IAuthPlugin {
  readonly name = 'oauth2-authcode';
  private dataDir = '';
  private config: Record<string, unknown> = {};
  private tokens: TokenData | null = null;

  async init(dataDir: string, config: Record<string, unknown>): Promise<void> {
    this.dataDir = dataDir;
    this.config = config;

    // Load existing tokens from disk
    const tokensPath = path.join(dataDir, 'tokens.json');
    if (fs.existsSync(tokensPath)) {
      try {
        const raw = fs.readFileSync(tokensPath, 'utf-8');
        this.tokens = JSON.parse(raw) as TokenData;
        console.log(`   🔌 [oauth2-authcode] Loaded existing tokens from ${tokensPath}`);
      } catch (err) {
        console.error(`   🔌 [oauth2-authcode] Failed to load tokens: ${err}`);
        this.tokens = null;
      }
    }
  }

  async rewriteRequest(ctx: AuthPluginContext): Promise<AuthPluginResult> {
    const headers = { ...ctx.headers };

    if (!this.tokens) {
      throw new Error('No OAuth2 tokens found. Run clawguard auth <service> to authenticate');
    }

    // Check if access_token is expired
    if (this.isExpired()) {
      if (this.tokens.refresh_token) {
        await this.refreshAccessToken();
      } else {
        throw new Error('Access token expired and no refresh token available. Run clawguard auth <service> to re-authenticate');
      }
    }

    // Inject Bearer token
    const tokenType = this.tokens.token_type || 'Bearer';
    headers['authorization'] = `${tokenType} ${this.tokens.access_token}`;

    return { headers, body: ctx.body };
  }

  private isExpired(): boolean {
    if (!this.tokens || !this.tokens.expires_at) {
      return false; // no expiry info — assume valid
    }
    // Consider expired 60s before actual expiry to avoid edge cases
    return Date.now() / 1000 >= this.tokens.expires_at - 60;
  }

  private async refreshAccessToken(): Promise<void> {
    const tokenUrl = this.config['tokenUrl'] as string | undefined;
    const clientId = this.config['clientId'] as string | undefined;
    const clientSecret = this.config['clientSecret'] as string | undefined;

    if (!tokenUrl) {
      throw new Error('oauth2-authcode: tokenUrl is required for token refresh');
    }
    if (!clientId) {
      throw new Error('oauth2-authcode: clientId is required for token refresh');
    }
    if (!this.tokens?.refresh_token) {
      throw new Error('oauth2-authcode: no refresh_token available');
    }

    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: this.tokens.refresh_token,
      client_id: clientId,
    });
    if (clientSecret) {
      params.set('client_secret', clientSecret);
    }

    console.log(`   🔌 [oauth2-authcode] Refreshing access token via ${tokenUrl}`);

    const tokenResponse = await this.postToken(tokenUrl, params.toString());

    this.tokens = {
      access_token: tokenResponse.access_token,
      refresh_token: tokenResponse.refresh_token ?? this.tokens.refresh_token,
      expires_at: tokenResponse.expires_in
        ? Math.floor(Date.now() / 1000) + tokenResponse.expires_in
        : undefined,
      token_type: tokenResponse.token_type ?? 'Bearer',
    };

    this.saveTokens();
    console.log(`   🔌 [oauth2-authcode] Token refreshed successfully`);
  }

  private saveTokens(): void {
    const tokensPath = path.join(this.dataDir, 'tokens.json');
    fs.writeFileSync(tokensPath, JSON.stringify(this.tokens, null, 2), 'utf-8');
  }

  private postToken(url: string, body: string): Promise<TokenResponse> {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);

      if (parsed.protocol !== 'https:') {
        return reject(new Error('oauth2-authcode: tokenUrl must use HTTPS'));
      }

      const req = https.request(
        {
          hostname: parsed.hostname,
          port: parsed.port || 443,
          path: parsed.pathname + parsed.search,
          method: 'POST',
          headers: {
            'content-type': 'application/x-www-form-urlencoded',
            'content-length': Buffer.byteLength(body),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => chunks.push(chunk));
          res.on('end', () => {
            const raw = Buffer.concat(chunks).toString('utf-8');
            if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
              return reject(new Error(`Token refresh failed (HTTP ${res.statusCode}): ${raw}`));
            }
            try {
              const data = JSON.parse(raw) as TokenResponse;
              if (!data.access_token) {
                return reject(new Error('Token response missing access_token'));
              }
              resolve(data);
            } catch {
              reject(new Error(`Failed to parse token response: ${raw}`));
            }
          });
        }
      );

      req.on('error', (err) => reject(new Error(`Token refresh request failed: ${err.message}`)));
      req.write(body);
      req.end();
    });
  }
}

/** Factory function — required by the plugin loader */
export function createPlugin(): IAuthPlugin {
  return new OAuth2AuthCodePlugin();
}
