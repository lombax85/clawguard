import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import http from 'http';
import https from 'https';
import readline from 'readline';
import yaml from 'js-yaml';

interface OAuth2Config {
  authorizeUrl: string;
  tokenUrl: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  scopes?: string[];
  usePkce?: boolean;
}

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
  error?: string;
  error_description?: string;
}

interface TokenData {
  access_token: string;
  refresh_token?: string;
  expires_at?: number;
  token_type?: string;
}

/**
 * Resolve the clawguard.yaml config path (same logic as main config.ts).
 */
function resolveConfigPath(): string {
  return process.env['CLAWGUARD_CONFIG']
    || process.env['AGENTGATE_CONFIG']
    || path.resolve('clawguard.yaml');
}

/**
 * Extract OAuth2 config from a service definition.
 * Supports both `type: plugin` with pluginPath=oauth2-authcode and
 * `type: oauth2_authorization_code`.
 */
function extractOAuth2Config(serviceName: string, serviceConfig: Record<string, unknown>): OAuth2Config {
  const auth = serviceConfig['auth'] as Record<string, unknown> | undefined;
  if (!auth) {
    console.error(`\u274c Service '${serviceName}' has no auth configuration.`);
    process.exit(1);
  }

  const authType = auth['type'] as string;

  let source: Record<string, unknown>;

  if (authType === 'plugin') {
    const pluginPath = auth['pluginPath'] as string | undefined;
    if (pluginPath !== 'oauth2-authcode') {
      console.error(`\u274c Service '${serviceName}' uses plugin '${pluginPath}', not oauth2-authcode.`);
      console.error(`   The 'auth' command only works with oauth2-authcode services.`);
      process.exit(1);
    }
    source = (auth['pluginConfig'] as Record<string, unknown>) || {};
  } else if (authType === 'oauth2_authorization_code') {
    source = auth;
  } else {
    console.error(`\u274c Service '${serviceName}' uses auth type '${authType}'.`);
    console.error(`   The 'auth' command only works with oauth2-authcode / oauth2_authorization_code services.`);
    process.exit(1);
  }

  // Validate required fields
  const required: (keyof OAuth2Config)[] = ['authorizeUrl', 'tokenUrl', 'clientId', 'redirectUri'];
  for (const field of required) {
    if (!source[field]) {
      console.error(`\u274c Missing required field '${field}' in service '${serviceName}' auth config.`);
      process.exit(1);
    }
  }

  return {
    authorizeUrl: source['authorizeUrl'] as string,
    tokenUrl: source['tokenUrl'] as string,
    clientId: source['clientId'] as string,
    clientSecret: source['clientSecret'] as string | undefined,
    redirectUri: source['redirectUri'] as string,
    scopes: source['scopes'] as string[] | undefined,
    usePkce: source['usePkce'] as boolean | undefined,
  };
}

/**
 * Generate PKCE code_verifier and code_challenge (S256).
 */
function generatePkce(): { codeVerifier: string; codeChallenge: string } {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  return { codeVerifier, codeChallenge };
}

/**
 * Build the authorization URL.
 */
function buildAuthorizeUrl(
  config: OAuth2Config,
  state: string,
  pkce?: { codeChallenge: string },
): string {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    state,
  });

  if (config.scopes && config.scopes.length > 0) {
    params.set('scope', config.scopes.join(' '));
  }

  if (pkce) {
    params.set('code_challenge', pkce.codeChallenge);
    params.set('code_challenge_method', 'S256');
  }

  const sep = config.authorizeUrl.includes('?') ? '&' : '?';
  return `${config.authorizeUrl}${sep}${params.toString()}`;
}

/**
 * Exchange authorization code for tokens via HTTPS POST.
 */
function exchangeCode(
  tokenUrl: string,
  body: string,
): Promise<TokenResponse> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(tokenUrl);
    const isHttps = parsed.protocol === 'https:';
    const transport = isHttps ? https : http;

    const req = transport.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
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
            return reject(new Error(`Token exchange failed (HTTP ${res.statusCode}): ${raw}`));
          }
          try {
            const data = JSON.parse(raw) as TokenResponse;
            if (data.error) {
              return reject(new Error(`Token error: ${data.error} — ${data.error_description || ''}`));
            }
            if (!data.access_token) {
              return reject(new Error(`Token response missing access_token: ${raw}`));
            }
            resolve(data);
          } catch {
            reject(new Error(`Failed to parse token response: ${raw}`));
          }
        });
      },
    );

    req.on('error', (err) => reject(new Error(`Token exchange request failed: ${err.message}`)));
    req.write(body);
    req.end();
  });
}

/**
 * Parse the authorization code from a redirect URL.
 */
function parseCodeFromUrl(urlStr: string): { code: string; state: string } | null {
  try {
    // Handle both full URL and just query string
    const url = urlStr.startsWith('http') ? new URL(urlStr) : new URL(`http://dummy${urlStr}`);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state') || '';
    if (code) {
      return { code, state };
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Start a temporary HTTP server to receive the OAuth2 callback.
 * Also reads from stdin as a fallback for pasting the redirect URL.
 */
function waitForCallback(
  redirectUri: string,
  expectedState: string,
  timeoutMs: number,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(redirectUri);
    const port = parseInt(parsed.port, 10) || 80;
    const callbackPath = parsed.pathname || '/callback';

    let settled = false;
    const settle = (err: Error | null, code?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      rl.close();
      server.close();
      if (err) reject(err);
      else resolve(code!);
    };

    // ── Timeout ────────────────────────────────────────────
    const timer = setTimeout(() => {
      settle(new Error('Timeout: no callback received within 5 minutes.'));
    }, timeoutMs);

    // ── HTTP callback server ───────────────────────────────
    const server = http.createServer((req, res) => {
      if (!req.url?.startsWith(callbackPath)) {
        res.writeHead(404);
        res.end('Not found');
        return;
      }

      const result = parseCodeFromUrl(req.url);
      if (!result) {
        res.writeHead(400);
        res.end('Missing authorization code');
        return;
      }

      if (result.state !== expectedState) {
        res.writeHead(400);
        res.end('State mismatch — possible CSRF attack');
        return;
      }

      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<html><body><h2>Authorization successful!</h2><p>You can close this window.</p></body></html>');
      settle(null, result.code);
    });

    server.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        console.log(`\n\u26a0\ufe0f  Port ${port} is in use. Paste the redirect URL below instead.`);
      }
      // Don't settle — stdin fallback still active
    });

    server.listen(port, () => {
      // server is ready
    });

    // ── Stdin fallback ─────────────────────────────────────
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.on('line', (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      const result = parseCodeFromUrl(trimmed);
      if (result) {
        if (result.state && result.state !== expectedState) {
          console.error('\u274c State mismatch — try again.');
          return;
        }
        settle(null, result.code);
      }
    });
  });
}

/**
 * Save tokens to the plugin data directory.
 */
function saveTokens(tokenData: TokenData): void {
  const tokensDir = path.resolve('data', 'plugins', 'oauth2-authcode');
  fs.mkdirSync(tokensDir, { recursive: true });
  const tokensPath = path.join(tokensDir, 'tokens.json');
  fs.writeFileSync(tokensPath, JSON.stringify(tokenData, null, 2), 'utf-8');
}

/**
 * Main auth command handler.
 */
export async function runAuth(serviceName: string): Promise<void> {
  // ── 1. Load config ───────────────────────────────────────
  const configPath = resolveConfigPath();
  if (!fs.existsSync(configPath)) {
    console.error(`\u274c Config file not found: ${configPath}`);
    console.error(`   Create one from clawguard.yaml.example`);
    process.exit(1);
  }

  const raw = fs.readFileSync(configPath, 'utf-8');
  const config = yaml.load(raw) as Record<string, unknown>;
  const services = config['services'] as Record<string, unknown> | undefined;

  if (!services || !services[serviceName]) {
    console.error(`\u274c Service '${serviceName}' not found in ${configPath}`);
    const available = services ? Object.keys(services).join(', ') : '(none)';
    console.error(`   Available services: ${available}`);
    process.exit(1);
  }

  const serviceConfig = services[serviceName] as Record<string, unknown>;
  const oauth2 = extractOAuth2Config(serviceName, serviceConfig);

  // ── 2. Generate PKCE (if enabled) ───────────────────────
  let pkce: { codeVerifier: string; codeChallenge: string } | undefined;
  if (oauth2.usePkce) {
    pkce = generatePkce();
  }

  // ── 3. Generate state ───────────────────────────────────
  const state = crypto.randomBytes(16).toString('hex');

  // ── 4. Build & display authorize URL ────────────────────
  const authorizeUrl = buildAuthorizeUrl(
    oauth2,
    state,
    pkce ? { codeChallenge: pkce.codeChallenge } : undefined,
  );

  console.log(`\n\ud83d\udd10 OAuth2 Authorization Code Flow for: ${serviceName}\n`);
  console.log(`1. Open this URL in your browser:`);
  console.log(`   ${authorizeUrl}\n`);

  const parsed = new URL(oauth2.redirectUri);
  console.log(`2. Waiting for callback on ${parsed.origin}${parsed.pathname}...`);
  console.log(`   (Or paste the full redirect URL here if the browser can't reach localhost)\n`);

  // ── 5. Wait for callback ────────────────────────────────
  const TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
  let code: string;
  try {
    code = await waitForCallback(oauth2.redirectUri, state, TIMEOUT_MS);
  } catch (err) {
    console.error(`\n\u274c ${(err as Error).message}`);
    process.exit(1);
  }

  // ── 6. Exchange code for tokens ─────────────────────────
  const exchangeParams = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: oauth2.redirectUri,
    client_id: oauth2.clientId,
  });

  if (oauth2.clientSecret) {
    exchangeParams.set('client_secret', oauth2.clientSecret);
  }
  if (pkce) {
    exchangeParams.set('code_verifier', pkce.codeVerifier);
  }

  let tokenResponse: TokenResponse;
  try {
    tokenResponse = await exchangeCode(oauth2.tokenUrl, exchangeParams.toString());
  } catch (err) {
    console.error(`\n\u274c ${(err as Error).message}`);
    process.exit(1);
  }

  // ── 7. Save tokens ─────────────────────────────────────
  const tokenData: TokenData = {
    access_token: tokenResponse.access_token,
    refresh_token: tokenResponse.refresh_token,
    expires_at: tokenResponse.expires_in
      ? Math.floor(Date.now() / 1000) + tokenResponse.expires_in
      : undefined,
    token_type: tokenResponse.token_type ?? 'Bearer',
  };

  saveTokens(tokenData);

  // ── 8. Success ──────────────────────────────────────────
  console.log(`\u2705 Authorization successful!`);
  if (tokenResponse.expires_in) {
    console.log(`   Access token expires in: ${tokenResponse.expires_in} seconds`);
  }
  console.log(`   Refresh token: ${tokenResponse.refresh_token ? 'stored' : 'not provided'}`);
  console.log(`   Service '${serviceName}' is now authenticated.\n`);
}
