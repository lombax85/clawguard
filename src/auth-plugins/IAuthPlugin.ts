/**
 * Auth Plugin Interface for ClawGuard.
 *
 * Plugins can intercept and modify requests before they are forwarded upstream.
 * They can inject credentials, rewrite headers/body, and even override the upstream URL.
 */

/** Context passed to the plugin on each request */
export interface AuthPluginContext {
  serviceName: string;
  method: string;
  path: string;
  headers: Record<string, string>;
  body: Buffer;
  upstreamUrl: string;
  /** Directory where the plugin can persist state: data/plugins/<plugin-name>/ */
  dataDir: string;
  /** Plugin-specific config from clawguard.yaml auth.pluginConfig */
  config: Record<string, unknown>;
}

/** Result returned by the plugin after processing a request */
export interface AuthPluginResult {
  headers: Record<string, string>;
  body: Buffer;
  /** If set, overrides the upstream URL for this request */
  upstreamUrl?: string;
  /** Opaque plugin-owned state passed only to rewriteResponseHeaders. */
  requestState?: unknown;
  /** Safe audit replacement for a request body that contains injected secrets. */
  auditRequestBody?: string | null;
}

export interface AuthPluginRequestDescription {
  approvalPath?: string;
  action?: string;
  risk?: 'read' | 'session' | 'write' | 'destructive' | 'unknown';
  target?: string;
  details?: Array<{ label: string; value: string }>;
  oneTime?: boolean;
}

export interface AuthPluginResponseHeadersContext {
  serviceName: string;
  method: string;
  path: string;
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  requestState?: unknown;
  dataDir: string;
  config: Record<string, unknown>;
}

export interface AuthPluginResponseHeadersResult {
  headers: Record<string, string | string[] | undefined>;
  /** Safe audit replacement when the upstream response may contain secrets. */
  auditResponseBody?: string | null;
}

/** Interface that all auth plugins must implement */
export interface IAuthPlugin {
  /** Unique plugin name (used for logging and data directory) */
  readonly name: string;

  /**
   * Called once at startup. Use this to set up persistent state,
   * load cached tokens, etc.
   */
  init?(dataDir: string, config: Record<string, unknown>): Promise<void>;

  /**
   * Optional, side-effect-free request inspection performed before policy and
   * approval. Returned strings must contain no credentials or session tokens.
   */
  describeRequest?(ctx: AuthPluginContext): Promise<AuthPluginRequestDescription | undefined>;

  /**
   * Called for each request. Must return modified headers/body
   * and optionally a new upstream URL.
   */
  rewriteRequest(ctx: AuthPluginContext): Promise<AuthPluginResult>;

  /**
   * Optional response-header hook. It can broker upstream cookies without
   * exposing them to the caller; response bodies remain streaming.
   */
  rewriteResponseHeaders?(
    ctx: AuthPluginResponseHeadersContext
  ): Promise<AuthPluginResponseHeadersResult>;
}
