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
   * Called for each request. Must return modified headers/body
   * and optionally a new upstream URL.
   */
  rewriteRequest(ctx: AuthPluginContext): Promise<AuthPluginResult>;
}
