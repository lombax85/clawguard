/** Credentials an SSH credential plugin may supply to the lease manager. */
export interface SshCredentials {
  readonly username: string;
  readonly privateKey: string | Buffer;
}

/** Non-target context supplied when credentials are requested. */
export interface SshCredentialContext {
  readonly serviceName: string;
  /** Aborted when broker shutdown or the credential retrieval deadline occurs. */
  readonly signal?: AbortSignal;
}

/**
 * SSH credential plugins are deliberately separate from HTTP auth plugins.
 * Host, port, host keys, and other target data are not part of this contract.
 */
export interface ISshCredentialPlugin {
  readonly name: string;

  /** Called once before the plugin is registered for a service. */
  init?(dataDir: string, config: Record<string, unknown>): Promise<void>;

  /**
   * Return only the upstream username and private key. Plugins should honor
   * ctx.signal and return a disposable Buffer copy when practical.
   */
  getCredentials(ctx: SshCredentialContext): Promise<SshCredentials>;
}
