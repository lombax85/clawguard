/** Credentials an FTP credential plugin may supply to an approved lease. */
export interface FtpCredentials {
  readonly username: string;
  /** Disposable copy. The broker wipes it after sending the lease to the sidecar. */
  readonly password: Buffer;
}

/** Target-independent context supplied when credentials are requested. */
export interface FtpCredentialContext {
  readonly serviceName: string;
  /** Aborted when gateway shutdown or the credential retrieval deadline occurs. */
  readonly signal?: AbortSignal;
}

/**
 * FTP credential plugins deliberately cannot choose a host, port, root, or TLS mode.
 * Those values remain fixed in the YAML service configuration.
 */
export interface IFtpCredentialPlugin {
  readonly name: string;
  init?(dataDir: string, config: Record<string, unknown>): Promise<void>;
  getCredentials(ctx: FtpCredentialContext): Promise<FtpCredentials>;
}
