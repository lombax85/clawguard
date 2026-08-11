import {
  ISshCredentialPlugin,
  SshCredentialContext,
  SshCredentials,
} from './ISshCredentialPlugin';

const MAX_PRIVATE_KEY_BYTES = 1024 * 1024;

function cloneKey(value: string | Buffer): string | Buffer {
  return Buffer.isBuffer(value) ? Buffer.from(value) : value;
}

class SshAgentKeyPlugin implements ISshCredentialPlugin {
  readonly name = 'ssh-agent-key';

  private username: string | undefined;
  private privateKey: string | Buffer | undefined;

  async init(_dataDir: string, config: Record<string, unknown>): Promise<void> {
    // Clear any prior initialization before validating a replacement config.
    this.username = undefined;
    this.privateKey = undefined;

    if (typeof config.username !== 'string' || config.username.trim().length === 0) {
      throw new Error('ssh-agent-key plugin requires config.username as a non-empty string');
    }

    const key = config.privateKey;
    if (typeof key === 'string') {
      if (key.trim().length === 0) {
        throw new Error('ssh-agent-key plugin requires a non-empty config.privateKey');
      }
      if (Buffer.byteLength(key, 'utf8') > MAX_PRIVATE_KEY_BYTES) {
        throw new Error('ssh-agent-key plugin config.privateKey is too large');
      }
    } else if (Buffer.isBuffer(key)) {
      if (key.length === 0) {
        throw new Error('ssh-agent-key plugin requires a non-empty config.privateKey');
      }
      if (key.length > MAX_PRIVATE_KEY_BYTES) {
        throw new Error('ssh-agent-key plugin config.privateKey is too large');
      }
    } else {
      throw new Error('ssh-agent-key plugin requires config.privateKey as a string or Buffer');
    }

    // The existing config layer has already resolved secret references. Keep
    // the credential in process memory only and never use the plugin data dir.
    this.username = config.username;
    this.privateKey = cloneKey(key);
  }

  async getCredentials(_ctx: SshCredentialContext): Promise<SshCredentials> {
    if (this.username === undefined || this.privateKey === undefined) {
      throw new Error('ssh-agent-key plugin has not been initialized');
    }
    return {
      username: this.username,
      privateKey: cloneKey(this.privateKey),
    };
  }
}

export function createPlugin(): ISshCredentialPlugin {
  return new SshAgentKeyPlugin();
}
