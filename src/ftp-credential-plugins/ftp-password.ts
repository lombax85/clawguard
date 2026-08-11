import {
  FtpCredentialContext,
  FtpCredentials,
  IFtpCredentialPlugin,
} from './IFtpCredentialPlugin';

const MAX_PASSWORD_BYTES = 16 * 1024;

class FtpPasswordPlugin implements IFtpCredentialPlugin {
  readonly name = 'ftp-password';

  private username: string | undefined;
  private password: Buffer | undefined;

  async init(_dataDir: string, config: Record<string, unknown>): Promise<void> {
    this.password?.fill(0);
    this.username = undefined;
    this.password = undefined;

    if (typeof config.username !== 'string'
      || !/^[^\0\r\n]{1,255}$/.test(config.username)) {
      throw new Error('ftp-password plugin requires config.username as a 1-255 character single-line string');
    }

    const password = config.password;
    if (typeof password !== 'string' && !Buffer.isBuffer(password)) {
      throw new Error('ftp-password plugin requires config.password as a string or Buffer');
    }
    const copy = Buffer.isBuffer(password) ? Buffer.from(password) : Buffer.from(password, 'utf8');
    if (copy.length === 0 || copy.length > MAX_PASSWORD_BYTES
      || copy.includes(0x00) || copy.includes(0x0a) || copy.includes(0x0d)) {
      copy.fill(0);
      throw new Error('ftp-password plugin password must contain 1-16384 non-NUL bytes');
    }

    this.username = config.username;
    this.password = copy;
  }

  async getCredentials(_ctx: FtpCredentialContext): Promise<FtpCredentials> {
    if (this.username === undefined || this.password === undefined) {
      throw new Error('ftp-password plugin has not been initialized');
    }
    return { username: this.username, password: Buffer.from(this.password) };
  }
}

export function createPlugin(): IFtpCredentialPlugin {
  return new FtpPasswordPlugin();
}
