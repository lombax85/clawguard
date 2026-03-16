import { SecretProvider } from './provider';

/**
 * Static secret provider — returns the value as-is.
 * This is the default behavior when no provider prefix is used.
 */
export class StaticSecretProvider implements SecretProvider {
  name = 'static';

  async resolve(ref: string): Promise<string> {
    return ref;
  }
}
