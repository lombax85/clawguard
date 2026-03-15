import { SecretsConfig } from '../types';
import { StaticSecretProvider } from './static';
import { VaultSecretProvider } from './vault';

export interface SecretProvider {
  name: string;
  resolve(ref: string): Promise<string>;
}

// Secret reference format: "provider:path#field"
// Examples:
//   "vault:secret/data/github#token"      -> Vault KV v2
//   "vault:secret/github#token"           -> Vault KV v1
//   "my-plain-token"                      -> Static (no prefix)
const SECRET_REF_REGEX = /^(\w+):(.+)#(\w+)$/;

export function parseSecretRef(value: string): { provider: string; path: string; field: string } | null {
  const match = value.match(SECRET_REF_REGEX);
  if (!match) return null;
  return { provider: match[1], path: match[2], field: match[3] };
}

export async function createSecretProviders(config?: SecretsConfig): Promise<Map<string, SecretProvider>> {
  const providers = new Map<string, SecretProvider>();

  // Static provider is always available (identity resolver)
  providers.set('static', new StaticSecretProvider());

  if (config?.vault) {
    const vault = new VaultSecretProvider(config.vault);
    await vault.init();
    providers.set('vault', vault);
  }

  // Future: aws, gcp, azure providers

  return providers;
}

export async function resolveSecretValue(
  value: string,
  providers: Map<string, SecretProvider>
): Promise<string> {
  const ref = parseSecretRef(value);
  if (!ref) return value; // plain string, return as-is

  const provider = providers.get(ref.provider);
  if (!provider) {
    throw new Error(`Unknown secret provider: "${ref.provider}". Available: ${[...providers.keys()].join(', ')}`);
  }

  return provider.resolve(`${ref.path}#${ref.field}`);
}
