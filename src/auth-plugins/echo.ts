import { IAuthPlugin, AuthPluginContext, AuthPluginResult } from './IAuthPlugin';

/**
 * Echo plugin — logs request details and passes through without modification.
 * Useful for testing and debugging the plugin system.
 */
class EchoPlugin implements IAuthPlugin {
  readonly name = 'echo';
  private config: Record<string, unknown> = {};

  async init(_dataDir: string, config: Record<string, unknown>): Promise<void> {
    this.config = config;
    console.log(`   🔌 Echo plugin initialized (config keys: ${Object.keys(config).join(', ') || 'none'})`);
  }

  async rewriteRequest(ctx: AuthPluginContext): Promise<AuthPluginResult> {
    console.log(`   🔌 [echo] ${ctx.method} ${ctx.path} → ${ctx.upstreamUrl}`);
    console.log(`   🔌 [echo] headers: ${Object.keys(ctx.headers).join(', ')}`);
    if (ctx.body.length > 0) {
      console.log(`   🔌 [echo] body: ${ctx.body.length} bytes`);
    }

    // If a custom header is configured, inject it (for testing)
    const headers = { ...ctx.headers };
    if (this.config['injectHeader'] && this.config['injectValue']) {
      headers[this.config['injectHeader'] as string] = this.config['injectValue'] as string;
      console.log(`   🔌 [echo] injected header: ${this.config['injectHeader']}`);
    }

    return {
      headers,
      body: ctx.body,
    };
  }
}

/** Factory function — required by the plugin loader */
export function createPlugin(): IAuthPlugin {
  return new EchoPlugin();
}
