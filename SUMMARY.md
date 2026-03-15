# Auth Plugin System — PR Summary

## What was implemented

Auth plugin system for ClawGuard (issue #22, Phase 1): a new `type: plugin` auth mode that lets users write custom JavaScript modules to handle authentication flows that don't fit the built-in modes (bearer, header, query, oauth2, body_json).

### Core components

- **`IAuthPlugin` interface** (`src/auth-plugins/IAuthPlugin.ts`) — defines the contract: `name`, optional `init()`, and `rewriteRequest(ctx) → {headers, body, upstreamUrl?}`.
- **Plugin loader** (`src/auth-plugins/pluginLoader.ts`) — loads built-in or custom `.js` plugins, validates exports, creates per-plugin data directories, manages lifecycle.
- **`echo` built-in plugin** (`src/auth-plugins/builtins/echo.ts`) — passes requests through with logging; optionally injects a custom header. Useful for testing.
- **Proxy integration** — `type: plugin` is handled in the main proxy flow alongside other auth types.

### Security hardening (3 follow-up commits)

- Plugin names sanitized: only `[a-zA-Z0-9_-]` allowed (prevents path traversal).
- Upstream URL overrides from plugins are re-validated against the security allowlist.
- Headers passed to plugins are defensive copies (no mutation side-channels).
- Fail-closed: plugin load failure → server exits; runtime failure → HTTP 500.
- Plugin data directories are scoped to `data/plugins/<name>/`.

### Tests

26 tests pass, including:
- Plugin loading, validation, and rejection of invalid modules
- Path traversal prevention in plugin names
- Echo plugin behavior (passthrough, header injection)
- Plugin `applyPlugin()` integration with security re-validation
- Upstream URL override blocked when not in allowlist

### Documentation

- README updated with full "Auth Plugins" section (interface, config, plugin authoring guide, security notes).
- `clawguard.yaml.example` includes commented plugin examples (built-in `echo` and custom `.js` file).
- Roadmap checkbox marked complete.

## How to use — complete example

### 1. Write a plugin

```javascript
// my-plugins/hmac-signer.js
const crypto = require('crypto');

module.exports.createPlugin = () => ({
  name: 'hmac-signer',

  async init(dataDir, config) {
    // Optional: load cached state from dataDir
    this.secretKey = config.secretKey;
  },

  async rewriteRequest(ctx) {
    const signature = crypto
      .createHmac('sha256', ctx.config.secretKey)
      .update(ctx.body)
      .digest('hex');

    return {
      headers: {
        ...ctx.headers,
        'x-signature': signature,
        'x-timestamp': Date.now().toString(),
      },
      body: ctx.body,
    };
  },
});
```

### 2. Configure the service

```yaml
services:
  my-api:
    upstream: https://api.example.com
    auth:
      type: plugin
      token: "unused"
      pluginPath: ./my-plugins/hmac-signer.js
      pluginConfig:
        secretKey: "your-hmac-secret"
    policy:
      default: require_approval

security:
  allowedUpstreams:
    - api.example.com
```

### 3. Use the built-in echo plugin for testing

```yaml
services:
  test-echo:
    upstream: https://httpbin.org
    auth:
      type: plugin
      token: "unused"
      pluginPath: echo
      pluginConfig:
        injectHeader: x-custom-auth
        injectValue: "my-secret"
    policy:
      default: auto_approve
```

## Known limitations

- **No TypeScript plugins** — plugins must be plain `.js` files (CommonJS). TypeScript plugins need to be compiled first.
- **No hot-reload** — plugin changes require a server restart.
- **No async init timeout** — a plugin that hangs in `init()` will block server startup indefinitely.
- **No plugin sandboxing** — plugins run in the same Node.js process with full access. Only load plugins you trust.
- **Single plugin per service** — each service can have at most one auth plugin (no plugin chaining).

## Next steps (Phase 2 from issue #22)

- **Plugin sandboxing** — run plugins in isolated workers or VM contexts to limit blast radius.
- **TypeScript plugin support** — allow `.ts` plugins with automatic compilation.
- **Plugin marketplace / registry** — community-contributed plugins for common auth flows (AWS SigV4, HMAC, OAuth2 PKCE, etc.).
- **Hot-reload** — watch plugin files and reload without server restart.
- **Plugin chaining** — allow multiple plugins per service (e.g., rate-limit → sign → inject).
- **Init timeout** — configurable timeout for plugin `init()` to prevent startup hangs.
