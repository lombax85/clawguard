// Preload this file to make Node.js fetch() respect HTTPS_PROXY.
// Usage: NODE_OPTIONS="--require /path/to/clawguard-proxy-bootstrap.js" node your-script.js
const { setGlobalDispatcher, EnvHttpProxyAgent } = require('undici');
setGlobalDispatcher(new EnvHttpProxyAgent());
