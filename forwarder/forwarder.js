#!/usr/bin/env node
/**
 * ClawGuard Forwarder — runs on the AGENT machine (untrusted).
 *
 * Intercepts HTTPS traffic for hardcoded API domains and forwards
 * it to a remote ClawGuard instance. The forwarder has NO access
 * to real API tokens — it only knows the ClawGuard agent key.
 *
 * Usage:
 *   1. Generate certs:  ./generate-certs.sh api.openai.com slack.com
 *   2. Trust the CA:    sudo cp certs/ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates
 *   3. Edit /etc/hosts: 127.0.0.1 api.openai.com slack.com
 *   4. Edit forwarder.json
 *   5. Run:             node forwarder.js
 *
 * No dependencies — pure Node.js stdlib.
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const tls = require('tls');

// ─── Load config ─────────────────────────────────────────────

const CONFIG_PATH = process.env.CLAWGUARD_FORWARDER_CONFIG || path.join(__dirname, 'forwarder.json');

if (!fs.existsSync(CONFIG_PATH)) {
  console.error(`\n❌ Config not found: ${CONFIG_PATH}`);
  console.error(`   Copy forwarder.json.example to forwarder.json and edit it.\n`);
  process.exit(1);
}

const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));

const CLAWGUARD_HOST = config.clawguard || 'http://192.168.1.100:9090';
const AGENT_KEY = config.agentKey || '';
const LISTEN_HOST = config.listenHost || '127.0.0.1';
const LISTEN_PORT = config.listenPort || 443;
const CERTS_DIR = config.certsDir || path.join(__dirname, 'certs');
const ROUTES = config.routes || {};

// ─── Load TLS certs (per-domain via SNI) ─────────────────────

const contexts = {};

for (const hostname of Object.keys(ROUTES)) {
  const certFile = path.join(CERTS_DIR, `${hostname}.crt`);
  const keyFile = path.join(CERTS_DIR, `${hostname}.key`);

  if (fs.existsSync(certFile) && fs.existsSync(keyFile)) {
    contexts[hostname] = tls.createSecureContext({
      cert: fs.readFileSync(certFile),
      key: fs.readFileSync(keyFile),
    });
    console.log(`   ✓ Cert loaded for: ${hostname}`);
  } else {
    console.warn(`   ⚠️  No cert found for ${hostname} — generate with: ./generate-certs.sh ${hostname}`);
  }
}

// Fallback cert (first one found, or self-signed)
const fallbackCert = path.join(CERTS_DIR, 'fallback.crt');
const fallbackKey = path.join(CERTS_DIR, 'fallback.key');

if (!fs.existsSync(fallbackCert) || !fs.existsSync(fallbackKey)) {
  console.error(`\n❌ No fallback cert found. Run ./generate-certs.sh first.\n`);
  process.exit(1);
}

// ─── HTTPS server with SNI ───────────────────────────────────

const server = https.createServer(
  {
    cert: fs.readFileSync(fallbackCert),
    key: fs.readFileSync(fallbackKey),
    SNICallback: (hostname, cb) => {
      const ctx = contexts[hostname];
      if (ctx) {
        cb(null, ctx);
      } else {
        cb(null); // use default
      }
    },
  },
  (req, res) => {
    const host = (req.headers.host || '').split(':')[0];
    const serviceName = ROUTES[host];

    if (!serviceName) {
      console.log(`❌ Unknown host: ${host}`);
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Unknown host: ${host}` }));
      return;
    }

    console.log(`→ ${req.method} ${host}${req.url} → ClawGuard/${serviceName}`);

    // Collect request body
    const bodyChunks = [];
    req.on('data', (chunk) => bodyChunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(bodyChunks);

      // Forward to ClawGuard: http://clawguard-host:9090/{service}{path}
      // Using host-based routing: path stays as-is, Host header preserved
      const clawguardUrl = new URL(`/${serviceName}${req.url}`, CLAWGUARD_HOST);
      const isHttps = clawguardUrl.protocol === 'https:';
      const transport = isHttps ? https : http;

      const headers = { ...req.headers };
      headers['x-clawguard-key'] = AGENT_KEY;
      headers['host'] = clawguardUrl.host;
      // Preserve original host for ClawGuard logging
      headers['x-forwarded-host'] = host;

      const proxyReq = transport.request(
        clawguardUrl.toString(),
        {
          method: req.method,
          headers: headers,
        },
        (proxyRes) => {
          res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
          proxyRes.pipe(res);
        }
      );

      proxyReq.on('error', (err) => {
        console.error(`❌ ClawGuard unreachable: ${err.message}`);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `ClawGuard unreachable: ${err.message}` }));
      });

      if (body.length > 0) {
        proxyReq.write(body);
      }
      proxyReq.end();
    });
  }
);

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  console.log(`
╔══════════════════════════════════════════════╗
║   🔀 ClawGuard Forwarder                    ║
║   Runs on agent machine — no real tokens     ║
╚══════════════════════════════════════════════╝

🔗 ClawGuard:  ${CLAWGUARD_HOST}
🖥️  Listening:  https://${LISTEN_HOST}:${LISTEN_PORT}
📡 Routes:`);
  for (const [host, service] of Object.entries(ROUTES)) {
    console.log(`   ${host} → ${CLAWGUARD_HOST}/${service}`);
  }
  console.log(`\n⏳ Waiting for traffic...\n`);
});

// Graceful shutdown
process.on('SIGINT', () => { console.log('\n🛑 Forwarder stopped.'); server.close(); process.exit(0); });
process.on('SIGTERM', () => { server.close(); process.exit(0); });
