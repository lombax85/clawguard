import express from 'express';
import http from 'http';
import https from 'https';
import tls from 'tls';
import { Config } from './types';
import { ApprovalManager } from './approval';
import { AuditLogger } from './audit';
import { CertManager } from './cert-manager';
import { handleHostProxy } from './proxy';

export function startTransparentProxy(
  config: Config,
  approvalManager: ApprovalManager,
  audit: AuditLogger,
  certManager: CertManager
): void {
  if (!config.transparentProxy.enabled) return;

  const app = express();

  // Parse raw body for forwarding
  app.use(express.raw({ type: '*/*', limit: '10mb' }));

  // Forward all requests via host-based routing, skipping agentKey validation
  // passthrough: unknown hosts are forwarded directly without auth injection
  app.all('*', handleHostProxy(config, approvalManager, audit, { requireAgentKey: false, passthrough: true }));

  // ─── HTTP Server ──────────────────────────────────────────────

  const httpPort = config.transparentProxy.httpPort;
  http.createServer(app).listen(httpPort, () => {
    console.log(`\n🔀 Transparent HTTP proxy running on http://localhost:${httpPort}`);
  });

  // ─── HTTPS Server with dynamic SNI ────────────────────────────

  const httpsPort = config.transparentProxy.httpsPort;
  const httpsOptions: https.ServerOptions = {
    SNICallback: (servername, cb) => {
      try {
        const certPair = certManager.getCertForHost(servername);
        const secureContext = tls.createSecureContext({
          key: certPair.key,
          cert: certPair.cert,
        });
        cb(null, secureContext);
      } catch (err) {
        cb(err as Error, undefined);
      }
    },
  };

  https.createServer(httpsOptions, app).listen(httpsPort, () => {
    console.log(`🔀 Transparent HTTPS proxy running on https://localhost:${httpsPort}`);
  });
}
