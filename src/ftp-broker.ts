import { randomBytes } from 'crypto';
import { ApprovalManager } from './approval';
import { AuditLogger } from './audit';
import {
  FtpGatewayContract,
  FtpGatewayOpenRequest,
} from './ftp-gateway-client';
import {
  FtpCredentials,
  IFtpCredentialPlugin,
} from './ftp-credential-plugins/IFtpCredentialPlugin';
import { getFtpCredentialPlugin } from './ftp-credential-plugins/loader';
import { validateFtpTargetRuntime } from './security';
import { Config, FtpAccessMode, RequestMeta, ServiceConfig } from './types';

interface ApprovalContract {
  checkFtpSessionApproval(
    service: string,
    serviceConfig: ServiceConfig,
    path: string,
    agentIp: string,
    meta: RequestMeta | undefined,
    timeoutMs: number,
    signal?: AbortSignal
  ): Promise<FtpAccessMode | false>;
}

interface AuditContract {
  startFtpSession: AuditLogger['startFtpSession'];
  updateFtpSession: AuditLogger['updateFtpSession'];
  finalizeFtpSession: AuditLogger['finalizeFtpSession'];
}

export interface FtpBrokerDependencies {
  approvalManager: ApprovalContract | ApprovalManager;
  audit: AuditContract | AuditLogger;
  gateway: FtpGatewayContract;
  credentialPluginForService?: (service: string) => IFtpCredentialPlugin | undefined;
  validateTarget?: typeof validateFtpTargetRuntime;
}

export interface FtpLeaseResponse {
  id: string;
  protocol: 'ftp' | 'ftps';
  host: string;
  port: number;
  username: string;
  password: string;
  tlsMode: 'none' | 'explicit';
  accessMode: FtpAccessMode;
  expiresAt: string;
}

interface ActiveSession {
  timer: NodeJS.Timeout;
}

export class FtpBrokerError extends Error {
  constructor(readonly status: number, readonly publicMessage: string) {
    super(publicMessage);
  }
}

class BrokerClosingError extends Error {}
class CredentialTimeoutError extends Error {}

function createSessionId(): string {
  return randomBytes(24).toString('base64url');
}

function combinedSignal(a: AbortSignal, b?: AbortSignal): { signal: AbortSignal; cleanup: () => void } {
  const controller = new AbortController();
  const abort = (source: AbortSignal) => {
    if (!controller.signal.aborted) controller.abort(source.reason);
  };
  const onA = () => abort(a);
  const onB = () => b && abort(b);
  if (a.aborted) abort(a); else a.addEventListener('abort', onA, { once: true });
  if (b) {
    if (b.aborted) abort(b); else b.addEventListener('abort', onB, { once: true });
  }
  return {
    signal: controller.signal,
    cleanup: () => {
      a.removeEventListener('abort', onA);
      b?.removeEventListener('abort', onB);
    },
  };
}

export class FtpBroker {
  private readonly active = new Map<string, ActiveSession>();
  private reserved = 0;
  private closing = false;
  private readonly shutdown = new AbortController();

  constructor(
    private readonly config: Config,
    private readonly dependencies: FtpBrokerDependencies
  ) {}

  private async credentialsBounded(
    plugin: IFtpCredentialPlugin,
    serviceName: string,
    outerSignal: AbortSignal
  ): Promise<FtpCredentials> {
    const controller = new AbortController();
    const onAbort = () => controller.abort(outerSignal.reason);
    if (outerSignal.aborted) onAbort();
    else outerSignal.addEventListener('abort', onAbort, { once: true });
    const timeout = setTimeout(
      () => controller.abort(new CredentialTimeoutError()),
      this.config.ftpGateway.credentialTimeoutMs
    );
    timeout.unref();

    const operation = Promise.resolve()
      .then(() => plugin.getCredentials({
        serviceName,
        signal: controller.signal,
      }))
      .then((credentials) => {
        // A plugin is allowed to ignore AbortSignal. If it resolves after the
        // timeout/shutdown race was lost, wipe its password before rejecting.
        if (controller.signal.aborted) {
          credentials.password.fill(0);
          throw controller.signal.reason ?? new Error('credential retrieval aborted');
        }
        return credentials;
      });
    const aborted = new Promise<never>((_resolve, reject) => {
      const fail = () => reject(controller.signal.reason ?? new Error('credential retrieval aborted'));
      if (controller.signal.aborted) fail();
      else controller.signal.addEventListener('abort', fail, { once: true });
    });
    try {
      return await Promise.race([operation, aborted]);
    } finally {
      clearTimeout(timeout);
      outerSignal.removeEventListener('abort', onAbort);
    }
  }

  async openSession(
    serviceName: string,
    clientIp: string,
    meta?: RequestMeta,
    requestSignal?: AbortSignal
  ): Promise<FtpLeaseResponse> {
    if (this.closing) throw new FtpBrokerError(503, 'FTP gateway is shutting down');
    const service = this.config.services[serviceName];
    if (!service || (service.protocol !== 'ftp' && service.protocol !== 'ftps') || !service.ftp) {
      throw new FtpBrokerError(404, 'Unknown FTP/FTPS service');
    }
    if (this.reserved >= this.config.ftpGateway.maxConcurrentSessions) {
      throw new FtpBrokerError(429, 'FTP gateway capacity is exhausted');
    }

    const sessionId = createSessionId();
    const protocol = service.protocol;
    const targetUrl = new URL(service.upstream);
    const targetHost = targetUrl.hostname.replace(/^\[|\]$/g, '');
    // WHATWG strips the explicit default :21 from ftp:// URLs.
    const targetPort = Number(targetUrl.port || (protocol === 'ftp' ? '21' : '990'));
    this.dependencies.audit.startFtpSession({
      id: sessionId,
      service: serviceName,
      protocol,
      clientIp,
      targetHost,
      targetPort,
      outcome: 'received',
    });
    this.reserved++;
    let keepReservation = false;
    let sidecarActivationAttempted = false;
    let credentials: FtpCredentials | undefined;
    const signals = combinedSignal(this.shutdown.signal, requestSignal);

    try {
      if (signals.signal.aborted) throw new BrokerClosingError();
      const validation = await (this.dependencies.validateTarget ?? validateFtpTargetRuntime)(
        service,
        this.config.security
      );
      if (!validation.valid || !validation.resolvedAddresses?.length) {
        this.dependencies.audit.finalizeFtpSession(sessionId, {
          outcome: 'target_rejected',
          closeReason: validation.reason ?? 'no validated target address',
        });
        throw new FtpBrokerError(403, 'FTP target failed security validation');
      }

      this.dependencies.audit.updateFtpSession(sessionId, { outcome: 'pending_approval' });
      const accessMode = await this.dependencies.approvalManager.checkFtpSessionApproval(
        serviceName,
        service,
        `open ${protocol.toUpperCase()} lease to ${targetHost}:${targetPort}`,
        clientIp,
        meta,
        this.config.ftpGateway.approvalTimeoutMs,
        signals.signal
      );
      if (signals.signal.aborted) {
        throw signals.signal.reason ?? new Error('FTP session request aborted');
      }
      if (!accessMode) {
        this.dependencies.audit.finalizeFtpSession(sessionId, {
          approved: false,
          outcome: 'denied',
          closeReason: 'approval_denied_or_unavailable',
        });
        throw new FtpBrokerError(403, 'FTP session approval denied or unavailable');
      }
      this.dependencies.audit.updateFtpSession(sessionId, {
        approved: true,
        accessMode,
        outcome: 'retrieving_credentials',
      });

      const plugin = (this.dependencies.credentialPluginForService ?? getFtpCredentialPlugin)(serviceName);
      if (!plugin) {
        this.dependencies.audit.finalizeFtpSession(sessionId, {
          approved: true,
          outcome: 'credential_error',
          closeReason: 'credential_plugin_unavailable',
        });
        throw new FtpBrokerError(503, 'FTP credential plugin unavailable');
      }
      credentials = await this.credentialsBounded(plugin, serviceName, signals.signal);

      const gatewayUsername = `cg-${sessionId.slice(0, 16)}`;
      const gatewayPassword = randomBytes(32).toString('base64url');
      const expiresAt = new Date(Date.now() + this.config.ftpGateway.sessionTtlSeconds * 1000).toISOString();
      const gatewayRequest: FtpGatewayOpenRequest = {
        sessionId,
        service: serviceName,
        protocol,
        accessMode,
        clientIp,
        expiresAt,
        upstream: {
          hostname: targetHost,
          port: targetPort,
          resolvedAddresses: validation.resolvedAddresses,
          root: service.ftp.root ?? '',
          tlsMode: protocol === 'ftp' ? 'none' : service.ftp.tlsMode!,
          noCheckCertificate: service.ftp.noCheckCertificate === true,
        },
        upstreamCredentials: {
          username: credentials.username,
          passwordBase64: credentials.password.toString('base64'),
        },
        gatewayCredentials: { username: gatewayUsername, password: gatewayPassword },
      };
      // A rejected Unix-socket request is ambiguous: the sidecar may have
      // committed the session before the response transport failed. Treat
      // every attempted activation as cleanup-required until ownership is
      // transferred to the active-session map below.
      sidecarActivationAttempted = true;
      const opened = await this.dependencies.gateway.openSession(gatewayRequest, signals.signal);
      if (opened.sessionId !== sessionId
        || opened.controlPort < this.config.ftpGateway.controlPortStart
        || opened.controlPort > this.config.ftpGateway.controlPortEnd) {
        throw new Error('FTP sidecar allocated an unexpected session or control port');
      }
      if (signals.signal.aborted) {
        throw signals.signal.reason ?? new Error('FTP session request aborted');
      }

      // Persist the active transition before registering quota/timers. If the
      // audit store fails, close the otherwise unreachable sidecar session.
      try {
        this.dependencies.audit.updateFtpSession(sessionId, {
          approved: true,
          outcome: 'active',
          upstreamUser: credentials.username,
          controlPort: opened.controlPort,
          leaseExpiresAt: expiresAt,
        });
      } catch (err) {
        throw err;
      }
      if (signals.signal.aborted) {
        throw signals.signal.reason ?? new Error('FTP session request aborted');
      }

      const timer = setTimeout(() => {
        void this.endSession(sessionId, 'lease_expired');
      }, this.config.ftpGateway.sessionTtlSeconds * 1000);
      timer.unref();
      this.active.set(sessionId, { timer });
      keepReservation = true;
      sidecarActivationAttempted = false;
      return {
        id: sessionId,
        protocol,
        host: this.config.ftpGateway.publicHost,
        port: opened.controlPort,
        username: gatewayUsername,
        password: gatewayPassword,
        tlsMode: protocol === 'ftps' ? 'explicit' : 'none',
        accessMode,
        expiresAt,
      };
    } catch (err) {
      if (err instanceof FtpBrokerError) throw err;
      const outcome = err instanceof CredentialTimeoutError ? 'credential_timeout'
        : err instanceof BrokerClosingError || this.shutdown.signal.aborted ? 'gateway_shutdown'
          : requestSignal?.aborted ? 'client_disconnected'
          : 'gateway_error';
      try {
        this.dependencies.audit.finalizeFtpSession(sessionId, {
          outcome,
          closeReason: outcome,
        });
      } catch {
        // Cleanup and the sanitized response remain authoritative if audit is unavailable.
      }
      if (outcome === 'gateway_shutdown') throw new FtpBrokerError(503, 'FTP gateway is shutting down');
      if (outcome === 'client_disconnected') throw new FtpBrokerError(499, 'FTP gateway client disconnected');
      if (outcome === 'credential_timeout') throw new FtpBrokerError(503, 'FTP credential retrieval timed out');
      throw new FtpBrokerError(503, 'FTP sidecar could not create the session');
    } finally {
      credentials?.password.fill(0);
      signals.cleanup();
      if (!keepReservation && sidecarActivationAttempted) {
        await this.dependencies.gateway.closeSession(sessionId).catch(() => undefined);
      }
      if (!keepReservation) this.reserved--;
    }
  }

  private async endSession(id: string, reason: 'client_closed' | 'lease_expired' | 'gateway_shutdown'): Promise<boolean> {
    const session = this.active.get(id);
    if (!session) return false;
    this.active.delete(id);
    clearTimeout(session.timer);
    this.reserved--;
    try {
      await this.dependencies.gateway.closeSession(id);
    } catch {
      // The hard lease deadline is also enforced inside the sidecar. Audit the
      // requested terminal state without leaking transport detail.
    }
    this.dependencies.audit.finalizeFtpSession(id, {
      outcome: reason === 'client_closed' ? 'closed' : reason,
      closeReason: reason,
    });
    return true;
  }

  closeSession(id: string): Promise<boolean> {
    return this.endSession(id, 'client_closed');
  }

  async close(): Promise<void> {
    if (this.closing) return;
    this.closing = true;
    this.shutdown.abort(new BrokerClosingError());
    await Promise.all([...this.active.keys()].map((id) => this.endSession(id, 'gateway_shutdown')));
  }
}
