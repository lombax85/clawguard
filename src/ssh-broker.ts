import fs from 'fs';
import http, { IncomingMessage, ServerResponse } from 'http';
import net from 'net';
import path from 'path';
import { randomBytes } from 'crypto';
import { ApprovalManager } from './approval';
import { AuditLogger, SshSessionAction } from './audit';
import { Config, ServiceConfig } from './types';
import { validateSshTargetRuntime } from './security';
import {
  ISshCredentialPlugin,
  SshCredentials,
} from './ssh-credential-plugins/ISshCredentialPlugin';
import { getSshCredentialPlugin } from './ssh-credential-plugins/loader';
import { SshAgentLease, SshAgentLeaseManager } from './ssh-agent-lease';

const MAX_BODY_BYTES = 4096;
const MAX_SERVICE_LENGTH = 64;
const MAX_USERNAME_LENGTH = 64;
const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]{32,64}$/;
const SESSION_COMPLETION_GRACE_MS = 10_000;
const SESSION_ACTIVATION_TIMEOUT_MS = 10_000;

interface BrokerSessionRequest {
  service: string;
  clientIp: string;
  action: SshSessionAction;
}

interface BrokerCompletionRequest {
  exitStatus: number;
}

interface ActiveBrokerSession {
  agentLeaseId: string;
  activationTimer?: NodeJS.Timeout;
  leaseExpiryTimer: NodeJS.Timeout;
  sessionExpiryTimer: NodeJS.Timeout;
  leaseRelease?: Promise<boolean>;
}

interface LeaseManagerContract {
  create(privateKey: string | Buffer): Promise<SshAgentLease>;
  release(id: string): Promise<boolean>;
}

interface ApprovalManagerContract {
  checkSshSessionApproval(
    service: string,
    serviceConfig: ServiceConfig,
    path: string,
    agentIp: string,
    meta: undefined,
    timeoutMs: number,
    signal?: AbortSignal
  ): Promise<boolean>;
}

interface AuditContract {
  startSshSession: AuditLogger['startSshSession'];
  updateSshSession: AuditLogger['updateSshSession'];
  finalizeSshSession: AuditLogger['finalizeSshSession'];
}

export interface SshBrokerDependencies {
  approvalManager: ApprovalManagerContract | ApprovalManager;
  audit: AuditContract | AuditLogger;
  leaseManager: LeaseManagerContract | SshAgentLeaseManager;
  credentialPluginForService?: (serviceName: string) => ISshCredentialPlugin | undefined;
  validateTarget?: typeof validateSshTargetRuntime;
  /** Test-only override for the bounded completion grace. */
  sessionCompletionGraceMs?: number;
  /** Test-only override for the provisional wrapper acknowledgement. */
  sessionActivationTimeoutMs?: number;
  /** Enables unprivileged unit tests only; never set in a deployed broker. */
  allowNonRootForTests?: boolean;
}

class BrokerShutdownError extends Error {}
class CredentialRetrievalTimeoutError extends Error {}

class BrokerHttpError extends Error {
  constructor(
    readonly status: number,
    readonly publicMessage: string
  ) {
    super(publicMessage);
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactlyKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function parseSessionRequest(value: unknown): BrokerSessionRequest {
  if (!isPlainObject(value) || !hasExactlyKeys(value, ['service', 'clientIp', 'action'])) {
    throw new BrokerHttpError(400, 'invalid session request');
  }
  if (typeof value.service !== 'string'
    || value.service.length > MAX_SERVICE_LENGTH
    || !/^[A-Za-z0-9_-]+$/.test(value.service)) {
    throw new BrokerHttpError(400, 'invalid service alias');
  }
  if (typeof value.clientIp !== 'string' || net.isIP(value.clientIp) === 0) {
    throw new BrokerHttpError(400, 'invalid client address');
  }
  if (value.action !== 'shell' && value.action !== 'exec') {
    throw new BrokerHttpError(400, 'invalid SSH action');
  }
  return {
    service: value.service,
    clientIp: value.clientIp,
    action: value.action,
  };
}

function parseCompletionRequest(value: unknown): BrokerCompletionRequest {
  if (!isPlainObject(value) || !hasExactlyKeys(value, ['exitStatus'])) {
    throw new BrokerHttpError(400, 'invalid completion request');
  }
  if (!Number.isInteger(value.exitStatus)
    || (value.exitStatus as number) < 0
    || (value.exitStatus as number) > 255) {
    throw new BrokerHttpError(400, 'invalid SSH exit status');
  }
  return { exitStatus: value.exitStatus as number };
}

function parseActivationRequest(value: unknown): void {
  if (!isPlainObject(value) || !hasExactlyKeys(value, [])) {
    throw new BrokerHttpError(400, 'invalid activation request');
  }
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const contentType = req.headers['content-type']?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') {
    throw new BrokerHttpError(415, 'content-type must be application/json');
  }

  const declaredLength = Number(req.headers['content-length']);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
    throw new BrokerHttpError(413, 'request body too large');
  }

  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += buffer.length;
    if (length > MAX_BODY_BYTES) {
      throw new BrokerHttpError(413, 'request body too large');
    }
    chunks.push(buffer);
  }

  if (length === 0) throw new BrokerHttpError(400, 'request body is required');
  try {
    return JSON.parse(Buffer.concat(chunks, length).toString('utf8'));
  } catch {
    throw new BrokerHttpError(400, 'invalid JSON body');
  }
}

function sendJson(res: ServerResponse, status: number, body: Record<string, unknown>): boolean {
  if (res.destroyed || res.writableEnded) return false;
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': String(payload.length),
    'cache-control': 'no-store',
  });
  res.end(payload);
  return true;
}

function parseConfiguredTarget(service: ServiceConfig): { host: string; port: number } {
  const parsed = new URL(service.upstream);
  return {
    host: parsed.hostname.replace(/^\[|\]$/g, ''),
    port: Number(parsed.port),
  };
}

function validateUsername(username: string): void {
  if (username.length > MAX_USERNAME_LENGTH
    || !/^[A-Za-z0-9_][A-Za-z0-9._-]*$/.test(username)) {
    throw new Error('SSH credential plugin returned an unsupported username');
  }
}

function createSessionId(): string {
  return randomBytes(24).toString('base64url');
}

function eraseCredentialKey(credentials: SshCredentials): void {
  if (Buffer.isBuffer(credentials.privateKey)) credentials.privateKey.fill(0);
}

async function socketHasListener(socketPath: string): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    let settled = false;
    const finish = (value: boolean, error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve(value);
    };
    const timer = setTimeout(() => finish(false, new Error('Timed out probing SSH broker socket')), 500);
    socket.once('connect', () => finish(true));
    socket.once('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'ECONNREFUSED' || err.code === 'ENOENT') finish(false);
      else finish(false, err);
    });
  });
}

export class SshBroker {
  private readonly server: http.Server;
  private readonly activeSessions = new Map<string, ActiveBrokerSession>();
  private reservedSessions = 0;
  private started = false;
  private closing = false;
  private readonly shutdownController = new AbortController();
  private readonly inFlightRequests = new Set<Promise<void>>();
  private ownedSocketIdentity: { dev: number; ino: number } | undefined;

  constructor(
    private readonly config: Config,
    private readonly dependencies: SshBrokerDependencies
  ) {
    this.server = http.createServer((req, res) => {
      const task = this.handleRequest(req, res);
      this.inFlightRequests.add(task);
      void task
        .finally(() => this.inFlightRequests.delete(task))
        .catch(() => { /* handleRequest normally contains its own error boundary */ });
    });
    this.server.headersTimeout = 5000;
    this.server.requestTimeout = 10000;
    this.server.keepAliveTimeout = 1000;
    this.server.maxRequestsPerSocket = 2;
  }

  async start(): Promise<void> {
    if (this.started) return;
    if (this.closing) throw new Error('SSH broker is closing');
    const processUid = typeof process.getuid === 'function' ? process.getuid() : undefined;
    if (processUid !== undefined && processUid !== 0 && !this.dependencies.allowNonRootForTests) {
      throw new Error('The experimental ClawGuard SSH broker must run as root');
    }

    const { runtimeDir, socketPath, gatewayGid } = this.config.sshBroker;
    if (path.dirname(path.resolve(socketPath)) !== path.resolve(runtimeDir)) {
      throw new Error('SSH broker socketPath must be directly inside runtimeDir');
    }
    fs.mkdirSync(runtimeDir, { recursive: true, mode: 0o710 });
    const runtimeStat = fs.lstatSync(runtimeDir);
    if (!runtimeStat.isDirectory() || runtimeStat.isSymbolicLink()) {
      throw new Error('SSH broker runtimeDir must be a real directory');
    }
    const brokerOwnerUid = typeof process.getuid === 'function' ? process.getuid() : 0;
    fs.chmodSync(runtimeDir, 0o710);
    fs.chownSync(runtimeDir, brokerOwnerUid, gatewayGid);

    if (fs.existsSync(socketPath)) {
      const socketStat = fs.lstatSync(socketPath);
      if (socketStat.isSymbolicLink() || !socketStat.isSocket()) {
        throw new Error('Refusing to replace unsafe SSH broker socket path');
      }
      if (await socketHasListener(socketPath)) {
        throw new Error('Another SSH broker is already listening');
      }
      fs.unlinkSync(socketPath);
    }

    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error) => {
        this.server.removeListener('listening', onListening);
        reject(err);
      };
      const onListening = () => {
        this.server.removeListener('error', onError);
        resolve();
      };
      this.server.once('error', onError);
      this.server.once('listening', onListening);
      this.server.listen(socketPath);
    });

    try {
      fs.chmodSync(socketPath, 0o660);
      fs.chownSync(socketPath, brokerOwnerUid, gatewayGid);
      const ownedSocket = fs.lstatSync(socketPath);
      this.ownedSocketIdentity = { dev: ownedSocket.dev, ino: ownedSocket.ino };
    } catch (err) {
      await new Promise<void>((resolve) => this.server.close(() => resolve()));
      try { fs.unlinkSync(socketPath); } catch { /* best effort after failed startup */ }
      throw err;
    }

    this.started = true;
  }

  private waitUnlessShuttingDown<T>(operation: Promise<T>): Promise<T> {
    const signal = this.shutdownController.signal;
    if (signal.aborted) return Promise.reject(new BrokerShutdownError());

    return new Promise<T>((resolve, reject) => {
      let settled = false;
      const finish = (callback: () => void) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener('abort', onAbort);
        callback();
      };
      const onAbort = () => finish(() => reject(new BrokerShutdownError()));
      signal.addEventListener('abort', onAbort, { once: true });
      operation.then(
        (value) => finish(() => resolve(value)),
        (err) => finish(() => reject(err))
      );
    });
  }

  private async getCredentialsBounded(
    plugin: ISshCredentialPlugin,
    serviceName: string
  ): Promise<SshCredentials> {
    const brokerSignal = this.shutdownController.signal;
    if (brokerSignal.aborted) throw new BrokerShutdownError();

    const retrievalController = new AbortController();
    const onBrokerShutdown = () => retrievalController.abort(new BrokerShutdownError());
    brokerSignal.addEventListener('abort', onBrokerShutdown, { once: true });

    const timeout = setTimeout(() => {
      retrievalController.abort(new CredentialRetrievalTimeoutError());
    }, this.config.sshBroker.credentialTimeoutMs);
    timeout.unref();

    const operation = Promise.resolve().then(() => plugin.getCredentials({
      serviceName,
      signal: retrievalController.signal,
    }));
    const guardedOperation = operation.then((credentials) => {
      if (retrievalController.signal.aborted) {
        eraseCredentialKey(credentials);
        throw retrievalController.signal.reason;
      }
      return credentials;
    });

    let onRetrievalAbort: (() => void) | undefined;
    const aborted = new Promise<never>((_resolve, reject) => {
      onRetrievalAbort = () => reject(retrievalController.signal.reason);
      if (retrievalController.signal.aborted) onRetrievalAbort();
      else retrievalController.signal.addEventListener('abort', onRetrievalAbort, { once: true });
    });

    try {
      return await Promise.race([guardedOperation, aborted]);
    } finally {
      clearTimeout(timeout);
      brokerSignal.removeEventListener('abort', onBrokerShutdown);
      if (onRetrievalAbort) {
        retrievalController.signal.removeEventListener('abort', onRetrievalAbort);
      }
    }
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      if (this.closing) throw new BrokerHttpError(503, 'SSH broker is shutting down');
      const requestUrl = new URL(req.url || '/', 'http://localhost');
      if (requestUrl.search) throw new BrokerHttpError(404, 'not found');

      if (req.method === 'POST' && requestUrl.pathname === '/session') {
        const input = parseSessionRequest(await readJson(req));
        await this.openSession(input, req, res);
        return;
      }

      const activation = requestUrl.pathname.match(/^\/session\/([A-Za-z0-9_-]{32,64})\/activate$/);
      if (req.method === 'POST' && activation) {
        parseActivationRequest(await readJson(req));
        this.activateSession(activation[1]);
        sendJson(res, 200, { ok: true });
        return;
      }

      const completion = requestUrl.pathname.match(/^\/session\/([A-Za-z0-9_-]{32,64})\/complete$/);
      if (req.method === 'POST' && completion) {
        const input = parseCompletionRequest(await readJson(req));
        await this.completeSession(completion[1], input.exitStatus);
        sendJson(res, 200, { ok: true });
        return;
      }

      throw new BrokerHttpError(404, 'not found');
    } catch (err) {
      if (err instanceof BrokerHttpError) {
        sendJson(res, err.status, { error: err.publicMessage });
        return;
      }
      console.error('❌ Internal SSH broker request failed');
      sendJson(res, 500, { error: 'internal SSH broker error' });
    }
  }

  private async openSession(
    input: BrokerSessionRequest,
    req: IncomingMessage,
    res: ServerResponse
  ): Promise<void> {
    const sessionId = createSessionId();
    let disconnected = req.aborted || res.destroyed;
    const markDisconnected = () => { disconnected = true; };
    req.once('aborted', markDisconnected);
    res.once('close', markDisconnected);

    this.dependencies.audit.startSshSession({
      id: sessionId,
      service: input.service,
      clientIp: input.clientIp,
      action: input.action,
      outcome: 'received',
    });

    const service = this.config.services[input.service];
    if (!service || service.protocol !== 'ssh' || !service.ssh) {
      this.dependencies.audit.finalizeSshSession(sessionId, {
        outcome: 'unknown_service',
        closeReason: 'unknown_or_non_ssh_service',
      });
      throw new BrokerHttpError(404, 'unknown SSH service');
    }

    const target = parseConfiguredTarget(service);
    this.dependencies.audit.updateSshSession(sessionId, {
      targetHost: target.host,
      targetPort: target.port,
      outcome: 'validating_target',
    });

    if (this.reservedSessions >= this.config.sshBroker.maxConcurrentLeases) {
      this.dependencies.audit.finalizeSshSession(sessionId, {
        outcome: 'capacity_denied',
        closeReason: 'session_capacity_reached',
      });
      throw new BrokerHttpError(429, 'SSH gateway is at session capacity');
    }
    this.reservedSessions++;
    let reservationTransferred = false;
    let approvalGranted = false;

    try {
      const validateTarget = this.dependencies.validateTarget ?? validateSshTargetRuntime;
      let validation;
      try {
        validation = await this.waitUnlessShuttingDown(
          validateTarget(service, this.config.security)
        );
      } catch (err) {
        if (err instanceof BrokerShutdownError) throw err;
        this.dependencies.audit.finalizeSshSession(sessionId, {
          outcome: 'target_validation_failed',
          closeReason: 'target_validation_failed',
        });
        throw new BrokerHttpError(502, 'SSH target validation failed');
      }
      const connectHost = validation.resolvedAddresses?.[0];
      if (!validation.valid || !connectHost || net.isIP(connectHost) === 0) {
        this.dependencies.audit.finalizeSshSession(sessionId, {
          outcome: 'target_validation_failed',
          closeReason: 'target_validation_failed',
        });
        throw new BrokerHttpError(502, 'SSH target validation failed');
      }

      if (this.closing) throw new BrokerShutdownError();
      if (disconnected) {
        this.dependencies.audit.finalizeSshSession(sessionId, {
          outcome: 'client_disconnected',
          closeReason: 'broker_client_disconnected_before_approval',
        });
        throw new BrokerHttpError(499, 'SSH gateway client disconnected');
      }

      this.dependencies.audit.updateSshSession(sessionId, { outcome: 'pending_approval' });
      let approved: boolean;
      try {
        approved = await this.waitUnlessShuttingDown(
          this.dependencies.approvalManager.checkSshSessionApproval(
            input.service,
            service,
            `${input.action} ${target.host}:${target.port}`,
            input.clientIp,
            undefined,
            this.config.sshBroker.approvalTimeoutMs,
            this.shutdownController.signal
          )
        );
      } catch (err) {
        if (err instanceof BrokerShutdownError) throw err;
        approved = false;
      }

      if (this.closing) throw new BrokerShutdownError();
      if (!approved) {
        this.dependencies.audit.finalizeSshSession(sessionId, {
          approved: false,
          outcome: 'denied',
          closeReason: 'approval_denied_or_unavailable',
        });
        throw new BrokerHttpError(403, 'SSH session approval denied or unavailable');
      }
      approvalGranted = true;
      if (disconnected) {
        this.dependencies.audit.finalizeSshSession(sessionId, {
          approved: true,
          outcome: 'client_disconnected',
          closeReason: 'broker_client_disconnected_before_lease',
        });
        throw new BrokerHttpError(499, 'SSH gateway client disconnected');
      }

      const pluginForService = this.dependencies.credentialPluginForService
        ?? getSshCredentialPlugin;
      const plugin = pluginForService(input.service);
      if (!plugin) {
        this.dependencies.audit.finalizeSshSession(sessionId, {
          approved: true,
          outcome: 'credential_plugin_unavailable',
          closeReason: 'credential_plugin_unavailable',
        });
        throw new BrokerHttpError(503, 'SSH credential plugin unavailable');
      }

      let lease: SshAgentLease | undefined;
      let activeRegistration: ActiveBrokerSession | undefined;
      try {
        const credentials = await this.getCredentialsBounded(plugin, input.service);
        validateUsername(credentials.username);
        this.dependencies.audit.updateSshSession(sessionId, { upstreamUser: credentials.username });
        try {
          lease = await this.dependencies.leaseManager.create(credentials.privateKey);
        } finally {
          if (Buffer.isBuffer(credentials.privateKey)) credentials.privateKey.fill(0);
        }

        if (this.closing) {
          await this.dependencies.leaseManager.release(lease.id);
          lease = undefined;
          throw new BrokerShutdownError();
        }
        if (disconnected) {
          await this.dependencies.leaseManager.release(lease.id);
          lease = undefined;
          this.dependencies.audit.finalizeSshSession(sessionId, {
            approved: true,
            outcome: 'client_disconnected',
            closeReason: 'broker_client_disconnected_after_lease',
          });
          throw new BrokerHttpError(499, 'SSH gateway client disconnected');
        }

        const expiresAtIso = new Date(lease.expiresAt).toISOString();
        // Persist the active transition before registering timers/quota. If
        // audit storage fails, the catch below can still release the lease
        // without leaving an unreachable active session behind.
        this.dependencies.audit.updateSshSession(sessionId, {
          approved: true,
          outcome: 'active',
          leaseExpiresAt: expiresAtIso,
        });

        const expiryDelay = Math.max(1, lease.expiresAt - Date.now());
        const leaseExpiryTimer = setTimeout(() => {
          void this.expireSessionLease(sessionId).catch(() => {
            console.error('❌ Failed to expire SSH signing capability');
          });
        }, expiryDelay);
        leaseExpiryTimer.unref();
        const sessionExpiryDelay = this.config.sshBroker.maxSessionSeconds * 1000
          + (this.dependencies.sessionCompletionGraceMs ?? SESSION_COMPLETION_GRACE_MS);
        const sessionExpiryTimer = setTimeout(() => {
          void this.expireSession(sessionId).catch(() => {
            console.error('❌ Failed to expire abandoned SSH session');
          });
        }, sessionExpiryDelay);
        sessionExpiryTimer.unref();
        const activationTimer = setTimeout(() => {
          void this.expireUnactivatedSession(sessionId).catch(() => {
            console.error('❌ Failed to expire unacknowledged SSH session');
          });
        }, this.dependencies.sessionActivationTimeoutMs ?? SESSION_ACTIVATION_TIMEOUT_MS);
        activationTimer.unref();
        activeRegistration = {
          agentLeaseId: lease.id,
          activationTimer,
          leaseExpiryTimer,
          sessionExpiryTimer,
        };
        this.activeSessions.set(sessionId, activeRegistration);
        reservationTransferred = true;

        const hostKeyAlias = `clawguard-${input.service}`;
        const responseStarted = sendJson(res, 201, {
          leaseId: sessionId,
          agentSocket: lease.socketPath,
          expiresAt: expiresAtIso,
          maxSessionSeconds: this.config.sshBroker.maxSessionSeconds,
          target: {
            host: connectHost,
            port: target.port,
            username: credentials.username,
            hostKeyAlias,
            knownHostsLine: `${hostKeyAlias} ${service.ssh.knownHostKey}`,
          },
        });
        if (!responseStarted) {
          throw new BrokerHttpError(499, 'SSH gateway client disconnected');
        }
      } catch (err) {
        if (activeRegistration && this.activeSessions.get(sessionId) === activeRegistration) {
          this.activeSessions.delete(sessionId);
          this.reservedSessions--;
          clearTimeout(activeRegistration.activationTimer);
          clearTimeout(activeRegistration.leaseExpiryTimer);
          clearTimeout(activeRegistration.sessionExpiryTimer);
          // The original reservation has been explicitly returned.
          reservationTransferred = true;
        }
        if (lease) {
          await this.dependencies.leaseManager.release(lease.id);
          lease = undefined;
        }
        if (err instanceof BrokerHttpError && err.status === 499 && activeRegistration) {
          try {
            this.dependencies.audit.finalizeSshSession(sessionId, {
              approved: true,
              outcome: 'client_disconnected',
              closeReason: 'broker_response_not_delivered',
            });
          } catch {
            // The lease/quota rollback above is authoritative even if audit is unavailable.
          }
        }
        if (err instanceof BrokerHttpError || err instanceof BrokerShutdownError) throw err;
        try {
          this.dependencies.audit.finalizeSshSession(sessionId, {
            approved: true,
            outcome: 'credential_lease_failed',
            closeReason: 'credential_or_lease_setup_failed',
          });
        } catch {
          // Cleanup already happened; preserve a sanitized broker response.
        }
        throw new BrokerHttpError(502, 'SSH credential lease could not be created');
      }
    } catch (err) {
      if (err instanceof BrokerShutdownError) {
        this.dependencies.audit.finalizeSshSession(sessionId, {
          approved: approvalGranted,
          outcome: 'gateway_shutdown',
          closeReason: 'gateway_shutdown_during_session_setup',
        });
        throw new BrokerHttpError(503, 'SSH broker is shutting down');
      }
      throw err;
    } finally {
      if (!reservationTransferred) this.reservedSessions--;
    }
  }

  private activateSession(sessionId: string): void {
    if (!SESSION_ID_PATTERN.test(sessionId)) {
      throw new BrokerHttpError(400, 'invalid session id');
    }
    const active = this.activeSessions.get(sessionId);
    if (!active) throw new BrokerHttpError(404, 'SSH session not found or already closed');

    // Idempotent acknowledgement lets the wrapper safely retry only this
    // local handoff if it did not receive the acknowledgement response.
    if (active.activationTimer) {
      clearTimeout(active.activationTimer);
      active.activationTimer = undefined;
    }
  }

  private async completeSession(sessionId: string, exitStatus: number): Promise<void> {
    if (!SESSION_ID_PATTERN.test(sessionId)) {
      throw new BrokerHttpError(400, 'invalid session id');
    }
    const active = this.activeSessions.get(sessionId);
    if (!active) throw new BrokerHttpError(404, 'SSH session not found or already closed');

    this.activeSessions.delete(sessionId);
    this.reservedSessions--;
    clearTimeout(active.activationTimer);
    clearTimeout(active.leaseExpiryTimer);
    clearTimeout(active.sessionExpiryTimer);
    await this.releaseAgentLease(active);
    this.dependencies.audit.finalizeSshSession(sessionId, {
      outcome: exitStatus === 0 ? 'completed' : 'remote_exit_nonzero',
      exitStatus,
      closeReason: 'wrapper_completed',
    });
  }

  private async expireUnactivatedSession(sessionId: string): Promise<void> {
    const active = this.activeSessions.get(sessionId);
    if (!active?.activationTimer) return;

    this.activeSessions.delete(sessionId);
    this.reservedSessions--;
    clearTimeout(active.activationTimer);
    active.activationTimer = undefined;
    clearTimeout(active.leaseExpiryTimer);
    clearTimeout(active.sessionExpiryTimer);
    try {
      await this.releaseAgentLease(active);
    } finally {
      this.dependencies.audit.finalizeSshSession(sessionId, {
        outcome: 'activation_timeout',
        closeReason: 'wrapper_activation_not_acknowledged',
      });
    }
  }

  private releaseAgentLease(active: ActiveBrokerSession): Promise<boolean> {
    // The broker timer and the lease manager's own TTL intentionally race as
    // independent cleanup backstops. Share one promise so completion/shutdown
    // cannot run a second cleanup or return while the first one is in flight.
    active.leaseRelease ??= this.dependencies.leaseManager.release(active.agentLeaseId);
    return active.leaseRelease;
  }

  private async expireSessionLease(sessionId: string): Promise<void> {
    const active = this.activeSessions.get(sessionId);
    if (!active) return;
    await this.releaseAgentLease(active);

    // An agent key is needed only for SSH authentication. An already
    // authenticated stock-OpenSSH channel can legitimately outlive that
    // short-lived signing capability. Keep the session and its capacity slot
    // until the wrapper reports the real exit status; record only an
    // intermediate metadata transition here.
    if (this.activeSessions.get(sessionId) === active) {
      this.dependencies.audit.updateSshSession(sessionId, {
        outcome: 'active_lease_expired',
      });
    }
  }

  private async expireSession(sessionId: string): Promise<void> {
    const active = this.activeSessions.get(sessionId);
    if (!active) return;
    this.activeSessions.delete(sessionId);
    this.reservedSessions--;
    clearTimeout(active.activationTimer);
    clearTimeout(active.leaseExpiryTimer);
    clearTimeout(active.sessionExpiryTimer);
    try {
      await this.releaseAgentLease(active);
    } finally {
      this.dependencies.audit.finalizeSshSession(sessionId, {
        outcome: 'session_timeout',
        closeReason: 'maximum_session_duration_or_completion_lost',
      });
    }
  }

  async close(): Promise<void> {
    if (this.closing) return;
    this.closing = true;
    this.shutdownController.abort();

    let serverClose: Promise<void> | undefined;
    if (this.started) {
      serverClose = new Promise<void>((resolve) => {
        this.server.close(() => resolve());
        this.server.closeAllConnections?.();
      });
    }

    const sessions = [...this.activeSessions.entries()];
    this.activeSessions.clear();
    this.reservedSessions = Math.max(0, this.reservedSessions - sessions.length);
    await Promise.all(sessions.map(async ([sessionId, active]) => {
      clearTimeout(active.activationTimer);
      clearTimeout(active.leaseExpiryTimer);
      clearTimeout(active.sessionExpiryTimer);
      await this.releaseAgentLease(active);
      this.dependencies.audit.finalizeSshSession(sessionId, {
        outcome: 'gateway_shutdown',
        closeReason: 'gateway_shutdown',
      });
    }));

    await Promise.allSettled([...this.inFlightRequests]);
    if (serverClose) {
      await serverClose;
      this.started = false;
    }

    if (this.ownedSocketIdentity) {
      try {
        const stat = fs.lstatSync(this.config.sshBroker.socketPath);
        if (stat.isSocket()
          && !stat.isSymbolicLink()
          && stat.dev === this.ownedSocketIdentity.dev
          && stat.ino === this.ownedSocketIdentity.ino) {
          fs.unlinkSync(this.config.sshBroker.socketPath);
        }
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
      } finally {
        this.ownedSocketIdentity = undefined;
      }
    }
  }
}
