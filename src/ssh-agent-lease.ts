import { randomBytes } from 'crypto';
import fs from 'fs';
import path from 'path';
import { ChildProcessWithoutNullStreams, spawn } from 'child_process';

export interface SshAgentLeaseManagerOptions {
  runtimeDir: string;
  gatewayUid: number;
  gatewayGid: number;
  leaseTtlSeconds: number;
  maxConcurrentLeases: number;
  sshAgentPath: string;
  sshAddPath: string;
  startupTimeoutMs?: number;
  /** Enables unprivileged unit tests only; never set in a deployed broker. */
  allowNonRootForTests?: boolean;
}

export interface SshAgentLease {
  id: string;
  socketPath: string;
  expiresAt: number;
}

interface ActiveLease extends SshAgentLease {
  directory: string;
  process: ChildProcessWithoutNullStreams;
  timer: NodeJS.Timeout;
  releasing: boolean;
}

interface AgentDiagnostics {
  spawnError?: Error;
  stderr: () => string;
}

const DEFAULT_STARTUP_TIMEOUT_MS = 5000;
const MAX_TOOL_OUTPUT_BYTES = 4096;
const MAX_PRIVATE_KEY_BYTES = 1024 * 1024;
// Darwin sockaddr_un.sun_path is 104 bytes including its terminating NUL.
// Staying within 103 bytes also works on Linux (108-byte sun_path).
const MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES = 103;
const LEASE_DIRECTORY_PREFIX = 'a-';
const LEASE_DIRECTORY_TOKEN_BYTES = 6; // eight base64url characters
const LEASE_SOCKET_NAME = 's';
const LEASE_CREATE_ATTEMPTS = 16;

function isProcessRunning(child: ChildProcessWithoutNullStreams): boolean {
  return child.pid !== undefined && child.exitCode === null && child.signalCode === null;
}

function waitForExit(child: ChildProcessWithoutNullStreams, timeoutMs: number): Promise<void> {
  if (!isProcessRunning(child)) return Promise.resolve();

  return new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.removeListener('exit', finish);
      child.removeListener('close', finish);
      resolve();
    };
    const timer = setTimeout(finish, timeoutMs);
    child.once('exit', finish);
    child.once('close', finish);
  });
}

async function terminateProcess(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (isProcessRunning(child)) child.kill('SIGTERM');
  await waitForExit(child, 500);
  if (isProcessRunning(child)) {
    child.kill('SIGKILL');
    await waitForExit(child, 250);
  }
}

function captureBoundedOutput(stream: NodeJS.ReadableStream): () => string {
  const chunks: Buffer[] = [];
  let bytes = 0;
  stream.on('data', (chunk: Buffer | string) => {
    if (bytes >= MAX_TOOL_OUTPUT_BYTES) return;
    const source = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const retained = source.subarray(0, MAX_TOOL_OUTPUT_BYTES - bytes);
    chunks.push(Buffer.from(retained));
    bytes += retained.length;
  });
  return () => Buffer.concat(chunks, bytes).toString('utf8');
}

function diagnosticSuffix(diagnostics: AgentDiagnostics): string {
  const raw = diagnostics.spawnError?.message || diagnostics.stderr();
  const detail = raw.trim().replace(/[\r\n]+/g, ' ').slice(0, 500);
  return detail ? `: ${detail}` : '';
}

async function waitForSocket(
  socketPath: string,
  child: ChildProcessWithoutNullStreams,
  timeoutMs: number,
  diagnostics: AgentDiagnostics
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (diagnostics.spawnError) {
      throw new Error(`Failed to start ssh-agent${diagnosticSuffix(diagnostics)}`);
    }
    if (!isProcessRunning(child)) {
      // A failed spawn reports its `error` event on a later turn. Give it one
      // opportunity to populate the actionable diagnostic before failing.
      if (child.pid === undefined) {
        await new Promise<void>((resolve) => setImmediate(resolve));
        if (diagnostics.spawnError) {
          throw new Error(`Failed to start ssh-agent${diagnosticSuffix(diagnostics)}`);
        }
      }
      throw new Error(`ssh-agent exited before creating its socket${diagnosticSuffix(diagnostics)}`);
    }
    try {
      if (fs.lstatSync(socketPath).isSocket()) return;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`Timed out waiting for ssh-agent socket${diagnosticSuffix(diagnostics)}`);
}

function generatedSocketPath(runtimeDir: string): string {
  const tokenChars = Buffer.alloc(LEASE_DIRECTORY_TOKEN_BYTES).toString('base64url').length;
  return path.join(
    runtimeDir,
    `${LEASE_DIRECTORY_PREFIX}${'x'.repeat(tokenChars)}`,
    LEASE_SOCKET_NAME
  );
}

function validateOptions(options: SshAgentLeaseManagerOptions): void {
  if (!path.isAbsolute(options.runtimeDir)) {
    throw new Error('SSH agent runtimeDir must be an absolute path');
  }
  const socketBytes = Buffer.byteLength(generatedSocketPath(path.resolve(options.runtimeDir)), 'utf8');
  if (socketBytes > MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES) {
    throw new Error(
      `SSH agent runtimeDir is too long for a portable Unix socket path ` +
      `(${socketBytes} generated bytes, maximum ${MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES})`
    );
  }
  if (!Number.isInteger(options.gatewayUid) || options.gatewayUid < 0) {
    throw new Error('SSH agent gatewayUid must be a non-negative integer');
  }
  if (!Number.isInteger(options.gatewayGid) || options.gatewayGid < 0) {
    throw new Error('SSH agent gatewayGid must be a non-negative integer');
  }
  const processUid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  if (processUid !== undefined && processUid !== 0 && !options.allowNonRootForTests) {
    throw new Error('The experimental ClawGuard SSH broker must run as root');
  }
  if (!Number.isInteger(options.leaseTtlSeconds) || options.leaseTtlSeconds < 1) {
    throw new Error('SSH agent leaseTtlSeconds must be a positive integer');
  }
  if (!Number.isInteger(options.maxConcurrentLeases) || options.maxConcurrentLeases < 1) {
    throw new Error('SSH agent maxConcurrentLeases must be a positive integer');
  }
  if (!options.sshAgentPath || !path.isAbsolute(options.sshAgentPath)) {
    throw new Error('SSH agent executable path must be absolute');
  }
  if (!options.sshAddPath || !path.isAbsolute(options.sshAddPath)) {
    throw new Error('ssh-add executable path must be absolute');
  }
  if (options.startupTimeoutMs !== undefined &&
      (!Number.isInteger(options.startupTimeoutMs) || options.startupTimeoutMs < 1)) {
    throw new Error('SSH agent startupTimeoutMs must be a positive integer');
  }
}

export class SshAgentLeaseManager {
  private readonly options: SshAgentLeaseManagerOptions;
  private readonly leases = new Map<string, ActiveLease>();
  private closing = false;
  private pendingCreates = 0;
  private pendingCreateWaiters: Array<() => void> = [];

  constructor(options: SshAgentLeaseManagerOptions) {
    validateOptions(options);
    this.options = { ...options, runtimeDir: path.resolve(options.runtimeDir) };
    this.prepareRuntimeDir();
  }

  get activeCount(): number {
    return this.leases.size;
  }

  private prepareRuntimeDir(): void {
    fs.mkdirSync(this.options.runtimeDir, { recursive: true, mode: 0o710 });
    const stat = fs.lstatSync(this.options.runtimeDir);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error('SSH agent runtimeDir must be a real directory');
    }
    // The sidecar group may traverse to paths returned by the broker, but may
    // not list, create, replace, or unlink other sessions' sockets.
    fs.chmodSync(this.options.runtimeDir, 0o710);
    this.applyRuntimeOwnership(this.options.runtimeDir);
  }

  private applyRuntimeOwnership(target: string): void {
    const stat = fs.statSync(target);
    const ownerUid = typeof process.getuid === 'function' ? process.getuid() : 0;
    if (stat.uid === ownerUid && stat.gid === this.options.gatewayGid) return;
    try {
      fs.chownSync(target, ownerUid, this.options.gatewayGid);
    } catch (err) {
      const after = fs.statSync(target);
      if (after.uid !== ownerUid || after.gid !== this.options.gatewayGid) {
        const code = (err as NodeJS.ErrnoException).code || 'unknown';
        throw new Error(`Cannot set SSH agent runtime ownership (${code})`);
      }
    }
  }

  private applyGatewayOwnership(target: string): void {
    const stat = fs.statSync(target);
    if (stat.uid === this.options.gatewayUid && stat.gid === this.options.gatewayGid) return;
    try {
      fs.chownSync(target, this.options.gatewayUid, this.options.gatewayGid);
    } catch (err) {
      const after = fs.statSync(target);
      if (after.uid !== this.options.gatewayUid || after.gid !== this.options.gatewayGid) {
        const code = (err as NodeJS.ErrnoException).code || 'unknown';
        throw new Error(`Cannot set SSH agent gateway ownership (${code})`);
      }
    }
  }

  private reserveCreate(): void {
    if (this.closing) throw new Error('SSH agent lease manager is shutting down');
    if (this.leases.size + this.pendingCreates >= this.options.maxConcurrentLeases) {
      throw new Error('SSH agent lease capacity reached');
    }
    this.pendingCreates += 1;
  }

  private finishCreate(): void {
    this.pendingCreates -= 1;
    if (this.pendingCreates !== 0) return;
    const waiters = this.pendingCreateWaiters;
    this.pendingCreateWaiters = [];
    for (const resolve of waiters) resolve();
  }

  private waitForPendingCreates(): Promise<void> {
    if (this.pendingCreates === 0) return Promise.resolve();
    return new Promise((resolve) => this.pendingCreateWaiters.push(resolve));
  }

  private createLeaseDirectory(): { directory: string; socketPath: string } {
    for (let attempt = 0; attempt < LEASE_CREATE_ATTEMPTS; attempt += 1) {
      const token = randomBytes(LEASE_DIRECTORY_TOKEN_BYTES).toString('base64url');
      const directory = path.join(this.options.runtimeDir, `${LEASE_DIRECTORY_PREFIX}${token}`);
      try {
        // ssh-agent verifies peer UID in addition to socket permissions. It
        // runs as the fixed gateway identity and creates its socket inside a
        // private child; the broker-owned parent remains non-listable.
        fs.mkdirSync(directory, { mode: 0o700 });
        this.applyGatewayOwnership(directory);
        return { directory, socketPath: path.join(directory, LEASE_SOCKET_NAME) };
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === 'EEXIST') continue;
        throw err;
      }
    }
    throw new Error('Could not allocate a unique SSH agent lease directory');
  }

  async create(privateKey: string | Buffer): Promise<SshAgentLease> {
    this.reserveCreate();
    let keyBuffer: Buffer | undefined;
    try {
      keyBuffer = Buffer.isBuffer(privateKey)
        ? Buffer.from(privateKey)
        : Buffer.from(privateKey, 'utf8');
      if (keyBuffer.length === 0) throw new Error('SSH private key is empty');
      if (keyBuffer.length > MAX_PRIVATE_KEY_BYTES) throw new Error('SSH private key is too large');
      return await this.createReserved(keyBuffer);
    } finally {
      keyBuffer?.fill(0);
      this.finishCreate();
    }
  }

  private async createReserved(keyBuffer: Buffer): Promise<SshAgentLease> {
    const id = randomBytes(32).toString('base64url');
    const { directory, socketPath } = this.createLeaseDirectory();
    const agent = spawn(
      this.options.sshAgentPath,
      ['-D', '-a', socketPath, '-t', String(this.options.leaseTtlSeconds)],
      {
        uid: this.options.gatewayUid,
        gid: this.options.gatewayGid,
        env: { PATH: path.dirname(this.options.sshAgentPath), LANG: 'C' },
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      }
    );
    const diagnostics: AgentDiagnostics = {
      stderr: captureBoundedOutput(agent.stderr),
    };
    agent.stdout.resume();
    agent.once('error', (err) => {
      diagnostics.spawnError = err;
    });

    let agentExited = false;
    agent.once('exit', () => {
      agentExited = true;
      const current = this.leases.get(id);
      if (!current || current.releasing) return;
      clearTimeout(current.timer);
      this.leases.delete(id);
      this.removeLeaseDirectory(current.directory);
    });

    try {
      await waitForSocket(
        socketPath,
        agent,
        this.options.startupTimeoutMs ?? DEFAULT_STARTUP_TIMEOUT_MS,
        diagnostics
      );
      fs.chmodSync(socketPath, 0o600);
      this.applyGatewayOwnership(socketPath);

      await this.addKey(socketPath, keyBuffer);
      if (this.closing) throw new Error('SSH agent lease manager is shutting down');
      if (agentExited || !isProcessRunning(agent)) {
        throw new Error(`ssh-agent exited while loading the private key${diagnosticSuffix(diagnostics)}`);
      }

      const expiresAt = Date.now() + this.options.leaseTtlSeconds * 1000;
      const timer = setTimeout(() => {
        void this.release(id);
      }, this.options.leaseTtlSeconds * 1000);
      timer.unref();

      const active: ActiveLease = {
        id,
        socketPath,
        expiresAt,
        directory,
        process: agent,
        timer,
        releasing: false,
      };
      this.leases.set(id, active);
      return Object.freeze({ id, socketPath, expiresAt });
    } catch (err) {
      await terminateProcess(agent);
      this.removeLeaseDirectory(directory);
      throw err;
    }
  }

  private addKey(socketPath: string, privateKey: Buffer): Promise<void> {
    return new Promise((resolve, reject) => {
      const child = spawn(
        this.options.sshAddPath,
        ['-t', String(this.options.leaseTtlSeconds), '-'],
        {
          env: {
            PATH: path.dirname(this.options.sshAddPath),
            LANG: 'C',
            SSH_AUTH_SOCK: socketPath,
            SSH_ASKPASS: '',
            SSH_ASKPASS_REQUIRE: 'never',
          },
          stdio: ['pipe', 'pipe', 'pipe'],
          windowsHide: true,
        }
      );

      const stderr = captureBoundedOutput(child.stderr);
      child.stdout.resume();
      let settled = false;
      let timedOut = false;
      let killTimer: NodeJS.Timeout | undefined;
      const timeout = setTimeout(() => {
        timedOut = true;
        if (isProcessRunning(child)) child.kill('SIGTERM');
        killTimer = setTimeout(() => {
          if (isProcessRunning(child)) child.kill('SIGKILL');
          settle(new Error('Timed out while loading the configured private key with ssh-add'));
        }, 250);
        killTimer.unref();
      }, this.options.startupTimeoutMs ?? DEFAULT_STARTUP_TIMEOUT_MS);
      timeout.unref();

      const settle = (error?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        if (killTimer) clearTimeout(killTimer);
        if (error) reject(error);
        else resolve();
      };

      child.once('error', (err) => {
        settle(new Error(`Failed to start ssh-add: ${err.message}`));
      });
      child.stdin.on('error', (err: NodeJS.ErrnoException) => {
        // ssh-add may reject and close stdin before all key bytes are written.
        // Its close status and bounded stderr are the authoritative diagnostic.
        if (err.code !== 'EPIPE') {
          if (isProcessRunning(child)) child.kill('SIGTERM');
          settle(new Error(`Failed to write private key to ssh-add: ${err.message}`));
        }
      });
      child.once('close', (code, signal) => {
        if (timedOut) {
          settle(new Error('Timed out while loading the configured private key with ssh-add'));
          return;
        }
        if (code === 0) {
          settle();
          return;
        }
        const detail = stderr().trim().replace(/[\r\n]+/g, ' ').slice(0, 500);
        const status = code === null && signal ? ` (signal ${signal})` : '';
        settle(new Error(
          `ssh-add rejected the configured private key${status}${detail ? `: ${detail}` : ''}`
        ));
      });

      try {
        child.stdin.end(privateKey);
      } catch (err) {
        if (isProcessRunning(child)) child.kill('SIGTERM');
        settle(new Error(`Failed to write private key to ssh-add: ${(err as Error).message}`));
      }
    });
  }

  has(id: string): boolean {
    return this.leases.has(id);
  }

  get(id: string): SshAgentLease | undefined {
    const lease = this.leases.get(id);
    if (!lease) return undefined;
    return { id: lease.id, socketPath: lease.socketPath, expiresAt: lease.expiresAt };
  }

  async release(id: string): Promise<boolean> {
    const lease = this.leases.get(id);
    if (!lease || lease.releasing) return false;
    lease.releasing = true;
    clearTimeout(lease.timer);
    this.leases.delete(id);

    await terminateProcess(lease.process);
    this.removeLeaseDirectory(lease.directory);
    return true;
  }

  async close(): Promise<void> {
    this.closing = true;
    await this.waitForPendingCreates();
    await Promise.all([...this.leases.keys()].map((id) => this.release(id)));
  }

  private removeLeaseDirectory(directory: string): void {
    const relative = path.relative(this.options.runtimeDir, directory);
    if (!/^a-[A-Za-z0-9_-]{8}$/.test(relative) || path.dirname(directory) !== this.options.runtimeDir) return;
    try {
      fs.rmSync(directory, { recursive: true, force: true });
    } catch {
      // Cleanup is best-effort; never replace the primary process/key error.
    }
  }
}
