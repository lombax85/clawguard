import { ChildProcess, spawn } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import net from 'net';
import { Config, ServiceConfig } from './types';
import { isAllowedUpstream, isValidKnownHostKey, validateSshTargetRuntime } from './security';

const MAX_PRIVATE_KEY_BYTES = 1024 * 1024;
const SSH_KEY_TOOL_TIMEOUT_MS = 10_000;
const SSH_AGENT_START_TIMEOUT_MS = 2_000;
const MAX_TOOL_OUTPUT_BYTES = 1024 * 1024;
const MAX_HOST_SCAN_ADDRESSES = 8;
const HOST_KEY_SCAN_TIMEOUT_SECONDS = 5;
const SSH_HOST_KEY_PROBE = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC';

type JsonObject = Record<string, unknown>;

export type AdminSshKeyMode = 'paste' | 'generate' | 'reuse' | 'keep';

export interface AdminSshPublicKeyInfo {
  publicKey: string;
  fingerprint: string;
}

export interface AdminSshGeneratedKey extends AdminSshPublicKeyInfo {
  privateKey: string;
}

export interface AdminSshHostKeyInfo extends AdminSshPublicKeyInfo {
  algorithm: string;
  recommended: boolean;
}

export interface AdminSshKeyTools {
  generate(comment: string): Promise<AdminSshGeneratedKey>;
  inspect(privateKey: string): Promise<AdminSshPublicKeyInfo>;
  scanHost(addresses: string[], port: number): Promise<AdminSshHostKeyInfo[]>;
}

export interface AdminSshWizardResult {
  service: ServiceConfig;
  keyInfo?: AdminSshPublicKeyInfo;
  keyMode: AdminSshKeyMode;
}

export interface AdminSshKeySource {
  service: string;
  services: string[];
  upstream: string;
  username: string;
}

export interface AdminSshWizardMetadata {
  available: boolean;
  username?: string;
  hostKey?: {
    algorithm: string;
    fingerprint: string;
  };
}

export interface AdminSshHostKeyDiscovery {
  host: string;
  port: number;
  keys: AdminSshHostKeyInfo[];
}

function isPlainObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${field} is required`);
  }
  return value.trim();
}

interface ProcessResult {
  stdout: string;
  stderr: string;
}

function runProcess(
  command: string,
  args: string[],
  env: NodeJS.ProcessEnv,
  input?: string
): Promise<ProcessResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env, stdio: ['pipe', 'pipe', 'pipe'] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let outputBytes = 0;
    let settled = false;
    const finish = (err?: Error, result?: ProcessResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (err) reject(err);
      else resolve(result!);
    };
    const collect = (target: Buffer[]) => (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes > MAX_TOOL_OUTPUT_BYTES) {
        child.kill('SIGKILL');
        finish(new Error('SSH key tool produced too much output'));
        return;
      }
      target.push(Buffer.from(chunk));
    };
    child.stdout.on('data', collect(stdout));
    child.stderr.on('data', collect(stderr));
    child.on('error', (err) => finish(err));
    child.on('close', (code) => {
      const result = {
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      };
      if (code === 0) finish(undefined, result);
      else finish(new Error(`SSH key tool exited with code ${String(code)}`));
    });
    const timeout = setTimeout(() => {
      child.kill('SIGKILL');
      finish(new Error('SSH key tool timed out'));
    }, SSH_KEY_TOOL_TIMEOUT_MS);

    if (input !== undefined) {
      const inputBuffer = Buffer.from(input, 'utf8');
      child.stdin.end(inputBuffer, () => inputBuffer.fill(0));
    } else {
      child.stdin.end();
    }
  });
}

function uint32(value: number): Buffer {
  const result = Buffer.allocUnsafe(4);
  result.writeUInt32BE(value >>> 0);
  return result;
}

function sshString(value: string | Buffer): Buffer {
  const content = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
  return Buffer.concat([uint32(content.length), content]);
}

function base64UrlBuffer(value: string): Buffer {
  return Buffer.from(value, 'base64url');
}

function publicKeyInfo(publicKey: string): AdminSshPublicKeyInfo {
  const parts = publicKey.trim().split(/[ \t]+/);
  if (parts.length < 2 || !parts[0] || !parts[1]) {
    throw new Error('SSH agent returned an invalid public key');
  }
  let blob: Buffer;
  try {
    blob = Buffer.from(parts[1], 'base64');
  } catch {
    throw new Error('SSH agent returned an invalid public key');
  }
  if (blob.length === 0) throw new Error('SSH agent returned an empty public key');
  const fingerprint = `SHA256:${crypto.createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;
  return { publicKey: parts.join(' '), fingerprint };
}

function generateOpenSshEd25519Key(comment: string): AdminSshGeneratedKey {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = privateKey.export({ format: 'jwk' });
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.x || !jwk.d) {
    throw new Error('Unable to export generated Ed25519 key');
  }
  const publicBytes = base64UrlBuffer(jwk.x);
  const seed = base64UrlBuffer(jwk.d);
  if (publicBytes.length !== 32 || seed.length !== 32) {
    throw new Error('Generated Ed25519 key has an invalid size');
  }

  const keyType = 'ssh-ed25519';
  const publicBlob = Buffer.concat([sshString(keyType), sshString(publicBytes)]);
  const check = crypto.randomBytes(4).readUInt32BE(0);
  const unpaddedPrivate = Buffer.concat([
    uint32(check),
    uint32(check),
    sshString(keyType),
    sshString(publicBytes),
    sshString(Buffer.concat([seed, publicBytes])),
    sshString(comment),
  ]);
  const paddingLength = 8 - (unpaddedPrivate.length % 8);
  const padding = Buffer.from(Array.from({ length: paddingLength }, (_, index) => index + 1));
  const privateBlock = Buffer.concat([unpaddedPrivate, padding]);
  const encoded = Buffer.concat([
    Buffer.from('openssh-key-v1\0', 'utf8'),
    sshString('none'),
    sshString('none'),
    sshString(Buffer.alloc(0)),
    uint32(1),
    sshString(publicBlob),
    sshString(privateBlock),
  ]).toString('base64').match(/.{1,70}/g)?.join('\n');
  if (!encoded) throw new Error('Unable to encode generated Ed25519 key');

  const publicKey = `${keyType} ${publicBlob.toString('base64')} ${comment}`;
  return {
    privateKey: `-----BEGIN OPENSSH PRIVATE KEY-----\n${encoded}\n-----END OPENSSH PRIVATE KEY-----\n`,
    ...publicKeyInfo(publicKey),
  };
}

function waitForAgentSocket(socketPath: string, child: ChildProcess): Promise<void> {
  return new Promise((resolve, reject) => {
    const startedAt = Date.now();
    const check = () => {
      if (fs.existsSync(socketPath)) {
        resolve();
        return;
      }
      if (child.exitCode !== null || Date.now() - startedAt >= SSH_AGENT_START_TIMEOUT_MS) {
        reject(new Error('SSH agent did not create its socket'));
        return;
      }
      setTimeout(check, 20);
    };
    check();
  });
}

async function stopAgent(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null) return;
  await new Promise<void>((resolve) => {
    const timeout = setTimeout(() => {
      if (child.exitCode === null) child.kill('SIGKILL');
      resolve();
    }, 500);
    child.once('close', () => {
      clearTimeout(timeout);
      resolve();
    });
    child.kill('SIGTERM');
  });
}

async function inspectWithEphemeralAgent(
  privateKey: string,
  sshAgentPath: string,
  sshAddPath: string
): Promise<AdminSshPublicKeyInfo> {
  if (Buffer.byteLength(privateKey, 'utf8') > MAX_PRIVATE_KEY_BYTES) {
    throw new Error('Private key is too large');
  }
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'clawguard-admin-ssh-agent-'));
  fs.chmodSync(directory, 0o700);
  const socketPath = path.join(directory, 'agent.sock');
  const agent = spawn(sshAgentPath, ['-D', '-a', socketPath], {
    stdio: ['ignore', 'ignore', 'ignore'],
  });
  try {
    await waitForAgentSocket(socketPath, agent);
    const env = { ...process.env, SSH_AUTH_SOCK: socketPath };
    await runProcess(sshAddPath, ['-'], env, privateKey);
    const listed = await runProcess(sshAddPath, ['-L'], env);
    const keys = listed.stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    if (keys.length !== 1) throw new Error('SSH agent did not return exactly one public key');
    return publicKeyInfo(keys[0]);
  } catch {
    throw new Error('Private key is invalid or encrypted; provide an unencrypted OpenSSH private key');
  } finally {
    await stopAgent(agent);
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

function hostKeyPreference(algorithm: string): number {
  if (algorithm === 'ssh-ed25519') return 0;
  if (algorithm.startsWith('ecdsa-sha2-')) return 1;
  if (algorithm === 'ssh-rsa') return 2;
  return 3;
}

async function scanHostKeys(
  addresses: string[],
  port: number,
  sshKeyscanPath: string
): Promise<AdminSshHostKeyInfo[]> {
  const scanAddresses = [...new Set(addresses)].slice(0, MAX_HOST_SCAN_ADDRESSES);
  if (scanAddresses.length === 0) throw new Error('SSH target resolved to no addresses');

  // Scan only the literal IPs returned by the validated DNS lookup. This avoids
  // resolving the hostname a second time between the SSRF check and key scan.
  const results = await Promise.allSettled(scanAddresses.map((address) => runProcess(
    sshKeyscanPath,
    [
      '-T', String(HOST_KEY_SCAN_TIMEOUT_SECONDS),
      '-p', String(port),
      '-t', 'ed25519,ecdsa,rsa',
      address,
    ],
    process.env
  )));

  const discovered = new Map<string, AdminSshHostKeyInfo>();
  for (const result of results) {
    if (result.status !== 'fulfilled') continue;
    for (const line of result.value.stdout.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      try {
        const publicKey = normalizeKnownHostKey(trimmed);
        if (!isValidKnownHostKey(publicKey)) continue;
        const identity = publicKeyInfo(publicKey);
        discovered.set(publicKey, {
          ...identity,
          algorithm: publicKey.split(/[ \t]+/, 1)[0],
          recommended: false,
        });
      } catch {
        // Ignore malformed tool output and fail closed if no valid key remains.
      }
    }
  }

  const keys = [...discovered.values()].sort((a, b) =>
    hostKeyPreference(a.algorithm) - hostKeyPreference(b.algorithm)
      || a.fingerprint.localeCompare(b.fingerprint)
  );
  if (keys.length === 0) {
    throw new Error('ClawGuard could not read an SSH host key. Check the host, port, firewall, and SSH service.');
  }
  keys[0].recommended = true;
  return keys;
}

export function createAdminSshKeyTools(
  sshAgentPath = 'ssh-agent',
  sshAddPath = 'ssh-add',
  sshKeyscanPath = 'ssh-keyscan'
): AdminSshKeyTools {
  return {
    async generate(comment: string): Promise<AdminSshGeneratedKey> {
      return generateOpenSshEd25519Key(comment);
    },
    inspect(privateKey: string): Promise<AdminSshPublicKeyInfo> {
      return inspectWithEphemeralAgent(privateKey, sshAgentPath, sshAddPath);
    },
    scanHost(addresses: string[], port: number): Promise<AdminSshHostKeyInfo[]> {
      return scanHostKeys(addresses, port, sshKeyscanPath);
    },
  };
}

function reusablePrivateKey(service: ServiceConfig | undefined): string | undefined {
  if (service?.protocol !== 'ssh'
    || service.auth?.type !== 'plugin'
    || service.auth.pluginPath !== 'ssh-agent-key'
    || !isPlainObject(service.auth.pluginConfig)) {
    return undefined;
  }
  const value = service.auth.pluginConfig['privateKey'];
  if (typeof value === 'string' && value.trim().length > 0) return value;
  if (Buffer.isBuffer(value) && value.length > 0) return value.toString('utf8');
  return undefined;
}

function reusableUsername(service: ServiceConfig | undefined): string | undefined {
  if (service?.protocol !== 'ssh'
    || service.auth?.type !== 'plugin'
    || service.auth.pluginPath !== 'ssh-agent-key'
    || !isPlainObject(service.auth.pluginConfig)) {
    return undefined;
  }
  const username = service.auth.pluginConfig['username'];
  return typeof username === 'string' && username.trim().length > 0
    ? username.trim()
    : undefined;
}

export function listAdminSshKeySources(config: Config): AdminSshKeySource[] {
  const sourcesByPrivateKey = new Map<string, AdminSshKeySource>();
  for (const [name, service] of Object.entries(config.services)
    .sort(([left], [right]) => left.localeCompare(right))) {
    const username = reusableUsername(service);
    const privateKey = reusablePrivateKey(service);
    if (!username || !privateKey) continue;
    const existing = sourcesByPrivateKey.get(privateKey);
    if (existing) existing.services.push(name);
    else sourcesByPrivateKey.set(privateKey, {
      service: name,
      services: [name],
      upstream: service.upstream,
      username,
    });
  }
  return [...sourcesByPrivateKey.values()];
}

export function getAdminSshWizardMetadata(service: ServiceConfig): AdminSshWizardMetadata {
  const username = reusableUsername(service);
  if (!username || !reusablePrivateKey(service)) return { available: false };
  const metadata: AdminSshWizardMetadata = { available: true, username };
  if (service.ssh?.knownHostKey && isValidKnownHostKey(service.ssh.knownHostKey)) {
    const identity = publicKeyInfo(service.ssh.knownHostKey);
    metadata.hostKey = {
      algorithm: service.ssh.knownHostKey.split(/[ \t]+/, 1)[0],
      fingerprint: identity.fingerprint,
    };
  }
  return metadata;
}

function normalizeKnownHostKey(value: unknown): string {
  const raw = requiredString(value, 'Host public key');
  if (/\r|\n/.test(raw)) throw new Error('Host public key must contain exactly one key');
  const parts = raw.split(/[ \t]+/);
  const looksLikeKeyType = (part: string | undefined) =>
    part !== undefined && /^(?:ssh-|ecdsa-|sk-)/.test(part);
  if (looksLikeKeyType(parts[0])) {
    if (parts.length < 2) throw new Error('Host public key is incomplete');
    return `${parts[0]} ${parts[1]}`;
  }
  if (looksLikeKeyType(parts[1]) && parts.length >= 3) {
    // Accept one ssh-keyscan/known_hosts line and discard its host prefix.
    return `${parts[1]} ${parts[2]}`;
  }
  return raw;
}

function normalizeHost(value: unknown): string {
  let host = requiredString(value, 'SSH host');
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (/[:][/][/]|[\s/@?#\\]/.test(host)) {
    throw new Error('SSH host must be a hostname or IP address without scheme, port, path, or credentials');
  }
  if (host.includes(':') && !net.isIPv6(host)) {
    throw new Error('SSH port must be entered in the separate port field');
  }
  return host;
}

function formatSshUpstream(host: string, port: number): string {
  return `ssh://${net.isIPv6(host) ? `[${host}]` : host}:${port}`;
}

function normalizePort(value: unknown): number {
  const port = value === undefined ? 22 : Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('SSH port must be an integer between 1 and 65535');
  }
  return port;
}

export async function discoverAdminSshHostKeys(
  candidate: unknown,
  config: Config,
  keyTools: AdminSshKeyTools
): Promise<AdminSshHostKeyDiscovery> {
  if (!isPlainObject(candidate)) throw new Error('SSH target must be a JSON object');
  const host = normalizeHost(candidate['host']);
  const port = normalizePort(candidate['port']);
  if (typeof candidate['allowPrivateTarget'] !== 'boolean') {
    throw new Error('Private target choice is required');
  }
  if (config.security.allowedUpstreams.length === 0
    || !isAllowedUpstream(host, config.security.allowedUpstreams)) {
    throw new Error('Automatic host identity detection requires the SSH host to be covered by security.allowedUpstreams');
  }

  const probe: ServiceConfig = {
    protocol: 'ssh',
    upstream: formatSshUpstream(host, port),
    auth: {
      type: 'plugin',
      token: 'unused',
      pluginPath: 'ssh-agent-key',
      pluginConfig: { username: 'clawguard-probe', privateKey: 'not-used' },
    },
    policy: { default: 'require_approval' },
    ssh: {
      knownHostKey: SSH_HOST_KEY_PROBE,
      allowPrivateTarget: candidate['allowPrivateTarget'],
    },
  };
  const validation = await validateSshTargetRuntime(probe, config.security);
  if (!validation.valid) {
    throw new Error(validation.reason || 'SSH target validation failed');
  }
  const addresses = validation.resolvedAddresses || [host];
  const keys = await keyTools.scanHost(addresses, port);
  return { host, port, keys };
}

function keyModeFrom(value: unknown, editing: boolean): AdminSshKeyMode {
  if (!isPlainObject(value)) throw new Error('SSH key source is required');
  const mode = value['mode'];
  const allowed = editing
    ? new Set(['paste', 'generate', 'reuse', 'keep'])
    : new Set(['paste', 'generate', 'reuse']);
  if (typeof mode !== 'string' || !allowed.has(mode)) {
    throw new Error(`SSH key mode must be ${editing ? 'keep, paste, generate, or reuse' : 'paste, generate, or reuse'}`);
  }
  return mode as AdminSshKeyMode;
}

export async function buildAdminSshService(
  candidate: unknown,
  config: Config,
  keyTools: AdminSshKeyTools,
  existing?: ServiceConfig
): Promise<AdminSshWizardResult> {
  if (!isPlainObject(candidate)) throw new Error('SSH host configuration must be a JSON object');

  const name = requiredString(candidate['name'], 'Host ID');
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(name)) {
    throw new Error('Host ID must be 1-64 letters, digits, hyphens, or underscores');
  }
  const host = normalizeHost(candidate['host']);
  const username = requiredString(candidate['username'], 'SSH username');
  if (!/^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$/.test(username)) {
    throw new Error('SSH username contains unsupported characters');
  }
  const port = normalizePort(candidate['port']);
  if (typeof candidate['allowPrivateTarget'] !== 'boolean') {
    throw new Error('Private target choice is required');
  }
  const knownHostKey = normalizeKnownHostKey(candidate['knownHostKey']);
  const key = candidate['key'];
  const keyMode = keyModeFrom(key, existing !== undefined);
  const keyObject = key as JsonObject;

  let privateKey: string;
  let keyInfo: AdminSshPublicKeyInfo | undefined;
  if (keyMode === 'keep') {
    privateKey = reusablePrivateKey(existing)
      || (() => { throw new Error('The current SSH service has no reusable built-in key'); })();
  } else if (keyMode === 'reuse') {
    const sourceName = requiredString(keyObject['sourceService'], 'Source SSH service');
    const source = config.services[sourceName];
    privateKey = reusablePrivateKey(source)
      || (() => { throw new Error(`SSH service "${sourceName}" has no reusable built-in key`); })();
    keyInfo = await keyTools.inspect(privateKey);
  } else if (keyMode === 'paste') {
    privateKey = requiredString(keyObject['privateKey'], 'Private key');
    keyInfo = await keyTools.inspect(privateKey);
  } else {
    const generated = await keyTools.generate(`clawguard-${name}`);
    privateKey = generated.privateKey;
    keyInfo = { publicKey: generated.publicKey, fingerprint: generated.fingerprint };
  }

  const base = existing ? structuredClone(existing) : undefined;
  const service: ServiceConfig = {
    ...(base || {}),
    protocol: 'ssh',
    upstream: formatSshUpstream(host, port),
    auth: {
      type: 'plugin',
      token: 'unused',
      pluginPath: 'ssh-agent-key',
      pluginConfig: { username, privateKey },
    },
    policy: base?.policy || { default: 'require_approval' },
    ssh: {
      ...(base?.ssh || {}),
      knownHostKey,
      allowPrivateTarget: candidate['allowPrivateTarget'],
    },
  };
  delete service.hostnames;
  delete service.http;
  delete service.ftp;

  return { service, keyInfo, keyMode };
}
