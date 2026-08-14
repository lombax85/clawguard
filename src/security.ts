import { URL } from 'url';
import dns from 'dns';
import net from 'net';
import { Config, SecurityConfig, ServiceConfig } from './types';

const PRIVATE_IP_BLOCKLIST = new net.BlockList();
const MAX_KNOWN_HOST_KEY_BYTES = 16 * 1024;
PRIVATE_IP_BLOCKLIST.addSubnet('0.0.0.0', 8, 'ipv4');
PRIVATE_IP_BLOCKLIST.addSubnet('10.0.0.0', 8, 'ipv4');
PRIVATE_IP_BLOCKLIST.addSubnet('100.64.0.0', 10, 'ipv4');
PRIVATE_IP_BLOCKLIST.addSubnet('127.0.0.0', 8, 'ipv4');
PRIVATE_IP_BLOCKLIST.addSubnet('169.254.0.0', 16, 'ipv4');
PRIVATE_IP_BLOCKLIST.addSubnet('172.16.0.0', 12, 'ipv4');
PRIVATE_IP_BLOCKLIST.addSubnet('192.168.0.0', 16, 'ipv4');
PRIVATE_IP_BLOCKLIST.addAddress('::', 'ipv6');
PRIVATE_IP_BLOCKLIST.addAddress('::1', 'ipv6');
PRIVATE_IP_BLOCKLIST.addSubnet('fc00::', 7, 'ipv6');
PRIVATE_IP_BLOCKLIST.addSubnet('fe80::', 10, 'ipv6');

function mappedIpv4Address(ip: string): string | undefined {
  let candidate = ip.toLowerCase();
  const dottedSeparator = candidate.lastIndexOf(':');
  if (candidate.includes('.') && dottedSeparator >= 0) {
    const dotted = candidate.slice(dottedSeparator + 1);
    if (!net.isIPv4(dotted)) return undefined;
    const octets = dotted.split('.').map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    candidate = `${candidate.slice(0, dottedSeparator + 1)}${high}:${low}`;
  }

  const halves = candidate.split('::');
  if (halves.length > 2) return undefined;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = halves.length === 2 ? 8 - left.length - right.length : 0;
  const hextets = [...left, ...Array(Math.max(0, missing)).fill('0'), ...right];
  if (hextets.length !== 8 || hextets.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) {
    return undefined;
  }
  const values = hextets.map((part) => parseInt(part, 16));
  if (!values.slice(0, 5).every((part) => part === 0) || values[5] !== 0xffff) {
    return undefined;
  }
  return [values[6] >> 8, values[6] & 0xff, values[7] >> 8, values[7] & 0xff].join('.');
}

export function isPrivateIP(ip: string): boolean {
  const normalized = ip.startsWith('[') && ip.endsWith(']') ? ip.slice(1, -1) : ip;
  const family = net.isIP(normalized);
  if (family === 0) return false;
  // Reject every IPv4-mapped IPv6 form conservatively. Downstream APIs do not
  // all classify these consistently, which can otherwise create SSRF bypasses.
  if (family === 6 && mappedIpv4Address(normalized) !== undefined) return true;
  return PRIVATE_IP_BLOCKLIST.check(normalized, family === 4 ? 'ipv4' : 'ipv6');
}

export function isAllowedUpstream(hostname: string, allowedUpstreams: string[]): boolean {
  if (allowedUpstreams.length === 0) return true; // no allowlist = allow all (backward compat)
  return allowedUpstreams.some((allowed) => {
    // exact match or subdomain match
    return hostname === allowed || hostname.endsWith('.' + allowed);
  });
}

export function validateUpstreamUrl(
  urlString: string,
  security: SecurityConfig,
  allowPrivateTarget: boolean = false
): { valid: boolean; reason?: string } {
  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch {
    return { valid: false, reason: `Invalid URL: ${urlString}` };
  }

  // Check allowlist
  if (!isAllowedUpstream(parsed.hostname, security.allowedUpstreams)) {
    return {
      valid: false,
      reason: `Upstream "${parsed.hostname}" is not in the allowed upstreams list`,
    };
  }

  // Check private IPs
  if (security.blockPrivateIPs && isPrivateIP(parsed.hostname) && !allowPrivateTarget) {
    return {
      valid: false,
      reason: `Upstream "${parsed.hostname}" resolves to a private IP (blocked by security policy)`,
    };
  }

  // Only allow http/https
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return {
      valid: false,
      reason: `Unsupported protocol: ${parsed.protocol}`,
    };
  }

  return { valid: true };
}

export interface SshValidationResult {
  valid: boolean;
  reason?: string;
  resolvedAddresses?: string[];
}

export type FtpValidationResult = SshValidationResult;

export type SshDnsResolver = (hostname: string) => Promise<Array<{ address: string; family: number }>>;

function parseSshTarget(upstream: string): { parsed?: URL; reason?: string } {
  let parsed: URL;
  try {
    parsed = new URL(upstream);
  } catch {
    return { reason: `Invalid SSH upstream URL: ${upstream}` };
  }

  if (parsed.protocol !== 'ssh:') return { reason: `SSH upstream must use ssh://, got ${parsed.protocol}` };
  if (!parsed.hostname) return { reason: 'SSH upstream must include a hostname' };
  if (!parsed.port) return { reason: 'SSH upstream must include an explicit port' };
  const port = Number(parsed.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { reason: 'SSH upstream port must be an integer between 1 and 65535' };
  }
  if (parsed.username || parsed.password) {
    return { reason: 'SSH upstream must not contain a username or password' };
  }
  if (parsed.pathname || parsed.search || parsed.hash) {
    return { reason: 'SSH upstream must be a fixed ssh://host:port target without path, query or fragment' };
  }
  return { parsed };
}

export function isValidKnownHostKey(value: unknown): boolean {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value || /[\r\n]/.test(value)) return false;
  if (Buffer.byteLength(value, 'utf8') > MAX_KNOWN_HOST_KEY_BYTES) return false;
  const parts = value.split(/[ \t]+/);
  if (parts.length !== 2 || !/^[A-Za-z0-9@._+-]+$/.test(parts[0])) return false;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(parts[1]) || parts[1].length % 4 === 1) return false;

  try {
    const blob = Buffer.from(parts[1], 'base64');
    if (blob.length < 9) return false;
    const typeLength = blob.readUInt32BE(0);
    if (typeLength === 0 || typeLength > blob.length - 5) return false;
    return blob.subarray(4, 4 + typeLength).toString('ascii') === parts[0];
  } catch {
    return false;
  }
}

/** Static, protocol-specific validation for one SSH service. */
export function validateSshService(service: ServiceConfig, security: SecurityConfig): SshValidationResult {
  if (service.protocol !== 'ssh') return { valid: false, reason: 'service.protocol must be ssh' };
  if (!service.ssh) return { valid: false, reason: 'service.ssh is required' };
  if (typeof service.ssh.allowPrivateTarget !== 'boolean') {
    return { valid: false, reason: 'ssh.allowPrivateTarget must be explicitly true or false' };
  }
  if (!isValidKnownHostKey(service.ssh.knownHostKey)) {
    return { valid: false, reason: 'ssh.knownHostKey must be one complete single-line OpenSSH public key (keytype base64)' };
  }

  const target = parseSshTarget(service.upstream);
  if (!target.parsed) return { valid: false, reason: target.reason };
  const hostname = target.parsed.hostname.replace(/^\[|\]$/g, '');
  if (!isAllowedUpstream(hostname, security.allowedUpstreams)) {
    return { valid: false, reason: `Upstream "${hostname}" is not in the allowed upstreams list` };
  }
  if (isPrivateIP(hostname) && !service.ssh.allowPrivateTarget) {
    return { valid: false, reason: `Private SSH target "${hostname}" requires ssh.allowPrivateTarget: true` };
  }
  return { valid: true };
}

const defaultSshDnsResolver: SshDnsResolver = async (hostname) => {
  return dns.promises.lookup(hostname, { all: true, verbatim: true });
};

/** Runtime DNS validation for SSH. Resolution errors and empty answers fail closed. */
export async function validateSshTargetRuntime(
  service: ServiceConfig,
  security: SecurityConfig,
  resolver: SshDnsResolver = defaultSshDnsResolver
): Promise<SshValidationResult> {
  const staticResult = validateSshService(service, security);
  if (!staticResult.valid) return staticResult;

  const target = parseSshTarget(service.upstream);
  const hostname = target.parsed!.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(hostname)) return { valid: true, resolvedAddresses: [hostname] };

  let answers: Array<{ address: string; family: number }>;
  try {
    answers = await resolver(hostname);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { valid: false, reason: `SSH target DNS resolution failed closed: ${message}` };
  }
  if (answers.length === 0) return { valid: false, reason: 'SSH target DNS resolution returned no addresses' };

  const addresses: string[] = [];
  for (const answer of answers) {
    const detectedFamily = net.isIP(answer.address);
    if (detectedFamily === 0 || detectedFamily !== answer.family) {
      return { valid: false, reason: `SSH target DNS returned an invalid address: ${answer.address}` };
    }
    if (isPrivateIP(answer.address) && !service.ssh!.allowPrivateTarget) {
      return { valid: false, reason: `SSH target resolves to private address ${answer.address}; explicit opt-in required` };
    }
    addresses.push(answer.address);
  }
  return { valid: true, resolvedAddresses: addresses };
}

function explicitFtpPort(upstream: string): number | undefined {
  const schemeEnd = upstream.indexOf('://');
  if (schemeEnd < 0) return undefined;
  const authority = upstream.slice(schemeEnd + 3).split(/[/?#]/, 1)[0];
  const match = authority.startsWith('[')
    ? authority.match(/^\[[^\]]+\]:(\d+)$/)
    : authority.match(/:([0-9]+)$/);
  if (!match) return undefined;
  const port = Number(match[1]);
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : undefined;
}

function parseFtpTarget(service: ServiceConfig): { parsed?: URL; port?: number; reason?: string } {
  let parsed: URL;
  try {
    parsed = new URL(service.upstream);
  } catch {
    return { reason: `Invalid FTP upstream URL: ${service.upstream}` };
  }
  const expected = service.protocol === 'ftps' ? 'ftps:' : 'ftp:';
  if (parsed.protocol !== expected) {
    return { reason: `${String(service.protocol).toUpperCase()} upstream must use ${expected}//, got ${parsed.protocol}` };
  }
  if (!parsed.hostname) return { reason: 'FTP upstream must include a hostname' };
  const port = explicitFtpPort(service.upstream);
  if (port === undefined) {
    return { reason: 'FTP upstream port must be an integer between 1 and 65535' };
  }
  if (parsed.username || parsed.password) return { reason: 'FTP upstream must not contain credentials' };
  if ((parsed.pathname && parsed.pathname !== '/') || parsed.search || parsed.hash) {
    return { reason: 'FTP upstream must be a fixed scheme://host:port target without path, query or fragment' };
  }
  return { parsed, port };
}

function isValidFtpRoot(root: unknown): boolean {
  if (root === undefined) return true;
  if (typeof root !== 'string' || Buffer.byteLength(root, 'utf8') > 1024 || /[\0\r\n]/.test(root)) return false;
  if (root.startsWith('/') || root.endsWith('/')) return false;
  return !root.split('/').some((segment) => segment.length === 0 || segment === '.' || segment === '..');
}

/** Static, protocol-specific validation for one FTP or FTPS service. */
export function validateFtpService(service: ServiceConfig, security: SecurityConfig): FtpValidationResult {
  if (service.protocol !== 'ftp' && service.protocol !== 'ftps') {
    return { valid: false, reason: 'service.protocol must be ftp or ftps' };
  }
  if (!service.ftp || typeof service.ftp.allowPrivateTarget !== 'boolean') {
    return { valid: false, reason: 'ftp.allowPrivateTarget must be explicitly true or false' };
  }
  if (!isValidFtpRoot(service.ftp.root)) {
    return { valid: false, reason: 'ftp.root must be a normalized relative path without empty, dot, or parent segments' };
  }
  if (service.protocol === 'ftp') {
    if (service.ftp.tlsMode !== undefined) return { valid: false, reason: 'plain FTP must not define ftp.tlsMode' };
    if (service.ftp.noCheckCertificate) return { valid: false, reason: 'plain FTP must not disable TLS certificate checks' };
  } else if (service.ftp.tlsMode !== 'explicit' && service.ftp.tlsMode !== 'implicit') {
    return { valid: false, reason: 'FTPS requires ftp.tlsMode: explicit or implicit' };
  }

  const target = parseFtpTarget(service);
  if (!target.parsed) return { valid: false, reason: target.reason };
  const hostname = target.parsed.hostname.replace(/^\[|\]$/g, '');
  if (!isAllowedUpstream(hostname, security.allowedUpstreams)) {
    return { valid: false, reason: `Upstream "${hostname}" is not in the allowed upstreams list` };
  }
  if (isPrivateIP(hostname) && !service.ftp.allowPrivateTarget) {
    return { valid: false, reason: `Private FTP target "${hostname}" requires ftp.allowPrivateTarget: true` };
  }
  return { valid: true };
}

/** Runtime DNS validation for FTP/FTPS; the resulting IP set is pinned by the sidecar's SOCKS relay. */
export async function validateFtpTargetRuntime(
  service: ServiceConfig,
  security: SecurityConfig,
  resolver: SshDnsResolver = defaultSshDnsResolver
): Promise<FtpValidationResult> {
  const staticResult = validateFtpService(service, security);
  if (!staticResult.valid) return staticResult;

  const target = parseFtpTarget(service);
  const hostname = target.parsed!.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(hostname)) return { valid: true, resolvedAddresses: [hostname] };

  let answers: Array<{ address: string; family: number }>;
  try {
    answers = await resolver(hostname);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { valid: false, reason: `FTP target DNS resolution failed closed: ${message}` };
  }
  if (answers.length === 0) return { valid: false, reason: 'FTP target DNS resolution returned no addresses' };

  const addresses: string[] = [];
  for (const answer of answers) {
    const detectedFamily = net.isIP(answer.address);
    if (detectedFamily === 0 || detectedFamily !== answer.family) {
      return { valid: false, reason: `FTP target DNS returned an invalid address: ${answer.address}` };
    }
    if (isPrivateIP(answer.address) && !service.ftp!.allowPrivateTarget) {
      return { valid: false, reason: `FTP target resolves to private address ${answer.address}; explicit opt-in required` };
    }
    addresses.push(answer.address);
  }
  return { valid: true, resolvedAddresses: [...new Set(addresses)] };
}

/**
 * Validates all configured service upstreams at startup.
 * Exits the process if any upstream is invalid.
 */
export function validateAllUpstreams(config: Config): void {
  const security = config.security;

  for (const [name, service] of Object.entries(config.services)) {
    // Validate upstream URL against allowlist
    const result = service.protocol === 'ssh'
      ? validateSshService(service, security)
      : service.protocol === 'ftp' || service.protocol === 'ftps'
        ? validateFtpService(service, security)
        : validateUpstreamUrl(
          service.upstream,
          security,
          service.http?.allowPrivateTarget === true
        );
    if (!result.valid) {
      console.error(`❌ Security violation for service "${name}": ${result.reason}`);
      process.exit(1);
    }
    console.log(`   ✓ ${name}: ${service.upstream} (allowed)`);

    // Validate hostnames: each hostname used for host-based routing
    // MUST correspond to the upstream's domain. This prevents an attacker
    // from injecting a hostname that routes to their own server.
    if ((service.protocol ?? 'http') === 'http' && service.hostnames && service.hostnames.length > 0) {
      const upstreamHost = new URL(service.upstream).hostname;
      for (const hostname of service.hostnames) {
        // The hostname must either match the upstream domain exactly
        // or be in the security allowlist
        if (hostname !== upstreamHost && !isAllowedUpstream(hostname, security.allowedUpstreams)) {
          console.error(`❌ Security violation for service "${name}": hostname "${hostname}" is not in the allowed upstreams list`);
          process.exit(1);
        }
      }
      console.log(`   ✓ ${name}: host-based routing for [${service.hostnames.join(', ')}]`);
    }
  }
}

/**
 * Validates a fully constructed upstream URL at runtime,
 * before forwarding the request. Prevents path traversal attacks
 * that could change the target host.
 */
export function validateRuntimeUrl(
  constructedUrl: string,
  originalUpstream: string,
  security: SecurityConfig,
  allowPrivateTarget: boolean = false
): { valid: boolean; reason?: string } {
  let constructed: URL;
  let original: URL;

  try {
    constructed = new URL(constructedUrl);
    original = new URL(originalUpstream);
  } catch {
    return { valid: false, reason: 'Failed to parse URL' };
  }

  // The constructed URL must resolve to the same host as the configured upstream
  if (constructed.hostname !== original.hostname) {
    return {
      valid: false,
      reason: `Path traversal detected: constructed URL points to "${constructed.hostname}" instead of "${original.hostname}"`,
    };
  }

  // Re-validate against security policy
  return validateUpstreamUrl(constructedUrl, security, allowPrivateTarget);
}

/**
 * Async DNS resolution check — resolves hostname and checks
 * if it points to a private IP. Use for runtime validation.
 */
export async function resolveAndCheckPrivateIP(hostname: string): Promise<boolean> {
  return new Promise((resolve) => {
    dns.resolve4(hostname, (err, addresses) => {
      if (err) {
        resolve(false); // can't resolve = not private
        return;
      }
      const hasPrivate = addresses.some((addr) => isPrivateIP(addr));
      resolve(hasPrivate);
    });
  });
}
