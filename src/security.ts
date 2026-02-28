import { URL } from 'url';
import dns from 'dns';
import { Config, SecurityConfig } from './types';

const PRIVATE_IP_RANGES = [
  /^127\./,                    // loopback
  /^10\./,                     // class A private
  /^172\.(1[6-9]|2\d|3[01])\./, // class B private
  /^192\.168\./,               // class C private
  /^169\.254\./,               // link-local
  /^0\./,                      // current network
  /^::1$/,                     // IPv6 loopback
  /^fc00:/i,                   // IPv6 unique local
  /^fe80:/i,                   // IPv6 link-local
];

export function isPrivateIP(ip: string): boolean {
  return PRIVATE_IP_RANGES.some((range) => range.test(ip));
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
  security: SecurityConfig
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
  if (security.blockPrivateIPs && isPrivateIP(parsed.hostname)) {
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

/**
 * Validates all configured service upstreams at startup.
 * Exits the process if any upstream is invalid.
 */
export function validateAllUpstreams(config: Config): void {
  const security = config.security;

  for (const [name, service] of Object.entries(config.services)) {
    // Validate upstream URL against allowlist
    const result = validateUpstreamUrl(service.upstream, security);
    if (!result.valid) {
      console.error(`❌ Security violation for service "${name}": ${result.reason}`);
      process.exit(1);
    }
    console.log(`   ✓ ${name}: ${service.upstream} (allowed)`);

    // Validate hostnames: each hostname used for host-based routing
    // MUST correspond to the upstream's domain. This prevents an attacker
    // from injecting a hostname that routes to their own server.
    if (service.hostnames && service.hostnames.length > 0) {
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
  security: SecurityConfig
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
  return validateUpstreamUrl(constructedUrl, security);
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
