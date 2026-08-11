#!/usr/bin/env node

'use strict';

const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const { spawnSync } = require('child_process');

const CONFIG_PATH = process.env.CLAWGUARD_FORWARDER_CONFIG
  || path.join(__dirname, 'forwarder.json');
const APPROVAL_TIMEOUT_MS = 125_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;

function usage(exitCode = 0) {
  const stream = exitCode === 0 ? process.stdout : process.stderr;
  stream.write(`Usage:
  clawguard-ftp.js list SERVICE [REMOTE_PATH] --user TEXT --reason TEXT [--insecure]
  clawguard-ftp.js lease SERVICE --user TEXT --reason TEXT [--insecure]
  clawguard-ftp.js revoke LEASE_ID --user TEXT --reason TEXT [--insecure]

Environment alternatives:
  CLAWGUARD_USER, CLAWGUARD_REASON, CLAWGUARD_FORWARDER_CONFIG

The list command keeps the ephemeral password out of process arguments and
revokes the lease automatically. The lease command prints credential-bearing
JSON; use it only when another FTP client must consume the lease directly.
`);
  process.exit(exitCode);
}

function fail(message) {
  console.error(`clawguard-ftp: ${message}`);
  process.exitCode = 1;
}

function parseArgs(argv) {
  const positional = [];
  const options = {
    user: process.env.CLAWGUARD_USER || '',
    reason: process.env.CLAWGUARD_REASON || '',
    insecure: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') usage(0);
    if (arg === '--insecure' || arg === '-k') {
      options.insecure = true;
      continue;
    }
    if (arg === '--user' || arg === '--reason') {
      const value = argv[i + 1];
      if (!value || value.startsWith('--')) usage(2);
      options[arg.slice(2)] = value;
      i += 1;
      continue;
    }
    if (arg.startsWith('--')) usage(2);
    positional.push(arg);
  }

  const [command, target, remotePath] = positional;
  if (!command || !target || positional.length > 3) usage(2);
  if (!['list', 'lease', 'revoke'].includes(command)) usage(2);
  if (command !== 'list' && remotePath !== undefined) usage(2);
  if (!options.user.trim() || !options.reason.trim()) {
    throw new Error('both --user and --reason are required (or set CLAWGUARD_USER and CLAWGUARD_REASON)');
  }
  rejectControlChars(options.user, 'user');
  rejectControlChars(options.reason, 'reason');
  return { command, target, remotePath: remotePath || '/', ...options };
}

function rejectControlChars(value, label) {
  if (/[\x00-\x1f\x7f]/.test(value)) throw new Error(`${label} contains invalid control characters`);
}

function loadConfig() {
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch (error) {
    throw new Error(`cannot read forwarder config at ${CONFIG_PATH}: ${error.message}`);
  }
  if (!parsed.agentKey || typeof parsed.agentKey !== 'string') {
    throw new Error('forwarder config has no agentKey');
  }

  let api = parsed.ftpApi;
  if (!api) {
    let gateway;
    try {
      gateway = new URL(parsed.clawguard);
    } catch {
      throw new Error('forwarder config needs ftpApi or a valid clawguard URL');
    }
    api = `https://${gateway.hostname}:9443`;
  }

  let apiUrl;
  try {
    apiUrl = new URL(api);
  } catch {
    throw new Error('ftpApi is not a valid URL');
  }
  if (!['https:', 'http:'].includes(apiUrl.protocol)) {
    throw new Error('ftpApi must use HTTP or HTTPS');
  }
  return { agentKey: parsed.agentKey, apiUrl };
}

function apiRequest(config, method, pathname, options, body) {
  const requestUrl = new URL(pathname, config.apiUrl);
  const transport = requestUrl.protocol === 'https:' ? https : http;
  const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));

  return new Promise((resolve, reject) => {
    const req = transport.request(requestUrl, {
      method,
      rejectUnauthorized: !options.insecure,
      timeout: APPROVAL_TIMEOUT_MS,
      headers: {
        'X-ClawGuard-Key': config.agentKey,
        'X-ClawGuard-User': options.user,
        'X-ClawGuard-Reason': options.reason,
        Accept: 'application/json',
        ...(payload ? {
          'Content-Type': 'application/json',
          'Content-Length': payload.length,
        } : {}),
      },
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) {
          req.destroy(new Error('ClawGuard response is too large'));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        const status = res.statusCode || 0;
        if (status === 403) {
          reject(new Error('approval denied or timed out; approve in Telegram and run again manually'));
          return;
        }
        if (status < 200 || status >= 300) {
          reject(new Error(`ClawGuard FTP API returned HTTP ${status}`));
          return;
        }
        const text = Buffer.concat(chunks).toString('utf8');
        if (!text) {
          resolve({});
          return;
        }
        try {
          resolve(JSON.parse(text));
        } catch {
          reject(new Error('ClawGuard FTP API returned invalid JSON'));
        }
      });
    });

    req.on('timeout', () => req.destroy(new Error('ClawGuard approval timed out')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function validateLease(lease) {
  const stringFields = ['id', 'protocol', 'host', 'username', 'password'];
  for (const field of stringFields) {
    if (!lease || typeof lease[field] !== 'string' || !lease[field]) {
      throw new Error(`lease response is missing ${field}`);
    }
    rejectControlChars(lease[field], `lease ${field}`);
  }
  if (!['ftp', 'ftps'].includes(lease.protocol)) {
    throw new Error(`unsupported lease protocol: ${lease.protocol}`);
  }
  if (!['read_only', 'read_write'].includes(lease.accessMode)) {
    throw new Error(`unsupported lease access mode: ${lease.accessMode}`);
  }
  if (!Number.isInteger(lease.port) || lease.port < 1 || lease.port > 65535) {
    throw new Error('lease response has an invalid port');
  }
  return lease;
}

function curlConfigValue(value) {
  rejectControlChars(value, 'curl configuration value');
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function leaseUrl(lease, remotePath) {
  rejectControlChars(remotePath, 'remote path');
  const host = lease.host.includes(':') && !lease.host.startsWith('[')
    ? `[${lease.host}]`
    : lease.host;
  const normalized = remotePath.startsWith('/') ? remotePath : `/${remotePath}`;
  const encodedPath = normalized.split('/').map((segment) => encodeURIComponent(segment)).join('/');
  return `ftp://${host}:${lease.port}${encodedPath}`;
}

function listLease(lease, remotePath, insecure) {
  const lines = [
    'silent',
    'show-error',
    'fail',
    'list-only',
    `connect-timeout = "15"`,
    `max-time = "120"`,
    `user = ${curlConfigValue(`${lease.username}:${lease.password}`)}`,
    `url = ${curlConfigValue(leaseUrl(lease, remotePath))}`,
  ];
  if (lease.protocol === 'ftps') lines.push('ssl-reqd');
  if (insecure) lines.push('insecure');
  if (lease.protocol === 'ftp') {
    console.error('clawguard-ftp: warning: this lease uses unencrypted FTP');
  }

  const result = spawnSync('curl', ['--config', '-'], {
    input: `${lines.join('\n')}\n`,
    encoding: 'utf8',
    timeout: APPROVAL_TIMEOUT_MS,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error) throw new Error(`curl failed: ${result.error.message}`);
  if (result.status !== 0) {
    const detail = String(result.stderr || '').trim();
    throw new Error(`FTP listing failed${detail ? `: ${detail}` : ''}`);
  }
  process.stdout.write(result.stdout || '');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const config = loadConfig();

  if (args.command === 'revoke') {
    await apiRequest(config, 'DELETE', `/__ftp/session/${encodeURIComponent(args.target)}`, args);
    console.log('FTP lease revoked.');
    return;
  }

  const lease = validateLease(await apiRequest(
    config,
    'POST',
    '/__ftp/session',
    args,
    { service: args.target },
  ));

  if (args.command === 'lease') {
    process.stdout.write(`${JSON.stringify(lease, null, 2)}\n`);
    return;
  }

  let operationError;
  try {
    listLease(lease, args.remotePath, args.insecure);
  } catch (error) {
    operationError = error;
  }

  try {
    await apiRequest(
      config,
      'DELETE',
      `/__ftp/session/${encodeURIComponent(lease.id)}`,
      { ...args, reason: `Revoke FTP lease after: ${args.reason}` },
    );
  } catch (error) {
    if (operationError) {
      console.error(`clawguard-ftp: additionally failed to revoke lease: ${error.message}`);
    } else {
      throw new Error(`listing completed but lease revocation failed: ${error.message}`);
    }
  }
  if (operationError) throw operationError;
}

main().catch((error) => fail(error.message));
