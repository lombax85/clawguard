'use strict';

const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const { spawn, spawnSync } = require('node:child_process');

const SOCKET_PATH = process.env.CLAWGUARD_FTP_GATEWAY_SOCKET || '/run/clawguard-ftp/gateway.sock';
const RCLONE = process.env.CLAWGUARD_RCLONE_PATH || '/usr/local/bin/rclone';
const CERT_FILE = process.env.CLAWGUARD_FTP_CERT_FILE || '/data/tls.crt';
const KEY_FILE = process.env.CLAWGUARD_FTP_KEY_FILE || '/data/tls.key';
const PUBLIC_IP = process.env.CLAWGUARD_FTP_PUBLIC_IP || '';

function intEnv(name, fallback, min, max) {
  const raw = process.env[name] || String(fallback);
  if (!/^\d+$/.test(raw)) throw new Error(`${name} must be an integer`);
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) throw new Error(`${name} is out of range`);
  return value;
}

const CONTROL_START = intEnv('CLAWGUARD_FTP_CONTROL_PORT_START', 21210, 1024, 65535);
const CONTROL_END = intEnv('CLAWGUARD_FTP_CONTROL_PORT_END', 21219, 1024, 65535);
const PASSIVE_START = intEnv('CLAWGUARD_FTP_PASSIVE_PORT_START', 30000, 1024, 65535);
const PASSIVE_PER_SESSION = intEnv('CLAWGUARD_FTP_PASSIVE_PORTS_PER_SESSION', 10, 1, 100);
const MAX_SESSIONS = intEnv('CLAWGUARD_FTP_MAX_SESSIONS', 10, 1, 100);
const MAX_SESSION_SECONDS = intEnv('CLAWGUARD_FTP_MAX_SESSION_SECONDS', 86400, 10, 86400);
if (CONTROL_END - CONTROL_START + 1 < MAX_SESSIONS) throw new Error('control port range is too small');
if (PASSIVE_START + PASSIVE_PER_SESSION * MAX_SESSIONS - 1 > 65535) throw new Error('passive port range exceeds 65535');

const sessions = new Map();
const slots = Array.from({ length: MAX_SESSIONS }, (_unused, index) => index);
let closing = false;

function exactKeys(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, i) => key === expected[i]);
}

function validText(value, max) {
  return typeof value === 'string' && value.length > 0 && value.length <= max && !/[\0\r\n]/.test(value);
}

function decodeBase64Canonical(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 22000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error('invalid upstream password encoding');
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length === 0 || decoded.length > 16384 || decoded.includes(0x00)
    || decoded.includes(0x0a) || decoded.includes(0x0d)
    || decoded.toString('base64') !== value) {
    decoded.fill(0);
    throw new Error('invalid upstream password');
  }
  return decoded;
}

function validateOpenRequest(value) {
  if (!exactKeys(value, [
    'sessionId', 'service', 'protocol', 'accessMode', 'clientIp', 'expiresAt', 'upstream',
    'upstreamCredentials', 'gatewayCredentials',
  ])) throw new Error('invalid session request');
  if (!/^[A-Za-z0-9_-]{32,64}$/.test(value.sessionId)
    || !/^[A-Za-z0-9_-]{1,64}$/.test(value.service)
    || !['ftp', 'ftps'].includes(value.protocol)
    || !['read_only', 'read_write'].includes(value.accessMode)
    || net.isIP(value.clientIp) === 0) throw new Error('invalid session identity');

  const expiresAtMs = Date.parse(value.expiresAt);
  if (!Number.isFinite(expiresAtMs)
    || expiresAtMs <= Date.now() + 1000
    || expiresAtMs > Date.now() + MAX_SESSION_SECONDS * 1000 + 5000) {
    throw new Error('invalid session expiry');
  }
  if (!exactKeys(value.upstream, [
    'hostname', 'port', 'resolvedAddresses', 'root', 'tlsMode', 'noCheckCertificate',
  ])) throw new Error('invalid upstream target');
  const upstream = value.upstream;
  if (!validText(upstream.hostname, 253)
    || !Number.isInteger(upstream.port) || upstream.port < 1 || upstream.port > 65535
    || !Array.isArray(upstream.resolvedAddresses) || upstream.resolvedAddresses.length < 1
    || upstream.resolvedAddresses.length > 16
    || upstream.resolvedAddresses.some((address) => net.isIP(address) === 0)
    || typeof upstream.root !== 'string' || upstream.root.length > 1024 || /[\0\r\n]/.test(upstream.root)
    || !['none', 'explicit', 'implicit'].includes(upstream.tlsMode)
    || typeof upstream.noCheckCertificate !== 'boolean') throw new Error('invalid upstream target');
  if ((value.protocol === 'ftp' && upstream.tlsMode !== 'none')
    || (value.protocol === 'ftps' && upstream.tlsMode === 'none')) throw new Error('protocol/TLS mismatch');

  if (!exactKeys(value.upstreamCredentials, ['username', 'passwordBase64'])
    || !validText(value.upstreamCredentials.username, 255)) throw new Error('invalid upstream credentials');
  const upstreamPassword = decodeBase64Canonical(value.upstreamCredentials.passwordBase64);
  if (!exactKeys(value.gatewayCredentials, ['username', 'password'])
    || !/^[A-Za-z0-9_-]{1,64}$/.test(value.gatewayCredentials.username)
    || !/^[A-Za-z0-9_-]{32,128}$/.test(value.gatewayCredentials.password)) {
    upstreamPassword.fill(0);
    throw new Error('invalid gateway credentials');
  }
  return { ...value, expiresAtMs, upstreamPassword };
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    if (req.headers['content-type']?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      reject(Object.assign(new Error('content-type must be application/json'), { status: 415 }));
      return;
    }
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 65536) req.destroy(new Error('request too large'));
      else chunks.push(Buffer.from(chunk));
    });
    req.on('error', reject);
    req.on('end', () => {
      const raw = Buffer.concat(chunks, size);
      try { resolve(JSON.parse(raw.toString('utf8'))); }
      catch { reject(Object.assign(new Error('invalid JSON'), { status: 400 })); }
      finally {
        raw.fill(0);
        for (const chunk of chunks) chunk.fill(0);
      }
    });
  });
}

function send(res, status, body) {
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': String(payload.length),
    'cache-control': 'no-store',
  });
  res.end(payload);
}

function obscure(password) {
  const result = spawnSync(RCLONE, ['obscure', '-'], {
    input: password,
    encoding: 'utf8',
    timeout: 5000,
    maxBuffer: 65536,
  });
  if (result.status !== 0 || !validText(result.stdout.trim(), 32768)) throw new Error('rclone password preparation failed');
  return result.stdout.trim();
}

function createPinnedSocksServer(expectedHost, allowedAddresses) {
  const sockets = new Set();
  const server = net.createServer((client) => {
    sockets.add(client);
    let buffer = Buffer.alloc(0);
    let state = 'greeting';
    let upstream;

    const fail = (code = 1) => {
      if (!client.destroyed && state === 'request') client.write(Buffer.from([5, code, 0, 1, 0, 0, 0, 0, 0, 0]));
      client.destroy();
      upstream?.destroy();
    };

    const processBuffer = () => {
      if (state === 'greeting') {
        if (buffer.length < 2) return;
        const count = buffer[1];
        if (buffer.length < 2 + count) return;
        const methods = buffer.subarray(2, 2 + count);
        buffer = buffer.subarray(2 + count);
        if (buffer[0] !== undefined || buffer.length !== 0) {
          // SOCKS clients wait for the greeting response; pipelining is not needed here.
          fail();
          return;
        }
        if (client.destroyed || methods.indexOf(0) < 0) { client.end(Buffer.from([5, 0xff])); return; }
        client.write(Buffer.from([5, 0]));
        state = 'request';
        return;
      }
      if (state !== 'request' || buffer.length < 4) return;
      if (buffer[0] !== 5 || buffer[1] !== 1 || buffer[2] !== 0) { fail(7); return; }
      const atyp = buffer[3];
      let host;
      let offset;
      if (atyp === 1) {
        if (buffer.length < 10) return;
        host = [...buffer.subarray(4, 8)].join('.');
        offset = 8;
      } else if (atyp === 3) {
        if (buffer.length < 5) return;
        const length = buffer[4];
        if (buffer.length < 7 + length) return;
        host = buffer.subarray(5, 5 + length).toString('utf8');
        offset = 5 + length;
      } else if (atyp === 4) {
        if (buffer.length < 22) return;
        const parts = [];
        for (let i = 4; i < 20; i += 2) parts.push(buffer.readUInt16BE(i).toString(16));
        host = parts.join(':');
        offset = 20;
      } else { fail(8); return; }
      if (buffer.length < offset + 2) return;
      const port = buffer.readUInt16BE(offset);
      if (port < 1) { fail(2); return; }
      const hostAllowed = host.toLowerCase() === expectedHost.toLowerCase() || allowedAddresses.includes(host);
      if (!hostAllowed) { fail(2); return; }
      state = 'connecting';
      buffer = Buffer.alloc(0);

      const candidates = allowedAddresses.includes(host) ? [host] : allowedAddresses;
      let index = 0;
      const connectNext = () => {
        if (index >= candidates.length) { fail(5); return; }
        upstream = net.createConnection({ host: candidates[index++], port });
        sockets.add(upstream);
        upstream.once('connect', () => {
          state = 'stream';
          client.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
          client.pipe(upstream);
          upstream.pipe(client);
        });
        upstream.once('error', () => {
          sockets.delete(upstream);
          upstream.destroy();
          if (state === 'connecting') connectNext();
        });
        upstream.once('close', () => sockets.delete(upstream));
      };
      connectNext();
    };

    client.on('data', (chunk) => {
      if (state === 'stream') return;
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > 1024) { fail(); return; }
      processBuffer();
    });
    client.once('error', () => fail());
    client.once('close', () => {
      sockets.delete(client);
      upstream?.destroy();
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      const address = server.address();
      resolve({
        port: address.port,
        close: () => {
          for (const socket of sockets) socket.destroy();
          server.close();
        },
      });
    });
  });
}

function waitForPort(port, child) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 5000;
    let finished = false;
    const done = (err) => {
      if (finished) return;
      finished = true;
      child.removeListener('exit', onExit);
      child.removeListener('error', onError);
      err ? reject(err) : resolve();
    };
    const onExit = () => done(new Error('rclone exited before becoming ready'));
    const onError = () => done(new Error('rclone could not be started'));
    child.once('exit', onExit);
    child.once('error', onError);
    const probe = () => {
      if (Date.now() > deadline) { done(new Error('rclone startup timed out')); return; }
      const socket = net.createConnection({ host: '127.0.0.1', port });
      socket.once('connect', () => { socket.destroy(); done(); });
      socket.once('error', () => { socket.destroy(); setTimeout(probe, 50); });
    };
    probe();
  });
}

async function stopSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return false;
  sessions.delete(sessionId);
  clearTimeout(session.expiryTimer);
  session.socks.close();
  session.child.kill('SIGTERM');
  const killTimer = setTimeout(() => session.child.kill('SIGKILL'), 5000);
  killTimer.unref();
  session.child.once('exit', () => clearTimeout(killTimer));
  slots.push(session.slot);
  slots.sort((a, b) => a - b);
  return true;
}

async function openSession(raw) {
  if (closing) throw Object.assign(new Error('gateway shutting down'), { status: 503 });
  if (sessions.has(raw?.sessionId)) throw Object.assign(new Error('duplicate session'), { status: 409 });
  if (slots.length === 0) throw Object.assign(new Error('gateway capacity exhausted'), { status: 429 });
  const request = validateOpenRequest(raw);
  const slot = slots.shift();
  const controlPort = CONTROL_START + slot;
  const passivePortStart = PASSIVE_START + slot * PASSIVE_PER_SESSION;
  const passivePortEnd = passivePortStart + PASSIVE_PER_SESSION - 1;
  let socks;
  let child;
  let registered = false;
  try {
    socks = await createPinnedSocksServer(request.upstream.hostname, request.upstream.resolvedAddresses);
    const upstreamPass = obscure(request.upstreamPassword);
    request.upstreamPassword.fill(0);
    const env = {
      ...process.env,
      HOME: '/tmp',
      RCLONE_CONFIG_CGLEASE_TYPE: 'ftp',
      RCLONE_CONFIG_CGLEASE_HOST: request.upstream.hostname,
      RCLONE_CONFIG_CGLEASE_PORT: String(request.upstream.port),
      RCLONE_CONFIG_CGLEASE_USER: request.upstreamCredentials.username,
      RCLONE_CONFIG_CGLEASE_PASS: upstreamPass,
      RCLONE_CONFIG_CGLEASE_TLS: String(request.upstream.tlsMode === 'implicit'),
      RCLONE_CONFIG_CGLEASE_EXPLICIT_TLS: String(request.upstream.tlsMode === 'explicit'),
      RCLONE_CONFIG_CGLEASE_NO_CHECK_CERTIFICATE: String(request.upstream.noCheckCertificate),
      RCLONE_CONFIG_CGLEASE_SOCKS_PROXY: `127.0.0.1:${socks.port}`,
    };
    const args = [
      'serve', 'ftp', `cglease:${request.upstream.root}`,
      `--addr=0.0.0.0:${controlPort}`,
      `--passive-port=${passivePortStart}-${passivePortEnd}`,
      `--user=${request.gatewayCredentials.username}`,
      `--pass=${request.gatewayCredentials.password}`,
      '--config=/dev/null',
      // DEBUG output includes command-line and environment configuration.
      // Keep this fixed at NOTICE because both contain lease credentials.
      '--log-level=NOTICE',
    ];
    if (PUBLIC_IP) args.push(`--public-ip=${PUBLIC_IP}`);
    if (request.accessMode === 'read_only') args.push('--read-only');
    if (request.protocol === 'ftps') args.push(`--cert=${CERT_FILE}`, `--key=${KEY_FILE}`);
    child = spawn(RCLONE, args, { env, stdio: ['ignore', 'ignore', 'inherit'] });
    delete env.RCLONE_CONFIG_CGLEASE_PASS;
    child.once('error', () => { void stopSession(request.sessionId); });
    await waitForPort(controlPort, child);

    const expiryTimer = setTimeout(() => { void stopSession(request.sessionId); }, request.expiresAtMs - Date.now());
    expiryTimer.unref();
    sessions.set(request.sessionId, { slot, child, socks, expiryTimer });
    registered = true;
    child.once('exit', () => { void stopSession(request.sessionId); });
    if (child.exitCode !== null || child.signalCode !== null) {
      await stopSession(request.sessionId);
      throw new Error('rclone exited during session activation');
    }
    return { sessionId: request.sessionId, controlPort, passivePortStart, passivePortEnd };
  } catch (err) {
    request.upstreamPassword.fill(0);
    if (registered) {
      await stopSession(request.sessionId);
    } else {
      child?.kill('SIGKILL');
      socks?.close();
      slots.push(slot);
      slots.sort((a, b) => a - b);
    }
    throw err;
  }
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', 'http://localhost');
    if (url.search) throw Object.assign(new Error('not found'), { status: 404 });
    if (req.method === 'GET' && url.pathname === '/health') {
      send(res, 200, { status: 'ok', activeSessions: sessions.size });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/session') {
      const result = await openSession(await readJson(req));
      send(res, 201, result);
      return;
    }
    const match = url.pathname.match(/^\/session\/([A-Za-z0-9_-]{32,64})$/);
    if (req.method === 'DELETE' && match) {
      const stopped = await stopSession(match[1]);
      send(res, stopped ? 200 : 404, stopped ? { ok: true } : { error: 'not found' });
      return;
    }
    throw Object.assign(new Error('not found'), { status: 404 });
  } catch (err) {
    const status = Number.isInteger(err.status) ? err.status : 400;
    send(res, status, { error: status >= 500 ? 'internal gateway error' : err.message });
  }
});
server.headersTimeout = 5000;
server.requestTimeout = 15000;
server.maxRequestsPerSocket = 2;

if (fs.existsSync(SOCKET_PATH)) fs.unlinkSync(SOCKET_PATH);
server.listen(SOCKET_PATH, () => {
  fs.chmodSync(SOCKET_PATH, 0o660);
  process.stderr.write(`ClawGuard FTP sidecar ready on ${SOCKET_PATH}\n`);
});

async function shutdown() {
  if (closing) return;
  closing = true;
  await Promise.all([...sessions.keys()].map(stopSession));
  server.close(() => {
    try { if (fs.existsSync(SOCKET_PATH)) fs.unlinkSync(SOCKET_PATH); } catch {}
    process.exit(0);
  });
}
process.on('SIGTERM', () => { void shutdown(); });
process.on('SIGINT', () => { void shutdown(); });
