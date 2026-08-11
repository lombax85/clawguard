'use strict';

const http = require('node:http');

const body = process.env.FTP_GATEWAY_REQUEST || '';
const method = process.env.FTP_GATEWAY_METHOD || 'POST';
const requestPath = process.env.FTP_GATEWAY_PATH || '/session';
const payload = body ? Buffer.from(body) : undefined;
const req = http.request({
  socketPath: '/run/clawguard-ftp/gateway.sock',
  path: requestPath,
  method,
  headers: payload ? {
    'content-type': 'application/json',
    'content-length': String(payload.length),
  } : undefined,
}, (res) => {
  const chunks = [];
  res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
  res.on('end', () => {
    process.stdout.write(JSON.stringify({
      status: res.statusCode,
      body: JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'),
    }));
  });
});
req.once('error', (err) => {
  process.stderr.write(`${err.message}\n`);
  process.exitCode = 1;
});
req.end(payload);
