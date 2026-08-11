import { timingSafeEqual } from 'crypto';
import express, { Request, Response } from 'express';
import net from 'net';
import { FtpBroker, FtpBrokerError } from './ftp-broker';
import { extractRequestMeta } from './request-meta';
import { Config } from './types';

const SESSION_ID = /^[A-Za-z0-9_-]{32,64}$/;

function secretEqual(actual: string | undefined, expected: string): boolean {
  if (actual === undefined) return false;
  const a = Buffer.from(actual);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

function clientIp(req: Request): string | undefined {
  const raw = req.socket.remoteAddress;
  if (!raw) return undefined;
  const normalized = raw.startsWith('::ffff:') ? raw.slice(7) : raw;
  return net.isIP(normalized) === 0 ? undefined : normalized;
}

function parseOpenBody(req: Request): string {
  const contentType = req.headers['content-type']?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') throw new FtpBrokerError(415, 'Content-Type must be application/json');
  if (!Buffer.isBuffer(req.body) || req.body.length === 0 || req.body.length > 4096) {
    throw new FtpBrokerError(400, 'Invalid FTP session request body');
  }
  let parsed: unknown;
  try { parsed = JSON.parse(req.body.toString('utf8')); } catch {
    throw new FtpBrokerError(400, 'Invalid JSON body');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)
    || Object.keys(parsed).length !== 1
    || typeof (parsed as Record<string, unknown>).service !== 'string'
    || !/^[A-Za-z0-9_-]{1,64}$/.test((parsed as Record<string, string>).service)) {
    throw new FtpBrokerError(400, 'Body must contain exactly one valid service alias');
  }
  return (parsed as Record<string, string>).service;
}

export function createFtpRouter(config: Config, broker: FtpBroker): express.Router {
  const router = express.Router();
  router.use((req, res, next) => {
    const key = req.headers['x-clawguard-key'];
    if (typeof key !== 'string' || !secretEqual(key, config.server.agentKey)) {
      res.status(401).json({ error: 'Invalid or missing X-ClawGuard-Key' });
      return;
    }
    res.setHeader('cache-control', 'no-store');
    next();
  });

  router.post('/session', async (req: Request, res: Response) => {
    const controller = new AbortController();
    let leaseId: string | undefined;
    const onAbort = () => {
      if (!controller.signal.aborted) controller.abort(new Error('client disconnected'));
      if (leaseId && !res.writableFinished) {
        void broker.closeSession(leaseId).catch(() => undefined);
      }
    };
    const onFinish = () => res.removeListener('close', onAbort);
    req.once('aborted', onAbort);
    res.once('close', onAbort);
    res.once('finish', onFinish);
    try {
      const ip = clientIp(req);
      if (!ip) throw new FtpBrokerError(400, 'Unable to determine client IP');
      const lease = await broker.openSession(parseOpenBody(req), ip, extractRequestMeta(req.headers), controller.signal);
      leaseId = lease.id;
      if (controller.signal.aborted || res.destroyed) {
        await broker.closeSession(lease.id);
        return;
      }
      res.status(201).json(lease);
    } catch (err) {
      const failure = err instanceof FtpBrokerError ? err : new FtpBrokerError(500, 'Internal FTP gateway error');
      if (!res.headersSent) res.status(failure.status).json({ error: failure.publicMessage });
    } finally {
      req.removeListener('aborted', onAbort);
      if (res.writableFinished) res.removeListener('close', onAbort);
    }
  });

  router.delete('/session/:id', async (req: Request, res: Response) => {
    const rawId = req.params.id;
    const id = Array.isArray(rawId) ? rawId[0] : rawId;
    if (!SESSION_ID.test(id)) {
      res.status(400).json({ error: 'Invalid FTP session id' });
      return;
    }
    const closed = await broker.closeSession(id);
    if (!closed) {
      res.status(404).json({ error: 'FTP session not found' });
      return;
    }
    res.json({ ok: true });
  });
  return router;
}
