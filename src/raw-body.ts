import { RequestHandler } from 'express';

const DEFAULT_BODY_LIMIT_BYTES = 10 * 1024 * 1024;

/**
 * Buffers the request body without decoding Content-Encoding.
 *
 * A proxy must forward the exact bytes received from the client. Express'
 * built-in raw parser inflates gzip/deflate bodies by default, which makes the
 * body inconsistent with the original Content-Encoding and Content-Length
 * headers when those headers are forwarded upstream.
 */
export function preserveRawBody(
  limitBytes: number = DEFAULT_BODY_LIMIT_BYTES
): RequestHandler {
  return (req, res, next): void => {
    const declaredLength = Number(req.headers['content-length']);
    if (Number.isFinite(declaredLength) && declaredLength > limitBytes) {
      req.resume();
      res.status(413).json({ error: 'Request body too large' });
      return;
    }

    const chunks: Buffer[] = [];
    let totalBytes = 0;
    let settled = false;

    const cleanup = (): void => {
      req.removeListener('data', onData);
      req.removeListener('end', onEnd);
      req.removeListener('error', onError);
      req.removeListener('aborted', onAborted);
    };

    const rejectTooLarge = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      req.resume();
      res.status(413).json({ error: 'Request body too large' });
    };

    const onData = (chunk: Buffer): void => {
      totalBytes += chunk.length;
      if (totalBytes > limitBytes) {
        rejectTooLarge();
        return;
      }
      chunks.push(chunk);
    };

    const onEnd = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      req.body = Buffer.concat(chunks, totalBytes);
      next();
    };

    const onError = (error: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      next(error);
    };

    const onAborted = (): void => {
      const error = new Error('Request aborted');
      (error as Error & { status?: number }).status = 400;
      onError(error);
    };

    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
    req.on('aborted', onAborted);
  };
}
