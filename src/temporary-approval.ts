import { createHash } from 'crypto';
import { FtpAccessMode, ServiceConfig, TemporaryServiceApproval } from './types';

export const MAX_TEMPORARY_APPROVAL_SECONDS = 24 * 60 * 60;

export function serviceApprovalHash(service: ServiceConfig): string {
  // Bind the grant to the full reviewed service, including its credentials.
  // Sorting avoids invalidating an unchanged service after a JSON round trip.
  const canonical = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b))
        .map(([key, item]) => [key, canonical(item)]));
    }
    return value;
  };
  return createHash('sha256').update(JSON.stringify(canonical({ ...service, protocol: service.protocol ?? 'http' }))).digest('hex');
}

export function temporaryApprovalDuration(input: string): number {
  const match = /^(\d{1,4})(m|h)$/i.exec(input);
  const seconds = match ? Number(match[1]) * (match[2].toLowerCase() === 'h' ? 3600 : 60) : 0;
  if (seconds < 60 || seconds > MAX_TEMPORARY_APPROVAL_SECONDS) {
    throw new Error('Use a duration from 1m to 24h, for example 30m or 1h.');
  }
  return seconds;
}

export interface TemporaryApprovalController {
  grantTemporaryServiceApproval(service: string, config: ServiceConfig, ttlSeconds: number,
    approvedBy: string, chatId: string, accessMode?: FtpAccessMode): TemporaryServiceApproval;
  revokeApproval(service: string): boolean;
  getTemporaryServiceApprovals(): TemporaryServiceApproval[];
}
