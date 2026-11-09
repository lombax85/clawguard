export interface WebhookSchedule {
  description: string;
  isActive(at: Date): boolean;
}

/** Validate YAML input and compile a daily window in an explicit time zone. */
export function createWebhookSchedule(value: unknown): WebhookSchedule | undefined {
  if (value === undefined) return undefined;
  const prefix = 'notifications.webhook.activeHours';
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${prefix} must contain start, end and timezone`);
  }
  const { start, end, timezone } = value as Record<string, unknown>;
  const timePattern = /^([01]\d|2[0-3]):[0-5]\d$/;
  for (const [key, time] of Object.entries({ start, end })) {
    if (typeof time !== 'string' || !timePattern.test(time)) {
      throw new Error(`${prefix}.${key} must be a quoted HH:mm time from "00:00" to "23:59"`);
    }
  }
  if (start === end) {
    throw new Error(`${prefix}.start and end must differ; omit activeHours for all-day delivery`);
  }
  let formatter: Intl.DateTimeFormat;
  try {
    if (typeof timezone !== 'string' || !timezone || /^[+-]/.test(timezone)) {
      throw new Error('Missing or invalid time zone');
    }
    formatter = new Intl.DateTimeFormat('en-GB', {
      timeZone: timezone, hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
    });
  } catch {
    throw new Error(`${prefix}.timezone must be a valid named time zone, for example Europe/Rome or UTC`);
  }
  const minutes = (time: string): number => {
    const [hour, minute] = time.split(':').map(Number);
    return hour * 60 + minute;
  };
  const from = minutes(start as string);
  const until = minutes(end as string);
  return {
    description: `${start}–${end} (${timezone}), daily`,
    isActive(at: Date): boolean {
      const parts = formatter.formatToParts(at);
      const now = Number(parts.find(part => part.type === 'hour')!.value) * 60
        + Number(parts.find(part => part.type === 'minute')!.value);
      return from < until ? now >= from && now < until : now >= from || now < until;
    },
  };
}
