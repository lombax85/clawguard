/**
 * Simple per-key sliding-window attempt throttle, used to slow brute-force
 * guessing of the Telegram pairing secret. Pure and deterministic: the clock
 * is injectable for testing.
 */
export class PairThrottle {
  private attempts: Map<string, { count: number; firstAt: number }> = new Map();

  constructor(
    private readonly maxAttempts: number = 5,
    private readonly windowMs: number = 10 * 60 * 1000,
    private readonly now: () => number = () => Date.now(),
  ) {}

  /** True if `key` has reached the failure cap within the current window. */
  isThrottled(key: string): boolean {
    const rec = this.attempts.get(key);
    if (!rec) return false;
    if (this.now() - rec.firstAt > this.windowMs) {
      this.attempts.delete(key);
      return false;
    }
    return rec.count >= this.maxAttempts;
  }

  /** Record a failed attempt for `key` (starts a fresh window if expired). */
  registerFailure(key: string): void {
    const t = this.now();
    const rec = this.attempts.get(key);
    if (!rec || t - rec.firstAt > this.windowMs) {
      this.attempts.set(key, { count: 1, firstAt: t });
    } else {
      rec.count++;
    }
  }

  /** Clear all recorded attempts for `key` (e.g. after a successful pair). */
  reset(key: string): void {
    this.attempts.delete(key);
  }
}
