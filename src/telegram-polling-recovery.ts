export interface TelegramPollingBot {
  startPolling(options?: { restart?: boolean }): Promise<void>;
  stopPolling(options?: { cancel?: boolean; reason?: string }): Promise<void>;
  isPolling(): boolean;
}

export interface TelegramPollingRecoveryState {
  recovering: boolean;
  conflictCount: number;
  circuitOpen: boolean;
  nextRetryAt: number | null;
  lastRecoveryAt: number | null;
  lastRecoveryOkAt: number | null;
  lastRecoveryErrorAt: number | null;
}

export interface TelegramPollingRecoveryOptions {
  conflictRetryDelayMs?: number;
  stabilityWindowMs?: number;
  stopTimeoutMs?: number;
  now?: () => number;
  log?: (level: 'info' | 'warn' | 'error', message: string) => void;
  onStable?: () => void;
  onCircuitOpen?: () => void;
}

const DEFAULT_CONFLICT_RETRY_DELAY_MS = 15_000;
const DEFAULT_STABILITY_WINDOW_MS = 60_000;
const DEFAULT_STOP_TIMEOUT_MS = 9_000;

/**
 * Serializes Telegram long-poll ownership recovery.
 *
 * Telegram permits only one getUpdates consumer. A conflict receives one
 * delayed retry; a second conflict stops polling until the process is
 * deliberately restarted after the duplicate owner has been removed.
 */
export class TelegramPollingRecovery {
  private readonly conflictRetryDelayMs: number;
  private readonly stabilityWindowMs: number;
  private readonly stopTimeoutMs: number;
  private readonly now: () => number;
  private readonly log: NonNullable<TelegramPollingRecoveryOptions['log']>;
  private readonly onStable: NonNullable<TelegramPollingRecoveryOptions['onStable']>;
  private readonly onCircuitOpen: NonNullable<TelegramPollingRecoveryOptions['onCircuitOpen']>;

  private stopped = false;
  private recoveryPromise: Promise<void> | undefined;
  private retryTimer: ReturnType<typeof setTimeout> | undefined;
  private retryResolve: (() => void) | undefined;
  private stabilityTimer: ReturnType<typeof setTimeout> | undefined;
  private state: TelegramPollingRecoveryState = {
    recovering: false,
    conflictCount: 0,
    circuitOpen: false,
    nextRetryAt: null,
    lastRecoveryAt: null,
    lastRecoveryOkAt: null,
    lastRecoveryErrorAt: null,
  };

  constructor(
    private readonly bot: TelegramPollingBot,
    options: TelegramPollingRecoveryOptions = {}
  ) {
    this.conflictRetryDelayMs = options.conflictRetryDelayMs
      ?? DEFAULT_CONFLICT_RETRY_DELAY_MS;
    this.stabilityWindowMs = options.stabilityWindowMs
      ?? DEFAULT_STABILITY_WINDOW_MS;
    this.stopTimeoutMs = options.stopTimeoutMs ?? DEFAULT_STOP_TIMEOUT_MS;
    this.now = options.now ?? Date.now;
    this.log = options.log ?? (() => undefined);
    this.onStable = options.onStable ?? (() => undefined);
    this.onCircuitOpen = options.onCircuitOpen ?? (() => undefined);
  }

  getState(): TelegramPollingRecoveryState {
    return { ...this.state };
  }

  /** Restart the no-error stability window after a non-conflict error. */
  notePollingError(): void {
    this.clearStabilityTimer();
    if (this.stopped || this.state.recovering || this.state.circuitOpen) return;
    this.armStabilityTimer();
  }

  /**
   * A delivered update is encouraging, but does not prove that a competing
   * poller is gone: two instances can briefly alternate ownership. Keep the
   * conflict armed until the complete no-error stability window has elapsed.
   */
  noteHealthy(): void {
    if (this.stopped || this.state.recovering || this.state.circuitOpen) return;
    if (this.state.conflictCount > 0 && !this.stabilityTimer) {
      this.armStabilityTimer();
    }
  }

  handleConflict(): boolean {
    this.clearStabilityTimer();
    if (this.stopped || this.state.circuitOpen || this.recoveryPromise) return false;

    this.state.conflictCount += 1;
    this.state.lastRecoveryAt = this.now();
    const shouldRetry = this.state.conflictCount === 1;
    if (!shouldRetry) this.openCircuit();
    this.state.recovering = true;

    const task = this.pauseAndMaybeRetry(shouldRetry);
    this.recoveryPromise = task;
    void task.finally(() => {
      if (this.recoveryPromise === task) this.recoveryPromise = undefined;
      this.state.recovering = false;
    }).catch(() => {
      // pauseAndMaybeRetry contains its own error boundary.
    });
    return true;
  }

  private async pauseAndMaybeRetry(shouldRetry: boolean): Promise<void> {
    try {
      // Deliberately graceful. Older node-telegram-bot-api releases could
      // re-arm a cancel:true poll after stop resolved and create two owners.
      await this.withTimeout(
        this.bot.stopPolling(),
        this.stopTimeoutMs,
        'Telegram graceful stop'
      );
    } catch (err) {
      this.openCircuit();
      this.state.lastRecoveryErrorAt = this.now();
      this.log(
        'error',
        `Telegram polling could not stop safely; no replacement poll was started: ${this.errorMessage(err)}`
      );
      return;
    }

    // Shutdown may have begun while the graceful stop was awaiting the active
    // getUpdates call. Do not create a fresh retry timer after stop() already
    // cancelled the existing timers.
    if (this.stopped) return;

    if (!shouldRetry) {
      this.log(
        'error',
        'Telegram polling paused after repeated 409 conflicts; stop the other bot instance, then restart ClawGuard'
      );
      return;
    }

    this.state.nextRetryAt = this.now() + this.conflictRetryDelayMs;
    this.log(
      'warn',
      `Telegram polling conflict detected; retrying once in ${Math.ceil(this.conflictRetryDelayMs / 1000)}s`
    );
    await this.waitForRetry();
    this.state.nextRetryAt = null;
    if (this.stopped) return;

    try {
      // The previous poll has completed and cannot re-arm. restart:false is
      // intentional: recovery must never replace a poll that is still alive.
      await this.bot.startPolling({ restart: false });
      if (this.stopped) return;
      if (!this.bot.isPolling()) {
        throw new Error('Telegram client did not enter polling state');
      }
      this.state.lastRecoveryOkAt = this.now();
      this.log('info', 'Telegram polling retry started');
      this.armStabilityTimer();
    } catch (err) {
      this.openCircuit();
      this.state.lastRecoveryErrorAt = this.now();
      this.log('error', `Telegram polling retry failed: ${this.errorMessage(err)}`);
    }
  }

  private waitForRetry(): Promise<void> {
    return new Promise((resolve) => {
      this.retryResolve = resolve;
      this.retryTimer = setTimeout(() => {
        this.retryTimer = undefined;
        this.retryResolve = undefined;
        resolve();
      }, this.conflictRetryDelayMs);
    });
  }

  private armStabilityTimer(): void {
    if (this.stopped || this.state.circuitOpen) return;
    this.clearStabilityTimer();
    this.stabilityTimer = setTimeout(() => {
      this.stabilityTimer = undefined;
      if (!this.stopped && !this.state.circuitOpen && this.bot.isPolling()) {
        this.markStable();
      }
    }, this.stabilityWindowMs);
  }

  private markStable(): void {
    if (this.state.conflictCount > 0) {
      this.log('info', 'Telegram polling ownership is stable again');
    }
    this.state.conflictCount = 0;
    this.onStable();
  }

  private openCircuit(): void {
    if (this.state.circuitOpen) return;
    this.state.circuitOpen = true;
    try {
      this.onCircuitOpen();
    } catch (err) {
      this.log('error', `Telegram circuit-open handler failed: ${this.errorMessage(err)}`);
    }
  }

  private clearStabilityTimer(): void {
    if (!this.stabilityTimer) return;
    clearTimeout(this.stabilityTimer);
    this.stabilityTimer = undefined;
  }

  private cancelRetryTimer(): void {
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = undefined;
    const resolve = this.retryResolve;
    this.retryResolve = undefined;
    resolve?.();
  }

  private async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    label: string
  ): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        promise,
        new Promise<T>((_resolve, reject) => {
          timer = setTimeout(
            () => reject(new Error(`${label} timed out after ${timeoutMs}ms`)),
            timeoutMs
          );
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private errorMessage(err: unknown): string {
    return err instanceof Error ? err.message : String(err);
  }

  async stop(): Promise<void> {
    if (this.stopped) return;
    this.stopped = true;
    this.clearStabilityTimer();
    this.cancelRetryTimer();
    await this.recoveryPromise;

    try {
      await this.withTimeout(
        this.bot.stopPolling({ cancel: true, reason: 'ClawGuard shutdown' }),
        this.stopTimeoutMs,
        'Telegram shutdown stop'
      );
    } catch (err) {
      this.log('error', `Telegram polling shutdown did not complete cleanly: ${this.errorMessage(err)}`);
    }
  }
}
