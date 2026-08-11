const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');

const { TelegramPollingRecovery } = require('../dist/telegram-polling-recovery');
const { TelegramNotifier } = require('../dist/telegram');

function waitFor(predicate, timeoutMs = 500) {
  const startedAt = Date.now();
  return new Promise((resolve, reject) => {
    const check = () => {
      if (predicate()) {
        resolve();
        return;
      }
      if (Date.now() - startedAt >= timeoutMs) {
        reject(new Error('condition was not met before timeout'));
        return;
      }
      setTimeout(check, 2);
    };
    check();
  });
}

function makeBot(options = {}) {
  const stopCalls = [];
  const startCalls = [];
  let polling = true;
  return {
    stopCalls,
    startCalls,
    isPolling() {
      return polling;
    },
    async stopPolling(stopOptions) {
      stopCalls.push(stopOptions);
      if (options.stop) await options.stop(stopOptions, stopCalls.length);
      polling = false;
    },
    async startPolling(startOptions) {
      startCalls.push(startOptions);
      if (options.start) await options.start(startOptions, startCalls.length);
      if (!options.startLeavesStopped) polling = true;
    },
  };
}

function makeRecovery(bot, overrides = {}) {
  const logs = [];
  let stableCalls = 0;
  const recovery = new TelegramPollingRecovery(bot, {
    conflictRetryDelayMs: 10,
    stabilityWindowMs: 25,
    stopTimeoutMs: 30,
    log: (level, message) => logs.push({ level, message }),
    onStable: () => { stableCalls += 1; },
    ...overrides,
  });
  return { recovery, logs, getStableCalls: () => stableCalls };
}

test('a 409 gracefully stops before exactly one delayed non-replacing retry', async () => {
  const bot = makeBot();
  const { recovery, logs, getStableCalls } = makeRecovery(bot);

  recovery.handleConflict();
  recovery.handleConflict(); // burst events must share the same recovery

  await waitFor(() => bot.stopCalls.length === 1);
  assert.equal(bot.stopCalls[0], undefined, 'conflict stop must not use cancel:true');
  assert.equal(bot.startCalls.length, 0, 'retry must not be immediate');

  await waitFor(() => bot.startCalls.length === 1);
  assert.deepEqual(bot.startCalls[0], { restart: false });
  assert.equal(recovery.getState().conflictCount, 1);
  assert.equal(recovery.getState().circuitOpen, false);
  assert.equal(logs.some((entry) => /retrying once/.test(entry.message)), true);

  recovery.noteHealthy();
  assert.equal(
    recovery.getState().conflictCount,
    1,
    'one delivered update must not clear a conflict while another poller may still exist'
  );
  await waitFor(() => recovery.getState().conflictCount === 0);
  assert.equal(getStableCalls(), 1);
  await recovery.stop();
});

test('a second 409 opens the circuit and never starts another polling owner', async () => {
  const bot = makeBot();
  const { recovery, logs } = makeRecovery(bot, { stabilityWindowMs: 200 });

  recovery.handleConflict();
  await waitFor(() => bot.startCalls.length === 1);
  recovery.handleConflict();

  await waitFor(() => recovery.getState().circuitOpen);
  await waitFor(() => bot.stopCalls.length === 2);
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(bot.startCalls.length, 1);
  assert.equal(bot.isPolling(), false);
  assert.equal(logs.some((entry) => /stop the other bot instance/.test(entry.message)), true);

  recovery.handleConflict();
  assert.equal(bot.stopCalls.length, 2, 'open circuit must ignore further conflict events');
  await recovery.stop();
});

test('a graceful-stop timeout fails closed without starting a competing poll', async () => {
  const bot = makeBot({
    stop: (options) => options?.cancel ? Promise.resolve() : new Promise(() => {}),
  });
  const { recovery, logs } = makeRecovery(bot, { stopTimeoutMs: 10 });

  recovery.handleConflict();
  await waitFor(() => recovery.getState().circuitOpen);

  assert.equal(bot.startCalls.length, 0);
  assert.equal(recovery.getState().lastRecoveryErrorAt !== null, true);
  assert.equal(logs.some((entry) => /no replacement poll was started/.test(entry.message)), true);
  await recovery.stop();
});

test('shutdown cancels a pending retry and uses cancellation only for final teardown', async () => {
  const bot = makeBot();
  const { recovery } = makeRecovery(bot, { conflictRetryDelayMs: 200 });

  recovery.handleConflict();
  await waitFor(() => recovery.getState().nextRetryAt !== null);
  await recovery.stop();

  assert.equal(bot.startCalls.length, 0);
  assert.equal(bot.stopCalls.length, 2);
  assert.equal(bot.stopCalls[0], undefined);
  assert.deepEqual(bot.stopCalls[1], { cancel: true, reason: 'ClawGuard shutdown' });
});

test('shutdown during graceful conflict stop cannot create a new retry timer', async () => {
  let releaseConflictStop;
  const bot = makeBot({
    stop: (_options, callNumber) => callNumber === 1
      ? new Promise((resolve) => { releaseConflictStop = resolve; })
      : Promise.resolve(),
  });
  const { recovery } = makeRecovery(bot, { conflictRetryDelayMs: 200 });

  recovery.handleConflict();
  await waitFor(() => typeof releaseConflictStop === 'function');
  const stopping = recovery.stop();
  releaseConflictStop();
  await stopping;

  assert.equal(bot.startCalls.length, 0);
  assert.equal(recovery.getState().nextRetryAt, null);
  assert.equal(bot.stopCalls.length, 2);
});

test('a retry that does not enter polling state opens the circuit', async () => {
  const bot = makeBot({ startLeavesStopped: true });
  const { recovery, logs } = makeRecovery(bot);

  recovery.handleConflict();
  await waitFor(() => recovery.getState().circuitOpen);

  assert.equal(bot.startCalls.length, 1);
  assert.equal(recovery.getState().lastRecoveryErrorAt !== null, true);
  assert.equal(logs.some((entry) => /did not enter polling state/.test(entry.message)), true);
  await recovery.stop();
});

test('another polling error restarts the no-error stability window', async () => {
  const bot = makeBot();
  const { recovery, getStableCalls } = makeRecovery(bot, { stabilityWindowMs: 50 });

  recovery.handleConflict();
  await waitFor(() => bot.startCalls.length === 1);
  await new Promise((resolve) => setTimeout(resolve, 25));
  recovery.notePollingError();
  await new Promise((resolve) => setTimeout(resolve, 30));

  assert.equal(recovery.getState().conflictCount, 1);
  assert.equal(getStableCalls(), 0);
  await waitFor(() => recovery.getState().conflictCount === 0);
  assert.equal(getStableCalls(), 1);
  await recovery.stop();
});

test('an idle bot clears a non-409 error after the no-error stability window', async () => {
  const bot = makeBot();
  const { recovery, getStableCalls } = makeRecovery(bot, { stabilityWindowMs: 25 });

  recovery.notePollingError();
  assert.equal(getStableCalls(), 0);
  await waitFor(() => getStableCalls() === 1);
  await recovery.stop();
});

test('shutdown during a pending start cannot arm a post-shutdown stability timer', async () => {
  let releaseStart;
  const bot = makeBot({
    start: () => new Promise((resolve) => { releaseStart = resolve; }),
  });
  const { recovery, getStableCalls } = makeRecovery(bot, {
    conflictRetryDelayMs: 5,
    stabilityWindowMs: 20,
  });

  recovery.handleConflict();
  await waitFor(() => bot.startCalls.length === 1);
  const stopping = recovery.stop();
  await waitFor(() => typeof releaseStart === 'function');
  releaseStart();
  await stopping;
  await new Promise((resolve) => setTimeout(resolve, 30));

  assert.equal(bot.isPolling(), false);
  assert.equal(recovery.getState().lastRecoveryOkAt, null);
  assert.equal(getStableCalls(), 0);
});

test('TelegramNotifier wires 409 errors into the guard without raw getUpdates calls', async () => {
  class FakeTelegramBot extends EventEmitter {
    constructor() {
      super();
      this.polling = true;
      this.stopCalls = [];
      this.startCalls = [];
      this.sendCalls = [];
      this.answerCalls = [];
      this.editCalls = [];
      this.callbackAck = null;
    }

    onText() {}

    isPolling() {
      return this.polling;
    }

    async stopPolling(options) {
      this.stopCalls.push(options);
      this.polling = false;
    }

    async startPolling(options) {
      this.startCalls.push(options);
      this.polling = true;
    }

    async sendMessage(...args) {
      this.sendCalls.push(args);
      return { message_id: this.sendCalls.length, chat: { id: 123 } };
    }

    async answerCallbackQuery(...args) {
      this.answerCalls.push(args);
      if (this.callbackAck) await this.callbackAck;
    }

    async editMessageText(...args) {
      this.editCalls.push(args);
    }
  }

  const bot = new FakeTelegramBot();
  const originalFetch = global.fetch;
  const originalLog = console.log;
  const originalWarn = console.warn;
  const originalError = console.error;
  let fetchCalls = 0;
  global.fetch = async () => {
    fetchCalls += 1;
    throw new Error('raw fetch must not be used');
  };
  console.log = () => {};
  console.warn = () => {};
  console.error = () => {};

  const notifier = new TelegramNotifier(
    {
      botToken: 'clawguard-managed',
      chatId: '123',
      pairing: { enabled: false, secret: '' },
    },
    {},
    {
      bot,
      pollingRecoveryOptions: {
        conflictRetryDelayMs: 10,
        stabilityWindowMs: 200,
        stopTimeoutMs: 30,
      },
    }
  );

  try {
    let releaseCallbackAck;
    bot.callbackAck = new Promise((resolve) => { releaseCallbackAck = resolve; });
    const claimedApproval = notifier.requestApproval(
      'claimed-before-circuit',
      'test-service',
      'POST',
      '/claimed',
      '127.0.0.1'
    );
    const pendingApproval = notifier.requestApproval(
      'pending-before-circuit',
      'test-service',
      'POST',
      '/dangerous',
      '127.0.0.1'
    );
    await waitFor(() => notifier.getHealth().pendingCallbacks === 2);

    const statusConflict = new Error('polling ownership collision');
    statusConflict.response = { status: 409 };
    bot.emit('polling_error', statusConflict);
    await waitFor(() => bot.startCalls.length === 1);
    await waitFor(() => notifier.getHealth().restartingPolling === false);
    assert.equal(fetchCalls, 0);
    assert.equal(notifier.getHealth().pollingConflict, true);

    bot.emit('callback_query', {
      id: 'callback-in-flight',
      data: 'approve_once:claimed-before-circuit',
      message: { message_id: 1, chat: { id: 123 } },
      from: { id: 456, first_name: 'Alice' },
    });
    await waitFor(() => bot.answerCalls.length === 1);
    assert.equal(
      notifier.getHealth().pendingCallbacks,
      1,
      'the in-flight callback must be claimed before its acknowledgement await'
    );

    bot.emit('polling_error', new Error(
      'ETELEGRAM: 409 Conflict: terminated by other getUpdates request'
    ));
    await waitFor(() => notifier.getHealth().pollingCircuitOpen);
    assert.equal(bot.startCalls.length, 1);
    assert.equal(bot.isPolling(), false);
    assert.deepEqual(await pendingApproval, {
      approved: false,
      ttlSeconds: 0,
      approvedBy: 'telegram_polling_unavailable',
      pathScoped: false,
    });
    assert.equal(notifier.getHealth().pendingCallbacks, 0);

    releaseCallbackAck();
    assert.deepEqual(await claimedApproval, {
      approved: true,
      ttlSeconds: 1,
      approvedBy: 'Alice',
      pathScoped: false,
    });
    await waitFor(() => bot.editCalls.length === 1);
    assert.match(bot.editCalls[0][0], /Approved once/);

    const sendCountAtCircuitOpen = bot.sendCalls.length;
    assert.deepEqual(
      await notifier.requestApproval(
        'new-after-circuit',
        'test-service',
        'POST',
        '/dangerous',
        '127.0.0.1'
      ),
      {
        approved: false,
        ttlSeconds: 0,
        approvedBy: 'telegram_polling_unavailable',
        pathScoped: false,
      }
    );
    assert.equal(bot.sendCalls.length, sendCountAtCircuitOpen);
  } finally {
    await notifier.stop();
    global.fetch = originalFetch;
    console.log = originalLog;
    console.warn = originalWarn;
    console.error = originalError;
  }
});
