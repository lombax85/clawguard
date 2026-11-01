const test = require('node:test');
const assert = require('node:assert/strict');
const { setTimeout: delay } = require('node:timers/promises');
const http = require('node:http');
const express = require('express');
const { createAdminRouter } = require('../dist/admin');
const { fixture, button, listen } = require('./helpers/telegram-fixture.cjs');

async function begin(f, target, method = 'GET', alias = 'app') {
  const before = f.transport.messages.length;
  const response = f.request(method, alias, target);
  let menu;
  for (let i = 0; i < 100 && !menu; i++) {
    menu = f.transport.messages.slice(before).find(item => item.options.reply_markup);
    if (!menu) await delay(5);
  }
  assert.ok(menu, 'request must wait for an approval');
  return { menu, response, tap: text => f.transport.tap(menu, button(menu, text)) };
}
async function deny(f, target, method = 'GET', alias = 'app') {
  const r = await begin(f, target, method, alias);
  await r.tap('❌ Deny');
  assert.equal(await r.response, 403);
}
async function scope(f, target, method = 'GET') {
  const r = await begin(f, target, method);
  await r.tap('Path-based');
  const path = target.split('?')[0];
  const choice = `${path}${path.endsWith('/') ? '' : '/'}*`;
  while (!r.menu.options.reply_markup.inline_keyboard.flat().some(b => b.text === choice)) await r.tap('Next →');
  await r.tap(choice);
  return r;
}

async function withAdmin(f, run) {
  f.config.admin = { enabled: true, pin: 'test-pin', allowedIPs: ['127.0.0.1'], strictMode: false };
  f.config.sshBroker = {};
  const app = express();
  app.use('/__admin', createAdminRouter(f.config, f.manager, f.audit));
  const server = http.createServer(app);
  const base = await listen(server);
  async function admin(path, method = 'GET', authenticated = true) {
    const res = await fetch(`${base}/__admin/api/${path}`, { method, headers: authenticated ? { 'X-ClawGuard-Pin': 'test-pin' } : {} });
    return { status: res.status, body: await res.json() };
  }
  try { await run(admin); } finally { await new Promise(resolve => server.close(resolve)); }
}

test('initial buttons offer one single-request action and the method-wide shortcut', async () => {
  await fixture(async f => {
    const r = await begin(f, '/quick');
    assert.deepEqual(r.menu.options.reply_markup.inline_keyboard.map(row => row.map(b => b.text)), [
      ['✅ Only this request', '⚡ 1h method-wide'],
      ['Method-wide', 'Path-based'],
      ['❌ Deny'],
    ]);
    const quick = button(r.menu, '✅ Only this request');
    await f.transport.tap(r.menu, quick);
    assert.equal(await r.response, 200);
    assert.deepEqual(f.audit.getActiveApprovals(), []);
    assert.deepEqual(f.audit.getScopedApprovals(), []);
    await f.transport.tap(r.menu, quick);
    await deny(f, '/quick');
  }, 3000);
});

test('quick 1h is limited to its service and method, survives restart, and expires exactly on time', async t => {
  await fixture(async f => {
    f.config.services.other = structuredClone(f.config.services.app);
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
    try {
      const r = await begin(f, '/repo/refs?service=upload');
      const quick = button(r.menu, '⚡ 1h method-wide');
      for (const overrides of [{ from: { id: 8, is_bot: false } }, { from: { id: 7, is_bot: true } },
        { message: { ...r.menu, chat: { id: 200 } } }, { message: { ...r.menu, message_id: -1 } }]) {
        await f.transport.tap(r.menu, quick, overrides);
        assert.equal(f.hits(), 0);
      }
      await Promise.all([f.transport.tap(r.menu, quick), f.transport.tap(r.menu, quick)]);
      assert.equal(await r.response, 200);
      assert.match(r.menu.text, /1h \(method-wide\)/);
      const [grant] = f.audit.getActiveApprovals();
      assert.equal(grant.method, 'GET');
      assert.equal(grant.path, null);
      assert.equal(grant.expiresAt - grant.approvedAt, 3600_000);
      assert.equal(await f.request('GET', 'app', '/different-repo?new=query'), 200);
      await deny(f, '/repo/refs?service=upload', 'POST');
      await deny(f, '/repo/refs?service=upload', 'GET', 'other');
      await f.restart();
      t.mock.timers.setTime(grant.expiresAt - 1);
      assert.equal(await f.request('GET', 'app', '/different-repo'), 200);
      t.mock.timers.setTime(grant.expiresAt);
      await deny(f, '/different-repo');
      const renewed = await begin(f, '/repo/refs');
      await renewed.tap('⚡ 1h method-wide');
      assert.equal(await renewed.response, 200);
      await f.transport.command('/revoke app');
      await deny(f, '/different-repo');
    } finally { t.mock.timers.reset(); }
  }, 3000);
});

test('method-wide takes two taps, ignores path and query, and preserves service, method and expiry boundaries', async t => {
  await fixture(async f => {
    f.config.services.other = structuredClone(f.config.services.app);
    const r = await begin(f, '/repo/refs?service=upload');
    await r.tap('Method-wide');
    assert.match(r.menu.text, /Methods: GET\nPath: all\nQuery: ignored/);
    assert.deepEqual(r.menu.options.reply_markup.inline_keyboard.map(row => row.map(b => b.text)), [
      ['15m', '30m', '1h'], ['4h', '24h', '1w'], ['1month', 'Forever'],
      ['Methods: GET ▾'], ['← Back'], ['❌ Deny'],
    ]);
    assert.equal(f.hits(), 0);
    await r.tap('1month');
    assert.equal(await r.response, 200);
    const [grant] = f.audit.getScopedApprovals();
    assert.deepEqual(grant.scope, { path: '/', includeSubpaths: true, methods: ['GET'], query: { mode: 'ignore', params: [] } });
    assert.equal(grant.expiresAt - grant.approvedAt, 30 * 86400_000);
    await f.restart();
    assert.equal(await f.request('GET', 'app', '/'), 200);
    assert.equal(await f.request('GET', 'app', '/other/path?new=value'), 200);
    await deny(f, '/other/path?new=value', 'POST');
    await deny(f, '/other/path?new=value', 'GET', 'other');
    t.mock.timers.enable({ apis: ['Date'], now: grant.expiresAt });
    try { await deny(f, '/other/path?new=value'); } finally { t.mock.timers.reset(); }
  }, 3000);
});

test('path-based takes three taps and includes subpaths and any query for both ancestor and complete paths', async t => {
  for (const selected of ['/users/Fabio%20Lombardo', '/users/Fabio%20Lombardo/documents/123']) {
    await t.test(selected, async () => {
      await fixture(async f => {
        const r = await begin(f, '/users/Fabio%20Lombardo/documents/123?format=pdf');
        await r.tap('Path-based');
        assert.deepEqual(r.menu.options.reply_markup.inline_keyboard.map(row => row.map(b => b.text)), [
          ['/users/*'], ['/users/Fabio%20Lombardo/*'], ['/users/Fabio%20Lombardo/documents/*'],
          ['/users/Fabio%20Lombardo/documents/123/*'], ['← Back'], ['❌ Deny'],
        ]);
        const forged = button(r.menu, selected + '/*').replace(/pick-\d+$/, 'grant-forever');
        await f.transport.tap(r.menu, forged);
        assert.match(f.transport.answers.at(-1).text, /Choice not available/);
        await r.tap(selected + '/*');
        assert.match(r.menu.text, /Subpaths: included\nQuery: Ignored/);
        assert.equal(f.hits(), 0);
        await r.tap('1h');
        assert.equal(await r.response, 200);
        for (const target of [selected, selected + '?format=json&new=1', selected + '/child?new=2']) {
          assert.equal(await f.request('GET', 'app', target), 200);
        }
        await deny(f, selected + '-other');
        await deny(f, '/users/other/documents/123');
        await deny(f, selected, 'POST');
        await f.restart();
        assert.equal(await f.request('GET', 'app', selected + '/child?different=1'), 200);
      }, 3000);
    });
  }
});

test('method-wide optionally adds allowed methods, keeps the original method, and can be revoked', async () => {
  await fixture(async f => {
    const r = await begin(f, '/api?x=1');
    await r.tap('Method-wide');
    const forged = button(r.menu, '1h').replace('grant-1h', 'view-query');
    await f.transport.tap(r.menu, forged);
    assert.match(f.transport.answers.at(-1).text, /Choice not available/);
    await r.tap('Methods: GET ▾');
    await r.tap('✓ GET');
    button(r.menu, '✓ GET');
    await r.tap('POST'); await r.tap('Done');
    assert.match(r.menu.text, /Methods: GET, POST/);
    await r.tap('Forever');
    assert.equal(await r.response, 200);
    assert.equal(f.audit.getScopedApprovals()[0].expiresAt, null);
    assert.equal(await f.request('POST', 'app', '/other?x=2'), 200);
    assert.equal(await f.request('DELETE', 'app', '/other'), 405);
    await f.transport.command('/revoke app');
    await deny(f, '/other');
    await deny(f, '/other', 'POST');
  }, 3000);
});

test('back navigation switches modes with fresh defaults and rejects buttons from previous views', async () => {
  await fixture(async f => {
    const r = await begin(f, '/a/b?owner=me');
    const initialPath = button(r.menu, 'Path-based');
    await r.tap('Method-wide');
    await f.transport.tap(r.menu, initialPath);
    assert.match(f.transport.answers.at(-1).text, /expired/);
    await r.tap('Methods: GET ▾'); await r.tap('POST'); await r.tap('Done');
    const oldGrant = button(r.menu, 'Forever');
    await r.tap('← Back'); await r.tap('Path-based'); await r.tap('/a/b/*');
    assert.match(r.menu.text, /Methods: GET\nPath: \/a\/b\nSubpaths: included\nQuery: Ignored/);
    await r.tap('Query: ignored ▾'); await r.tap('Same parameters and values');
    await r.tap('More options'); await r.tap('Exact path only');
    await r.tap('← Change path'); await r.tap('/a/*');
    assert.match(r.menu.text, /Subpaths: included/);
    assert.ok(!r.menu.options.reply_markup.inline_keyboard.flat().some(b => b.text === 'More options'));
    await r.tap('← Change path'); await r.tap('← Back'); await r.tap('Method-wide');
    assert.match(r.menu.text, /Methods: GET\nPath: all\nQuery: ignored/);
    await f.transport.tap(r.menu, oldGrant);
    assert.match(f.transport.answers.at(-1).text, /expired/);
    assert.equal(f.hits(), 0);
    assert.deepEqual(f.audit.getScopedApprovals(), []);
    await r.tap('❌ Deny');
    assert.equal(await r.response, 403);
  }, 3000);
});

test('quick actions still work after returning from the path selector', async t => {
  for (const quick of ['✅ Only this request', '⚡ 1h method-wide']) {
    await t.test(quick, async () => {
      await fixture(async f => {
        const r = await begin(f, '/a/b?x=1');
        await r.tap('Path-based'); await r.tap('← Back');
        const callback = button(r.menu, quick);
        await r.tap(quick);
        assert.equal(await r.response, 200);
        await f.transport.tap(r.menu, callback);
        assert.deepEqual(f.audit.getScopedApprovals(), []);
        if (quick === '✅ Only this request') {
          assert.deepEqual(f.audit.getActiveApprovals(), []);
          await deny(f, '/a/b?x=1');
        } else {
          assert.equal(f.audit.getActiveApprovals().length, 1);
          assert.equal(await f.request('GET', 'app', '/other?x=2'), 200);
          await deny(f, '/other?x=2', 'POST');
        }
      }, 3000);
    });
  }
});

test('week and month buttons persist the selected duration and expire at the exact boundary', async t => {
  for (const [label, days] of [['1w', 7], ['1month', 30]]) {
    await t.test(label, async t => {
      await fixture(async f => {
        const r = await scope(f, '/long-running?owner=me');
        for (const choice of ['15m', '30m', '1h', '4h', '24h', '1w', '1month', 'Forever']) button(r.menu, choice);
        await r.tap(label);
        assert.equal(await r.response, 200);
        const [grant] = f.audit.getScopedApprovals();
        assert.equal(grant.expiresAt - grant.approvedAt, days * 86400_000);
        await f.restart();
        t.mock.timers.enable({ apis: ['Date'], now: grant.expiresAt - 1 });
        try {
          assert.equal(await f.request('GET', 'app', '/long-running?owner=me'), 200);
          t.mock.timers.setTime(grant.expiresAt);
          await deny(f, '/long-running?owner=me');
          await f.restart();
          await deny(f, '/long-running?owner=me');
        } finally { t.mock.timers.reset(); }
      }, 3000);
    });
  }
});

test('Forever has no expiry after decades and restart, keeps its scope and remains revocable in the dashboard', async t => {
  await fixture(async f => {
    const r = await scope(f, '/permanent?owner=me');
    await r.tap('Query: ignored ▾'); await r.tap('Same parameters and values');
    await r.tap('Forever');
    assert.equal(await r.response, 200);
    assert.match(r.menu.text, /Approved until revoked/);
    assert.equal(f.audit.getScopedApprovals()[0].expiresAt, null);
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 20 * 365 * 86400_000 });
    try {
      await f.restart();
      assert.equal(await f.request('GET', 'app', '/permanent?owner=me'), 200);
      await deny(f, '/permanent?owner=someone-else');
      await deny(f, '/permanent?owner=me', 'POST');
      await withAdmin(f, async admin => {
        const data = (await admin('approvals')).body;
        const [grant] = Object.values(data.active);
        assert.equal(grant.expiresAt, null);
        assert.equal(grant.remainingMinutes, null);
        assert.equal(data.recent[0].ttl_seconds, null);
        assert.equal((await admin(`revoke/app?scopeId=${grant.scopeId}`, 'POST')).status, 200);
      });
      await f.restart();
      await deny(f, '/permanent?owner=me');
    } finally { t.mock.timers.reset(); }
  }, 3000);
});

test('optional exact path and all query values survive restart and expire at the boundary', async t => {
  await fixture(async f => {
    const r = await scope(f, '/api/items?owner=me&page=1&tag=a&tag=b');
    await r.tap('More options'); await r.tap('Exact path only');
    await r.tap('Query: ignored ▾'); await r.tap('Same parameters and values');
    assert.match(r.menu.text, /Subpaths: excluded/);
    assert.match(r.menu.text, /All parameters/);
    assert.equal(f.hits(), 0);
    await r.tap('30m');
    assert.equal(await r.response, 200);
    assert.equal(await f.request('GET', 'app', '/api/items?tag=a&tag=b&page=1&owner=me'), 200);
    for (const target of ['/api/items?owner=me&page=2&tag=a&tag=b', '/api/items?owner=me&page=1&tag=b&tag=a',
      '/api/items?owner=me&page=1&tag=a&tag=b&extra=1', '/api/items', '/api/items/child?owner=me&page=1&tag=a&tag=b']) {
      await deny(f, target);
    }
    await deny(f, '/api/items?owner=me&page=1&tag=a&tag=b', 'POST');
    await f.restart();
    assert.equal(await f.request('GET', 'app', '/api/items?owner=me&page=1&tag=a&tag=b'), 200);
    const [grant] = f.audit.getScopedApprovals();
    t.mock.timers.enable({ apis: ['Date'], now: grant.expiresAt });
    try { await deny(f, '/api/items?owner=me&page=1&tag=a&tag=b'); }
    finally { t.mock.timers.reset(); }
  }, 3000);
});

test('repository scope ignores query, selects GET and POST and respects path boundaries and method restrictions', async () => {
  await fixture(async f => {
    f.config.services.other = structuredClone(f.config.services.app);
    const r = await scope(f, '/logotel_spa/repo.git/info/refs?service=git-upload-pack');
    await r.tap('← Change path');
    await r.tap('/logotel_spa/repo.git/*');
    assert.match(r.menu.text, /Subpaths: included/);
    await r.tap('Query: ignored ▾'); await r.tap('Ignore query');
    await r.tap('Methods: GET ▾'); await r.tap('POST'); await r.tap('Done');
    await r.tap('1h');
    assert.equal(await r.response, 200);
    for (const target of ['/logotel_spa/repo.git', '/logotel_spa/repo.git/info/refs?different=1', '/logotel_spa/repo.git/git-upload-pack']) {
      assert.equal(await f.request('GET', 'app', target), 200);
      assert.equal(await f.request('POST', 'app', target), 200);
    }
    for (const target of ['/logotel_spa/repo.git-other/info', '/logotel_spa/other.git/info',
      '/logotel_spa/repo.git/../other.git/info', '/logotel_spa/repo.git/%2e%2e/other',
      '/logotel_spa/repo.git/a%2fb', '/logotel_spa/repo.git/a%252fb', '/logotel_spa/repo.git/a%5cb']) {
      await deny(f, target);
    }
    await deny(f, '/logotel_spa/repo.git/info/refs', 'GET', 'other');
    assert.equal(await f.request('DELETE', 'app', '/logotel_spa/repo.git/info'), 405);
    await f.transport.command('/revoke app');
    await deny(f, '/logotel_spa/repo.git/info');
    await f.restart();
    await deny(f, '/logotel_spa/repo.git/info');
  }, 3000);
});

test('selected query parameters keep their values and multiplicity while other parameters can change', async () => {
  await fixture(async f => {
    const r = await scope(f, '/api/items?owner=me&page=1&tag=a&tag=b');
    await r.tap('Query: ignored ▾'); await r.tap('Choose parameters');
    await r.tap('Done');
    assert.ok(!r.menu.options.reply_markup.inline_keyboard.flat().some(b => b.text === '1h'));
    await r.tap('Query: selected ▾'); await r.tap('Choose parameters');
    await r.tap('owner'); await r.tap('Done');
    assert.match(r.menu.text, /Selected parameters: owner=me/);
    await r.tap('15m');
    assert.equal(await r.response, 200);
    assert.equal(await f.request('GET', 'app', '/api/items?extra=yes&owner=me&page=50'), 200);
    for (const target of ['/api/items?owner=you', '/api/items?page=1', '/api/items?owner=me&owner=you', '/api/items?owner=me&owner=me']) {
      await deny(f, target);
    }
    await f.restart();
    assert.equal(await f.request('GET', 'app', '/api/items?owner=me'), 200);
  }, 3000);
});

test('scope callbacks bind message, chat, user and revision; once cannot be replayed or cached', async () => {
  await fixture(async f => {
    const r = await begin(f, '/a/b');
    const original = structuredClone(r.menu);
    const open = button(r.menu, 'Path-based');
    for (const overrides of [{ from: { id: 8, is_bot: false } }, { from: { id: 7, is_bot: true } },
      { message: { ...r.menu, chat: { id: 200 } } }, { message: { ...r.menu, message_id: -1 } }]) {
      await f.transport.tap(r.menu, open, overrides);
      assert.equal(f.hits(), 0);
    }
    await r.tap('Path-based');
    await r.tap('/a/b/*');
    const oldGrant = button(r.menu, '1h');
    await r.tap('← Change path');
    await f.transport.tap(r.menu, oldGrant);
    assert.equal(f.hits(), 0);
    await r.tap('/a/*');
    const grant = button(r.menu, '30m');
    const forged = button(original, '✅ Only this request').replace('approve_once:', 'approve_1month:');
    await f.transport.tap(original, forged);
    assert.equal(f.hits(), 0);
    await Promise.all([f.transport.tap(r.menu, grant), f.transport.tap(r.menu, grant)]);
    assert.equal(await r.response, 200);
    assert.equal(f.audit.getScopedApprovals().length, 1);
    await f.transport.command('/revoke app');
    await f.transport.tap(r.menu, grant);
    assert.equal(f.audit.getScopedApprovals().length, 0);
    const single = await begin(f, '/single');
    await single.tap('✅ Only this request');
    assert.equal(await single.response, 200);
    await deny(f, '/single');
  }, 3000);
});

test('expired request cannot be revived by navigation or a duration button', async t => {
  await fixture(async f => {
    const r = await scope(f, '/api/items');
    const grant = button(r.menu, '1h');
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 4000 });
    try {
      await f.transport.tap(r.menu, grant);
      assert.match(f.transport.answers.at(-1).text, /expired/);
      assert.equal(f.audit.getScopedApprovals().length, 0);
      assert.equal(await r.response, 403);
    } finally { t.mock.timers.reset(); }
  }, 3000);
});

test('path and query menus paginate and show full scope; sensitive query values are hidden in the preview', async () => {
  await fixture(async f => {
    const path = '/a/b/c/d/e/f/g/h/i/j';
    const r = await scope(f, `${path}?token=private-test-value&${Array.from({ length: 10 }, (_, i) => `p${i}=v${i}`).join('&')}`);
    assert.ok(!r.menu.text.includes('private-test-value'));
    await r.tap('Query: ignored ▾');
    assert.ok(!r.menu.text.includes('private-test-value'));
    assert.match(r.menu.text, /token=\[hidden\]/);
    await r.tap('Ignore query');
    await r.tap('← Change path'); await r.tap('Next →'); await r.tap('/a/b/c/d/e/f/g/h/*');
    await r.tap('Query: ignored ▾'); await r.tap('Choose parameters'); await r.tap('Next →');
    await r.tap('p9'); await r.tap('Done');
    assert.match(r.menu.text, /Path: \/a\/b\/c\/d\/e\/f\/g\/h\n/);
    await r.tap('24h');
    assert.equal(await r.response, 200);
    assert.equal(f.audit.getScopedApprovals()[0].scope.path, '/a/b/c/d/e/f/g/h');
  }, 3000);
});

test('long path choices remain distinct and query previews fit a Telegram message when edited again', async () => {
  await fixture(async f => {
    const prefix = '/' + 'a'.repeat(80);
    const r = await begin(f, `${prefix}/items/details?value=${'%00'.repeat(500)}`);
    await r.tap('Path-based');
    const paths = r.menu.options.reply_markup.inline_keyboard.flat().filter(b => b.callback_data.includes(':pick-'));
    assert.equal(new Set(paths.map(b => b.text)).size, 3);
    assert.ok(paths.every(b => b.text.endsWith('/*') && b.text.length <= 60));
    await r.tap(paths.at(-1).text);
    await r.tap('Query: ignored ▾');
    assert.ok(r.menu.text.length <= 4096);
    await r.tap('Same parameters and values');
    assert.ok(r.menu.text.length <= 4096);
    await r.tap('Query: same ▾');
    assert.ok(r.menu.text.length <= 4096);
    await r.tap('Ignore query');
    await r.tap('1h');
    assert.equal(await r.response, 200);
    assert.equal(await f.request('GET', 'app', `${prefix}/items/details/child?changed=1`), 200);
  }, 3000);
});

test('dashboard shows structured scope and can revoke its ID without removing a different scope', async () => {
  await fixture(async f => {
    for (const target of ['/one?owner=me', '/two?owner=me']) {
      const r = await scope(f, target); await r.tap('1h'); assert.equal(await r.response, 200);
    }
    await withAdmin(f, async admin => {
      assert.equal((await admin('approvals', 'GET', false)).status, 401);
      const data = (await admin('approvals')).body;
      const approvals = Object.values(data.active);
      assert.equal(approvals.length, 2);
      assert.equal(data.recent[0].scope.query.mode, 'ignore');
      const one = approvals.find(item => item.scope.path === '/one');
      assert.deepEqual(one.scope.methods, ['GET']);
      assert.ok(one.expiresAt && one.remainingMinutes > 0);
      assert.equal((await admin(`revoke/wrong?scopeId=${one.scopeId}`, 'POST')).status, 404);
      assert.equal((await admin(`revoke/app?scopeId=${one.scopeId}&method=GET`, 'POST')).status, 400);
      assert.equal((await admin(`revoke/app?scopeId=${one.scopeId}`, 'POST')).status, 200);
      await deny(f, '/one?owner=me');
      assert.equal(await f.request('GET', 'app', '/two?owner=me'), 200);
      assert.equal((await admin('revoke-all', 'POST')).status, 200);
      await deny(f, '/two?owner=me');
    });
  }, 3000);
});

test('new allow replaces scopes; service configuration changes invalidate scopes', async t => {
  await fixture(async f => {
    let r = await scope(f, '/one'); await r.tap('Forever'); assert.equal(await r.response, 200);
    await f.transport.command('/allow app 30m');
    assert.deepEqual(f.audit.getScopedApprovals(), []);
    const [temporary] = f.audit.getTemporaryServiceApprovals();
    t.mock.timers.enable({ apis: ['Date'], now: temporary.expiresAt });
    try { await deny(f, '/one'); } finally { t.mock.timers.reset(); }
    await f.transport.command('/revoke app');
    r = await scope(f, '/two'); await r.tap('Forever'); assert.equal(await r.response, 200);
    f.config.services.app.http.allowedMethods.push('PUT');
    await deny(f, '/two');
    assert.deepEqual(f.audit.getScopedApprovals(), []);
  }, 3000);
});

test('legacy approvals keep their scope after upgrade and a new allow replaces them durably', async t => {
  await fixture(async f => {
    // Simulate a database written by the previous release, then use public requests.
    f.audit.logApproval('app', 'GET', 'previous owner', 3600, null);
    f.audit.logApproval('app', 'POST', 'previous owner', 86400, '/exact?x=1');
    await f.restart();
    assert.equal(await f.request('GET', 'app', '/any'), 200);
    assert.equal(await f.request('POST', 'app', '/exact?x=1'), 200);
    await deny(f, '/exact?x=2', 'POST');
    await f.transport.command('/allow app 30m');
    const [grant] = f.audit.getTemporaryServiceApprovals();
    t.mock.timers.enable({ apis: ['Date'], now: grant.expiresAt });
    try {
      await f.restart();
      await deny(f, '/any');
      await deny(f, '/exact?x=1', 'POST');
    } finally { t.mock.timers.reset(); }
  }, 3000);
});

test('a root scope cannot authorize a plugin operation that requires a fresh decision', async () => {
  await fixture(async f => {
    const r = await begin(f, '/sdk/read');
    await r.tap('Method-wide');
    await r.tap('Methods: GET ▾'); await r.tap('POST'); await r.tap('Done');
    await r.tap('1h'); assert.equal(await r.response, 200);
    const before = f.transport.messages.length;
    const decision = f.manager.checkApproval('app', f.config.services.app, 'POST', '/sdk', '127.0.0.1', undefined,
      { approvalPath: '/sdk/write/PowerOnVM_Task', oneTime: true });
    const prompt = f.transport.messages.slice(before).find(msg => msg.options.reply_markup);
    assert.ok(prompt);
    assert.deepEqual(prompt.options.reply_markup.inline_keyboard.flat().map(b => b.text), ['✅ Approve this request', '❌ Deny']);
    // Let sendMessage finish binding the returned message before the callback.
    await delay(0);
    const forgedWide = button(prompt, '✅ Approve this request').replace('approve_once:', 'approve_1h:');
    await f.transport.tap(prompt, forgedWide);
    assert.match(f.transport.answers.at(-1).text, /Choice not available/);
    await f.transport.tap(prompt, button(prompt, '❌ Deny'));
    assert.equal(await decision, false);
  }, 3000);
});
