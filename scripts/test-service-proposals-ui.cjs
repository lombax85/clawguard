// Optional browser E2E. Run after npm run build. Set CLAWGUARD_PLAYWRIGHT_MODULE
// to an installed Playwright module if it is not available on Node's module path.
const assert = require('node:assert/strict');
const http = require('node:http');
const { chromium } = require(process.env.CLAWGUARD_PLAYWRIGHT_MODULE || 'playwright');
const { createProxy } = require('../dist/proxy');
const { AuditLogger } = require('../dist/audit');
const { ApprovalManager } = require('../dist/approval');
const { createAdminSshKeyTools } = require('../dist/admin-ssh');
const { DEFAULT_SSH_BROKER, DEFAULT_FTP_GATEWAY } = require('../dist/config');

async function main() {
  const audit = new AuditLogger(':memory:');
  const manager = new ApprovalManager(undefined, audit);
  const key = await createAdminSshKeyTools().generate('ui-test-only');
  const hostKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC';
  const source = { protocol: 'ssh', upstream: 'ssh://127.0.0.1:22',
    auth: { type: 'plugin', pluginPath: 'ssh-agent-key', pluginConfig: { username: 'root', privateKey: key.privateKey } },
    policy: { default: 'require_approval' }, ssh: { allowPrivateTarget: true, knownHostKey: hostKey } };
  const config = { server: { agentKey: 'test-agent' }, services: { source, 'http-update': {
      protocol: 'http', upstream: 'https://api.example.com', auth: { type: 'bearer', token: 'UI-ONLY-TEST-TOKEN' },
      policy: { default: 'require_approval' }, http: { allowedMethods: ['GET'] },
    } },
    admin: { enabled: true, strictMode: false, pin: 'test-owner', allowedIPs: ['127.0.0.1'] },
    security: { allowedUpstreams: ['127.0.0.1', 'api.example.com'], blockPrivateIPs: true, followRedirects: false, maxPayloadLogSize: 1024 },
    audit: { logPayload: false }, sshBroker: { ...DEFAULT_SSH_BROKER, enabled: true },
    ftpGateway: { ...DEFAULT_FTP_GATEWAY, enabled: false } };
  const server = http.createServer(createProxy(config, manager, audit));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({ headless: true, channel: process.env.CLAWGUARD_BROWSER_CHANNEL || undefined });
  try {
    for (const [name, ssh] of [['old-placeholder', { allowPrivateTarget: true, knownHostKey: { $clawguard: 'input' } }],
      ['proposed-first-use', { allowPrivateTarget: true, trustOnFirstUse: true }]]) {
      const response = await fetch(base + '/__proposals/services', { method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-ClawGuard-Key': 'test-agent' },
        body: JSON.stringify({ name, config: { ...source, ssh,
          auth: { ...source.auth, pluginConfig: { username: 'root', privateKey: { $clawguard: 'credential' } } } } }) });
      assert.equal(response.status, 202, await response.text());
    }
    const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    // The chart CDN is irrelevant to this offline form test.
    await page.route('**/*', route => route.request().url().startsWith(base)
      ? route.continue() : route.fulfill({ contentType: 'application/javascript', body: 'window.Chart=class {destroy(){}};' }));
    await page.goto(base + '/__admin/');
    await page.locator('#pin-input').fill('test-owner');
    await page.locator('#pin-input').press('Enter');
    await page.locator('[data-section="proposals"]').click();
    const oldRow = page.locator('#proposals-table tr').filter({ hasText: 'old-placeholder' });
    await oldRow.getByRole('button', { name: 'Review' }).click();
    assert.equal(await page.locator('#proposal-ssh-trust').inputValue(), 'first-use');
    assert.equal(await page.locator('#proposal-inputs').isVisible(), false);
    await page.locator('#proposal-ssh-trust').selectOption('pinned');
    assert.equal(await page.locator('#proposal-inputs textarea').isVisible(), true);
    await page.locator('#proposal-ssh-trust').selectOption('first-use');
    await page.locator('#proposal-credentials select').selectOption('0');
    const approved = page.waitForResponse(response => response.url().endsWith('/approve'));
    await page.locator('#proposal-approve-btn').click();
    assert.equal((await approved).status(), 200);
    await page.locator('#proposal-modal').waitFor({ state: 'hidden' });
    assert.equal(config.services['old-placeholder'].ssh.trustOnFirstUse, true);
    assert.equal(config.services['old-placeholder'].ssh.knownHostKey, undefined);
    assert.equal(audit.getSshHostIdentity('old-placeholder', source.upstream), undefined);

    await page.locator('#proposals-table tr').filter({ hasText: 'proposed-first-use' }).getByRole('button', { name: 'Review' }).click();
    await page.locator('#proposal-ssh-trust').selectOption('pinned');
    await page.locator('#proposal-inputs textarea').fill(hostKey);
    await page.locator('#proposal-credentials select').selectOption('0');
    const pinned = page.waitForResponse(response => response.url().endsWith('/approve'));
    await page.locator('#proposal-approve-btn').click();
    assert.equal((await pinned).status(), 200);
    await page.locator('#proposal-modal').waitFor({ state: 'hidden' });
    assert.equal(config.services['proposed-first-use'].ssh.knownHostKey, hostKey);

    async function proposeUpdate(patch) {
      const res = await fetch(base + '/__proposals/services', { method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-ClawGuard-Key': 'test-agent' },
        body: JSON.stringify({ name: 'http-update', config: patch }) });
      assert.equal(res.status, 202); return res.json();
    }
    await proposeUpdate({ http: { allowedMethods: ['GET', 'POST'] } });
    await page.locator('[data-section="proposals"]').click();
    await page.locator('#proposals-table tr').filter({ hasText: 'http-update' }).getByRole('button', { name: 'Review', exact: true }).click();
    await page.locator('#proposal-modal').waitFor({ state: 'visible' });
    assert.match(await page.locator('#proposal-title').innerText(), /Review update/);
    assert.match(await page.locator('#proposal-changes').innerText(), /HTTP methods/);
    assert.match(await page.locator('#proposal-changes').innerText(), /POST/);
    assert.equal(await page.locator('#proposal-credentials select').inputValue(), 'keep');
    assert.equal(await page.locator('#proposal-credentials input').isVisible(), false);
    assert.equal(await page.locator('#proposal-reuse-review').isVisible(), false);
    assert.ok(!(await page.locator('#proposal-config').inputValue()).includes('UI-ONLY-TEST-TOKEN'));
    assert.equal(await page.locator('#proposal-approve-btn').innerText(), 'Approve changes');
    await page.screenshot({ path: '/tmp/clawguard-proposal-update-desktop.png', fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: '/tmp/clawguard-proposal-update-mobile.png', fullPage: true });
    const modalBounds = await page.locator('#proposal-modal .modal').boundingBox();
    assert.ok(modalBounds.x >= 0 && modalBounds.x + modalBounds.width <= 390);
    await page.setViewportSize({ width: 1280, height: 1000 });
    const updated = page.waitForResponse(response => response.url().endsWith('/approve'));
    await page.locator('#proposal-approve-btn').click();
    assert.equal((await updated).status(), 200);
    await page.locator('#proposal-modal').waitFor({ state: 'hidden' });
    assert.deepEqual(config.services['http-update'].http.allowedMethods, ['GET', 'POST']);
    assert.equal(config.services['http-update'].auth.token, 'UI-ONLY-TEST-TOKEN');
    const stale = await proposeUpdate({ http: { allowedMethods: ['GET', 'POST', 'PUT'] } });
    const changed = await fetch(base + '/__admin/api/services/http-update', { method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-ClawGuard-Pin': 'test-owner' },
      body: JSON.stringify({ config: { http: { noCheckCertificate: true } } }) });
    assert.equal(changed.status, 200);
    await page.locator('[data-section="proposals"]').click();
    await page.locator('#proposals-table tr').filter({ hasText: 'http-update' }).filter({ hasText: 'stale' })
      .getByRole('button', { name: 'Review', exact: true }).click();
    await page.locator('#proposal-modal').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#proposal-approve-btn').isDisabled(), true);
    assert.match(await page.locator('#proposal-changes').innerText(), /out of date/);
    await page.evaluate(() => hideProposal());

    await page.locator('[data-section="services"]').click();
    await page.locator('#add-ssh-host-btn').click();
    await page.locator('#ssh-host-id').fill('wizard-first-use');
    await page.locator('#ssh-host').fill('127.0.0.1');
    await page.locator('#ssh-username').fill('root');
    await page.locator('#ssh-allow-private').check();
    await page.locator('#ssh-key-mode').selectOption('paste');
    await page.locator('#ssh-private-key').fill(key.privateKey.trim());
    assert.equal(await page.locator('#ssh-host-key-mode').inputValue(), 'first-use');
    let scans = 0;
    page.on('request', request => { if (request.url().includes('/ssh-host-keys/scan')) scans++; });
    const saved = page.waitForResponse(response => response.url().endsWith('/api/ssh-services') && response.request().method() === 'POST');
    await page.locator('#ssh-wizard-save-btn').click();
    assert.equal((await saved).status(), 200);
    await page.getByRole('button', { name: 'Done', exact: true }).click();
    await page.locator('#ssh-wizard-modal').waitFor({ state: 'hidden' });
    assert.equal(scans, 0, 'first-use mode must not scan during configuration');
    assert.equal(config.services['wizard-first-use'].ssh.trustOnFirstUse, true);
    audit.rememberSshHostIdentity('wizard-first-use', source.upstream, hostKey);
    await page.locator('[data-section="services"]').click();
    await page.locator('#services-table tr').filter({ hasText: 'wizard-first-use' }).getByRole('button', { name: 'Edit', exact: true }).click();
    assert.equal(await page.locator('#ssh-host-key-mode').inputValue(), 'first-use');
    assert.match(await page.locator('#ssh-host-key-saved-status').innerText(), /SHA256:/);
    await page.screenshot({ path: '/tmp/clawguard-ssh-first-use-ui.png', fullPage: true });
    assert.deepEqual(errors, []);
    console.log('PASS: update diff, credential retention, stale update, mobile layout, existing proposal, first-use/pinned choice, managed key reuse, pasted key without final newline, SSH wizard and learned fingerprint');
  } finally {
    await browser.close(); await new Promise(resolve => server.close(resolve)); audit.close();
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
