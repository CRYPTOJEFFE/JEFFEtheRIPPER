/* Optional development check. Requires Playwright and Chromium, not runtime deps.
 * Run: node ultimate/tests/browser-check.cjs (from any working directory).
 * Uses a real temporary TeamServer and synthetic users/files. No engine runs.
 */
'use strict';
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const ultimate = path.resolve(__dirname, '..');
const reports = path.join(ultimate, 'reports');
const fixture = String.raw`
import hashlib, json, sys, tempfile, threading
from pathlib import Path
from jeffe.server import build_server
with tempfile.TemporaryDirectory(prefix='jeffe-browser-fixture-') as root:
    root = Path(root)
    auth = root / 'auth.json'
    auth.write_text(json.dumps({'principals': [
        {'name': 'browser-operator', 'role': 'operator', 'token_sha256': hashlib.sha256(b'a' * 64).hexdigest()},
        {'name': 'browser-viewer', 'role': 'viewer', 'token_sha256': hashlib.sha256(b'b' * 64).hexdigest()}]}))
    auth.chmod(0o600)
    backlog = [{'id': i, 'idea': 'Synthetic browser-test proposal ' + str(i),
                'category': 'Synthetic fixture', 'priority': 'P1', 'effort': 'M',
                'status': 'planned'} for i in range(1, 1001)]
    integrations = [{'repo': 'synthetic/review-fixture', 'decision': 'reference-only',
                     'reason': 'Synthetic browser validation entry; no software installed.'}]
    server = build_server('127.0.0.1', 0, root / 'work', auth,
                          {'john': 'john'}, integrations, backlog)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    print(server.server_address[1], flush=True)
    try:
        sys.stdin.readline()
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
`;

async function run() {
  let browser;
  const child = spawn(process.env.JEFFE_TEST_PYTHON || 'python', ['-u', '-c', fixture], {
    cwd: ultimate,
    env: { ...process.env, PYTHONPATH: ultimate },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const exitPromise = once(child, 'exit');
  let serverErrors = '';
  child.stderr.on('data', chunk => { serverErrors += chunk.toString(); });
  const reader = readline.createInterface({ input: child.stdout });
  const port = await new Promise((resolve, reject) => {
    reader.once('line', line => /^\d+$/.test(line) ? resolve(line) : reject(new Error('Invalid fixture port')));
    child.once('error', reject);
    child.once('exit', code => reject(new Error('Fixture exited before startup: ' + code + ' ' + serverErrors)));
  });
  try {
    const executablePath = process.env.CHROMIUM_EXECUTABLE || (fs.existsSync('/usr/bin/chromium') ? '/usr/bin/chromium' : undefined);
    browser = await chromium.launch({ executablePath, headless: true, args: ['--no-sandbox'] });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto('http://127.0.0.1:' + port);
    await page.locator('#access-token').fill('a'.repeat(64));
    await page.getByRole('button', { name: 'Connect', exact: true }).click();
    await page.getByText('Workspace refreshed.', { exact: true }).waitFor();
    assert.equal(await page.locator('#access-token').inputValue(), '');
    const frame = page.frameLocator('#report-frame');
    await frame.locator('#idea-count').getByText('1000 of 1000 ideas').waitFor();
    await frame.locator('#idea-search').fill('1000');
    assert.match(await frame.locator('#idea-count').textContent(), /^1 of 1000/);
    await frame.locator('#idea-search').fill('');
    await frame.locator('#next').click();
    assert.match(await frame.locator('#page-number').textContent(), /Page 2 of 20/);
    for (const [kind, body] of [['hashes', '0123456789abcdef\n'], ['wordlist', 'synthetic-candidate\n']]) {
      await page.locator('#upload-kind').selectOption(kind);
      await page.locator('#input-file').setInputFiles({ name: 'synthetic.txt', mimeType: 'text/plain', buffer: Buffer.from(body) });
      await page.getByRole('button', { name: 'Import file', exact: true }).click();
      await page.locator('#message').filter({ hasText: 'Imported asset' }).waitFor();
      await page.waitForFunction(type => document.querySelector(type === 'hashes' ? '#hash-asset' : '#wordlist-asset').options.length === 2, kind);
    }
    await page.locator('#format').fill('raw-sha256');
    await page.locator('#hash-asset').selectOption({ index: 1 });
    await page.locator('#wordlist-asset').selectOption({ index: 1 });
    await page.getByRole('button', { name: 'Create job', exact: true }).click();
    await page.locator('#message').filter({ hasText: 'Created job' }).waitFor();
    await page.getByRole('button', { name: 'Start', exact: true }).waitFor();
    assert.equal(await page.getByRole('button', { name: 'Start', exact: true }).isEnabled(), true);
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    await page.evaluate(() => window.scrollTo(0, 0));
    fs.mkdirSync(reports, { recursive: true, mode: 0o700 });
    const screenshot = path.join(reports, 'team-dashboard-synthetic.png');
    await page.screenshot({ path: screenshot });
    fs.chmodSync(screenshot, 0o600);
    await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
    assert.equal(await page.locator('#workspace').isVisible(), false);
    assert.equal(await page.locator('#report-frame').getAttribute('srcdoc'), null);
    await page.locator('#access-token').fill('b'.repeat(64));
    await page.getByRole('button', { name: 'Connect', exact: true }).click();
    await page.getByText('Workspace refreshed.', { exact: true }).waitFor();
    assert.equal(await page.getByRole('button', { name: 'Create job', exact: true }).isEnabled(), false);
    assert.equal(await page.getByRole('button', { name: 'Start', exact: true }).count(), 0);
    await page.setViewportSize({ width: 390, height: 844 });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    assert.equal(errors.length, 0, errors.join('\n'));
    const result = {
      passed: true,
      server: 'Real TeamServer bound to loopback with temporary storage',
      data: 'Synthetic users, files, 1000 planned tracker entries, and one reference-only catalog entry',
      engine_execution: false,
      browser: await browser.version(),
      checks: ['operator authentication', 'token field clearing', '1000-row tracker', 'exact ID search',
        'tracker pagination', 'hash import', 'wordlist import', 'queued job creation', 'enabled Start control',
        'disconnect cleanup', 'viewer authentication and restrictions', 'no persistent token storage',
        '390px mobile layout', 'no JavaScript errors'],
      screenshot: path.basename(screenshot),
    };
    const output = path.join(reports, 'dashboard-browser.json');
    fs.writeFileSync(output, JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
    console.log(JSON.stringify(result, null, 2));
  } finally {
    if (browser) await browser.close();
    child.stdin.end('stop\n');
    const timer = setTimeout(() => child.kill('SIGTERM'), 5000);
    await exitPromise;
    clearTimeout(timer);
    reader.close();
  }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
