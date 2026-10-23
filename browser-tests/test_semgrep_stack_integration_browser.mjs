import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { before, after, test } from 'node:test';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const appRoot = process.env.APP_ROOT || path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const staticRoot = path.join(appRoot, 'static');
const chromiumPath = process.env.CHROMIUM_PATH || '/ms-playwright/chromium-1248/chrome-linux-arm64/chrome';
const requests = [];
let server, browser, origin;

before(async () => {
  server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    requests.push({ path: url.pathname, method: request.method });
    if (url.pathname.startsWith('/api/')) {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(url.pathname === '/api/engagements' ? '{"engagements":[]}' : '{}');
      return;
    }
    const relative = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    const full = path.resolve(staticRoot, relative);
    if (!full.startsWith(staticRoot + path.sep) || !fs.existsSync(full)) {
      response.writeHead(404); response.end(); return;
    }
    response.writeHead(200, { 'content-type': full.endsWith('.js') ? 'text/javascript' : full.endsWith('.css') ? 'text/css' : 'text/html' });
    fs.createReadStream(full).pipe(response);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = 'http://127.0.0.1:' + server.address().port + '/';
  browser = await chromium.launch({ executablePath: chromiumPath, headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
});
after(async () => {
  if (browser) await browser.close();
  if (server) await new Promise(resolve => server.close(resolve));
});

async function toolingPage() {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  page.setDefaultTimeout(5000);
  await page.goto(origin);
  await page.waitForFunction(() => typeof showModal === 'function');
  const toolingNav = page.getByLabel('Ana menü').locator('.nav-item[data-nav="tooling"]');
  await toolingNav.focus();
  assert.equal(await toolingNav.evaluate(node => node === document.activeElement), true);
  await page.keyboard.press('Enter');
  const launcher = page.locator('details.ui-tool-launcher').first();
  await launcher.locator(':scope > summary').focus();
  await page.keyboard.press('Enter');
  assert.equal(await launcher.evaluate(node => node.open), true);
  return page;
}
async function visible(page, selector) {
  return page.locator(selector).evaluate(node => !node.classList.contains('hidden'));
}
async function focusInside(page, selector) {
  return page.locator(selector).evaluate(node => node.contains(document.activeElement));
}
function noPost(start) {
  assert.deepEqual(requests.slice(start).filter(request => request.method === 'POST'), []);
}

test('Semgrep opener followed by generic top dialog closes one layer per Escape', async () => {
  const page = await toolingPage();
  try {
    const start = requests.length;
    const opener = page.locator('[data-action="open-semgrep-local"]');
    await opener.click();
    assert.equal(await visible(page, '#semgrep-local-modal'), true);
    assert.equal(await focusInside(page, '#semgrep-local-modal'), true);
    await page.evaluate(() => showModal('target-modal', true));
    assert.equal(await visible(page, '#target-modal'), true);
    assert.equal(await focusInside(page, '#target-modal'), true);
    await page.keyboard.press('Tab');
    assert.equal(await focusInside(page, '#target-modal'), true);
    await page.keyboard.press('Escape');
    assert.equal(await visible(page, '#target-modal'), false);
    assert.equal(await visible(page, '#semgrep-local-modal'), true);
    assert.equal(await focusInside(page, '#semgrep-local-modal'), true);
    await page.keyboard.press('Escape');
    assert.equal(await visible(page, '#semgrep-local-modal'), false);
    assert.equal(await opener.evaluate(node => node === document.activeElement), true);
    noPost(start);
  } finally { await page.close(); }
});

test('generic top dialog blocks background Semgrep opener without a scan', async () => {
  const page = await toolingPage();
  try {
    const start = requests.length;
    const opener = page.locator('[data-action="add-target"]').first();
    await opener.click();
    assert.equal(await visible(page, '#target-modal'), true);
    await page.evaluate(() => document.querySelector('[data-action="open-semgrep-local"]').click());
    assert.equal(await visible(page, '#target-modal'), true);
    assert.equal(await visible(page, '#semgrep-local-modal'), false);
    assert.equal(await focusInside(page, '#target-modal'), true);
    await page.keyboard.press('Escape');
    assert.equal(await visible(page, '#target-modal'), false);
    noPost(start);
  } finally { await page.close(); }
});
