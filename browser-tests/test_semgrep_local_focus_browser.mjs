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
    const contentType = full.endsWith('.js') ? 'text/javascript' : full.endsWith('.css') ? 'text/css' : 'text/html';
    response.writeHead(200, { 'content-type': contentType });
    fs.createReadStream(full).pipe(response);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}/`;
  browser = await chromium.launch({ executablePath: chromiumPath, headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
});
after(async () => {
  if (browser) await browser.close();
  if (server) await new Promise(resolve => server.close(resolve));
});

async function page() {
  const p = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  await p.goto(origin);
  const toolingNav = p.getByLabel('Ana menü').locator('.nav-item[data-nav="tooling"]');
  await toolingNav.focus();
  assert.equal(await toolingNav.evaluate(node => node === document.activeElement), true);
  await p.keyboard.press('Enter');
  const launcher = p.locator('details.ui-tool-launcher').first();
  await launcher.locator(':scope > summary').focus();
  await p.keyboard.press('Enter');
  assert.equal(await launcher.evaluate(node => node.open), true);
  return p;
}
async function open(p) {
  const opener = p.locator('[data-action="open-semgrep-local"]');
  await opener.click();
  return opener;
}
async function inside(p) {
  return p.locator('#semgrep-local-modal').evaluate(modal => modal.contains(document.activeElement));
}
function noActivePost(start) {
  assert.deepEqual(requests.slice(start).filter(request => request.method === 'POST'), []);
}

test('real local Semgrep launcher opens both forms without starting a scan or link', async () => {
  const p = await page();
  try {
    const start = requests.length;
    await open(p);
    assert.equal(await p.locator('#semgrep-local-modal').evaluate(node => node.classList.contains('hidden')), false);
    assert.equal(await p.locator('#semgrep-local-submit').isDisabled(), true);
    assert.equal(await p.locator('#semgrep-evidence-submit').isDisabled(), true);
    assert.equal(requests.slice(start).some(request => request.path === '/api/engagements' && request.method === 'GET'), true);
    noActivePost(start);
  } finally { await p.close(); }
});

test('opening focuses an enabled visible control inside the direct dialog', async () => {
  const p = await page();
  try {
    await open(p);
    assert.equal(await inside(p), true);
    assert.equal(await p.evaluate(() => document.activeElement?.disabled), false);
  } finally { await p.close(); }
});

test('forward and reverse Tab stay in the direct Semgrep dialog without requests', async () => {
  const p = await page();
  try {
    const start = requests.length;
    await open(p);
    assert.equal(await inside(p), true);
    for (let i = 0; i < 24; i += 1) {
      await p.keyboard.press('Tab');
      assert.equal(await inside(p), true, `forward Tab ${i}`);
    }
    for (let i = 0; i < 24; i += 1) {
      await p.keyboard.press('Shift+Tab');
      assert.equal(await inside(p), true, `reverse Tab ${i}`);
    }
    noActivePost(start);
  } finally { await p.close(); }
});

test('Escape, close button and backdrop each restore the opener and do not submit either form', async () => {
  const p = await page();
  try {
    const start = requests.length;
    const opener = await open(p);
    await p.waitForFunction(() => document.querySelector('#semgrep-evidence-engagement option')?.textContent === 'Uygun etkin denetim yok');
    await p.locator('#semgrep-evidence-confirm-local').check();
    await p.keyboard.press('Escape');
    assert.equal(await p.locator('#semgrep-evidence-confirm-local').isChecked(), false);
    assert.equal(await p.locator('#semgrep-local-modal').evaluate(node => node.classList.contains('hidden')), true);
    assert.equal(await opener.evaluate(node => node === document.activeElement), true);
    await opener.click();
    await p.locator('#semgrep-local-modal .modal-close').click();
    assert.equal(await opener.evaluate(node => node === document.activeElement), true);
    await opener.click();
    await p.locator('#semgrep-local-modal').evaluate(node => node.click());
    assert.equal(await p.locator('#semgrep-local-modal').evaluate(node => node.classList.contains('hidden')), true);
    assert.equal(await opener.evaluate(node => node === document.activeElement), true);
    noActivePost(start);
  } finally { await p.close(); }
});
