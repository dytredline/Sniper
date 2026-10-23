'use strict';
// Sniper yetkili-hedef tarayıcı sürücüsü: bwrap sandbox'ında (ağ ad alanında yalnız lo + tek hedef aktarıcı) çalışır.
// Kullanıcı kodu çalıştırmaz; yalnız /job/plan.json'daki doğrulanmış yolları açar ve olgu toplar.
// Yanıt gövdeleri, çerez değerleri ve form değerleri dışarı yazılmaz; yalnız sayılar, bayraklar ve kısaltılmış iletiler.
const fs = require('node:fs');
const { chromium } = require('/opt/playwright-core');

const plan = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const BASE = new URL(plan.base_url);
const MAX_TEXT = 200;
const MAX_SAMPLES = 5;

const clip = (value) => String(value ?? '').replace(/[\u0000-\u001f]/g, ' ').slice(0, MAX_TEXT);
const sameOrigin = (url) => {
  try { return new URL(url).origin === BASE.origin; } catch { return false; }
};
const describeUrl = (url) => {
  try {
    const parsed = new URL(url);
    return parsed.origin === BASE.origin ? parsed.pathname : parsed.origin;
  } catch { return 'gecersiz-url'; }
};
const pushSample = (list, value) => { if (list.length < MAX_SAMPLES) list.push(value); };

const SECURITY_HEADERS = [
  'content-security-policy', 'x-frame-options', 'strict-transport-security', 'x-content-type-options',
  'referrer-policy', 'permissions-policy', 'cross-origin-opener-policy',
];
const DISCLOSURE_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'];

async function visit(context, path, probe) {
  const page = await context.newPage();
  const facts = {
    path, probe: Boolean(probe), status: null, final_path: null, left_origin: false, title: '',
    console_errors: 0, console_samples: [], page_errors: 0, page_error_samples: [],
    failed_requests: 0, failed_samples: [], requests: 0, external_origins: [], mixed_content: 0,
    headers: {}, disclosure_headers: {}, forms: null, reflection: null, error: null,
  };
  const external = new Set();
  page.on('console', (msg) => {
    if (msg.type() === 'error') { facts.console_errors += 1; pushSample(facts.console_samples, clip(msg.text())); }
  });
  page.on('pageerror', (err) => { facts.page_errors += 1; pushSample(facts.page_error_samples, clip(err.message)); });
  page.on('request', (req) => {
    facts.requests += 1;
    const url = req.url();
    if (!sameOrigin(url) && /^https?:/.test(url)) external.add(new URL(url).origin);
    if (BASE.protocol === 'https:' && url.startsWith('http:')) facts.mixed_content += 1;
  });
  page.on('requestfailed', (req) => {
    facts.failed_requests += 1;
    pushSample(facts.failed_samples, `${describeUrl(req.url())} ${clip(req.failure()?.errorText)}`);
  });
  let url = new URL(path, BASE).toString();
  if (probe) url += (url.includes('?') ? '&' : '?') + 'sniper_probe=' + encodeURIComponent(probe.payload);
  try {
    const response = await page.goto(url, { waitUntil: 'load', timeout: plan.nav_timeout_ms });
    if (response) {
      facts.status = response.status();
      const headers = response.headers();
      for (const name of SECURITY_HEADERS) facts.headers[name] = name in headers ? clip(headers[name]) : null;
      for (const name of DISCLOSURE_HEADERS) if (name in headers) facts.disclosure_headers[name] = clip(headers[name]);
    }
    await page.waitForLoadState('networkidle', { timeout: Math.min(5000, plan.nav_timeout_ms) }).catch(() => {});
    const finalUrl = page.url();
    facts.left_origin = !sameOrigin(finalUrl);
    facts.final_path = describeUrl(finalUrl);
    facts.title = clip(await page.title());
    facts.forms = await page.evaluate((origin) => {
      const forms = [...document.forms];
      const passwordForms = forms.filter((f) => f.querySelector('input[type=password]'));
      const external = forms.filter((f) => { try { return new URL(f.action, location.href).origin !== origin; } catch { return false; } });
      return {
        count: forms.length,
        password_forms: passwordForms.length,
        password_get_forms: passwordForms.filter((f) => (f.method || 'get').toLowerCase() === 'get').length,
        external_action_forms: external.length,
        inline_scripts: document.querySelectorAll('script:not([src])').length,
        inline_handlers: document.querySelectorAll('[onclick],[onload],[onerror],[onmouseover],[onsubmit]').length,
        iframes: document.querySelectorAll('iframe').length,
      };
    }, BASE.origin);
    if (probe) {
      facts.reflection = await page.evaluate((p) => ({
        element_injected: document.getElementsByTagName(p.tag).length > 0,
        raw_text_reflected: document.documentElement.outerHTML.includes(p.marker),
      }), { tag: probe.tag, marker: probe.marker });
    }
    if (plan.screenshot && !probe && plan.shots_left > 0) {
      plan.shots_left -= 1;
      await page.screenshot({ path: '/out/shot.png', type: 'png', fullPage: false, timeout: 10000 });
      facts.screenshot = true;
    }
  } catch (err) {
    facts.error = clip(err.message.split('\n')[0]);
  } finally {
    facts.external_origins = [...external].slice(0, 20);
    await page.close().catch(() => {});
  }
  return facts;
}

async function main() {
  const started = Date.now();
  const browser = await chromium.launch({
    executablePath: '/opt/chromium/chrome',
    headless: true,
    // Genel hedef akışında Chromium renderer sandbox'ı zorunludur. Çalışma zamanı bu korumayı
    // kuramıyorsa üst katman koşuyu başlamadan reddeder; burada --no-sandbox geri dönüşü yoktur.
    chromiumSandbox: true,
    timeout: 45000,
    args: ['--disable-gpu', '--disable-dev-shm-usage', '--no-first-run', '--disable-background-networking',
      '--disable-component-update', '--disable-sync', '--metrics-recording-only', '--disable-breakpad',
      `--host-resolver-rules=MAP ${BASE.hostname} 127.0.0.1,EXCLUDE localhost`],
  });
  const result = { format: 'sniper-playwright-facts-v1', browser_version: browser.version(), pages: [], cookies: [] };
  try {
    const context = await browser.newContext({
      ignoreHTTPSErrors: Boolean(plan.ignore_https_errors), javaScriptEnabled: true, serviceWorkers: 'block',
      acceptDownloads: false, viewport: { width: 1280, height: 800 }, userAgent: plan.user_agent,
    });
    context.setDefaultTimeout(plan.nav_timeout_ms);
    for (const path of plan.paths) {
      result.pages.push(await visit(context, path, null));
      if (plan.reflection_probe) result.pages.push(await visit(context, path, plan.probe));
    }
    result.cookies = (await context.cookies(BASE.origin)).slice(0, 50).map((c) => ({
      name: clip(c.name), secure: c.secure, http_only: c.httpOnly, same_site: c.sameSite,
    }));
    await context.close();
  } finally {
    await browser.close().catch(() => {});
  }
  result.elapsed_ms = Date.now() - started;
  fs.writeFileSync('/out/playwright.json', JSON.stringify(result));
}

main().catch((err) => {
  process.stderr.write(`surucu_hatasi: ${clip(err && err.message)}\n`);
  process.exit(2);
});
