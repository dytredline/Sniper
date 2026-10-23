'use strict';
// Sniper PDF rapor sürücüsü: bwrap sandbox'ında (ağ ad alanında yalnız lo, hiçbir dinleyici yok) çalışır.
// Yalnız /job/report.html dosyasını açar (JavaScript kapalı, ağ istekleri reddedilir) ve /out/report.pdf yazar.
// Kullanıcı kodu çalıştırmaz; HTML Sniper'ın kendi rapor üreticisinden gelir.
const fs = require('node:fs');
const { chromium } = require('/opt/playwright-core');

const plan = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const clip = (value) => String(value ?? '').replace(/[\u0000-\u001f]/g, ' ').slice(0, 200);

async function main() {
  const started = Date.now();
  const html = fs.readFileSync('/job/report.html', 'utf8');
  const browser = await chromium.launch({
    executablePath: '/opt/chromium/chrome',
    headless: true,
    // Bkz. sandbox_playwright_driver.cjs: Chromium'un iç sandbox'ı bwrap içinde kurulamaz; yalıtım bwrap + seccomp.
    chromiumSandbox: false,
    timeout: 45000,
    args: ['--disable-gpu', '--disable-dev-shm-usage', '--no-first-run', '--disable-background-networking',
      '--disable-component-update', '--disable-sync', '--metrics-recording-only', '--disable-breakpad'],
  });
  const result = { format: 'sniper-pdf-facts-v1', browser_version: browser.version(), blocked_requests: 0 };
  try {
    const context = await browser.newContext({
      javaScriptEnabled: false, serviceWorkers: 'block', acceptDownloads: false, offline: true,
    });
    context.setDefaultTimeout(plan.timeout_ms);
    // Rapor yalnız satır içi stil ve data: görselleri kullanır; başka her istek (dosya dahil) reddedilir.
    await context.route('**/*', (route) => {
      const url = route.request().url();
      if (url.startsWith('data:') || url === 'about:blank') return route.continue();
      result.blocked_requests += 1;
      return route.abort('blockedbyclient');
    });
    const page = await context.newPage();
    await page.setContent(html, { waitUntil: 'load', timeout: plan.timeout_ms });
    await page.emulateMedia({ media: 'print' });
    await page.pdf({
      path: '/out/report.pdf', format: plan.page_format, printBackground: true, preferCSSPageSize: true,
      margin: { top: '14mm', bottom: '16mm', left: '12mm', right: '12mm' },
      displayHeaderFooter: true, headerTemplate: '<span></span>',
      footerTemplate: '<div style="font-size:7px;width:100%;text-align:center;color:#666">'
        + '<span class="pageNumber"></span> / <span class="totalPages"></span></div>',
    });
    result.title = clip(await page.title());
    await context.close();
  } finally {
    await browser.close().catch(() => {});
  }
  result.elapsed_ms = Date.now() - started;
  fs.writeFileSync('/out/pdf.json', JSON.stringify(result));
}

main().catch((err) => {
  process.stderr.write(`pdf_surucu_hatasi: ${clip(err && err.message)}\n`);
  process.exit(2);
});
