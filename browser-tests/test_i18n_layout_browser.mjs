import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright-core");
const appRoot = process.env.APP_ROOT || path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const staticRoot = path.join(appRoot, "static");
const chromiumPath = process.env.CHROMIUM_PATH || "/opt/sniper-playwright/chromium-1194/chrome-linux/chrome";
let server, browser, origin;

const apiBodies = {
  "/api/targets": "{\"targets\":[]}",
  "/api/scans": "{\"scans\":[]}",
  "/api/project-audits": "{\"audits\":[]}",
  "/api/engagements": "{\"engagements\":[]}",
};

before(async () => {
  server = http.createServer((request, response) => {
    const url = new URL(request.url, "http://127.0.0.1");
    if (url.pathname.startsWith("/api/")) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(apiBodies[url.pathname] || "{}");
      return;
    }
    let relative = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
    if (relative.startsWith("static/")) relative = relative.slice("static/".length);
    const full = path.resolve(staticRoot, relative);
    if (!full.startsWith(staticRoot + path.sep) || !fs.existsSync(full)) {
      response.writeHead(404); response.end(); return;
    }
    const contentType = full.endsWith(".js") ? "text/javascript"
      : full.endsWith(".css") ? "text/css"
      : full.endsWith(".tsv") ? "text/tab-separated-values; charset=utf-8"
      : full.endsWith(".svg") ? "image/svg+xml"
      : "text/html; charset=utf-8";
    response.writeHead(200, { "content-type": contentType });
    fs.createReadStream(full).pipe(response);
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${server.address().port}/`;
  browser = await chromium.launch({ executablePath: chromiumPath, headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"] });
});

after(async () => {
  if (browser) await browser.close();
  if (server) await new Promise(resolve => server.close(resolve));
});

const locales = new Map([
  ["tr", "Tarama raporu"],
  ["en", "Scan report"],
  ["ja", "スキャンレポート"],
  ["zh-CN", "扫描报告"],
  ["ko", "스캔 보고서"],
]);
const viewports = [
  { name: "desktop", width: 1440, height: 1000 },
  { name: "mobile", width: 390, height: 844 },
];

async function layoutProblems(page) {
  return page.evaluate(() => {
    const problems = [];
    const width = document.documentElement.clientWidth;
    if (document.documentElement.scrollWidth > width + 1) {
      problems.push(`document:${document.documentElement.scrollWidth}>${width}`);
    }
    if (document.body.scrollWidth > width + 1) {
      problems.push(`body:${document.body.scrollWidth}>${width}`);
    }
    const roots = document.querySelectorAll([
      ".topbar", ".top-actions", ".lang-switch", ".view.active", ".hero-row",
      ".ui-quick-links", ".ui-quick-link", ".panel", ".panel-head", ".metric",
      ".sidebar.open", ".sidebar.open .nav-item", ".button", ".mini-button",
    ].join(","));
    for (const node of roots) {
      const style = getComputedStyle(node);
      const rect = node.getBoundingClientRect();
      if (style.display === "none" || style.visibility === "hidden" || rect.width === 0 || rect.height === 0) continue;
      if (rect.right > 0 && rect.left < width && (rect.left < -1 || rect.right > width + 1)) {
        problems.push(`${node.className || node.tagName}:outside:${rect.left.toFixed(1)}..${rect.right.toFixed(1)}`);
      }
      if (node.scrollWidth > node.clientWidth + 2 && !["auto", "scroll", "hidden"].includes(style.overflowX)) {
        problems.push(`${node.className || node.tagName}:x:${node.scrollWidth}>${node.clientWidth}`);
      }
      if (node.matches(".button,.mini-button,.nav-item,.ui-quick-link,.lang-switch")
          && node.scrollHeight > node.clientHeight + 2 && style.overflowY === "hidden") {
        problems.push(`${node.className || node.tagName}:y:${node.scrollHeight}>${node.clientHeight}`);
      }
    }
    if (problems.length) {
      problems.push(...Array.from(document.querySelector(".top-actions")?.children || []).map(node => {
        const rect = node.getBoundingClientRect();
        const style = getComputedStyle(node);
        return `top-child:${node.className || node.tagName}:${rect.width.toFixed(1)}:${style.minWidth}:${style.maxWidth}:${node.textContent.trim().slice(0, 80)}`;
      }));
    }
    return problems;
  });
}

for (const [locale, report] of locales) {
  for (const viewport of viewports) {
    test(`${locale} ${viewport.name}: translated controls fit without horizontal or clipped overflow`, async () => {
      const page = await browser.newPage({ viewport });
      try {
        await page.goto(origin, { waitUntil: "load" });
        await page.waitForFunction(() => typeof SniperI18n === "object");
        await page.evaluate(async selected => { await SniperI18n.setLang(selected); }, locale);
        assert.equal(await page.locator("html").getAttribute("lang"), locale);
        assert.equal(await page.evaluate(text => SniperI18n.t("Tarama raporu") === text, report), true);
        assert.equal(await page.locator('[data-i18n-lang-select]').first().inputValue(), locale);
        const closedProblems = await layoutProblems(page);
        let openProblems = [];
        if (viewport.name === "mobile") {
          await page.locator("#mobile-menu").click();
          assert.equal(await page.locator("#main-navigation").evaluate(node => node.classList.contains("open")), true);
          openProblems = await layoutProblems(page);
        }
        assert.deepEqual({ closedProblems, openProblems }, { closedProblems: [], openProblems: [] });
      } finally {
        await page.close();
      }
    });
  }
}
