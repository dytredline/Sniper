import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { test, before, after } from "node:test";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright-core");
const appRoot = process.env.APP_ROOT || path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const staticRoot = path.join(appRoot, "static");
const browserPath = process.env.CHROMIUM_PATH || "/ms-playwright/chromium-1248/chrome-linux-arm64/chrome";
const posts = [];
let server, browser, base;

before(async () => {
  server = http.createServer((request, response) => {
    const pathname = new URL(request.url, "http://localhost").pathname;
    if (request.method === "POST") {
      posts.push(pathname);
      response.writeHead(503, { "content-type": "application/json" });
      response.end("{}");
      return;
    }
    if (pathname.startsWith("/api/")) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end("{}");
      return;
    }
    const relative = pathname === "/" ? "index.html" : pathname.slice(1);
    const full = path.resolve(staticRoot, relative);
    if (!full.startsWith(staticRoot + path.sep) || !fs.existsSync(full)) {
      response.writeHead(404); response.end(); return;
    }
    response.writeHead(200, { "content-type": full.endsWith(".js") ? "text/javascript" : full.endsWith(".css") ? "text/css" : "text/html" });
    fs.createReadStream(full).pipe(response);
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  base = "http://127.0.0.1:" + server.address().port + "/";
  browser = await chromium.launch({ executablePath: browserPath, headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"] });
});
after(async () => {
  if (browser) await browser.close();
  if (server) await new Promise(resolve => server.close(resolve));
});

async function toolingPage() {
  const page = await browser.newPage();
  page.setDefaultTimeout(5000);
  await page.goto(base, { waitUntil: "load" });
  await page.waitForFunction(() => typeof navigate === "function" && typeof showModal === "function");
  await page.evaluate(() => navigate("tooling"));
  const launcher = page.locator("details.ui-tool-launcher").first();
  assert.equal(await launcher.evaluate(node => node.open), false);
  await launcher.locator(":scope > summary").focus();
  await page.keyboard.press("Enter");
  assert.equal(await launcher.evaluate(node => node.open), true);
  return page;
}
async function visible(page, selector) {
  return page.locator(selector).evaluate(node => !node.classList.contains("hidden"));
}
async function focusInside(page, selector) {
  return page.locator(selector).evaluate(node => node.contains(document.activeElement));
}

test("generic target modal alone closes on Escape and returns focus", async () => {
  const page = await toolingPage();
  try {
    const opener = page.locator('[data-action="add-target"]').first();
    await opener.click();
    assert.equal(await visible(page, "#target-modal"), true);
    assert.equal(await focusInside(page, "#target-modal"), true);
    await page.keyboard.press("Escape");
    assert.equal(await visible(page, "#target-modal"), false);
    assert.equal(await opener.evaluate(node => node === document.activeElement), true);
    assert.deepEqual(posts, []);
  } finally { await page.close(); }
});

test("one Escape closes only the top generic dialog above passive Nmap; focus and scroll remain valid", async () => {
  const page = await toolingPage();
  try {
    const opener = page.locator('[data-action="open-nmap-xml-preview"]').first();
    await opener.click();
    assert.equal(await visible(page, "#nmap-xml-preview-modal"), true);
    await page.evaluate(() => showModal("target-modal", true));
    assert.equal(await visible(page, "#target-modal"), true);
    assert.equal(await focusInside(page, "#target-modal"), true);
    await page.keyboard.press("Tab");
    assert.equal(await focusInside(page, "#target-modal"), true);
    await page.keyboard.press("Escape");
    assert.equal(await visible(page, "#target-modal"), false);
    assert.equal(await visible(page, "#nmap-xml-preview-modal"), true);
    assert.equal(await focusInside(page, "#nmap-xml-preview-modal"), true,
      JSON.stringify(await page.evaluate(() => ({ activeId: document.activeElement?.id,
        activeOuter: document.activeElement?.outerHTML?.slice(0, 200),
        nmapInert: document.getElementById("nmap-xml-preview-modal").inert,
        targetHidden: document.getElementById("target-modal").classList.contains("hidden") }))));
    assert.equal(await page.evaluate(() => document.body.style.overflow), "hidden");
    await page.keyboard.press("Escape");
    assert.equal(await visible(page, "#nmap-xml-preview-modal"), false);
    assert.equal(await opener.evaluate(node => node === document.activeElement), true);
    assert.deepEqual(posts, []);
  } finally { await page.close(); }
});

test("one Escape closes only the top generic dialog above Gitleaks, without starting a scan", async () => {
  const page = await toolingPage();
  try {
    const opener = page.locator('[data-action="open-gitleaks-filesystem"]').first();
    await opener.click();
    assert.equal(await visible(page, "#gitleaks-filesystem-modal"), true);
    await page.evaluate(() => showModal("target-modal", true));
    assert.equal(await visible(page, "#target-modal"), true);
    assert.equal(await focusInside(page, "#target-modal"), true);
    await page.keyboard.press("Escape");
    assert.equal(await visible(page, "#target-modal"), false);
    assert.equal(await visible(page, "#gitleaks-filesystem-modal"), true);
    assert.equal(await focusInside(page, "#gitleaks-filesystem-modal"), true,
      JSON.stringify(await page.evaluate(() => ({ activeId: document.activeElement?.id,
        activeOuter: document.activeElement?.outerHTML?.slice(0, 200),
        gitleaksInert: document.getElementById("gitleaks-filesystem-modal").inert,
        targetHidden: document.getElementById("target-modal").classList.contains("hidden") }))));
    await page.keyboard.press("Escape");
    assert.equal(await visible(page, "#gitleaks-filesystem-modal"), false);
    assert.equal(await opener.evaluate(node => node === document.activeElement), true);
    assert.deepEqual(posts, []);
  } finally { await page.close(); }
});

test("direct Gitleaks dialog keeps Tab and Shift+Tab inside, then Escape restores focus", async () => {
  const page = await toolingPage();
  try {
    const opener = page.locator('[data-action="open-gitleaks-filesystem"]').first();
    await opener.click();
    assert.equal(await visible(page, "#gitleaks-filesystem-modal"), true);
    assert.equal(await page.evaluate(() => document.activeElement?.id), "gitleaks-filesystem-path");
    await page.keyboard.press("Shift+Tab");
    assert.equal(await page.locator('[data-close="gitleaks-filesystem-modal"]').evaluate(node => node === document.activeElement), true);
    await page.keyboard.press("Shift+Tab");
    assert.equal(await page.evaluate(() => document.activeElement?.id), "gitleaks-filesystem-consent");
    await page.keyboard.press("Tab");
    assert.equal(await page.locator('[data-close="gitleaks-filesystem-modal"]').evaluate(node => node === document.activeElement), true);
    await page.keyboard.press("Escape");
    assert.equal(await visible(page, "#gitleaks-filesystem-modal"), false);
    assert.equal(await opener.evaluate(node => node === document.activeElement), true);
    assert.deepEqual(posts, []);
  } finally { await page.close(); }
});
