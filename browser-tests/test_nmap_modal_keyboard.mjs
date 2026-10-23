import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { before, after, test } from "node:test";

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
      response.writeHead(503, {"content-type": "application/json"});
      response.end("{}");
      return;
    }
    if (pathname.startsWith("/api/")) {
      response.writeHead(200, {"content-type": "application/json"});
      response.end("{}");
      return;
    }
    const relative = pathname === "/" ? "index.html" : pathname.slice(1);
    const full = path.resolve(staticRoot, relative);
    if (!full.startsWith(staticRoot + path.sep) || !fs.existsSync(full)) {
      response.writeHead(404); response.end(); return;
    }
    const type = full.endsWith(".js") ? "text/javascript" : full.endsWith(".css") ? "text/css" : "text/html";
    response.writeHead(200, {"content-type": type});
    fs.createReadStream(full).pipe(response);
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  base = "http://127.0.0.1:" + server.address().port + "/";
  browser = await chromium.launch({
    executablePath: browserPath, headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
});

after(async () => {
  if (browser) await browser.close();
  if (server) await new Promise(resolve => server.close(resolve));
});

async function page() {
  const p = await browser.newPage();
  p.setDefaultTimeout(5000);
  await p.goto(base, {waitUntil: "load"});
  await p.waitForFunction(() => typeof navigate === "function");
  await p.evaluate(() => navigate("tooling"));
  return p;
}
const open = p => p.locator("[data-action=\"open-nmap-xml-preview\"]").first();
const launcher = p => p.locator("details.ui-tool-launcher").first();
async function revealLauncherWithKeyboard(p) {
  const details = launcher(p);
  if (!await details.evaluate(node => node.open)) {
    const summary = details.locator(":scope > summary");
    await summary.focus();
    await p.keyboard.press("Enter");
  }
  assert.equal(await details.evaluate(node => node.open), true);
  assert.equal(await open(p).isVisible(), true);
  return open(p);
}
const modal = p => p.locator("#nmap-xml-preview-modal");
const hidden = p => modal(p).evaluate(node => node.classList.contains("hidden"));
const focusedInside = p => modal(p).evaluate(node => node.contains(document.activeElement));

test("collapsed tool launcher exposes the passive Nmap action through keyboard disclosure", async () => {
  const p = await page();
  try {
    assert.equal(await launcher(p).evaluate(node => node.open), false);
    const opener = await revealLauncherWithKeyboard(p);
    assert.equal(await opener.isVisible(), true);
    assert.equal(await p.locator("details.ui-tool-launcher > summary").evaluate(node => node === document.activeElement), true);
  } finally { await p.close(); }
});

test("passive dialog opens and closes with no report POST or active scan", async () => {
  const p = await page();
  try {
    const beforePosts = posts.length;
    const opener = await revealLauncherWithKeyboard(p);
    await opener.click();
    assert.equal(await hidden(p), false);
    assert.equal(await modal(p).getAttribute("role"), "dialog");
    assert.equal(await modal(p).getAttribute("aria-modal"), "true");
    assert.equal(posts.length, beforePosts);
    await p.locator("[data-close=\"nmap-xml-preview-modal\"]").click();
    assert.equal(await hidden(p), true);
    assert.equal(posts.length, beforePosts);
  } finally { await p.close(); }
});

test("initial focus and forward/reverse Tab remain in passive Nmap dialog", async () => {
  const p = await page();
  try {
    const opener = await revealLauncherWithKeyboard(p);
    await opener.click();
    assert.equal(await p.locator("#nmap-xml-paste").evaluate(node => node === document.activeElement), true);
    await p.keyboard.press("Shift+Tab");
    assert.equal(await p.locator("[data-close=\"nmap-xml-preview-modal\"]").evaluate(node => node === document.activeElement), true);
    await p.keyboard.press("Shift+Tab");
    assert.equal(await p.locator("#nmap-xml-preview-submit").evaluate(node => node === document.activeElement), true);
    await p.keyboard.press("Tab");
    assert.equal(await p.locator("[data-close=\"nmap-xml-preview-modal\"]").evaluate(node => node === document.activeElement), true);
    assert.equal(await focusedInside(p), true);
  } finally { await p.close(); }
});

test("background focus and programmatic activation cannot open another dialog", async () => {
  const p = await page();
  try {
    const beforePosts = posts.length;
    const opener = await revealLauncherWithKeyboard(p);
    await opener.click();
    assert.equal(await p.locator(".app-shell").evaluate(node => node.inert), true);
    await p.evaluate(() => document.querySelector("[data-action=\"add-target\"]").focus());
    assert.equal(await focusedInside(p), true);
    await p.evaluate(() => document.querySelector("[data-action=\"add-target\"]").click());
    assert.equal(await p.locator("#target-modal").evaluate(node => node.classList.contains("hidden")), true);
    assert.equal(await hidden(p), false);
    assert.equal(posts.length, beforePosts);
    await p.keyboard.press("Escape");
    assert.equal(await p.locator(".app-shell").evaluate(node => node.inert), false);
  } finally { await p.close(); }
});

test("Escape, close and backdrop restore the opener and prior scroll state", async () => {
  const p = await page();
  try {
    await p.evaluate(() => {document.body.style.overflow = "scroll";});
    const opener = await revealLauncherWithKeyboard(p);
    await opener.click();
    assert.equal(await p.evaluate(() => document.body.style.overflow), "hidden");
    await p.keyboard.press("Escape");
    assert.equal(await hidden(p), true);
    assert.equal(await opener.evaluate(node => node === document.activeElement), true);
    assert.equal(await p.evaluate(() => document.body.style.overflow), "scroll");

    await opener.click();
    await p.locator("[data-close=\"nmap-xml-preview-modal\"]").click();
    assert.equal(await hidden(p), true);
    assert.equal(await opener.evaluate(node => node === document.activeElement), true);

    await opener.click();
    await modal(p).click({position: {x: 5, y: 5}});
    assert.equal(await hidden(p), true);
    assert.equal(await opener.evaluate(node => node === document.activeElement), true);
    assert.equal(await p.evaluate(() => document.body.style.overflow), "scroll");
  } finally { await p.close(); }
});

test("other visible modal prevents passive Nmap dialog from opening behind it", async () => {
  const p = await page();
  try {
    await revealLauncherWithKeyboard(p);
    await p.evaluate(() => showModal("target-modal", true));
    assert.equal(await p.locator("#target-modal").evaluate(node => node.classList.contains("hidden")), false);
    await p.evaluate(() => document.querySelector("[data-action=\"open-nmap-xml-preview\"]").click());
    assert.equal(await hidden(p), true);
    assert.equal(await p.locator("#target-modal").evaluate(node => node.classList.contains("hidden")), false);
    assert.equal(await p.evaluate(() => document.body.style.overflow), "hidden");
  } finally { await p.close(); }
});

test("removed opener restores focus to a visible fallback", async () => {
  const p = await page();
  try {
    const opener = await revealLauncherWithKeyboard(p);
    await opener.click();
    await p.evaluate(() => document.querySelector("[data-action=\"open-nmap-xml-preview\"]").remove());
    await p.keyboard.press("Escape");
    assert.equal(await hidden(p), true);
    assert.equal(await p.evaluate(() => document.activeElement !== document.body && !document.activeElement.closest(".hidden,[hidden]")), true);
  } finally { await p.close(); }
});

test("stacked Escape closes the top generic dialog before passive Nmap, preserving focus and scroll", async () => {
  const p = await page();
  try {
    const priorOverflow = await p.evaluate(() => document.body.style.overflow);
    const opener = await revealLauncherWithKeyboard(p);
    await opener.click();
    await p.evaluate(() => showModal("target-modal", true));
    assert.equal(await hidden(p), false);
    assert.equal(await p.locator("#target-modal").evaluate(node => node.classList.contains("hidden")), false);
    assert.equal(await p.locator("#target-modal").evaluate(node => node.contains(document.activeElement)), true);
    await p.keyboard.press("Escape");
    assert.equal(await p.locator("#target-modal").evaluate(node => node.classList.contains("hidden")), true);
    assert.equal(await hidden(p), false);
    assert.equal(await p.locator("#nmap-xml-preview-modal").evaluate(node => node.contains(document.activeElement)), true);
    assert.equal(await p.evaluate(() => document.body.style.overflow), "hidden");
    await p.keyboard.press("Escape");
    assert.equal(await hidden(p), true);
    assert.equal(await p.evaluate(() => document.body.style.overflow), priorOverflow);
    assert.equal(await open(p).evaluate(node => node === document.activeElement), true);
    assert.deepEqual(posts, []);
  } finally { await p.close(); }
});
