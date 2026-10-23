import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { test, before, after } from "node:test";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright-core");
const project = process.env.APP_ROOT || path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const staticRoot = path.join(project, "static");
const browserPath = process.env.CHROMIUM_PATH || "/ms-playwright/chromium-1248/chrome-linux-arm64/chrome";
let server, browser, base;

before(async () => {
  server = http.createServer((request, response) => {
    const pathname = new URL(request.url, "http://localhost").pathname;
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
    const type = full.endsWith(".js") ? "text/javascript" : full.endsWith(".css") ? "text/css" : "text/html";
    response.writeHead(200, { "content-type": type });
    fs.createReadStream(full).pipe(response);
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${server.address().port}/`;
  browser = await chromium.launch({ executablePath: browserPath, headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"] });
});
after(async () => {
  if (browser) await browser.close();
  if (server) await new Promise(resolve => server.close(resolve));
});

async function page() {
  const instance = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  await instance.goto(base);
  await instance.waitForFunction(() => typeof showModal === "function");
  return instance;
}
async function activeId(instance) {
  return instance.evaluate(() => document.activeElement?.id || document.activeElement?.getAttribute("data-action") || document.activeElement?.getAttribute("data-close") || document.activeElement?.tagName);
}

test("target dialog traps forward and reverse Tab while normal form controls stay reachable", async () => {
  const p = await page();
  try {
    await p.locator('[data-action="add-target"]').first().click();
    await p.waitForTimeout(70);
    assert.equal(await p.locator("#target-modal").evaluate(node => node.contains(document.activeElement)), true);
    assert.equal(await activeId(p), "target-modal");
    await p.keyboard.press("Tab");
    assert.equal(await p.locator("#target-modal input[name=url]").evaluate(node => node === document.activeElement), true);
    await p.keyboard.press("Tab");
    assert.equal(await p.locator("#target-form button[type=submit]").evaluate(node => node === document.activeElement), true);
    await p.keyboard.press("Tab");
    assert.equal(await activeId(p), "target-modal");
    await p.keyboard.press("Shift+Tab");
    assert.equal(await p.locator("#target-form button[type=submit]").evaluate(node => node === document.activeElement), true);
  } finally { await p.close(); }
});

test("background keyboard focus and activation cannot escape an open dialog", async () => {
  const p = await page();
  try {
    await p.locator('[data-action="add-target"]').first().click();
    await p.waitForTimeout(70);
    await p.evaluate(() => document.querySelector('.nav-item[data-nav="tooling"]').focus());
    assert.equal(await p.locator("#target-modal").evaluate(node => node.contains(document.activeElement)), true);
    await p.evaluate(() => document.querySelector('.nav-item[data-nav="tooling"]').click());
    assert.equal(await p.locator('[data-view="tooling"]').evaluate(node => node.classList.contains("active")), false);
    assert.equal(await p.locator("#target-modal").evaluate(node => node.classList.contains("hidden")), false);
  } finally { await p.close(); }
});

test("Escape, close button and backdrop each restore the opener", async () => {
  const p = await page();
  try {
    const opener = p.locator('[data-action="add-target"]').first();
    await opener.click();
    await p.keyboard.press("Escape");
    assert.equal(await p.locator("#target-modal").evaluate(node => node.classList.contains("hidden")), true);
    assert.equal(await opener.evaluate(node => node === document.activeElement), true);
    await opener.click();
    await p.locator("#target-modal .modal-close").click();
    assert.equal(await opener.evaluate(node => node === document.activeElement), true);
    await opener.click();
    await p.mouse.click(8, 8);
    assert.equal(await p.locator("#target-modal").evaluate(node => node.classList.contains("hidden")), true);
    assert.equal(await opener.evaluate(node => node === document.activeElement), true);
  } finally { await p.close(); }
});

test("topmost overlay closes alone, restores inner focus and keeps scroll locked", async () => {
  const p = await page();
  try {
    const result = await p.evaluate(() => {
      const opener = document.querySelector('[data-action="add-target"]');
      opener.focus();
      showModal("pentest-workspace");
      const innerOpener = document.querySelector("#pentest-workspace .modal-close");
      innerOpener.focus();
      showModal("finding-modal");
      return document.activeElement.closest("#finding-modal") !== null;
    });
    assert.equal(result, true);
    await p.keyboard.press("Escape");
    assert.equal(await p.locator("#finding-modal").evaluate(node => node.classList.contains("hidden")), true);
    assert.equal(await p.locator("#pentest-workspace").evaluate(node => node.classList.contains("hidden")), false);
    assert.equal(await p.evaluate(() => document.activeElement?.closest("#pentest-workspace") !== null), true);
    assert.equal(await p.evaluate(() => document.body.style.overflow), "hidden");
    await p.keyboard.press("Escape");
    assert.equal(await p.locator("#pentest-workspace").evaluate(node => node.classList.contains("hidden")), true);
    assert.equal(await p.locator('[data-action="add-target"]').first().evaluate(node => node === document.activeElement), true);
    assert.equal(await p.evaluate(() => document.body.style.overflow), "");
  } finally { await p.close(); }
});

test("removed opener falls back to a visible page control", async () => {
  const p = await page();
  try {
    await p.locator('[data-action="add-target"]').first().click();
    await p.evaluate(() => document.querySelector('[data-action="add-target"]').remove());
    await p.keyboard.press("Escape");
    assert.equal(await p.evaluate(() => document.activeElement !== document.body && !document.activeElement.closest(".hidden")), true);
  } finally { await p.close(); }
});

test("closing a dialog never leaves a delayed focus steal; non-modal navigation stays usable", async () => {
  const p = await page();
  try {
    await p.locator('[data-action="add-target"]').first().click();
    await p.keyboard.press("Escape");
    const toolingNav = p.getByLabel("Ana menü").locator('.nav-item[data-nav="tooling"]');
    await toolingNav.focus();
    assert.equal(await toolingNav.evaluate(node => node === document.activeElement), true);
    await p.keyboard.press("Enter");
    assert.equal(await p.locator('[data-view="tooling"]').evaluate(node => node.classList.contains("active")), true);
    await p.evaluate(() => showModal("scan-modal"));
    await p.waitForTimeout(90);
    assert.equal(await p.locator("#scan-modal").evaluate(node => node.contains(document.activeElement)), true);
  } finally { await p.close(); }
});

test("dialog semantics, inert background and prior scroll state survive opening and closing", async () => {
  const p = await page();
  try {
    await p.evaluate(() => { document.body.style.overflow = "scroll"; });
    await p.locator('[data-action="add-target"]').first().click();
    assert.equal(await p.getByRole("dialog", { name: "Hedef ekleyin" }).count(), 1);
    assert.equal(await p.locator(".app-shell").evaluate(node => node.inert), true);
    assert.equal(await p.evaluate(() => document.body.style.overflow), "hidden");
    await p.keyboard.press("Escape");
    assert.equal(await p.locator(".app-shell").evaluate(node => node.inert), false);
    assert.equal(await p.evaluate(() => document.body.style.overflow), "scroll");
  } finally { await p.close(); }
});

test("SARIF close still clears inputs and result state", async () => {
  const p = await page();
  try {
    await p.evaluate(() => {
      document.querySelector("#sarif-paste").value = "sample";
      document.querySelector("#sarif-file").value = "";
      showModal("sarif-preview-modal");
      showModal("sarif-preview-modal", false);
    });
    assert.equal(await p.locator("#sarif-paste").inputValue(), "");
    assert.equal(await p.locator("#sarif-preview-result").evaluate(node => node.classList.contains("hidden")), true);
  } finally { await p.close(); }
});
