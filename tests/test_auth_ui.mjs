import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const authJs = readFileSync(new URL("../static/auth.js", import.meta.url), "utf8");
const loginHtml = readFileSync(new URL("../static/login.html", import.meta.url), "utf8");
const indexHtml = readFileSync(new URL("../static/index.html", import.meta.url), "utf8");

function load({ cookie = "", status = 200 } = {}) {
  const calls = [];
  const location = { href: "http://127.0.0.1:8787/", origin: "http://127.0.0.1:8787" };
  const window = {
    fetch: (input, init) => {
      calls.push({ input, init });
      return Promise.resolve({ status, ok: status < 400, json: async () => ({}) });
    },
  };
  const context = {
    window, location, URL, Headers, console, Promise, setTimeout,
    document: { cookie, readyState: "loading", addEventListener() {}, querySelector: () => null },
  };
  vm.createContext(context);
  vm.runInContext(authJs, context);
  return { fetch: window.fetch, calls, location };
}

test("aynı kökenli POST'a CSRF başlığı eklenir, GET'e eklenmez", async () => {
  const { fetch, calls } = load({ cookie: "x=1; sniper_csrf=belirtec123" });
  await fetch("/api/project-audits", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  await fetch("/api/dashboard");
  await fetch("https://baska.example/api/x", { method: "POST" });
  assert.equal(calls[0].init.headers.get("X-Sniper-CSRF"), "belirtec123");
  assert.equal(calls[0].init.headers.get("Content-Type"), "application/json");
  assert.equal(calls[1].init.headers, undefined);
  assert.equal(calls[2].init.headers, undefined);
});

test("giriş kapalıyken (çerez yok) istekler değişmez", async () => {
  const { fetch, calls } = load();
  await fetch("/api/scans", { method: "POST", body: "{}" });
  assert.equal(calls[0].init.headers, undefined);
});

test("API 401 giriş sayfasına yönlendirir; giriş ucunun kendi 401'i yönlendirmez", async () => {
  let env = load({ status: 401 });
  await env.fetch("/api/dashboard");
  assert.equal(env.location.href, "/login.html");
  env = load({ status: 401 });
  await env.fetch("/api/auth/login", { method: "POST" });
  assert.equal(env.location.href, "http://127.0.0.1:8787/");
});

test("sayfalar CSP ile uyumlu: satır içi betik/stil yok, auth.js ilk betik", () => {
  for (const page of [loginHtml]) {
    assert.ok(!/<script(?![^>]*\bsrc=)/.test(page), "satır içi betik");
    assert.ok(!/\sstyle=/.test(page), "satır içi stil");
  }
  assert.ok(!/innerHTML/.test(authJs), "auth.js innerHTML kullanmamalı");
  const scripts = [...indexHtml.matchAll(/<script[^>]*src="([^"?]+)/g)].map(m => m[1]);
  assert.equal(scripts[0], "/auth.js");
});
