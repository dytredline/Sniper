// 17. tur W3-UI: açılış ön yüklemesi (boot_prefetch.js) ve paketlenebilirlik (tek IIFE) sözleşmesi.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/boot_prefetch.js', import.meta.url), 'utf8');

function load({ boot = { format: 1, responses: { '/api/targets': { status: 200, body: { targets: [1] } }, '/api/dashboard': { status: 403 } } }, bootOk = true } = {}) {
  const calls = [];
  let clock = 0;
  const network = async (input, init) => {
    const url = typeof input === 'string' ? input : input.url;
    calls.push({ url, method: (init && init.method) || 'GET' });
    if (url === '/api/bootstrap') {
      if (!bootOk) throw new Error('ağ');
      return new Response(JSON.stringify(boot), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return new Response(JSON.stringify({ from: 'network', url }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  const window = { fetch: network };
  const scope = {
    window, location: { href: 'http://127.0.0.1:8787/', origin: 'http://127.0.0.1:8787' }, URL, Response, Set, Map, String,
    JSON, Promise, Error, setTimeout, clearTimeout, AbortController, performance: { now: () => clock },
  };
  vm.runInNewContext(source, scope);
  return { fetch: window.fetch, calls, tick: (ms) => { clock += ms; } };
}

test('paketteki yol ağdan istenmez; izin verilmeyen yol ve paket dışı yol ağdan istenir', async () => {
  const { fetch, calls } = load();
  const targets = await (await fetch('/api/targets')).json();
  assert.deepEqual(targets, { targets: [1] });
  const dashboard = await (await fetch('/api/dashboard')).json();
  assert.equal(dashboard.from, 'network', '403 alt yanıt ağdan yeniden denenir');
  await fetch('/api/tooling/readiness');
  assert.deepEqual(calls.map(c => c.url), ['/api/bootstrap', '/api/dashboard', '/api/tooling/readiness']);
});

test('açılışta yinelenen GET birleştirilir; her tüketici ayrı klon alır', async () => {
  const { fetch, calls } = load();
  const [a, b] = await Promise.all([fetch('/api/tooling/readiness'), fetch('/api/tooling/readiness')]);
  assert.equal((await a.json()).from, 'network');
  assert.equal((await b.json()).from, 'network');
  assert.equal(calls.filter(c => c.url === '/api/tooling/readiness').length, 1);
});

test('durum değiştiren istek ve süre dolması ön yüklemeyi kapatır', async () => {
  let env = load();
  await env.fetch('/api/targets');
  await env.fetch('/api/targets', { method: 'POST', body: '{}' });
  const after = await (await env.fetch('/api/targets')).json();
  assert.equal(after.from, 'network');
  env = load();
  await env.fetch('/api/targets');
  env.tick(5000);
  assert.equal((await (await env.fetch('/api/targets')).json()).from, 'network');
});

test('paket alınamazsa her şey ağdan', async () => {
  const { fetch, calls } = load({ bootOk: false });
  assert.equal((await (await fetch('/api/targets')).json()).from, 'network');
  assert.ok(calls.some(c => c.url === '/api/targets'));
});

test('paketlenen klasik betiklerin hepsi (app.js hariç) tek IIFE: try ile sarmak anlamı değiştirmez', () => {
  const require = createRequire(import.meta.url);
  const parser = require('../vendor/babel-parser');
  const html = fs.readFileSync(new URL('../static/index.html', import.meta.url), 'utf8');
  const scripts = [...html.matchAll(/<script src="\/(?:static\/)?([A-Za-z0-9_.-]+\.js)(?:\?v=[^"]*)?" defer><\/script>/g)].map(m => m[1]);
  assert.ok(scripts.length > 40);
  for (const name of scripts) {
    if (name === 'app.js') continue;
    const code = fs.readFileSync(new URL(`../static/${name}`, import.meta.url), 'utf8');
    const ast = parser.parse(code, { sourceType: 'script' });
    const body = ast.program.body;
    assert.equal(body.length, 1, `${name}: üst düzeyde tek deyim olmalı`);
    const expr = body[0].expression;
    const call = expr && (expr.type === 'CallExpression' ? expr : expr.argument);
    assert.ok(call && /FunctionExpression|ArrowFunctionExpression/.test(call.callee.type), `${name}: IIFE olmalı`);
  }
});
