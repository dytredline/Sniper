import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/joern_deep.js', import.meta.url), 'utf8');

class Node {
  constructor() { this.children = []; this.textContent = ''; this.value = ''; this.checked = false; this.disabled = true; this.dataset = {}; this.listeners = {}; this.classes = new Set(); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren() { this.children = []; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  set innerHTML(_v) { throw new Error('innerHTML kullanılmamalı'); }
  get classList() { const c = this.classes; return { add: n => c.add(n), remove: n => c.delete(n) }; }
}

function load(jobResult, extraIds = []) {
  const ids = Object.fromEntries(['joern-deep-form', 'joern-deep-path', 'joern-deep-confirm', 'joern-deep-status',
    'joern-deep-error', 'joern-deep-summary', 'joern-deep-body', 'joern-deep-sarif', ...extraIds].map(id => [id, new Node()]));
  const calls = [];
  const document = { readyState: 'complete', getElementById: id => ids[id] || null, createElement: () => new Node() };
  const window = {
    SniperJobs: {
      run: async (route, payload) => { calls.push({ route, payload }); return jobResult; },
      stateLabel: s => s,
    },
  };
  vm.runInNewContext(source, { window, globalThis: window, document, String, Number, Object, Array, JSON, Promise, Error, setTimeout });
  return { ids, calls, api: window.SniperJoernDeep };
}

test('onay ve yol olmadan iş başlatılmaz', async () => {
  const { ids, calls, api } = load({ state: 'succeeded', result: {} });
  assert.equal(await api.submit(), null);
  assert.match(ids['joern-deep-error'].textContent, /Proje klasörü/);
  ids['joern-deep-path'].value = '/home/community-user/proj';
  assert.equal(await api.submit(), null);
  assert.match(ids['joern-deep-error'].textContent, /onay/);
  assert.equal(calls.length, 0);
});

test('iş kuyruğundan sonuç tabloya textContent ile yazılır ve SARIF etkinleşir', async () => {
  const result = {
    finding_count: 1, duration_seconds: 12.5, languages: { c: 3 }, engine: { version: '4.0.647' },
    findings: [{ severity: 'critical', title: '<b>Komut</b>', file: 'a.c', line: 9, evidence: 'Veri akışı' }],
    sarif: { version: '2.1.0' },
  };
  const { ids, calls, api } = load({ state: 'succeeded', result });
  ids['joern-deep-path'].value = ' /home/community-user/proj ';
  ids['joern-deep-confirm'].checked = true;
  const plain = value => JSON.parse(JSON.stringify(value));
  assert.deepEqual(plain(await api.submit()), result);
  assert.deepEqual(plain(calls[0]), { route: '/api/tool-runs/joern-deep', payload: { confirm_local: true, project_path: '/home/community-user/proj' } });
  const row = ids['joern-deep-body'].children[0];
  assert.equal(row.children[0].textContent, 'KRİTİK');
  assert.equal(row.children[1].textContent, '<b>Komut</b>');
  assert.equal(row.children[2].textContent, 'a.c:9');
  assert.match(ids['joern-deep-summary'].textContent, /c: 3 dosya/);
  assert.equal(ids['joern-deep-sarif'].disabled, false);
});

test('başarısız iş hata olarak gösterilir', async () => {
  const { ids, api } = load({ state: 'failed', error: 'Joern kurulu değil.' });
  ids['joern-deep-path'].value = '/home/community-user/p';
  ids['joern-deep-confirm'].checked = true;
  assert.equal(await api.submit(), null);
  assert.equal(ids['joern-deep-error'].textContent, 'Joern kurulu değil.');
});

test('JS/TS-Python seçeneği ve süre bütçesi isteğe eklenir; kısmi sonuç uyarısı gösterilir', async () => {
  const result = {
    finding_count: 2, duration_seconds: 300, languages: { python: 4 }, engine: { version: '4.0.647' }, partial: true,
    warnings: ['Süre bütçesi Python analizi sırasında bitti; bulunan akışlar gösteriliyor (kısmi sonuç).'],
    scripting_fast_engine: { available: true, matched: 1, confirmed_uncertain: 0, conflicting: 0, joern_only: 1 },
    findings: [
      { severity: 'critical', title: 'Komut', file: 'app.py', line: 8, evidence: 'Akış A', fast_engine_match: true },
      { severity: 'high', title: 'SSRF', file: 'app.py', line: 20, evidence: 'Akış B', joern_only: true },
    ],
  };
  const extra = ['joern-deep-scripting', 'joern-deep-budget', 'joern-deep-warnings'];
  const { ids, calls, api } = load({ state: 'succeeded', result }, extra);
  ids['joern-deep-path'].value = '/home/community-user/p';
  ids['joern-deep-confirm'].checked = true;
  ids['joern-deep-scripting'].checked = true;
  ids['joern-deep-budget'].value = '5';
  await api.submit();
  assert.deepEqual(JSON.parse(JSON.stringify(calls[0].payload)),
    { confirm_local: true, project_path: '/home/community-user/p', include_scripting: true, time_budget_seconds: 300 });
  assert.match(ids['joern-deep-summary'].textContent, /KISMİ SONUÇ/);
  assert.match(ids['joern-deep-summary'].textContent, /yalnız Joern 1/);
  assert.match(ids['joern-deep-warnings'].textContent, /kısmi sonuç/);
  assert.equal(ids['joern-deep-warnings'].classes.has('hidden'), false);
  const rows = ids['joern-deep-body'].children;
  assert.match(rows[0].children[3].textContent, /Proje analizinde de doğrulandı/);
  assert.match(rows[1].children[3].textContent, /\[Yalnız Joern\]/);
});

test('geçersiz süre bütçesi iş başlatmaz', async () => {
  const { ids, calls, api } = load({ state: 'succeeded', result: {} }, ['joern-deep-budget']);
  ids['joern-deep-path'].value = '/home/community-user/p';
  ids['joern-deep-confirm'].checked = true;
  ids['joern-deep-budget'].value = '90';
  assert.equal(await api.submit(), null);
  assert.match(ids['joern-deep-error'].textContent, /1–60 dakika/);
  assert.equal(calls.length, 0);
});
