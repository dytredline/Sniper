import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/taint_rules.js', import.meta.url), 'utf8');

class Node {
  constructor(tag = 'div') { this.tag = tag; this.children = []; this.textContent = ''; this.value = ''; this.checked = false; this.className = ''; this.dataset = {}; this.listeners = {}; this.classes = new Set(); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  set innerHTML(_v) { throw new Error('innerHTML kullanılmamalı'); }
  get classList() { const c = this.classes; return { add: n => c.add(n), remove: n => c.delete(n), toggle: (n, on) => (on ? c.add(n) : c.delete(n)) }; }
}

function load(handler) {
  const ids = Object.fromEntries(['taint-rules-panel', 'taint-rules-body', 'taint-rules-state', 'taint-rules-empty', 'taint-rules-content',
    'taint-rules-code', 'taint-rules-filename', 'taint-rules-confirm', 'taint-rules-save', 'taint-rules-try', 'taint-rules-refresh',
    'taint-rules-message', 'taint-rules-trial'].map(id => [id, new Node()]));
  const calls = [];
  const document = { readyState: 'complete', getElementById: id => ids[id] || null, createElement: tag => new Node(tag), addEventListener() {} };
  const window = { api: async (path, options = {}) => { calls.push({ path, options }); return handler(path, options); } };
  vm.runInNewContext(source, { window, globalThis: window, document, String, Object, Array, JSON, Promise, Error, encodeURIComponent });
  return { ids, calls, api: window.SniperTaintRules };
}

const listing = { available: true, activation: 'Kurallar derlendi', rules: [{ name: '<b>kural</b>', language: 'python', sink_kinds: ['sql'], counts: { sinks: 1 }, stored_at: '2026-10-19' }] };

test('liste textContent ile çizilir ve sil düğmesi onay ister', async () => {
  const { ids, calls, api } = load(() => listing);
  await api.refresh();
  const row = ids['taint-rules-body'].children[0];
  assert.equal(row.children[0].textContent, '<b>kural</b>');
  assert.equal(row.children[2].textContent, 'sql');
  assert.equal(ids['taint-rules-state'].textContent, 'Kurallar derlendi');
  const before = calls.length;
  await row.children[5].children[0].listeners.click();
  assert.equal(calls.length, before);
  assert.match(ids['taint-rules-message'].textContent, /onay/);
  ids['taint-rules-confirm'].checked = true;
  await api.remove('<b>kural</b>');
  const del = calls.find(c => c.path.includes('/delete'));
  assert.equal(del.path, '/api/taint-rules/%3Cb%3Ekural%3C%2Fb%3E/delete');
  assert.deepEqual(JSON.parse(del.options.body), { confirm_custom_rules: true });
});

test('kaydetme onaysız yapılmaz, onaylıysa içerik gönderilir', async () => {
  const { ids, calls, api } = load((path, options) => (options.method === 'POST' ? { name: 'k', language: 'python' } : listing));
  ids['taint-rules-content'].value = 'format: sniper-taint-rules-v1';
  assert.equal(await api.save(), null);
  assert.equal(calls.filter(c => c.options.method === 'POST').length, 0);
  ids['taint-rules-confirm'].checked = true;
  await api.save();
  const post = calls.find(c => c.options.method === 'POST');
  assert.equal(post.path, '/api/taint-rules');
  assert.deepEqual(JSON.parse(post.options.body), { content: 'format: sniper-taint-rules-v1', confirm_custom_rules: true });
  assert.match(ids['taint-rules-message'].textContent, /kaydedildi/);
});

test('kuralı dene: yeni akışlar listelenir, hata gösterilir', async () => {
  let fail = false;
  const { ids, calls, api } = load(path => {
    if (path === '/api/taint-rules/try') {
      if (fail) throw new Error('Kural geçersiz');
      return { flows: [{}], new_flows: [{ source: 'request.args', source_line: 5, sink: '<script>', sink_kind: 'sql', sink_line: 7 }], removed_flows: [], note: '' };
    }
    return listing;
  });
  ids['taint-rules-code'].value = 'kod';
  ids['taint-rules-filename'].value = 'a.py';
  await api.tryRule();
  const post = calls.find(c => c.path === '/api/taint-rules/try');
  assert.deepEqual(JSON.parse(post.options.body), { content: '', code: 'kod', filename: 'a.py' });
  const trial = ids['taint-rules-trial'];
  assert.match(trial.children[0].textContent, /eklenen akış: 1/);
  assert.equal(trial.children.at(-1).children[0].textContent, 'request.args (satır 5) → <script> [sql] (satır 7)');
  fail = true;
  assert.equal(await api.tryRule(), null);
  assert.equal(ids['taint-rules-message'].className, 'error-message');
});
