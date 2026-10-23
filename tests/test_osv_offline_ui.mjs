import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/osv_offline.js', import.meta.url), 'utf8');

function node(tag) {
  return {
    tag, children: [], textContent: '', className: '', value: '', attrs: {}, listeners: {}, dataset: {},
    append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = [...items]; },
    setAttribute(name, value) { this.attrs[name] = value; }, addEventListener(name, fn) { this.listeners[name] = fn; },
    after() {}, querySelector() { return null; },
    set innerHTML(_v) { throw new Error('innerHTML kullanılmamalı'); },
  };
}

function load() {
  const document = { createElement: (tag) => node(tag) };  // readyState/addEventListener yok → otomatik bağlama atlanır
  const window = {};
  vm.runInNewContext(source, { window, globalThis: window, document, String, Number, Object, JSON, Error, Promise, Array, Date });
  return window.SniperOsvOffline;
}

function texts(root) {
  const out = [];
  const walk = (n) => { if (n.textContent) out.push(n.textContent); (n.children || []).forEach(walk); };
  walk(root);
  return out;
}

test('veritabanı durumu tabloya textContent ile yazılır; kötü amaçlı ekosistem adı metin kalır', () => {
  const ui = load();
  const container = node('div');
  ui.renderStatus(container, { databases: [
    { ecosystem: '<img src=x onerror=alert(1)>', status: 'ok', retrieved_utc: '2026-10-20T21:00:00Z', bytes: 36557817, records: 26420 },
    { ecosystem: 'Go', status: 'missing' },
    { ecosystem: 'npm', status: 'untrusted' },
  ] });
  const all = texts(container);
  assert.ok(all.includes('<img src=x onerror=alert(1)>'));
  assert.ok(all.includes('Güncel'));
  assert.ok(all.includes('Yok'));
  assert.ok(all.includes('Doğrulanamadı'));
  assert.ok(all.includes('34.9 MB'));
});

test('kapsam özeti ve boyut biçimi', () => {
  const ui = load();
  assert.equal(ui.coverageText({ coverage: [
    { ecosystem: 'PyPI', components: 34, vulnerabilities: 151, status: 'ok' },
    { ecosystem: 'crates.io', components: 2, status: 'unavailable' },
  ] }), 'PyPI: 34 bileşen, 151 açık · crates.io: veritabanı yok');
  assert.equal(ui.sizeText(0), '—');
  assert.equal(ui.sizeText(2048), '2 KB');
});

test('öncelik listesi textContent ile, katman etiketleri ve kanıt konumuyla yazılır (20. tur)', () => {
  const ui = load();
  const box = node('div');
  ui.renderPriority(box, {
    tiers: { fix_first: 1, plan: 1, monitor: 0 },
    order: [
      { package_name: '<b>lodash</b>', installed_version: '4.17.4', vulnerability_id: 'GHSA-x', score: 79, tier: 'fix_first',
        usage: 'used', fixed_version: '4.17.21', evidence: [{ file: 'app.js', line: 3 }] },
      { package_name: 'ms', installed_version: '0.7.1', vulnerability_id: 'GHSA-y', score: 22, tier: 'plan', usage: 'transitive_only' },
    ],
  });
  const all = texts(box);
  assert.ok(all.includes('Önce bunları düzelt'));
  assert.ok(all.includes('Önce düzelt'));
  assert.ok(all.some(t => t.includes('<b>lodash</b>@4.17.4')));
  assert.ok(all.some(t => t.includes('yalnız geçişli')));
  assert.ok(all.some(t => t.includes('app.js:3')));
  const empty = node('div');
  ui.renderPriority(empty, { order: [] });
  assert.equal(empty.children.length, 0);
});
