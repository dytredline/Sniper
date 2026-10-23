import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/system_version.js', import.meta.url), 'utf8');

function node(tag) {
  return {
    tag, children: [], textContent: '', className: '', classList: { hidden: null, toggle(name, on) { this.hidden = on; } },
    append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = [...items]; },
    set innerHTML(_v) { throw new Error('innerHTML kullanılmamalı'); },
  };
}

function load(response) {
  const ids = {
    'system-version-facts': node('dl'), 'system-version-command': node('pre'),
    'system-version-backups': node('tbody'), 'system-version-backups-empty': node('div'),
  };
  const calls = [];
  const document = {
    readyState: 'complete', getElementById: (id) => ids[id] || null, createElement: (tag) => node(tag),
    addEventListener() {},
  };
  const window = {
    async fetch(path, options = {}) {
      calls.push({ path, method: options.method || 'GET' });
      return { ok: response.status < 400, status: response.status, json: async () => response.body };
    },
  };
  vm.runInNewContext(source, { window, globalThis: window, document, fetch: window.fetch, Intl, Date, Number, Math, String, Error });
  return { ids, calls, api: window.SniperSystemVersion };
}

const PAYLOAD = {
  product_version: '2.0.1', engine_id: 'abc123', packaged: true, restart_pending: true, installed_version: '2.2.0',
  release: { version: '2.1.0', signature: 'verified', installed_at: '2026-10-20T10:00:00Z' },
  last_update: { at: '2026-10-20T11:00:00Z', action: 'auto_rollback', status: 'rolled_back' },
  backups: [{ id: '20261020T110000-2.1.0', created_at: '2026-10-20T11:00:00Z', version: '2.1.0', reason: 'güncelleme öncesi (2.2.0)', has_db: true, bytes: 3145728 }],
  maintenance_note: 'Review the next Community source archive before replacement.',
};

test('sürüm kartı yalnız GET ile okur ve textContent ile gösterir', async () => {
  const { ids, calls, api } = load({ status: 200, body: PAYLOAD });
  await api.load();
  assert.deepEqual(calls.map((c) => c.method), ['GET', 'GET']);  // açılışta ve elle load() — ikisi de salt okunur
  assert.ok(calls.every((c) => c.path === '/api/system/version'));
  const texts = ids['system-version-facts'].children.map((c) => c.textContent);
  assert.ok(texts.includes('2.1.0'));
  assert.ok(texts.includes('Bekleyen sürüm'));
  assert.ok(texts.includes('2.2.0 (servis yeniden başlatılınca)'));
  assert.ok(texts.includes('Ed25519 imzası doğrulandı'));
  assert.ok(texts.some((t) => t.includes('Otomatik geri dönüş') && t.includes('Geri dönüldü')));
  assert.match(ids['system-version-command'].textContent, /Review the next Community source archive/);
  const row = ids['system-version-backups'].children[0].children.map((c) => c.textContent);
  assert.deepEqual([row[0], row[2], row[4], row[5]], ['20261020T110000-2.1.0', '2.1.0', 'Var', '3.0 MB']);
  assert.equal(ids['system-version-backups-empty'].classList.hidden, true);
});

test('paketsiz kurulum ve hata durumu', async () => {
  const facts = load({ status: 200, body: {} }).api.facts({ product_version: '2.0.1', engine_id: 'e' });
  assert.equal(facts[0][1], '2.0.1 (paketsiz kurulum)');
  const { ids, api } = load({ status: 401, body: {} });
  await api.load();
  assert.match(ids['system-version-facts'].children[1].textContent, /Sürüm bilgisi alınamadı \(401\)/);
});
