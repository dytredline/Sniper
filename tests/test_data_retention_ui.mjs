import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/data_retention.js', import.meta.url), 'utf8');

function node(tag) {
  return {
    tag, children: [], textContent: '', className: '', dataset: {}, listeners: {}, disabled: false, attrs: {},
    append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = [...items]; },
    addEventListener(name, fn) { this.listeners[name] = fn; }, setAttribute(k, v) { this.attrs[k] = v; },
    insertAdjacentElement(_where, item) { this.after = item; },
    set innerHTML(_v) { throw new Error('innerHTML kullanılmamalı'); },
  };
}

function texts(root) {
  const out = [];
  const walk = (n) => { if (n.textContent) out.push(n.textContent); (n.children || []).forEach(walk); };
  walk(root);
  return out;
}

const backups = {
  db_backups: [{ name: '<img src=x>.bak', kind: 'sniper', label: 'claude-r9', named: true, created_at: '2026-10-20T10:00:00Z',
    bytes: 1048576, world_readable: true, mode: '0o644' }],
  summary: { count: 1, bytes: 1048576, named: 1 }, update_backups: [],
  restore_commands: { db: 'python3 update.py --restore-db <yedek-adı>', update: 'python3 update.py --rollback <id> --with-db' },
};
const policy = { enabled: false, auto_daily: false, backups: { keep_last: 10, keep_daily: 7, keep_weekly: 4, include_named: false },
  project_audits: { enabled: false, older_than_days: 365, keep_per_project: 20 }, notifications: { enabled: true, read_older_than_days: 90 },
  jobs: { enabled: true, older_than_days: 30 }, temp: { enabled: true, older_than_days: 7 } };
const retention = { policy, plan: { plan_id: 'abc', enabled: false, total: { count: 2, bytes: 10 },
  summary: { backups: { label: 'Veritabanı yedekleri', count: 2, bytes: 10 } } } };

test('kart sistem sağlığı panelinin ardına eklenir, yalnız GET ile yüklenir ve textContent kullanır', async () => {
  const anchor = node('section');
  const calls = [];
  const document = { readyState: 'complete', getElementById: (id) => (id === 'system-health-panel' ? anchor : null),
    createElement: (tag) => node(tag), addEventListener() {} };
  const window = {
    async fetch(path, options = {}) {
      calls.push({ path, method: options.method || 'GET', body: options.body });
      const body = path === '/api/system/backups' ? backups : retention;
      return { ok: true, status: 200, json: async () => body };
    },
  };
  vm.runInNewContext(source, { window, globalThis: window, document, fetch: window.fetch, String, Number, Boolean, JSON, Error });
  await new Promise((resolve) => setTimeout(resolve, 10));
  const section = anchor.after;
  assert.ok(section, 'kart eklenmeli');
  assert.equal(section.id, 'data-retention-panel');
  assert.deepEqual(calls.map((c) => `${c.method} ${c.path}`), ['GET /api/system/backups', 'GET /api/system/retention']);
  const all = texts(section);
  assert.ok(all.includes('<img src=x>.bak'), 'dosya adı metin olarak kalır');
  assert.ok(all.some((t) => t.includes('başkalarınca okunabilir')));
  assert.ok(all.some((t) => t.includes('Politika kapalı')));
  const run = section.children.at(-1).children[0];
  assert.equal(run.disabled, true, 'politika kapalıyken yürütme kapalı');
});

test('politika formu okunur ve yürütme önizlenen plan_id ile onaylı gönderilir', async () => {
  const anchor = node('section');
  const calls = [];
  const enabled = { ...retention, policy: { ...policy, enabled: true }, plan: { ...retention.plan, enabled: true } };
  const document = { readyState: 'complete', getElementById: (id) => (id === 'system-health-panel' ? anchor : null),
    createElement: (tag) => node(tag), addEventListener() {} };
  const window = {
    confirm: () => true,
    async fetch(path, options = {}) {
      calls.push({ path, method: options.method || 'GET', body: options.body ? JSON.parse(options.body) : null });
      if (path === '/api/system/backups') return { ok: true, status: 200, json: async () => backups };
      if (path === '/api/system/retention/run') return { ok: true, status: 200, json: async () => ({ ...enabled, executed: true, freed_bytes: 10 }) };
      return { ok: true, status: 200, json: async () => enabled };
    },
  };
  vm.runInNewContext(source, { window, globalThis: window, document, fetch: window.fetch, String, Number, Boolean, JSON, Error });
  await new Promise((resolve) => setTimeout(resolve, 10));
  const section = anchor.after;
  const run = section.children.at(-1).children[0];
  assert.equal(run.disabled, false);
  await run.listeners.click();
  const post = calls.find((c) => c.path === '/api/system/retention/run');
  assert.deepEqual(post.body, { confirm: true, plan_id: 'abc' });
  const form = { elements: { enabled: { checked: true }, 'backups.keep_last': { value: '5' }, 'temp.enabled': { checked: false } } };
  const read = window.SniperDataRetention.readPolicy(form);
  assert.equal(read.enabled, true);
  assert.equal(read.backups.keep_last, 5);
  assert.equal(read.temp.enabled, false);
  assert.equal(read.jobs.older_than_days, 30, 'formda olmayan alan korunur');
});
