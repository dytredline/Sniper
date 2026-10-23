import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

// 25. tur: toplu depo taraması paneli (static/bulk_scan.js) — yalnız textContent, onay + confirm alanı, seçim ve seçenekler.
const source = fs.readFileSync(new URL('../static/bulk_scan.js', import.meta.url), 'utf8');

function node(tag) {
  return {
    tag, children: [], textContent: '', className: '', attrs: {}, listeners: {}, disabled: false, hidden: false,
    value: '', checked: false,
    append(...items) { this.children.push(...items); },
    after(item) { this.afterNode = item; },
    setAttribute(name, value) { this.attrs[name] = value; },
    addEventListener(name, fn) { this.listeners[name] = fn; },
    set innerHTML(_v) { throw new Error('innerHTML kullanılmamalı'); },
  };
}

function load({ responses = [], confirmAnswer = true } = {}) {
  const calls = [];
  const document = {
    createElement: (tag) => node(tag),
    createElementNS: (_namespace, tag) => node(tag),
  };  // addEventListener yok → otomatik bağlama atlanır
  const window = {
    confirm: () => confirmAnswer,
    fetch: async (path, options = {}) => {
      calls.push({ path, method: options.method || 'GET', body: options.body ? JSON.parse(options.body) : undefined });
      const next = responses.shift() || { status: 200, body: {} };
      return { ok: next.status < 400, status: next.status, json: async () => next.body };
    },
  };
  vm.runInNewContext(source, { window, globalThis: window, document, String, Number, Object, JSON, Error, Promise, Math, Set,
    encodeURIComponent, setTimeout: () => 0, clearTimeout: () => {} });
  return { win: window, calls };
}

function texts(root) {
  const out = [];
  const walk = (n) => { if (n.textContent) out.push(n.textContent); (n.children || []).forEach(walk); };
  walk(root);
  return out;
}

const FOUND = {
  root: '/home/community-user/projeler', truncated: ['count'], skipped: { symlink: 1, depth: 2 },
  candidates: [
    { name: 'alpha', rel: 'alpha', path: '/home/community-user/projeler/alpha', kind: 'git', selected: true, commit: 'abcdef0123456789',
      committed_at: '2026-10-20T10:00:00+03:00', remote: { name: 'acme/alpha', host: 'github.com' },
      languages: [{ name: 'Python', files: 3 }], file_count: 4, size_bytes: 2_500_000, unchanged: true, too_large: [] },
    { name: '<img src=x onerror=alert(1)>', rel: '<img src=x onerror=alert(1)>', path: '/home/community-user/projeler/x', kind: 'manifest',
      selected: false, languages: [], file_count: 1, size_bytes: 10, too_large: ['size'], image_count: 1 },
  ],
};

test('önizleme textContent ile çizilir; seçim ve uyarılar doğru', () => {
  const { win } = load();
  const panel = win.SniperBulkScan.buildPanel();
  assert.equal(panel.attrs.id, 'bulk-scan-launcher');
  const icon = panel.children[0].children[0];
  assert.equal(icon.textContent, '');
  assert.equal(icon.children[0]?.tag, 'svg');
  assert.equal(icon.children[0]?.children[0]?.attrs.href, '/static/ui-icons.svg#repositories');
  const ui = win.SniperBulkScan.state.ui;
  assert.equal(ui.start.disabled, true);
  win.SniperBulkScan.renderPreview(FOUND);
  assert.equal(ui.start.disabled, false);
  const all = texts(ui.list);
  assert.ok(all.includes('<img src=x onerror=alert(1)>'), 'ad metin olarak kalır');
  assert.ok(all.some(t => t.includes('github.com/acme/alpha') && t.includes('abcdef01 · 2026-10-20') && t.includes('2.5 MB')));
  assert.ok(all.includes('son taramadan beri commit değişmedi'));
  assert.ok(all.includes('boyut sınırını aşıyor'));
  assert.ok(ui.summary.textContent.includes('2 depo bulundu') && ui.summary.textContent.includes('sınıra ulaşıldı: count'));
  assert.deepEqual([...win.SniperBulkScan.selectedPaths()], ['/home/community-user/projeler/alpha']);
  win.SniperBulkScan.state.rows[1].box.checked = true;
  assert.equal(win.SniperBulkScan.selectedPaths().length, 2);
  assert.deepEqual({ ...win.SniperBulkScan.collectOptions() },
    { sca: true, container: false, skip_unchanged: true, changed_files: false, parallel: 1 });
});

test('keşif ve başlatma istekleri confirm: true taşır; ilerleme ve iptal düğmesi', async () => {
  const run = { id: 'blk_0123456789ab', status: 'running', progress: { detail: 'alpha' },
    totals: { total: 1, succeeded: 0 }, items: [{ name: 'alpha', rel: 'alpha', status: 'running' }] };
  const { win, calls } = load({ responses: [
    { status: 200, body: FOUND }, { status: 202, body: { bulk: run, job: { id: 'job_1' } } }, { status: 200, body: run },
  ] });
  win.SniperBulkScan.buildPanel();
  const ui = win.SniperBulkScan.state.ui;
  ui.root.value = ' /home/community-user/projeler ';
  const form = win.SniperBulkScan.state.ui.section.children.find(c => c.tag === 'form');
  await form.listeners.submit({ preventDefault() {} });
  assert.deepEqual(calls[0], { path: '/api/bulk-scans/discover', method: 'POST', body: { confirm: true, root: '/home/community-user/projeler', max_depth: 4 } });
  ui.group.value = 'ekip';
  ui.parallel.value = '3';
  await ui.start.listeners.click();
  assert.equal(calls[1].path, '/api/bulk-scans');
  assert.deepEqual(calls[1].body, { confirm: true, root: '/home/community-user/projeler', paths: ['/home/community-user/projeler/alpha'], group: 'ekip',
    options: { sca: true, container: false, skip_unchanged: true, changed_files: false, parallel: 3 } });
  await new Promise(resolve => setImmediate(resolve));
  assert.ok(ui.runStatus.textContent.includes('şu an: alpha'));
  assert.equal(ui.cancel.hidden, false);
  win.SniperBulkScan.renderRun({ ...run, status: 'succeeded', totals: { total: 1, succeeded: 1 },
    items: [{ name: 'alpha', rel: 'alpha', status: 'succeeded', finding_count: 3, severity_counts: { high: 2 }, sca: { status: 'succeeded', finding_count: 1 } }] });
  assert.equal(ui.cancel.hidden, true);
  assert.ok(texts(ui.runList).some(t => t.includes('3 bulgu (high 2)') && t.includes('SCA 1 açık')));
});

test('onay verilmezse tarama başlatılmaz; hata iletisi durum satırına yazılır', async () => {
  const { win, calls } = load({ confirmAnswer: false, responses: [{ status: 400, body: { error: 'Seçilen depo kök dizinin altında değil.' } }] });
  win.SniperBulkScan.buildPanel();
  win.SniperBulkScan.renderPreview(FOUND);
  const ui = win.SniperBulkScan.state.ui;
  await ui.start.listeners.click();
  assert.equal(calls.length, 0);
  win.confirm = () => true;
  await ui.start.listeners.click();
  assert.equal(ui.runStatus.textContent, 'Seçilen depo kök dizinin altında değil.');
});
