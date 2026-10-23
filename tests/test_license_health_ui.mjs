import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const licenseSource = fs.readFileSync(new URL('../static/license_report.js', import.meta.url), 'utf8');
const healthSource = fs.readFileSync(new URL('../static/system_health.js', import.meta.url), 'utf8');

function node(tag) {
  return {
    tag, children: [], textContent: '', className: '', dataset: {}, open: false, listeners: {},
    append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = [...items]; },
    insertBefore(item) { this.children.unshift(item); }, remove() {}, querySelector() { return null; },
    addEventListener(name, fn) { this.listeners[name] = fn; },
    set innerHTML(_v) { throw new Error('innerHTML kullanılmamalı'); },
  };
}

function texts(root) {
  const out = [];
  const walk = (n) => { if (n.textContent) out.push(n.textContent); (n.children || []).forEach(walk); };
  walk(root);
  return out;
}

test('lisans bölümü textContent ile çizilir; kötü amaçlı paket adı metin olarak kalır', () => {
  const document = { createElement: (tag) => node(tag) };
  const window = {};
  vm.runInNewContext(licenseSource, { window, globalThis: window, document, String, Number, Boolean, JSON, Object });
  const detail = node('div');
  const audit = { licenses: {
    component_count: 3, by_category: { allowed: 1, caution: 1, review: 1, denied: 0 },
    project_license: { expression: 'MIT', source: 'package.json' },
    by_license: [{ license: 'GPL-3.0-only', count: 1, category: 'caution' }],
    items: [{ ecosystem: 'npm', name: '<img src=x onerror=alert(1)>', version: '1.0.0', expression: 'GPL-3.0-only', category: 'caution', dev: false, source: 'package-lock.json' }],
    notes: ['Bu bir hukuki görüş değildir.'],
  } };
  window.renderLicenseSummary(audit, detail);
  const all = texts(detail);
  assert.ok(all.includes('<img src=x onerror=alert(1)>@1.0.0'));
  assert.ok(all.some((t) => t.startsWith('Proje lisansı: MIT')));
  assert.ok(all.includes('Dikkat'));
  assert.deepEqual([...window.SniperLicense.policyLines('MIT, Apache-2.0\nGPL-*\n\n')], ['MIT', 'Apache-2.0', 'GPL-*']);
  assert.equal(window.SniperLicense.summaryLine(audit.licenses), 'Yasak 0 · Dikkat 1 · İnceleme 1 · İzinli 1');
});

test('öz sağlık kartı yalnız GET ile okur ve satırları textContent ile yazar', async () => {
  const ids = { 'system-health-panel': node('section'), 'system-health-overall': node('p'), 'system-health-checks': node('tbody'), 'system-health-refresh': node('button') };
  const calls = [];
  const document = { readyState: 'complete', getElementById: (id) => ids[id] || null, createElement: (tag) => node(tag), addEventListener() {} };
  const report = { overall: 'warn', overall_label: 'Uyarı', counts: { fail: 0, warn: 1 }, checks: [
    { id: 'db_backup', label: 'Veritabanı yedeği', status: 'warn', status_label: 'Uyarı', value: 'yedek bulunamadı', detail: '', recommendation: 'Yedek alın.' },
  ] };
  const window = {
    async fetch(path, options = {}) {
      calls.push({ path, method: options.method || 'GET' });
      return { ok: true, status: 200, json: async () => report };
    },
  };
  vm.runInNewContext(healthSource, { window, globalThis: window, document, fetch: window.fetch, String, Number, Error });
  await new Promise((resolve) => setTimeout(resolve, 10));  // IntersectionObserver yok → hemen yüklenir
  assert.deepEqual(calls, [{ path: '/api/system/health-report', method: 'GET' }]);
  assert.equal(ids['system-health-overall'].textContent, 'Genel durum: Uyarı · 0 sorun · 1 uyarı');
  assert.equal(ids['system-health-checks'].children.length, 1);
  ids['system-health-refresh'].listeners.click();
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(calls[1].path, '/api/system/health-report?refresh=1');
});
