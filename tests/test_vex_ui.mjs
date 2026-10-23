import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/vex.js', import.meta.url), 'utf8');

function node(tag) {
  return {
    tag, children: [], textContent: '', className: '', hidden: false, value: '', attrs: {}, listeners: {},
    append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = [...items]; },
    setAttribute(name, value) { this.attrs[name] = value; }, addEventListener(name, fn) { this.listeners[name] = fn; },
    after() {}, remove() {},
    set innerHTML(_v) { throw new Error('innerHTML kullanılmamalı'); },
  };
}

function load() {
  const document = { createElement: (tag) => node(tag) };  // addEventListener yok → otomatik bağlama atlanır
  const window = {};
  vm.runInNewContext(source, { window, globalThis: window, document, String, Number, Object, JSON, Error, Promise });
  return window.SniperVex;
}

function texts(root) {
  const out = [];
  const walk = (n) => { if (n.textContent) out.push(n.textContent); (n.children || []).forEach(walk); };
  walk(root);
  return out;
}

const RESULT = {
  summary: { total: 2, statuses: { not_affected: 1, affected: 1, fixed: 0, under_investigation: 0 } },
  statements: [
    { finding_id: 'depfnd_1', vulnerability_id: 'GHSA-1', package: '<img src=x onerror=alert(1)>', version: '1.0.0',
      status: 'affected', justification: '', basis: 'auto', impact_statement: '', action_statement: 'Yükseltin.', status_notes: '' },
    { finding_id: 'depfnd_2', vulnerability_id: 'CVE-1', package: 'qs', version: '6.0.0', status: 'not_affected',
      justification: 'component_not_present', basis: 'auto', impact_statement: 'Kilitte yok.', action_statement: '', status_notes: '' },
  ],
};

test('VEX sonucu textContent ile çizilir; kötü amaçlı paket adı metin kalır', () => {
  const vex = load();
  const container = node('div');
  vex.renderResult(container, RESULT, () => {});
  const all = texts(container);
  assert.ok(all.includes('<img src=x onerror=alert(1)>@1.0.0'));
  assert.ok(all.includes('2 ifade · Etkilenmiyor 1 · Etkileniyor 1 · Düzeltildi 0 · İnceleniyor 0'));
  assert.ok(all.includes(' · Bileşen üründe yok'));
  assert.ok(all.includes('Karar ver'));
});

test('karar formu: gerekçe ve etki yalnız Etkilenmiyor, eylem yalnız Etkileniyor için görünür', () => {
  const vex = load();
  const form = vex.decisionForm({ ...RESULT.statements[0], basis: 'analyst', action_statement: 'Yükselt' }, () => {});
  const [status, justification, impact, action] = form.children;
  status.value = 'affected';
  status.listeners.change();
  assert.equal(justification.hidden, true);
  assert.equal(impact.hidden, true);
  assert.equal(action.hidden, false);
  status.value = 'not_affected';
  status.listeners.change();
  assert.equal(justification.hidden, false);
  assert.equal(impact.hidden, false);
  assert.equal(action.hidden, true);
  assert.ok(texts(form).includes('Kararı kaldır'));  // analist kararı kaldırılabilir
  const auto = vex.decisionForm(RESULT.statements[1], () => {});
  assert.ok(!texts(auto).includes('Kararı kaldır'));  // otomatik kararda kaldırma yok
});
