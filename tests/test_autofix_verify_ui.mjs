import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/autofix.js', import.meta.url), 'utf8');

class Node {
  constructor(tag = 'div') { this.tag = tag; this.children = []; this.textContent = ''; this.className = ''; this.dataset = {}; this.disabled = false; this.classes = new Set(['hidden']); this.listeners = {}; this.parentElement = null; }
  append(...nodes) { for (const n of nodes) { if (n && typeof n === 'object') n.parentElement = this; } this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  set innerHTML(_v) { throw new Error('innerHTML kullanılmamalı'); }
  get classList() { const c = this.classes; return { add: n => c.add(n), remove: n => c.delete(n), contains: n => c.has(n) }; }
}

const flat = node => [node.textContent, ...node.children.flatMap(flat)].join('');
const find = (node, pred) => pred(node) ? node : node.children.map(c => find(c, pred)).find(Boolean) || null;

function load(apiImpl) {
  const calls = [];
  const document = { createElement: tag => new Node(tag), addEventListener: () => {}, body: new Node('body') };
  const window = { api: async (path, options) => { calls.push({ path, options }); return apiImpl(path, options); } };
  vm.runInNewContext(source, { window, globalThis: window, document, String, Object, Array, JSON, Promise, Error, Number });
  return { window, calls };
}

const VERIFIED = {
  verdict: 'verified', duration_ms: 12, reasons: ['Hedef bulgu(lar) kapandı <b>x</b>'],
  targets: [{ index: 2, file: 'app.py', line: 10, title: 'SQL', applied: true, closed: true }],
  new_findings: [], new_notes: [{ title: 'Not', file: 'app.py', line: 1, severity: 'low' }], also_closed: [],
  diff: '--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-a\n+b', patch_filename: 'sniper-fix-prj_1-2.patch',
};

test('doğrulama isteği gönderilir, rozet ve gerekçeler textContent ile çizilir', async () => {
  const { window, calls } = load(() => VERIFIED);
  const result = new Node();
  const badge = new Node('span');
  const article = { querySelector: sel => (sel === '[data-autofix-result="2"]' ? result : sel === '[data-autofix-badge="2"]' ? badge : null) };
  const button = new Node('button');
  button.dataset = { autofixVerifyAudit: 'prj_1', autofixVerify: '2' };
  button.closest = () => article;
  const data = await window.SniperAutofix.verify(button);
  assert.equal(data.verdict, 'verified');
  assert.equal(calls[0].path, '/api/project-audits/prj_1/findings/2/autofix/verify');
  assert.equal(calls[0].options.method, 'POST');
  assert.equal(calls[0].options.body, '{}');
  assert.equal(badge.className, 'autofix-badge verified');
  assert.equal(badge.textContent, 'Doğrulandı');
  assert.match(flat(result), /<b>x<\/b>/);
  assert.match(flat(result), /proje dosyalarına yazılmadı/);
  assert.ok(find(result, n => n.tag === 'button' && n.textContent === '.patch indir'));
  assert.equal(button.disabled, false);
});

test('başarısız doğrulamada hata mesajı gösterilir', async () => {
  const { window } = load(() => { throw new Error('Bulgu bulunamadı.'); });
  const result = new Node();
  const button = new Node('button');
  button.dataset = { autofixVerifyAudit: 'prj_1', autofixVerify: '3' };
  button.closest = () => ({ querySelector: sel => (sel === '[data-autofix-result="3"]' ? result : null) });
  assert.equal(await window.SniperAutofix.verify(button), null);
  assert.match(flat(result), /Doğrulama yapılamadı: Bulgu bulunamadı/);
});

test('gruplar listelenir ve toplu düzeltme grup anahtarıyla istenir', async () => {
  const { window, calls } = load((path) => path.endsWith('/autofix-groups')
    ? { groups: [{ key: 'sql|CWE-89|execute', kind: 'sql', reference: 'CWE-89', api: 'execute', strategy: 'Parametreli sorgu', count: 2, files: ['a.py', 'b.py'] }] }
    : { ...VERIFIED, verdict: 'partial', targets: [VERIFIED.targets[0], { index: 5, file: 'b.py', line: 4, title: 'SQL', applied: false, closed: false, reason: 'üretilemedi' }] });
  const container = new Node();
  container.dataset = { autofixGroupsResult: 'prj_1' };
  const holder = new Node();
  holder.querySelector = sel => (sel === '[data-autofix-groups-result]' ? container : null);
  const button = new Node('button');
  button.dataset = { autofixGroups: 'prj_1' };
  button.parentElement = holder;
  await window.SniperAutofix.groups(button);
  assert.equal(calls[0].path, '/api/project-audits/prj_1/autofix-groups');
  assert.equal(calls[0].options, undefined);
  assert.match(flat(container), /Parametreli sorgu · CWE-89 · execute/);
  const action = find(container, n => n.tag === 'button' && n.textContent === 'Toplu düzelt ve doğrula');
  await action.listeners.click();
  assert.equal(calls[1].path, '/api/project-audits/prj_1/autofix/bulk');
  assert.equal(calls[1].options.body, JSON.stringify({ group: 'sql|CWE-89|execute' }));
  const badge = find(container, n => n.className === 'autofix-badge partial');
  assert.equal(badge.textContent, 'Kısmen');
  assert.match(flat(container), /üretilemedi/);
});
