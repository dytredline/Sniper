import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/autofix.js', import.meta.url), 'utf8');

class Node {
  constructor(tag = 'div') { this.tag = tag; this.children = []; this.textContent = ''; this.className = ''; this.dataset = {}; this.disabled = false; this.classes = new Set(['hidden']); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  set innerHTML(_v) { throw new Error('innerHTML kullanılmamalı'); }
  get classList() { const c = this.classes; return { add: n => c.add(n), remove: n => c.delete(n), contains: n => c.has(n) }; }
}

function load(apiImpl) {
  const result = new Node();
  const article = { querySelector: sel => (sel === '[data-autofix-result="2"]' ? result : null) };
  const button = new Node('button');
  button.dataset = { autofixAudit: 'prj_1', autofixIndex: '2' };
  button.closest = () => article;
  const calls = [];
  const listeners = {};
  const document = { createElement: tag => new Node(tag), addEventListener: (n, fn) => { listeners[n] = fn; } };
  const window = { api: async (path, options) => { calls.push({ path, options }); return apiImpl(path); } };
  vm.runInNewContext(source, { window, globalThis: window, document, String, Object, Array, JSON, Promise, Error });
  return { window, button, result, calls, listeners };
}

const flat = node => [node.textContent, ...node.children.flatMap(flat)].join('');

test('öneri isteği gönderilir ve fark textContent ile satır sınıflarıyla çizilir', async () => {
  const diff = "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n-os.system('<img src=x>' + q)\n+subprocess.run(['ls', q])";
  const { window, button, result, calls } = load(() => ({ mode: 'diff', diff, confidence: 'orta', notes: ['<b>not</b>'], strategy: { title: 'Kabuksuz', cwe: 'CWE-78', explanation: 'Açıklama' } }));
  const data = await window.SniperAutofix.suggest(button);
  assert.equal(data.mode, 'diff');
  assert.equal(calls[0].path, '/api/project-audits/prj_1/findings/2/autofix');
  assert.equal(calls[0].options.method, 'POST');
  assert.equal(calls[0].options.body, '{}');
  assert.equal(button.disabled, false);
  assert.equal(result.classList.contains('hidden'), false);
  const pre = result.children.find(n => n.tag === 'pre');
  const classes = pre.children.map(n => n.className);
  assert.deepEqual(classes, ['', '', 'diff-hunk', 'diff-del', 'diff-add']);
  assert.match(flat(result), /<img src=x>/);
  assert.match(flat(result), /<b>not<\/b>/);
  assert.match(flat(result), /dosya değiştirilmedi/);
});

test('metin kipinde örnek gösterilir, hata mesajı textContent ile yazılır', async () => {
  let fail = false;
  const { window, button, result } = load(() => { if (fail) throw new Error('Bulgu bulunamadı.'); return { mode: 'text', snippet: 'html.escape(x)', strategy: {} }; });
  await window.SniperAutofix.suggest(button);
  assert.equal(result.children.at(-1).textContent, 'html.escape(x)');
  fail = true;
  assert.equal(await window.SniperAutofix.suggest(button), null);
  assert.match(result.children[0].textContent, /Öneri üretilemedi: Bulgu bulunamadı/);
  assert.equal(button.disabled, false);
});

test('geçersiz sıra numarasıyla istek yapılmaz; tıklama olay devri çalışır', async () => {
  const { window, button, calls, listeners } = load(() => ({ mode: 'text', snippet: 'x', strategy: {} }));
  button.dataset.autofixIndex = '1;x';
  assert.equal(await window.SniperAutofix.suggest(button), null);
  assert.equal(calls.length, 0);
  button.dataset.autofixIndex = '2';
  let prevented = false;
  listeners.click({ target: { closest: () => button }, preventDefault: () => { prevented = true; } });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(prevented, true);
  assert.equal(calls.length, 1);
});
