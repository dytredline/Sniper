import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

// 25. tur: AI/ajan triyaj paneli. Ajan metni (gerekçe, düzeltme önerisi) yalnız textContent ile yazılmalı.
const source = fs.readFileSync(new URL('../static/ai_triage.js', import.meta.url), 'utf8');
const trackingSource = fs.readFileSync(new URL('../static/finding_tracking.js', import.meta.url), 'utf8');

function makeElement(tag) {
  const el = {
    tagName: tag.toUpperCase(), children: [], className: '', type: '', dataset: {}, staticHtml: '',
    _text: '',
    get textContent() { return this._text + this.children.map(c => c.textContent).join(''); },
    set textContent(value) { this._text = String(value); this.children = []; },
    appendChild(child) { this.children.push(child); return child; },
    append(...items) { items.forEach(item => this.children.push(item)); },
    querySelector(selector) {
      if (selector === 'tbody') { if (!this.tbody) this.tbody = makeElement('tbody'); return this.tbody; }
      return this.found?.[selector] || null;
    },
  };
  // Yalnız tablo iskeleti (sabit metin) innerHTML ile kurulabilir; ajan verisi asla.
  Object.defineProperty(el, 'innerHTML', { set(value) { if (/ajan|<script|onerror/i.test(value)) throw new Error('ajan metni innerHTML ile yazıldı'); el.staticHtml = value; } });
  return el;
}

function load(extra = {}) {
  const listeners = {};
  const document = {
    addEventListener: (name, fn) => { listeners[name] = fn; },
    querySelector: () => null,
    createElement: makeElement,
  };
  const scope = { document, String, Object, Array, JSON, Promise, Error, Number, Boolean, encodeURIComponent, setTimeout, FormData: class {}, Element: class {}, ...extra };
  scope.globalThis = scope;
  vm.runInNewContext(source, scope);
  return { scope, listeners };
}

test('AI rozeti öneri olduğunu belirtir ve kaçışlıdır', () => {
  const { scope } = load();
  const html = scope.sniperAiChip({ verdict: 'likely_false', confidence: 0.912, decision: 'pending', agent: '<b>ajan</b>' });
  assert.match(html, /AI: Muhtemelen yanlış alarm 0\.91/);
  assert.match(html, /öneridir; analist kararı değildir/);
  assert.match(html, /&lt;b&gt;ajan&lt;\/b&gt;/);
  assert.doesNotMatch(html, /<b>ajan/);
  assert.equal(scope.sniperAiChip(null), '');
  assert.equal(scope.sniperAiChip({ verdict: '<img>' }), '');
  assert.match(scope.sniperAiChip({ verdict: 'likely_true', confidence: 1, decision: 'auto_applied', agent: 'x' }), /Otomatik uygulandı/);
});

test('öneri listesi ajan metnini textContent ile yazar; roller düğmeleri belirler', () => {
  const { scope } = load();
  const internals = scope.sniperAiTriageInternals;
  const list = makeElement('div');
  const root = { querySelector: sel => (sel === '#ai-suggestion-list' ? list : null) };
  internals.state.suggestions = [
    { id: 'ais_1', tracked_id: 'trk_1', verdict: 'likely_false', confidence: 0.9, decision: 'pending', agent: 'claude-code', model: 'm',
      finding_title: '<img src=x onerror=alert(1)>', rationale: '<script>alert(1)</script> ajan gerekçesi', fix_suggestion: 'parametre bağla' },
    { id: 'ais_2', tracked_id: 'trk_1', verdict: 'uncertain', confidence: 0.2, decision: 'pending', agent: 'codex', rationale: 'emin değilim' },
    { id: 'ais_3', tracked_id: 'trk_1', verdict: 'likely_false', confidence: 0.95, decision: 'auto_applied', agent: 'x', rationale: 'r' },
  ];
  internals.state.role = { admin: false, analyst: true };
  internals.renderList(root);
  const table = list.children[0];
  assert.equal(table.tagName, 'TABLE');
  const rows = table.tbody.children;
  assert.equal(rows.length, 3);
  assert.match(rows[0].textContent, /<script>alert\(1\)<\/script> ajan gerekçesi/);  // düz metin
  assert.match(rows[0].textContent, /Düzeltme önerisi: parametre bağla/);
  const buttons = row => row.children[3].children.filter(c => c.tagName === 'BUTTON').map(b => b.dataset.aiDecision);
  assert.deepEqual(buttons(rows[0]), ['accept', 'reject']);
  assert.deepEqual(buttons(rows[1]), ['reject']);  // belirsiz kabul edilemez
  assert.deepEqual(buttons(rows[2]), ['revert']);
  internals.state.role = { admin: false, analyst: false };  // okuyucu: düğme yok
  internals.renderList(root);
  assert.deepEqual(buttons(list.children[0].tbody.children[0]), []);
  internals.state.suggestions = [];
  internals.renderList(root);
  assert.match(list.textContent, /Karar bekleyen öneri yok/);
});

test('ayar kartı: izin varsayılan kapalı, yönetici düğmeleri yalnız yöneticiye, gizlilik uyarısı', () => {
  const { scope } = load();
  const internals = scope.sniperAiTriageInternals;
  internals.state.settings = { policy: { auto_apply: { enabled: false, min_confidence: 0.9 } }, local: { enabled: false, endpoint: 'http://127.0.0.1:8080/v1"><x', model: '' }, project_external_allowed: false };
  internals.state.role = { admin: true, analyst: true };
  let html = internals.cardHtml();
  assert.match(html, /data-ai-consent="on"/);
  assert.match(html, /model sağlayıcısına gönderilir/);
  assert.match(html, /id="ai-local-form"/);
  assert.match(html, /8080\/v1&quot;&gt;&lt;x/);
  assert.doesNotMatch(html, /data-ai-batch/);  // yerel model kapalı
  internals.state.role = { admin: false, analyst: true };
  html = internals.cardHtml();
  assert.doesNotMatch(html, /data-ai-consent|data-ai-auto|ai-local-form/);
  assert.deepEqual(JSON.parse(JSON.stringify(internals.roleFrom({ enabled: true, user: { role: 'reader' } }))), { admin: false, analyst: false });
  assert.deepEqual(JSON.parse(JSON.stringify(internals.roleFrom({ enabled: false }))), { admin: true, analyst: true });
});

test('bulgu takibi satırı AI rozetini ve yerel model açıksa AI düğmesini gösterir', () => {
  const { scope } = load();
  scope.sniperAiLocalEnabled = true;
  vm.runInNewContext(trackingSource, scope);
  const row = scope.sniperTrackingInternals.rowHtml({ id: 'trk_9', severity: 'high', status: 'open', status_label: 'Açık', title: 't', file: 'a.py', line: 3, reference: 'CWE-89',
    ai: { verdict: 'likely_true', confidence: 0.8, decision: 'pending', agent: 'codex' } }, false);
  assert.match(row, /ai-chip ai-likely_true/);
  assert.match(row, /data-ai-run="trk_9"/);
  scope.sniperAiLocalEnabled = false;
  const plain = scope.sniperTrackingInternals.rowHtml({ id: 'trk_8', severity: 'low', status: 'fixed', status_label: 'Düzeldi', title: 't', file: 'a.py', line: 1, reference: '' }, false);
  assert.doesNotMatch(plain, /data-ai-run|ai-chip/);
});

test('karar düğmesi doğru uca onaylı istek gönderir', async () => {
  const calls = [];
  const { listeners } = load({ api: async (path, options) => { calls.push({ path, options }); return { suggestions: [], policy: { auto_apply: {} }, local: {} }; } });
  class FakeElement {}
  const button = Object.assign(new FakeElement(), { dataset: { aiDecision: 'accept', aiTracked: 'trk_1', aiId: 'ais_1' } });
  button.closest = sel => (sel === '[data-ai-decision]' ? button : null);
  // instanceof Element denetimi için sahte sınıf kapsamda değiştirilir
  const scopeLoad = load({ Element: FakeElement, api: async (path, options) => { calls.push({ path, options }); return { suggestions: [], policy: { auto_apply: {} }, local: {} }; } });
  scopeLoad.listeners.click({ target: button });
  await new Promise(resolve => setTimeout(resolve, 10));
  const post = calls.find(c => c.options && c.options.method === 'POST');
  assert.equal(post.path, '/api/finding-tracking/trk_1/ai/ais_1/decision');
  assert.deepEqual(JSON.parse(post.options.body), { confirm: true, decision: 'accept' });
  assert.ok(listeners.click && listeners.submit && listeners.change);
});

test('26. tur: ajan başına eşik satırları (yönetici formu, okuyucu tablosu) ve per_agent gövdesi', () => {
  const { scope } = load();
  const internals = scope.sniperAiTriageInternals;
  internals.state.settings = { policy: { auto_apply: { enabled: true, min_confidence: 0.9, require_consensus: true,
    per_agent: { claude: { enabled: true, min_confidence: 0.9 }, codex: { enabled: false, min_confidence: 0.99 }, 'x"><b': { enabled: true, min_confidence: 0.8 } } } }, local: {} };
  internals.state.role = { admin: true, analyst: true };
  let html = internals.cardHtml();
  assert.match(html, /id="ai-agent-form"/);
  assert.match(html, /data-agent="codex" min="0.5" max="1" step="0.01" value="0.99"/);
  assert.match(html, /<option value="on" selected>Her zaman uzlaşı<\/option>/);
  assert.match(html, /name="consensus_min_confidence" type="number" min="0.5" max="1" step="0.01" value="0.70"/);
  assert.match(html, /x&quot;&gt;&lt;b/);
  assert.doesNotMatch(html, /x"><b/);
  internals.state.role = { admin: false, analyst: true };
  html = internals.cardHtml();
  assert.doesNotMatch(html, /ai-agent-form/);
  assert.match(html, /<td><code>codex<\/code><\/td><td>Kapalı<\/td><td>0.99<\/td>/);
  assert.match(html, /Uzlaşı modu:<\/b> Her zaman uzlaşı/);
  internals.state.settings.policy.auto_apply.require_consensus = 'auto';
  internals.state.settings.policy.auto_apply.consensus_min_confidence = 0.75;
  html = internals.cardHtml();
  assert.match(html, /Uzlaşı modu:<\/b> Otomatik \(en az iki ajan varsa\)/);
  assert.match(html, /Uzlaşı eşiği:<\/b> 0.75/);
  const inputs = { 'agent-conf': [{ dataset: { agent: 'claude' }, value: '0.93' }, { dataset: { agent: 'codex' }, value: '0.99' }],
    'agent-enabled': [{ dataset: { agent: 'claude' }, checked: true }, { dataset: { agent: 'codex' }, checked: false }] };
  const form = {
    querySelectorAll: sel => inputs[sel.match(/name=([\w-]+)/)[1]] || [],
    querySelector: sel => ({ '[name=new-agent]': { value: ' Gemini ' }, '[name=new-agent-conf]': { value: '0.95' }, '[name=require_consensus]': form.mode, '[name=consensus_min_confidence]': { value: '0.8' } })[sel],
    mode: { value: 'off' },
  };
  assert.deepEqual(JSON.parse(JSON.stringify(internals.agentPayload(form))), { enabled: true, require_consensus: false, consensus_min_confidence: 0.8,
    per_agent: { claude: { enabled: true, min_confidence: 0.93 }, codex: { enabled: false, min_confidence: 0.99 }, gemini: { enabled: true, min_confidence: 0.95 } } });
  for (const [value, expected] of [['auto', 'auto'], ['on', true]]) {
    form.mode = { value };
    assert.equal(internals.agentPayload(form).require_consensus, expected);
  }
});
