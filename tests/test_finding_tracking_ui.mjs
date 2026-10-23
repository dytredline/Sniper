import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/finding_tracking.js', import.meta.url), 'utf8');

function load() {
  const listeners = {};
  const calls = [];
  const document = {
    addEventListener: (name, fn) => { listeners[name] = fn; },
    querySelector: () => null,
  };
  const scope = {
    document, String, Object, Array, JSON, Promise, Error, Number, encodeURIComponent, FormData: class {},
    api: async (path, options) => { calls.push({ path, options }); return {}; },
  };
  scope.globalThis = scope;
  vm.runInNewContext(source, scope);
  return { scope, listeners, calls };
}

test('rozet durum, yeni bilgisi ve durum düğmesini kaçışlı üretir', () => {
  const { scope } = load();
  const html = scope.sniperTrackingBadge({ tracking: { id: 'trk_1"x', status: 'open', status_label: '<Açık>', is_new: true } });
  assert.match(html, /track-chip new/);
  assert.match(html, /&lt;Açık&gt;/);
  assert.match(html, /data-track-edit="trk_1&quot;x"/);
  assert.equal(scope.sniperTrackingBadge({}), '');
});

test('düzelmiş bulguda durum düğmesi yok, tekrar görülme sayısı gösterilir', () => {
  const { scope } = load();
  const html = scope.sniperTrackingBadge({ tracking: { id: 'trk_2', status: 'fixed', status_label: 'Düzeldi', is_new: false, seen_count: 3 } });
  assert.doesNotMatch(html, /data-track-edit/);
  assert.match(html, /3\. kez/);
});

test('belge düzeyinde tıklama, gönderme ve değişiklik dinleyicileri kurulur', () => {
  const { listeners } = load();
  assert.deepEqual(Object.keys(listeners).sort(), ['change', 'click', 'submit']);
});

// -- 16. tur: iş birliği (sorumlu, son tarih, yorumlar, bana atananlar) --------------------------
function fakeDocument() {
  const make = (tag) => {
    const el = {
      tagName: tag.toUpperCase(), children: [], attributes: {}, className: '', textContent: '', type: '',
      get firstChild() { return this.children[0] || null; },
      appendChild(child) { this.children.push(child); return child; },
      removeChild(child) { this.children.splice(this.children.indexOf(child), 1); return child; },
      setAttribute(name, value) { this.attributes[name] = String(value); },
    };
    Object.defineProperty(el, 'innerHTML', { set() { throw new Error('innerHTML kullanılmamalı'); } });
    return el;
  };
  return { createElement: make };
}

test('yorumlar yalnız textContent ile yazılır; silme düğmesi yetkiye göre', () => {
  const { scope } = load();
  const t = scope.sniperTrackingInternals;
  const doc = fakeDocument();
  const container = doc.createElement('div');
  container.ownerDocument = doc;
  const comments = [
    { id: 1, author_id: 'usr_a', author_name: 'ali', body: '<img src=x onerror=alert(1)>', created_at: '2026-10-20' },
    { id: 2, author_id: 'usr_b', author_name: 'veli', body: 'ikinci', created_at: '2026-10-21' },
  ];
  t.renderComments(container, comments, { authEnabled: true, me: { id: 'usr_a', role: 'analyst' } }, 'trk_1');
  assert.equal(container.children.length, 2);
  const [first, second] = container.children;
  assert.equal(first.children[1].textContent, '<img src=x onerror=alert(1)>');
  assert.equal(first.children[0].children.length, 1, 'kendi yorumunu silebilir');
  assert.equal(first.children[0].children[0].attributes['data-track-comment-delete'], '1');
  assert.equal(second.children[0].children.length, 0, 'başkasının yorumunu analist silemez');
  t.renderComments(container, comments, { authEnabled: true, me: { id: 'usr_c', role: 'admin' } }, 'trk_1');
  assert.ok(container.children.every((box) => box.children[0].children.length === 1), 'yönetici hepsini silebilir');
  t.renderComments(container, comments, { authEnabled: true, me: { id: 'usr_a', role: 'reader' } }, 'trk_1');
  assert.ok(container.children.every((box) => box.children[0].children.length === 0), 'okuyucu silemez');
  t.renderComments(container, [], { authEnabled: false }, 'trk_1');
  assert.equal(container.children[0].textContent, 'Henüz yorum yok.');
  t.renderComments(container, [{ id: 3, author_name: '', body: 'x' }], { authEnabled: false }, 'trk_1');
  assert.match(container.children[0].children[0].textContent, /^yerel kullanıcı/);
  assert.equal(container.children[0].children[0].children.length, 1, 'giriş kapalıyken tek yerel kullanıcı silebilir');
});

test('sorumlu hücresi, son tarih çipi ve rozet kaçışlı; gecikme gösterilir', () => {
  const { scope } = load();
  const t = scope.sniperTrackingInternals;
  const cell = t.ownerCell({ assignee_name: '<b>Ali</b>', due_date: '2026-10-01', overdue: true });
  assert.match(cell, /&lt;b&gt;Ali&lt;\/b&gt;/);
  assert.match(cell, /track-chip due overdue/);
  assert.match(cell, /gecikmiş/);
  assert.match(t.ownerCell({}), /atanmamış/);
  const html = scope.sniperTrackingBadge({ tracking: { id: 'trk_1', status: 'open', status_label: 'Açık', is_new: false, seen_count: 2, assignee_name: 'Veli"x', due_date: '2026-12-01', overdue: false } });
  assert.match(html, /track-chip owner/);
  assert.match(html, /Veli&quot;x/);
  assert.match(html, /son tarih 2026-12-01/);
  assert.doesNotMatch(html, /overdue/);
});

test('bana atananlar sorgusu giriş durumuna göre kurulur', () => {
  const { scope } = load();
  const t = scope.sniperTrackingInternals;
  assert.equal(t.assignedQuery({ assignee: '', status: 'active', severity: '', overdue: false }, { authEnabled: true }),
    '/api/finding-tracking/assigned?assignee=me&status=open,in_progress,reopened');
  assert.equal(t.assignedQuery({ assignee: 'Ali Kaya', status: 'all', severity: 'high', overdue: true }, { authEnabled: false }),
    '/api/finding-tracking/assigned?assignee=Ali%20Kaya&severity=high&overdue=1');
  assert.equal(t.assignedQuery({ assignee: '', status: 'all' }, { authEnabled: false }), '/api/finding-tracking/assigned?assignee=all');
});

test('birleşik bulgu görünümü kaynakları filtreler ve tüm dinamik alanları kaçışlar', () => {
  const { scope } = load();
  const t = scope.sniperTrackingInternals;
  assert.equal(t.unifiedQuery({ source: 'manual', status: 'active', severity: 'high' }),
    '/api/findings/unified?source=manual&status=open%2Cin_progress%2Creopened&severity=high&limit=500');
  const html = t.unifiedTableHtml([{
    id: 'manual:fnd_1', source: 'manual', severity: 'high', title: '<img src=x>', reference: 'CWE-1',
    status: 'open', native_status: 'open', location: { asset: '/<secret>' },
    scope: { name: '<denetim>' }, assignee: { name: '<ekip>' }, due_date: '2026-10-22', overdue: true,
    first_seen_at: '2026-10-21T00:00:00Z', updated_at: '2026-10-21T00:00:00Z', triage: null,
  }]);
  assert.match(html, /Elle/);
  assert.match(html, /&lt;img src=x&gt;/);
  assert.match(html, /&lt;secret&gt;/);
  assert.match(html, /&lt;denetim&gt;/);
  assert.match(html, /&lt;ekip&gt;/);
  assert.doesNotMatch(html, /<img src=x>/);
});

test('ayrıntı paneli: okuyucuya form yok; giriş açıkken kullanıcı seçimi, kapalıyken serbest metin', () => {
  const { scope } = load();
  const t = scope.sniperTrackingInternals;
  const item = { id: 'trk_9', assignee_id: 'usr_a', assignee_name: 'ali', due_date: '2026-10-01', overdue: true };
  const reader = t.detailHtml(item, { authEnabled: true, me: { id: 'usr_r', role: 'reader' }, users: [] });
  assert.doesNotMatch(reader, /data-track-assign|data-track-comment=|data-track-due=/);
  const analyst = t.detailHtml(item, { authEnabled: true, me: { id: 'usr_b', role: 'analyst' }, users: [{ id: 'usr_a', username: 'ali', role_label: 'analist' }, { id: 'usr_<x>', username: '<x>', role_label: 'okuyucu' }] });
  assert.match(analyst, /<select name="assignee_id">/);
  assert.match(analyst, /value="usr_a" selected/);
  assert.match(analyst, /&lt;x&gt;/);
  assert.match(analyst, /maxlength="4000"/);
  assert.match(analyst, /data-track-due-clear="trk_9"/);
  const local = t.detailHtml({ id: 'trk_9', assignee_name: 'Ali"' }, { authEnabled: false, names: ['Ali"'] });
  assert.match(local, /name="assignee_name"[^>]*value="Ali&quot;"/);
  assert.match(local, /<datalist/);
  assert.doesNotMatch(local, /data-track-due-clear/);
});
