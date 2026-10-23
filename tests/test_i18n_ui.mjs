import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import { test } from 'node:test';

const require = createRequire(import.meta.url);
const STATIC = new URL('../static/', import.meta.url);
const source = fs.readFileSync(new URL('i18n.js', STATIC), 'utf8');
const dictionaryText = fs.readFileSync(new URL('i18n-en.tsv', STATIC), 'utf8');

// --- Asgari DOM (jsdom yok): metin/öğe düğümleri, öznitelikler, closest, TreeWalker, MutationObserver kaydı ---
class FakeText {
  constructor(value) { this.nodeType = 3; this.nodeValue = value; this.parentNode = null; }
  get parentElement() { return this.parentNode && this.parentNode.nodeType === 1 ? this.parentNode : null; }
  get textContent() { return this.nodeValue; }
}
let currentDocument = null;
let dictionary = null;
class FakeElement {
  get ownerDocument() { return currentDocument; }
  constructor(tag, attrs = {}) {
    this.nodeType = 1; this.tagName = tag.toUpperCase(); this.attrs = new Map(Object.entries(attrs));
    this.childNodes = []; this.parentNode = null; this.listeners = {};
  }
  get parentElement() { return this.parentNode && this.parentNode.nodeType === 1 ? this.parentNode : null; }
  append(...nodes) { for (const n of nodes) { const node = typeof n === 'string' ? new FakeText(n) : n; node.parentNode = this; this.childNodes.push(node); } return this; }
  getAttribute(name) { return this.attrs.has(name) ? this.attrs.get(name) : null; }
  setAttribute(name, value) { this.attrs.set(name, String(value)); }
  hasAttribute(name) { return this.attrs.has(name); }
  matches(selector) {
    return selector.split(',').some((part) => {
      const s = part.trim();
      const attr = /^\[([\w-]+)(?:='([^']*)')?\]$/.exec(s);
      if (attr) return this.attrs.has(attr[1]) && (attr[2] === undefined || this.attrs.get(attr[1]) === attr[2]);
      return this.tagName === s.toUpperCase();
    });
  }
  closest(selector) { let el = this; while (el && el.nodeType === 1) { if (el.matches(selector)) return el; el = el.parentNode; } return null; }
  get textContent() { return this.childNodes.map((n) => n.textContent).join(''); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  querySelectorAll(selector) { const out = []; walk(this, (n) => { if (n.nodeType === 1 && n.matches(selector)) out.push(n); }); return out; }
}
function walk(root, fn) { for (const child of root.childNodes) { fn(child); if (child.nodeType === 1) walk(child, fn); } }
function makeDocument() {
  const html = new FakeElement('html', { lang: 'tr' });
  const doc = {
    nodeType: 9, readyState: 'complete', documentElement: html,
    createTreeWalker(root) { const list = []; walk(root, (n) => list.push(n)); let i = 0; return { nextNode: () => list[i++] || null }; },
    querySelectorAll: (s) => html.querySelectorAll(s),
    addEventListener() {},
  };
  currentDocument = doc;
  return doc;
}

function load({ storage, lang } = {}) {
  const document = makeDocument();
  const observers = [];
  class MutationObserver { constructor(cb) { this.cb = cb; observers.push(this); } observe() { this.active = true; } disconnect() { this.active = false; } }
  const dialogs = [];
  const window = {
    document, MutationObserver, console,
    localStorage: storage === 'throws'
      ? { getItem() { throw new Error('engelli'); }, setItem() { throw new Error('engelli'); } }
      : { data: new Map(lang ? [['sniper.lang', lang]] : []), getItem(k) { return this.data.get(k) ?? null; }, setItem(k, v) { this.data.set(k, v); } },
    fetch: async () => ({ ok: true, text: async () => dictionaryText }),
    confirm: (m) => { dialogs.push(m); return true; },
    alert: (m) => { dialogs.push(m); },
  };
  vm.runInNewContext(source, { window, setTimeout });
  dictionary = window.SniperI18n.parseDictionary(dictionaryText);
  const notify = (records) => observers.filter((o) => o.active).forEach((o) => o.cb(records));
  return { window, document, i18n: window.SniperI18n, notify, dialogs };
}

test('varsayılan dil Türkçe; sözlük yüklenmeden hiçbir metin değişmez', () => {
  const { document, i18n } = load();
  const button = new FakeElement('button').append('Taramayı başlat');
  document.documentElement.append(button);
  assert.equal(i18n.lang, 'tr');
  assert.equal(i18n.t('Taramayı başlat'), 'Taramayı başlat');
  assert.equal(button.textContent, 'Taramayı başlat');
});

test('İngilizceye geçiş metin düğümlerini, öznitelikleri ve <html lang> değerini çevirir; geri dönüş özgün metni yazar', async () => {
  const { document, i18n } = load();
  const root = document.documentElement;
  const label = new FakeElement('label').append('  Proje klasörü\n  ');
  const input = new FakeElement('input', { placeholder: 'Alan adı ara…', title: 'Kapat', type: 'text' });
  const submit = new FakeElement('input', { type: 'submit', value: 'Kaydet' });
  root.append(label, input, submit);
  await i18n.setLang('en');
  assert.equal(root.getAttribute('lang'), 'en');
  assert.equal(label.childNodes[0].nodeValue, '  Project folder\n  ', 'baştaki/sondaki boşluk korunur');
  assert.equal(input.getAttribute('placeholder'), 'Search domain…');
  assert.equal(input.getAttribute('title'), 'Close');
  assert.equal(submit.getAttribute('value'), 'Save');
  await i18n.setLang('tr');
  assert.equal(root.getAttribute('lang'), 'tr');
  assert.equal(label.childNodes[0].nodeValue, '  Proje klasörü\n  ');
  assert.equal(input.getAttribute('placeholder'), 'Alan adı ara…');
  assert.equal(submit.getAttribute('value'), 'Kaydet');
});

test('kod, pre, textarea içeriği ve translate="no" alanları çevrilmez; textarea placeholder çevrilir', async () => {
  const { document, i18n } = load();
  const code = new FakeElement('code').append('Kaydet');
  const keep = new FakeElement('div', { translate: 'no' }).append(new FakeElement('span').append('Kaydet'));
  const area = new FakeElement('textarea', { placeholder: 'Gerçek kişisel veri veya sır eklemeyin.' }).append('Kaydet');
  document.documentElement.append(code, keep, area);
  await i18n.setLang('en');
  assert.equal(code.textContent, 'Kaydet');
  assert.equal(keep.textContent, 'Kaydet');
  assert.equal(area.textContent, 'Kaydet');
  assert.equal(area.getAttribute('placeholder'), 'Do not add real personal data or secrets.');
});

test('değer içeren kalıplar: yer tutucular korunur, iç değer sözlükteyse o da çevrilir', async () => {
  const { i18n } = load();
  await i18n.setLang('en');
  assert.equal(i18n.t('Kural kaydedildi: sql-ham (python).'), 'Rule saved: sql-ham (python).');
  assert.equal(i18n.t('İstek 503 durum koduyla başarısız oldu.'), 'Request failed with status code 503.');
  assert.equal(i18n.t('12 rota · 3 korumalı · 1 korumasız hassas · 0 IDOR adayı'),
    '12 routes · 3 protected · 1 unprotected sensitive · 0 IDOR candidates');
  assert.equal(i18n.t('Durum: Tamamlandı · Kalan gün: 4'), 'Status: Completed · Days left: 4');
  // Kısa sabitli kalıp ("{0} sn") yalnız sayısal değer alır; serbest metinle aşırı eşleşmez.
  assert.equal(i18n.t('12 sn'), '12 s');
  assert.equal(i18n.t('Yarın sn'), 'Yarın sn');
});

test('birleşik metinler ayırıcıdan bölünerek yalnız tam eşleşen parçalar çevrilir; sözlükte olmayan veri olduğu gibi kalır', async () => {
  const { i18n } = load();
  await i18n.setLang('en');
  assert.equal(i18n.t('Önem: Yüksek'), 'Severity: High');
  assert.equal(i18n.t('app/models.py · Yüksek'), 'app/models.py · High');
  assert.equal(i18n.t('bilinmeyen-dosya.py'), 'bilinmeyen-dosya.py');
});

test('MutationObserver: betiğin sonradan eklediği düğümler ve değiştirdiği metin çevrilir; kendi yazımımız döngü yaratmaz', async () => {
  const { document, i18n, notify } = load();
  await i18n.setLang('en');
  const panel = new FakeElement('div');
  const title = new FakeElement('h3').append('Henüz hedef yok');
  panel.append(title);
  document.documentElement.append(panel);
  notify([{ type: 'childList', addedNodes: [panel] }]);
  assert.equal(title.textContent, 'No targets yet');
  const text = title.childNodes[0];
  text.nodeValue = 'Tarama tamamlandı';            // uygulama metni değiştirir
  notify([{ type: 'characterData', target: text }]);
  assert.equal(text.nodeValue, 'Scan completed');
  notify([{ type: 'characterData', target: text }]);   // kendi yazımımızın bildirimi
  assert.equal(text.nodeValue, 'Scan completed');
  assert.equal(i18n.source(title), 'Tarama tamamlandı', 'karşılaştırmalar için özgün metin');
  const field = new FakeElement('input', { type: 'text' });
  document.documentElement.append(field);
  field.setAttribute('placeholder', 'Hedef seçin');
  notify([{ type: 'attributes', target: field, attributeName: 'placeholder' }]);
  assert.equal(field.getAttribute('placeholder'), 'Select target');
});

test('localStorage erişimi hata verirse Türkçe açılır; seçim yine çalışır ve kalıcılık hatası yutulur', async () => {
  const { i18n } = load({ storage: 'throws' });
  assert.equal(i18n.lang, 'tr');
  await i18n.setLang('en');
  assert.equal(i18n.lang, 'en');
  assert.equal(i18n.t('Kaydet'), 'Save');
});

test('kaydedilmiş dil açılışta uygulanır; dil seçici bağlanır ve onay/uyarı iletileri çevrilir', async () => {
  const { window, document, dialogs } = load({ lang: 'en' });
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(document.documentElement.getAttribute('lang'), 'en');
  window.confirm('“Gece” planı silinsin mi?');
  assert.equal(dialogs[0], 'Delete plan “Gece”?');
});

test('sözlük dosyası: biçim, yer tutucu tutarlılığı, HTML içermeyen değerler', () => {
  assert.ok(dictionaryText.startsWith('# sniper-i18n/1\ten\n'));
  assert.ok(Object.keys(dictionary.strings).length > 1500);
  for (const [tr, en] of Object.entries(dictionary.strings)) {
    assert.ok(en.trim(), `boş çeviri: ${tr}`);
    assert.ok(!/<\/?(a|b|i|p|div|span|button|strong|small|h\d|option|input|label|form|tr|td|th|ul|li|script)\b/i.test(en), `çeviride HTML: ${tr}`);
  }
  for (const [tr, en] of dictionary.patterns) {
    const a = (tr.match(/\{\d+\}/g) || []).sort().join();
    const b = (en.match(/\{\d+\}/g) || []).sort().join();
    assert.equal(a, b, `yer tutucu uyuşmazlığı: ${tr}`);
  }
});

// --- Kapsam ölçümü: index.html, login.html ve static/*.js içindeki görünür Türkçe dizgeler ---
const TR_CHARS = /[çğıöşüÇĞİÖŞÜ]/;
const TAG = /<[a-zA-Z/!][^>]*>/;
function htmlTexts(html) {
  const out = [];
  const body = html.replace(/<(script|style|code|pre)[\s\S]*?<\/\1>/g, '<x>');
  for (const m of body.matchAll(/(?:placeholder|title|aria-label|alt)="([^"]*)"/g)) out.push(m[1]);
  for (const piece of body.replace(/<[^>]*>/g, '\u0000').split('\u0000')) out.push(piece);
  return out.map((s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim())
    .filter((s) => TR_CHARS.test(s));
}
function jsTexts(code) {
  const parser = require('../vendor/babel-parser/index.js');
  const ast = parser.parse(code, { sourceType: 'unambiguous', errorRecovery: true });
  const out = [];
  const visit = (node) => {
    if (!node || typeof node.type !== 'string') return;
    if (node.type === 'StringLiteral') out.push({ text: node.value });
    else if (node.type === 'TemplateLiteral') out.push({ text: node.quasis.map((q) => q.value.cooked).join('{0}'), template: node.expressions.length > 0 });
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'extra') continue;
      const v = node[key];
      if (Array.isArray(v)) v.forEach(visit); else if (v && typeof v.type === 'string') visit(v);
    }
  };
  visit(ast.program);
  const pieces = [];
  for (const item of out) {
    const parts = item.text.split(TAG);
    for (const p of parts) {
      const s = p.replace(/\s+/g, ' ').trim();
      if (TR_CHARS.test(s.replace(/\{\d+\}/g, ''))) pieces.push(s);
    }
  }
  return pieces;
}

test('kapsam: görünür Türkçe dizgelerin en az %90’ı sözlükte (oran yazdırılır)', async () => {
  const { i18n } = load();
  await i18n.setLang('en');
  const patternSources = new Set(dictionary.patterns.map(([s]) => s));
  const candidates = new Set();
  for (const file of ['index.html', 'login.html']) htmlTexts(fs.readFileSync(new URL(file, STATIC), 'utf8')).forEach((s) => candidates.add(s));
  for (const file of fs.readdirSync(STATIC).filter((f) => f.endsWith('.js') && f !== 'i18n.js')) {
    jsTexts(fs.readFileSync(new URL(file, STATIC), 'utf8')).forEach((s) => candidates.add(s));
  }
  candidates.delete('Türkçe');  // dil seçici kendi adını gösterir (translate="no")
  const missing = [];
  for (const s of candidates) {
    const sample = s.replace(/\{\d+\}/g, '7');
    const covered = patternSources.has(s) || i18n.translate(s) != null || i18n.translate(sample) != null
      || s.replace(/\{\d+\}/g, ' ').split(/\s{2,}| · /).every((part) => !TR_CHARS.test(part) || i18n.translate(part.trim()) != null);
    if (!covered) missing.push(s);
  }
  const ratio = 1 - missing.length / candidates.size;
  console.log(`i18n kapsamı: ${(ratio * 100).toFixed(1)}% (${candidates.size - missing.length}/${candidates.size}); örnek eksikler: ${JSON.stringify(missing.slice(0, 8))}`);
  assert.ok(ratio >= 0.9, `kapsam düşük: ${ratio}`);
});

test('HTML rapor bağlantıları etkin dilde açılır: ?lang=en eklenir, Türkçeye dönüşte kaldırılır; diğer bağlantılar değişmez', async () => {
  const { document, i18n } = load();
  const report = new FakeElement('a', { href: '/api/scans/scn_1/report.html?download=1' });
  const other = new FakeElement('a', { href: '/api/scans/scn_1/report.json' });
  document.documentElement.append(report, other);
  await i18n.setLang('en');
  assert.equal(report.getAttribute('href'), '/api/scans/scn_1/report.html?download=1&lang=en');
  assert.equal(other.getAttribute('href'), '/api/scans/scn_1/report.json');
  await i18n.setLang('tr');
  assert.equal(report.getAttribute('href'), '/api/scans/scn_1/report.html?download=1');
});

test('serbest biçimli kanıt metni: sözlük parçalarıyla (F) çevrilir; yönetici yetkisi rozeti sözlükte', async () => {
  const { i18n } = load();
  await i18n.setLang('en');
  const out = i18n.t("Veri akışı: bodyJSON parametresi (src/LoginAPI.java satır 31) → isValidUser → executeQuery() (satır 224); kaynak satır içeriği kaydedilmedi.");
  assert.equal(out, 'Data flow: bodyJSON parameter (src/LoginAPI.java line 31) → isValidUser → executeQuery() (line 224); source line content was not recorded.');
  assert.equal(i18n.t('YÖNETİCİ YETKİSİ'), 'ADMIN PRIVILEGE');
  assert.equal(i18n.t('dosya_adı.py'), 'dosya_adı.py');
});

test('22. tur QA: bildirimlerdeki küçük harfli [önem] öneki, virgüllü sayım listesi ve konteyner/SBOM başlıkları çevrilir', async () => {
  const { i18n } = load();
  await i18n.setLang('en');
  assert.equal(i18n.t('pygoat analizi tamamlandı (14 kritik, 19 yüksek, 15 orta, 18 düşük).'),
    'pygoat analysis completed (14 critical, 19 high, 15 medium, 18 low).');
  assert.equal(i18n.t('[critical] Açıklı işletim sistemi paketi: zlib (CVE-2023-45853) — var/lib/dpkg/status'),
    '[critical] Vulnerable OS package: zlib (CVE-2023-45853) — var/lib/dpkg/status');
  assert.equal(i18n.t('[high] Açıklı bileşen (SBOM): fsevents 1.2.9 (MAL-2023-462) — x.spdx.json'),
    '[high] Vulnerable component (SBOM): fsevents 1.2.9 (MAL-2023-462) — x.spdx.json');
  // Öğelerden biri çevrilemiyorsa liste olduğu gibi kalır (yarı çeviri yok).
  assert.equal(i18n.t('Elma, armut ve kiraz'), 'Elma, armut ve kiraz');
  // Virgül içeren ama sözlükte tam karşılığı olan metin bölünmez; puan/düzeltme kalıbı çevrilir.
  assert.equal(i18n.t('İzinli hedef, seçili kapsam spider ve site-aktif profilleri'), 'Authorized target, selected-scope spider and site-active profiles');
  assert.equal(i18n.t('fsevents 1.2.9 — MAL-2023-462 (puan 100, düzeltme ≥ 1.2.11)'), 'fsevents 1.2.9 — MAL-2023-462 (score 100, fix ≥ 1.2.11)');
});
