import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/container_scan.js', import.meta.url), 'utf8');

function node(tag) {
  return {
    tag, children: [], textContent: '', className: '', attrs: {}, listeners: {}, removed: false, disabled: false,
    value: '', checked: false,
    append(...items) { this.children.push(...items); },
    after(item) { this.afterNode = item; },
    remove() { this.removed = true; },
    setAttribute(name, value) { this.attrs[name] = value; },
    addEventListener(name, fn) { this.listeners[name] = fn; },
    querySelector(selector) {
      if (selector === '#container-scan-summary') return this.children.find(c => c.attrs.id === 'container-scan-summary') || null;
      if (selector === '.project-audit-summary') return null;
      return null;
    },
    get firstElementChild() { return null; },
    set innerHTML(_v) { throw new Error('innerHTML kullanılmamalı'); },
  };
}

function load(extra = {}) {
  const document = {
    createElement: (tag) => node(tag),
    createElementNS: (_namespace, tag) => node(tag),
  };  // addEventListener yok → otomatik bağlama atlanır
  const window = { ...extra };
  vm.runInNewContext(source, { window, globalThis: window, document, String, Number, Object, JSON, Error, Promise, encodeURIComponent });
  return window;
}

function texts(root) {
  const out = [];
  const walk = (n) => { if (n.textContent) out.push(n.textContent); (n.children || []).forEach(walk); };
  walk(root);
  return out;
}

function findByAttr(root, tag, name, value) {
  if (root.tag === tag && root.attrs?.[name] === value) return root;
  for (const child of root.children || []) {
    const found = findByAttr(child, tag, name, value);
    if (found) return found;
  }
  return null;
}

const AUDIT = {
  id: 'prj_0123456789ab', audit_kind: 'container',
  container: {
    image: { format: 'docker-save', layers: 2, tags: ['<img src=x onerror=alert(1)>:1'] },
    os: { id: 'alpine', pretty_name: 'Alpine Linux v3.19', ecosystem: 'Alpine:v3.19' },
    package_count: 3, package_types: { apk: 3 }, fixable_findings: 8,
    osv: { retrieved_utc: '2026-10-21T00:00:00+00:00', cached: true }, language_components: 2, language_matching: 'unavailable',
  },
};

test('konteyner özeti textContent ile çizilir; imaj etiketi metin kalır, SBOM bağlantısı doğru', () => {
  const win = load();
  const host = node('div');
  win.SniperContainerScan.renderContainerSummary(AUDIT, host);
  const box = host.children.find(c => c.attrs.id === 'container-scan-summary');
  assert.ok(box, 'özet eklenmeli');
  const all = texts(box);
  assert.ok(all.includes('docker-save · 2 katman · <img src=x onerror=alert(1)>:1'));
  assert.ok(all.includes('Alpine Linux v3.19 → OSV Alpine:v3.19'));
  assert.ok(all.includes('2 (OSV çok ekosistem eşleyicisi bekleniyor)'));
  const link = box.children.find(c => c.tag === 'a');
  assert.equal(link.attrs.href, '/api/container-images/prj_0123456789ab/sbom');
});

test('konteyner olmayan analizde özet eklenmez; zincir önceki lisans çizicisini korur', () => {
  let calls = 0;
  const win = load({ renderLicenseSummary: () => { calls += 1; } });
  const host = node('div');
  win.SniperContainerScan.chain();
  win.renderLicenseSummary({ id: 'prj_x', audit_kind: undefined }, host);
  assert.equal(calls, 1);
  assert.equal(host.children.length, 0);
  win.SniperContainerScan.chain();  // ikinci zincirleme sarmalamaz
  win.renderLicenseSummary(AUDIT, host);
  assert.equal(calls, 2);
  assert.equal(host.children.length, 1);
});

test('başlatıcı paneli form alanları ve durum satırıyla kurulur', () => {
  const win = load();
  const panel = win.SniperContainerScan.buildPanel();
  assert.equal(panel.attrs.id, 'container-scan-launcher');
  const icon = panel.children[0].children[0];
  assert.equal(icon.textContent, '');
  assert.equal(icon.children[0]?.tag, 'svg');
  assert.equal(icon.children[0]?.children[0]?.attrs.href, '/static/ui-icons.svg#container');
  const form = panel.children.find(c => c.tag === 'form');
  const imagePath = findByAttr(form, 'input', 'name', 'image_path');
  const dockerfilePath = findByAttr(form, 'input', 'name', 'dockerfile_path');
  const ignoreUnfixed = findByAttr(form, 'input', 'name', 'ignore_unfixed');
  const button = form.children.find(c => c.tag === 'button');
  assert.ok(imagePath, 'image_path alanı bulunmalı');
  assert.ok(dockerfilePath, 'isteğe bağlı dockerfile_path alanı bulunmalı');
  assert.equal(ignoreUnfixed?.attrs.type, 'checkbox');
  assert.equal(button.textContent, 'Taramayı başlat');
  assert.equal(panel.children.find(c => c.tag === 'p').attrs['aria-live'], 'polite');
});

test('başlatıcı API gövdesinde checkbox boolean kalır ve boş Dockerfile yolu gönderilmez', async () => {
  const calls = [];
  const win = load({
    fetch: async (route, options) => {
      calls.push({ route, options });
      return { ok: true, json: async () => ({ id: 'prj_0123456789ab', project_name: 'yerel-imaj', findings: [], container: {} }) };
    },
  });
  const panel = win.SniperContainerScan.buildPanel();
  const form = panel.children.find(c => c.tag === 'form');
  const imagePath = findByAttr(form, 'input', 'name', 'image_path');
  const dockerfilePath = findByAttr(form, 'input', 'name', 'dockerfile_path');
  const ignoreUnfixed = findByAttr(form, 'input', 'name', 'ignore_unfixed');
  imagePath.value = ' /tmp/image.tar ';
  dockerfilePath.value = '   ';
  ignoreUnfixed.checked = true;
  await form.listeners.submit({ preventDefault() {} });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].route, '/api/container-images');
  assert.deepEqual(JSON.parse(calls[0].options.body), { image_path: '/tmp/image.tar', ignore_unfixed: true });
});

test('boş imaj yolunda istek yapılmaz; Dockerfile yolu verilirse sözleşmeye eklenir', async () => {
  const calls = [];
  const win = load({
    fetch: async (_route, options) => {
      calls.push(JSON.parse(options.body));
      return { ok: true, json: async () => ({ id: 'prj_0123456789ab', project_name: 'rootfs', findings: [], container: {} }) };
    },
  });
  const panel = win.SniperContainerScan.buildPanel();
  const form = panel.children.find(c => c.tag === 'form');
  const imagePath = findByAttr(form, 'input', 'name', 'image_path');
  const dockerfilePath = findByAttr(form, 'input', 'name', 'dockerfile_path');
  const ignoreUnfixed = findByAttr(form, 'input', 'name', 'ignore_unfixed');
  imagePath.value = '   ';
  await form.listeners.submit({ preventDefault() {} });
  assert.equal(calls.length, 0);
  imagePath.value = '/tmp/rootfs';
  dockerfilePath.value = ' /tmp/Dockerfile ';
  ignoreUnfixed.checked = false;
  await form.listeners.submit({ preventDefault() {} });
  assert.deepEqual(calls, [{ image_path: '/tmp/rootfs', ignore_unfixed: false, dockerfile_path: '/tmp/Dockerfile' }]);
});
