import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/sbom_tools.js', import.meta.url), 'utf8');

function node(tag) {
  return {
    tag, children: [], textContent: '', className: '', attrs: {}, dataset: {}, listeners: {},
    append(...items) { this.children.push(...items); }, prepend(...items) { this.children.unshift(...items); },
    replaceChildren(...items) { this.children = [...items]; },
    setAttribute(name, value) { this.attrs[name] = String(value); }, getAttribute(name) { return this.attrs[name]; },
    addEventListener(name, fn) { this.listeners[name] = fn; }, after(item) { this.afterNode = item; },
    set innerHTML(_v) { throw new Error('innerHTML kullanılmamalı'); },
  };
}

function load() {
  const document = { createElement: (tag) => node(tag) };  // readyState yok → otomatik bağlama atlanır
  const window = {};
  vm.runInNewContext(source, { window, globalThis: window, document, String, Number, Array, JSON, Error, Promise });
  return window.SniperSbomTools;
}

function texts(root) {
  const out = [];
  const walk = (n) => { if (n.textContent) out.push(n.textContent); (n.children || []).forEach(walk); };
  walk(root);
  return out;
}

test('SPDX ve VEX bağlantıları yalnız beklenen kimlik biçimlerinde üretilir', () => {
  const ui = load();
  assert.equal(ui.spdxHref('/api/dependency-sboms/sbom_9c1aeb94bc49'), '/api/dependency-sboms/sbom_9c1aeb94bc49?format=spdx');
  assert.equal(ui.spdxHref('/api/container-images/prj_0123456789ab/sbom'), '/api/container-images/prj_0123456789ab/sbom?format=spdx');
  assert.equal(ui.spdxHref('javascript:alert(1)'), '');
  assert.equal(ui.spdxHref('/api/dependency-sboms/../x'), '');
  assert.equal(ui.vexHref('prj_0123456789ab', 'cyclonedx'), '/api/dependency-security/sbom-scans/prj_0123456789ab/vex?format=cyclonedx');
  assert.equal(ui.vexHref('"><img>', 'openvex'), '');
});

test('tarama sonucu textContent ile yazılır; kötü amaçlı adlar metin kalır', () => {
  const ui = load();
  const container = node('div');
  ui.renderScanResult(container, {
    id: 'prj_0123456789ab', project_name: '<img src=x onerror=alert(1)>', score: 62,
    finding_counts: { critical: 1, high: 2 }, warnings: ['3 bileşen eşlenemedi'],
    sbom: { source_format: 'cyclonedx-json', spec_version: '1.5', component_count: 10, matched_components: 7 },
    findings: [{ severity: 'critical', reference: 'GHSA-x', package: { source: 'log4j-core', installed_version: '2.14.1' }, fixed_version: '2.15.0' }],
  });
  const all = texts(container).join('\n');
  assert.match(all, /<img src=x onerror=alert\(1\)>/);
  assert.match(all, /bileşen 10 · eşlenen 7 · bulgu 1 \(kritik 1, yüksek 2\) · puan 62/);
  assert.match(all, /GHSA-x — log4j-core 2\.14\.1 → 2\.15\.0/);
  const links = [];
  const walk = (n) => { if (n.tag === 'a') links.push(n.attrs.href); (n.children || []).forEach(walk); };
  walk(container);
  assert.deepEqual(links, ['/api/dependency-security/sbom-scans/prj_0123456789ab/vex?format=openvex',
    '/api/dependency-security/sbom-scans/prj_0123456789ab/vex?format=cyclonedx']);
});

test('SBOM bağlantılarına bir kez SPDX karşılığı eklenir', () => {
  const ui = load();
  const anchor = node('a');
  anchor.setAttribute('href', '/api/dependency-sboms/sbom_abc');
  const container = { querySelectorAll: () => [anchor] };
  assert.equal(ui.decorateSources(container), 1);
  assert.equal(anchor.afterNode.attrs.href, '/api/dependency-sboms/sbom_abc?format=spdx');
  assert.equal(ui.decorateSources(container), 0);
});
