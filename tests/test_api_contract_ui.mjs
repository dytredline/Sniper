import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/authz_inventory.js', import.meta.url), 'utf8');

function node(tag) {
  return {
    tag, children: [], textContent: '', className: '', nextSibling: null,
    append(...items) { this.children.push(...items); }, insertBefore(item) { this.children.unshift(item); },
    remove() {}, querySelector() { return null },
    set innerHTML(_v) { throw new Error('innerHTML kullanılmamalı'); },
  };
}

function texts(root) {
  const out = [];
  const walk = (n) => { if (n.textContent) out.push(n.textContent); (n.children || []).forEach(walk); };
  walk(root);
  return out;
}

test('API sözleşmesi bölümü textContent ile çizilir; rota envanteri olmasa da görünür', () => {
  const document = { createElement: (tag) => node(tag), createTextNode: (text) => ({ textContent: String(text) }) };
  const window = {};
  vm.runInNewContext(source, { window, globalThis: window, document, String, Number, Math, Object });
  const detail = node('div');
  const audit = { route_inventory: null, api_contract: {
    summary: { specs: 1, spec_operations: 3, matched_operations: 2, shadow_routes: 1, missing_in_code: 1, auth_mismatch: 1 },
    specs: [{ file: 'docs/openapi.json', format: 'openapi3', operations: 3, matched: 2, matched_by_operation_id: 0, coverage: 0.67 }],
    shadow: [{ method: 'GET', path: '/v1/<img src=x onerror=alert(1)>', file: 'routes.js', line: 9, protected: false }],
    auth_mismatch: [{ method: 'PUT', path: '/v1/items/{id}', file: 'routes.js', line: 7 }],
    missing: [{ spec: 'docs/openapi.json', method: 'GET', path: '/v1/legacy' }],
  } };
  const section = window.renderRouteInventory(audit, detail);
  assert.ok(section && section.className.includes('api-contract-report'));
  const all = texts(section);
  assert.ok(all.includes('/v1/<img src=x onerror=alert(1)>'));
  assert.ok(all.includes('Belgelenmemiş (gölge) uç noktalar'));
  assert.ok(all.includes('67 %'));
  assert.ok(all.some((t) => t.startsWith('1 sözleşme · 3 işlem · 2 eşleşti')));
  assert.equal(window.renderApiContract({}), null);
});
