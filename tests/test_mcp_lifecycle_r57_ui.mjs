import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { test } from 'node:test';

const fallbackRoot = new URL('../', import.meta.url).pathname;
const root = process.env.SNIPER_SOURCE_ROOT ? path.resolve(process.env.SNIPER_SOURCE_ROOT) + '/' : fallbackRoot;
const source = fs.readFileSync(root + 'static/mcp_scan_approval.js', 'utf8');

function node(tag) {
  return {
    tag, children: [], textContent: '', className: '', disabled: false, checked: false, attrs: {}, listeners: {},
    append(...items) { this.children.push(...items); },
    replaceChildren(...items) { this.children = [...items]; },
    setAttribute(key, value) { this.attrs[key] = value; },
    addEventListener(name, fn) { this.listeners[name] = fn; },
    set innerHTML(_value) { throw new Error('innerHTML kullanılmamalı'); },
  };
}

function buttons(nodeValue, found = []) {
  if (nodeValue?.tag === 'button') found.push(nodeValue);
  for (const child of nodeValue?.children || []) buttons(child, found);
  return found;
}

function fixture({ failCancel = false } = {}) {
  const nodes = new Map([
    ['mcp-scan-approval-panel', node('section')],
    ['mcp-scan-approval-body', node('tbody')],
    ['mcp-scan-approval-status', node('p')],
    ['mcp-scan-approval-refresh', node('button')],
  ]);
  const requests = [
    { id: 'msr_0123456789abcdef', profile_id: 'operator_authorized_http', status: 'pending',
      parameters: { tool_id: 'nmap', target: 'pending.example' }, requested_by: { username: 'analist' } },
    { id: 'msr_1111111111111111', profile_id: 'operator_authorized_http', status: 'approved',
      parameters: { tool_id: 'burp-suite', target: 'approved.example' }, requested_by: { username: 'analist' } },
    { id: 'msr_fedcba9876543210', profile_id: 'operator_authorized_http', status: 'running',
      parameters: { tool_id: 'testssl', target: 'running.example:443' }, requested_by: { username: 'analist' } },
  ];
  const calls = [];
  const document = {
    readyState: 'complete',
    getElementById: id => nodes.get(id) || null,
    createElement: tag => node(tag),
    addEventListener() {},
  };
  const window = {
    async fetch(requestPath, options = {}) {
      const body = options.body ? JSON.parse(options.body) : null;
      calls.push({ path: requestPath, options, body });
      if ((options.method || 'GET') === 'POST') {
        if (failCancel) return { ok: false, status: 409, json: async () => ({ error: 'İş artık iptal edilemez.' }) };
        return { ok: true, status: 200, json: async () => ({ request: { status: 'cancelled' } }) };
      }
      return { ok: true, status: 200, json: async () => ({ requests }) };
    },
  };
  vm.runInNewContext(source, { window, globalThis: window, document, JSON, String, Array, Error });
  return { nodes, calls };
}

test('pending reject is independent from authorization checkbox and never calls approve', async () => {
  const f = fixture();
  await new Promise(resolve => setTimeout(resolve, 5));
  const rows = f.nodes.get('mcp-scan-approval-body').children;
  assert.equal(rows.length, 3);
  const reject = buttons(rows[0]).find(button => button.textContent === 'Reddet');
  assert.ok(reject);
  assert.equal(reject.disabled, false);
  await reject.listeners.click();
  const posts = f.calls.filter(call => call.options.method === 'POST');
  assert.deepEqual(posts.map(call => ({ path: call.path, body: call.body })), [{
    path: '/api/mcp-scan-requests/msr_0123456789abcdef/cancel', body: { confirm: true },
  }]);
  assert.equal(posts.some(call => call.path.endsWith('/approve')), false);
  assert.equal(f.calls.filter(call => (call.options.method || 'GET') === 'GET').length, 2);
  assert.match(f.nodes.get('mcp-scan-approval-status').textContent, /reddedildi|iptal edildi/i);
});

test('running row exposes cancel and renders server error through textContent', async () => {
  const f = fixture({ failCancel: true });
  await new Promise(resolve => setTimeout(resolve, 5));
  const rows = f.nodes.get('mcp-scan-approval-body').children;
  const cancel = buttons(rows[2]).find(button => button.textContent === 'İptal');
  assert.ok(cancel);
  await cancel.listeners.click();
  const post = f.calls.find(call => call.options.method === 'POST');
  assert.equal(post.path, '/api/mcp-scan-requests/msr_fedcba9876543210/cancel');
  assert.deepEqual(post.body, { confirm: true });
  assert.equal(f.nodes.get('mcp-scan-approval-status').textContent, 'İş artık iptal edilemez.');
});

test('approved manual handoff remains visible with an explicit close action', async () => {
  const f = fixture();
  await new Promise(resolve => setTimeout(resolve, 5));
  const approved = f.nodes.get('mcp-scan-approval-body').children[1];
  const close = buttons(approved).find(button => button.textContent === 'Kapat');
  assert.ok(close);
  await close.listeners.click();
  const post = f.calls.find(call => call.path === '/api/mcp-scan-requests/msr_1111111111111111/cancel');
  assert.deepEqual(post.body, { confirm: true });
});
