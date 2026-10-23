import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const root = new URL('../', import.meta.url).pathname;
const html = fs.readFileSync(root + 'static/index.html', 'utf8');
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

function fixture() {
  const nodes = new Map([
    ['mcp-scan-approval-panel', node('section')],
    ['mcp-scan-approval-body', node('tbody')],
    ['mcp-scan-approval-status', node('p')],
    ['mcp-scan-approval-refresh', node('button')],
  ]);
  const calls = [];
  const pending = { requests: [{
    id: 'msr_0123456789abcdef', profile_id: 'operator_authorized_http', status: 'pending',
    parameters: { tool_id: 'nuclei', target: 'https://example.com/team/' },
    effective_profile: 'nuclei-authorized-origin-v1',
    scope_summary: ['Tek kök originde sabit üç Nuclei HTTP şablonu'],
    requested_by: { id: 'u1', username: '<analist>' }, created_at: '2026-10-22T12:00:00Z',
  }] };
  const document = {
    readyState: 'complete',
    getElementById: id => nodes.get(id) || null,
    createElement: tag => node(tag),
    addEventListener() {},
  };
  const window = {
    async fetch(path, options = {}) {
      calls.push({ path, options, body: options.body ? JSON.parse(options.body) : null });
      if ((options.method || 'GET') === 'POST') {
        return { ok: true, status: 202, json: async () => ({
          request: { status: 'started', authorization_receipt: { receipt_sha256: 'a'.repeat(64) } },
          job: { id: 'job_' + 'b'.repeat(24), state: 'queued' },
        }) };
      }
      return { ok: true, status: 200, json: async () => pending };
    },
  };
  vm.runInNewContext(source, { window, globalThis: window, document, JSON, String, Array, Error });
  return { nodes, calls, window };
}

test('audit page contains the human authorization checkbox control', () => {
  assert.match(html, /id="mcp-scan-approval-panel"/);
  assert.match(html, /id="mcp-scan-approval-body"/);
  assert.match(html, /mcp_scan_approval\.js\?v=2/);
  assert.match(html, /yalnız yetkiniz varsa kutuyu işaretleyin/);
});

test('tool-specific consent text discloses Qualys transfer and schema mutations', () => {
  const f = fixture();
  const text = f.window.SniperMCPScanApproval.consentText;
  assert.match(text({ parameters: { tool_id: 'ssllabs' } }), /Qualys SSL Labs/);
  assert.match(text({ parameters: { tool_id: 'schemathesis' } }), /POST\/DELETE/);
});

test('approval plan text shows bounded effective profile and scope without HTML rendering', () => {
  const f = fixture();
  const text = f.window.SniperMCPScanApproval.planText;
  assert.match(text({ parameters: { tool_id: 'nmap' }, effective_profile: 'service-light',
    scope_summary: ['Tek host/IP için sabit port seti (service-light)'] }), /service-light/);
  assert.match(text({ parameters: { tool_id: 'testssl' }, effective_profile: 'full',
    scope_summary: ['Tek HOST:PORT için testssl full profili'] }), /testssl full/);
  assert.match(text({ parameters: { tool_id: 'schemathesis' }, effective_profile: 'schemathesis-authorized-schema-v1',
    scope_summary: ['Tek kök originde inline şemadaki tüm operasyonlar'] }), /inline şemadaki tüm operasyonlar/);
});

test('page load is read-only and checked approval sends the exact authorization declaration', async () => {
  const f = fixture();
  await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].path, '/api/mcp-scan-requests');
  assert.equal(f.calls[0].options.method, undefined);
  const row = f.nodes.get('mcp-scan-approval-body').children[0];
  assert.equal(row.children[1].textContent, 'https://example.com/team/');
  assert.equal(row.children[2].textContent, '<analist>');
  const actions = row.children[4];
  const consent = actions.children[0].children[0];
  const approve = actions.children[1];
  assert.equal(approve.disabled, true);
  await approve.listeners.click();
  assert.equal(f.calls.length, 1, 'işaretlenmeden POST yapılmaz');
  consent.checked = true;
  consent.listeners.change();
  assert.equal(approve.disabled, false);
  await approve.listeners.click();
  const post = f.calls.find(call => call.options.method === 'POST');
  assert.equal(post.path, '/api/mcp-scan-requests/msr_0123456789abcdef/approve');
  assert.deepEqual(post.body, { confirm: true, confirm_authorized: true });
  assert.equal(f.calls.filter(call => (call.options.method || 'GET') === 'GET').length, 2, 'onaydan sonra kuyruk yenilenir');
  assert.match(f.nodes.get('mcp-scan-approval-status').textContent, /iş kuyruğuna alındı/);
  assert.match(f.nodes.get('mcp-scan-approval-status').textContent, /SHA-256/);
});
