import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const jsPath = process.env.SNIPER_TESTSSL_UI_JS || new URL('../static/testssl_loopback_full.js', import.meta.url).pathname;
const htmlPath = process.env.SNIPER_TESTSSL_UI_HTML || new URL('../static/index.html', import.meta.url).pathname;
const source = fs.readFileSync(jsPath, 'utf8');
const html = fs.readFileSync(htmlPath, 'utf8');

function fixture() {
  const nodes = new Map();
  const listeners = new Map();
  const requests = [];
  let scannerResponse = {
    ok: true,
    json: async () => ({
      format: 'testssl-loopback-full-v1', record_count: 2,
      severity_counts: { INFO: 0, OK: 1, LOW: 0, MEDIUM: 0, HIGH: 1,
        CRITICAL: 0, WARN: 0, DEBUG: 0, FATAL: 0 },
      report_sha256: 'a'.repeat(64), scan_complete: true, scanner_exit_code: 0,
    }),
  };
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(['hidden']);
    const handlers = new Map();
    const element = {
      id, value: '', checked: false, disabled: false, textContent: '', handlers,
      classList: { add(c) { classes.add(c); }, remove(c) { classes.delete(c); }, contains(c) { return classes.has(c); } },
      addEventListener(type, cb) { handlers.set(type, [...(handlers.get(type) || []), cb]); },
      querySelectorAll() { return []; }, // browser API for keyboard focus; payload assertions unchanged
      focus() { document.activeElement = element; },
      closest() { return null; },
    };
    nodes.set(id, element);
    return element;
  }
  const openButton = node('open');
  const document = {
    activeElement: null,
    getElementById: node,
    querySelector(selector) { return selector === '[data-action="open-testssl-loopback-full"]' ? openButton : null; },
    addEventListener(type, cb) { listeners.set(type, [...(listeners.get(type) || []), cb]); },
  };
  async function dispatch(element, type, extra = {}) {
    for (const cb of element.handlers.get(type) || []) await cb({ target: element, preventDefault() {}, ...extra });
  }
  async function documentEvent(type, event) {
    for (const cb of listeners.get(type) || []) await cb(event);
  }
  const fetch = async (path, options) => { requests.push({ path, options }); return scannerResponse; };
  vm.runInNewContext(source, { document, fetch, Number, Object, Array, JSON, Promise });
  return {
    node, requests, openButton, dispatch, documentEvent,
    setResponse(r) { scannerResponse = r; },
    async init() { await documentEvent('DOMContentLoaded', {}); },
    async open() { await dispatch(openButton, 'click'); },
    async input(value) { node('testssl-loopback-full-port').value = value; await dispatch(node('testssl-loopback-full-port'), 'input'); },
    async consent() { node('testssl-loopback-full-consent').checked = true; await dispatch(node('testssl-loopback-full-consent'), 'change'); },
    async submit() { await dispatch(node('testssl-loopback-full-form'), 'submit'); },
  };
}

const reply = (complete = true) => ({
  format: 'testssl-loopback-full-v1', record_count: 2,
  severity_counts: { INFO: 0, OK: 1, LOW: 0, MEDIUM: 0, HIGH: 1,
    CRITICAL: 0, WARN: 0, DEBUG: 0, FATAL: 0 },
  report_sha256: 'b'.repeat(64), scan_complete: complete, scanner_exit_code: complete ? 0 : 1,
});

test('full local scanner has a distinct launcher with fixed loopback input and explicit consent', () => {
  assert.match(html, /testssl_loopback_full\.js\?v=1/);
  assert.match(html, /data-action="open-testssl-loopback-full"/);
  assert.match(html, /id="testssl-loopback-full-port"/);
  assert.match(html, /id="testssl-loopback-full-consent"/);
  assert.match(html, /127\.0\.0\.1/);
});

test('opening, missing consent and invalid ports send no requests', async () => {
  const f = fixture(); await f.init(); await f.open();
  assert.equal(f.requests.length, 0);
  assert.equal(f.node('testssl-loopback-full-modal').classList.contains('hidden'), false);
  await f.input('443'); await f.submit();
  assert.equal(f.requests.length, 0);
  await f.consent();
  for (const bad of ['0', '65536', 'example.com:443', '127.0.0.2', ' 443', '-1', '443x']) {
    await f.input(bad); await f.submit();
    assert.equal(f.requests.length, 0, bad);
  }
});

test('consented loopback port sends only exact full-profile request and renders aggregate result', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.input('8443'); await f.consent(); await f.submit();
  assert.equal(f.requests.length, 1);
  const call = f.requests[0];
  assert.equal(call.path, '/api/tool-runs/testssl-full');
  assert.equal(call.options.method, 'POST');
  assert.deepEqual(JSON.parse(call.options.body), { confirm_local: true, target: '127.0.0.1:8443' });
  assert.equal(f.node('testssl-loopback-full-record-count').textContent, '2');
  assert.equal(f.node('testssl-loopback-full-complete').textContent, 'Tamamlandı');
  assert.equal(f.node('testssl-loopback-full-report-sha256').textContent, 'a'.repeat(64));
  assert.equal(f.node('testssl-loopback-full-result').classList.contains('hidden'), false);
});

test('nonzero scanner exit is labeled incomplete while preserving validated aggregate', async () => {
  const f = fixture(); f.setResponse({ ok: true, json: async () => reply(false) });
  await f.init(); await f.open(); await f.input('443'); await f.consent(); await f.submit();
  assert.match(f.node('testssl-loopback-full-complete').textContent, /Kısmi/);
  assert.equal(f.node('testssl-loopback-full-record-count').textContent, '2');
});

test('signal-terminated partial report remains visibly incomplete', async () => {
  const f = fixture(); f.setResponse({ ok: true, json: async () => ({ ...reply(false), scanner_exit_code: -9 }) });
  await f.init(); await f.open(); await f.input('65535'); await f.consent(); await f.submit();
  assert.match(f.node('testssl-loopback-full-complete').textContent, /Kısmi/);
  assert.equal(JSON.parse(f.requests[0].options.body).target, '127.0.0.1:65535');
});

test('malformed or hostile response and failed HTTP do not render raw content', async () => {
  const f = fixture(); f.setResponse({ ok: true, json: async () => ({ ...reply(), record_count: '<script>alert(1)</script>' }) });
  await f.init(); await f.open(); await f.input('443'); await f.consent(); await f.submit();
  assert.equal(f.node('testssl-loopback-full-result').classList.contains('hidden'), true);
  assert.equal(f.node('testssl-loopback-full-error').classList.contains('hidden'), false);
  assert.doesNotMatch(f.node('testssl-loopback-full-error').textContent, /script/);
  f.setResponse({ ok: false, status: 502, json: async () => ({ error: 'PRIVATE_REPORT' }) });
  await f.submit();
  assert.doesNotMatch(f.node('testssl-loopback-full-error').textContent, /PRIVATE_REPORT/);
});

test('a pending request blocks duplicate submits, and close discards late results and consent', async () => {
  const f = fixture(); let release;
  f.setResponse(new Promise(resolve => { release = resolve; }));
  await f.init(); await f.open(); await f.input('443'); await f.consent();
  const first = f.submit();
  assert.equal(f.requests.length, 1);
  await f.submit(); assert.equal(f.requests.length, 1);
  await f.documentEvent('click', { target: f.node('testssl-loopback-full-modal') });
  assert.equal(f.node('testssl-loopback-full-consent').checked, false);
  release({ ok: true, json: async () => reply() });
  await first;
  assert.equal(f.node('testssl-loopback-full-result').classList.contains('hidden'), true);
  assert.equal(f.node('testssl-loopback-full-submit').disabled, true);
});
