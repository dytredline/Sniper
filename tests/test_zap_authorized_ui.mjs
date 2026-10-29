import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const sourcePath = new URL('../static/zap_authorized.js', import.meta.url).pathname;
const htmlPath = new URL('../static/index.html', import.meta.url).pathname;
const source = fs.readFileSync(sourcePath, 'utf8');
const html = fs.readFileSync(htmlPath, 'utf8');
const flush = async () => { await new Promise(resolve => setTimeout(resolve, 0)); await new Promise(resolve => setTimeout(resolve, 0)); };

function fixture({ ready = true } = {}) {
  const requests = [];
  const documentListeners = new Map();
  const nodes = new Map();
  function makeNode(id) {
    const handlers = new Map();
    const classes = new Set(['hidden']);
    return {
      id, value: '', textContent: '', checked: false, disabled: false, handlers,
      classList: {
        add(name) { classes.add(name); },
        remove(name) { classes.delete(name); },
        contains(name) { return classes.has(name); },
      },
      addEventListener(name, handler) { handlers.set(name, [...(handlers.get(name) || []), handler]); },
      closest() { return null; },
    };
  }
  function node(id) {
    if (!nodes.has(id)) nodes.set(id, makeNode(id));
    return nodes.get(id);
  }
  const openButton = node('open-zap-authorized');
  const document = {
    getElementById: node,
    querySelector(selector) { return selector === '[data-action="open-zap-authorized"]' ? openButton : null; },
    addEventListener(name, handler) {
      documentListeners.set(name, [...(documentListeners.get(name) || []), handler]);
    },
  };
  const response = (body, ok = true, status = 200) => ({ ok, status, json: async () => body });
  const readiness = {
    format: 'zap-authorized-readiness-v1', ready,
    runtime: 'owasp-zap-2.17.0-java17', checks: [],
    missing: ready ? [] : ['systemd-run:missing:/usr/bin/systemd-run'],
  };
  const result = {
    format: 'zap-authorized-v1', profile: 'same-origin-authorized-spider-active-v1',
    site_count: 1, alert_type_count: 1, instance_count: 2,
    risk_counts: { informational: 0, low: 1, medium: 0, high: 0 },
    report_sha256: 'a'.repeat(64), elapsed_seconds: 1.25,
    receipt: {
      format: 'zap-authorization-receipt-v1', run_id: 'zaprun_0123456789abcdef',
      actor: { id: 'usr_1', username: 'operator', role: 'admin' },
      confirmed_at: '2026-10-22T15:00:00+00:00', consent_version: 'zap-authorized-consent-v1',
      target: 'http://127.0.0.1:43117/app', target_sha256: 'b'.repeat(64),
    },
  };
  let runResponse = result;
  let deferred = null;
  async function fetch(path, options = {}) {
    requests.push({ path, options });
    if (path === '/api/tools/zap/authorized/readiness') return response(readiness);
    if (path === '/api/tool-runs/zap-authorized') return deferred || response(runResponse);
    throw new Error('unexpected fetch ' + path);
  }
  const context = vm.createContext({ document, fetch, Promise, Number, Object, Array, Set, console });
  vm.runInContext(source, context, { filename: sourcePath });

  async function dispatch(target, name, extra = {}) {
    for (const handler of target.handlers.get(name) || []) {
      await handler({ target, preventDefault() {}, ...extra });
    }
  }
  async function dispatchDocument(name, event = {}) {
    for (const handler of documentListeners.get(name) || []) await handler(event);
  }
  return {
    requests, node, openButton, result,
    setRunResponse(value) { runResponse = value; },
    setDeferred(value) { deferred = value; },
    async init() { await dispatchDocument('DOMContentLoaded'); },
    async open() { await dispatch(openButton, 'click'); await flush(); },
    async input(target) {
      node('zap-authorized-target').value = target;
      await dispatch(node('zap-authorized-target'), 'input');
    },
    async consent(value = true) {
      node('zap-authorized-consent').checked = value;
      await dispatch(node('zap-authorized-consent'), 'change');
    },
    async submit() { await dispatch(node('zap-authorized-form'), 'submit'); await flush(); },
    posts() { return requests.filter(item => item.path === '/api/tool-runs/zap-authorized'); },
  };
}

test('authorized UI is mounted separately with one human authorization checkbox', () => {
  assert.match(html, /data-action="open-zap-authorized"/);
  assert.match(html, /id="zap-authorized-target"/);
  assert.match(html, /id="zap-authorized-consent"/);
  assert.match(html, /zap_authorized\.js\?v=1/);
});

test('open performs readiness only and missing consent never starts a scan', async () => {
  const f = fixture(); await f.init(); await f.open();
  assert.equal(f.posts().length, 0);
  assert.equal(f.node('zap-authorized-modal').classList.contains('hidden'), false);
  await f.input('http://127.0.0.1:43117/app');
  assert.equal(f.node('zap-authorized-submit').disabled, true);
  await f.submit();
  assert.equal(f.posts().length, 0);
});

test('one checked authorization sends only target and exact boolean then renders receipt', async () => {
  const f = fixture(); await f.init(); await f.open();
  await f.input('http://127.0.0.1:43117/app'); await f.consent();
  assert.equal(f.node('zap-authorized-submit').disabled, false);
  await f.submit();
  assert.equal(f.posts().length, 1);
  assert.deepEqual(JSON.parse(f.posts()[0].options.body), {
    target: 'http://127.0.0.1:43117/app', confirm_authorized: true,
  });
  assert.equal(f.node('zap-authorized-result').classList.contains('hidden'), false);
  assert.equal(f.node('zap-authorized-result-target').textContent, 'http://127.0.0.1:43117/app');
  assert.equal(f.node('zap-authorized-result-actor').textContent, 'operator (usr_1)');
  assert.equal(f.node('zap-authorized-run-id').textContent, 'zaprun_0123456789abcdef');
  assert.equal(f.node('zap-authorized-consent').checked, false);
});

test('failed readiness names missing prerequisite and blocks dispatch', async () => {
  const f = fixture({ ready: false }); await f.init(); await f.open();
  await f.input('https://example.test/'); await f.consent();
  assert.equal(f.node('zap-authorized-submit').disabled, true);
  assert.match(f.node('zap-authorized-readiness').textContent, /systemd-run:missing/);
  await f.submit();
  assert.equal(f.posts().length, 0);
});

test('response with unexpected field is rejected without rendering it', async () => {
  const f = fixture(); await f.init(); await f.open();
  await f.input('https://example.test/'); await f.consent();
  f.setRunResponse({ ...f.result, raw_report: 'PRIVATE' });
  await f.submit();
  assert.equal(f.posts().length, 1);
  assert.equal(f.node('zap-authorized-result').classList.contains('hidden'), true);
  assert.equal(f.node('zap-authorized-error').textContent.includes('PRIVATE'), false);
});
