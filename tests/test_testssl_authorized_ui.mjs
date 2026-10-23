import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/testssl_authorized.js', import.meta.url), 'utf8');
const html = fs.readFileSync(new URL('../static/index.html', import.meta.url), 'utf8');

const severities = { INFO: 0, OK: 1, LOW: 0, MEDIUM: 0, HIGH: 1,
  CRITICAL: 0, WARN: 0, DEBUG: 0, FATAL: 0 };

function fixture() {
  const nodes = new Map(), listeners = new Map(), requests = [];
  let scannerResponse = {
    ok: true,
    json: async () => ({
      format: 'testssl-authorized-v1', profile: 'authorized-protocols-v1',
      record_count: 2, severity_counts: severities,
      report_sha256: 'a'.repeat(64), target_sha256: 'b'.repeat(64), resolved_ip_sha256: 'c'.repeat(64),
      authorization_receipt: {
        consent_version: 'direct-target-authorization-v1', confirm_authorized: true,
        confirmed_at: '2026-10-22T15:00:00+00:00',
      },
    }),
  };
  const document = {
    activeElement: null,
    getElementById: node,
    querySelector(selector) { return selector === '[data-action="open-testssl-authorized"]' ? opener : null; },
    querySelectorAll() { return [modal].filter(item => !item.classList.contains('hidden')); },
    addEventListener(type, callback) { listeners.set(type, [...(listeners.get(type) || []), callback]); },
  };
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(id.endsWith('-modal') || id.endsWith('-result') || id.endsWith('-error') ? ['hidden'] : []);
    const handlers = new Map();
    const element = {
      id, value: id === 'testssl-authorized-profile' ? 'protocols' : '', checked: false,
      disabled: id === 'testssl-authorized-submit', textContent: '', tabIndex: 0, handlers,
      classList: {
        add(value) { classes.add(value); }, remove(value) { classes.delete(value); },
        contains(value) { return classes.has(value); },
      },
      addEventListener(type, callback) { handlers.set(type, [...(handlers.get(type) || []), callback]); },
      querySelectorAll() { return []; },
      getClientRects() { return [{}]; },
      focus() { document.activeElement = element; },
      contains(other) { return other === element; },
      closest() { return null; },
    };
    nodes.set(id, element);
    return element;
  }
  const opener = node('testssl-authorized-launcher');
  const modal = node('testssl-authorized-modal');
  async function dispatch(element, type) {
    for (const callback of element.handlers.get(type) || []) {
      await callback({ target: element, preventDefault() {}, stopImmediatePropagation() {} });
    }
  }
  async function documentEvent(type, event = {}) {
    for (const callback of listeners.get(type) || []) await callback(event);
  }
  const fetch = async (path, options) => {
    requests.push({ path, options });
    return scannerResponse;
  };
  vm.runInNewContext(source, {
    document, fetch, Number, Object, Array, JSON, Promise,
    getComputedStyle: () => ({ zIndex: '50' }),
  });
  return {
    node, requests,
    setResponse(value) { scannerResponse = value; },
    async init() { await documentEvent('DOMContentLoaded'); },
    async open() { await dispatch(opener, 'click'); },
    async input(value) { node('testssl-authorized-target').value = value; await dispatch(node('testssl-authorized-target'), 'input'); },
    async select(value) { node('testssl-authorized-profile').value = value; await dispatch(node('testssl-authorized-profile'), 'change'); },
    async consent() { node('testssl-authorized-consent').checked = true; await dispatch(node('testssl-authorized-consent'), 'change'); },
    async submit() { await dispatch(node('testssl-authorized-form'), 'submit'); },
  };
}

test('authorized testssl modal and direct launcher are present', () => {
  assert.match(html, /testssl_authorized\.js\?v=1/);
  assert.match(html, /data-action="open-testssl-authorized"/);
  for (const id of ['testssl-authorized-modal', 'testssl-authorized-form', 'testssl-authorized-target',
    'testssl-authorized-profile', 'testssl-authorized-consent', 'testssl-authorized-submit']) {
    assert.match(html, new RegExp(`id=["']${id}["']`));
  }
  assert.match(html, /HER ÇALIŞTIRMADA İNSAN ONAYI/);
});

test('opening, typing and selecting a profile never start a scan', async () => {
  const f = fixture(); await f.init(); await f.open();
  await f.input('example.test:443'); await f.select('full');
  assert.equal(f.requests.length, 0);
  assert.equal(f.node('testssl-authorized-consent').checked, false);
  assert.equal(f.node('testssl-authorized-submit').disabled, true);
});

test('exact target profile and fresh checkbox consent are the only submitted fields', async () => {
  const f = fixture(); await f.init(); await f.open();
  await f.input('example.test:443'); await f.consent(); await f.submit();
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].path, '/api/tool-runs/testssl-authorized');
  assert.deepEqual(JSON.parse(f.requests[0].options.body), {
    target: 'example.test:443', profile: 'protocols', confirm_authorized: true,
  });
  assert.equal(f.node('testssl-authorized-consent').checked, false);
  assert.equal(f.node('testssl-authorized-record-count').textContent, '2');
  assert.equal(f.node('testssl-authorized-confirmed-at').textContent, '2026-10-22T15:00:00+00:00');
  assert.equal(f.node('testssl-authorized-result').classList.contains('hidden'), false);
});

test('changing target after consent revokes consent and blocks submission', async () => {
  const f = fixture(); await f.init(); await f.open();
  await f.input('first.example:443'); await f.consent(); await f.input('second.example:443'); await f.submit();
  assert.equal(f.node('testssl-authorized-consent').checked, false);
  assert.equal(f.requests.length, 0);
});

test('invalid or hostile server response is not rendered', async () => {
  const f = fixture();
  f.setResponse({ ok: true, json: async () => ({ record_count: '<script>PRIVATE</script>' }) });
  await f.init(); await f.open(); await f.input('example.test:443'); await f.consent(); await f.submit();
  assert.equal(f.node('testssl-authorized-result').classList.contains('hidden'), true);
  assert.equal(f.node('testssl-authorized-error').classList.contains('hidden'), false);
  assert.doesNotMatch(f.node('testssl-authorized-error').textContent, /script|PRIVATE/);
});
