import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const sourcePath = process.env.SNIPER_ZAP_UI_JS || new URL('../static/zap_target_spider.js', import.meta.url).pathname;
const htmlPath = process.env.SNIPER_ZAP_UI_HTML || new URL('../static/index.html', import.meta.url).pathname;
const source = fs.readFileSync(sourcePath, 'utf8');
const html = fs.readFileSync(htmlPath, 'utf8');
const flush = () => new Promise(resolve => setTimeout(resolve, 0));

function fixture(overrides = {}, targetUrl = 'https://example.test/') {
  const target = { id: 't-one', url: targetUrl, hostname: 'example.test' };
  const now = Date.now();
  const iso = milliseconds => new Date(Math.floor(milliseconds / 1000) * 1000).toISOString().replace('.000Z', 'Z');
  const engagement = {
    id: 'e-one', target_id: target.id, target_url: target.url, name: 'Authorized test',
    status: 'active', authorization_ref: 'AUTH-001', scope_notes: 'single URL',
    out_of_scope: '["/admin"]', test_window: iso(now - 60000) + '/' + iso(now + 900000),
    ...overrides,
  };
  const requests = [];
  const listeners = new Map();
  const nodes = new Map();
  function makeNode(id) {
    const handlers = new Map();
    const classes = new Set(['hidden']);
    let markup = '';
    const node = {
      id, value: '', textContent: '', checked: false, disabled: false, dataset: {},
      options: [],
      handlers,
      classList: {
        add(name) { classes.add(name); },
        remove(name) { classes.delete(name); },
        contains(name) { return classes.has(name); },
      },
      addEventListener(name, handler) {
        handlers.set(name, [...(handlers.get(name) || []), handler]);
      },
      appendChild(child) { this.options.push(child); },
      closest() { return null; },
    };
    Object.defineProperty(node, 'innerHTML', {
      get() { return markup; },
      set(value) { markup = value; if (value === '') node.options = []; },
    });
    return node;
  }
  function node(id) {
    if (!nodes.has(id)) nodes.set(id, makeNode(id));
    return nodes.get(id);
  }
  const openButton = node('open-button');
  const document = {
    getElementById(id) { return node(id); },
    querySelector(selector) {
      return selector === '[data-action="open-zap-target-spider"]' ? openButton : null;
    },
    createElement(tag) { return makeNode('created-' + tag); },
    addEventListener(name, handler) {
      listeners.set(name, [...(listeners.get(name) || []), handler]);
    },
  };
  async function dispatch(target, name, extra = {}) {
    for (const handler of target.handlers.get(name) || []) {
      await handler({ target, preventDefault() {}, ...extra });
    }
  }
  async function dispatchDocument(name, event) {
    for (const handler of listeners.get(name) || []) await handler(event);
  }
  const response = body => ({ ok: true, status: 200, json: async () => body });
  const summary = {
    format: 'zap-target-spider-v1', profile: 'same-origin-root-spider-v1',
    site_count: 1, alert_type_count: 1, instance_count: 2,
    risk_counts: { informational: 0, low: 1, medium: 0, high: 0 },
    report_sha256: 'a'.repeat(64), elapsed_seconds: 1.2,
  };
  let activeResponse = summary;
  let deferred = null;
  async function fetch(path, options = {}) {
    requests.push({ path, options });
    if (path === '/api/targets') return response({ targets: [target] });
    if (path === '/api/engagements') return response({ engagements: [engagement] });
    if (path === '/api/tool-runs/zap-target-spider') {
      if (deferred) return deferred;
      return response(activeResponse);
    }
    throw new Error('unexpected fetch');
  }
  const context = vm.createContext({ document, fetch, Date, Number, Object, Array, Set, Promise, console, URL });
  vm.runInContext('const state = {}; const api = () => {}; const esc = () => {};', context);
  vm.runInContext(source, context, { filename: sourcePath });
  return {
    target, engagement, requests, node, dispatch, dispatchDocument, openButton, summary,
    setActiveResponse(value) { activeResponse = value; },
    setDeferred(value) { deferred = value; },
    async init() { await dispatchDocument('DOMContentLoaded', {}); },
    async open() { await dispatch(openButton, 'click'); await flush(); },
    async choose() {
      node('zap-target-spider-target').value = target.id;
      await dispatch(node('zap-target-spider-target'), 'change');
      node('zap-target-spider-engagement').value = engagement.id;
      await dispatch(node('zap-target-spider-engagement'), 'change');
    },
    async consent() {
      for (const id of ['zap-target-spider-consent-1', 'zap-target-spider-consent-2']) {
        node(id).checked = true;
        await dispatch(node(id), 'change');
      }
    },
    async submit() {
      await dispatch(node('zap-target-spider-form'), 'submit');
      await flush();
    },
    posts() { return requests.filter(item => item.path === '/api/tool-runs/zap-target-spider'); },
  };
}

test('spider UI is mounted separately from ZAP active launcher', () => {
  assert.match(html, /data-action="open-zap-target-spider"/);
  assert.match(html, /id="zap-target-spider-target"/);
  assert.match(html, /id="zap-target-spider-engagement"/);
  assert.match(html, /zap_target_spider\.js\?v=1/);
  assert.match(html, /ZAP izinli site bağlantı keşfi/);
  assert.match(html, /ZAP hedef aktif taraması/);
});

test('opening and missing consent never start an spider crawl', async () => {
  const f = fixture(); await f.init(); await f.open();
  assert.equal(f.posts().length, 0);
  assert.equal(f.node('zap-target-spider-modal').classList.contains('hidden'), false);
  await f.choose();
  assert.equal(f.node('zap-target-spider-target-url').textContent, f.target.url);
  assert.equal(f.node('zap-target-spider-auth-ref').textContent, 'AUTH-001');
  assert.equal(f.node('zap-target-spider-window').textContent, f.engagement.test_window);
  assert.equal(f.node('zap-target-spider-submit').disabled, true);
  await f.submit();
  assert.equal(f.posts().length, 0);
});

test('expired window, invalid exclusions, and target mismatch block POST', async () => {
  const cases = [
    { test_window: '2020-01-01T00:00:00Z/2020-01-01T00:10:00Z' },
    { out_of_scope: 'https://example.test/' },
    { out_of_scope: '[]' },
    { out_of_scope: '["/admin//users"]' },
    { out_of_scope: '["/admin","/admin"]' },
    { target_url: 'https://other.test/' },
  ];
  for (const value of cases) {
    const f = fixture(value); await f.init(); await f.open(); await f.choose(); await f.consent(); await f.submit();
    assert.equal(f.posts().length, 0);
    assert.equal(f.node('zap-target-spider-submit').disabled, true);
  }
});

test('valid explicit confirmations send exactly one four-field POST and show aggregate only', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.choose(); await f.consent();
  assert.equal(f.node('zap-target-spider-submit').disabled, false);
  await f.submit();
  assert.equal(f.posts().length, 1);
  assert.equal(f.posts()[0].options.method, 'POST');
  assert.deepEqual(JSON.parse(f.posts()[0].options.body), {
    target_id: 't-one', engagement_id: 'e-one', confirm_authorized: true, confirm_crawl: true,
  });
  assert.equal(f.node('zap-target-spider-result').classList.contains('hidden'), false);
  assert.equal(f.node('zap-target-spider-report-sha256').textContent, 'a'.repeat(64));
  assert.equal(f.node('zap-target-spider-consent-1').checked, false);
  assert.equal(f.node('zap-target-spider-consent-2').checked, false);
  assert.equal(f.node('zap-target-spider-submit').disabled, true);
});

test('unexpected private response field is not rendered', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.choose(); await f.consent();
  f.setActiveResponse({ ...f.summary, secret: 'PRIVATE_MARKER' });
  await f.submit();
  assert.equal(f.posts().length, 1);
  assert.equal(f.node('zap-target-spider-result').classList.contains('hidden'), true);
  const visible = [...['zap-target-spider-error', 'zap-target-spider-format', 'zap-target-spider-profile',
    'zap-target-spider-report-sha256'].map(id => f.node(id).textContent)].join(' ');
  assert.equal(visible.includes('PRIVATE_MARKER'), false);
});

test('invalid calendar date, missing scope, and paused engagement cannot launch', async () => {
  const cases = [
    { test_window: '2026-02-30T00:00:00Z/2026-03-01T00:10:00Z' },
    { scope_notes: ' ' },
    { status: 'paused' },
  ];
  for (const value of cases) {
    const f = fixture(value); await f.init(); await f.open(); await f.choose(); await f.consent(); await f.submit();
    assert.equal(f.posts().length, 0);
    assert.equal(f.node('zap-target-spider-submit').disabled, true);
  }
});

test('pending request cannot be sent twice, and close does not reveal a late result', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.choose(); await f.consent();
  let finish;
  f.setDeferred(new Promise(resolve => { finish = resolve; }));
  await f.submit();
  await f.submit();
  assert.equal(f.posts().length, 1);
  await f.dispatchDocument('click', {
    target: { closest(selector) {
      return selector === '[data-close="zap-target-spider-modal"]' ? this : null;
    } },
  });
  assert.equal(f.node('zap-target-spider-modal').classList.contains('hidden'), true);
  finish({ ok: true, json: async () => f.summary });
  await flush();
  assert.equal(f.node('zap-target-spider-result').classList.contains('hidden'), true);
});

test('server error text stays private and retry needs renewed confirmations', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.choose(); await f.consent();
  f.setDeferred(Promise.resolve({
    ok: false, status: 403, json: async () => ({ error: 'PRIVATE_AUTH_MARKER' }),
  }));
  await f.submit();
  assert.equal(f.posts().length, 1);
  assert.equal(f.node('zap-target-spider-error').textContent.includes('PRIVATE_AUTH_MARKER'), false);
  assert.equal(f.node('zap-target-spider-consent-1').checked, false);
  assert.equal(f.node('zap-target-spider-consent-2').checked, false);
  assert.equal(f.node('zap-target-spider-submit').disabled, true);
});


test('non-root target is excluded from selector and cannot launch', async () => {
  const f = fixture({}, 'https://example.test/admin'); await f.init(); await f.open();
  assert.equal(f.node('zap-target-spider-target').options.length, 1);
  await f.choose(); await f.consent(); await f.submit();
  assert.equal(f.posts().length, 0);
});

test('changing engagement clears previous consent and aggregate result', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.choose(); await f.consent(); await f.submit();
  assert.equal(f.node('zap-target-spider-result').classList.contains('hidden'), false);
  await f.dispatch(f.node('zap-target-spider-engagement'), 'change');
  assert.equal(f.node('zap-target-spider-result').classList.contains('hidden'), true);
  assert.equal(f.node('zap-target-spider-consent-1').checked, false);
  assert.equal(f.node('zap-target-spider-consent-2').checked, false);
  assert.equal(f.node('zap-target-spider-submit').disabled, true);
});


test('pending request locks selections and never re-labels its result', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.choose(); await f.consent();
  let finish;
  f.setDeferred(new Promise(resolve => { finish = resolve; }));
  await f.submit();
  assert.equal(f.node('zap-target-spider-target').disabled, true);
  assert.equal(f.node('zap-target-spider-engagement').disabled, true);
  f.node('zap-target-spider-target').value = '';
  await f.dispatch(f.node('zap-target-spider-target'), 'change');
  f.node('zap-target-spider-engagement').value = '';
  await f.dispatch(f.node('zap-target-spider-engagement'), 'change');
  assert.equal(f.node('zap-target-spider-target').value, f.target.id);
  assert.equal(f.node('zap-target-spider-engagement').value, f.engagement.id);
  finish({ ok: true, json: async () => f.summary });
  await flush();
  assert.equal(f.posts().length, 1);
  assert.equal(f.node('zap-target-spider-result').classList.contains('hidden'), false);
  assert.equal(f.node('zap-target-spider-target').disabled, false);
  assert.equal(f.node('zap-target-spider-engagement').disabled, false);
});
