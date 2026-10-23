import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/openssl_loopback_active.js', import.meta.url), 'utf8');
const html = fs.readFileSync(new URL('../static/index.html', import.meta.url), 'utf8');
const result = () => ({
  format: 'openssl-x509-loopback-v1', verification: 'passed', validity: 'expiring_soon',
  not_before_utc: '2026-10-01T00:00:00Z', not_after_utc: '2026-10-15T00:00:00Z',
  days_until_expiry: 2, report_sha256: 'a'.repeat(64),
});

function fixture() {
  const nodes = new Map(), listeners = new Map(), requests = [], modal = [];
  let response = result();
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(['hidden']), events = new Map();
    const n = { id, value: '', checked: false, disabled: false, textContent: '', events,
      classList: { add(c) { classes.add(c); }, remove(c) { classes.delete(c); }, contains(c) { return classes.has(c); } },
      addEventListener(t, cb) { events.set(t, [...(events.get(t) || []), cb]); },
      closest(selector) { return this.action && selector.includes(this.action) ? this : null; },
    };
    nodes.set(id, n); return n;
  }
  const document = {
    getElementById: node,
    addEventListener(t, cb) { listeners.set(t, [...(listeners.get(t) || []), cb]); },
  };
  async function fire(n, t) { for (const cb of n.events.get(t) || []) await cb({ target: n, preventDefault() {} }); }
  async function doc(t, n) { for (const cb of listeners.get(t) || []) await cb({ target: n, preventDefault() {} }); }
  const api = async (path, options) => { requests.push({ path, options }); return typeof response === 'function' ? response() : response; };
  vm.runInNewContext(source, { document, api, showModal: (...args) => modal.push(args),
    Number, Object, JSON, Promise });
  const open = node('open'); open.action = 'open-openssl-loopback';
  return { node, requests, modal, fire, doc, open, setResponse(v) { response = v; },
    async submit() { await fire(node('openssl-loopback-form'), 'submit'); },
    async input(v) { node('openssl-loopback-target').value = v; await fire(node('openssl-loopback-target'), 'input'); },
    async consent() { node('openssl-loopback-consent').checked = true; await fire(node('openssl-loopback-consent'), 'change'); },
  };
}

test('separate local launcher and opening or typing never connects', async () => {
  assert.match(html, /openssl_loopback_active\.js\?v=1/);
  assert.match(html, /id="openssl-loopback-modal"/);
  assert.match(html, /id="openssl-loopback-consent"/);
  const f = fixture(); await f.doc('click', f.open); await f.input('127.0.0.1:443');
  assert.equal(f.requests.length, 0);
  assert.equal(f.node('openssl-loopback-submit').disabled, true);
});

test('explicit consent only sends literal loopback and renders aggregate result', async () => {
  const f = fixture(); await f.doc('click', f.open); await f.input('127.0.0.1:443'); await f.consent();
  await f.submit();
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].path, '/api/tool-runs/openssl-x509-loopback');
  assert.deepEqual(JSON.parse(f.requests[0].options.body), { confirm_local: true, target: '127.0.0.1:443' });
  assert.equal(f.node('openssl-loopback-validity').textContent, 'Doğrulandı · yakında bitecek');
  assert.equal(f.node('openssl-loopback-sha').textContent, 'a'.repeat(64));
  assert.equal(f.node('openssl-loopback-target').value, '');
  assert.equal(f.node('openssl-loopback-consent').checked, false);
  assert.equal(f.node('openssl-loopback-result').classList.contains('hidden'), false);
});

test('invalid target and absent consent do not connect', async () => {
  const f = fixture(); await f.doc('click', f.open);
  for (const bad of ['https://example.com', '127.0.0.1:0', '127.0.0.1:65536', 'localhost:443']) {
    await f.input(bad); await f.consent(); await f.submit();
    assert.equal(f.requests.length, 0, bad);
  }
});

test('rejected and hostile responses never echo private data', async () => {
  const f = fixture(); await f.doc('click', f.open); await f.input('127.0.0.1:443'); await f.consent();
  f.setResponse({ format: 'openssl-x509-loopback-v1', verification: 'rejected' }); await f.submit();
  assert.equal(f.node('openssl-loopback-validity').textContent, 'Zincir veya IP kimliği doğrulanamadı');
  await f.input('127.0.0.1:443'); await f.consent();
  f.setResponse({ ...result(), validity: '<PRIVATE-CERT>' }); await f.submit();
  assert.equal(f.node('openssl-loopback-result').classList.contains('hidden'), true);
  assert.doesNotMatch(f.node('openssl-loopback-error').textContent, /PRIVATE/);
});

test('concurrent submit and late result after close are suppressed', async () => {
  const f = fixture(); let release;
  f.setResponse(() => new Promise(resolve => { release = resolve; }));
  await f.doc('click', f.open); await f.input('127.0.0.1:443'); await f.consent();
  const first = f.submit(); assert.equal(f.requests.length, 1);
  await f.submit(); assert.equal(f.requests.length, 1);
  await f.doc('click', f.node('openssl-loopback-modal'));
  release(result()); await first;
  assert.equal(f.node('openssl-loopback-result').classList.contains('hidden'), true);
  assert.equal(f.node('openssl-loopback-consent').checked, false);
});
