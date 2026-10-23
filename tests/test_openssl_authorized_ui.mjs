import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/openssl_authorized_active.js', import.meta.url), 'utf8');
const html = fs.readFileSync(new URL('../static/index.html', import.meta.url), 'utf8');
const response = () => ({
  format: 'openssl-x509-authorized-v1', verification: 'passed',
  normalized_target: 'https://api.example.com:443', consent_version: 'authorized-tls-target-v1',
  validity: 'valid', not_before_utc: '2026-10-01T00:00:00Z',
  not_after_utc: '2027-10-01T00:00:00Z', days_until_expiry: 344,
  report_sha256: 'b'.repeat(64),
});

function fixture() {
  const nodes = new Map(), listeners = new Map(), requests = [];
  let result = response();
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(['hidden']), events = new Map();
    const value = { id, value: '', checked: false, disabled: false, textContent: '', events,
      classList: { add(c) { classes.add(c); }, remove(c) { classes.delete(c); }, contains(c) { return classes.has(c); } },
      addEventListener(type, cb) { events.set(type, [...(events.get(type) || []), cb]); },
      closest(selector) { return this.action && selector.includes(this.action) ? this : null; },
    };
    nodes.set(id, value); return value;
  }
  const document = {
    getElementById: node,
    addEventListener(type, cb) { listeners.set(type, [...(listeners.get(type) || []), cb]); },
  };
  async function fire(value, type) {
    for (const cb of value.events.get(type) || []) await cb({ target: value, preventDefault() {} });
  }
  async function doc(type, value) {
    for (const cb of listeners.get(type) || []) await cb({ target: value, preventDefault() {} });
  }
  const api = async (path, options) => { requests.push({ path, options }); return result; };
  vm.runInNewContext(source, { document, api, showModal() {}, Number, Object, JSON, Promise });
  const open = node('open'); open.action = 'open-openssl-authorized';
  return { node, requests, fire, doc, open, setResponse(value) { result = value; } };
}

test('authorized TLS UI is separate and opening or typing never connects', async () => {
  assert.match(html, /openssl_authorized_active\.js\?v=1/);
  assert.match(html, /id="openssl-authorized-modal"/);
  assert.match(html, /id="openssl-authorized-consent"[^>]*type="checkbox"/);
  const f = fixture();
  await f.doc('click', f.open);
  f.node('openssl-authorized-target').value = 'https://api.example.com';
  await f.fire(f.node('openssl-authorized-target'), 'input');
  assert.equal(f.requests.length, 0);
  assert.equal(f.node('openssl-authorized-submit').disabled, true);
});

test('exact UI authorization sends one general target request and renders normalized receipt', async () => {
  const f = fixture();
  await f.doc('click', f.open);
  f.node('openssl-authorized-target').value = 'https://Api.Example.COM';
  await f.fire(f.node('openssl-authorized-target'), 'input');
  f.node('openssl-authorized-consent').checked = true;
  await f.fire(f.node('openssl-authorized-consent'), 'change');
  await f.fire(f.node('openssl-authorized-form'), 'submit');
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].path, '/api/tool-runs/openssl-x509-authorized');
  assert.deepEqual(JSON.parse(f.requests[0].options.body), {
    confirm_authorized: true, target: 'https://Api.Example.COM',
  });
  assert.equal(f.node('openssl-authorized-normalized').textContent, 'https://api.example.com:443');
  assert.equal(f.node('openssl-authorized-validity').textContent, 'Doğrulandı · geçerli');
  assert.equal(f.node('openssl-authorized-consent').checked, false);
});

test('invalid UI target never connects and hostile response is not rendered', async () => {
  const f = fixture();
  await f.doc('click', f.open);
  f.node('openssl-authorized-target').value = 'http://example.com';
  f.node('openssl-authorized-consent').checked = true;
  await f.fire(f.node('openssl-authorized-consent'), 'change');
  await f.fire(f.node('openssl-authorized-form'), 'submit');
  assert.equal(f.requests.length, 0);

  f.node('openssl-authorized-target').value = 'https://example.com';
  await f.fire(f.node('openssl-authorized-target'), 'input');
  f.setResponse({ ...response(), normalized_target: '<PRIVATE>' });
  await f.fire(f.node('openssl-authorized-form'), 'submit');
  assert.equal(f.node('openssl-authorized-result').classList.contains('hidden'), true);
  assert.doesNotMatch(f.node('openssl-authorized-error').textContent, /PRIVATE/);
});
