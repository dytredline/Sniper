import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const appRoot = process.env.SNIPER_UI_TEST_APP_ROOT || '';
const appPath = appRoot ? `${appRoot}/static/app.js` : new URL('../static/app.js', import.meta.url).pathname;
const htmlPath = appRoot ? `${appRoot}/static/index.html` : new URL('../static/index.html', import.meta.url).pathname;
const app = fs.readFileSync(appPath, 'utf8');
const marker = '// Direct SSL Labs authorization: one human checkbox, no automatic request.';
const section = app.slice(app.indexOf(marker));

function fixture() {
  const nodes = new Map();
  const handlers = new Map();
  const requests = [];
  function node(id) {
    if (!nodes.has(id)) {
      const classes = new Set(['hidden']);
      nodes.set(id, {
        id, value: '', checked: false, disabled: false, textContent: '',
        classList: {
          add(value) { classes.add(value); },
          remove(value) { classes.delete(value); },
          contains(value) { return classes.has(value); },
        },
      });
    }
    return nodes.get(id);
  }
  const document = {
    getElementById: node,
    addEventListener(name, fn) {
      if (!handlers.has(name)) handlers.set(name, []);
      handlers.get(name).push(fn);
    },
  };
  async function api(path, options = {}) {
    requests.push({path, body: JSON.parse(options.body)});
    return {
      format: 'ssllabs-v4-host', assessment_status: 'READY', endpoint_count: 1,
      grade_counts: {'A+': 0, A: 1, 'A-': 0, B: 0, C: 0, D: 0, E: 0, F: 0, T: 0, M: 0},
      report_sha256: 'a'.repeat(64),
      authorization_receipt: {
        consent_version: 'ssllabs-third-party-authorization-v1',
        confirm_authorized: true, normalized_target: 'example.com',
        third_party: 'Qualys SSL Labs', confirmed_at: '2026-10-22T12:00:00+00:00',
      },
    };
  }
  const context = vm.createContext({document, api, showModal() {}, console});
  vm.runInContext(section, context);
  return {node, handlers, requests};
}

async function dispatch(fixture, name, event) {
  for (const handler of fixture.handlers.get(name) || []) await handler(event);
  await new Promise(resolve => setImmediate(resolve));
}

test('modal has exactly one checkbox that states authorization and Qualys disclosure', () => {
  const html = fs.readFileSync(htmlPath, 'utf8');
  const start = html.indexOf('id="ssllabs-authorized-modal"');
  const end = html.indexOf('</div>\n</div>', start) + 12;
  const modal = html.slice(start, end);
  assert.ok(start >= 0);
  assert.equal((modal.match(/type="checkbox"/g) || []).length, 1);
  assert.match(modal, /yetkili olduğumu/i);
  assert.match(modal, /Qualys SSL Labs üçüncü taraf hizmetine gönderileceğini/i);
});

test('loading and opening the modal do not make a request', async () => {
  const f = fixture();
  assert.equal(f.requests.length, 0);
  await dispatch(f, 'click', {
    preventDefault() {},
    target: {id: '', closest: () => ({dataset: {action: 'open-ssllabs-authorized'}})},
  });
  assert.equal(f.requests.length, 0);
});

test('submit sends only the target and exact human consent', async () => {
  const f = fixture();
  f.node('ssllabs-authorized-target').value = 'Example.COM.';
  f.node('ssllabs-authorized-confirm').checked = true;
  await dispatch(f, 'change', {target: f.node('ssllabs-authorized-confirm')});
  await dispatch(f, 'submit', {
    preventDefault() {}, target: f.node('ssllabs-authorized-form'),
  });
  assert.deepEqual(f.requests, [{
    path: '/api/tool-runs/ssllabs-authorized',
    body: {target: 'Example.COM.', confirm_authorized: true},
  }]);
  assert.equal(f.node('ssllabs-authorized-confirm').checked, false);
  assert.equal(f.node('ssllabs-authorized-status').textContent, 'READY');
  assert.equal(f.node('ssllabs-authorized-confirmed-at').textContent, '2026-10-22T12:00:00+00:00');
});

test('editing the target revokes consent and prevents submit', async () => {
  const f = fixture();
  f.node('ssllabs-authorized-target').value = 'first.example';
  f.node('ssllabs-authorized-confirm').checked = true;
  await dispatch(f, 'input', {target: f.node('ssllabs-authorized-target')});
  await dispatch(f, 'submit', {
    preventDefault() {}, target: f.node('ssllabs-authorized-form'),
  });
  assert.equal(f.node('ssllabs-authorized-confirm').checked, false);
  assert.equal(f.requests.length, 0);
});
