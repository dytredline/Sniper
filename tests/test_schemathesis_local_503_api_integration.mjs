import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

const appSource = readFileSync(new URL('../static/app.js', import.meta.url), 'utf8');
const localSource = readFileSync(new URL('../static/schemathesis_local.js', import.meta.url), 'utf8');

// Evaluate the exact installed helper body without booting the rest of app.js.
const apiStart = appSource.indexOf('async function api(path, options = {}) {');
const apiEnd = appSource.indexOf('\n\nfunction toast(', apiStart);
assert.ok(apiStart >= 0 && apiEnd > apiStart, 'real app.js api() helper must be extractable');
const realApiSource = appSource.slice(apiStart, apiEnd).trim();

function setup(
  status,
  serverDetail,
  {
    runtime = 'precheck_passed',
    action = 'local_input_required',
    profileRoute = '/api/tool-runs/schemathesis-local',
    profiles = null,
  } = {},
) {
  const requests = [];
  const modals = [];
  const opener = {
    id: 'schemathesis-top-action', disabled: false, title: '',
    closest(selector) { return selector.includes('open-schemathesis-local') ? this : null; },
  };
  const fetch = async (path, options) => {
    requests.push([path, options]);
    if (path === '/api/tooling/readiness') {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          tools: [{
            id: 'schemathesis',
            profiles: profiles ?? [{ route: profileRoute, runtime, action }],
          }],
        }),
      };
    }
    return { ok: false, status, json: async () => ({ error: serverDetail }) };
  };
  const api = vm.runInNewContext(`${realApiSource}\napi`, { fetch });
  const nodes = new Map();
  const listeners = new Map();
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(['hidden']);
    const item = {
      id, value: '', checked: false, disabled: false, textContent: '',
      classList: {
        add(name) { classes.add(name); },
        remove(name) { classes.delete(name); },
        contains(name) { return classes.has(name); },
      },
      querySelector() { return node('submit-button'); },
    };
    nodes.set(id, item);
    return item;
  }
  const document = {
    getElementById: node,
    querySelectorAll(selector) {
      return selector === '[data-action="open-schemathesis-local"]' ? [opener] : [];
    },
    addEventListener(name, callback) {
      const group = listeners.get(name) || [];
      group.push(callback);
      listeners.set(name, group);
    },
  };
  vm.runInNewContext(localSource, {
    document, TextEncoder, api,
    showModal(id, visible) { modals.push([id, visible]); },
  });
  async function ready() {
    await new Promise(resolve => setImmediate(resolve));
  }
  async function clickOpener() {
    for (const callback of listeners.get('click') || []) {
      await callback({ target: opener, preventDefault() {} });
    }
  }
  function readinessGets() {
    return requests.filter(([path]) => path === '/api/tooling/readiness');
  }
  function posts() {
    return requests.filter(([path]) => path === '/api/tool-runs/schemathesis-local');
  }
  async function submit() {
    await ready();
    node('schemathesis-local-schema').value = '{"openapi":"3.0.3"}';
    node('schemathesis-local-consent').checked = true;
    for (const callback of listeners.get('submit') || []) {
      await callback({ target: node('schemathesis-local-form'), preventDefault() {} });
    }
    assert.equal(posts().length, 1);
    assert.equal(posts()[0][0], '/api/tool-runs/schemathesis-local');
    assert.deepEqual(JSON.parse(posts()[0][1].body), {
      confirm_local: true, schema: { openapi: '3.0.3' },
    });
    assert.equal(node('schemathesis-local-error').classList.contains('hidden'), false);
    assert.equal(node('schemathesis-local-result').classList.contains('hidden'), true);
    assert.equal(node('submit-button').disabled, false);
    return node('schemathesis-local-error').textContent;
  }
  return {
    node, opener, modals, requests, readinessGets, posts, ready, clickOpener, submit,
    async submitRaw() {
      node('schemathesis-local-schema').value = '{"openapi":"3.0.3"}';
      node('schemathesis-local-consent').checked = true;
      for (const callback of listeners.get('submit') || []) {
        await callback({ target: node('schemathesis-local-form'), preventDefault() {} });
      }
    },
  };
}

test('real app.js api() completes readiness GET then propagates 503 to the local form without disclosing server detail', async () => {
  const harness = setup(503, 'Schemathesis local fixture is unavailable or busy. PRIVATE_URL=https://secret.invalid');
  await harness.ready();
  assert.equal(harness.readinessGets().length, 1);
  assert.equal(harness.opener.disabled, false);
  await harness.clickOpener();
  assert.deepEqual(harness.modals, [['schemathesis-local-modal', true]]);
  assert.equal(harness.posts().length, 0);
  const message = await harness.submit();
  assert.match(message, /kullanılamıyor veya meşgul/i);
  assert.doesNotMatch(message, /PRIVATE_URL|secret\.invalid|fixture/i);
});

test('real app.js api() keeps non-503 local failures generic', async () => {
  const message = await setup(502, 'PRIVATE_URL=https://secret.invalid').submit();
  assert.equal(message, 'Yerel sentetik test çalıştırılamadı. Girdi, kurulum veya sınırları denetleyin.');
});

test('real app.js api() readiness GET keeps missing or unknown profiles disabled without unintended POST', async () => {
  for (const options of [
    { profiles: [] },
    { runtime: 'unknown' },
    { action: 'unknown' },
    { profileRoute: '/api/tool-runs/schemathesis-loopback' },
  ]) {
    const harness = setup(503, 'PRIVATE_URL=https://secret.invalid', options);
    await harness.ready();
    assert.equal(harness.readinessGets().length, 1);
    assert.equal(harness.opener.disabled, true);
    assert.equal(harness.opener.title, 'Sentetik yerel testin çalışma zamanı hazır değil.');
    await harness.clickOpener();
    assert.equal(harness.modals.length, 0);
    await harness.submitRaw();
    assert.equal(harness.posts().length, 0);
    assert.equal(harness.node('submit-button').disabled, true);
  }
});
