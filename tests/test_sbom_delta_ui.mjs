import fs from 'node:fs';
import vm from 'node:vm';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

const appPath = process.env.SNIPER_UI_APP_JS || new URL('../static/app.js', import.meta.url).pathname;
const htmlPath = new URL('../static/index.html', import.meta.url).pathname;

function browser(sboms, deltaReply) {
  const elements = new Map();
  const listeners = new Map();
  const requests = [];

  function node(selector) {
    if (elements.has(selector)) return elements.get(selector);
    const classes = new Set();
    const result = {
      id: selector.replace(/^#/, ''), dataset: {}, style: {}, value: '', files: [],
      innerHTML: '', textContent: '', disabled: false,
      classList: {
        add: value => classes.add(value),
        remove: value => classes.delete(value),
        contains: value => classes.has(value),
        toggle(value, force) {
          if (force === undefined ? !classes.has(value) : force) classes.add(value);
          else classes.delete(value);
        },
      },
      addEventListener(name, callback) {
        this.handlers ??= new Map();
        const callbacks = this.handlers.get(name) || [];
        callbacks.push(callback);
        this.handlers.set(name, callbacks);
      },
      append() {}, appendChild() {}, remove() {}, focus() {}, reset() {},
      setSelectionRange() {}, setAttribute() {}, removeAttribute() {},
      querySelector: child => node(child), querySelectorAll: () => [],
      closest: () => null,
    };
    elements.set(selector, result);
    return result;
  }

  const document = {
    body: node('body'),
    querySelector: selector => node(selector), querySelectorAll: () => [],
    getElementById: id => node('#' + id), createElement: tag => node('created:' + tag),
    addEventListener(name, callback) {
      const callbacks = listeners.get(name) || [];
      callbacks.push(callback);
      listeners.set(name, callbacks);
    },
  };
  node('#sbom-delta-result').classList.add('hidden');
  node('#sbom-delta-error').classList.add('hidden');
  const empty = {
    '/api/dashboard': {}, '/api/targets': { targets: [] },
    '/api/scans?limit=200': { scans: [] }, '/api/engagements': { engagements: [] },
    '/api/lab-runs': { lab_runs: [] },
    '/api/project-audits': { project_audits: [], total: 0 },
    '/api/tooling': { tools: [], categories: [], summary: {}, policy: {} },
  };
  async function fetch(path, options = {}) {
    requests.push({ path, options });
    if (path === '/api/dependency-security') {
      return { ok: true, status: 200, json: async () => ({ sboms, imports: [], findings: [], summary: {} }) };
    }
    if (path.startsWith('/api/dependency-sboms/') && path.includes('/delta/')) {
      return { ok: deltaReply.ok ?? true, status: deltaReply.status ?? 200, json: async () => deltaReply.body };
    }
    return { ok: true, status: 200, json: async () => empty[path] || {} };
  }
  const context = vm.createContext({
    document, window: { addEventListener() {} }, location: { hash: '' },
    history: { replaceState() {} }, fetch, TextEncoder, URL, console,
    setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0,
  });
  vm.runInContext(fs.readFileSync(appPath, 'utf8'), context, { filename: appPath });
  async function loaded() { await new Promise(resolve => setImmediate(resolve)); }
  async function submit(selector) {
    const currentTarget = node(selector);
    for (const handler of currentTarget.handlers?.get('submit') || []) {
      await handler({ currentTarget, preventDefault() {} });
    }
  }
  return { node, requests, loaded, submit };
}

const sboms = [
  { id: 'sbom-before', project_path: '/safe/a', project_name: 'A', component_count: 1, created_at: '2026-10-09T10:00:00Z' },
  { id: 'sbom-after', project_path: '/safe/a', project_name: 'A', component_count: 2, created_at: '2026-10-09T11:00:00Z' },
  { id: 'sbom-other', project_path: '/safe/b', project_name: 'B', component_count: 3, created_at: '2026-10-09T12:00:00Z' },
];

describe('saved SBOM delta browser flow', () => {
  it('renders only same-project choices and fetches only after explicit valid submission', async () => {
    const html = fs.readFileSync(htmlPath, 'utf8');
    for (const id of ['sbom-delta-form', 'sbom-delta-before', 'sbom-delta-after', 'sbom-delta-result']) {
      assert.ok(html.includes(`id="${id}"`), `${id} missing from HTML`);
    }
    const ui = browser(sboms, { body: {
      before_id: 'sbom-before', after_id: 'sbom-after', project_path: '/safe/a',
      summary: { added: 2, removed: 1, changed: 3 },
      added: [{ purl: 'PRIVATE_PACKAGE_SHOULD_NOT_RENDER' }],
      removed: [], changed: [], document: 'PRIVATE_DOCUMENT_SHOULD_NOT_RENDER',
    } });
    await ui.loaded();
    assert.match(ui.node('#sbom-delta-before').innerHTML, /sbom-before/);
    assert.match(ui.node('#sbom-delta-before').innerHTML, /sbom-after/);
    assert.doesNotMatch(ui.node('#sbom-delta-before').innerHTML, /sbom-other/);
    assert.equal(ui.requests.filter(item => item.path.includes('/delta/')).length, 0);
    ui.node('#sbom-delta-before').value = 'sbom-before';
    ui.node('#sbom-delta-after').value = 'sbom-after';
    await ui.submit('#sbom-delta-form');
    assert.equal(ui.requests.filter(item => item.path === '/api/dependency-sboms/sbom-before/delta/sbom-after').length, 1);
    assert.equal(ui.node('#sbom-delta-added').textContent, '2');
    assert.equal(ui.node('#sbom-delta-removed').textContent, '1');
    assert.equal(ui.node('#sbom-delta-changed').textContent, '3');
    assert.equal(ui.node('#sbom-delta-result').classList.contains('hidden'), false);
    const rendered = ['#sbom-delta-result', '#sbom-delta-added', '#sbom-delta-removed', '#sbom-delta-changed']
      .map(id => ui.node(id).innerHTML + ui.node(id).textContent).join(' ');
    assert.doesNotMatch(rendered, /PRIVATE_PACKAGE_SHOULD_NOT_RENDER|PRIVATE_DOCUMENT_SHOULD_NOT_RENDER/);
  });

  it('rejects identical and cross-project selections before a network request', async () => {
    const ui = browser(sboms, { body: {} });
    await ui.loaded();
    ui.node('#sbom-delta-before').value = 'sbom-before';
    ui.node('#sbom-delta-after').value = 'sbom-before';
    await ui.submit('#sbom-delta-form');
    ui.node('#sbom-delta-after').value = 'sbom-other';
    await ui.submit('#sbom-delta-form');
    assert.equal(ui.requests.filter(item => item.path.includes('/delta/')).length, 0);
    assert.equal(ui.node('#sbom-delta-error').classList.contains('hidden'), false);
  });

  it('rejects a mismatched server response without rendering the result', async () => {
    const ui = browser(sboms, { body: {
      before_id: 'sbom-before', after_id: 'sbom-other', project_path: '/safe/b',
      summary: { added: 999, removed: 999, changed: 999 },
    } });
    await ui.loaded();
    ui.node('#sbom-delta-before').value = 'sbom-before';
    ui.node('#sbom-delta-after').value = 'sbom-after';
    await ui.submit('#sbom-delta-form');
    assert.equal(ui.node('#sbom-delta-result').classList.contains('hidden'), true);
    assert.equal(ui.node('#sbom-delta-error').classList.contains('hidden'), false);
  });

  it('requires at least two snapshots from one project', async () => {
    const ui = browser([sboms[0], sboms[2]], { body: {} });
    await ui.loaded();
    assert.equal(ui.node('#sbom-delta-submit').disabled, true);
    assert.equal(ui.requests.filter(item => item.path.includes('/delta/')).length, 0);
  });
});
