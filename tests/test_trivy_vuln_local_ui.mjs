import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import vm from 'node:vm';

const appJs = new URL('../static/app.js', import.meta.url).pathname;
const htmlPath = new URL('../static/index.html', import.meta.url).pathname;

const summary = () => ({
  format: 'trivy-native-json',
  schema_version: 2,
  profile: 'local-python-requirements-v1',
  result_count: 1,
  class_counts: {'os-pkgs':0, 'lang-pkgs':1, config:0, secret:0, license:0, 'license-file':0, crypto:0, custom:0, unknown:0},
  vuln_counts: {critical:0, high:0, medium:1, low:0, unknown:0},
  misconfig_sev_counts: {critical:0, high:0, medium:0, low:0, unknown:0},
  finding_counts: {vulnerabilities:1, misconfigurations:0, secrets:0, licenses:0},
  report_sha256: 'a'.repeat(64),
});

function setup(scanResponse = summary()) {
  const nodes = new Map();
  const listeners = new Map();
  const requests = [];
  const node = key => {
    if (nodes.has(key)) return nodes.get(key);
    const classes = new Set(['hidden']);
    const el = {
      id: key.replace(/^#/, ''), dataset: {}, style: {}, value: '', checked: false,
      disabled: false, textContent: '', innerHTML: '', files: [],
      handlers: new Map(),
      classList: {
        add: name => classes.add(name),
        remove: name => classes.delete(name),
        contains: name => classes.has(name),
        toggle(name, force) { if (force ?? !classes.has(name)) classes.add(name); else classes.delete(name); },
      },
      addEventListener(type, fn) {
        const entries = this.handlers.get(type) || [];
        entries.push(fn);
        this.handlers.set(type, entries);
      },
      append() {}, appendChild() {}, replaceChildren() {}, remove() {}, focus() {},
      reset() {}, setAttribute() {}, removeAttribute() {}, setSelectionRange() {},
      querySelector: selector => node(selector), querySelectorAll: () => [], closest: () => null,
    };
    nodes.set(key, el);
    return el;
  };
  const document = {
    body: node('body'), querySelector: node, querySelectorAll: () => [],
    getElementById: id => node('#' + id), createElement: tag => node('created:' + tag),
    addEventListener(type, fn) {
      const entries = listeners.get(type) || [];
      entries.push(fn);
      listeners.set(type, entries);
    },
  };
  async function fetch(path, options = {}) {
    requests.push({ path, options });
    const defaults = {
      '/api/dashboard': {},
      '/api/targets': {targets:[]},
      '/api/scans?limit=200': {scans:[]},
      '/api/engagements': {engagements:[]},
      '/api/lab-runs': {lab_runs:[]},
      '/api/project-audits': {project_audits:[], total:0},
      '/api/tooling': {tools:[], categories:[], summary:{}, policy:{}},
      '/api/dependency-security': {},
    };
    const data = path === '/api/tool-runs/trivy-vulnerability' ? scanResponse : (defaults[path] || {});
    return {ok:true, status:200, json:async () => data};
  }
  const context = vm.createContext({
    document, window:{addEventListener(){}}, location:{hash:''},
    history:{replaceState(){}}, fetch, TextEncoder, URL, console,
    setTimeout:() => 0, clearTimeout(){}, setInterval:() => 0,
  });
  vm.runInContext(fs.readFileSync(appJs, 'utf8'), context, {filename:appJs});
  return {node, requests};
}

async function submit(form) {
  for (const fn of form.handlers.get('submit') || []) {
    await fn({preventDefault(){}, target:form});
  }
  await new Promise(resolve => setImmediate(resolve));
}

test('local Trivy vulnerability form states its exact scope and has consent control', () => {
  const html = fs.readFileSync(htmlPath, 'utf8');
  for (const id of ['trivy-vuln-local-form', 'trivy-vuln-local-path', 'trivy-vuln-local-consent',
    'trivy-vuln-local-submit', 'trivy-vuln-local-error', 'trivy-vuln-local-result',
    'trivy-vuln-local-groups', 'trivy-vuln-local-total', 'trivy-vuln-local-severity', 'trivy-vuln-local-hash']) {
    assert.match(html, new RegExp('id=["\\x27]' + id + '["\\x27]'));
  }
  assert.match(html, /requirements\.txt/);
  assert.match(html, /type="checkbox" required/);
  assert.match(html, /type="submit" disabled/);
});

test('explicit consent gates exact local-only request and aggregate display', async () => {
  const {node, requests} = setup();
  const form = node('#trivy-vuln-local-form');
  const consent = node('#trivy-vuln-local-consent');
  node('#trivy-vuln-local-path').value = '/home/community-user/my-project';
  await submit(form);
  assert.equal(requests.filter(x => x.path === '/api/tool-runs/trivy-vulnerability').length, 0);
  consent.checked = true;
  for (const fn of consent.handlers.get('change') || []) fn();
  assert.equal(node('#trivy-vuln-local-submit').disabled, false);
  await submit(form);
  const posts = requests.filter(x => x.path === '/api/tool-runs/trivy-vulnerability' && x.options.method === 'POST');
  assert.equal(posts.length, 1);
  assert.deepEqual(JSON.parse(posts[0].options.body), {confirm_local:true, project_path:'/home/community-user/my-project'});
  assert.equal(node('#trivy-vuln-local-groups').textContent, '1');
  assert.equal(node('#trivy-vuln-local-total').textContent, '1');
  assert.equal(node('#trivy-vuln-local-severity').textContent, 'critical:0 high:0 medium:1 low:0 unknown:0');
  assert.equal(node('#trivy-vuln-local-hash').textContent, 'a'.repeat(64));
  assert.equal(node('#trivy-vuln-local-result').classList.contains('hidden'), false);
});

test('empty path is blocked even when consent is set', async () => {
  const {node, requests} = setup();
  node('#trivy-vuln-local-consent').checked = true;
  node('#trivy-vuln-local-path').value = '   ';
  await submit(node('#trivy-vuln-local-form'));
  assert.equal(requests.filter(x => x.path === '/api/tool-runs/trivy-vulnerability').length, 0);
  assert.equal(node('#trivy-vuln-local-error').classList.contains('hidden'), false);
});

test('unexpected response field is rejected without rendering private content', async () => {
  const privateMarker = 'PRIVATE_PACKAGE_AND_PATH_MARKER';
  const response = summary();
  response.package_names = [privateMarker];
  const {node} = setup(response);
  node('#trivy-vuln-local-consent').checked = true;
  node('#trivy-vuln-local-path').value = '/home/community-user/private';
  await submit(node('#trivy-vuln-local-form'));
  assert.equal(node('#trivy-vuln-local-result').classList.contains('hidden'), true);
  const visible = ['trivy-vuln-local-error','trivy-vuln-local-groups','trivy-vuln-local-total',
    'trivy-vuln-local-severity','trivy-vuln-local-hash'].map(id => node('#' + id).textContent).join(' ');
  assert.equal(visible.includes(privateMarker), false);
  assert.equal(node('#trivy-vuln-local-error').classList.contains('hidden'), false);
});

test('malformed counts are rejected before showing a result', async () => {
  const response = summary();
  response.class_counts['lang-pkgs'] = 2;
  const {node} = setup(response);
  node('#trivy-vuln-local-consent').checked = true;
  node('#trivy-vuln-local-path').value = '/home/community-user/local';
  await submit(node('#trivy-vuln-local-form'));
  assert.equal(node('#trivy-vuln-local-result').classList.contains('hidden'), true);
  assert.equal(node('#trivy-vuln-local-error').classList.contains('hidden'), false);
});

test('completed scan consumes consent and cannot silently repeat', async () => {
  const {node, requests} = setup();
  node('#trivy-vuln-local-consent').checked = true;
  node('#trivy-vuln-local-path').value = '/home/community-user/local';
  await submit(node('#trivy-vuln-local-form'));
  assert.equal(node('#trivy-vuln-local-consent').checked, false);
  assert.equal(node('#trivy-vuln-local-submit').disabled, true);
  await submit(node('#trivy-vuln-local-form'));
  assert.equal(requests.filter(x => x.path === '/api/tool-runs/trivy-vulnerability').length, 1);
});

test('a non-string digest is rejected', async () => {
  const response = summary();
  response.report_sha256 = ['a'.repeat(64)];
  const {node} = setup(response);
  node('#trivy-vuln-local-consent').checked = true;
  node('#trivy-vuln-local-path').value = '/home/community-user/local';
  await submit(node('#trivy-vuln-local-form'));
  assert.equal(node('#trivy-vuln-local-result').classList.contains('hidden'), true);
  assert.equal(node('#trivy-vuln-local-error').classList.contains('hidden'), false);
});
