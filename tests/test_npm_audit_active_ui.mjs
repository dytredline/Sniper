import assert from 'node:assert/strict';
import {test} from 'node:test';
import fs from 'node:fs';
import vm from 'node:vm';

const script = new URL('../static/npm_audit_active.js', import.meta.url).pathname;
const htmlPath = new URL('../static/index.html', import.meta.url).pathname;
const validResponse = () => ({
  format: 'npm-audit-v2', profile: 'local-npm-audit-v1', affected_package_count: 1,
  package_severity_counts: {info:0, low:0, moderate:0, high:1, critical:0},
  report_sha256: 'a'.repeat(64),
});

function setup(reply = validResponse()) {
  const nodes = new Map();
  const requests = [];
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(['hidden']);
    const value = {id, value:'', checked:false, disabled:false, textContent:'', handlers:new Map(),
      classList:{add:key=>classes.add(key), remove:key=>classes.delete(key), contains:key=>classes.has(key)},
      addEventListener(type, fn) {this.handlers.set(type, [...(this.handlers.get(type) || []), fn]);}};
    nodes.set(id, value);
    return value;
  }
  const document = {
    getElementById: node,
    querySelector(selector) {
      return selector === 'meta[name="sniper-local-home"]' ? {content:'/home/community-user'} : null;
    },
  };
  async function api(path, options) {
    requests.push({path, options});
    if (reply instanceof Error) throw reply;
    return reply;
  }
  vm.runInNewContext(fs.readFileSync(script, 'utf8'), {document, api, Object}, {filename:script});
  async function submit() {
    const form = node('npm-audit-active-form');
    for (const handler of form.handlers.get('submit') || []) await handler({preventDefault(){}});
  }
  const approve = () => {
    node('npm-audit-active-local-consent').checked = true;
    node('npm-audit-active-registry-consent').checked = true;
    for (const id of ['npm-audit-active-local-consent','npm-audit-active-registry-consent'])
      for (const handler of node(id).handlers.get('change') || []) handler();
  };
  return {node, requests, submit, approve};
}

test('active panel has separate local and registry consent with exact disclosure', () => {
  const html = fs.readFileSync(htmlPath, 'utf8');
  for (const id of ['npm-audit-active-form','npm-audit-active-path','npm-audit-active-local-consent',
      'npm-audit-active-registry-consent','npm-audit-active-submit','npm-audit-active-error',
      'npm-audit-active-result','npm-audit-active-count','npm-audit-active-severity','npm-audit-active-hash']) {
    assert.match(html, new RegExp('id="' + id + '"'));
  }
  assert.match(html, /resmî npm registry güvenlik bildirimlerini sorgular/);
  assert.match(html, /Paket kurulmaz, düzeltme veya proje betiği çalıştırılmaz/);
  assert.match(html, /data-action="open-npm-audit-preview"/);
  assert.match(html, /id="npm-audit-preview-modal"/);
  assert.match(html, /npm_audit_active\.js\?v=1/);
});

test('both consents gate exact active request and aggregate output', async () => {
  const {node, requests, submit, approve} = setup();
  node('npm-audit-active-path').value = '/home/community-user/project';
  await submit();
  assert.equal(requests.length, 0);
  node('npm-audit-active-local-consent').checked = true;
  await submit();
  assert.equal(requests.length, 0);
  approve();
  assert.equal(node('npm-audit-active-submit').disabled, false);
  await submit();
  assert.equal(requests.length, 1);
  assert.equal(requests[0].path, '/api/tool-runs/npm-audit-local');
  assert.equal(requests[0].options.method, 'POST');
  assert.deepEqual(JSON.parse(requests[0].options.body), {
    confirm_local:true, confirm_registry:true, project_path:'/home/community-user/project',
  });
  assert.equal(node('npm-audit-active-count').textContent, '1');
  assert.equal(node('npm-audit-active-severity').textContent, 'info:0 low:0 moderate:0 high:1 critical:0');
  assert.equal(node('npm-audit-active-hash').textContent, 'a'.repeat(64));
  assert.equal(node('npm-audit-active-result').classList.contains('hidden'), false);
  assert.equal(node('npm-audit-active-path').value, '');
  assert.equal(node('npm-audit-active-local-consent').checked, false);
  assert.equal(node('npm-audit-active-registry-consent').checked, false);
  assert.equal(node('npm-audit-active-submit').disabled, true);
  await submit();
  assert.equal(requests.length, 1);
});

test('non-home and traversal paths are blocked before any request', async () => {
  const {node, requests, submit, approve} = setup();
  approve();
  for (const value of ['', '/tmp/project', '/home/community-user/../outsider']) {
    node('npm-audit-active-path').value = value;
    await submit();
    assert.equal(requests.length, 0);
    assert.equal(node('npm-audit-active-error').classList.contains('hidden'), false);
  }
});

test('unexpected private response fields and malformed counts fail closed', async () => {
  for (const response of [
    {...validResponse(), package_names:['PRIVATE_PACKAGE_MARKER']},
    {...validResponse(), affected_package_count:2},
    {...validResponse(), report_sha256:['a'.repeat(64)]},
  ]) {
    const {node, requests, submit, approve} = setup(response);
    approve(); node('npm-audit-active-path').value = '/home/community-user/project';
    await submit();
    assert.equal(requests.length, 1);
    assert.equal(node('npm-audit-active-result').classList.contains('hidden'), true);
    assert.equal(node('npm-audit-active-error').classList.contains('hidden'), false);
    const visible = ['npm-audit-active-count','npm-audit-active-severity','npm-audit-active-hash',
      'npm-audit-active-error'].map(id=>node(id).textContent).join(' ');
    assert.equal(visible.includes('PRIVATE_PACKAGE_MARKER'), false);
  }
});

test('network failure shows bounded error without leaking server detail', async () => {
  const {node, submit, approve} = setup(new Error('PRIVATE_REGISTRY_AND_PATH_MARKER'));
  approve(); node('npm-audit-active-path').value = '/home/community-user/project';
  await submit();
  assert.equal(node('npm-audit-active-result').classList.contains('hidden'), true);
  assert.equal(node('npm-audit-active-error').classList.contains('hidden'), false);
  assert.equal(node('npm-audit-active-error').textContent.includes('PRIVATE_REGISTRY_AND_PATH_MARKER'), false);
});
