import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const jsPath = process.env.SNIPER_GITLEAKS_FS_UI_JS || new URL('../static/gitleaks_filesystem.js', import.meta.url).pathname;
const htmlPath = process.env.SNIPER_GITLEAKS_FS_UI_HTML || new URL('../static/index.html', import.meta.url).pathname;
const source = fs.readFileSync(jsPath, 'utf8');
const html = fs.readFileSync(htmlPath, 'utf8');
const summary = () => ({
  format: 'gitleaks-native-json', total_findings: 2, rules_triggered: 1,
  files_affected: 2, report_sha256: 'a'.repeat(64),
});

function fixture() {
  const nodes = new Map(); const listeners = new Map(); const requests = [];
  let response = { ok: true, json: async () => summary() };
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(['hidden']); const handlers = new Map();
    const element = {
      id, value: '', checked: false, disabled: false, textContent: '', handlers,
      classList: { add(c) { classes.add(c); }, remove(c) { classes.delete(c); }, contains(c) { return classes.has(c); } },
      addEventListener(type, cb) { handlers.set(type, [...(handlers.get(type) || []), cb]); },
      closest() { return null; },
    };
    nodes.set(id, element); return element;
  }
  const openButton = node('open');
  const document = {
    getElementById: node,
    querySelector(selector) {
      if (selector === '[data-action="open-gitleaks-filesystem"]') return openButton;
      if (selector === 'meta[name="sniper-local-home"]') return { content: '/home/community-user' };
      return null;
    },
    addEventListener(type, cb) { listeners.set(type, [...(listeners.get(type) || []), cb]); },
  };
  async function dispatch(element, type, extra = {}) {
    for (const cb of element.handlers.get(type) || []) await cb({ target: element, preventDefault() {}, ...extra });
  }
  async function documentEvent(type, event) { for (const cb of listeners.get(type) || []) await cb(event); }
  const fetch = async (path, options) => { requests.push({ path, options }); return response; };
  vm.runInNewContext(source, { document, fetch, Number, Object, Array, JSON, Promise });
  return {
    node, requests, openButton, dispatch, documentEvent, setResponse(r) { response = r; },
    async init() { await documentEvent('DOMContentLoaded', {}); },
    async open() { await dispatch(openButton, 'click'); },
    async input(value) { node('gitleaks-filesystem-path').value = value; await dispatch(node('gitleaks-filesystem-path'), 'input'); },
    async consent() { node('gitleaks-filesystem-consent').checked = true; await dispatch(node('gitleaks-filesystem-consent'), 'change'); },
    async submit() { await dispatch(node('gitleaks-filesystem-form'), 'submit'); },
  };
}

test('Filesystem has separate launcher, local path, consent and script', () => {
  assert.match(html, /gitleaks_filesystem\.js\?v=1/);
  assert.match(html, /data-action="open-gitleaks-filesystem"/);
  assert.match(html, /id="gitleaks-filesystem-path"/);
  assert.match(html, /id="gitleaks-filesystem-consent"/);
  assert.match(html, /uzman doğrulaması gerektirir/i);
});

test('opening, missing consent and invalid paths send no request', async () => {
  const f = fixture(); await f.init(); await f.open();
  assert.equal(f.requests.length, 0);
  await f.input('/home/community-user/project'); await f.submit();
  assert.equal(f.requests.length, 0);
  await f.consent();
  for (const bad of ['/tmp/project', '/opt/other/project', '/home/community-user/../project', '/home/community-user/a//b', '/home/community-user/project\n', 'https://example.com']) {
    await f.input(bad); await f.submit(); assert.equal(f.requests.length, 0, bad);
  }
});

test('explicit consent sends exact local scanner request and renders only aggregate', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.input('/home/community-user/project'); await f.consent(); await f.submit();
  assert.equal(f.requests.length, 1);
  const call = f.requests[0];
  assert.equal(call.path, '/api/tool-runs/gitleaks');
  assert.equal(call.options.method, 'POST');
  assert.deepEqual(JSON.parse(call.options.body), { confirm_local: true, project_path: '/home/community-user/project' });
  assert.equal(f.node('gitleaks-filesystem-total').textContent, '2');
  assert.equal(f.node('gitleaks-filesystem-rules').textContent, '1');
  assert.equal(f.node('gitleaks-filesystem-files').textContent, '2');
  assert.equal(f.node('gitleaks-filesystem-report-sha256').textContent, 'a'.repeat(64));
  assert.equal(f.node('gitleaks-filesystem-result').classList.contains('hidden'), false);
});

test('inconsistent or hostile response and failed HTTP never show raw content', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.input('/home/community-user/project'); await f.consent();
  f.setResponse({ ok: true, json: async () => ({ ...summary(), rules_triggered: '<script>PRIVATE_REPORT</script>' }) });
  await f.submit();
  assert.equal(f.node('gitleaks-filesystem-result').classList.contains('hidden'), true);
  assert.doesNotMatch(f.node('gitleaks-filesystem-error').textContent, /PRIVATE_REPORT/);
  f.setResponse({ ok: true, json: async () => ({ ...summary(), files_affected: 3 }) });
  await f.submit();
  assert.equal(f.node('gitleaks-filesystem-result').classList.contains('hidden'), true);
  f.setResponse({ ok: false, status: 503, json: async () => ({ error: 'PRIVATE_REPORT' }) });
  await f.submit();
  assert.doesNotMatch(f.node('gitleaks-filesystem-error').textContent, /PRIVATE_REPORT/);
});

test('pending submit is single-shot and closing discards late response and consent', async () => {
  const f = fixture(); let release;
  f.setResponse(new Promise(resolve => { release = resolve; }));
  await f.init(); await f.open(); await f.input('/home/community-user/project'); await f.consent();
  const first = f.submit(); assert.equal(f.requests.length, 1);
  await f.submit(); assert.equal(f.requests.length, 1);
  await f.documentEvent('click', { target: f.node('gitleaks-filesystem-modal') });
  assert.equal(f.node('gitleaks-filesystem-consent').checked, false);
  release({ ok: true, json: async () => summary() }); await first;
  assert.equal(f.node('gitleaks-filesystem-result').classList.contains('hidden'), true);
  assert.equal(f.node('gitleaks-filesystem-submit').disabled, true);
});
