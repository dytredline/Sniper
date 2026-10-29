import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const jsPath = process.env.SNIPER_SEMGREP_LOCAL_UI_JS || new URL('../static/semgrep_local.js', import.meta.url).pathname;
const htmlPath = process.env.SNIPER_SEMGREP_LOCAL_UI_HTML || new URL('../static/index.html', import.meta.url).pathname;
const source = fs.readFileSync(jsPath, 'utf8');
const html = fs.readFileSync(htmlPath, 'utf8');
const severities = ['ERROR', 'WARNING', 'EXPERIMENT', 'INVENTORY', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
function summary() {
  return {
    format: 'semgrep-native-json', profile: 'local-trusted-rules-v1', result_count: 2,
    severity_counts: Object.fromEntries(severities.map(key => [key, key === 'ERROR' ? 1 : key === 'WARNING' ? 1 : 0])),
    report_sha256: 'a'.repeat(64),
  };
}
function fixture(opts = {}) {
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
      if (selector === '[data-action="open-semgrep-local"]') return openButton;
      if (selector === 'meta[name="sniper-local-home"]') return { content: '/home/community-user' };
      return null;
    },
    addEventListener(type, cb) { listeners.set(type, [...(listeners.get(type) || []), cb]); },
  };
  if (opts.dom) {
    document.createElement = tag => ({ tag, textContent: '', children: [], appendChild(child) { this.children.push(child); } });
    const body = node('semgrep-local-findings');
    body.children = [];
    body.appendChild = child => body.children.push(child);
    body.replaceChildren = () => { body.children = []; };
  }
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
    async input(value) { node('semgrep-local-path').value = value; await dispatch(node('semgrep-local-path'), 'input'); },
    async consent() { node('semgrep-local-consent').checked = true; await dispatch(node('semgrep-local-consent'), 'change'); },
    async submit() { await dispatch(node('semgrep-local-form'), 'submit'); },
    async close() { await documentEvent('click', { target: { closest: () => true } }); },
  };
}

test('active Semgrep launcher is separate from passive JSON preview', () => {
  assert.match(html, /semgrep_local\.js\?v=2/);
  assert.match(html, /data-action="open-semgrep-local"/);
  assert.match(html, /id="semgrep-local-path"/);
  assert.match(html, /id="semgrep-local-consent"/);
  assert.match(html, /data-action="open-semgrep-preview"/);
  assert.match(html, /Bulgular uzman doğrulaması gerektirir/);
});

test('opening, missing consent and invalid paths never send a scan request', async () => {
  const f = fixture(); await f.init(); await f.open();
  assert.equal(f.requests.length, 0);
  await f.input('/home/community-user/project'); await f.submit();
  assert.equal(f.requests.length, 0);
  await f.consent();
  for (const bad of ['/tmp/project', '/opt/other/project', '/home/community-user/../project', '/home/community-user/a//b', '/home/community-user/project\n', 'https://example.com']) {
    await f.input(bad); await f.submit(); assert.equal(f.requests.length, 0, bad);
  }
});

test('explicit consent sends exact local scan request and renders aggregate result', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.input('/home/community-user/project'); await f.consent(); await f.submit();
  assert.equal(f.requests.length, 1);
  const call = f.requests[0];
  assert.equal(call.path, '/api/tool-runs/semgrep');
  assert.equal(call.options.method, 'POST');
  assert.deepEqual(JSON.parse(call.options.body), { confirm_local: true, project_path: '/home/community-user/project' });
  assert.equal(f.node('semgrep-local-count').textContent, '2');
  assert.match(f.node('semgrep-local-severity').textContent, /ERROR: 1/);
  assert.equal(f.node('semgrep-local-hash').textContent, 'a'.repeat(64));
  assert.equal(f.node('semgrep-local-result').classList.contains('hidden'), false);
});

test('invalid aggregate, raw hostile data and HTTP errors never show report contents', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.input('/home/community-user/project'); await f.consent();
  f.setResponse({ ok: true, json: async () => ({ ...summary(), severity_counts: { ...summary().severity_counts, ERROR: '<script>PRIVATE</script>' } }) });
  await f.submit();
  assert.equal(f.node('semgrep-local-result').classList.contains('hidden'), true);
  assert.doesNotMatch(f.node('semgrep-local-error').textContent, /PRIVATE/);
  f.setResponse({ ok: true, json: async () => ({ ...summary(), result_count: 3 }) });
  await f.submit();
  assert.equal(f.node('semgrep-local-result').classList.contains('hidden'), true);
  f.setResponse({ ok: false, status: 503, json: async () => ({ error: 'PRIVATE' }) });
  await f.submit();
  assert.doesNotMatch(f.node('semgrep-local-error').textContent, /PRIVATE/);
});

test('pending scan is single-shot; closing discards late result and resets consent', async () => {
  const f = fixture(); let release;
  f.setResponse(new Promise(resolve => { release = resolve; }));
  await f.init(); await f.open(); await f.input('/home/community-user/project'); await f.consent();
  const pending = f.submit();
  await f.submit();
  assert.equal(f.requests.length, 1);
  await f.close();
  release({ ok: true, json: async () => summary() });
  await pending;
  assert.equal(f.node('semgrep-local-result').classList.contains('hidden'), true);
  assert.equal(f.node('semgrep-local-consent').checked, false);
  assert.equal(f.node('semgrep-local-submit').disabled, true);
});

test('findings are rendered as text cells only and engine is shown', async () => {
  const f = fixture({ dom: true });
  f.setResponse({ ok: true, json: async () => ({
    ...summary(),
    engine: { tool: 'opengrep', version: '1.30.1' },
    findings: [
      { rule_id: 'sniper.py.sql-injection', severity: 'ERROR', cwe: 'CWE-89: SQL Injection', path: 'src/app.py', line: 9, message: '<img src=x onerror=alert(1)>' },
      { rule_id: 'sniper.js.weak-hash', severity: 'WARNING', cwe: null, path: 'a.js', line: 'x', message: 'm' },
    ],
  }) });
  await f.init(); await f.open(); await f.input('/home/community-user/project'); await f.consent(); await f.submit();
  assert.equal(f.node('semgrep-local-engine').textContent, 'opengrep 1.30.1');
  const rows = f.node('semgrep-local-findings').children;
  assert.equal(rows.length, 2);
  assert.deepEqual(rows[0].children.map(c => c.textContent),
    ['ERROR', 'sniper.py.sql-injection · CWE-89: SQL Injection', 'src/app.py:9', '<img src=x onerror=alert(1)>']);
  assert.equal(rows[1].children[2].textContent, 'a.js');
  await f.close();
  assert.equal(f.node('semgrep-local-findings').children.length, 0);
});
