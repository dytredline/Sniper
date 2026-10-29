import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const jsPath = process.env.SNIPER_TRUFFLEHOG_GIT_UI_JS || new URL('../static/trufflehog_git_history.js', import.meta.url).pathname;
const htmlPath = process.env.SNIPER_TRUFFLEHOG_GIT_UI_HTML || new URL('../static/index.html', import.meta.url).pathname;
const source = fs.readFileSync(jsPath, 'utf8');
const html = fs.readFileSync(htmlPath, 'utf8');
const summary = () => ({
  format: 'trufflehog-native-json-records', profile: 'local-git-history-no-verification-v1',
  total_findings: 2, verified_findings: 0, unverified_findings: 2,
  detectors_triggered: 1, report_sha256: 'a'.repeat(64),
});

function fixture({ localHome = '/home/community-user' } = {}) {
  const nodes = new Map(); const listeners = new Map(); const requests = [];
  let response = { ok: true, json: async () => summary() };
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(['hidden']); const handlers = new Map();
    const element = {
      id, value: '', checked: false, disabled: false, textContent: '', handlers,
      classList: { add(c) { classes.add(c); }, remove(c) { classes.delete(c); }, contains(c) { return classes.has(c); } },
      addEventListener(type, cb) { handlers.set(type, [...(handlers.get(type) || []), cb]); },
      querySelectorAll() { return []; }, // browser DOM API; no focusable children needed by these legacy payload tests
      focus() { document.activeElement = element; },
      closest() { return null; },
    };
    nodes.set(id, element); return element;
  }
  const openButton = node('open');
  const document = {
    activeElement: null,
    getElementById: node,
    querySelector(selector) {
      if (selector === '[data-action="open-trufflehog-git-history"]') return openButton;
      if (selector === 'meta[name="sniper-local-home"]') return localHome === null ? null : { content: localHome };
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
    async input(value) { node('trufflehog-git-history-path').value = value; await dispatch(node('trufflehog-git-history-path'), 'input'); },
    async consent() { node('trufflehog-git-history-consent').checked = true; await dispatch(node('trufflehog-git-history-consent'), 'change'); },
    async submit() { await dispatch(node('trufflehog-git-history-form'), 'submit'); },
  };
}

test('Git history has separate launcher, local path, consent and script', () => {
  assert.match(html, /trufflehog_git_history\.js\?v=1/);
  assert.match(html, /data-action="open-trufflehog-git-history"/);
  assert.match(html, /id="trufflehog-git-history-path"/);
  assert.match(html, /id="trufflehog-git-history-consent"/);
  assert.match(html, /sır doğrulaması yapılmaz/i);
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

test('missing injected local-home metadata fails closed before any request', async () => {
  const f = fixture({ localHome: null });
  await f.init(); await f.open(); await f.input('/home/community-user/project'); await f.consent(); await f.submit();
  assert.equal(f.requests.length, 0);
  assert.equal(f.node('trufflehog-git-history-submit').disabled, true);
});

test('explicit consent sends exact local profile request and renders only aggregate', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.input('/home/community-user/project'); await f.consent(); await f.submit();
  assert.equal(f.requests.length, 1);
  const call = f.requests[0];
  assert.equal(call.path, '/api/tool-runs/trufflehog-git-history');
  assert.equal(call.options.method, 'POST');
  assert.deepEqual(JSON.parse(call.options.body), { confirm_local: true, project_path: '/home/community-user/project' });
  assert.equal(f.node('trufflehog-git-history-total').textContent, '2');
  assert.equal(f.node('trufflehog-git-history-unverified').textContent, '2');
  assert.equal(f.node('trufflehog-git-history-detectors').textContent, '1');
  assert.equal(f.node('trufflehog-git-history-report-sha256').textContent, 'a'.repeat(64));
  assert.equal(f.node('trufflehog-git-history-result').classList.contains('hidden'), false);
});

test('inconsistent or hostile response and failed HTTP never show raw content', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.input('/home/community-user/project'); await f.consent();
  f.setResponse({ ok: true, json: async () => ({ ...summary(), unverified_findings: '<script>PRIVATE_REPORT</script>' }) });
  await f.submit();
  assert.equal(f.node('trufflehog-git-history-result').classList.contains('hidden'), true);
  assert.doesNotMatch(f.node('trufflehog-git-history-error').textContent, /PRIVATE_REPORT/);
  f.setResponse({ ok: true, json: async () => ({ ...summary(), verified_findings: 1 }) });
  await f.submit();
  assert.equal(f.node('trufflehog-git-history-result').classList.contains('hidden'), true);
  f.setResponse({ ok: false, status: 503, json: async () => ({ error: 'PRIVATE_REPORT' }) });
  await f.submit();
  assert.doesNotMatch(f.node('trufflehog-git-history-error').textContent, /PRIVATE_REPORT/);
});

test('pending submit is single-shot and closing discards late response and consent', async () => {
  const f = fixture(); let release;
  f.setResponse(new Promise(resolve => { release = resolve; }));
  await f.init(); await f.open(); await f.input('/home/community-user/project'); await f.consent();
  const first = f.submit(); assert.equal(f.requests.length, 1);
  await f.submit(); assert.equal(f.requests.length, 1);
  await f.documentEvent('click', { target: f.node('trufflehog-git-history-modal') });
  assert.equal(f.node('trufflehog-git-history-consent').checked, false);
  release({ ok: true, json: async () => summary() }); await first;
  assert.equal(f.node('trufflehog-git-history-result').classList.contains('hidden'), true);
  assert.equal(f.node('trufflehog-git-history-submit').disabled, true);
});
