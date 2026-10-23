import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const jsPath = process.env.SNIPER_ZAP_LINK_JS || new URL('../static/zap_evidence_link.js', import.meta.url).pathname;
const htmlPath = process.env.SNIPER_ZAP_LINK_HTML || new URL('../static/index.html', import.meta.url).pathname;
const source = fs.readFileSync(jsPath, 'utf8');
const html = fs.readFileSync(htmlPath, 'utf8');
const report = { site: [{ alerts: [{ riskcode: '3', count: '2', name: 'PRIVATE_ALERT' }] }] };

function fixture() {
  const nodes = new Map();
  const documentEvents = new Map();
  const requests = [];
  const engagement = {
    id: 'eng_fixture', name: 'Synthetic review', status: 'active', authorization_ref: 'AUTH',
    scope_notes: 'fixture scope', special_approvals: { redacted_data_proof: true },
    tests: [{ control_id: 'CTRL-1', title: 'Synthetic control' }],
  };
  let linked = {
    tool_identity: 'zap-traditional-json', site_count: 1, alert_type_count: 1,
    instance_count: 2, risk_counts: { informational: 0, low: 0, medium: 0, high: 1 },
    report_sha256: 'a'.repeat(64),
  };
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(['hidden']);
    const handlers = new Map();
    const item = {
      id, value: '', checked: false, disabled: false, textContent: '', handlers,
      files: [], children: [],
      get options() { return this.children; },
      classList: {
        add(c) { classes.add(c); }, remove(c) { classes.delete(c); },
        contains(c) { return classes.has(c); }, toggle(c, force) { if (force) classes.add(c); else classes.delete(c); },
      },
      addEventListener(type, cb) { handlers.set(type, [...(handlers.get(type) || []), cb]); },
      replaceChildren() { this.children = []; this.value = ''; },
      appendChild(child) { this.children.push(child); },
    };
    nodes.set(id, item); return item;
  }
  const open = node('open');
  const modal = node('zap-preview-modal');
  const document = {
    getElementById: node,
    createElement() { return { value: '', textContent: '' }; },
    querySelector(selector) { return selector === '[data-action="open-zap-preview"]' ? open : null; },
    addEventListener(type, cb) { documentEvents.set(type, [...(documentEvents.get(type) || []), cb]); },
  };
  const fetch = async (path, options) => {
    requests.push({ path, options });
    if (path === '/api/engagements') return { ok: true, json: async () => ({ engagements: [engagement] }) };
    if (path === '/api/engagements/eng_fixture') return { ok: true, json: async () => engagement };
    if (path === '/api/engagements/eng_fixture/tool-evidence/zap-traditional-json') return { ok: true, json: async () => linked };
    return { ok: false, json: async () => ({ error: 'PRIVATE_SERVER_ERROR' }) };
  };
  vm.runInNewContext(source, { document, fetch, TextEncoder, JSON, Number, Object, Array, Promise, encodeURIComponent });
  const dispatch = async (element, type) => {
    for (const cb of element.handlers.get(type) || []) await cb({ target: element, preventDefault() {} });
  };
  const documentEvent = async (type, event) => {
    for (const cb of documentEvents.get(type) || []) await cb(event);
  };
  const flush = () => new Promise(resolve => setImmediate(resolve));
  return {
    node, requests, modal, open, report,
    setLinked(value) { linked = value; },
    async init() { await documentEvent('DOMContentLoaded', {}); },
    async openModal() { await dispatch(open, 'click'); await flush(); },
    async selectEngagement() { node('zap-evidence-link-engagement').value = 'eng_fixture'; await dispatch(node('zap-evidence-link-engagement'), 'change'); await flush(); },
    async selectControl() { node('zap-evidence-link-control').value = 'CTRL-1'; await dispatch(node('zap-evidence-link-control'), 'change'); },
    async consent() { node('zap-evidence-link-consent').checked = true; await dispatch(node('zap-evidence-link-consent'), 'change'); },
    async submit() { await dispatch(node('zap-evidence-link-form'), 'submit'); },
    async close() { await documentEvent('click', { target: modal }); },
  };
}

test('ZAP link has a separate explicit-consent form and no scanner control', () => {
  assert.match(html, /zap_evidence_link\.js\?v=1/);
  for (const id of ['zap-evidence-link-form', 'zap-evidence-link-engagement', 'zap-evidence-link-control', 'zap-evidence-link-consent']) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
});

test('opening preview and selecting controls never POST; missing consent blocks link', async () => {
  const f = fixture(); await f.init(); await f.openModal();
  await f.selectEngagement(); await f.selectControl();
  f.node('zap-evidence-link-paste').value = JSON.stringify(report);
  await f.submit();
  assert.equal(f.requests.filter(request => request.options?.method === 'POST').length, 0);
  assert.equal(f.node('zap-evidence-link-submit').disabled, true);
});

test('explicit link sends exact aggregate route and clears raw input', async () => {
  const f = fixture(); await f.init(); await f.openModal(); await f.selectEngagement(); await f.selectControl(); await f.consent();
  f.node('zap-evidence-link-paste').value = JSON.stringify(report);
  await f.submit();
  const posts = f.requests.filter(request => request.options?.method === 'POST');
  assert.equal(posts.length, 1);
  assert.equal(posts[0].path, '/api/engagements/eng_fixture/tool-evidence/zap-traditional-json');
  assert.deepEqual(JSON.parse(posts[0].options.body), { control_id: 'CTRL-1', report, confirm_link: true });
  assert.equal(f.node('zap-evidence-link-paste').value, '');
  assert.equal(f.node('zap-evidence-link-consent').checked, false);
  assert.doesNotMatch(f.node('zap-evidence-link-result').textContent, /PRIVATE_ALERT/);
});

test('invalid server aggregate is rejected without rendering private content', async () => {
  const f = fixture(); await f.init(); await f.openModal(); await f.selectEngagement(); await f.selectControl(); await f.consent();
  f.setLinked({ tool_identity: 'zap-traditional-json', report_sha256: 'PRIVATE_SERVER_ERROR' });
  f.node('zap-evidence-link-paste').value = JSON.stringify(report);
  await f.submit();
  assert.equal(f.node('zap-evidence-link-result').classList.contains('hidden'), true);
  assert.doesNotMatch(f.node('zap-evidence-link-error').textContent, /PRIVATE_SERVER_ERROR|PRIVATE_ALERT/);
});

test('closing resets consent and sensitive input', async () => {
  const f = fixture(); await f.init(); await f.openModal(); await f.selectEngagement(); await f.selectControl(); await f.consent();
  f.node('zap-evidence-link-paste').value = JSON.stringify(report);
  await f.close();
  assert.equal(f.node('zap-evidence-link-paste').value, '');
  assert.equal(f.node('zap-evidence-link-consent').checked, false);
  assert.equal(f.node('zap-evidence-link-submit').disabled, true);
});
