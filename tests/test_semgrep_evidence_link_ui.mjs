import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const jsPath = process.env.SNIPER_SEMGREP_EVIDENCE_JS || new URL('../static/semgrep_evidence_link.js', import.meta.url).pathname;
const htmlPath = process.env.SNIPER_SEMGREP_EVIDENCE_HTML || new URL('../static/index.html', import.meta.url).pathname;
const source = fs.readFileSync(jsPath, 'utf8');
const html = fs.readFileSync(htmlPath, 'utf8');
const severities = ['ERROR', 'WARNING', 'EXPERIMENT', 'INVENTORY', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const engagement = {
  id: 'eng-synthetic', name: 'Synthetic manual review', status: 'active',
  authorization_ref: 'FIXTURE-AUTH', scope_notes: 'fixture', special_approvals: { redacted_data_proof: true }
};
const detail = { ...engagement, tests: [{ control_id: 'CTL-1', title: 'Synthetic control' }] };
function summary(overrides = {}) {
  return {
    tool_identity: 'semgrep-local', profile: 'local-trusted-rules-v1',
    engagement_id: engagement.id, control_id: 'CTL-1', result_count: 2,
    severity_counts: Object.fromEntries(severities.map(key => [key, key === 'ERROR' || key === 'WARNING' ? 1 : 0])),
    report_sha256: 'a'.repeat(64), ...overrides
  };
}

function fixture() {
  const nodes = new Map(), listeners = new Map(), calls = [];
  let postResponse = { ok: true, json: async () => summary() };
  let listResponse = { ok: true, json: async () => ({ engagements: [engagement] }) };
  let detailResponse = { ok: true, json: async () => detail };
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(['hidden']), handlers = new Map();
    const item = {
      id, value: '', checked: false, disabled: false, textContent: '', handlers, children: [],
      classList: {
        add(key) { classes.add(key); }, remove(key) { classes.delete(key); },
        toggle(key, force) { if (force) classes.add(key); else classes.delete(key); },
        contains(key) { return classes.has(key); }
      },
      replaceChildren() { this.children = []; this.value = ''; },
      appendChild(child) { this.children.push(child); },
      addEventListener(type, cb) { handlers.set(type, [...(handlers.get(type) || []), cb]); },
      closest() { return null; },
    };
    nodes.set(id, item);
    return item;
  }
  const open = node('open');
  const document = {
    getElementById: node,
    querySelector(selector) {
      if (selector === '[data-action="open-semgrep-local"]') return open;
      if (selector === 'meta[name="sniper-local-home"]') return { content: '/home/community-user' };
      return null;
    },
    createElement() { return { value: '', textContent: '' }; },
    addEventListener(type, cb) { listeners.set(type, [...(listeners.get(type) || []), cb]); },
  };
  async function dispatch(element, type, extra = {}) {
    for (const cb of element.handlers.get(type) || []) await cb({ target: element, preventDefault() {}, ...extra });
    await new Promise(resolve => setImmediate(resolve));
  }
  async function documentEvent(type, event) {
    for (const cb of listeners.get(type) || []) await cb(event);
    await new Promise(resolve => setImmediate(resolve));
  }
  const fetch = async (path, options = {}) => {
    calls.push({ path, options });
    if (path === '/api/engagements') return listResponse;
    if (!options.method && path.startsWith('/api/engagements/')) return detailResponse;
    return postResponse;
  };
  vm.runInNewContext(source, { document, fetch, Number, Object, Array, JSON, Promise, Set, encodeURIComponent });
  return {
    node, calls, openButton: open, setPostResponse(value) { postResponse = value; },
    setListResponse(value) { listResponse = value; }, setDetailResponse(value) { detailResponse = value; },
    async init() { await documentEvent('DOMContentLoaded', {}); },
    async open() { await dispatch(open, 'click'); },
    async close() { await documentEvent('click', { target: { closest: () => true } }); },
    async chooseEngagement(value = engagement.id) { node('semgrep-evidence-engagement').value = value; await dispatch(node('semgrep-evidence-engagement'), 'change'); },
    async chooseControl(value = 'CTL-1') { node('semgrep-evidence-control').value = value; await dispatch(node('semgrep-evidence-control'), 'change'); },
    async path(value) { node('semgrep-evidence-path').value = value; await dispatch(node('semgrep-evidence-path'), 'input'); },
    async consent(local, link) {
      node('semgrep-evidence-confirm-local').checked = local;
      node('semgrep-evidence-confirm-link').checked = link;
      await dispatch(node('semgrep-evidence-confirm-local'), 'change');
      await dispatch(node('semgrep-evidence-confirm-link'), 'change');
    },
    async submit() { await dispatch(node('semgrep-evidence-form'), 'submit'); },
  };
}

test('browser exposes a separate opt-in aggregate evidence workflow', () => {
  assert.match(html, /semgrep_evidence_link\.js\?v=1/);
  assert.match(html, /id="semgrep-evidence-form"/);
  assert.match(html, /id="semgrep-evidence-confirm-local"/);
  assert.match(html, /id="semgrep-evidence-confirm-link"/);
  assert.match(html, /Projenin denetim kapsamındaki hedefe ait olduğunu siz doğrulamalısınız/);
});

test('opening and choosing an engagement never start a scan; ineligible engagements stay unavailable', async () => {
  const f = fixture();
  f.setListResponse({ ok: true, json: async () => ({ engagements: [
    { ...engagement, id: 'bad', special_approvals: { redacted_data_proof: false } }, engagement
  ] }) });
  await f.init(); await f.open(); await f.chooseEngagement(); await f.chooseControl();
  assert.deepEqual(f.calls.map(call => call.path), ['/api/engagements', '/api/engagements/eng-synthetic']);
  assert.equal(f.node('semgrep-evidence-engagement').children.length, 2);
  assert.equal(f.node('semgrep-evidence-submit').disabled, true);
});

test('both distinct consents and a selected control are required for an exact run-and-link request', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.chooseEngagement(); await f.chooseControl();
  const project = '/home/community-user/synthetic-secret-project';
  await f.path(project);
  await f.consent(true, false); await f.submit();
  await f.consent(false, true); await f.submit();
  assert.equal(f.calls.filter(call => call.options.method === 'POST').length, 0);
  for (const invalid of ['/tmp/repo', '/opt/other/repo', '/home/community-user/a/../b', '/home/community-user/a//b', '/home/community-user/a\n']) {
    await f.path(invalid); await f.consent(true, true); await f.submit();
    assert.equal(f.calls.filter(call => call.options.method === 'POST').length, 0, invalid);
  }
  await f.path(project); await f.consent(true, true); await f.submit();
  const posts = f.calls.filter(call => call.options.method === 'POST');
  assert.equal(posts.length, 1);
  assert.equal(posts[0].path, '/api/engagements/eng-synthetic/tool-runs/semgrep-local');
  assert.deepEqual(JSON.parse(posts[0].options.body), {
    control_id: 'CTL-1', project_path: project, confirm_local: true, confirm_link: true
  });
  assert.equal(f.node('semgrep-evidence-count').textContent, '2');
  assert.match(f.node('semgrep-evidence-severity').textContent, /ERROR: 1/);
  assert.equal(f.node('semgrep-evidence-hash').textContent, 'a'.repeat(64));
  assert.equal(f.node('semgrep-evidence-path').value, '');
  assert.equal(f.node('semgrep-evidence-confirm-local').checked, false);
  assert.equal(f.node('semgrep-evidence-confirm-link').checked, false);
  assert.doesNotMatch(f.node('semgrep-evidence-result').textContent + f.node('semgrep-evidence-message').textContent, /synthetic-secret-project/);
});

test('changing the path or control invalidates prior consent; malformed or hostile response is not rendered', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.chooseEngagement(); await f.chooseControl();
  await f.path('/home/community-user/a'); await f.consent(true, true);
  await f.path('/home/community-user/b'); await f.submit();
  assert.equal(f.calls.filter(call => call.options.method === 'POST').length, 0);
  await f.consent(true, true); await f.chooseControl(); await f.submit();
  assert.equal(f.calls.filter(call => call.options.method === 'POST').length, 0);
  f.setPostResponse({ ok: true, json: async () => summary({ severity_counts: { ...summary().severity_counts, ERROR: '<script>PRIVATE</script>' } }) });
  await f.consent(true, true); await f.submit();
  assert.equal(f.node('semgrep-evidence-result').classList.contains('hidden'), true);
  assert.doesNotMatch(f.node('semgrep-evidence-error').textContent, /PRIVATE/);
  f.setPostResponse({ ok: false, status: 403, json: async () => ({ error: 'PRIVATE' }) });
  await f.submit();
  assert.doesNotMatch(f.node('semgrep-evidence-error').textContent, /PRIVATE/);
});

test('pending request is single-shot and closing discards late aggregate response', async () => {
  const f = fixture(); let release;
  f.setPostResponse(new Promise(resolve => { release = resolve; }));
  await f.init(); await f.open(); await f.chooseEngagement(); await f.chooseControl();
  await f.path('/home/community-user/fixture'); await f.consent(true, true);
  const pending = f.submit();
  await f.submit();
  assert.equal(f.calls.filter(call => call.options.method === 'POST').length, 1);
  await f.close();
  release({ ok: true, json: async () => summary() });
  await pending;
  assert.equal(f.node('semgrep-evidence-result').classList.contains('hidden'), true);
  assert.equal(f.node('semgrep-evidence-path').value, '');
  assert.equal(f.node('semgrep-evidence-confirm-link').checked, false);
});

test('backend-eligible engagement with empty scope_notes is selectable, loads controls without scanning, and preserves all link gates', async () => {
  const f = fixture();
  const emptyScopeEngagement = {
    id: 'eng-empty-scope', name: 'Empty scope review', status: 'active',
    authorization_ref: 'AUTH-EMPTY-SCOPE', scope_notes: '',
    special_approvals: { redacted_data_proof: true }
  };
  const emptyScopeDetail = {
    ...emptyScopeEngagement,
    tests: [{ control_id: 'CTL-EMPTY-1', title: 'Empty scope control' }]
  };
  f.setListResponse({
    ok: true,
    json: async () => ({
      engagements: [
        { ...emptyScopeEngagement, id: 'inactive-eng', status: 'paused', scope_notes: 'documented' },
        { ...emptyScopeEngagement, id: 'missing-auth', authorization_ref: '   ', scope_notes: 'documented' },
        { ...emptyScopeEngagement, id: 'no-proof', scope_notes: 'documented', special_approvals: { redacted_data_proof: false } },
        emptyScopeEngagement
      ]
    })
  });
  f.setDetailResponse({ ok: true, json: async () => emptyScopeDetail });
  f.setPostResponse({
    ok: true,
    json: async () => summary({ engagement_id: emptyScopeEngagement.id, control_id: 'CTL-EMPTY-1' })
  });

  await f.init();
  await f.open();
  const engSelect = f.node('semgrep-evidence-engagement');
  assert.equal(engSelect.disabled, false);
  assert.deepEqual(engSelect.children.map(item => item.value), ['', 'eng-empty-scope']);
  assert.equal(f.calls.filter(call => call.options.method === 'POST').length, 0);

  const origCallsLen = f.calls.length;
  await f.chooseEngagement('eng-empty-scope');
  assert.equal(f.calls.length, origCallsLen + 1);
  assert.equal(f.calls[f.calls.length - 1].path, '/api/engagements/eng-empty-scope');
  assert.equal(f.calls.filter(call => call.options.method === 'POST').length, 0);

  const ctrlSelect = f.node('semgrep-evidence-control');
  assert.equal(ctrlSelect.disabled, false);
  assert.deepEqual(ctrlSelect.children.map(item => item.value), ['', 'CTL-EMPTY-1']);
  assert.equal(f.node('semgrep-evidence-submit').disabled, true);

  await f.chooseControl('CTL-EMPTY-1');
  const project = '/home/community-user/empty-scope-project';
  await f.path(project);
  await f.consent(true, false);
  await f.submit();
  await f.consent(false, true);
  await f.submit();
  assert.equal(f.calls.filter(call => call.options.method === 'POST').length, 0);

  await f.consent(true, true);
  assert.equal(f.node('semgrep-evidence-submit').disabled, false);
  await f.submit();

  const posts = f.calls.filter(call => call.options.method === 'POST');
  assert.equal(posts.length, 1);
  assert.equal(posts[0].path, '/api/engagements/eng-empty-scope/tool-runs/semgrep-local');
  assert.deepEqual(JSON.parse(posts[0].options.body), {
    control_id: 'CTL-EMPTY-1', project_path: project, confirm_local: true, confirm_link: true
  });
  assert.equal(f.node('semgrep-evidence-result').classList.contains('hidden'), false);
  assert.equal(f.node('semgrep-evidence-count').textContent, '2');
  assert.equal(f.node('semgrep-evidence-hash').textContent, 'a'.repeat(64));
  assert.match(f.node('semgrep-evidence-message').textContent, /otomatik başarılı yapılmaz/);
  assert.doesNotMatch(f.node('semgrep-evidence-result').textContent + f.node('semgrep-evidence-message').textContent, /empty-scope-project/);
});

test('detail fetch for empty-scope engagement fails closed if status, authorization_ref, or redacted_data_proof becomes ineligible', async () => {
  const f = fixture();
  const emptyScopeEngagement = {
    id: 'eng-empty-scope', name: 'Empty scope review', status: 'active',
    authorization_ref: 'AUTH-EMPTY-SCOPE', scope_notes: '',
    special_approvals: { redacted_data_proof: true }
  };
  f.setListResponse({ ok: true, json: async () => ({ engagements: [emptyScopeEngagement] }) });
  f.setDetailResponse({
    ok: true,
    json: async () => ({
      ...emptyScopeEngagement,
      special_approvals: { redacted_data_proof: false },
      tests: [{ control_id: 'CTL-EMPTY-1', title: 'Empty scope control' }]
    })
  });
  await f.init();
  await f.open();
  await f.chooseEngagement('eng-empty-scope');
  assert.equal(f.node('semgrep-evidence-control').disabled, true);
  assert.equal(f.node('semgrep-evidence-error').classList.contains('hidden'), false);
  assert.equal(f.node('semgrep-evidence-submit').disabled, true);
  assert.equal(f.calls.filter(call => call.options.method === 'POST').length, 0);
});

