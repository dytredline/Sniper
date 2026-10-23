import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/nmap_preview.js', import.meta.url), 'utf8');
const sample = '<nmaprun><host><status state="up"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>';
const summary = {
  format: 'nmap-xml', host_count: 1, up_host_count: 1, open_port_count: 1,
  open_protocol_counts: { tcp: 1, udp: 0 },
  open_port_bands: { well_known: 1, registered: 0, dynamic: 0 },
  report_sha256: 'a'.repeat(64), private_detail: 'PRIVATE_HOST_MUST_NOT_RENDER',
};

function harness(reply = summary, lookup = {}) {
  const nodes = new Map();
  const listeners = new Map();
  const requests = [];
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(['hidden']);
    const handlers = new Map();
    const item = {
      id, value: '', files: [], textContent: '', disabled: false, children: [],
      set innerHTML(_value) { this.children = []; },
      get innerHTML() { return ''; },
      classList: {
        add: value => classes.add(value),
        remove: value => classes.delete(value),
        contains: value => classes.has(value),
        toggle: (value, force) => force ? classes.add(value) : classes.delete(value),
      },
      addEventListener(name, handler) { handlers.set(name, handler); },
      append(child) { (this.children ||= []).push(child); },
      closest(selector) {
        if (selector.includes('open-nmap-xml-preview') && id === 'open') return this;
        if (selector.includes('data-close') && id === 'close') return this;
        return null;
      },
      handlers,
    };
    nodes.set(id, item);
    return item;
  }
  const document = {
    body: { style: {} },
    getElementById: node,
    createElement: tag => ({ tag, value: '', textContent: '' }),
    addEventListener(name, handler) { listeners.set(name, handler); },
  };
  const fetch = async (url, options) => {
    requests.push({ url, options });
    const entry = Object.hasOwn(lookup, url) ? lookup[url] : reply;
    if (typeof entry === 'function') return entry(url, options);
    return { ok: true, json: async () => entry };
  };
  vm.runInNewContext(source, { document, fetch, TextEncoder, AbortController });
  const click = async id => listeners.get('click')({ target: node(id), preventDefault() {} });
  const submit = async () => node('nmap-xml-preview-form').handlers.get('submit')({ preventDefault() {} });
  return { node, requests, click, submit };
}

test('saved Nmap XML preview sends exact report and renders only bounded aggregate fields', async () => {
  const h = harness();
  await h.click('open');
  assert.equal(h.node('nmap-xml-preview-modal').classList.contains('hidden'), false);
  h.node('nmap-xml-paste').value = sample;
  await h.submit();
  assert.equal(h.requests.length, 1);
  assert.equal(h.requests[0].url, '/api/tool-reports/nmap/summary');
  assert.equal(h.requests[0].options.method, 'POST');
  assert.deepEqual(JSON.parse(h.requests[0].options.body), { report: sample });
  assert.equal(h.node('nmap-xml-host-count').textContent, '1');
  assert.equal(h.node('nmap-xml-protocol-counts').textContent, 'TCP:1 UDP:0');
  assert.equal(h.node('nmap-xml-preview-result').classList.contains('hidden'), false);
  assert.equal(h.node('nmap-xml-paste').value, '');
  assert.equal([...['host-count', 'up-host-count', 'open-port-count', 'protocol-counts', 'port-bands', 'report-sha256']]
    .map(id => h.node(`nmap-xml-${id}`).textContent).join(' ').includes('PRIVATE_HOST'), false);
});

test('file input works and clears after success', async () => {
  const h = harness();
  await h.click('open');
  h.node('nmap-xml-file').files = [{ size: Buffer.byteLength(sample), text: async () => sample }];
  await h.submit();
  assert.equal(h.requests.length, 1);
  assert.deepEqual(JSON.parse(h.requests[0].options.body), { report: sample });
  assert.equal(h.node('nmap-xml-file').value, '');
});

test('oversize file and UTF-8 pasted input never reach the API', async () => {
  const h = harness();
  await h.click('open');
  h.node('nmap-xml-file').files = [{ size: 60001, text: async () => { throw new Error('should not read'); } }];
  await h.submit();
  assert.equal(h.requests.length, 0);
  assert.equal(h.node('nmap-xml-preview-error').classList.contains('hidden'), false);
  h.node('nmap-xml-file').files = [];
  h.node('nmap-xml-paste').value = 'ü'.repeat(30001);
  await h.submit();
  assert.equal(h.requests.length, 0);
});

test('inconsistent API summary is rejected without showing raw details', async () => {
  const h = harness({ ...summary, open_port_count: 2 });
  await h.click('open');
  h.node('nmap-xml-paste').value = sample;
  await h.submit();
  assert.equal(h.node('nmap-xml-preview-result').classList.contains('hidden'), true);
  assert.equal(h.node('nmap-xml-preview-error').classList.contains('hidden'), false);
  assert.equal(h.node('nmap-xml-preview-error').textContent.includes('PRIVATE_HOST'), false);
  await h.click('close');
  assert.equal(h.node('nmap-xml-preview-error').classList.contains('hidden'), true);
  assert.equal(h.node('nmap-xml-paste').value, '');
});

test('explicitly links a parsed aggregate to an authorized manual control', async () => {
  const linked = {
    tool_identity: 'nmap-xml', host_count: 1, up_host_count: 1, open_port_count: 1,
    open_tcp_count: 1, open_udp_count: 0, well_known_count: 1,
    registered_count: 0, dynamic_count: 0, report_sha256: 'b'.repeat(64),
    private_detail: 'PRIVATE_HOST_MUST_NOT_RENDER',
  };
  const h = harness(linked, {
    '/api/engagements': { engagements: [{
      id: 'eng_one', name: 'Authorized', status: 'active', authorization_ref: 'AUTH-1',
      special_approvals: { redacted_data_proof: true },
    }] },
    '/api/engagements/eng_one': { tests: [{ control_id: 'SNIPER-INF-01', title: 'Inventory' }] },
  });
  await h.click('open');
  h.node('nmap-xml-link-opt-in').checked = true;
  await h.node('nmap-xml-link-opt-in').handlers.get('change')();
  assert.equal(h.node('nmap-xml-link-engagement').children[1].value, 'eng_one');
  h.node('nmap-xml-link-engagement').value = 'eng_one';
  await h.node('nmap-xml-link-engagement').handlers.get('change')();
  h.node('nmap-xml-link-control').value = 'SNIPER-INF-01';
  h.node('nmap-xml-paste').value = sample;
  await h.submit();
  const post = h.requests.at(-1);
  assert.equal(post.url, '/api/engagements/eng_one/tool-evidence/nmap');
  assert.deepEqual(JSON.parse(post.options.body), {
    control_id: 'SNIPER-INF-01', report: sample, confirm_link: true,
  });
  assert.equal(h.node('nmap-xml-open-port-count').textContent, '1');
  assert.equal(h.node('nmap-xml-link-result').classList.contains('hidden'), false);
  assert.equal(h.node('nmap-xml-report-sha256').textContent, 'b'.repeat(64));
  assert.equal(h.node('nmap-xml-preview-result').classList.contains('hidden'), false);
  assert.equal(['host-count', 'up-host-count', 'open-port-count', 'protocol-counts', 'port-bands', 'report-sha256']
    .map(id => h.node(`nmap-xml-${id}`).textContent).join(' ').includes('PRIVATE_HOST'), false);
});

test('opt-in without selected authorization and control does not POST a report', async () => {
  const h = harness(summary, { '/api/engagements': { engagements: [] } });
  await h.click('open');
  h.node('nmap-xml-link-opt-in').checked = true;
  await h.node('nmap-xml-link-opt-in').handlers.get('change')();
  h.node('nmap-xml-paste').value = sample;
  await h.submit();
  assert.equal(h.requests.some(item => item.options?.method === 'POST'), false);
  assert.equal(h.node('nmap-xml-preview-error').classList.contains('hidden'), false);
});

const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

test('closing while local file read is pending must not POST old report', async () => {
  const h = harness();
  await h.click('open');
  const read = deferred();
  h.node('nmap-xml-file').files = [{ size: Buffer.byteLength(sample), text: () => read.promise }];
  const pending = h.submit();
  assert.equal(h.node('nmap-xml-preview-submit').disabled, true);
  await h.click('close');
  assert.equal(h.node('nmap-xml-preview-submit').disabled, false);
  read.resolve(sample);
  await pending;
  assert.equal(h.requests.filter(r => r.options?.method === 'POST').length, 0);
  assert.equal(h.node('nmap-xml-preview-result').classList.contains('hidden'), true);
  assert.equal(h.node('nmap-xml-preview-error').classList.contains('hidden'), true);
});

test('editing paste or changing file selection while local file read is pending invalidates stale file read', async () => {
  const h = harness();
  await h.click('open');
  const read = deferred();
  h.node('nmap-xml-file').files = [{ size: Buffer.byteLength(sample), text: () => read.promise }];
  const pending = h.submit();
  h.node('nmap-xml-paste').value = '<nmaprun><host><status state="up"/></host></nmaprun>';
  await h.node('nmap-xml-paste').handlers.get('input')?.();
  read.resolve(sample);
  await pending;
  assert.equal(h.requests.filter(r => r.options?.method === 'POST').length, 0);
  assert.equal(h.node('nmap-xml-preview-submit').disabled, false);
});

test('second submit while old file read is pending must not send old file too', async () => {
  const h = harness();
  await h.click('open');
  const read = deferred();
  h.node('nmap-xml-file').files = [{ size: Buffer.byteLength(sample), text: () => read.promise }];
  const pending = h.submit();
  const replacement = '<nmaprun><host><status state="up"/></host></nmaprun>';
  h.node('nmap-xml-paste').value = replacement;
  await h.submit();
  read.resolve(sample);
  await pending;
  const posts = h.requests.filter(r => r.options?.method === 'POST');
  assert.equal(posts.length, 1);
  assert.deepEqual(JSON.parse(posts[0].options.body), { report: replacement });
  assert.equal(h.node('nmap-xml-preview-result').classList.contains('hidden'), false);
});

test('linked evidence: delayed first file must not create a second distinct report link', async () => {
  const linked = {
    tool_identity: 'nmap-xml', host_count: 1, up_host_count: 1, open_port_count: 1,
    open_tcp_count: 1, open_udp_count: 0, well_known_count: 1,
    registered_count: 0, dynamic_count: 0, report_sha256: 'b'.repeat(64),
  };
  const h = harness(linked, {
    '/api/engagements': { engagements: [{
      id: 'eng_one', name: 'Authorized', status: 'active', authorization_ref: 'AUTH-1',
      special_approvals: { redacted_data_proof: true },
    }] },
    '/api/engagements/eng_one': { tests: [{ control_id: 'SNIPER-INF-01', title: 'Inventory' }] },
  });
  await h.click('open');
  h.node('nmap-xml-link-opt-in').checked = true;
  await h.node('nmap-xml-link-opt-in').handlers.get('change')();
  h.node('nmap-xml-link-engagement').value = 'eng_one';
  await h.node('nmap-xml-link-engagement').handlers.get('change')();
  h.node('nmap-xml-link-control').value = 'SNIPER-INF-01';
  const read = deferred();
  h.node('nmap-xml-file').files = [{ size: Buffer.byteLength(sample), text: () => read.promise }];
  const pending = h.submit();
  const replacement = '<nmaprun><host><status state="up"/></host></nmaprun>';
  h.node('nmap-xml-paste').value = replacement;
  await h.submit();
  read.resolve(sample);
  await pending;
  const linkPosts = h.requests.filter(r => r.url === '/api/engagements/eng_one/tool-evidence/nmap');
  assert.equal(linkPosts.length, 1);
  assert.deepEqual(JSON.parse(linkPosts[0].options.body), {
    control_id: 'SNIPER-INF-01', report: replacement, confirm_link: true,
  });
});

test('opt-in ON -> OFF -> ON delayed engagement GET does not append stale options or corrupt current selection, and sends no POST', async () => {
  const pendingGets = [];
  const makeEngagement = id => ({
    id, name: id, status: 'active', authorization_ref: 'AUTH-1',
    special_approvals: { redacted_data_proof: true },
  });
  const h = harness(summary, {
    '/api/engagements': () => {
      const d = deferred();
      pendingGets.push(d);
      return d.promise;
    },
    '/api/engagements/current-engagement': {
      tests: [{ control_id: 'SNIPER-INF-01', title: 'Inventory' }],
    },
  });
  await h.click('open');
  h.node('nmap-xml-paste').value = sample;
  await h.submit();
  assert.equal(h.node('nmap-xml-preview-result').classList.contains('hidden'), false);
  const postsBeforeToggle = h.requests.filter(r => r.options?.method === 'POST').length;

  const optIn = h.node('nmap-xml-link-opt-in');
  const changeOptIn = () => optIn.handlers.get('change')();

  // Normal single ON control
  optIn.checked = true;
  const firstOn = changeOptIn();
  pendingGets[0].resolve({ ok: true, json: async () => ({ engagements: [makeEngagement('normal-control')] }) });
  await firstOn;
  assert.deepEqual(h.node('nmap-xml-link-engagement').children.map(c => c.value), ['', 'normal-control']);

  // OFF preserves passive summary and clears selector
  optIn.checked = false;
  await changeOptIn();
  assert.equal(h.node('nmap-xml-preview-result').classList.contains('hidden'), false);
  assert.deepEqual(h.node('nmap-xml-link-engagement').children.map(c => c.value), []);

  // ON #1 (stale) -> OFF -> ON #2 (latest)
  optIn.checked = true;
  const staleOn = changeOptIn();
  optIn.checked = false;
  await changeOptIn();
  optIn.checked = true;
  const latestOn = changeOptIn();

  pendingGets[2].resolve({ ok: true, json: async () => ({ engagements: [makeEngagement('current-engagement')] }) });
  await latestOn;
  assert.deepEqual(h.node('nmap-xml-link-engagement').children.map(c => c.value), ['', 'current-engagement']);

  h.node('nmap-xml-link-engagement').value = 'current-engagement';
  await h.node('nmap-xml-link-engagement').handlers.get('change')();
  h.node('nmap-xml-link-control').value = 'SNIPER-INF-01';

  // Stale ON #1 resolves after latest ON #2
  pendingGets[1].resolve({ ok: true, json: async () => ({ engagements: [makeEngagement('older-engagement')] }) });
  await staleOn;

  assert.deepEqual(h.node('nmap-xml-link-engagement').children.map(c => c.value), ['', 'current-engagement']);
  assert.equal(h.node('nmap-xml-link-engagement').value, 'current-engagement');
  assert.equal(h.node('nmap-xml-link-control').value, 'SNIPER-INF-01');
  assert.equal(optIn.checked, true);
  assert.equal(h.node('nmap-xml-preview-error').classList.contains('hidden'), true);
  assert.equal(h.requests.filter(r => r.options?.method === 'POST').length, postsBeforeToggle);
});

test('stale opt-in GET resolving first or failing after OFF/ON never populates list or shows stale error', async () => {
  const pendingGets = [];
  const makeEngagement = id => ({
    id, name: id, status: 'active', authorization_ref: 'AUTH-1',
    special_approvals: { redacted_data_proof: true },
  });
  const h = harness(summary, {
    '/api/engagements': () => {
      const d = deferred();
      pendingGets.push(d);
      return d.promise;
    },
  });
  await h.click('open');
  const optIn = h.node('nmap-xml-link-opt-in');
  const changeOptIn = () => optIn.handlers.get('change')();

  // Case 1: Stale ON #1 resolves before latest ON #2
  optIn.checked = true;
  const staleFirst = changeOptIn();
  optIn.checked = false;
  await changeOptIn();
  optIn.checked = true;
  const latestSecond = changeOptIn();

  pendingGets[0].resolve({ ok: true, json: async () => ({ engagements: [makeEngagement('stale-first')] }) });
  await staleFirst;
  assert.deepEqual(h.node('nmap-xml-link-engagement').children.map(c => c.value), []);

  pendingGets[1].resolve({ ok: true, json: async () => ({ engagements: [makeEngagement('latest-second')] }) });
  await latestSecond;
  assert.deepEqual(h.node('nmap-xml-link-engagement').children.map(c => c.value), ['', 'latest-second']);

  // Case 2: Stale ON #3 fails after OFF -> ON #4 succeeds
  optIn.checked = false;
  await changeOptIn();
  optIn.checked = true;
  const staleFail = changeOptIn();
  optIn.checked = false;
  await changeOptIn();
  optIn.checked = true;
  const latestOk = changeOptIn();

  pendingGets[3].resolve({ ok: true, json: async () => ({ engagements: [makeEngagement('valid-after-fail')] }) });
  await latestOk;
  pendingGets[2].resolve({ ok: false, json: async () => ({}) });
  await staleFail;

  assert.deepEqual(h.node('nmap-xml-link-engagement').children.map(c => c.value), ['', 'valid-after-fail']);
  assert.equal(h.node('nmap-xml-preview-error').classList.contains('hidden'), true);
  assert.equal(h.node('nmap-xml-preview-error').textContent, '');
  assert.equal(h.requests.some(r => r.options?.method === 'POST'), false);
});
