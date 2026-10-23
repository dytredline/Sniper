import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const APP = process.env.SNIPER_UI_APP_JS || new URL('../static/app.js', import.meta.url).pathname;
const LINK_JS = new URL('../static/nuclei_link_preview.js', import.meta.url).pathname;

const LINE_A = JSON.stringify({
  'template-id': 'http-missing-security-headers',
  type: 'http',
  info: { name: 'Missing Headers', severity: 'high' }
});
const LINE_B = JSON.stringify({
  'template-id': 'tls-version',
  type: 'ssl',
  info: { name: 'TLS Version', severity: 'low' }
});

function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function tick() {
  return new Promise(resolve => setImmediate(resolve));
}

function summaryResponse(severity, shaChar) {
  return {
    format: 'nuclei-jsonl',
    record_count: 1,
    unique_template_count: 1,
    severity_counts: {
      info: 0,
      low: severity === 'low' ? 1 : 0,
      medium: 0,
      high: severity === 'high' ? 1 : 0,
      critical: 0,
      unknown: 0,
    },
    report_sha256: shaChar.repeat(64),
  };
}

function harness() {
  const nodes = new Map();
  const listeners = new Map();
  const pending = [];
  const posts = [];
  const controlPending = new Map();

  function node(key) {
    if (nodes.has(key)) return nodes.get(key);
    const classes = new Set();
    const n = {
      id: String(key).replace(/^#/, ''),
      dataset: {},
      style: {},
      value: '',
      files: [],
      checked: false,
      disabled: false,
      innerHTML: '',
      textContent: '',
      classList: {
        add: name => classes.add(name),
        remove: name => classes.delete(name),
        contains: name => classes.has(name),
        toggle(name, force) {
          if (force === undefined ? !classes.has(name) : force) classes.add(name);
          else classes.delete(name);
        },
      },
      addEventListener() {},
      append(child) {
        if (child && typeof child === 'object') {
          this.innerHTML += `<option value="${child.value ?? ''}">${child.textContent ?? ''}</option>`;
        }
      },
      replaceChildren() {
        this.innerHTML = '';
        this.value = '';
      },
      appendChild() {},
      remove() {},
      focus() {},
      reset() {},
      setSelectionRange() {},
      setAttribute() {},
      removeAttribute() {},
      hasAttribute() { return false; },
      getClientRects() { return [1]; },
      querySelector: selector => node(selector),
      querySelectorAll: () => [],
      matches() { return false; },
      closest(selector) {
        if (selector === '[data-action]' && this.dataset.action) return this;
        if (selector === '[data-close]' && this.dataset.close) return this;
        if (selector.startsWith('[data-action=') && selector.includes(this.dataset.action)) return this;
        if (selector.startsWith('[data-close=') && selector.includes(this.dataset.close)) return this;
        return null;
      },
    };
    nodes.set(key, n);
    return n;
  }

  const document = {
    body: node('body'),
    activeElement: node('body'),
    querySelector: selector => node(selector),
    querySelectorAll: selector => {
      if (selector === '.modal') {
        return [node('#nuclei-jsonl-preview-modal')];
      }
      return [];
    },
    getElementById: id => node('#' + id),
    createElement: tag => node('created:' + tag),
    addEventListener(name, cb) {
      const list = listeners.get(name) || [];
      list.push(cb);
      listeners.set(name, list);
    },
  };

  const getResponses = {
    '/api/dashboard': {},
    '/api/targets': { targets: [] },
    '/api/scans?limit=200': { scans: [] },
    '/api/engagements': {
      engagements: [
        {
          id: 'eng-1',
          name: 'Yetkili Denetim',
          status: 'active',
          authorization_ref: 'AUTH-2026-1',
          scope_notes: 'Kapsam onaylı',
          special_approvals: { redacted_data_proof: true },
        },
      ],
    },
    '/api/lab-runs': { lab_runs: [] },
    '/api/project-audits': { project_audits: [], total: 0 },
    '/api/tooling': { tools: [], categories: [], summary: {}, policy: { native: '', external: '', completion: '' } },
    '/api/dependency-security': {},
  };

  async function fetch(path, options = {}) {
    if (path === '/api/engagements/eng-1') {
      if (controlPending.has('eng-1')) {
        return controlPending.get('eng-1').promise.then(body => ({ ok: true, status: 200, json: async () => body }));
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ id: 'eng-1', tests: [{ control_id: 'API-01', title: 'Sema' }] }),
      };
    }
    if (options.method === 'POST') {
      posts.push({ path, body: JSON.parse(options.body) });
      assert.ok(
        path === '/api/tool-reports/nuclei-jsonl/summary' ||
          path === '/api/engagements/eng-1/tool-evidence/nuclei-jsonl',
        `Unexpected POST path: ${path}`
      );
      const d = deferred();
      pending.push(d);
      return d.promise.then(
        body => ({ ok: true, status: 200, json: async () => body }),
        err => ({ ok: false, status: err?.status || 500, json: async () => ({ error: err?.message || 'Sunucu hatası.' }) })
      );
    }
    return { ok: true, status: 200, json: async () => getResponses[path] || {} };
  }

  const context = vm.createContext({
    document,
    window: { addEventListener() {} },
    location: { hash: '' },
    history: { replaceState() {} },
    fetch,
    TextEncoder,
    URL,
    console,
    setTimeout: () => 0,
    clearTimeout() {},
    setInterval: () => 0,
  });

  vm.runInContext(fs.readFileSync(APP, 'utf8'), context, { filename: APP });
  if (fs.existsSync(LINK_JS)) {
    vm.runInContext(fs.readFileSync(LINK_JS, 'utf8'), context, { filename: LINK_JS });
  }

  node('#nuclei-jsonl-preview-modal').classList.add('hidden');
  node('#nuclei-jsonl-preview-result').classList.add('hidden');
  node('#nuclei-jsonl-preview-error').classList.add('hidden');
  node('#nuclei-jsonl-link-result').classList.add('hidden');

  async function dispatch(name, target, wait = true, extra = {}) {
    let defaultPrevented = false;
    const event = {
      target,
      currentTarget: target,
      ...extra,
      get defaultPrevented() { return defaultPrevented; },
      preventDefault() { defaultPrevented = true; },
      stopPropagation() {},
      stopImmediatePropagation() {},
    };
    const run = Promise.all((listeners.get(name) || []).map(cb => cb(event)));
    if (wait) await run;
    return run;
  }

  function action(value) {
    const n = node('action:' + value);
    n.dataset.action = value;
    return n;
  }

  function close(value) {
    const n = node('close:' + value);
    n.dataset.close = value;
    return n;
  }

  return { node, pending, posts, controlPending, dispatch, action, close, context, ready: tick };
}

test('control: in-order paste and file Nuclei JSONL summary POSTs render aggregate without linking', async () => {
  const h = harness();
  await h.ready();
  await h.dispatch('click', h.action('open-nuclei-jsonl-preview'));
  assert.equal(h.posts.length, 0);

  h.node('#nuclei-jsonl-paste').value = LINE_A;
  const pasteRun = h.dispatch('submit', h.node('#nuclei-jsonl-preview-form'), false);
  await tick();
  assert.equal(h.posts.length, 1);
  assert.equal(h.posts[0].path, '/api/tool-reports/nuclei-jsonl/summary');
  h.pending[0].resolve(summaryResponse('high', 'a'));
  await pasteRun;

  assert.equal(h.node('#nuclei-jsonl-preview-result').classList.contains('hidden'), false);
  assert.equal(h.node('#nuclei-jsonl-report-sha256').textContent, 'a'.repeat(64));
  assert.equal(h.node('#nuclei-jsonl-paste').value, '');

  h.node('#nuclei-jsonl-file').value = 'report.jsonl';
  h.node('#nuclei-jsonl-file').files = [{ size: LINE_B.length, text: async () => LINE_B }];
  const fileRun = h.dispatch('submit', h.node('#nuclei-jsonl-preview-form'), false);
  await tick();
  assert.equal(h.posts.length, 2);
  h.pending[1].resolve(summaryResponse('low', 'b'));
  await fileRun;

  assert.equal(h.node('#nuclei-jsonl-preview-result').classList.contains('hidden'), false);
  assert.equal(h.node('#nuclei-jsonl-report-sha256').textContent, 'b'.repeat(64));
  assert.equal(h.node('#nuclei-jsonl-file').value, '');
});

test('close/reopen via close button, backdrop, and Escape invalidates late summary and error responses', async () => {
  const h = harness();
  await h.ready();

  // 1. Close button while summary POST is in flight
  await h.dispatch('click', h.action('open-nuclei-jsonl-preview'));
  h.node('#nuclei-jsonl-paste').value = LINE_A;
  const run1 = h.dispatch('submit', h.node('#nuclei-jsonl-preview-form'), false);
  await tick();
  assert.equal(h.posts.length, 1);

  await h.dispatch('click', h.close('nuclei-jsonl-preview-modal'));
  assert.equal(h.node('#nuclei-jsonl-preview-modal').classList.contains('hidden'), true);
  assert.equal(h.node('#nuclei-jsonl-preview-result').classList.contains('hidden'), true);

  h.pending[0].resolve(summaryResponse('high', 'a'));
  await run1;

  await h.dispatch('click', h.action('open-nuclei-jsonl-preview'));
  assert.equal(h.node('#nuclei-jsonl-preview-result').classList.contains('hidden'), true);
  assert.equal(h.node('#nuclei-jsonl-report-sha256').textContent, '');

  // 2. Backdrop click while error response is in flight
  h.node('#nuclei-jsonl-paste').value = LINE_A;
  const run2 = h.dispatch('submit', h.node('#nuclei-jsonl-preview-form'), false);
  await tick();
  assert.equal(h.posts.length, 2);

  await h.dispatch('click', h.node('#nuclei-jsonl-preview-modal'));
  assert.equal(h.node('#nuclei-jsonl-preview-modal').classList.contains('hidden'), true);
  h.pending[1].reject(new Error('network error'));
  await run2;

  assert.equal(h.node('#nuclei-jsonl-preview-error').classList.contains('hidden'), true);
  assert.equal(h.node('#nuclei-jsonl-preview-error').textContent, '');

  // 3. Escape key while summary POST is in flight
  await h.dispatch('click', h.action('open-nuclei-jsonl-preview'));
  h.node('#nuclei-jsonl-paste').value = LINE_B;
  const run3 = h.dispatch('submit', h.node('#nuclei-jsonl-preview-form'), false);
  await tick();
  assert.equal(h.posts.length, 3);

  await h.dispatch('keydown', h.node('body'), true, { key: 'Escape' });
  assert.equal(h.node('#nuclei-jsonl-preview-modal').classList.contains('hidden'), true);
  assert.equal(h.node('#nuclei-jsonl-paste').value, '');
  h.pending[2].resolve(summaryResponse('low', 'b'));
  await run3;

  assert.equal(h.node('#nuclei-jsonl-preview-result').classList.contains('hidden'), true);
  assert.equal(h.node('#nuclei-jsonl-report-sha256').textContent, '');
  assert.equal(h.posts.length, 3);
});

test('older request A resolving or failing after newer request B must not overwrite B summary or confirmed evidence link', async () => {
  const h = harness();
  await h.ready();

  await h.dispatch('click', h.action('open-nuclei-jsonl-preview'));
  h.node('#nuclei-jsonl-paste').value = LINE_A;
  const first = h.dispatch('submit', h.node('#nuclei-jsonl-preview-form'), false);
  await tick();
  assert.equal(h.posts.length, 1);

  await h.dispatch('click', h.close('nuclei-jsonl-preview-modal'));
  await h.dispatch('click', h.action('open-nuclei-jsonl-preview'));

  const optIn = h.node('#nuclei-jsonl-link-opt-in');
  optIn.checked = true;
  await h.dispatch('change', optIn);
  const engagement = h.node('#nuclei-jsonl-link-engagement');
  engagement.value = 'eng-1';
  await h.dispatch('change', engagement);
  const control = h.node('#nuclei-jsonl-link-control');
  control.value = 'API-01';

  h.node('#nuclei-jsonl-paste').value = LINE_B;
  const second = h.dispatch('submit', h.node('#nuclei-jsonl-preview-form'), false);
  await tick();
  assert.equal(h.posts.length, 2);
  assert.equal(h.posts[1].path, '/api/engagements/eng-1/tool-evidence/nuclei-jsonl');
  assert.equal(h.posts[1].body.confirm_link, true);
  assert.equal(h.posts[1].body.control_id, 'API-01');

  h.pending[1].resolve({
    ...summaryResponse('low', 'b'),
    tool_identity: 'nuclei-jsonl',
  });
  await second;

  assert.equal(h.node('#nuclei-jsonl-preview-result').classList.contains('hidden'), false);
  assert.equal(h.node('#nuclei-jsonl-link-result').classList.contains('hidden'), false);
  assert.equal(h.node('#nuclei-jsonl-report-sha256').textContent, 'b'.repeat(64));

  // Late response from A must not overwrite B
  h.pending[0].resolve(summaryResponse('high', 'a'));
  await first;

  assert.equal(h.node('#nuclei-jsonl-report-sha256').textContent, 'b'.repeat(64));
  assert.equal(h.node('#nuclei-jsonl-severity-counts').textContent, 'info:0 low:1 medium:0 high:0 critical:0 unknown:0');
  assert.equal(h.node('#nuclei-jsonl-link-result').classList.contains('hidden'), false);
  assert.equal(h.node('#nuclei-jsonl-preview-error').classList.contains('hidden'), true);
});

test('async file.text() close/reopen and same-open-modal input edit invalidate stale responses', async () => {
  const h = harness();
  await h.ready();

  await h.dispatch('click', h.action('open-nuclei-jsonl-preview'));
  const slowFile = deferred();
  h.node('#nuclei-jsonl-file').value = 'slow.jsonl';
  h.node('#nuclei-jsonl-file').files = [{ size: LINE_A.length, text: () => slowFile.promise }];

  const fileSubmit = h.dispatch('submit', h.node('#nuclei-jsonl-preview-form'), false);
  await tick();
  assert.equal(h.posts.length, 0);

  // Close before file.text() finishes: must not POST when file.text() resolves
  await h.dispatch('click', h.close('nuclei-jsonl-preview-modal'));
  slowFile.resolve(LINE_A);
  await fileSubmit;
  assert.equal(h.posts.length, 0);
  assert.equal(h.node('#nuclei-jsonl-preview-result').classList.contains('hidden'), true);

  // Reopen, submit paste A, then edit paste while A is in flight
  await h.dispatch('click', h.action('open-nuclei-jsonl-preview'));
  h.node('#nuclei-jsonl-paste').value = LINE_A;
  const editRun = h.dispatch('submit', h.node('#nuclei-jsonl-preview-form'), false);
  await tick();
  assert.equal(h.posts.length, 1);

  h.node('#nuclei-jsonl-paste').value = LINE_B;
  await h.dispatch('input', h.node('#nuclei-jsonl-paste'));

  h.pending[0].resolve(summaryResponse('high', 'a'));
  await editRun;

  assert.equal(h.node('#nuclei-jsonl-paste').value, LINE_B);
  assert.equal(h.node('#nuclei-jsonl-preview-result').classList.contains('hidden'), true);
  assert.equal(h.node('#nuclei-jsonl-report-sha256').textContent, '');
});

test('Escape close resets opt-in consent, engagement/control selections and options, hidden link fields, and ignores late engagement/control fetches; reopen requires fresh opt-in selection', async () => {
  const h = harness();
  await h.ready();

  await h.dispatch('click', h.action('open-nuclei-jsonl-preview'));
  assert.equal(h.node('#nuclei-jsonl-preview-modal').classList.contains('hidden'), false);
  assert.equal(h.posts.length, 0);

  const optIn = h.node('#nuclei-jsonl-link-opt-in');
  const fields = h.node('#nuclei-jsonl-link-fields');
  const engagement = h.node('#nuclei-jsonl-link-engagement');
  const control = h.node('#nuclei-jsonl-link-control');
  const linkResult = h.node('#nuclei-jsonl-link-result');

  optIn.checked = true;
  await h.dispatch('change', optIn);
  await tick();
  assert.equal(fields.classList.contains('hidden'), false);
  assert.match(engagement.innerHTML, /eng-1/);

  engagement.value = 'eng-1';
  await h.dispatch('change', engagement);
  await tick();
  assert.match(control.innerHTML, /API-01/);
  control.value = 'API-01';
  h.node('#nuclei-jsonl-paste').value = LINE_A;

  // Press Escape while opt-in, engagement, control, and paste input are populated
  await h.dispatch('keydown', h.node('body'), true, { key: 'Escape' });

  // Hidden DOM must not retain opt-in consent or engagement/control selections/options
  assert.equal(h.node('#nuclei-jsonl-preview-modal').classList.contains('hidden'), true);
  assert.equal(optIn.checked, false);
  assert.equal(fields.classList.contains('hidden'), true);
  assert.equal(engagement.value, '');
  assert.equal(engagement.innerHTML, '');
  assert.equal(control.value, '');
  assert.equal(control.innerHTML, '');
  assert.equal(linkResult.classList.contains('hidden'), true);
  assert.equal(linkResult.textContent, '');
  assert.equal(h.node('#nuclei-jsonl-paste').value, '');
  assert.equal(h.node('#nuclei-jsonl-file').value, '');
  assert.equal(h.posts.length, 0);

  // In-flight control fetch when Escape closes the modal must not repopulate hidden DOM
  const slowControls = deferred();
  h.controlPending.set('eng-1', slowControls);
  await h.dispatch('click', h.action('open-nuclei-jsonl-preview'));
  optIn.checked = true;
  await h.dispatch('change', optIn);
  await tick();
  engagement.value = 'eng-1';
  const controlLoad = h.dispatch('change', engagement, false);
  await tick();

  await h.dispatch('keydown', h.node('body'), true, { key: 'Escape' });
  slowControls.resolve({ id: 'eng-1', tests: [{ control_id: 'API-01', title: 'Sema' }] });
  await controlLoad;
  await tick();
  h.controlPending.delete('eng-1');

  assert.equal(h.node('#nuclei-jsonl-preview-modal').classList.contains('hidden'), true);
  assert.equal(optIn.checked, false);
  assert.equal(fields.classList.contains('hidden'), true);
  assert.equal(engagement.value, '');
  assert.equal(engagement.innerHTML, '');
  assert.equal(control.value, '');
  assert.equal(control.innerHTML, '');
  assert.equal(h.posts.length, 0);

  // Reopening requires fresh explicit selection; submitting without opt-in performs passive summary only
  await h.dispatch('click', h.action('open-nuclei-jsonl-preview'));
  assert.equal(optIn.checked, false);
  assert.equal(fields.classList.contains('hidden'), true);
  assert.equal(engagement.value, '');
  assert.equal(control.value, '');

  h.node('#nuclei-jsonl-paste').value = LINE_A;
  const passiveRun = h.dispatch('submit', h.node('#nuclei-jsonl-preview-form'), false);
  await tick();
  assert.equal(h.posts.length, 1);
  assert.equal(h.posts[0].path, '/api/tool-reports/nuclei-jsonl/summary');
  h.pending[0].resolve(summaryResponse('high', 'a'));
  await passiveRun;
  assert.equal(h.node('#nuclei-jsonl-preview-result').classList.contains('hidden'), false);
  assert.equal(linkResult.classList.contains('hidden'), true);

  // Checking opt-in again without selecting engagement/control blocks POST
  optIn.checked = true;
  await h.dispatch('change', optIn);
  await tick();
  h.node('#nuclei-jsonl-paste').value = LINE_B;
  await h.dispatch('submit', h.node('#nuclei-jsonl-preview-form'));
  assert.equal(h.posts.length, 1);
  assert.equal(h.node('#nuclei-jsonl-preview-error').classList.contains('hidden'), false);

  // Fresh explicit selection of engagement and control succeeds
  engagement.value = 'eng-1';
  await h.dispatch('change', engagement);
  await tick();
  control.value = 'API-01';
  h.node('#nuclei-jsonl-paste').value = LINE_B;
  const linkRun = h.dispatch('submit', h.node('#nuclei-jsonl-preview-form'), false);
  await tick();
  assert.equal(h.posts.length, 2);
  assert.equal(h.posts[1].path, '/api/engagements/eng-1/tool-evidence/nuclei-jsonl');
  assert.equal(h.posts[1].body.confirm_link, true);
  assert.equal(h.posts[1].body.control_id, 'API-01');
  h.pending[1].resolve({
    ...summaryResponse('low', 'b'),
    tool_identity: 'nuclei-jsonl',
  });
  await linkRun;
  assert.equal(linkResult.classList.contains('hidden'), false);
  assert.equal(h.node('#nuclei-jsonl-report-sha256').textContent, 'b'.repeat(64));
});
