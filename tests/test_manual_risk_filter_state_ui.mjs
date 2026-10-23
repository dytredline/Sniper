import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const appJsPath = process.env.SNIPER_UI_APP_JS || new URL('../static/app.js', import.meta.url).pathname;

function makeHarness(findings) {
  const engagement = {
    id: 'eng-task30',
    name: 'Synthetic manual review',
    target_id: 'target-1',
    target_url: 'https://127.0.0.1:8443',
    authorization_ref: 'SYNTHETIC-AUTH',
    status: 'active',
    coverage: { percent: 0, completed: 0, total: 0 },
    remediation: { active: 1, resolved: 1, risk_accepted: 1 },
    categories: [],
    tests: [],
    findings: structuredClone(findings),
  };
  const originalFindings = structuredClone(engagement.findings);
  const elements = new Map();
  const listeners = new Map();
  const requests = [];

  function element(key) {
    if (elements.has(key)) return elements.get(key);
    const classes = new Set();
    const node = {
      id: String(key).replace(/^#/, ''),
      dataset: {},
      style: {},
      value: '',
      files: [],
      innerHTML: '',
      textContent: '',
      href: '',
      disabled: false,
      classList: {
        add(name) { classes.add(name); },
        remove(name) { classes.delete(name); },
        contains(name) { return classes.has(name); },
        toggle(name, force) {
          if (force === undefined ? !classes.has(name) : force) classes.add(name);
          else classes.delete(name);
        },
      },
      addEventListener() {},
      append() {},
      appendChild() {},
      replaceChildren() {},
      remove() {},
      focus() {},
      reset() {},
      setSelectionRange() {},
      setAttribute() {},
      removeAttribute() {},
      querySelector(selector) { return element(selector); },
      querySelectorAll() { return []; },
      closest() { return null; },
    };
    elements.set(key, node);
    return node;
  }

  const document = {
    body: element('body'),
    getElementById(id) { return element('#' + id); },
    querySelector(selector) { return element(selector); },
    querySelectorAll() { return []; },
    createElement(tag) { return element('created:' + tag); },
    addEventListener(type, callback) {
      const list = listeners.get(type) || [];
      list.push(callback);
      listeners.set(type, list);
    },
  };

  async function fetch(path, options = {}) {
    requests.push({ path, method: options.method || 'GET' });
    if (path === '/api/engagements/' + encodeURIComponent(engagement.id)) {
      return { ok: true, status: 200, json: async () => structuredClone(engagement) };
    }
    const defaults = {
      '/api/dashboard': {},
      '/api/targets': { targets: [] },
      '/api/scans?limit=200': { scans: [] },
      '/api/engagements': { engagements: [] },
      '/api/lab-runs': { lab_runs: [] },
      '/api/project-audits': { project_audits: [], total: 0 },
      '/api/tooling': { tools: [], categories: [], summary: {}, policy: {} },
      '/api/tooling/readiness': { tools: [] },
      '/api/dependency-security': {},
    };
    return { ok: true, status: 200, json: async () => defaults[path] || {} };
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
  vm.runInContext(fs.readFileSync(appJsPath, 'utf8'), context, { filename: appJsPath });

  async function click(dataset) {
    const target = {
      dataset,
      id: '',
      classList: { contains() { return false; } },
      closest(selector) {
        if (selector === '[data-action]' && dataset.action) return this;
        if (selector === '[data-workspace-tab]' && dataset.workspaceTab) return this;
        if (selector === '[data-finding-filter]' && dataset.findingFilter) return this;
        return null;
      },
    };
    for (const callback of listeners.get('click') || []) {
      await callback({ target, preventDefault() {}, stopPropagation() {} });
    }
  }

  return {
    async showFindings() {
      await new Promise(resolve => setImmediate(resolve));
      await click({ action: 'open-engagement', id: engagement.id });
      await click({ workspaceTab: 'findings' });
    },
    click,
    get html() { return element('#workspace-content').innerHTML; },
    get requests() { return requests; },
    get currentFindings() {
      return JSON.parse(vm.runInContext('JSON.stringify(state.selectedEngagement.findings)', context));
    },
    originalFindings,
  };
}

function buttonState(html, key) {
  for (const match of html.matchAll(/<button\b([^>]*)>([^<]*)<\/button>/g)) {
    const attrs = match[1];
    const filter = attrs.match(/\bdata-finding-filter="([^"]+)"/);
    if (!filter || filter[1] !== key) continue;
    return {
      label: match[2],
      nativeButton: true,
      active: /\bclass="[^"]*\bactive\b/.test(attrs),
      pressed: attrs.match(/\baria-pressed="(true|false)"/)?.[1] ?? null,
    };
  }
  return null;
}

function cardIds(html) {
  return [...html.matchAll(/<article\b[^>]*class="manual-finding-card[^"]*"[^>]*data-id="([^"]+)"/g)]
    .map(match => match[1]);
}

const findings = [
  { id: 'F-ACCEPTED', status: 'risk_accepted', severity: 'low', title: 'Accepted risk',
    description: 'Compensating control', affected_asset: '/internal',
    updated_at: '2026-10-16T10:00:00Z', evidence: 'RAW_SECRET_DO_NOT_RENDER' },
  { id: 'F-RESOLVED', status: 'resolved', severity: 'medium', title: 'Resolved risk',
    description: 'Patched', affected_asset: '/public', updated_at: '2026-10-16T11:00:00Z' },
  { id: 'F-OPEN', status: 'open', severity: 'high', title: 'Open risk',
    description: 'Unresolved', affected_asset: '/api', updated_at: '2026-10-16T12:00:00Z' },
];

test('control: existing all and closed groups still render runtime counts and cards', async () => {
  const h = makeHarness(findings);
  await h.showFindings();
  assert.match(h.html, /<b>3 \/ 3 kayıt<\/b>/);
  assert.deepEqual(cardIds(h.html), ['F-ACCEPTED', 'F-RESOLVED', 'F-OPEN']);
  await h.click({ findingFilter: 'closed' });
  assert.match(h.html, /<b>2 \/ 3 kayıt<\/b>/);
  assert.deepEqual(cardIds(h.html), ['F-ACCEPTED', 'F-RESOLVED']);
});

test('native Risk kabulü button filters locally and updates aria-pressed with no mutation', async () => {
  const h = makeHarness(findings);
  await h.showFindings();
  assert.deepEqual(buttonState(h.html, 'risk_accepted'), {
    label: 'Risk kabulü', nativeButton: true, active: false, pressed: 'false',
  });
  const requestCount = h.requests.length;
  await h.click({ findingFilter: 'risk_accepted' });
  assert.equal(h.requests.length, requestCount);
  assert.match(h.html, /<b>1 \/ 3 kayıt<\/b>/);
  assert.deepEqual(cardIds(h.html), ['F-ACCEPTED']);
  assert.deepEqual(buttonState(h.html, 'risk_accepted'), {
    label: 'Risk kabulü', nativeButton: true, active: true, pressed: 'true',
  });
  assert.equal(buttonState(h.html, 'closed').pressed, 'false');
  assert.doesNotMatch(h.html, /RAW_SECRET_DO_NOT_RENDER/);
  assert.deepEqual(h.currentFindings, h.originalFindings);
  await h.click({ findingFilter: 'closed' });
  assert.equal(buttonState(h.html, 'risk_accepted').pressed, 'false');
  assert.equal(buttonState(h.html, 'closed').pressed, 'true');
});

test('Risk kabulü empty state clears prior cards', async () => {
  const h = makeHarness(findings.filter(f => f.status !== 'risk_accepted'));
  await h.showFindings();
  assert.deepEqual(cardIds(h.html), ['F-RESOLVED', 'F-OPEN']);
  await h.click({ findingFilter: 'risk_accepted' });
  assert.match(h.html, /<b>0 \/ 2 kayıt<\/b>/);
  assert.deepEqual(cardIds(h.html), []);
  assert.match(h.html, /Bu filtrede bulgu yok/);
});
