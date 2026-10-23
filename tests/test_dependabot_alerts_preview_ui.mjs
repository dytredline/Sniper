import fs from 'node:fs';
import vm from 'node:vm';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

const appJsPath = process.env.SNIPER_UI_APP_JS || new URL('../static/app.js', import.meta.url).pathname;

function buildFakeDom() {
  const elements = new Map();
  const documentListeners = new Map();
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
      disabled: false,
      classList: {
        add: name => classes.add(name),
        remove: name => classes.delete(name),
        contains: name => classes.has(name),
        toggle(name, force) {
          if (force === undefined ? !classes.has(name) : force) classes.add(name);
          else classes.delete(name);
        },
      },
      addEventListener(name, callback) {
        const key = String(name);
        this.handlers ??= new Map();
        const items = this.handlers.get(key) || [];
        items.push(callback);
        this.handlers.set(key, items);
      },
      append() {},
      appendChild() {},
      remove() {},
      focus() {},
      reset() {},
      setSelectionRange() {},
      setAttribute() {},
      removeAttribute() {},
      querySelector: selector => element(selector),
      querySelectorAll: () => [],
      closest(selector) {
        if (selector === '[data-action]') {
          if (this.dataset.action === 'open-dependabot-alerts-preview') return this;
          if (this.dataset.action === 'submit-dependabot-preview') return this;
        }
        if (selector === '[data-close]') {
          if (this.dataset.close === 'dependabot-preview-modal') return this;
        }
        return null;
      },
    };
    elements.set(key, node);
    return node;
  }

  const document = {
    body: element('body'),
    querySelector: selector => element(selector),
    querySelectorAll: () => [],
    getElementById: id => element('#' + id),
    createElement: tag => element('created:' + tag),
    addEventListener(name, callback) {
      const callbacks = documentListeners.get(name) || [];
      callbacks.push(callback);
      documentListeners.set(name, callbacks);
    },
  };

  const getResponses = {
    '/api/dashboard': {},
    '/api/targets': { targets: [] },
    '/api/scans?limit=200': { scans: [] },
    '/api/engagements': { engagements: [] },
    '/api/lab-runs': { lab_runs: [] },
    '/api/project-audits': { project_audits: [], total: 0 },
    '/api/tooling': { tools: [], categories: [], summary: {}, policy: { native: '', external: '', completion: '' } },
    '/api/dependency-security': {},
  };

  let summaryResponseOverride = null;
  function setSummaryResponseOverride(fn) {
    summaryResponseOverride = fn;
  }

  async function fetch(path, options = {}) {
    requests.push({ path, options });
    const isPost = options.method === 'POST';
    if (isPost && path === '/api/tool-reports/dependabot/summary') {
      const body = JSON.parse(options.body);
      if (body && typeof body === 'object' && Array.isArray(body.alerts)) {
        const synthetic = body.alerts;
        const openCount = synthetic.filter(a => a && a.state === 'open').length;
        const dismissedCount = synthetic.filter(a => a && a.state === 'dismissed').length;
        const fixedCount = synthetic.filter(a => a && a.state === 'fixed').length;
        const autoDismissedCount = synthetic.filter(a => a && a.state === 'auto_dismissed').length;
        const lowCount = synthetic.filter(a => a && a.security_advisory?.severity === 'low').length;
        const mediumCount = synthetic.filter(a => a && a.security_advisory?.severity === 'medium').length;
        const highCount = synthetic.filter(a => a && a.security_advisory?.severity === 'high').length;
        const criticalCount = synthetic.filter(a => a && a.security_advisory?.severity === 'critical').length;
        const openPatchableCount = synthetic.filter(a => {
          if (!a || typeof a !== 'object' || a.state !== 'open') return false;
          const vuln = a.security_vulnerability;
          if (!vuln || typeof vuln !== 'object') return false;
          const firstPatched = vuln.first_patched_version;
          if (!firstPatched || typeof firstPatched !== 'object') return false;
          const id = firstPatched.identifier;
          return typeof id === 'string' && id.trim().length > 0;
        }).length;
        const alertCount = synthetic.length;
        const stateCounts = {
          open: openCount,
          dismissed: dismissedCount,
          fixed: fixedCount,
          auto_dismissed: autoDismissedCount,
        };
        const severityCounts = {
          low: lowCount,
          medium: mediumCount,
          high: highCount,
          critical: criticalCount,
        };
        const reportSha256 = 'a'.repeat(64);
        const defaultPayload = {
          format: 'dependabot-alerts',
          alert_count: alertCount,
          state_counts: stateCounts,
          severity_counts: severityCounts,
          open_alerts_with_available_patched_version: openPatchableCount,
          report_sha256: reportSha256,
        };
        const finalPayload = summaryResponseOverride ? summaryResponseOverride(defaultPayload) : defaultPayload;
        return {
          ok: true,
          status: 200,
          json: async () => finalPayload,
        };
      }
      return { ok: true, status: 200, json: async () => ({ format: '', alert_count: 0, state_counts: {}, severity_counts: {}, report_sha256: '' }) };
    }
    const body = getResponses[path] || {};
    return { ok: true, status: 200, json: async () => body };
  }

  async function dispatchDocument(name, target) {
    const callbacks = documentListeners.get(name) || [];
    const event = { target, currentTarget: target, preventDefault() {}, stopPropagation() {} };
    for (const callback of callbacks) await callback(event);
  }

  return { document, element, requests, documentListeners, fetch, dispatchDocument, setSummaryResponseOverride };
}

function createContext(document, fetch) {
  return vm.createContext({
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
}

function runApp(document, fetch) {
  const context = createContext(document, fetch);
  const appJs = fs.readFileSync(appJsPath, 'utf8');
  vm.runInContext(appJs, context, { filename: appJsPath });
  return new Promise(resolve => setImmediate(resolve));
}

describe('Dependabot alerts preview UI', () => {
  it('should open modal, submit valid alerts object, render aggregate summary, clear inputs', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-dependabot-alerts-preview');
    openBtn.dataset.action = 'open-dependabot-alerts-preview';
    const modal = element('#dependabot-preview-modal');
    modal.classList.add('hidden');
    const form = element('#dependabot-preview-form');
    const pasteInput = element('#dependabot-paste');
    const errorEl = element('#dependabot-preview-error');
    const resultEl = element('#dependabot-preview-result');
    const formatEl = element('#dependabot-format');
    const alertCountEl = element('#dependabot-alert-count');
    const stateCountsEl = element('#dependabot-state-counts');
    const severityCountsEl = element('#dependabot-severity-counts');
    const sha256El = element('#dependabot-report-sha256');

    // Open modal
    await dispatchDocument('click', openBtn);
    assert.strictEqual(modal.classList.contains('hidden'), false);

    // Paste valid alerts object with synthetic open/high and fixed/medium
    const syntheticJson = JSON.stringify({
      alerts: [
        { state: 'open', security_advisory: { severity: 'high', summary: 'Marker in advisory' }, dependency: { package: { name: 'Marker in package' } } },
        { state: 'fixed', security_advisory: { severity: 'medium', summary: 'Marker in advisory' }, dependency: { package: { name: 'Marker in package' } } },
      ],
    });
    pasteInput.value = syntheticJson;

    // Submit form
    await dispatchDocument('submit', form);

    // Assert exactly one POST to /api/tool-reports/dependabot/summary
    const postRequests = requests.filter(r => r.path === '/api/tool-reports/dependabot/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 1);
    const body = JSON.parse(postRequests[0].options.body);
    assert.deepStrictEqual(body, { alerts: JSON.parse(syntheticJson).alerts });

    // Assert aggregate fields rendered
    assert.strictEqual(formatEl.textContent, 'dependabot-alerts');
    assert.strictEqual(String(alertCountEl.textContent), '2');
    assert.strictEqual(stateCountsEl.textContent, 'open:1 dismissed:0 fixed:1 auto_dismissed:0');
    assert.strictEqual(severityCountsEl.textContent, 'low:0 medium:1 high:1 critical:0');
    assert.strictEqual(sha256El.textContent, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

    // Assert result visible and error hidden
    assert.strictEqual(resultEl.classList.contains('hidden'), false);
    assert.strictEqual(errorEl.classList.contains('hidden'), true);

    // Assert no marker or raw advisory/package/path in rendered content
    const formatText = formatEl.textContent;
    const alertCountText = alertCountEl.textContent;
    const stateCountsText = stateCountsEl.textContent;
    const severityCountsText = severityCountsEl.textContent;
    const sha256Text = sha256El.textContent;
    const resultText = resultEl.innerHTML;
    const errorText = errorEl.textContent;
    const allText = [formatText, alertCountText, stateCountsText, severityCountsText, sha256Text, resultText, errorText].join(' ');
    assert.strictEqual(allText.includes('Marker in advisory'), false);
    assert.strictEqual(allText.includes('Marker in package'), false);
    assert.strictEqual(allText.includes('open'), true);
    assert.strictEqual(allText.includes('high'), true);
    assert.strictEqual(allText.includes('fixed'), true);
    assert.strictEqual(allText.includes('medium'), true);
    assert.strictEqual(allText.includes('advisory'), false);
    assert.strictEqual(allText.includes('dependency'), false);
    assert.strictEqual(allText.includes('name'), false);
    assert.strictEqual(allText.includes('state'), false);
    assert.strictEqual(allText.includes('severity'), false);

    // Assert inputs cleared
    assert.strictEqual(pasteInput.value, '');
  });

  it('should reject malformed JSON with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#dependabot-preview-form');
    const pasteInput = element('#dependabot-paste');
    const errorEl = element('#dependabot-preview-error');

    pasteInput.value = '{ invalid json';
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/dependabot/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should reject non-object or non-alerts-array with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#dependabot-preview-form');
    const pasteInput = element('#dependabot-paste');
    const errorEl = element('#dependabot-preview-error');

    pasteInput.value = JSON.stringify({ findings: [] });
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/dependabot/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should clear inputs on close', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-dependabot-alerts-preview');
    const closeBtn = element('#dependabot-preview-modal [data-close="dependabot-preview-modal"]');
    closeBtn.dataset.close = 'dependabot-preview-modal';
    const pasteInput = element('#dependabot-paste');
    const fileInput = element('#dependabot-file');

    await dispatchDocument('click', openBtn);
    pasteInput.value = 'Marker in advisory';
    fileInput.value = 'test.txt';

    await dispatchDocument('click', closeBtn);

    assert.strictEqual(pasteInput.value, '');
    assert.strictEqual(fileInput.value, '');
  });

  it('should render validated open_alerts_with_available_patched_version including positive and zero counts without raw markers', async () => {
    const indexHtmlPath = new URL('../static/index.html', import.meta.url).pathname;
    const indexHtml = fs.readFileSync(indexHtmlPath, 'utf8');
    assert.strictEqual(indexHtml.includes('id="dependabot-open-patchable-count"'), true);

    const { document, element, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-dependabot-alerts-preview');
    openBtn.dataset.action = 'open-dependabot-alerts-preview';
    const form = element('#dependabot-preview-form');
    const pasteInput = element('#dependabot-paste');
    const errorEl = element('#dependabot-preview-error');
    const resultEl = element('#dependabot-preview-result');
    const formatEl = element('#dependabot-format');
    const alertCountEl = element('#dependabot-alert-count');
    const stateCountsEl = element('#dependabot-state-counts');
    const severityCountsEl = element('#dependabot-severity-counts');
    const openPatchableEl = element('#dependabot-open-patchable-count');
    const sha256El = element('#dependabot-report-sha256');

    await dispatchDocument('click', openBtn);

    pasteInput.value = JSON.stringify({
      alerts: [
        {
          state: 'open',
          security_advisory: { severity: 'high', summary: 'SECRET_ADVISORY_TASK16' },
          dependency: { package: { name: 'SECRET_PKG_TASK16' }, manifest_path: 'secret/path/package.json' },
          security_vulnerability: { first_patched_version: { identifier: '2.4.1-PATCH-MARKER' } },
        },
        {
          state: 'open',
          security_advisory: { severity: 'medium', summary: 'SECRET_ADVISORY_TASK16' },
          dependency: { package: { name: 'SECRET_PKG_TASK16' }, manifest_path: 'secret/path/package.json' },
          security_vulnerability: { first_patched_version: null },
        },
        {
          state: 'fixed',
          security_advisory: { severity: 'low', summary: 'SECRET_ADVISORY_TASK16' },
          dependency: { package: { name: 'SECRET_PKG_TASK16' }, manifest_path: 'secret/path/package.json' },
          security_vulnerability: { first_patched_version: { identifier: '1.0.9-FIXED-MARKER' } },
        },
      ],
    });

    await dispatchDocument('submit', form);

    assert.strictEqual(resultEl.classList.contains('hidden'), false);
    assert.strictEqual(errorEl.classList.contains('hidden'), true);
    assert.strictEqual(formatEl.textContent, 'dependabot-alerts');
    assert.strictEqual(String(alertCountEl.textContent), '3');
    assert.strictEqual(stateCountsEl.textContent, 'open:2 dismissed:0 fixed:1 auto_dismissed:0');
    assert.strictEqual(severityCountsEl.textContent, 'low:1 medium:1 high:1 critical:0');
    assert.strictEqual(String(openPatchableEl.textContent), '1');
    assert.strictEqual(sha256El.textContent, 'a'.repeat(64));

    const combined = [
      formatEl.textContent,
      alertCountEl.textContent,
      stateCountsEl.textContent,
      severityCountsEl.textContent,
      openPatchableEl.textContent,
      sha256El.textContent,
      resultEl.innerHTML,
      errorEl.textContent,
    ].join(' ');
    for (const forbidden of [
      'SECRET_ADVISORY_TASK16',
      'SECRET_PKG_TASK16',
      'secret/path/package.json',
      '2.4.1-PATCH-MARKER',
      '1.0.9-FIXED-MARKER',
    ]) {
      assert.strictEqual(combined.includes(forbidden), false);
    }

    // Zero patch-ready count case
    pasteInput.value = JSON.stringify({
      alerts: [
        {
          state: 'open',
          security_advisory: { severity: 'critical' },
          security_vulnerability: { first_patched_version: { identifier: '   ' } },
        },
      ],
    });
    await dispatchDocument('submit', form);
    assert.strictEqual(resultEl.classList.contains('hidden'), false);
    assert.strictEqual(errorEl.classList.contains('hidden'), true);
    assert.strictEqual(String(openPatchableEl.textContent), '0');
  });

  it('should reject missing, negative, fractional, string, or inconsistent patch-ready counts and clear stale state', async () => {
    const { document, element, fetch, dispatchDocument, setSummaryResponseOverride } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-dependabot-alerts-preview');
    openBtn.dataset.action = 'open-dependabot-alerts-preview';
    const closeBtn = element('#dependabot-preview-modal [data-close="dependabot-preview-modal"]');
    closeBtn.dataset.close = 'dependabot-preview-modal';
    const form = element('#dependabot-preview-form');
    const pasteInput = element('#dependabot-paste');
    const errorEl = element('#dependabot-preview-error');
    const resultEl = element('#dependabot-preview-result');
    const openPatchableEl = element('#dependabot-open-patchable-count');

    const validJson = JSON.stringify({
      alerts: [
        {
          state: 'open',
          security_advisory: { severity: 'high' },
          security_vulnerability: { first_patched_version: { identifier: '1.2.3' } },
        },
        {
          state: 'fixed',
          security_advisory: { severity: 'low' },
          security_vulnerability: { first_patched_version: { identifier: '1.0.0' } },
        },
      ],
    });

    const invalidCases = [
      base => {
        const copy = { ...base };
        delete copy.open_alerts_with_available_patched_version;
        return copy;
      },
      base => ({ ...base, open_alerts_with_available_patched_version: -1 }),
      base => ({ ...base, open_alerts_with_available_patched_version: 0.5 }),
      base => ({ ...base, open_alerts_with_available_patched_version: '1' }),
      base => ({ ...base, open_alerts_with_available_patched_version: 2 }), // > state_counts.open (1)
      base => ({ ...base, state_counts: { open: 2, dismissed: 0, fixed: 0, auto_dismissed: 0 }, open_alerts_with_available_patched_version: 3 }), // > alert_count (2)
    ];

    for (const makeBad of invalidCases) {
      // Seed valid state first
      setSummaryResponseOverride(null);
      pasteInput.value = validJson;
      await dispatchDocument('submit', form);
      assert.strictEqual(resultEl.classList.contains('hidden'), false);
      assert.strictEqual(String(openPatchableEl.textContent), '1');

      // Now submit with invalid patch-ready count
      setSummaryResponseOverride(makeBad);
      pasteInput.value = validJson;
      await dispatchDocument('submit', form);
      assert.strictEqual(errorEl.classList.contains('hidden'), false);
      assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
      assert.strictEqual(resultEl.classList.contains('hidden'), true);
      assert.strictEqual(openPatchableEl.textContent, '');
    }

    // Seed valid state again, then test close and reopen clearing
    setSummaryResponseOverride(null);
    pasteInput.value = validJson;
    await dispatchDocument('submit', form);
    assert.strictEqual(String(openPatchableEl.textContent), '1');

    await dispatchDocument('click', closeBtn);
    assert.strictEqual(openPatchableEl.textContent, '');
    assert.strictEqual(resultEl.classList.contains('hidden'), true);

    pasteInput.value = validJson;
    await dispatchDocument('submit', form);
    assert.strictEqual(String(openPatchableEl.textContent), '1');

    await dispatchDocument('click', openBtn);
    assert.strictEqual(openPatchableEl.textContent, '');
    assert.strictEqual(resultEl.classList.contains('hidden'), true);
  });
});

