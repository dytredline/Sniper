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
          if (this.dataset.action === 'open-zap-preview') return this;
          if (this.dataset.action === 'submit-zap-preview') return this;
        }
        if (selector === '[data-close]') {
          if (this.dataset.close === 'zap-preview-modal') return this;
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

  async function fetch(path, options = {}) {
    requests.push({ path, options });
    const isPost = options.method === 'POST';
    if (isPost && path === '/api/tool-runs/zap-self-passive') {
      return { ok: true, status: 200, json: async () => ({
        format: 'zap-self-passive-v1', profile: 'single-health-get-passive-v1',
        site_count: 1, alert_type_count: 1, instance_count: 2,
        risk_counts: { informational: 0, low: 1, medium: 0, high: 0 },
        report_sha256: 'b'.repeat(64),
        secret: 'DO_NOT_RENDER_ZAP_DETAIL',
      }) };
    }
    if (isPost && path === '/api/tool-reports/zap/summary') {
      const body = JSON.parse(options.body);
      if (body && typeof body === 'object' && !Array.isArray(body) && body.report && typeof body.report === 'object' && !Array.isArray(body.report)) {
        const report = body.report;
        const sites = report.site;
        if (Array.isArray(sites)) {
          let totalAlertTypes = 0;
          let totalInstances = 0;
          const riskCounts = { informational: 0, low: 0, medium: 0, high: 0 };
          for (const site of sites) {
            if (site && typeof site === 'object' && !Array.isArray(site)) {
              const alerts = site.alerts;
              if (Array.isArray(alerts)) {
                totalAlertTypes += alerts.length;
                for (const alert of alerts) {
                  if (alert && typeof alert === 'object' && !Array.isArray(alert)) {
                    const riskcodeRaw = alert.riskcode;
                    const countRaw = alert.count;
                    if (typeof riskcodeRaw === 'string' && /[0-3]/.test(riskcodeRaw) && typeof countRaw === 'string' && /^[0-9]+$/.test(countRaw)) {
                      const count = Number(countRaw);
                      if (Number.isSafeInteger(count) && count > 0) {
                        if (riskcodeRaw === '0') riskCounts.informational++;
                        else if (riskcodeRaw === '1') riskCounts.low++;
                        else if (riskcodeRaw === '2') riskCounts.medium++;
                        else if (riskcodeRaw === '3') riskCounts.high++;
                        totalInstances += count;
                      }
                    }
                  }
                }
              }
            }
          }
          const reportSha256 = 'a'.repeat(64);
          return {
            ok: true,
            status: 200,
            json: async () => ({
              format: 'zap-traditional-json',
              site_count: sites.length,
              alert_type_count: totalAlertTypes,
              instance_count: totalInstances,
              risk_counts: riskCounts,
              report_sha256: reportSha256,
            }),
          };
        }
      }
      return { ok: true, status: 200, json: async () => ({ format: '', site_count: 0, alert_type_count: 0, instance_count: 0, risk_counts: {}, report_sha256: '' }) };
    }
    const body = getResponses[path] || {};
    return { ok: true, status: 200, json: async () => body };
  }

  async function dispatchDocument(name, target) {
    const callbacks = documentListeners.get(name) || [];
    const event = { target, currentTarget: target, preventDefault() {}, stopPropagation() {} };
    for (const callback of callbacks) await callback(event);
  }

  return { document, element, requests, documentListeners, fetch, dispatchDocument };
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

describe('ZAP preview UI', () => {
  it('should open modal, submit valid ZAP JSON, render aggregate summary, clear inputs', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-zap-preview');
    openBtn.dataset.action = 'open-zap-preview';
    const modal = element('#zap-preview-modal');
    modal.classList.add('hidden');
    const form = element('#zap-preview-form');
    const pasteInput = element('#zap-paste');
    const errorEl = element('#zap-preview-error');
    const resultEl = element('#zap-preview-result');
    const formatEl = element('#zap-format');
    const siteCountEl = element('#zap-site-count');
    const alertTypeCountEl = element('#zap-alert-type-count');
    const instanceCountEl = element('#zap-instance-count');
    const riskCountsEl = element('#zap-risk-counts');
    const sha256El = element('#zap-report-sha256');

    // Open modal
    await dispatchDocument('click', openBtn);
    assert.strictEqual(modal.classList.contains('hidden'), false);

    // Paste valid ZAP JSON with synthetic report
    const syntheticJson = JSON.stringify({
      site: [{
        name: 'SYNTHETIC_PRIVATE_MARKER',
        alerts: [
          { riskcode: '3', count: '2', name: 'SYNTHETIC_PRIVATE_MARKER' },
          { riskcode: '0', count: '1', name: 'SYNTHETIC_PRIVATE_MARKER' }
        ]
      }]
    });
    pasteInput.value = syntheticJson;

    // Submit form
    await dispatchDocument('submit', form);

    // Assert exactly one POST to /api/tool-reports/zap/summary
    const postRequests = requests.filter(r => r.path === '/api/tool-reports/zap/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 1);
    const body = JSON.parse(postRequests[0].options.body);
    assert.deepStrictEqual(body, { report: JSON.parse(syntheticJson) });

    // Assert aggregate fields rendered
    assert.strictEqual(formatEl.textContent, 'zap-traditional-json');
    assert.strictEqual(String(siteCountEl.textContent), '1');
    assert.strictEqual(String(alertTypeCountEl.textContent), '2');
    assert.strictEqual(String(instanceCountEl.textContent), '3');
    assert.strictEqual(riskCountsEl.textContent, 'informational:1 low:0 medium:0 high:1');
    assert.strictEqual(sha256El.textContent, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

    // Assert result visible and error hidden
    assert.strictEqual(resultEl.classList.contains('hidden'), false);
    assert.strictEqual(errorEl.classList.contains('hidden'), true);

    // Assert no marker or site URL/alert detail/evidence in rendered content
    const formatText = formatEl.textContent;
    const siteCountText = siteCountEl.textContent;
    const alertTypeCountText = alertTypeCountEl.textContent;
    const instanceCountText = instanceCountEl.textContent;
    const riskCountsText = riskCountsEl.textContent;
    const sha256Text = sha256El.textContent;
    const resultText = resultEl.innerHTML;
    const errorText = errorEl.textContent;
    const allText = [formatText, siteCountText, alertTypeCountText, instanceCountText, riskCountsText, sha256Text, resultText, errorText].join(' ');
    assert.strictEqual(allText.includes('SYNTHETIC_PRIVATE_MARKER'), false);
    assert.strictEqual(allText.includes('SYNTHETIC_PRIVATE_MARKER'), false);
    assert.strictEqual(allText.includes('SYNTHETIC_PRIVATE_MARKER'), false);
    assert.strictEqual(allText.includes('riskcode'), false);
    assert.strictEqual(allText.includes('count'), false);
    assert.strictEqual(allText.includes('name'), false);
    assert.strictEqual(allText.includes('informational'), true);
    assert.strictEqual(allText.includes('high'), true);
    assert.strictEqual(allText.includes('zap-traditional-json'), true);

    // Assert inputs cleared
    assert.strictEqual(pasteInput.value, '');
  });

  it('should reject malformed JSON with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#zap-preview-form');
    const pasteInput = element('#zap-paste');
    const errorEl = element('#zap-preview-error');

    pasteInput.value = '{ invalid json';
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/zap/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should reject non-array site with generic error and zero POST', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const form = element('#zap-preview-form');
    const pasteInput = element('#zap-paste');
    const errorEl = element('#zap-preview-error');

    pasteInput.value = JSON.stringify({ site: 'not-array' });
    await dispatchDocument('submit', form);

    const postRequests = requests.filter(r => r.path === '/api/tool-reports/zap/summary' && r.options.method === 'POST');
    assert.strictEqual(postRequests.length, 0);
    assert.strictEqual(errorEl.textContent, 'Geçersiz JSON.');
    assert.strictEqual(errorEl.classList.contains('hidden'), false);
  });

  it('should clear inputs on close', async () => {
    const { document, element, requests, documentListeners, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);

    const openBtn = element('#open-zap-preview');
    const closeBtn = element('#zap-preview-modal [data-close="zap-preview-modal"]');
    closeBtn.dataset.close = 'zap-preview-modal';
    const pasteInput = element('#zap-paste');
    const fileInput = element('#zap-file');

    await dispatchDocument('click', openBtn);
    pasteInput.value = 'Marker in advisory';
    fileInput.value = 'test.txt';

    await dispatchDocument('click', closeBtn);

    assert.strictEqual(pasteInput.value, '');
    assert.strictEqual(fileInput.value, '');
  });

  it('requires explicit consent before a self passive run', async () => {
    const { document, element, requests, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);
    const form = element('#zap-self-passive-form');
    await dispatchDocument('submit', form);
    assert.strictEqual(requests.filter(r => r.path === '/api/tool-runs/zap-self-passive').length, 0);
    assert.strictEqual(element('#zap-self-error').classList.contains('hidden'), false);
  });

  it('runs the fixed self passive profile and renders only aggregate fields', async () => {
    const { document, element, requests, fetch, dispatchDocument } = buildFakeDom();
    await runApp(document, fetch);
    const form = element('#zap-self-passive-form');
    element('#zap-self-confirm').checked = true;
    await dispatchDocument('submit', form);
    const posts = requests.filter(r => r.path === '/api/tool-runs/zap-self-passive');
    assert.strictEqual(posts.length, 1);
    assert.deepStrictEqual(JSON.parse(posts[0].options.body), { confirm_local: true });
    assert.strictEqual(element('#zap-self-result').classList.contains('hidden'), false);
    assert.strictEqual(element('#zap-self-alert-types').textContent, '1');
    assert.strictEqual(element('#zap-self-instances').textContent, '2');
    assert.strictEqual(element('#zap-self-risks').textContent, 'informational:0 low:1 medium:0 high:0');
    assert.strictEqual(element('#zap-self-sha256').textContent, 'b'.repeat(64));
    assert.strictEqual(element('#zap-self-confirm').checked, false);
    assert.strictEqual(element('#zap-self-run-button').disabled, false);
    const rendered = [
      element('#zap-self-alert-types').textContent,
      element('#zap-self-instances').textContent,
      element('#zap-self-risks').textContent,
      element('#zap-self-sha256').textContent,
    ].join(' ');
    assert.strictEqual(rendered.includes('DO_NOT_RENDER_ZAP_DETAIL'), false);
  });
});
