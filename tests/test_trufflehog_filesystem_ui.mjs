import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const jsPath = process.env.SNIPER_TRUFFLEHOG_FS_UI_JS || new URL('../static/trufflehog_filesystem.js', import.meta.url).pathname;
const htmlPath = process.env.SNIPER_TRUFFLEHOG_FS_UI_HTML || new URL('../static/index.html', import.meta.url).pathname;
const source = fs.readFileSync(jsPath, 'utf8');
const html = fs.readFileSync(htmlPath, 'utf8');
const summary = () => ({
  format: 'trufflehog-native-json-records', profile: 'local-filesystem-no-verification-v1',
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
      closest() { return null; },
    };
    nodes.set(id, element); return element;
  }
  const openButton = node('open');
  const document = {
    getElementById: node,
    querySelector(selector) {
      if (selector === '[data-action="open-trufflehog-filesystem"]') return openButton;
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
    async input(value) { node('trufflehog-filesystem-path').value = value; await dispatch(node('trufflehog-filesystem-path'), 'input'); },
    async consent() { node('trufflehog-filesystem-consent').checked = true; await dispatch(node('trufflehog-filesystem-consent'), 'change'); },
    async submit() { await dispatch(node('trufflehog-filesystem-form'), 'submit'); },
  };
}

test('Filesystem has separate launcher, local path, consent and script', () => {
  assert.match(html, /trufflehog_filesystem\.js\?v=1/);
  assert.match(html, /data-action="open-trufflehog-filesystem"/);
  assert.match(html, /id="trufflehog-filesystem-path"/);
  assert.match(html, /id="trufflehog-filesystem-consent"/);
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
  assert.equal(f.node('trufflehog-filesystem-submit').disabled, true);
});

test('explicit consent sends exact local profile request and renders only aggregate', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.input('/home/community-user/project'); await f.consent(); await f.submit();
  assert.equal(f.requests.length, 1);
  const call = f.requests[0];
  assert.equal(call.path, '/api/tool-runs/trufflehog-filesystem');
  assert.equal(call.options.method, 'POST');
  assert.deepEqual(JSON.parse(call.options.body), { confirm_local: true, project_path: '/home/community-user/project' });
  assert.equal(f.node('trufflehog-filesystem-total').textContent, '2');
  assert.equal(f.node('trufflehog-filesystem-unverified').textContent, '2');
  assert.equal(f.node('trufflehog-filesystem-detectors').textContent, '1');
  assert.equal(f.node('trufflehog-filesystem-report-sha256').textContent, 'a'.repeat(64));
  assert.equal(f.node('trufflehog-filesystem-result').classList.contains('hidden'), false);
});

test('inconsistent or hostile response and failed HTTP never show raw content', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.input('/home/community-user/project'); await f.consent();
  f.setResponse({ ok: true, json: async () => ({ ...summary(), unverified_findings: '<script>PRIVATE_REPORT</script>' }) });
  await f.submit();
  assert.equal(f.node('trufflehog-filesystem-result').classList.contains('hidden'), true);
  assert.doesNotMatch(f.node('trufflehog-filesystem-error').textContent, /PRIVATE_REPORT/);
  f.setResponse({ ok: true, json: async () => ({ ...summary(), verified_findings: 1 }) });
  await f.submit();
  assert.equal(f.node('trufflehog-filesystem-result').classList.contains('hidden'), true);
  f.setResponse({ ok: false, status: 503, json: async () => ({ error: 'PRIVATE_REPORT' }) });
  await f.submit();
  assert.doesNotMatch(f.node('trufflehog-filesystem-error').textContent, /PRIVATE_REPORT/);
});

test('pending submit is single-shot and closing discards late response and consent', async () => {
  const f = fixture(); let release;
  f.setResponse(new Promise(resolve => { release = resolve; }));
  await f.init(); await f.open(); await f.input('/home/community-user/project'); await f.consent();
  const first = f.submit(); assert.equal(f.requests.length, 1);
  await f.submit(); assert.equal(f.requests.length, 1);
  await f.documentEvent('click', { target: f.node('trufflehog-filesystem-modal') });
  assert.equal(f.node('trufflehog-filesystem-consent').checked, false);
  release({ ok: true, json: async () => summary() }); await first;
  assert.equal(f.node('trufflehog-filesystem-result').classList.contains('hidden'), true);
  assert.equal(f.node('trufflehog-filesystem-submit').disabled, true);
});

const appJsPath = process.env.SNIPER_TRUFFLEHOG_APP_JS || new URL('../static/app.js', import.meta.url).pathname;
const appJsSource = fs.readFileSync(appJsPath, 'utf8');

function extractTagAttributes(rawHtml, pattern) {
  const match = rawHtml.match(pattern);
  if (!match) return {};
  const attrs = {};
  for (const attrMatch of match[0].matchAll(/([a-zA-Z0-9_-]+)(?:="([^"]*)")?/g)) {
    attrs[attrMatch[1]] = attrMatch[2] ?? '';
  }
  return attrs;
}

function browserIntegrationFixture() {
  const nodes = new Map();
  const docListeners = new Map();
  const requests = [];
  const scannerCalls = [];
  let activeElement = null;

  function makeElement(id, initialClasses = [], attrs = {}) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(initialClasses);
    const handlers = new Map();
    const attrMap = new Map(Object.entries(attrs));
    const el = {
      id,
      tagName: (attrs.tagName || 'DIV').toUpperCase(),
      value: '',
      checked: Boolean(attrs.checked),
      disabled: Object.prototype.hasOwnProperty.call(attrs, 'disabled'),
      hidden: classes.has('hidden'),
      tabIndex: 0,
      textContent: '',
      innerHTML: '',
      style: {},
      dataset: { ...(attrs.dataset || {}) },
      handlers,
      classList: {
        add(c) { classes.add(c); if (c === 'hidden') el.hidden = true; },
        remove(c) { classes.delete(c); if (c === 'hidden') el.hidden = false; },
        contains(c) { return classes.has(c); },
        toggle(c, force) {
          const next = force === undefined ? !classes.has(c) : Boolean(force);
          if (next) classes.add(c);
          else classes.delete(c);
          if (c === 'hidden') el.hidden = next;
          return next;
        },
      },
      getAttribute(name) { return attrMap.has(name) ? attrMap.get(name) : null; },
      hasAttribute(name) { return attrMap.has(name); },
      setAttribute(name, val) { attrMap.set(name, String(val)); },
      removeAttribute(name) { attrMap.delete(name); },
      addEventListener(type, cb) {
        handlers.set(type, [...(handlers.get(type) || []), cb]);
      },
      focus() {
        if (!el.disabled && !classes.has('hidden')) {
          activeElement = el;
        }
      },
      click() {
        return dispatchElement(el, 'click');
      },
      reset() {},
      append() {},
      appendChild() {},
      replaceChildren() {},
      remove() {},
      scrollIntoView() {},
      matches() { return false; },
      closest(selector) {
        if (selector === '[data-close="trufflehog-filesystem-modal"]' && el.dataset.close === 'trufflehog-filesystem-modal') {
          return el;
        }
        if (selector === '[data-action="open-trufflehog-filesystem"]' && el.dataset.action === 'open-trufflehog-filesystem') {
          return el;
        }
        return null;
      },
      querySelector(selector) {
        return document.querySelector(selector);
      },
      querySelectorAll(selector) {
        if (el.id === 'trufflehog-filesystem-modal') {
          return [closeButton, pathInput, consentInput, submitButton];
        }
        return [];
      },
    };
    nodes.set(id, el);
    return el;
  }

  const modalAttrs = extractTagAttributes(html, /<div[^>]*id="trufflehog-filesystem-modal"[^>]*>/);
  const closeAttrs = extractTagAttributes(html, /<button[^>]*data-close="trufflehog-filesystem-modal"[^>]*>/);
  const submitAttrs = extractTagAttributes(html, /<button[^>]*id="trufflehog-filesystem-submit"[^>]*>/);

  const body = makeElement('body', [], { tagName: 'BODY' });
  activeElement = body;

  const launcher = makeElement('open-trufflehog-filesystem-btn', ['button', 'primary'], {
    tagName: 'BUTTON',
    dataset: { action: 'open-trufflehog-filesystem' },
  });
  const modal = makeElement(
    'trufflehog-filesystem-modal',
    (modalAttrs.class || 'modal-backdrop hidden').split(/\s+/).filter(Boolean),
    { ...modalAttrs, tagName: 'DIV' }
  );
  const closeButton = makeElement(
    'trufflehog-filesystem-close',
    (closeAttrs.class || 'modal-close').split(/\s+/).filter(Boolean),
    { ...closeAttrs, tagName: 'BUTTON', dataset: { close: 'trufflehog-filesystem-modal' } }
  );
  const pathInput = makeElement('trufflehog-filesystem-path', [], { tagName: 'INPUT' });
  const consentInput = makeElement('trufflehog-filesystem-consent', [], { tagName: 'INPUT' });
  const submitButton = makeElement('trufflehog-filesystem-submit', ['button', 'primary'], {
    ...submitAttrs,
    tagName: 'BUTTON',
  });
  const errorNode = makeElement('trufflehog-filesystem-error', ['error-message', 'hidden'], { tagName: 'P' });
  const resultNode = makeElement('trufflehog-filesystem-result', ['panel', 'hidden'], { tagName: 'SECTION' });
  const formNode = makeElement('trufflehog-filesystem-form', ['form-grid'], { tagName: 'FORM' });
  makeElement('trufflehog-filesystem-total', [], { tagName: 'B' });
  makeElement('trufflehog-filesystem-unverified', [], { tagName: 'B' });
  makeElement('trufflehog-filesystem-detectors', [], { tagName: 'B' });
  makeElement('trufflehog-filesystem-report-sha256', [], { tagName: 'CODE' });

  // Unrelated overlays in index.html managed by app.js showModal / Escape
  const reportDrawer = makeElement('report-drawer', ['drawer-backdrop', 'hidden'], { tagName: 'DIV' });
  const engagementWorkspace = makeElement('engagement-workspace', ['workspace-backdrop', 'hidden'], { tagName: 'DIV' });
  const sarifModal = makeElement('sarif-preview-modal', ['modal-backdrop', 'hidden'], { tagName: 'DIV' });
  const allOverlays = [modal, reportDrawer, engagementWorkspace, sarifModal];

  const document = {
    body,
    readyState: 'loading',
    get activeElement() { return activeElement; },
    set activeElement(el) { activeElement = el; },
    getElementById(id) {
      return makeElement(id);
    },
    createElement(tag) {
      return makeElement(`created-${tag}-${nodes.size}`, [], { tagName: tag });
    },
    querySelector(selector) {
      if (selector === 'meta[name="sniper-local-home"]') {
        return { content: '/home/community-user' };
      }
      if (
        selector === '[data-action="open-trufflehog-filesystem"]' ||
        selector === '[data-view="tooling"] [data-action="open-trufflehog-filesystem"]'
      ) {
        return launcher;
      }
      if (selector === '[data-close="trufflehog-filesystem-modal"]') {
        return closeButton;
      }
      const idMatch = selector.match(/^#([a-zA-Z0-9_-]+)$/);
      if (idMatch) return makeElement(idMatch[1]);
      return makeElement(`qs:${selector}`);
    },
    querySelectorAll(selector) {
      if (selector.includes('.modal-backdrop')) {
        return allOverlays;
      }
      return [];
    },
    addEventListener(type, cb) {
      docListeners.set(type, [...(docListeners.get(type) || []), cb]);
    },
  };

  async function dispatchElement(element, type, extra = {}) {
    let defaultPrevented = false;
    let propagationStopped = false;
    const event = {
      type,
      target: element,
      currentTarget: element,
      get defaultPrevented() { return defaultPrevented; },
      preventDefault() { defaultPrevented = true; },
      stopPropagation() { propagationStopped = true; },
      ...extra,
    };
    for (const cb of element.handlers.get(type) || []) {
      await cb(event);
    }
    if (!propagationStopped && (type === 'click' || type === 'keydown')) {
      for (const cb of docListeners.get(type) || []) {
        await cb(event);
      }
    }
    return event;
  }

  async function dispatchDocument(type, extra = {}) {
    let defaultPrevented = false;
    let immediatePropagationStopped = false;
    const event = {
      type,
      target: extra.target || activeElement || body,
      currentTarget: document,
      get defaultPrevented() { return defaultPrevented; },
      preventDefault() { defaultPrevented = true; },
      stopPropagation() {},
      stopImmediatePropagation() { immediatePropagationStopped = true; },
      ...extra,
    };
    for (const cb of docListeners.get(type) || []) {
      await cb(event);
      if (immediatePropagationStopped) break;
    }
    return event;
  }

  async function fetchStub(path, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    requests.push({ method, path, options });
    if (method !== 'GET' || path.startsWith('/api/tool-runs/')) {
      scannerCalls.push({ method, path, options });
      throw new Error(`Forbidden POST/scanner request reached in keyboard/focus test: ${method} ${path}`);
    }
    if (path === '/api/tooling/readiness') {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          tools: [
            {
              id: 'trufflehog',
              profiles: [
                {
                  route: '/api/tool-runs/trufflehog-filesystem',
                  action: 'local_input_required',
                  runtime: 'precheck_passed',
                },
              ],
            },
          ],
        }),
      };
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({
        targets: [],
        scans: [],
        engagements: [],
        lab_runs: [],
        project_audits: [],
        total: 0,
        tools: [],
        categories: [],
        summary: {},
        policy: { native: '', external: '', completion: '' },
        events: [],
      }),
    };
  }

  const ctx = vm.createContext({
    document,
    window: { addEventListener() {} },
    location: { hash: '#tooling' },
    history: { replaceState() {} },
    fetch: fetchStub,
    Intl,
    Date,
    Set,
    Map,
    Number,
    String,
    Boolean,
    Array,
    Object,
    Math,
    JSON,
    Promise,
    RegExp,
    Error,
    encodeURIComponent,
    TextEncoder,
    URL,
    console,
    setTimeout: () => 0,
    clearTimeout() {},
    setInterval: () => 0,
  });

  vm.runInContext(appJsSource, ctx, { filename: appJsPath });
  vm.runInContext(source, ctx, { filename: jsPath });

  return {
    ctx,
    document,
    launcher,
    modal,
    closeButton,
    pathInput,
    consentInput,
    submitButton,
    errorNode,
    resultNode,
    formNode,
    reportDrawer,
    engagementWorkspace,
    sarifModal,
    requests,
    scannerCalls,
    dispatchElement,
    dispatchDocument,
    async init() {
      document.readyState = 'interactive';
      await dispatchDocument('DOMContentLoaded');
      await new Promise(resolve => setImmediate(resolve));
    },
    async clickLauncher() {
      launcher.focus();
      await dispatchElement(launcher, 'click');
    },
    async pressKey(key, extra = {}) {
      return dispatchDocument('keydown', { key, shiftKey: false, ...extra });
    },
  };
}

test('control: full app.js + trufflehog_filesystem.js opens only dialog with role/aria-modal, unchecked consent, disabled submit and zero POST/scanner calls', async () => {
  const env = browserIntegrationFixture();
  await env.init();

  assert.equal(env.modal.getAttribute('role'), 'dialog');
  assert.equal(env.modal.getAttribute('aria-modal'), 'true');
  assert.equal(env.modal.classList.contains('hidden'), true);

  await env.clickLauncher();
  assert.equal(env.modal.classList.contains('hidden'), false);
  assert.equal(env.reportDrawer.classList.contains('hidden'), true);
  assert.equal(env.engagementWorkspace.classList.contains('hidden'), true);
  assert.equal(env.sarifModal.classList.contains('hidden'), true);
  assert.equal(env.consentInput.checked, false);
  assert.equal(env.submitButton.disabled, true);
  assert.equal(env.scannerCalls.length, 0);

  // Close and verify tool-card delegation route also opens the dialog without submitting a scan
  env.modal.classList.add('hidden');
  const routed = env.ctx.openToolCardRoute('/api/tool-runs/trufflehog-filesystem');
  assert.equal(routed, true);
  assert.equal(env.modal.classList.contains('hidden'), false);
  assert.equal(env.consentInput.checked, false);
  assert.equal(env.submitButton.disabled, true);
  assert.equal(env.scannerCalls.length, 0);
});

test('initial focus moves inside #trufflehog-filesystem-modal to its close control on launcher activation', async () => {
  const env = browserIntegrationFixture();
  await env.init();

  await env.clickLauncher();
  assert.equal(env.modal.classList.contains('hidden'), false);
  assert.notEqual(env.document.activeElement, env.launcher, 'Focus must not remain on launcher after opening dialog');
  assert.equal(env.document.activeElement, env.closeButton, 'Initial focus should move to the dialog close button');
  assert.equal(env.scannerCalls.length, 0);
});

test('Tab and Shift+Tab wrap within enabled dialog controls and never escape while submit is disabled', async () => {
  const env = browserIntegrationFixture();
  await env.init();
  await env.clickLauncher();

  const enabledControls = [env.closeButton, env.pathInput, env.consentInput];
  assert.equal(env.submitButton.disabled, true);

  // Starting on last enabled control (consentInput), Tab wraps to first (closeButton)
  env.consentInput.focus();
  assert.equal(env.document.activeElement, env.consentInput);
  await env.pressKey('Tab', { shiftKey: false });
  assert.equal(env.document.activeElement, env.closeButton);

  // Starting on first enabled control (closeButton), Shift+Tab wraps to last (consentInput)
  env.closeButton.focus();
  assert.equal(env.document.activeElement, env.closeButton);
  await env.pressKey('Tab', { shiftKey: true });
  assert.equal(env.document.activeElement, env.consentInput);

  // Repeated forward/backward traversal stays strictly inside enabled dialog controls
  for (let i = 0; i < 9; i += 1) {
    await env.pressKey('Tab', { shiftKey: false });
    assert.ok(enabledControls.includes(env.document.activeElement));
  }
  for (let i = 0; i < 9; i += 1) {
    await env.pressKey('Tab', { shiftKey: true });
    assert.ok(enabledControls.includes(env.document.activeElement));
  }
  assert.equal(env.scannerCalls.length, 0);
});

test('Escape with installed app.js active closes only #trufflehog-filesystem-modal, resets UI state, and restores launcher focus', async () => {
  const env = browserIntegrationFixture();
  await env.init();

  // Suppose an unrelated overlay is open when TruffleHog dialog is opened
  env.reportDrawer.classList.remove('hidden');

  await env.clickLauncher();
  env.pathInput.value = '/home/community-user/synthetic';
  await env.dispatchElement(env.pathInput, 'input');
  env.consentInput.checked = true;
  await env.dispatchElement(env.consentInput, 'change');
  assert.equal(env.submitButton.disabled, false);

  await env.pressKey('Escape');

  assert.equal(env.modal.classList.contains('hidden'), true);
  assert.equal(env.consentInput.checked, false, 'Escape must reset consent checkbox');
  assert.equal(env.pathInput.value, '', 'Escape must reset path input');
  assert.equal(env.submitButton.disabled, true, 'Escape must disable submit button');
  assert.equal(env.document.activeElement, env.launcher, 'Escape must restore focus to launcher');
  assert.equal(env.reportDrawer.classList.contains('hidden'), false, 'Escape must close only the active TruffleHog dialog');
  assert.equal(env.scannerCalls.length, 0);
});

test('close button and backdrop click restore launcher focus, reset state, and leave no keyboard trap', async () => {
  const env = browserIntegrationFixture();
  await env.init();

  await env.clickLauncher();
  env.pathInput.value = '/home/community-user/synthetic';
  await env.dispatchElement(env.pathInput, 'input');
  env.consentInput.checked = true;
  await env.dispatchElement(env.consentInput, 'change');

  // Close via [data-close="trufflehog-filesystem-modal"] button
  await env.dispatchElement(env.closeButton, 'click');
  assert.equal(env.modal.classList.contains('hidden'), true);
  assert.equal(env.consentInput.checked, false);
  assert.equal(env.pathInput.value, '');
  assert.equal(env.submitButton.disabled, true);
  assert.equal(env.document.activeElement, env.launcher);

  // Reopen starts clean, then close via backdrop click
  await env.clickLauncher();
  assert.equal(env.consentInput.checked, false);
  assert.equal(env.pathInput.value, '');
  assert.equal(env.submitButton.disabled, true);

  await env.dispatchDocument('click', { target: env.modal });
  assert.equal(env.modal.classList.contains('hidden'), true);
  assert.equal(env.document.activeElement, env.launcher);

  // Pressing Tab when dialog is closed does not trap focus inside the hidden dialog
  await env.pressKey('Tab', { shiftKey: false });
  assert.equal(env.document.activeElement, env.launcher);
  assert.equal(env.scannerCalls.length, 0);
});



test('topmost generic dialog alone handles first Escape; underlying TruffleHog state survives until second Escape', async () => {
  const env = browserIntegrationFixture();
  await env.init();
  await env.clickLauncher();
  env.pathInput.value = '/home/community-user/synthetic';
  await env.dispatchElement(env.pathInput, 'input');
  env.consentInput.checked = true;
  await env.dispatchElement(env.consentInput, 'change');
  assert.equal(env.submitButton.disabled, false);

  // This is a programmatic stacking edge: the generic dialog is explicitly opened above
  // the already-open direct TruffleHog dialog. The generic stack is the topmost owner.
  env.closeButton.isConnected = true;
  env.closeButton.getClientRects = () => [{}];
  env.ctx.showModal('sarif-preview-modal', true);
  assert.equal(env.sarifModal.classList.contains('hidden'), false);
  assert.equal(env.modal.classList.contains('hidden'), false);

  await env.pressKey('Escape');
  assert.equal(env.sarifModal.classList.contains('hidden'), true, 'First Escape closes the top generic dialog');
  assert.equal(env.modal.classList.contains('hidden'), false, 'Underlying TruffleHog stays open');
  assert.equal(env.pathInput.value, '/home/community-user/synthetic', 'Underlying path remains intact');
  assert.equal(env.consentInput.checked, true, 'Underlying consent remains intact');
  assert.equal(env.submitButton.disabled, false, 'Underlying submit state remains intact');
  assert.equal(env.document.activeElement, env.closeButton, 'Focus returns into the underlying dialog');

  await env.pressKey('Escape');
  assert.equal(env.modal.classList.contains('hidden'), true, 'Second Escape closes TruffleHog');
  assert.equal(env.pathInput.value, '', 'TruffleHog path resets only when it closes');
  assert.equal(env.consentInput.checked, false, 'TruffleHog consent resets only when it closes');
  assert.equal(env.submitButton.disabled, true);
  assert.equal(env.document.activeElement, env.launcher, 'Focus returns to launcher');
  assert.equal(env.scannerCalls.length, 0);
});
