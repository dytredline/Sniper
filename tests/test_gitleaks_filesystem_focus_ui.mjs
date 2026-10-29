import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const jsPath = process.env.SNIPER_GITLEAKS_FS_UI_JS || new URL('../static/gitleaks_filesystem.js', import.meta.url).pathname;
const source = fs.readFileSync(jsPath, 'utf8');

function fixture() {
  const nodes = new Map();
  const listeners = new Map();
  const requests = [];
  const document = {
    activeElement: null,
    getElementById: id => node(id),
    querySelector(selector) {
      if (selector === '[data-action="open-gitleaks-filesystem"]') return launcher;
      if (selector === 'meta[name="sniper-local-home"]') return { content: '/home/community-user' };
      return null;
    },
    addEventListener(type, listener, capture = false) {
      listeners.set(type, [...(listeners.get(type) || []), { listener, capture: capture === true }]);
    },
  };

  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(id === 'gitleaks-filesystem-modal' ? ['hidden'] : []);
    const handlers = new Map();
    const element = {
      id, value: '', checked: false, disabled: false, isConnected: true,
      textContent: '', handlers,
      classList: {
        add(value) { classes.add(value); },
        remove(value) { classes.delete(value); },
        contains(value) { return classes.has(value); },
      },
      addEventListener(type, listener) { handlers.set(type, [...(handlers.get(type) || []), listener]); },
      focus() { document.activeElement = this; },
      getClientRects() { return modal.classList.contains('hidden') ? [] : [1]; },
      closest(selector) {
        return selector === '[data-close="gitleaks-filesystem-modal"]' && id === 'close' ? this : null;
      },
      querySelector(selector) {
        return id === 'gitleaks-filesystem-modal' && selector === '[data-close="gitleaks-filesystem-modal"]' ? closeButton : null;
      },
      contains(candidate) {
        return id === 'gitleaks-filesystem-modal' && [closeButton, path, consent, submit].includes(candidate);
      },
    };
    nodes.set(id, element);
    return element;
  }

  const modal = node('gitleaks-filesystem-modal');
  const launcher = node('launcher');
  const closeButton = node('close');
  const path = node('gitleaks-filesystem-path');
  const consent = node('gitleaks-filesystem-consent');
  const submit = node('gitleaks-filesystem-submit');
  const fetch = async (...request) => { requests.push(request); throw new Error('No scanner calls allowed in focus test'); };
  vm.runInNewContext(source, { document, fetch, Number, Object, Array, JSON, Promise });

  async function documentEvent(type, event = {}) {
    const ordered = [...(listeners.get(type) || [])].sort((a, b) => Number(b.capture) - Number(a.capture));
    let stopped = false;
    const payload = {
      preventDefault() { this.defaultPrevented = true; },
      stopImmediatePropagation() { stopped = true; },
      ...event,
    };
    for (const { listener } of ordered) {
      await listener(payload);
      if (stopped) break;
    }
    return payload;
  }
  async function dispatch(element, type) {
    const event = { target: element, preventDefault() {} };
    for (const listener of element.handlers.get(type) || []) await listener(event);
  }
  return {
    document, modal, launcher, closeButton, path, consent, submit, requests,
    init: () => documentEvent('DOMContentLoaded'),
    open: () => dispatch(launcher, 'click'),
    key: (key, shiftKey = false) => documentEvent('keydown', { key, shiftKey }),
    clickClose: () => documentEvent('click', { target: closeButton }),
    input: async value => { path.value = value; await dispatch(path, 'input'); },
    optIn: async () => { consent.checked = true; await dispatch(consent, 'change'); },
  };
}

test('direct Gitleaks opening focuses the active dialog without a scan', async () => {
  const f = fixture(); await f.init(); f.launcher.focus(); await f.open();
  assert.equal(f.modal.classList.contains('hidden'), false);
  assert.equal(f.document.activeElement, f.path);
  assert.equal(f.consent.checked, false);
  assert.equal(f.submit.disabled, true);
  assert.equal(f.requests.length, 0);
});

test('Tab and Shift+Tab wrap within enabled dialog controls without a scan', async () => {
  const f = fixture(); await f.init(); await f.open();
  f.consent.focus();
  const forward = await f.key('Tab');
  assert.equal(forward.defaultPrevented, true);
  assert.equal(f.document.activeElement, f.closeButton);
  const backward = await f.key('Tab', true);
  assert.equal(backward.defaultPrevented, true);
  assert.equal(f.document.activeElement, f.consent);
  await f.input('/home/community-user/synthetic-project'); await f.optIn();
  assert.equal(f.submit.disabled, false);
  f.submit.focus(); await f.key('Tab');
  assert.equal(f.document.activeElement, f.closeButton);
  assert.equal(f.requests.length, 0);
});

test('Escape and close control restore launcher focus and reset opt-in without a scan', async () => {
  const f = fixture(); await f.init(); await f.open(); await f.optIn();
  const escape = await f.key('Escape');
  assert.equal(escape.defaultPrevented, true);
  assert.equal(f.modal.classList.contains('hidden'), true);
  assert.equal(f.consent.checked, false);
  assert.equal(f.document.activeElement, f.launcher);
  await f.open(); f.path.focus(); await f.clickClose();
  assert.equal(f.modal.classList.contains('hidden'), true);
  assert.equal(f.document.activeElement, f.launcher);
  assert.equal(f.requests.length, 0);
});
