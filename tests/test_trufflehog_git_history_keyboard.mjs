import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';

// Public runtime assertions against actual module text. This fixture executes
// the exact frozen Task38-v2 generic capture listener before the direct module.
const root = process.env.SNIPER_TASK39_SOURCE_ROOT || new URL('..', import.meta.url).pathname.replace(/\/$/, '');
const source = fs.readFileSync(`${root}/static/trufflehog_git_history.js`, 'utf8');

const appSource = fs.readFileSync(root + '/static/app.js', 'utf8');
const keydownMarker = 'document.addEventListener("keydown", event => {';
const focusinMarker = 'document.addEventListener("focusin", event => {';
const focusinStart = appSource.indexOf(focusinMarker);
const keydownStart = appSource.indexOf(keydownMarker, focusinStart);
const keydownEnd = appSource.indexOf('\n}, true);', keydownStart);
assert.ok(focusinStart > 0 && keydownStart > focusinStart && keydownEnd > keydownStart,
  'frozen generic keydown handler must exist');
const genericKeydown = appSource.slice(keydownStart, keydownEnd + '\n}, true);'.length);

function fixture() {
  const nodes = new Map(), listeners = new Map(), requests = [];
  const modalId = 'trufflehog-git-history-modal';
  const document = {
    activeElement: null,
    getElementById: element,
    querySelector(s) { return s === '[data-action="open-trufflehog-git-history"]' ? opener : null; },
    querySelectorAll() { return [modal, top].filter(x => !x.classList.contains('hidden')); },
    addEventListener(type, fn, capture = false) {
      listeners.set(type, [...(listeners.get(type) || []), { fn, capture: !!capture }]);
    },
  };
  function element(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(id.endsWith('-modal') ? ['hidden'] : []);
    const handlers = new Map();
    const node = {
      id, value: '', checked: false, disabled: id === 'trufflehog-git-history-submit',
      tabIndex: 0, dataset: {}, textContent: '', handlers,
      classList: {
        add(name) { classes.add(name); }, remove(name) { classes.delete(name); },
        contains(name) { return classes.has(name); },
      },
      addEventListener(type, fn) { handlers.set(type, [...(handlers.get(type) || []), fn]); },
      getClientRects() { return [{}]; },
      focus() { document.activeElement = node; },
      closest(selector) {
        return node.dataset.close && (selector === '[data-close]' || selector === `[data-close="${node.dataset.close}"]`) ? node : null;
      },
      contains(child) { return id === modalId && [closeButton, path, consent, submit].includes(child); },
      querySelectorAll(selector) {
        if (id === modalId) return selector === '[data-close]' ? [closeButton] : [closeButton, path, consent, submit];
        if (id === 'top-modal') return [topClose];
        return [];
      },
      click() { dispatchDocument('click', { target: node }); },
    };
    nodes.set(id, node); return node;
  }
  const opener = element('launcher'), modal = element(modalId);
  const closeButton = element('git-close'); closeButton.dataset.close = modalId;
  const path = element('trufflehog-git-history-path');
  const consent = element('trufflehog-git-history-consent');
  const submit = element('trufflehog-git-history-submit');
  const top = element('top-modal'), topClose = element('top-close'); topClose.dataset.close = 'top-modal';
  function dispatchDocument(type, event) {
    let stopped = false;
    const e = { preventDefault() { this.defaultPrevented = true; },
      stopImmediatePropagation() { stopped = true; }, stopPropagation() {}, defaultPrevented: false, ...event };
    const handlers = listeners.get(type) || [];
    for (const { fn } of [...handlers.filter(x => x.capture), ...handlers.filter(x => !x.capture)]) {
      if (stopped) break;
      fn(e);
    }
    return e;
  }
  function dispatchNode(node, type) {
    const event = { target: node, preventDefault() {} };
    for (const fn of node.handlers.get(type) || []) fn(event);
    if (type === 'click') dispatchDocument('click', { target: node });
  }
  // Evaluate the exact frozen managed-modal capture handler before the module.
  // The top test dialog is the generic stack owner; the direct Git dialog is not.
  vm.runInNewContext(genericKeydown, {
    document,
    activeModal: () => top.classList.contains('hidden') ? null : top,
    showModal: (id, visible) => element(id).classList[visible ? 'remove' : 'add']('hidden'),
    modalContains: (dialog, target) => dialog.contains(target),
    modalControls: dialog => dialog.querySelectorAll('button, input'),
    focusModal: dialog => dialog.querySelectorAll('button, input')[0]?.focus(),
    focusModalBoundary: dialog => dialog.querySelectorAll('button, input')[0]?.focus(),
  });
  document.addEventListener('click', e => {
    const close = e.target.closest?.('[data-close]');
    if (close) element(close.dataset.close).classList.add('hidden');
    else if (e.target === modal || e.target === top) e.target.classList.add('hidden');
  });
  vm.runInNewContext(source, {
    document, getComputedStyle: () => ({ zIndex: '50' }),
    fetch: async (...args) => { requests.push(args); throw new Error('scanner must not run'); },
    Number, Object, Array, JSON, Promise,
  });
  dispatchDocument('DOMContentLoaded', {});
  return {
    document, opener, modal, closeButton, consent, top, topClose, requests,
    open() { opener.focus(); dispatchNode(opener, 'click'); },
    key(key, shiftKey = false) { dispatchDocument('keydown', { key, shiftKey, target: document.activeElement }); },
    click(node) { dispatchNode(node, 'click'); },
    backdrop() { dispatchDocument('click', { target: modal }); },
  };
}

test('opening focuses inside Git-history dialog without scanner request', () => {
  const f = fixture(); f.open();
  assert.equal(f.modal.classList.contains('hidden'), false);
  assert.equal(f.modal.contains(f.document.activeElement), true);
  assert.equal(f.requests.length, 0);
});
test('Tab and Shift+Tab wrap inside active Git-history dialog', () => {
  const f = fixture(); f.open();
  f.consent.focus(); f.key('Tab');
  assert.equal(f.document.activeElement, f.closeButton);
  f.closeButton.focus(); f.key('Tab', true);
  assert.equal(f.document.activeElement, f.consent);
  assert.equal(f.requests.length, 0);
});
test('Escape closes via direct lifecycle and restores opener', () => {
  const f = fixture(); f.open(); f.consent.checked = true; f.key('Escape');
  assert.equal(f.modal.classList.contains('hidden'), true);
  assert.equal(f.consent.checked, false);
  assert.equal(f.document.activeElement, f.opener);
  assert.equal(f.requests.length, 0);
});
test('close control and backdrop restore opener and permit reopen', () => {
  const f = fixture(); f.open(); f.consent.focus(); f.click(f.closeButton);
  assert.equal(f.modal.classList.contains('hidden'), true);
  assert.equal(f.document.activeElement, f.opener);
  f.open(); f.consent.focus(); f.backdrop();
  assert.equal(f.modal.classList.contains('hidden'), true);
  assert.equal(f.document.activeElement, f.opener);
  f.open(); assert.equal(f.modal.classList.contains('hidden'), false);
  assert.equal(f.requests.length, 0);
});
test('first Escape closes only a stacked top dialog', () => {
  const f = fixture(); f.open(); f.consent.checked = true;
  f.top.classList.remove('hidden'); f.topClose.focus(); f.key('Escape');
  assert.equal(f.top.classList.contains('hidden'), true);
  assert.equal(f.modal.classList.contains('hidden'), false);
  assert.equal(f.consent.checked, true);
  f.key('Escape');
  assert.equal(f.modal.classList.contains('hidden'), true);
  assert.equal(f.document.activeElement, f.opener);
  assert.equal(f.requests.length, 0);
});

test('control: launcher and explicit close remain request-free', () => {
  const f = fixture(); f.open();
  assert.equal(f.modal.classList.contains('hidden'), false);
  f.click(f.closeButton);
  assert.equal(f.modal.classList.contains('hidden'), true);
  assert.equal(f.requests.length, 0);
});

test('unrelated managed dialog closes independently without a scanner request', () => {
  const f = fixture();
  f.top.classList.remove('hidden'); f.topClose.focus(); f.key('Escape');
  assert.equal(f.top.classList.contains('hidden'), true);
  assert.equal(f.modal.classList.contains('hidden'), true);
  assert.equal(f.requests.length, 0);
});
