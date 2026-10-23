import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const app = process.env.SNIPER_TASK41_SOURCE_ROOT || new URL('..', import.meta.url).pathname.replace(/\/$/, '');
const moduleSource = fs.readFileSync(app + '/static/testssl_loopback_full.js', 'utf8');
const appSource = fs.readFileSync(app + '/static/app.js', 'utf8');
const keydownMarker = 'document.addEventListener("keydown", event => {';
const focusinStart = appSource.indexOf('document.addEventListener("focusin", event => {');
const keydownStart = appSource.indexOf(keydownMarker, focusinStart);
const keydownEnd = appSource.indexOf('\n}, true);', keydownStart);
assert.ok(focusinStart > 0 && keydownStart > focusinStart && keydownEnd > keydownStart,
  'frozen managed-modal capture handler must exist');
const genericKeydown = appSource.slice(keydownStart, keydownEnd + '\n}, true);'.length);

function fixture() {
  const nodes = new Map(), listeners = new Map(), requests = [];
  const modalId = 'testssl-loopback-full-modal';
  const document = {
    activeElement: null, getElementById: node,
    querySelectorAll() { return [modal, top].filter(x => !x.classList.contains('hidden')); },
    querySelector(s) { return s === '[data-action="open-testssl-loopback-full"]' ? opener : null; },
    addEventListener(type, fn) { listeners.set(type, [...(listeners.get(type) || []), fn]); },
  };
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(id.endsWith('-modal') ? ['hidden'] : []);
    const handlers = new Map();
    const element = {
      id, value: '', checked: false, disabled: id === 'testssl-loopback-full-submit',
      textContent: '', dataset: {}, tabIndex: 0, handlers,
      classList: {
        add(s) { classes.add(s); }, remove(s) { classes.delete(s); },
        contains(s) { return classes.has(s); },
      },
      addEventListener(type, fn) { handlers.set(type, [...(handlers.get(type) || []), fn]); },
      focus() { document.activeElement = element; },
      getClientRects() { return [{}]; },
      querySelectorAll() { return id === modalId ? [close, port, consent, submit] : id === 'top-modal' ? [topClose] : []; },
      closest(selector) {
        return selector === '[data-close="testssl-loopback-full-modal"]' &&
          element.dataset.close === modalId ? element : null;
      },
      contains(other) { return id === modalId ? [close, port, consent, submit].includes(other) : id === 'top-modal' && other === topClose; },
    };
    nodes.set(id, element); return element;
  }
  const opener = node('testssl-launcher'), modal = node(modalId);
  const close = node('testssl-close'); close.dataset.close = modalId;
  const port = node('testssl-loopback-full-port');
  const consent = node('testssl-loopback-full-consent');
  const submit = node('testssl-loopback-full-submit');
  const outside = node('outside-control');
  const top = node('top-modal'), topClose = node('top-close');
  const focusOrder = [opener, close, port, consent, submit, outside];
  function documentEvent(type, event) {
    let stopped = false;
    event.stopImmediatePropagation = () => { stopped = true; };
    for (const fn of listeners.get(type) || []) {
      if (stopped) break;
      fn(event);
    }
  }
  function click(target) {
    for (const fn of target.handlers.get('click') || []) fn({ target, preventDefault() {} });
    documentEvent('click', { target });
  }
  function key(key, shiftKey = false) {
    let prevented = false;
    const event = {
      key, shiftKey, target: document.activeElement,
      preventDefault() { prevented = true; },
      stopPropagation() {}, stopImmediatePropagation() {},
    };
    documentEvent('keydown', event);
    if (key === 'Tab' && !prevented) {
      const active = focusOrder.indexOf(document.activeElement);
      const direction = shiftKey ? -1 : 1;
      let next = (active + direction + focusOrder.length) % focusOrder.length;
      while (focusOrder[next].disabled) next = (next + direction + focusOrder.length) % focusOrder.length;
      focusOrder[next].focus();
    }
  }
  vm.runInNewContext(genericKeydown, {
    document,
    activeModal: () => top.classList.contains('hidden') ? null : top,
    showModal: (id, visible) => node(id).classList[visible ? 'remove' : 'add']('hidden'),
    modalContains: (dialog, target) => dialog.contains(target),
    modalControls: dialog => dialog.querySelectorAll(),
    focusModal: dialog => dialog.querySelectorAll()[0]?.focus(),
    focusModalBoundary: dialog => dialog.querySelectorAll()[0]?.focus(),
  });
  vm.runInNewContext(moduleSource, {
    document,
    fetch: async (...args) => { requests.push(args); throw new Error('scanner must not run'); },
    Number, Object, Array, JSON, Promise,
    getComputedStyle: node => ({ zIndex: node === top ? '51' : '50' }),
  });
  documentEvent('DOMContentLoaded', {});
  return {
    document, opener, modal, close, port, consent, submit, outside, top, topClose, requests, click, key,
    open() { opener.focus(); click(opener); },
    backdrop() { documentEvent('click', { target: modal }); },
  };
}

test('control: opening and explicit close are request-free', () => {
  const f = fixture(); f.open();
  assert.equal(f.modal.classList.contains('hidden'), false);
  assert.equal(f.requests.length, 0);
  f.click(f.close);
  assert.equal(f.modal.classList.contains('hidden'), true);
  assert.equal(f.requests.length, 0);
});
test('opening moves keyboard focus into TestSSL dialog', () => {
  const f = fixture(); f.open();
  assert.equal(f.modal.contains(f.document.activeElement), true);
  assert.equal(f.requests.length, 0);
});
test('Tab from last enabled control stays inside TestSSL dialog', () => {
  const f = fixture(); f.open(); f.consent.focus(); f.key('Tab');
  assert.equal(f.modal.contains(f.document.activeElement), true);
  assert.equal(f.requests.length, 0);
});
test('Shift+Tab from close control stays inside TestSSL dialog', () => {
  const f = fixture(); f.open(); f.close.focus(); f.key('Tab', true);
  assert.equal(f.modal.contains(f.document.activeElement), true);
  assert.equal(f.requests.length, 0);
});
test('Escape closes, clears consent and restores launcher focus', () => {
  const f = fixture(); f.open(); f.consent.checked = true; f.key('Escape');
  assert.equal(f.modal.classList.contains('hidden'), true);
  assert.equal(f.consent.checked, false);
  assert.equal(f.document.activeElement, f.opener);
  assert.equal(f.requests.length, 0);
});
test('close button and backdrop return focus to launcher', () => {
  const f = fixture(); f.open(); f.port.focus(); f.click(f.close);
  assert.equal(f.document.activeElement, f.opener);
  f.open(); f.port.focus(); f.backdrop();
  assert.equal(f.modal.classList.contains('hidden'), true);
  assert.equal(f.document.activeElement, f.opener);
  assert.equal(f.requests.length, 0);
});

test('first Escape closes only unrelated managed top; second closes TestSSL', () => {
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
test('unrelated managed modal closes without opening TestSSL or scanning', () => {
  const f = fixture(); f.top.classList.remove('hidden'); f.topClose.focus(); f.key('Escape');
  assert.equal(f.top.classList.contains('hidden'), true);
  assert.equal(f.modal.classList.contains('hidden'), true);
  assert.equal(f.requests.length, 0);
});
