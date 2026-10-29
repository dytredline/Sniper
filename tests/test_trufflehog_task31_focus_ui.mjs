import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../static/trufflehog_filesystem.js', import.meta.url), 'utf8');

function fixture() {
  const nodes = new Map(), listeners = new Map(), requests = [];
  let activeElement;
  function node(id, hidden = false) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(hidden ? ['hidden'] : []), handlers = new Map();
    const el = {
      id, value: '', checked: false, disabled: false, tabIndex: 0, textContent: '', handlers,
      classList: { add(c) { classes.add(c); }, remove(c) { classes.delete(c); }, contains(c) { return classes.has(c); } },
      getAttribute() { return null; },
      addEventListener(type, cb) { handlers.set(type, [...(handlers.get(type) || []), cb]); },
      querySelector(selector) { return selector === '[data-close="trufflehog-filesystem-modal"]' ? closeButton : null; },
      closest(selector) { return selector === '[data-close="trufflehog-filesystem-modal"]' && id === 'close-button' ? el : null; },
      focus() { if (!el.disabled) activeElement = el; },
    };
    nodes.set(id, el); return el;
  }
  const opener = node('opener'), modal = node('trufflehog-filesystem-modal', true), closeButton = node('close-button');
  const path = node('trufflehog-filesystem-path'), consent = node('trufflehog-filesystem-consent'), submit = node('trufflehog-filesystem-submit');
  node('trufflehog-filesystem-error', true); node('trufflehog-filesystem-result', true); node('trufflehog-filesystem-form');
  for (const key of ['total', 'unverified', 'detectors', 'report-sha256']) node('trufflehog-filesystem-' + key);
  activeElement = opener;
  const document = {
    readyState: 'loading', get activeElement() { return activeElement; },
    getElementById(id) { return nodes.get(id) || null; },
    querySelector(selector) {
      if (selector === '[data-action="open-trufflehog-filesystem"]') return opener;
      if (selector === '[data-close="trufflehog-filesystem-modal"]') return closeButton;
      if (selector === 'meta[name="sniper-local-home"]') return { content: '/home/community-user' };
      return null;
    },
    addEventListener(type, cb) { listeners.set(type, [...(listeners.get(type) || []), cb]); },
  };
  function event(target, extras = {}) {
    let prevented = false;
    return { target, key: undefined, shiftKey: false, get defaultPrevented() { return prevented; },
      preventDefault() { prevented = true; }, stopPropagation() {}, stopImmediatePropagation() {}, ...extras };
  }
  function fire(el, type) {
    const e = event(el);
    for (const cb of el.handlers.get(type) || []) cb(e);
    if (type === 'click') for (const cb of listeners.get('click') || []) cb(e);
  }
  function onDocument(type, target, extras = {}) {
    const e = event(target, extras);
    for (const cb of listeners.get(type) || []) cb(e);
    return e;
  }
  vm.runInNewContext(source, { document,
    fetch: async (url, options) => { requests.push({ url, options }); throw new Error('scan forbidden in focus test'); },
    Number, JSON, Promise });
  onDocument('DOMContentLoaded', document);
  return { document, opener, modal, closeButton, path, consent, submit, requests,
    open() { fire(opener, 'click'); }, key(key, shiftKey = false) { return onDocument('keydown', document.activeElement, { key, shiftKey }); },
    input(value) { path.value = value; fire(path, 'input'); },
    consentOn() { consent.checked = true; fire(consent, 'change'); },
    closeClick() { fire(closeButton, 'click'); }, backdropClick() { onDocument('click', modal); } };
}

test('TruffleHog open focuses the close control and Tab wraps over enabled controls with zero scans', () => {
  const f = fixture(); f.open();
  assert.equal(f.modal.classList.contains('hidden'), false);
  assert.equal(f.submit.disabled, true);
  assert.equal(f.document.activeElement, f.closeButton);
  f.consent.focus();
  assert.equal(f.key('Tab').defaultPrevented, true);
  assert.equal(f.document.activeElement, f.closeButton);
  assert.equal(f.key('Tab', true).defaultPrevented, true);
  assert.equal(f.document.activeElement, f.consent);
  assert.equal(f.requests.length, 0);
});

test('Escape, close button, and backdrop reset state and restore opener focus', () => {
  const f = fixture();
  for (const close of [() => f.key('Escape'), () => f.closeClick(), () => f.backdropClick()]) {
    f.open(); f.input('/home/community-user/synthetic'); f.consentOn();
    assert.equal(f.submit.disabled, false);
    close();
    assert.equal(f.modal.classList.contains('hidden'), true);
    assert.equal(f.path.value, '');
    assert.equal(f.consent.checked, false);
    assert.equal(f.submit.disabled, true);
    assert.equal(f.document.activeElement, f.opener);
  }
  assert.equal(f.requests.length, 0);
});
