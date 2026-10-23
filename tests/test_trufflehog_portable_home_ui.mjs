import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';


const ROOT = new URL('../', import.meta.url);

function fixture(relative, prefix, launcherAction) {
  const source = fs.readFileSync(new URL(relative, ROOT), 'utf8');
  const nodes = new Map();
  const documentHandlers = new Map();

  function element(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(id.endsWith('-modal') ? ['hidden'] : []);
    const handlers = new Map();
    const node = {
      id, value: '', checked: false, disabled: id.endsWith('-submit'), tabIndex: 0,
      textContent: '', handlers,
      classList: {
        add(name) { classes.add(name); },
        remove(name) { classes.delete(name); },
        contains(name) { return classes.has(name); },
      },
      addEventListener(type, fn) { handlers.set(type, fn); },
      getAttribute() { return null; },
      getClientRects() { return [{}]; },
      focus() { document.activeElement = node; },
      contains(target) { return target === node || target?.parent === node; },
      closest() { return null; },
      querySelector(selector) { return selector.includes('[data-close=') ? close : null; },
      querySelectorAll() { return [close, path, consent, submit]; },
    };
    nodes.set(id, node);
    return node;
  }

  const opener = element('launcher');
  const modal = element(prefix + 'modal');
  const close = element('close'); close.parent = modal;
  const path = element(prefix + 'path'); path.parent = modal;
  const consent = element(prefix + 'consent'); consent.parent = modal;
  const submit = element(prefix + 'submit'); submit.parent = modal;
  element(prefix + 'error'); element(prefix + 'result'); element(prefix + 'form');
  for (const suffix of ['total', 'unverified', 'detectors', 'report-sha256']) element(prefix + suffix);

  const document = {
    activeElement: null,
    readyState: 'loading',
    getElementById: element,
    querySelector(selector) {
      if (selector === `[data-action="${launcherAction}"]`) return opener;
      if (selector.includes('[data-close=')) return close;
      return null;
    },
    querySelectorAll() { return [modal].filter(node => !node.classList.contains('hidden')); },
    addEventListener(type, fn) { documentHandlers.set(type, fn); },
  };

  vm.runInNewContext(source, {
    document,
    fetch: async () => { throw new Error('scanner must not run'); },
    getComputedStyle: () => ({zIndex: '10'}),
    Number, Object, Array, JSON, Promise,
  });
  documentHandlers.get('DOMContentLoaded')?.({});

  return {
    path, consent, submit,
    set(value) {
      path.value = value;
      path.handlers.get('input')?.({target: path});
      consent.checked = true;
      consent.handlers.get('change')?.({target: consent});
      return submit.disabled;
    },
  };
}

for (const [relative, prefix, action] of [
  ['static/trufflehog_filesystem.js', 'trufflehog-filesystem-', 'open-trufflehog-filesystem'],
  ['static/trufflehog_git_history.js', 'trufflehog-git-history-', 'open-trufflehog-git-history'],
]) {
  test(`${relative} accepts portable home accounts`, () => {
    assert.equal(fixture(relative, prefix, action).set('/home/community-user/project'), false);
    assert.equal(fixture(relative, prefix, action).set(['/home', 'another-user', 'project'].join('/')), false);
  });

  test(`${relative} rejects traversal and non-home paths`, () => {
    assert.equal(fixture(relative, prefix, action).set('/home/community-user/../project'), true);
    assert.equal(fixture(relative, prefix, action).set('/home//project'), true);
    assert.equal(fixture(relative, prefix, action).set('/opt/project'), true);
  });
}
