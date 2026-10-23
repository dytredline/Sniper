import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

// Public Task160 contract: Escape dismissal of the top Dependabot preview
// clears draft/file/summary/error, while unrelated overlays keep their state.
const root = resolve(fileURLToPath(new URL('../', import.meta.url)));
const appPath = process.env.SNIPER_TASK47_APP_JS || resolve(root, 'static/app.js');
const app = readFileSync(appPath, 'utf8');
function actualSections(text) {
  const cleanStart = text.indexOf('function clearDependabotPreviewResult() {');
  const cleanEnd = text.indexOf('\ndocument.addEventListener("click",(e)=>{', cleanStart);
  const keyStart = text.indexOf('document.addEventListener("keydown", event => {\n  if (event.key === "Escape") {');
  const keyEnd = text.indexOf('\n}, true);\n\nnavigate(', keyStart);
  assert.ok(cleanStart >= 0 && cleanEnd > cleanStart, 'real preview cleanup functions required');
  assert.ok(keyStart >= 0 && keyEnd > keyStart, 'real modal-stack keydown handler required');
  return text.slice(cleanStart, cleanEnd) + '\n' + text.slice(keyStart, keyEnd + '\n}, true);'.length);
}
function node(hidden = false) {
  const classes = new Set(hidden ? ['hidden'] : []);
  return {
    value: '', textContent: '',
    classList: { contains: x => classes.has(x), add: x => classes.add(x), remove: x => classes.delete(x) },
  };
}
function scenario() {
  const ids = ['dependabot-paste', 'dependabot-file', 'dependabot-preview-error',
    'dependabot-preview-result', 'dependabot-format', 'dependabot-alert-count',
    'dependabot-state-counts', 'dependabot-severity-counts',
    'dependabot-open-patchable-count', 'dependabot-report-sha256'];
  const nodes = Object.fromEntries(ids.map(id => [id, node()]));
  let selectedFileValue = '';
  Object.defineProperty(nodes['dependabot-file'], 'value', {
    get() { return selectedFileValue; },
    set(value) { selectedFileValue = value; if (!value) this.files = []; },
  });
  nodes['dependabot-preview-modal'] = { id: 'dependabot-preview-modal', ...node() };
  nodes['other-modal'] = { id: 'other-modal', ...node() };
  nodes['trufflehog-filesystem-modal'] = { id: 'trufflehog-filesystem-modal', ...node(true) };
  let stack = [];
  const closes = [];
  let keyHandler;
  let apiCalls = 0;
  const context = {
    document: {
      getElementById: id => nodes[id] || null,
      addEventListener(kind, fn) { if (kind === 'keydown') keyHandler = fn; },
      activeElement: null,
    },
    activeModal: () => stack.at(-1) || null,
    showModal(id, visible) {
      if (visible) stack.push(nodes[id]);
      else { stack = stack.filter(item => item.id !== id); nodes[id].classList.add('hidden'); closes.push(id); }
    },
    api() { apiCalls++; throw Error('Escape must not make an API call'); },
    modalContains: () => true,
    modalControls: () => [],
    focusModal: () => {},
    focusModalBoundary: () => {},
  };
  vm.runInNewContext(actualSections(app), context, { filename: 'real-dependabot-and-modal-handler.js' });
  assert.equal(typeof keyHandler, 'function');
  function draft() {
    nodes['dependabot-paste'].value = '{invalid-json';
    const file = nodes['dependabot-file'];
    file.value = 'C:\\fakepath\\alerts.json';
    file.files = [{ name: 'alerts.json' }];
    nodes['dependabot-preview-error'].textContent = 'Invalid JSON';
    nodes['dependabot-preview-error'].classList.remove('hidden');
    nodes['dependabot-preview-result'].classList.remove('hidden');
    for (const id of ids.slice(4)) nodes[id].textContent = `stale-${id}`;
  }
  function escape() {
    const event = {
      key: 'Escape', defaultPrevented: false,
      preventDefault() { this.defaultPrevented = true; },
      stopImmediatePropagation() { this.stopped = true; },
      stopPropagation() { this.stopped = true; },
    };
    keyHandler(event);
    return event;
  }
  function assertCleared() {
    assert.equal(nodes['dependabot-paste'].value, '');
    assert.equal(nodes['dependabot-file'].value, '');
    assert.equal(nodes['dependabot-file'].files.length, 0);
    assert.equal(nodes['dependabot-preview-error'].textContent, '');
    assert.equal(nodes['dependabot-preview-error'].classList.contains('hidden'), true);
    assert.equal(nodes['dependabot-preview-result'].classList.contains('hidden'), true);
    for (const id of ids.slice(4)) assert.equal(nodes[id].textContent, '', `${id} must clear`);
  }
  return { nodes, draft, escape, assertCleared, closes, apiCalls: () => apiCalls,
    putTop(id) { nodes[id].classList.remove('hidden'); stack.push(nodes[id]); },
  };
}

test('top Dependabot Escape clears pasted draft, file value, error and summary without API', () => {
  const h = scenario();
  h.putTop('dependabot-preview-modal'); h.draft();
  const event = h.escape();
  assert.equal(event.defaultPrevented, true);
  assert.deepEqual(h.closes, ['dependabot-preview-modal']);
  h.assertCleared();
  assert.equal(h.apiCalls(), 0);
});

test('stacked unrelated top consumes first Escape; Dependabot draft clears only on second Escape', () => {
  const h = scenario();
  h.putTop('dependabot-preview-modal'); h.draft(); h.putTop('other-modal');
  h.escape();
  assert.deepEqual(h.closes, ['other-modal']);
  assert.equal(h.nodes['dependabot-paste'].value, '{invalid-json');
  assert.equal(h.nodes['dependabot-file'].value, 'C:\\fakepath\\alerts.json');
  assert.equal(h.nodes['dependabot-preview-error'].textContent, 'Invalid JSON');
  h.escape();
  assert.deepEqual(h.closes, ['other-modal', 'dependabot-preview-modal']);
  h.assertCleared();
  assert.equal(h.apiCalls(), 0);
});

test('unrelated-only overlay Escape does not erase hidden Dependabot draft', () => {
  const h = scenario();
  h.draft(); h.nodes['dependabot-preview-modal'].classList.add('hidden');
  h.putTop('other-modal');
  h.escape();
  assert.deepEqual(h.closes, ['other-modal']);
  assert.equal(h.nodes['dependabot-paste'].value, '{invalid-json');
  assert.equal(h.nodes['dependabot-preview-error'].textContent, 'Invalid JSON');
  assert.equal(h.apiCalls(), 0);
});
