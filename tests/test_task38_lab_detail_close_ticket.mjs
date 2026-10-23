import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const appRoot = process.env.SNIPER_TEST_APP_ROOT || resolve(fileURLToPath(new URL('../', import.meta.url)));
const source = readFileSync(join(appRoot, 'static/app.js'), 'utf8');

function actualShowModal(sourceText) {
  const start = sourceText.indexOf('function showModal(id, visible = true) {');
  const end = sourceText.indexOf('\nfunction navigate(view)', start);
  assert.ok(start >= 0 && end > start, 'actual common modal lifecycle must be present');
  return sourceText.slice(start, end);
}
function actualLabDetail(sourceText) {
  const functionStart = sourceText.indexOf('async function openLabDetail(runId) {');
  assert.ok(functionStart >= 0, 'actual lab detail function must be present');
  const ticketStart = sourceText.lastIndexOf('let activeLabDetailTicket = null;', functionStart);
  assert.ok(ticketStart >= 0 && functionStart - ticketStart < 100, 'Task38 request ticket must be present');
  const end = sourceText.indexOf('\nfunction openEngagementCreator()', functionStart);
  assert.ok(end > functionStart, 'actual lab detail function boundary must be present');
  return sourceText.slice(ticketStart, end);
}
function run(id) {
  return { id, name: `Run ${id}`, scenario_type: 'capacity_plan', environment: 'staging',
    authorization_ref: `auth-${id}`, status: 'planned', evidence_summary: `evidence-${id}`,
    results: { projected_requests: 8, estimated_concurrency: 2 } };
}
function harness() {
  const classes = new Set(['modal-backdrop', 'hidden']);
  const modal = {
    id: 'lab-detail-modal', style: { zIndex: '' },
    classList: {
      add(name) { classes.add(name); },
      remove(name) { classes.delete(name); },
      contains(name) { return classes.has(name); },
    },
  };
  const title = { textContent: '' };
  const content = { innerHTML: '' };
  const form = {
    elements: { status: { value: '' }, evidence_summary: { value: '' } },
    reset() { this.elements.status.value = ''; this.elements.evidence_summary.value = ''; },
  };
  const elements = { '#lab-detail-title': title, '#lab-detail-content': content, '#lab-update-form': form };
  const modalStack = [];
  const state = { selectedLabRun: null };
  const requests = [];
  const toasts = [];
  const document = {
    activeElement: null,
    body: { style: { overflow: '' } },
    getElementById(id) { return id === 'lab-detail-modal' ? modal : null; },
  };
  const context = {
    document, modalStack, lastModalTrigger: null, originalBodyOverflow: '', state,
    activeModal() { return modalStack.at(-1)?.modal ?? null; },
    visibleModalControl() { return false; },
    modalContains() { return false; },
    syncModalInert() {}, focusModal() {}, restoreModalFocus() {},
    $(selector) { return elements[selector]; },
    api(path) { return new Promise((resolveRequest, rejectRequest) => requests.push({ path, resolveRequest, rejectRequest, done: false })); },
    esc(value) { return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;'); },
    labScenarioLabel(value) { return value; },
    labScenarioDetails(value) { return `<span>${value.id}</span>`; },
    toast(message, type) { toasts.push({ message, type }); },
  };
  const methods = vm.runInNewContext(actualShowModal(source) + '\n' + actualLabDetail(source) + '\n({showModal, openLabDetail})', context, { filename: 'app.js/modal-and-lab-detail' });
  function take(id) {
    const request = requests.find(item => !item.done && item.path === `/api/lab-runs/${encodeURIComponent(id)}`);
    assert.ok(request, `deferred local GET for ${id} must exist`);
    request.done = true;
    return request;
  }
  return { ...methods, take, state, title, content, form, requests, toasts,
    visible() { return !classes.has('hidden'); }, modalStack };
}

test('closing a pending lab detail invalidates its late success without reopening the dialog', async () => {
  const h = harness();
  const pending = h.openLabDetail('A');
  const request = h.take('A');
  h.showModal('lab-detail-modal', false);
  assert.equal(h.visible(), false, 'the generic close path must hide the dialog');
  request.resolveRequest(run('A'));
  await pending;
  assert.equal(h.visible(), false, 'a late result must not reopen a closed dialog');
  assert.equal(h.state.selectedLabRun, null, 'a closed result must not become the editor selection');
  assert.equal(h.title.textContent, '', 'a closed result must not repaint the heading');
  assert.equal(h.form.elements.status.value, '', 'a closed result must not populate the status editor');
  assert.equal(h.toasts.length, 0);
});

test('closing a pending error suppresses its toast while a later fresh open still succeeds', async () => {
  const h = harness();
  const pending = h.openLabDetail('B');
  const request = h.take('B');
  h.showModal('lab-detail-modal', false);
  request.rejectRequest(new Error('late closed detail failure'));
  await pending;
  assert.equal(h.toasts.length, 0, 'a dismissed workflow must not surface an obsolete failure');
  assert.equal(h.visible(), false);
  const fresh = h.openLabDetail('C');
  h.take('C').resolveRequest(run('C'));
  await fresh;
  assert.equal(h.visible(), true, 'a fresh selection can still open the dialog');
  assert.equal(h.state.selectedLabRun?.id, 'C');
  assert.equal(h.title.textContent, 'Run C');
  assert.equal(h.form.elements.evidence_summary.value, 'evidence-C');
  assert.equal(h.modalStack.length, 1);
  h.showModal('lab-detail-modal', false);
  assert.equal(h.visible(), false, 'normal close must still work');
  assert.equal(h.modalStack.length, 0);
});
