import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const appRoot = process.env.SNIPER_TEST_APP_ROOT || resolve(fileURLToPath(new URL('../', import.meta.url)));
const bundle = readFileSync(join(appRoot, 'static/app.js'), 'utf8');

function functionSlice(source) {
  let start = source.indexOf('async function openLabDetail(runId) {');
  assert.notEqual(start, -1, 'the real lab detail function must exist');
  for (const marker of ['let activeLabDetailTicket = null;', 'let labDetailRequestSeq = 0;']) {
    const pos = source.lastIndexOf(marker, start);
    if (pos !== -1 && start - pos < 100) start = pos;
  }
  const end = source.indexOf('\nfunction openEngagementCreator()', start);
  assert.notEqual(end, -1, 'the actual function boundary must be present');
  return source.slice(start, end);
}

function makeRun(id) {
  return {
    id, name: `Run ${id}`, scenario_type: 'capacity_plan', environment: 'staging',
    authorization_ref: `auth-${id}`, status: 'planned', evidence_summary: `evidence-${id}`,
    results: { projected_requests: 12, estimated_concurrency: 2 },
  };
}
function harness(source) {
  const title = { textContent: '' };
  const content = { innerHTML: '' };
  const form = {
    elements: { status: { value: '' }, evidence_summary: { value: '' } },
    reset() { this.elements.status.value = ''; this.elements.evidence_summary.value = ''; },
  };
  const elements = { '#lab-detail-title': title, '#lab-detail-content': content, '#lab-update-form': form };
  const state = { selectedLabRun: null };
  const requests = [];
  const modals = [];
  const toasts = [];
  const context = {
    state,
    $(selector) { return elements[selector]; },
    api(path) { return new Promise((resolveRequest, rejectRequest) => requests.push({ path, resolveRequest, rejectRequest, done: false })); },
    esc(value) { return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;'); },
    labScenarioLabel(value) { return value; },
    labScenarioDetails(run) { return `<span>${run.id}</span>`; },
    showModal(id) { modals.push(id); },
    toast(message, type) { toasts.push({ message, type }); },
  };
  const open = vm.runInNewContext(functionSlice(source) + '\nopenLabDetail', context, { filename: 'app.js/openLabDetail' });
  function take(id) {
    const request = requests.find(req => !req.done && req.path === `/api/lab-runs/${encodeURIComponent(id)}`);
    assert.ok(request, `GET request for ${id} must be issued`);
    request.done = true;
    return request;
  }
  return { open, take, state, title, content, form, modals, toasts, requests };
}

test('newer lab selection owns title, editor and selected ID despite late older success or failure', async () => {
  const h = harness(bundle);
  const control = h.open('C');
  h.take('C').resolveRequest(makeRun('C'));
  await control;
  assert.equal(h.state.selectedLabRun?.id, 'C', 'single request control must open');
  assert.equal(h.title.textContent, 'Run C');
  assert.equal(h.form.elements.evidence_summary.value, 'evidence-C');
  assert.equal(h.modals.at(-1), 'lab-detail-modal');

  const slowA = h.open('A');
  const fastB = h.open('B');
  h.take('B').resolveRequest(makeRun('B'));
  await fastB;
  assert.equal(h.state.selectedLabRun?.id, 'B');
  assert.equal(h.title.textContent, 'Run B');
  assert.equal(h.form.elements.status.value, 'planned');
  assert.equal(h.form.elements.evidence_summary.value, 'evidence-B');
  const modalCount = h.modals.length;
  h.take('A').resolveRequest(makeRun('A'));
  await slowA;
  assert.equal(h.state.selectedLabRun?.id, 'B', 'late A must not change the ID used by the status editor');
  assert.equal(h.title.textContent, 'Run B', 'late A must not repaint the heading');
  assert.match(h.content.innerHTML, /auth-B/);
  assert.equal(h.form.elements.evidence_summary.value, 'evidence-B');
  assert.equal(h.modals.length, modalCount, 'late A must not reopen an obsolete modal');

  const staleError = h.open('D');
  const newer = h.open('E');
  h.take('E').resolveRequest(makeRun('E'));
  await newer;
  const toastCount = h.toasts.length;
  h.take('D').rejectRequest(new Error('stale D failure'));
  await staleError;
  assert.equal(h.state.selectedLabRun?.id, 'E');
  assert.equal(h.title.textContent, 'Run E');
  assert.equal(h.toasts.length, toastCount, 'a superseded failure must not show an error toast');

  const wrongId = h.open('F');
  h.take('F').resolveRequest(makeRun('not-F'));
  await wrongId;
  assert.equal(h.state.selectedLabRun, null, 'mismatched response ID must not become the selected record');
  assert.equal(h.title.textContent, '');
  assert.equal(h.form.elements.status.value, '');
  assert.equal(h.toasts.at(-1)?.type, 'error');
  assert.equal(h.requests.length, 6, 'only the six explicit local GETs were issued');
});
