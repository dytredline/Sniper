'use strict';
// Contract probe authored for Task44 from the public Lab API/UI behavior.
// It receives only persisted GET payloads and executes the selected UI source.
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[2], 'utf8');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
function section(first, after) {
  const a = source.indexOf(first);
  const b = source.indexOf(after, a + first.length);
  if (a < 0 || b < 0 || b <= a) throw Error(`UI source marker missing: ${first}`);
  return source.substring(a, b);
}
const editor = { status: { value: '' }, evidence_summary: { value: '' } };
const form = {
  elements: editor,
  reset() { editor.status.value = 'planned'; editor.evidence_summary.value = ''; },
  addEventListener(kind, fn) { if (kind === 'submit') this.submit = fn; },
};
const title = { textContent: '' };
const content = { innerHTML: '' };
const submitButton = { disabled: false };
const modalEvents = [], toasts = [], apiCalls = [];
const nodes = new Map([
  ['#lab-detail-title', title], ['#lab-detail-content', content], ['#lab-update-form', form],
]);
let pending = null;
const sandbox = {
  state: { selectedLabRun: null, labRuns: [], engagements: [] },
  $: (query, root) => query === 'button[type=submit]' && root === form ? submitButton : nodes.get(query),
  showModal: (name, visible = true) => modalEvents.push([name, visible]),
  toast: (message, kind = 'info') => toasts.push({ message, kind }),
  loadAll: async () => {},
  navigate: () => {},
  api: (url, options = {}) => {
    apiCalls.push({ url, method: options.method || 'GET', body: options.body || null });
    if (options.method === 'POST') return Promise.resolve({ ok: true });
    const prefix = '/api/lab-runs/';
    if (!url.startsWith(prefix)) return Promise.reject(Error(`Unexpected request ${url}`));
    const id = decodeURIComponent(url.substring(prefix.length));
    if (pending && Object.prototype.hasOwnProperty.call(pending, id)) return pending[id].promise;
    if (!Object.prototype.hasOwnProperty.call(input.records, id)) return Promise.reject(Error('Record absent'));
    return Promise.resolve(input.records[id]);
  },
  FormData: class {
    constructor(target) { this.target = target; }
    entries() { return Object.entries({status: this.target.elements.status.value, evidence_summary: this.target.elements.evidence_summary.value}); }
  },
  Number, String, Object, Array, Symbol, encodeURIComponent,
};
vm.createContext(sandbox);
vm.runInContext([
  section('const esc =', 'async function api('),
  section('function labScenarioLabel(type)', 'function openEngagementCreator()'),
  section('$("#lab-update-form").addEventListener("submit"', '$("#test-form").addEventListener("submit"'),
].join('\n'), sandbox, { filename: 'contract-ui-slices.js' });
function snapshot() {
  return {
    selected: sandbox.state.selectedLabRun?.id || null,
    title: title.textContent,
    html: content.innerHTML,
    status: editor.status.value,
    evidence: editor.evidence_summary.value,
    modals: modalEvents.slice(),
    toasts: toasts.slice(),
  };
}
function deferred() {
  let yes, no;
  const promise = new Promise((resolve, reject) => { yes = resolve; no = reject; });
  return { promise, yes, no };
}
async function run() {
  const order = input.order;
  if (input.mode === 'render') {
    const views = [];
    for (const id of order) { await sandbox.openLabDetail(id); views.push(snapshot()); }
    await sandbox.openLabDetail('missing_task44');
    views.push(snapshot());
    return { views, apiCalls };
  }
  if (input.mode !== 'race') throw Error(`Unexpected probe mode ${input.mode}`);
  const [slowId, fastId, controlId] = order;
  await sandbox.openLabDetail(controlId);
  const control = snapshot();
  pending = { [slowId]: deferred(), [fastId]: deferred() };
  const slow = sandbox.openLabDetail(slowId);
  const fast = sandbox.openLabDetail(fastId);
  pending[fastId].yes(input.records[fastId]);
  await fast;
  const firstWinner = snapshot();
  pending[slowId].yes(input.records[slowId]);
  await slow;
  const lateSuccess = snapshot();
  editor.status.value = 'completed';
  editor.evidence_summary.value = 'B-only signed evidence';
  if (typeof form.submit !== 'function') throw Error('Lab update submit handler missing');
  await form.submit({ preventDefault() {}, currentTarget: form });
  const afterSubmit = snapshot();
  pending = { [slowId]: deferred(), [fastId]: deferred() };
  const lateFailureTask = sandbox.openLabDetail(slowId);
  const secondWinnerTask = sandbox.openLabDetail(fastId);
  pending[fastId].yes(input.records[fastId]);
  await secondWinnerTask;
  const toastCount = toasts.length;
  pending[slowId].no(Error('obsolete failed request'));
  await lateFailureTask;
  return { control, firstWinner, lateSuccess, afterSubmit, lateFailure: snapshot(), priorToastCount: toastCount, apiCalls };
}
run().then(output => process.stdout.write(JSON.stringify(output))).catch(error => { console.error(error.stack || error); process.exitCode = 1; });
