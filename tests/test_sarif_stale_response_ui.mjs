import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const appPath = process.env.SNIPER_TASK72_APP_JS || fileURLToPath(new URL('../static/app.js', import.meta.url));
const nodes = new Map();
const listeners = new Map();
const pending = [];
const requests = [];
function node(key) {
  if (nodes.has(key)) return nodes.get(key);
  const classes = new Set();
  const n = {
    id: String(key).replace(/^#/, ''), dataset: {}, style: {},
    value: '', files: [], innerHTML: '', textContent: '', disabled: false,
    classList: {
      add: k => classes.add(k), remove: k => classes.delete(k),
      contains: k => classes.has(k),
      toggle(k, force) { if (force ?? !classes.has(k)) classes.add(k); else classes.delete(k); },
    },
    addEventListener() {}, append() {}, appendChild() {}, remove() {},
    focus() {}, reset() {}, setSelectionRange() {}, setAttribute() {}, removeAttribute() {},
    querySelector: q => node(q), querySelectorAll: () => [],
    closest() { return null; },
  };
  nodes.set(key,n); return n;
}
const document = {
  body: node('body'),
  querySelector: q => node(q), querySelectorAll: () => [],
  getElementById: id => node('#'+id), createElement: t => node('created:'+t),
  addEventListener(name, callback) {
    const a = listeners.get(name) || []; a.push(callback); listeners.set(name,a);
  },
};
const getResponses = {
  '/api/dashboard': {}, '/api/targets': {targets: []},
  '/api/scans?limit=200': {scans: []}, '/api/engagements': {engagements: []},
  '/api/lab-runs': {lab_runs: []}, '/api/project-audits': {project_audits: [], total: 0},
  '/api/tooling': {tools: [], categories: [], summary: {}, policy: {native: '', external: '', completion: ''}},
  '/api/dependency-security': {},
};
async function fetch(path, options={}) {
  requests.push({path,method:options.method || 'GET'});
  if (options.method === 'POST') {
    assert.equal(path,'/api/tool-reports/sarif/summary');
    return new Promise(resolve => pending.push(data => resolve(data === null
      ? {ok:false,status:503,json:async()=>({error:'synthetic failure'})}
      : {ok:true,status:200,json:async()=>data})));
  }
  return {ok:true,status:200,json:async()=>getResponses[path]||{}};
}
const context = vm.createContext({
  document, window:{addEventListener(){}}, location:{hash:''},
  history:{replaceState(){}}, fetch, TextEncoder, URL, console,
  setTimeout:()=>0, clearTimeout(){}, setInterval:()=>0,
});
vm.runInContext(fs.readFileSync(appPath,'utf8'),context,{filename:appPath});
await new Promise(resolve => setImmediate(resolve));
async function dispatch(name,target,wait=true) {
  const event={target,currentTarget:target,preventDefault(){},stopPropagation(){}};
  const ps=(listeners.get(name)||[]).map(cb=>cb(event));
  if (wait) await Promise.all(ps);
  return Promise.all(ps);
}
function sarif(tag) { return JSON.stringify({version:'2.1.0',runs:[{tool:{driver:{name:'osv-scanner'}},results:[{message:{text:tag}}]}]}); }
function summary(tag,count) {
  return {format:'sarif',run_count:1,result_count:count,
    tools:[{name:'osv-scanner',result_count:count,levels:{error:count,warning:0,note:0,none:0}}],
    report_sha256: tag.repeat(64)};
}
function closeTarget() {
  const t=node('close-target');
  t.dataset.close='sarif-preview-modal';
  t.closest=function(q){return q==='[data-close]'?this:null;};
  return t;
}
function openTarget() {
  const t=node('open-target');
  t.dataset.action='open-sarif-preview';
  t.closest=function(q){return q==='[data-action]'?this:null;};
  return t;
}
test('saved SARIF preview ignores dismissed and superseded asynchronous responses', async () => {
const paste=node('#sarif-paste');
const result=node('#sarif-preview-result');
const modal=node('#sarif-preview-modal');
const form=node('#sarif-preview-form');

// Passing normal control: valid saved OSV SARIF renders, one synthetic POST.
await dispatch('click',openTarget());
paste.value=sarif('a');
const p1=dispatch('submit',form,false);
assert.equal(pending.length,1);
pending.shift()(summary('a',1));
await p1;
assert.equal(node('#sarif-result-count').textContent,1);
assert.equal(result.classList.contains('hidden'),false);
console.log('CONTROL_PASS: valid OSV SARIF summary visible; synthetic POST count',requests.filter(r=>r.method==='POST').length);

// Edge 1: close before response. Close should clear and keep hidden on reopen.
paste.value=sarif('b');
const p2=dispatch('submit',form,false);
assert.equal(pending.length,1);
await dispatch('click',closeTarget());
assert.equal(result.classList.contains('hidden'),true);
pending.shift()(summary('b',2));
await p2;
const afterClose={
  modalHidden:modal.classList.contains('hidden'),
  resultHidden:result.classList.contains('hidden'),
  resultCount:node('#sarif-result-count').textContent
};
await dispatch('click',openTarget());
const afterReopen={resultHidden:result.classList.contains('hidden'),resultCount:node('#sarif-result-count').textContent};
console.log('EDGE_CLOSE_RESPONSE',JSON.stringify({afterClose,afterReopen}));
assert.equal(afterReopen.resultHidden,true);
assert.equal(afterReopen.resultCount,'');

// Edge 2: a delayed older response must not overwrite a newer summary.
paste.value=sarif('c');
const old=dispatch('submit',form,false);
paste.value=sarif('d');
const newer=dispatch('submit',form,false);
assert.equal(pending.length,2);
const [resolveOld,resolveNew]=pending.splice(0);
resolveNew(summary('d',4)); await newer;
assert.equal(node('#sarif-result-count').textContent,4);
resolveOld(summary('c',3)); await old;
const race={resultCount:node('#sarif-result-count').textContent,reportHash:node('#sarif-report-sha256').textContent};
console.log('EDGE_OLDER_RESPONSE',JSON.stringify(race));
assert.equal(race.resultCount,4);
assert.equal(race.reportHash,'d'.repeat(64));
assert.equal(requests.filter(r=>r.method==='POST').length,4);

// Edge 3: closing while the selected file is still being read must not POST it.
paste.value='';
let resolveRead;
const fileInput=node('#sarif-file');
fileInput.files=[{size:32,text:()=>new Promise(resolve=>{resolveRead=resolve;})}];
const filePending=dispatch('submit',form,false);
assert.equal(typeof resolveRead,'function');
await dispatch('click',closeTarget());
resolveRead(sarif('e'));
await filePending;
assert.equal(requests.filter(r=>r.method==='POST').length,4);
assert.equal(result.classList.contains('hidden'),true);
await dispatch('click',openTarget());

// Edge 4: a late server failure after close must not reveal an error.
fileInput.files=[];
paste.value=sarif('f');
const failed=dispatch('submit',form,false);
assert.equal(pending.length,1);
await dispatch('click',closeTarget());
pending.shift()(null);
await failed;
assert.equal(node('#sarif-preview-error').classList.contains('hidden'),true);
assert.equal(node('#sarif-preview-error').textContent,'');
assert.equal(requests.filter(r=>r.method==='POST').length,5);
});
