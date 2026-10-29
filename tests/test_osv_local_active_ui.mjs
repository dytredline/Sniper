import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {test} from 'node:test';

const script = new URL('../static/osv_local_active.js', import.meta.url);
const index = fs.readFileSync(new URL('../static/index.html', import.meta.url), 'utf8');
const source = fs.readFileSync(script, 'utf8');
const validReply = () => ({
  format:'osv-scanner-json', profile:'local-npm-lock-osv-offline-v1',
  coverage:'public-registry-lockfile', package_count:3,
  affected_package_count:1, vulnerability_group_count:2,
  offline_db_sha256:'a'.repeat(64), offline_db_retrieved_utc:'2026-10-13T10:00:00+00:00',
  report_sha256:'b'.repeat(64),
});

function setup(reply = validReply()) {
  const nodes = new Map();
  const requests = [];
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const classes = new Set(['hidden']);
    const value = {id, value:'', checked:false, disabled:false, textContent:'', handlers:new Map(),
      classList:{add:key=>classes.add(key),remove:key=>classes.delete(key),contains:key=>classes.has(key)},
      addEventListener(type,handler) {this.handlers.set(type,[...(this.handlers.get(type)||[]),handler]);}};
    nodes.set(id,value);
    return value;
  }
  const document = {
    getElementById: node,
    querySelector(selector) {
      return selector === 'meta[name="sniper-local-home"]' ? {content:'/home/community-user'} : null;
    },
  };
  async function api(route, options) {
    requests.push({route,options});
    if (reply instanceof Error) throw reply;
    return reply;
  }
  vm.runInNewContext(source,{document,api,Object},{filename:script.pathname});
  async function submit() {
    for (const handler of node('osv-active-form').handlers.get('submit') || [])
      await handler({preventDefault(){}});
  }
  function change(id,type) {
    for (const handler of node(id).handlers.get(type) || []) handler();
  }
  function approve(projectPath='/home/community-user/demo') {
    node('osv-active-path').value=projectPath;
    node('osv-active-consent').checked=true;
    change('osv-active-path','input');change('osv-active-consent','change');
  }
  return {node,requests,submit,change,approve};
}

test('tool matrix offers separate ready local form and saved SARIF preview',()=>{
  const app=fs.readFileSync(new URL('../static/app.js', import.meta.url),'utf8');
  assert.match(app,/"\/api\/tool-runs\/osv-scanner-local": \{ panel: "osv-active-panel" \}/);
  assert.match(app,/"\/api\/tool-reports\/sarif\/summary": \{ action: "open-sarif-preview" \}/);
  assert.match(index,/id="sarif-preview-modal"/);
  assert.match(index,/id="osv-active-panel"/);
  assert.match(index,/osv_local_active\.js\?v=1/);
  assert.doesNotMatch(index.match(/id="osv-active-panel"[\s\S]*?id="tooling-policy"/)?.[0] || '',/type="file"/);
});

test('no scan on load, path entry, or consent; submit sends exactly one consented local request',async()=>{
  const ui=setup();
  assert.equal(ui.requests.length,0);
  ui.node('osv-active-path').value='/home/community-user/demo';
  ui.change('osv-active-path','input');
  assert.equal(ui.requests.length,0);
  await ui.submit();
  assert.equal(ui.requests.length,0);
  ui.node('osv-active-consent').checked=true;
  ui.change('osv-active-consent','change');
  assert.equal(ui.requests.length,0);
  assert.equal(ui.node('osv-active-submit').disabled,false);
  await ui.submit();
  assert.equal(ui.requests.length,1);
  assert.equal(ui.requests[0].route,'/api/tool-runs/osv-scanner-local');
  assert.equal(ui.requests[0].options.method,'POST');
  assert.deepEqual(JSON.parse(ui.requests[0].options.body),{
    confirm_local:true,project_path:'/home/community-user/demo',
  });
  assert.equal(ui.node('osv-active-packages').textContent,'3');
  assert.equal(ui.node('osv-active-affected').textContent,'1');
  assert.equal(ui.node('osv-active-groups').textContent,'2');
  assert.equal(ui.node('osv-active-coverage').textContent,'public-registry-lockfile');
  assert.equal(ui.node('osv-active-db-time').textContent,'2026-10-13T10:00:00+00:00');
  assert.equal(ui.node('osv-active-db-hash').textContent,'a'.repeat(64));
  assert.equal(ui.node('osv-active-report-hash').textContent,'b'.repeat(64));
  assert.equal(ui.node('osv-active-result').classList.contains('hidden'),false);
  assert.equal(ui.node('osv-active-path').value,'');
  assert.equal(ui.node('osv-active-consent').checked,false);
  assert.equal(ui.node('osv-active-submit').disabled,true);
});

test('external paths and traversal are rejected before any request',async()=>{
  for (const path of ['/tmp/elsewhere','/home/community-user','/home/community-user//double',
    '/home/community-user/../elsewhere','http://example.test','/home/community-user/a\\b']) {
    const ui=setup();ui.approve(path);await ui.submit();
    assert.equal(ui.requests.length,0,path);
    assert.equal(ui.node('osv-active-error').classList.contains('hidden'),false,path);
  }
});

test('malformed or private fields fail closed without printing server data',async()=>{
  for (const reply of [
    {...validReply(),packages:[{name:'PRIVATE_PACKAGE'}]},
    {...validReply(),affected_package_count:4},
    {...validReply(),vulnerability_group_count:0},
    {...validReply(),report_sha256:['b'.repeat(64)]},
    {...validReply(),offline_db_retrieved_utc:'untrusted timestamp'},
    new Error('PRIVATE_PATH_AND_NAME'),
  ]) {
    const ui=setup(reply);ui.approve();await ui.submit();
    assert.equal(ui.requests.length,1);
    assert.equal(ui.node('osv-active-result').classList.contains('hidden'),true);
    assert.equal(ui.node('osv-active-error').classList.contains('hidden'),false);
    const displayed=['osv-active-error','osv-active-packages','osv-active-affected','osv-active-groups']
      .map(id=>ui.node(id).textContent).join(' ');
    assert.equal(displayed.includes('PRIVATE'),false);
  }
});
