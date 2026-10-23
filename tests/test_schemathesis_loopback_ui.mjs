import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

const url = new URL('../static/schemathesis_loopback.js', import.meta.url);
const source = existsSync(url) ? readFileSync(url, 'utf8') : '';
const html = readFileSync(new URL('../static/index.html', import.meta.url), 'utf8');
const appSource = readFileSync(new URL('../static/app.js', import.meta.url), 'utf8');
const route = '/api/tool-runs/schemathesis-loopback';
const schema = {openapi:'3.0.3',info:{title:'fixture',version:'1'},paths:{'/api/ping':{get:{responses:{'200':{description:'ok'}}}}}};
const aggregate = {status:'completed',scope:'approved-loopback',request_count:2,format:'schemathesis-junit-xml',suite_count:1,testcase_count:2,outcome_counts:{passed:2,failed:0,errors:0,skipped:0},report_sha256:'a'.repeat(64),private_url:'https://secret.invalid/'};
const profile = runtime => ({tools:[{id:'schemathesis',profiles:[{route,runtime,action:'local_input_required'}]}]});
function setup(runtime='precheck_passed', response=aggregate) {
  const nodes=new Map(), listeners=new Map(), calls=[], modals=[];
  function node(id) {
    if(nodes.has(id))return nodes.get(id);
    const classes=new Set(['hidden']);
    const n={id,value:'',checked:false,textContent:'',disabled:false,
      classList:{add(name){classes.add(name)},remove(name){classes.delete(name)},contains(name){return classes.has(name)}},
      querySelector(){return node('submit-button')}};
    nodes.set(id,n);return n;
  }
  const document={getElementById:node,addEventListener(name,handler){const group=listeners.get(name)||[];group.push(handler);listeners.set(name,group)}};
  vm.runInNewContext(source,{document,TextEncoder,showModal(id,visible){modals.push([id,visible])},
    async api(path,options){calls.push([path,options]);return path==='/api/tooling/readiness'?profile(runtime):response}});
  async function dispatch(name,target){for(const handler of listeners.get(name)||[])await handler({target,preventDefault(){}})}
  const open={id:'open',closest(selector){return selector.includes('open-schemathesis-loopback')?this:null}};
  return {node,dispatch,calls,modals,open};
}

test('separate general modal and catalog mapping are present',()=>{
  assert.ok(/id="schemathesis-loopback-modal"/.test(html));
  assert.ok(/data-action="open-schemathesis-loopback"/.test(html));
  assert.ok(/src="\/schemathesis_loopback\.js\?v=/.test(html));
  assert.ok(/"\/api\/tool-runs\/schemathesis-loopback":\s*\{\s*action:\s*"open-schemathesis-loopback"\s*\}/.test(appSource));
  assert.ok(source.length>0);
});

test('unconfigured profile refuses a scan despite programmatic submit',async()=>{
  const ui=setup('unavailable');await ui.dispatch('click',ui.open);
  assert.equal(ui.node('submit-button').disabled,true);
  ui.node('schemathesis-loopback-port').value='49123';ui.node('schemathesis-loopback-schema').value=JSON.stringify(schema);ui.node('schemathesis-loopback-consent').checked=true;
  await ui.dispatch('submit',ui.node('schemathesis-loopback-form'));
  assert.equal(ui.calls.filter(call=>call[0]===route).length,0);
  assert.match(ui.node('schemathesis-loopback-availability').textContent,/kullanılamıyor/i);
});

test('ready submission calls only general route and renders bounded aggregate, then clears private input',async()=>{
  const ui=setup();await ui.dispatch('click',ui.open);
  ui.node('schemathesis-loopback-port').value='49123';ui.node('schemathesis-loopback-schema').value=JSON.stringify(schema);
  await ui.dispatch('submit',ui.node('schemathesis-loopback-form'));
  assert.equal(ui.calls.filter(call=>call[0]===route).length,0);
  ui.node('schemathesis-loopback-consent').checked=true;
  await ui.dispatch('submit',ui.node('schemathesis-loopback-form'));
  const posts=ui.calls.filter(call=>call[0]===route);
  assert.equal(posts.length,1);
  assert.deepEqual(JSON.parse(posts[0][1].body),{confirm_local:true,target_url:'http://127.0.0.1:49123',schema});
  assert.equal(ui.node('schemathesis-loopback-request-count').textContent,'2');
  assert.equal(ui.node('schemathesis-loopback-report-sha256').textContent,'a'.repeat(64));
  assert.equal(ui.node('schemathesis-loopback-result').classList.contains('hidden'),false);
  assert.doesNotMatch(ui.node('schemathesis-loopback-outcomes').textContent,/secret|private/);
  assert.equal(ui.node('schemathesis-loopback-port').value,'');
  assert.equal(ui.node('schemathesis-loopback-schema').value,'');
  assert.equal(ui.node('schemathesis-loopback-consent').checked,false);
});

test('nonliteral port and malformed aggregate fail closed',async()=>{
  const ui=setup('precheck_passed',{...aggregate,request_count:25});await ui.dispatch('click',ui.open);
  ui.node('schemathesis-loopback-consent').checked=true;ui.node('schemathesis-loopback-schema').value=JSON.stringify(schema);
  ui.node('schemathesis-loopback-port').value='example.com';
  await ui.dispatch('submit',ui.node('schemathesis-loopback-form'));
  assert.equal(ui.calls.filter(call=>call[0]===route).length,0);
  ui.node('schemathesis-loopback-port').value='49123';
  await ui.dispatch('submit',ui.node('schemathesis-loopback-form'));
  assert.equal(ui.calls.filter(call=>call[0]===route).length,1);
  assert.equal(ui.node('schemathesis-loopback-result').classList.contains('hidden'),true);
  assert.equal(ui.node('schemathesis-loopback-request-count').textContent,'');
});
