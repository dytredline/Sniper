import assert from 'node:assert/strict';
import {test} from 'node:test';
import fs from 'node:fs';
import vm from 'node:vm';

const root = new URL('../', import.meta.url).pathname;
const htmlPath = process.env.SNIPER_TRIVY_SECRET_HTML || root + 'static/index.html';
const jsPath = process.env.SNIPER_TRIVY_SECRET_JS || root + 'static/trivy_secret_ui.js';
const html = fs.readFileSync(htmlPath, 'utf8');
const result = (secretCount = 2) => ({
  format:'trivy-native-json', schema_version:2, profile:'local-secret-v1', result_count: secretCount ? 1 : 0,
  class_counts: {'os-pkgs':0,'lang-pkgs':0,config:0,secret:secretCount ? 1 : 0,license:0,'license-file':0,crypto:0,custom:0,unknown:0},
  vuln_counts: {critical:0,high:0,medium:0,low:0,unknown:0},
  misconfig_sev_counts: {critical:0,high:0,medium:0,low:0,unknown:0},
  finding_counts: {vulnerabilities:0,misconfigurations:0,secrets:secretCount,licenses:0},
  report_sha256:'a'.repeat(64),
});

function fixture(initial = result()) {
  const nodes = new Map(), calls = [];
  let response = {ok:true,status:200,json:async()=>initial};
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const handlers = new Map(), classes = new Set(['hidden']);
    const item = {id,value:'',checked:false,disabled:false,textContent:'',handlers,
      classList:{add(k){classes.add(k)},remove(k){classes.delete(k)},contains(k){return classes.has(k)}},
      addEventListener(type,callback){handlers.set(type,[...(handlers.get(type)||[]),callback]);}};
    nodes.set(id,item); return item;
  }
  const document = {getElementById:node};
  const fetch = async (url,options={}) => {calls.push({url,options});return response;};
  vm.runInNewContext(fs.readFileSync(jsPath,'utf8'), {document,fetch,JSON,String,Number,Object,Array,Promise}, {timeout:1000});
  async function emit(id,type){for(const cb of node(id).handlers.get(type)||[]) await cb({target:node(id),preventDefault(){}});}
  return {node,calls,emit,setResponse(next){response=next}};
}

test('tool matrix exposes a separate explicit-consent local Trivy secret form', () => {
  assert.match(html,/id="trivy-secret-form"/);
  assert.match(html,/id="trivy-secret-consent"/);
  assert.match(html,/trivy_secret_ui\.js\?v=1/);
  assert.match(html,/Trivy yerel sır taraması/);
});

test('page load, missing consent and invalid paths never call scanner API', async () => {
  const f=fixture();
  assert.equal(f.calls.length,0);
  f.node('trivy-secret-path').value='/home/community-user/project';
  await f.emit('trivy-secret-form','submit');
  assert.equal(f.calls.length,0);
  f.node('trivy-secret-consent').checked=true;
  for (const invalid of ['/', '/home/community-user/../private','/home//project','/home\\project']) {
    f.node('trivy-secret-path').value=invalid;
    await f.emit('trivy-secret-path','input');
    await f.emit('trivy-secret-form','submit');
    assert.equal(f.calls.length,0,invalid);
  }
  assert.equal(f.node('trivy-secret-submit').disabled,true);
});

test('explicit submit sends exact payload and displays changing aggregate result', async () => {
  const f=fixture();
  f.node('trivy-secret-path').value='/home/community-user/synthetic';
  f.node('trivy-secret-consent').checked=true;
  await f.emit('trivy-secret-consent','change');
  assert.equal(f.node('trivy-secret-submit').disabled,false);
  await f.emit('trivy-secret-form','submit');
  assert.equal(f.calls.length,1);
  assert.equal(f.calls[0].url,'/api/tool-runs/trivy-secret');
  assert.equal(f.calls[0].options.method,'POST');
  assert.deepEqual(JSON.parse(f.calls[0].options.body),{confirm_local:true,project_path:'/home/community-user/synthetic'});
  assert.equal(f.node('trivy-secret-groups').textContent,'1');
  assert.equal(f.node('trivy-secret-total').textContent,'2');
  assert.equal(f.node('trivy-secret-hash').textContent,'a'.repeat(64));
  assert.equal(f.node('trivy-secret-result').classList.contains('hidden'),false);
  assert.equal(f.node('trivy-secret-path').value,'');
  assert.equal(f.node('trivy-secret-consent').checked,false);
  f.setResponse({ok:true,json:async()=>result(0)});
  f.node('trivy-secret-path').value='/home/community-user/synthetic';
  f.node('trivy-secret-consent').checked=true;
  await f.emit('trivy-secret-consent','change');
  await f.emit('trivy-secret-form','submit');
  assert.equal(f.calls.length,2);
  assert.equal(f.node('trivy-secret-total').textContent,'0');
});

test('wrong profile, extra private data or malformed response never renders raw secrets', async () => {
  for (const data of [
    {...result(),profile:'local-vuln-v1'},
    {...result(),raw_secret:'EXAMPLE-PRIVATE-VALUE'},
    {...result(),result_count:2},
    {...result(),finding_counts:{...result().finding_counts,secrets:-1}},
  ]) {
    const f=fixture(data);
    f.node('trivy-secret-path').value='/home/community-user/private';
    f.node('trivy-secret-consent').checked=true;
    await f.emit('trivy-secret-consent','change');
    await f.emit('trivy-secret-form','submit');
    assert.equal(f.calls.length,1);
    assert.equal(f.node('trivy-secret-result').classList.contains('hidden'),true);
    assert.equal(f.node('trivy-secret-hash').textContent,'');
    assert.doesNotMatch(f.node('trivy-secret-error').textContent,/EXAMPLE-PRIVATE|\/home\/converserai\/private/);
  }
});
