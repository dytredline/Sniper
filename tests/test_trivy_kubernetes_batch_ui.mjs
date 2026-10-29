import assert from 'node:assert/strict';
import {test} from 'node:test';
import fs from 'node:fs';
import vm from 'node:vm';

const root = new URL('../', import.meta.url).pathname;
const htmlPath = process.env.SNIPER_K8S_BATCH_HTML || root + 'static/index.html';
const jsPath = process.env.SNIPER_K8S_BATCH_JS || root + 'static/trivy_kubernetes_batch_ui.js';
const html = fs.readFileSync(htmlPath, 'utf8');
const validResult = () => ({
  format: 'trivy-native-json', schema_version: 2, profile: 'local-kubernetes-manifest-config-batch-v1',
  result_count: 2,
  class_counts: {'os-pkgs':0, 'lang-pkgs':0, config:2, secret:0, license:0, 'license-file':0, crypto:0, custom:0, unknown:0},
  vuln_counts: {critical:0, high:0, medium:0, low:0, unknown:0},
  misconfig_sev_counts: {critical:0, high:0, medium:2, low:0, unknown:0},
  finding_counts: {vulnerabilities:0, misconfigurations:2, secrets:0, licenses:0},
  report_sha256: 'a'.repeat(64),
});
function fixture(initial = validResult()) {
  const nodes = new Map(), calls = [];
  let response = {ok:true, status:200, json:async()=>initial};
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const handlers = new Map(), classes = new Set(['hidden']);
    const item = {
      id, value:'', checked:false, disabled:false, textContent:'', handlers,
      classList: {add(key){classes.add(key)}, remove(key){classes.delete(key)}, contains(key){return classes.has(key)}},
      addEventListener(type, callback){handlers.set(type,[...(handlers.get(type)||[]),callback]);},
    };
    nodes.set(id,item); return item;
  }
  const document = {getElementById:node};
  const fetch = async (url, options={}) => {calls.push({url,options}); return response;};
  vm.runInNewContext(fs.readFileSync(jsPath,'utf8'), {document,fetch,JSON,String,Number,Object,Array,Promise,Set}, {timeout:1000});
  async function emit(id,type){for(const cb of node(id).handlers.get(type)||[]) await cb({target:node(id),preventDefault(){}});}
  return {node,calls,emit,setResponse(next){response=next}};
}

test('tool matrix offers a separate consented local Kubernetes batch form', () => {
  assert.match(html, /id="trivy-kubernetes-batch-form"/);
  assert.match(html, /id="trivy-kubernetes-batch-consent"/);
  assert.match(html, /trivy_kubernetes_batch_ui\.js\?v=1/);
});

test('opening the page or submitting invalid names cannot trigger a batch scan', async () => {
  const f=fixture();
  assert.equal(f.calls.length,0);
  f.node('trivy-kubernetes-batch-path').value='/home/community-user/synthetic';
  f.node('trivy-kubernetes-batch-names').value='pod.yaml\ndeployment.yaml';
  await f.emit('trivy-kubernetes-batch-form','submit');
  assert.equal(f.calls.length,0);
  f.node('trivy-kubernetes-batch-consent').checked=true;
  for(const invalid of ['../pod.yaml','pod.json','pod.yaml\npod.yaml','x/pod.yaml',Array.from({length:9},(_,i)=>`pod${i}.yaml`).join('\n')]) {
    f.node('trivy-kubernetes-batch-names').value=invalid;
    await f.emit('trivy-kubernetes-batch-names','input');
    await f.emit('trivy-kubernetes-batch-form','submit');
    assert.equal(f.calls.length,0,invalid);
  }
  assert.equal(f.node('trivy-kubernetes-batch-submit').disabled,true);
});

test('one consented submit sends exact batch payload and renders aggregate runtime result', async () => {
  const f=fixture();
  f.node('trivy-kubernetes-batch-path').value='/home/community-user/synthetic';
  f.node('trivy-kubernetes-batch-names').value='pod.yaml\ndeployment.yaml';
  f.node('trivy-kubernetes-batch-consent').checked=true;
  await f.emit('trivy-kubernetes-batch-consent','change');
  assert.equal(f.node('trivy-kubernetes-batch-submit').disabled,false);
  await f.emit('trivy-kubernetes-batch-form','submit');
  assert.equal(f.calls.length,1);
  assert.equal(f.calls[0].url,'/api/tool-runs/trivy-kubernetes-config-batch');
  assert.equal(f.calls[0].options.method,'POST');
  assert.deepEqual(JSON.parse(f.calls[0].options.body),{confirm_local:true,project_path:'/home/community-user/synthetic',manifest_names:['pod.yaml','deployment.yaml']});
  assert.equal(f.node('trivy-kubernetes-batch-groups').textContent,'2');
  assert.equal(f.node('trivy-kubernetes-batch-total').textContent,'2');
  assert.equal(f.node('trivy-kubernetes-batch-hash').textContent,'a'.repeat(64));
  assert.equal(f.node('trivy-kubernetes-batch-result').classList.contains('hidden'),false);
  assert.equal(f.node('trivy-kubernetes-batch-path').value,'');
  assert.equal(f.node('trivy-kubernetes-batch-names').value,'');
  assert.equal(f.node('trivy-kubernetes-batch-consent').checked,false);
});

test('malformed or private result is rejected without displaying source details', async () => {
  const f=fixture();
  f.setResponse({ok:true,json:async()=>({...validResult(),private_manifest:'secret.yaml'})});
  f.node('trivy-kubernetes-batch-path').value='/home/community-user/private';
  f.node('trivy-kubernetes-batch-names').value='pod.yaml\ndeployment.yaml';
  f.node('trivy-kubernetes-batch-consent').checked=true;
  await f.emit('trivy-kubernetes-batch-consent','change');
  await f.emit('trivy-kubernetes-batch-form','submit');
  assert.equal(f.node('trivy-kubernetes-batch-result').classList.contains('hidden'),true);
  assert.equal(f.node('trivy-kubernetes-batch-hash').textContent,'');
  assert.doesNotMatch(f.node('trivy-kubernetes-batch-error').textContent,/secret\.yaml|\/home\/converserai\/private/i);
});
