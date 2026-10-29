import assert from 'node:assert/strict';
import {test} from 'node:test';
import fs from 'node:fs';
import vm from 'node:vm';

const root = new URL('../', import.meta.url).pathname;
const htmlPath = process.env.SNIPER_K8S_SINGLE_HTML || root + 'static/index.html';
const jsPath = process.env.SNIPER_K8S_SINGLE_JS || root + 'static/trivy_kubernetes_single_ui.js';
const html = fs.readFileSync(htmlPath, 'utf8');
const validResult = (count = 2) => ({
  format: 'trivy-native-json', schema_version: 2, profile: 'local-kubernetes-manifest-config-v1', result_count: 1,
  class_counts: {'os-pkgs':0, 'lang-pkgs':0, config:1, secret:0, license:0, 'license-file':0, crypto:0, custom:0, unknown:0},
  vuln_counts: {critical:0, high:0, medium:0, low:0, unknown:0},
  misconfig_sev_counts: {critical:0, high:0, medium:count, low:0, unknown:0},
  finding_counts: {vulnerabilities:0, misconfigurations:count, secrets:0, licenses:0},
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
      addEventListener(type, callback) {handlers.set(type,[...(handlers.get(type)||[]),callback]);},
    };
    nodes.set(id,item); return item;
  }
  const document = {getElementById:node};
  const fetch = async (url, options={}) => {calls.push({url,options}); return response;};
  vm.runInNewContext(fs.readFileSync(jsPath,'utf8'), {document,fetch,JSON,String,Number,Object,Array,Promise}, {timeout:1000});
  async function emit(id,type){for(const cb of node(id).handlers.get(type)||[]) await cb({target:node(id),preventDefault(){}});}
  return {node,calls,emit,setResponse(next){response=next}};
}

test('tool matrix exposes a separate, consented single Kubernetes manifest form', () => {
  assert.match(html, /id="trivy-kubernetes-single-form"/);
  assert.match(html, /id="trivy-kubernetes-single-consent"/);
  assert.match(html, /trivy_kubernetes_single_ui\.js\?v=1/);
  assert.match(html, /Trivy tek Kubernetes manifesti taraması/);
});

test('page load, missing consent, invalid path or filename never triggers a scan', async () => {
  const f=fixture();
  assert.equal(f.calls.length,0);
  f.node('trivy-kubernetes-single-path').value='/home/community-user/synthetic';
  f.node('trivy-kubernetes-single-name').value='pod.yaml';
  await f.emit('trivy-kubernetes-single-form','submit');
  assert.equal(f.calls.length,0);
  f.node('trivy-kubernetes-single-consent').checked=true;
  for (const invalid of ['/', '/home/community-user/../private', '/home//project', '/home\\project']) {
    f.node('trivy-kubernetes-single-path').value=invalid;
    await f.emit('trivy-kubernetes-single-path','input');
    await f.emit('trivy-kubernetes-single-form','submit');
    assert.equal(f.calls.length,0,invalid);
  }
  f.node('trivy-kubernetes-single-path').value='/home/community-user/synthetic';
  for (const invalid of ['../pod.yaml', '/tmp/pod.yaml', '.hidden.yaml', 'pod.yaml/../x.yaml', 'pod.json', 'pod\\x.yaml', 'pod.YAML']) {
    f.node('trivy-kubernetes-single-name').value=invalid;
    await f.emit('trivy-kubernetes-single-name','input');
    await f.emit('trivy-kubernetes-single-form','submit');
    assert.equal(f.calls.length,0,invalid);
  }
  assert.equal(f.node('trivy-kubernetes-single-submit').disabled,true);
});

test('explicit submit sends exact single-file payload and shows changing runtime aggregate', async () => {
  const f=fixture();
  f.node('trivy-kubernetes-single-path').value='/home/community-user/synthetic';
  f.node('trivy-kubernetes-single-name').value='pod.yaml';
  f.node('trivy-kubernetes-single-consent').checked=true;
  await f.emit('trivy-kubernetes-single-consent','change');
  assert.equal(f.node('trivy-kubernetes-single-submit').disabled,false);
  await f.emit('trivy-kubernetes-single-form','submit');
  assert.equal(f.calls.length,1);
  assert.equal(f.calls[0].url,'/api/tool-runs/trivy-kubernetes-config');
  assert.equal(f.calls[0].options.method,'POST');
  assert.deepEqual(JSON.parse(f.calls[0].options.body), {confirm_local:true, project_path:'/home/community-user/synthetic', manifest_name:'pod.yaml'});
  assert.equal(f.node('trivy-kubernetes-single-groups').textContent,'1');
  assert.equal(f.node('trivy-kubernetes-single-total').textContent,'2');
  assert.equal(f.node('trivy-kubernetes-single-hash').textContent,'a'.repeat(64));
  assert.equal(f.node('trivy-kubernetes-single-result').classList.contains('hidden'),false);
  assert.equal(f.node('trivy-kubernetes-single-path').value,'');
  assert.equal(f.node('trivy-kubernetes-single-name').value,'');
  assert.equal(f.node('trivy-kubernetes-single-consent').checked,false);
  f.setResponse({ok:true,json:async()=>validResult(0)});
  f.node('trivy-kubernetes-single-path').value='/home/community-user/synthetic';
  f.node('trivy-kubernetes-single-name').value='deployment.yml';
  f.node('trivy-kubernetes-single-consent').checked=true;
  await f.emit('trivy-kubernetes-single-consent','change');
  await f.emit('trivy-kubernetes-single-form','submit');
  assert.equal(f.calls.length,2);
  assert.equal(f.node('trivy-kubernetes-single-total').textContent,'0');
  assert.equal(JSON.parse(f.calls[1].options.body).manifest_name,'deployment.yml');
});

test('wrong profile, extra private field and malformed response never display raw data', async () => {
  for (const data of [
    {...validResult(), profile:'local-kubernetes-manifest-config-batch-v1'},
    {...validResult(), private_manifest:'secret.yaml'},
    {...validResult(), result_count:2},
  ]) {
    const f=fixture(data);
    f.node('trivy-kubernetes-single-path').value='/home/community-user/private';
    f.node('trivy-kubernetes-single-name').value='pod.yaml';
    f.node('trivy-kubernetes-single-consent').checked=true;
    await f.emit('trivy-kubernetes-single-consent','change');
    await f.emit('trivy-kubernetes-single-form','submit');
    assert.equal(f.calls.length,1);
    assert.equal(f.node('trivy-kubernetes-single-result').classList.contains('hidden'),true);
    assert.equal(f.node('trivy-kubernetes-single-hash').textContent,'');
    assert.doesNotMatch(f.node('trivy-kubernetes-single-error').textContent,/secret\.yaml|\/home\/converserai\/private/i);
  }
});
