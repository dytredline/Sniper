import assert from 'node:assert/strict';
import {test} from 'node:test';
import fs from 'node:fs';
import vm from 'node:vm';

const root = new URL('../', import.meta.url).pathname;
const htmlPath = process.env.SNIPER_DOCKERFILE_UI_HTML || root + 'static/index.html';
const jsPath = process.env.SNIPER_DOCKERFILE_UI_JS || root + 'static/trivy_dockerfile_config_ui.js';
const html = fs.readFileSync(htmlPath, 'utf8');
const validResult = (count = 2) => ({
  format: 'trivy-native-json', schema_version: 2, profile: 'local-dockerfile-config-v1', result_count: 1,
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

test('tool matrix exposes a separate consented local Dockerfile scan', () => {
  assert.match(html, /id="trivy-dockerfile-config-form"/);
  assert.match(html, /id="trivy-dockerfile-config-consent"/);
  assert.match(html, /trivy_dockerfile_config_ui\.js\?v=1/);
  assert.match(html, /Trivy Dockerfile yapılandırma taraması/);
});

test('page load, missing consent, and invalid local paths never call the API', async () => {
  const f=fixture();
  assert.equal(f.calls.length,0);
  f.node('trivy-dockerfile-config-path').value='/home/community-user/synthetic';
  await f.emit('trivy-dockerfile-config-path','input');
  await f.emit('trivy-dockerfile-config-form','submit');
  assert.equal(f.calls.length,0);
  f.node('trivy-dockerfile-config-consent').checked=true;
  for (const invalid of ['/', '/home/community-user/../private', '/home//project', '/home\\project']) {
    f.node('trivy-dockerfile-config-path').value=invalid;
    await f.emit('trivy-dockerfile-config-path','input');
    await f.emit('trivy-dockerfile-config-form','submit');
    assert.equal(f.calls.length,0,invalid);
  }
  assert.equal(f.node('trivy-dockerfile-config-submit').disabled,true);
});

test('explicit submit calls the exact API and shows changing aggregate runtime results', async () => {
  const f=fixture();
  f.node('trivy-dockerfile-config-path').value='/home/community-user/synthetic';
  f.node('trivy-dockerfile-config-consent').checked=true;
  await f.emit('trivy-dockerfile-config-consent','change');
  assert.equal(f.node('trivy-dockerfile-config-submit').disabled,false);
  await f.emit('trivy-dockerfile-config-form','submit');
  assert.equal(f.calls.length,1);
  assert.equal(f.calls[0].url,'/api/tool-runs/trivy-dockerfile-config');
  assert.equal(f.calls[0].options.method,'POST');
  assert.deepEqual(JSON.parse(f.calls[0].options.body), {confirm_local:true, project_path:'/home/community-user/synthetic'});
  assert.equal(f.node('trivy-dockerfile-config-groups').textContent,'1');
  assert.equal(f.node('trivy-dockerfile-config-total').textContent,'2');
  assert.equal(f.node('trivy-dockerfile-config-hash').textContent,'a'.repeat(64));
  assert.equal(f.node('trivy-dockerfile-config-result').classList.contains('hidden'),false);
  assert.equal(f.node('trivy-dockerfile-config-path').value,'');
  assert.equal(f.node('trivy-dockerfile-config-consent').checked,false);
  f.setResponse({ok:true,json:async()=>validResult(0)});
  f.node('trivy-dockerfile-config-path').value='/home/community-user/synthetic';
  f.node('trivy-dockerfile-config-consent').checked=true;
  await f.emit('trivy-dockerfile-config-consent','change');
  await f.emit('trivy-dockerfile-config-form','submit');
  assert.equal(f.calls.length,2);
  assert.equal(f.node('trivy-dockerfile-config-total').textContent,'0');
});

test('malformed or private response is rejected without displaying raw data', async () => {
  const f=fixture();
  f.setResponse({ok:true,json:async()=>({...validResult(),private_file:'secret.Dockerfile'})});
  f.node('trivy-dockerfile-config-path').value='/home/community-user/private';
  f.node('trivy-dockerfile-config-consent').checked=true;
  await f.emit('trivy-dockerfile-config-consent','change');
  await f.emit('trivy-dockerfile-config-form','submit');
  assert.equal(f.calls.length,1);
  assert.equal(f.node('trivy-dockerfile-config-result').classList.contains('hidden'),true);
  assert.equal(f.node('trivy-dockerfile-config-hash').textContent,'');
  assert.doesNotMatch(f.node('trivy-dockerfile-config-error').textContent,/secret\.Dockerfile|\/home\/converserai\/private/i);
});
