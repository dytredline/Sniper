import assert from 'node:assert/strict';
import {test} from 'node:test';
import fs from 'node:fs';
import vm from 'node:vm';

const root = new URL('../', import.meta.url).pathname;
const htmlPath = process.env.SNIPER_TERRAFORM_UI_HTML || root + 'static/index.html';
const jsPath = process.env.SNIPER_TERRAFORM_UI_JS || root + 'static/trivy_terraform_config_ui.js';
const html = fs.readFileSync(htmlPath, 'utf8');
const validResult = (count = 2, groups = 2) => ({
  format: 'trivy-native-json', schema_version: 2, profile: 'local-terraform-config-v1', result_count: groups,
  class_counts: {'os-pkgs':0, 'lang-pkgs':0, config:groups, secret:0, license:0, 'license-file':0, crypto:0, custom:0, unknown:0},
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

test('tool matrix exposes a separate consented local Terraform scan', () => {
  assert.match(html, /id="trivy-terraform-config-form"/);
  assert.match(html, /id="trivy-terraform-config-consent"/);
  assert.match(html, /trivy_terraform_config_ui\.js\?v=1/);
  assert.match(html, /Trivy Terraform yapılandırma taraması/);
});

test('page load, missing consent, invalid paths and filenames never call the API', async () => {
  const f=fixture();
  assert.equal(f.calls.length,0);
  f.node('trivy-terraform-config-path').value='/home/community-user/synthetic';
  f.node('trivy-terraform-config-file').value='main.tf';
  await f.emit('trivy-terraform-config-path','input');
  await f.emit('trivy-terraform-config-form','submit');
  assert.equal(f.calls.length,0);
  f.node('trivy-terraform-config-consent').checked=true;
  for (const invalid of ['/', '/home/community-user/../private', '/home//project', '/home\\project']) {
    f.node('trivy-terraform-config-path').value=invalid;
    await f.emit('trivy-terraform-config-path','input');
    await f.emit('trivy-terraform-config-form','submit');
    assert.equal(f.calls.length,0,invalid);
  }
  f.node('trivy-terraform-config-path').value='/home/community-user/synthetic';
  for (const invalid of ['../main.tf', '/tmp/main.tf', '.hidden.tf', 'main.tf/../x.tf', 'main.json', 'main\\x.tf']) {
    f.node('trivy-terraform-config-file').value=invalid;
    await f.emit('trivy-terraform-config-file','input');
    await f.emit('trivy-terraform-config-form','submit');
    assert.equal(f.calls.length,0,invalid);
  }
  assert.equal(f.node('trivy-terraform-config-submit').disabled,true);
});

test('explicit submit calls the exact API and shows changing aggregate runtime results', async () => {
  const f=fixture();
  f.node('trivy-terraform-config-path').value='/home/community-user/synthetic';
  f.node('trivy-terraform-config-file').value='main.tf';
  f.node('trivy-terraform-config-consent').checked=true;
  await f.emit('trivy-terraform-config-consent','change');
  assert.equal(f.node('trivy-terraform-config-submit').disabled,false);
  await f.emit('trivy-terraform-config-form','submit');
  assert.equal(f.calls.length,1);
  assert.equal(f.calls[0].url,'/api/tool-runs/trivy-terraform-config');
  assert.equal(f.calls[0].options.method,'POST');
  assert.deepEqual(JSON.parse(f.calls[0].options.body), {confirm_local:true, project_path:'/home/community-user/synthetic', terraform_file:'main.tf'});
  assert.equal(f.node('trivy-terraform-config-groups').textContent,'2');
  assert.equal(f.node('trivy-terraform-config-total').textContent,'2');
  assert.equal(f.node('trivy-terraform-config-hash').textContent,'a'.repeat(64));
  assert.equal(f.node('trivy-terraform-config-result').classList.contains('hidden'),false);
  assert.equal(f.node('trivy-terraform-config-path').value,'');
  assert.equal(f.node('trivy-terraform-config-file').value,'');
  assert.equal(f.node('trivy-terraform-config-consent').checked,false);
  f.setResponse({ok:true,json:async()=>validResult(0,1)});
  f.node('trivy-terraform-config-path').value='/home/community-user/synthetic';
  f.node('trivy-terraform-config-file').value='main.tf';
  f.node('trivy-terraform-config-consent').checked=true;
  await f.emit('trivy-terraform-config-consent','change');
  await f.emit('trivy-terraform-config-form','submit');
  assert.equal(f.calls.length,2);
  assert.equal(f.node('trivy-terraform-config-groups').textContent,'1');
  assert.equal(f.node('trivy-terraform-config-total').textContent,'0');
});

test('malformed or private response is rejected without displaying raw data', async () => {
  const f=fixture();
  f.setResponse({ok:true,json:async()=>({...validResult(),private_file:'secret.Terraform'})});
  f.node('trivy-terraform-config-path').value='/home/community-user/private';
  f.node('trivy-terraform-config-file').value='main.tf';
  f.node('trivy-terraform-config-consent').checked=true;
  await f.emit('trivy-terraform-config-consent','change');
  await f.emit('trivy-terraform-config-form','submit');
  assert.equal(f.calls.length,1);
  assert.equal(f.node('trivy-terraform-config-result').classList.contains('hidden'),true);
  assert.equal(f.node('trivy-terraform-config-hash').textContent,'');
  assert.doesNotMatch(f.node('trivy-terraform-config-error').textContent,/secret\.Terraform|\/home\/converserai\/private/i);
});
