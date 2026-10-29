import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import vm from 'node:vm';

const root = new URL('../', import.meta.url).pathname;
const htmlPath = process.env.SNIPER_IMAGE_UI_HTML || root + 'static/index.html';
const jsPath = process.env.SNIPER_IMAGE_UI_JS || root + 'static/trivy_image_archive_ui.js';
const html = fs.readFileSync(htmlPath, 'utf8');
const validResult = () => ({
  format: 'trivy-native-json', schema_version: 2, profile: 'local-image-archive-offline-v1',
  result_count: 1,
  class_counts: {'os-pkgs':1, 'lang-pkgs':0, config:0, secret:0, license:0, 'license-file':0, crypto:0, custom:0, unknown:0},
  vuln_counts: {critical:0, high:1, medium:1, low:0, unknown:0},
  misconfig_sev_counts: {critical:0, high:0, medium:0, low:0, unknown:0},
  finding_counts: {vulnerabilities:2, misconfigurations:0, secrets:0, licenses:0},
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
      classList: {
        add(key){classes.add(key)}, remove(key){classes.delete(key)},
        contains(key){return classes.has(key)}
      },
      addEventListener(type, callback) {handlers.set(type,[...(handlers.get(type)||[]),callback]);},
    };
    nodes.set(id,item); return item;
  }
  const document = {getElementById:node};
  const fetch = async (path, options={}) => {calls.push({path,options}); return response;};
  vm.runInNewContext(fs.readFileSync(jsPath,'utf8'), {document,fetch,JSON,String,Number,Object,Array,Promise}, {timeout:1000});
  async function emit(id,type){for(const cb of node(id).handlers.get(type)||[]) await cb({target:node(id),preventDefault(){}});}
  return {node,calls,emit,setResponse(next){response=next}};
}

test('tool matrix offers a distinct local image archive scan with explicit consent', () => {
  assert.match(html, /id="trivy-image-archive-form"/);
  assert.match(html, /id="trivy-image-archive-consent"/);
  assert.match(html, /trivy_image_archive_ui\.js\?v=1/);
  assert.match(html, /çevrimdışı imaj arşivi/);
});

test('opening the page and invalid or unconsented inputs never start an image scan', async () => {
  const f=fixture();
  assert.equal(f.calls.length,0);
  f.node('trivy-image-archive-path').value='/home/community-user/synthetic';
  f.node('trivy-image-archive-name').value='image.tar';
  await f.emit('trivy-image-archive-path','input');
  await f.emit('trivy-image-archive-name','input');
  await f.emit('trivy-image-archive-form','submit');
  assert.equal(f.calls.length,0);
  f.node('trivy-image-archive-consent').checked=true;
  for(const invalid of ['../image.tar','folder/image.tar','image.zip','x\\image.tar']) {
    f.node('trivy-image-archive-name').value=invalid;
    await f.emit('trivy-image-archive-name','input');
    await f.emit('trivy-image-archive-form','submit');
    assert.equal(f.calls.length,0,invalid);
  }
  assert.equal(f.node('trivy-image-archive-submit').disabled,true);
});

test('one consented submit sends the exact endpoint payload and renders aggregate runtime result', async () => {
  const f=fixture();
  f.node('trivy-image-archive-path').value='/home/community-user/synthetic';
  f.node('trivy-image-archive-name').value='image.tar';
  f.node('trivy-image-archive-consent').checked=true;
  await f.emit('trivy-image-archive-consent','change');
  assert.equal(f.node('trivy-image-archive-submit').disabled,false);
  await f.emit('trivy-image-archive-form','submit');
  assert.equal(f.calls.length,1);
  assert.equal(f.calls[0].path,'/api/tool-runs/trivy-image-archive-vulnerability');
  assert.equal(f.calls[0].options.method,'POST');
  assert.deepEqual(JSON.parse(f.calls[0].options.body), {confirm_local:true,project_path:'/home/community-user/synthetic',archive_name:'image.tar'});
  assert.equal(f.node('trivy-image-archive-groups').textContent,'1');
  assert.equal(f.node('trivy-image-archive-total').textContent,'2');
  assert.equal(f.node('trivy-image-archive-severity').textContent,'critical:0 high:1 medium:1 low:0 unknown:0');
  assert.equal(f.node('trivy-image-archive-hash').textContent,'a'.repeat(64));
  assert.equal(f.node('trivy-image-archive-result').classList.contains('hidden'),false);
  assert.equal(f.node('trivy-image-archive-path').value,'');
  assert.equal(f.node('trivy-image-archive-name').value,'');
  assert.equal(f.node('trivy-image-archive-consent').checked,false);
});

test('malformed or private result is rejected without displaying raw data', async () => {
  const f=fixture();
  f.setResponse({ok:true,json:async()=>({...validResult(),raw_private_marker:'CVE-PRIVATE'})});
  f.node('trivy-image-archive-path').value='/home/community-user/private';
  f.node('trivy-image-archive-name').value='secret.tar';
  f.node('trivy-image-archive-consent').checked=true;
  await f.emit('trivy-image-archive-consent','change');
  await f.emit('trivy-image-archive-form','submit');
  assert.equal(f.node('trivy-image-archive-result').classList.contains('hidden'),true);
  assert.equal(f.node('trivy-image-archive-hash').textContent,'');
  assert.doesNotMatch(f.node('trivy-image-archive-error').textContent,/CVE-PRIVATE|private|secret\.tar/i);
});
