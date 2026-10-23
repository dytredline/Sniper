import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createServer} from 'node:http';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

// Synthetic loopback response, matching the Trivy summary contract. No scanner or external target.
const jsPath = process.env.SNIPER_TASK66_UI_JS || new URL('../static/trivy_image_archive_ui.js', import.meta.url).pathname;
const validSummary = () => ({
  format: 'trivy-native-json', schema_version: 2, profile: 'local-image-archive-offline-v1',
  result_count: 1,
  class_counts: {'os-pkgs': 1, 'lang-pkgs': 0, config: 0, secret: 0, license: 0,
    'license-file': 0, crypto: 0, custom: 0, unknown: 0},
  vuln_counts: {critical: 0, high: 1, medium: 0, low: 0, unknown: 0},
  misconfig_sev_counts: {critical: 0, high: 1, medium: 0, low: 0, unknown: 0},
  finding_counts: {vulnerabilities: 1, misconfigurations: 1, secrets: 0, licenses: 0},
  report_sha256: 'b'.repeat(64),
});

function mount(fetch) {
  const nodes = new Map();
  function node(id) {
    if (nodes.has(id)) return nodes.get(id);
    const handlers = new Map();
    const classes = new Set(['hidden']);
    const item = {
      id, value: '', checked: false, disabled: false, textContent: '', handlers,
      classList: {
        add(key) { classes.add(key); },
        remove(key) { classes.delete(key); },
        contains(key) { return classes.has(key); },
      },
      addEventListener(type, callback) { handlers.set(type, [...(handlers.get(type) || []), callback]); },
    };
    nodes.set(id, item);
    return item;
  }
  const document = {getElementById: node};
  vm.runInNewContext(readFileSync(jsPath, 'utf8'), {document, fetch, JSON, String, Number, Object, Array, Promise}, {timeout: 1000});
  async function emit(id, type) {
    for (const callback of node(id).handlers.get(type) || []) {
      await callback({target: node(id), preventDefault() {}});
    }
  }
  return {node, emit};
}

test('Trivy image UI accepts exact nine-key HTTP 200 summary and rejects malformed counts and extra fields', async () => {
  let nextSummary = validSummary();
  const requests = [];
  const server = createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    requests.push({method: request.method, path: request.url, body: JSON.parse(body)});
    response.writeHead(200, {'Content-Type': 'application/json'});
    response.end(JSON.stringify(nextSummary));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const fetchLoopback = (path, options) => fetch(`http://127.0.0.1:${address.port}${path}`, options);
  async function submit() {
    const ui = mount(fetchLoopback);
    ui.node('trivy-image-archive-path').value = '/synthetic/project';
    ui.node('trivy-image-archive-name').value = 'image.tar';
    ui.node('trivy-image-archive-consent').checked = true;
    await ui.emit('trivy-image-archive-consent', 'change');
    await ui.emit('trivy-image-archive-form', 'submit');
    return ui;
  }
  try {
    const accepted = await submit();
    assert.equal(accepted.node('trivy-image-archive-result').classList.contains('hidden'), false);
    assert.equal(accepted.node('trivy-image-archive-total').textContent, '1');
    assert.equal(accepted.node('trivy-image-archive-hash').textContent, 'b'.repeat(64));
    assert.equal(requests[0].method, 'POST');
    assert.equal(requests[0].path, '/api/tool-runs/trivy-image-archive-vulnerability');
    assert.deepEqual(requests[0].body, {
      confirm_local: true, project_path: '/synthetic/project', archive_name: 'image.tar',
    });
    nextSummary = {...validSummary(), extra_private: 'do-not-display'};
    const extra = await submit();
    assert.equal(extra.node('trivy-image-archive-result').classList.contains('hidden'), true);
    assert.equal(extra.node('trivy-image-archive-hash').textContent, '');
    assert.doesNotMatch(extra.node('trivy-image-archive-error').textContent, /do-not-display/);
    nextSummary = {...validSummary(), misconfig_sev_counts: {critical: 0, high: 2, medium: 0, low: 0, unknown: 0}};
    const wrongTotal = await submit();
    assert.equal(wrongTotal.node('trivy-image-archive-result').classList.contains('hidden'), true);
    nextSummary = {...validSummary(), misconfig_sev_counts: {critical: 0, high: 1, medium: 0, low: 0}};
    const missingBucket = await submit();
    assert.equal(missingBucket.node('trivy-image-archive-result').classList.contains('hidden'), true);
    assert.equal(requests.length, 4);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
