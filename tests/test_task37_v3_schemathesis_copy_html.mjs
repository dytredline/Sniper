import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const ownRoot = resolve(fileURLToPath(new URL('../', import.meta.url)));
const appRoot = process.env.SNIPER_TEST_APP_ROOT || ownRoot;
const html = readFileSync(join(appRoot, 'static/index.html'), 'utf8');
const script = readFileSync(join(appRoot, 'static/schemathesis_junit_preview.js'), 'utf8');

function openingTag(tag, id) {
  const match = html.match(new RegExp(`<${tag}\\b[^>]*\\bid="${id}"[^>]*>`, 'i'));
  return match?.[0] || '';
}
function hasId(id) { return html.includes(`id="${id}"`); }
function node(id) {
  const classes = new Set(['schemathesis-junit-preview-result', 'schemathesis-junit-preview-error',
    'schemathesis-junit-copy-sha256', 'schemathesis-junit-copy-status'].includes(id) ? ['hidden'] : []);
  return {
    id, value: '', files: [], textContent: '', hidden: true, disabled: true,
    classList: {
      add(name) { classes.add(name); },
      remove(name) { classes.delete(name); },
      contains(name) { return classes.has(name); },
    },
  };
}

test('saved JUnit preview exposes a distinct accessible digest control that copies only the visible valid result', async () => {
  const buttonTag = openingTag('button', 'schemathesis-junit-copy-sha256');
  const statusTag = openingTag('output', 'schemathesis-junit-copy-status');
  assert.ok(buttonTag, 'the rendered HTML must contain a real digest copy button');
  assert.match(buttonTag, /\btype="button"/);
  assert.match(buttonTag, /\bdisabled(?:\s|>|=)/);
  assert.match(buttonTag, /\bhidden(?:\s|>|=)/);
  assert.match(buttonTag, /\baria-describedby="schemathesis-junit-report-sha256 schemathesis-junit-copy-status"/);
  assert.ok(statusTag, 'the rendered HTML must contain a real copy status output');
  assert.match(statusTag, /\brole="status"/);
  assert.match(statusTag, /\baria-live="polite"/);
  assert.match(statusTag, /\bhidden(?:\s|>|=)/);
  assert.equal(html.split('id="schemathesis-junit-copy-sha256"').length - 1, 1);
  assert.equal(html.split('id="schemathesis-junit-copy-status"').length - 1, 1);

  const ids = [
    'schemathesis-junit-preview-form', 'schemathesis-junit-paste', 'schemathesis-junit-file',
    'schemathesis-junit-preview-error', 'schemathesis-junit-preview-result',
    'schemathesis-junit-copy-sha256', 'schemathesis-junit-copy-status',
    'schemathesis-junit-suite-count', 'schemathesis-junit-testcase-count',
    'schemathesis-junit-outcomes', 'schemathesis-junit-report-sha256',
  ];
  const nodes = Object.fromEntries(ids.filter(hasId).map(id => [id, node(id)]));
  const submitButton = node('submit');
  const form = nodes['schemathesis-junit-preview-form'];
  assert.ok(form);
  form.querySelector = selector => selector === 'button[type="submit"]' ? submitButton : null;
  const handlers = {};
  const writes = [];
  const shown = [];
  const digest = 'a'.repeat(64);
  let reportCalls = 0;
  const clipboard = { async writeText(text) { writes.push(text); } };
  const document = {
    getElementById(id) { return nodes[id] || null; },
    addEventListener(type, listener) { handlers[type] = listener; },
    defaultView: { navigator: { clipboard } },
  };
  const context = {
    document, navigator: { clipboard }, window: { navigator: { clipboard } }, TextEncoder,
    showModal(id, visible) { shown.push([id, visible]); },
    async api(route, options) {
      reportCalls += 1;
      assert.equal(route, '/api/tool-reports/schemathesis-junit/summary');
      assert.equal(options.method, 'POST');
      assert.deepEqual(JSON.parse(options.body), { report: '<testsuite><testcase/></testsuite>' });
      return { format: 'schemathesis-junit-xml', suite_count: 1, testcase_count: 1,
        outcome_counts: { passed: 1, failed: 0, errors: 0, skipped: 0 }, report_sha256: digest };
    },
  };
  vm.runInNewContext(script, context, { filename: 'schemathesis_junit_preview.js' });
  const copy = nodes['schemathesis-junit-copy-sha256'];
  assert.equal(copy.disabled, true);
  assert.equal(copy.hidden, true);
  const copyClick = () => handlers.click({ target: { id: copy.id, closest() { return null; } }, preventDefault() {} });
  await copyClick();
  assert.deepEqual(writes, [], 'copy before a valid response must not write to the clipboard');

  handlers.click({
    target: { closest(selector) { return selector.includes('open-schemathesis-junit-preview') ? {} : null; } },
    preventDefault() {},
  });
  nodes['schemathesis-junit-paste'].value = '<testsuite><testcase/></testsuite>';
  await handlers.submit({ target: form, preventDefault() {} });
  assert.equal(reportCalls, 1);
  assert.deepEqual(shown, [['schemathesis-junit-preview-modal', true]]);
  assert.equal(nodes['schemathesis-junit-report-sha256'].textContent, digest);
  assert.equal(copy.disabled, false);
  assert.equal(copy.hidden, false);
  assert.equal(copy.classList.contains('hidden'), false);
  await copyClick();
  assert.deepEqual(writes, [digest], 'one deliberate click must copy exactly the visible digest once');
  assert.match(nodes['schemathesis-junit-copy-status'].textContent, /panoya kopyalandı/);
  assert.equal(nodes['schemathesis-junit-copy-status'].hidden, false);

  nodes['schemathesis-junit-report-sha256'].textContent = 'b'.repeat(64);
  await copyClick();
  assert.deepEqual(writes, [digest], 'a changed displayed digest must never be copied as the earlier response');
  assert.match(nodes['schemathesis-junit-copy-status'].textContent, /kopyalanamadı/);
  assert.equal(reportCalls, 1, 'copy is passive and must not launch or repeat a report request');
});
