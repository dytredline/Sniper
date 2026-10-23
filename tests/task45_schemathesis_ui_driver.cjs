'use strict';

const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');

const [htmlPath, modulePath, baseUrl, report] = process.argv.slice(2);
if (!htmlPath || !modulePath || !baseUrl || !report) throw new Error('four inputs required');
const html = fs.readFileSync(htmlPath, 'utf8');
const moduleSource = fs.readFileSync(modulePath, 'utf8');
const sha256 = text => crypto.createHash('sha256').update(text, 'utf8').digest('hex');
const domTags = new Map();
const tagPattern = /<([a-z][a-z0-9-]*)\b([^>]*)>/gi;
for (const match of html.matchAll(tagPattern)) {
  const id = match[2].match(/\bid="([^"]+)"/i)?.[1];
  if (!id) continue;
  const bare = match[2].replace(/"[^"]*"/g, '""');
  const classes = match[2].match(/\bclass="([^"]*)"/i)?.[1] || '';
  domTags.set(id, {
    tag: match[1].toLowerCase(),
    raw: match[2],
    classes: classes.split(/\s+/).filter(Boolean),
    hidden: /(?:^|\s)hidden(?:\s|$)/i.test(bare),
    disabled: /(?:^|\s)disabled(?:\s|$)/i.test(bare),
    end: match.index + match[0].length,
  });
}
const nodes = new Map();
const submit = { disabled: false };
function getNode(id) {
  if (!domTags.has(id)) return null;
  if (nodes.has(id)) return nodes.get(id);
  const info = domTags.get(id);
  const classNames = new Set(info.classes);
  const item = {
    id,
    value: '',
    files: [],
    textContent: '',
    hidden: info.hidden,
    disabled: info.disabled,
    classList: {
      add(name) { classNames.add(name); },
      remove(name) { classNames.delete(name); },
      contains(name) { return classNames.has(name); },
    },
    querySelector(selector) {
      if (id === 'schemathesis-junit-preview-form' && selector === 'button[type="submit"]') return submit;
      return null;
    },
    closest(selector) { return selector === '#' + id ? this : null; },
  };
  if (id === 'schemathesis-junit-copy-sha256') {
    const buttonText = html.slice(info.end).split('</button>', 1)[0];
    if (buttonText.includes('<') || buttonText.includes('>')) {
      throw new Error('copy button label must be plain text');
    }
    item.textContent = buttonText.trim();
  }
  nodes.set(id, item);
  return item;
}
const listeners = new Map();
const clipboardWrites = [];
const requests = [];
const displayed = getNode('schemathesis-junit-report-sha256');
const previewResult = getNode('schemathesis-junit-preview-result');
const copy = getNode('schemathesis-junit-copy-sha256');
const status = getNode('schemathesis-junit-copy-status');
let denyClipboard = false;
const clipboard = {
  async writeText(text) {
    if (denyClipboard) throw new Error('synthetic clipboard rejection');
    clipboardWrites.push(text);
  },
};
const document = {
  getElementById: getNode,
  defaultView: { navigator: { clipboard } },
  addEventListener(type, callback) {
    if (!listeners.has(type)) listeners.set(type, []);
    listeners.get(type).push(callback);
  },
};
function target(kind) {
  if (kind === 'opener') return {
    id: 'synthetic-saved-report-launcher',
    closest(selector) { return selector.includes('open-schemathesis-junit-preview') ? this : null; },
  };
  if (kind === 'closer') return {
    id: 'synthetic-dialog-close',
    closest(selector) { return selector.includes('data-close=') ? this : null; },
  };
  return getNode(kind);
}
async function dispatch(type, item) {
  for (const callback of listeners.get(type) || []) {
    await callback({ target: item, preventDefault() {} });
  }
}
const context = {
  document,
  navigator: { clipboard },
  window: { navigator: { clipboard } },
  TextEncoder,
  showModal(id, visible) {
    const modal = getNode(id);
    if (!modal) throw new Error('real HTML modal missing');
    modal.hidden = !visible;
    if (visible) modal.classList.remove('hidden');
    else modal.classList.add('hidden');
  },
  async api(route, options) {
    if (route !== '/api/tool-reports/schemathesis-junit/summary' || options?.method !== 'POST') {
      throw new Error('unexpected route or method');
    }
    const body = JSON.parse(options.body);
    if (Object.keys(body).length !== 1 || typeof body.report !== 'string') throw new Error('invalid request shape');
    requests.push({ route, method: options.method, keys: Object.keys(body), reportSha256: sha256(body.report) });
    const response = await fetch(baseUrl + route, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: options.body,
    });
    const data = await response.json();
    if (!response.ok) throw new Error('summary HTTP ' + response.status);
    return data;
  },
};

async function main() {
  vm.runInNewContext(moduleSource, context, { filename: 'schemathesis_junit_preview.js' });
  const initial = { disabled: copy?.disabled ?? null, hidden: copy?.hidden ?? null,
    copyClassHidden: copy?.classList.contains('hidden') ?? null };
  await dispatch('click', target('opener'));
  getNode('schemathesis-junit-paste').value = report;
  await dispatch('submit', getNode('schemathesis-junit-preview-form'));
  const importState = {
    digest: displayed.textContent,
    resultHidden: previewResult.classList.contains('hidden'),
    buttonDisabled: copy?.disabled ?? null,
    buttonHidden: copy?.hidden ?? null,
    buttonLabel: copy?.textContent ?? null,
    requestCount: requests.length,
    suites: getNode('schemathesis-junit-suite-count').textContent,
    cases: getNode('schemathesis-junit-testcase-count').textContent,
    outcomes: getNode('schemathesis-junit-outcomes').textContent,
  };
  if (copy) await dispatch('click', target('schemathesis-junit-copy-sha256'));
  const success = {
    clipboardWrites: [...clipboardWrites],
    status: status?.textContent ?? null,
    requestCount: requests.length,
  };
  denyClipboard = true;
  if (copy) await dispatch('click', target('schemathesis-junit-copy-sha256'));
  const denial = {
    clipboardWrites: [...clipboardWrites],
    status: status?.textContent ?? null,
    digest: displayed.textContent,
    resultHidden: previewResult.classList.contains('hidden'),
    requestCount: requests.length,
  };
  await dispatch('click', target('closer'));
  const closed = {
    disabled: copy?.disabled ?? null,
    hidden: copy?.hidden ?? null,
    status: status?.textContent ?? null,
    digest: displayed.textContent,
  };
  await dispatch('click', target('opener'));
  const reopened = { disabled: copy?.disabled ?? null, hidden: copy?.hidden ?? null,
    status: status?.textContent ?? null, digest: displayed.textContent };
  getNode('schemathesis-junit-paste').value = '<not-junit/>';
  await dispatch('submit', getNode('schemathesis-junit-preview-form'));
  if (copy) await dispatch('click', target('schemathesis-junit-copy-sha256'));
  const invalid = {
    disabled: copy?.disabled ?? null,
    hidden: copy?.hidden ?? null,
    status: status?.textContent ?? null,
    digest: displayed.textContent,
    resultHidden: previewResult.classList.contains('hidden'),
    clipboardWrites: [...clipboardWrites],
    requestCount: requests.length,
  };
  process.stdout.write(JSON.stringify({
    realHtml: {
      copyButtonTag: domTags.get('schemathesis-junit-copy-sha256')?.tag ?? null,
      copyButtonRaw: domTags.get('schemathesis-junit-copy-sha256')?.raw ?? null,
      statusTag: domTags.get('schemathesis-junit-copy-status')?.tag ?? null,
      statusRaw: domTags.get('schemathesis-junit-copy-status')?.raw ?? null,
    },
    initial, importState, success, denial, closed, reopened, invalid, requests,
  }));
}
main().catch(error => { console.error(String(error?.message || error)); process.exitCode = 1; });
