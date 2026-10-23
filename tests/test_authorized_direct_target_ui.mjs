import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const appPath = new URL('../static/app.js', import.meta.url).pathname;
const htmlPath = new URL('../static/index.html', import.meta.url).pathname;
const app = fs.readFileSync(appPath, 'utf8');
const section = app.slice(
  app.indexOf('// Direct operator targets:'),
  app.indexOf('// Nuclei HTTP: explicit, authorized broad catalog'),
);

function fixture() {
  const nodes = new Map();
  const requests = [];
  function node(id) {
    if (!nodes.has(id)) {
      const classes = new Set(['hidden']);
      nodes.set(id, {
        value: '', checked: false, disabled: false, textContent: '',
        classList: {
          add(value) { classes.add(value); },
          remove(value) { classes.delete(value); },
          contains(value) { return classes.has(value); },
        },
        handlers: new Map(),
        addEventListener(name, fn) { this.handlers.set(name, fn); },
      });
    }
    return nodes.get(id);
  }
  const document = {
    addEventListener() {},
    querySelector(selector) { return node(selector.slice(1)); },
  };
  async function api(path, options = {}) {
    requests.push({ path, body: options.body ? JSON.parse(options.body) : null });
    if (path === '/api/nmap/authorized-target-scan') return {
      profile: 'authorized-default-v1', open_port_count: 1, open_ports: [8080],
      report_sha256: 'a'.repeat(64),
      authorization_receipt: {
        consent_version: 'direct-target-authorization-v1', confirm_authorized: true,
        confirmed_at: '2026-10-22T12:00:00+00:00',
      },
    };
    if (path === '/api/nuclei/authorized-origin-scans') return {
      job_id: '0123456789abcdef', state: 'starting', profile: 'authorized-origin-fixed-http-v1',
      authorization_receipt: { consent_version: 'direct-target-authorization-v1', confirmed_at: '2026-10-22T12:00:00+00:00' },
    };
    return { job_id: '0123456789abcdef', state: 'running' };
  }
  const context = vm.createContext({
    document, api, showModal() {}, console, Number, encodeURIComponent,
    $: selector => node(selector.slice(1)),
    setTimeout: () => 0, clearTimeout() {},
  });
  vm.runInContext(section, context);
  return { node, requests };
}

async function submit(form) {
  await form.handlers.get('submit')({ preventDefault() {} });
  await new Promise(resolve => setImmediate(resolve));
}

test('direct target controls are present and state that each run needs authorization', () => {
  const html = fs.readFileSync(htmlPath, 'utf8');
  for (const id of [
    'direct-nmap-scan-modal', 'direct-nmap-scan-form', 'direct-nmap-target', 'direct-nmap-profile',
    'direct-nmap-confirm-authorized', 'direct-nuclei-scan-modal', 'direct-nuclei-scan-form',
    'direct-nuclei-origin', 'direct-nuclei-confirm-authorized', 'direct-nuclei-cancel',
  ]) assert.match(html, new RegExp(`id=["']${id}["']`));
  assert.match(html, /HER ÇALIŞTIRMADA İNSAN ONAYI/g);
});

test('direct Nmap UI sends only target, fixed profile and exact consent', async () => {
  const f = fixture();
  f.node('direct-nmap-target').value = 'example.test';
  f.node('direct-nmap-profile').value = 'default';
  f.node('direct-nmap-confirm-authorized').checked = true;
  await submit(f.node('direct-nmap-scan-form'));
  assert.deepEqual(f.requests[0], {
    path: '/api/nmap/authorized-target-scan',
    body: { target: 'example.test', profile: 'default', confirm_authorized: true },
  });
  assert.equal(f.node('direct-nmap-confirm-authorized').checked, false);
});

test('direct Nuclei UI sends only origin and exact consent', async () => {
  const f = fixture();
  f.node('direct-nuclei-origin').value = 'https://example.test';
  f.node('direct-nuclei-confirm-authorized').checked = true;
  await submit(f.node('direct-nuclei-scan-form'));
  assert.deepEqual(f.requests[0], {
    path: '/api/nuclei/authorized-origin-scans',
    body: { target_origin: 'https://example.test', confirm_authorized: true },
  });
  assert.equal(f.node('direct-nuclei-confirm-authorized').checked, false);
});

test('editing a direct target revokes the earlier checkbox consent', async () => {
  const f = fixture();
  f.node('direct-nmap-target').value = 'first.example';
  f.node('direct-nmap-profile').value = 'default';
  f.node('direct-nmap-confirm-authorized').checked = true;
  f.node('direct-nmap-target').value = 'second.example';
  f.node('direct-nmap-target').handlers.get('input')();
  await submit(f.node('direct-nmap-scan-form'));
  assert.equal(f.node('direct-nmap-confirm-authorized').checked, false);
  assert.equal(f.requests.length, 0);
});
