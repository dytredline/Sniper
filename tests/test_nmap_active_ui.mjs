import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const app = fs.readFileSync(process.env.SNIPER_NMAP_UI_JS || new URL('../static/app.js', import.meta.url), 'utf8');
const modal = app.slice(app.indexOf('function openNmapScan(target) {'), app.indexOf('async function openTrend('));
const handler = app.slice(app.indexOf('let nmapScanBusy = false;'), app.indexOf('$("#target-search").addEventListener('));
assert.ok(modal.startsWith('function openNmapScan(target) {'));
assert.ok(handler.startsWith('let nmapScanBusy = false;'));

function fixture(response = { open_port_count: 1, open_ports: [42424] }) {
  const nodes = new Map();
  const requests = [];
  const target = { id: 'target-1', hostname: 'example.test' };
  const engagement = {
    id: 'engagement-1', target_id: target.id, name: 'Authorized', status: 'active',
    authorization_ref: 'AUTH-1', scope_notes: 'TCP ports in scope',
  };
  function node(id) {
    if (!nodes.has(id)) {
      const classes = new Set(['hidden']);
      nodes.set(id, {
        value: '', textContent: '', checked: false, disabled: false, options: [],
        classList: {
          add(name) { classes.add(name); },
          toggle(name, force) { if (force) classes.add(name); else classes.delete(name); },
          contains(name) { return classes.has(name); },
        },
        replaceChildren() { this.options = []; },
        appendChild(child) { this.options.push(child); },
        addEventListener(name, fn) { this[name] = fn; },
      });
    }
    return nodes.get(id);
  }
  const document = {
    getElementById: node,
    createElement: () => ({ value: '', textContent: '', disabled: false, selected: false }),
  };
  const state = { selectedTarget: null, engagements: [engagement] };
  const context = vm.createContext({
    document, state, console, Number, Set,
    $: selector => node(selector.slice(1)),
    showModal() {}, toast() {},
    async api(path, options) { requests.push({ path, body: JSON.parse(options.body) }); return response; },
  });
  vm.runInContext(modal + '\n' + handler, context);
  vm.runInContext('openNmapScan(state.engagements[0].target_id === "target-1" ? {id:"target-1",hostname:"example.test"} : null)', context);
  node('nmap-engagement-select').value = engagement.id;
  node('nmap-confirm-authorized').checked = true;
  node('nmap-confirm-authorized').change();
  return {
    node, requests,
    setPorts(value) { node('nmap-ports').value = value; node('nmap-ports').input(); },
    confirm() { node('nmap-confirm-authorized').checked = true; node('nmap-confirm-authorized').change(); },
    ready() { node('nmap-engagement-select').change(); return !node('nmap-start-button').disabled; },
    async submit() { await node('nmap-start-button').click(); },
  };
}

test('blank port field retains the existing bounded profile request', async () => {
  const f = fixture({ open_port_count: 1, open_ports: [80] });
  assert.equal(f.ready(), true);
  await f.submit();
  assert.deepEqual(f.requests, [{ path: '/api/nmap/tcp-scan', body: {
    target_id: 'target-1', engagement_id: 'engagement-1', confirm_authorized: true,
  } }]);
  assert.match(f.node('nmap-result').textContent, /Portlar: \[80\]/);
});

test('valid custom ports are sorted and passed to the API', async () => {
  const f = fixture();
  f.setPorts('42424, 80');
  f.confirm();
  assert.equal(f.ready(), true);
  await f.submit();
  assert.deepEqual(f.requests[0].body.ports, [80, 42424]);
  assert.match(f.node('nmap-result').textContent, /Portlar: \[42424\]/);
});

test('invalid custom port selections cannot start a scan', async () => {
  for (const ports of ['80,80', '0', '65536', '80,', 'a', Array.from({ length: 65 }, (_, i) => i + 1).join(',')]) {
    const f = fixture();
    f.setPorts(ports);
    assert.equal(f.ready(), false, ports);
    await f.submit();
    assert.equal(f.requests.length, 0, ports);
    assert.equal(f.node('nmap-ports-error').classList.contains('hidden'), false);
  }
});

test('a port outside the requested set is not shown', async () => {
  const f = fixture({ open_port_count: 1, open_ports: [22] });
  f.setPorts('42424');
  f.confirm();
  await f.submit();
  assert.equal(f.requests.length, 1);
  assert.equal(f.node('nmap-result').textContent.includes('22'), false);
  assert.match(f.node('nmap-result').textContent, /Tarama başarısız/);
});
