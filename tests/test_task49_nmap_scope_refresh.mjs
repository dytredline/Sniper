import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const sourcePath = process.env.SNIPER_NMAP_UI_JS || new URL('../static/app.js', import.meta.url);
const source = fs.readFileSync(sourcePath, 'utf8');
const openStart = source.indexOf('function openNmapScan(target) {');
const openEnd = source.indexOf('async function openTrend(', openStart);
const handlerStart = source.indexOf('let nmapScanBusy = false;');
const handlerEnd = source.indexOf('$("#target-search").addEventListener(', handlerStart);
assert.ok(openStart >= 0 && openEnd > openStart && handlerStart >= 0 && handlerEnd > handlerStart);
const runnable = source.slice(openStart, openEnd) + '\n' + source.slice(handlerStart, handlerEnd);
const defaultPorts = [21,22,25,53,80,110,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,6379,8080,8443,9200,27017];

function fixture() {
  const nodes = new Map();
  const calls = [];
  const target = { id: 'target-a', hostname: 'scope.example.test' };
  const engagementA = { id: 'eng-a', target_id: target.id, name: 'A', status: 'active',
    authorization_ref: 'AUTH-A', scope_notes: 'Synthetic TCP scope' };
  const engagementB = { ...engagementA, id: 'eng-b', name: 'B' };
  const classes = () => {
    const set = new Set(['hidden']);
    return { add: name => set.add(name), toggle(name, force) { if (force) set.add(name); else set.delete(name); },
      contains: name => set.has(name) };
  };
  function node(id) {
    if (!nodes.has(id)) nodes.set(id, {
      value: '', textContent: '', checked: false, disabled: false, options: [], classList: classes(),
      replaceChildren() { this.options = []; },
      appendChild(option) { this.options.push(option); },
      addEventListener(kind, handler) { this[kind] = handler; },
    });
    return nodes.get(id);
  }
  const state = { selectedTarget: null, engagements: [engagementA, engagementB] };
  const context = vm.createContext({
    document: { getElementById: node, createElement: () => ({ value: '', textContent: '', disabled: false, selected: false }) },
    state, Number, Set, JSON,
    $: selector => node(selector.slice(1)),
    showModal() {}, toast() {},
    async api(path, options) {
      calls.push({ path, body: JSON.parse(options.body) });
      return { open_port_count: 0, open_ports: [] };
    },
  });
  vm.runInContext(runnable, context);
  vm.runInContext('openNmapScan(state.engagements[0] && { id: "target-a", hostname: "scope.example.test" })', context);
  node('nmap-engagement-select').value = 'eng-a';
  function selectEngagement(value, emit = true) {
    node('nmap-engagement-select').value = value;
    if (emit) node('nmap-engagement-select').change();
  }
  function ports(value, emit = true) {
    node('nmap-ports').value = value;
    if (emit) node('nmap-ports').input();
  }
  function confirm() {
    node('nmap-confirm-authorized').checked = true;
    node('nmap-confirm-authorized').change();
  }
  async function submit() { await node('nmap-start-button').click(); }
  return { node, calls, target, context, confirm, selectEngagement, ports, submit };
}

test('confirmed valid port edit clears consent and does not send request', async () => {
  const f = fixture();
  f.confirm();
  assert.equal(f.node('nmap-start-button').disabled, false);
  f.ports('42424,80');
  assert.equal(f.node('nmap-confirm-authorized').checked, false);
  assert.equal(f.node('nmap-start-button').disabled, true);
  await f.submit();
  assert.equal(f.calls.length, 0);
  f.confirm();
  await f.submit();
  assert.deepEqual(f.calls, [{ path: '/api/nmap/tcp-scan',
    body: { target_id: 'target-a', engagement_id: 'eng-a', confirm_authorized: true, ports: [80,42424] } }]);
});

test('effective port equality keeps confirmation across reordered and default-equivalent input', () => {
  const f = fixture();
  f.ports('443,80');
  f.confirm();
  f.ports('80,443');
  assert.equal(f.node('nmap-confirm-authorized').checked, true);
  assert.equal(f.node('nmap-start-button').disabled, false);
  const g = fixture();
  g.confirm();
  g.ports(defaultPorts.slice().reverse().join(','));
  assert.equal(g.node('nmap-confirm-authorized').checked, true);
  assert.equal(g.node('nmap-start-button').disabled, false);
  g.ports('');
  assert.equal(g.node('nmap-confirm-authorized').checked, true);
});

test('engagement switch and return cannot reuse prior confirmation', async () => {
  const f = fixture();
  f.confirm();
  f.selectEngagement('eng-b');
  assert.equal(f.node('nmap-confirm-authorized').checked, false);
  f.selectEngagement('eng-a');
  assert.equal(f.node('nmap-start-button').disabled, true);
  await f.submit();
  assert.equal(f.calls.length, 0);
});

test('invalid ports revoke confirmation and stay revoked after repair', () => {
  const f = fixture();
  f.confirm();
  f.ports('80,80');
  assert.equal(f.node('nmap-confirm-authorized').checked, false);
  assert.equal(f.node('nmap-start-button').disabled, true);
  f.ports('');
  assert.equal(f.node('nmap-confirm-authorized').checked, false);
  assert.equal(f.node('nmap-start-button').disabled, true);
});

test('submit rechecks scope after mutation that did not emit input event', async () => {
  const f = fixture();
  f.confirm();
  f.ports('443', false);
  await f.submit();
  assert.equal(f.calls.length, 0);
  assert.equal(f.node('nmap-confirm-authorized').checked, false);
});

test('opening target again resets the original confirmation and modal state', () => {
  const f = fixture();
  f.confirm();
  vm.runInContext('openNmapScan({ id: "target-a", hostname: "scope.example.test" })', f.context);
  assert.equal(f.node('nmap-confirm-authorized').checked, false);
  assert.equal(f.node('nmap-ports').value, '');
  assert.equal(f.node('nmap-start-button').disabled, true);
});
