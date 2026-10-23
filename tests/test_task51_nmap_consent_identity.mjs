import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(process.env.SNIPER_NMAP_UI_JS || new URL('../static/app.js', import.meta.url), 'utf8');
const openStart = source.indexOf('function openNmapScan(target) {');
const openEnd = source.indexOf('async function openTrend(', openStart);
const handlerStart = source.indexOf('let nmapScanBusy = false;');
const handlerEnd = source.indexOf('$("#target-search").addEventListener(', handlerStart);
assert.ok(openStart >= 0 && openEnd > openStart && handlerStart >= 0 && handlerEnd > handlerStart);
const runnable = source.slice(openStart, openEnd) + '\n' + source.slice(handlerStart, handlerEnd);

function fixture() {
  const nodes = new Map();
  const calls = [];
  const target = {
    id: 'target-a', url: 'https://a.example.test/root', scheme: 'https',
    hostname: 'a.example.test', port: 443, path: '/root',
  };
  const engagement = {
    id: 'eng-a', target_id: target.id, name: 'Authorized', status: 'active',
    authorization_ref: 'AUTH-A', scope_notes: 'Only a.example.test TCP 80 and 443',
  };
  function node(id) {
    if (!nodes.has(id)) {
      const set = new Set(['hidden']);
      nodes.set(id, {
        value: '', textContent: '', checked: false, disabled: false, options: [],
        classList: {
          add: name => set.add(name),
          toggle(name, force) { if (force) set.add(name); else set.delete(name); },
          contains: name => set.has(name),
        },
        replaceChildren() { this.options = []; },
        appendChild(child) { this.options.push(child); },
        addEventListener(kind, handler) { this[kind] = handler; },
      });
    }
    return nodes.get(id);
  }
  const state = { selectedTarget: null, targets: [target], engagements: [engagement] };
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
  vm.runInContext('openNmapScan(state.targets[0])', context);
  node('nmap-engagement-select').value = engagement.id;
  function confirm() {
    node('nmap-confirm-authorized').checked = true;
    node('nmap-confirm-authorized').change();
  }
  async function submit() { await node('nmap-start-button').click(); }
  return { node, calls, target, engagement, state, confirm, submit };
}

test('unchanged target, authorization metadata and effective ports keep explicit consent', async () => {
  const f = fixture();
  f.node('nmap-ports').value = '443,80';
  f.node('nmap-ports').input();
  f.confirm();
  f.node('nmap-ports').value = '80,443';
  f.node('nmap-ports').input();
  assert.equal(f.node('nmap-confirm-authorized').checked, true);
  await f.submit();
  assert.deepEqual(f.calls, [{ path: '/api/nmap/tcp-scan', body: {
    target_id: 'target-a', engagement_id: 'eng-a', confirm_authorized: true, ports: [80, 443],
  } }]);
});

test('same target ID with changed displayed hostname revokes consent before POST', async () => {
  const f = fixture();
  f.confirm();
  f.target.hostname = 'other.example.test';
  await f.submit();
  assert.equal(f.calls.length, 0);
  assert.equal(f.node('nmap-confirm-authorized').checked, false);
  f.confirm();
  await f.submit();
  assert.equal(f.calls.length, 1);
});

test('same target ID with changed URL, scheme or port cannot reuse confirmation', async () => {
  for (const [field, value] of [
    ['url', 'http://a.example.test/root'],
    ['scheme', 'http'],
    ['port', 8443],
    ['path', '/other'],
  ]) {
    const f = fixture();
    f.confirm();
    f.target[field] = value;
    await f.submit();
    assert.equal(f.calls.length, 0, field);
    assert.equal(f.node('nmap-confirm-authorized').checked, false, field);
  }
});

test('fresh target-list object with same ID and new address revokes stale selected target consent', async () => {
  const f = fixture();
  f.confirm();
  f.state.targets = [{ ...f.target, hostname: 'changed.example.test', url: 'https://changed.example.test/root' }];
  await f.submit();
  assert.equal(f.calls.length, 0);
  assert.equal(f.node('nmap-confirm-authorized').checked, false);
});

test('same engagement ID with changed scope notes or authorization reference revokes consent', async () => {
  for (const [field, value] of [
    ['scope_notes', 'Only a.example.test TCP 22'],
    ['authorization_ref', 'AUTH-B'],
  ]) {
    const f = fixture();
    f.confirm();
    f.engagement[field] = value;
    await f.submit();
    assert.equal(f.calls.length, 0, field);
    assert.equal(f.node('nmap-confirm-authorized').checked, false, field);
  }
});
