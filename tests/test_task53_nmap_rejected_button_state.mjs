import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(process.env.SNIPER_NMAP_UI_JS || new URL('../static/app.js', import.meta.url), 'utf8');
const modalStart = source.indexOf('function openNmapScan(target) {');
const modalEnd = source.indexOf('async function openTrend(', modalStart);
const handlerStart = source.indexOf('let nmapScanBusy = false;');
const handlerEnd = source.indexOf('$("#target-search").addEventListener(', handlerStart);
assert.ok(modalStart >= 0 && modalEnd > modalStart && handlerStart >= 0 && handlerEnd > handlerStart);
const runnable = source.slice(modalStart, modalEnd) + '\n' + source.slice(handlerStart, handlerEnd);

function fixture() {
  const nodes = new Map();
  const calls = [];
  const target = {
    id: 'target-a', url: 'https://a.example.test/', scheme: 'https',
    hostname: 'a.example.test', port: 443, path: '/',
  };
  const engagement = {
    id: 'eng-a', target_id: target.id, name: 'Authorized', status: 'active',
    authorization_ref: 'AUTH-A', scope_notes: 'Synthetic TCP 80 and 443',
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
  const state = { targets: [target], selectedTarget: null, engagements: [engagement] };
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
  const checkbox = node('nmap-confirm-authorized');
  const button = node('nmap-start-button');
  checkbox.checked = true;
  checkbox.change();
  return { node, calls, state, target, engagement, checkbox, button };
}

test('unchanged confirmed scope keeps Start enabled and sends one bounded API request', async () => {
  const f = fixture();
  assert.equal(f.button.disabled, false);
  await f.button.click();
  assert.deepEqual(f.calls, [{ path: '/api/nmap/tcp-scan', body: {
    target_id: 'target-a', engagement_id: 'eng-a', confirm_authorized: true,
  } }]);
});

test('silent same-ID target-list address change rejects click and immediately disables Start', async () => {
  const f = fixture();
  assert.equal(f.button.disabled, false);
  f.state.targets = [{ ...f.target, hostname: 'changed.example.test', url: 'https://changed.example.test/' }];
  await f.button.click();
  assert.equal(f.calls.length, 0);
  assert.equal(f.checkbox.checked, false);
  assert.equal(f.button.disabled, true);
});

test('silent same-ID authorization scope change rejects click and immediately disables Start', async () => {
  const f = fixture();
  assert.equal(f.button.disabled, false);
  f.engagement.scope_notes = 'Changed synthetic TCP scope';
  await f.button.click();
  assert.equal(f.calls.length, 0);
  assert.equal(f.checkbox.checked, false);
  assert.equal(f.button.disabled, true);
});
