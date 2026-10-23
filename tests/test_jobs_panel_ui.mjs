import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/jobs_panel.js', import.meta.url), 'utf8');
const html = fs.readFileSync(new URL('../static/index.html', import.meta.url), 'utf8');

class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.textContent = ''; this.dataset = {}; this.listeners = {}; this.disabled = false; this.classes = new Set(); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren() { this.children = []; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  set innerHTML(_v) { throw new Error('innerHTML kullanılmamalı'); }
  get classList() { const c = this.classes; return { toggle: (n, on) => (on ? c.add(n) : c.delete(n)), add: n => c.add(n), remove: n => c.delete(n), contains: n => c.has(n) }; }
}

function load(jobs, cancelCalls) {
  const ids = Object.fromEntries(['jobs-panel', 'jobs-panel-body', 'jobs-panel-empty', 'jobs-panel-error', 'jobs-panel-refresh'].map(id => [id, new Node('x')]));
  const document = { readyState: 'complete', visibilityState: 'visible', getElementById: id => ids[id] || null, createElement: tag => new Node(tag) };
  const window = {
    setInterval: () => 1, clearInterval() {},
    SniperJobs: {
      list: async () => jobs,
      cancel: async id => { cancelCalls.push(id); return { id, state: 'running', cancel_requested: true }; },
      stateLabel: s => ({ running: 'Çalışıyor', succeeded: 'Tamamlandı', queued: 'Kuyrukta' })[s] || 'Bilinmiyor',
    },
  };
  vm.runInNewContext(source, { window, globalThis: window, document, String, Boolean, Promise });
  return { ids, panel: window.SniperJobsPanel };
}

test('index.html iş kuyruğu ve panel betiklerini app.js öncesi/sonrası yükler', () => {
  assert.ok(html.indexOf('/job_queue.js?v=2') < html.indexOf('/app.js?v='), 'job_queue.js app.js öncesinde');
  assert.match(html, /\/jobs_panel\.js\?v=1/);
  for (const id of ['jobs-panel', 'jobs-panel-body', 'jobs-panel-empty', 'jobs-panel-refresh', 'advanced-tool-background', 'advanced-tool-job-status']) {
    assert.match(html, new RegExp(`id="${id}"`), id);
  }
});

test('işler listelenir, yalnız etkin işlerde iptal düğmesi olur ve metin textContent ile yazılır', async () => {
  const cancels = [];
  const jobs = [
    { id: 'job_a', route: '/api/tool-runs/semgrep', state: 'running', created_at: 't1' },
    { id: 'job_b', route: '<b>x</b>', state: 'succeeded', created_at: 't2', http_status: 200 },
  ];
  const { ids, panel } = load(jobs, cancels);
  await panel.refresh();
  const rows = ids['jobs-panel-body'].children;
  assert.equal(rows.length, 2);
  assert.equal(rows[0].children[2].textContent, 'Çalışıyor');
  assert.equal(rows[1].children[1].textContent, '<b>x</b>');
  const button = rows[0].children[5].children[0];
  assert.equal(button.textContent, 'İptal et');
  assert.equal(rows[1].children[5].children.length, 0);
  await button.listeners.click();
  assert.deepEqual(cancels, ['job_a']);
  assert.ok(ids['jobs-panel-empty'].classes.has('hidden'));
});
