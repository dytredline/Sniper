import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/job_queue.js', import.meta.url), 'utf8');

function load(responses) {
  const calls = [];
  const delays = [];
  const window = {
    setTimeout(fn, ms) { delays.push(ms); fn(); return 0; },
    async fetch(path, options = {}) {
      calls.push({ path, method: options.method || 'GET', body: options.body ? JSON.parse(options.body) : undefined });
      const next = responses.shift();
      return { ok: next.status < 400, status: next.status, json: async () => next.body };
    },
  };
  vm.runInNewContext(source, { window, globalThis: window, encodeURIComponent, JSON, Promise, Math, Error, Object, Set, Array, String });
  return { jobs: window.SniperJobs, calls, delays };
}

function element() {
  return { textContent: '', dataset: {}, set innerHTML(_v) { throw new Error('innerHTML kullanılmamalı'); } };
}

test('iş başlatılır, geri çekilmeli yoklanır ve sonuç textContent ile gösterilir', async () => {
  const { jobs, calls, delays } = load([
    { status: 202, body: { id: 'job_1', state: 'queued', queue_position: 1 } },
    { status: 200, body: { id: 'job_1', state: 'running' } },
    { status: 200, body: { id: 'job_1', state: 'running' } },
    { status: 200, body: { id: 'job_1', state: 'succeeded', result: { ok: true } } },
  ]);
  const el = element();
  const updates = [];
  const job = await jobs.run('/api/tool-runs/semgrep', { project_path: '/p' }, el, j => updates.push(j.state));
  assert.equal(job.state, 'succeeded');
  assert.deepEqual(calls[0], { path: '/api/jobs', method: 'POST', body: { route: '/api/tool-runs/semgrep', payload: { project_path: '/p' } } });
  assert.equal(calls[1].path, '/api/jobs/job_1');
  assert.deepEqual(updates, ['running', 'running', 'succeeded']);
  assert.ok(delays[1] > delays[0], 'yoklama aralığı artmalı');
  assert.match(el.textContent, /Tamamlandı/);
  assert.equal(el.dataset.jobState, 'succeeded');
});

test('sunucu hatası Türkçe mesajla gösterilir ve HTML yorumlanmaz', async () => {
  const { jobs } = load([{ status: 409, body: { error: '<b>Aynı araç</b> için etkin iş var.' } }]);
  const el = element();
  await assert.rejects(() => jobs.run('/api/tool-runs/semgrep', {}, el), /etkin iş/);
  assert.equal(el.textContent, 'İş başlatılamadı: <b>Aynı araç</b> için etkin iş var.');
});

test('iptal ve geçersiz rota', async () => {
  const { jobs, calls } = load([{ status: 200, body: { id: 'job_9', state: 'running', cancel_requested: true } }]);
  const el = element();
  const job = await jobs.cancel('job_9', el);
  assert.equal(job.state, 'running');
  assert.equal(calls[0].path, '/api/jobs/job_9/cancel');
  assert.equal(calls[0].method, 'POST');
  assert.match(el.textContent, /iptal istendi/);
  await assert.rejects(() => jobs.run('javascript:alert(1)', {}, el), /Geçersiz rota/);
  assert.equal(jobs.stateLabel('expired'), 'Süre sınırı aşıldı');
});
