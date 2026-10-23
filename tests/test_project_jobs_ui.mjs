// 17. tur W1-JOBS: arka plan proje analizi istemcisi (ilerleme, iptal, devam etme) ve alt proje özeti.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/project_jobs.js', import.meta.url), 'utf8');

function node(tag) {
  const n = {
    tag, children: [], parentNode: null, textContent: '', className: '', dataset: {}, attrs: {}, value: 0, max: 0,
    disabled: false, open: false, id: '', onclick: null,
    classList: {
      add(c) { if (!n.className.split(' ').includes(c)) n.className = `${n.className} ${c}`.trim(); },
      remove(c) { n.className = n.className.split(' ').filter((x) => x !== c).join(' '); },
      contains(c) { return n.className.split(' ').includes(c); },
    },
    append(...items) { for (const item of items) { item.parentNode = n; n.children.push(item); } },
    insertBefore(item, ref) {
      item.parentNode = n;
      const index = ref ? n.children.indexOf(ref) : -1;
      if (index < 0) n.children.push(item); else n.children.splice(index, 0, item);
    },
    get nextSibling() {
      if (!n.parentNode) return null;
      const siblings = n.parentNode.children;
      return siblings[siblings.indexOf(n) + 1] || null;
    },
    setAttribute(k, v) { n.attrs[k] = String(v); },
    remove() { if (n.parentNode) n.parentNode.children = n.parentNode.children.filter((x) => x !== n); },
    querySelector(selector) {
      const cls = selector.startsWith('.') ? selector.slice(1) : null;
      const walk = (root) => {
        for (const child of root.children) {
          if (cls && child.className.split(' ').includes(cls)) return child;
          const found = walk(child);
          if (found) return found;
        }
        return null;
      };
      return walk(n);
    },
    set innerHTML(_v) { throw new Error('innerHTML kullanılmamalı'); },
  };
  return n;
}

function texts(root) {
  const out = [];
  const walk = (n) => { if (n.textContent) out.push(String(n.textContent)); (n.children || []).forEach(walk); };
  walk(root);
  return out;
}

function setup({ responses, stored = null }) {
  const body = node('body');
  const page = node('main');
  const form = node('form');
  form.id = 'project-audit-form';
  body.append(page);
  page.append(form);
  const calls = [];
  const listeners = {};
  const storage = new Map(stored ? [['sniper.projectJob', stored]] : []);
  const document = {
    body,
    createElement: (tag) => node(tag),
    getElementById(id) {
      const walk = (root) => { for (const c of root.children) { if (c.id === id) return c; const f = walk(c); if (f) return f; } return null; };
      return walk(body);
    },
    addEventListener(name, fn) { listeners[name] = fn; },
  };
  const toasts = [];
  const window = {
    localStorage: { getItem: (k) => storage.get(k) ?? null, setItem: (k, v) => storage.set(k, v), removeItem: (k) => storage.delete(k) },
    setTimeout: (fn) => setTimeout(fn, 0),
    toast: (message, type) => toasts.push([message, type || 'success']),
    async fetch(path, options = {}) {
      calls.push({ path, method: options.method || 'GET', body: options.body ? JSON.parse(options.body) : undefined });
      const next = responses(path, options);
      return { ok: next.status < 400, status: next.status, json: async () => next.body };
    },
  };
  vm.runInNewContext(source, { window, globalThis: window, document, String, Number, Math, JSON, Object, Error, Set, Promise, encodeURIComponent });
  return { window, document, form, page, calls, storage, listeners, toasts };
}

test('analiz iş kuyruğunda başlar, ilerleme çubuğu ve dosya sayısı textContent ile güncellenir', async () => {
  const states = [
    { id: 'job_000000000000000000000001', state: 'running', label: 'shop', progress: { stage: 'files', label: 'Dosyalar analiz ediliyor', percent: 45, done: 50, total: 100 } },
    { id: 'job_000000000000000000000001', state: 'succeeded', label: 'shop', progress: { percent: 100 }, result: { id: 'prj_1', project_name: 'shop' } },
  ];
  const seen = [];
  const env = setup({
    responses(path) {
      if (path === '/api/jobs') return { status: 202, body: { id: 'job_000000000000000000000001', state: 'queued', queue_position: 1, label: 'shop' } };
      const job = states.shift();
      seen.push(job.state);
      return { status: 200, body: job };
    },
  });
  const promise = env.window.SniperProjectJobs.start({ project_path: '/p/shop' }, env.form);
  const box = env.document.getElementById('project-job-status');
  assert.ok(box, 'durum kutusu formun yanına eklenir');
  assert.equal(env.page.children[1], box);
  assert.equal(box.attrs['aria-live'], 'polite');
  const audit = await promise;
  assert.equal(audit.id, 'prj_1');
  assert.deepEqual(env.calls[0], { path: '/api/jobs', method: 'POST', body: { route: '/api/project-audits', payload: { project_path: '/p/shop' } } });
  assert.deepEqual(seen, ['running', 'succeeded']);
  assert.equal(env.storage.has('sniper.projectJob'), false, 'biten iş tarayıcı belleğinden silinir');
  assert.equal(box.querySelector('.project-job-bar').value, 100);
  assert.ok(box.classList.contains('hidden'));
});

test('ara durum: aşama etiketi, dosya sayısı, yüzde ve iptal düğmesi', () => {
  const env = setup({ responses: () => ({ status: 200, body: {} }) });
  const pj = env.window.SniperProjectJobs;
  const box = env.document.createElement('div');
  box.append(Object.assign(env.document.createElement('progress'), { className: 'project-job-bar' }));
  for (const cls of ['project-job-name', 'project-job-stage', 'project-job-count', 'project-job-percent']) {
    box.append(Object.assign(env.document.createElement('span'), { className: cls }));
  }
  box.append(Object.assign(env.document.createElement('button'), { className: 'project-job-cancel' }));
  pj.render(box, { id: 'job_x', state: 'running', label: '<b>x</b>', progress: { label: 'Dosyalar analiz ediliyor', percent: 42.4, done: 7, total: 9 } });
  assert.deepEqual(texts(box), [' · <b>x</b>', 'Dosyalar analiz ediliyor', ' · 7/9 dosya', ' · %42']);
  assert.equal(box.querySelector('.project-job-bar').value, 42.4);
  pj.render(box, { id: 'job_x', state: 'queued', queue_position: 3, progress: null });
  assert.equal(box.querySelector('.project-job-count').textContent, ' · sıra 3');
  assert.equal(box.querySelector('.project-job-stage').textContent, 'Sırada bekliyor');
  pj.render(box, { id: 'job_x', state: 'cancelled', error: 'İş kullanıcı isteğiyle iptal edildi.' });
  assert.equal(box.querySelector('.project-job-cancel').disabled, true);
});

test('iptal edilen iş hata olarak döner; iptal isteği POST ile gider', async () => {
  let polls = 0;
  const env = setup({
    responses(path, options) {
      if (path === '/api/jobs') return { status: 202, body: { id: 'job_000000000000000000000002', state: 'queued' } };
      if (path.endsWith('/cancel')) return { status: 200, body: { id: 'job_000000000000000000000002', state: 'running', cancel_requested: true } };
      polls += 1;
      return { status: 200, body: polls < 2
        ? { id: 'job_000000000000000000000002', state: 'running', progress: { percent: 10 } }
        : { id: 'job_000000000000000000000002', state: 'cancelled', error: 'İş kullanıcı isteğiyle iptal edildi.' } };
    },
  });
  const promise = env.window.SniperProjectJobs.start({ project_path: '/p' }, env.form);
  await new Promise((resolve) => setTimeout(resolve, 0));
  const box = env.document.getElementById('project-job-status');
  await box.querySelector('.project-job-cancel').onclick();
  await assert.rejects(promise, /iptal edildi/);
  assert.ok(env.calls.some((c) => c.path === '/api/jobs/job_000000000000000000000002/cancel' && c.method === 'POST'));
});

test('sayfa yeniden açılınca süren analiz izlenir, bitince ayrıntı açılır', async () => {
  const opened = [];
  const env = setup({
    stored: 'job_000000000000000000000003',
    responses: () => ({ status: 200, body: { id: 'job_000000000000000000000003', route: '/api/project-audits', state: 'succeeded', result: { id: 'prj_9', project_name: 'eski' } } }),
  });
  env.window.loadAll = async () => opened.push('loadAll');
  env.window.openProjectAudit = async (id) => opened.push(id);
  const audit = await env.window.SniperProjectJobs.resume();
  assert.equal(audit.id, 'prj_9');
  assert.deepEqual(opened, ['loadAll', 'prj_9']);
  assert.deepEqual(env.toasts, [['eski analizi tamamlandı.', 'success']]);
  assert.equal(env.storage.has('sniper.projectJob'), false);
  // başka rotaya ait ya da biçimi bozuk kimlik izlenmez
  const other = setup({ stored: 'bad id', responses: () => ({ status: 200, body: {} }) });
  assert.equal(await other.window.SniperProjectJobs.resume(), null);
  assert.equal(other.calls.length, 0);
});

test('alt proje özeti lisans kancasına zincirlenir; adlar metin olarak kalır', () => {
  const env = setup({ responses: () => ({ status: 200, body: {} }) });
  const calls = [];
  env.window.renderLicenseSummary = (audit) => calls.push(audit.id);
  env.window.SniperProjectJobs.installDetailHook();
  env.window.SniperProjectJobs.installDetailHook();  // iki kez kurulsa da tek zincir
  const detail = env.document.createElement('section');
  const audit = { id: 'prj_1', subprojects: { count: 1, declared: true, subprojects: [
    { path: 'packages/<img src=x>', kind: 'npm', file_count: 3, languages: { JavaScript: 3 }, finding_counts: { high: 1 }, dependencies: { component_count: 2, by_ecosystem: { npm: 2 } } },
  ], root: { path: '.', kind: 'root', file_count: 1, languages: {}, finding_counts: {}, finding_count: 0 } } };
  env.window.renderLicenseSummary(audit, detail);
  assert.deepEqual(calls, ['prj_1']);
  const all = texts(detail);
  assert.ok(all.includes('packages/<img src=x>'));
  assert.ok(all.includes('2 bileşen (npm 2)'));
  assert.ok(all.includes('0 kritik · 1 yüksek · 0 orta · 0 düşük'));
  assert.ok(all.includes('(kök)'));
  env.window.renderLicenseSummary({ id: 'prj_2', subprojects: null }, detail);
  assert.equal(detail.querySelector('.subproject-panel'), null, 'tek projeli analizde özet kaldırılır');
});
