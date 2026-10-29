import fs from 'node:fs';
import vm from 'node:vm';

const [root, mode] = process.argv.slice(2);
const source = fs.readFileSync(`${root}/static/app.js`, 'utf8');
const listeners = {};
const elements = new Map();
let backend = {
  id: 'synthetic-1', source: 'trivy', vulnerability_id: 'CVE-2099-0001',
  package_name: 'pkg', installed_version: '1.0', fixed_version: '1.1',
  project_path: '/tmp/synthetic', title: 'Synthetic', summary: 'Synthetic only',
  target: 'requirements.txt', references: [], status: 'open', severity: 'high',
  resolution_notes: 'Prior mitigation evidence', first_seen_at: '2026-10-16T00:00:00Z',
  last_seen_at: '2026-10-16T00:00:00Z'
};
const posted = [];
const requested = [];
const classes = () => {
  const names = new Set(['hidden']);
  return {
    add: (...items) => items.forEach(item => names.add(item)),
    remove: (...items) => items.forEach(item => names.delete(item)),
    toggle: (item, force) => {
      if (force === undefined) force = !names.has(item);
      if (force) names.add(item); else names.delete(item);
      return force;
    },
    contains: item => names.has(item),
  };
};
function elem(id = '') {
  return {
    id, value: id.startsWith('dependency-filter-') && id !== 'dependency-filter-query' ? 'all' : '',
    dataset: {}, innerHTML: '', textContent: '', style: {}, classList: classes(),
    disabled: false, checked: false, files: [],
    append() {}, remove() {}, addEventListener() {}, querySelector() { return null; },
    querySelectorAll() { return []; }, closest() { return null; }, matches() { return false; },
    setAttribute() {}, getAttribute() { return null; }, focus() {}, setSelectionRange() {}
  };
}
function get(selector) {
  const id = String(selector).replace(/^#/, '');
  if (!elements.has(id)) elements.set(id, elem(id));
  return elements.get(id);
}
function response(data) {
  return { ok: true, status: 200, json: async () => data };
}
const sandbox = {
  console, URL, URLSearchParams, TextEncoder, Intl, Date, Math, Number, String, Boolean, Array,
  Object, Set, Map, RegExp, Error, JSON, encodeURIComponent, decodeURIComponent,
  setTimeout: () => 1, clearTimeout: () => {}, setInterval: () => 1, clearInterval: () => {},
  location: { hash: '#projects' },
  fetch: async (path, options = {}) => {
    requested.push(path);
    if (path.startsWith('/api/dependency-findings/')) {
      const payload = JSON.parse(options.body);
      posted.push(payload);
      backend = { ...backend, ...payload };
      return response(backend);
    }
    if (path.startsWith('/api/dependency-security')) {
      if (mode === 'refresh_failure') throw Error('Synthetic dependency list outage');
      if (mode === 'page_navigation' && new URL(path, 'http://local').searchParams.get('offset') === '100') {
        return response({
          findings: [{ ...backend, id: 'synthetic-501', vulnerability_id: 'CVE-2099-0500' }], imports: [], sboms: [],
          summary: { total: 501, active: 501, critical: 0, high: 0 },
          page: { offset: 100, limit: 100, filtered_total: 501, has_more: true },
        });
      }
      return response({
        findings: [backend], imports: [], sboms: [],
        summary: { total: 1, active: backend.status === 'resolved' ? 0 : 1, critical: 0, high: 1 },
        page: { offset: 0, limit: 100, filtered_total: 1, has_more: false },
      });
    }
    if (path === '/api/dashboard' && mode === 'refresh_failure') throw Error('Synthetic dashboard outage');
    return response({ targets: [], scans: [], engagements: [], lab_runs: [], project_audits: [], total: 0, categories: [], tools: [] });
  },
  document: {
    body: { style: {} },
    addEventListener(type, fn) { (listeners[type] ||= []).push(fn); },
    getElementById: get, querySelector: get, querySelectorAll: () => [],
    createElement: () => elem(),
  },
};
sandbox.window = sandbox;
sandbox.addEventListener = () => {};
vm.createContext(sandbox);
vm.runInContext(source.replace(/\bnavigate\(location\.hash\.slice\(1\) \|\| "dashboard"\);\s*loadAll\(\);/, ''), sandbox);
const initialPage = mode === 'page_navigation'
  ? { offset: 0, limit: 100, filtered_total: 501, has_more: true }
  : { offset: 0, limit: 100, filtered_total: 1, has_more: false };
vm.runInContext(`state.dependencySecurity = {findings:[${JSON.stringify(backend)}], imports:[], sboms:[], summary:{total:${mode === 'page_navigation' ? 501 : 1}, active:1, critical:0, high:1}, page:${JSON.stringify(initialPage)}}; state.selectedDependencyFindingId='synthetic-1';`, sandbox);
sandbox.openDependencyFindingDetail('synthetic-1');

if (mode === 'quick_status') {
  const select = elem();
  select.value = 'resolved';
  select.dataset.id = 'synthetic-1';
  select.matches = selector => selector === '[data-dependency-status]';
  for (const fn of listeners.change || []) await fn({ target: select });
} else if (mode === 'refresh_failure') {
  const form = elem('dependency-finding-detail-form');
  form.dataset.id = 'synthetic-1';
  form.querySelector = selector => {
    if (selector === '[name="status"]') return { value: 'resolved' };
    if (selector === '[name="resolution_notes"]') return { value: 'New verified remediation' };
    if (selector === 'button[type="submit"]') return { disabled: false };
    return null;
  };
  for (const fn of listeners.submit || []) await fn({ target: form, preventDefault() {} });
} else if (mode === 'page_navigation') {
  const next = elem('dependency-page-next');
  for (const fn of listeners.click || []) await fn({ target: next, preventDefault() {} });
} else {
  throw Error(`Unknown mode: ${mode}`);
}

const detail = get('#dependency-finding-detail').innerHTML;
process.stdout.write(JSON.stringify({
  posted, backend_status: backend.status, backend_note: backend.resolution_notes,
  displayed_old_note: detail.includes('Prior mitigation evidence'),
  displayed_new_note: detail.includes('New verified remediation'),
  displayed_refresh_warning: detail.includes('liste yenilenemedi'),
  displayed_success: detail.includes('Durum ve çözüm notu güncellendi.'),
  requested_offset_100: requested.some(path => path.startsWith('/api/dependency-security?') && new URL(path, 'http://local').searchParams.get('offset') === '100'),
  rendered_later_finding: get('#dependency-findings').innerHTML.includes('CVE-2099-0500'),
}) + '\n');
