import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/portfolio.js', import.meta.url), 'utf8');

function load({ hash = '', status = { enabled: false } } = {}) {
  const listeners = {};
  const calls = [];
  const created = [];
  const document = {
    readyState: 'complete',
    addEventListener: (name, fn) => { listeners[name] = fn; },
    querySelector: () => null,
    getElementById: () => null,
    createElement: (tag) => { const el = { tag, dataset: {}, classList: { add() {} } }; created.push(el); return el; },
    body: { appendChild() {} },
  };
  const scope = {
    document, location: { hash }, String, Object, Array, JSON, Promise, Error, Number, Math, URLSearchParams,
    FormData: class { constructor(form) { this.form = form; } get(name) { return this.form.values[name] ?? null; } entries() { return Object.entries(this.form.values); } },
    api: async (path, options) => { calls.push({ path, options }); return path === '/api/auth/status' ? status : {}; },
  };
  scope.globalThis = scope;
  scope.module = { exports: {} };
  vm.runInNewContext(source, scope);
  return { scope, listeners, calls, created, exp: scope.module.exports };
}

test('görünüm bölümü betikçe oluşturulur; yükleyici ve dinleyiciler kurulur', () => {
  const { scope, listeners, created } = load();
  assert.equal(typeof scope.sniperLoadPortfolio, 'function');
  assert.ok(listeners.click && listeners.submit);
  assert.equal(created[0].dataset.view, 'portfolio');
});

test('proje tablosu ve kartlar sunucu metnini kaçışlar; satır içi stil üretilmez', () => {
  const { exp } = load();
  const evil = '<img src=x onerror=alert(1)>';
  const html = exp.projectTable([{ project_name: evil, project_path: `/p/${evil}`, risk_score: 12, active_by_severity: { critical: 1 }, sla_breached: 1, overdue: 0, mttr_days: null, last_audit_at: evil, grade: '"A"' }]);
  assert.doesNotMatch(html, /<img/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.match(html, /data-portfolio-open="\/p\/&lt;img/);
  assert.doesNotMatch(html, /style=/);
  const cards = exp.cards({ totals: { active: 3, sla_breached: 2, overdue: 0 }, sla: { fixed_within_sla_ratio: 0.5 }, mttr: { overall: { mean_days: 4.5 } }, recent_days: 30 });
  assert.match(cards, /portfolio-card bad/);
  assert.match(cards, /<b>50<\/b><span>SLA içinde düzelme \(%\)/);
  assert.doesNotMatch(cards, /style=/);
});

test('eğilim grafiği SVG özniteliğiyle çizilir (CSP: style yok), boş veride ileti', () => {
  const { exp } = load();
  const svg = exp.trendChart([{ week_end: '2026-10-06', new: 2, fixed: 1, reopened: 0, active: 5 }, { week_end: '2026-10-13', new: 0, fixed: 3, reopened: 0, active: 2 }]);
  assert.match(svg, /<svg viewBox=/);
  assert.match(svg, /<polyline class="line-active"/);
  assert.match(svg, /rect class="bar-new"/);
  assert.doesNotMatch(svg, /style=/);
  assert.match(exp.trendChart([]), /Eğilim için veri yok/);
});

test('politika formu: boş gün SLA yok, yönetici olmayan için kilitli', async () => {
  const { exp } = load();
  const parsed = exp.policyFromForm({ values: { days_critical: '5', days_high: '', days_medium: '60', days_low: '', days_info: '', auto_due_date: 'on', risk_acceptance_days: '30' } });
  assert.deepEqual(JSON.parse(JSON.stringify(parsed)), { days: { critical: 5, high: null, medium: 60, low: null, info: null }, auto_due_date: true, risk_acceptance_days: 30 });
  assert.doesNotMatch(exp.policyForm({ policy: { days: { critical: 7 }, auto_due_date: false, risk_acceptance_days: 0 } }), / disabled/);
  exp.state.authEnabled = true;
  exp.state.role = 'analyst';
  const locked = exp.policyForm({ policy: { days: {}, auto_due_date: false, risk_acceptance_days: 0 } });
  assert.match(locked, / disabled/);
  assert.match(locked, /yalnız yönetici/);
  assert.doesNotMatch(exp.exportForm([]), / disabled/);  // analist dışa aktarabilir
  exp.state.role = 'reader';
  assert.match(exp.exportForm([]), / disabled/);
});

test('dışa aktarım adresi parametreleri kodlar', () => {
  const { exp } = load();
  assert.equal(exp.exportUrl({ format: 'jira', status: 'all', project_path: '/home/community-user b&c' }), '/api/portfolio/export?format=jira&status=all&project_path=%2Fhome%2Fcommunity-user+b%26c');
  assert.equal(exp.exportUrl({}), '/api/portfolio/export?format=csv&status=active');
});

test('21. tur: alanlara göre etkin bulgular tablosu kaçışlı ve sayısal', () => {
  const { exp } = load();
  const html = exp.sectionTable([{ project_name: '<b>x</b>', project_path: '/p',
    by_section: { code: 3, dependencies: 5, iac: 2, container: 0, license: 1, api: 1, supply_chain: 1 } }]);
  assert.match(html, /Alanlara göre etkin bulgular/);
  assert.match(html, /&lt;b&gt;x&lt;\/b&gt;/);
  assert.match(html, /<td class="num">5<\/td>/);
  assert.match(html, /<td class="num">3<\/td><\/tr>/);  // lisans + API + tedarik zinciri
  assert.equal(exp.sectionTable([{ project_name: 'y' }]), '');
});
