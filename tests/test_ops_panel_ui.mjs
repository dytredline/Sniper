import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../static/ops_panel.js', import.meta.url), 'utf8');
const html = fs.readFileSync(new URL('../static/index.html', import.meta.url), 'utf8');
const appJs = fs.readFileSync(new URL('../static/app.js', import.meta.url), 'utf8');

class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.textContent = ''; this.listeners = {}; this.classes = new Set(); this.options = []; this.value = ''; this.className = ''; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren() { this.children = []; }
  add(option) { this.options.push(option); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  set innerHTML(_v) { throw new Error('innerHTML kullanılmamalı'); }
  get classList() { const c = this.classes; return { toggle: (n, on) => (on ? c.add(n) : c.delete(n)), add: n => c.add(n), remove: n => c.delete(n), contains: n => c.has(n) }; }
}

function load() {
  const ids = Object.fromEntries(['ops-scan-type', 'ops-scope-field', 'ops-base-ref-field', 'ops-schedule-body', 'ops-schedule-empty',
    'ops-schedule-count', 'ops-notification-list', 'ops-notification-empty', 'ops-unread-count', 'ops-unread-badge'].map(id => [id, new Node('x')]));
  const document = { getElementById: id => ids[id] || null, createElement: tag => new Node(tag), querySelector: () => null, activeElement: null };
  const window = {};
  class Option { constructor(label, value) { this.label = label; this.value = value; } }
  vm.runInNewContext(source, { window, globalThis: window, document, Option, Intl, Date, Number, String, Boolean, Object, Promise });
  return { ids, ops: window.SniperOps };
}

test('index.html görünümleri, menüyü ve betiği içerir; app.js gezinmesi yeni görünümleri tanır', () => {
  for (const id of ['ops-schedule-form', 'ops-schedule-body', 'ops-timezone-form', 'ops-notification-list', 'ops-settings-form', 'ops-unread-badge', 'ops-send-test']) {
    assert.match(html, new RegExp(`id="${id}"`), id);
  }
  assert.match(html, /data-view="schedules"/);
  assert.match(html, /data-view="notifications"/);
  assert.match(html, /\/ops_panel\.js\?v=1/);
  assert.match(appJs, /schedules:\s*Object\.freeze\(\{ view: "schedules", hash: "#schedules"/);
  assert.match(appJs, /notifications:\s*Object\.freeze\(\{ view: "notifications", hash: "#notifications"/);
  assert.match(appJs, /case "schedules": return NAVIGATION_DESTINATIONS\.schedules/);
  assert.match(appJs, /case "notifications": return NAVIGATION_DESTINATIONS\.notifications/);
  assert.match(appJs, /SniperOps\.show\(view\)/);
});

test('planlar ve bildirimler textContent ile yazılır; okunmamış rozeti güncellenir', () => {
  const { ids, ops } = load();
  ops.renderSchedules({
    timezone: 'Europe/Istanbul', max_schedules: 50,
    scan_types: [{ key: 'project_audit', label: 'Proje analizi', uses_scope: true }],
    schedules: [{ id: 'sch_aaaaaaaaaaaa', name: '<img src=x>', project_path: '/p', scan_type: 'project_audit', frequency: 'daily 03:00', enabled: true, next_run_at: null, last_status: 'skipped_overlap' }],
  });
  const row = ids['ops-schedule-body'].children[0];
  assert.equal(row.children[0].textContent, '<img src=x>');
  assert.equal(row.children[2].textContent, 'Proje analizi');
  assert.equal(row.children[6].textContent, 'Atlandı (önceki iş sürüyor)');
  assert.equal(row.children[7].children[0].children.length, 3);
  assert.equal(ids['ops-scan-type'].options.length, 1);
  assert.ok(ids['ops-schedule-empty'].classes.has('hidden'));

  ops.renderNotifications({ unread: 3, items: [{ id: 'ntf_1', title: '<b>x</b>', message: 'm', severity: 'critical', read: false, details: ['a.py:3'], channels: { center: 'stored', webhook: 'sent' }, created_at: '2026-10-20T00:00:00Z' }] });
  const card = ids['ops-notification-list'].children[0];
  assert.equal(card.children[0].textContent, '<b>x</b>');
  assert.match(card.className, /critical/);
  assert.match(card.className, /unread/);
  assert.equal(ids['ops-unread-badge'].textContent, '3');
  assert.ok(!ids['ops-unread-badge'].classes.has('hidden'));
  ops.renderNotifications({ unread: 0, items: [] });
  assert.ok(ids['ops-unread-badge'].classes.has('hidden'));
});

test('ayar formu nesneye çevrilir; parola alanı forma geri yazılmaz', () => {
  const { ops } = load();
  const field = (value, checked = false) => ({ value, checked, placeholder: '' });
  const elements = {
    new_findings: field('', true), min_severity: field('critical'), fixed_findings: field('', false), scan_failed: field('', true),
    desktop: field('', false), smtp: field('', true), smtp_host: field(' 127.0.0.1 '), smtp_port: field('2525'), smtp_security: field('none'),
    smtp_username: field('ben'), smtp_password: field('gizli'), smtp_password_clear: field('', false), smtp_from: field('s@o.local'),
    smtp_to: field('a@o.local, b@o.local'), webhook: field('', true), webhook_url: field('http://127.0.0.1:9/x'),
    quiet: field('', true), quiet_start: field('23:00'), quiet_end: field('07:00'), quiet_allow_critical: field('', false), confirm: field('', true),
  };
  const settings = ops.settingsFromForm({ elements });
  assert.equal(settings.events.new_findings.min_severity, 'critical');
  assert.equal(JSON.stringify(settings.channels.smtp.to), JSON.stringify(['a@o.local', 'b@o.local']));
  assert.equal(settings.channels.smtp.host, '127.0.0.1');
  assert.equal(settings.channels.smtp.port, 2525);
  assert.equal(JSON.stringify(settings).includes('gizli'), false);
  assert.equal(settings.quiet_hours.allow_critical, false);
});
