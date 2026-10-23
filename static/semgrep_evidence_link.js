(function () {
  'use strict';

  const get = suffix => document.getElementById('semgrep-evidence-' + suffix);
  const severities = ['ERROR', 'WARNING', 'EXPERIMENT', 'INVENTORY', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const state = { generation: 0, controlGeneration: 0, pending: false, engagements: [], controlIds: new Set() };
  let modal, form, path, engagement, control, confirmLocal, confirmLink, submit, error, result;

  function option(select, value, label) {
    const item = document.createElement('option');
    item.value = value;
    item.textContent = label;
    select.appendChild(item);
  }

  function message(element, value) {
    element.textContent = value;
    element.classList.toggle('hidden', !value);
  }

  function configuredHome() {
    const value = document.querySelector?.('meta[name="sniper-local-home"]')?.content;
    if (typeof value !== 'string' || value.length < 2 || value.length > 1024 ||
        !value.startsWith('/') || value.endsWith('/') || value.includes('//') || /[\\\x00-\x1f\x7f]/.test(value)) return '';
    return value.split('/').slice(1).every(segment => segment && segment !== '.' && segment !== '..') ? value : '';
  }

  function validPath() {
    const value = path.value;
    const home = configuredHome();
    return !!home && value.length <= 1024 && value.startsWith(home + '/') &&
      !/[\\\x00-\x1f\x7f]/.test(value) &&
      value.slice(home.length + 1).split('/').every(segment => segment && segment !== '.' && segment !== '..');
  }

  function eligible(item) {
    return item && item.status === 'active' && typeof item.id === 'string' && item.id &&
      typeof item.authorization_ref === 'string' && item.authorization_ref.trim() &&
      item.special_approvals?.redacted_data_proof === true;
  }

  function updateSubmit() {
    submit.disabled = state.pending || !validPath() || !confirmLocal.checked || !confirmLink.checked ||
      !state.engagements.some(item => item.id === engagement.value) ||
      !state.controlIds.has(control.value);
  }

  function reset() {
    state.generation += 1;
    state.controlGeneration += 1;
    state.engagements = [];
    state.controlIds.clear();
    path.value = '';
    confirmLocal.checked = false;
    confirmLink.checked = false;
    engagement.replaceChildren();
    option(engagement, '', 'Denetimler yükleniyor');
    engagement.disabled = true;
    control.replaceChildren();
    option(control, '', 'Önce denetim seçin');
    control.disabled = true;
    message(error, '');
    result.classList.add('hidden');
    for (const suffix of ['message', 'count', 'severity', 'hash']) get(suffix).textContent = '';
    updateSubmit();
  }

  async function loadEngagements() {
    reset();
    const generation = state.generation;
    try {
      const response = await fetch('/api/engagements', { cache: 'no-store' });
      if (!response.ok) throw new Error('engagement list unavailable');
      const data = await response.json();
      if (!data || !Array.isArray(data.engagements)) throw new Error('invalid engagement list');
      if (generation !== state.generation) return;
      state.engagements = data.engagements.filter(eligible);
      engagement.replaceChildren();
      option(engagement, '', state.engagements.length ? 'Denetim seçin' : 'Uygun etkin denetim yok');
      for (const item of state.engagements) {
        option(engagement, item.id, String(item.name || item.id) + ' · ' + item.authorization_ref);
      }
      engagement.disabled = state.engagements.length === 0;
    } catch (_) {
      if (generation !== state.generation) return;
      engagement.replaceChildren();
      option(engagement, '', 'Denetimler yüklenemedi');
      engagement.disabled = true;
      message(error, 'Etkin ve yetkili manuel denetim listesi alınamadı.');
    }
    updateSubmit();
  }

  async function loadControls() {
    const selected = engagement.value;
    const generation = state.generation;
    const controlGeneration = ++state.controlGeneration;
    state.controlIds.clear();
    confirmLink.checked = false;
    control.replaceChildren();
    option(control, '', selected ? 'Test adımları yükleniyor' : 'Önce denetim seçin');
    control.disabled = true;
    updateSubmit();
    if (!state.engagements.some(item => item.id === selected)) return;
    try {
      const response = await fetch('/api/engagements/' + encodeURIComponent(selected), { cache: 'no-store' });
      if (!response.ok) throw new Error('control list unavailable');
      const data = await response.json();
      if (!data || data.id !== selected || !eligible(data) || !Array.isArray(data.tests)) {
        throw new Error('invalid engagement');
      }
      if (generation !== state.generation || controlGeneration !== state.controlGeneration || engagement.value !== selected) return;
      control.replaceChildren();
      option(control, '', data.tests.length ? 'Test adımı seçin' : 'Test adımı yok');
      for (const item of data.tests) {
        if (typeof item.control_id === 'string' && item.control_id && typeof item.title === 'string') {
          option(control, item.control_id, item.control_id + ' · ' + item.title);
          state.controlIds.add(item.control_id);
        }
      }
      control.disabled = state.controlIds.size === 0;
    } catch (_) {
      if (generation !== state.generation || controlGeneration !== state.controlGeneration || engagement.value !== selected) return;
      control.replaceChildren();
      option(control, '', 'Test adımları yüklenemedi');
      control.disabled = true;
      message(error, 'Denetim test adımları alınamadı.');
    }
    updateSubmit();
  }

  function validSummary(data, selected, selectedControl) {
    if (!data || data.tool_identity !== 'semgrep-local' || data.profile !== 'local-trusted-rules-v1' ||
        data.engagement_id !== selected || data.control_id !== selectedControl ||
        !Number.isSafeInteger(data.result_count) || data.result_count < 0 || data.result_count > 500 ||
        typeof data.report_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(data.report_sha256)) return false;
    const counts = data.severity_counts;
    if (!counts || typeof counts !== 'object' || Array.isArray(counts)) return false;
    const keys = Object.keys(counts);
    if (keys.length !== severities.length || !severities.every(key => keys.includes(key))) return false;
    let total = 0;
    for (const key of severities) {
      if (!Number.isSafeInteger(counts[key]) || counts[key] < 0 || counts[key] > 500) return false;
      total += counts[key];
    }
    return total === data.result_count;
  }

  async function submitLink(event) {
    event.preventDefault();
    updateSubmit();
    if (submit.disabled) return;
    const selected = engagement.value;
    const selectedControl = control.value;
    const projectPath = path.value;
    const generation = state.generation;
    state.pending = true;
    updateSubmit();
    message(error, '');
    result.classList.add('hidden');
    try {
      const response = await fetch('/api/engagements/' + encodeURIComponent(selected) + '/tool-runs/semgrep-local', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ control_id: selectedControl, project_path: projectPath, confirm_local: true, confirm_link: true })
      });
      if (!response.ok) throw new Error('link rejected');
      const data = await response.json();
      if (!validSummary(data, selected, selectedControl)) throw new Error('invalid aggregate');
      if (generation !== state.generation) return;
      get('count').textContent = String(data.result_count);
      get('severity').textContent = severities.filter(key => data.severity_counts[key] > 0)
        .map(key => `${key}: ${data.severity_counts[key]}`).join(' · ') || 'Bulgu yok';
      get('hash').textContent = data.report_sha256;
      get('message').textContent = 'Toplu Semgrep kanıtı ' + selectedControl +
        ' test adımına bağlandı. Uzman incelemesi gerekir; kontrol otomatik başarılı yapılmaz.';
      result.classList.remove('hidden');
      path.value = '';
      confirmLocal.checked = false;
      confirmLink.checked = false;
    } catch (_) {
      if (generation === state.generation) {
        message(error, 'Yerel Semgrep taraması ve kanıt bağlantısı tamamlanamadı. Proje yolunu, denetim yetkisini ve iki açık onayı kontrol edin.');
      }
    } finally {
      state.pending = false;
      updateSubmit();
    }
  }

  function init() {
    const open = document.querySelector('[data-action="open-semgrep-local"]');
    modal = document.getElementById('semgrep-local-modal');
    form = get('form'); path = get('path'); engagement = get('engagement'); control = get('control');
    confirmLocal = get('confirm-local'); confirmLink = get('confirm-link');
    submit = get('submit'); error = get('error'); result = get('result');
    if (!open || !modal || !form || !path || !engagement || !control || !confirmLocal || !confirmLink ||
        !submit || !error || !result || !get('message') || !get('count') || !get('severity') || !get('hash')) return;
    open.addEventListener('click', () => { void loadEngagements(); });
    path.addEventListener('input', () => {
      confirmLocal.checked = false;
      confirmLink.checked = false;
      updateSubmit();
    });
    engagement.addEventListener('change', () => { void loadControls(); });
    control.addEventListener('change', () => { confirmLink.checked = false; updateSubmit(); });
    confirmLocal.addEventListener('change', updateSubmit);
    confirmLink.addEventListener('change', updateSubmit);
    form.addEventListener('submit', submitLink);
    document.addEventListener('click', event => {
      if (event.target.closest?.('[data-close="semgrep-local-modal"]') || event.target === modal) reset();
    });
  }

  document.addEventListener('DOMContentLoaded', init);
}());
