(function () {
  'use strict';

  const prefix = 'zap-evidence-link-';
  const get = suffix => document.getElementById(prefix + suffix);
  const state = { generation: 0, busy: false, engagements: [] };
  let form, paste, file, engagement, control, consent, submit, error, result;

  function message(element, value) {
    element.textContent = value;
    element.classList.toggle('hidden', !value);
  }

  function option(select, value, label) {
    const item = document.createElement('option');
    item.value = value;
    item.textContent = label;
    select.appendChild(item);
  }

  function eligible(item) {
    return item && item.status === 'active' &&
      typeof item.id === 'string' && typeof item.authorization_ref === 'string' &&
      item.authorization_ref.trim() && typeof item.scope_notes === 'string' &&
      item.scope_notes.trim() && item.special_approvals?.redacted_data_proof === true;
  }

  function updateSubmit() {
    submit.disabled = state.busy || !consent.checked || !engagement.value ||
      !control.value || control.disabled;
  }

  function reset() {
    state.generation += 1;
    state.engagements = [];
    state.busy = false;
    paste.value = '';
    file.value = '';
    consent.checked = false;
    engagement.replaceChildren();
    option(engagement, '', 'Denetimler yükleniyor');
    engagement.disabled = true;
    control.replaceChildren();
    option(control, '', 'Önce denetim seçin');
    control.disabled = true;
    message(error, '');
    message(result, '');
    updateSubmit();
  }

  async function loadEngagements() {
    reset();
    const generation = state.generation;
    try {
      const response = await fetch('/api/engagements', { cache: 'no-store' });
      if (!response.ok) throw new Error('engagement list unavailable');
      const data = await response.json();
      if (!Array.isArray(data.engagements)) throw new Error('invalid engagement list');
      if (generation !== state.generation) return;
      state.engagements = data.engagements.filter(eligible);
      engagement.replaceChildren();
      option(engagement, '', state.engagements.length ? 'Denetim seçin' : 'Uygun etkin denetim yok');
      for (const item of state.engagements) option(engagement, item.id, item.name + ' · ' + item.authorization_ref);
      engagement.disabled = state.engagements.length === 0;
    } catch (_) {
      if (generation !== state.generation) return;
      engagement.replaceChildren();
      option(engagement, '', 'Denetimler yüklenemedi');
      engagement.disabled = true;
      message(error, 'Etkin ve yetkili denetim listesi alınamadı.');
    }
    updateSubmit();
  }

  async function loadControls() {
    const selected = engagement.value;
    const generation = state.generation;
    control.replaceChildren();
    option(control, '', selected ? 'Test adımları yükleniyor' : 'Önce denetim seçin');
    control.disabled = true;
    updateSubmit();
    if (!state.engagements.some(item => item.id === selected)) return;
    try {
      const response = await fetch('/api/engagements/' + encodeURIComponent(selected), { cache: 'no-store' });
      if (!response.ok) throw new Error('control list unavailable');
      const data = await response.json();
      if (data.id !== selected || !eligible(data) || !Array.isArray(data.tests)) throw new Error('invalid engagement');
      if (generation !== state.generation || engagement.value !== selected) return;
      control.replaceChildren();
      option(control, '', data.tests.length ? 'Test adımı seçin' : 'Test adımı yok');
      for (const item of data.tests) {
        if (typeof item.control_id === 'string' && typeof item.title === 'string') {
          option(control, item.control_id, item.control_id + ' · ' + item.title);
        }
      }
      control.disabled = control.options.length < 2;
    } catch (_) {
      if (generation !== state.generation || engagement.value !== selected) return;
      control.replaceChildren();
      option(control, '', 'Test adımları yüklenemedi');
      control.disabled = true;
      message(error, 'Test adımları alınamadı.');
    }
    updateSubmit();
  }

  async function submitLink(event) {
    event.preventDefault();
    if (submit.disabled || state.busy) return;
    const selected = engagement.value;
    const selectedControl = control.value;
    if (!state.engagements.some(item => item.id === selected) || !selectedControl || !consent.checked) return;
    const generation = state.generation;
    state.busy = true;
    updateSubmit();
    message(error, '');
    message(result, '');
    try {
      let raw = paste.value.trim();
      if (!raw && file.files[0]) {
        if (file.files[0].size > 60000) throw new Error('size');
        raw = await file.files[0].text();
      }
      if (!raw || new TextEncoder().encode(raw).length > 60000) throw new Error('size');
      const report = JSON.parse(raw);
      if (!report || typeof report !== 'object' || Array.isArray(report)) throw new Error('shape');
      const body = JSON.stringify({ control_id: selectedControl, report, confirm_link: true });
      if (new TextEncoder().encode(body).length > 65536) throw new Error('size');
      const response = await fetch('/api/engagements/' + encodeURIComponent(selected) + '/tool-evidence/zap-traditional-json', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body
      });
      if (!response.ok) throw new Error('link rejected');
      const data = await response.json();
      if (data.tool_identity !== 'zap-traditional-json' ||
          typeof data.report_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(data.report_sha256) ||
          !Number.isSafeInteger(data.site_count) || data.site_count < 0 || data.site_count > 20 ||
          !Number.isSafeInteger(data.alert_type_count) || data.alert_type_count < 0 || data.alert_type_count > 500 ||
          !Number.isSafeInteger(data.instance_count) || data.instance_count < 0 || data.instance_count > 5000 ||
          !data.risk_counts || typeof data.risk_counts !== 'object' || Array.isArray(data.risk_counts)) {
        throw new Error('invalid summary');
      }
      const risks = ['informational', 'low', 'medium', 'high'];
      if (Object.keys(data.risk_counts).length !== risks.length ||
          !risks.every(key => Number.isSafeInteger(data.risk_counts[key]) && data.risk_counts[key] >= 0) ||
          risks.reduce((sum, key) => sum + data.risk_counts[key], 0) !== data.alert_type_count) {
        throw new Error('invalid counts');
      }
      if (generation !== state.generation) return;
      message(result, 'Toplu ZAP kanıtı ' + selectedControl + ' test adımına bağlandı. Uzman incelemesi gerekir; ham rapor saklanmaz ve SHA-256 hedef/provenans kanıtı değildir.');
      paste.value = '';
      file.value = '';
      consent.checked = false;
    } catch (_) {
      if (generation === state.generation) message(error, 'ZAP raporu bağlanamadı. Biçimi, boyutu, açık onayı ve denetim yetkisini kontrol edin.');
    } finally {
      state.busy = false;
      updateSubmit();
    }
  }

  function init() {
    form = get('form');
    paste = get('paste');
    file = get('file');
    engagement = get('engagement');
    control = get('control');
    consent = get('consent');
    submit = get('submit');
    error = get('error');
    result = get('result');
    if (![form, paste, file, engagement, control, consent, submit, error, result].every(Boolean)) return;
    const open = document.querySelector('[data-action="open-zap-preview"]');
    const modal = document.getElementById('zap-preview-modal');
    if (!open || !modal) return;
    open.addEventListener('click', () => { void loadEngagements(); });
    engagement.addEventListener('change', () => { void loadControls(); });
    control.addEventListener('change', updateSubmit);
    consent.addEventListener('change', updateSubmit);
    form.addEventListener('submit', submitLink);
    document.addEventListener('click', event => {
      if (event.target.closest?.('[data-close="zap-preview-modal"]') || event.target === modal) reset();
    });
  }
  document.addEventListener('DOMContentLoaded', init);
}());
