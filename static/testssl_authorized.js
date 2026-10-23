(function () {
  'use strict';
  const prefix = 'testssl-authorized-';
  const severities = ['INFO', 'OK', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'WARN', 'DEBUG', 'FATAL'];
  const profiles = new Set(['protocols', 'full']);
  const get = suffix => document.getElementById(prefix + suffix);
  const state = { pending: false, generation: 0 };
  let modal, target, profile, consent, submit, status, error, result, opener;

  function validTarget() {
    const value = target.value.trim();
    return value.length > 2 && value.length <= 320 && !/[\u0000-\u0020\u007f]/.test(value);
  }

  function updateSubmit() {
    submit.disabled = state.pending || !consent.checked || !validTarget() || !profiles.has(profile.value);
  }

  function revokeConsent() {
    consent.checked = false;
    updateSubmit();
  }

  function clearView() {
    consent.checked = false;
    status.textContent = 'Hedef, çalışma başlamadan önce tek IP\'ye sabitlenecektir.';
    error.textContent = '';
    error.classList.add('hidden');
    result.classList.add('hidden');
    for (const suffix of ['complete', 'record-count', 'severity-counts', 'report-sha256', 'confirmed-at']) {
      get(suffix).textContent = '';
    }
    updateSubmit();
  }

  function focusableControls() {
    return Array.from(modal.querySelectorAll('button, input, select, textarea, a[href], [tabindex]'))
      .filter(node => !node.disabled && node.tabIndex >= 0 && node.getClientRects().length > 0);
  }

  function topVisibleBackdrop() {
    const visible = document.querySelectorAll('.modal-backdrop:not(.hidden), .drawer-backdrop:not(.hidden), .workspace-backdrop:not(.hidden)');
    let top = null, topZ = -Infinity;
    for (const node of visible) {
      const parsed = Number.parseInt(getComputedStyle(node).zIndex, 10);
      const z = Number.isFinite(parsed) ? parsed : 0;
      if (z >= topZ) { top = node; topZ = z; }
    }
    return top;
  }

  function close() {
    state.generation += 1;
    modal.classList.add('hidden');
    clearView();
    opener?.focus();
  }

  function onKeydown(event) {
    if (modal.classList.contains('hidden') || (event.key !== 'Escape' && event.key !== 'Tab')) return;
    if (topVisibleBackdrop() !== modal) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      event.stopImmediatePropagation();
      close();
      return;
    }
    const controls = focusableControls();
    if (!controls.length) return;
    const active = document.activeElement;
    if (!modal.contains(active)) {
      event.preventDefault();
      controls[event.shiftKey ? controls.length - 1 : 0].focus();
    } else if (event.shiftKey && active === controls[0]) {
      event.preventDefault();
      controls[controls.length - 1].focus();
    } else if (!event.shiftKey && active === controls[controls.length - 1]) {
      event.preventDefault();
      controls[0].focus();
    }
  }

  function validSummary(data, selectedProfile) {
    const receipt = data?.authorization_receipt;
    if (!data || data.format !== 'testssl-authorized-v1' ||
        data.profile !== `authorized-${selectedProfile}-v1` ||
        !Number.isInteger(data.record_count) || data.record_count < 0 || data.record_count > 500 ||
        !/^[0-9a-f]{64}$/.test(data.report_sha256 || '') ||
        !/^[0-9a-f]{64}$/.test(data.target_sha256 || '') ||
        !/^[0-9a-f]{64}$/.test(data.resolved_ip_sha256 || '') ||
        receipt?.consent_version !== 'direct-target-authorization-v1' ||
        receipt?.confirm_authorized !== true || typeof receipt?.confirmed_at !== 'string' ||
        !data.severity_counts || typeof data.severity_counts !== 'object' || Array.isArray(data.severity_counts) ||
        Object.keys(data.severity_counts).length !== severities.length) return false;
    if (selectedProfile === 'full' &&
        (typeof data.scan_complete !== 'boolean' || !Number.isInteger(data.scanner_exit_code) ||
         data.scan_complete !== (data.scanner_exit_code === 0))) return false;
    let total = 0;
    for (const key of severities) {
      const value = data.severity_counts[key];
      if (!Number.isInteger(value) || value < 0 || value > 500) return false;
      total += value;
    }
    return total === data.record_count;
  }

  async function onSubmit(event) {
    event.preventDefault();
    if (state.pending || !consent.checked || !validTarget() || !profiles.has(profile.value)) return;
    const generation = state.generation;
    const requestedTarget = target.value.trim();
    const requestedProfile = profile.value;
    state.pending = true;
    updateSubmit();
    error.classList.add('hidden');
    result.classList.add('hidden');
    status.textContent = 'testssl.sh taraması çalışıyor…';
    try {
      const response = await fetch('/api/tool-runs/testssl-authorized', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: requestedTarget, profile: requestedProfile, confirm_authorized: true }),
      });
      if (!response.ok) throw new Error('scanner unavailable');
      const data = await response.json();
      if (!validSummary(data, requestedProfile)) throw new Error('invalid summary');
      if (generation !== state.generation) return;
      get('complete').textContent = requestedProfile === 'full'
        ? (data.scan_complete ? 'Tamamlandı' : 'Kısmi sonuç; tamamlanmadı') : 'Tamamlandı';
      get('record-count').textContent = String(data.record_count);
      get('severity-counts').textContent = severities.map(key => `${key}: ${data.severity_counts[key]}`).join(' · ');
      get('report-sha256').textContent = data.report_sha256;
      get('confirmed-at').textContent = data.authorization_receipt.confirmed_at;
      result.classList.remove('hidden');
      status.textContent = 'Tarama tamamlandı; sonuç hedef ayrıntısı içermeyen toplu özettir.';
    } catch (_) {
      if (generation === state.generation) {
        status.textContent = '';
        error.textContent = 'Tarama başlatılamadı veya geçerli bir toplu sonuç alınamadı.';
        error.classList.remove('hidden');
      }
    } finally {
      state.pending = false;
      consent.checked = false;
      updateSubmit();
    }
  }

  function init() {
    opener = document.querySelector('[data-action="open-testssl-authorized"]');
    modal = get('modal');
    target = get('target');
    profile = get('profile');
    consent = get('consent');
    submit = get('submit');
    status = get('status');
    error = get('error');
    result = get('result');
    const form = get('form');
    if (!opener || !modal || !target || !profile || !consent || !submit || !status || !error || !result || !form) return;
    opener.addEventListener('click', event => {
      event.preventDefault();
      state.generation += 1;
      clearView();
      modal.classList.remove('hidden');
      const controls = focusableControls();
      controls[0]?.focus();
    });
    document.addEventListener('keydown', onKeydown, true);
    target.addEventListener('input', revokeConsent);
    profile.addEventListener('change', revokeConsent);
    consent.addEventListener('change', updateSubmit);
    form.addEventListener('submit', onSubmit);
    document.addEventListener('click', event => {
      if (event.target.closest?.('[data-close="testssl-authorized-modal"]') || event.target === modal) close();
    });
  }
  document.addEventListener('DOMContentLoaded', init);
}());
