(function () {
  'use strict';
  const prefix = 'testssl-loopback-full-';
  const severities = ['INFO', 'OK', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'WARN', 'DEBUG', 'FATAL'];
  const get = suffix => document.getElementById(prefix + suffix);
  const state = { pending: false, generation: 0 };
  let modal, port, consent, submit, error, result, opener;

  function validPort() {
    const value = port.value;
    if (!/^[1-9][0-9]{0,4}$/.test(value)) return false;
    const number = Number(value);
    return number >= 1 && number <= 65535;
  }

  function updateSubmit() {
    submit.disabled = state.pending || !consent.checked || !validPort();
  }

  function clearView() {
    consent.checked = false;
    error.textContent = '';
    error.classList.add('hidden');
    result.classList.add('hidden');
    for (const suffix of ['complete', 'record-count', 'severity-counts', 'report-sha256']) {
      get(suffix).textContent = '';
    }
    updateSubmit();
  }

  function focusableControls() {
    return Array.from(modal.querySelectorAll('button, input, select, textarea, a[href], [tabindex]'))
      .filter(node => !node.disabled && node.tabIndex >= 0 && node.getClientRects().length > 0);
  }

  function focusFirst() {
    const first = focusableControls()[0];
    if (first) first.focus();
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

  function showError() {
    error.textContent = 'Yerel tarama başlatılamadı veya geçerli bir toplu sonuç alınamadı.';
    error.classList.remove('hidden');
  }

  function validateSummary(data) {
    if (!data || data.format !== 'testssl-loopback-full-v1' ||
        !Number.isInteger(data.record_count) || data.record_count < 0 || data.record_count > 500 ||
        typeof data.scan_complete !== 'boolean' ||
        !Number.isInteger(data.scanner_exit_code) || data.scanner_exit_code < -255 || data.scanner_exit_code > 255 ||
        (data.scan_complete !== (data.scanner_exit_code === 0)) ||
        typeof data.report_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(data.report_sha256) ||
        !data.severity_counts || typeof data.severity_counts !== 'object' || Array.isArray(data.severity_counts) ||
        Object.keys(data.severity_counts).length !== severities.length) return false;
    let sum = 0;
    for (const key of severities) {
      const value = data.severity_counts[key];
      if (!Number.isInteger(value) || value < 0 || value > 500) return false;
      sum += value;
    }
    return sum === data.record_count;
  }

  async function onSubmit(event) {
    event.preventDefault();
    if (state.pending || !consent.checked || !validPort()) return;
    const generation = state.generation;
    const target = '127.0.0.1:' + Number(port.value);
    state.pending = true;
    updateSubmit();
    error.classList.add('hidden');
    result.classList.add('hidden');
    try {
      const response = await fetch('/api/tool-runs/testssl-full', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm_local: true, target })
      });
      if (!response.ok) throw new Error('scanner unavailable');
      const data = await response.json();
      if (!validateSummary(data)) throw new Error('invalid summary');
      if (generation !== state.generation) return;
      get('complete').textContent = data.scan_complete ? 'Tamamlandı' : 'Kısmi sonuç; tamamlanmadı';
      get('record-count').textContent = String(data.record_count);
      get('severity-counts').textContent = severities.map(key => key + ': ' + data.severity_counts[key]).join(' · ');
      get('report-sha256').textContent = data.report_sha256;
      result.classList.remove('hidden');
    } catch (_) {
      if (generation === state.generation) showError();
    } finally {
      state.pending = false;
      updateSubmit();
    }
  }

  function init() {
    opener = document.querySelector('[data-action="open-testssl-loopback-full"]');
    modal = get('modal');
    port = get('port');
    consent = get('consent');
    submit = get('submit');
    error = get('error');
    result = get('result');
    const form = get('form');
    if (!opener || !modal || !port || !consent || !submit || !error || !result || !form) return;
    opener.addEventListener('click', event => {
      event.preventDefault();
      state.generation += 1;
      clearView();
      modal.classList.remove('hidden');
      focusFirst();
    });
    document.addEventListener('keydown', onKeydown, true);
    port.addEventListener('input', updateSubmit);
    consent.addEventListener('change', updateSubmit);
    form.addEventListener('submit', onSubmit);
    document.addEventListener('click', event => {
      if (event.target.closest?.('[data-close="testssl-loopback-full-modal"]') || event.target === modal) close();
    });
  }
  document.addEventListener('DOMContentLoaded', init);
}());
