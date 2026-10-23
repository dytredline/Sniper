(function () {
  'use strict';
  const prefix = 'trufflehog-filesystem-';
  const get = suffix => document.getElementById(prefix + suffix);
  const state = { pending: false, generation: 0 };
  let opener, modal, closeButton, path, consent, submit, error, result;
  let initialized = false;
  let opened = false;

  function validPath() {
    const value = path.value;
    if (!value.startsWith('/home/') || value.length > 1024 || /[\x00-\x1f\x7f]/.test(value)) return false;
    const segments = value.split('/');
    return segments.length >= 4 && /^[A-Za-z0-9._-]+$/.test(segments[2]) &&
      segments[2] !== '.' && segments[2] !== '..' &&
      segments.slice(3).every(segment => segment && segment !== '.' && segment !== '..');
  }

  function updateSubmit() {
    submit.disabled = state.pending || !consent.checked || !validPath();
  }

  function reset() {
    path.value = '';
    consent.checked = false;
    error.textContent = '';
    error.classList.add('hidden');
    result.classList.add('hidden');
    for (const suffix of ['total', 'unverified', 'detectors', 'report-sha256']) get(suffix).textContent = '';
    updateSubmit();
  }

  function dialogVisible() {
    return Boolean(modal && !modal.classList.contains('hidden'));
  }

  function focusTargets() {
    if (!dialogVisible()) return [];
    return [closeButton, path, consent, submit].filter(control =>
      control && !control.disabled && control.getAttribute?.('aria-hidden') !== 'true' &&
      !(typeof control.tabIndex === 'number' && control.tabIndex < 0)
    );
  }

  function close() {
    if (!opened && !dialogVisible()) return;
    opened = false;
    state.generation += 1;
    modal.classList.add('hidden');
    reset();
    opener?.focus?.();
  }

  function handleKeyboard(event) {
    if (!dialogVisible()) return;
    if (event.key === 'Escape') {
      event.preventDefault?.();
      event.stopImmediatePropagation?.();
      close();
      return;
    }
    if (event.key !== 'Tab') return;
    const controls = focusTargets();
    event.preventDefault?.();
    if (!controls.length) return;
    const current = controls.indexOf(document.activeElement);
    const next = event.shiftKey
      ? (current <= 0 ? controls.length - 1 : current - 1)
      : (current < 0 || current === controls.length - 1 ? 0 : current + 1);
    controls[next].focus?.();
  }

  function validSummary(data) {
    if (!data || data.format !== 'trufflehog-native-json-records' ||
        data.profile !== 'local-filesystem-no-verification-v1' ||
        typeof data.report_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(data.report_sha256)) return false;
    for (const key of ['total_findings', 'verified_findings', 'unverified_findings', 'detectors_triggered']) {
      if (!Number.isInteger(data[key]) || data[key] < 0 || data[key] > 500) return false;
    }
    return data.total_findings === data.verified_findings + data.unverified_findings &&
      data.verified_findings === 0 && data.detectors_triggered <= data.total_findings;
  }

  async function onSubmit(event) {
    event.preventDefault();
    if (state.pending || !consent.checked || !validPath()) return;
    const generation = state.generation;
    const projectPath = path.value;
    state.pending = true;
    updateSubmit();
    error.classList.add('hidden');
    result.classList.add('hidden');
    try {
      const response = await fetch('/api/tool-runs/trufflehog-filesystem', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm_local: true, project_path: projectPath })
      });
      if (!response.ok) throw new Error('scanner unavailable');
      const data = await response.json();
      if (!validSummary(data)) throw new Error('invalid aggregate');
      if (generation !== state.generation) return;
      get('total').textContent = String(data.total_findings);
      get('unverified').textContent = String(data.unverified_findings);
      get('detectors').textContent = String(data.detectors_triggered);
      get('report-sha256').textContent = data.report_sha256;
      result.classList.remove('hidden');
    } catch (_) {
      if (generation === state.generation) {
        error.textContent = 'Yerel dosya taraması başlatılamadı veya geçerli bir toplu sonuç alınamadı.';
        error.classList.remove('hidden');
      }
    } finally {
      state.pending = false;
      updateSubmit();
    }
  }

  function init() {
    if (initialized) return;
    opener = document.querySelector('[data-action="open-trufflehog-filesystem"]');
    modal = get('modal'); path = get('path'); consent = get('consent');
    submit = get('submit'); error = get('error'); result = get('result');
    const form = get('form');
    closeButton = modal?.querySelector?.('[data-close="trufflehog-filesystem-modal"]') ||
      document.querySelector?.('[data-close="trufflehog-filesystem-modal"]') || null;
    if (!opener || !modal || !path || !consent || !submit || !error || !result || !form) return;
    initialized = true;
    opener.addEventListener('click', event => {
      event.preventDefault();
      state.generation += 1;
      reset();
      modal.classList.remove('hidden');
      opened = true;
      focusTargets()[0]?.focus?.();
    });
    path.addEventListener('input', updateSubmit);
    consent.addEventListener('change', updateSubmit);
    form.addEventListener('submit', onSubmit);
    closeButton?.addEventListener?.('click', event => {
      event.preventDefault?.();
      close();
    });
    document.addEventListener('click', event => {
      if (event.target === modal || event.target?.closest?.('[data-close="trufflehog-filesystem-modal"]')) close();
    });
    document.addEventListener('keydown', handleKeyboard, true);
  }
  document.addEventListener('DOMContentLoaded', init);
  if (document.readyState === 'interactive' || document.readyState === 'complete') init();
}());
