(function () {
  'use strict';
  const prefix = 'trufflehog-git-history-';
  const get = suffix => document.getElementById(prefix + suffix);
  const state = { pending: false, generation: 0 };
  let modal, path, consent, submit, error, result, opener;

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
    consent.checked = false;
    error.textContent = '';
    error.classList.add('hidden');
    result.classList.add('hidden');
    for (const suffix of ['total', 'unverified', 'detectors', 'report-sha256']) get(suffix).textContent = '';
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
    reset();
    opener?.focus();
  }

  function onKeydown(event) {
    if (modal.classList.contains('hidden') || (event.key !== 'Escape' && event.key !== 'Tab')) return;
    const top = topVisibleBackdrop();
    if (event.key === 'Escape') {
      if (top !== modal) return; // another visible dialog owns its own keyboard event
      event.preventDefault();
      event.stopImmediatePropagation();
      close();
      return;
    }
    if (top !== modal) return;
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

  function validSummary(data) {
    if (!data || data.format !== 'trufflehog-native-json-records' ||
        data.profile !== 'local-git-history-no-verification-v1' ||
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
      const response = await fetch('/api/tool-runs/trufflehog-git-history', {
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
        error.textContent = 'Yerel Git geçmişi taraması başlatılamadı veya geçerli bir toplu sonuç alınamadı.';
        error.classList.remove('hidden');
      }
    } finally {
      state.pending = false;
      updateSubmit();
    }
  }

  function init() {
    opener = document.querySelector('[data-action="open-trufflehog-git-history"]');
    modal = get('modal'); path = get('path'); consent = get('consent');
    submit = get('submit'); error = get('error'); result = get('result');
    const form = get('form');
    if (!opener || !modal || !path || !consent || !submit || !error || !result || !form) return;
    opener.addEventListener('click', event => {
      event.preventDefault();
      state.generation += 1;
      reset();
      modal.classList.remove('hidden');
      focusFirst();
    });
    document.addEventListener('keydown', onKeydown, true);
    path.addEventListener('input', updateSubmit);
    consent.addEventListener('change', updateSubmit);
    form.addEventListener('submit', onSubmit);
    document.addEventListener('click', event => {
      if (event.target.closest?.('[data-close="trufflehog-git-history-modal"]') || event.target === modal) close();
    });
  }
  document.addEventListener('DOMContentLoaded', init);
}());
