(() => {
  'use strict';

  const ids = [
    'zap-authorized-modal', 'zap-authorized-readiness', 'zap-authorized-form',
    'zap-authorized-target', 'zap-authorized-consent', 'zap-authorized-submit',
    'zap-authorized-error', 'zap-authorized-result', 'zap-authorized-result-target',
    'zap-authorized-result-actor', 'zap-authorized-result-time', 'zap-authorized-alert-types',
    'zap-authorized-instances', 'zap-authorized-risks', 'zap-authorized-report-sha256',
    'zap-authorized-run-id'
  ];
  const els = {};
  const state = { ready: false, submitting: false, generation: 0 };

  document.addEventListener('DOMContentLoaded', () => {
    for (const id of ids) els[id] = document.getElementById(id);
    els.open = document.querySelector('[data-action="open-zap-authorized"]');
    if (!els.open || ids.some(id => !els[id])) return;
    els.open.addEventListener('click', open);
    els['zap-authorized-target'].addEventListener('input', updateSubmit);
    els['zap-authorized-consent'].addEventListener('change', updateSubmit);
    els['zap-authorized-form'].addEventListener('submit', submit);
    document.addEventListener('click', event => {
      if (!event.target.closest?.('[data-close="zap-authorized-modal"]')) return;
      state.generation += 1;
      els['zap-authorized-modal'].classList.add('hidden');
      resetRunState();
    });
  });

  function open() {
    state.generation += 1;
    resetRunState();
    els['zap-authorized-modal'].classList.remove('hidden');
    const generation = state.generation;
    els['zap-authorized-readiness'].textContent = 'ZAP çalışma zamanı denetleniyor…';
    fetch('/api/tools/zap/authorized/readiness')
      .then(response => response.ok ? response.json() : Promise.reject(new Error('readiness')))
      .then(data => {
        if (generation !== state.generation || !validReadiness(data)) return;
        state.ready = data.ready === true;
        els['zap-authorized-readiness'].textContent = state.ready
          ? 'Sabitlenmiş ZAP 2.17.0 ve Java 17 çalışma zamanı hazır.'
          : 'Eksik önkoşullar: ' + data.missing.join(' · ');
        updateSubmit();
      })
      .catch(() => {
        if (generation !== state.generation) return;
        state.ready = false;
        els['zap-authorized-readiness'].textContent = 'ZAP çalışma zamanı durumu alınamadı.';
        updateSubmit();
      });
  }

  function resetRunState() {
    state.ready = false;
    state.submitting = false;
    els['zap-authorized-consent'].checked = false;
    els['zap-authorized-submit'].disabled = true;
    els['zap-authorized-error'].textContent = '';
    els['zap-authorized-error'].classList.add('hidden');
    els['zap-authorized-result'].classList.add('hidden');
  }

  function updateSubmit() {
    const target = els['zap-authorized-target'].value.trim();
    els['zap-authorized-submit'].disabled = !state.ready || state.submitting || !target ||
      !els['zap-authorized-consent'].checked;
  }

  function validReadiness(data) {
    return data && typeof data === 'object' && !Array.isArray(data) &&
      data.format === 'zap-authorized-readiness-v1' && typeof data.ready === 'boolean' &&
      Array.isArray(data.missing) && data.missing.every(item => typeof item === 'string');
  }

  function submit(event) {
    event.preventDefault();
    if (state.submitting || !state.ready || !els['zap-authorized-consent'].checked) return;
    const target = els['zap-authorized-target'].value.trim();
    if (!target) return;
    state.submitting = true;
    updateSubmit();
    const generation = state.generation;
    fetch('/api/tool-runs/zap-authorized', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, confirm_authorized: true })
    }).then(async response => {
      const data = await response.json();
      if (!response.ok) {
        if (validReadiness(data.readiness)) {
          state.ready = data.readiness.ready;
          els['zap-authorized-readiness'].textContent = 'Eksik önkoşullar: ' + data.readiness.missing.join(' · ');
        }
        throw new Error('run');
      }
      return data;
    }).then(data => {
      if (generation !== state.generation || !validResult(data)) throw new Error('result');
      render(data);
    }).catch(() => {
      if (generation !== state.generation) return;
      els['zap-authorized-error'].textContent = 'Yetkili ZAP taraması tamamlanamadı.';
      els['zap-authorized-error'].classList.remove('hidden');
    }).finally(() => {
      if (generation !== state.generation) return;
      state.submitting = false;
      els['zap-authorized-consent'].checked = false;
      updateSubmit();
    });
  }

  function validResult(data) {
    if (!data || typeof data !== 'object' || Array.isArray(data)) return false;
    const allowed = new Set(['format', 'profile', 'site_count', 'alert_type_count', 'instance_count',
      'risk_counts', 'report_sha256', 'elapsed_seconds', 'receipt']);
    if (Object.keys(data).length !== allowed.size || Object.keys(data).some(key => !allowed.has(key))) return false;
    if (data.format !== 'zap-authorized-v1' || data.profile !== 'same-origin-authorized-spider-active-v1') return false;
    for (const key of ['site_count', 'alert_type_count', 'instance_count']) {
      if (!Number.isSafeInteger(data[key]) || data[key] < 0) return false;
    }
    if (typeof data.report_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(data.report_sha256)) return false;
    if (typeof data.elapsed_seconds !== 'number' || !Number.isFinite(data.elapsed_seconds) || data.elapsed_seconds < 0 || data.elapsed_seconds > 300) return false;
    const risk = data.risk_counts;
    const riskKeys = ['informational', 'low', 'medium', 'high'];
    if (!risk || Object.keys(risk).length !== 4 || riskKeys.some(key => !Number.isSafeInteger(risk[key]) || risk[key] < 0)) return false;
    const receipt = data.receipt;
    const receiptKeys = ['format', 'run_id', 'actor', 'confirmed_at', 'consent_version', 'target', 'target_sha256'];
    if (!receipt || Object.keys(receipt).length !== receiptKeys.length || receiptKeys.some(key => !(key in receipt))) return false;
    return receipt.format === 'zap-authorization-receipt-v1' &&
      /^zaprun_[0-9a-f]{16}$/.test(receipt.run_id) && receipt.consent_version === 'zap-authorized-consent-v1' &&
      typeof receipt.target === 'string' && /^[0-9a-f]{64}$/.test(receipt.target_sha256) &&
      receipt.actor && typeof receipt.actor.id === 'string' && typeof receipt.confirmed_at === 'string';
  }

  function render(data) {
    const receipt = data.receipt;
    els['zap-authorized-result-target'].textContent = receipt.target;
    els['zap-authorized-result-actor'].textContent = receipt.actor.username + ' (' + receipt.actor.id + ')';
    els['zap-authorized-result-time'].textContent = receipt.confirmed_at;
    els['zap-authorized-alert-types'].textContent = String(data.alert_type_count);
    els['zap-authorized-instances'].textContent = String(data.instance_count);
    els['zap-authorized-risks'].textContent = ['informational', 'low', 'medium', 'high']
      .map(key => key + ': ' + data.risk_counts[key]).join(', ');
    els['zap-authorized-report-sha256'].textContent = data.report_sha256;
    els['zap-authorized-run-id'].textContent = receipt.run_id;
    els['zap-authorized-error'].classList.add('hidden');
    els['zap-authorized-result'].classList.remove('hidden');
  }
})();
