(function() {
  'use strict';

  const MODAL_ID = 'zap-target-spider-modal';

  const els = {
    openBtn: null,
    modal: null,
    choices: null,
    targetSelect: null,
    engagementSelect: null,
    targetUrl: null,
    engagementName: null,
    engagementStatus: null,
    authRef: null,
    scope: null,
    outOfScope: null,
    window: null,
    error: null,
    form: null,
    submitBtn: null,
    consent1: null,
    consent2: null,
    result: null,
    resultFormat: null,
    resultProfile: null,
    resultSiteCount: null,
    resultAlertTypeCount: null,
    resultInstanceCount: null,
    resultRiskCounts: null,
    resultReportSha256: null
  };

  const state = {
    targets: [],
    engagements: [],
    selectedTargetId: null,
    selectedEngagementId: null,
    isSubmitting: false,
    loadGeneration: 0
  };

  function init() {
    els.openBtn = document.querySelector('[data-action="open-zap-target-spider"]');
    els.modal = document.getElementById(MODAL_ID);
    els.choices = document.getElementById('zap-target-spider-choices');
    els.targetSelect = document.getElementById('zap-target-spider-target');
    els.engagementSelect = document.getElementById('zap-target-spider-engagement');
    els.targetUrl = document.getElementById('zap-target-spider-target-url');
    els.engagementName = document.getElementById('zap-target-spider-engagement-name');
    els.engagementStatus = document.getElementById('zap-target-spider-engagement-status');
    els.authRef = document.getElementById('zap-target-spider-auth-ref');
    els.scope = document.getElementById('zap-target-spider-scope');
    els.outOfScope = document.getElementById('zap-target-spider-out-of-scope');
    els.window = document.getElementById('zap-target-spider-window');
    els.error = document.getElementById('zap-target-spider-error');
    els.form = document.getElementById('zap-target-spider-form');
    els.submitBtn = document.getElementById('zap-target-spider-submit');
    els.consent1 = document.getElementById('zap-target-spider-consent-1');
    els.consent2 = document.getElementById('zap-target-spider-consent-2');
    els.result = document.getElementById('zap-target-spider-result');
    els.resultFormat = document.getElementById('zap-target-spider-format');
    els.resultProfile = document.getElementById('zap-target-spider-profile');
    els.resultSiteCount = document.getElementById('zap-target-spider-site-count');
    els.resultAlertTypeCount = document.getElementById('zap-target-spider-alert-type-count');
    els.resultInstanceCount = document.getElementById('zap-target-spider-instance-count');
    els.resultRiskCounts = document.getElementById('zap-target-spider-risk-counts');
    els.resultReportSha256 = document.getElementById('zap-target-spider-report-sha256');

    if (els.openBtn) {
      els.openBtn.addEventListener('click', handleOpen);
    }
    if (els.targetSelect) {
      els.targetSelect.addEventListener('change', handleTargetChange);
    }
    if (els.engagementSelect) {
      els.engagementSelect.addEventListener('change', handleEngagementChange);
    }
    if (els.form) {
      els.form.addEventListener('submit', handleSubmit);
    }
    for (const consent of [els.consent1, els.consent2]) {
      if (consent) consent.addEventListener('change', () => {
        els.submitBtn.disabled = !isSubmitReady();
      });
    }
    document.addEventListener('click', event => {
      const close = event.target.closest?.('[data-close="zap-target-spider-modal"]');
      if (close || event.target === els.modal) {
        state.loadGeneration += 1;
        els.modal.classList.add('hidden');
        resetState();
      }
    });
  }

  function resetState() {
    state.selectedTargetId = null;
    state.selectedEngagementId = null;
    state.isSubmitting = false;

    els.choices.classList.add('hidden');
    els.error.classList.add('hidden');
    els.form.classList.add('hidden');
    els.result.classList.add('hidden');

    els.targetSelect.innerHTML = '';
    els.targetSelect.disabled = false;

    els.engagementSelect.innerHTML = '';
    els.engagementSelect.disabled = true;

    els.targetUrl.textContent = '';
    els.engagementName.textContent = '';
    els.engagementStatus.textContent = '';
    els.authRef.textContent = '';
    els.scope.textContent = '';
    els.outOfScope.textContent = '';
    els.window.textContent = '';

    els.consent1.checked = false;
    els.consent2.checked = false;
    els.submitBtn.disabled = true;
  }

  function handleOpen() {
    const loadGeneration = ++state.loadGeneration;
    resetState();
    els.modal.classList.remove('hidden');

    Promise.all([
      fetch('/api/targets').then(r => {
        if (!r.ok) throw new Error('GET failed');
        return r.json();
      }),
      fetch('/api/engagements').then(r => {
        if (!r.ok) throw new Error('GET failed');
        return r.json();
      })
    ]).then(([targetsData, engagementsData]) => {
      if (loadGeneration !== state.loadGeneration) return;
      const targets = targetsData.targets || [];
      const engagements = engagementsData.engagements || [];

      if (!Array.isArray(targets) || !Array.isArray(engagements)) {
        showGenericError();
        return;
      }

      state.targets = targets;
      state.engagements = engagements;

      populateTargetSelect();
    }).catch(() => {
      if (loadGeneration === state.loadGeneration) showGenericError();
    });
  }

  function populateTargetSelect() {
    if (!state.targets || !Array.isArray(state.targets)) {
      showGenericError();
      return;
    }

    els.targetSelect.innerHTML = '';
    const placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.textContent = 'Seçiniz...';
    placeholder.disabled = true;
    placeholder.selected = true;
    els.targetSelect.appendChild(placeholder);

    state.targets.forEach(t => {
      if (t && typeof t.id === 'string' && t.id && isCanonicalRootTarget(t)) {
        const opt = document.createElement('option');
        opt.value = t.id;
        opt.textContent = t.url || 'Hedef';
        els.targetSelect.appendChild(opt);
      }
    });

    if (els.targetSelect.options.length <= 1) {
      showGenericError();
      return;
    }

    els.choices.classList.remove('hidden');
    els.targetSelect.disabled = false;
  }

  function handleTargetChange(e) {
    if (state.isSubmitting) {
      e.target.value = state.selectedTargetId || '';
      return;
    }
    const targetId = e.target.value;
    state.selectedTargetId = targetId || null;
    state.selectedEngagementId = null;
    els.engagementSelect.disabled = true;
    els.engagementSelect.innerHTML = '';
    els.targetUrl.textContent = '';
    els.engagementName.textContent = '';
    els.engagementStatus.textContent = '';
    els.authRef.textContent = '';
    els.scope.textContent = '';
    els.outOfScope.textContent = '';
    els.window.textContent = '';
    els.consent1.checked = false;
    els.consent2.checked = false;
    els.submitBtn.disabled = true;
    els.form.classList.add('hidden');
    els.result.classList.add('hidden');
    els.error.classList.add('hidden');

    if (!targetId) return;

    const target = state.targets.find(t => t && t.id === targetId);
    if (target && typeof target.url === 'string') {
      els.targetUrl.textContent = target.url;
    }

    const matchingEngagements = (state.engagements || []).filter(e => e && e.target_id === targetId);
    populateEngagementSelect(matchingEngagements);
  }

  function populateEngagementSelect(matches) {
    els.engagementSelect.innerHTML = '';
    const placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.textContent = 'Seçiniz...';
    placeholder.disabled = true;
    placeholder.selected = true;
    els.engagementSelect.appendChild(placeholder);

    if (!Array.isArray(matches)) {
      showGenericError();
      return;
    }

    matches.forEach(e => {
      if (e && typeof e.id === 'string' && e.id) {
        const opt = document.createElement('option');
        opt.value = e.id;
        let label = e.name || 'Denetim';
        if (e.status && e.status !== 'active') {
          label += ` (${e.status})`;
        }
        if (e.out_of_scope && e.out_of_scope.trim()) {
          label += ' (Dışlananlar var)';
        }
        if (e.authorization_ref && !e.authorization_ref.trim()) {
          label += ' (Yetersiz yetki)';
        }
        if (e.scope_notes && !e.scope_notes.trim()) {
          label += ' (Yetersiz kapsam)';
        }
        opt.textContent = label;
        els.engagementSelect.appendChild(opt);
      }
    });

    if (els.engagementSelect.options.length > 1) {
      els.engagementSelect.disabled = false;
    } else {
      els.engagementSelect.disabled = true;
    }
  }

  function handleEngagementChange(e) {
    if (state.isSubmitting) {
      e.target.value = state.selectedEngagementId || '';
      return;
    }
    const engagementId = e.target.value;
    state.selectedEngagementId = engagementId || null;
    els.consent1.checked = false;
    els.consent2.checked = false;
    els.result.classList.add('hidden');
    els.error.classList.add('hidden');

    if (!engagementId) {
      els.submitBtn.disabled = true;
      els.form.classList.add('hidden');
      return;
    }

    const engagement = (state.engagements || []).find(en => en && en.id === engagementId);
    if (!engagement) {
      els.submitBtn.disabled = true;
      els.form.classList.add('hidden');
      return;
    }

    const target = (state.targets || []).find(t => t && t.id === state.selectedTargetId);

    // Display details
    els.engagementName.textContent = engagement.name || '';
    els.engagementStatus.textContent = engagement.status || '';
    els.authRef.textContent = engagement.authorization_ref || '';
    els.scope.textContent = engagement.scope_notes || '';
    els.outOfScope.textContent = engagement.out_of_scope || '(yok)';
    els.window.textContent = engagement.test_window || '';

    // Validate selection for submit (including exact URL match)
    const isValid = validateEngagement(engagement, target);

    if (isValid) {
      els.form.classList.remove('hidden');
      els.submitBtn.disabled = !isSubmitReady();
    } else {
      els.submitBtn.disabled = true;
      els.form.classList.add('hidden');
    }
  }

  function validateEngagement(engagement, target) {
    if (!engagement || !target) return false;

    // Must match
    if (engagement.target_id !== target.id) return false;

    // Exact target URL match
    if (engagement.target_url !== target.url) return false;

    // Active status
    if (engagement.status !== 'active') return false;

    // Nonempty auth_ref
    if (typeof engagement.authorization_ref !== 'string' || !engagement.authorization_ref.trim()) return false;

    // Nonempty scope_notes
    if (typeof engagement.scope_notes !== 'string' || !engagement.scope_notes.trim()) return false;

    // Only literal, segment-bounded exclusions in the stored engagement are accepted.
    if (!isValidScopePrefixes(engagement.out_of_scope)) return false;
    if (!isCanonicalRootTarget(target)) return false;

    // test_window validation
    const windowStr = engagement.test_window;
    if (!isValidTestWindow(windowStr)) return false;

    return true;
  }

  function isCanonicalRootTarget(target) {
    if (!target || typeof target.url !== 'string') return false;
    try {
      const url = new URL(target.url);
      return (url.protocol === 'http:' || url.protocol === 'https:') &&
        url.pathname === '/' && !url.search && !url.hash &&
        !url.username && !url.password && url.href === target.url;
    } catch (_) {
      return false;
    }
  }

  function isValidScopePrefixes(raw) {
    if (typeof raw !== 'string') return false;
    if (raw === '') return true;
    try {
      const paths = JSON.parse(raw);
      if (!Array.isArray(paths) || paths.length === 0 || paths.length > 16) return false;
      const seen = new Set();
      for (const path of paths) {
        if (typeof path !== 'string' ||
            !/^\/[A-Za-z0-9_~-]+(?:\/[A-Za-z0-9_~-]+)*$/.test(path) || seen.has(path)) return false;
        seen.add(path);
      }
      return true;
    } catch (_) {
      return false;
    }
  }

  function isValidTestWindow(raw) {
    if (typeof raw !== 'string' || raw.length !== 41) return false;
    const re = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
    if (!re.test(raw)) return false;

    const [startStr, endStr] = raw.split('/');
    // Exact parsing: do NOT let JS Date auto-correct
    const startVal = Date.parse(startStr);
    const endVal = Date.parse(endStr);
    if (Number.isNaN(startVal) || Number.isNaN(endVal)) return false;

    // Verify roundtrip matches input after removing milliseconds (.000Z) from JS ISO string
    const startDt = new Date(startStr);
    const endDt = new Date(endStr);
    if (startDt.toISOString().replace(/\.\d{3}Z$/, 'Z') !== startStr ||
        endDt.toISOString().replace(/\.\d{3}Z$/, 'Z') !== endStr) return false;

    // Constraint checks
    const now = Date.now();
    if (startVal >= endVal) return false;
    if (startVal > now) return false;
    if (endVal < now + 300000) return false;
    if ((endVal - startVal) > 24 * 60 * 60 * 1000) return false;

    return true;
  }

  function handleSubmit(e) {
    e.preventDefault();

    if (state.isSubmitting || els.modal.classList.contains('hidden')) return;

    const target = (state.targets || []).find(t => t && t.id === state.selectedTargetId);
    const engagement = (state.engagements || []).find(en => en && en.id === state.selectedEngagementId);

    // Final validation including time window
    if (!validateEngagement(engagement, target)) {
      showGenericError();
      return;
    }

    // Consent validation
    if (!els.consent1.checked || !els.consent2.checked) {
      showGenericError();
      return;
    }

    state.isSubmitting = true;
    els.submitBtn.disabled = true;
    els.targetSelect.disabled = true;
    els.engagementSelect.disabled = true;

    const payload = {
      target_id: target.id,
      engagement_id: engagement.id,
      confirm_authorized: true,
      confirm_crawl: true
    };
    const generation = state.loadGeneration;

    fetch('/api/tool-runs/zap-target-spider', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).then(r => {
      if (!r.ok) {
        throw new Error('Bad response');
      }
      return r.json();
    }).then(data => {
      if (generation !== state.loadGeneration) return;
      const validated = validateResponse(data);
      if (validated) {
        renderResult(data);
      } else {
        showGenericError();
      }
    }).catch(() => {
      if (generation === state.loadGeneration) showGenericError();
    }).finally(() => {
      if (generation !== state.loadGeneration) return;
      state.isSubmitting = false;
      els.targetSelect.disabled = false;
      els.engagementSelect.disabled = els.engagementSelect.options.length <= 1;
      resetConsents();
      els.submitBtn.disabled = !isSubmitReady();
    });
  }

  function validateResponse(data) {
    if (!data || typeof data !== 'object' || Array.isArray(data)) return false;

    const allowedKeys = new Set([
      'format', 'profile', 'site_count', 'alert_type_count',
      'instance_count', 'risk_counts', 'report_sha256', 'elapsed_seconds'
    ]);

    const actualKeys = Object.keys(data);
    if (actualKeys.length !== allowedKeys.size ||
        actualKeys.some(k => !allowedKeys.has(k))) return false;

    // format and profile exact
    if (data.format !== 'zap-target-spider-v1' || data.profile !== 'same-origin-root-spider-v1') return false;

    // Counts bounded safe integers >= 0
    if (!isSafeNonNegativeInteger(data.site_count) || data.site_count > 1 ||
        !isSafeNonNegativeInteger(data.alert_type_count) || data.alert_type_count > 500 ||
        !isSafeNonNegativeInteger(data.instance_count) || data.instance_count > 5000) return false;

    // risk_counts: exact keys, safe integers, sum == alert_type_count
    const risk = data.risk_counts;
    if (!risk || typeof risk !== 'object' || Array.isArray(risk)) return false;
    const riskKeys = ['informational', 'low', 'medium', 'high'];
    let riskSum = 0;
    for (const k of riskKeys) {
      if (!isSafeNonNegativeInteger(risk[k]) || risk[k] > 500) return false;
      riskSum += risk[k];
    }
    if (riskSum !== data.alert_type_count) return false;
    // No extra keys in risk_counts
    const riskObjKeys = Object.keys(risk);
    for (const k of riskKeys) {
      if (!riskObjKeys.includes(k)) return false;
    }
    if (riskObjKeys.length !== 4) return false;

    // sha256 lowercase hex 64
    if (typeof data.report_sha256 !== 'string' || data.report_sha256.length !== 64) return false;
    if (!/^[0-9a-f]{64}$/.test(data.report_sha256)) return false;

    // elapsed_seconds finite nonnegative
    if (typeof data.elapsed_seconds !== 'number' || data.elapsed_seconds < 0 ||
        data.elapsed_seconds > 300 || !Number.isFinite(data.elapsed_seconds)) return false;

    return true;
  }

  function isSafeNonNegativeInteger(v) {
    return Number.isInteger(v) && v >= 0 && v <= 2 ** 53 - 1;
  }

  function renderResult(data) {
    els.resultFormat.textContent = data.format || '';
    els.resultProfile.textContent = data.profile || '';
    els.resultSiteCount.textContent = String(data.site_count ?? 0);
    els.resultAlertTypeCount.textContent = String(data.alert_type_count ?? 0);
    els.resultInstanceCount.textContent = String(data.instance_count ?? 0);

    // risk_counts display: label: value (low, medium, high etc)
    const rc = data.risk_counts || {};
    const riskStr = 'informational: ' + (rc.informational ?? 0)
      + ', low: ' + (rc.low ?? 0)
      + ', medium: ' + (rc.medium ?? 0)
      + ', high: ' + (rc.high ?? 0);
    els.resultRiskCounts.textContent = riskStr;

    els.resultReportSha256.textContent = data.report_sha256 || '';

    els.result.classList.remove('hidden');
  }

  function resetConsents() {
    els.consent1.checked = false;
    els.consent2.checked = false;
  }

  function isSubmitReady() {
    if (state.isSubmitting) return false;
    if (!state.selectedTargetId || !state.selectedEngagementId) return false;
    if (!els.consent1.checked || !els.consent2.checked) return false;
    const target = (state.targets || []).find(t => t && t.id === state.selectedTargetId);
    const engagement = (state.engagements || []).find(e => e && e.id === state.selectedEngagementId);
    return validateEngagement(engagement, target);
  }

  function showGenericError() {
    els.error.textContent = 'İşlem sırasında bir hata oluştu. Lütfen tekrar deneyin.';
    els.error.classList.remove('hidden');
  }

  document.addEventListener('DOMContentLoaded', init);
})();
