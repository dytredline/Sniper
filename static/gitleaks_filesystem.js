(function () {
  'use strict';
  const prefix = 'gitleaks-filesystem-';
  const get = suffix => document.getElementById(prefix + suffix);
  const state = { pending: false, generation: 0 };
  let modal, path, consent, submit, error, result, opener;
  let previousOverflow = '';
  let backgroundInert = [];
  const browserDOM = typeof document.querySelectorAll === 'function' && !!document.body?.children;

  function isVisible(node) {
    return !!node?.isConnected && !node.closest?.('.hidden,[hidden],[inert]') &&
      (typeof node.getClientRects !== 'function' || node.getClientRects().length > 0);
  }

  function otherVisibleOverlay() {
    if (!browserDOM) return null;
    return Array.from(document.querySelectorAll('.modal-backdrop,.drawer-backdrop,.workspace-backdrop'))
      .find(node => node !== modal && !node.closest('.hidden,[hidden]') && node.getClientRects().length > 0) || null;
  }

  function lockBackground() {
    if (!browserDOM) return;
    backgroundInert = Array.from(document.body.children)
      .filter(node => node !== modal)
      .map(node => [node, node.inert]);
    for (const [node] of backgroundInert) node.inert = true;
  }

  function unlockBackground() {
    for (const [node, wasInert] of backgroundInert) node.inert = wasInert;
    backgroundInert = [];
  }

  function restoreFocus() {
    const target = browserDOM
      ? (isVisible(opener) ? opener : Array.from(document.querySelectorAll('.nav-item.active,[data-nav="tooling"],#mobile-menu,.main')).find(isVisible))
      : (opener && opener.isConnected !== false ? opener : null);
    if (target && target.tabIndex < 0) target.setAttribute?.('tabindex', '-1');
    target?.focus?.();
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
    if (!home || value.length > 1024 || !value.startsWith(home + '/') || /[\\\x00-\x1f\x7f]/.test(value)) return false;
    return value.slice(home.length + 1).split('/').every(segment => segment && segment !== '.' && segment !== '..');
  }

  function updateSubmit() {
    submit.disabled = state.pending || !consent.checked || !validPath();
  }

  function reset() {
    consent.checked = false;
    error.textContent = '';
    error.classList.add('hidden');
    result.classList.add('hidden');
    for (const suffix of ['total', 'rules', 'files', 'report-sha256']) get(suffix).textContent = '';
    updateSubmit();
  }

  function close() {
    if (modal.classList.contains('hidden')) return;
    state.generation += 1;
    modal.classList.add('hidden');
    unlockBackground();
    if (browserDOM) document.body.style.overflow = otherVisibleOverlay() ? 'hidden' : previousOverflow;
    reset();
    restoreFocus();
    opener = null;
  }

  function focusableControls() {
    const closeButton = modal.querySelector?.('[data-close="gitleaks-filesystem-modal"]');
    return [closeButton, path, consent, submit].filter(control => control && !control.disabled &&
      (typeof control.getClientRects !== 'function' || control.getClientRects().length > 0));
  }

  function onKeydown(event) {
    if (modal.classList.contains('hidden')) return;
    const otherOverlay = document.activeElement?.closest?.(
      '.modal-backdrop:not(.hidden), .drawer-backdrop:not(.hidden), .workspace-backdrop:not(.hidden)');
    if (otherOverlay && otherOverlay !== modal) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      event.stopImmediatePropagation?.();
      close();
      return;
    }
    if (event.key !== 'Tab') return;
    const controls = focusableControls();
    if (!controls.length) return;
    const position = controls.indexOf(document.activeElement);
    if (event.shiftKey && position <= 0) {
      event.preventDefault();
      controls[controls.length - 1].focus();
    } else if (!event.shiftKey && (position < 0 || position === controls.length - 1)) {
      event.preventDefault();
      controls[0].focus();
    }
  }

  function validSummary(data) {
    if (!data || data.format !== 'gitleaks-native-json' ||
        typeof data.report_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(data.report_sha256)) return false;
    for (const key of ['total_findings', 'rules_triggered', 'files_affected']) {
      if (!Number.isInteger(data[key]) || data[key] < 0 || data[key] > 500) return false;
    }
    return data.rules_triggered <= data.total_findings && data.files_affected <= data.total_findings;
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
      const response = await fetch('/api/tool-runs/gitleaks', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm_local: true, project_path: projectPath })
      });
      if (!response.ok) throw new Error('scanner unavailable');
      const data = await response.json();
      if (!validSummary(data)) throw new Error('invalid aggregate');
      if (generation !== state.generation) return;
      get('total').textContent = String(data.total_findings);
      get('rules').textContent = String(data.rules_triggered);
      get('files').textContent = String(data.files_affected);
      get('report-sha256').textContent = data.report_sha256;
      result.classList.remove('hidden');
    } catch (_) {
      if (generation === state.generation) {
        error.textContent = 'Yerel Gitleaks taraması başlatılamadı veya geçerli bir toplu sonuç alınamadı.';
        error.classList.remove('hidden');
      }
    } finally {
      state.pending = false;
      updateSubmit();
    }
  }

  function init() {
    const open = document.querySelector('[data-action="open-gitleaks-filesystem"]');
    modal = get('modal'); path = get('path'); consent = get('consent');
    submit = get('submit'); error = get('error'); result = get('result');
    const form = get('form');
    if (!open || !modal || !path || !consent || !submit || !error || !result || !form) return;
    open.addEventListener('click', event => {
      event.preventDefault();
      if (otherVisibleOverlay()) return;
      state.generation += 1;
      reset();
      opener = open;
      if (browserDOM) previousOverflow = document.body.style.overflow;
      modal.classList.remove('hidden');
      lockBackground();
      if (browserDOM) document.body.style.overflow = 'hidden';
      path.focus?.();
    });
    path.addEventListener('input', updateSubmit);
    consent.addEventListener('change', updateSubmit);
    form.addEventListener('submit', onSubmit);
    document.addEventListener('keydown', onKeydown, true);
    document.addEventListener('focusin', event => {
      if (!modal.classList.contains('hidden') && !modal.contains?.(event.target))
        (focusableControls()[0] || modal).focus?.();
    }, true);
    document.addEventListener('click', event => {
      if (modal.classList.contains('hidden')) return;
      if (event.target.closest?.('[data-close="gitleaks-filesystem-modal"]') || event.target === modal) {
        close();
        return;
      }
      if (!browserDOM || modal.contains(event.target)) return;
      event.preventDefault();
      event.stopImmediatePropagation?.();
    }, true);
  }
  document.addEventListener('DOMContentLoaded', init);
}());
