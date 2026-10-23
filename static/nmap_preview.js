// Passive saved-report preview. It never starts the active Nmap scan.
(() => {
  const byId = id => document.getElementById(id);
  const modal = byId('nmap-xml-preview-modal');
  const input = byId('nmap-xml-paste');
  const fileInput = byId('nmap-xml-file');
  const error = byId('nmap-xml-preview-error');
  // Dil katmanı açıkken görünen metin çevrilmiş olabilir; karşılaştırma özgün (Türkçe) metinle yapılır.
  const errorText = () => (typeof SniperI18n === 'object' && SniperI18n ? SniperI18n.source(error) : error.textContent);
  const result = byId('nmap-xml-preview-result');
  const submit = byId('nmap-xml-preview-submit');
  const linkOptIn = byId('nmap-xml-link-opt-in');
  const linkFields = byId('nmap-xml-link-fields');
  const linkEngagement = byId('nmap-xml-link-engagement');
  const linkControl = byId('nmap-xml-link-control');
  const linkResult = byId('nmap-xml-link-result');
  const fields = ['host-count', 'up-host-count', 'open-port-count', 'protocol-counts', 'port-bands', 'report-sha256'];
  let generation = 0;
  let submitGeneration = 0;
  let optInGeneration = 0;
  let controlGeneration = 0;
  let busy = false;
  let activeSnapshot = null;
  let requestController = null;
  let focusOpener = null;
  let previousOverflow = '';
  let backgroundInert = [];
  const browserDOM = typeof document.querySelectorAll === 'function' && !!document.body?.children;

  function isVisible(node) {
    return !!node?.isConnected && !node.closest('.hidden,[hidden],[inert]') &&
      typeof node.getClientRects === 'function' && node.getClientRects().length > 0;
  }

  function focusableInModal() {
    if (!browserDOM) return [];
    return Array.from(modal.querySelectorAll('a[href],button,input,select,textarea,[tabindex]'))
      .filter(node => !node.disabled && node.tabIndex >= 0 && isVisible(node));
  }

  function focusNode(node) {
    if (typeof node?.focus === 'function') node.focus({ preventScroll: true });
  }

  function otherVisibleOverlay() {
    if (!browserDOM) return null;
    return Array.from(document.querySelectorAll('.modal-backdrop,.drawer-backdrop,.workspace-backdrop'))
      .find(node => node !== modal && !node.closest('.hidden,[hidden]') &&
        node.getClientRects().length > 0) || null;
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
    if (!browserDOM) return;
    const fallback = ['[data-action="open-nmap-xml-preview"]', '.nav-item.active',
      '[data-nav="tooling"]', '#mobile-menu', '.main']
      .map(selector => document.querySelector(selector)).find(isVisible);
    const target = isVisible(focusOpener) ? focusOpener : fallback;
    if (target && target.tabIndex < 0) target.setAttribute('tabindex', '-1');
    focusNode(target);
  }

  function openDialog(trigger) {
    if (otherVisibleOverlay()) return;
    reset();
    focusOpener = trigger;
    previousOverflow = document.body.style.overflow;
    modal.classList.remove('hidden');
    lockBackground();
    document.body.style.overflow = 'hidden';
    focusNode(input);
  }

  function closeDialog() {
    if (modal.classList.contains('hidden')) return;
    reset();
    modal.classList.add('hidden');
    unlockBackground();
    const other = otherVisibleOverlay();
    document.body.style.overflow = other ? 'hidden' : previousOverflow;
    if (other && browserDOM) {
      const next = Array.from(other.querySelectorAll('button,input,select,textarea,a[href],[tabindex]'))
        .find(node => !node.disabled && node.tabIndex >= 0 && isVisible(node));
      if (!next) other.setAttribute('tabindex', '-1');
      focusNode(next || other);
    } else {
      restoreFocus();
    }
    focusOpener = null;
  }

  if (browserDOM) {
    document.addEventListener('click', event => {
      if (modal.classList.contains('hidden')) return;
      if (event.target === modal || event.target.closest?.('[data-close="nmap-xml-preview-modal"]')) {
        event.preventDefault();
        event.stopImmediatePropagation();
        closeDialog();
        return;
      }
      if (modal.contains(event.target)) return;
      event.preventDefault();
      event.stopImmediatePropagation();
    }, true);
    document.addEventListener('focusin', event => {
      if (!modal.classList.contains('hidden') && !modal.contains(event.target))
        focusNode(focusableInModal()[0] || modal);
    }, true);
    document.addEventListener('keydown', event => {
      if (modal.classList.contains('hidden')) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopImmediatePropagation();
        closeDialog();
        return;
      }
      if (event.key !== 'Tab') return;
      const controls = focusableInModal();
      if (!controls.length) {
        event.preventDefault();
        modal.setAttribute('tabindex', '-1');
        focusNode(modal);
        return;
      }
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        focusNode(last);
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        focusNode(first);
      } else if (!modal.contains(document.activeElement)) {
        event.preventDefault();
        focusNode(event.shiftKey ? last : first);
      }
    }, true);
  }

  function clearSummary() {
    result.classList.add('hidden');
    error.classList.add('hidden');
    error.textContent = '';
    for (const field of fields) byId(`nmap-xml-${field}`).textContent = '';
    linkResult.classList.add('hidden');
  }

  function clearSelect(select) {
    select.innerHTML = '';
    select.value = '';
    if (Array.isArray(select.options)) select.options.length = 0;
    if (Array.isArray(select.children)) select.children.length = 0;
  }

  function currentSnapshot() {
    return {
      paste: input.value,
      file: fileInput.files?.[0] || null,
      linking: Boolean(linkOptIn.checked),
      engagementId: linkEngagement.value,
      controlId: linkControl.value,
    };
  }

  function sameSnapshot(a, b) {
    return Boolean(a && b) &&
      a.paste === b.paste &&
      a.file === b.file &&
      a.linking === b.linking &&
      a.engagementId === b.engagementId &&
      a.controlId === b.controlId;
  }

  function invalidateSubmit() {
    submitGeneration += 1;
    requestController?.abort();
    requestController = null;
    busy = false;
    activeSnapshot = null;
    submit.disabled = false;
  }

  function reset() {
    generation += 1;
    optInGeneration += 1;
    controlGeneration += 1;
    invalidateSubmit();
    input.value = '';
    fileInput.value = '';
    if (Array.isArray(fileInput.files)) fileInput.files = [];
    linkOptIn.checked = false;
    linkFields.classList.add('hidden');
    clearSelect(linkEngagement);
    clearSelect(linkControl);
    clearSummary();
  }

  function showError() {
    clearSummary();
    error.textContent = 'Geçersiz Nmap XML raporu.';
    error.classList.remove('hidden');
  }

  function count(value, max) {
    return Number.isSafeInteger(value) && value >= 0 && value <= max;
  }

  function countMap(value, keys, max) {
    return value && typeof value === 'object' && !Array.isArray(value) &&
      Object.keys(value).length === keys.length &&
      keys.every(key => Object.hasOwn(value, key) && count(value[key], max));
  }

  function validSummary(data) {
    if (!data || typeof data !== 'object' || Array.isArray(data) || data.format !== 'nmap-xml' ||
        !count(data.host_count, 500) || !count(data.up_host_count, data.host_count) ||
        !count(data.open_port_count, 5000) ||
        !countMap(data.open_protocol_counts, ['tcp', 'udp'], 5000) ||
        !countMap(data.open_port_bands, ['well_known', 'registered', 'dynamic'], 5000) ||
        typeof data.report_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(data.report_sha256)) return false;
    return data.open_protocol_counts.tcp + data.open_protocol_counts.udp === data.open_port_count &&
      data.open_port_bands.well_known + data.open_port_bands.registered + data.open_port_bands.dynamic === data.open_port_count;
  }

  function option(select, value, label) {
    const element = document.createElement('option');
    element.value = value;
    element.textContent = label;
    select.append(element);
  }

  input.addEventListener('input', invalidateSubmit);
  fileInput.addEventListener('change', invalidateSubmit);
  linkControl.addEventListener('change', invalidateSubmit);

  linkOptIn.addEventListener('change', async () => {
    invalidateSubmit();
    const currentGeneration = generation;
    const currentOptInGeneration = ++optInGeneration;
    controlGeneration += 1;
    linkFields.classList.toggle('hidden', !linkOptIn.checked);
    clearSelect(linkEngagement);
    clearSelect(linkControl);
    if (errorText() === 'Yetkili denetim yüklenemedi.' ||
        errorText() === 'Test adımları yüklenemedi.' ||
        errorText() === 'Yetkili denetim ve test adımı seçin.') {
      error.textContent = '';
      error.classList.add('hidden');
    }
    if (!linkOptIn.checked) return;
    const isCurrentOptIn = () =>
      generation === currentGeneration &&
      optInGeneration === currentOptInGeneration &&
      Boolean(linkOptIn.checked);
    try {
      const response = await fetch('/api/engagements');
      if (!isCurrentOptIn()) return;
      if (!response.ok) throw new Error();
      const data = await response.json();
      if (!isCurrentOptIn()) return;
      if (!Array.isArray(data?.engagements)) throw new Error();
      const eligible = data.engagements.filter(item => item && item.status === 'active' &&
        typeof item.authorization_ref === 'string' && item.authorization_ref.trim() &&
        item.special_approvals?.redacted_data_proof === true &&
        typeof item.id === 'string' && typeof item.name === 'string');
      clearSelect(linkEngagement);
      option(linkEngagement, '', 'Denetim seçin');
      for (const item of eligible) option(linkEngagement, item.id, item.name);
      if (!eligible.length) throw new Error();
    } catch {
      if (isCurrentOptIn()) {
        error.textContent = 'Yetkili denetim yüklenemedi.';
        error.classList.remove('hidden');
      }
    }
  });

  linkEngagement.addEventListener('change', async () => {
    invalidateSubmit();
    const currentGeneration = generation;
    const currentOptInGeneration = optInGeneration;
    const currentControlGeneration = ++controlGeneration;
    clearSelect(linkControl);
    if (errorText() === 'Test adımları yüklenemedi.' ||
        errorText() === 'Yetkili denetim ve test adımı seçin.') {
      error.textContent = '';
      error.classList.add('hidden');
    }
    if (!linkOptIn.checked || !linkEngagement.value) return;
    const engagementId = linkEngagement.value;
    const isCurrentControl = () =>
      generation === currentGeneration &&
      optInGeneration === currentOptInGeneration &&
      controlGeneration === currentControlGeneration &&
      Boolean(linkOptIn.checked) &&
      linkEngagement.value === engagementId;
    try {
      const response = await fetch(`/api/engagements/${encodeURIComponent(engagementId)}`);
      if (!isCurrentControl()) return;
      if (!response.ok) throw new Error();
      const detail = await response.json();
      if (!isCurrentControl()) return;
      if (!Array.isArray(detail?.tests)) throw new Error();
      clearSelect(linkControl);
      option(linkControl, '', 'Test adımı seçin');
      for (const item of detail.tests) {
        if (typeof item.control_id === 'string' && typeof item.title === 'string')
          option(linkControl, item.control_id, `${item.control_id} · ${item.title}`);
      }
    } catch {
      if (isCurrentControl()) {
        error.textContent = 'Test adımları yüklenemedi.';
        error.classList.remove('hidden');
      }
    }
  });

  document.addEventListener('click', event => {
    const opener = event.target.closest('[data-action="open-nmap-xml-preview"]');
    if (opener) {
      event.preventDefault();
      openDialog(opener);
      return;
    }
    const closer = event.target.closest('[data-close="nmap-xml-preview-modal"]');
    if (closer || event.target === modal) {
      event.preventDefault();
      closeDialog();
    }
  });

  byId('nmap-xml-preview-form').addEventListener('submit', async event => {
    event.preventDefault();
    const nextSnapshot = currentSnapshot();
    if (busy && sameSnapshot(activeSnapshot, nextSnapshot)) return;
    invalidateSubmit();
    const currentGeneration = generation;
    const currentSubmitGeneration = submitGeneration;
    const wasHiddenAtStart = modal.classList.contains('hidden');
    const isCurrent = () =>
      generation === currentGeneration &&
      submitGeneration === currentSubmitGeneration &&
      (wasHiddenAtStart || !modal.classList.contains('hidden')) &&
      sameSnapshot(nextSnapshot, currentSnapshot());

    activeSnapshot = nextSnapshot;
    submit.disabled = true;
    clearSummary();
    try {
      let report = nextSnapshot.paste;
      if (!report.trim() && nextSnapshot.file) {
        const file = nextSnapshot.file;
        if (file.size > 60000) { showError(); return; }
        try {
          report = await file.text();
        } catch {
          if (isCurrent()) showError();
          return;
        }
        if (!isCurrent()) return;
      }
      if (!isCurrent()) return;
      if (!report.trim()) { showError(); return; }
      const linking = nextSnapshot.linking;
      const engagementId = nextSnapshot.engagementId;
      const controlId = nextSnapshot.controlId;
      if (linking && (!engagementId || !controlId)) {
        error.textContent = 'Yetkili denetim ve test adımı seçin.';
        error.classList.remove('hidden');
        return;
      }
      let payload;
      try {
        if (new TextEncoder().encode(report).length > 60000) { showError(); return; }
        payload = JSON.stringify(linking ? { control_id: controlId, report, confirm_link: true } : { report });
        if (new TextEncoder().encode(payload).length > 65536) { showError(); return; }
      } catch { showError(); return; }

      const controller = new AbortController();
      requestController = controller;
      busy = true;
      const endpoint = linking ? `/api/engagements/${encodeURIComponent(engagementId)}/tool-evidence/nmap`
        : '/api/tool-reports/nmap/summary';
      const response = await fetch(endpoint, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: payload, signal: controller.signal,
      });
      if (!response.ok) throw new Error('Invalid report');
      const raw = await response.json();
      if (!isCurrent()) return;
      const data = linking ? {
        format: raw.tool_identity, host_count: raw.host_count, up_host_count: raw.up_host_count,
        open_port_count: raw.open_port_count,
        open_protocol_counts: { tcp: raw.open_tcp_count, udp: raw.open_udp_count },
        open_port_bands: { well_known: raw.well_known_count, registered: raw.registered_count, dynamic: raw.dynamic_count },
        report_sha256: raw.report_sha256,
      } : raw;
      if (!validSummary(data)) throw new Error('Invalid summary');
      byId('nmap-xml-host-count').textContent = String(data.host_count);
      byId('nmap-xml-up-host-count').textContent = String(data.up_host_count);
      byId('nmap-xml-open-port-count').textContent = String(data.open_port_count);
      byId('nmap-xml-protocol-counts').textContent = `TCP:${data.open_protocol_counts.tcp} UDP:${data.open_protocol_counts.udp}`;
      byId('nmap-xml-port-bands').textContent = `1–1024:${data.open_port_bands.well_known} 1025–49151:${data.open_port_bands.registered} 49152–65535:${data.open_port_bands.dynamic}`;
      byId('nmap-xml-report-sha256').textContent = data.report_sha256;
      input.value = '';
      fileInput.value = '';
      if (Array.isArray(fileInput.files)) fileInput.files = [];
      result.classList.remove('hidden');
      if (linking) linkResult.classList.remove('hidden');
    } catch {
      if (isCurrent()) showError();
    } finally {
      if (generation === currentGeneration && submitGeneration === currentSubmitGeneration) {
        busy = false;
        requestController = null;
        activeSnapshot = null;
        submit.disabled = false;
      }
    }
  });
})();
