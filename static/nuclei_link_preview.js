// Nuclei JSONL opt-in selector UI helper
(() => {
  const byId = id => document.getElementById(id);
  const modal = byId('nuclei-jsonl-preview-modal');
  const linkOptIn = byId('nuclei-jsonl-link-opt-in');
  const linkFields = byId('nuclei-jsonl-link-fields');
  const linkEngagement = byId('nuclei-jsonl-link-engagement');
  const linkControl = byId('nuclei-jsonl-link-control');
  const linkResult = byId('nuclei-jsonl-link-result');
  const errorEl = byId('nuclei-jsonl-preview-error');

  const fields = ['host-count', 'up-host-count', 'open-port-count', 'protocol-counts', 'port-bands', 'report-sha256'];
  let generation = 0;
  let requestController = null;
  let handledChangeEvent = null;

  function clearSelect(select) {
    if (!select) return;
    if (typeof select.replaceChildren === 'function') select.replaceChildren();
    select.innerHTML = '';
    select.value = '';
    if (Array.isArray(select.options)) select.options.length = 0;
    if (Array.isArray(select.children)) select.children.length = 0;
  }

  function clearLinkResult() {
    linkResult.classList.add('hidden');
    linkResult.textContent = '';
  }

  function reset() {
    generation += 1;
    requestController?.abort();
    requestController = null;
    linkOptIn.checked = false;
    linkFields.classList.add('hidden');
    clearSelect(linkEngagement);
    clearSelect(linkControl);
    clearLinkResult();
  }

  globalThis.resetNucleiJsonlLinkPreview = reset;
  if (typeof window === 'object' && window) {
    window.resetNucleiJsonlLinkPreview = reset;
  }

  function option(select, value, label) {
    const element = document.createElement('option');
    element.value = value;
    element.textContent = label;
    select.append(element);
    if (Array.isArray(select.options)) select.options.push(element);
    if (Array.isArray(select.children) && !select.children.includes(element)) select.children.push(element);
  }

  async function onOptInChange(event) {
    if (event && event === handledChangeEvent) return;
    if (event) handledChangeEvent = event;
    generation += 1;
    linkFields.classList.toggle('hidden', !linkOptIn.checked);
    clearSelect(linkEngagement);
    clearSelect(linkControl);
    clearLinkResult();
    if (!linkOptIn.checked) return;

    const currentGeneration = generation;
    try {
      const response = await fetch('/api/engagements');
      if (!response.ok) throw new Error();
      const data = await response.json();
      if (generation !== currentGeneration || !linkOptIn.checked) return;
      if (!Array.isArray(data.engagements)) throw new Error();

      const eligible = data.engagements.filter(item =>
        item &&
        item.status === 'active' &&
        typeof item.authorization_ref === 'string' && item.authorization_ref.trim() &&
        item.special_approvals?.redacted_data_proof === true &&
        typeof item.id === 'string' && typeof item.name === 'string'
      );

      option(linkEngagement, '', 'Denetim seçin');
      for (const item of eligible) option(linkEngagement, item.id, item.name);

      if (!eligible.length) throw new Error();
    } catch {
      if (generation === currentGeneration && linkOptIn.checked && !modal.classList.contains('hidden')) {
        errorEl.textContent = 'Yetkili denetim yüklenemedi.';
        errorEl.classList.remove('hidden');
      }
    }
  }

  async function onEngagementChange(event) {
    if (event && event === handledChangeEvent) return;
    if (event) handledChangeEvent = event;
    generation += 1;
    clearSelect(linkControl);
    clearLinkResult();
    if (!linkOptIn.checked || !linkEngagement.value) return;

    const currentGeneration = generation;
    const engagementId = linkEngagement.value;
    try {
      const response = await fetch(`/api/engagements/${encodeURIComponent(engagementId)}`);
      if (!response.ok) throw new Error();
      const detail = await response.json();
      if (generation !== currentGeneration || linkEngagement.value !== engagementId || !linkOptIn.checked) return;
      if (!Array.isArray(detail.tests)) throw new Error();

      option(linkControl, '', 'Test adımı seçin');
      for (const item of detail.tests) {
        if (typeof item.control_id === 'string' && typeof item.title === 'string') {
          option(linkControl, item.control_id, `${item.control_id} · ${item.title}`);
        }
      }
    } catch {
      if (generation === currentGeneration && linkOptIn.checked && !modal.classList.contains('hidden')) {
        errorEl.textContent = 'Test adımları yüklenemedi.';
        errorEl.classList.remove('hidden');
      }
    }
  }

  linkOptIn.addEventListener('change', onOptInChange);
  linkEngagement.addEventListener('change', onEngagementChange);

  document.addEventListener('change', event => {
    if (event?.target === linkOptIn || event?.target?.id === 'nuclei-jsonl-link-opt-in') {
      return onOptInChange(event);
    }
    if (event?.target === linkEngagement || event?.target?.id === 'nuclei-jsonl-link-engagement') {
      return onEngagementChange(event);
    }
  });

  document.addEventListener('click', event => {
    const opener = event.target.closest('[data-action="open-nuclei-jsonl-preview"]');
    if (opener) {
      event.preventDefault();
      reset();
      modal.classList.remove('hidden');
      document.body.style.overflow = 'hidden';
      return;
    }
    const closer = event.target.closest('[data-close="nuclei-jsonl-preview-modal"]');
    if (closer || event.target === modal) {
      event.preventDefault();
      reset();
      modal.classList.add('hidden');
      document.body.style.overflow = '';
    }
  });

  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !event.defaultPrevented && typeof showModal !== 'function' && !modal.classList.contains('hidden')) {
      event.preventDefault();
      reset();
      modal.classList.add('hidden');
      document.body.style.overflow = '';
    }
  });
})();
