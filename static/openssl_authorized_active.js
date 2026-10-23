// Explicit per-run authorization for one operator-supplied HTTPS target.
(() => {
  const id = 'openssl-authorized-modal';
  const form = document.getElementById('openssl-authorized-form');
  if (!form) return;
  const target = document.getElementById('openssl-authorized-target');
  const consent = document.getElementById('openssl-authorized-consent');
  const submit = document.getElementById('openssl-authorized-submit');
  const error = document.getElementById('openssl-authorized-error');
  const result = document.getElementById('openssl-authorized-result');
  const value = name => document.getElementById('openssl-authorized-' + name);
  let pending = false, generation = 0, open = false;
  const resetResult = () => { error.textContent = ''; error.classList.add('hidden'); result.classList.add('hidden'); };
  const valid = () => target.value.length <= 512 && /^https:\/\/[^\s\\]+$/i.test(target.value) && consent.checked;
  const update = () => { submit.disabled = pending || !valid(); };
  target.addEventListener('input', update);
  consent.addEventListener('change', update);
  document.addEventListener('click', event => {
    if (event.target.closest?.('[data-action="open-openssl-authorized"]')) {
      event.preventDefault(); open = true; resetResult(); update(); showModal(id, true);
    }
    if (event.target.closest?.(`[data-close="${id}"]`) || event.target.id === id) {
      event.preventDefault(); open = false; generation += 1;
      target.value = ''; consent.checked = false; update(); resetResult(); showModal(id, false);
    }
  });
  form.addEventListener('submit', async event => {
    event.preventDefault(); resetResult();
    if (pending) return;
    if (!valid()) {
      error.textContent = 'HTTPS hedefi ve açık yetki beyanı gerekli.';
      error.classList.remove('hidden'); return;
    }
    pending = true; submit.disabled = true;
    const requestGeneration = generation;
    try {
      const body = await api('/api/tool-runs/openssl-x509-authorized', {
        method: 'POST', body: JSON.stringify({ confirm_authorized: true, target: target.value }),
      });
      if (!open || generation !== requestGeneration) return;
      const hex = /^[0-9a-f]{64}$/;
      const date = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;
      if (body.format !== 'openssl-x509-authorized-v1' ||
          body.consent_version !== 'authorized-tls-target-v1' ||
          typeof body.normalized_target !== 'string' || !body.normalized_target.startsWith('https://') ||
          !['passed', 'rejected'].includes(body.verification)) throw Error('Invalid result');
      value('normalized').textContent = body.normalized_target;
      if (body.verification === 'passed') {
        if (!['valid', 'expiring_soon'].includes(body.validity) || !date.test(body.not_before_utc) ||
            !date.test(body.not_after_utc) || !Number.isInteger(body.days_until_expiry) ||
            body.days_until_expiry < 0 || !hex.test(body.report_sha256)) throw Error('Invalid result');
        value('validity').textContent = body.validity === 'expiring_soon' ? 'Doğrulandı · yakında bitecek' : 'Doğrulandı · geçerli';
        value('before').textContent = body.not_before_utc;
        value('after').textContent = body.not_after_utc;
        value('days').textContent = String(body.days_until_expiry);
        value('sha').textContent = body.report_sha256;
      } else {
        if (Object.keys(body).sort().join(',') !== 'consent_version,format,normalized_target,verification') throw Error('Invalid result');
        value('validity').textContent = 'Zincir veya hedef kimliği doğrulanamadı';
        for (const field of ['before', 'after', 'days', 'sha']) value(field).textContent = '—';
      }
      result.classList.remove('hidden'); target.value = ''; consent.checked = false;
    } catch {
      if (!open || generation !== requestGeneration) return;
      error.textContent = 'Yetkili TLS doğrulaması tamamlanamadı. Hedefi, yetkiyi ve sunucu güven kökünü kontrol edin.';
      error.classList.remove('hidden');
    } finally { pending = false; update(); }
  });
})();
