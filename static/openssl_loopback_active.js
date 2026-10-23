// Explicitly requested loopback TLS certificate check. Opening or typing never connects.
(() => {
  const id = 'openssl-loopback-modal';
  const form = document.getElementById('openssl-loopback-form');
  if (!form) return;
  const target = document.getElementById('openssl-loopback-target');
  const consent = document.getElementById('openssl-loopback-consent');
  const submit = document.getElementById('openssl-loopback-submit');
  const error = document.getElementById('openssl-loopback-error');
  const result = document.getElementById('openssl-loopback-result');
  const value = name => document.getElementById('openssl-loopback-' + name);
  let pending = false, generation = 0, open = false;
  const resetResult = () => { error.textContent = ''; error.classList.add('hidden'); result.classList.add('hidden'); };
  const valid = () => /^127\.0\.0\.1:([1-9][0-9]{0,4})$/.test(target.value) &&
    Number(target.value.slice(10)) <= 65535 && consent.checked;
  const update = () => { submit.disabled = pending || !valid(); };
  target.addEventListener('input', update);
  consent.addEventListener('change', update);
  document.addEventListener('click', event => {
    if (event.target.closest?.('[data-action="open-openssl-loopback"]')) {
      event.preventDefault();
      open = true;
      resetResult();
      update();
      showModal(id, true);
    }
    if (event.target.closest?.(`[data-close="${id}"]`) || event.target.id === id) {
      event.preventDefault();
      open = false;
      generation += 1;
      target.value = '';
      consent.checked = false;
      update();
      resetResult();
      showModal(id, false);
    }
  });
  form.addEventListener('submit', async event => {
    event.preventDefault();
    resetResult();
    if (pending) return;
    if (!valid()) { error.textContent = 'Yalnız açık onaylı 127.0.0.1:PORT kabul edilir.'; error.classList.remove('hidden'); return; }
    pending = true;
    submit.disabled = true;
    const requestGeneration = generation;
    try {
      const body = await api('/api/tool-runs/openssl-x509-loopback', {
        method: 'POST', body: JSON.stringify({ confirm_local: true, target: target.value }),
      });
      if (!open || generation !== requestGeneration) return;
      const hex = /^[0-9a-f]{64}$/;
      const date = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;
      if (body.format !== 'openssl-x509-loopback-v1' || !['passed', 'rejected'].includes(body.verification)) throw Error('Invalid result');
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
        if (Object.keys(body).length !== 2) throw Error('Invalid result');
        value('validity').textContent = 'Zincir veya IP kimliği doğrulanamadı';
        for (const field of ['before', 'after', 'days', 'sha']) value(field).textContent = '—';
      }
      result.classList.remove('hidden');
      target.value = '';
      consent.checked = false;
    } catch {
      if (!open || generation !== requestGeneration) return;
      error.textContent = 'Yerel TLS doğrulaması tamamlanamadı. İzinli hedefi ve sunucu yapılandırmasını kontrol edin.';
      error.classList.remove('hidden');
    } finally { pending = false; update(); }
  });
})();
