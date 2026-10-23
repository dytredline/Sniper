// Arka plan iş kuyruğu istemcisi: uzun araç çalıştırmalarını /api/jobs üzerinden başlatır,
// durumu geri çekilmeli yoklar, iptal eder ve sonucu yalnız textContent ile gösterir.
// Kullanım: window.SniperJobs.run(route, payload, element) → Promise<iş>
//           window.SniperJobs.cancel(jobId)
(() => {
  const STATE_LABELS = Object.freeze({
    queued: 'Kuyrukta',
    interrupted: 'Yeniden başlatmada yarıda kaldı',
    running: 'Çalışıyor',
    succeeded: 'Tamamlandı',
    failed: 'Başarısız',
    cancelled: 'İptal edildi',
    expired: 'Süre sınırı aşıldı',
  });
  const FINAL = new Set(['succeeded', 'failed', 'cancelled', 'expired', 'interrupted']);
  const MIN_DELAY_MS = 1000;
  const MAX_DELAY_MS = 15000;
  const MAX_POLLS = 2000;

  const scope = typeof window !== 'undefined' ? window : globalThis;
  const fetcher = (...args) => scope.fetch(...args);
  const wait = ms => new Promise(resolve => scope.setTimeout(resolve, ms));

  async function request(path, options = {}) {
    const response = await fetcher(path, {
      method: options.method || 'GET',
      headers: options.body ? { 'Content-Type': 'application/json' } : undefined,
      body: options.body ? JSON.stringify(options.body) : undefined,
      credentials: 'same-origin',
    });
    let data = {};
    try {
      data = await response.json();
    } catch (_error) {
      data = {};
    }
    if (!response.ok) {
      const error = new Error(typeof data.error === 'string' ? data.error : `İstek ${response.status} durum koduyla başarısız oldu.`);
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function stateLabel(state) {
    return STATE_LABELS[state] || 'Bilinmiyor';
  }

  function render(element, job, note) {
    if (!element) return;
    const parts = [`İş ${job.id || ''}: ${stateLabel(job.state)}`];
    if (job.queue_position) parts.push(`sıra ${job.queue_position}`);
    if (job.error) parts.push(String(job.error));
    if (note) parts.push(note);
    element.textContent = parts.join(' · ');
    if (element.dataset) {
      element.dataset.jobId = job.id || '';
      element.dataset.jobState = job.state || '';
    }
  }

  async function poll(jobId, element, onUpdate) {
    let delay = MIN_DELAY_MS;
    for (let count = 0; count < MAX_POLLS; count += 1) {
      const job = await request(`/api/jobs/${encodeURIComponent(jobId)}`);
      render(element, job);
      if (typeof onUpdate === 'function') onUpdate(job);
      if (FINAL.has(job.state)) return job;
      await wait(delay);
      delay = Math.min(MAX_DELAY_MS, Math.round(delay * 1.5));
    }
    throw new Error('İş durumu çok uzun süre değişmedi; Araç Matrisi > İşler bölümünden kontrol edin.');
  }

  async function run(route, payload, element, onUpdate) {
    if (typeof route !== 'string' || !route.startsWith('/api/')) {
      throw new Error('Geçersiz rota.');
    }
    if (element) element.textContent = 'İş başlatılıyor…';
    try {
      const job = await request('/api/jobs', { method: 'POST', body: { route, payload: payload || {} } });
      render(element, job);
      return await poll(job.id, element, onUpdate);
    } catch (error) {
      if (element) element.textContent = `İş başlatılamadı: ${error.message}`;
      throw error;
    }
  }

  async function cancel(jobId, element) {
    const job = await request(`/api/jobs/${encodeURIComponent(jobId)}/cancel`, { method: 'POST', body: {} });
    render(element, job, job.state === 'running' ? 'iptal istendi' : '');
    return job;
  }

  async function list() {
    const data = await request('/api/jobs');
    return Array.isArray(data.jobs) ? data.jobs : [];
  }

  scope.SniperJobs = Object.freeze({ run, cancel, list, poll, stateLabel });
})();
