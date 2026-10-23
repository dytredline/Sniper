(() => {
  const ids = {
    form: 'osv-active-form', path: 'osv-active-path', consent: 'osv-active-consent',
    submit: 'osv-active-submit', error: 'osv-active-error', result: 'osv-active-result',
    packages: 'osv-active-packages', affected: 'osv-active-affected',
    groups: 'osv-active-groups', coverage: 'osv-active-coverage',
    dbTime: 'osv-active-db-time', dbHash: 'osv-active-db-hash',
    reportHash: 'osv-active-report-hash',
  };
  const elements = Object.fromEntries(Object.entries(ids).map(([key, id]) => [key, document.getElementById(id)]));
  if (Object.values(elements).some(element => !element)) return;
  const fields = ['packages', 'affected', 'groups', 'coverage', 'dbTime', 'dbHash', 'reportHash'];
  const responseKeys = ['format', 'profile', 'coverage', 'package_count', 'affected_package_count',
    'vulnerability_group_count', 'offline_db_sha256', 'offline_db_retrieved_utc', 'report_sha256'];
  let busy = false;

  function configuredHome() {
    const value = document.querySelector?.('meta[name="sniper-local-home"]')?.content;
    if (typeof value !== 'string' || value.length < 2 || value.length > 1024 ||
        !value.startsWith('/') || value.endsWith('/') || value.includes('//') ||
        /[\\\u0000-\u001f\u007f]/.test(value)) return '';
    return value.split('/').slice(1).every(segment => segment && segment !== '.' && segment !== '..') ? value : '';
  }
  function validPath(value) {
    const home = configuredHome();
    return !!home && value.length <= 1024 && value.startsWith(home + '/') &&
      !/[\\\u0000-\u001f\u007f]/.test(value) &&
      value.slice(home.length + 1).split('/').every(segment => segment && segment !== '.' && segment !== '..');
  }
  function validSummary(data) {
    if (!data || typeof data !== 'object' || Array.isArray(data) ||
        Object.keys(data).length !== responseKeys.length ||
        !responseKeys.every(key => Object.hasOwn(data, key)) ||
        data.format !== 'osv-scanner-json' || data.profile !== 'local-npm-lock-osv-offline-v1' ||
        data.coverage !== 'public-registry-lockfile') return false;
    const count = value => Number.isSafeInteger(value) && value >= 0;
    if (!count(data.package_count) || data.package_count > 2000 ||
        !count(data.affected_package_count) || data.affected_package_count > data.package_count ||
        !count(data.vulnerability_group_count) ||
        data.vulnerability_group_count < data.affected_package_count) return false;
    const hash = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
    const time = data.offline_db_retrieved_utc;
    return hash(data.offline_db_sha256) && hash(data.report_sha256) &&
      typeof time === 'string' &&
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(time) &&
      Number.isFinite(Date.parse(time));
  }
  function clearDisplay() {
    elements.error.textContent = '';
    elements.error.classList.add('hidden');
    elements.result.classList.add('hidden');
    for (const field of fields) elements[field].textContent = '';
  }
  function update() {
    elements.submit.disabled = busy || !elements.consent.checked ||
      !validPath(elements.path.value.trim());
  }
  elements.path.addEventListener('input', update);
  elements.consent.addEventListener('change', update);
  elements.form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy) return;
    clearDisplay();
    const projectPath = elements.path.value.trim();
    if (!elements.consent.checked || !validPath(projectPath)) {
      elements.error.textContent = 'DGX hizmet kullanıcısının evindeki proje klasörü ve açık onay gerekli.';
      elements.error.classList.remove('hidden');
      update();
      return;
    }
    busy = true;
    update();
    try {
      const data = await api('/api/tool-runs/osv-scanner-local', {
        method: 'POST',
        body: JSON.stringify({confirm_local: true, project_path: projectPath}),
      });
      if (!validSummary(data)) throw new Error('invalid_summary');
      elements.packages.textContent = String(data.package_count);
      elements.affected.textContent = String(data.affected_package_count);
      elements.groups.textContent = String(data.vulnerability_group_count);
      elements.coverage.textContent = data.coverage;
      elements.dbTime.textContent = data.offline_db_retrieved_utc;
      elements.dbHash.textContent = data.offline_db_sha256;
      elements.reportHash.textContent = data.report_sha256;
      elements.result.classList.remove('hidden');
      elements.path.value = '';
      elements.consent.checked = false;
    } catch {
      elements.error.textContent = 'Çevrimdışı OSV analizi tamamlanamadı. Yerel kilit dosyasını, sabitlenmiş veritabanını ve hizmet durumunu denetleyin.';
      elements.error.classList.remove('hidden');
    } finally {
      busy = false;
      update();
    }
  });
  update();
})();
