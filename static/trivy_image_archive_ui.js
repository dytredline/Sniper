(() => {
  const form = document.getElementById('trivy-image-archive-form');
  if (!form) return;
  const path = document.getElementById('trivy-image-archive-path');
  const name = document.getElementById('trivy-image-archive-name');
  const consent = document.getElementById('trivy-image-archive-consent');
  const submit = document.getElementById('trivy-image-archive-submit');
  const error = document.getElementById('trivy-image-archive-error');
  const result = document.getElementById('trivy-image-archive-result');
  const classKeys = ['os-pkgs', 'lang-pkgs', 'config', 'secret', 'license', 'license-file', 'crypto', 'custom', 'unknown'];
  const severityKeys = ['critical', 'high', 'medium', 'low', 'unknown'];
  const findingKeys = ['vulnerabilities', 'misconfigurations', 'secrets', 'licenses'];
  const responseKeys = ['format', 'schema_version', 'profile', 'result_count', 'class_counts', 'vuln_counts', 'misconfig_sev_counts', 'finding_counts', 'report_sha256'];
  let busy = false;
  const cleanPath = value => value.startsWith('/') && value !== '/' && !value.includes('//') && !value.includes('\\')
    && !/[\x00-\x1f\x7f]/.test(value) && !value.split('/').some(segment => segment === '.' || segment === '..');
  const cleanName = value => value.endsWith('.tar') && value.length > 4 && !/[\/\\\x00-\x1f\x7f]/.test(value);
  const validCountMap = (value, keys) => !!value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key) && Number.isSafeInteger(value[key]) && value[key] >= 0);
  const validSummary = data => !!data && typeof data === 'object' && !Array.isArray(data)
    && Object.keys(data).length === responseKeys.length && responseKeys.every(key => Object.hasOwn(data, key))
    && data.format === 'trivy-native-json' && data.schema_version === 2
    && data.profile === 'local-image-archive-offline-v1'
    && Number.isSafeInteger(data.result_count) && data.result_count >= 0 && data.result_count <= 500
    && validCountMap(data.class_counts, classKeys)
    && validCountMap(data.vuln_counts, severityKeys)
    && validCountMap(data.misconfig_sev_counts, severityKeys)
    && validCountMap(data.finding_counts, findingKeys)
    && classKeys.reduce((total, key) => total + data.class_counts[key], 0) === data.result_count
    && severityKeys.reduce((total, key) => total + data.vuln_counts[key], 0) === data.finding_counts.vulnerabilities
    && severityKeys.reduce((total, key) => total + data.misconfig_sev_counts[key], 0) === data.finding_counts.misconfigurations
    && typeof data.report_sha256 === 'string' && /^[0-9a-f]{64}$/.test(data.report_sha256);
  const clearDisplay = () => {
    error.textContent = '';
    error.classList.add('hidden');
    result.classList.add('hidden');
    for (const id of ['trivy-image-archive-groups', 'trivy-image-archive-total', 'trivy-image-archive-severity', 'trivy-image-archive-hash'])
      document.getElementById(id).textContent = '';
  };
  const ready = () => consent.checked && cleanPath(path.value.trim()) && cleanName(name.value.trim());
  const update = () => { submit.disabled = busy || !ready(); };
  path.addEventListener('input', update);
  name.addEventListener('input', update);
  consent.addEventListener('change', update);
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy) return;
    clearDisplay();
    const projectPath = path.value.trim();
    const archiveName = name.value.trim();
    if (!ready()) {
      error.textContent = 'Yerel proje, kök .tar arşivi ve açık tarama onayı gerekli.';
      error.classList.remove('hidden');
      update();
      return;
    }
    busy = true;
    update();
    try {
      const response = await fetch('/api/tool-runs/trivy-image-archive-vulnerability', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({confirm_local:true,project_path:projectPath,archive_name:archiveName}),
      });
      if (!response.ok) throw new Error('scan_failed');
      const data = await response.json();
      if (!validSummary(data)) throw new Error('invalid_summary');
      document.getElementById('trivy-image-archive-groups').textContent = String(data.result_count);
      document.getElementById('trivy-image-archive-total').textContent = String(data.finding_counts.vulnerabilities);
      document.getElementById('trivy-image-archive-severity').textContent = severityKeys.map(key => `${key}:${data.vuln_counts[key]}`).join(' ');
      document.getElementById('trivy-image-archive-hash').textContent = data.report_sha256;
      result.classList.remove('hidden');
      path.value = '';
      name.value = '';
      consent.checked = false;
    } catch {
      error.textContent = 'Yerel imaj arşivi taraması tamamlanamadı. Arşivi, Trivy aracını ve çevrimdışı veritabanını denetleyin.';
      error.classList.remove('hidden');
    } finally {
      busy = false;
      update();
    }
  });
})();
