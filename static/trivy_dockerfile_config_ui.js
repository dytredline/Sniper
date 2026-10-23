(() => {
  const form = document.getElementById('trivy-dockerfile-config-form');
  if (!form) return;
  const path = document.getElementById('trivy-dockerfile-config-path');
  const consent = document.getElementById('trivy-dockerfile-config-consent');
  const submit = document.getElementById('trivy-dockerfile-config-submit');
  const error = document.getElementById('trivy-dockerfile-config-error');
  const result = document.getElementById('trivy-dockerfile-config-result');
  const classKeys = ['os-pkgs', 'lang-pkgs', 'config', 'secret', 'license', 'license-file', 'crypto', 'custom', 'unknown'];
  const severityKeys = ['critical', 'high', 'medium', 'low', 'unknown'];
  const findingKeys = ['vulnerabilities', 'misconfigurations', 'secrets', 'licenses'];
  const responseKeys = ['format', 'schema_version', 'profile', 'result_count', 'class_counts', 'vuln_counts', 'misconfig_sev_counts', 'finding_counts', 'report_sha256'];
  let busy = false;
  const cleanPath = value => value.startsWith('/') && value !== '/' && !value.includes('//') && !value.includes('\\')
    && !/[\x00-\x1f\x7f]/.test(value) && !value.split('/').some(segment => segment === '.' || segment === '..');
  const countMap = (value, keys) => !!value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key) && Number.isSafeInteger(value[key]) && value[key] >= 0);
  const validSummary = data => !!data && typeof data === 'object' && !Array.isArray(data)
    && Object.keys(data).length === responseKeys.length && responseKeys.every(key => Object.hasOwn(data, key))
    && data.format === 'trivy-native-json' && data.schema_version === 2
    && data.profile === 'local-dockerfile-config-v1' && data.result_count === 1
    && countMap(data.class_counts, classKeys) && countMap(data.vuln_counts, severityKeys)
    && countMap(data.misconfig_sev_counts, severityKeys)
    && countMap(data.finding_counts, findingKeys)
    && data.class_counts.config === 1
    && classKeys.reduce((total, key) => total + data.class_counts[key], 0) === 1
    && severityKeys.every(key => data.vuln_counts[key] === 0)
    && data.finding_counts.vulnerabilities === 0 && data.finding_counts.secrets === 0
    && data.finding_counts.licenses === 0
    && severityKeys.reduce((total, key) => total + data.misconfig_sev_counts[key], 0) === data.finding_counts.misconfigurations
    && typeof data.report_sha256 === 'string' && /^[0-9a-f]{64}$/.test(data.report_sha256);
  const clearDisplay = () => {
    error.textContent = '';
    error.classList.add('hidden');
    result.classList.add('hidden');
    for (const id of ['trivy-dockerfile-config-groups', 'trivy-dockerfile-config-total', 'trivy-dockerfile-config-hash'])
      document.getElementById(id).textContent = '';
  };
  const ready = () => consent.checked && cleanPath(path.value.trim());
  const update = () => { submit.disabled = busy || !ready(); };
  path.addEventListener('input', update);
  consent.addEventListener('change', update);
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy) return;
    clearDisplay();
    const projectPath = path.value.trim();
    if (!ready()) {
      error.textContent = 'Yerel proje klasörü ve açık Dockerfile tarama onayı gerekli.';
      error.classList.remove('hidden');
      update();
      return;
    }
    busy = true;
    update();
    try {
      const response = await fetch('/api/tool-runs/trivy-dockerfile-config', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({confirm_local: true, project_path: projectPath}),
      });
      if (!response.ok) throw new Error('scan_failed');
      const data = await response.json();
      if (!validSummary(data)) throw new Error('invalid_summary');
      document.getElementById('trivy-dockerfile-config-groups').textContent = String(data.result_count);
      document.getElementById('trivy-dockerfile-config-total').textContent = String(data.finding_counts.misconfigurations);
      document.getElementById('trivy-dockerfile-config-hash').textContent = data.report_sha256;
      result.classList.remove('hidden');
      path.value = '';
      consent.checked = false;
    } catch {
      error.textContent = 'Yerel Dockerfile taraması tamamlanamadı. Dockerfile dosyasını ve Trivy aracını denetleyin.';
      error.classList.remove('hidden');
    } finally {
      busy = false;
      update();
    }
  });
})();
