(() => {
  const form = document.getElementById('trivy-kubernetes-batch-form');
  if (!form) return;
  const path = document.getElementById('trivy-kubernetes-batch-path');
  const names = document.getElementById('trivy-kubernetes-batch-names');
  const consent = document.getElementById('trivy-kubernetes-batch-consent');
  const submit = document.getElementById('trivy-kubernetes-batch-submit');
  const error = document.getElementById('trivy-kubernetes-batch-error');
  const result = document.getElementById('trivy-kubernetes-batch-result');
  const classKeys = ['os-pkgs', 'lang-pkgs', 'config', 'secret', 'license', 'license-file', 'crypto', 'custom', 'unknown'];
  const severityKeys = ['critical', 'high', 'medium', 'low', 'unknown'];
  const findingKeys = ['vulnerabilities', 'misconfigurations', 'secrets', 'licenses'];
  const responseKeys = ['format', 'schema_version', 'profile', 'result_count', 'class_counts', 'vuln_counts', 'misconfig_sev_counts', 'finding_counts', 'report_sha256'];
  let busy = false;
  const cleanPath = value => value.startsWith('/') && value !== '/' && !value.includes('//') && !value.includes('\\')
    && !/[\x00-\x1f\x7f]/.test(value) && !value.split('/').some(segment => segment === '.' || segment === '..');
  const cleanName = value => /^[A-Za-z0-9][A-Za-z0-9._-]{0,123}\.ya?ml$/.test(value) && !value.includes('..');
  const selectedNames = () => names.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
  const cleanNames = values => values.length >= 1 && values.length <= 8
    && new Set(values).size === values.length && values.every(cleanName);
  const validCountMap = (value, keys) => !!value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key) && Number.isSafeInteger(value[key]) && value[key] >= 0);
  const validSummary = (data, expectedCount) => !!data && typeof data === 'object' && !Array.isArray(data)
    && Object.keys(data).length === responseKeys.length && responseKeys.every(key => Object.hasOwn(data, key))
    && data.format === 'trivy-native-json' && data.schema_version === 2
    && data.profile === 'local-kubernetes-manifest-config-batch-v1'
    && Number.isSafeInteger(data.result_count) && data.result_count === expectedCount
    && validCountMap(data.class_counts, classKeys)
    && validCountMap(data.vuln_counts, severityKeys) && validCountMap(data.misconfig_sev_counts, severityKeys)
    && validCountMap(data.finding_counts, findingKeys)
    && data.class_counts.config === expectedCount
    && classKeys.reduce((total, key) => total + data.class_counts[key], 0) === expectedCount
    && severityKeys.every(key => data.vuln_counts[key] === 0)
    && data.finding_counts.vulnerabilities === 0 && data.finding_counts.secrets === 0
    && data.finding_counts.licenses === 0
    && severityKeys.reduce((total, key) => total + data.misconfig_sev_counts[key], 0) === data.finding_counts.misconfigurations
    && typeof data.report_sha256 === 'string' && /^[0-9a-f]{64}$/.test(data.report_sha256);
  const clearDisplay = () => {
    error.textContent = '';
    error.classList.add('hidden');
    result.classList.add('hidden');
    for (const id of ['trivy-kubernetes-batch-groups', 'trivy-kubernetes-batch-total', 'trivy-kubernetes-batch-hash'])
      document.getElementById(id).textContent = '';
  };
  const ready = () => consent.checked && cleanPath(path.value.trim()) && cleanNames(selectedNames());
  const update = () => { submit.disabled = busy || !ready(); };
  path.addEventListener('input', update);
  names.addEventListener('input', update);
  consent.addEventListener('change', update);
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy) return;
    clearDisplay();
    const projectPath = path.value.trim();
    const manifestNames = selectedNames();
    if (!ready()) {
      error.textContent = 'Yerel proje, 1-8 ayrı kök YAML dosya adı ve açık tarama onayı gerekli.';
      error.classList.remove('hidden');
      update();
      return;
    }
    busy = true;
    update();
    try {
      const response = await fetch('/api/tool-runs/trivy-kubernetes-config-batch', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({confirm_local: true, project_path: projectPath, manifest_names: manifestNames}),
      });
      if (!response.ok) throw new Error('scan_failed');
      const data = await response.json();
      if (!validSummary(data, manifestNames.length)) throw new Error('invalid_summary');
      document.getElementById('trivy-kubernetes-batch-groups').textContent = String(data.result_count);
      document.getElementById('trivy-kubernetes-batch-total').textContent = String(data.finding_counts.misconfigurations);
      document.getElementById('trivy-kubernetes-batch-hash').textContent = data.report_sha256;
      result.classList.remove('hidden');
      path.value = '';
      names.value = '';
      consent.checked = false;
    } catch {
      error.textContent = 'Yerel Kubernetes manifest taraması tamamlanamadı. Dosyaları ve Trivy aracını denetleyin.';
      error.classList.remove('hidden');
    } finally {
      busy = false;
      update();
    }
  });
})();
