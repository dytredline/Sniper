(() => {
  const form = document.getElementById('trivy-kubernetes-single-form');
  if (!form) return;
  const path = document.getElementById('trivy-kubernetes-single-path');
  const name = document.getElementById('trivy-kubernetes-single-name');
  const consent = document.getElementById('trivy-kubernetes-single-consent');
  const submit = document.getElementById('trivy-kubernetes-single-submit');
  const error = document.getElementById('trivy-kubernetes-single-error');
  const result = document.getElementById('trivy-kubernetes-single-result');
  const classKeys = ['os-pkgs', 'lang-pkgs', 'config', 'secret', 'license', 'license-file', 'crypto', 'custom', 'unknown'];
  const severityKeys = ['critical', 'high', 'medium', 'low', 'unknown'];
  const findingKeys = ['vulnerabilities', 'misconfigurations', 'secrets', 'licenses'];
  const responseKeys = ['format', 'schema_version', 'profile', 'result_count', 'class_counts', 'vuln_counts', 'misconfig_sev_counts', 'finding_counts', 'report_sha256'];
  let busy = false;
  const cleanPath = value => value.startsWith('/') && value !== '/' && !value.includes('//') && !value.includes('\\')
    && !/[\x00-\x1f\x7f]/.test(value) && !value.split('/').some(segment => segment === '.' || segment === '..');
  const cleanName = value => /^[A-Za-z0-9][A-Za-z0-9._-]{0,123}\.ya?ml$/.test(value) && !value.includes('..');
  const countMap = (value, keys) => !!value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key) && Number.isSafeInteger(value[key]) && value[key] >= 0);
  const validSummary = data => !!data && typeof data === 'object' && !Array.isArray(data)
    && Object.keys(data).length === responseKeys.length && responseKeys.every(key => Object.hasOwn(data, key))
    && data.format === 'trivy-native-json' && data.schema_version === 2
    && data.profile === 'local-kubernetes-manifest-config-v1' && data.result_count === 1
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
    for (const id of ['trivy-kubernetes-single-groups', 'trivy-kubernetes-single-total', 'trivy-kubernetes-single-hash'])
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
    const manifestName = name.value.trim();
    if (!ready()) {
      error.textContent = 'Yerel proje klasörü, kök YAML dosya adı ve açık tarama onayı gerekli.';
      error.classList.remove('hidden');
      update();
      return;
    }
    busy = true;
    update();
    try {
      const response = await fetch('/api/tool-runs/trivy-kubernetes-config', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({confirm_local: true, project_path: projectPath, manifest_name: manifestName}),
      });
      if (!response.ok) throw new Error('scan_failed');
      const data = await response.json();
      if (!validSummary(data)) throw new Error('invalid_summary');
      document.getElementById('trivy-kubernetes-single-groups').textContent = String(data.result_count);
      document.getElementById('trivy-kubernetes-single-total').textContent = String(data.finding_counts.misconfigurations);
      document.getElementById('trivy-kubernetes-single-hash').textContent = data.report_sha256;
      result.classList.remove('hidden');
      path.value = '';
      name.value = '';
      consent.checked = false;
    } catch {
      error.textContent = 'Yerel tek-manifest taraması tamamlanamadı. YAML dosyasını ve Trivy aracını denetleyin.';
      error.classList.remove('hidden');
    } finally {
      busy = false;
      update();
    }
  });
})();
