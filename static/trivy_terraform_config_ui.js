(() => {
  const form = document.getElementById('trivy-terraform-config-form');
  if (!form) return;
  const path = document.getElementById('trivy-terraform-config-path');
  const filename = document.getElementById('trivy-terraform-config-file');
  const consent = document.getElementById('trivy-terraform-config-consent');
  const submit = document.getElementById('trivy-terraform-config-submit');
  const error = document.getElementById('trivy-terraform-config-error');
  const result = document.getElementById('trivy-terraform-config-result');
  const classKeys = ['os-pkgs', 'lang-pkgs', 'config', 'secret', 'license', 'license-file', 'crypto', 'custom', 'unknown'];
  const severityKeys = ['critical', 'high', 'medium', 'low', 'unknown'];
  const findingKeys = ['vulnerabilities', 'misconfigurations', 'secrets', 'licenses'];
  const responseKeys = ['format', 'schema_version', 'profile', 'result_count', 'class_counts', 'vuln_counts', 'misconfig_sev_counts', 'finding_counts', 'report_sha256'];
  let busy = false;
  const cleanPath = value => value.startsWith('/') && value !== '/' && !value.includes('//') && !value.includes('\\')
    && !/[\x00-\x1f\x7f]/.test(value) && !value.split('/').some(segment => segment === '.' || segment === '..');
  const cleanFile = value => value.length > 3 && value.length <= 255 && !value.startsWith('.')
    && value.endsWith('.tf') && !value.includes('..') && !value.includes('/') && !value.includes('\\')
    && !/[\x00-\x1f\x7f]/.test(value);
  const countMap = (value, keys) => !!value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key) && Number.isSafeInteger(value[key]) && value[key] >= 0);
  const validSummary = data => !!data && typeof data === 'object' && !Array.isArray(data)
    && Object.keys(data).length === responseKeys.length && responseKeys.every(key => Object.hasOwn(data, key))
    && data.format === 'trivy-native-json' && data.schema_version === 2
    && data.profile === 'local-terraform-config-v1'
    && Number.isSafeInteger(data.result_count) && [1, 2].includes(data.result_count)
    && countMap(data.class_counts, classKeys) && countMap(data.vuln_counts, severityKeys)
    && countMap(data.misconfig_sev_counts, severityKeys)
    && countMap(data.finding_counts, findingKeys)
    && data.class_counts.config === data.result_count
    && classKeys.reduce((total, key) => total + data.class_counts[key], 0) === data.result_count
    && severityKeys.every(key => data.vuln_counts[key] === 0)
    && data.finding_counts.vulnerabilities === 0 && data.finding_counts.secrets === 0
    && data.finding_counts.licenses === 0
    && severityKeys.reduce((total, key) => total + data.misconfig_sev_counts[key], 0) === data.finding_counts.misconfigurations
    && typeof data.report_sha256 === 'string' && /^[0-9a-f]{64}$/.test(data.report_sha256);
  const clearDisplay = () => {
    error.textContent = '';
    error.classList.add('hidden');
    result.classList.add('hidden');
    for (const id of ['trivy-terraform-config-groups', 'trivy-terraform-config-total', 'trivy-terraform-config-hash'])
      document.getElementById(id).textContent = '';
  };
  const ready = () => consent.checked && cleanPath(path.value.trim()) && cleanFile(filename.value.trim());
  const update = () => { submit.disabled = busy || !ready(); };
  path.addEventListener('input', update);
  filename.addEventListener('input', update);
  consent.addEventListener('change', update);
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy) return;
    clearDisplay();
    const projectPath = path.value.trim();
    const terraformFile = filename.value.trim();
    if (!ready()) {
      error.textContent = 'Yerel proje klasörü, kök .tf dosya adı ve açık tarama onayı gerekli.';
      error.classList.remove('hidden');
      update();
      return;
    }
    busy = true;
    update();
    try {
      const response = await fetch('/api/tool-runs/trivy-terraform-config', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({confirm_local: true, project_path: projectPath, terraform_file: terraformFile}),
      });
      if (!response.ok) throw new Error('scan_failed');
      const data = await response.json();
      if (!validSummary(data)) throw new Error('invalid_summary');
      document.getElementById('trivy-terraform-config-groups').textContent = String(data.result_count);
      document.getElementById('trivy-terraform-config-total').textContent = String(data.finding_counts.misconfigurations);
      document.getElementById('trivy-terraform-config-hash').textContent = data.report_sha256;
      result.classList.remove('hidden');
      path.value = '';
      filename.value = '';
      consent.checked = false;
    } catch {
      error.textContent = 'Yerel Terraform taraması tamamlanamadı. .tf dosyasını ve Trivy aracını denetleyin.';
      error.classList.remove('hidden');
    } finally {
      busy = false;
      update();
    }
  });
})();
