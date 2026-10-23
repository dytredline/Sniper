(() => {
  const form = document.getElementById("npm-audit-active-form");
  if (!form) return;
  const path = document.getElementById("npm-audit-active-path");
  const localConsent = document.getElementById("npm-audit-active-local-consent");
  const registryConsent = document.getElementById("npm-audit-active-registry-consent");
  const submit = document.getElementById("npm-audit-active-submit");
  const error = document.getElementById("npm-audit-active-error");
  const result = document.getElementById("npm-audit-active-result");
  const count = document.getElementById("npm-audit-active-count");
  const severity = document.getElementById("npm-audit-active-severity");
  const hash = document.getElementById("npm-audit-active-hash");
  const levels = ["info", "low", "moderate", "high", "critical"];
  const responseKeys = ["format", "profile", "affected_package_count", "package_severity_counts", "report_sha256"];
  let busy = false;

  function updateSubmit() {
    submit.disabled = busy || !localConsent.checked || !registryConsent.checked;
  }
  function clearDisplay() {
    error.textContent = "";
    error.classList.add("hidden");
    result.classList.add("hidden");
    count.textContent = "";
    severity.textContent = "";
    hash.textContent = "";
  }
  function validSummary(data) {
    if (!data || typeof data !== "object" || Array.isArray(data)) return false;
    const keys = Object.keys(data);
    if (keys.length !== responseKeys.length || !responseKeys.every(key => keys.includes(key))) return false;
    if (data.format !== "npm-audit-v2" || data.profile !== "local-npm-audit-v1") return false;
    if (!Number.isSafeInteger(data.affected_package_count) || data.affected_package_count < 0 ||
        data.affected_package_count > 500) return false;
    const counts = data.package_severity_counts;
    if (!counts || typeof counts !== "object" || Array.isArray(counts)) return false;
    if (Object.keys(counts).length !== levels.length || !levels.every(key =>
      Object.hasOwn(counts, key) && Number.isSafeInteger(counts[key]) && counts[key] >= 0)) return false;
    if (levels.reduce((total, key) => total + counts[key], 0) !== data.affected_package_count) return false;
    return typeof data.report_sha256 === "string" && /^[0-9a-f]{64}$/.test(data.report_sha256);
  }
  function configuredHome() {
    const value = document.querySelector?.('meta[name="sniper-local-home"]')?.content;
    if (typeof value !== "string" || value.length < 2 || value.length > 1024 ||
        !value.startsWith("/") || value.endsWith("/") || value.includes("//") ||
        /[\\\u0000-\u001f\u007f]/.test(value)) return "";
    return value.split("/").slice(1).every(segment => segment && segment !== "." && segment !== "..") ? value : "";
  }
  function validPath(projectPath) {
    const home = configuredHome();
    if (!home || projectPath.length > 1024 || /[\\\u0000-\u001f\u007f]/.test(projectPath)) return false;
    if (projectPath === home) return true;
    if (!projectPath.startsWith(home + "/")) return false;
    return projectPath.slice(home.length + 1).split("/").every(segment => segment && segment !== "." && segment !== "..");
  }
  localConsent.addEventListener("change", updateSubmit);
  registryConsent.addEventListener("change", updateSubmit);
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (busy) return;
    clearDisplay();
    const projectPath = path.value.trim();
    if (!localConsent.checked || !registryConsent.checked || !validPath(projectPath)) {
      error.textContent = "Hizmet kullanıcısının evindeki yerel proje yolu ve iki açık onay gerekli.";
      error.classList.remove("hidden");
      updateSubmit();
      return;
    }
    busy = true;
    updateSubmit();
    try {
      const data = await api("/api/tool-runs/npm-audit-local", {
        method: "POST",
        body: JSON.stringify({ confirm_local: true, confirm_registry: true, project_path: projectPath }),
      });
      if (!validSummary(data)) throw new Error("invalid_summary");
      count.textContent = String(data.affected_package_count);
      severity.textContent = levels.map(key => `${key}:${data.package_severity_counts[key]}`).join(" ");
      hash.textContent = data.report_sha256;
      result.classList.remove("hidden");
      localConsent.checked = false;
      registryConsent.checked = false;
      path.value = "";
    } catch {
      error.textContent = "npm audit tamamlanamadı. Yerel yolu, resmî registry erişimini ve hizmet durumunu denetleyin.";
      error.classList.remove("hidden");
    } finally {
      busy = false;
      updateSubmit();
    }
  });
})();
