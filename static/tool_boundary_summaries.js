// Unified bounded tool workflow UI summary renderers and API helpers.
// Strictly escapes all dynamic fields and never executes active scans directly.

const NUCLEI_VERIFICATION_ENDPOINT = "/api/tool-reports/nuclei/verification-coverage";
const BURP_HANDOFF_ENDPOINT = "/api/tool-reports/burp-sitemap/handoff-manifest";
const DEPENDENCY_PLAN_ENDPOINT = "/api/tool-reports/dependencies/remediation-plan";
const SECRET_BUNDLE_ENDPOINT = "/api/tool-runs/secret-bundle/validate";

export function defaultEscapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function createEscaper(escapeHtml) {
  if (typeof escapeHtml === "function") {
    return (value) =>
      String(escapeHtml(String(value ?? "")))
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
  }
  return defaultEscapeHtml;
}

function assertPlainObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Geçersiz ${label} verisi.`);
  }
}

export function renderNucleiVerificationCoverageHtml(summary, escapeHtml) {
  assertPlainObject(summary, "Nuclei doğrulama kapsam özeti");
  if (
    summary.finding_count === undefined &&
    summary.findings === undefined &&
    summary.format !== "nuclei-verification-coverage-v1"
  ) {
    throw new Error("Eksik Nuclei doğrulama kapsam özeti alanları.");
  }
  if (summary.findings !== undefined && !Array.isArray(summary.findings)) {
    throw new Error("Nuclei bulgu listesi dizi olmalıdır.");
  }
  if (
    summary.matched_template_ids !== undefined &&
    !Array.isArray(summary.matched_template_ids)
  ) {
    throw new Error("Eşleşen şablon listesi dizi olmalıdır.");
  }
  if (
    summary.executed_template_ids !== undefined &&
    !Array.isArray(summary.executed_template_ids)
  ) {
    throw new Error("Çalıştırılan şablon listesi dizi olmalıdır.");
  }
  if (
    summary.unmatched_executed_template_ids !== undefined &&
    !Array.isArray(summary.unmatched_executed_template_ids)
  ) {
    throw new Error("Eşleşmeyen şablon listesi dizi olmalıdır.");
  }
  if (
    summary.severity_counts !== undefined &&
    (!summary.severity_counts ||
      typeof summary.severity_counts !== "object" ||
      Array.isArray(summary.severity_counts))
  ) {
    throw new Error("Nuclei önem dağılımı nesne olmalıdır.");
  }

  const esc = createEscaper(escapeHtml);
  const findings = summary.findings ?? [];
  const matchedIds = summary.matched_template_ids ?? [];
  const executedIds = summary.executed_template_ids ?? [];
  const unmatchedIds = summary.unmatched_executed_template_ids ?? [];
  const sev = summary.severity_counts ?? {};

  const findingRows = findings
    .map((item, idx) => {
      assertPlainObject(item, "Nuclei bulgu satırı");
      return (
        `<tr class="nuclei-coverage-finding-row" data-index="${idx}">` +
        `<td data-field="template_id">${esc(item.template_id ?? "-")}</td>` +
        `<td data-field="type">${esc(item.type ?? "-")}</td>` +
        `<td data-field="severity">${esc(item.severity ?? "unknown")}</td>` +
        `<td data-field="verification_state">${esc(
          item.verification_state ?? "independent_confirmation_required"
        )}</td>` +
        `</tr>`
      );
    })
    .join("");

  return (
    `<div class="tool-boundary-card nuclei-verification-coverage-card" data-format="${esc(
      summary.format ?? "nuclei-verification-coverage-v1"
    )}">` +
    `<div class="boundary-meta">` +
    `<span data-field="coverage_scope">${esc(
      summary.coverage_scope ?? "bounded_template_subset_only"
    )}</span>` +
    `<span data-field="verification_policy">${esc(
      summary.verification_policy ?? "independent_confirmation_required"
    )}</span>` +
    `<span data-field="finding_count">${esc(summary.finding_count ?? findings.length)}</span>` +
    `<span data-field="unverified_finding_count">${esc(
      summary.unverified_finding_count ?? findings.length
    )}</span>` +
    `<span data-field="executed_template_count">${esc(
      summary.executed_template_count ?? executedIds.length
    )}</span>` +
    `<span data-field="unmatched_executed_template_count">${esc(
      summary.unmatched_executed_template_count ?? unmatchedIds.length
    )}</span>` +
    `</div>` +
    `<div class="boundary-severities">` +
    `<span data-field="sev_critical">${esc(sev.critical ?? 0)}</span>` +
    `<span data-field="sev_high">${esc(sev.high ?? 0)}</span>` +
    `<span data-field="sev_medium">${esc(sev.medium ?? 0)}</span>` +
    `<span data-field="sev_low">${esc(sev.low ?? 0)}</span>` +
    `<span data-field="sev_info">${esc(sev.info ?? 0)}</span>` +
    `<span data-field="sev_unknown">${esc(sev.unknown ?? 0)}</span>` +
    `</div>` +
    `<div class="boundary-templates">` +
    `<div data-field="matched_template_ids">${matchedIds.map((id) => esc(id)).join(", ")}</div>` +
    `<div data-field="executed_template_ids">${executedIds.map((id) => esc(id)).join(", ")}</div>` +
    `<div data-field="unmatched_executed_template_ids">${unmatchedIds
      .map((id) => esc(id))
      .join(", ")}</div>` +
    `</div>` +
    `<table class="boundary-table"><tbody>${findingRows}</tbody></table>` +
    `<div class="boundary-digests">` +
    `<code data-field="report_sha256">${esc(summary.report_sha256 ?? "")}</code>` +
    `<code data-field="summary_sha256">${esc(summary.summary_sha256 ?? "")}</code>` +
    `</div>` +
    `</div>`
  );
}

export function renderBurpHandoffManifestHtml(manifest, escapeHtml) {
  assertPlainObject(manifest, "Burp devir manifestosu");
  if (
    manifest.allowed_host === undefined &&
    manifest.in_scope_endpoint_count === undefined &&
    manifest.format !== "burp-manual-handoff-v1"
  ) {
    throw new Error("Eksik Burp devir manifestosu alanları.");
  }
  if (manifest.methods_observed !== undefined && !Array.isArray(manifest.methods_observed)) {
    throw new Error("Burp gözlemlenen HTTP metotları dizi olmalıdır.");
  }
  if (
    manifest.status_counts !== undefined &&
    (!manifest.status_counts ||
      typeof manifest.status_counts !== "object" ||
      Array.isArray(manifest.status_counts))
  ) {
    throw new Error("Burp durum sayıları nesne olmalıdır.");
  }
  if (
    manifest.mimetype_counts !== undefined &&
    (!manifest.mimetype_counts ||
      typeof manifest.mimetype_counts !== "object" ||
      Array.isArray(manifest.mimetype_counts))
  ) {
    throw new Error("Burp MIME türü sayıları nesne olmalıdır.");
  }

  const esc = createEscaper(escapeHtml);
  const methods = (manifest.methods_observed ?? []).map((m) => esc(m)).join(", ");
  const statusEntries = Object.entries(manifest.status_counts ?? {})
    .map(([k, v]) => `<span class="status-bucket" data-bucket="${esc(k)}">${esc(k)}:${esc(v)}</span>`)
    .join(" ");
  const mimeEntries = Object.entries(manifest.mimetype_counts ?? {})
    .map(([k, v]) => `<span class="mime-bucket" data-mime="${esc(k)}">${esc(k)}:${esc(v)}</span>`)
    .join(" ");

  return (
    `<div class="tool-boundary-card burp-handoff-manifest-card" data-format="${esc(
      manifest.format ?? "burp-manual-handoff-v1"
    )}">` +
    `<div class="boundary-meta">` +
    `<span data-field="automation_mode">${esc(
      manifest.automation_mode ?? "manual_operator_guided_only"
    )}</span>` +
    `<span data-field="allowed_host">${esc(manifest.allowed_host ?? "")}</span>` +
    `<span data-field="in_scope_endpoint_count">${esc(
      manifest.in_scope_endpoint_count ?? 0
    )}</span>` +
    `<span data-field="parameterized_endpoint_count">${esc(
      manifest.parameterized_endpoint_count ?? 0
    )}</span>` +
    `<span data-field="methods_observed">${methods}</span>` +
    `</div>` +
    `<div class="boundary-buckets" data-field="status_counts">${statusEntries}</div>` +
    `<div class="boundary-buckets" data-field="mimetype_counts">${mimeEntries}</div>` +
    `<div class="boundary-digests">` +
    `<code data-field="sitemap_report_sha256">${esc(
      manifest.sitemap_report_sha256 ?? ""
    )}</code>` +
    `<code data-field="manifest_sha256">${esc(manifest.manifest_sha256 ?? "")}</code>` +
    `</div>` +
    `</div>`
  );
}

export function renderDependencyRemediationPlanHtml(plan, escapeHtml) {
  assertPlainObject(plan, "Bağımlılık iyileştirme planı");
  if (
    plan.package_actions === undefined &&
    plan.total_advisories === undefined &&
    plan.format !== "dependency-remediation-plan-v1"
  ) {
    throw new Error("Eksik bağımlılık iyileştirme planı alanları.");
  }
  if (plan.package_actions !== undefined && !Array.isArray(plan.package_actions)) {
    throw new Error("Paket aksiyon listesi dizi olmalıdır.");
  }
  if (
    plan.severity_totals !== undefined &&
    (!plan.severity_totals ||
      typeof plan.severity_totals !== "object" ||
      Array.isArray(plan.severity_totals))
  ) {
    throw new Error("Önem toplamları nesne olmalıdır.");
  }

  const esc = createEscaper(escapeHtml);
  const actions = plan.package_actions ?? [];
  const sev = plan.severity_totals ?? {};

  const actionRows = actions
    .map((item, idx) => {
      assertPlainObject(item, "Paket aksiyon satırı");
      return (
        `<tr class="dependency-action-row" data-index="${idx}">` +
        `<td data-field="ecosystem">${esc(item.ecosystem ?? "-")}</td>` +
        `<td data-field="package">${esc(item.package ?? "-")}</td>` +
        `<td data-field="max_severity">${esc(item.max_severity ?? "-")}</td>` +
        `<td data-field="fixed_version_available">${esc(
          Boolean(item.fixed_version_available)
        )}</td>` +
        `<td data-field="recommended_action">${esc(item.recommended_action ?? "-")}</td>` +
        `</tr>`
      );
    })
    .join("");

  return (
    `<div class="tool-boundary-card dependency-remediation-plan-card" data-format="${esc(
      plan.format ?? "dependency-remediation-plan-v1"
    )}">` +
    `<div class="boundary-meta">` +
    `<span data-field="mutates_lockfile">${esc(Boolean(plan.mutates_lockfile))}</span>` +
    `<span data-field="network_sync">${esc(
      plan.network_sync ?? "offline_saved_reports_only"
    )}</span>` +
    `<span data-field="total_advisories">${esc(plan.total_advisories ?? actions.length)}</span>` +
    `</div>` +
    `<div class="boundary-severities">` +
    `<span data-field="sev_critical">${esc(sev.critical ?? 0)}</span>` +
    `<span data-field="sev_high">${esc(sev.high ?? 0)}</span>` +
    `<span data-field="sev_medium">${esc(sev.medium ?? 0)}</span>` +
    `<span data-field="sev_low">${esc(sev.low ?? 0)}</span>` +
    `<span data-field="sev_info">${esc(sev.info ?? 0)}</span>` +
    `</div>` +
    `<table class="boundary-table"><tbody>${actionRows}</tbody></table>` +
    `<div class="boundary-digests">` +
    `<code data-field="plan_sha256">${esc(plan.plan_sha256 ?? "")}</code>` +
    `</div>` +
    `</div>`
  );
}

export function renderSecretBundleManifestHtml(manifest, escapeHtml) {
  assertPlainObject(manifest, "Gizli bilgi tarama paketi manifestosu");
  if (
    manifest.files === undefined &&
    manifest.file_count === undefined &&
    manifest.format !== "secret-scan-bundle-manifest-v1"
  ) {
    throw new Error("Eksik gizli bilgi tarama paketi manifestosu alanları.");
  }
  if (manifest.files !== undefined && !Array.isArray(manifest.files)) {
    throw new Error("Paket dosya listesi dizi olmalıdır.");
  }

  const esc = createEscaper(escapeHtml);
  const files = manifest.files ?? [];

  const fileRows = files
    .map((entry, idx) => {
      assertPlainObject(entry, "Paket dosya satırı");
      return (
        `<tr class="secret-bundle-file-row" data-index="${idx}">` +
        `<td data-field="relative_path">${esc(entry.relative_path ?? "-")}</td>` +
        `<td data-field="size_bytes">${esc(entry.size_bytes ?? 0)}</td>` +
        `<td data-field="sha256"><code>${esc(entry.sha256 ?? "-")}</code></td>` +
        `</tr>`
      );
    })
    .join("");

  return (
    `<div class="tool-boundary-card secret-bundle-manifest-card" data-format="${esc(
      manifest.format ?? "secret-scan-bundle-manifest-v1"
    )}">` +
    `<div class="boundary-meta">` +
    `<span data-field="scope">${esc(
      manifest.scope ?? "explicit_in_memory_bundle_only"
    )}</span>` +
    `<span data-field="file_count">${esc(manifest.file_count ?? files.length)}</span>` +
    `<span data-field="total_bytes">${esc(manifest.total_bytes ?? 0)}</span>` +
    `</div>` +
    `<table class="boundary-table"><tbody>${fileRows}</tbody></table>` +
    `<div class="boundary-digests">` +
    `<code data-field="bundle_sha256">${esc(manifest.bundle_sha256 ?? "")}</code>` +
    `</div>` +
    `</div>`
  );
}

export async function requestNucleiVerificationCoverage(
  api,
  report,
  executedTemplateIds = []
) {
  if (typeof api !== "function") {
    throw new Error("Geçerli bir API istemcisi gereklidir.");
  }
  if (typeof report !== "string" || !report.trim()) {
    throw new Error("Nuclei JSONL raporu boş olamaz.");
  }
  if (!Array.isArray(executedTemplateIds)) {
    throw new Error("executedTemplateIds dizi olmalıdır.");
  }
  return await api(NUCLEI_VERIFICATION_ENDPOINT, {
    method: "POST",
    body: JSON.stringify({
      report,
      executed_template_ids: executedTemplateIds,
    }),
  });
}

export async function requestBurpHandoffManifest(api, report, allowedHost) {
  if (typeof api !== "function") {
    throw new Error("Geçerli bir API istemcisi gereklidir.");
  }
  if (typeof report !== "string" || !report.trim()) {
    throw new Error("Burp sitemap XML raporu boş olamaz.");
  }
  if (typeof allowedHost !== "string" || !allowedHost.trim()) {
    throw new Error("İzin verilen hedef ana bilgisayar adı gereklidir.");
  }
  return await api(BURP_HANDOFF_ENDPOINT, {
    method: "POST",
    body: JSON.stringify({
      report,
      allowed_host: allowedHost.trim(),
    }),
  });
}

export async function requestDependencyRemediationPlan(
  api,
  { npmAuditReport = null, dependabotReport = null } = {}
) {
  if (typeof api !== "function") {
    throw new Error("Geçerli bir API istemcisi gereklidir.");
  }
  if (npmAuditReport === null && dependabotReport === null) {
    throw new Error("En az bir bağımlılık raporu sağlanmalıdır.");
  }
  return await api(DEPENDENCY_PLAN_ENDPOINT, {
    method: "POST",
    body: JSON.stringify({
      npm_audit_report: npmAuditReport,
      dependabot_report: dependabotReport,
    }),
  });
}

export async function requestSecretBundleManifest(api, files) {
  if (typeof api !== "function") {
    throw new Error("Geçerli bir API istemcisi gereklidir.");
  }
  if (!Array.isArray(files) || files.length < 1 || files.length > 16) {
    throw new Error("Gizli bilgi tarama paketi 1 ile 16 arasında dosya içermelidir.");
  }
  return await api(SECRET_BUNDLE_ENDPOINT, {
    method: "POST",
    body: JSON.stringify({ files }),
  });
}

// app.js'teki aynı adlı yardımcıları ezmemek için tek bir ad alanı altında yayımlanır
// (gelişmiş araç akışları paneli bu işleyicileri kullanır).
if (typeof globalThis !== "undefined") {
  globalThis.SniperToolBoundary = Object.freeze({
    renderNucleiVerificationCoverageHtml,
    renderBurpHandoffManifestHtml,
    renderDependencyRemediationPlanHtml,
    renderSecretBundleManifestHtml,
    requestNucleiVerificationCoverage,
    requestBurpHandoffManifest,
    requestDependencyRemediationPlan,
    requestSecretBundleManifest,
  });
}
