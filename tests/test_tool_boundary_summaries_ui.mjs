import assert from "node:assert/strict";
import { test } from "node:test";
import {
  renderNucleiVerificationCoverageHtml,
  renderBurpHandoffManifestHtml,
  renderDependencyRemediationPlanHtml,
  renderSecretBundleManifestHtml,
  requestNucleiVerificationCoverage,
  requestBurpHandoffManifest,
  requestDependencyRemediationPlan,
  requestSecretBundleManifest,
} from "../static/tool_boundary_summaries.js";

test("all 4 boundary summary renderers render valid inputs and API callers send bounded requests", async () => {
  const nucleiSummary = {
    format: "nuclei-verification-coverage-v1",
    coverage_scope: "bounded_template_subset_only",
    verification_policy: "independent_confirmation_required",
    finding_count: 1,
    unverified_finding_count: 1,
    severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0, unknown: 0 },
    matched_template_ids: ["http/exposures/env-file"],
    executed_template_ids: ["http/exposures/env-file", "http/misconfig/debug-header"],
    executed_template_count: 2,
    unmatched_executed_template_ids: ["http/misconfig/debug-header"],
    unmatched_executed_template_count: 1,
    findings: [
      {
        template_id: "http/exposures/env-file",
        type: "http",
        severity: "high",
        verification_state: "independent_confirmation_required",
      },
    ],
    report_sha256: "a".repeat(64),
    summary_sha256: "b".repeat(64),
  };

  const nucleiHtml = renderNucleiVerificationCoverageHtml(nucleiSummary);
  assert.match(nucleiHtml, /data-format="nuclei-verification-coverage-v1"/);
  assert.match(nucleiHtml, /http\/exposures\/env-file/);
  assert.match(nucleiHtml, /independent_confirmation_required/);
  assert.match(nucleiHtml, /data-field="unmatched_executed_template_count">1</);

  const burpManifest = {
    format: "burp-manual-handoff-v1",
    automation_mode: "manual_operator_guided_only",
    allowed_host: "app.internal.example",
    in_scope_endpoint_count: 4,
    methods_observed: ["GET", "POST"],
    parameterized_endpoint_count: 2,
    status_counts: { "2xx": 3, "4xx": 1 },
    mimetype_counts: { JSON: 3, HTML: 1 },
    sitemap_report_sha256: "c".repeat(64),
    manifest_sha256: "d".repeat(64),
  };

  const burpHtml = renderBurpHandoffManifestHtml(burpManifest);
  assert.match(burpHtml, /data-format="burp-manual-handoff-v1"/);
  assert.match(burpHtml, /app\.internal\.example/);
  assert.match(burpHtml, /GET, POST/);
  assert.match(burpHtml, /2xx:3/);

  const depPlan = {
    format: "dependency-remediation-plan-v1",
    mutates_lockfile: false,
    network_sync: "offline_saved_reports_only",
    total_advisories: 2,
    severity_totals: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
    package_actions: [
      {
        ecosystem: "npm",
        package: "lodash",
        max_severity: "critical",
        fixed_version_available: true,
        recommended_action: "review_and_pin_patched_version_manually",
      },
    ],
    plan_sha256: "e".repeat(64),
  };

  const depHtml = renderDependencyRemediationPlanHtml(depPlan);
  assert.match(depHtml, /data-format="dependency-remediation-plan-v1"/);
  assert.match(depHtml, /offline_saved_reports_only/);
  assert.match(depHtml, /lodash/);
  assert.match(depHtml, /review_and_pin_patched_version_manually/);

  const secretManifest = {
    format: "secret-scan-bundle-manifest-v1",
    scope: "explicit_in_memory_bundle_only",
    file_count: 1,
    total_bytes: 42,
    files: [
      {
        relative_path: "src/config.yaml",
        size_bytes: 42,
        sha256: "f".repeat(64),
      },
    ],
    bundle_sha256: "0".repeat(64),
  };

  const secretHtml = renderSecretBundleManifestHtml(secretManifest);
  assert.match(secretHtml, /data-format="secret-scan-bundle-manifest-v1"/);
  assert.match(secretHtml, /explicit_in_memory_bundle_only/);
  assert.match(secretHtml, /src\/config\.yaml/);

  const calls = [];
  const api = async (url, options) => {
    calls.push({ url, options });
    return { ok: true };
  };
  await requestNucleiVerificationCoverage(api, '{"template-id":"t1"}\n', ["t1"]);
  await requestBurpHandoffManifest(api, "<items></items>", "app.internal.example");
  await requestDependencyRemediationPlan(api, { npmAuditReport: "{}" });
  await requestSecretBundleManifest(api, [{ relative_path: "a.txt", content: "x" }]);
  assert.equal(calls.length, 4);
  assert.equal(calls[0].url, "/api/tool-reports/nuclei/verification-coverage");
  assert.equal(calls[1].url, "/api/tool-reports/burp-sitemap/handoff-manifest");
  assert.equal(calls[2].url, "/api/tool-reports/dependencies/remediation-plan");
  assert.equal(calls[3].url, "/api/tool-runs/secret-bundle/validate");
});

test("XSS payloads (<script>, attribute breakouts) are strictly escaped across all 4 renderers", () => {
  const xssTag = "<script>alert('xss')</script>";
  const xssAttr = '" onload="alert(1)';

  const customEscape = (s) =>
    String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");

  const nucleiXss = renderNucleiVerificationCoverageHtml(
    {
      format: `nuclei-verification-coverage-v1${xssAttr}`,
      coverage_scope: xssTag,
      verification_policy: xssAttr,
      finding_count: xssTag,
      matched_template_ids: [xssTag],
      executed_template_ids: [xssAttr],
      unmatched_executed_template_ids: [xssTag],
      findings: [
        {
          template_id: xssTag,
          type: xssAttr,
          severity: xssTag,
          verification_state: xssAttr,
        },
      ],
      report_sha256: xssTag,
      summary_sha256: xssAttr,
    },
    customEscape
  );

  const burpXss = renderBurpHandoffManifestHtml(
    {
      format: "burp-manual-handoff-v1",
      automation_mode: xssTag,
      allowed_host: `${xssTag}${xssAttr}`,
      in_scope_endpoint_count: 1,
      methods_observed: [xssTag],
      status_counts: { [xssAttr]: xssTag },
      mimetype_counts: { [xssTag]: xssAttr },
      sitemap_report_sha256: xssTag,
      manifest_sha256: xssAttr,
    },
    customEscape
  );

  const depXss = renderDependencyRemediationPlanHtml(
    {
      format: "dependency-remediation-plan-v1",
      network_sync: xssTag,
      total_advisories: 1,
      package_actions: [
        {
          ecosystem: xssTag,
          package: `${xssTag}${xssAttr}`,
          max_severity: xssAttr,
          fixed_version_available: true,
          recommended_action: xssTag,
        },
      ],
      plan_sha256: xssAttr,
    },
    customEscape
  );

  const secretXss = renderSecretBundleManifestHtml(
    {
      format: "secret-scan-bundle-manifest-v1",
      scope: xssTag,
      file_count: 1,
      total_bytes: 10,
      files: [
        {
          relative_path: `${xssTag}${xssAttr}`,
          size_bytes: xssTag,
          sha256: xssAttr,
        },
      ],
      bundle_sha256: xssTag,
    },
    customEscape
  );

  for (const html of [nucleiXss, burpXss, depXss, secretXss]) {
    assert.doesNotMatch(html, /<script>/i);
    assert.doesNotMatch(html, /<\/script>/i);
    assert.doesNotMatch(html, /" onload="/i);
    assert.match(html, /&lt;script&gt;alert\(&#39;xss&#39;\)&lt;\/script&gt;/);
    assert.match(html, /&quot; onload=&quot;alert\(1\)/);
  }
});

test("malformed and null inputs are rejected by all 4 renderers and API callers", async () => {
  const renderers = [
    renderNucleiVerificationCoverageHtml,
    renderBurpHandoffManifestHtml,
    renderDependencyRemediationPlanHtml,
    renderSecretBundleManifestHtml,
  ];

  for (const render of renderers) {
    for (const invalid of [null, undefined, "", 123, [], {}]) {
      assert.throws(() => render(invalid));
    }
  }

  assert.throws(() =>
    renderNucleiVerificationCoverageHtml({
      format: "nuclei-verification-coverage-v1",
      findings: "not-an-array",
    })
  );
  assert.throws(() =>
    renderBurpHandoffManifestHtml({
      format: "burp-manual-handoff-v1",
      methods_observed: "GET",
    })
  );
  assert.throws(() =>
    renderDependencyRemediationPlanHtml({
      format: "dependency-remediation-plan-v1",
      package_actions: "not-an-array",
    })
  );
  assert.throws(() =>
    renderSecretBundleManifestHtml({
      format: "secret-scan-bundle-manifest-v1",
      files: "not-an-array",
    })
  );

  const noopApi = async () => ({});
  await assert.rejects(() => requestNucleiVerificationCoverage(noopApi, ""));
  await assert.rejects(() => requestBurpHandoffManifest(noopApi, "<items/>", ""));
  await assert.rejects(() => requestDependencyRemediationPlan(noopApi, {}));
  await assert.rejects(() => requestSecretBundleManifest(noopApi, []));
});
