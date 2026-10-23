import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseOpenSslBatchInputs,
  renderOpenSslBatchPreviewHtml,
  requestOpenSslBatchPreview,
} from "../static/openssl_batch_preview.js";

const SAMPLE_CERT_A = [
  "notBefore=Jan  1 00:00:00 2026 GMT",
  "notAfter=Jan  1 00:00:00 2027 GMT",
  "sha256 Fingerprint=" + Array(32).fill("AA").join(":"),
].join("\n");

const SAMPLE_CERT_B = [
  "notBefore=Jan  1 00:00:00 2024 GMT",
  "notAfter=Jan  1 00:00:00 2025 GMT",
  "sha256 Fingerprint=" + Array(32).fill("BB").join(":"),
].join("\n");

const SAMPLE_PEM_C = [
  "-----BEGIN CERTIFICATE-----",
  "MIIBszCCAVmgAwIBAgIUbtestCertBlockC==",
  "-----END CERTIFICATE-----",
].join("\n");

test("valid batch preview request and escaped HTML rendering", async () => {
  const rawDelimited = `${SAMPLE_CERT_A}\n---CERT---\n${SAMPLE_CERT_B}\n---CERT---\n${SAMPLE_PEM_C}`;
  const parsed = parseOpenSslBatchInputs(rawDelimited);
  assert.deepEqual(parsed, [SAMPLE_CERT_A, SAMPLE_CERT_B, SAMPLE_PEM_C]);

  const blankSeparated = `${SAMPLE_CERT_A}\n\n${SAMPLE_CERT_B}`;
  assert.deepEqual(parseOpenSslBatchInputs(blankSeparated), [SAMPLE_CERT_A, SAMPLE_CERT_B]);

  const calls = [];
  const mockSummary = {
    format: "openssl-x509-batch-summary-v1",
    certificate_count: 3,
    status_counts: {
      valid: 1,
      expired: 1,
      not_yet_valid: 1,
    },
    nearest_expiry_days: 14,
    batch_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    certificates: [
      {
        subject: "CN=api.internal.example",
        issuer: "CN=Example Corp Root CA",
        status: "valid",
        days_until_expiry: 14,
        not_before: "2026-01-01T00:00:00Z",
        not_after: "2027-01-01T00:00:00Z",
        sha256: "a".repeat(64),
      },
      {
        subject: "CN=legacy.internal.example",
        issuer: "CN=Example Corp Root CA",
        status: "expired",
        days_until_expiry: 0,
        not_before: "2024-01-01T00:00:00Z",
        not_after: "2025-01-01T00:00:00Z",
        sha256: "b".repeat(64),
      },
    ],
  };

  const api = async (endpoint, options) => {
    calls.push({ endpoint, options });
    return mockSummary;
  };

  const response = await requestOpenSslBatchPreview(api, parsed);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].endpoint, "/api/tool-reports/openssl-x509/batch-summary");
  assert.equal(calls[0].options.method, "POST");
  assert.deepEqual(JSON.parse(calls[0].options.body), { reports: parsed });
  assert.deepEqual(response, mockSummary);

  const html = renderOpenSslBatchPreviewHtml(response);
  assert.match(html, /data-format="openssl-x509-batch-summary-v1"/);
  assert.match(html, /data-field="certificate_count">3</);
  assert.match(html, /data-field="status_valid">1</);
  assert.match(html, /data-field="status_expired">1</);
  assert.match(html, /data-field="status_not_yet_valid">1</);
  assert.match(html, /data-field="nearest_expiry_days">14</);
  assert.match(
    html,
    /data-field="batch_sha256">e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</
  );
  assert.match(html, /CN=api\.internal\.example/);
  assert.match(html, /CN=legacy\.internal\.example/);
});

test("XSS payload in summary fields is strictly escaped (<script> -> &lt;script&gt;)", () => {
  const maliciousSummary = {
    format: "openssl-x509-batch-summary-v1",
    certificate_count: "<script>alert('count')</script>",
    status_counts: {
      valid: "<script>alert('valid')</script>",
      expired: "<img src=x onerror=alert(1)>",
      not_yet_valid: "<script>alert('nyv')</script>",
    },
    nearest_expiry_days: "<script>alert('days')</script>",
    batch_sha256: "<script>alert('sha')</script>",
    certificates: [
      {
        subject: "<script>alert('subject')</script>",
        issuer: "<script>alert('issuer')</script>",
        status: "<script>alert('status')</script>",
        days_until_expiry: "<script>alert('exp')</script>",
        not_before: "<script>alert('nb')</script>",
        not_after: "<script>alert('na')</script>",
        sha256: "<script>alert('fp')</script>",
      },
    ],
  };

  const customEscape = (val) =>
    String(val ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");

  for (const html of [
    renderOpenSslBatchPreviewHtml(maliciousSummary, customEscape),
    renderOpenSslBatchPreviewHtml(maliciousSummary),
  ]) {
    assert.doesNotMatch(html, /<script>/i);
    assert.doesNotMatch(html, /<\/script>/i);
    assert.doesNotMatch(html, /<img\b/i);
    assert.match(html, /&lt;script&gt;alert\(&#39;subject&#39;\)&lt;\/script&gt;/);
    assert.match(html, /&lt;script&gt;alert\(&#39;sha&#39;\)&lt;\/script&gt;/);
    assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  }
});

test("empty or >8 certificate blocks or oversized payload rejected before calling api", async () => {
  const calls = [];
  const api = async (endpoint, options) => {
    calls.push({ endpoint, options });
    return {};
  };

  for (const emptyInput of ["", "   \n\t  ", "---CERT---", `${SAMPLE_CERT_A}\n---CERT---\n   `, []]) {
    assert.throws(() => parseOpenSslBatchInputs(emptyInput));
    await assert.rejects(() => requestOpenSslBatchPreview(api, emptyInput));
  }

  const elevenBlocksArray = Array.from({ length: 9 }, (_, idx) => `${SAMPLE_CERT_A}\n# ${idx}`);
  const elevenBlocksText = elevenBlocksArray.join("\n---CERT---\n");
  const elevenBlankBlocks = elevenBlocksArray.join("\n\n");

  for (const tooMany of [elevenBlocksArray, elevenBlocksText, elevenBlankBlocks]) {
    assert.throws(() => parseOpenSslBatchInputs(tooMany));
    await assert.rejects(() => requestOpenSslBatchPreview(api, tooMany));
  }

  const oversizedInput = "A".repeat(65537);
  assert.throws(() => parseOpenSslBatchInputs(oversizedInput));
  await assert.rejects(() => requestOpenSslBatchPreview(api, oversizedInput));

  assert.equal(calls.length, 0);
});
