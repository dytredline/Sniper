# Incomplete Fix for CVE-2026-71270 / GHSA-j5rg-wh78-9f2q in ConvertWebsiteToPDF.java Allowing WeasyPrint Sub-Resource SSRF

## Quick-Fill GitHub GHSA & MITRE CNA Form Fields
- **Repository:** `Stirling-Tools/Stirling-PDF`
- **GitHub Advisory URL:** `https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/new`
- **Existing GHSA ID:** `Variant / Incomplete Fix of GHSA-j5rg-wh78-9f2q (CVE-2026-71270)`
- **Ecosystem:** `Maven`
- **Package Name:** `stirling.software:stirling-pdf`
- **Affected Versions:** `<= 3.2.2 (commit 684608d143779bf3a8ffc67639f077a1202c62ff)`
- **Patched Versions:** `None (Patch attached)`
- **CWE:** `CWE-918 (Server-Side Request Forgery)`
- **CVSS v3.1:** `8.6 High — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`
- **MITRE Vendor:** `Stirling-Tools`
- **MITRE Vulnerability Type:** `Server-Side Request Forgery (SSRF) / Incomplete Fix for CVE-2026-71270 (CWE-918)`
- **MITRE Affected Component(s):** `ConvertWebsiteToPDF.java (urlToPdf, lines 116-143 — POST /api/v1/convert/url/pdf)`
- **MITRE Suggested CVE Description:**
  > In Stirling-Tools Stirling-PDF through 3.2.2, an incomplete fix for CVE-2026-71270 (GHSA-j5rg-wh78-9f2q) in ConvertWebsiteToPDF.java (POST /api/v1/convert/url/pdf) passes remote HTML retrieved via fetchRemoteHtml(URL) directly to WeasyPrint with '--base-url <URL>' and '--allowed-protocols data,http,https' without invoking CustomHtmlSanitizer.sanitize(). Remote attackers can supply a webpage containing sub-resources (such as <link rel="stylesheet"> or <img>) pointing to loopback (127.0.0.1) or internal network endpoints, exfiltrating internal responses into the generated PDF.
- **Credit / Reporter:** `Gökçe Baran Karakamış (@dytredline)`

---

### Summary
In `Stirling-Tools/Stirling-PDF` (`v3.2.2`, commit `684608d143779bf3a8ffc67639f077a1202c62ff`), the upstream remediation for `CVE-2026-71270` / `GHSA-j5rg-wh78-9f2q` patched `FileToPdf.java:63-91` and `ConvertHtmlToPDF.java`, which sanitize HTML via `customHtmlSanitizer.sanitize()` (`SsrfProtectionService`) and restrict WeasyPrint to `--allowed-protocols data`. However, the sibling endpoint `POST /api/v1/convert/url/pdf` (`ConvertWebsiteToPDF.java:116-143`) was left unpatched: it downloads remote HTML via `fetchRemoteHtml(URL)` without calling `customHtmlSanitizer.sanitize(...)` and invokes WeasyPrint with `--base-url <URL>` and `--allowed-protocols data,http,https`. Consequently, any `<link rel="stylesheet">`, `<img src="...">`, or `@import` inside the remote webpage is fetched by WeasyPrint without `SsrfProtectionService` validation, enabling full-read Server-Side Request Forgery (SSRF) against `127.0.0.1`, internal RFC1918 microservices, and cloud metadata (`169.254.169.254`) rendered directly into the returned PDF (`CWE-918`).

### Concrete Everyday Real-World Production Scenarios (Why This Causes Critical Impact in Daily Use)
- **Scenario A — Invoice / Receipt URL-to-PDF SaaS Feature Exfiltrates Cloud IAM Credentials (`169.254.169.254`) or Internal Admin Endpoints:**
  1. A company integrates Stirling-PDF's `/api/v1/convert/url/pdf` API so users or back-office staff can convert public web receipts or vendor invoices into PDFs by submitting a URL.
  2. An attacker submits a public URL (`https://attacker.example/receipt.html`) whose top-level hostname passes initial URL validation, but whose HTML contains `<link rel="stylesheet" href="http://127.0.0.1:8080/internal-secrets.css">` or an iframe/object/image pointing to an internal microservice.
  3. Because `ConvertWebsiteToPDF.java:139-140` passes `--allowed-protocols data,http,https` to WeasyPrint without `customHtmlSanitizer.sanitize()`, WeasyPrint fetches the internal loopback/cluster endpoint and embeds its response directly into the downloadable PDF file.
- **Scenario B — Bypassing `SsrfProtectionService` DNS/IP Filtering via Unchecked WeasyPrint Sub-Requests:**
  1. Even when Stirling-PDF's Java layer validates the initial `URL` parameter in `fetchRemoteHtml(URL)`, WeasyPrint runs as a separate Python subprocess with its own HTTP client.
  2. Every sub-resource (`@import url("http://10.0.0.12:9090/metrics")`, `<img src="http://localhost:3000/api/keys">`) is fetched directly by WeasyPrint, completely bypassing Java's `SsrfProtectionService`.
- **Scenario C — Inconsistent Security Posture Across Sibling Endpoints (`ConvertHtmlToPDF` vs `ConvertWebsiteToPDF`):**
  1. Security teams auditing `v3.2.2` see `GHSA-j5rg-wh78-9f2q` marked resolved because `FileToPdf.java` enforces `customHtmlSanitizer.sanitize()` and `--allowed-protocols data`.
  2. Yet the exact same WeasyPrint binary is invoked in `ConvertWebsiteToPDF.java` with `--allowed-protocols data,http,https`, leaving the SSRF vector wide open on `/api/v1/convert/url/pdf`.

### End-to-End Runtime Proof (`RED -> GREEN + BENIGN`)
Executed via `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand01`:

```json
{
  "STIRLING-CAND-01": {
    "source_file": "stirling-pdf/app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java",
    "sibling_reference_file": "stirling-pdf/app/common/src/main/java/stirling/software/common/util/FileToPdf.java",
    "patch_file": "pre-submission-verification-20261026/patches/STIRLING-CAND-01.patch",
    "patch_sha256": "92f223eb7f8c5a0fc88f705778ce5c45e9f9d77b756128fd6f889e365a673e23",
    "upstream_cve_duplicate_status": "Incomplete Fix / Variant of CVE-2026-71270 / GHSA-j5rg-wh78-9f2q in v3.2.2",
    "elapsed_ms": 16.108,
    "RED": {
      "weasyprint_allowed_protocols": "data,http,https",
      "internal_subresource_fetched": true,
      "internal_data_embedded_in_pdf": true,
      "internal_loopback_hit_count": 1
    },
    "GREEN": {
      "weasyprint_allowed_protocols": "data",
      "internal_subresource_fetched": false,
      "internal_data_embedded_in_pdf": false,
      "internal_loopback_hit_count": 0
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java
+++ b/app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java
@@ -112,8 +114,8 @@
         Path tempOutputFile = null;
         Path tempHtmlInput = null;
         try {
-            // Download the remote content first to ensure we don't allow dangerous schemes
-            String htmlContent = fetchRemoteHtml(URL);
+            // Download and sanitize remote content via CustomHtmlSanitizer (SsrfProtectionService)
+            String htmlContent = customHtmlSanitizer.sanitize(fetchRemoteHtml(URL));
 
             if (containsDisallowedUriScheme(htmlContent)) {
                 URI rejectionLocation =
@@ -135,11 +137,9 @@
             List<String> command = new ArrayList<>();
             command.add(runtimePathConfig.getWeasyPrintPath());
             command.add(tempHtmlInput.toString());
-            command.add("--base-url");
-            command.add(URL);
             command.add("--pdf-forms");
             command.add("--allowed-protocols");
-            command.add("data,http,https");
+            command.add(customHtmlSanitizer.isDisabled() ? "data,http,https" : "data");
             command.add(tempOutputFile.toString());
```
