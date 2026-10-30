# Incomplete Fix for CVE-2026-71270 / GHSA-j5rg-wh78-9f2q in ConvertWebsiteToPDF.java Allowing WeasyPrint Sub-Resource SSRF (`GHSA-ff6j-8xch-j8r6`)

**English** | [Türkçe](tr/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | [日本語](ja/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | [简体中文](zh-CN/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | [한국어](ko/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
In `Stirling-Tools/Stirling-PDF` (`v3.2.2`, commit `684608d143779bf3a8ffc67639f077a1202c62ff`), the upstream fix for `CVE-2026-71270` / `GHSA-j5rg-wh78-9f2q` hardened `FileToPdf.java:63-91` (`ConvertHtmlToPDF`) by sanitizing HTML via `customHtmlSanitizer.sanitize()` (`SsrfProtectionService`) and locking WeasyPrint down to `--allowed-protocols data`. However, the sibling endpoint `POST /api/v1/convert/url/pdf` (`ConvertWebsiteToPDF.java:116-143`) was left unpatched, turning remote HTML sub-resource loading into a full-read Server-Side Request Forgery (`CWE-918`):

1. **Step 1 — Missing `customHtmlSanitizer.sanitize()` on Downloaded HTML (`ConvertWebsiteToPDF.java:115-116`):**
   `urlToPdf` fetches the top-level webpage via `String htmlContent = fetchRemoteHtml(URL);` and writes it directly to `tempHtmlInput` without passing `htmlContent` through `customHtmlSanitizer.sanitize(...)`.
2. **Step 2 — Unfettered `http` and `https` Protocols Enabled in WeasyPrint (`ConvertWebsiteToPDF.java:137-140`):**
   Unlike `FileToPdf.java` (which passes `--allowed-protocols data`), `ConvertWebsiteToPDF.java` invokes WeasyPrint with `--base-url <URL>` and `--allowed-protocols data,http,https`. Because WeasyPrint executes as an external Python process, its HTTP client completely bypasses Java's `SsrfProtectionService`.
3. **Step 3 — Exfiltration of Loopback and Cloud Metadata into the Output PDF:**
   When WeasyPrint renders the HTML, it fetches any embedded `<link rel="stylesheet">`, `@import`, or `<img src="...">` targeting `http://127.0.0.1:...`, internal RFC1918 services, or `http://169.254.169.254/...`, rendering the internal response directly into the PDF returned to the caller.

### Vulnerable Code Snippet (`ConvertWebsiteToPDF.java:114-141`)
```java
// File: app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java (lines 114-141)
            // Download the remote content first to ensure we don't allow dangerous schemes
            String htmlContent = fetchRemoteHtml(URL); // BUG 1: Never passed to customHtmlSanitizer.sanitize()!
...
            List<String> command = new ArrayList<>();
            command.add(runtimePathConfig.getWeasyPrintPath());
            command.add(tempHtmlInput.toString());
            command.add("--base-url");
            command.add(URL);
            command.add("--pdf-forms");
            command.add("--allowed-protocols");
            command.add("data,http,https");            // BUG 2: Allows WeasyPrint to fetch arbitrary internal HTTP/HTTPS URLs!
            command.add(tempOutputFile.toString());
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Invoice / Receipt URL-to-PDF SaaS Feature Exfiltrates Cloud IAM Credentials (`169.254.169.254`)
1. A company integrates Stirling-PDF's `/api/v1/convert/url/pdf` API in AWS/GCP/Azure so users or back-office workflows can convert public web receipts or vendor invoices into PDFs by submitting a URL.
2. An attacker submits a public URL (`https://attacker.example/receipt.html`) whose top-level hostname resolves to a public IP and passes initial validation, but whose HTML contains `<link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/iam/security-credentials/prod-role">` or `<link rel="stylesheet" href="http://127.0.0.1:8080/internal-secrets.css">`.
3. WeasyPrint fetches the internal metadata/loopback endpoint with `--allowed-protocols data,http,https` and renders the credentials into the downloadable PDF file.

### Scenario B — Internal Kubernetes Service Mesh & Spring Actuator Reconnaissance via CSS `@import`
1. Stirling-PDF runs inside an enterprise Kubernetes cluster (`cluster.local`) as an internal document conversion microservice exposed through an API gateway.
2. An attacker submits a URL whose HTML embeds `@import url("http://10.96.0.15:9090/metrics");` or references internal Spring Boot Actuator / Consul endpoints (`http://127.0.0.1:8080/actuator/env`).
3. Because WeasyPrint executes outside Java's `SsrfProtectionService`, it fetches those internal RFC1918 and loopback services directly and embeds their responses into the generated PDF.

### Scenario C — Automated Legal / Compliance Web-Archival Pipeline SSRF via Third-Party Webpage
1. A financial or compliance platform automatically archives external vendor webpages into PDFs using Stirling-PDF's `POST /api/v1/convert/url/pdf` endpoint and stores the resulting PDFs in a shared compliance portal.
2. A third-party webpage embeds a sub-resource pointing to `http://127.0.0.1:3000/api/keys` or an intranet service reachable from the Stirling-PDF host.
3. Stirling-PDF's WeasyPrint invocation fetches the internal endpoint and bakes the sensitive internal data into the archived PDF shared with external auditors.

---

## 3. Example Execution & Verification Commands

### 1. Auditing the Component with Sniper CLI
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/Stirling-PDF \
  --include "app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java"
```

### 2. Local Isolated Reproduction & Verification
```bash
# Inspect the unpatched WeasyPrint command construction in ConvertWebsiteToPDF.java vs FileToPdf.java
grep -n -C 8 "allowed-protocols" \
  /home/community-user/targets/Stirling-PDF/app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java \
  /home/community-user/targets/Stirling-PDF/app/common/src/main/java/stirling/software/common/util/FileToPdf.java
```

### 3. Running the Automated `RED -> GREEN + BENIGN` E2E Verification Harness
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand01
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Optional Defensive Diff

Executed via `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand01`:

```json
{
  "STIRLING-CAND-01": {
    "ghsa_id": "GHSA-ff6j-8xch-j8r6",
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
