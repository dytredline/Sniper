# ConvertWebsiteToPDF.java 对 CVE-2026-71270 / GHSA-j5rg-wh78-9f2q 修复不完整导致 WeasyPrint 子资源 SSRF (`GHSA-ff6j-8xch-j8r6`)

[English](../02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | [Türkçe](../tr/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | [日本語](../ja/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | **简体中文** | [한국어](../ko/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)

## GitHub GHSA 与 MITRE CNA 表单快速填写字段
- **代码仓库:** `Stirling-Tools/Stirling-PDF`
- **GitHub 安全公告 URL:** `https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/GHSA-ff6j-8xch-j8r6`
- **现有 GHSA ID:** `GHSA-ff6j-8xch-j8r6 (GHSA-j5rg-wh78-9f2q / CVE-2026-71270 的不完整修复变体)`
- **生态系统:** `Maven`
- **软件包名称:** `stirling.software:stirling-pdf`
- **受影响版本:** `<= 3.2.2 (commit 684608d143779bf3a8ffc67639f077a1202c62ff)`
- **已修复版本:** `无（附修复补丁）`
- **CWE:** `CWE-918 (服务端请求伪造 — SSRF)`
- **CVSS v3.1:** `8.6 High — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`
- **MITRE 厂商:** `Stirling-Tools`
- **MITRE 漏洞类型:** `Server-Side Request Forgery (SSRF) / Incomplete Fix for CVE-2026-71270 (CWE-918)`
- **MITRE 受影响组件:** `ConvertWebsiteToPDF.java (urlToPdf, lines 116-143 — POST /api/v1/convert/url/pdf)`
- **MITRE 建议漏洞描述:**
  > 在 Stirling-Tools Stirling-PDF 3.2.2 及更早版本中，`ConvertWebsiteToPDF.java`（`POST /api/v1/convert/url/pdf`）对 `CVE-2026-71270`（`GHSA-j5rg-wh78-9f2q`）的修复不完整，将 `fetchRemoteHtml(URL)` 获取的远程 HTML 未经 `CustomHtmlSanitizer.sanitize()` 净化便直接连同 `--base-url <URL>` 和 `--allowed-protocols data,http,https` 传递给 WeasyPrint。远程攻击者可提供包含指向本地回环（`127.0.0.1`）或内网端点的子资源（如 `<link rel="stylesheet">` 或 `<img>`）的网页，将内部服务响应泄露到生成的 PDF 文件中。
- **报告者 / 致谢:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. 代码缺陷如何演变为可被利用的安全漏洞

### 分步技术机制剖析
在 `Stirling-Tools/Stirling-PDF`（`v3.2.2`，提交 `684608d143779bf3a8ffc67639f077a1202c62ff`）中，上游针对 `CVE-2026-71270` / `GHSA-j5rg-wh78-9f2q` 的补丁通过 `customHtmlSanitizer.sanitize()`（`SsrfProtectionService`）净化 HTML 并将 WeasyPrint 锁定为 `--allowed-protocols data`，加固了 `FileToPdf.java:63-91`（`ConvertHtmlToPDF`）。然而，相邻端点 `POST /api/v1/convert/url/pdf`（`ConvertWebsiteToPDF.java:116-143`）却被遗漏，导致远程 HTML 子资源加载演变为完整回显的服务端请求伪造（`CWE-918`）：

1. **步骤 1 — 下载的远程 HTML 未调用 `customHtmlSanitizer.sanitize()` (`ConvertWebsiteToPDF.java:115-116`)：**
   `urlToPdf` 通过 `String htmlContent = fetchRemoteHtml(URL);` 获取顶层网页后，未经过 `customHtmlSanitizer.sanitize(...)` 处理便直接写入临时文件 `tempHtmlInput`。
2. **步骤 2 — WeasyPrint 仍开启不受限的 `http` 与 `https` 协议 (`ConvertWebsiteToPDF.java:137-140`)：**
   与传递 `--allowed-protocols data` 的 `FileToPdf.java` 不同，`ConvertWebsiteToPDF.java` 使用 `--base-url <URL>` 和 `--allowed-protocols data,http,https` 启动 WeasyPrint。由于 WeasyPrint 作为外部 Python 进程运行，其内置 HTTP 客户端完全绕过了 Java 层的 `SsrfProtectionService`。
3. **步骤 3 — 本地回环与云元数据响应被直接渲染进输出 PDF：**
   当 WeasyPrint 渲染 HTML 时，会自动抓取指向 `http://127.0.0.1:...`、内网 RFC1918 服务或 `http://169.254.169.254/...` 的 `<link rel="stylesheet">`、`@import` 或 `<img src="...">`，并将内网响应内容直接渲染进返回给调用者的 PDF 中。

### 漏洞源码片段 (`ConvertWebsiteToPDF.java:114-141`)
```java
// File: app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java (lines 114-141)
            // Download the remote content first to ensure we don't allow dangerous schemes
            String htmlContent = fetchRemoteHtml(URL); // BUG 1: 从未传入 customHtmlSanitizer.sanitize()！
...
            List<String> command = new ArrayList<>();
            command.add(runtimePathConfig.getWeasyPrintPath());
            command.add(tempHtmlInput.toString());
            command.add("--base-url");
            command.add(URL);
            command.add("--pdf-forms");
            command.add("--allowed-protocols");
            command.add("data,http,https");            // BUG 2: 允许 WeasyPrint 直接请求任意内网 HTTP/HTTPS URL！
            command.add(tempOutputFile.toString());
```

---

## 2. 日常实际生产环境中的 3 个关键高危场景 (场景 A / 场景 B / 场景 C)

### 场景 A — 发票/收据 URL 转 PDF 的 SaaS 功能泄露云主机 IAM 凭据 (`169.254.169.254`)
1. 企业在 AWS/GCP/Azure 环境集成 Stirling-PDF 的 `/api/v1/convert/url/pdf` 接口，供用户或后台流程提交网页账单、电子收据 URL 并自动转换为 PDF。
2. 攻击者提交一个公网 URL（`https://attacker.example/receipt.html`），其顶层域名解析为公网 IP 并通过初始校验，但网页 HTML 内嵌了 `<link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/iam/security-credentials/prod-role">` 或 `<link rel="stylesheet" href="http://127.0.0.1:8080/internal-secrets.css">`。
3. WeasyPrint 凭借 `--allowed-protocols data,http,https` 直接抓取云元数据或本地回环接口，并将 IAM 临时密钥渲染进可供下载的 PDF 文件中。

### 场景 B — 利用 CSS `@import` 探测企业 Kubernetes 服务网格与 Spring Actuator 内部接口
1. Stirling-PDF 作为文档转换微服务运行在企业 Kubernetes 集群（`cluster.local`）内部，并通过 API 网关对外提供服务。
2. 攻击者提交包含 `@import url("http://10.96.0.15:9090/metrics");` 或指向内部 Spring Boot Actuator / Consul 接口（`http://127.0.0.1:8080/actuator/env`）的网页 URL。
3. 由于 WeasyPrint 运行在 Java `SsrfProtectionService` 之外，它会直接请求这些内网 RFC1918 和本地回环服务，并将敏感响应嵌入生成的 PDF。

### 场景 C — 自动化法务/合规网页归档流水线被第三方网页触发 SSRF
1. 金融或合规平台定期调用 Stirling-PDF 的 `POST /api/v1/convert/url/pdf` 接口，将外部供应商网页自动归档为 PDF 并存入共享合规门户。
2. 第三方网页中嵌入指向 `http://127.0.0.1:3000/api/keys` 或 Stirling-PDF 所在主机可达内网服务的子资源。
3. Stirling-PDF 启动的 WeasyPrint 抓取该内部接口并将敏感内网数据写入归档 PDF，导致内部机密向外部审计人员泄露。

---

## 3. 示例执行、复现与验证命令

### 1. 使用 Sniper CLI 审计目标组件
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/Stirling-PDF \
  --include "app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java"
```

### 2. 本地隔离环境复现与验证
```bash
# 对比 ConvertWebsiteToPDF.java（未修复）与 FileToPdf.java（已修复）中的 WeasyPrint 参数构造
grep -n -C 8 "allowed-protocols" \
  /home/community-user/targets/Stirling-PDF/app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java \
  /home/community-user/targets/Stirling-PDF/app/common/src/main/java/stirling/software/common/util/FileToPdf.java
```

### 3. 运行自动化 `RED -> GREEN + BENIGN` 端到端验证套件
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand01
```

---

## 4. 端到端运行时证明 (RED -> GREEN + BENIGN) 与防御补丁

通过 `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand01` 执行的验证结果：

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

### Unified Diff 补丁 (`git apply --check` 验证通过)
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
