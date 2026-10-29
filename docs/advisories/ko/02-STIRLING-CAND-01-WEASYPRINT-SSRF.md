# ConvertWebsiteToPDF.java의 CVE-2026-71270 / GHSA-j5rg-wh78-9f2q 불완전 패치로 인한 WeasyPrint 하위 리소스 SSRF (`GHSA-ff6j-8xch-j8r6`)

[English](../02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | [Türkçe](../tr/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | [日本語](../ja/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | [简体中文](../zh-CN/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | **한국어**

## GitHub GHSA 및 MITRE CNA 양식 필드 요약
- **저장소:** `Stirling-Tools/Stirling-PDF`
- **GitHub 보안 권고 URL:** `https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/GHSA-ff6j-8xch-j8r6`
- **기존 GHSA ID:** `GHSA-ff6j-8xch-j8r6 (GHSA-j5rg-wh78-9f2q / CVE-2026-71270의 변종 및 불완전 패치)`
- **에코시스템:** `Maven`
- **패키지 이름:** `stirling.software:stirling-pdf`
- **영향받는 버전:** `<= 3.2.2 (commit 684608d143779bf3a8ffc67639f077a1202c62ff)`
- **패치된 버전:** `없음 (패치 첨부)`
- **CWE:** `CWE-918 (서버 사이드 요청 위조 — SSRF)`
- **CVSS v3.1:** `8.6 High — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`
- **MITRE 벤더:** `Stirling-Tools`
- **MITRE 취약점 유형:** `Server-Side Request Forgery (SSRF) / Incomplete Fix for CVE-2026-71270 (CWE-918)`
- **MITRE 영향받는 컴포넌트:** `ConvertWebsiteToPDF.java (urlToPdf, lines 116-143 — POST /api/v1/convert/url/pdf)`
- **MITRE 권장 CVE 설명:**
  > Stirling-Tools Stirling-PDF 3.2.2 이하 버전에서 `ConvertWebsiteToPDF.java`(`POST /api/v1/convert/url/pdf`)는 `CVE-2026-71270`(`GHSA-j5rg-wh78-9f2q`)에 대한 패치가 누락되어, `fetchRemoteHtml(URL)`로 가져온 원격 HTML을 `CustomHtmlSanitizer.sanitize()`로 정제하지 않은 채 `--base-url <URL>` 및 `--allowed-protocols data,http,https` 옵션과 함께 WeasyPrint에 직접 전달합니다. 원격 공격자는 루프백(`127.0.0.1`)이나 내부 네트워크 엔드포인트를 가리키는 하위 리소스(예: `<link rel="stylesheet">` 또는 `<img>`)가 포함된 웹페이지를 제출하여 내부 응답을 생성된 PDF 파일로 유출할 수 있습니다.
- **제보자 / 크레딧:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. 코드 결함이 실제 악용 가능한 취약점으로 전환되는 메커니즘

### 단계별 기술적 메커니즘
`Stirling-Tools/Stirling-PDF`(`v3.2.2`, 커밋 `684608d143779bf3a8ffc67639f077a1202c62ff`)에서 업스트림의 `CVE-2026-71270` / `GHSA-j5rg-wh78-9f2q` 패치는 `FileToPdf.java:63-91`(`ConvertHtmlToPDF`)에 대해 `customHtmlSanitizer.sanitize()`(`SsrfProtectionService`)로 HTML을 정제하고 WeasyPrint를 `--allowed-protocols data`로 제한했습니다. 그러나 형제 엔드포인트인 `POST /api/v1/convert/url/pdf`(`ConvertWebsiteToPDF.java:116-143`)는 패치되지 않은 채로 남아 원격 HTML 하위 리소스 로딩이 전체 응답 읽기 가능한 SSRF(`CWE-918`)로 이어집니다.

1. **1단계 — 다운로드한 HTML에 대한 `customHtmlSanitizer.sanitize()` 누락 (`ConvertWebsiteToPDF.java:115-116`):**
   `urlToPdf`는 `String htmlContent = fetchRemoteHtml(URL);`로 최상위 웹페이지를 가져온 뒤 `customHtmlSanitizer.sanitize(...)`를 거치지 않고 임시 파일 `tempHtmlInput`에 바로 기록합니다.
2. **2단계 — WeasyPrint에 무제한 `http` 및 `https` 프로토콜 허용 (`ConvertWebsiteToPDF.java:137-140`):**
   `--allowed-protocols data`만 허용하는 `FileToPdf.java`와 달리, `ConvertWebsiteToPDF.java`는 `--base-url <URL>` 및 `--allowed-protocols data,http,https`로 WeasyPrint를 실행합니다. WeasyPrint는 외부 Python 프로세스로 실행되므로 자체 HTTP 클라이언트가 Java의 `SsrfProtectionService`를 완전히 우회합니다.
3. **3단계 — 루프백 및 클라우드 메타데이터 응답이 출력 PDF에 렌더링되어 유출:**
   WeasyPrint가 HTML을 렌더링할 때 `http://127.0.0.1:...`, 내부 RFC1918 서비스 또는 `http://169.254.169.254/...`를 가리키는 `<link rel="stylesheet">`, `@import`, `<img src="...">`를 직접 가져와 호출자에게 반환되는 PDF에 내부 응답을 그대로 렌더링합니다.

### 취약한 코드 조각 (`ConvertWebsiteToPDF.java:114-141`)
```java
// File: app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java (lines 114-141)
            // Download the remote content first to ensure we don't allow dangerous schemes
            String htmlContent = fetchRemoteHtml(URL); // BUG 1: customHtmlSanitizer.sanitize()가 전혀 호출되지 않음!
...
            List<String> command = new ArrayList<>();
            command.add(runtimePathConfig.getWeasyPrintPath());
            command.add(tempHtmlInput.toString());
            command.add("--base-url");
            command.add(URL);
            command.add("--pdf-forms");
            command.add("--allowed-protocols");
            command.add("data,http,https");            // BUG 2: WeasyPrint가 임의의 내부 HTTP/HTTPS URL을 직접 가져오도록 허용함!
            command.add(tempOutputFile.toString());
```

---

## 2. 일상 운영 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A` / `시나리오 B` / `시나리오 C`)

### 시나리오 A — 청구서/영수증 URL-to-PDF SaaS 기능을 통한 클라우드 IAM 자격 증명 (`169.254.169.254`) 유출
1. 기업이 AWS/GCP/Azure 환경에서 Stirling-PDF의 `/api/v1/convert/url/pdf` API를 연동하여 사용자나 백오피스 워크플로가 외부 웹 영수증이나 청구서 URL을 제출하면 PDF로 변환해 주는 기능을 운영합니다.
2. 공격자는 최상위 도메인이 공인 IP로 해석되어 초기 검증을 통과하지만, HTML 본문에 `<link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/iam/security-credentials/prod-role">` 또는 `<link rel="stylesheet" href="http://127.0.0.1:8080/internal-secrets.css">`가 포함된 공개 URL(`https://attacker.example/receipt.html`)을 제출합니다.
3. WeasyPrint는 `--allowed-protocols data,http,https` 옵션으로 내부 메타데이터/루프백 엔드포인트를 가져와 다운로드 가능한 PDF 파일 안에 자격 증명을 그대로 그려 넣습니다.

### 시나리오 B — CSS `@import`를 이용한 사내 Kubernetes 서비스 메시 및 Spring Actuator 정찰
1. Stirling-PDF가 사내 Kubernetes 클러스터(`cluster.local`) 내부에서 문서 변환 마이크로서비스로 실행되며 API 게이트웨이를 통해 노출되어 있습니다.
2. 공격자가 `@import url("http://10.96.0.15:9090/metrics");` 또는 내부 Spring Boot Actuator / Consul 엔드포인트(`http://127.0.0.1:8080/actuator/env`)를 참조하는 HTML URL을 제출합니다.
3. WeasyPrint는 Java의 `SsrfProtectionService` 외부에서 실행되므로 내부 RFC1918 및 루프백 서비스를 직접 호출하여 그 응답을 생성된 PDF에 포함시킵니다.

### 시나리오 C — 자동화된 법무/컴플라이언스 웹 아카이빙 파이프라인에서 서드파티 웹페이지를 통한 SSRF
1. 금융 또는 컴플라이언스 플랫폼이 Stirling-PDF의 `POST /api/v1/convert/url/pdf` 엔드포인트를 사용해 외부 협력사 웹페이지를 자동으로 PDF로 아카이빙하고 공유 감사 포털에 보관합니다.
2. 외부 웹페이지에 `http://127.0.0.1:3000/api/keys` 또는 Stirling-PDF 호스트에서 접근 가능한 인트라넷 서비스를 가리키는 하위 리소스가 포함되어 있습니다.
3. Stirling-PDF가 실행한 WeasyPrint가 내부 엔드포인트를 가져와 민감한 내부 데이터를 아카이빙된 PDF에 기록함으로써 외부 감사자에게 내부 기밀이 유출됩니다.

---

## 3. 예제 실행 및 검증 명령어

### 1. Sniper CLI로 대상 컴포넌트 감사
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/Stirling-PDF \
  --include "app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java"
```

### 2. 로컬 격리 환경 재현 및 검증
```bash
# ConvertWebsiteToPDF.java(미패치)와 FileToPdf.java(패치됨)의 WeasyPrint 명령어 생성 방식 비교
grep -n -C 8 "allowed-protocols" \
  /home/community-user/targets/Stirling-PDF/app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java \
  /home/community-user/targets/Stirling-PDF/app/common/src/main/java/stirling/software/common/util/FileToPdf.java
```

### 3. 자동화된 `RED -> GREEN + BENIGN` E2E 검증 하네스 실행
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand01
```

---

## 4. 엔드투엔드 런타임 증명 (`RED -> GREEN + BENIGN`) 및 방어 패치

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand01` 실행 결과:

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

### Unified Diff 패치 (`git apply --check` 검증 완료)
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
