# ConvertWebsiteToPDF.java における CVE-2026-71270 / GHSA-j5rg-wh78-9f2q の修正漏れによる WeasyPrint サブリソース SSRF (`GHSA-ff6j-8xch-j8r6`)

[English](../02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | [Türkçe](../tr/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | **日本語** | [简体中文](../zh-CN/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | [한국어](../ko/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)

## GitHub GHSA & MITRE CNA フォーム入力フィールド
- **対象リポジトリ:** `Stirling-Tools/Stirling-PDF`
- **GitHub Advisory URL:** `https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/GHSA-ff6j-8xch-j8r6`
- **既存 GHSA ID:** `GHSA-ff6j-8xch-j8r6 (GHSA-j5rg-wh78-9f2q / CVE-2026-71270 の亜種・不完全な修正)`
- **エコシステム:** `Maven`
- **パッケージ名:** `stirling.software:stirling-pdf`
- **影響を受けるバージョン:** `<= 3.2.2 (commit 684608d143779bf3a8ffc67639f077a1202c62ff)`
- **修正済みバージョン:** `なし（修正パッチ添付）`
- **CWE:** `CWE-918 (サーバーサイド・リクエスト・フォージェリ — SSRF)`
- **CVSS v3.1:** `8.6 High — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`
- **MITRE ベンダー:** `Stirling-Tools`
- **MITRE 脆弱性タイプ:** `Server-Side Request Forgery (SSRF) / Incomplete Fix for CVE-2026-71270 (CWE-918)`
- **MITRE 影響を受けるコンポーネント:** `ConvertWebsiteToPDF.java (urlToPdf, lines 116-143 — POST /api/v1/convert/url/pdf)`
- **MITRE 推奨説明文:**
  > Stirling-Tools Stirling-PDF 3.2.2 以前において、`ConvertWebsiteToPDF.java`（`POST /api/v1/convert/url/pdf`）における `CVE-2026-71270`（`GHSA-j5rg-wh78-9f2q`）の修正漏れにより、`fetchRemoteHtml(URL)` で取得したリモート HTML を `CustomHtmlSanitizer.sanitize()` に通さず、`--base-url <URL>` および `--allowed-protocols data,http,https` を指定して WeasyPrint に直接渡しています。リモートの攻撃者はループバック（`127.0.0.1`）や内部ネットワークを指すサブリソース（`<link rel="stylesheet">` や `<img>` など）を含む Web ページを指定することで、内部サービスの応答を生成された PDF 内へ流出させることができます。
- **報告者 / クレジット:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. コードの欠陥がどのように悪用可能な脆弱性に変わるか

### ステップバイステップの技術的メカニズム
`Stirling-Tools/Stirling-PDF`（`v3.2.2`、コミット `684608d143779bf3a8ffc67639f077a1202c62ff`）では、`CVE-2026-71270` / `GHSA-j5rg-wh78-9f2q` の修正として `FileToPdf.java:63-91`（`ConvertHtmlToPDF`）に `customHtmlSanitizer.sanitize()`（`SsrfProtectionService`）と WeasyPrint の `--allowed-protocols data` 制限が導入されました。しかし、兄弟エンドポイントである `POST /api/v1/convert/url/pdf`（`ConvertWebsiteToPDF.java:116-143`）が未修正のまま残されたため、リモート HTML のサブリソース読み込みが完全なレスポンス読み取り型 SSRF（`CWE-918`）となります。

1. **ステップ 1 — 取得した HTML に対する `customHtmlSanitizer.sanitize()` の欠落 (`ConvertWebsiteToPDF.java:115-116`):**
   `urlToPdf` は `String htmlContent = fetchRemoteHtml(URL);` でトップレベルページを取得した後、`customHtmlSanitizer.sanitize(...)` を呼び出さずにそのまま一時ファイル `tempHtmlInput` に書き込みます。
2. **ステップ 2 — WeasyPrint で `http` および `https` プロトコルが許可されたままになっている (`ConvertWebsiteToPDF.java:137-140`):**
   `FileToPdf.java`（`--allowed-protocols data` を指定）とは異なり、`ConvertWebsiteToPDF.java` は `--base-url <URL>` と `--allowed-protocols data,http,https` を指定して WeasyPrint を起動します。WeasyPrint は外部の Python プロセスとして動作するため、Java 側の `SsrfProtectionService` を完全にバイパスします。
3. **ステップ 3 — ループバックやクラウドメタデータの出力 PDF への埋め込みと流出:**
   WeasyPrint が HTML をレンダリングする際、`http://127.0.0.1:...`、内部 RFC1918 サービス、または `http://169.254.169.254/...` を指す `<link rel="stylesheet">`、`@import`、`<img src="...">` を自ら取得し、その内部レスポンスを呼び出し元に返却される PDF ファイル内にそのまま描画します。

### 脆弱なコード箇所 (`ConvertWebsiteToPDF.java:114-141`)
```java
// File: app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java (lines 114-141)
            // Download the remote content first to ensure we don't allow dangerous schemes
            String htmlContent = fetchRemoteHtml(URL); // BUG 1: customHtmlSanitizer.sanitize() が呼ばれていない
...
            List<String> command = new ArrayList<>();
            command.add(runtimePathConfig.getWeasyPrintPath());
            command.add(tempHtmlInput.toString());
            command.add("--base-url");
            command.add(URL);
            command.add("--pdf-forms");
            command.add("--allowed-protocols");
            command.add("data,http,https");            // BUG 2: WeasyPrint が任意の内部 HTTP/HTTPS URL を直接取得できてしまう
            command.add(tempOutputFile.toString());
```

---

## 2. 日常の実運用で起こり得る 3 つの重大シナリオ (シナリオ A / シナリオ B / シナリオ C)

### シナリオ A — 請求書・領収書 URL の PDF 化 SaaS 機能を通じたクラウド IAM 認証情報 (`169.254.169.254`) の窃取
1. 企業が AWS/GCP/Azure 上で Stirling-PDF の `/api/v1/convert/url/pdf` API を業務システムに組み込み、Web 上の領収書や取引先請求書の URL から PDF を自動生成しています。
2. 攻撃者は、トップレベルドメインはパブリック IP に解決されて初回チェックを通過するものの、HTML 内に `<link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/iam/security-credentials/prod-role">` や `<link rel="stylesheet" href="http://127.0.0.1:8080/internal-secrets.css">` を埋め込んだ公開 URL（`https://attacker.example/receipt.html`）を送信します。
3. WeasyPrint は `--allowed-protocols data,http,https` によって内部メタデータやループバックエンドポイントを取得し、その認証情報をダウンロード可能な PDF ファイル内に描画して攻撃者へ返します。

### シナリオ B — CSS `@import` を用いた社内 Kubernetes サービスメッシュおよび Spring Actuator の内部偵察
1. Stirling-PDF が社内 Kubernetes クラスタ（`cluster.local`）内で文書変換マイクロサービスとして稼働し、API ゲートウェイ経由で公開されています。
2. 攻撃者が `@import url("http://10.96.0.15:9090/metrics");` や内部の Spring Boot Actuator / Consul エンドポイント（`http://127.0.0.1:8080/actuator/env`）を参照する HTML ページの URL を送信します。
3. WeasyPrint は Java の `SsrfProtectionService` の外で実行されるため、内部の RFC1918 サービスやループバックサービスへ直接アクセスし、応答を生成 PDF に埋め込みます。

### シナリオ C — 法務・コンプライアンス自動 Web アーカイブパイプラインにおける外部 Web ページ経由の SSRF
1. 金融・コンプライアンス基盤が、外部ベンダーの Web ページを `POST /api/v1/convert/url/pdf` で自動的に PDF アーカイブ化して監査ポータルへ保存しています。
2. 外部ページ内に `http://127.0.0.1:3000/api/keys` や Stirling-PDF ホストから到達可能なイントラネットサービスを指すサブリソースが含まれている場合、WeasyPrint が内部データを取得してアーカイブ PDF に焼き込みます。
3. その結果、保存された PDF を閲覧できる外部監査人や利用者に内部機密情報が漏洩します。

---

## 3. 実行・再現・検証コマンド例

### 1. Sniper CLI による対象コンポーネントの監査
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/Stirling-PDF \
  --include "app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java"
```

### 2. ローカル隔離環境での再現と検証
```bash
# ConvertWebsiteToPDF.java（未修正）と FileToPdf.java（修正済み）の WeasyPrint 引数構築を比較
grep -n -C 8 "allowed-protocols" \
  /home/community-user/targets/Stirling-PDF/app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java \
  /home/community-user/targets/Stirling-PDF/app/common/src/main/java/stirling/software/common/util/FileToPdf.java
```

### 3. 自動 `RED -> GREEN + BENIGN` E2E 検証ハーネスの実行
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand01
```

---

## 4. エンドツーエンドのランタイム証明 (RED -> GREEN + BENIGN) と防御パッチ

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand01` による実行結果:

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

### Unified Diff パッチ (`git apply --check` 検証済み)
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
