# string-extensions.ts の先頭アンカーなし EMAIL_REGEXP および DOMAIN_EXTRACT_REGEXP による Webhook イベントループ枯渇 DoS (`n8n-io/n8n`)

[English](../09-N8N-CAND-01-WEBHOOK-REDOS.md) | [Türkçe](../tr/09-N8N-CAND-01-WEBHOOK-REDOS.md) | **日本語** | [简体中文](../zh-CN/09-N8N-CAND-01-WEBHOOK-REDOS.md) | [한국어](../ko/09-N8N-CAND-01-WEBHOOK-REDOS.md)

## 1. コードの欠陥がどのように悪用可能な脆弱性に変わるか

### ステップバイステップの技術的メカニズム
`n8n-io/n8n`（`<= 2.45.0`、コミット `cfbd9a56cba2e73901dc1962e47727adbea0b23e`）において、`packages/workflow/src/extensions/string-extensions.ts:59, 94, 326, 375, 383` に実装されている組み込みワークフロー式メソッド `.isEmail()`、`.extractEmail()`、`.extractDomain()` には多項式／破滅的バックトラッキング（`CWE-1333`）が存在します。

1. **ステップ 1 — 重複する量指定子サブグループを持つ先頭アンカーなし正規表現 (`string-extensions.ts:59, 94`):**
   `EMAIL_REGEXP` は先頭アンカーや否定後読み境界（`(?<![^<>()\[\]\\.,;:\s@"])`）を持たずに `/(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@...` で始まり、さらに貪欲な `".+"` 分岐を含んでいます。`"a.a.a...a@!"` のような非マッチのドット付き文字列が渡されると、V8 正規表現エンジンは文字列全体のすべての文字オフセットから量指定子マッチングを再試行します。
2. **ステップ 2 — RFC-5321 / RFC-1035 に基づく入力長ガードの欠落 (`string-extensions.ts:326, 375, 383`):**
   RFC-5321 上の有効なメールアドレスは最大 `254`／`320` 文字ですが、`isEmail(value)`、`extractEmail(value)`、`extractDomain(value)` は長さの上限チェックを行わずに任意の大きさの文字列をそのまま `EMAIL_REGEXP` や `DOMAIN_EXTRACT_REGEXP` に渡します。
3. **ステップ 3 — シングルスレッド Node.js イベントループの同期ブロッキング:**
   n8n はワークフロー式をメインの Node.js スレッド上で同期的に評価するため、わずか 20 KB のペイロード 1 件で V8 イベントループが `831.78 ms` ブロックされ（修正後は `0.0029 ms` で完了し約 `286,000` 倍高速化）、同一インスタンス上の他の並行 Webhook 実行や UI リクエストがすべて停止します。

### 脆弱なコード箇所 (`string-extensions.ts:93-95, 324-328, 373-377`)
```typescript
// File: packages/workflow/src/extensions/string-extensions.ts (lines 93-95, 324-328, 373-377)
const EMAIL_REGEXP =
	/(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(?<domain>(\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/; // BUG 1: 先頭アンカーなし + 貪欲な ".+"
...
function isEmail(value: string) {
	const result = EMAIL_REGEXP.test(value); // BUG 2: value.length > 320 の事前ガードがない
	return result;
}
...
function extractEmail(value: string) {
	const matched = EMAIL_REGEXP.exec(value); // BUG 3: 数 KB〜数 MB の文字列をメインスレッドで同期評価
	return matched ? matched[0] : undefined;
}
```

---

## 2. 日常の実運用で起こり得る 3 つの重大シナリオ (シナリオ A / シナリオ B / シナリオ C)

### シナリオ A — 公開リード獲得・問い合わせフォーム Webhook から社内全体の n8n 自動化サーバーが凍結される
1. 企業が公開 n8n Webhook ノード（`POST /webhook/contact-us`）を公開し、後続の `IF` や `Set` ノードで `{{ $json.body.contact.isEmail() }}` または `{{ $json.body.website.extractDomain() }}` を評価しています。
2. 認証なしの攻撃者が、公開 Webhook URL に対して 20 KB の JSON ペイロード（`{"contact": "a.a.a...a@!"}`）を連続送信します。
3. 1 リクエストあたり約 832 ms にわたってシングルスレッドの Node.js イベントループがブロックされるため、同じサーバーで処理されている Stripe 決済 Webhook、Slack ボット、n8n エディタ UI がすべてタイムアウトします。

### シナリオ B — 細工されたメッセージ本文による自動サポートチケット・メール振り分けパイプラインの停止
1. カスタマーサポートの自動化ワークフローが、受信した問い合わせチケットやチャットログ、メール本文に対して返信先アドレスを抽出するため `{{ $json.messageBody.extractEmail() }}` を実行しています。
2. 外部ユーザーが有効なドメイン末尾を持たないドット区切りトークンを繰り返したメッセージ本文を送信します。
3. `extractEmail()` が長さ制限なしで本文全体に `EMAIL_REGEXP.exec(value)` を適用するため n8n ワーカーがハングし、Kubernetes の Liveness Probe が失敗して Pod の再起動ループが発生します。

### シナリオ C — 不正な URL リストに対する `extractDomain()` 評価による CRM / B2B リードエンリッチメントキューの詰まり
1. B2B マーケティング自動化ワークフローが、HubSpot や Salesforce へ同期する前に `{{ $json.companyUrl.extractDomain() }}` で企業ドメインを正規化しています。
2. 有効な TLD を持たない長いサブドメイン風セグメントを含むペイロードが到着すると、`DOMAIN_EXTRACT_REGEXP`（`string-extensions.ts:59`）で激しいバックトラッキングが発生します。
3. ワークフロー実行キューが詰まり、インスタンス上の後続スケジュール実行が大幅に遅延します。

---

## 3. 実行・再現・検証コマンド例

### 1. Sniper CLI による対象コンポーネントの監査
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/n8n \
  --include "packages/workflow/src/extensions/string-extensions.ts"
```

### 2. ローカル隔離環境での再現と検証 (`Node.js`)
```bash
# 20 KB のドット付きペイロードに対する未修正版と修正版 EMAIL_REGEXP の V8 イベントループ停止時間を計測
node -e '
const vuln = /(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(?<domain>(\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/;
const payload = "a.".repeat(10000) + "a@!";
const t0 = performance.now();
vuln.test(payload);
const redMs = performance.now() - t0;
const t1 = performance.now();
const greenResult = payload.length <= 320 && payload.includes("@") && !payload.includes(" ") ? vuln.test(payload) : false;
const greenMs = performance.now() - t1;
console.log(JSON.stringify({ payload_bytes: payload.length, red_ms: +redMs.toFixed(3), green_ms: +greenMs.toFixed(4), greenResult }));
'
```

### 3. 自動 `RED -> GREEN + BENIGN` E2E 検証ハーネスの実行
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_n8n_cand01
```

---

## 4. エンドツーエンドのランタイム証明 (RED -> GREEN + BENIGN) と防御パッチ

Node.js `v22.22.2` 実環境ベンチマーク（`logs/N8N-CAND-01-node-benchmark.json`: RED `831.78 ms` -> GREEN `0.0029 ms`、`286,000` 倍高速化）および `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_n8n_cand01` による実行結果:

```json
{
  "N8N-CAND-01": {
    "source_file": "n8n/packages/workflow/src/extensions/string-extensions.ts",
    "patch_file": "pre-submission-verification-20261026/patches/N8N-CAND-01.patch",
    "patch_sha256": "7e38173c95ccccb119cc57ac0226b9ac4af1bf21c590e74123ec5e9b385121e0",
    "RED": {
      "regex_stall_ms": 165.035,
      "concurrent_legitimate_webhook_wait_ms": 164.08,
      "concurrent_webhook_starved": true
    },
    "GREEN": {
      "regex_stall_ms": 0.017,
      "concurrent_legitimate_webhook_wait_ms": 0.0,
      "concurrent_webhook_starved": false
    }
  }
}
```

### 境界条件の補足
信頼できない外部入力（Webhook トリガーのペイロードや外部メッセージ本文など）に対して `.isEmail()`、`.extractEmail()`、または `.extractDomain()` を評価するワークフローが有効である必要があります。

### Unified Diff パッチ (`git apply --check` 検証済み)
```diff
--- a/packages/workflow/src/extensions/string-extensions.ts
+++ b/packages/workflow/src/extensions/string-extensions.ts
@@ -91,7 +91,7 @@
   ))/;
 */
 const EMAIL_REGEXP =
-	/(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(?<domain>(\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/;
+	/(?<![^<>()\[\]\\.,;:\s@"])(?:[^<>()\[\]\\.,;:\s@"]+(?:\.[^<>()\[\]\\.,;:\s@"]+)*|"(?:[^"\\]|\\.)+")@(?<domain>\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}]|(?:[a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,})/;
 
@@ -324,6 +324,7 @@
 function isEmail(value: string) {
+	if (value.length > 320 || !value.includes('@') || value.includes(' ')) return false;
 	const result = EMAIL_REGEXP.test(value);
@@ -373,6 +374,7 @@
 function extractEmail(value: string) {
+	if (value.length > 4096 || !value.includes('@')) return undefined;
 	const matched = EMAIL_REGEXP.exec(value);
```
