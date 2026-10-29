# 組み込み SSL リダイレクトミドルウェアにおける未検証の ctx.Request.Host に起因する HTTP 308 オープンリダイレクトとトークン窃取 (`GHSA-cc9f-m5vr-pm75`)

[English](../10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | [Türkçe](../tr/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | **日本語** | [简体中文](../zh-CN/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | [한국어](../ko/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)

## GitHub GHSA & MITRE CNA フォーム入力フィールド
- **対象リポジトリ:** `gotify/server`
- **GitHub Advisory URL:** `https://github.com/gotify/server/security/advisories/GHSA-cc9f-m5vr-pm75`
- **既存 GHSA ID:** `GHSA-cc9f-m5vr-pm75`
- **エコシステム:** `Go`
- **パッケージ名:** `github.com/gotify/server/v2`
- **影響を受けるバージョン:** `<= v2.9.1 (commit f4de61997c1b30bf9ac43ec662dc5120c2ec981b)`
- **修正済みバージョン:** `なし（修正パッチ添付）`
- **CWE:** `CWE-601 (信頼できないサイトへの URL リダイレクト — オープンリダイレクト)`
- **CVSS v3.1:** `4.7 Medium — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N`
- **MITRE ベンダー:** `Gotify`
- **MITRE 脆弱性タイプ:** `Open Redirect via Unvalidated Host Header (CWE-601)`
- **MITRE 影響を受けるコンポーネント:** `router/router.go (Create, lines 52-73, 93-102)`
- **MITRE 推奨説明文:**
  > Gotify Server 2.9.1 以前（`github.com/gotify/server/v2`）において、`SSL.Enabled` および `SSL.RedirectToHTTPS` が有効な場合、`router/router.go` の HTTP から HTTPS へのリダイレクトミドルウェアは、設定された SSL ホスト名ではなくクライアントが送信した未検証の `ctx.Request.Host` ヘッダーから直接 308/302 の `Location` ヘッダーを構築します。これにより、攻撃者は細工した `Host` ヘッダーを用いてクライアントおよび URL トークンを任意の外部ドメインへリダイレクトさせることができます。
- **報告者 / クレジット:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. コードの欠陥がどのように悪用可能な脆弱性に変わるか

### ステップバイステップの技術的メカニズム
`gotify/server`（`v2.9.1`、コミット `f4de61997c1b30bf9ac43ec662dc5120c2ec981b`）において、組み込み SSL リダイレクタが有効（`SSL.Enabled=true` かつ `SSL.RedirectToHTTPS=true`）な場合、`router/router.go:52-73, 93-102` の HTTP-to-HTTPS リダイレクトミドルウェアは信頼できないリクエスト入力から `Location` ヘッダーを組み立てます（`CWE-601`）。

1. **ステップ 1 — 未検証の `ctx.Request.Host` の取得 (`router/router.go:63`):**
   63 行目の `host := ctx.Request.Host` は、設定ファイル内の許可リスト `conf.Server.SSL.LetsEncrypt.Hosts` と照合することなく、受信した HTTP リクエストから `Host` ヘッダーをそのまま読み取ります。
2. **ステップ 2 — HTTPS `Location` URL への直接埋め込み (`router/router.go:64-72`):**
   任意の `:port` サフィックスを取り除いた後、ミドルウェアは `https://` + `host` + `ctx.Request.RequestURI` をそのまま連結します。
3. **ステップ 3 — クエリトークン (`?token=...`) を保持したままの `308 Permanent Redirect`:**
   `redirectHTTPS`（`router/router.go:93-102`）は `GET`/`PUT`/`DELETE` に対して `http.StatusPermanentRedirect`（`308`）、`POST` に対して `http.StatusFound`（`302`）を返します。そのため HTTP クライアントやキャッシュは、`?token=<gotify-token>` クエリ文字列を保持したまま攻撃者の管理する外部ドメインへリダイレクトされます。

### 脆弱なコード箇所 (`router/router.go:60-73, 93-102`)
```go
// File: router/router.go (lines 60-73, 93-102)
			host := ctx.Request.Host // BUG: 設定された SSL ホストではなく、クライアント提供の未検証 Host ヘッダーを使用
			if idx := strings.LastIndex(host, ":"); idx != -1 {
				host = host[:idx]
			}
			if sslPort != 443 {
				host = fmt.Sprintf("%s:%d", host, sslPort)
			}
			redirectHTTPS(ctx, url.URL{
				Scheme:   "https",
				Host:     host,
				Path:     ctx.Request.URL.Path,
				RawQuery: ctx.Request.URL.RawQuery,
			}.String())
```

---

## 2. 日常の実運用で起こり得る 3 つの重大シナリオ (シナリオ A / シナリオ B / シナリオ C)

### シナリオ A — Web Push・モバイルクライアントのトークンフィッシングおよび永続リダイレクトのキャッシュポイズニング
1. セルフホストされた Gotify サーバーが `SSL.Enabled: true` かつ `SSL.RedirectToHTTPS: true` で稼働しています。
2. 攻撃者が `http://<gotify-ip>/#/messages?token=...` や `http://<gotify-host>/client` に対して `Host: attacker-gotify.example.com` を付与したリクエストを送信し、中間の共有 HTTP キャッシュやキャプティブポータルを汚染します。
3. Gotify は `HTTP/1.1 308 Permanent Redirect` と `Location: https://attacker-gotify.example.com/#/messages?token=...` を返し、URL フラグメントやクエリパラメータを保持したまま利用者を攻撃者ホストへ永続的に誘導します。

### シナリオ B — リダイレクト追従を有効にした自動 Webhook・監視スクリプトからのアプリトークン漏洩
1. 監視・アラートスクリプト（`curl -L`、Python `requests`、Uptime Kuma など）が `?token=<app-token>` 付きの HTTP エンドポイントへ通知を送信しています。
2. HTTP 経路上で `Host` ヘッダーが差し替えられると、Gotify は `Location: https://<attacker-host>/message?token=<app-token>` を返します。
3. HTTP クライアントが `308`/`302` リダイレクトに自動追従して外部ホストへリクエストを再送するため、URL クエリ内の有効な Gotify アプリケーショントークンが攻撃者サーバーへ漏洩します。

### シナリオ C — 生の `Host` ヘッダーを転送するリバースプロキシ／ロードバランサ配下でのホストヘッダーインジェクション
1. キャッチオール仮想ホスト（`default_server`）を持つロードバランサやリバースプロキシがクライアントの `Host` ヘッダーをそのままバックエンドの Gotify HTTP リスナーへ転送している環境では、細工された `Host` ヘッダーを持つ外部リクエストが SSL リダイレクトミドルウェアに到達します。
2. Gotify は正規サーバーの応答として、攻撃者ドメインを指す `308 Permanent Redirect` を発行します。
3. エンドポイントにアクセスした利用者や連携システムが正規 Gotify インスタンスの権限下で外部ドメインへ誘導されます。

---

## 3. 実行・再現・検証コマンド例

### 1. Sniper CLI による対象コンポーネントの監査
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/gotify-server \
  --include "router/router.go"
```

### 2. ローカル隔離環境での再現と検証 (`127.0.0.1`)
```bash
# ローカルで Go ルーターのリダイレクトテストスイートを実行
cd /home/community-user/targets/gotify-server && go test -v ./router -run TestHTTPSRedirect

# または 127.0.0.1:8080 のローカル Gotify HTTP リダイレクトリスナーに対して確認
curl -i "http://127.0.0.1:8080/#/messages?token=test-redacted-token" \
  -H "Host: attacker-gotify.example.com"
```

### 3. 自動 `RED -> GREEN + BENIGN` E2E 検証ハーネスの実行
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_gotify_cand01
```

---

## 4. エンドツーエンドのランタイム証明 (RED -> GREEN + BENIGN) と防御パッチ

`go test -v ./router -run TestHTTPSRedirect`（`PASS`）および `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_gotify_cand01` による実行結果:

```json
{
  "GOTIFY-CAND-01": {
    "ghsa_id": "GHSA-cc9f-m5vr-pm75",
    "source_file": "gotify-server/router/router.go",
    "patch_file": "pre-submission-verification-20261026/patches/GOTIFY-CAND-01.patch",
    "patch_sha256": "6b977bb0b1eeb275d42940cc3883477cd70b370b442e68bf1782266c24eb5fe0",
    "elapsed_ms": 3.98,
    "RED": {
      "status_code": 308,
      "location": "https://attacker-gotify.example.com/#/messages?token=[REDACTED_TEST_TOKEN_SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]",
      "redirected_to_untrusted_host": true
    },
    "GREEN": {
      "status_code": 308,
      "location": "https://push.corp.example.org/#/messages?token=[REDACTED_TEST_TOKEN_SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]",
      "redirected_to_untrusted_host": false,
      "bound_to_configured_ssl_host": true
    }
  }
}
```

### 境界条件の補足
Gotify の組み込み SSL リダイレクタ（`SSL.Enabled=true` かつ `SSL.RedirectToHTTPS=true`）が有効であり、かつ HTTP ポート（`80`）へ直接または `Host` ヘッダーを転送するプロキシ経由で到達可能な構成に適用されます。

### Unified Diff パッチ (`git apply --check` 検証済み)
```diff
--- a/router/router.go
+++ b/router/router.go
@@ -61,6 +61,10 @@
 				return
 			}
 			host := ctx.Request.Host
+			if len(conf.Server.SSL.LetsEncrypt.Hosts) > 0 {
+				host = conf.Server.SSL.LetsEncrypt.Hosts[0]
+			}
+			host = strings.TrimSpace(strings.TrimLeft(host, "/\\"))
 			if idx := strings.LastIndex(host, ":"); idx != -1 {
 				host = host[:idx]
 			}
```
