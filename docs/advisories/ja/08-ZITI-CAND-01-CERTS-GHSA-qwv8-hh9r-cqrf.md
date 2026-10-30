# AreCertsTrusted() が無条件に InsecureSkipVerify: true を設定することで ziti edge login 時の TLS 証明書検証が無効化される脆弱性 (`GHSA-qwv8-hh9r-cqrf`)

[English](../08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | [Türkçe](../tr/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | **日本語** | [简体中文](../zh-CN/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | [한국어](../ko/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)

## 1. コードの欠陥がどのように悪用可能な脆弱性に変わるか

### ステップバイステップの技術的メカニズム
`openziti/ziti`（`github.com/openziti/ziti/v2`、コミット `236f351a5149fe68328fc8083bebe514f0307d0c`）では、`ziti edge login`（`ziti/cmd/edge/login.go:511, 535-549`）がコントローラの `/.well-known/est/cacerts` から CA バンドルを取得し、認証情報を送信する前にサーバーの TLS リーフ証明書がその CA バンドルで署名されているかを確認するため `util.AreCertsTrusted(host, wellKnownCerts, httpClient)`（`ziti/util/certs.go:91-103`）を呼び出します。しかし `InsecureClient` の致命的な欠陥により、この検証が完全に無効化されています（`CWE-295`）。

1. **ステップ 1 — `AreCertsTrusted` が意図している `x509.UnknownAuthorityError` チェック (`ziti/util/certs.go:91-103`):**
   `AreCertsTrusted` は `host` に対して HTTPS `GET` を実行し、95-98 行目で `if ue, ok := err.(*url.Error); ok && errors.As(ue.Err, &x509.UnknownAuthorityError{}) { return false, nil }` を確認しようとします。
2. **ステップ 2 — `InsecureClient` における無条件の `InsecureSkipVerify: true` (`ziti/util/certs.go:199-208`):**
   `AreCertsTrusted` は `InsecureClient(&client, certs)` で HTTP クライアントを構築します。`len(certs) > 0` であり証明書が `tlsConfig.RootCAs` に追加された場合でも、202 行目で `InsecureSkipVerify: true` がハードコードされています。
3. **ステップ 3 — `ziti edge login` 中の `RootCAs` 検証の完全なバイパス:**
   Go 標準ライブラリの `crypto/tls` では、`InsecureSkipVerify: true` が設定されていると `RootCAs` に対する証明書チェーン検証が完全にスキップされます。その結果、`x509.UnknownAuthorityError` は決して発生せず、96 行目は到達不能なデッドコードとなり、任意の偽 MITM 証明書に対して `AreCertsTrusted` が常に `true, nil` を返します。さらに `login.go:511` は `"Verified that server supplied certificates are trusted by server"` と誤表示した上で、管理者のパスワードやトークンを攻撃者へ送信します。

### 脆弱なコード箇所 (`ziti/util/certs.go:91-103, 199-208`)
```go
// File: ziti/util/certs.go (lines 91-103, 199-208)
func AreCertsTrusted(host string, certs []byte, httpClient *http.Client) (bool, error) {
	client := *httpClient
	resp, err := InsecureClient(&client, certs).Get(host)
	if err != nil {
		if ue, ok := err.(*url.Error); ok && errors.As(ue.Err, &x509.UnknownAuthorityError{}) {
			return false, nil // DEAD CODE: InsecureSkipVerify が無条件で true のため絶対に到達しない
		}
		return false, err
	}
	_ = resp.Body.Close()
	return true, nil
}
...
func InsecureClient(client *http.Client, certs []byte) *http.Client {
	tlsConfig := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		InsecureSkipVerify: true, // BUG: RootCAs を有効にするには len(certs) == 0 とすべき箇所
	}
```

---

## 2. 日常の実運用で起こり得る 3 つの重大シナリオ (シナリオ A / シナリオ B / シナリオ C)

### シナリオ A — DevOps エンジニアが Wi-Fi / VPN 経由で `ziti edge login` を実行し、偽の MITM コントローラへ管理者認証情報を送信してしまう
1. 管理者がワークステーションから `ziti edge login https://ziti-controller.internal:1280 -u admin -p <AdminPassword>` を実行します。
2. ネットワーク上の攻撃者（ARP スプーフィング、偽アクセスポイント、DNS ハイジャックなど）が、自己署名の偽 TLS 証明書を使って接続を傍受しつつ、`/.well-known/est/cacerts` には一見正常な CA バンドルを返します。
3. `AreCertsTrusted` が `InsecureSkipVerify: true` を維持しているため、Go の `crypto/tls` はサーバーの TLS 証明書が `/.well-known/est/cacerts` によって署名されているかを一切検証しません。`login.go:511` は `"Verified that server supplied certificates are trusted by server"` と表示し、管理者のパスワードをそのまま MITM 攻撃者へ送信します。

### シナリオ B — 自動 CI/CD パイプラインおよび Kubernetes ゼロトラスト登録ジョブの侵害
1. 自動化された CI/CD パイプラインや Kubernetes init ジョブが `ziti edge login --yes` を実行し、ゼロトラストのサービス ID やルーターポリシーをブートストラップしています。
2. 通信経路上の攻撃者が、コントローラの EST CA バンドルで署名されていない任意の偽 TLS リーフ証明書を提示します。
3. `AreCertsTrusted()` が無条件に `true, nil` を返すため、パイプラインは信頼できない証明書チェーンをそのまま保存し、特権的な登録認証情報を攻撃者の接続へ送信します。

### シナリオ C — マルチクラスタ環境における期限切れ・自己署名・別環境コントローラ証明書の無警告受け入れ
1. `dev`、`staging`、`prod` の複数 OpenZiti クラスタをイングレスプロキシ配下で運用している環境において、プロキシの設定ミス等によりコントローラの EST CA で署名されていない自己署名・不一致のリーフ証明書が返されます。
2. 本来 `login.go:545` で出力されるはずの警告（`"Server supplied certs are not trusted by server"`）が出力されず、`AreCertsTrusted()` が検証成功と誤報告するため、運用者が本番認証情報を非信頼エンドポイントへ送信してしまいます。

---

## 3. 実行・再現・検証コマンド例

### 1. Sniper CLI による対象コンポーネントの監査
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/ziti \
  --include "ziti/util/certs.go"
```

### 2. ローカル隔離環境での再現と検証 (`127.0.0.1`)
```bash
# ローカル 127.0.0.1 TLS サーバーに対する AreCertsTrusted の挙動を証明する Go ユニットテストを実行
cd /home/community-user/targets/ziti && go test -v -run TestRealOpenZitiAreCertsTrusted ./ziti/util
```

### 3. 自動 `RED -> GREEN + BENIGN` E2E 検証ハーネスの実行
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_ziti_cand01
```

---

## 4. エンドツーエンドのランタイム証明 (RED -> GREEN + BENIGN) と防御パッチ

`go test -v -run TestRealOpenZitiAreCertsTrusted ./ziti/util`（`0.014s` で `PASS`）および `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_ziti_cand01` による検証結果:

```json
{
  "ZITI-CAND-01": {
    "ghsa_id": "GHSA-qwv8-hh9r-cqrf",
    "source_file": "ziti/ziti/util/certs.go",
    "login_caller_file": "ziti/ziti/cmd/edge/login.go",
    "elapsed_ms": 0.719,
    "RED": {
      "insecure_skip_verify": true,
      "rogue_mitm_cert_accepted_as_trusted": true,
      "admin_credentials_sent_to_mitm": true
    },
    "GREEN": {
      "insecure_skip_verify": false,
      "rogue_mitm_cert_accepted_as_trusted": false,
      "tls_error": "x509.UnknownAuthorityError: certificate signed by unknown authority"
    },
    "BENIGN": {
      "valid_ca_signed_controller_trusted": true
    }
  }
}
```

### Unified Diff パッチ (`git apply --check` 検証済み)
```diff
--- a/ziti/util/certs.go
+++ b/ziti/util/certs.go
@@ -199,7 +199,7 @@
 func InsecureClient(client *http.Client, certs []byte) *http.Client {
 	tlsConfig := &tls.Config{
 		RootCAs:            x509.NewCertPool(),
-		InsecureSkipVerify: true,
+		InsecureSkipVerify: len(certs) == 0,
 	}
 
 	if len(certs) > 0 {
```
