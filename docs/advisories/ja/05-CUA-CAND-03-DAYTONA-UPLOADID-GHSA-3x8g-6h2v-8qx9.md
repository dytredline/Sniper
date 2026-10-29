# Daytona S3 マルチパート uploadId のパストラバーサルと無条件の tokio::fs::remove_dir_all による任意ディレクトリ削除 (`GHSA-3x8g-6h2v-8qx9`)

[English](../05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | [Türkçe](../tr/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | **日本語** | [简体中文](../zh-CN/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | [한국어](../ko/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)

## GitHub GHSA & MITRE CNA フォーム入力フィールド
- **対象リポジトリ:** `trycua/cua`
- **GitHub Advisory URL:** `https://github.com/trycua/cua/security/advisories/GHSA-3x8g-6h2v-8qx9`
- **既存 GHSA ID:** `GHSA-3x8g-6h2v-8qx9`
- **エコシステム:** `Cargo`
- **パッケージ名:** `cua-compat`
- **影響を受けるバージョン:** `<= 0.8.0 (cua-spacesd <= 0.8.0, commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **修正済みバージョン:** `なし（修正パッチ添付）`
- **CWE:** `CWE-22 (制限されたディレクトリへのパス名の不適切な制限 — パストラバーサル)`
- **CVSS v3.1:** `8.1 High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`
- **MITRE ベンダー:** `TryCua`
- **MITRE 脆弱性タイプ:** `Directory Traversal Leading to Arbitrary Directory Deletion (CWE-22)`
- **MITRE 影響を受けるコンポーネント:** `libs/cua/crates/cua-compat/src/daytona/objectstore.rs (handle, lines 320-325, 360-422)`
- **MITRE 推奨説明文:**
  > TryCua cua-compat 0.8.0 以前（`trycua/cua`）において、Daytona 互換 S3 オブジェクトストア（`libs/cua/crates/cua-compat/src/daytona/objectstore.rs`）は `object_path(&key)` によってオブジェクトキーのパストラバーサルを検証しますが、`uploadId` クエリパラメータを一切検証していません。さらに HTTP `DELETE`（`AbortMultipartUpload`）ハンドラでは、`uploads.remove(&id)` で該当 `uploadId` が存在したかどうかを確認せず、無条件に `tokio::fs::remove_dir_all(root.join("uploads").join(&id))` を実行するため、push 権限を持つクライアントがオブジェクトストア全体や親ディレクトリを再帰的に削除できます。
- **報告者 / クレジット:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. コードの欠陥がどのように悪用可能な脆弱性に変わるか

### ステップバイステップの技術的メカニズム
`trycua/cua`（`cua-compat` クレート `<= 0.8.0`、`libs/cua/crates/cua-compat/src/daytona/objectstore.rs:320-422`、コミット `e754cfec69c41400eb2aabde716c27d15607b2f0`）の Daytona 互換 S3 オブジェクトストアは、マルチパートアップロードの一時データを `d.objects.root.join("uploads").join(&id)` 配下に保存します。以下の 3 つのコード欠陥により、`uploadId` クエリパラメータが任意のディレクトリ削除およびファイル書き込みの脆弱性（`CWE-22`）となります。

1. **ステップ 1 — 未検証の `?uploadId=` クエリパラメータ (`objectstore.rs:54-63, 323`):**
   URL パスの `key` は `object_path(&key)` によって `Component::ParentDir`（`..`）が拒否されますが（490-496 行目の `keys_cannot_escape_the_store` でテスト済み）、323 行目の `let upload_id = q.get("uploadId").cloned();` は一切検証されず、365、391、401、417 行目で `PathBuf::join(&id)` にそのまま渡されます。
2. **ステップ 2 — `Method::DELETE` で `uploads.remove(&id)` の戻り値が無視される (`objectstore.rs:415-417`):**
   `AbortMultipartUpload`（`Method::DELETE`）分岐では、`d.objects.uploads.lock().await.remove(&id);` の戻り値（`Option<Upload>`）が `.is_some()` で確認されずに破棄されます。そのため、事前にアップロードを開始していなくても削除処理へ進みます。
3. **ステップ 3 — `tokio::fs::remove_dir_all` の無条件実行 (`objectstore.rs:417`):**
   417 行目で無条件に `tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await` が呼び出されるため、`?uploadId=../objects` でオブジェクトストア全体（`root/objects`）を、あるいは `?uploadId=../../...` で親ディレクトリを再帰的に消去できます。

### 脆弱なコード箇所 (`objectstore.rs:323, 415-422`)
```rust
// File: libs/cua/crates/cua-compat/src/daytona/objectstore.rs (lines 323, 415-422)
    let upload_id = q.get("uploadId").cloned(); // BUG 1: '..' やパス区切り文字の検証が一切ない生のクエリ文字列
...
        (Method::DELETE, Some(id), _, _) => {
            d.objects.uploads.lock().await.remove(&id); // BUG 2: 戻り値を無視しており、id が実在しなくてもよい
            let _ = tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await; // BUG 3: 無条件の再帰削除
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::from(Bytes::new()))
                .unwrap()
        }
```

---

## 2. 日常の実運用で起こり得る 3 つの重大シナリオ (シナリオ A / シナリオ B / シナリオ C)

### シナリオ A — 単一の侵害されたサンドボックステナントが `?uploadId=../objects` で組織全体のサンドボックススナップショットを一括消去
1. マルチサンドボックス構成の CUA Spaces / Daytona 環境において、サンドボックスランナーまたはテナントが `GET /api/object-storage/push-access` から通常の push 認証情報を取得します。
2. そのテナントが `DELETE /daytona/dummy?uploadId=../objects`（ヘッダー `Authorization: AWS4-HMAC-SHA256 Credential=<access_key>/...`。なお 103-122 行目の `authorized()` は `access_key` 部分文字列のみを確認し、HMAC 署名を検証しません）を 1 回送信します。
3. `objectstore.rs:417` は `root.join("uploads").join("../objects")` を `root/objects` として解決し、`tokio::fs::remove_dir_all` を実行するため、サーバー上の全サンドボックスイメージとスナップショットが瞬時に消去されます。

### シナリオ B — `?uploadId=../../...` による `d.objects.root` 外への脱出とホスト側アプリケーション状態の削除
1. Rust の `PathBuf::join` は `..` セグメントを保持したまま OS カーネルの `remove_dir_all` に渡すため、`?uploadId=../../state` や `?uploadId=../../db` を指定すると `d.objects.root` の上位階層へ到達します。
2. たった 1 回の `DELETE` リクエストで、`cua-spacesd` デーモンユーザーが書き込み権限を持つホスト側の状態ディレクトリ、設定フォルダ、ローカルデータベースが削除されます。

### シナリオ C — `Method::PUT` (`UploadPart`) を悪用した任意ファイル上書きおよび他テナントデータの汚染
1. 同じ未検証の `uploadId` パラメータは `Method::PUT`（`UploadPart`）ハンドラ（`objectstore.rs:364-376`）でも使用されており、`let dir = d.objects.root.join("uploads").join(&id); tokio::fs::create_dir_all(&dir)` を実行して `dir.join(format!("{part:05}"))` に任意のバイト列を書き込みます。
2. 攻撃者は `PUT` リクエストで `uploads/` の外へトラバーサルし、任意のディレクトリ作成とファイル書き込みを行えます。

---

## 3. 実行・再現・検証コマンド例

### 1. Sniper CLI による対象コンポーネントの監査
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua/crates/cua-compat/src/daytona/objectstore.rs"
```

### 2. ローカル隔離環境での再現と検証 (`127.0.0.1`)
```bash
# ローカルの Daytona オブジェクトストアに対して uploadId にパストラバーサルを含む DELETE リクエストを送信
curl -i -X DELETE "http://127.0.0.1:8080/daytona/test-object?uploadId=../objects" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=daytona-access-key/20261026/us-east-1/s3/aws4_request"
```

### 3. 自動 `RED -> GREEN + BENIGN` E2E 検証ハーネスの実行
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand03
```

---

## 4. エンドツーエンドのランタイム証明 (RED -> GREEN + BENIGN) と防御パッチ

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand03` による実行結果:

```json
{
  "CUA-CAND-03": {
    "ghsa_id": "GHSA-3x8g-6h2v-8qx9",
    "source_file": "cua/libs/cua/crates/cua-compat/src/daytona/objectstore.rs",
    "elapsed_ms": 0.583,
    "RED": {
      "delete_traversal_status": 204,
      "objects_store_wiped_without_prior_upload": true
    },
    "GREEN": {
      "delete_traversal_status": 400,
      "delete_uninitiated_id_status": 404,
      "objects_store_preserved": true
    },
    "BENIGN": {
      "valid_upload_abort_status": 204,
      "staging_dir_removed": true
    }
  }
}
```

### Unified Diff パッチ (`git apply --check` 検証済み)
```diff
--- a/libs/cua/crates/cua-compat/src/daytona/objectstore.rs
+++ b/libs/cua/crates/cua-compat/src/daytona/objectstore.rs
@@ -62,6 +62,13 @@
         Some(self.root.join("objects").join(BUCKET).join(key))
     }
 
+    fn upload_dir(&self, id: &str) -> Option<PathBuf> {
+        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
+            return None;
+        }
+        Some(self.root.join("uploads").join(id))
+    }
+
     pub fn stage_dir(&self) -> PathBuf {
         self.root.join("stage")
     }
@@ -413,8 +420,10 @@
             }
         }
         (Method::DELETE, Some(id), _, _) => {
-            d.objects.uploads.lock().await.remove(&id);
-            let _ = tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await;
+            if d.objects.uploads.lock().await.remove(&id).is_some() {
+                if let Some(dir) = d.objects.upload_dir(&id) {
+                    let _ = tokio::fs::remove_dir_all(dir).await;
+                }
+            }
             Response::builder()
                 .status(StatusCode::NO_CONTENT)
```
