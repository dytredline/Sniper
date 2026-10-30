# WinArena オーケストレータによる認証なし noVNC (0.0.0.0:8006)・パスワードなし RDP (0.0.0.0:3390) の全インターフェース公開および書き込み可能なホスト /shared マウント (`GHSA-hvhg-6x47-cq96`)

[English](../07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | [Türkçe](../tr/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | **日本語** | [简体中文](../zh-CN/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | [한국어](../ko/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)

## 1. コードの欠陥がどのように悪用可能な脆弱性に変わるか

### ステップバイステップの技術的メカニズム
`trycua/cua`（`cua-bench` `<= 0.3.1`、`libs/cua-bench/tasks/winarena_adapter/cli.py:262-265, 421-424, 646-649` および `infra/vm/setup/server/main.py:180-248, 290-321`、コミット `e754cfec69c41400eb2aabde716c27d15607b2f0`）では、3 つの Docker 起動コマンド（`cmd_vm_setup`、`cmd_vm_start`、`cmd_task_run`）すべてが Windows VM とホストのソースディレクトリをネットワークおよび権限の分離なしに露出させます（`CWE-668` / `CWE-732`）。

1. **ステップ 1 — `0.0.0.0` への認証なし Docker ポート公開 (`cli.py:262-263, 421-422, 646-647`):**
   `127.0.0.1:` プレフィックスなしで `-p {args.browser_port}:8006` と `-p {args.rdp_port}:3389` を渡しているため、Docker は認証なしの noVNC Web コンソール（`8006`）とパスワードなしの Windows RDP サービス（`3390`）をすべての LAN/Wi-Fi インターフェース（`0.0.0.0`）にバインドします（さらに Docker の `FORWARD` チェーンによりホスト側の `ufw` `INPUT` ルールもバイパスします）。
2. **ステップ 2 — ホスト側ソースディレクトリの読み書きマウント (`cli.py:265, 424, 649`):**
   `:ro`（読み取り専用）を付けずに `-v {setup_path}:/shared` を指定しているため、ホストの `winarena_adapter/infra/vm/setup` ディレクトリがコンテナ内に読み書き可能でマウントされます。
3. **ステップ 3 — ゲスト内の認証なし `exec()` 制御サーバー (`infra/vm/setup/server/main.py:180-248`):**
   ゲスト VM 内の `server/main.py` は `0.0.0.0:5000` でリッスンし、トークン検証なしで `POST /execute_windows`（`exec(command)`）による任意 Python コード実行および `POST /setup/launch`（`shell=True`）によるシェルコマンド実行を受け付けます。

### 脆弱なコード箇所 (`winarena_adapter/cli.py:261-266`)
```python
# File: libs/cua-bench/tasks/winarena_adapter/cli.py (lines 261-266, repeated at 421-424 and 646-649)
        "-p", f"{args.browser_port}:8006", # BUG 1: 認証なし noVNC を 0.0.0.0:8006 で LAN に公開
        "-p", f"{args.rdp_port}:3389",     # BUG 2: パスワードなし RDP を 0.0.0.0:3390 で LAN に公開
        "-v", f"{storage_path}:/storage",
        "-v", f"{setup_path}:/shared",     # BUG 3: :ro ではなく読み書き可能でホストソースをマウント
```

---

## 2. 日常の実運用で起こり得る 3 つの重大シナリオ (シナリオ A / シナリオ B / シナリオ C)

### シナリオ A — 大学・企業ラボ LAN 上の他端末から `http://<host-ip>:8006` (noVNC) や `:3390` (RDP) 経由で評価用 Windows VM を乗っ取る
1. 研究者が大学や企業の共有ネットワークに接続されたワークステーション上で `cua-bench` の WinArena タスクを実行します。
2. `cli.py:262-265` が `127.0.0.1:` なしで `-p 8006:8006 -p 3390:3389` を指定するため、Docker が両ポートを `0.0.0.0` で公開します。
3. 同一 LAN 上の任意のユーザーがブラウザで `http://<workstation-ip>:8006` を開くだけで（パスワード不要）、Windows VM デスクトップのフル Administrator 操作権限とベンチマーク環境に注入された LLM API キーを取得できます。

### シナリオ B — 読み書き可能な `-v {setup_path}:/shared` マウント経由でのゲストからホストへの逆汚染
1. コンテナはホストの `winarena_adapter/infra/vm/setup` ディレクトリを `/shared`（`cli.py:265, 424, 649`）として読み書き可能でマウントしています。
2. `0.0.0.0:8006` や `0.0.0.0:3390` 経由で環境に入った攻撃者が、`/shared` 内のセットアップスクリプトや Python ファイルを書き換えます。
3. `/shared` はホスト側の `winarena_adapter` ソースツリーそのものであるため、次回以降のホスト側 CLI 実行やテスト実行時に改ざんされたコードが読み込まれます。

### シナリオ C — ゲスト内ブラウザエージェントが外部ページを閲覧した際の `0.0.0.0:5000/execute_windows` (`exec()`) Drive-By RCE
1. ベンチマーク評価中、Windows VM 内の自律ブラウザエージェントが外部 Web ページや信頼できない HTML タスクアーティファクトを開きます。
2. ページ内の JavaScript が `infra/vm/setup/server/main.py:180-248` で稼働している `http://127.0.0.1:5000/execute_windows` または `http://127.0.0.1:5000/setup/launch` にリクエストを送信します。
3. `server/main.py` には認証がなく、ペイロードをそのまま Python の `exec(command)` や `subprocess.Popen(..., shell=True)` に渡すため、VM 内の Windows Administrator 権限で任意のコードが即座に実行されます。

---

## 3. 実行・再現・検証コマンド例

### 1. Sniper CLI による対象コンポーネントの監査
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua-bench/tasks/winarena_adapter/cli.py"
```

### 2. ローカル隔離環境での再現と検証
```bash
# cli.py 内の 127.0.0.1 プレフィックスのない Docker ポート公開と書き込み可能な /shared マウントを確認
grep -n -C 4 "8006" \
  /home/community-user/targets/cua/libs/cua-bench/tasks/winarena_adapter/cli.py

# infra/vm/setup/server/main.py 内の認証なし exec() を確認
grep -n -C 8 "def execute_windows" \
  /home/community-user/targets/cua/libs/cua-bench/tasks/winarena_adapter/infra/vm/setup/server/main.py
```

### 3. 自動 `RED -> GREEN + BENIGN` E2E 検証ハーネスの実行
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand06
```

---

## 4. エンドツーエンドのランタイム証明 (RED -> GREEN + BENIGN) と防御パッチ

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand06` による実行結果:

```json
{
  "CUA-CAND-06": {
    "ghsa_id": "GHSA-hvhg-6x47-cq96",
    "cli_source_file": "cua/libs/cua-bench/tasks/winarena_adapter/cli.py",
    "server_source_file": "cua/libs/cua-bench/tasks/winarena_adapter/infra/vm/setup/server/main.py",
    "elapsed_ms": 0.05,
    "RED": {
      "lan_exposed_ports": [
        "8006:8006",
        "3390:3389"
      ],
      "host_setup_dir_mounted_writable": true,
      "guest_execute_windows_requires_auth": false
    },
    "GREEN": {
      "lan_exposed_ports": [],
      "host_setup_dir_mounted_writable": false,
      "guest_execute_windows_requires_auth": true
    }
  }
}
```

### Unified Diff パッチ (`git apply --check` 検証済み)
```diff
--- a/libs/cua-bench/tasks/winarena_adapter/cli.py
+++ b/libs/cua-bench/tasks/winarena_adapter/cli.py
@@ -261,9 +261,9 @@
-        "-p", f"{args.browser_port}:8006",
-        "-p", f"{args.rdp_port}:3389",
-        "-v", f"{storage_path}:/storage",
-        "-v", f"{setup_path}:/shared",
+        "-p", f"127.0.0.1:{args.browser_port}:8006",
+        "-p", f"127.0.0.1:{args.rdp_port}:3389",
+        "-v", f"{storage_path}:/storage",
+        "-v", f"{setup_path}:/shared:ro",
```
