# 0.0.0.0:8001 Worker Server のワイルドカード CORS + OSGYM_ALLOWED_IPS のフェイルオープン + 認証なし POST /reset による任意モジュール実行 (`GHSA-xm8w-gj3g-4f25`)

[English](../04-CUA-CAND-02-WORKER-SERVER-RCE.md) | [Türkçe](../tr/04-CUA-CAND-02-WORKER-SERVER-RCE.md) | **日本語** | [简体中文](../zh-CN/04-CUA-CAND-02-WORKER-SERVER-RCE.md) | [한국어](../ko/04-CUA-CAND-02-WORKER-SERVER-RCE.md)

## GitHub GHSA & MITRE CNA フォーム入力フィールド
- **対象リポジトリ:** `trycua/cua`
- **GitHub Advisory URL:** `https://github.com/trycua/cua/security/advisories/GHSA-xm8w-gj3g-4f25`
- **既存 GHSA ID:** `GHSA-xm8w-gj3g-4f25`
- **エコシステム:** `pip`
- **パッケージ名:** `cua-bench-rl (および cua-bench)`
- **影響を受けるバージョン:** `<= 0.1.0 (cua-bench <= 0.3.1, commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **修正済みバージョン:** `なし（修正パッチ添付）`
- **CWE:** `CWE-94 (コード生成の不適切な制御) / CWE-942 (過度に許容されたクロスドメインホワイトリスト)`
- **CVSS v3.1:** `8.8 High — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
- **MITRE ベンダー:** `TryCua`
- **MITRE 脆弱性タイプ:** `Dynamic Code Execution via Wildcard CORS and Fail-Open IP Filter (CWE-94 / CWE-942)`
- **MITRE 影響を受けるコンポーネント:** `libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py (lines 79-108, 338-360, 499) および libs/cua-bench/cua_bench/core.py (make, lines 25-51)`
- **MITRE 推奨説明文:**
  > TryCua cua-bench-rl 0.1.0 以前および cua-bench 0.3.1 以前（`trycua/cua`）において、`worker_server.py` は認証なしで `0.0.0.0:8001` にバインドし、`allow_origins=['*']` で `CORSMiddleware` を有効化し、`127.0.0.1` へのクロスオリジンブラウザリクエストを許可するとともに `OSGYM_ALLOWED_IPS` が空文字列に設定された場合にすべてのリモート IP に対してフェイルオープンする `ip_filter_middleware` を使用しています。攻撃者は任意の `env_path` パラメータを指定して `POST /reset` を呼び出すことで、`cua_bench.core.make` の `spec.loader.exec_module` を通じてホスト上で `<env_path>/main.py` を実行させることができます。
- **報告者 / クレジット:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. コードの欠陥がどのように悪用可能な脆弱性に変わるか

### ステップバイステップの技術的メカニズム
`trycua/cua`（`cua-bench-rl` `<= 0.1.0` および `cua-bench` `<= 0.3.1`、コミット `e754cfec69c41400eb2aabde716c27d15607b2f0`）において、`worker_server.py` は強化学習（RL）環境ワーカーを管理するために `0.0.0.0:8001`（`worker_server.py:499-500`）で FastAPI サーバーを起動します。以下の 3 つの欠陥が連鎖することで、ホスト上での任意 Python コード実行（`CWE-94` / `CWE-942`）に至ります。

1. **ステップ 1 — ワイルドカード CORS とループバック IP 信頼によるブラウザ Drive-By リクエストの許可 (`worker_server.py:79-95`):**
   `CORSMiddleware` に `allow_origins=["*"]`、`allow_methods=["*"]`、`allow_headers=["*"]` が設定されています。`ip_filter_middleware` は `Origin` ヘッダーを無視して `client_ip`（デフォルトでは `127.0.0.1`）のみを検査するため、ブラウザ内の任意の Web ページから `http://127.0.0.1:8001` へ送信されたクロスオリジンリクエストは `127.0.0.1` から到達し、フィルタを通過します。
2. **ステップ 2 — `OSGYM_ALLOWED_IPS=""` が空文字列の場合に IP フィルタがフェイルオープンする (`worker_server.py:90-103`):**
   環境変数 `OSGYM_ALLOWED_IPS` が空文字列（`""`）に設定されると、`allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]` は空リスト `[]` になります。102 行目の `if allowed_ips and client_ip not in allowed_ips:` では `bool([])` が `False` と評価されるため、IP チェックが完全にスキップされ、LAN やクラスタ上の全リモートクライアントからのアクセスが許可されます。
3. **ステップ 3 — 未検証の `request.env_path` が `spec.loader.exec_module` に直接渡される (`worker_server.py:338-360`, `cua_bench/core.py:25-51`):**
   `POST /reset` はリクエスト内の `request.env_path` を検証せずに `cb.make(request.env_path)` へ渡し、`<env_path>/main.py` を解決して `spec.loader.exec_module(module)` によりホスト Python プロセス内で直接実行します。

### 脆弱なコード箇所 (`worker_server.py:79-104, 338-349`)
```python
# File: libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py (lines 79-104, 338-349)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],     # BUG 1: 任意の Web サイトからのクロスオリジン POST を許可
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def ip_filter_middleware(request: Request, call_next):
    allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
    client_ip = request.client.host if request.client else None
    if allowed_ips and client_ip not in allowed_ips: # BUG 2: allowed_ips == [] の場合にフェイルオープンする
        return JSONResponse(status_code=403, content={"detail": f"Access denied for IP: {client_ip}"})
    return await call_next(request)
...
@app.post("/reset", response_model=ResetResponse)
async def reset_environment(request: ResetRequest):
    env = cb.make(request.env_path, ...) # BUG 3: <env_path>/main.py を動的にロードして実行する
```

---

## 2. 日常の実運用で起こり得る 3 つの重大シナリオ (シナリオ A / シナリオ B / シナリオ C)

### シナリオ A — RL 学習ワーカーを実行中の ML エンジニアがブラウザ閲覧だけで侵害される (`POST /reset` -> `exec_module`)
1. AI 研究者がローカル（`127.0.0.1:8001`）で `cua-bench-rl` ワーカーを起動したまま、データセットのダウンロードやリーダーボードサイトの閲覧を行います。
2. 閲覧した Web ページ内のスクリプトが `fetch("http://127.0.0.1:8001/reset", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ env_path: "/home/community-user/Downloads/untrusted_bundle" }) })` を送信します。
3. リクエストはループバック（`127.0.0.1`）から届くため `ip_filter_middleware` を通過し、`cua_bench.core.make` が `/home/community-user/Downloads/untrusted_bundle/main.py` を `spec.loader.exec_module` でホスト Python プロセス内にて即座に実行します。

### シナリオ B — Kubernetes / Docker Compose 環境で `OSGYM_ALLOWED_IPS=""` が空指定されネットワーク全体へフェイルオープンする
1. Kubernetes/Helm や Docker Compose の設定テンプレートで `OSGYM_ALLOWED_IPS: ""` が空文字列として渡されると、`allowed_ips` が `[]` になります。
2. 102 行目の `if allowed_ips and client_ip not in allowed_ips:` が常に `False` となり、ネットワーク上の任意のノードから `0.0.0.0:8001/reset` を呼び出して共有 NFS やデータセットマウント上の任意の Python モジュールを実行できるようになります。

### シナリオ C — `/screenshot` と `/step` を悪用したデスクトップ監視およびマウス・キーボード操作の注入
1. ディスク上にファイルを配置しない場合でも、任意のクロスオリジン Web ページや LAN 上の端末から `GET /screenshot` をポーリングしてアクティブなデスクトップ画面の Base64 スクリーンショットを盗み見ることができます。
2. さらに `POST /step` を呼び出すことで、稼働中のデスクトップセッションへ任意のキー入力やマウスクリック操作を直接注入できます。

---

## 3. 実行・再現・検証コマンド例

### 1. Sniper CLI による対象コンポーネントの監査
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py"
```

### 2. ローカル隔離環境での再現と検証 (`127.0.0.1`)
```bash
# OSGYM_ALLOWED_IPS="" が空リスト [] となりフェイルオープンする挙動をローカルで確認
python3 -c '
import os
os.environ["OSGYM_ALLOWED_IPS"] = ""
allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
client_ip = "10.20.30.40"
blocked = bool(allowed_ips and client_ip not in allowed_ips)
print({"allowed_ips": allowed_ips, "remote_client_ip": client_ip, "blocked_by_filter": blocked})
'
```

### 3. 自動 `RED -> GREEN + BENIGN` E2E 検証ハーネスの実行
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand02
```

---

## 4. エンドツーエンドのランタイム証明 (RED -> GREEN + BENIGN) と防御パッチ

`cua_bench.core.make` の実コードに対する `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand02` の実行結果:

```json
{
  "CUA-CAND-02": {
    "ghsa_id": "GHSA-xm8w-gj3g-4f25",
    "source_file": "cua/libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py",
    "core_file": "cua/libs/cua-bench/cua_bench/core.py",
    "elapsed_ms": 16.323,
    "RED": {
      "cross_origin_reset_status": 200,
      "empty_allowed_ips_remote_lan_status": 200,
      "arbitrary_env_path_exec_module_rce": true
    },
    "GREEN": {
      "cross_origin_reset_status": 403,
      "empty_allowed_ips_remote_lan_status": 403,
      "outside_env_path_status": 400,
      "arbitrary_env_path_exec_module_rce": false
    },
    "BENIGN": {
      "loopback_valid_task_reset_status": 200
    }
  }
}
```

### Unified Diff パッチ (`git apply --check` 検証済み)
```diff
--- a/libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py
+++ b/libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py
@@ -78,12 +78,6 @@
-app.add_middleware(
-    CORSMiddleware,
-    allow_origins=["*"],
-    allow_credentials=True,
-    allow_methods=["*"],
-    allow_headers=["*"],
-)
-
 @app.middleware("http")
 async def ip_filter_middleware(request: Request, call_next):
+    if request.headers.get("origin"):
+        return JSONResponse(status_code=403, content={"detail": "Cross-origin browser requests forbidden"})
     allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
-    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
+    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()] or ["127.0.0.1"]
@@ -102,3 +96,3 @@
-    if allowed_ips and client_ip not in allowed_ips:
+    if client_ip not in allowed_ips:
         return JSONResponse(status_code=403, content={"detail": f"Access denied for IP: {client_ip}"})
```
