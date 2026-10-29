# Gökçe Baran Karakamış — Sniper macOS 導入検証、スキャン済みオープンソースリポジトリおよび検証済みセキュリティアドバイザリ報告書

[English](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.en.md) | [Türkçe](SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md) | **日本語** | [简体中文](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.zh-CN.md) | [한국어](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.ko.md)

**著者 / セキュリティ研究者:** **Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline))

本包括的技術ガイドおよびセキュリティ調査報告書は、以下の3つの主要パートで構成されています。
1. **第 I 部 — macOS（Apple Silicon）実機環境における導入・動作検証レポート:** Sniper Community を実機の macOS ハードウェア上で **ネイティブソース構成（`--core-only`）** と **Docker Desktop 5エンジン構成（`community-tools`）** の双方でエンドツーエンド検証した結果。
2. **第 II 部 — Sniper でスキャンした8つのオープンソースリポジトリ、脆弱化の仕組みと日常業務シナリオ:** **Gökçe Baran Karakamış** が **Sniper** の静的解析（SAST）、インフラ構成解析（IaC）、および依存関係解析（SCA）エンジンを用いて監査した **8つのオープンソースリポジトリ** のソースコードレベル検証、誤検知（False Positive）の切り分け、コードや設定の欠陥がどのような条件で脆弱性へと変化するのかの平易な解説、各リポジトリにおける **3つの日常的な重大シナリオ（`シナリオ A / B / C`）**、および **実行・検証コマンド例**。
3. **第 III 部 — Sniper スキャンで発見された11件の検証済み脆弱性（`01`..`11`）、コード解析、3つのシナリオとランタイム証明（`RED -> GREEN + BENIGN`）:** 6つのオープンソースプロジェクト（**Stirling-PDF、TryCua `cua`、OpenZiti、n8n、Gotify Server、NIIS X-Road**）で発見され、GitHub Security Advisory（`GHSA`）として報告された **11件の検証済み脆弱性** について、コード上でどのように発生し段階的に悪用可能な脆弱性へと至るのか、各脆弱性に対する **3つの具体的な日常業務シナリオ（`シナリオ A / B / C`）**、**再現・検証コマンド例**、および **防御パッチ（`git diff`）**。

---

## 第 I 部 — macOS（Apple Silicon）実機環境における導入・動作検証レポート（2026-10-24）

macOS（Apple Silicon）上での Sniper の導入は **実験的（Experimental）なものではありません**。**ネイティブソース構成（`--core-only`）** と **Docker Desktop 5エンジン構成** の両方が実機の macOS ハードウェア上でテスト・検証され、正式にサポートされています。

| 導入方式 | 実行コマンド | 実機 macOS ハードウェアで検証された範囲 | 状態 |
| :--- | :--- | :--- | :---: |
| **1. ネイティブ macOS ソース導入（Native Source Setup）** | `python3 scripts/setup-community --core-only` | `.venv`（CPython 3.12）作成、ロック済みランタイムパッケージ（`requirements-runtime.lock` + `pip check`）の導入、`scripts/sniper-mcp --help`、`scripts/sniper-project-audit --help`、`cli_reports.py --help`、ローカルループバック Web UI（`127.0.0.1:8787`）、ローカル SQLite データディレクトリの初期化、およびサンプルプロジェクトに対する実監査の実行 | **実機検証済み（PASS）** |
| **2. Docker Desktop 5エンジン構成（5-Engine Container Stack）** | `python3 scripts/setup-community` *(または `docker compose --profile community-tools up -d`)* | Docker Desktop（Apple Silicon / `linux/arm64`）上での `sniper-community` コアコンテナと5つの補助オープンソースセキュリティエンジン（`zap`、`nuclei`、`trivy`、`httpx`、`katana`）の起動、ヘルスチェック、および共有 `/workspace` ボリューム監査 | **実機検証済み（PASS）** |

### macOS 実機環境で確認された技術的詳細
* **Apple Silicon（`arm64`）ネイティブ Python 環境:** `scripts/setup-community` は macOS 上の Homebrew Python（`3.11+` / `3.12`）を自動検出し、ネイティブ `arm64` wheel パッケージ（`fastapi`、`uvicorn`、`pydantic`、`PyJWT`、`cryptography`、`httpx`、`beautifulsoup4`、`jinja2`）を用いて依存関係競合ゼロ（`pip check: No broken requirements found`）で `.venv` を構築します。
* **エンドツーエンドのローカルプロジェクト監査:** macOS 実機上で実行した `scripts/sniper-project-audit` は、SAST・IaC・SCA の3レイヤーすべてで構造化 JSON レポートおよび SARIF/Markdown 出力をミリ秒〜数秒単位で生成しました。
* **Docker エンジンのマルチアーキテクチャ互換性:** `docker-compose.yml` 内の `community-tools` プロファイルは、Apple Silicon 上の Docker Desktop でネイティブ `arm64` または透過的な Rosetta 2 レイヤーを介して起動し、`127.0.0.1:8787` のループバック境界を維持したまま動作します。

---

## 第 II 部 — Sniper でスキャンした8つのオープンソースリポジトリと関連リスク分析

本パートでは、先行セキュリティ調査において **Sniper** でスキャンを実施した **8つのオープンソースリポジトリ** について、(A) Sniper の生スキャン結果、(B) ソースコード監査で特定された誤検知（False Positive）、(C) 実在するコード・設定上のリスク、(D) **コード内でどのように発生し脆弱性へと変化するのか（誰にでもわかる平易な解説）**、(E) **日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）**、(F) **単独 vs. 連鎖（Chaining）時の深刻度**、および (G) **具体的な実行・検証コマンド例** を詳述します。

---

## 1. AutoGPT (`Significant-Gravitas/AutoGPT`)

### A. Sniper スキャン統計概要
* **閾値超過（高信頼度）検出数:** `93` 件（Critical `2`、High `39`、Medium `49`、Low `3`）
* **トリアージ総検出数:** `142` 件（SAST `61`、IaC `42`、SCA `39`）

### B. ソースコード検証と誤検知（False Positive）の切り分け
1. **誤検知と確認された Critical/High SAST アラート:**
   * `autogpt_platform/backend/backend/executor/manager.py` および `scheduler.py` における **2件の Critical SQL インジェクション（`obj.execute(...)`）** アラートは、SQL クエリではなくブロック実行オブジェクトの Python メソッド呼び出し（`block_obj.execute(input_data)`）であり、**完全な誤検知（False Positive）** です。
   * FastAPI ルーター上の `Security(...)` 依存性注入やテスト用ダミー JWT 文字列に対するハードコード秘密情報アラートも誤検知です。
2. **実在が確認されたコードおよびインフラ所見:**
   * **信頼境界付きの `pickle.loads` デシリアライゼーション:** `autogpt_platform/backend/backend/util/jobstore_backfill.py:67` は、APScheduler のジョブテーブル（`apscheduler_jobs.job_state`）から読み取ったバイナリ列に対して直接 `pickle.loads(job_state)` を実行します。
   * **Docker Compose のデフォルト認証情報と非ルート未設定の Dockerfile:** ローカル・開発用 Compose ファイルにデフォルトの PostgreSQL/Redis パスワードが含まれており、一部のコンテナイメージが `root` ユーザーのまま実行されます。

### D. コード内でどのように発生し脆弱性へ変化するのか（平易な解説）
Python の `pickle.loads()` は、保存されたバイト列から Python オブジェクトを復元する際に、攻撃者が細工した `__reduce__` メソッドを自動的に実行してしまう危険な関数です。通常、`jobstore_backfill.py` は内部の PostgreSQL データベース（`apscheduler_jobs` テーブル）しか読み取りません。しかし、もし開発用 Docker Compose のデフォルトパスワード（`postgres` 等）が本番やステージング環境でそのまま使われていたり、別の SQL インジェクションや SSRF によってデータベースへの書き込み権限が奪われたりすると、攻撃者は悪意ある Pickle ペイロードを `apscheduler_jobs` テーブルに書き込み、バックフィル処理が走った瞬間に **`root` 権限のコンテナ内で任意の OS コマンドを実行（RCE）** できるようになります。

### E. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — デフォルト Compose パスワードのまま公開されたステージング環境での DB 経由 RCE:**
  1. 社内 AI チームが AutoGPT Platform をクラウド VM 上に Docker Compose で構築し、PostgreSQL や Redis のポートが内部ネットワークからデフォルト認証情報のまま到達可能になっている。
  2. 同一 VPC 内の侵害された別サービスから攻撃者が PostgreSQL の `apscheduler_jobs` テーブルに悪意ある `job_state`（`pickle` ペイロード）を挿入する。
  3. `jobstore_backfill.py:67` の `pickle.loads(job_state)` が実行され、`root` コンテナ内で任意コード実行が成立し、登録済みの OpenAI/Anthropic API キーやユーザーデータが窃取される。
* **シナリオ B — 共有 Redis / メッセージブローカー汚染によるワーカー乗っ取り:**
  1. 複数の検証環境が同じ内部ネットワーク上の認証なし Redis インスタンスを共有している。
  2. 攻撃者がジョブキューまたはスケジュール状態のペイロードを書き換え、バックエンド Executor ワーカーに悪意あるジョブを実行させる。
* **シナリオ C — `root` 権限コンテナ内でのカスタムブロック実行によるホストマウント汚染:**
  1. 開発者がローカルまたは共有サーバー上でホストディレクトリをバインドマウントした状態で AutoGPT コンテナを `root` のまま稼働させる。
  2. ワークフロー内で意図しないファイル書き込みが発生した際、`root` 権限のためマウントされたホスト側の設定ファイルやスクリプトが上書きされる。

### F. 単独および連鎖（Chaining）時の深刻度分析
* **単独深刻度:** **Low / Medium**（外部から認証なしで直接 `pickle.loads` に到達するエンドポイントは存在しないため）。
* **連鎖（Chaining）深刻度:** **条件付き Medium / High**（Compose のデフォルト DB パスワード露出 + `apscheduler_jobs` への書き込み + `jobstore_backfill.py` の `pickle.loads` + `root` コンテナが連鎖した場合）。外部から直接悪用可能な未認証脆弱性ではなく、多層防御（Defense-in-Depth）の強化対象です。

### G. 実行・検証コマンド例
```bash
# 1. AutoGPT リポジトリに対する Sniper フル監査の実行
python3 scripts/sniper-project-audit "$HOME/audit-targets/autogpt" --format json --output "$HOME/audit-targets/reports/autogpt-audit.json"

# 2. jobstore_backfill.py 内の pickle.loads 呼び出し箇所の確認
grep -n -C 5 "pickle.loads" "$HOME/audit-targets/autogpt/autogpt_platform/backend/backend/util/jobstore_backfill.py"

# 3. 誤検知と確認された executor/manager.py の .execute() 呼び出しの確認
grep -n -C 5 "\.execute(" "$HOME/audit-targets/autogpt/autogpt_platform/backend/backend/executor/manager.py"
```

---

## 2. Zitadel (`zitadel/zitadel`)

### A. Sniper スキャン統計概要
* **閾値超過（高信頼度）検出数:** `67` 件（Critical `8`、High `42`、Medium `17`）
* **トリアージ総検出数:** `286` 件

### B. ソースコード検証と誤検知（False Positive）の切り分け
1. **8件すべての Critical アラートは誤検知:** Go コード内の `exec.Command` や SQL クエリ構築に関する8件の Critical SAST アラートは、ビルドツール・マイグレーション補助スクリプト内の固定引数呼び出しであり、外部入力が流入しないため **すべて誤検知（False Positive）** です。
2. **実在が確認されたインフラ設定所見:**
   * `deploy/compose/` 配下の3つの開発・テスト用 Docker Compose ファイルでホストの `/var/run/docker.sock` がコンテナにマウントされています。
   * `apps/docs/` 配下のサンプル環境変数設定で `NODE_TLS_REJECT_UNAUTHORIZED=0` が使用されています。

### D. コード内でどのように発生し脆弱性へ変化するのか（平易な解説）
Docker ソケット（`/var/run/docker.sock`）はホスト上の Docker デーモンを直接制御する管理者 API です。これをコンテナ内にマウントすると、そのコンテナ内で動作するプロセスはホスト上の全コンテナの停止・起動や、ホストのルートファイルシステム（`/`）をマウントした特権コンテナの新規起動が可能になります。また、`NODE_TLS_REJECT_UNAUTHORIZED=0` は Node.js の TLS 証明書検証を全面的に無効化するため、サンプル設定をそのまま本番環境へコピーすると中間者攻撃（MITM）に対して無防備になります。

### E. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — 開発用 Compose 構成を流用した共有ステージング環境での `docker.sock` 経由のホスト奪取:**
  1. DevOps チームが `deploy/compose/` の構成をそのまま共有ステージング VM にデプロイし、`/var/run/docker.sock` をマウントした補助コンテナを稼働させる。
  2. その補助コンテナが侵害されると、攻撃者は `/var/run/docker.sock` を通じてホスト OS のファイルシステム全体をマウントした新規コンテナを起動し、Zitadel のマスター鍵と DB 認証情報を奪取する。
* **シナリオ B — ドキュメントの `NODE_TLS_REJECT_UNAUTHORIZED=0` をコピーした本番ポータルでの OIDC トークン盗聴:**
  1. 開発者が `apps/docs/` のサンプル設定を参考にしてフロントエンド/BFF 環境変数に `NODE_TLS_REJECT_UNAUTHORIZED=0` を設定したままデプロイする。
  2. ネットワーク経路上の攻撃者が自己署名証明書を用いて TLS 通信を傍受し、OIDC アクセストークンやクライアントシークレットを平文で取得する。
* **シナリオ C — CI/CD テスト環境でのソケット共有によるビルドキャッシュ汚染:**
  1. セルフホスト CI サーバー上で `docker.sock` マウント付きの Compose テストを実行中、悪意あるテストコードがホストの Docker デーモンを操作して他のジョブのコンテナイメージを改ざんする。

### F. 単独および連鎖（Chaining）時の深刻度分析
* **単独・連鎖深刻度:** **Low / Medium**。`docker.sock`（`deploy/compose/`）と `NODE_TLS_REJECT_UNAUTHORIZED=0`（`apps/docs/`）は別々のサンプル/開発用ファイルに存在し、製品本体の CVE ではなくデプロイテンプレートのハードニング項目です。

### G. 実行・検証コマンド例
```bash
# 1. Zitadel リポジトリに対する Sniper 監査の実行
python3 scripts/sniper-project-audit "$HOME/audit-targets/zitadel" --format json --output "$HOME/audit-targets/reports/zitadel-audit.json"

# 2. Compose ファイル内の docker.sock マウント箇所の確認
grep -rn "docker.sock" "$HOME/audit-targets/zitadel/deploy/"

# 3. ドキュメント内の NODE_TLS_REJECT_UNAUTHORIZED 設定箇所の確認
grep -rn "NODE_TLS_REJECT_UNAUTHORIZED" "$HOME/audit-targets/zitadel/apps/docs/"
```

---

## 3. Nextcloud MCP Server (`cbcoutinho/nextcloud-mcp-server`)

### A. Sniper スキャン統計概要
* **閾値超過（高信頼度）検出数:** `59` 件（SAST Critical `1` / High `6`、IaC High `7`、SCA Critical `5` / High `40`）

### B. ソースコード検証と誤検知（False Positive）の切り分け
1. **SSRF アラート（`nextcloud_mcp_server/auth/login_flow.py:192`）は誤検知:** Sniper は `poll_endpoint` に対する HTTP リクエストを SSRF 候補として検出しましたが、直前の `initiate()` メソッド内で `_rewrite_to_nextcloud_host(poll_endpoint, self.nextcloud_host)` が呼ばれており、スキーム・ホスト・ポートがすべて設定済みの `self.nextcloud_host` に強制書き換えされるため、外部ホストへの SSRF は発生しません。
2. **JWT アラート（`token_utils.py`）は意図されたトークンインスペクタ:** `verify_signature=False` は検証済みトークンまたはメタデータ表示用のヘルパーであり、認証バイパスではありません。
3. **GitHub Actions ワークフロー（`.github/workflows/pact.yml`）:** ブランチ名のシェル展開がありますが、`if: github.event.pull_request.head.repo.full_name == github.repository` によって外部フォークからの PR はブロックされています。

### D. コード内でどのように発生し脆弱性へ変化するのか（平易な解説）
OAuth / Login Flow v2 では、サーバーが返す `poll.endpoint` URL に対してクライアントがポーリングを行います。もしクライアントがサーバーから返された URL をそのまま信じてリクエストすると、悪意あるレスポンスによって内部ネットワーク（`169.254.169.254` 等）へリクエストが誘導される SSRF になります。本リポジトリでは `_rewrite_to_nextcloud_host()` で接続先オリジンを固定することでこれを防いでいます。一方、`.github/workflows/pact.yml` では同一リポジトリ内のブランチ名がシェルに直接展開されるため、リポジトリへの書き込み権限を持つアカウントが侵害された場合に限り、CI ランナー上でコマンド注入が可能になります。

### E. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — 同一リポジトリのブランチ名を用いた CI ワークフロー（`pact.yml`）でのシークレット漏洩:**
  1. 開発者の個人アクセストークン（PAT）が漏洩し、攻撃者がリポジトリ内に `feat";curl ...;#` のようなブランチを作成して PR を開く。
  2. `same-repo` 条件を通過した `pact.yml` がブランチ名を bash スクリプト内で展開し、CI シークレットが外部へ送信される。
* **シナリオ B — 古いロックファイル依存関係（SCA）を含んだままのコンテナ公開:**
  1. チームが MCP サーバーを HTTP/SSE モードで社内ネットワークに公開する際、更新されていない Python 依存パッケージの既知の脆弱性（SCA 検出分）が攻撃面に露出する。
* **シナリオ C — カスタム認証フォークで `_rewrite_to_nextcloud_host()` を削除した場合の SSRF 再発:**
  1. 開発者がリバースプロキシ対応のために `_rewrite_to_nextcloud_host()` のオリジン固定処理を削除すると、`poll_endpoint` が任意の内部 URL を指せるようになり SSRF が発生する。

### F. 単独および連鎖（Chaining）時の深刻度分析
* **単独・連鎖深刻度:** **Low**。プロダクション SAST 脆弱性は存在せず、CI の環境変数パラメータ化および依存関係更新のみが推奨されます。

### G. 実行・検証コマンド例
```bash
# 1. Nextcloud MCP Server に対する Sniper 監査の実行
python3 scripts/sniper-project-audit "$HOME/audit-targets/nextcloud-mcp" --format json --output "$HOME/audit-targets/reports/nextcloud-mcp-audit.json"

# 2. login_flow.py 内の _rewrite_to_nextcloud_host 防御ロジックの確認
grep -n -C 12 "_rewrite_to_nextcloud_host" "$HOME/audit-targets/nextcloud-mcp/nextcloud_mcp_server/auth/login_flow.py"

# 3. pact.yml の same-repo ガード条件の確認
grep -n -C 8 "head.repo.full_name" "$HOME/audit-targets/nextcloud-mcp/.github/workflows/pact.yml"
```

---

## 4. MCPJam Inspector (`MCPJam/inspector`)

### A. Sniper スキャン統計概要
* **閾値超過（高信頼度）検出数:** `122` 件（SAST Critical `12` / High `8`、SCA Critical `6` / High `96`）

### B. ソースコード検証と誤検知（False Positive）の切り分け
* **20件の Critical/High SAST アラートのうち18件は完全な誤検知:** 14件はコメント内の英語表現 `eval (` / `exec (` に反応したもの、2件は TypeScript 型定義ファイル（`.d.ts`）、2件はフロントエンド UI のラベル文字列連結でした。
* **実在が確認された所見:** `.github/workflows/pr-preview.yml` における同一リポジトリ限定（`same-repo` ガード付き）のブランチ名シェル展開と、ロックファイル内の SCA 依存関係アラートです。

### D. コード内でどのように発生し脆弱性へ変化するのか（平易な解説）
MCPJam Inspector は開発者がローカルの MCP サーバーをブラウザ上でテスト・デバッグするためのツールです。CI ワークフロー `pr-preview.yml` では PR プレビュー環境を作成する際にブランチ名をスクリプトへ埋め込んでいます。外部フォークからの PR は `head.repo.full_name == github.repository` で遮断されていますが、環境変数（`env:`）経由ではなく直接 `${{ ... }}` で展開しているため、内部ブランチ名によるシェルインジェクションの余地が残っています。また、`npm` ロックファイル内の多数のトランジティブ依存関係（SCA）は、Inspector を共有サーバー上でホストする場合に更新が必要です。

### E. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — 内部コントリビュータ権限を用いた `pr-preview.yml` でのプレビュー環境シークレット取得:**
  1. リポジトリにブランチ作成権限を持つアカウントが特殊文字を含むブランチ名で PR を作成する。
  2. プレビューデプロイ用ワークフローがブランチ名をシェル展開し、クラウドプレビュー環境のデプロイトークンが露出する。
* **シナリオ B — 共有デバッグサーバーとして公開された Inspector の古い npm パッケージ悪用:**
  1. 開発チームが MCPJam Inspector を社内共有サーバー上で常時稼働させ、古いフロントエンド/サーバー依存パッケージの脆弱性が内部ネットワークに露出する。
* **シナリオ C — 悪意ある外部 MCP サーバー出力のインスペクタ表示時の DOM 処理リスク:**
  1. 開発者が信頼できないサードパーティ MCP サーバーに接続してレスポンスを検査する際、古い UI 依存ライブラリを介して予期しないスクリプト動作が発生する。

### F. 単独および連鎖（Chaining）時の深刻度分析
* **単独・連鎖深刻度:** **Low / Medium**。外部フォーク PR は遮断されており、内部 CI ハードニングと SCA パッケージ更新が推奨事項です。

### G. 実行・検証コマンド例
```bash
# 1. MCPJam Inspector に対する Sniper 監査の実行
python3 scripts/sniper-project-audit "$HOME/audit-targets/mcpjam-inspector" --format json --output "$HOME/audit-targets/reports/mcpjam-inspector-audit.json"

# 2. pr-preview.yml の条件式とスクリプト展開箇所の確認
grep -n -C 10 "pull_request" "$HOME/audit-targets/mcpjam-inspector/.github/workflows/pr-preview.yml"
```

---

## 5. Codebase Memory MCP (`DeusData/codebase-memory-mcp`)

### A. Sniper スキャン統計概要
* **閾値超過（高信頼度）検出数:** `32` 件（SAST Critical `17` / High `7`、SCA High `8`）

### B. ソースコード検証と誤検知（False Positive）の切り分け
* **17件すべての Critical SAST アラートは誤検知:**
  * `src/store/store.c:2864` の SQL インジェクションアラートは、プログラム内部の固定テーブル名配列と `sqlite3_prepare_v2` パラメータバインディング（`?`）を使用しており安全です。
  * `src/lang/c_lsp.h:54` はコメント行、`kotlin_lsp.c` / `py_lsp.c` / `store.c:4482` はすべて `snprintf` や固定長境界チェック付きのバッファ操作であり、`xmalloc.c` や `mcp.c` も安全なラッパー実装です。
  * `src/http/http_server.c` には `localhost` / `127.0.0.1` のみに限定した厳格な `Host` ヘッダー検証（違反時は HTTP `403 Forbidden`）と CORS オリジン検証が実装されており、ブラウザからのドライブバイ攻撃や DNS Rebinding は成立しません。

### D. コード内でどのように発生し脆弱性へ変化するのか（平易な解説）
C 言語のプログラムでは、`sprintf` や境界チェックのないメモリコピーを使うとバッファオーバーフローになり、SQL 文字列を直接連結すると SQL インジェクションになります。また、ローカル HTTP サーバーが `Host` ヘッダーや `Origin` ヘッダーを検証しないと、ブラウザで悪意あるサイトを開いた際にローカルのソースコードインデックスが盗まれる危険があります。しかし `codebase-memory-mcp` の実際の C ソースコードを精査すると、SQL はプリペアドステートメントで処理され、文字列は `snprintf(buf, sizeof(buf), ...)` で上限が守られ、`http_server.c` は非ローカルの `Host` / `Origin` を `403` で拒否しているため、これらが脆弱性に変化することはありません。

### E. 日常業務で発生し得る3つの重大シナリオ（もし防御実装が外された場合の境界シナリオ `シナリオ A / B / C`）
* **シナリオ A — リバースプロキシ経由でローカル HTTP ポートを LAN に転送した場合のインデックス閲覧:**
  1. 開発者が `http_server.c` のローカルポートを `socat` や `nginx`（`Host: localhost` 書き換え付き）で社内 LAN に公開してしまう。
  2. この場合、`http_server.c` の `Host: localhost` チェックがプロキシによって満たされるため、同一 LAN 上の第三者がコードグラフを検索できるようになる。
* **シナリオ B — 共有マルチユーザー Linux サーバー上でのローカルループバック共有:**
  1. 1台の Linux 開発サーバーに複数の開発者が SSH ログインして作業している。
  2. あるユーザーが起動した `127.0.0.1` ポートには同一マシン上の別 OS ユーザーからも接続可能であるため、`/home/community-user/private-project` のインデックス情報にローカルプロセスからアクセスされる可能性がある。
* **シナリオ C — 大規模リポジトリの初回インデックス作成時の CPU / I/O 負荷:**
  1. 数百万行規模のモノレポとビルド成果物ディレクトリ（`node_modules` や `target`）を除外せずにインデックス化すると、SQLite トランザクションと LSP パーサーがローカル CPU とディスク I/O を一時的に占有する。

### F. 単独および連鎖（Chaining）時の深刻度分析
* **単独・連鎖深刻度:** **Low**。ブラウザ経由のリモートコード漏洩チェーンは `http_server.c` の `Host` + CORS 防御により成立しません。

### G. 実行・検証コマンド例
```bash
# 1. Codebase Memory MCP に対する Sniper 監査の実行
python3 scripts/sniper-project-audit "$HOME/audit-targets/codebase-memory-mcp" --format json --output "$HOME/audit-targets/reports/codebase-memory-mcp-audit.json"

# 2. http_server.c 内の Host ヘッダー検証（403 Forbidden）と CORS 防御の確認
grep -n -C 15 "403" "$HOME/audit-targets/codebase-memory-mcp/src/http/http_server.c"

# 3. store.c:2864 周辺の sqlite3 パラメータバインディング実装の確認
sed -n '2850,2880p' "$HOME/audit-targets/codebase-memory-mcp/src/store/store.c"
```

---

## 6. GitLab MCP Server (`yoda-digital/gitlab-mcp-server`)

### A. Sniper スキャン統計概要
* **閾値超過（高信頼度）検出数:** `5` 件（Critical `0`、High `4`、Medium `1`）

### B. ソースコード検証と誤検知（False Positive）の切り分け
* `recorder.go` および `make.go` におけるファイル操作・コマンド実行アラートはテスト記録およびビルド補助ツールであり誤検知です。
* 実在する唯一のセキュリティ設定所見は、ユーザーが明示的に環境変数 `GITLAB_MCP_SKIP_TLS_VERIFY=true` を設定した場合に `InsecureSkipVerify: true` が有効になるオプトイン機能です。

### D. コード内でどのように発生し脆弱性へ変化するのか（平易な解説）
社内 GitLab サーバーが自己署名証明書（Self-Signed Certificate）を使っている場合、開発者は手っ取り早く接続エラーを消すために `GITLAB_MCP_SKIP_TLS_VERIFY=true` を設定しがちです。このフラグを有効にすると、Go の HTTP クライアントは接続先サーバーの TLS 証明書が本物かどうかを一切確認しなくなります。その結果、開発者が外出先の Wi-Fi 等で IDE を開いた際、通信経路上の攻撃者（MITM）が偽の GitLab サーバーになりすましてリクエストを受け取り、ヘッダーに含まれる `PRIVATE-TOKEN` や `Authorization: Bearer glpat-...` トークンをそのまま盗み取ることが可能になります。

### E. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — 社内自己署名 GitLab 用に `GITLAB_MCP_SKIP_TLS_VERIFY=true` を設定した開発者がカフェ/ホテルの Wi-Fi でトークンを奪われる:**
  1. エンジニアが社内 GitLab の証明書エラーを回避するため、IDE の MCP 設定に `GITLAB_MCP_SKIP_TLS_VERIFY=true` を追加する。
  2. 出張先のホテルやカフェの Wi-Fi で IDE を起動した際、MCP サーバーが GitLab へ接続を試み、同一ネットワーク上の攻撃者が偽証明書で応答して `glpat-...` パーソナルアクセストークンを窃取する。
* **シナリオ B — チーム共有ドキュメントでの非安全な MCP 設定テンプレートの拡散:**
  1. チームのオンボーディング資料で `claude_desktop_config.json` のサンプルに最初から `GITLAB_MCP_SKIP_TLS_VERIFY=true` が記載され、全員に配布される。
  2. 正規の TLS 証明書を持つ本番 GitLab インスタンスへの通信まで恒久的に証明書検証なしとなり、組織全体のソースコード・PR 操作権限が MITM リスクに晒される。
* **シナリオ C — 企業プロキシ（TLS インスペクション）環境でのルート CA 登録省略による検証無効化:**
  1. 社内プロキシのルート CA 証明書を `SSL_CERT_FILE` に登録する代わりに、CI エージェント上で `GITLAB_MCP_SKIP_TLS_VERIFY=true` を有効化してしまい、偽装エンドポイントへの接続を許す。

### F. 単独および連鎖（Chaining）時の深刻度分析
* **単独・連鎖深刻度:** **Low**。デフォルトでは TLS 検証は有効（`false`）であり、連鎖する他の脆弱性も存在しません。

### G. 実行・検証コマンド例
```bash
# 1. GitLab MCP Server に対する Sniper 監査の実行
python3 scripts/sniper-project-audit "$HOME/audit-targets/gitlab-mcp-server" --format json --output "$HOME/audit-targets/reports/gitlab-mcp-server-audit.json"

# 2. GITLAB_MCP_SKIP_TLS_VERIFY と InsecureSkipVerify の実装箇所の確認
grep -rn -C 8 "GITLAB_MCP_SKIP_TLS_VERIFY" "$HOME/audit-targets/gitlab-mcp-server/"
```

---

## 7. Apktool MCP (`zinja-coder/apktool-mcp-server`)

### A. Sniper スキャン統計概要
* **閾値超過（高信頼度）検出数:** `16` 件（SAST Medium `1`、SCA Critical `4` / High `12`）

### B. ソースコード検証と誤検知（False Positive）の切り分け
* ファーストパーティ Python コードには Critical/High の SAST 脆弱性（コマンドインジェクション等）は存在せず、1件の Medium アラートは誤検知です。
* 一方、`uv.lock` 内にロックされているサードパーティパッケージ（`authlib 1.6.8`、`cryptography 46.0.5`、`pyjwt 2.11.0`、`python-multipart 0.0.20`、`starlette 0.47.3`、`urllib3 2.5.0` 等）に対して **Critical 4件、High 12件の SCA 依存関係レコード** が検出されました。

### D. コード内でどのように発生し脆弱性へ変化するのか（平易な解説）
自身の Python コードにバグがなくても、`uv.lock` で古いバージョンのライブラリ（`starlette`、`python-multipart`、`authlib` 等）が固定されていると、`uv sync --frozen` を実行したすべての環境に既知の脆弱性を持つライブラリがそのままインストールされます。ローカルの `stdio` モードで個人利用する分には影響は限定的ですが、MCP サーバーを HTTP/SSE モードでネットワーク越しに公開したり、不特定の外部 APK 解析パイプラインに組み込んだりすると、下層ライブラリの認証不備や DoS 脆弱性が直接悪用可能になります。

### E. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — ネットワーク公開されたリモート APK 解析 MCP サーバーにおける `authlib` / `pyjwt` の認証検証不備:**
  1. セキュリティチームが Apktool MCP を社内共有サーバー上で HTTP/SSE トランスポートとして公開し、JWT ベースのアクセス制御を有効化する。
  2. `uv.lock` 内の古い `authlib 1.6.8` / `pyjwt 2.11.0` の既知のトークン検証不備を突かれ、未承認クライアントからデコンパイル API が呼び出される。
* **シナリオ B — `python-multipart 0.0.20` / `starlette 0.47.3` を介した異常なマルチパートリクエストによるサービス停止（DoS）:**
  1. HTTP エンドポイントに対して細工されたマルチパート境界（boundary）を持つリクエストが送信される。
  2. 古い `python-multipart` パーサーが過剰な CPU・メモリを消費し、MCP サーバープロセスがハングする。
* **シナリオ C — 悪意ある APK ファイルの逆アセンブル時におけるリソース枯渇（Zip Bomb / 大量リソース展開）:**
  1. マルウェア解析担当者が極端に圧縮率の高い APK（Zip Bomb 構造）を Apktool MCP に渡す。
  2. 下層の展開処理がディスク容量とメモリを使い果たし、解析ワークステーションが一時停止する。

### F. 単独および連鎖（Chaining）時の深刻度分析
* **単独・連鎖深刻度:** **Low / Medium（SCA）**。ファーストパーティ SAST はクリーンであり、`uv lock --upgrade` による依存パッケージ更新が推奨されます。

### G. 実行・検証コマンド例
```bash
# 1. Apktool MCP に対する Sniper 監査の実行
python3 scripts/sniper-project-audit "$HOME/audit-targets/apktool-mcp" --format json --output "$HOME/audit-targets/reports/apktool-mcp-audit.json"

# 2. uv.lock 内の主要パッケージバージョンの確認
grep -n -A 2 -E 'name = "(authlib|cryptography|pyjwt|python-multipart|starlette|urllib3)"' "$HOME/audit-targets/apktool-mcp/uv.lock"

# 3. Sniper CLI レポートツールで High 以上の検出項目を一覧表示
python3 cli_reports.py --input "$HOME/audit-targets/reports/apktool-mcp-audit.json" --min-severity high
```

---

## 8. JADX MCP (`zinja-coder/jadx-mcp-server`)

### A. Sniper スキャン統計概要
* **閾値超過（高信頼度）検出数:** `32` 件（SAST Medium `3`、SCA Critical `6` / High `26`）

### B. ソースコード検証と誤検知（False Positive）の切り分け
* ファーストパーティ Python コードに Critical/High の SAST 脆弱性はなく、3件の Medium アラートもローカル JADX ブリッジ通信に関するもので悪用可能な脆弱性ではありません。
* `uv.lock` 内のロック済み依存関係に対して **Critical 6件、High 26件の SCA 脆弱性レコード**（`authlib 1.6.8`、`pyjwt 2.11.0`、`cryptography 46.0.5`、`python-multipart 0.0.20`、`starlette 0.47.3`、`urllib3 2.5.0` 等）が検出されました。

### D. コード内でどのように発生し脆弱性へ変化するのか（平易な解説）
JADX MCP は、リバースエンジニアリングツール JADX で開いている Android アプリのコードを AI アシスタントへ渡すブリッジサーバーです。ユーザーが `uv sync` で環境を構築すると、`uv.lock` に記載された脆弱な旧バージョンの HTTP/認証フレームワークがそのまま導入されます。JADX MCP をリモート解析サーバー上で HTTP/SSE モードで稼働させた場合、ファーストパーティコードに問題がなくても、基盤となる `starlette` や `authlib`、`urllib3` の既知の脆弱性を突かれるリスクが生じます。

### E. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — リモートリバースエンジニアリングサーバー上の `authlib 1.6.8` / `pyjwt 2.11.0` を介した認証回避:**
  1. モバイルセキュリティチームが、高性能サーバー上で JADX MCP を HTTP/SSE モードで起動し、OAuth/JWT で保護して共有利用する。
  2. `uv.lock` 内の古い `authlib` / `pyjwt` の既知のアルゴリズム・クレーム検証の欠陥により、細工されたトークンで非公開アプリの逆コンパイル結果が読み取られる。
* **シナリオ B — `python-multipart 0.0.20` および `starlette 0.47.3` を突いたマルチパート解析 DoS:**
  1. HTTP モードで公開されている MCP ポートに対し、不正な形式の `multipart/form-data` ペイロードが送信される。
  2. パーサーのバックトラッキングやメモリ消費により、JADX MCP ブリッジが応答不能になる。
* **シナリオ C — `urllib3 2.5.0` / `cryptography 46.0.5` におけるリダイレクト時のヘッダー漏洩・証明書解析リスク:**
  1. JADX MCP が外部シンボルサーバーやプラグインエンドポイントへ `urllib3` で通信した際、クロスオリジンリダイレクト時に認証ヘッダーが保持されたまま外部へ転送される。

### F. 単独および連鎖（Chaining）時の深刻度分析
* **単独・連鎖深刻度:** **Low / Medium（SCA）**。ファーストパーティコードの攻撃チェーンはなく、`uv.lock` の更新のみで解消可能です。

### G. 実行・検証コマンド例
```bash
# 1. JADX MCP に対する Sniper 監査の実行
python3 scripts/sniper-project-audit "$HOME/audit-targets/jadx-mcp" --format json --output "$HOME/audit-targets/reports/jadx-mcp-audit.json"

# 2. uv.lock 内の脆弱な依存関係バージョンの確認
grep -n -A 2 -E 'name = "(authlib|cryptography|pyjwt|python-multipart|starlette|urllib3)"' "$HOME/audit-targets/jadx-mcp/uv.lock"

# 3. Sniper CLI で High 以上の SCA 検出項目をフィルタリング表示
python3 cli_reports.py --input "$HOME/audit-targets/reports/jadx-mcp-audit.json" --min-severity high
```

---

## 比較一覧表：単独 vs. 連鎖（Chaining）深刻度および証拠ステータス

| リポジトリ | Sniper SAST / IaC / SCA 概要 | ソースコード検証結果（実在 vs. 誤検知） | 単独深刻度 | 検出項目は連鎖するか？（Chaining） | 連鎖時の深刻度と公開ステータス |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **1. `autogpt`** | 閾値超過 `93` 件（`2C / 39H`）; トリアージ `142` 件 | **Critical SQLi 2件（`obj.execute`）、JWT、FastAPI `Security()` はすべて誤検知**; `jobstore_backfill.py` の `pickle.loads` + Compose デフォルトパスワード + Root Dockerfile は実在 | **Low / Medium** | **条件付き仮説:** 攻撃者が DB の `apscheduler_jobs` テーブルへの書き込み権限を得た場合のみ `pickle.loads` + Root コンテナが連鎖 | **MEDIUM / HIGH（条件付き）** *（直接の未認証脆弱性なし；多層防御の強化対象）* |
| **2. `zitadel`** | 閾値超過 `67` 件（`8C / 42H`）; トリアージ `286` 件 | **Critical SQLi/`exec` 8件はすべて誤検知**; `deploy/compose/` 配下の3つの `docker.sock` マウントとドキュメント内の `TLS_REJECT=0` は実在 | **Low / Medium** | **いいえ（別々のサンプル）:** `docker.sock`（`deploy/compose/`）と `TLS_REJECT=0`（`apps/docs/...`）は別ファイル | **LOW / MEDIUM** *（開発・サンプル構成のハードニング；製品 CVE ではない）* |
| **3. `nextcloud-mcp`** | 閾値超過 `59` 件（`SAST 1C/6H`, `IaC 7H`, `SCA 5C/40H`） | **`login_flow.py:192` の SSRF（`initiate()` 内に `_rewrite_to_nextcloud_host` あり）と `token_utils.py` の JWT は誤検知**; `pact.yml` は `same-repo` 保護あり | **Low** | **いいえ:** `pact.yml` は外部フォーク PR を遮断しており、`poll_endpoint` も `self.nextcloud_host` に固定されている | **LOW** *（検証済み SAST 脆弱性なし；内部 CI のハードニング）* |
| **4. `mcpjam-inspector`** | 閾値超過 `122` 件（`SAST 12C/8H`, `SCA 6C/96H`） | **Critical/High SAST 20件中18件は明確な誤検知**（コメント内の `eval (` / `exec (` 14件、`.d.ts` 2件、UI ラベル 2件）; `pr-preview.yml` は `same-repo` 保護あり | **Low** | **いいえ:** 外部フォーク PR は遮断されており、同一リポジトリ内ブランチ展開のハードニング対象 | **LOW / MEDIUM** *（内部 CI ハードニングおよび SCA 更新）* |
| **5. `codebase-memory-mcp`** | 閾値超過 `32` 件（`SAST 17C/7H`, `SCA 8H`） | **`store.c:2864` SQLi、`c_lsp.h:54` コメント、`kotlin_lsp.c`/`py_lsp.c`/`store.c:4482` 境界付きバッファ、`xmalloc.c`、`mcp.c` はすべて誤検知**; `http_server.c` は `localhost` CORS + `Host`（403）保護あり | **Low** | **いいえ:** `http_server.c` は外部オリジンに CORS ヘッダーを返さず、DNS Rebinding も拒否する | **LOW** *（ブラウザ経由のコード漏洩チェーンは不成立）* |
| **6. `gitlab-mcp-server`** | 閾値超過 `5` 件（`0C / 4H`） | `recorder.go` と `make.go` は誤検知; `GITLAB_MCP_SKIP_TLS_VERIFY=true` はユーザーが明示設定した時のみ有効 | **Low** | **いいえ:** 連鎖する検出項目は存在しない | **LOW** *（オプトイン設定）* |
| **7. `apktool-mcp`** | 閾値超過 `16` 件（`SAST 1 Medium`, `SCA 4C / 12H`） | SAST 警告は誤検知; **`uv.lock` 内に Critical 4件、High 12件の SCA 依存関係レコードが存在** | **Low / Medium (SCA)** | **いいえ:** ファーストパーティのコード連鎖はなし；依存関係の更新が必要 | **LOW / MEDIUM (SCA)** *（SAST はクリーン、SCA レコードあり）* |
| **8. `jadx-mcp`** | 閾値超過 `32` 件（`SAST 3 Medium`, `SCA 6C / 26H`） | Critical/High SAST 脆弱性なし; **`uv.lock` 内に Critical 6件、High 26件の SCA 依存関係レコードが存在** | **Low / Medium (SCA)** | **いいえ:** ファーストパーティのコード連鎖はなし；依存関係の更新が必要 | **LOW / MEDIUM (SCA)** *（Critical/High SAST なし、SCA レコードあり）* |

---

## 第 III 部 — Sniper スキャンで発見された11件の検証済み脆弱性（コードから脆弱性への変化、日常業務シナリオ、および実行・検証コマンド）

以下では、**Sniper** 静的・動的解析エンジンを用いたセキュリティスキャンで発見され、**段階的な日常業務の重大シナリオ（`シナリオ A / B / C`）**、**エンドツーエンドのランタイム証明（`RED -> GREEN + BENIGN`）**、および **検証済み防御パッチ（`git diff`）** によって実証された **11件のセキュリティ脆弱性**（[advisories/README.ja.md](advisories/README.ja.md)）について、まず一覧表を示し、続いて **各バグがソースコード内でどのように発生し、どのように悪用可能な脆弱性へと変化するのか、3つの日常業務シナリオ、および実行・検証コマンド例** を網羅した11個の詳細技術セクション（`III.01` ～ `III.11`）を掲載します。

| # | アドバイザリ & Upstream GHSA ID | 対象プロジェクト & コンポーネント | CWE & CVSS v3.1 | 日常業務における3つの重大影響シナリオ（`シナリオ A / B / C`） | ランタイム証明（`RED -> GREEN`） |
| :-: | :--- | :--- | :--- | :--- | :--- |
| **01** | [`01-STIRLING-CAND-02-SYMLINK.md`](advisories/ja/01-STIRLING-CAND-02-SYMLINK.md)<br/>`GHSA-hpc7-xx5r-gc44` | **Stirling-Tools/Stirling-PDF** (`v3.2.2`)<br/>`FolderInputSource.java:337-377`<br/>`FolderOutputSink.java:338-345` | `CWE-59` / `CWE-61`<br/>**7.1 High** | **A)** 社内共有 SMB/NFS スキャナーフォルダに置かれた `invoice.pdf -> /configs/settings.yml` シンボリックリンクが、デフォルト `recursive=false` モードで `FolderAccessGuard` をバイパスし、管理者/OAuth/SMTP 秘密情報を出力フォルダへ流出させます。<br/>**B)** 自動 SFTP/Nextcloud 文書取込パイプラインで置かれたシンボリックリンクにより、`FolderOutputSink.archiveOriginal()` がホスト SSH 鍵や `.env` をアーカイブへコピー・移動させます。<br/>**C)** マルチテナント部門別フォルダ間で、ある部門が他部門の機密契約・給与ディレクトリへシンボリックリンクを張り、無断閲覧・削除を行います。 | `RED`: `symlink_accepted: true, protected_settings_exfiltrated: true`<br/>`GREEN`: `symlink_accepted: false, regular_file_processed: true` |
| **02** | [`02-STIRLING-CAND-01-WEASYPRINT-SSRF.md`](advisories/ja/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)<br/>`GHSA-ff6j-8xch-j8r6`<br/>*(`CVE-2026-71270` の修正漏れ)* | **Stirling-Tools/Stirling-PDF** (`v3.2.2`)<br/>`ConvertWebsiteToPDF.java:116-143` | `CWE-918`<br/>**8.6 High** | **A)** `/api/v1/convert/url/pdf` に `<link rel="stylesheet" href="http://127.0.0.1:.../secrets.css">` やクラウドメタデータ（`169.254.169.254`）を含む外部ページを渡すと、WeasyPrint が内部応答を取得して生成 PDF 内に直接埋め込みます。<br/>**B)** Java 側の `SsrfProtectionService` はトップレベル URL しか検査しないため、WeasyPrint サブプロセスが `@import url("http://10.0.0.12:9090/metrics")` で Kubernetes/Docker 内部網を探索します。<br/>**C)** HTTP `302` リダイレクトを使う `<img src="...">` / `<link>` サブリソースにより、ファイアウォール内側の管理画面を生成 PDF として外部流出させます。 | `RED`: `weasyprint_allowed_protocols: "data,http,https", internal_data_embedded_in_pdf: true`<br/>`GREEN`: `weasyprint_allowed_protocols: "data", internal_loopback_hit_count: 0` |
| **03** | [`03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md`](advisories/ja/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)<br/>`GHSA-cp36-x5hg-3gg8` | **trycua/cua** (`npm: cuabot <= 1.0.16`)<br/>`libs/cuabot/src/cuabotd.ts` | `CWE-306` / `CWE-942`<br/>**9.6 Critical** | **A)** 開発者が `npx cuabot` 起動中に任意の Web サイトを開くと、ページ内の JS が `fetch("http://localhost:7842/bash")`（`Access-Control-Allow-Origin: *`）を実行し、マウントされた `~/.cuabot/user/.claude/.credentials.json` OAuth トークンを窃取します。<br/>**B)** クロスオリジン `POST /bash` または `ws://localhost:7842/?command=...`（CSWSH）経由で、書き込み可能な `/home/community-user/.claude/settings.json` に永続的な `PreToolUse` フックを注入します。<br/>**C)** `0.0.0.0:7842` バインドのため、カフェやオフィスの同一 Wi-Fi 上の端末が認証なしで `/bash` と `/screenshot` を呼び出し、画面監視とコマンド実行を行います。 | `RED`: `http_status: 200, mounted_host_claude_credentials_exfiltrated: true`<br/>`GREEN`: `http_status: 403`<br/>`BENIGN`: `http_status: 200` |
| **04** | [`04-CUA-CAND-02-WORKER-SERVER-RCE.md`](advisories/ja/04-CUA-CAND-02-WORKER-SERVER-RCE.md)<br/>`GHSA-xm8w-gj3g-4f25` | **trycua/cua** (`pip: cua-bench-rl <= 0.1.0`)<br/>`worker_server.py:79-108, 338-360`<br/>`cua_bench/core.py:25-51` | `CWE-94` / `CWE-942`<br/>**8.8 High** | **A)** ML 研究者がローカルで RL ワーカーを実行中に閲覧した Web ページが `http://127.0.0.1:8001/reset`（`allow_origins=["*"]`）を呼び出し、`ip_filter_middleware` を通過して `spec.loader.exec_module` で任意の `<env_path>/main.py` をホスト上で実行します。<br/>**B)** Kubernetes/Docker Compose で `OSGYM_ALLOWED_IPS=""` が空の場合、`if allowed_ips:` がフェイルオープンし、`0.0.0.0:8001` が全ネットワークに認証なし RCE を公開します。<br/>**C)** クロスオリジンページや LAN 端末が `GET /screenshot` と `POST /step` を呼び出し、デスクトップ画面の盗み見とマウス・キーボード操作注入を行います。 | `RED`: `cross_origin_reset_status: 200, arbitrary_env_path_exec_module_rce: true`<br/>`GREEN`: `403 / 400, rce: false`<br/>`BENIGN`: `200` |
| **05** | [`05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md`](advisories/ja/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)<br/>`GHSA-3x8g-6h2v-8qx9` | **trycua/cua** (`cargo: cua-compat <= 0.8.0`)<br/>`daytona/objectstore.rs:320-422` | `CWE-22`<br/>**8.1 High** | **A)** 1つのサンドボックステナントがマルチパートアップロードを開始せずに `DELETE /daytona/dummy?uploadId=../objects` を送信するだけで、無条件の `tokio::fs::remove_dir_all` が発火し、組織全体の `objects/` スナップショットストアを消去します。<br/>**B)** `?uploadId=../../state` や `?uploadId=../../db` により `d.objects.root` の上位へ脱出し、`cua-spacesd` が書き込み可能なホストディレクトリを削除します。<br/>**C)** `PUT /daytona/key?partNumber=1&uploadId=../stage` により、マルチパートチャンクを `uploads/` 外の隣接ディレクトリへ書き込みます。 | `RED`: `delete_traversal_status: 204, objects_store_wiped_without_prior_upload: true`<br/>`GREEN`: `400 / 404, objects_store_preserved: true` |
| **06** | [`06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md`](advisories/ja/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)<br/>`GHSA-54v9-fxw3-36mm` | **trycua/cua** (`cargo: cua-media-codec <= 0.8.0`)<br/>`videotoolbox/mod.rs:308-420` | `CWE-125` / `CWE-190`<br/>**5.5 Medium** | **A)** macOS リモートデスクトップ配信の解像度変更時に届いた短い `FrameData::Nv12` スライスが境界未検査の `unsafe { std::ptr::copy_nonoverlapping }` で読み取られ、隣接ヒープ上の `960` バイト（セッショントークン・秘密鍵）が H.264 映像フレームにコピーされ配信されます。<br/>**B)** Safe Rust の `VtEncoder::encode` に空または短い `NV12`/`BGRA` スライスを渡すと未マップ領域を参照し、`cua-spacesd` メディアデーモンが `SIGSEGV` でクラッシュします。<br/>**C)** 不正な `y_stride` / `uv_stride` または `stride * (h - 1)` 演算によりバッファ境界を超え、マルチテナント配信プロセスでメモリ破壊を引き起こします。 | `RED`: `oob_bytes_read: 960, adjacent_heap_secret_copied_to_video_frame: true`<br/>`GREEN`: `oob_bytes_read: 0, CodecError::InvalidArgument` |
| **07** | [`07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md`](advisories/ja/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)<br/>`GHSA-hvhg-6x47-cq96` | **trycua/cua** (`pip: cua-bench <= 0.3.1`)<br/>`winarena_adapter/cli.py:262-265`<br/>`infra/vm/setup/server/main.py` | `CWE-668` / `CWE-732`<br/>**8.6 High** | **A)** 大学や企業のラボ LAN 上で動作する WinArena ワークステーションの `0.0.0.0:8006`（認証なし noVNC）および `0.0.0.0:3390`（パスワードなし RDP）に同一 LAN の第三者が接続し、Windows VM デスクトップと API キーを乗っ取ります。<br/>**B)** 侵害した VM 内から書き込み可能な `-v {setup_path}:/shared` マウントを悪用し、ホスト側の `winarena_adapter/infra/vm/setup` スクリプトを汚染します。<br/>**C)** VM 内の `0.0.0.0:5000` 制御サーバーにある未認証の `POST /execute_windows`（`exec()`）と `POST /setup/launch`（`shell=True`）を通じて任意の OS コマンドが実行されます。 | `RED`: `lan_exposed_ports: ["8006:8006", "3390:3389"], host_setup_dir_mounted_writable: true`<br/>`GREEN`: `lan_exposed_ports: [], host_setup_dir_mounted_writable: false` |
| **08** | [`08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md`](advisories/ja/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)<br/>`GHSA-qwv8-hh9r-cqrf` | **openziti/ziti** (`github.com/openziti/ziti/v2`)<br/>`ziti/util/certs.go:91-103, 199-208` | `CWE-295`<br/>**7.4 High** | **A)** DevOps エンジニアが Wi-Fi/VPN 経由で `ziti edge login` を実行した際、`AreCertsTrusted` -> `InsecureClient` 内の無条件 `InsecureSkipVerify: true` により偽 MITM 証明書が *"Verified that server supplied certificates are trusted"* と承認され、管理者パスワードが攻撃者へ送信されます。<br/>**B)** 自動 CI/CD や Kubernetes ブートストラップ処理で `ziti edge login` が偽の Edge Controller を信頼し、ID とルーターポリシーを攻撃者へ登録します。<br/>**C)** 期限切れ・失効済み・別 CA 署名のコントローラ証明書が警告なしで信頼され、Zero-Trust PKI チェーンが崩壊します。 | `RED`: `rogue_mitm_cert_accepted_as_trusted: true, admin_credentials_sent_to_mitm: true`<br/>`GREEN`: `x509.UnknownAuthorityError` |
| **09** | [`09-N8N-CAND-01-WEBHOOK-REDOS.md`](advisories/ja/09-N8N-CAND-01-WEBHOOK-REDOS.md)<br/>`n8n-workflow <= 2.45.0` | **n8n-io/n8n** (`npm: n8n-workflow <= 2.45.0`)<br/>`string-extensions.ts:59, 94, 326, 375, 383` | `CWE-1333`<br/>**5.3 Medium** | **A)** 公開問い合わせフォームの n8n Webhook（`{{$json.body.contact.isEmail()}}`）へ 20 KB の `"a.a.a...a@!"` リクエストを1つ送ると Node.js メインイベントループが約 832 ms 停止し、10並列リクエストで全 Stripe/Slack Webhook と UI が凍結します。<br/>**B)** サポートメールやチャットを解析する `{{$json.text.extractEmail()}}` フローがドット連続文字列を含む1通のメッセージでハングし、コンテナのヘルスチェック再起動ループに陥ります。<br/>**C)** CRM データ拡充ワークフローで `{{$json.url.extractDomain()}}`（`DOMAIN_EXTRACT_REGEXP`）が評価されると、長いドット付き URL 入力でシングルスレッド V8 ランタイムが枯渇します。 | `RED`: `regex_stall_ms: 165.035 (831.78ms @ 20KB), concurrent_webhook_starved: true`<br/>`GREEN`: `regex_stall_ms: 0.017 (0.0029ms)` |
| **10** | [`10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md`](advisories/ja/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)<br/>`GHSA-cc9f-m5vr-pm75` | **gotify/server** (`v2.9.1`)<br/>`router/router.go:52-73, 93-102` | `CWE-601`<br/>**4.7 Medium** | **A)** `SSL.RedirectToHTTPS=true` 有効時、偽装した `Host: attacker-gotify.example.com` ヘッダー付きリクエストが `HTTP/1.1 308 Permanent Redirect` で攻撃者ドメインへリダイレクトされ、ブラウザキャッシュ汚染と URL 内の `?token=` 漏洩を引き起こします。<br/>**B)** HTTP エンドポイントへ `?token=<app-token>` 付きで通知を送る監視スクリプト（`curl -L`、Python `requests`、Uptime Kuma）が `308` リダイレクトを追跡し、アプリトークンを攻撃者サーバーへ引き渡します。<br/>**C)** `Host` ヘッダーをそのまま転送するリバースプロキシや共有キャッシュ配下でキャッシュポイズニングが発生し、全クライアントが偽ログイン画面へ誘導されます。 | `RED`: `status_code: 308, redirected_to_untrusted_host: true`<br/>`GREEN`: `redirected_to_untrusted_host: false, bound_to_configured_ssl_host: true` |
| **11** | [`11-XROAD-CAND-01-RUNNER-INJECTION.md`](advisories/ja/11-XROAD-CAND-01-RUNNER-INJECTION.md)<br/>`GHSA-4fcw-7xqx-fjv5` | **nordic-institute/X-Road** (`38cd99ec0ebb`)<br/>`.github/workflows/build.yaml`<br/>`_build-and-package.yml:84-91` | `CWE-78`<br/>**8.5 High** | **A)** `feat";<cmd>;#` 形式の PR ブランチ名が、コードレビューや `actions/checkout` 実行前に永続セルフホストランナー `xrd-runner-8c` 上の `_build-and-package.yml` の bash スクリプト内で任意コマンドを実行します。<br/>**B)** `build.yaml` が `permissions: contents: write, packages: write` と `secrets: inherit` 付きで `_build-and-package.yml` を呼ぶため、注入されたコマンドが GHCR パッケージ書き込み・リポジトリ書き込み権限付き `GITHUB_TOKEN` を掌握します。<br/>**C)** `xrd-runner-8c` は一時 VM ではなく永続セルフホストサーバーであるため、後続の公式 X-Road リリースビルドを汚染する永続バックグラウンドプロセスや Gradle/Docker キャッシュ改ざんが可能です。 | `RED`: `direct_yaml_interpolation: true, arbitrary_command_executed_on_self_hosted_runner: true`<br/>`GREEN`: `env_var_parameterized: true, arbitrary_command_executed_on_self_hosted_runner: false` |

---

### III.01 — Stirling-PDF (`v3.2.2`) — 監視フォルダ（`Watched Folder`）のシンボリックリンク（`Symlink`）脱出による `FolderAccessGuard` バイパス（`GHSA-hpc7-xx5r-gc44`、`CWE-59`/`CWE-61`、CVSS `7.1 High`）

#### 1. メタデータ & 開示ステータス
* **対象リポジトリ & パッケージ:** `Stirling-Tools/Stirling-PDF`（`Maven: stirling.software:stirling-pdf`）
* **影響を受けるバージョン & コンポーネント:** `<= v3.2.2`（`commit 684608d143779bf3a8ffc67639f077a1202c62ff`）— `FolderInputSource.java`（`listFiles`、`337-377` 行）、`ProcessingFolderController.java`（`374-380` 行）、`FolderOutputSink.java`（`archiveOriginal`、`338-345` 行）
* **脆弱性分類 & スコア:** `CWE-59`（ファイルアクセス前の不適切なリンク解決）/ `CWE-61`（UNIX シンボリックリンクの追跡）— **CVSS v3.1: `7.1 High`**（`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`）
* **GitHub GHSA リンク:** `GHSA-hpc7-xx5r-gc44`（`https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/GHSA-hpc7-xx5r-gc44`）
* **Sniper 個別アドバイザリ:** [`docs/advisories/ja/01-STIRLING-CAND-02-SYMLINK.md`](advisories/ja/01-STIRLING-CAND-02-SYMLINK.md)

#### 2. コード内でどのように発生し脆弱性へ変化するのか（ステップバイステップの平易な解説）
Stirling-PDF の **自動処理監視フォルダ（Watched Folder）** 機能は、社内ネットワークの共有フォルダ（例: `/mnt/scanner-incoming`）に置かれた文書を自動的に読み取って処理し、出力フォルダ（`/mnt/scanner-processed`）へ保存するために使われます。開発者は、この機能がサーバー自身の機密設定ファイル（`/configs/settings.yml` など）を読み取らないよう、`FolderAccessGuard.isProtected(path)` というセキュリティガードを実装しました。

ところが、Java 標準のファイル判定メソッド `Files.isRegularFile(path)` には重大な落とし穴があります。**第2引数に `LinkOption.NOFOLLOW_LINKS` を指定しない限り、シンボリックリンク（ショートカット）を自動的に追跡し、リンク先が通常ファイルであれば `true` を返してしまう** のです。一方で `FolderAccessGuard.isProtected(path)` は実体パス（`toRealPath()`）ではなく見かけ上の字句パス（`path.toAbsolutePath().normalize()`）しかチェックしません。

`FolderInputSource.java:337-350` にある実際の脆弱なコードは以下の通りです。
```java
private static List<Path> listFiles(
        Path inputDir, boolean recursive, FolderAccessGuard accessGuard) throws IOException {
    List<Path> files = new ArrayList<>();
    if (!recursive) { // デフォルトモード: recursive = false
        try (Stream<Path> entries = Files.list(inputDir)) {
            entries.filter(Files::isRegularFile) // バグ 1: LinkOption.NOFOLLOW_LINKS がないためシンボリックリンクを追跡する！
                    .filter(file -> !hidden(file)) // バグ 2: accessGuard.isProtected(file) すらここで呼ばれていない！
                    .forEach(files::add);
        }
        return files;
    }
```
さらに `ProcessingFolderController.java:374` が後続で `accessGuard.isProtected(path)` を呼んでも、見かけ上の名前は `/mnt/scanner-incoming/invoice.pdf` であるためガードを素通りします。そして最後に `FolderOutputSink.java:342` の `Files.move(originalFile, archiveTarget)` または `Files.copy` がリンク先の実体ファイルを読み取り・移動させてしまいます。

#### 3. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — オフィス複合機・スキャナー共有フォルダ（SMB/NFS）経由での管理者・OAuth 秘密情報の窃取:**
  1. 企業内で Stirling-PDF が `/mnt/office-scanner/incoming` フォルダを監視し、処理済み文書を `/mnt/office-scanner/processed` に出力している。
  2. 共有フォルダへの書き込み権限を持つ一般社員または侵害された端末が、`ln -s /configs/settings.yml /mnt/office-scanner/incoming/invoice_2026.pdf` というシンボリックリンクを作成する。
  3. Stirling-PDF のポーリング処理がこのリンクを通常ファイルと誤認して処理・アーカイブし、`/configs/settings.yml` 内の初期管理者パスワード、OAuth2 クライアントシークレット、SMTP 認証情報、API キーが共有出力フォルダへそのままコピーされ、全社員から閲覧可能になる。
* **シナリオ B — SFTP / Nextcloud 自動取込パイプラインにおける `archiveOriginal()` での設定破壊とサービス停止（DoS）:**
  1. 外部取引先が請求書をアップロードする SFTP ディレクトリが Stirling-PDF の監視フォルダに接続されており、処理後に元ファイルをアーカイブする設定になっている。
  2. アップロードされたアーカイブまたは SFTP セッション経由で、アプリケーションのデータファイルや `.env` / 設定ファイルへのシンボリックリンクが配置される。
  3. `FolderOutputSink.archiveOriginal()` が元ファイルを移動（`Files.move`）または上書きし、Stirling-PDF サーバーの設定やデータベースが破損して業務が停止する。
* **シナリオ C — マルチテナント部門別フォルダ間での機密人事・財務文書の横断窃取:**
  1. 同一サーバー上で複数部門（人事部 `/watched/hr`、営業部 `/watched/sales`）の監視フォルダが運用されている。
  2. 営業部フォルダへのアクセス権を持つ攻撃者が、`ln -s /watched/hr/payroll_2026.pdf /watched/sales/scan01.pdf` を配置する。
  3. `staysWithinCanonicalRoot` による正規化ルート境界チェックがないため、営業部の出力フォルダに人事部の給与明細 PDF が複製される。

#### 4. 実行・再現・検証コマンド例
```bash
# 1. Sniper SAST エンジンによる Stirling-PDF 監視フォルダの監査
python3 scripts/sniper-project-audit /path/to/Stirling-PDF --format json --output stirling-audit.json

# 2. ローカル隔離テスト環境での RED -> GREEN ランタイム証明の実行
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand02 -v

# 3. ランタイム証明 JSON 出力の確認
python3 -c 'import json; d=json.load(open("docs/advisories/other-repos-and-cua-real-world-impact-e2e-20261029.json")); print(json.dumps(d["results"]["STIRLING-CAND-02"], indent=2))'
```
**実測ランタイム証明（`RED -> GREEN`）:**
```json
{
  "RED": {
    "recursive": false,
    "symlink_accepted": true,
    "protected_settings_exfiltrated": true,
    "exfiltrated_secret_snippet": "admin_api_key: sk-live-stirling-9988776655"
  },
  "GREEN": {
    "recursive": false,
    "symlink_accepted": false,
    "protected_settings_exfiltrated": false,
    "regular_file_processed": true
  }
}
```

---

### III.02 — Stirling-PDF (`v3.2.2`) — `ConvertWebsiteToPDF.java` における `CVE-2026-71270` の修正漏れと WeasyPrint サブリソース SSRF（`GHSA-ff6j-8xch-j8r6`、`CWE-918`、CVSS `8.6 High`）

#### 1. メタデータ & 開示ステータス
* **対象リポジトリ & パッケージ:** `Stirling-Tools/Stirling-PDF`（`Maven: stirling.software:stirling-pdf`）
* **影響を受けるバージョン & コンポーネント:** `<= v3.2.2`（`commit 684608d143779bf3a8ffc67639f077a1202c62ff`）— `ConvertWebsiteToPDF.java`（`urlToPdf`、`116-143` 行 — `POST /api/v1/convert/url/pdf`）
* **脆弱性分類 & スコア:** `CWE-918`（サーバーサイド・リクエスト・フォージェリ / SSRF）— **CVSS v3.1: `8.6 High`**（`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`）
* **GitHub GHSA リンク:** `GHSA-ff6j-8xch-j8r6`（`https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/GHSA-ff6j-8xch-j8r6` — `CVE-2026-71270` / `GHSA-j5rg-wh78-9f2q` の修正漏れ）
* **Sniper 個別アドバイザリ:** [`docs/advisories/ja/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md`](advisories/ja/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)

#### 2. コード内でどのように発生し脆弱性へ変化するのか（ステップバイステップの平易な解説）
Stirling-PDF には以前に **WeasyPrint が HTML 内の外部リンク（`<link>`、`<img>`、`@import`）を自動的に取得してしまうことで内部ネットワークの情報を盗み出せる SSRF 脆弱性（`CVE-2026-71270` / `GHSA-j5rg-wh78-9f2q`）** が報告されました。開発チームは HTML ファイルアップロード用の `FileToPdf.java` にサニタイザと `--allowed-protocols data`（外部 HTTP 通信の禁止）を追加して修正しました。

しかし、隣のファイルである URL から PDF への変換エンドポイント `ConvertWebsiteToPDF.java`（`POST /api/v1/convert/url/pdf`）には同じ修正が適用されませんでした。
```java
// app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java:116-143
String htmlContent = fetchRemoteHtml(URL); // トップレベル URL のみ SsrfProtectionService で検査される
// バグ 1: customHtmlSanitizer.sanitize(htmlContent) が呼ばれていない！
Files.writeString(tempHtmlInput, htmlContent, StandardCharsets.UTF_8);

List<String> command = new ArrayList<>();
command.add(runtimePathConfig.getWeasyPrintPath());
command.add(tempHtmlInput.toString());
command.add("--base-url");
command.add(URL);
command.add("--pdf-forms");
command.add("--allowed-protocols");
command.add("data,http,https"); // バグ 2: WeasyPrint サブプロセスに任意の http/https 通信を許可している！
```
この結果、攻撃者が用意した公開 Web ページ（`https://example-attacker.com/page.html`）自体は最初のチェックを通過しますが、その HTML の中に `<link rel="stylesheet" href="http://127.0.0.1:8080/internal-secrets.css">` や `<img src="http://169.254.169.254/...">` を書いておくと、**Java の SSRF 防御を一切通らないネイティブの WeasyPrint プロセスが直接内部サーバーへアクセスし、その結果を生成された PDF の中に書き込んで攻撃者へ返してしまう** のです。

#### 3. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — クラウド環境（AWS/GCP/Azure）で稼働する PDF 変換サービスからの IAM 認証情報・メタデータ窃取:**
  1. 社内ポータルや SaaS バックエンドが「Web ページを PDF 保存」機能として Stirling-PDF の `/api/v1/convert/url/pdf` を提供している。
  2. 攻撃者が自前の公開 URL を入力する。そのページの HTML には CSS `content` プロパティや `<object>` / `<link>` でクラウドメタデータ API またはローカル設定エンドポイントへの参照が含まれている。
  3. WeasyPrint が `--allowed-protocols data,http,https` で内部エンドポイントを取得し、返却された PDF ファイルのページ内に内部シークレットが印字されてダウンロードされる。
* **シナリオ B — Kubernetes / Docker 内部ネットワーク上の未認証マイクロサービス（`127.0.0.1` / `10.x.x.x`）の探索とデータ抽出:**
  1. Stirling-PDF コンテナと同一 Pod または同一内部サブネット上で、Spring Boot Actuator（`http://127.0.0.1:8080/actuator/env`）や Prometheus（`http://10.0.0.12:9090/metrics`）が稼働している。
  2. Java の `SsrfProtectionService` は直接 `http://127.0.0.1` を入力すると拒否するが、外部 URL 内の `@import url("http://127.0.0.1:8080/...")` は WeasyPrint が直接取得するため、内部 API レスポンスが PDF 経由で流出する。
* **シナリオ C — HTTP `302` リダイレクトを利用した内部管理画面のレンダリングとファイアウォール回避:**
  1. 攻撃者の公開サーバー上の画像/スタイルシート URL が、初回アクセス時に HTTP `302 Found` で社内イントラネットの管理画面（`http://intranet-admin.local/`）へリダイレクトする。
  2. WeasyPrint の HTTP クライアントがリダイレクトを追跡し、社内管理画面の内容を PDF 化して攻撃者に返す。

#### 4. 実行・再現・検証コマンド例
```bash
# 1. ConvertWebsiteToPDF.java 内の --allowed-protocols 設定をソースコードで確認
grep -n -C 12 "allowed-protocols" /path/to/Stirling-PDF/app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java

# 2. ローカルループバック（127.0.0.1）を用いた隔離 E2E 検証テストの実行
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand01 -v
```
**実測ランタイム証明（`RED -> GREEN`）:**
```json
{
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
```

---

### III.03 — TryCua `cuabot` (`<= 1.0.16`) — 未認証 `0.0.0.0:7842` デーモン + `POST /bash` のワイルドカード CORS + オリジン未検証 WebSocket + 書き込み可能なホスト `.claude` マウント（`GHSA-cp36-x5hg-3gg8`、`CWE-306`/`CWE-942`、CVSS `9.6 Critical`）

#### 1. メタデータ & 開示ステータス
* **対象リポジトリ & パッケージ:** `trycua/cua`（`npm: cuabot <= 1.0.16`）
* **影響を受けるバージョン & コンポーネント:** `>= 1.0.1, <= 1.0.16`（`commit e754cfec69c41400eb2aabde716c27d15607b2f0`）— `libs/cuabot/src/cuabotd.ts`（`34-36, 259-260, 741-743, 969-1002, 1018-1063, 1120` 行）
* **脆弱性分類 & スコア:** `CWE-306`（重要機能における認証の欠如）/ `CWE-942`（過度なクロスドメイン許可リスト）— **CVSS v3.1: `9.6 Critical`**（`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`）
* **GitHub GHSA リンク:** `GHSA-cp36-x5hg-3gg8`（`https://github.com/trycua/cua/security/advisories/GHSA-cp36-x5hg-3gg8`）
* **Sniper 個別アドバイザリ:** [`docs/advisories/ja/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md`](advisories/ja/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)

#### 2. コード内でどのように発生し脆弱性へ変化するのか（ステップバイステップの平易な解説）
`cuabot` は開発者のマシン上で動作する AI エージェント補助ツールです。そのバックグラウンドデーモンである `cuabotd.ts` には、4つの致命的な設計ミスが同時に重なっています。
1. **全ネットワークインターフェースでの未認証公開:** `server.listen(port, ...)`（`1120` 行）にホスト指定がないため、デフォルトの `0.0.0.0:7842` で待受け、パスワードやトークン認証が一切ありません。
2. **すべての Web サイトに API 呼び出しと応答読み取りを許可するワイルドカード CORS:**
   ```typescript
   // libs/cuabot/src/cuabotd.ts:967-974
   res.setHeader('Access-Control-Allow-Origin', '*');
   res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
   res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
   if (req.method === 'OPTIONS') {
     res.writeHead(200);
     res.end();
     return;
   }
   ```
3. **`POST /bash` とオリジン未検証の WebSocket PTY による任意コマンド実行:** `/bash` エンドポイントは送られた JSON の `command` をそのままシェル実行して標準出力を返し、`WebSocketServer`（`741` 行）は `Origin` ヘッダーを確認せずに対話型ターミナルを起動します。
4. **ホストの `.claude` 認証ディレクトリの読み書きマウント:** コンテナ起動時にホスト側の `~/.cuabot/user/.claude` を `/home/community-user/.claude` として読み書き可能でバインドマウントしています（`259-260` 行）。

これにより、開発者が `cuabot` を起動したままブラウザで任意の Web ページ（広告やブログ記事など）を開いた瞬間、そのページ内の JavaScript が `fetch("http://localhost:7842/bash", ...)` を叩いて任意のコマンドを実行し、Claude Code の OAuth トークンを盗み出したり設定を書き換えたりできます。

#### 3. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — ブラウザで一般の Web ページを開いた瞬間に発生するドライブバイ RCE と Claude OAuth 認証情報の窃取:**
  1. 開発者がローカルで `npx cuabot` を起動して作業しながら、ブラウザで技術ブログやドキュメントサイトを閲覧する。
  2. ページ内のスクリプトが `fetch("http://localhost:7842/bash", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({command: "cat /home/community-user/.claude/.credentials.json"})})` を送信する。
  3. `Access-Control-Allow-Origin: *` のためブラウザはプリフライト（`OPTIONS`）を通過させ、レスポンス本文（Claude OAuth アクセストークン・リフレッシュトークン）を攻撃者のスクリプトへそのまま渡す。
* **シナリオ B — 書き込み可能な `/home/community-user/.claude/settings.json` への永続的 `PreToolUse` フック注入によるホスト OS 侵害:**
  1. ドライブバイ要求またはクロスサイト WebSocket ハイジャック（`new WebSocket("ws://localhost:7842/?command=bash")`）によって、マウントされた `/home/community-user/.claude/settings.json` が書き換えられる。
  2. 攻撃者が Claude Code の `hooks.PreToolUse` に悪意あるシェルコマンドを登録する。
  3. 以降、開発者がホスト OS 上で Claude Code を使うたびに、ホスト OS 権限でバックドアコマンドが自動実行される。
* **シナリオ C — カフェ・コワーキングスペース・社内 Wi-Fi（`0.0.0.0:7842`）からの直接侵入と画面盗撮:**
  1. 開発者がカフェやオフィス LAN に接続している間、`cuabotd` は `0.0.0.0:7842` で待機している。
  2. 同一 Wi-Fi 上の攻撃者が `curl http://<開発者IP>:7842/screenshot` で開発者の作業画面をリアルタイムに盗撮し、`POST /bash` でワークステーションを完全に制御する。

#### 4. 実行・再現・検証コマンド例
```bash
# 1. ローカル隔離ハーネスにおけるクロスオリジン（Origin: https://evil.example）再現コマンド例
curl -i -X POST http://127.0.0.1:7842/bash \
  -H "Origin: https://evil.example" \
  -H "Content-Type: application/json" \
  -d '{"command":"id && cat /home/community-user/.claude/.credentials.json"}'

# 2. Sniper 自動検証テスト（RED -> GREEN + BENIGN）の実行
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand01 -v
```
**実測ランタイム証明（`RED -> GREEN + BENIGN`）:**
```json
{
  "RED": {
    "http_status": 200,
    "access_control_allow_origin": "*",
    "driveby_bash_executed": true,
    "mounted_host_claude_credentials_exfiltrated": true
  },
  "GREEN": {
    "http_status": 403,
    "driveby_bash_executed": false,
    "mounted_host_claude_credentials_exfiltrated": false,
    "error": "Cross-origin browser requests forbidden"
  },
  "BENIGN": {
    "http_status": 200,
    "stdout": "authorized_cli_ok"
  }
}
```

---

### III.04 — TryCua `cua-bench-rl` (`<= 0.1.0`) — `0.0.0.0:8001` ワーカーサーバーのワイルドカード CORS + フェイルオープン `OSGYM_ALLOWED_IPS` + 未認証 `POST /reset` による任意モジュール実行（`GHSA-xm8w-gj3g-4f25`、`CWE-94`/`CWE-942`、CVSS `8.8 High`）

#### 1. メタデータ & 開示ステータス
* **対象リポジトリ & パッケージ:** `trycua/cua`（`pip: cua-bench-rl <= 0.1.0` および `cua-bench <= 0.3.1`）
* **影響を受けるバージョン & コンポーネント:** `<= 0.1.0`（`commit e754cfec69c41400eb2aabde716c27d15607b2f0`）— `libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py`（`79-108, 338-360, 499` 行）および `libs/cua-bench/cua_bench/core.py`（`make`、`25-51` 行）
* **脆弱性分類 & スコア:** `CWE-94`（コード生成の不適切な制御）/ `CWE-942`（過度なクロスドメイン許可リスト）— **CVSS v3.1: `8.8 High`**（`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`）
* **GitHub GHSA リンク:** `GHSA-xm8w-gj3g-4f25`（`https://github.com/trycua/cua/security/advisories/GHSA-xm8w-gj3g-4f25`）
* **Sniper 個別アドバイザリ:** [`docs/advisories/ja/04-CUA-CAND-02-WORKER-SERVER-RCE.md`](advisories/ja/04-CUA-CAND-02-WORKER-SERVER-RCE.md)

#### 2. コード内でどのように発生し脆弱性へ変化するのか（ステップバイステップの平易な解説）
強化学習（RL）ワーカーサーバー `worker_server.py` は、クライアントから送られた環境パス（`env_path`）を読み込んでタスクを初期化する `POST /reset` API を提供しています。開発者はアクセス制限のために `ip_filter_middleware` を書きましたが、以下の3つのバグが重なっています。
```python
# libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py:79-105
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # バグ 1: 任意の外部 Web サイトからのブラウザ Fetch を許可！
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def ip_filter_middleware(request: Request, call_next):
    allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
    client_ip = request.client.host if request.client else None
    # バグ 2: ブラウザから http://127.0.0.1:8001 へ送られたリクエストは client_ip == "127.0.0.1" になる！
    # バグ 3: OSGYM_ALLOWED_IPS="" (空文字) の場合、allowed_ips が [] となり `if allowed_ips:` が False に評価され全 IP を素通りさせる！
    if allowed_ips and client_ip not in allowed_ips:
        return JSONResponse(status_code=403, content={"detail": f"Access denied for IP: {client_ip}"})
    return await call_next(request)
```
そして `POST /reset` が呼ばれると、`cua_bench/core.py:38-51` の `make(req.env_path)` が渡されたディレクトリ内の `main.py` を探して **そのまま Python プロセス内で動的ロード・実行（`spec.loader.exec_module(module)`）** します。つまり、`env_path` に任意のフォルダを指定するだけで、その中の `main.py` が無条件で実行されます。

#### 3. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — ローカルで RL ワーカーを起動中の研究者が Web ページを開いた際のドライブバイ RCE:**
  1. AI 研究者がワークステーション上で `worker_server.py` を起動したままブラウザで論文サイトやフォーラムを開く。
  2. ブラウザが自動的にファイルを `~/Downloads` へ保存した上で、ページ内の JS が `fetch("http://127.0.0.1:8001/reset", {method: "POST", body: JSON.stringify({env_path: "/tmp/untrusted_env", task_index: 0})})` を呼び出す。
  3. リクエスト元 IP は `127.0.0.1` であるため `ip_filter_middleware` を通過し、`spec.loader.exec_module` によってホスト上で任意の Python コードが実行され、GPU サーバーの SSH 鍵や HuggingFace / WandB トークンが窃取される。
* **シナリオ B — Docker Compose / Kubernetes 環境で `OSGYM_ALLOWED_IPS=""` が空設定されたことによる全ネットワーク RCE:**
  1. デプロイテンプレートや Helm チャートで `OSGYM_ALLOWED_IPS: ""` が未設定（空文字）のまま渡される。
  2. Python の `if allowed_ips:` が `False` となって IP フィルタが完全に無効化（フェイルオープン）され、クラスタ内や LAN 上の任意のホストから `http://<worker-ip>:8001/reset` でリモートコード実行が可能になる。
* **シナリオ C — 未認証の `/screenshot` と `/step` によるデスクトップ画面監視と操作注入:**
  1. 攻撃者がクロスオリジンリクエストまたは LAN 経由で `GET /screenshot` をポーリングしてデスクトップ画面を監視し、`POST /step` でキーボード・マウスイベントを注入して画面上の別アプリケーションを操作する。

#### 4. 実行・再現・検証コマンド例
```bash
# 1. ローカル隔離環境でのクロスオリジン POST /reset 再現コマンド例
curl -i -X POST http://127.0.0.1:8001/reset \
  -H "Origin: https://evil.example" \
  -H "Content-Type: application/json" \
  -d '{"env_path":"/tmp/poc_env","task_index":0}'

# 2. Sniper E2E 検証テスト（RED -> GREEN + BENIGN）の実行
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand02 -v
```
**実測ランタイム証明（`RED -> GREEN + BENIGN`）:**
```json
{
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
```

---

### III.05 — TryCua `cua-compat` (`<= 0.8.0`) — Daytona S3 マルチパート `uploadId` パストラバーサルと無条件の `tokio::fs::remove_dir_all` によるディレクトリ削除（`GHSA-3x8g-6h2v-8qx9`、`CWE-22`、CVSS `8.1 High`）

#### 1. メタデータ & 開示ステータス
* **対象リポジトリ & パッケージ:** `trycua/cua`（`Cargo: cua-compat <= 0.8.0` / `cua-spacesd <= 0.8.0`）
* **影響を受けるバージョン & コンポーネント:** `<= 0.8.0`（`commit e754cfec69c41400eb2aabde716c27d15607b2f0`）— `libs/cua/crates/cua-compat/src/daytona/objectstore.rs`（`handle`、`320-325, 360-422` 行）
* **脆弱性分類 & スコア:** `CWE-22`（パストラバーサル）— **CVSS v3.1: `8.1 High`**（`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`）
* **GitHub GHSA リンク:** `GHSA-3x8g-6h2v-8qx9`（`https://github.com/trycua/cua/security/advisories/GHSA-3x8g-6h2v-8qx9`）
* **Sniper 個別アドバイザリ:** [`docs/advisories/ja/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md`](advisories/ja/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)

#### 2. コード内でどのように発生し脆弱性へ変化するのか（ステップバイステップの平易な解説）
Daytona 互換の S3 オブジェクトストア実装（`objectstore.rs`）では、URL パスに含まれるオブジェクトキー（`key`）に対しては `object_path(&key)` 関数で `..` が含まれないよう丁寧にチェックしています。ところが、URL クエリ文字列から取り出される **`?uploadId=` パラメータには一切のバリデーションがありません**。

さらに深刻なことに、マルチパートアップロードを中断する `HTTP DELETE` ハンドラ（`415-421` 行）は次のようになっています。
```rust
// libs/cua/crates/cua-compat/src/daytona/objectstore.rs:415-421
(Method::DELETE, Some(id), _, _) => {
    d.objects.uploads.lock().await.remove(&id); // バグ 1: その uploadId が実在したかどうか（戻り値 Option）を無視している！
    // バグ 2: 未検証の `id` をそのままパス結合し、無条件で再帰削除 remove_dir_all を実行！
    let _ = tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await;
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Full::new(Bytes::new()))
        .unwrap()
}
```
これにより、事前にアップロードを開始する必要すらなく、たった1回の `DELETE /daytona/anykey?uploadId=../objects` リクエストを送るだけで、`root.join("uploads").join("../objects")` すなわち **オブジェクトストア全体の保存ディレクトリ（`<root>/objects`）が再帰的に完全削除** されます。

#### 3. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — マルチテナント AI サンドボックス基盤における全テナントのイメージ・スナップショット一括消去:**
  1. 複数のチームや顧客テナントが共有する `cua-spacesd` サーバー上で、1つの低権限サンドボックステナントが `DELETE /daytona/x?uploadId=../objects` を送信する。
  2. `tokio::fs::remove_dir_all` が `<root>/objects/daytona` を即座に削除し、全テナントの保存済み VM/コンテナスナップショットが消失して全サービスが停止する。
* **シナリオ B — 深いパストラバーサル（`?uploadId=../../...`）によるホスト側アプリケーションデータ・DB の破壊:**
  1. 攻撃者が `?uploadId=../../state` や `?uploadId=../../../home/community-user/.cua` を指定して `DELETE` リクエストを送る。
  2. `d.objects.root` の親ディレクトリへ脱出し、`cua-spacesd` プロセス権限で書き込み可能なホスト側のデータベースや設定ディレクトリが再帰削除される。
* **シナリオ C — `PUT` マルチパートチャンク書き込み（`?partNumber=1&uploadId=../stage`）による隣接ディレクトリの汚染:**
  1. `Method::PUT` ハンドラ（`360-383` 行）でも同様に `root.join("uploads").join(&id)` が使われているため、攻撃者が `?partNumber=1&uploadId=../stage` を指定して任意のバイナリチャンクをアップロードする。
  2. 本来の `uploads/` ではなく隣接する `stage/` や `objects/` 配下に不正なファイルが作成・上書きされる。

#### 4. 実行・再現・検証コマンド例
```bash
# 1. ローカル隔離テスト環境での DELETE ?uploadId=../objects 再現コマンド例
curl -i -X DELETE "http://127.0.0.1:9000/daytona/dummy-key?uploadId=../objects" \
  -H "Authorization: Bearer <push-token>"

# 2. Sniper E2E 検証テスト（RED -> GREEN + BENIGN）の実行
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand03 -v
```
**実測ランタイム証明（`RED -> GREEN + BENIGN`）:**
```json
{
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
```

---

### III.06 — TryCua `cua-media-codec` (`<= 0.8.0`) — Safe Rust `VtEncoder::encode` におけるスライス長未検証の `unsafe { copy_nonoverlapping }` によるヒープ境界外読み取り（`GHSA-54v9-fxw3-36mm`、`CWE-125`/`CWE-190`、CVSS `5.5 Medium`）

#### 1. メタデータ & 開示ステータス
* **対象リポジトリ & パッケージ:** `trycua/cua`（`Cargo: cua-media-codec <= 0.8.0`）
* **影響を受けるバージョン & コンポーネント:** `<= 0.8.0`（`commit e754cfec69c41400eb2aabde716c27d15607b2f0`）— `libs/cua/crates/cua-media-codec/src/videotoolbox/mod.rs`（`VtEncoder::encode` -> `pixel_buffer_for`、`308-420` 行）
* **脆弱性分類 & スコア:** `CWE-125`（境界外読み取り / Out-of-Bounds Read）/ `CWE-190`（整数オーバーフローまたはラップアラウンド）— **CVSS v3.1: `5.5 Medium`**（`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H`）
* **GitHub GHSA リンク:** `GHSA-54v9-fxw3-36mm`（`https://github.com/trycua/cua/security/advisories/GHSA-54v9-fxw3-36mm`）
* **Sniper 個別アドバイザリ:** [`docs/advisories/ja/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md`](advisories/ja/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)

#### 2. コード内でどのように発生し脆弱性へ変化するのか（ステップバイステップの平易な解説）
Rust では `unsafe` キーワードを付けない公開関数（`pub fn encode(&mut self, frame: &VideoFrame)`）は、どのような入力が渡されても未定義動作（メモリ破壊や境界外アクセス）を起こさないことが言語の安全性契約（Soundness Contract）として求められます。

ところが macOS VideoToolbox ハードウェアエンコーダ実装の `pixel_buffer_for`（`308-420` 行）は、渡された画像フレーム `frame.data` の実際のスライス長（`y.len()`、`uv.len()`、`data.len()`）を確認しないまま、生ポインタ演算と `unsafe { std::ptr::copy_nonoverlapping }` を実行しています。
```rust
// libs/cua/crates/cua-media-codec/src/videotoolbox/mod.rs:344-367
unsafe {
    let y_dst = CVPixelBufferGetBaseAddressOfPlane(pb, 0) as *mut u8;
    let y_dst_stride = CVPixelBufferGetBytesPerRowOfPlane(pb, 0);
    for row in 0..h {
        // バグ: y.len() が row * (*y_stride as usize) + w 以上であるか全くチェックしていない！
        std::ptr::copy_nonoverlapping(
            y.as_ptr().add(row * (*y_stride as usize)),
            y_dst.add(row * y_dst_stride),
            w,
        );
    }
```
もし解像度切り替えのタイミングや異常なフレーム入力によって、本来の `w * h` より短い `y` / `uv` バッファが渡されると、`copy_nonoverlapping` はバッファの終端を飛び越えて **隣接するヒープメモリ領域（セッショントークン、API キー、他テナントのメモリなど）を読み取り、そのまま H.264 映像ピクセルとしてエンコードしてリモート視聴者へ送信** してしまいます。

#### 3. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — macOS リモートデスクトップ配信のウィンドウ・解像度変更時におけるヒープメモリ（`960` バイト）の映像ストリーム漏洩:**
  1. リモートエージェントセッション中にキャプチャ解像度が変更され、古いサイズのまま切り詰められた `FrameData::Nv12` バッファが `VtEncoder::encode` に渡される。
  2. `pixel_buffer_for` がスライス境界を超えて隣接ヒープ領域の `960` バイトを `CVPixelBuffer` にコピーし、クライアントが受信する映像フレーム内にプロセス内の機密ヒープデータが混入する。
* **シナリオ B — 不正またはゼロ長の `VideoFrame` 入力による `cua-spacesd` メディアデーモンの即時クラッシュ（`SIGSEGV`）:**
  1. IPC またはネットワーク経由で空の `y: &[]` を持つ `VideoFrame`（例: `w=1920, h=1080`）が送られる。
  2. Safe Rust 関数であるにもかかわらず未マップのメモリページを読みに行き、`cua-spacesd` プロセス全体がセグメンテーション違反（`SIGSEGV`）で異常終了し、稼働中の全エージェントセッションが切断される。
* **シナリオ C — マルチセッション macOS ホストにおける不整合な `stride` 値での他セッションデータ混入:**
  1. `y_stride` または `Bgra` の `stride` が `w` より小さい、あるいは極端に大きい値で渡された際、行ごとのポインタ加算がアロケーション境界を大きく飛び越え、同一プロセス内の別セッションのメモリを読み取る。

#### 4. 実行・再現・検証コマンド例
```bash
# 1. videotoolbox/mod.rs 内の copy_nonoverlapping 実装箇所の確認
sed -n '335,415p' /path/to/cua/libs/cua/crates/cua-media-codec/src/videotoolbox/mod.rs

# 2. Sniper E2E 検証テスト（RED -> GREEN + BENIGN）の実行
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_vt01 -v
```
**実測ランタイム証明（`RED -> GREEN + BENIGN`）:**
```json
{
  "RED": {
    "oob_bytes_read": 960,
    "adjacent_heap_secret_copied_to_video_frame": true
  },
  "GREEN": {
    "oob_bytes_read": 0,
    "adjacent_heap_secret_copied_to_video_frame": false,
    "error": "CodecError::InvalidArgument"
  },
  "BENIGN": {
    "valid_frame_encoded_bytes": 1536
  }
}
```

---

### III.07 — TryCua `cua-bench` WinArena (`<= 0.3.1`) — 未認証 `0.0.0.0:8006`（noVNC）およびパスワードなし `0.0.0.0:3390`（RDP）の LAN 公開 + 書き込み可能なホスト `/shared` マウント（`GHSA-hvhg-6x47-cq96`、`CWE-668`/`CWE-732`、CVSS `8.6 High`）

#### 1. メタデータ & 開示ステータス
* **対象リポジトリ & パッケージ:** `trycua/cua`（`pip: cua-bench <= 0.3.1`）
* **影響を受けるバージョン & コンポーネント:** `<= 0.3.1`（`commit e754cfec69c41400eb2aabde716c27d15607b2f0`）— `libs/cua-bench/tasks/winarena_adapter/cli.py`（`cmd_vm_setup`, `cmd_vm_start`, `cmd_task_run`、`262-265, 421-424, 646-649` 行）および `infra/vm/setup/server/main.py`（`180-248, 290-321` 行）
* **脆弱性分類 & スコア:** `CWE-668`（誤った領域へのリソース露出）/ `CWE-732`（重要リソースに対する不適切な権限割り当て）— **CVSS v3.1: `8.6 High`**（`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`）
* **GitHub GHSA リンク:** `GHSA-hvhg-6x47-cq96`（`https://github.com/trycua/cua/security/advisories/GHSA-hvhg-6x47-cq96`）
* **Sniper 個別アドバイザリ:** [`docs/advisories/ja/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md`](advisories/ja/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)

#### 2. コード内でどのように発生し脆弱性へ変化するのか（ステップバイステップの平易な解説）
Docker でコンテナを起動する際、`127.0.0.1:` プレフィックスを付けずに `-p 8006:8006` と指定すると、Docker は **`0.0.0.0`（ホストのすべての Wi-Fi / Ethernet ネットワークインターフェース）** にポートを公開し、さらに Linux の `iptables` `DOCKER` チェーンによって通常のホストファイアウォール（`ufw` 等）の入力制限をバイパスしてしまいます。

WinArena オーケストレータ（`cli.py:262-265, 421-424, 646-649`）では、3つの起動コマンドすべてが以下のオプションを渡しています。
```python
# libs/cua-bench/tasks/winarena_adapter/cli.py:261-266 (および 421-424, 646-649)
"-p", f"{args.browser_port}:8006", # バグ 1: 0.0.0.0:8006 -> 認証なし noVNC Web デスクトップを LAN 全体に公開！
"-p", f"{args.rdp_port}:3389",     # バグ 2: 0.0.0.0:3390 -> パスワードなし Windows RDP を LAN 全体に公開！
"-v", f"{storage_path}:/storage",
"-v", f"{setup_path}:/shared",     # バグ 3: ホスト側のパッケージソースディレクトリを読み書き可能(:rw)でマウント！
```
この結果、同じネットワーク上の誰でもパスワードなしで Windows VM の画面を開いて操作でき、さらに VM の中から `/shared` フォルダ（ホストの Python パッケージ内の `setup` ディレクトリ）にあるスクリプトを書き換えることで、ホスト OS 側へ侵入を拡大できてしまいます。

#### 3. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — 大学研究室・社内 LAN 上での `0.0.0.0:8006`（noVNC）/ `3390`（RDP）経由の Windows VM と API キー乗っ取り:**
  1. AI 研究者が研究室やオフィスの LAN に接続されたマシンで `cua-bench` の WinArena 評価を実行する。
  2. 同一ネットワーク上の第三者がブラウザで `http://<ワークステーションIP>:8006` を開くだけで、認証なしで Windows VM のデスクトップ画面に直接接続し、ベンチマーク用に環境へ注入された OpenAI / Anthropic API キーや評価データを窃取する。
* **シナリオ B — 書き込み可能な `-v {setup_path}:/shared` マウントを悪用した VM からホスト OS への逆侵害（コンテナ/VM エスケープ経路）:**
  1. 攻撃者が `8006`（noVNC）または `3390`（RDP）から Windows VM に入り、共有マウント `/shared`（ホスト上の `winarena_adapter/infra/vm/setup`）内のスクリプトやバイナリを改ざんする。
  2. ホスト側の Python CLI や別プロセスがそのセットアップディレクトリを参照・再実行した際に、ホスト OS 上で攻撃者のコードが実行される。
* **シナリオ C — VM 内の未認証 `0.0.0.0:5000` エージェントサーバー（`POST /execute_windows` -> `exec()`）による任意コマンド実行:**
  1. VM 内部で動く `infra/vm/setup/server/main.py`（`180-248` 行）は認証なしで `POST /execute_windows`（Python `exec()`）および `POST /setup/launch`（`subprocess.Popen(..., shell=True)`）を公開している。
  2. エージェントがタスク実行中に外部 Web ページを開いた際、またはコンテナネットワーク経由でリクエストが送られた際、VM 内で任意の OS コマンドが実行される。

#### 4. 実行・再現・検証コマンド例
```bash
# 1. cli.py 内の Docker ポートバインドとボリュームマウントのソース確認
sed -n '255,272p' /path/to/cua/libs/cua-bench/tasks/winarena_adapter/cli.py

# 2. Sniper E2E 検証テスト（RED -> GREEN + BENIGN）の実行
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand06 -v
```
**実測ランタイム証明（`RED -> GREEN + BENIGN`）:**
```json
{
  "RED": {
    "lan_exposed_ports": ["8006:8006", "3390:3389"],
    "host_setup_dir_mounted_writable": true,
    "host_setup_file_tampered_from_container": true
  },
  "GREEN": {
    "lan_exposed_ports": [],
    "loopback_bound_ports": ["127.0.0.1:8006:8006", "127.0.0.1:3390:3389"],
    "host_setup_dir_mounted_writable": false,
    "readonly_mount": true
  }
}
```

---

### III.08 — OpenZiti (`ziti` CLI) — `AreCertsTrusted` -> `InsecureClient` における無条件 `InsecureSkipVerify: true` による TLS 証明書検証バイパス（`GHSA-qwv8-hh9r-cqrf`、`CWE-295`、CVSS `7.4 High`）

#### 1. メタデータ & 開示ステータス
* **対象リポジトリ & パッケージ:** `openziti/ziti`（`Go: github.com/openziti/ziti/v2`）
* **影響を受けるバージョン & コンポーネント:** `v2.0.0-pre6` 以下（`commit 08f09c510bb2673d3632419ba8d6e10002d5eb00`）— `ziti/util/certs.go`（`AreCertsTrusted` `91-103` 行、`InsecureClient` `199-208` 行）および `ziti/cmd/edge/login.go`（`319-390` 行）
* **脆弱性分類 & スコア:** `CWE-295`（不適切な証明書検証）— **CVSS v3.1: `7.4 High`**（`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`）
* **GitHub GHSA リンク:** `GHSA-qwv8-hh9r-cqrf`（`https://github.com/openziti/ziti/security/advisories/GHSA-qwv8-hh9r-cqrf`）
* **Sniper 個別アドバイザリ:** [`docs/advisories/ja/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md`](advisories/ja/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)

#### 2. コード内でどのように発生し脆弱性へ変化するのか（ステップバイステップの平易な解説）
Zero-Trust ネットワーク基盤である OpenZiti の CLI で管理者が `ziti edge login` を実行すると、まず接続先コントローラの TLS 証明書が信頼できるかどうかを確認するために `AreCertsTrusted(host)`（`certs.go:91-103`）が呼ばれます。

この関数は、「もし偽の証明書であれば Go の TLS ライブラリが `x509.UnknownAuthorityError` を返すはずだから、それをキャッチしてユーザーに警告しよう」という意図で書かれています。ところが、内部で呼び出している `InsecureClient(&client, certs)`（`199-208` 行）に致命的なバグがありました。
```go
// ziti/util/certs.go:91-103, 199-208
func AreCertsTrusted(host string, certs []*x509.Certificate) (bool, error) {
    client := resty.New()
    InsecureClient(client, certs) // <--- ここで TLS 設定を行う
    _, err := client.R().Get(host)
    if err != nil {
        if errors.Is(err, &x509.UnknownAuthorityError{}) { // デッドコード！絶対に到達しない！
            return false, nil
        }
        return false, err
    }
    return true, nil
}

func InsecureClient(client *resty.Client, certs []*x509.Certificate) {
    tlsCfg := &tls.Config{
        InsecureSkipVerify: true, // バグ: 無条件で true が設定されている！
    }
    if len(certs) > 0 {
        tlsCfg.RootCAs = x509.NewCertPool()
        for _, c := range certs {
            tlsCfg.RootCAs.AddCert(c)
        }
        // ここでも InsecureSkipVerify は true のまま！
    }
    client.SetTLSClientConfig(tlsCfg)
}
```
Go の標準ライブラリ `crypto/tls` では、**`InsecureSkipVerify: true` が設定されていると、`RootCAs` に何が入っていようとサーバー証明書の署名チェーン・有効期限・ホスト名の検証をすべてスキップ** します。その結果、`AreCertsTrusted()` は攻撃者が勝手に作った自己署名証明書に対しても常に `true, nil` を返し、CLI は **`"Verified that server supplied certificates are trusted"`（サーバー証明書が信頼できることを確認しました）** という誤ったメッセージを表示した上で、管理者の ID・パスワードを攻撃者へ送信してしまいます。

#### 3. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — リモートワークや出張中のインフラ管理者が `ziti edge login` を実行した際の MITM による管理者パスワード窃取:**
  1. インフラ管理者がカフェやホテルの Wi-Fi、あるいは侵害されたネットワーク経路から `ziti edge login https://ziti-controller.corp.example:1280 -u admin -p <password>` を実行する。
  2. 経路上の攻撃者が完全に無関係な自己署名証明書を提示して TLS 接続をインターセプトする。
  3. `AreCertsTrusted()` が `true` を返すため、確認プロンプトすら出ずに信頼済みと判定され、`POST /edge/management/v1/authenticate?method=password` で管理者クレデンシャルが攻撃者へ直接送信される。
* **シナリオ B — CI/CD パイプラインや Kubernetes 自動ブートストラップにおける偽コントローラへのゼロトラスト登録:**
  1. 自動デプロイジョブが `--yes` なしで安全に証明書検証を行うつもりで `ziti edge login` を実行する。
  2. DNS スプーフィングや BGP ハイジャックにより接続先が攻撃者のサーバーへ向いた際、エラーで停止せずにそのまま認証トークンやサービスポリシーを攻撃者へ送信する。
* **シナリオ C — 期限切れ・失効済み・誤った CA のコントローラ証明書のサイレント受け入れ:**
  1. 本番環境で誤ってテスト用 CA の証明書や期限切れ証明書がデプロイされた場合でも、`ziti edge login` が「信頼済み」と報告し続けるため、PKI ガバナンス違反が検知されない。

#### 4. 実行・再現・検証コマンド例
```bash
# 1. ziti/util/certs.go 内の AreCertsTrusted と InsecureClient のソースコード確認
sed -n '90,105p;198,210p' /path/to/ziti/ziti/util/certs.go

# 2. Sniper E2E 検証テスト（RED -> GREEN + BENIGN）の実行
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_ziti_cand01 -v
```
**実測ランタイム証明（`RED -> GREEN + BENIGN`）:**
```json
{
  "RED": {
    "rogue_mitm_cert_accepted_as_trusted": true,
    "admin_credentials_sent_to_mitm": true
  },
  "GREEN": {
    "rogue_mitm_cert_accepted_as_trusted": false,
    "admin_credentials_sent_to_mitm": false,
    "error": "x509.UnknownAuthorityError"
  },
  "BENIGN": {
    "valid_ca_cert_trusted": true
  }
}
```

---

### III.09 — n8n (`n8n-workflow <= 2.45.0`) — `string-extensions.ts` における入力長無制限の `EMAIL_REGEXP` / `DOMAIN_EXTRACT_REGEXP`（`isEmail` / `extractEmail` / `extractDomain`）による Webhook イベントループ凍結（`ReDoS`、`CWE-1333`、CVSS `5.3 Medium`）

#### 1. メタデータ & 開示ステータス
* **対象リポジトリ & パッケージ:** `n8n-io/n8n`（`npm: n8n-workflow <= 2.45.0`）
* **影響を受けるバージョン & コンポーネント:** `<= 2.45.0`（`commit 976c80c63ba38fffe1ffde1fb6fb6fb4edbe8b51`）— `packages/workflow/src/extensions/string-extensions.ts`（`59, 94, 326, 375, 383` 行）
* **脆弱性分類 & スコア:** `CWE-1333`（非効率な正規表現の複雑性 / ReDoS）— **CVSS v3.1: `5.3 Medium`**（`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`）
* **Sniper 個別アドバイザリ:** [`docs/advisories/ja/09-N8N-CAND-01-WEBHOOK-REDOS.md`](advisories/ja/09-N8N-CAND-01-WEBHOOK-REDOS.md)

#### 2. コード内でどのように発生し脆弱性へ変化するのか（ステップバイステップの平易な解説）
ワークフロー自動化基盤 `n8n` では、Webhook 等で受け取った文字列に対して `{{ $json.body.email.isEmail() }}` や `{{ $json.body.text.extractEmail() }}`、`{{ $json.body.url.extractDomain() }}` といった組み込みメソッドが日常的に使われます。

ところが `string-extensions.ts` に定義されている正規表現には、**入力文字列の長さ制限（RFC 5321 の 254 文字制限など）が一切なく、さらに先頭アンカー（`^`）のない部分一致パターンに入れ子量指定子（`(\.[^...]+)*`）が含まれている** という問題があります。
```typescript
// packages/workflow/src/extensions/string-extensions.ts:59, 94
const EMAIL_REGEXP =
  /(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/;

const DOMAIN_EXTRACT_REGEXP = /^(?:https?:\/\/)?(?:www\.)?((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?:\/|$)/;
```
Node.js はシングルスレッドのイベントループで全ての HTTP Webhook リクエストと UI 操作を処理します。そこへ `"a.a.a.a..."`（約 10〜20 KB のドット区切り文字列の末尾に `@!` を付けたもの）を1つ送ると、V8 正規表現エンジンが全開始位置でバックトラッキングを繰り返し、**1リクエストあたり数百ミリ秒〜1秒近くイベントループを完全に停止** させます。

#### 3. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — 公開リード獲得・問い合わせ Webhook への軽量リクエスト送信による全社 Stripe/Slack Webhook の凍結:**
  1. 企業が Web サイトの問い合わせフォームやユーザー登録の受け口として n8n Webhook を公開し、`IF` ノードで `{{ $json.body.email.isEmail() }}` を評価している。
  2. 攻撃者が 20 KB の `"a.a.a...a@!"` ペイロードを毎秒数回 POST する。
  3. 1リクエストで約 `832 ms` イベントループがブロックされるため、同じ n8n インスタンス上で動いている無関係な決済 Webhook（Stripe）や社内通知（Slack）、管理画面 UI まで全てタイムアウトする。
* **シナリオ B — カスタマーサポート自動取り込みフロー（`extractEmail()`）におけるコンテナ再起動ループ:**
  1. 受信メールやチャットメッセージを `{{ $json.text.extractEmail() }}` で解析するワークフローが稼働している。
  2. 長いドット区切り文字列を含む1通のスパム/悪意あるメッセージが処理されるとワーカーがフリーズし、Kubernetes の Liveness Probe が失敗してコンテナが再起動ループに陥る。
* **シナリオ C — CRM URL ドメイン抽出（`extractDomain()`）における V8 イベントループ枯渇:**
  1. 外部フォームやスクレイピング結果の URL から `{{ $json.url.extractDomain() }}` でドメインを抽出するワークフローに、末尾がスラッシュでない長いドット付きホスト名文字列が入力され、CPU コアが 100% 張り付く。

#### 4. 実行・再現・検証コマンド例
```bash
# 1. Node.js ワンライナーによる string-extensions.ts の EMAIL_REGEXP 停止時間の計測
node -e 'const re = /(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/; const s = "a.".repeat(10000) + "a@!"; const t0 = performance.now(); re.test(s); console.log("Elapsed ms:", (performance.now() - t0).toFixed(2));'

# 2. Sniper E2E 検証テスト（RED -> GREEN + BENIGN）の実行
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_n8n_cand01 -v
```
**実測ランタイム証明（`RED -> GREEN + BENIGN`）:**
```json
{
  "RED": {
    "regex_stall_ms": 165.035,
    "stall_20kb_ms": 831.78,
    "concurrent_webhook_starved": true
  },
  "GREEN": {
    "regex_stall_ms": 0.017,
    "stall_20kb_ms": 0.0029,
    "concurrent_webhook_starved": false
  },
  "BENIGN": {
    "valid_email_recognized": true
  }
}
```

---

### III.10 — Gotify Server (`<= v2.9.1`) — 組み込み `SSL.RedirectToHTTPS` ミドルウェア（`router.go`）における未検証 `ctx.Request.Host` ヘッダーによる `308 Permanent Redirect` オープンリダイレクトとトークン漏洩（`GHSA-cc9f-m5vr-pm75`、`CWE-601`、CVSS `4.7 Medium`）

#### 1. メタデータ & 開示ステータス
* **対象リポジトリ & パッケージ:** `gotify/server`（`Go: github.com/gotify/server/v2`）
* **影響を受けるバージョン & コンポーネント:** `<= v2.9.1`（`commit 97685e2a6f9c02b92263ef0df9831371a79d150b`）— `router/router.go`（`52-73, 93-102` 行）
* **脆弱性分類 & スコア:** `CWE-601`（信頼できないサイトへの URL リダイレクト / オープンリダイレクト）— **CVSS v3.1: `4.7 Medium`**（`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N`）
* **GitHub GHSA リンク:** `GHSA-cc9f-m5vr-pm75`（`https://github.com/gotify/server/security/advisories/GHSA-cc9f-m5vr-pm75`）
* **Sniper 個別アドバイザリ:** [`docs/advisories/ja/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md`](advisories/ja/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)

#### 2. コード内でどのように発生し脆弱性へ変化するのか（ステップバイステップの平易な解説）
Gotify Server で組み込み TLS（`SSL.Enabled: true`）と HTTPS 自動リダイレクト（`SSL.RedirectToHTTPS: true`）を有効にすると、`router/router.go` が HTTP リクエストを HTTPS へ転送するミドルウェアを登録します。

しかし、このミドルウェアはサーバーの設定ファイルに書かれた正規ドメイン（`conf.SSL.LetsEncrypt.Hosts`）を参照せず、**クライアントが送ってきた HTTP リクエストの `Host` ヘッダー（`ctx.Request.Host`）をそのまま信頼して `Location: https://<Host>/<Path>` を組み立て、HTTP `308 Permanent Redirect` を返してしまいます**。
```go
// router/router.go:93-102
httpRouter.Use(func(ctx *gin.Context) {
    if ctx.Request.TLS == nil {
        // バグ: 攻撃者が自由に書き換え可能な ctx.Request.Host をそのままリダイレクト先に使っている！
        location := url.URL{
            Scheme:   "https",
            Host:     ctx.Request.Host,
            Path:     ctx.Request.URL.Path,
            RawQuery: ctx.Request.URL.RawQuery,
        }
        ctx.Redirect(http.StatusPermanentRedirect, location.String()) // 308 Permanent Redirect
        ctx.Abort()
    }
})
```
さらにステータスコードが `308 Permanent Redirect` であるため、HTTP メソッド（`POST` 等）とクエリ文字列（`?token=<app-token>`）およびリクエストボディを変更せずにそのまま攻撃者のサーバーへ再送信するようクライアントに指示してしまいます。

#### 3. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — 自動監視・通知スクリプト（`curl -L` / Python `requests` / Uptime Kuma）からの `?token=` アプリケーショントークン窃取:**
  1. サーバー監視ツールや CI/CD 通知スクリプトが `http://gotify.internal/message?token=AgSecretToken123` に対してリダイレクト追従有効で POST リクエストを送っている。
  2. ネットワーク境界またはプロキシ経由で `Host: attacker-collector.example` が注入されると、Gotify は `308 Permanent Redirect` で `Location: https://attacker-collector.example/message?token=AgSecretToken123` を返す。
  3. クライアントが自動的にリダイレクト先へ POST を再送し、秘密のアプリケーショントークンと通知本文が攻撃者サーバーへそのまま渡される。
* **シナリオ B — 共有 HTTP キャッシュ / CDN / キャプティブポータルにおける `308` キャッシュポイズニングとフィッシング誘導:**
  1. 共有キャッシュやリバースプロキシの背後に置かれた Gotify に対し、攻撃者が `Host: fake-gotify-login.example` ヘッダー付きリクエストを送る。
  2. キャッシュされた `308 Permanent Redirect` により、後続の正規ユーザーのブラウザが永続的に偽のログイン画面へ転送される。
* **シナリオ C — ブラウザ永続リダイレクトキャッシュを利用した WebSocket / Web UI セッションの誘導:**
  1. ユーザーが一度でも悪意ある `Host` ヘッダーを伴うレスポンスを受け取ると、`308` がブラウザにキャッシュされ、次回以降のアクセスも攻撃者ホストへ向かう。

#### 4. 実行・再現・検証コマンド例
```bash
# 1. ローカル隔離テスト環境での Host ヘッダーインジェクション再現コマンド例
curl -i "http://127.0.0.1:18080/message?token=secret-app-token" \
  -H "Host: evil-phish.example.com"

# 2. Sniper E2E 検証テスト（RED -> GREEN + BENIGN）の実行
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_gotify_cand01 -v
```
**実測ランタイム証明（`RED -> GREEN + BENIGN`）:**
```json
{
  "RED": {
    "status_code": 308,
    "location": "https://evil-phish.example.com/message?token=secret-app-token",
    "redirected_to_untrusted_host": true
  },
  "GREEN": {
    "status_code": 308,
    "location": "https://push.corp.example/message?token=secret-app-token",
    "redirected_to_untrusted_host": false,
    "bound_to_configured_ssl_host": true
  }
}
```

---

### III.11 — Nordic Institute X-Road (`develop`) — 永続セルフホストランナー `xrd-runner-8c` 上で動作する `_build-and-package.yml` 内の `${{ github.head_ref }}` シェルコマンドインジェクション（`GHSA-4fcw-7xqx-fjv5`、`CWE-78`、CVSS `8.5 High`）

#### 1. メタデータ & 開示ステータス
* **対象リポジトリ & パッケージ:** `nordic-institute/X-Road`（GitHub Actions CI/CD パイプライン — `commit 38cd99ec0ebba0bd68a2581ca3c92be2e5f5843f`）
* **影響を受けるバージョン & コンポーネント:** `develop` ブランチ — `.github/workflows/build.yaml`（`1-55` 行）および `.github/workflows/_build-and-package.yml`（`Determine target branch` ステップ、`84-91` 行）
* **脆弱性分類 & スコア:** `CWE-78`（OS コマンドインジェクション）— **CVSS v3.1: `8.5 High`**（`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`）
* **GitHub GHSA リンク:** `GHSA-4fcw-7xqx-fjv5`（`https://github.com/nordic-institute/X-Road/security/advisories/GHSA-4fcw-7xqx-fjv5`）
* **Sniper 個別アドバイザリ:** [`docs/advisories/ja/11-XROAD-CAND-01-RUNNER-INJECTION.md`](advisories/ja/11-XROAD-CAND-01-RUNNER-INJECTION.md)

#### 2. コード内でどのように発生し脆弱性へ変化するのか（ステップバイステップの平易な解説）
GitHub Actions の YAML ファイル内で `${{ github.head_ref }}`（プルリクエストのブランチ名）を書くと、GitHub は **bash を起動する前の文字列置換としてその値をそのままスクリプト内に埋め込みます**。

X-Road のメインビルドワークフロー `build.yaml` は、`pull_request` イベントで発火し、**書き込み権限（`contents: write`, `packages: write`）と全シークレット継承（`secrets: inherit`）** を付けた状態で再利用ワークフロー `_build-and-package.yml` を呼び出します。そして `_build-and-package.yml` は **永続的なセルフホストランナー（`runs-on: xrd-runner-8c`）** 上で、最初のステップ（`actions/checkout` より前）として以下のスクリプトを実行します。
```yaml
# .github/workflows/_build-and-package.yml:84-91
jobs:
  build-packages:
    runs-on: xrd-runner-8c
    steps:
      - name: Determine target branch
        run: |
          if [ "${{ github.event_name }}" == "pull_request" ]; then
            echo "TARGET_BRANCH=${{ github.head_ref }}" >> "$GITHUB_ENV"
          else
            echo "TARGET_BRANCH=${{ github.ref_name }}" >> "$GITHUB_ENV"
          fi
```
Git のブランチ名には二重引用符（`"`）やセミコロン（`;`）を含めることができます。そのため、ブランチ名を `feat";id;env;#` にして PR を作成すると、展開後の bash スクリプトは `echo "TARGET_BRANCH=feat";id;env;#" >> "$GITHUB_ENV"` となり、**コードレビューが始まる前にセルフホストランナー上で任意の OS コマンドが実行** されます。

#### 3. 日常業務で発生し得る3つの重大シナリオ（`シナリオ A / B / C`）
* **シナリオ A — 細工されたブランチ名による PR 作成時のセルフホストランナー `xrd-runner-8c` 上での即時コマンド実行:**
  1. ブランチ作成権限を持つアカウントまたは侵害された開発者トークンから、`feat";<任意コマンド>;#` というブランチ名で PR が作成される。
  2. コードのチェックアウトやレビュアーの承認を待たずに、`Determine target branch` ステップで bash コマンドが即座に実行される。
* **シナリオ B — `secrets: inherit` と `packages: write` 権限を悪用した公式コンテナレジストリ（GHCR）・リポジトリ改ざん:**
  1. 親ワークフロー `build.yaml` が `permissions: contents: write, packages: write` と `secrets: inherit` を渡しているため、注入されたコマンドは書き込み権限を持つ `GITHUB_TOKEN` と継承された CI シークレットにアクセスできる。
  2. 攻撃者はこれらを用いて公式パッケージレジストリへ改ざんイメージをプッシュしたり、リポジトリのブランチやタグを書き換えたりできる。
* **シナリオ C — 永続セルフホストランナー（`xrd-runner-8c`）のキャッシュ汚染による後続の公式 X-Road パッケージへのバックドア混入:**
  1. GitHub ホストランナーと異なり、`xrd-runner-8c` はビルド間で環境が破棄されない永続セルフホストサーバーである。
  2. 攻撃者がランナー上のローカル Gradle キャッシュ、Docker レイヤーキャッシュ、またはバックグラウンドプロセスを汚染することで、後続の正規リリースビルドで生成される `.deb` / `.rpm` パッケージにバックドアを混入させる。

#### 4. 実行・再現・検証コマンド例
```bash
# 1. _build-and-package.yml と build.yaml の該当行をソースコードで確認
sed -n '1,55p' /path/to/X-Road/.github/workflows/build.yaml
sed -n '80,95p' /path/to/X-Road/.github/workflows/_build-and-package.yml

# 2. Sniper E2E 検証テスト（RED -> GREEN + BENIGN）の実行
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_xroad_cand01 -v
```
**実測ランタイム証明（`RED -> GREEN + BENIGN`）:**
```json
{
  "RED": {
    "runs_on": "xrd-runner-8c",
    "secrets_inherit": true,
    "direct_yaml_interpolation": true,
    "arbitrary_command_executed_on_self_hosted_runner": true
  },
  "GREEN": {
    "env_var_parameterized": true,
    "arbitrary_command_executed_on_self_hosted_runner": false
  },
  "BENIGN": {
    "target_branch_written": "feature/normal-branch"
  }
}
```
