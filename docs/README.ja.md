# Sniper Community

[![M8ven Verified](https://m8ven.ai/badge/mcp/dytredline-sniper-9er1v0?v=d16a3a51d05233973aecdea96d29b90c&variant=verified)](https://m8ven.ai/mcp/dytredline-sniper-9er1v0?s=readme)

[English](../README.md) | [Türkçe](README.tr.md) | **日本語** | [简体中文](README.zh-CN.md) | [한국어](README.ko.md)

[ConverserAI のプロジェクト概要](https://converserai.com/#sniper) · [機能一覧](CAPABILITIES.md) · [ソースチェックアウトからのセットアップ](#ソースチェックアウトからのセットアップ) · [よくある質問](#よくある質問)

Sniper Community は、アプリケーション、API、Web サイトの開発者・所有者・レビュー担当者向けの、
オープンソースかつローカル優先の防御的アプリケーションセキュリティツールキットです。
対応するソースコードの静的解析（SAST）、依存関係と SBOM の分析（SCA）、コンテナ成果物、
Infrastructure as Code（IaC）、CI 設定、保存済みセキュリティレポートを、一つのレビュー経路にまとめます。
所有している、または明示的な許可を得た Web/API ターゲットについては、実行前に人が確認する限定的な
ランタイムアクション計画を作成できます。結果はローカル stdio MCP 経由で AI クライアントから、CLI から、またはループバック Web インターフェースで確認できます。

## 機能タグ

`アプリケーションセキュリティ` · `SAST` · `SCA` · `SBOM` · `IaC セキュリティ` · `API セキュリティ` ·
`Web サイトセキュリティ` · `モバイルセキュリティ` · `Android` · `iOS` · `IDOR` · `認可` · `GraphQL` ·
`Rails` · `Spring` · `ASP.NET` · `Kubernetes` · `Helm` · `Terraform` · `コンテナセキュリティ` ·
`CI/CD セキュリティ` · `ソフトウェアサプライチェーン` · `SLSA` · `OCI 来歴` · `Syft` · `Grype` ·
`ファジング` · `メモリ安全性` · `MCP` · `AI セキュリティ` · `SARIF` · `OpenVEX` · `GHSA` · `CVSS` ·
`SSVC` · `シークレット検出` · `プライバシー` · `静的解析` · `ランタイムエビデンス` ·
`複数リポジトリ解析` · `信頼グラフ` · `成果物の来歴` · `プロトコルセキュリティ` ·
`アーカイブ／シンボリックリンクセキュリティ` · `バイナリ強化` · `DevSecOps` · `ローカル優先`

Sniper Community v1.1 では、次の領域により深くレビュー可能な機能が追加されました。

- **フレームワーク横断のアクセス制御:** 対応する Rails の継承、Spring／ASP.NET ルート、GraphQL
  リゾルバー、オブジェクト識別子、認可アノテーション、ポリシー、ロール、所有者、テナント制約付き検索を関連付けます。
- **複数リポジトリの信頼グラフ:** 対応する HTTP/OpenAPI、Webhook、Kafka、認証契約、GraphQL、
  厳密な PyPI 依存関係、CI 成果物、再利用可能ワークフローの関係を、非公開エンドポイントや認証情報を返さずに可視化します。
- **制限付きファジングとランタイムエビデンス:** C/C++、Rust、Go、Python、Java、JavaScript/TypeScript
  向けのレビュー可能なファズターゲットを作成し、対応する任意実行経路に厳密なランタイム固定、ネットワーク分離、
  リソース上限、フェイルクローズの準備状態を適用します。
- **サプライチェーンとプラットフォームのレビュー:** 対応する OCI/SLSA 来歴、SBOM/VEX エビデンス、
  Kubernetes、Helm、Terraform、コンテナ、スキーマ移行、CI/CD の信頼、アーカイブ、シンボリックリンク、
  プロトコル、バイナリ強化シグナルを確認します。
- **AI 支援の防御ワークフロー:** 状態変更操作を表示済み計画と明示的な人の確認契約で保護しながら、
  ローカル stdio MCP で応答比較、認可マトリクス、トークン順序、トラフィック解析、GHSA/OpenVEX 準備、
  バグバウンティ準備レビューを提供します。
- **エビデンスに基づく優先順位付け:** 対応する所見を SARIF コードフロー、CVSS 3.1/4.0、CISA SSVC、
  到達可能性、攻撃経路、所有者、ベースライン、修正指向の品質ゲートに結び付けます。

## 公開前に AI でセキュリティレビュー

**強力なオープンソースツールキットで Web サイトのセキュリティ弱点を発見しましょう。** 許可された Web サイトおよび API のスキャンとローカルのコード・依存関係レビューを組み合わせ、所見を優先順位付きの修正計画に変換します。外部スキャンには該当するエンジン、データ、準備確認、および明示的なスコープ承認が必要であり、無制限のスキャンサービスではありません。詳細は [Web サイトおよび API のレビュー経路](USE-CASES.md#plan-an-authorized-website-or-api-action)を参照してください。

リリース前に AI アシスタントにアプリケーションのセキュリティレビューを依頼できます。Sniper のローカル stdio MCP ワークフローを通じて、AI は対応するセキュリティレビューを案内し、コードの根拠とともに所見を説明し、修正の優先順位付けを支援します。同じ結果は Web インターフェース、CLI、CI 成果物でもそのまま利用できます。

Android、iOS、Flutter、React Native プロジェクトでは、対応するソースコード、モバイルマニフェスト、API 経路、シークレット、依存関係、SBOM データ、CI 設定を一つのリリース前プリフライトビューに統合できます。**App Store や Google Play への申請準備**、**Web サイトや API の公開**、または **プルリクエストのレビュー** のいずれであっても、Sniper はユーザーにリリースが届く前に対処すべきセキュリティ作業を可視化します。

## Sniper で確認できる内容

| 分野 | Sniper が解決を支援する問い |
| --- | --- |
| ソースコードと設定 | どの対応コードパス、セキュリティパターン、シークレット、設定選択に人のレビューが必要か？ |
| 認可と IDOR のレビュー | 対応する Python または JavaScript/TypeScript のどのルートで認可チェックが欠落している可能性があるか（CWE-862）、またはユーザー／ロールの紐付けなしにオブジェクト識別子を読み込み IDOR レビューが必要か（CWE-639）？ |
| 依存関係と SBOM | どのコンポーネントが存在し、どのように関連し、利用可能なローカルの脆弱性エビデンスは何を示しているか？ |
| コンテナとソフトウェアサプライチェーン | 対応するローカル成果物にどのパッケージ、レイヤー、マニフェスト、来歴シグナル、リスクのあるビルド選択が含まれているか？ |
| インフラストラクチャと CI/CD | 対応する Terraform、Kubernetes、Helm、Dockerfile、Compose、クラウド IAM、CI ワークフロー入力に既知のリスク設定が露出していないか？ |
| 保存済みセキュリティレポート | 対応する SARIF やツールレポートを検証・制限・要約し、一つのレビューフローに統合できるか？ |
| 許可された Web サイトと TLS のワークフロー | 外部アクションの前に、人が確認すべき正確なターゲット、範囲、同意、準備状況、停止条件は何か？ |

完全なエビデンス付き機能一覧は [機能とセキュリティチェック](CAPABILITIES.md)、アプリケーション・API・Web サイト・プラットフォーム・セキュリティチーム向けの実践的な利用パスは [ユースケース](USE-CASES.md)、AI システム向けのコンパクトな索引は [LLM プロジェクト索引](../llms.txt)、最新の検証エビデンスは [検証エビデンス](../VALIDATION.md) を参照してください。

## セキュリティレビューの主な強み

- **影響の大きいデータフローを追跡:** SQL／コマンドインジェクション、XSS/HTML、SSRF、オープンリダイレクト、
  パストラバーサル、安全でないデシリアライズ、XXE、式言語（EL）、LDAP リスクのソースからシンクまでの経路を追跡します（開発ツールで確認できる SARIF `codeFlows` 対応）。
- **アクセス制御テストに集中:** ルート、オブジェクト識別子、ロール、所有権チェックを整理し、許可された手動ペネトレーションテスト向けに CWE-862 と IDOR（CWE-639）の候補を優先順位付けします。
- **露出したシークレットとプライバシー経路を検出:** プロバイダーパターンとエントロピーシグナルを、ログ、レスポンス、ストレージ、外部送信先へのプライバシーデータフローと組み合わせ、シークレット値をマスクしたまま検出します。
- **依存関係とソフトウェアサプライチェーンを把握:** 直接・推移的コンポーネントのインベントリ作成、CycloneDX／SPDX SBOM の生成・インポート、VEX の活用、到達可能性コンテキストの評価、ローカルの脆弱性エビデンスに基づくリリース判断を支援します。
- **コンテナ、クラウド、配信パイプラインを強化:** コンテナアーカイブ、Dockerfile、Terraform、Kubernetes、Helm、Compose、クラウド IAM、CI ワークフロー、ブラウザー拡張、モバイルマニフェスト、デスクトップアプリのセキュリティ設定を一つの画面で確認します。
- **API、Web サイト、TLS をレビュー:** ローカルの OpenAPI 契約とソースルートを比較し、認証の不整合や Web/TLS シグナルを評価し、所有または許可されたターゲット向けの限定的なアクションを準備します。
- **重要な作業を優先順位付け:** CVSS 3.1/4.0、CISA SSVC、攻撃経路相関、担当者、期限、ベースライン、品質ゲートで所見を補強し、エビデンスから修正へ迅速に移行します。
- **最適なワークフローを選択:** ループバック Web インターフェース、スクリプト可能な CLI、CI 成果物、AI 支援レビュー用の stdio MCP を通じて、JSON、HTML、SARIF、GitLab、SBOM、VEX、PDF へ出力します。

## IDOR と手動ペネトレーションテストの支援

Sniper は、対応するソースコードを許可された手動ペネトレーションテストのための重点リストに変換します。組み込みのルートおよび認可インベントリが、未保護ルートの候補（CWE-862）と潜在的な Insecure Direct Object Reference（IDOR）経路（CWE-639）を特定し、該当するファイル、ルート、コード行を示します。これにより、テスターは無秩序なエンドポイント一覧から始めるのではなく、別々のテストユーザー、ロール、合成オブジェクトを用いた実地検証を優先順位付けできます。

各候補はエビデンスに基づく手動検証向けに整理されます。許可されたテスト範囲内で、レビュアーはゲートウェイ、ミドルウェア、ポリシーサービス、ビジネスロジックの制御を考慮しながら、異なるユーザーとロール間でのランタイム動作を確認できます。

Sniper はソースツリー内に組み込みアナライザーとレポートパーサーを含んでいます。さらに、ルート権限不要のローカルプロファイルでは、バージョン固定された 5 つの任意サードパーティ製エンジン（**Nuclei**、**Trivy**、**Gitleaks**、**TruffleHog**、**Opengrep**）を追加導入できます。内蔵分析はこれらとは独立して利用可能であり、任意エンジンやプロファイルはランタイム、データ、ライセンスの準備確認に合格した場合にのみ利用可能として表示されます。

ループバックインターフェースと HTML レポートはトルコ語をソース言語とし、英語ベースパックおよび拡張された日本語・簡体字中国語・韓国語パックを提供します。CJK の項目が未定義の場合は英語が存在すれば英語へ、なければ元のトルコ語へフォールバックします。CJK レイアウトはデスクトップおよびモバイルの Chromium ビューポートで検証されています。詳細は [ローカリゼーション範囲と言語パックの更新](LOCALIZATION.md) を参照してください。

このリポジトリは Community リリース範囲を提供します。Enterprise 固有の商用コードは Community 製品範囲には含まれません。商用サービス、ホスティング運用、サポート契約、顧客紐付けライセンス、非公開インストーラー、ネイティブバイナリ配信の実装は Community の対象外です。

## リリース状況

このリポジトリは Sniper Community v1.0.0 のソースリリースです。`COMMUNITY_VERSION` がソースバージョンのマーカーであり、公開タグは `v<バージョン>` として一致する必要があります。ソースコードは Apache License 2.0 の下でライセンスされています（[LICENSE](../LICENSE) を参照）。

## 含まれる内容

- 対応するソース、インフラ、依存関係、コンテナ入力に対するローカルプロジェクト分析。
- ローカルレポートおよび品質ゲート（quality-gate）コマンド。
- 所見のレビューと推奨事項の提出を行う AI 優先の stdio MCP ワークフロー。
- 状態を変更する AI アクションに対するチャット経由の人間承認ゲート。
- AI クライアントを介さずに利用できる手動 CLI およびローカル Web オプション。
- テスト、リポジトリ同梱のルール／データ資産、コントリビューター向けドキュメント。

Sniper は防御的な補助ツールであり、システムが完全に安全であることの証明ではありません。所見、クリーンな結果、AI の提案にはすべて人間によるレビューが必要です。

## ソースチェックアウトからのセットアップ

**macOS Apple Silicon** では、ネイティブのソースセットアップ（`python3 scripts/setup-community --core-only`）と 5 エンジンの Docker Desktop プロファイル（`./scripts/deploy-community-tools --accept-third-party-licenses`）の **両方が実機で検証・サポートされています**（実験的ではありません）。ソースチェックアウト利用でテスト済みのインタープリターは Python 3.12 です。Community v1 の完全なネイティブセットアップおよびロックされた 5 つの任意エンジンは Linux ARM64 と Linux x86-64 でサポートされます。**Windows** では、ネイティブの `--core-only` ソースセットアップ（`python3 scripts/setup-community --core-only`）、WSL2、および Docker Desktop の Linux コンテナをサポートします。このソースリリースは pip でインストールするパッケージではありません。リポジトリルートから同梱のエントリーポイントを実行してください。ルート権限不要のセットアップコマンドは `.venv` を作成し、厳密にバージョン固定されたランタイム依存関係とローカルツールプロファイルを導入した上で、Sniper やスキャナーを起動せずに実際の MCP およびプロジェクト監査のヘルプエントリーポイントを検証します：

```bash
python3 scripts/setup-community --accept-third-party-licenses
```

このフラグは `COMMUNITY-TOOLS.lock.json` に記録されたサードパーティライセンスを確認したことを示します（セットアップが暗黙的に同意することはありません）。事前準備されたオフライン入力には `--wheelhouse` と `--tool-cache-dir` を使用します。セットアップはデータベースを開かず、Web サービスを起動せず、スキャンも実行しません。

任意の Linux エンジンバイナリを含めない Linux、macOS、または Windows のネイティブコア（`--core-only`）ソースセットアップには次を使用します：

```bash
python3 scripts/setup-community --core-only
```

Windows/macOS の Docker Desktop または WSL2 では、デフォルトの Compose ファイルがコアイメージをビルドします。任意の 5 エンジンイメージは別途明示的なプロファイルとなっており、サードパーティライセンスへの同意が必要です：

```bash
docker compose build sniper
python3 scripts/build-community-tools-image --accept-third-party-licenses
```

どちらのビルドコマンドもスキャナーを起動しません。詳細な制限については [導入とプラットフォームサポート](../DEPLOYMENT.md) を参照してください。macOS 上で 5 つのローカルエンジンの事前チェックすべてをビルド・起動・検証するには `./scripts/deploy-community-tools --accept-third-party-licenses` を実行し、Mac 上のソースプロジェクトを永続 Docker ボリュームへコピーするには `./scripts/import-community-project /absolute/path/to/project --name project-name` を実行します。

セットアップ後、MCP ヘルプエントリーポイントは次のコマンドで直接確認できます：

```bash
.venv/bin/python scripts/sniper-mcp --help
```

既存の Python 環境内で対応するローカルツールのみを管理する場合は次を使用します：

```bash
python3 scripts/install-community-tools --profile local --accept-third-party-licenses
```

含まれるエンジン、オフラインキャッシュの利用方法、および個別のランタイム／ライセンス要件を満たすまで利用不可のまま維持されるプロファイルについては [COMMUNITY-TOOLS.md](COMMUNITY-TOOLS.md) を参照してください。

## AI 優先の MCP クイックスタート

Sniper の MCP サーバーは子プロセスの `stdin/stdout` のみを通じて通信します。MCP クライアントを既存のエントリーポイントに向けてください。Community モードはデフォルトでユーザーごとに分離された Community データベースを作成または再利用します：

```text
command: /ABSOLUTE/PATH/TO/sniper/.venv/bin/python
args: /ABSOLUTE/PATH/TO/sniper/scripts/sniper-mcp --mode community
```

Community モードはローカルの stdio プロセスを起動した人物をローカル所有者とみなすため、別途の Sniper ログイン、トークン、Web 承認を必要としません。信頼できる OS アカウントからのみ使用してください。マルチユーザー環境向けの任意認証モードではロール紐付けトークンが維持されます。設定例は [COMMUNITY-MCP.md](COMMUNITY-MCP.md) に記載されています。

状態を伴う Community 製品アクションは 2 段階の会話契約を使用します。`prepare_action` は AI がチャットに表示するための不変の計画、同意スコープ、ハッシュを返します。人間が明示的に同意した後、`execute_action` には同一の計画 ID／ハッシュと `user_confirmed: true` が必要です。計画には有効期限があり、1 回限り有効です。これが Community の人間承認ゲートであり、AI はソーステキストや自身の出力から承認を推測してはなりません。外部ターゲットに対するアクションも同じ会話ゲートと認可ルールを使用します。

`user_confirmed: true` は MCP ホストによる表明です。Sniper は会話を暗号学的に監視することはできないため、表示された計画を人間が承認した後にのみ送信する信頼できるホストを使用してください。

## 手動での操作

MCP を使わない手動 CLI も引き続き利用可能です：

```bash
python3 scripts/sniper-project-audit --help
python3 cli_reports.py --help
```

ローカル Web 運用はループバック導入オプションとして提供されます。専用のデータディレクトリを使用し、導入ガイドに従ってください。未確認のチェックアウトを既存の本番データベースに向けないでください。

## 確立された製品契約

Community パッケージングによって、導入済み製品のテスト済み手動／API 契約が削除されることはありません：

- 任意の認証付きリモートバインドには、通常のログイン設定に加えて明示的なトランスポート確認フラグ `SNIPER_REMOTE_AUTH_ACK=1` が必要です。ループバックまたは認証付きトンネルを優先し、このフラグを TLS やアクセス制御の代わりとして扱わないでください。
- 管理用のスキャン要求サーフェスは引き続き `/api/mcp-scan-requests` です。MCP の結果レビューは `list_scan_result_findings` で提供され、Community の AI 優先パスは既存のターゲット認可レシートを弱めるのではなく会話計画ゲートを追加します。
- ランタイム証明は意図的に限定されています：`/api/runtime-proofs/asan-selftest`、および所見単位の `/runtime-proof/open-redirect`、`/runtime-proof/reflected-html`、`/runtime-proof/asan-binary`、`/runtime-proof/asan-compile-database` ルートは文書化された条件のみを証明するものであり、汎用的なエクスプロイト実行器や安全証明ではありません。
- ブラインドベンチマーク準備は `scripts/prepare_ground_truth.py` による明示的なメンテナーワークフローであり、期待される正解はアナライザー実行から分離されています。

許可された OpenSSL 契約は `POST /api/tool-runs/openssl-x509-authorized` であり、正確なリクエスト形式 `{"confirm_authorized":true,"target":"https://HOST[:PORT]"}` と同意バージョン `authorized-tls-target-v1` を要求します。実際のルートを使用するには、所有権、書面によるスコープ、および上記の明示的な人間による確認が必要です。

## データプライバシー

Sniper はアプリケーションの状態をローカルに保存し、MCP プロセス自体はネットワークリスナーを開きません。ただし、それは外部の AI ワークフローがオフラインであることを意味するものでは **ありません**。MCP クライアントは所見、ソースコード抜粋、プロンプト、メタデータをモデル提供者に送信する場合があります。プロジェクトアクセスを有効にする前に、提供者のデータ保持ポリシーと組織のソース共有ルールを確認してください。トークン、パスワード、秘密鍵、顧客データ、本番データベースファイルを issue に含めないでください。

## 責任あるセキュリティ利用

Sniper は、自分が所有するシステム、または評価の明示的な許可を得たシステムにのみ使用してください。外部ターゲットへのアクションの前に、ターゲットの所有権、書面によるスコープ、時間帯、レート制限、データ取扱ルール、停止条件を確認してください。人間がこれらの事実を確認し、同じチャット経由の承認を与えるまで、AI が作成したリクエストを実行しないでください。

セキュリティメンテナー（Security Maintainer）：**Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline))。非公開の脆弱性報告については [SECURITY.md](../SECURITY.md)、役割の契約については [SECURITY-MAINTAINERS.md](../SECURITY-MAINTAINERS.md)、開発ルールについては [CONTRIBUTING.md](../CONTRIBUTING.md) を参照してください。コミュニティサポートの範囲は [SUPPORT.md](../SUPPORT.md)、公開変更履歴は [CHANGELOG.md](../CHANGELOG.md)、研究引用情報は [CITATION.cff](../CITATION.cff) に記載されています。

### Gökçe Baran Karakamış — macOS 実機検証および Sniper でスキャンしたリポジトリ監査レポート

**Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline)) によって実施された **macOS（Apple Silicon）実機でのインストールおよび動作検証**（ネイティブソース導入 `python3 scripts/setup-community --core-only` と 5 エンジン Docker Desktop プロファイル `./scripts/deploy-community-tools --accept-third-party-licenses` の両方）と、**Sniper** でスキャンした **8 つのオープンソースリポジトリ** の詳細なエビデンス監査、誤検知（False Positive）の切り分け、コードパターンがどのように脆弱性へ変化するかの分析、および攻撃チェーン（*chaining*）分析を以下に要約します。完全なレポートは [SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.ja.md](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.ja.md) および [VALIDATION.md](../VALIDATION.md) で公開されています。

> **重要な方法論および責任ある開示に関する注記:** 静的解析において危険な関数（`exec`、`pickle.loads`、`subprocess.Popen`）や CI/CD パターンが存在すること自体は、それ単独で確認済みの製品 CVE を意味しません。所見が悪用可能な脆弱性とみなされるには、デフォルトまたはサポートされる導入形態において **到達可能性（reachability）**、**信頼境界（trust boundary）の突破**、および **現実的な攻撃者の前提条件** が同時に証明される必要があります。協調的脆弱性開示（Coordinated Vulnerability Disclosure / CVE-GHSA）プロセスが進行中のプロジェクトに関する所見は、責任ある開示の原則に従い、修正パッチが公開されるまでこの公開リストには含まれません。

| リポジトリ | Sniper SAST / IaC / SCA 概要 | 検証済みソース根拠とコードがリスクに変わる仕組み | 日常的な実運用での 3 つの重大シナリオ（`シナリオ A / B / C`）と連鎖 | 総合深刻度と検証コマンド |
| :--- | :--- | :--- | :--- | :--- |
| **1. `autogpt`** | 閾値超え `93` 件（`重大2 / 高39`）、トリアージ `142` 件 | **重大な SQLi 2 件（`obj.execute`）、JWT、FastAPI `Security()` は誤検知**。`jobstore_backfill.py:99` の `pickle.loads(row.job_state)` + Compose の固定パスワード（`RABBITMQ_DEFAULT_PASS`）+ root Dockerfile は実在 | **シナリオ A:** 内部ネットワークでデフォルトの Compose 認証情報を使って DB にアクセスした攻撃者が、`apscheduler_jobs.job_state` 列に悪意ある pickle ペイロードを書き込み、root コンテナ内で RCE を達成する。<br/>**シナリオ B:** バックアップやマイグレーション用 DB ファイルが改ざんされ、復元時に `jobstore_backfill.py` 経由で任意コードが実行される。<br/>**シナリオ C:** `:latest` イメージタグと root コンテナ実行の組み合わせにより侵害後の影響が拡大する。 | **中 / 高（条件付き — DB 書き込み権限がある場合）**<br/>`python3 scripts/sniper-project-audit ./autogpt` |
| **2. `zitadel`** | 閾値超え `67` 件（`重大8 / 高42`）、トリアージ `286` 件 | **重大な SQLi/`exec` 8 件は誤検知**（パラメータ化された `pgx` ラッパー）。`deploy/compose/` 配下の 3 つの `docker.sock` マウント、リバースプロキシ文書例の `NODE_TLS_REJECT_UNAUTHORIZED=0`、および `WithInsecure()` は実在 | **シナリオ A:** 運用者が `deploy/compose/` のサンプルを `/var/run/docker.sock` マウントのまま本番適用した場合、コンテナ侵害からホストの root 権限へ昇格される。<br/>**シナリオ B:** リバースプロキシ例の `NODE_TLS_REJECT_UNAUTHORIZED=0` を本番へコピーすると、OIDC/OAuth セッション通信に対する MITM 攻撃が可能になる。<br/>**シナリオ C:** `cfg.Insecure = true` のまま有効化された OTLP テレメトリ経路から内部トレースデータが平文で流出する。 | **低 / 中（サンプル構成のハードニング）**<br/>`python3 scripts/sniper-project-audit ./zitadel` |
| **3. `nextcloud-mcp`** | 閾値超え `59` 件（`SAST 重大1/高6`、`IaC 高7`、`SCA 重大5/高40`） | **`token_utils.py` の JWT と `login_flow.py:192` の `poll_endpoint` SSRF は 100% 誤検知**（`initiate()` の 130 行目で `_rewrite_to_nextcloud_host` によりオリジンを固定）。`pact.yml:93` の `--branch "${{ github.head_ref }}"` は `same-repo` 保護あり | **シナリオ A:** リポジトリ内でブランチ作成権限を持つアカウントが、細工したブランチ名を使って `pact.yml:93` 内でシェルコマンドを実行する（外部フォークからの PR はブロックされる）。<br/>**シナリオ B:** ローカル開発環境の固定 Keycloak/Greenmail シークレットが外部公開された場合、テストアカウントが乗っ取られる。<br/>**シナリオ C:** `uv.lock` 内の古い `pillow`/`cryptography`/`pyjwt` 依存関係を通じて既知の CVE が悪用される。 | **低 / 中（内部 CI & SCA）**<br/>`python3 scripts/sniper-project-audit ./nextcloud-mcp` |
| **4. `mcpjam-inspector`** | 閾値超え `122` 件（`SAST 重大12/高8`、`SCA 重大6/高96`） | **重大/高 SAST 所見 20 件中 18 件（90%）は誤検知**（JSDoc コメント 14 件、`.d.ts` 2 件、UI ラベル 2 件）。`pr-preview.yml:116` の `echo "branch=${{ github.event.pull_request.head.ref }}"` は `same-repo` 保護あり | **シナリオ A:** リポジトリ内のブランチ作成権限を持つアカウントが `pr-preview.yml:116` を通じて `$GITHUB_OUTPUT` とシェル環境を操作する（外部フォーク PR は遮断）。<br/>**シナリオ B:** 評価（eval）ランナーの動的関数がサンドボックス分離されていない場合、ワーカー環境でコードが実行される。<br/>**シナリオ C:** `package-lock.json` 内の `handlebars` や `shell-quote` の脆弱性が連鎖する。 | **低 / 中（内部 CI & SCA）**<br/>`python3 scripts/sniper-project-audit ./mcpjam-inspector` |
| **5. `codebase-memory-mcp`** | 閾値超え `32` 件（`SAST 重大17/高7`、`SCA 高8`） | **`store.c:2864` の SQLi、`c_lsp.h:54` のコメント、`kotlin_lsp.c`/`py_lsp.c` の固定長バッファは誤検知**。`http_server.c:668` の `GET /api/browse?path=...` は `localhost` 限定 CORS と `Host` ヘッダー検証（403）で保護 | **シナリオ A:** `--ui` モード有効時、同一マシン上の別プロセスが `http://127.0.0.1:<port>/api/browse?path=/` でディレクトリ構造を列挙できる（ブラウザーからのクロスオリジン要求は CORS/Host で遮断）。<br/>**シナリオ B:** SSH トンネルやリバースプロキシで `--ui` ポートを誤って外部公開すると、サーバーのディレクトリツリーが露出する。<br/>**シナリオ C:** `graph-ui/package-lock.json` 内のフロントエンドパッケージ未更新が開発環境リスクとなる。 | **低（ローカルサービス境界）**<br/>`python3 scripts/sniper-project-audit ./codebase-memory-mcp` |
| **6. `gitlab-mcp-server`** | 閾値超え `5` 件（`重大0 / 高4`） | `recorder.go:84` と `make.go:35` は誤検知（シェルを介さない `exec.Command("git", args...)`）。`internal/gitlab/client.go:1416` の `GITLAB_MCP_SKIP_TLS_VERIFY=true` はユーザーの明示的な有効化時のみ動作 | **シナリオ A:** 開発者が自己署名証明書の社内 GitLab サーバー向けに `GITLAB_MCP_SKIP_TLS_VERIFY=true` を有効化した状態で共有 Wi-Fi/VPN を利用すると、MITM により GitLab PAT トークンが窃取される。<br/>**シナリオ B:** CI/CD 環境でこのフラグを常時有効にすると、偽装された GitLab API レスポンスにより MCP エージェントへ悪意あるデータが注入される。<br/>**シナリオ C:** PR ラベルワークフローの `pull_request_target` に将来 `checkout` が追加されると危険が生じる。 | **低（任意設定）**<br/>`python3 scripts/sniper-project-audit ./gitlab-mcp-server` |
| **7. `apktool-mcp`** | 閾値超え `16` 件（`SAST 中1`、`SCA 重大4 / 高12`） | SAST のプライバシー警告は誤検知。**`uv.lock` 内に重大 4 件・高 12 件の SCA 依存関係アドバイザリが存在**（`starlette 0.46.2`、`h11 0.14.0`、`fastmcp 2.2.0`、`mcp 1.6.0`） | **シナリオ A:** 悪意ある、または破損した APK の解析時に、古い `starlette`/`h11` の HTTP パーサー脆弱性を突かれて MCP サーバーでサービス拒否（DoS）やリクエストスマグリングが発生する。<br/>**シナリオ B:** 古い `mcp`/`fastmcp` バージョンのセッション・検証不備がローカルエージェントブリッジに影響する。<br/>**シナリオ C:** 未更新の `certifi`/`anyio` パッケージがトランスポート層の信頼性を低下させる。 | **低 / 中（SCA 依存関係リスク）**<br/>`python3 scripts/sniper-project-audit ./apktool-mcp` |
| **8. `jadx-mcp`** | 閾値超え `32` 件（`SAST 中3`、`SCA 重大6 / 高26`） | 確認済みの重大/高 SAST 脆弱性なし。**`uv.lock` 内に重大 6 件・高 26 件の SCA 依存関係アドバイザリが存在**（`authlib 1.6.8`、`cryptography 46.0.5`、`pyjwt 2.11.0`、`python-multipart 0.0.20`、`starlette 0.47.3`、`urllib3 2.5.0`） | **シナリオ A:** マルチパートのファイル／APK アップロードエンドポイントで、古い `python-multipart` と `starlette` によりメモリ／CPU 枯渇（DoS）が引き起こされる。<br/>**シナリオ B:** 古い `authlib` と `pyjwt` の検証不備により、認証付き MCP 導入環境でのトークン検証が弱体化する。<br/>**シナリオ C:** `urllib3` のリダイレクトヘッダー漏洩や `cryptography` の CVE が外部通信を危険にさらす。 | **低 / 中（SCA 依存関係リスク）**<br/>`python3 scripts/sniper-project-audit ./jadx-mcp` |

全 8 リポジトリのファイル・行単位の完全なエビデンス審査、`シナリオ A / B / C` の詳細、実行コマンド例、および macOS 検証の詳細については、[SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.ja.md](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.ja.md) を参照してください。

#### Sniper スキャンで発見・検証された脆弱性一覧（11 件の確認済みアドバイザリ）

当社の **Sniper** 静的／動的解析エンジンによるセキュリティ監査で発見され、**コードの不具合がどのように脆弱性へ変化するか**、**日常業務で起こり得る 3 つの重大なシナリオ（`シナリオ A / B / C`）**、**検証コマンド例**、および **エンドツーエンドのランタイム証明（`RED -> GREEN + BENIGN`）** によって実証された **11 件のセキュリティ脆弱性**（[advisories/README.ja.md](advisories/README.ja.md) および [SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.ja.md](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.ja.md)）を以下に公開します：

| # | アドバイザリ文書 & Upstream GHSA | 対象プロジェクト & コンポーネント | CWE & CVSS v3.1 | コードで脆弱性が生じる仕組み & 日常業務での 3 つの重大シナリオ（`シナリオ A / B / C`） | ランタイム証明（`RED -> GREEN`） & 実行コマンド例 |
| :-: | :--- | :--- | :--- | :--- | :--- |
| **01** | [`01-STIRLING-CAND-02-SYMLINK.md`](advisories/ja/01-STIRLING-CAND-02-SYMLINK.md)<br/>`GHSA-hpc7-xx5r-gc44` | **Stirling-Tools/Stirling-PDF** (`<= 3.2.2`)<br/>`FolderInputSource.java:337-377`<br/>`FolderOutputSink.java:338-345` | `CWE-59` / `CWE-61`<br/>**7.1 High** | **コード上の原因:** デフォルトの `recursive=false` モードで `Files.isRegularFile(entry)`（`LinkOption.NOFOLLOW_LINKS` なし）がシンボリックリンクを追跡する一方、`FolderAccessGuard.isProtected` はシンボリックリンク自体の字句パスのみを検査する。<br/>**シナリオ A:** 社内 SMB/NFS 共有スキャナーフォルダーに置かれた `invoice.pdf -> ../configs/settings.yml` シンボリックリンク経由で、管理者パスワードと OAuth シークレットが共有出力フォルダーへ流出する。<br/>**シナリオ B:** SFTP/Nextcloud の外部パートナー用アップロードフォルダーのシンボリックリンクからサーバーの `.env` や SSH 鍵が読み取られる。<br/>**シナリオ C:** `FolderOutputSink.archiveOriginal()` が設定ファイル本体をアーカイブフォルダーへ移動（`Files.move`）してサービスを停止させる。 | `RED`: `symlink_accepted: true, protected_settings_exfiltrated: true`<br/>`GREEN`: `symlink_accepted: false`<br/>`pytest -k test_stirling_cand02` |
| **02** | [`02-STIRLING-CAND-01-WEASYPRINT-SSRF.md`](advisories/ja/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)<br/>`GHSA-ff6j-8xch-j8r6` | **Stirling-Tools/Stirling-PDF** (`<= 3.2.2`)<br/>`ConvertWebsiteToPDF.java:116-143` | `CWE-918`<br/>**8.6 High** | **コード上の原因:** `CVE-2026-71270` の修正で `FileToPdf.java` 内の WeasyPrint は `--allowed-protocols data` に制限されたが、兄弟エンドポイント `/api/v1/convert/url/pdf`（`ConvertWebsiteToPDF.java`）は依然として `--allowed-protocols data,http,https` を渡し、`customHtmlSanitizer` も呼び出さない。<br/>**シナリオ A:** 請求書・領収書 URL を PDF 化する機能に渡された外部ページ内の `<link rel="stylesheet" href="http://169.254.169.254/...">` により、クラウド IAM 認証情報が生成 PDF に埋め込まれる。<br/>**シナリオ B:** 社内イントラネット上の内部マイクロサービス（`http://127.0.0.1:8080/actuator/env`）の応答が PDF 経由で外部へ持ち出される。<br/>**シナリオ C:** 悪意ある `@import`／`<img>` サブリクエストにより内部ポートスキャンや認証なし内部管理画面の PDF 化が行われる。 | `RED`: `internal_data_embedded_in_pdf: true`<br/>`GREEN`: `internal_loopback_hit_count: 0`<br/>`pytest -k test_stirling_cand01` |
| **03** | [`03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md`](advisories/ja/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)<br/>`GHSA-cp36-x5hg-3gg8` | **trycua/cua** (`npm: cuabot <= 1.0.16`)<br/>`libs/cuabot/src/cuabotd.ts` | `CWE-306` / `CWE-942`<br/>**9.6 Critical** | **コード上の原因:** `cuabotd.ts` がバックグラウンドで `0.0.0.0:7842` を認証なしで開き、全レスポンスに `Access-Control-Allow-Origin: *` を付与し、ホストの `~/.cuabot/user/.claude` ディレクトリを読み書き可能でマウントする。<br/>**シナリオ A:** 開発者が `cuabot` 起動中に任意の Web サイトを閲覧すると、ページ内の JS が `fetch("http://localhost:7842/bash")` でコマンドを実行し Claude OAuth 認証情報を窃取する。<br/>**シナリオ B:** 閲覧した Web ページが `ws://localhost:7842/?command=...`（CSWSH）経由で `.claude/settings.json` に永続的な `PreToolUse` フックを仕込む。<br/>**シナリオ C:** カフェ、コワーキングスペース、社内 Wi-Fi（`0.0.0.0:7842`）上の任意の端末が直接 `http://<lan-ip>:7842/bash` や `/screenshot` を呼び出して PC を乗っ取る。 | `RED`: `http_status: 200, mounted_host_claude_credentials_exfiltrated: true`<br/>`GREEN`: `http_status: 403`<br/>`pytest -k test_cua_cand01` |
| **04** | [`04-CUA-CAND-02-WORKER-SERVER-RCE.md`](advisories/ja/04-CUA-CAND-02-WORKER-SERVER-RCE.md)<br/>`GHSA-xm8w-gj3g-4f25` | **trycua/cua** (`pip: cua-bench-rl <= 0.1.0`)<br/>`worker_server.py:79-108, 338-360` | `CWE-94` / `CWE-942`<br/>**8.8 High** | **コード上の原因:** `worker_server.py` が `allow_origins=["*"]` を使用し、`ip_filter_middleware` がブラウザーから `127.0.0.1` へ届くクロスオリジン要求を遮断せず、`OSGYM_ALLOWED_IPS=""` が空の場合はフィルターがフェイルオープンになり、`POST /reset` が指定された `env_path/main.py` を `spec.loader.exec_module` で実行する。<br/>**シナリオ A:** 研究者がブラウザーで Web ページを開くと、`fetch("http://127.0.0.1:8001/reset")` によりダウンロード済みフォルダー内の `main.py` がホスト Python プロセスで実行される。<br/>**シナリオ B:** Kubernetes/Docker Compose 環境で `OSGYM_ALLOWED_IPS=""` が空のままの場合、クラスター／LAN 全体から `0.0.0.0:8001/reset` 経由でリモートコード実行が可能になる。<br/>**シナリオ C:** `/screenshot` と `/step` エンドポイント経由でデスクトップ画面の監視やマウス・キーボード操作の注入が行われる。 | `RED`: `arbitrary_env_path_exec_module_rce: true`<br/>`GREEN`: `403 / 400, rce: false`<br/>`pytest -k test_cua_cand02` |
| **05** | [`05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md`](advisories/ja/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)<br/>`GHSA-3x8g-6h2v-8qx9` | **trycua/cua** (`cargo: cua-compat <= 0.8.0`)<br/>`daytona/objectstore.rs:320-422` | `CWE-22`<br/>**8.1 High** | **コード上の原因:** `object_path(&key)` はオブジェクトキーの `..` を拒否するが、`?uploadId=` パラメータは一切検証されず、`Method::DELETE` 分岐は `uploads.remove(&id)` の結果に関わらず無条件で `tokio::fs::remove_dir_all(root.join("uploads").join(&id))` を実行する。<br/>**シナリオ A:** マルチテナント環境で 1 つのサンドボックステナントが `DELETE /daytona/x?uploadId=../objects` を送信し、組織全体のサンドボックスイメージを 1 リクエストで消去する。<br/>**シナリオ B:** `?uploadId=../../...` で `d.objects.root` の外へ脱出し、`cua-spacesd` プロセスが書き込み可能なホストディレクトリや DB ファイルを削除する。<br/>**シナリオ C:** 自動アップロード中断（`AbortMultipartUpload`）時に他テナントの進行中アップロード（`uploads/`）やステージング（`stage/`）フォルダーを破壊する。 | `RED`: `objects_store_wiped_without_prior_upload: true`<br/>`GREEN`: `objects_store_preserved: true`<br/>`pytest -k test_cua_cand03` |
| **06** | [`06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md`](advisories/ja/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)<br/>`GHSA-54v9-fxw3-36mm` | **trycua/cua** (`cargo: cua-media-codec <= 0.8.0`)<br/>`videotoolbox/mod.rs:308-420` | `CWE-125` / `CWE-190`<br/>**5.5 Medium** | **コード上の原因:** Safe Rust の `VtEncoder::encode` -> `pixel_buffer_for` 内で、`FrameData::Nv12`（`y` と `uv` スライス）および `FrameData::Bgra` のスライス長を検証せずに `unsafe { std::ptr::copy_nonoverlapping }` を呼び出す。<br/>**シナリオ A:** macOS リモートデスクトップ配信でのウィンドウ／解像度変更時、短い `NV12` バッファにより隣接ヒープメモリ上の `960` バイトの機密情報が H.264 ビデオフレームへコピーされ視聴側へ配信される。<br/>**シナリオ B:** 破損または空の `VideoFrame` が届くと `cua-spacesd` メディアサービスが `SIGSEGV` でクラッシュし、全リモートデスクトップセッションが切断される。<br/>**シナリオ C:** 複数セッションを収容する macOS エージェントサーバーで、境界外読み取りにより別セッションのヒープデータが映像ストリームに混入する。 | `RED`: `oob_bytes_read: 960, adjacent_heap_secret_copied_to_video_frame: true`<br/>`GREEN`: `oob_bytes_read: 0`<br/>`pytest -k test_cua_vt01` |
| **07** | [`07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md`](advisories/ja/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)<br/>`GHSA-hvhg-6x47-cq96` | **trycua/cua** (`pip: cua-bench <= 0.3.1`)<br/>`winarena_adapter/cli.py:262-265` | `CWE-668` / `CWE-732`<br/>**8.6 High** | **コード上の原因:** `cli.py` が Docker コンテナ起動時に `-p 8006:8006`（認証なし noVNC）と `-p 3390:3389`（パスワードなし RDP）を `0.0.0.0` にバインドし、ホストの `setup_path` を `-v {setup_path}:/shared` として読み書き可能でマウントする。<br/>**シナリオ A:** 大学やオフィス LAN 上の第三者がブラウザーで `http://<ip>:8006` を開き、Windows VM デスクトップと内部の API キーを平文のまま乗っ取る。<br/>**シナリオ B:** VM 内に侵入した攻撃者が `/shared`（`setup_path`）マウント経由でホスト側のセットアップスクリプトを書き換え、ホスト OS へ侵害を広げる。<br/>**シナリオ C:** VM 内の `server/main.py:180`（`POST /execute_windows` -> `exec()`）が認証なしで動作するため、エージェントが悪意あるページを開くと VM 内で任意のコマンドが実行される。 | `RED`: `lan_exposed_ports: ["8006:8006", "3390:3389"]`<br/>`GREEN`: `lan_exposed_ports: []`<br/>`pytest -k test_cua_cand06` |
| **08** | [`08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md`](advisories/ja/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)<br/>`GHSA-qwv8-hh9r-cqrf` | **openziti/ziti** (`github.com/openziti/ziti/v2`)<br/>`ziti/util/certs.go:91-103, 199-208` | `CWE-295`<br/>**7.4 High** | **コード上の原因:** `ziti edge login` 内の `AreCertsTrusted()` が呼び出す `InsecureClient(&client, certs)` が無条件で `InsecureSkipVerify: true` を設定するため、Go の `crypto/tls` が `RootCAs` プールを無視し、`x509.UnknownAuthorityError` チェックがデッドコード化する。<br/>**シナリオ A:** 管理者が `ziti edge login` を実行した際、中間者（MITM）攻撃者の偽証明書が *"Verified that server supplied certificates are trusted"* として受け入れられ、管理者パスワードが攻撃者へ送信される。<br/>**シナリオ B:** CI/CD パイプラインでゼロトラスト ID 登録を自動実行するジョブが偽の Edge Controller に接続し、本番サービストークンを漏洩する。<br/>**シナリオ C:** マルチリージョンの DNS/BGP ルーティング変動時に、クライアントが証明書警告なしに侵害されたコントローラーへログインしてしまう。 | `RED`: `rogue_mitm_cert_accepted_as_trusted: true`<br/>`GREEN`: `x509.UnknownAuthorityError`<br/>`pytest -k test_ziti_cand01` |
| **09** | [`09-N8N-CAND-01-WEBHOOK-REDOS.md`](advisories/ja/09-N8N-CAND-01-WEBHOOK-REDOS.md)<br/>`n8n-io/n8n` | **n8n-io/n8n** (`npm: n8n-workflow <= 2.45.0`)<br/>`string-extensions.ts:94, 326, 375` | `CWE-1333`<br/>**5.3 Medium** | **コード上の原因:** `string-extensions.ts` 内の `isEmail()`、`extractDomain()`、`extractEmail()` が、入力長制限なしに先頭アンカーのない入れ子量指定子付き正規表現をシングルスレッドの Node.js イベントループ上で実行する。<br/>**シナリオ A:** 外部公開の問い合わせ／登録 Webhook に送信された 20 KB の JSON リクエスト 1 件で Node.js イベントループが約 832 ms 停止し、同一サーバー上のすべての Stripe 決済・Slack Webhook が停止する。<br/>**シナリオ B:** 受信サポートメールやチャットを `{{ $json.text.extractEmail() }}` で解析するフローがハングし、Kubernetes の Liveness Probe タイムアウトによりコンテナ再起動が繰り返される。<br/>**シナリオ C:** マルチテナントの n8n サーバーで低権限ワークフローが V8 CPU コアを占有し、重要な本番ワークフローを枯渇させる。 | `RED`: `regex_stall_ms: 165.035, concurrent_webhook_starved: true`<br/>`GREEN`: `regex_stall_ms: 0.017`<br/>`pytest -k test_n8n_cand01` |
| **10** | [`10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md`](advisories/ja/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)<br/>`GHSA-cc9f-m5vr-pm75` | **gotify/server** (`<= v2.9.1`)<br/>`router/router.go:52-73, 93-102` | `CWE-601`<br/>**4.7 Medium** | **コード上の原因:** `SSL.Enabled=true` かつ `SSL.RedirectToHTTPS=true` のとき、`router.go` のリダイレクトミドルウェアが設定済みの `LetsEncrypt.Hosts` ではなく未検証の `ctx.Request.Host` ヘッダーから直接 `308 Permanent Redirect` の `Location` を生成する。<br/>**シナリオ A:** 攻撃者が `Host: phish-gotify.example` ヘッダーで `308 Permanent Redirect` 応答をキャッシュ汚染し、ユーザーのブラウザーを偽のログインページへ永続的に誘導する。<br/>**シナリオ B:** `http://gotify-host/message?token=<app-token>` にリクエストを送るリダイレクト追従クライアント（`curl -L` や通知スクリプト）が、`308` 応答によってアプリトークンを攻撃者サーバーへ漏洩する。<br/>**シナリオ C:** `Host` ヘッダーを転送するリバースプロキシ配下で、通知やクライアント接続が攻撃者のドメインへリダイレクトされる。 | `RED`: `status_code: 308, redirected_to_untrusted_host: true`<br/>`GREEN`: `redirected_to_untrusted_host: false`<br/>`pytest -k test_gotify_cand01` |
| **11** | [`11-XROAD-CAND-01-RUNNER-INJECTION.md`](advisories/ja/11-XROAD-CAND-01-RUNNER-INJECTION.md)<br/>`GHSA-4fcw-7xqx-fjv5` | **nordic-institute/X-Road** (`38cd99ec0ebb`)<br/>`_build-and-package.yml:84-91` | `CWE-78`<br/>**8.5 High** | **コード上の原因:** `build.yaml`（`secrets: inherit`、`packages: write`）から呼び出され、永続的な `xrd-runner-8c` セルフホストランナー上で動作する `_build-and-package.yml` が、`${{ github.head_ref }}` を二重引用符付きの bash `run:` ブロック内に直接展開する。<br/>**シナリオ A:** 細工したブランチ名（`feat";...;#`）で開かれた PR により、コードレビューが始まる前に永続的な `xrd-runner-8c` サーバー上でシェルコマンドが実行される。<br/>**シナリオ B:** `build.yaml` が `secrets: inherit` と `packages: write` を引き渡すため、注入されたコマンドから GHCR パッケージ書き込みトークンやリポジトリシークレットへアクセスされる。<br/>**シナリオ C:** 永続的な `xrd-runner-8c` ビルドサーバー上のローカル Gradle/Docker キャッシュが汚染され、以降の公式 X-Road リリースパッケージにバックドアが混入する。 | `RED`: `arbitrary_command_executed_on_self_hosted_runner: true`<br/>`GREEN`: `env_var_parameterized: true`<br/>`pytest -k test_xroad_cand01` |
| **12** | [`12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md`](advisories/ja/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md)<br/>`GITLAB-CAND-02`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/oauth/device_authorizations_controller.rb:4-50`<br/>`app/controllers/oauth/tokens_controller.rb:42-75` | `CWE-863 / CWE-285`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` | **How It Happens in Code:** `Oauth::DeviceAuthorizationsController` (`device_authorizations_controller.rb:4-50`) and `Oauth::TokensController` (`tokens_controller.rb:42-75`) omit `verify_admin_allowed!`, `verify_confirmed_email!`, `set_current_organization`, and `enforce_organization_maintenance_mode` (all enforced in sibling `Oauth::AuthorizationsController`).<br/>**Scenario A (Full Instance Admin Takeover):** A regular user creates an untrusted OAuth app (`trusted: false`); when an admin enters its `user_code` on `/oauth/device`, GitLab bypasses `disable_admin_oauth_scopes=true` and mints a full `api admin_mode` token allowing complete server takeover, private repo theft, and CI secret extraction.<br/>**Scenario B (Unverified Account API Backdoor):** An unconfirmed account (`confirmed_at: nil`) blocked on `/oauth/authorize` (`403`) mints persistent API & refresh tokens via `/oauth/device`.<br/>**Scenario C (Backdoor Commit During Legal/Migration Freeze):** Attackers mint tokens and push commits (`201 Created`) into frozen repositories while an organization is locked in `migration` (`503`) or `legal` (`403`) maintenance mode. | `RED`: `token_minted_admin_mode: true, post_token_admin_action_succeeded: true`<br/>`GREEN`: `503 / 403, token_minted_admin_mode: false`<br/>`pytest -k test_report1_cand02` |
| **13** | [`13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md`](advisories/ja/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md)<br/>`GITLAB-CAND-05`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/catalog/mcp_servers/callback_service.rb:17-50, 87-129`<br/>`refresh_token_service.rb:18-70`<br/>`dynamic_registration_client.rb:104-136` | `CWE-918 / CWE-209`<br/>**8.5 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `CallbackService`, `RefreshTokenService`, `RevokeTokenService`, and `DynamicRegistrationClient` accept unvalidated RFC 8414 `token_endpoint`/`revocation_endpoint` URLs and use `OAuth2::Client` (`max_redirects: 5`, no `UrlBlocker`), reflecting raw `OAuth2::Error` bodies into `flash[:alert]`.<br/>**Scenario A (Stealing Cloud IAM Keys via `flash[:alert]`):** A `307 Temporary Redirect` on `token_endpoint` hits `169.254.169.254` or `127.0.0.1` and prints cloud IAM credentials / internal API responses directly into the user's `flash[:alert]` banner.<br/>**Scenario B (Internal `POST` SSRF & Secret Replay):** `OAuth2::Client` replays `POST` requests with `client_secret` and `refresh_token` to firewalled internal `127.0.0.1` services.<br/>**Scenario C (`RevokeTokenService` SSRF):** Disconnecting an MCP server posts Basic Auth credentials to unvalidated internal/external `revocation_endpoint` targets. | `RED`: `canary_b_request_count: 5, iam_role_credentials_exposed: true`<br/>`GREEN`: `canary_b_request_count: 0, iam_role_credentials_exposed: false`<br/>`pytest -k test_report2_cand05` |
| **14** | [`14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md`](advisories/ja/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md)<br/>`GITLAB-CAND-06`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/controllers/oauth/mcp_connectors_auth_controller.rb:16-78`<br/>`ee/app/services/ai/catalog/mcp_servers/connect_service.rb:16-79`<br/>`ee/lib/gitlab/oauth/client_state.rb:17-23` | `CWE-639 / CWE-862`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | **How It Happens in Code:** `Oauth::McpConnectorsAuthController` calls global `Ai::Catalog::McpServer.find(params[:id])` without `.in_organization(Current.organization)`, `ConnectService` overwrites DCR credentials without checking `update_ai_catalog_mcp_server`, and `ClientState.from_state` discards `data` binding.<br/>**Scenario A (Cross-Organization AI Connector Hijack):** A user in Organization A overwrites `oauth_client_id` / `oauth_client_secret` on an `McpServer` belonging to Organization B.<br/>**Scenario B (Read-Only User Overwrites Production Connector):** A non-maintainer with read-only access overwrites company MCP OAuth credentials via DCR.<br/>**Scenario C (Cross-Session Account Binding / Login CSRF):** Replaying an unbound `ClientState` token binds a victim developer's GitLab session to the attacker's external MCP account. | `RED`: `cross_org_server_mutated: true`<br/>`GREEN`: `cross_org_server_mutated: false (404 RecordNotFound)`<br/>`pytest -k test_report2_cand05` |
| **15** | [`15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md`](advisories/ja/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md)<br/>`GITLAB-CAND-01`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:25-60, 101-112, 220-239` | `CWE-918 / CWE-522`<br/>**8.2 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `externalMcpTransport` in `workhorse/internal/ai_assist/duoworkflow/mcp.go:41-44` omits `transport.WithSSRFFilter()`, and `roundTripper.RoundTrip` (`mcp.go:101-104`) re-injects `Authorization: Bearer` headers on every redirect hop.<br/>**Scenario A (Bearer Token Theft & Account Takeover):** A `302` redirect from an external MCP server sends the victim's live `Authorization: Bearer` token to a cross-origin attacker server.<br/>**Scenario B (Workhorse Internal & Cloud Metadata SSRF):** Redirects reach `127.0.0.1` internal services or `169.254.169.254` from the Workhorse process.<br/>**Scenario C (DNS Rebinding into Corporate Intranet):** DNS rebinding bypasses initial URL validation because Workhorse's dialer lacks `WithSSRFFilter`. | `RED`: `bearer_token_leaked_to_canary: true`<br/>`GREEN`: `bearer_token_leaked_to_canary: false, ssrfFilterError: disallowlist`<br/>`pytest -k test_report2_cand05` |
| **16** | [`16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md`](advisories/ja/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md)<br/>`GITLAB-CAND-08`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:131-135`<br/>`ee/lib/api/ai/duo_workflows/workflows.rb:341-344, 1065`<br/>`connection_config_service.rb:220-228` | `CWE-862 / CWE-639`<br/>**7.7 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `McpConfigService#item_version` (`mcp_config_service.rb:134`) omits `Ability.allowed?(current_user, :read_ai_catalog_item, item_version)` (enforced at line 334), and `workflows.rb:1065` (`GET /ws`) allows overriding `workflow_definition` and `ai_catalog_item_version_id`.<br/>**Scenario A (Escalating Read-Only `chat` to Write-Capable Agent):** Overriding `workflow_definition` and `ai_catalog_item_version_id` on `/ws` injects withheld write tools (`create_issue`) into a restricted `chat` session.<br/>**Scenario B (Stealing Private `public: false` Agent Toolsets):** Enumerating `ai_catalog_item_version_id` discloses the confidential toolset of foreign private AI Catalog agents.<br/>**Scenario C (Unauthorized Private Agent Binding):** `POST /workflows` binds private cross-organization `ItemVersion` records without `:read_ai_catalog_item` checks. | `RED`: `unapproved_write_tool_injected: true, workflow_definition_overridden: true`<br/>`GREEN`: `unapproved_write_tool_injected: false`<br/>`pytest -k test_report3_cand08` |
| **17** | [`17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md`](advisories/ja/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md)<br/>`GITLAB-CAND-07`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:57-64`<br/>`ee/app/services/ai/catalog/mcp_servers/list_service.rb:14-24`<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:254` | `CWE-863 / CWE-639`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L` | **How It Happens in Code:** `McpConfigService#execute` (`mcp_config_service.rb:61`) calls `.merge(ai_catalog_mcp_servers.except(:orbit))` without excluding `:gitlab`, and `ListService`/`Agent::Create` omit `.in_organization`.<br/>**Scenario A (Unlocking All Prohibited Built-in GitLab MCP Tools):** An `Ai::Catalog::McpServer` named `"GitLab"` (`:gitlab`, `Tools: nil`) overwrites the built-in `:gitlab` entry so Workhorse (`mcp.go:254`) sets `allToolsAvailable = true`, disabling all `withheld_server_tools` restrictions.<br/>**Scenario B (Cross-Org MCP Server Binding):** GraphQL `aiCatalogAgentCreate`/`Update` binds foreign-organization `McpServer` Global IDs.<br/>**Scenario C (Duo Workflow `401` DoS):** Overwriting `Headers` on `:gitlab` strips `X-Gitlab-Oauth-Token` and breaks `/api/v4/mcp`. | `RED`: `builtin_gitlab_overwritten: true, workhorse_all_tools_available: true`<br/>`GREEN`: `builtin_gitlab_overwritten: false, workhorse_all_tools_available: false`<br/>`pytest -k test_report4_cand07` |
| **18** | [`18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md`](advisories/ja/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md)<br/>`GITLAB-CAND-04`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/projects/integrations/slash_commands_controller.rb:21-48`<br/>`app/models/concerns/integrations/base/slash_commands.rb:6-10, 68-76` | `CWE-601 / CWE-863`<br/>**5.4 Medium**<br/>`AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | **How It Happens in Code:** `SlashCommandsController#confirm` (`slash_commands_controller.rb:23-48`) redirects to unvalidated `request_params[:redirect_url]`, passes `request_params[:response_url]` to `VerifyRequest`, and keys Redis `CACHE_KEY` only by `command_id` without `project_id`/`integration_id`.<br/>**Scenario A (Corporate SSO Phishing After Slash Command Confirm):** Confirming a slash command on the trusted GitLab domain redirects (`302 Found`) the developer to an external credential-harvesting page.<br/>**Scenario B (Cross-Project ChatOps Account Binding):** A `command_id` minted in Project B is accepted on Project A's `/slash_commands/confirm` endpoint.<br/>**Scenario C (ChatOps Callback Hijack):** `request_params[:response_url]` overrides the cached `response_url` during `VerifyRequest#approve!`. | `RED`: `http_status: 302, open_redirect_triggered: true, cross_project_cache_collision_accepted: true`<br/>`GREEN`: `404, open_redirect_triggered: false`<br/>`pytest -k test_report5_cand04` |
| **19** | [`19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md`](advisories/ja/19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md)<br/>Upstream Duplicate: `CVE-2026-40295`<br/>*(GitHub Only — Not Submitted to MITRE)* | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`lib/gitlab/devise_failure.rb:4-18`<br/>`lib/gitlab/auth/session_expire_from_init_enforcer.rb:44-62`<br/>`app/controllers/oauth/authorizations_controller.rb:316-330` | `CWE-601 / CWE-345`<br/>**5.4 Medium (Upstream CVE-2026-40295 Duplicate)**<br/>`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | **[UPSTREAM DUPLICATE: `CVE-2026-40295` — Published on GitHub Only, Not Submitted to MITRE]**<br/>**How It Happens in Code:** `Gitlab::DeviseFailure` inherits `Devise 5.0.3` `redirect_url` (`CVE-2026-40295`), which redirects to an unsanitized external `Referer` on non-GET `:timeout` failures; `AuthorizationsController#validate_pkce_for_dynamic_applications` (`CAND-03`) has an early return on `nil` `code_challenge_method` (mitigated at runtime by `Doorkeeper 5.9.3`).<br/>**Scenario A/B/C:** Product-level `extract_path_from_location(request.referrer)` override in `lib/gitlab/devise_failure.rb` and controller-level PKCE defense-in-depth patch. | `DUPLICATE OF CVE-2026-40295` *(Not submitted to MITRE)*<br/>`RED`: `external_referer_redirect: true`<br/>`GREEN`: `path_extracted_only: true` |

## 検証とテスト

公開機能概要、再現可能な最新の Community 検証スナップショット、エビデンスの境界、および解釈ガイドについては [VALIDATION.md](../VALIDATION.md) を参照してください。

Community のドキュメント／メタデータ検証ゲートはオフラインかつ読み取り専用で実行できます：

```bash
python3 .github/scripts/validate-community-release.py
```

レビュー可能なソース配布物をこのチェックアウト外の新しいディレクトリにビルドし、組み立てられたツリーを検証するには：

```bash
python3 scripts/build-community-source.py --output /ABSOLUTE/PATH/TO/sniper-community-source
python3 .github/scripts/validate-community-release.py \
  --root /ABSOLUTE/PATH/TO/sniper-community-source --scan-release-tree
```

リポジトリの完全なローカルテストランチャーは次のとおりです：

```bash
python3 -m pip install --no-deps -r requirements-runtime.lock -r requirements-test.lock
python3 scripts/run_all_tests.py
```

一部の任意エンジンには、別途インストールされバージョン固定されたローカルツールが必要です。スキップされた任意統合テストは、そのエンジンがお使いのマシンで動作することの証明にはなりません。

## よくある質問

### Sniper Community とは何ですか？

Sniper Community は、許可されたソースコード、依存関係、SBOM、コンテナ、インフラ、Web サイト、API のレビュー向けの Apache-2.0 オープンソース・アプリケーションセキュリティツールキットです。ローカルアナライザーと保存済みレポートワークフローを、CLI、ループバック Web インターフェース、および Model Context Protocol（MCP）による任意の AI 支援レビューと統合します。[機能マップ](CAPABILITIES.md)で内蔵チェック、任意エンジン、手動レビューを区別しています。

### AI サブスクリプションなしで Sniper を使えますか？

はい。CLI とローカル Web インターフェースには AI クライアントは不要です。任意の MCP クライアントは独自のモデル提供者に接続できますが、その提供者の可用性、プライバシールール、料金は Sniper のソースライセンスとは別です。ローカルハードウェアや任意のサードパーティ製ツールにも独自の要件があります。

### Windows、macOS、Linux で使用できますか？

はい。Python 3.12 がテスト済みインタープリターです。Linux ARM64 および x86-64 では完全なネイティブ 5 エンジン構成をサポートします。**macOS（Apple Silicon）**では、ネイティブのソースセットアップ（`python3 scripts/setup-community --core-only`）と 5 エンジンの Docker Desktop プロファイル（`./scripts/deploy-community-tools --accept-third-party-licenses`）の **両方が実機で検証され、正式にサポートされています（実験的ではありません）**。**Windows** では、ネイティブの `--core-only` ソースセットアップ（`python3 scripts/setup-community --core-only`）、WSL2、および Docker Desktop の Linux コンテナをサポートしています。プラットフォームの詳細は [導入ガイド](../DEPLOYMENT.md) と [検証エビデンス](../VALIDATION.md) を参照してください。

### Web サイトの脆弱性をスキャンできますか？

はい。所有しているか、または明示的な評価許可を得た Web サイトと API に対して利用できます。対応ワークフローは限定的な外部ターゲットアクションを準備し、Web と TLS のエビデンスをローカルのソース分析と組み合わせ、レビュー可能な所見を生成します。該当するエンジン、固定カタログまたは脆弱性データ、ランタイム準備確認、および人間の承認が必要です。[Web サイト／API ワークフロー](USE-CASES.md#plan-an-authorized-website-or-api-action) と [機能の境界](CAPABILITIES.md) を参照してください。あらゆる脆弱性の発見を保証するツールは存在しません。

### モバイルアプリの脆弱性発見と修正に役立ちますか？

Sniper は、対応する Android、iOS、Flutter、React Native のコード、マニフェスト、依存関係、API 経路、リリース設定のレビューを支援します。App Store や Google Play へのリリース前に、エビデンスを優先順位付きの修正作業へと変換します。カバー範囲は対応する入力に依存し、あらゆるモバイルバイナリの万能スキャン、すべての脆弱性の自動修復、またはアプリストア審査通過の保証ではありません。[公開前のセキュリティレビュー](#公開前に-ai-でセキュリティレビュー) と [機能マップ](CAPABILITIES.md) を参照してください。

### Sniper はペネトレーションテストの代わりや安全なリリースの保証になりますか？

いいえ。Sniper は潜在的な認可不備や IDOR の問題を含むエビデンスとレビュー候補を生成します。資格のあるレビュアーが重要な所見を検証し、許可された範囲内でランタイム制御をテストし、修正内容を決定する必要があります。スキャン結果がクリーンであることはセキュリティ認証ではありません。[検証エビデンス](../VALIDATION.md) を参照してください。

### 公式ソースとインストール手順はどこにありますか？

公式ソースリポジトリは [dytredline/Sniper](https://github.com/dytredline/Sniper) です。お使いのプラットフォーム向けの [ソースチェックアウトからのセットアップ](#ソースチェックアウトからのセットアップ) と [導入ガイド](../DEPLOYMENT.md) から始めてください。プロジェクトは [ConverserAI](https://converserai.com/#sniper) で紹介されていますが、機能、プラットフォームサポート、ライセンス条項、リリースエビデンスの正式な情報源はこのリポジトリです。研究や公開物でソフトウェアを引用する際は [CITATION.cff](../CITATION.cff) を使用してください。

## ライセンス

Sniper Community は Apache License 2.0（`Apache-2.0`）の下でライセンスされています。完全な条項については [LICENSE](../LICENSE) を参照してください。サードパーティ製コンポーネントおよび任意ツールは、それぞれのライセンスに従います。
