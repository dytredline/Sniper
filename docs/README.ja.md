# Sniper Community

[English](../README.md) | [Türkçe](README.tr.md) | **日本語** | [简体中文](README.zh-CN.md) | [한국어](README.ko.md)

[ConverserAI のプロジェクト概要](https://converserai.com/#sniper) · [機能一覧](CAPABILITIES.md) · [セットアップ](#セットアップ) · [よくある質問](#よくある質問)

Sniper Community は、アプリケーション、API、Web サイトの開発者・所有者・レビュー担当者向けの、
オープンソースかつローカル優先の防御的アプリケーションセキュリティツールキットです。
対応するソースコードの静的解析（SAST）、依存関係と SBOM の分析（SCA）、コンテナ成果物、
Infrastructure as Code（IaC）、CI 設定、保存済みセキュリティレポートを、一つのレビュー経路にまとめます。
所有している、または明示的な許可を得た Web/API ターゲットについては、実行前に人が確認する限定的な
アクション計画を作成できます。結果はローカル stdio MCP 経由で AI クライアントから、CLI から、またはループバック Web インターフェースで確認できます。

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

**強力なオープンソースツールキットで Web サイトのセキュリティ弱点を発見しましょう。** 許可された Web サイトおよび API のスキャンとローカルのコード・依存関係レビューを組み合わせ、所見を優先順位付きの修正計画に変換します。外部スキャンには該当するエンジン、データ、準備確認、および明示的なスコープ承認が必要です。詳細は [Web サイトおよび API のレビュー経路](USE-CASES.md#plan-an-authorized-website-or-api-action)を参照してください。

App Store または Google Play への提出前に、AI アシスタントから Sniper のローカル stdio MCP に接続し、
対応する Android、iOS、Flutter、React Native のソースとモバイルマニフェストをレビューできます。
API 経路、シークレット、依存関係、SBOM、CI 設定を一つのリリース前ビューにまとめ、所見の説明と
修正優先順位付けに活用できます。同じ流れは Web サイト／API の公開前やリリース PR にも利用できます。

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

完全な機能一覧は [Capabilities and security checks](CAPABILITIES.md)、実践的な利用パスは [Use cases](USE-CASES.md)、AI 向け索引は [llms.txt](../llms.txt)、最新の検証エビデンスは [VALIDATION.md](../VALIDATION.md) を参照してください。

## セキュリティレビューの主な強み

- **影響の大きいデータフローを追跡:** SQL／コマンドインジェクション、XSS/HTML、SSRF、オープンリダイレクト、
  パストラバーサル、安全でないデシリアライズ、XXE、式言語（EL）、LDAP リスクのソースからシンクまでの経路を追跡します（SARIF `codeFlows` 対応）。
- **アクセス制御テストに集中:** ルート、ロール、オブジェクト識別子を整理し、IDOR（CWE-639）と認可チェック欠落（CWE-862）の
  手動検証を優先順位付けします。
- **露出したシークレットとプライバシー経路を検出:** シークレット値をマスクしたまま、ログ、レスポンス、ストレージ、外部送信先へのプライバシーデータフローを検出します。
- **依存関係とサプライチェーンを把握:** 直接・推移的コンポーネントのインベントリ作成、CycloneDX／SPDX SBOM の生成・インポート、
  VEX、到達可能性コンテキストを一つのレビューにまとめます。
- **コンテナ、クラウド、配信パイプラインを強化:** Dockerfile、Terraform、Kubernetes、Helm、Compose、クラウド IAM、CI、モバイル、ブラウザー拡張、
  デスクトップアプリのセキュリティ設定を確認します。
- **API、Web サイト、TLS をレビュー:** ローカルの OpenAPI 契約とソースルートを比較し、認証の不整合や Web/TLS シグナルを評価します。
- **重要な作業を優先順位付け:** CVSS 3.1/4.0、CISA SSVC、攻撃経路相関、担当者、期限、ベースライン、品質ゲートで対応順を整理します。
- **最適なワークフローを選択:** ループバック Web、CLI、CI、ローカル stdio MCP を通じて、JSON、HTML、SARIF、GitLab、SBOM、VEX、PDF ワークフローへ出力します。

## IDOR と手動ペネトレーションテストの支援

対応する Python および JavaScript/TypeScript のソースでは、組み込みのルート／認可インベントリが、
認可チェックの欠落候補（CWE-862）と Insecure Direct Object Reference（IDOR）の候補（CWE-639）を、
ファイル、ルート、行番号の根拠とともに提示します。これにより、許可を得たテスターは、別々のテストユーザー、
ロール、合成オブジェクトを使う手動ペネトレーションテストを優先順位付けできます。

各候補は、許可された範囲で、別々のテストユーザー／ロールと合成オブジェクトを使って手動検証するための
根拠付きの開始点になります。

## セキュリティレビューの主な強み

- 対応するデータフローから、SQL／コマンドインジェクション、XSS、SSRF、オープンリダイレクト、
  パストラバーサル、安全でないデシリアライズ、XXE などの重要なレビュー箇所を追跡します。
- ルート、ロール、オブジェクト識別子を整理し、IDOR（CWE-639）と認可チェック（CWE-862）の
  手動検証を優先順位付けします。
- シークレット候補とプライバシー関連フローを確認し、依存関係、コンテナ、CycloneDX／SPDX SBOM、
  VEX、到達可能性コンテキストを一つのレビューにまとめます。
- Dockerfile、Terraform、Kubernetes、Helm、Compose、クラウド IAM、CI、モバイル、ブラウザー拡張、
  デスクトップアプリのセキュリティ設定を確認します。
- CVSS 3.1/4.0、CISA SSVC、攻撃経路、ベースライン、品質ゲートで対応順を整理し、JSON、HTML、SARIF、
  GitLab、SBOM、VEX、対応する PDF ワークフローへ出力します。
- ループバック Web、CLI、CI、ローカル stdio MCP を通じて、同じエビデンスを人と AI が活用できます。

## IDOR と手動ペネトレーションテストの支援

対応する Python および JavaScript/TypeScript のソースでは、組み込みのルート／認可インベントリが、
認可チェックの欠落候補（CWE-862）と Insecure Direct Object Reference（IDOR）の候補（CWE-639）を、
ファイル、ルート、行番号の根拠とともに提示します。これにより、許可を得たテスターは、別々のテストユーザー、
ロール、合成オブジェクトを使う手動ペネトレーションテストを優先順位付けできます。

各候補は、許可された範囲で、別々のテストユーザー／ロールと合成オブジェクトを使って手動検証するための
根拠付きの開始点になります。

## 内蔵機能と任意のエンジン

内蔵アナライザー、レポートパーサー、MCP サーバー、CLI、ループバック Web UI はソースツリーに含まれます。
これらに加え、ルート権限を使わないローカルプロファイルでは、次の 7 つのバージョン固定された
サードパーティ製エンジンを任意で導入できます。

- Nuclei 3.11.1
- Trivy 0.75.0
- Gitleaks 8.30.1
- TruffleHog 3.99.0
- Syft 1.55.0
- Grype 0.121.0
- Opengrep 1.30.1

任意エンジンは、それぞれの実行ファイル、SHA-256、必要データ、入力範囲、ライセンスの準備確認に合格した場合に
のみ利用可能として表示されます。Nuclei の広範な許可済み HTTP ワークフローには別途固定されたテンプレート
カタログが必要で、Trivy の脆弱性プロファイルには別途固定されたオフラインデータベースが必要です。
内蔵分析はこれら 7 エンジンとは別に提供されます。インターフェースと HTML レポートの多言語対応については [LOCALIZATION.md](LOCALIZATION.md) を参照してください。

## リリース状況と含まれる内容

このリポジトリは Sniper Community v1.1.0 のソースリリースであり、Apache License 2.0（[LICENSE](../LICENSE)）の下で提供されます。ローカルプロジェクト分析、ローカルレポートと品質ゲート、AI 優先の stdio MCP ワークフロー、状態変更アクションに対するチャット経由の人間承認ゲート、手動 CLI、ループバック Web UI、およびテストとドキュメントが含まれます。

## セットアップ

テスト済みのインタープリターは Python 3.12 です。Community v1 の完全なネイティブ 7 エンジンセットアップは Linux ARM64／x86-64 をサポートします。
**macOS（Apple Silicon）**では、ネイティブの `--core-only` ソースセットアップ（`python3 scripts/setup-community --core-only`）と、
Docker Desktop を用いた 5 エンジンプロファイル（`./scripts/deploy-community-tools --accept-third-party-licenses`）の**両方が実機で検証・サポートされています**（実験的ではありません）。
**Windows** では、ネイティブの `--core-only` ソースセットアップ（`python3 scripts/setup-community --core-only`）、WSL2、および Docker Desktop の Linux コンテナをサポートします（詳細は [VALIDATION.md](../VALIDATION.md) および [DEPLOYMENT.md](../DEPLOYMENT.md) を参照してください）。

Linux で固定依存関係と 7 つのローカルツールを導入・検証する場合：

```bash
python3 scripts/setup-community --accept-third-party-licenses
```

Linux、macOS、または Windows で任意エンジンを除いたネイティブのコアセットアップを行う場合：

```bash
python3 scripts/setup-community --core-only
```

Windows/macOS の Docker Desktop または WSL2 でコンテナイメージをビルドする場合：

```bash
docker compose build sniper
python3 scripts/build-community-tools-image --accept-third-party-licenses
```

macOS Apple Silicon + Docker Desktop で 5 つのエンジンすべてをビルド・起動・検証する場合は `./scripts/deploy-community-tools --accept-third-party-licenses` を実行し、Mac 上のプロジェクトを永続 Docker ボリュームへコピーする場合は `./scripts/import-community-project /absolute/path/to/project --name project-name` を使用します。セットアップ後の MCP ヘルプ確認は `.venv/bin/python scripts/sniper-mcp --help`、手動 CLI は `python3 scripts/sniper-project-audit --help` および `python3 cli_reports.py --help` です。詳細は [Community ツールの導入](COMMUNITY-TOOLS.md)を参照してください。

## MCP、CLI、ローカル Web

- **MCP:** ローカルの stdio サーバー（`.venv/bin/python scripts/sniper-mcp --mode community`）を AI クライアントから利用し、所見の説明や対応アクションの準備を依頼できます。
- **CLI:** ローカルレビュー、CI ゲート、レポート出力を手動またはスクリプトから実行できます。
- **ローカル Web:** ループバック UI（`127.0.0.1:8787`）で、準備済み機能だけを人が選択・レビューできます。

状態を変更する Community MCP アクションは 2 段階です。`prepare_action` が不変の計画、同意範囲、有効期限、
SHA-256 を返し、AI はその計画をそのまま人に提示します。人が同じ会話で明示的に承認した後に限り、MCP ホストは
同一の計画で `execute_action` と `user_confirmed: true` を送れます。AI が自分で承認してはいけません。
詳細は [Community MCP ガイド](COMMUNITY-MCP.md)を参照してください。

## 安全性と許可の境界・検証レポート

- 自分が所有するシステム、または評価の明示的な許可を得たシステムにだけ使用してください。
- 外部アクションの前に、対象、書面の範囲、時間帯、レート制限、データ処理、停止条件を人が確認してください。
- MCP 自体はローカル stdio ですが、AI クライアントは選択したソースや所見をモデル提供者へ送信する場合があります。
- 「所見なし」は、選択した入力・有効なチェック・利用可能なデータの範囲だけを表し、安全証明ではありません。
- 秘密鍵、トークン、パスワード、顧客データ、本番データベースを issue や AI プロンプトに含めないでください。
- セキュリティメンテナー: **Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline))。脆弱性の非公開報告は [SECURITY.md](../SECURITY.md)、macOS 実機検証およびオープンソース 8 リポジトリ監査レポートは [VALIDATION.md](../VALIDATION.md) と [SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md](SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md) を参照してください。

## よくある質問

### Sniper Community とは何ですか？

Sniper Community は、許可されたソースコード、依存関係、SBOM、コンテナ、インフラ、Web サイト、API のレビュー向けの Apache-2.0 オープンソース・アプリケーションセキュリティツールキットです。[機能マップ](CAPABILITIES.md)で内蔵チェック、任意エンジン、手動レビューを区別しています。

### AI サブスクリプションなしで Sniper を使えますか？

はい。CLI とローカル Web インターフェースには AI クライアントは不要です。任意の MCP クライアントを使う場合、そのモデル提供者の料金やプライバシー規約は Sniper のライセンスとは別です。

### Windows、macOS、Linux で使用できますか？

はい。Python 3.12 がテスト済みインタープリターです。Linux ARM64／x86-64 では完全なネイティブ 5 エンジン構成をサポートします。**macOS（Apple Silicon）**では、ネイティブの `--core-only` ソースセットアップと Docker Desktop 5 エンジンプロファイルの**両方が実機で検証され、正式にサポートされています（実験的ではありません）**。**Windows** では、ネイティブの `--core-only` ソースセットアップ、WSL2、および Docker Desktop の Linux コンテナをサポートしています。詳細は [DEPLOYMENT.md](../DEPLOYMENT.md) と [VALIDATION.md](../VALIDATION.md) を参照してください。

### Web サイトの脆弱性をスキャンできますか？

はい。所有しているか明示的な評価許可を得た Web サイトと API に対して、限定された外部ターゲット計画を作成し、Web/TLS エビデンスとローカルのソース分析を組み合わせることができます。

### モバイルアプリの脆弱性発見と修正に役立ちますか？

はい。Android、iOS、Flutter、React Native の対応コード、マニフェスト、依存関係、API 経路、リリース設定をレビューし、App Store や Google Play への提出前に優先順位付きの修正作業へ変換できます。

### Sniper はペネトレーションテストの代わりや安全保証になりますか？

いいえ。Sniper はエビデンスとレビュー候補（認可や IDOR 候補を含む）を生成する防御支援ツールであり、資格のあるレビュアーによる検証が必要です。

### 公式ソースとインストール手順はどこにありますか？

公式リポジトリは [dytredline/Sniper](https://github.com/dytredline/Sniper)、プロジェクト紹介は [ConverserAI](https://converserai.com/#sniper)、引用情報は [CITATION.cff](../CITATION.cff)、ライセンスは Apache License 2.0（[LICENSE](../LICENSE)）です。
