# セルフホストランナー (xrd-runner-8c) 上の _build-and-package.yml における github.head_ref Bash スクリプトインジェクション (`GHSA-4fcw-7xqx-fjv5`)

[English](../11-XROAD-CAND-01-RUNNER-INJECTION.md) | [Türkçe](../tr/11-XROAD-CAND-01-RUNNER-INJECTION.md) | **日本語** | [简体中文](../zh-CN/11-XROAD-CAND-01-RUNNER-INJECTION.md) | [한국어](../ko/11-XROAD-CAND-01-RUNNER-INJECTION.md)

## 1. コードの欠陥がどのように悪用可能な脆弱性に変わるか

### ステップバイステップの技術的メカニズム
`nordic-institute/X-Road`（コミット `38cd99ec0ebbcc13ddbaaeb9187018d49bdd278b`）において、`.github/workflows/build.yaml:14-58` は `pull_request` イベントでトリガーされ、`permissions: contents: write, packages: write` および `secrets: inherit` を付与して `.github/workflows/_build-and-package.yml` を呼び出します。`_build-and-package.yml:27, 84-91` 内のジョブは永続的なセルフホストランナーフリート（`runs-on: labels: xrd-runner-8c`）上で実行され、`${{ github.head_ref }}` と `${{ github.ref_name }}` を bash `run:` スクリプト内へ直接展開します（`CWE-78`）。

1. **ステップ 1 — 実行前の YAML テンプレート直接展開 (`_build-and-package.yml:86-90`):**
   GitHub Actions は `/bin/bash` を起動する前に、`if [[ -n "${{ github.head_ref }}" ]]; then branch_name="${{ github.head_ref }}"` の中の `${{ github.head_ref }}` を文字列としてそのまま置換します。
2. **ステップ 2 — Git ブランチ名による二重引用符からの脱出:**
   Git のブランチ名には `"`、`;`、`$()`、`` ` `` などの文字を含めることができます。ブランチ名を `feat";<command>;#` とすると、87 行目は `branch_name="feat";<command>;#"` に書き換わり、二重引用符の代入文を抜け出して `<command>` がシェル文として実行されます。
3. **ステップ 3 — `secrets: inherit` と `packages: write` を持つ永続ランナー `xrd-runner-8c` 上での実行 (`build.yaml:50-58`):**
   このステップは `secrets: inherit` および `packages: write` が付与されたワークフロー内で `xrd-runner-8c` 上にて実行されるため、注入されたコマンドはセルフホストビルドマシンのファイルシステムとワークフロー認証情報に直接アクセスできます。

### 脆弱なコード箇所 (`.github/workflows/_build-and-package.yml:26-27, 84-91`)
```yaml
# File: .github/workflows/_build-and-package.yml (lines 26-27, 84-91)
    runs-on:
      labels: xrd-runner-8c # 永続的なセルフホストランナーフリート
...
          get_branch_name() {
            local branch_name=""
            if [[ -n "${{ github.head_ref }}" ]]; then # BUG 1: bash 内への直接テンプレート展開
              branch_name="${{ github.head_ref }}"     # BUG 2: ブランチ名が "..." を抜けて任意のシェルコマンドを実行
              echo "🔍 Using PR source branch: ${branch_name}" >&2
            elif [[ -n "${{ github.ref_name }}" ]]; then
              branch_name="${{ github.ref_name }}"
```

---

## 2. 日常の実運用で起こり得る 3 つの重大シナリオ (シナリオ A / シナリオ B / シナリオ C)

### シナリオ A — 細工された PR ブランチ名によりコードレビュー開始前に `xrd-runner-8c` 上で任意シェルコマンドが実行される
1. コントリビュータまたは侵害された開発者アカウントが、無害な 1 行のドキュメント修正だけを含む `feat";<command>;#` という名前のブランチをプッシュし、Pull Request を作成します。
2. レビュアーが PR の `Files changed` タブを確認しても、ビルドスクリプトやソースコードへの不審な変更は一切見えません。
3. しかし `xrd-runner-8c` 上で `Setup build configuration` ステップが開始された瞬間、GitHub Actions が `${{ github.head_ref }}` を bash スクリプトに展開し、セルフホストランナー上で `<command>` が実行されます。

### シナリオ B — 継承されたシークレットおよび `packages: write` GHCR トークンの流出
1. `build.yaml:50-58` が `permissions: contents: write, packages: write` を宣言し、`_build-and-package.yml` に `secrets: inherit` を渡しているため、ワークフローステップには書き込み権限付きトークンとリポジトリシークレットが渡されます。
2. 注入されたシェルコマンドはランナー環境から `GITHUB_TOKEN`（`contents: write`、`packages: write`）および継承されたシークレットを読み取ります。
3. 攻撃者はそれらの認証情報を使用して、改ざんしたコンテナイメージを GHCR へプッシュしたりリポジトリ内容を書き換えたりできます。

### シナリオ C — 永続的なセルフホストランナーのビルドキャッシュ汚染による後続公式ビルドへのバックドア混入
1. `xrd-runner-8c` は使い捨てのエフェメラル VM ではなく永続的なセルフホストランナーであるため、ランナーホストへの書き込みは次のジョブにも残ります。
2. `${{ github.head_ref }}` 経由で注入されたコマンドにより、ランナーホスト上にバックグラウンドプロセスを常駐させたり、ローカルの Gradle/Docker/APT キャッシュを汚染したりできます。
3. 同じ `xrd-runner-8c` ノードで後から実行される正規の `develop` ビルドやリリースビルドが汚染された依存関係を取り込み、公式 X-Road ビルド成果物が侵害されます。

---

## 3. 実行・再現・検証コマンド例

### 1. Sniper CLI による対象コンポーネントの監査
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/X-Road \
  --include ".github/workflows/_build-and-package.yml"
```

### 2. ローカル隔離環境での再現と検証 (`Bash`)
```bash
# github.head_ref の直接展開による二重引用符脱出と環境変数パラメータ化による防御を比較
bash -c '
HEAD_REF="feat\";echo INJECTED_ON_RUNNER >&2;#"
echo "--- [RED] Vulnerable inline expansion ---"
eval "if [[ -n \"${HEAD_REF}\" ]]; then branch_name=\"${HEAD_REF}\"; fi"

echo "--- [GREEN] Patched env var parameterization ---"
PR_HEAD_REF="$HEAD_REF" bash -c '\''if [[ -n "${PR_HEAD_REF}" ]]; then branch_name="${PR_HEAD_REF}"; echo "Safe literal branch_name=${branch_name}"; fi'\''
'
```

### 3. 自動 `RED -> GREEN + BENIGN` E2E 検証ハーネスの実行
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_xroad_cand01
```

---

## 4. エンドツーエンドのランタイム証明 (RED -> GREEN + BENIGN) と防御パッチ

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_xroad_cand01` による実行結果:

```json
{
  "XROAD-CAND-01": {
    "ghsa_id": "GHSA-4fcw-7xqx-fjv5",
    "build_workflow": "x-road/.github/workflows/build.yaml",
    "package_workflow": "x-road/.github/workflows/_build-and-package.yml",
    "elapsed_ms": 5.513,
    "RED": {
      "direct_yaml_interpolation": true,
      "arbitrary_command_executed_on_self_hosted_runner": true
    },
    "GREEN": {
      "env_var_parameterized": true,
      "arbitrary_command_executed_on_self_hosted_runner": false
    }
  }
}
```

### Unified Diff パッチ (`git apply --check` 検証済み)
```diff
--- a/.github/workflows/_build-and-package.yml
+++ b/.github/workflows/_build-and-package.yml
@@ -72,6 +72,9 @@
       - name: Setup build configuration
         id: build-config
         working-directory: ./src
+        env:
+          PR_HEAD_REF: ${{ github.head_ref }}
+          GIT_REF_NAME: ${{ github.ref_name }}
         run: |
@@ -84,11 +87,11 @@
           get_branch_name() {
             local branch_name=""
-            if [[ -n "${{ github.head_ref }}" ]]; then
-              branch_name="${{ github.head_ref }}"
+            if [[ -n "${PR_HEAD_REF}" ]]; then
+              branch_name="${PR_HEAD_REF}"
               echo "🔍 Using PR source branch: ${branch_name}" >&2
-            elif [[ -n "${{ github.ref_name }}" ]]; then
-              branch_name="${{ github.ref_name }}"
+            elif [[ -n "${GIT_REF_NAME}" ]]; then
+              branch_name="${GIT_REF_NAME}"
```
