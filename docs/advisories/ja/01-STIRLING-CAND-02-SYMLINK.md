# デフォルトの recursive=false モードで FolderAccessGuard.isProtected を回避する監視フォルダのシンボリックリンク脱出 (`GHSA-hpc7-xx5r-gc44`)

[English](../01-STIRLING-CAND-02-SYMLINK.md) | [Türkçe](../tr/01-STIRLING-CAND-02-SYMLINK.md) | **日本語** | [简体中文](../zh-CN/01-STIRLING-CAND-02-SYMLINK.md) | [한국어](../ko/01-STIRLING-CAND-02-SYMLINK.md)

## GitHub GHSA & MITRE CNA フォーム入力フィールド
- **対象リポジトリ:** `Stirling-Tools/Stirling-PDF`
- **GitHub Advisory URL:** `https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/GHSA-hpc7-xx5r-gc44`
- **既存 GHSA ID:** `GHSA-hpc7-xx5r-gc44`
- **エコシステム:** `Maven`
- **パッケージ名:** `stirling.software:stirling-pdf`
- **影響を受けるバージョン:** `<= 3.2.2 (commit 684608d143779bf3a8ffc67639f077a1202c62ff)`
- **修正済みバージョン:** `なし（修正パッチ添付）`
- **CWE:** `CWE-59 (ファイルアクセス前の不適切なリンク解決) / CWE-61 (UNIX シンボリックリンク追跡)`
- **CVSS v3.1:** `7.1 High — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **MITRE ベンダー:** `Stirling-Tools`
- **MITRE 脆弱性タイプ:** `Symlink Following / Improper Link Resolution (CWE-59)`
- **MITRE 影響を受けるコンポーネント:** `FolderInputSource.java (listFiles, lines 337-377), ProcessingFolderController.java (lines 374-380), FolderOutputSink.java (archiveOriginal, lines 338-345)`
- **MITRE 推奨説明文:**
  > Stirling-Tools Stirling-PDF 3.2.2 以前において、監視フォルダ（Watched Folder）自動取り込みパイプライン（`FolderInputSource.java`、`ProcessingFolderController.java`、`FolderOutputSink.java`）は、デフォルトの `recursive=false` モードで `LinkOption.NOFOLLOW_LINKS` を指定せずに `Files.isRegularFile(path)` を呼び出す一方、`FolderAccessGuard.isProtected` は監視ディレクトリ内の字句パス（lexical path）のみを検証します。監視対象の入力フォルダへの書き込み権限を持つ攻撃者が保護された設定ファイル（`settings.yml` など）を指すシンボリックリンクを配置すると、Stirling-PDF が機密情報や認証情報を読み取り、アクセス可能な出力ディレクトリへ出力・アーカイブしてしまいます。
- **報告者 / クレジット:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. コードの欠陥がどのように悪用可能な脆弱性に変わるか

### ステップバイステップの技術的メカニズム
`Stirling-Tools/Stirling-PDF`（`v3.2.2`、コミット `684608d143779bf3a8ffc67639f077a1202c62ff`）の自動処理監視フォルダ（Processing Watched Folder）パイプラインは、設定された入力ディレクトリを定期的にポーリングし、到着したファイルを処理して出力ディレクトリへ書き込みます。`FolderInputSource.listFiles` におけるリンク解決と `FolderAccessGuard.isProtected` におけるパス検証の不整合により、監視フォルダ内のシンボリックリンクが任意ファイルの読み取り・流出プリミティブ（`CWE-59` / `CWE-61`）へと変化します。

1. **ステップ 1 — `Files.isRegularFile` での無検証なシンボリックリンク追跡 (`FolderInputSource.java:337-345`):**
   デフォルトの `recursive=false` モードでは、`FolderInputSource.listFiles` は `Files.list(inputDir).filter(Files::isRegularFile)` でディレクトリエントリを列挙します。ここで `LinkOption.NOFOLLOW_LINKS` が省略されているため、Java NIO は `inputDir` 内のシンボリックリンクを監視ルート外のリンク先ファイルまで追跡し、リンク先が通常ファイルであれば `true` を返します。
2. **ステップ 2 — `FolderAccessGuard.isProtected` における字句パスのみの検査:**
   `FolderAccessGuard.isProtected(path)` は正規化された実体パス（`toRealPath()`）ではなく、字句パス（`toAbsolutePath().normalize()`）のみを検証します。そのため `/watched/input/report.pdf -> /configs/settings.yml` のようなシンボリックリンクは字句上 `/watched/input` 内に見えるため、`FolderAccessGuard` を完全に通過します。
3. **ステップ 3 — アクセス可能な出力先への取り込みと機密流出 (`ProcessingFolderController.java:374-380`, `FolderOutputSink.java:338-345`):**
   バックグラウンドパイプラインはシンボリックリンク先のファイルを読み取り、ユーザーが閲覧可能な出力・アーカイブフォルダへ内容をコピーします。皮肉なことに、`recursive=true` モードは `Files.walkFileTree`（デフォルトではシンボリックリンクを追跡しない）を使用しますが、デフォルトの `recursive=false` モードは無条件でシンボリックリンクを追跡してしまいます。

### 脆弱なコード箇所 (`FolderInputSource.java:337-346`)
```java
// File: app/proprietary/src/main/java/stirling/software/proprietary/policy/input/FolderInputSource.java (lines 337-346)
private static List<Path> listFiles(
        Path inputDir, boolean recursive, FolderAccessGuard accessGuard) throws IOException {
    List<Path> files = new ArrayList<>();
    if (!recursive) {
        try (Stream<Path> entries = Files.list(inputDir)) {
            entries.filter(Files::isRegularFile) // BUG: LinkOption.NOFOLLOW_LINKS がなく、inputDir 外へのシンボリックリンクを追跡してしまう
                    .filter(file -> !hidden(file))
                    .forEach(files::add);        // BUG: accessGuard.isProtected(file) と正規ルート境界チェックが欠落している
        }
        return files;
    }
```

---

## 2. 日常の実運用で起こり得る 3 つの重大シナリオ (シナリオ A / シナリオ B / シナリオ C)

### シナリオ A — 社内共有 SMB / NFS スキャナー受信フォルダ経由での管理者パスワードおよび OAuth 秘密情報の流出
1. 企業が社内共有の SMB/NFS ネットワークフォルダ（`/mnt/scanner-incoming`）をデフォルトの `recursive=false` モードで Stirling-PDF の監視フォルダに設定し、社員がスキャン書類を投入すると `/mnt/scanner-processed` へ自動出力される運用を行っています。
2. 低権限の一般社員アカウントや攻撃者が、共有受信フォルダに `ln -s /configs/settings.yml /mnt/scanner-incoming/invoice.pdf` というシンボリックリンクを配置します。
3. `Files.isRegularFile(entry)` は `settings.yml` を指すシンボリックリンクに対して `true` を返し、`FolderAccessGuard.isProtected` は字句パス `/mnt/scanner-incoming/invoice.pdf` のみを検査するため、バックグラウンドポーラーが `settings.yml` を取り込み、`SECURITY_INITIALADMINPASSWORD`、OAuth2 `clientSecret`、SMTP 認証情報を含む生データを閲覧可能な `/mnt/scanner-processed` フォルダへコピーします。

### シナリオ B — 外部パートナー向け SFTP / Nextcloud 自動取り込みパイプライン経由でのホスト SSH 秘密鍵・`.env` の窃取
1. 法律事務所や医療機関が、外部パートナーからのアップロードを SFTP や Nextcloud 外部ストレージ経由で Stirling-PDF の監視ディレクトリへ同期しています。
2. アップロードされたエントリ内に `/home/community-user/.ssh/id_ed25519` や `/app/configs/custom_settings.yml` を指すシンボリックリンクが含まれます。
3. `FolderOutputSink.archiveOriginal()`（`FolderOutputSink.java:338-345`）は `Files.notExists(target, NOFOLLOW_LINKS)`（シンボリックリンクに対しては `false`）を確認した後、`NOFOLLOW_LINKS` なしで `Files.move` / `Files.copy` を呼び出すため、リンク先の機密ファイルがそのままパートナーからアクセス可能な出力ストレージへアーカイブされます。

### シナリオ C — マルチテナント共有ボリューム環境における他部門の機密文書およびローカル H2 データベースの窃取
1. 単一の Stirling-PDF コンテナで複数部門の監視フォルダ（`/data/hr-watched`、`/data/finance-watched`、`/data/accounting-watched`）とローカル H2 データベース（`/configs/stirling-pdf.mv.db`）を運用しています。
2. `/data/accounting-watched` のみに書き込み権限を持つ利用者が、`/data/hr-watched/executive-payroll.pdf` または `/configs/stirling-pdf.mv.db` を指すシンボリックリンクを配置します。
3. `FolderInputSource.listFiles` には正規ルート境界チェック（`staysWithinCanonicalRoot`）が存在しないため、Stirling-PDF は人事部門の機密 PDF や内部データベースファイルを読み込み、経理部門の出力ディレクトリへ書き出します。

---

## 3. 実行・再現・検証コマンド例

### 1. Sniper CLI による対象コンポーネントの監査
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/Stirling-PDF \
  --include "app/proprietary/src/main/java/stirling/software/proprietary/policy/input/FolderInputSource.java"
```

### 2. ローカル隔離環境での再現と検証
```bash
# protected_configs と watched_input を模した一時隔離ワークスペースを作成
WORKDIR="$(mktemp -d /tmp/stirling-cand02-XXXXXX)"
mkdir -p "$WORKDIR/protected_configs" "$WORKDIR/watched_input" "$WORKDIR/processed_output"
echo "SECURITY_INITIALADMINPASSWORD=super-secret-admin-pass" > "$WORKDIR/protected_configs/settings.yml"
echo "Benign document content" > "$WORKDIR/watched_input/benign.txt"

# watched_input 内に外部の protected_configs/settings.yml を指すシンボリックリンクを作成
ln -s "$WORKDIR/protected_configs/settings.yml" "$WORKDIR/watched_input/report.txt"
ls -la "$WORKDIR/watched_input"
rm -rf "$WORKDIR"
```

### 3. 自動 `RED -> GREEN + BENIGN` E2E 検証ハーネスの実行
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand02
```

---

## 4. エンドツーエンドのランタイム証明 (RED -> GREEN + BENIGN) と防御パッチ

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand02` による実行結果:

```json
{
  "STIRLING-CAND-02": {
    "ghsa_id": "GHSA-hpc7-xx5r-gc44",
    "source_file": "stirling-pdf/app/proprietary/src/main/java/stirling/software/proprietary/policy/input/FolderInputSource.java",
    "patch_file": "pre-submission-verification-20261026/patches/STIRLING-CAND-02-SYMLINK.patch",
    "patch_sha256": "927749524cd31816a71f8dffab08146d420132e726e22bd681c6dce642882480",
    "elapsed_ms": 0.884,
    "RED": {
      "recursive": false,
      "symlink_accepted": true,
      "protected_settings_exfiltrated": true,
      "processed_files_count": 2,
      "exfiltrated_artifact": "processed_output/report_processed.txt"
    },
    "GREEN": {
      "recursive": false,
      "symlink_accepted": false,
      "protected_settings_exfiltrated": false,
      "regular_file_processed": true,
      "processed_files_count": 1
    }
  }
}
```

### 境界条件の補足
悪用には Processing Watched Folder 機能が有効であり、かつ監視対象の入力ディレクトリへの書き込み権限（SMB/NFS/SFTP 共有や共有コンテナボリューム経由など）が必要です。

### Unified Diff パッチ (`git apply --check` 検証済み)
```diff
--- a/app/proprietary/src/main/java/stirling/software/proprietary/policy/input/FolderInputSource.java
+++ b/app/proprietary/src/main/java/stirling/software/proprietary/policy/input/FolderInputSource.java
@@ -4,6 +4,7 @@
 import java.io.UncheckedIOException;
 import java.nio.file.FileVisitResult;
 import java.nio.file.Files;
+import java.nio.file.LinkOption;
 import java.nio.file.NoSuchFileException;
 import java.nio.file.Path;
 import java.nio.file.SimpleFileVisitor;
@@ -337,10 +338,13 @@
     private static List<Path> listFiles(
             Path inputDir, boolean recursive, FolderAccessGuard accessGuard) throws IOException {
         List<Path> files = new ArrayList<>();
+        Path canonicalRoot = FolderIdentities.canonicalDir(inputDir);
         if (!recursive) {
             try (Stream<Path> entries = Files.list(inputDir)) {
-                entries.filter(Files::isRegularFile)
+                entries.filter(file -> Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS))
                         .filter(file -> !hidden(file))
+                        .filter(file -> !accessGuard.isProtected(file))
+                        .filter(file -> staysWithinCanonicalRoot(file, canonicalRoot))
                         .forEach(files::add);
             }
             return files;
```
