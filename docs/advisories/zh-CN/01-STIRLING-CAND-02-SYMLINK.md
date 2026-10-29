# 默认 recursive=false 模式下监控文件夹符号链接逃逸绕过 FolderAccessGuard.isProtected (`GHSA-hpc7-xx5r-gc44`)

[English](../01-STIRLING-CAND-02-SYMLINK.md) | [Türkçe](../tr/01-STIRLING-CAND-02-SYMLINK.md) | [日本語](../ja/01-STIRLING-CAND-02-SYMLINK.md) | **简体中文** | [한국어](../ko/01-STIRLING-CAND-02-SYMLINK.md)

## 1. 代码缺陷如何演变为可被利用的安全漏洞

### 分步技术机制剖析
在 `Stirling-Tools/Stirling-PDF`（`v3.2.2`，提交 `684608d143779bf3a8ffc67639f077a1202c62ff`）中，自动化监控文件夹（Processing Watched Folder）流水线会定期轮询配置的输入目录、处理进入的文件，并将结果与归档写入输出目录。由于 `FolderInputSource.listFiles` 中的链接解析与 `FolderAccessGuard.isProtected` 中的路径校验存在逻辑脱节，监控文件夹中的任何符号链接都会变成任意文件读取与外带原语（`CWE-59` / `CWE-61`）：

1. **步骤 1 — `Files.isRegularFile` 无条件跟随符号链接 (`FolderInputSource.java:337-345`)：**
   在默认的 `recursive=false` 模式下，`FolderInputSource.listFiles` 通过 `Files.list(inputDir).filter(Files::isRegularFile)` 枚举目录项。由于省略了 `LinkOption.NOFOLLOW_LINKS`，Java NIO 会自动跟随 `inputDir` 内的符号链接追踪到监控根目录之外的目标文件，只要目标文件是普通文件即返回 `true`。
2. **步骤 2 — `FolderAccessGuard.isProtected` 仅检查字面路径：**
   `FolderAccessGuard.isProtected(path)` 仅对路径做字面规范化（`toAbsolutePath().normalize()`），而未解析符号链接的真实物理路径（`toRealPath()`）。因此，形如 `/watched/input/report.pdf -> /configs/settings.yml` 的符号链接在字面上仍位于 `/watched/input` 内，从而完全绕过 `FolderAccessGuard`。
3. **步骤 3 — 读取目标机密文件并写入可访问的输出目录 (`ProcessingFolderController.java:374-380`, `FolderOutputSink.java:338-345`)：**
   后台任务会读取符号链接指向的目标文件，并将其内容复制或归档至用户可读的输出目录。颇具讽刺意味的是，`recursive=true` 模式使用了 `Files.walkFileTree`（默认不跟随符号链接），而默认的 `recursive=false` 模式却无条件跟随了符号链接。

### 漏洞源码片段 (`FolderInputSource.java:337-346`)
```java
// File: app/proprietary/src/main/java/stirling/software/proprietary/policy/input/FolderInputSource.java (lines 337-346)
private static List<Path> listFiles(
        Path inputDir, boolean recursive, FolderAccessGuard accessGuard) throws IOException {
    List<Path> files = new ArrayList<>();
    if (!recursive) {
        try (Stream<Path> entries = Files.list(inputDir)) {
            entries.filter(Files::isRegularFile) // BUG: 缺少 LinkOption.NOFOLLOW_LINKS，会跟随符号链接跳出 inputDir！
                    .filter(file -> !hidden(file))
                    .forEach(files::add);        // BUG: 缺少 accessGuard.isProtected(file) 及真实根目录边界检查！
        }
        return files;
    }
```

---

## 2. 日常实际生产环境中的 3 个关键高危场景 (场景 A / 场景 B / 场景 C)

### 场景 A — 企业共享 SMB / NFS 办公扫描仪投递目录泄露管理员密码与 OAuth 密钥
1. 企业部署 Stirling-PDF 并将共享 SMB/NFS 网络投递文件夹（`/mnt/scanner-incoming`）以默认 `recursive=false` 模式配置为监控目录，供员工放入扫描件并自动输出至 `/mnt/scanner-processed`。
2. 低权限域用户或攻击者向共享投递目录放入符号链接 `ln -s /configs/settings.yml /mnt/scanner-incoming/invoice.pdf`。
3. 由于 `Files.isRegularFile(entry)` 对指向 `settings.yml` 的符号链接返回 `true`，且 `FolderAccessGuard.isProtected` 仅检查字面路径 `/mnt/scanner-incoming/invoice.pdf`，后台轮询器会直接读取 `settings.yml`，并将包含 `SECURITY_INITIALADMINPASSWORD`、OAuth2 `clientSecret` 及 SMTP 凭据的原始 YAML 复制到可读的 `/mnt/scanner-processed` 目录中。

### 场景 B — 外部合作伙伴 SFTP / Nextcloud 自动文档导入流水线读取宿主机 SSH 私钥或 `.env`
1. 律所或医疗机构通过 SFTP 或 Nextcloud 外部存储，将外部合作伙伴上传的文档同步至 Stirling-PDF 的监控目录。
2. 合作伙伴上传的目录项中包含指向 `/home/community-user/.ssh/id_ed25519` 或 `/app/configs/custom_settings.yml` 的符号链接。
3. `FolderOutputSink.archiveOriginal()`（`FolderOutputSink.java:338-345`）在检查 `Files.notExists(target, NOFOLLOW_LINKS)`（对符号链接返回 `false`）后，直接调用未带 `NOFOLLOW_LINKS` 的 `Files.move` / `Files.copy`，将目标机密文件归档到合作伙伴可访问的输出存储中。

### 场景 C — 多租户共享卷环境下跨部门机密文档与本地 H2 数据库窃取
1. 企业使用单个 Stirling-PDF 容器同时服务多个部门的监控目录（`/data/hr-watched`、`/data/finance-watched`、`/data/accounting-watched`）并存放本地数据库（`/configs/stirling-pdf.mv.db`）。
2. 仅拥有 `/data/accounting-watched` 写入权限的用户在其中放置指向 `/data/hr-watched/executive-payroll.pdf` 或 `/configs/stirling-pdf.mv.db` 的符号链接。
3. 由于 `FolderInputSource.listFiles` 未执行真实路径根目录约束（`staysWithinCanonicalRoot`），Stirling-PDF 会直接读取跨部门机密 PDF 或内部数据库文件，并将其写入财务部门的输出目录。

---

## 3. 示例执行、复现与验证命令

### 1. 使用 Sniper CLI 审计目标组件
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/Stirling-PDF \
  --include "app/proprietary/src/main/java/stirling/software/proprietary/policy/input/FolderInputSource.java"
```

### 2. 本地隔离环境复现与验证
```bash
# 创建模拟 protected_configs 和 watched_input 的临时隔离工作区
WORKDIR="$(mktemp -d /tmp/stirling-cand02-XXXXXX)"
mkdir -p "$WORKDIR/protected_configs" "$WORKDIR/watched_input" "$WORKDIR/processed_output"
echo "SECURITY_INITIALADMINPASSWORD=super-secret-admin-pass" > "$WORKDIR/protected_configs/settings.yml"
echo "Benign document content" > "$WORKDIR/watched_input/benign.txt"

# 在 watched_input 内创建指向外部 protected_configs/settings.yml 的符号链接
ln -s "$WORKDIR/protected_configs/settings.yml" "$WORKDIR/watched_input/report.txt"
ls -la "$WORKDIR/watched_input"
rm -rf "$WORKDIR"
```

### 3. 运行自动化 `RED -> GREEN + BENIGN` 端到端验证套件
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand02
```

---

## 4. 端到端运行时证明 (RED -> GREEN + BENIGN) 与防御补丁

通过 `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand02` 执行的验证结果：

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

### 边界条件说明
利用该漏洞需要启用 Processing Watched Folder 功能，且攻击者需具备对监控输入目录的写入权限（例如通过 SMB/NFS/SFTP 共享或容器共享卷放置符号链接）。

### Unified Diff 补丁 (`git apply --check` 验证通过)
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
