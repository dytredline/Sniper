# Watched-Folder Symlink Escape Bypassing FolderAccessGuard.isProtected in Default recursive=false Mode (`GHSA-hpc7-xx5r-gc44`)

**English** | [Türkçe](tr/01-STIRLING-CAND-02-SYMLINK.md) | [日本語](ja/01-STIRLING-CAND-02-SYMLINK.md) | [简体中文](zh-CN/01-STIRLING-CAND-02-SYMLINK.md) | [한국어](ko/01-STIRLING-CAND-02-SYMLINK.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
In `Stirling-Tools/Stirling-PDF` (`v3.2.2`, commit `684608d143779bf3a8ffc67639f077a1202c62ff`), the Automated Processing Watched Folder pipeline polls a configured input directory, processes incoming files, and writes results/archives to an output directory. A mismatch between link resolution in `FolderInputSource.listFiles` and path validation in `FolderAccessGuard.isProtected` turns any symlink inside the watched folder into an arbitrary file read/exfiltration primitive (`CWE-59` / `CWE-61`):

1. **Step 1 — Unchecked Symlink Following in `Files.isRegularFile` (`FolderInputSource.java:337-345`):**
   In default `recursive=false` mode, `FolderInputSource.listFiles` streams directory entries via `Files.list(inputDir).filter(Files::isRegularFile)`. Because `LinkOption.NOFOLLOW_LINKS` is omitted, Java NIO follows any symlink inside `inputDir` to its target file outside the watched root and returns `true` as long as the target is a regular file.
2. **Step 2 — Lexical-Only Validation in `FolderAccessGuard.isProtected`:**
   `FolderAccessGuard.isProtected(path)` normalizes the path lexically (`toAbsolutePath().normalize()`) rather than resolving canonical symlink targets (`toRealPath()`). A symlink at `/watched/input/report.pdf -> /configs/settings.yml` appears lexically inside `/watched/input`, completely bypassing `FolderAccessGuard`.
3. **Step 3 — Ingestion and Exfiltration into the Accessible Output Sink (`ProcessingFolderController.java:374-380`, `FolderOutputSink.java:338-345`):**
   The background pipeline reads the symlink target and archives/copies its contents into the user-accessible output/archive folder. Ironically, `recursive=true` uses `Files.walkFileTree` (which does not follow symlinks by default unless `FileVisitOption.FOLLOW_LINKS` is passed), whereas default `recursive=false` follows symlinks unconditionally.

### Vulnerable Code Snippet (`FolderInputSource.java:337-346`)
```java
// File: app/proprietary/src/main/java/stirling/software/proprietary/policy/input/FolderInputSource.java (lines 337-346)
private static List<Path> listFiles(
        Path inputDir, boolean recursive, FolderAccessGuard accessGuard) throws IOException {
    List<Path> files = new ArrayList<>();
    if (!recursive) {
        try (Stream<Path> entries = Files.list(inputDir)) {
            entries.filter(Files::isRegularFile) // BUG: missing LinkOption.NOFOLLOW_LINKS; follows symlinks outside inputDir!
                    .filter(file -> !hidden(file))
                    .forEach(files::add);        // BUG: missing accessGuard.isProtected(file) and canonical root boundary check!
        }
        return files;
    }
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Corporate SMB / NFS Office Scanner Drop-Folder Exfiltrates Admin & OAuth Secrets
1. An enterprise deploys Stirling-PDF with a shared SMB/NFS network drop-folder (`/mnt/scanner-incoming`) watched in default `recursive=false` mode so employees can drop documents for automated OCR/archiving into `/mnt/scanner-processed`.
2. A low-privileged domain user or attacker drops a symbolic link `ln -s /configs/settings.yml /mnt/scanner-incoming/invoice.pdf` into the shared drop-folder.
3. Because `Files.isRegularFile(entry)` returns `true` for a symlink pointing to `settings.yml` and `FolderAccessGuard.isProtected` only checks the lexical path `/mnt/scanner-incoming/invoice.pdf`, the background poller ingests `settings.yml` and copies/archives the raw YAML containing `SECURITY_INITIALADMINPASSWORD`, OAuth2 `clientSecret`, and SMTP credentials into the readable `/mnt/scanner-processed` folder.

### Scenario B — Automated SFTP / Nextcloud Document Ingestion Pipeline Reads Host SSH Keys or `.env`
1. A law firm or healthcare provider syncs external partner uploads into a Stirling-PDF watched directory via SFTP or Nextcloud external storage.
2. A partner upload creates a symlink pointing to `/home/community-user/.ssh/id_ed25519` or `/app/configs/custom_settings.yml`.
3. `FolderOutputSink.archiveOriginal()` (`FolderOutputSink.java:338-345`) checks `Files.notExists(target, NOFOLLOW_LINKS)` (which evaluates to `false` for a symlink) and then calls `Files.move` / `Files.copy` without `NOFOLLOW_LINKS`, archiving the target secret file directly into the processed output store accessible to the partner.

### Scenario C — Multi-Tenant Shared Volume Cross-Department Confidential Document & H2 Database Theft
1. An organization runs a consolidated Stirling-PDF container serving multiple departmental watched folders (`/data/hr-watched`, `/data/finance-watched`, `/data/accounting-watched`) alongside the local database (`/configs/stirling-pdf.mv.db`).
2. A user with write access only to `/data/accounting-watched` places a symlink pointing to `/data/hr-watched/executive-payroll.pdf` or `/configs/stirling-pdf.mv.db`.
3. Because `FolderInputSource.listFiles` enforces no canonical root confinement (`staysWithinCanonicalRoot`), Stirling-PDF ingests the cross-department confidential PDF or internal database file and writes it directly into the accounting output directory.

---

## 3. Example Execution & Verification Commands

### 1. Auditing the Component with Sniper CLI
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/Stirling-PDF \
  --include "app/proprietary/src/main/java/stirling/software/proprietary/policy/input/FolderInputSource.java"
```

### 2. Local Isolated Reproduction & Verification
```bash
# Create an isolated temporary workspace simulating protected_configs and watched_input
WORKDIR="$(mktemp -d /tmp/stirling-cand02-XXXXXX)"
mkdir -p "$WORKDIR/protected_configs" "$WORKDIR/watched_input" "$WORKDIR/processed_output"
echo "SECURITY_INITIALADMINPASSWORD=super-secret-admin-pass" > "$WORKDIR/protected_configs/settings.yml"
echo "Benign document content" > "$WORKDIR/watched_input/benign.txt"

# Place a symlink inside watched_input pointing outside to protected_configs/settings.yml
ln -s "$WORKDIR/protected_configs/settings.yml" "$WORKDIR/watched_input/report.txt"
ls -la "$WORKDIR/watched_input"
rm -rf "$WORKDIR"
```

### 3. Running the Automated `RED -> GREEN + BENIGN` E2E Verification Harness
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand02
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Optional Defensive Diff

Executed via `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand02`:

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

### Boundary Qualification
Exploitation requires the Processing Watched Folder feature to be enabled and requires an actor with write access to the watched input directory (e.g., via SMB/NFS/SFTP share or shared container volume) to place a symbolic link.

### Unified Diff Patch (`git apply --check` clean)
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
