# Watched-Folder Symlink Escape Bypassing FolderAccessGuard.isProtected in Default recursive=false Mode

## Quick-Fill GitHub GHSA & MITRE CNA Form Fields
- **Repository:** `Stirling-Tools/Stirling-PDF`
- **GitHub Advisory URL:** `https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/new`
- **Existing GHSA ID:** `None (New 0-Day GHSA & CNA Candidate)`
- **Ecosystem:** `Maven`
- **Package Name:** `stirling.software:stirling-pdf`
- **Affected Versions:** `<= 3.2.2 (commit 684608d143779bf3a8ffc67639f077a1202c62ff)`
- **Patched Versions:** `None (Patch attached)`
- **CWE:** `CWE-59 (Improper Link Resolution Before File Access) / CWE-61 (UNIX Symbolic Link Following)`
- **CVSS v3.1:** `7.1 High — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **MITRE Vendor:** `Stirling-Tools`
- **MITRE Vulnerability Type:** `Symlink Following / Improper Link Resolution (CWE-59)`
- **MITRE Affected Component(s):** `FolderInputSource.java (listFiles, lines 337-377), ProcessingFolderController.java (lines 374-380), FolderOutputSink.java (archiveOriginal, lines 338-345)`
- **MITRE Suggested CVE Description:**
  > In Stirling-Tools Stirling-PDF through 3.2.2, the watched-folder document ingestion pipeline (FolderInputSource.java, ProcessingFolderController.java, and FolderOutputSink.java) uses Files.isRegularFile(path) without LinkOption.NOFOLLOW_LINKS in its default recursive=false mode, while FolderAccessGuard.isProtected validates only the lexical path inside the watched directory. An attacker with write access to a watched input folder can place a symbolic link pointing to protected configuration files (such as settings.yml), causing Stirling-PDF to read, process, and archive sensitive credentials into the accessible output directory.
- **Credit / Reporter:** `Gökçe Baran Karakamış (@dytredline)`

---

### Summary
In `Stirling-Tools/Stirling-PDF` (`v3.2.2`, commit `684608d143779bf3a8ffc67639f077a1202c62ff`), the Automated Processing Watched Folder pipeline (`FolderInputSource.java:337-377`, `ProcessingFolderController.java:374-380`, and `FolderOutputSink.java:338-345`) fails to reject symbolic links in its default `recursive=false` mode. Because `Files.isRegularFile(path)` (without `LinkOption.NOFOLLOW_LINKS`) follows symbolic links to their target while `FolderAccessGuard.isProtected(path)` checks only the lexical path inside the watched folder (`toAbsolutePath().normalize()`), a symbolic link placed inside the watched folder bypasses `FolderAccessGuard` and causes Stirling-PDF to read, process, and archive protected server configuration files (`protected_configs/settings.yml`, database credentials, OAuth client secrets) into the user-accessible output directory (`CWE-59` / `CWE-61`).

### Concrete Everyday Real-World Production Scenarios (Why This Causes Critical Impact in Daily Use)
- **Scenario A — Corporate SMB / NFS Office Scanner Drop-Folder Exfiltrates Admin & OAuth Secrets:**
  1. An enterprise deploys Stirling-PDF with a shared network drop-folder (`/mnt/scanner-incoming`) watched in default `recursive=false` mode so employees can drop documents for automated OCR/archiving into `/mnt/scanner-processed`.
  2. An attacker or low-privileged domain user drops a symbolic link `ln -s /configs/settings.yml /mnt/scanner-incoming/invoice.pdf` into the shared drop-folder.
  3. Because `Files.isRegularFile(entry)` returns `true` for a symlink pointing to `settings.yml` and `FolderAccessGuard.isProtected` only checks the lexical path `/mnt/scanner-incoming/invoice.pdf`, the background poller ingests `settings.yml` and copies/archives the raw YAML containing `SECURITY_INITIALADMINPASSWORD`, OAuth2 `clientSecret`, and SMTP credentials into the readable output/archive folder.
- **Scenario B — Automated SFTP / Nextcloud Document Ingestion Pipeline Reads Host SSH Keys or `.env`:**
  1. A law firm or healthcare provider syncs external partner uploads into a Stirling-PDF watched directory via SFTP or Nextcloud external storage.
  2. A partner archive or SFTP upload creates a symlink pointing to `/home/community-user/.ssh/id_ed25519` or `/app/configs/custom_settings.yml`.
  3. `FolderOutputSink.archiveOriginal()` (`FolderOutputSink.java:338-345`) checks `Files.notExists(target, NOFOLLOW_LINKS)` (which is `false` for a symlink) and then calls `Files.move` / `Files.copy` without `NOFOLLOW_LINKS`, archiving the target secret file directly into the processed output store.
- **Scenario C — Sibling Security Parity Bypass Between `recursive=false` (Default) and `recursive=true`:**
  1. An administrator intentionally leaves `recursive: false` enabled believing it is safer and more restrictive than `recursive: true`.
  2. Ironically, `recursive: true` uses `Files.walkFileTree` (which does not follow symlinks by default unless `FileVisitOption.FOLLOW_LINKS` is passed), whereas default `recursive: false` calls `Files.list(inputDir).filter(Files::isRegularFile)` which silently follows symlinks outside the watched root.

### End-to-End Runtime Proof (`RED -> GREEN + BENIGN`)
Executed via `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand02`:

```json
{
  "STIRLING-CAND-02": {
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
