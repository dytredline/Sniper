# 기본 recursive=false 모드에서 FolderAccessGuard.isProtected를 우회하는 감시 폴더 심볼릭 링크 이스케이프 (`GHSA-hpc7-xx5r-gc44`)

[English](../01-STIRLING-CAND-02-SYMLINK.md) | [Türkçe](../tr/01-STIRLING-CAND-02-SYMLINK.md) | [日本語](../ja/01-STIRLING-CAND-02-SYMLINK.md) | [简体中文](../zh-CN/01-STIRLING-CAND-02-SYMLINK.md) | **한국어**

## 1. 코드 결함이 실제 악용 가능한 취약점으로 전환되는 메커니즘

### 단계별 기술적 메커니즘
`Stirling-Tools/Stirling-PDF`(`v3.2.2`, 커밋 `684608d143779bf3a8ffc67639f077a1202c62ff`)에서 자동 처리 감시 폴더(Processing Watched Folder) 파이프라인은 설정된 입력 디렉터리를 주기적으로 폴링하여 들어오는 파일을 처리하고 결과물을 출력 디렉터리에 기록합니다. `FolderInputSource.listFiles`의 링크 해석 방식과 `FolderAccessGuard.isProtected`의 경로 검증 방식 간의 불일치로 인해 감시 폴더 내부의 심볼릭 링크가 임의 파일 읽기 및 유출 수단(`CWE-59` / `CWE-61`)으로 악용됩니다.

1. **1단계 — `Files.isRegularFile`에서의 무검증 심볼릭 링크 추적 (`FolderInputSource.java:337-345`):**
   기본 `recursive=false` 모드에서 `FolderInputSource.listFiles`는 `Files.list(inputDir).filter(Files::isRegularFile)`로 디렉터리 항목을 순회합니다. 이때 `LinkOption.NOFOLLOW_LINKS`가 누락되어 있으므로 Java NIO는 `inputDir` 내부의 심볼릭 링크를 따라가 감시 루트 외부의 대상 파일을 확인하며, 대상이 일반 파일이면 `true`를 반환합니다.
2. **2단계 — `FolderAccessGuard.isProtected`의 어휘적 경로 단일 검증:**
   `FolderAccessGuard.isProtected(path)`는 실제 정규 경로(`toRealPath()`)를 확인하지 않고 어휘적 경로(`toAbsolutePath().normalize()`)만 정규화합니다. 따라서 `/watched/input/report.pdf -> /configs/settings.yml` 심볼릭 링크는 어휘적으로 `/watched/input` 내부에 있는 것으로 간주되어 `FolderAccessGuard`를 완전히 우회합니다.
3. **3단계 — 접근 가능한 출력 폴더로의 수집 및 기밀 유출 (`ProcessingFolderController.java:374-380`, `FolderOutputSink.java:338-345`):**
   백그라운드 파이프라인은 심볼릭 링크가 가리키는 대상 파일을 읽고 그 내용을 사용자가 접근할 수 있는 출력/보관 폴더에 복사합니다. 아이러니하게도 `recursive=true` 모드는 기본적으로 심볼릭 링크를 따라가지 않는 `Files.walkFileTree`를 사용하는 반면, 기본값인 `recursive=false` 모드는 무조건 심볼릭 링크를 따라갑니다.

### 취약한 코드 조각 (`FolderInputSource.java:337-346`)
```java
// File: app/proprietary/src/main/java/stirling/software/proprietary/policy/input/FolderInputSource.java (lines 337-346)
private static List<Path> listFiles(
        Path inputDir, boolean recursive, FolderAccessGuard accessGuard) throws IOException {
    List<Path> files = new ArrayList<>();
    if (!recursive) {
        try (Stream<Path> entries = Files.list(inputDir)) {
            entries.filter(Files::isRegularFile) // BUG: LinkOption.NOFOLLOW_LINKS 누락으로 inputDir 외부의 심볼릭 링크를 추적함!
                    .filter(file -> !hidden(file))
                    .forEach(files::add);        // BUG: accessGuard.isProtected(file) 및 정규 루트 경계 검증 누락!
        }
        return files;
    }
```

---

## 2. 일상 운영 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A` / `시나리오 B` / `시나리오 C`)

### 시나리오 A — 사내 공유 SMB / NFS 복합기 스캐너 수신 폴더를 통한 관리자 비밀번호 및 OAuth 비밀키 유출
1. 기업에서 임직원이 스캔 문서를 넣으면 자동으로 OCR 및 아카이빙이 수행되도록 공유 SMB/NFS 네트워크 폴더(`/mnt/scanner-incoming`)를 기본 `recursive=false` 모드로 Stirling-PDF에 연결하고 결과물을 `/mnt/scanner-processed`에 저장합니다.
2. 낮은 권한의 도메인 사용자 또는 내부 공격자가 공유 수신 폴더에 `ln -s /configs/settings.yml /mnt/scanner-incoming/invoice.pdf` 심볼릭 링크를 생성합니다.
3. `Files.isRegularFile(entry)`는 `settings.yml`을 가리키는 심볼릭 링크에 대해 `true`를 반환하고 `FolderAccessGuard.isProtected`는 어휘적 경로 `/mnt/scanner-incoming/invoice.pdf`만 검사하므로, 백그라운드 폴러가 `settings.yml`을 읽어 `SECURITY_INITIALADMINPASSWORD`, OAuth2 `clientSecret`, SMTP 자격 증명이 담긴 원본 YAML을 누구나 읽을 수 있는 `/mnt/scanner-processed` 폴더에 복사합니다.

### 시나리오 B — 외부 협력사 SFTP / Nextcloud 자동 문서 수집 파이프라인을 통한 호스트 SSH 개인키 및 `.env` 탈취
1. 법률 사무소나 의료 기관이 SFTP 또는 Nextcloud 외부 스토리지를 통해 외부 파트너가 업로드한 문서를 Stirling-PDF 감시 디렉터리와 동기화합니다.
2. 업로드된 항목에 `/home/community-user/.ssh/id_ed25519` 또는 `/app/configs/custom_settings.yml`을 가리키는 심볼릭 링크가 포함됩니다.
3. `FolderOutputSink.archiveOriginal()`(`FolderOutputSink.java:338-345`)은 `Files.notExists(target, NOFOLLOW_LINKS)`(심볼릭 링크의 경우 `false`)를 확인한 뒤 `NOFOLLOW_LINKS` 없이 `Files.move` / `Files.copy`를 호출하여 대상 기밀 파일을 파트너가 접근 가능한 출력 저장소로 그대로 아카이빙합니다.

### 시나리오 C — 멀티테넌트 공유 볼륨 환경에서 타 부서 기밀 문서 및 로컬 H2 데이터베이스 탈취
1. 조직이 단일 Stirling-PDF 컨테이너로 여러 부서의 감시 폴더(`/data/hr-watched`, `/data/finance-watched`, `/data/accounting-watched`)와 로컬 데이터베이스(`/configs/stirling-pdf.mv.db`)를 함께 운영합니다.
2. `/data/accounting-watched`에만 쓰기 권한이 있는 사용자가 `/data/hr-watched/executive-payroll.pdf` 또는 `/configs/stirling-pdf.mv.db`를 가리키는 심볼릭 링크를 배치합니다.
3. `FolderInputSource.listFiles`가 정규 루트 경계 검증(`staysWithinCanonicalRoot`)을 수행하지 않으므로 Stirling-PDF가 타 부서의 기밀 급여 문서나 내부 데이터베이스 파일을 읽어 회계 부서 출력 디렉터리에 기록합니다.

---

## 3. 예제 실행 및 검증 명령어

### 1. Sniper CLI로 대상 컴포넌트 감사
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/Stirling-PDF \
  --include "app/proprietary/src/main/java/stirling/software/proprietary/policy/input/FolderInputSource.java"
```

### 2. 로컬 격리 환경 재현 및 검증
```bash
# protected_configs와 watched_input을 시뮬레이션하는 격리된 임시 작업 공간 생성
WORKDIR="$(mktemp -d /tmp/stirling-cand02-XXXXXX)"
mkdir -p "$WORKDIR/protected_configs" "$WORKDIR/watched_input" "$WORKDIR/processed_output"
echo "SECURITY_INITIALADMINPASSWORD=super-secret-admin-pass" > "$WORKDIR/protected_configs/settings.yml"
echo "Benign document content" > "$WORKDIR/watched_input/benign.txt"

# watched_input 내부에 외부 protected_configs/settings.yml을 가리키는 심볼릭 링크 배치
ln -s "$WORKDIR/protected_configs/settings.yml" "$WORKDIR/watched_input/report.txt"
ls -la "$WORKDIR/watched_input"
rm -rf "$WORKDIR"
```

### 3. 자동화된 `RED -> GREEN + BENIGN` E2E 검증 하네스 실행
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand02
```

---

## 4. 엔드투엔드 런타임 증명 (`RED -> GREEN + BENIGN`) 및 방어 패치

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand02` 실행 결과:

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

### 경계 조건 명시
악용을 위해서는 Processing Watched Folder 기능이 활성화되어 있어야 하며, 공격자가 감시 입력 디렉터리에 심볼릭 링크를 생성할 수 있는 쓰기 권한(예: SMB/NFS/SFTP 공유 또는 컨테이너 공유 볼륨)을 가지고 있어야 합니다.

### Unified Diff 패치 (`git apply --check` 검증 완료)
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
