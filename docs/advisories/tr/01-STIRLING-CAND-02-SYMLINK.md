# Varsayılan `recursive=false` Modunda `FolderAccessGuard.isProtected` Kontrolünü Atlayan İzlenen Klasör Sembolik Bağ Kaçışı (`GHSA-hpc7-xx5r-gc44`)

[English](../01-STIRLING-CAND-02-SYMLINK.md) | **Türkçe** | [日本語](../ja/01-STIRLING-CAND-02-SYMLINK.md) | [简体中文](../zh-CN/01-STIRLING-CAND-02-SYMLINK.md) | [한국어](../ko/01-STIRLING-CAND-02-SYMLINK.md)

## GitHub GHSA ve MITRE CNA Hızlı Doldurma Alanları
- **Depo (Repository):** `Stirling-Tools/Stirling-PDF`
- **GitHub Danışma (Advisory) URL'si:** `https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/GHSA-hpc7-xx5r-gc44`
- **Mevcut GHSA Kimliği:** `GHSA-hpc7-xx5r-gc44`
- **Ekosistem:** `Maven`
- **Paket Adı:** `stirling.software:stirling-pdf`
- **Etkilenen Sürümler:** `<= 3.2.2 (commit 684608d143779bf3a8ffc67639f077a1202c62ff)`
- **Yamalı Sürümler:** `Yok (Savunma yaması aşağıda sunulmuştur)`
- **CWE:** `CWE-59 (Dosya Erişimi Öncesi Hatalı Bağ Çözümleme) / CWE-61 (UNIX Sembolik Bağ Takibi)`
- **CVSS v3.1:** `7.1 Yüksek (High) — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **MITRE Üreticisi:** `Stirling-Tools`
- **MITRE Zafiyet Türü:** `Sembolik Bağ Takibi / Hatalı Bağ Çözümleme (CWE-59)`
- **MITRE Etkilenen Bileşen(ler):** `FolderInputSource.java (listFiles, satır 337-377), ProcessingFolderController.java (satır 374-380), FolderOutputSink.java (archiveOriginal, satır 338-345)`
- **MITRE Önerilen CVE Açıklaması (Türkçe Özeti):**
  > Stirling-Tools Stirling-PDF 3.2.2 ve önceki sürümlerinde, izlenen klasör belge işleme hattı (`FolderInputSource.java`, `ProcessingFolderController.java` ve `FolderOutputSink.java`) varsayılan `recursive=false` modunda `LinkOption.NOFOLLOW_LINKS` bayrağı olmadan `Files.isRegularFile(path)` metodunu kullanırken, `FolderAccessGuard.isProtected` yalnızca izlenen dizin içindeki sözcüksel (lexical) yolu doğrular. İzlenen giriş klasörüne yazma erişimi olan bir saldırgan, korumalı yapılandırma dosyalarına (`settings.yml` gibi) işaret eden bir sembolik bağ bırakarak Stirling-PDF'in hassas kimlik bilgilerini okuyup erişilebilir çıktı dizinine kopyalamasına ve arşivlemesine neden olabilir.
- **Bildiren / Araştırmacı:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
`Stirling-Tools/Stirling-PDF` (`v3.2.2`, commit `684608d143779bf3a8ffc67639f077a1202c62ff`) içerisindeki otomatik klasör izleme (*Automated Processing Watched Folder*) mekanizması, belirlenen bir giriş klasörüne bırakılan belgeleri arka planda tarayıp işleyerek çıkış klasörüne aktarır. Ancak varsayılan `recursive=false` modunda iki temel dosya sistemi kontrolü arasındaki uyumsuzluk doğrudan bir **Sembolik Bağ Kaçışı (`Symlink Escape`, `CWE-59` / `CWE-61`)** zafiyetine yol açmaktadır:

1. **Adım 1 — `Files.isRegularFile(path)` Çağrısının Sembolik Bağları Takip Etmesi (`FolderInputSource.java:337-345`):**
   Java NIO kütüphanesinde `Files.isRegularFile(path)` metodu, ikinci parametre olarak `LinkOption.NOFOLLOW_LINKS` verilmediği sürece sembolik bağları (*symlink*) otomatik olarak hedef dosyaya kadar takip eder. Saldırgan izlenen klasöre `/configs/settings.yml` dosyasına işaret eden `invoice.pdf` adında bir sembolik bağ bıraktığında, hedef dosya gerçek bir dosya olduğu için `Files.isRegularFile(entry)` `true` döndürür.
2. **Adım 2 — `FolderAccessGuard.isProtected(path)` Kontrolünün Yalnızca Sözcüksel (*Lexical*) Yolu Doğrulaması:**
   Korumalı sistem dizinlerine (`/configs`, `/logs`, `/customFiles`) erişimi engellemek için tasarlanan `FolderAccessGuard.isProtected(path)` metodu, sembolik bağın gerçek hedefini (`toRealPath()`) çözmek yerine yalnızca sözcüksel yolu (`path.toAbsolutePath().normalize()`) kontrol eder. Sembolik bağın görünür yolu `/mnt/scanner-incoming/invoice.pdf` olduğu için `FolderAccessGuard` bu dosyayı güvenli kabul eder.
3. **Adım 3 — Korumalı Sunucu Yapılandırmasının Okunup Çıkış Klasörüne Kopyalanması (`FolderOutputSink.java:338-345`):**
   Arka plan işleyici (*poller*), sembolik bağı açarak hedeflediği `/configs/settings.yml` (veya `.env`, SSH anahtarları) dosyasını okur ve `FolderOutputSink.archiveOriginal()` aracılığıyla işlenmiş/arşivlenmiş çıktı olarak kullanıcının okuma yetkisi bulunan çıkış dizinine kopyalar. Üstelik aynı dosyadaki `recursive=true` dalı `Files.walkFileTree` kullandığı için varsayılan olarak sembolik bağları takip etmezken, daha güvenli olduğu düşünülen varsayılan `recursive=false` dalı `Files.list(inputDir).filter(Files::isRegularFile)` çağrısıyla sembolik bağları sessizce takip etmektedir.

### Zafiyetli Kod Kesiti (`FolderInputSource.java:337-346`)
```java
// Dosya: app/proprietary/src/main/java/stirling/software/proprietary/policy/input/FolderInputSource.java (satır 337-346)
private static List<Path> listFiles(
        Path inputDir, boolean recursive, FolderAccessGuard accessGuard) throws IOException {
    List<Path> files = new ArrayList<>();
    if (!recursive) {
        try (Stream<Path> entries = Files.list(inputDir)) {
            entries.filter(Files::isRegularFile) // HATA: LinkOption.NOFOLLOW_LINKS eksik; inputDir dışındaki sembolik bağları takip eder!
                    .filter(file -> !hidden(file))
                    .forEach(files::add);        // HATA: accessGuard.isProtected(file) ve kanonik kök dizin kontrolü eksik!
        }
        return files;
    }
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Kurumsal SMB / NFS Ofis Tarayıcı Klasöründen Yönetici ve OAuth Sırlarının Sızdırılması
1. Bir kurum, çalışanların tarayıcıdan çıkan belgeleri otomatik OCR ve arşivleme için bırakabilmesi amacıyla paylaşımlı bir SMB/NFS ağ klasörünü (`/mnt/scanner-incoming`) varsayılan `recursive=false` modunda Stirling-PDF'e bağlar; işlenen dosyalar `/mnt/scanner-processed` klasörüne yazılır.
2. Düşük yetkili bir etki alanı kullanıcısı veya ağa erişen saldırgan, paylaşımlı klasöre `ln -s /configs/settings.yml /mnt/scanner-incoming/invoice.pdf` komutunu kullanarak bir sembolik bağ bırakır.
3. Arka plan tarayıcısı `Files.isRegularFile` kontrolünden geçen bu bağı takip ederek `/configs/settings.yml` dosyasını okur ve içinde `SECURITY_INITIALADMINPASSWORD`, OAuth2 `clientSecret` ve SMTP kimlik bilgilerinin bulunduğu yapılandırma dosyasını herkesin okuyabildiği `/mnt/scanner-processed` dizinine kopyalar.

### Senaryo B — SFTP / Nextcloud Otomatik Belge Aktarım Hattında Ana Bilgisayar SSH Anahtarlarının veya `.env` Dosyalarının Okunması
1. Bir hukuk bürosu veya sağlık kuruluşu, dış iş ortaklarından SFTP veya Nextcloud harici depolama alanı üzerinden gelen dosyaları Stirling-PDF'in izlediği klasörle senkronize eder.
2. Dış yükleme kanalından `/home/community-user/.ssh/id_ed25519` veya `/app/configs/custom_settings.yml` dosyasına işaret eden bir sembolik bağ oluşturulur.
3. `FolderOutputSink.archiveOriginal()` (`FolderOutputSink.java:338-345`) metodu `Files.notExists(target, NOFOLLOW_LINKS)` kontrolünden sonra `NOFOLLOW_LINKS` olmadan `Files.move` / `Files.copy` çalıştırarak hedef gizli anahtar dosyasını doğrudan dış iş ortağının erişebildiği arşiv klasörüne aktarır.

### Senaryo C — Çok Kiracılı (*Multi-Tenant*) Kubernetes / Docker Volume Ortamında Departmanlar Arası Gizli Belge ve Veritabanı Sızıntısı
1. Bir şirkette İK (`hr-watched`), Finans (`finance-watched`) ve Muhasebe (`accounting-watched`) departmanları aynı Stirling-PDF konteynerinde ayrı izlenen klasörler kullanmaktadır.
2. Muhasebe klasörüne yazma yetkisi olan bir kullanıcı, kendi klasörüne `ln -s /data/hr-watched/executive-payroll.pdf /data/accounting-watched/payroll.pdf` veya yerel H2/SQLite veritabanı dosyasına (`/configs/stirling-pdf.mv.db`) işaret eden bir sembolik bağ bırakır.
3. Stirling-PDF, `canonicalRoot` doğrulaması yapmadığı için İK departmanının gizli maaş bordrosunu veya kullanıcı parola özetlerini içeren veritabanı dosyasını okuyup muhasebe departmanının çıktı klasörüne teslim eder.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

### 1. Sniper CLI ile Hedef Bileşenin Denetlenmesi
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/Stirling-PDF \
  --include "app/proprietary/src/main/java/stirling/software/proprietary/policy/input/FolderInputSource.java"
```

### 2. İzole Yerel Test Ortamında Tetikleme ve Doğrulama
```bash
# Korumalı yapılandırma (protected_configs) ve izlenen giriş (watched_input) dizinlerini simüle eden izole bir alan oluşturun
WORKDIR="$(mktemp -d /tmp/stirling-cand02-XXXXXX)"
mkdir -p "$WORKDIR/protected_configs" "$WORKDIR/watched_input" "$WORKDIR/processed_output"
echo "SECURITY_INITIALADMINPASSWORD=super-secret-admin-pass" > "$WORKDIR/protected_configs/settings.yml"
echo "Normal belge icerigi" > "$WORKDIR/watched_input/benign.txt"

# watched_input içerisine protected_configs/settings.yml dosyasına işaret eden bir sembolik bağ bırakın
ln -s "$WORKDIR/protected_configs/settings.yml" "$WORKDIR/watched_input/report.txt"
ls -la "$WORKDIR/watched_input"
rm -rf "$WORKDIR"
```

### 3. Otomatik `RED -> GREEN + BENIGN` E2E Doğrulama Testinin Çalıştırılması
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand02
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand02` komutu ile üretilen çalışma zamanı kanıtı:

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

### Sınır Koşulları (Boundary Qualification)
Bu zafiyetin istismar edilebilmesi için İzlenen Klasör (*Processing Watched Folder*) özelliğinin etkinleştirilmiş olması ve saldırganın izlenen giriş dizinine (örneğin paylaşımlı SMB/NFS/SFTP klasörü veya konteyner hacmi üzerinden) sembolik bağ bırakabilecek yazma erişimine sahip olması gerekir.

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
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
