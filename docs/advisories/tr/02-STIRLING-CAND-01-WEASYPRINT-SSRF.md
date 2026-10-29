# `ConvertWebsiteToPDF.java` İçinde Eksik `CVE-2026-71270` / `GHSA-j5rg-wh78-9f2q` Yaması Nedeniyle WeasyPrint Alt Kaynak SSRF Zafiyeti (`GHSA-ff6j-8xch-j8r6`)

[English](../02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | **Türkçe** | [日本語](../ja/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | [简体中文](../zh-CN/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | [한국어](../ko/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
`Stirling-Tools/Stirling-PDF` (`v3.2.2`, commit `684608d143779bf3a8ffc67639f077a1202c62ff`) içerisinde daha önce yayınlanan `CVE-2026-71270` (`GHSA-j5rg-wh78-9f2q`) yaması, `FileToPdf.java:63-91` (`ConvertHtmlToPDF`) uç noktasında HTML içeriğini `customHtmlSanitizer.sanitize()` (`SsrfProtectionService`) ile temizlemiş ve WeasyPrint alt sürecini `--allowed-protocols data` ile sınırlandırmıştı. Ancak aynı WeasyPrint motorunu çağıran kardeş uç nokta `POST /api/v1/convert/url/pdf` (`ConvertWebsiteToPDF.java:116-143`) unutulmuş ve eksik yama nedeniyle **Tam Okumalı SSRF (`CWE-918`)** zafiyetine açık kalmıştır:

1. **Adım 1 — `fetchRemoteHtml(URL)` Sonrasında `customHtmlSanitizer.sanitize()` Çağrısının Eksik Olması (`ConvertWebsiteToPDF.java:115-116`):**
   Kullanıcı `POST /api/v1/convert/url/pdf` uç noktasına dış dünyadaki bir web sayfasının adresini (`https://attacker.example/invoice.html`) gönderdiğinde, Java katmanı yalnızca ana URL'yi doğrular ve HTML metnini `fetchRemoteHtml(URL)` ile indirir. Ancak indirilen HTML içindeki alt kaynaklar (`<link rel="stylesheet">`, `<img src="...">`, CSS `@import`) `customHtmlSanitizer.sanitize()` süzgecinden geçirilmez.
2. **Adım 2 — WeasyPrint Alt Sürecine `--allowed-protocols data,http,https` ve `--base-url` Verilmesi (`ConvertWebsiteToPDF.java:137-140`):**
   Java uygulaması, indirdiği ham HTML dosyasını Python tabanlı WeasyPrint ikili dosyasına verirken `--allowed-protocols data,http,https` argümanını geçirir. WeasyPrint kendi bağımsız HTTP istemcisine sahip olduğu için Java'daki `SsrfProtectionService` kontrollerine hiç uğramaz.
3. **Adım 3 — Dahili (`127.0.0.1` / `169.254.169.254`) Yanıtların PDF İçine İşlenerek Saldırgana Döndürülmesi:**
   Saldırganın HTML sayfası içerisine yerleştirilen `<link rel="stylesheet" href="http://127.0.0.1:8080/internal-secrets.css">` veya `http://169.254.169.254/latest/meta-data/...` adresleri WeasyPrint tarafından doğrudan çekilir, CSS `content:` veya görsel/metin olarak oluşturulan PDF sayfasına basılır ve oluşan PDF dosyası HTTP yanıtı olarak saldırgana indirilir.

### Zafiyetli Kod Kesiti (`ConvertWebsiteToPDF.java:114-141`)
```java
// Dosya: app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java (satır 114-141)
            // Tehlikeli şemalara izin vermemek için önce uzak içeriği indir
            String htmlContent = fetchRemoteHtml(URL); // HATA 1: customHtmlSanitizer.sanitize() süzgecinden hiç geçirilmez!
...
            List<String> command = new ArrayList<>();
            command.add(runtimePathConfig.getWeasyPrintPath());
            command.add(tempHtmlInput.toString());
            command.add("--base-url");
            command.add(URL);
            command.add("--pdf-forms");
            command.add("--allowed-protocols");
            command.add("data,http,https");            // HATA 2: WeasyPrint'in dahili HTTP/HTTPS adreslerini çekmesine izin verir!
            command.add(tempOutputFile.toString());
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Fatura / Makbuz URL-to-PDF Servisinden Bulut IAM Kimlik Bilgilerinin (`169.254.169.254`) Çalınması
1. Bir şirket, müşterilerin veya arka ofis çalışanlarının web üzerindeki e-arşiv fatura bağlantılarından PDF üretmesi için Stirling-PDF'in `/api/v1/convert/url/pdf` uç noktasını AWS/GCP/Azure üzerinde çalıştırır.
2. Saldırgan, dışarıdan erişilebilen kendi web sunucusundaki bir URL'yi (`https://attacker.example/receipt.html`) gönderir. Bu URL ilk aşamada genel bir IP adresine çözümlendiği için Java'nın üst düzey URL kontrolünden geçer.
3. Sayfanın içindeki `<link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/iam/security-credentials/prod-role">` veya dahili yönetici paneline işaret eden alt kaynak WeasyPrint tarafından çekilir ve geçici AWS IAM anahtarları oluşturulan PDF dosyasının içine yazılarak saldırgana indirilir.

### Senaryo B — Kurumsal Kubernetes Kümesi İçindeki Korumasız Mikroservislerin (`Prometheus`, `Consul`, `Actuator`) Keşfi ve Sızdırılması
1. Stirling-PDF, kurumsal bir Kubernetes kümesi (`cluster.local`) içerisinde belge dönüştürme mikroservisi olarak çalışmaktadır; dış ağdan yalnızca Stirling-PDF'in `/api/v1/convert/url/pdf` uç noktasına izin verilmektedir.
2. Saldırgan, HTML sayfasının içine `@import url("http://10.96.0.15:9090/metrics");` veya `<img src="http://localhost:8080/actuator/env">` alt kaynakları ekler.
3. WeasyPrint alt süreci bu iç ağ adreslerine doğrudan HTTP isteği gönderir; yanıt içerikleri veya hata durumları PDF çıktısı üzerinden okunarak tüm iç ağ topolojisi ve ortam değişkenleri sızdırılır.

### Senaryo C — Otomatik Web Arşivleme ve Uyumluluk (*Compliance*) İş Akışlarında Kötü Amaçlı Üçüncü Taraf Sayfası Üzerinden İç Ağ Sızıntısı
1. Bir finans veya medya kuruluşu, denetim ve uyumluluk amacıyla dış web sayfalarını düzenli olarak PDF formatında arşivlemek için Stirling-PDF'in `/api/v1/convert/url/pdf` API'sini otomatik bir iş akışıyla çağırır.
2. Arşivlenen üçüncü taraf sitedeki bir reklam bileşeni veya değiştirilmiş CSS dosyası `http://127.0.0.1:3000/api/keys` adresine referans verir.
3. Arşivleme botu oluşturulan PDF'i paydaşlara veya genel arşive kaydettiğinde, sunucunun yerel servislerindeki gizli veriler PDF belgesinin içinde dışarıya sızmış olur.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

### 1. Sniper CLI ile Hedef Bileşenin Denetlenmesi
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/Stirling-PDF \
  --include "app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java"
```

### 2. İzole Yerel Test Ortamında Tetikleme ve Doğrulama
```bash
# ConvertWebsiteToPDF.java ve FileToPdf.java içindeki WeasyPrint protokol yapılandırmasını karşılaştırın
grep -n -C 8 "allowed-protocols" \
  /home/community-user/targets/Stirling-PDF/app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java \
  /home/community-user/targets/Stirling-PDF/app/common/src/main/java/stirling/software/common/util/FileToPdf.java
```

### 3. Otomatik `RED -> GREEN + BENIGN` E2E Doğrulama Testinin Çalıştırılması
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand01
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand01` komutu ile üretilen çalışma zamanı kanıtı:

```json
{
  "STIRLING-CAND-01": {
    "ghsa_id": "GHSA-ff6j-8xch-j8r6",
    "source_file": "stirling-pdf/app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java",
    "sibling_reference_file": "stirling-pdf/app/common/src/main/java/stirling/software/common/util/FileToPdf.java",
    "patch_file": "pre-submission-verification-20261026/patches/STIRLING-CAND-01.patch",
    "patch_sha256": "92f223eb7f8c5a0fc88f705778ce5c45e9f9d77b756128fd6f889e365a673e23",
    "upstream_cve_duplicate_status": "Incomplete Fix / Variant of CVE-2026-71270 / GHSA-j5rg-wh78-9f2q in v3.2.2",
    "elapsed_ms": 16.108,
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
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java
+++ b/app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java
@@ -112,8 +114,8 @@
         Path tempOutputFile = null;
         Path tempHtmlInput = null;
         try {
-            // Download the remote content first to ensure we don't allow dangerous schemes
-            String htmlContent = fetchRemoteHtml(URL);
+            // Download and sanitize remote content via CustomHtmlSanitizer (SsrfProtectionService)
+            String htmlContent = customHtmlSanitizer.sanitize(fetchRemoteHtml(URL));
 
             if (containsDisallowedUriScheme(htmlContent)) {
                 URI rejectionLocation =
@@ -135,11 +137,9 @@
             List<String> command = new ArrayList<>();
             command.add(runtimePathConfig.getWeasyPrintPath());
             command.add(tempHtmlInput.toString());
-            command.add("--base-url");
-            command.add(URL);
             command.add("--pdf-forms");
             command.add("--allowed-protocols");
-            command.add("data,http,https");
+            command.add(customHtmlSanitizer.isDisabled() ? "data,http,https" : "data");
             command.add(tempOutputFile.toString());
```
