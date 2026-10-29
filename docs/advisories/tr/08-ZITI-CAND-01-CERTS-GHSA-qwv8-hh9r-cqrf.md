# `AreCertsTrusted()` Fonksiyonunun Koşulsuz Olarak `InsecureSkipVerify: true` Ayarlayarak `ziti edge login` Sırasında TLS Sertifika Doğrulamasını Devre Dışı Bırakması (`GHSA-qwv8-hh9r-cqrf`)

[English](../08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | **Türkçe** | [日本語](../ja/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | [简体中文](../zh-CN/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | [한국어](../ko/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)

## GitHub GHSA ve MITRE CNA Hızlı Doldurma Alanları
- **Depo (Repository):** `openziti/ziti`
- **GitHub Danışma (Advisory) URL'si:** `https://github.com/openziti/security/security/advisories/GHSA-qwv8-hh9r-cqrf`
- **Mevcut GHSA Kimliği:** `GHSA-qwv8-hh9r-cqrf`
- **Ekosistem:** `Go`
- **Paket Adı:** `github.com/openziti/ziti/v2`
- **Etkilenen Sürümler:** `<= v2 (commit 236f351a5149fe68328fc8083bebe514f0307d0c)`
- **Yamalı Sürümler:** `Yok (Savunma yaması aşağıda sunulmuştur)`
- **CWE:** `CWE-295 (Hatalı Sertifika Doğrulaması — Improper Certificate Validation)`
- **CVSS v3.1:** `7.4 Yüksek (High) — CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`
- **MITRE Üreticisi:** `NetFoundry / OpenZiti`
- **MITRE Zafiyet Türü:** `Hatalı Sertifika Doğrulaması (CWE-295)`
- **MITRE Etkilenen Bileşen(ler):** `ziti/util/certs.go (AreCertsTrusted & InsecureClient, satır 91-103, 199-208) ve ziti/cmd/edge/login.go (fetchTrustedServerCerts, satır 511, 535-549)`
- **MITRE Önerilen CVE Açıklaması (Türkçe Özeti):**
  > OpenZiti `ziti` (`github.com/openziti/ziti/v2`, commit `236f351a5149fe68328fc8083bebe514f0307d0c` ve öncesi) içerisinde, `ziti/util/certs.go` dosyasındaki `util.AreCertsTrusted` fonksiyonu `InsecureClient(&client, certs)` yardımcısını çağırır; bu yardımcı ise `len(certs) > 0` olduğunda bile koşulsuz olarak `tls.Config{InsecureSkipVerify: true}` ayarlar. Go'nun `crypto/tls` kütüphanesi `InsecureSkipVerify: true` olduğunda `RootCAs` havuzunu tamamen yok saydığı için `AreCertsTrusted` içindeki `x509.UnknownAuthorityError` kontrolü erişilemez ölü koda dönüşür ve `ziti edge login` sırasında her zaman `true` döndürerek güvenilmeyen bir TLS sertifikasına sahip ortadaki adam (MITM) saldırganının yönetici kimlik bilgilerini ele geçirmesine olanak tanır.
- **Bildiren / Araştırmacı:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
`openziti/ziti` (`github.com/openziti/ziti/v2`, commit `236f351a5149fe68328fc8083bebe514f0307d0c`) içerisinde yöneticilerin ve otomasyon araçlarının Ziti Edge Controller'a oturum açmak için kullandığı `ziti edge login` komutu (`ziti/cmd/edge/login.go:511, 535-549`), ilk bağlantıda sunucunun `/.well-known/est/cacerts` uç noktasından CA sertifika paketini indirir ve ardından sunucunun sunduğu TLS sertifikasının gerçekten bu CA tarafından imzalanıp imzalanmadığını doğrulamak için `util.AreCertsTrusted(host, wellKnownCerts, httpClient)` (`ziti/util/certs.go:91-103`) fonksiyonunu çağırır. Ancak `certs.go` içindeki tek satırlık bir mantık hatası, bu doğrulamayı tamamen devre dışı bırakarak **TLS Sertifika Doğrulama Atlama (`CWE-295`)** zafiyetine yol açmaktadır:

1. **Adım 1 — `AreCertsTrusted` İçinde `x509.UnknownAuthorityError` Yakalama Niyeti (`ziti/util/certs.go:91-103`):**
   Geliştirici `AreCertsTrusted` fonksiyonunu yazarken, verilen `certs` havuzunu kullanarak `host` adresine bir `GET` isteği yapmayı ve eğer sunucu sertifikası bu CA havuzu tarafından imzalanmamışsa Go'nun döndüreceği `x509.UnknownAuthorityError` hatasını yakalayıp (`satır 96`) `false, nil` döndürmeyi amaçlamıştır.
2. **Adım 2 — `InsecureClient(&client, certs)` İçinde `InsecureSkipVerify: true` Bayrağının Koşulsuz Açık Bırakılması (`ziti/util/certs.go:199-208`):**
   `AreCertsTrusted`, HTTP istemcisini oluşturmak için `InsecureClient(&client, certs)` fonksiyonunu çağırır. `InsecureClient` ise `len(certs) > 0` olduğunda sertifikaları `tlsConfig.RootCAs` havuzuna eklemesine rağmen, `202. satırda` `InsecureSkipVerify: true` ayarını koşulsuz olarak `true` bırakır!
3. **Adım 3 — Go `crypto/tls` Standart Kütüphanesinin `RootCAs` Havuzunu Tamamen Yok Sayması ve Ölü Kod (*Dead Code*) Oluşumu:**
   Go'nun `crypto/tls` (`handshake_client.go`) kütüphanesinde `InsecureSkipVerify: true` olduğunda TLS el sıkışması hiçbir kök sertifika (`RootCAs`) veya alan adı kontrolü yapmaz ve **asla** `x509.UnknownAuthorityError` döndürmez. Böylece `certs.go:96` satırındaki kontrol erişilemez ölü koda (*dead code*) dönüşür, `AreCertsTrusted` sahte veya kendi kendine imzalı (*self-signed*) her sertifika için her zaman `true, nil` döndürür ve `login.go:511` ekrana yanıltıcı biçimde `"Verified that server supplied certificates are trusted by server"` yazarak yönetici şifresini saldırgana gönderir.

### Zafiyetli Kod Kesiti (`ziti/util/certs.go:91-103, 199-208`)
```go
// Dosya: ziti/util/certs.go (satır 91-103, 199-208)
func AreCertsTrusted(host string, certs []byte, httpClient *http.Client) (bool, error) {
	client := *httpClient
	resp, err := InsecureClient(&client, certs).Get(host)
	if err != nil {
		if ue, ok := err.(*url.Error); ok && errors.As(ue.Err, &x509.UnknownAuthorityError{}) {
			return false, nil // ÖLÜ KOD (DEAD CODE): InsecureSkipVerify her zaman true olduğu için buraya asla ulaşılamaz!
		}
		return false, err
	}
	_ = resp.Body.Close()
	return true, nil
}
...
func InsecureClient(client *http.Client, certs []byte) *http.Client {
	tlsConfig := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		InsecureSkipVerify: true, // HATA: RootCAs havuzunun doğrulanması için len(certs) == 0 olmalıdır!
	}
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — DevOps Mühendisi `ziti edge login` Çalıştırdığında Sahte Sertifikalı MITM Saldırganının Yönetici Şifresini Ele Geçirmesi
1. Bir altyapı yöneticisi, iş istasyonundan `ziti edge login https://ziti-controller.internal:1280 -u admin -p <AdminPassword>` komutunu çalıştırır.
2. Ağdaki aktif bir saldırgan (ARP zehirleme, sahte Wi-Fi erişim noktası veya DNS/BGP yönlendirmesi ile) bağlantıyı kendi oluşturduğu sahte (*self-signed*) bir TLS sertifikasıyla karşılar.
3. `AreCertsTrusted` fonksiyonu `InsecureSkipVerify: true` nedeniyle sahte TLS sertifikasının CA paketiyle uyumsuz olduğunu fark etmez, ekrana `"Verified that server supplied certificates are trusted by server"` yazar ve yönetici kullanıcı adı ile şifresini doğrudan saldırgana teslim eder.

### Senaryo B — Otomatik CI/CD ve Kubernetes Sıfır Güven (*Zero-Trust*) Bootstrap İş Akışlarının Sahte Kontrolcüye Kaydedilmesi
1. Kurumsal bir CI/CD hattı veya Kubernetes başlangıç betiği, yeni mikroservis kimliklerini ve yönlendirici (*router*) politikalarını oluşturmak için `ziti edge login --yes` komutunu çalıştırır.
2. Ağ katmanında araya giren bir saldırgan veya yanlış yapılandırılmış bir vekil sunucu (*reverse proxy*), geçerli Ziti CA'sı tarafından imzalanmamış rastgele bir TLS sertifikası sunar.
3. `AreCertsTrusted()` her koşulda `true` döndürdüğü için otomasyon hattı sahte sertifikayı yerel güven deposuna kaydeder ve tüm Zero-Trust ağ politikası anahtarlarını saldırgana sızdırır.

### Senaryo C — Süresi Dolmuş, İptal Edilmiş veya Yanlış Ortama (`Staging` vs `Production`) Ait Kontrolcü Sertifikasının Sessizce Kabul Edilmesi
1. Birden fazla OpenZiti ortamı (`dev`, `staging`, `prod`) yöneten bir güvenlik ekibi, bir yük dengeleyici (*load balancer*) veya Ingress arkasında yanlışlıkla farklı bir CA'ya ait veya süresi dolmuş/kendi kendine imzalı bir uç sertifikayı devreye alır.
2. `ziti edge login` normalde `Server supplied certs are not trusted by server` (`login.go:545`) uyarısı vererek operatörü durdurması gerekirken, `InsecureSkipVerify: true` yüzünden sertifikanın geçerli olduğunu bildirir ve üretim ortamı kimlik bilgilerinin yanlış/güvensiz uç noktaya akmasına neden olur.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

### 1. Sniper CLI ile Hedef Bileşenin Denetlenmesi
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/ziti \
  --include "ziti/util/certs.go"
```

### 2. İzole Yerel Test Ortamında (`127.0.0.1`) Tetikleme ve Doğrulama
```bash
# Yerel 127.0.0.1 TLS sunucusuna karşı AreCertsTrusted davranışını kanıtlayan Go birim testini çalıştırın
cd /home/community-user/targets/ziti && go test -v -run TestRealOpenZitiAreCertsTrusted ./ziti/util
```

### 3. Otomatik `RED -> GREEN + BENIGN` E2E Doğrulama Testinin Çalıştırılması
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_ziti_cand01
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Hem `go test -v -run TestRealOpenZitiAreCertsTrusted ./ziti/util` (`0.014s` içinde `PASS`) hem de `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_ziti_cand01` ile doğrulanmıştır:

```json
{
  "ZITI-CAND-01": {
    "ghsa_id": "GHSA-qwv8-hh9r-cqrf",
    "source_file": "ziti/ziti/util/certs.go",
    "login_caller_file": "ziti/ziti/cmd/edge/login.go",
    "elapsed_ms": 0.719,
    "RED": {
      "insecure_skip_verify": true,
      "rogue_mitm_cert_accepted_as_trusted": true,
      "admin_credentials_sent_to_mitm": true
    },
    "GREEN": {
      "insecure_skip_verify": false,
      "rogue_mitm_cert_accepted_as_trusted": false,
      "tls_error": "x509.UnknownAuthorityError: certificate signed by unknown authority"
    },
    "BENIGN": {
      "valid_ca_signed_controller_trusted": true
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/ziti/util/certs.go
+++ b/ziti/util/certs.go
@@ -199,7 +199,7 @@
 func InsecureClient(client *http.Client, certs []byte) *http.Client {
 	tlsConfig := &tls.Config{
 		RootCAs:            x509.NewCertPool(),
-		InsecureSkipVerify: true,
+		InsecureSkipVerify: len(certs) == 0,
 	}
 
 	if len(certs) > 0 {
```
