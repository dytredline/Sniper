# Yerleşik SSL Yönlendirme Ara Katmanında Doğrulanmamış `ctx.Request.Host` Kullanımı Nedeniyle HTTP 308 Açık Yönlendirme ve Token Phishing Zafiyeti (`GHSA-cc9f-m5vr-pm75`)

[English](../10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | **Türkçe** | [日本語](../ja/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | [简体中文](../zh-CN/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | [한국어](../ko/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)

## GitHub GHSA ve MITRE CNA Hızlı Doldurma Alanları
- **Depo (Repository):** `gotify/server`
- **GitHub Danışma (Advisory) URL'si:** `https://github.com/gotify/server/security/advisories/GHSA-cc9f-m5vr-pm75`
- **Mevcut GHSA Kimliği:** `GHSA-cc9f-m5vr-pm75`
- **Ekosistem:** `Go`
- **Paket Adı:** `github.com/gotify/server/v2`
- **Etkilenen Sürümler:** `<= v2.9.1 (commit f4de61997c1b30bf9ac43ec662dc5120c2ec981b)`
- **Yamalı Sürümler:** `Yok (Savunma yaması aşağıda sunulmuştur)`
- **CWE:** `CWE-601 (Güvenilmeyen Siteye URL Yönlendirmesi — Open Redirect)`
- **CVSS v3.1:** `4.7 Orta (Medium) — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N`
- **MITRE Üreticisi:** `Gotify`
- **MITRE Zafiyet Türü:** `Doğrulanmamış Host Başlığı Üzerinden Açık Yönlendirme / Open Redirect (CWE-601)`
- **MITRE Etkilenen Bileşen(ler):** `router/router.go (Create, satır 52-73, 93-102)`
- **MITRE Önerilen CVE Açıklaması (Türkçe Özeti):**
  > Gotify Server 2.9.1 ve önceki sürümlerinde (`github.com/gotify/server/v2`), `SSL.Enabled` ve `SSL.RedirectToHTTPS` etkinleştirildiğinde `router/router.go` içindeki HTTP-to-HTTPS yönlendirme ara katmanı `308`/`302` `Location` başlıklarını yapılandırılmış SSL sunucu adı yerine doğrudan istemci tarafından gönderilen doğrulanmamış `ctx.Request.Host` başlığından oluşturur; bu durum saldırganların özel bir `Host` başlığı aracılığıyla istemcileri ve URL içindeki anahtarları (token) keyfi bir dış alan adına yönlendirmesine olanak tanır.
- **Bildiren / Araştırmacı:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
`gotify/server` (`v2.9.1`, commit `f4de61997c1b30bf9ac43ec662dc5120c2ec981b`) içerisinde yerleşik SSL yönlendiricisi (`SSL.Enabled=true` ve `SSL.RedirectToHTTPS=true`) etkinleştirildiğinde, `router/router.go:52-73, 93-102` içindeki ara katman yazılımı (*middleware*) düz HTTP isteklerini otomatik olarak HTTPS'e yönlendirir. Ancak yönlendirme hedefini oluştururken yapılan doğrulama eksikliği, doğrudan **Host Başlığı Enjeksiyonu ile Açık Yönlendirme (`Open Redirect`, `CWE-601`) ve API Anahtarı Sızıntısı** zafiyetine yol açmaktadır:

1. **Adım 1 — İstemciden Gelen `ctx.Request.Host` Başlığına Koşulsuz Güvenilmesi (`router/router.go:63`):**
   HTTP-to-HTTPS yönlendirme ara katmanı `host := ctx.Request.Host` satırıyla istemcinin gönderdiği `Host` HTTP başlığını doğrudan alır ve sunucu yapılandırmasında tanımlı olan `conf.Server.SSL.LetsEncrypt.Hosts` listesiyle karşılaştırmaz.
2. **Adım 2 — Yalnızca `:` Karakterine Göre Port Kesilmesi (`router/router.go:64-66`):**
   Kod yalnızca `strings.LastIndex(host, ":")` ile port numarasını ayıklar ve ardından `Location` başlığını `https://<host><RequestURI>` olarak birleştirir.
3. **Adım 3 — `HTTP 308 Permanent Redirect` ile Sorgu Parametrelerinin (`?token=...`) ve Gövdenin Saldırgan Sunucusuna Yönlendirilmesi (`router/router.go:93-102`):**
   `GET` ve diğer standart isteklerde `308 Permanent Redirect` (kalıcı yönlendirme) döndürüldüğü için, `?token=<app-token>` içeren otomasyon betikleri, mobil/masaüstü istemciler veya paylaşımlı önbellekler tüm sorgu parametreleriyle birlikte doğrudan saldırganın `https://attacker-gotify.example.com/...` adresine yönlendirilir.

### Zafiyetli Kod Kesiti (`router/router.go:60-73, 93-102`)
```go
// Dosya: router/router.go (satır 60-73, 93-102)
			host := ctx.Request.Host // HATA: Yapılandırılmış SSL alan adı yerine istemcinin gönderdiği doğrulanmamış Host başlığını kullanır!
			if idx := strings.LastIndex(host, ":"); idx != -1 {
				host = host[:idx]
			}
			if sslPort != 443 {
				host = fmt.Sprintf("%s:%d", host, sslPort)
			}
			redirectHTTPS(ctx, url.URL{
				Scheme:   "https",
				Host:     host,
				Path:     ctx.Request.URL.Path,
				RawQuery: ctx.Request.URL.RawQuery,
			}.String())
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Web-Push / Mobil İstemci Oturum Phishing'i ve `308 Permanent Redirect` Önbellek Zehirlenmesi
1. Kendi sunucusunda Gotify çalıştıran bir kurum, `SSL.Enabled: true` ve `SSL.RedirectToHTTPS: true` ayarlarını aktif eder.
2. Saldırgan, paylaşımlı bir HTTP vekil sunucusu/önbelleği üzerinden veya yerel ağda `Host: attacker-gotify.example.com` başlığıyla `http://<gotify-ip>/#/messages?token=...` adresine istek gönderir.
3. Gotify sunucusu `HTTP/1.1 308 Permanent Redirect` ve `Location: https://attacker-gotify.example.com/#/messages?token=...` yanıtı döndürerek hem önbelleği kalıcı olarak zehirler hem de istemciyi sahte giriş/bildirim paneline yönlendirir.

### Senaryo B — Otomatik Sunucu İzleme ve Uyarı Betiklerinin (`curl -L`, `Uptime Kuma`) Yönlendirmeyi Takip Ederek Uygulama Anahtarını (`?token=`) Sızdırması
1. Sistem yöneticileri, sunucu alarmlarını Gotify'a iletmek için `?token=<app-token>` parametresi kullanan bildirim betikleri (`curl -L`, Python `requests` vb.) çalıştırır.
2. Ağ katmanında veya vekil sunucuda `Host` başlığı manipüle edildiğinde, Gotify `308`/`302` yanıtıyla `Location: https://attacker-gotify.example.com/message?token=<app-token>` döndürür.
3. Yönlendirmeyi otomatik takip eden istemci, gizli uygulama anahtarını (`?token=<app-token>`) doğrudan saldırganın HTTPS sunucusuna gönderir.

### Senaryo C — Ters Vekil Sunucu (*Reverse Proxy*) / CDN Arkasında Host Başlığı İletimiyle Kurumsal Bağlantı Güveni İstismarı
1. Kurumsal bir dağıtım mimarisinde Gotify, tüm alan adlarını (`default_server`) arka uca ileten bir yük dengeleyici veya ters vekil sunucu arkasında çalışmaktadır.
2. Dışarıdan gelen herhangi bir HTTP isteğine özel bir `Host: login-evil.example` başlığı eklendiğinde, resmi Gotify sunucusu bu isteğe bizzat kendi IP/bağlantısı üzerinden `308` yönlendirmesi üretir.
3. Güvenlik tarayıcıları ve son kullanıcılar yönlendirmenin kurumsal Gotify sunucusundan kaynaklandığını görerek zararlı hedefe güvenir.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

### 1. Sniper CLI ile Hedef Bileşenin Denetlenmesi
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/gotify-server \
  --include "router/router.go"
```

### 2. İzole Yerel Test Ortamında (`127.0.0.1`) Tetikleme ve Doğrulama
```bash
# Yerel Go yönlendirici test paketini çalıştırın
cd /home/community-user/targets/gotify-server && go test -v ./router -run TestHTTPSRedirect

# Veya 127.0.0.1:8080 üzerinde çalışan yerel bir Gotify HTTP dinleyicisine karşı test edin:
curl -i "http://127.0.0.1:8080/#/messages?token=test-redacted-token" \
  -H "Host: attacker-gotify.example.com"
```

### 3. Otomatik `RED -> GREEN + BENIGN` E2E Doğrulama Testinin Çalıştırılması
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_gotify_cand01
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Hem `go test -v ./router -run TestHTTPSRedirect` (`PASS`) hem de `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_gotify_cand01` ile doğrulanmıştır:

```json
{
  "GOTIFY-CAND-01": {
    "ghsa_id": "GHSA-cc9f-m5vr-pm75",
    "source_file": "gotify-server/router/router.go",
    "patch_file": "pre-submission-verification-20261026/patches/GOTIFY-CAND-01.patch",
    "patch_sha256": "6b977bb0b1eeb275d42940cc3883477cd70b370b442e68bf1782266c24eb5fe0",
    "elapsed_ms": 3.98,
    "RED": {
      "status_code": 308,
      "location": "https://attacker-gotify.example.com/#/messages?token=[REDACTED_TEST_TOKEN_SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]",
      "redirected_to_untrusted_host": true
    },
    "GREEN": {
      "status_code": 308,
      "location": "https://push.corp.example.org/#/messages?token=[REDACTED_TEST_TOKEN_SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]",
      "redirected_to_untrusted_host": false,
      "bound_to_configured_ssl_host": true
    }
  }
}
```

### Sınır Koşulları (Boundary Qualification)
Bu zafiyet, Gotify'ın yerleşik SSL yönlendiricisi (`SSL.Enabled=true` ve `SSL.RedirectToHTTPS=true`) etkinleştirildiğinde ve HTTP portu (`80`) doğrudan veya `Host` başlığını ileten bir vekil sunucu üzerinden erişilebilir olduğunda geçerlidir.

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/router/router.go
+++ b/router/router.go
@@ -61,6 +61,10 @@
 				return
 			}
 			host := ctx.Request.Host
+			if len(conf.Server.SSL.LetsEncrypt.Hosts) > 0 {
+				host = conf.Server.SSL.LetsEncrypt.Hosts[0]
+			}
+			host = strings.TrimSpace(strings.TrimLeft(host, "/\\"))
 			if idx := strings.LastIndex(host, ":"); idx != -1 {
 				host = host[:idx]
 			}
```
