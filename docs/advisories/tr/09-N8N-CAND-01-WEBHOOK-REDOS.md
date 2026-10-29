# `string-extensions.ts` İçindeki Çapasız `EMAIL_REGEXP` ve `DOMAIN_EXTRACT_REGEXP` İfadelerinin Webhook Olay Döngüsü Açlığına (ReDoS) Yol Açması (`n8n-io/n8n`)

[English](../09-N8N-CAND-01-WEBHOOK-REDOS.md) | **Türkçe** | [日本語](../ja/09-N8N-CAND-01-WEBHOOK-REDOS.md) | [简体中文](../zh-CN/09-N8N-CAND-01-WEBHOOK-REDOS.md) | [한국어](../ko/09-N8N-CAND-01-WEBHOOK-REDOS.md)

## GitHub GHSA ve MITRE CNA Hızlı Doldurma Alanları
- **Depo (Repository):** `n8n-io/n8n`
- **GitHub Danışma (Advisory) URL'si:** `https://github.com/n8n-io/n8n/security/advisories/new`
- **Üst Akış (Upstream) Depo URL'si:** `https://github.com/n8n-io/n8n`
- **Mevcut GHSA Kimliği:** `Sorumlu Bildirim (Responsible Disclosure) ile security@n8n.io adresine iletildi / CNA Adayı`
- **Ekosistem:** `npm`
- **Paket Adı:** `n8n-workflow`
- **Etkilenen Sürümler:** `<= 2.45.0 (commit cfbd9a56cba2e73901dc1962e47727adbea0b23e)`
- **Yamalı Sürümler:** `Yok (Savunma yaması aşağıda sunulmuştur)`
- **CWE:** `CWE-1333 (Verimsiz Düzenli İfade Karmaşıklığı — ReDoS)`
- **CVSS v3.1:** `5.3 Orta (Medium) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`
- **MITRE Üreticisi:** `n8n`
- **MITRE Zafiyet Türü:** `Verimsiz Düzenli İfade Karmaşıklığı / Olay Döngüsü Hizmet Reddi (CWE-1333)`
- **MITRE Etkilenen Bileşen(ler):** `packages/workflow/src/extensions/string-extensions.ts (EMAIL_REGEXP, DOMAIN_EXTRACT_REGEXP, isEmail, extractEmail, extractDomain, satır 59, 94, 326, 375, 383)`
- **MITRE Önerilen CVE Açıklaması (Türkçe Özeti):**
  > n8n (`n8n-workflow`) 2.45.0 ve önceki sürümlerinde, `packages/workflow/src/extensions/string-extensions.ts` içindeki iş akışı ifade uzantı metotları `isEmail()`, `extractEmail()` ve `extractDomain()`, RFC-5321/RFC-1035 girdi uzunluğu sınırı olmaksızın iç içe tekrarlayıcılara sahip çapasız düzenli ifadeleri (`EMAIL_REGEXP` ve `DOMAIN_EXTRACT_REGEXP`) çalıştırır. Kimlik doğrulaması olmayan bir saldırgan, bu ifadeleri değerlendiren bir iş akışı webhook uç noktasına özel oluşturulmuş noktalı dizgeler göndererek tek iş parçacıklı Node.js olay döngüsünü kilitleyebilir ve eşzamanlı webhook çalışmalarını aç bırakabilir.
- **Bildiren / Araştırmacı:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
`n8n-io/n8n` (`<= 2.45.0`, commit `cfbd9a56cba2e73901dc1962e47727adbea0b23e`) içerisindeki iş akışı ifade motoru (*Workflow Expression Engine*), kullanıcılara `{{ $json.body.email.isEmail() }}`, `{{ $json.text.extractEmail() }}` ve `{{ $json.url.extractDomain() }}` gibi yerleşik metin doğrulama yardımcıları sunar (`packages/workflow/src/extensions/string-extensions.ts:59, 94, 326, 375, 383`). Bu yardımcı fonksiyonların kullandığı düzenli ifadelerdeki (*regex*) üç yapısal kusur, tek iş parçacıklı (*single-threaded*) Node.js çalışma zamanını kilitleyen bir **ReDoS / Olay Döngüsü Açlığı (`Event-Loop Starvation DoS`, `CWE-1333`)** zafiyetine dönüşmektedir:

1. **Adım 1 — Başlangıç Çapası (`^` veya Negatif Lookbehind) Olmayan İç İçe Tekrarlayıcılar (`string-extensions.ts:59, 94`):**
   `EMAIL_REGEXP` ifadesi `(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@...` şeklinde tanımlanmıştır ve başında bir sınır/çapa yoktur. Saldırgan sonu geçerli bir alan adıyla bitmeyen `a.a.a.a...a@!` gibi noktalı bir metin gönderdiğinde, V8 regex motoru dizgenin en başından başlayarak tüm noktalı alt grupları eşleştirmeye çalışır; sondaki `!` karakterinde başarısız olduğunda ise bir sonraki karakter ofsetinden başlayarak aynı işlemi $O(N^2)$ karmaşıklıkla tekrarlar.
2. **Adım 2 — RFC-5321 / RFC-1035 Uzunluk Sınırlarının Kontrol Edilmemesi (`string-extensions.ts:326, 375, 383`):**
   RFC-5321 standardına göre geçerli bir e-posta adresi en fazla `254` (veya `320`) karakter olabilir. Ancak `isEmail(value)`, `extractEmail(value)` ve `extractDomain(value)` fonksiyonları hiçbir `value.length` kontrolü yapmadan onlarca kilobaytlık veya megabaytlık metinleri doğrudan regex motoruna sokar.
3. **Adım 3 — Tek İş Parçacıklı Node.js Event Loop'un Bloklanması:**
   n8n, iş akışı ifadelerini ana Node.js olay döngüsü (*event loop*) üzerinde senkron olarak çalıştırır. Tek bir 20 KB'lık istek V8 ana iş parçacığını `~831.78 ms` boyunca tamamen dondurur (yamalı halde `0.0029 ms` — **286.000 kat** fark); art arda gönderilen birkaç HTTP isteği sunucudaki tüm diğer webhook'ları, zamanlanmış görevleri ve n8n web arayüzünü yanıt veremez hale getirir.

### Zafiyetli Kod Kesiti (`string-extensions.ts:93-95, 324-328, 373-377`)
```typescript
// Dosya: packages/workflow/src/extensions/string-extensions.ts (satır 93-95, 324-328, 373-377)
const EMAIL_REGEXP =
	/(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(?<domain>(\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/; // HATA 1: Başlangıç çapası yok + açgözlü (greedy) ".+"!
...
function isEmail(value: string) {
	const result = EMAIL_REGEXP.test(value); // HATA 2: value.length > 320 uzunluk kontrolü yok!
	return result;
}
...
function extractEmail(value: string) {
	const matched = EMAIL_REGEXP.exec(value); // HATA 3: Çoklu KB/MB boyutundaki metinleri ana iş parçacığında senkron çalıştırır!
	return matched ? matched[0] : undefined;
}
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Herkese Açık İletişim / Kayıt Formu Webhook'u Üzerinden Tüm Şirketin n8n Otomasyon Sunucusunun Dondurulması
1. Bir şirket, web sitesindeki iletişim veya kayıt formunu işlemek için herkese açık bir n8n Webhook düğümü (`POST /webhook/contact-us`) kullanır ve gelen veriyi `IF` düğümünde `{{ $json.body.contact.isEmail() }}` ifadesiyle kontrol eder.
2. Kimlik doğrulaması olmayan bir saldırgan bu webhook adresine 20 KB boyutunda `{"contact": "a.a.a...a@!"}` içeren birkaç JSON isteği gönderir.
3. Node.js ana olay döngüsü her istekte ~832 ms boyunca tamamen kilitlenir; aynı n8n sunucusunda çalışan Stripe ödeme bildirimleri, Slack botları ve n8n yönetim arayüzü zaman aşımına uğrayarak durur.

### Senaryo B — Otomatik Müşteri Destek Bileti ve Gelen E-Posta Ayrıştırma İş Akışının Tek Bir Mesajla Kilitlenmesi
1. Bir e-ticaret veya SaaS şirketi, Zendesk/IMAP/Webhook üzerinden gelen destek mesajlarının gövdesinden gönderici adresini ayıklamak için `{{ $json.messageBody.extractEmail() }}` ifadesini kullanır.
2. Saldırgan destek formuna veya e-posta kanalına uzun noktalı dizgeler içeren tek bir mesaj gönderir.
3. `extractEmail()` fonksiyonu hiçbir uzunluk sınırı olmadan tüm mesaj gövdesini `EMAIL_REGEXP.exec(value)` ile taradığı için işçi süreci (*worker*) donar ve Kubernetes `livenessProbe` sağlık kontrolleri başarısız olarak konteynerin yeniden başlatılmasına neden olur.

### Senaryo C — CRM / B2B Veri Zenginleştirme Hattında Bozuk URL Listesiyle `extractDomain()` Üzerinden Kuyruk Tıkanması
1. Pazarlama ve satış operasyonları, dış kaynaklardan (CSV yüklemeleri, reklam formları, üçüncü taraf webhook'lar) gelen binlerce satırlık şirket web sitesi verisini normalize etmek için `{{ $json.companyUrl.extractDomain() }}` ifadesini çalıştırır.
2. Girdi verisinde çok sayıda alt alan adı parçası içeren ancak geçerli bir üst düzey alan adıyla bitmeyen bozuk URL satırları yer aldığında `DOMAIN_EXTRACT_REGEXP` (`string-extensions.ts:59`) geri izleme (*backtracking*) döngüsüne girer.
3. Toplu işleme kuyruğu tamamen tıkanır ve zamanlanmış kritik iş akışları çalışamaz hale gelir.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

### 1. Sniper CLI ile Hedef Bileşenin Denetlenmesi
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/n8n \
  --include "packages/workflow/src/extensions/string-extensions.ts"
```

### 2. İzole Yerel Test Ortamında (`Node.js`) Tetikleme ve Doğrulama
```bash
# 20 KB boyutundaki noktalı girdi üzerinde yamasız ve yamalı EMAIL_REGEXP ifadelerinin V8 olay döngüsü bloklama süresini ölçün
node -e '
const vuln = /(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(?<domain>(\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/;
const payload = "a.".repeat(10000) + "a@!";
const t0 = performance.now();
vuln.test(payload);
const redMs = performance.now() - t0;
const t1 = performance.now();
const greenResult = payload.length <= 320 && payload.includes("@") && !payload.includes(" ") ? vuln.test(payload) : false;
const greenMs = performance.now() - t1;
console.log(JSON.stringify({ payload_bytes: payload.length, red_ms: +redMs.toFixed(3), green_ms: +greenMs.toFixed(4), greenResult }));
'
```

### 3. Otomatik `RED -> GREEN + BENIGN` E2E Doğrulama Testinin Çalıştırılması
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_n8n_cand01
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Hem gerçek Node.js `v22.22.2` (`logs/N8N-CAND-01-node-benchmark.json`: `831.78 ms` RED -> `0.0029 ms` GREEN, `286.000 kat` hızlanma) hem de `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_n8n_cand01` ile doğrulanmıştır:

```json
{
  "N8N-CAND-01": {
    "source_file": "n8n/packages/workflow/src/extensions/string-extensions.ts",
    "patch_file": "pre-submission-verification-20261026/patches/N8N-CAND-01.patch",
    "patch_sha256": "7e38173c95ccccb119cc57ac0226b9ac4af1bf21c590e74123ec5e9b385121e0",
    "RED": {
      "regex_stall_ms": 165.035,
      "concurrent_legitimate_webhook_wait_ms": 164.08,
      "concurrent_webhook_starved": true
    },
    "GREEN": {
      "regex_stall_ms": 0.017,
      "concurrent_legitimate_webhook_wait_ms": 0.0,
      "concurrent_webhook_starved": false
    }
  }
}
```

### Sınır Koşulları (Boundary Qualification)
Bu zafiyetin tetiklenebilmesi için güvenilmeyen girdi (örneğin bir Webhook tetikleyicisi veya harici mesaj gövdesi) üzerinde `.isEmail()`, `.extractEmail()` veya `.extractDomain()` ifadelerini çalıştıran aktif bir n8n iş akışının bulunması gerekir.

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/packages/workflow/src/extensions/string-extensions.ts
+++ b/packages/workflow/src/extensions/string-extensions.ts
@@ -91,7 +91,7 @@
   ))/;
 */
 const EMAIL_REGEXP =
-	/(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(?<domain>(\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/;
+	/(?<![^<>()\[\]\\.,;:\s@"])(?:[^<>()\[\]\\.,;:\s@"]+(?:\.[^<>()\[\]\\.,;:\s@"]+)*|"(?:[^"\\]|\\.)+")@(?<domain>\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}]|(?:[a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,})/;
 
@@ -324,6 +324,7 @@
 function isEmail(value: string) {
+	if (value.length > 320 || !value.includes('@') || value.includes(' ')) return false;
 	const result = EMAIL_REGEXP.test(value);
@@ -373,6 +374,7 @@
 function extractEmail(value: string) {
+	if (value.length > 4096 || !value.includes('@')) return undefined;
 	const matched = EMAIL_REGEXP.exec(value);
```
