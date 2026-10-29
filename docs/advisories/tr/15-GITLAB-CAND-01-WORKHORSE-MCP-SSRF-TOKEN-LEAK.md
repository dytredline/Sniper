# GitLab Workhorse DuoWorkflow Harici MCP İstemcisinde `transport.WithSSRFFilter()` Eksikliği ve Çapraz Kökenli Yönlendirmelerde `Authorization: Bearer` Token Sızıntısı (`GITLAB-CAND-01`)

[English](../15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md) | **Türkçe** | [日本語](../ja/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md) | [简体中文](../zh-CN/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md) | [한국어](../ko/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — `externalMcpTransport` Tanımında `transport.WithSSRFFilter` Argümanının Unutulması (`workhorse/internal/ai_assist/duoworkflow/mcp.go:41-44`):** Workhorse'un `transport.NewRestrictedTransport` fonksiyonu yalnızca açıkça `transport.WithSSRFFilter(...)` opsiyonu verildiğinde (`workhorse/internal/sendurl/sendurl.go:365-374` içinde yapıldığı gibi) özel IP, loopback (`127.0.0.1`) ve bulut metadata (`169.254.169.254`) adreslerini engeller. `mcp.go:41-44` bu parametreyi vermediği için harici MCP bağlantılarında hiçbir IP seviyesi SSRF filtresi çalışmaz.
2. **Adım 2 — `roundTripper.RoundTrip` İçinde Her Yönlendirme Adımında `Authorization: Bearer` Başlığının Yeniden Eklenmesi (`mcp.go:101-104, 231-234`):** Standart Go `http.Client`, farklı bir alan adına yapılan yönlendirmelerde `Authorization` başlığını `RoundTrip` çağrısından *önce* siler; ancak `duoworkflow.roundTripper.RoundTrip` kendi içinde `r.Header.Set(name, value)` çalıştırdığı ve `CheckRedirect` politikası tanımlamadığı için, `302 Found` yönlendirmesinde gizli `Authorization: Bearer` başlığını yeni hedefe doğrudan sızdırır.

### Zafiyetli Kod Kesiti
```ruby
// File: workhorse/internal/ai_assist/duoworkflow/mcp.go (lines 41-44, 101-104, 231-234)
var externalMcpTransport = transport.NewRestrictedTransport(func(t *http.Transport) {
	t.MaxIdleConns = externalMcpMaxIdleConns
	t.MaxIdleConnsPerHost = externalMcpMaxIdleConnsPerHost
}) // BUG 1: Missing transport.WithSSRFFilter(false, nil)!

func (t *roundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	for name, value := range t.headers {
		r.Header.Set(name, value) // BUG 2: Re-injects Authorization header on cross-origin redirect hops!
	}
...
	t = &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: &http.Client{Transport: rt}, // BUG 3: No CheckRedirect policy!
		DisableStandaloneSSE: true,
	}
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Çapraz Kökenli (`Cross-Origin`) `302` Yönlendirmesiyle Kurban Geliştiricinin veya Yöneticinin Canlı `Authorization: Bearer` Erişim Jetonunun Çalınması (Tam Hesap ve Özel Depo Ele Geçirme)
Bir geliştirici veya yönetici Duo Workflow AI asistanını çalıştırdığında, GitLab Workhorse (`mcp.go`) harici MCP sunucusuna kullanıcının canlı `Authorization: Bearer <token>` başlığıyla bağlanır. Harici sunucu farklı bir alan adına (`https://attacker-collector.example/steal`) `302 Found` yönlendirmesi yaptığında, `roundTripper.RoundTrip` bu gizli başlığı silmeden yeni hedefe tekrar ekler (`bearer_token_leaked_to_canary: true`). **Saldırgan kurbanın canlı Bearer jetonunu doğrudan kendi sunucusunda yakalar ve bu jetonla kurbanın erişebildiği özel şirket depolarını indirir, gizli issue/MR kayıtlarını okur veya kurban adına işlem yapar.**

### Senaryo B — Workhorse Süreci Üzerinden İç Ağa (`127.0.0.1`), İç Mikroservislere ve Bulut Metadata (`169.254.169.254`) Servisine Doğrudan SSRF
`externalMcpTransport` içinde `transport.WithSSRFFilter()` unutulduğu için, ilk kayıtta geçerli bir genel adrese sahip olan MCP uç noktası `302` ile `http://127.0.0.1:...` veya `http://169.254.169.254/...` adresine yönlendirme yaptığında Workhorse doğrudan iç servise bağlanır.

### Senaryo C — DNS Rebinding İle Güvenlik Duvarı Arkasındaki İç Şirket Ağına Sızma
Kayıt sırasında genel IP döndüren alan adı, Workhorse bağlantı kurarken `127.0.0.1` veya `10.0.0.1` döndürdüğünde soket seviyesinde `WithSSRFFilter` olmadığı için iç şirket ağına doğrudan erişilir.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Compare externalMcpTransport in duoworkflow/mcp.go against sendurl/sendurl.go
grep -n -C 8 "NewRestrictedTransport" \
  /home/community-user/targets/gitlab/workhorse/internal/ai_assist/duoworkflow/mcp.go \
  /home/community-user/targets/gitlab/workhorse/internal/sendurl/sendurl.go

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report2_cand05
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

`pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py` ile üretilen çalışma zamanı kanıtı (bkz. [`gitlab-real-world-impact-e2e-20261029.json`](../gitlab-real-world-impact-e2e-20261029.json)):

```json
{
  "REPORT-02_CAND-05-06-01": {
    "GREEN": {
      "bearer_token_leaked_to_canary": false,
      "canary_b_request_count": 0,
      "cross_org_server_mutated": false,
      "iam_role_credentials_exposed": false,
      "reflected_flash_contains_secret": false
    },
    "RED": {
      "bearer_token_leaked_to_canary": true,
      "canary_b_request_count": 2,
      "cross_org_server_mutated": true,
      "iam_role_credentials_exposed": true,
      "reflected_flash_contains_secret": true
    },
    "patches": {
      "GITLAB-CAND-01.patch": "77be0cfe3092c808ea8f0a1f33689c61de1c9db01155e950b1192f883984b689",
      "GITLAB-CAND-05.patch": "e63dce6d6b71fcb0fa357103078290e07d66a0c756607b7b35da9eae209b687e",
      "GITLAB-CAND-06-MCP-IDOR-CSRF.patch": "8bed587ca203bfcde8fcf8e4ec27b12038e4e5366dc33f3d285b742811d2632b"
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/workhorse/internal/ai_assist/duoworkflow/mcp.go
+++ b/workhorse/internal/ai_assist/duoworkflow/mcp.go
@@ -38,10 +39,13 @@
-var externalMcpTransport = transport.NewRestrictedTransport(func(t *http.Transport) {
-	t.MaxIdleConns = externalMcpMaxIdleConns
-	t.MaxIdleConnsPerHost = externalMcpMaxIdleConnsPerHost
-})
+var externalMcpTransport = transport.NewRestrictedTransport(
+	transport.WithSSRFFilter(false, nil),
+	func(t *http.Transport) {
+		t.MaxIdleConns = externalMcpMaxIdleConns
+		t.MaxIdleConnsPerHost = externalMcpMaxIdleConnsPerHost
+	},
+)
@@ -99,8 +104,10 @@
 func (t *roundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
-	for name, value := range t.headers {
-		r.Header.Set(name, value)
+	if t.internal || t.allowedHost == "" || r.URL.Host == t.allowedHost {
+		for name, value := range t.headers {
+			r.Header.Set(name, value)
+		}
 	}
```
