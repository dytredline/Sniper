# Vercel `flags@4.4.0` `deserialize()` Fonksiyonunda `__no_flags__` Sabiti İle Compact JWS İmza Doğrulamasını Atlama (`VERCEL-FLAGS-05`)

[English](../43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md) | **Türkçe** | [日本語](../ja/43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md) | [简体中文](../zh-CN/43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md) | [한국어](../ko/43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — JWS İmza Doğrulamasından Önce Koşulsuz `__no_flags__` Dönüşü (`packages/flags/src/next/precompute.ts:206-214`):** `serialize()` fonksiyonu yalnızca `flags.length === 0` olduğunda `'__no_flags__'` üretirken, `deserialize(flags, code, secret)` fonksiyonu `flags.length === 0` olup olmadığını kontrol etmeden ve `compactVerify()` imza doğrulamasına hiç girmeden `if (code === '__no_flags__') return {};` döndürür.
2. **Adım 2 — Next.js `[code]` Dinamik Rota Parametresine Doğrudan Erişim:** Next.js App Router'da `app/[code]/checkout/page.tsx` yapısını kullanan uygulamalarda `[code]` parametresi URL yolunun bir parçasıdır. Saldırgan imza anahtarına (`FLAGS_SECRET`) sahip olmadan doğrudan `/__no_flags__/checkout` adresini çağırabilir.
3. **Adım 3 — Edge Middleware Kararının Atlanarak `flag.decide()` Fonksiyonunun Yeniden Çalışması:** `deserialize()` boş nesne `{}` döndürdüğünde `getPrecomputed()` ilgili bayrağı bulamaz ve Edge Middleware'in imzaladığı `false` kararını atlayarak sunucu tarafında `flag.decide()` fonksiyonunu yeniden çalıştırır (`true`).

### Zafiyetli Kod Kesiti
```typescript
// File: packages/flags/src/next/precompute.ts (lines 206-214)
export async function deserialize(
  flags: ReadonlyArray<Flag<any, any>>,
  code: string,
  secret: string | undefined = process.env.FLAGS_SECRET,
): Promise<Record<string, any>> {
  if (!secret) throw new Error('flags: deserialize was called without a secret');
  // BUG: Returns {} BEFORE JWS signature verification even when flags.length > 0!
  if (code === '__no_flags__') return {};
  // ... JWS compactVerify() only runs below this line
}
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Edge Middleware Coğrafi/Güvenlik Kısıtlamasının Atlanması
Edge Middleware güvenilmeyen bir istemci için `vipCheckoutFlag = false` kararını JWS ile imzalar; ancak istemci URL'deki imzalı segment yerine `__no_flags__` göndererek imza doğrulamasını atlar ve sunucu tarafında `true` değerini alır.

### Senaryo B — A/B Kampanya ve Fiyat Kohortu Manipülasyonu
İmzalı JWS kodu yerine `__no_flags__` gönderilerek `FLAGS_SECRET` bilinmeden yeni kohort hesaplaması tetiklenir.

### Senaryo C — Önbellek Parçalanması ve Asenkron `decide()` Yükü
`__no_flags__` segmenti her istekte `flag.decide()` çağrısını yeniden çalıştırır.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect deserialize in published flags@4.4.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/flags/dist/next/index.js | sed -n '115,155p'

# 2. Run the Live flags@4.4.0 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-05-flags-precompute-no-flags-sentinel-bypass.patch
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Vercel & Next.js Canlı npm Paketi Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`vercel-real-world-impact-e2e-20261029.json`](../vercel-real-world-impact-e2e-20261029.json)):

```json
{
  "VERCEL-FLAGS-05": {
    "RED": {
      "package_tested": "flags@4.4.0",
      "legitimate_signed_code_prefix": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..",
      "legitimate_precomputed_value": false,
      "forged_code_passed": "__no_flags__",
      "deserialize_output_for_no_flags": {},
      "getPrecomputed_value_with_no_flags_sentinel": true,
      "random_tampered_token_rejected": true
    },
    "GREEN": {
      "sentinel_rejected_when_flags_non_empty": true,
      "getPrecomputed_with_no_flags_throws": true
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/packages/flags/src/next/precompute.ts
+++ b/packages/flags/src/next/precompute.ts
@@ -208,7 +208,7 @@ export async function deserialize(
   if (!secret) {
     throw new Error('flags: deserialize was called without a secret');
   }
-  if (code === '__no_flags__') return {};
+  if (code === '__no_flags__' && flags.length === 0) return {};
```
