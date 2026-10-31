# Vercel `@vercel/flags-core@1.10.2` Öneksiz `x-datafile-Updated-At` Başlığı İle Watermark Zehirlemesi ve Kalıcı Özellik Bayrağı (Feature Flag) Dondurma DoS (`VERCEL-FLAGS-CORE-06`)

[English](../42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md) | **Türkçe** | [日本語](../ja/42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md) | [简体中文](../zh-CN/42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md) | [한국어](../ko/42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — Yanıt Gövdesi ve `res.ok` Doğrulanmadan `datafileUpdatedAtWatermark` Değerinin Güncellenmesi (`packages/flags-core/src/controller.ts:555-615`):** `@vercel/flags-core` içindeki `streamResponse()` metodu, `res.ok` (`200 OK`) durumunu ve geçerli bir JSON veri dosyasını doğrulamadan `x-datafile-Updated-At` başlığını okuyup `this.datafileUpdatedAtWatermark` değerini günceller.
2. **Adım 2 — `x-vercel-*` Öneki Olmayan Başlık Yüzeyi:** Başlık `x-vercel-*` önekine sahip olmadığı için hata yanıtları veya ara vekil sunucular üzerinden `x-datafile-Updated-At: 9999999999999` enjekte edilebilir.
3. **Adım 3 — Acil Durum Kill-Switch ve Feature Flag Güncellemelerinin Kalıcı Olarak Kilitlenmesi:** `datafileUpdatedAtWatermark` değeri `9999999999999` olduktan sonra gerçek zaman damgalı tüm bayrak güncellemeleri (`updatedAt <= this.datafileUpdatedAtWatermark`) süreç yeniden başlatılana kadar sessizce çöpe atılır.

### Zafiyetli Kod Kesiti
```typescript
// File: packages/flags-core/src/controller.ts (lines 555-615)
const res = await fetch(`${this.serviceUrl}/v1/stream`, { headers });
const updatedAtHeader = res.headers.get('x-datafile-Updated-At');
if (updatedAtHeader) {
  const updatedAt = Number(updatedAtHeader);
  if (!Number.isNaN(updatedAt)) {
    // BUG: Updates watermark BEFORE checking res.ok or validating the JSON datafile payload,
    // and accepts arbitrarily far-future timestamps (e.g. 9999999999999)!
    this.datafileUpdatedAtWatermark = Math.max(this.datafileUpdatedAtWatermark, updatedAt);
  }
}
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Olay Müdahalesi Sırasında Acil Durum Kill-Switch Bayrağının Devreye Girememesi
`x-datafile-Updated-At: 9999999999999` içeren tek bir `503` yanıtı `datafileUpdatedAtWatermark` değerini zehirler; operatörler acil durum bayrağını kapatsa bile uygulama eski (`stale-compromised-variant`) değerde takılı kalır.

### Senaryo B — `redirect: 'manual'` Eksikliği Nedeniyle Yönlendirme Takibi
`streamResponse()` içindeki `fetch()` çağrısında `redirect: 'manual'` bulunmadığı için `302` yönlendirmeleri otomatik takip edilir.

### Senaryo C — Uzun Ömürlü Node.js Sunucularında Kalıcı Durum Kayması
Zehirlenen iş parçacıkları süreç yeniden başlatılana kadar hiçbir bayrak güncellemesini kabul etmez.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect streamResponse and readBundledDefinitions in published @vercel/flags-core@1.10.2
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/flags-core/dist/index.js | sed -n '465,516p'

# 2. Run the Live @vercel/flags-core@1.10.2 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-06-flags-core-controller-stream-hardening.patch
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Vercel & Next.js Canlı npm Paketi Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`vercel-real-world-impact-e2e-20261029.json`](../vercel-real-world-impact-e2e-20261029.json)):

```json
{
  "VERCEL-FLAGS-CORE-06": {
    "RED": {
      "package_tested": "@vercel/flags-core@1.10.2",
      "initial_flag_value": "stale-compromised-variant",
      "bundled_legitimate_update_timestamp": 1700000100000,
      "poisoned_header_sent_on_503": "9999999999999",
      "flag_value_after_watermark_poisoning": "stale-compromised-variant",
      "legitimate_bundled_update_ignored": true
    },
    "GREEN": {
      "requires_res_ok_and_valid_datafile_before_watermark_update": true,
      "rejects_future_timestamp_skew": true,
      "legitimate_bundled_update_ignored": false
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/packages/flags-core/src/controller.ts
+++ b/packages/flags-core/src/controller.ts
@@ -560,7 +560,8 @@ export class Controller {
-    const res = await fetch(`${this.serviceUrl}/v1/stream`, { headers });
+    const res = await fetch(`${this.serviceUrl}/v1/stream`, { headers, redirect: 'manual' });
+    if (!res.ok) throw new Error(`Flags stream failed with status ${res.status}`);
     const updatedAtHeader = res.headers.get('x-datafile-Updated-At');
-    if (updatedAtHeader) {
+    if (updatedAtHeader && Number(updatedAtHeader) <= Date.now() + 300_000) {
```
