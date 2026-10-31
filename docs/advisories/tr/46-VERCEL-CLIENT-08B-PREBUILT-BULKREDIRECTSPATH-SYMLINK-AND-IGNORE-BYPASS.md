# Vercel `@vercel/client@18.10.0` Prebuilt `config.bulkRedirectsPath` Sembolik Bağ (Symlink) Kaçışı ve `.vercelignore` Atlaması İle Konak Dosyası Sızıntısı (`VERCEL-CLIENT-08B`)

[English](../46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md) | **Türkçe** | [日本語](../ja/46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md) | [简体中文](../zh-CN/46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md) | [한국어](../ko/46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — `buildFileTree()` İçinde Doğrulanmamış `config.bulkRedirectsPath` ve Symlink Takibi (`packages/client/src/utils/index.ts:116-148`):** `prebuilt: true` modunda `buildFileTree()`, `.vercel/output/config.json` içinden `config.bulkRedirectsPath` değerini okur ve `join(cwd, config.bulkRedirectsPath)` dizinini `fs.stat()` (sembolik bağları takip eder) ile tarar; `fs.realpath()` ile proje kökü sınır kontrolü yapmaz.
2. **Adım 2 — Prebuilt Modunda `.vercelignore` Kurallarının Atlanması:** `bulkRedirectsPath` taranırken `.vercelignore` filtreleri uygulanmadığı için hariç tutulan gizli dosyalar da okunur.
3. **Adım 3 — Konak Dosyalarının `/v2/files` API'sine Yüklenmesi:** Sembolik bağın işaret ettiği proje dışı konak dosyaları SHA-1 ile özetlenerek Vercel dağıtım sunucularına yüklenir.

### Zafiyetli Kod Kesiti
```typescript
// File: packages/client/src/utils/index.ts (lines 116-148)
if (config?.bulkRedirectsPath) {
  const bulkRedirectsPath = join(cwd, config.bulkRedirectsPath);
  // BUG: No realpath confinement check and .vercelignore is not applied;
  // readdir/stat follows symlinks pointing outside cwd!
  const bulkRedirectFiles = await readdir(bulkRedirectsPath, []);
  fileList.push(...bulkRedirectFiles);
}
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — `bulkRedirectsPath` İçindeki Sembolik Bağ İle SSH/Bulut Anahtarlarının Sızdırılması
`.vercel/output/config.json` içinde tanımlanan `bulkRedirectsPath` dizinine `/home/runner/.ssh/id_rsa` yönlendiren bir sembolik bağ konulduğunda `buildFileTree()` bu bağı takip ederek özel anahtarı dağıtıma yükler.

### Senaryo B — `config.json` İçinde Üst Dizin Geçişi (`"bulkRedirectsPath": "../../secrets"`)
Üst dizin yolu verilerek proje kökü dışındaki klasörün tamamı taranıp yüklenir.

### Senaryo C — `.vercelignore` İhlali
`.vercelignore` ile engellenen yerel sır dosyaları `bulkRedirectsPath` üzerinden dağıtıma dahil edilir.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect buildFileTree in published @vercel/client@18.10.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/client/dist/utils/index.js | sed -n '90,145p'

# 2. Run the Live @vercel/client@18.10.0 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-08-client-prebuilt-path-and-symlink-confinement.patch
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Vercel & Next.js Canlı npm Paketi Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`vercel-real-world-impact-e2e-20261029.json`](../vercel-real-world-impact-e2e-20261029.json)):

```json
{
  "VERCEL-CLIENT-08B": {
    "RED": {
      "package_tested": "@vercel/client@18.10.0",
      "bulkRedirectsPath_symlink_followed_outside_cwd": true,
      "outside_symlink_target_packaged_in_fileList": true,
      "uploaded_payload_excerpt": "OUTSIDE_SYMLINK_SECRET=top_secret_symlink_data_999"
    },
    "GREEN": {
      "bulkRedirectsPath_confined_to_cwd_realpath": true,
      "outside_symlink_target_packaged_in_fileList": false
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/packages/client/src/utils/index.ts
+++ b/packages/client/src/utils/index.ts
@@ -122,6 +122,11 @@ export async function buildFileTree(
   if (config?.bulkRedirectsPath) {
     const bulkRedirectsPath = join(cwd, config.bulkRedirectsPath);
+    const realCwd = await fs.realpath(cwd);
+    const realBulk = await fs.realpath(bulkRedirectsPath);
+    if (realBulk !== realCwd && !realBulk.startsWith(realCwd + sep)) {
+      throw new Error(`Invalid bulkRedirectsPath outside project root: ${config.bulkRedirectsPath}`);
+    }
```
