# Vercel `@vercel/client@18.10.0` Prebuilt `.vc-config.json` `filePathMap` Üzerinden Keyfi Konak Dosyası Okuma ve `.next/required-server-files.json` Yerel `.env` Sır Yüklemesi (`VERCEL-CLIENT-08A`)

[English](../45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md) | **Türkçe** | [日本語](../ja/45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md) | [简体中文](../zh-CN/45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md) | [한국어](../ko/45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — `filesFromFilePathMap()` İçinde Sınır Kontrolsüz `path.resolve(cwd, filePath)` (`packages/client/src/utils/hashes.ts:115-167`):** `vercel deploy --prebuilt` çalıştığında `@vercel/client`, `.vercel/output/functions/**/.vc-config.json` içindeki `filePathMap` tablosunu okur ve `path.resolve(cwd, filePath)` ile çözümlenen her dosyayı proje kökü (`cwd`) veya `.vercelignore` kontrolü yapmadan okur.
2. **Adım 2 — `.next/required-server-files.json` Üzerinden Yerel `.env` Sırlarının Sızması:** Standart Next.js derlemelerinde `.vc-config.json` içindeki `filePathMap`, yerel `.env.local` sırlarını barındıran `.next/required-server-files.json` dosyasını otomatik olarak dağıtım paketine dahil eder.
3. **Adım 3 — CI/CD Prebuilt Artifact Zehirlemesi İle Konak Dosyalarının `/v2/files` API'sine Yüklenmesi:** Üretilen `.vercel/output` dizinindeki `filePathMap` içine `../../../../etc/passwd` veya `~/.npmrc` yazıldığında `vercel deploy --prebuilt` bu dosyaları doğrudan Vercel sunucularına yükler.

### Zafiyetli Kod Kesiti
```typescript
// File: packages/client/src/utils/hashes.ts (lines 115-167)
export async function filesFromFilePathMap(
  filePathMap: Record<string, string>,
  cwd: string
): Promise<Map<string, DeploymentFile>> {
  for (const [funcPath, filePath] of Object.entries(filePathMap)) {
    // BUG: No check that fsPath stays within cwd, and .vercelignore is never applied!
    const fsPath = path.resolve(cwd, filePath);
    const data = await fs.readFile(fsPath);
    // ... packages data for upload to POST /v2/files
  }
}
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — `vercel build && vercel deploy --prebuilt` Sırasında `.vercelignore` Aşılarak `.env.local` Sırlarının Yüklenmesi
`.vercelignore` içinde `.env*` bulunsa bile `filePathMap` üzerinden `.next/required-server-files.json` yüklendiği için yerel sırlar dağıtım paketine girer.

### Senaryo B — Ayrık CI/CD Hattında (`build` -> `deploy --prebuilt`) Konak Dosyası Sızıntısı
PR derleme adımında üretilen `.vercel/output` içindeki `filePathMap`, ayrıcalıklı dağıtım adımında `/home/runner/.npmrc` gibi dosyaları Vercel'e yükler.

### Senaryo C — Paylaşılan Monorepo Derleme Önbelleği Zehirlemesi
Önbellekten gelen `.vc-config.json` dağıtım sırasında konak dosyalarını sızdırır.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect filesFromFilePathMap in published @vercel/client@18.10.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/client/dist/utils/hashes.js | sed -n '85,145p'

# 2. Run the Live @vercel/client@18.10.0 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-08-client-prebuilt-path-and-symlink-confinement.patch
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Vercel & Next.js Canlı npm Paketi Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`vercel-real-world-impact-e2e-20261029.json`](../vercel-real-world-impact-e2e-20261029.json)):

```json
{
  "VERCEL-CLIENT-08A": {
    "RED": {
      "package_tested": "@vercel/client@18.10.0",
      "outside_host_file_read_via_filePathMap": true,
      "dotnext_required_server_files_env_uploaded": true,
      "uploaded_payload_excerpt": "SUPER_SECRET_HOST_TOKEN=host_secret_value_12345"
    },
    "GREEN": {
      "outside_cwd_filePathMap_rejected": true,
      "outside_host_file_read_via_filePathMap": false
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/packages/client/src/utils/hashes.ts
+++ b/packages/client/src/utils/hashes.ts
@@ -122,6 +122,11 @@ export async function filesFromFilePathMap(
+  const realCwd = await fs.realpath(cwd);
   for (const [funcPath, filePath] of Object.entries(filePathMap)) {
     const fsPath = path.resolve(cwd, filePath);
+    const realFsPath = await fs.realpath(fsPath);
+    if (realFsPath !== realCwd && !realFsPath.startsWith(realCwd + path.sep)) {
+      throw new Error(`Invalid filePathMap entry outside project root: ${filePath}`);
+    }
```
