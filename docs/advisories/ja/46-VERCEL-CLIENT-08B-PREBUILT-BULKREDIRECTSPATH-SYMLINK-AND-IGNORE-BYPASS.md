# Vercel `@vercel/client@18.10.0` Prebuilt `config.bulkRedirectsPath` Symlink Escape & `.vercelignore` Bypass Uploading Arbitrary Host Files (`VERCEL-CLIENT-08B`)

[English](../46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md) | [Türkçe](../tr/46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md) | **日本語** | [简体中文](../zh-CN/46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md) | [한국어](../ko/46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Unvalidated `config.bulkRedirectsPath` & Symlink Following in `buildFileTree()` (`packages/client/src/utils/index.ts:116-148`):** In `buildFileTree()`, when `prebuilt` is `true`, `@vercel/client` reads `.vercel/output/config.json` and resolves `const bulkRedirectsRoot = join(cwd, config.bulkRedirectsPath)`. It then recursively walks `bulkRedirectsRoot` using `fs.stat()` (which transparently dereferences symlinks to files/directories outside `cwd`) without checking `fs.realpath()` confinement.
2. **Step 2 — Complete `.vercelignore` Bypass in Prebuilt Mode:** The `prebuilt` branch of `buildFileTree()` passes a no-op ignore filter when enumerating `bulkRedirectsPath`, uploading sensitive files (`id_rsa`, `.env.production`) even when explicitly listed in `.vercelignore`.
3. **Step 3 — External File Packaging & Upload to `/v2/files`:** Every file discovered under the symlinked or traversed `bulkRedirectsPath` is hashed (`hashes()`) and uploaded to Vercel's `/v2/files` deployment API.

### Vulnerable Code Snippet
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

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Symlink inside `bulkRedirectsPath` Exfiltrating Host SSH/Cloud Credentials During `vercel deploy --prebuilt`
A prebuilt output directory sets `"bulkRedirectsPath": ".vercel/output/redirects"` containing a symlink `leak.json -> /home/runner/.ssh/id_rsa`. `buildFileTree()` follows the symlink via `fs.stat()` and uploads the private key to the deployment.

### Scenario B — Relative Path Traversal in `.vercel/output/config.json` (`"bulkRedirectsPath": "../../secrets"`)
Setting `bulkRedirectsPath` to a parent directory walks and uploads all files in that host directory.

### Scenario C — `.vercelignore` Bypass for Local Secret Files
Files explicitly excluded by `.vercelignore` are still packaged when referenced via `bulkRedirectsPath`.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Inspect buildFileTree in published @vercel/client@18.10.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/client/dist/utils/index.js | sed -n '90,145p'

# 2. Run the Live @vercel/client@18.10.0 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-08-client-prebuilt-path-and-symlink-confinement.patch
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Vercel & Next.js Live npm Tarball Verification Suite (see [`vercel-real-world-impact-e2e-20261029.json`](../vercel-real-world-impact-e2e-20261029.json)):

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

### Unified Diff Patch (`git apply --check` clean)
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
