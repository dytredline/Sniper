# Vercel `@vercel/client@18.10.0` Prebuilt `.vc-config.json` `filePathMap` Arbitrary Host File Read & `.next/required-server-files.json` Local `.env` Secret Upload (`VERCEL-CLIENT-08A`)

[English](../45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md) | [Türkçe](../tr/45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md) | **日本語** | [简体中文](../zh-CN/45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md) | [한국어](../ko/45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Unconfined `path.resolve(cwd, filePath)` in `filesFromFilePathMap()` (`packages/client/src/utils/hashes.ts:115-167`):** When `prebuilt: true` (`vercel deploy --prebuilt`), `@vercel/client` parses `.vercel/output/functions/**/.vc-config.json` and iterates over `Object.entries(vcConfig.filePathMap)`. For each entry, it computes `const fsPath = path.resolve(cwd, filePath)` and reads the file (`fs.readFile(fsPath)`) without checking that `fsPath` is inside `cwd` or filtering against `.vercelignore`.
2. **Step 2 — Default Next.js `.next/required-server-files.json` Secret Leakage:** Even on an unmodified Next.js build, `.vc-config.json`'s `filePathMap` includes `.next/required-server-files.json`, which serializes local `config.env` values from `.env` / `.env.local` despite `.vercelignore` excluding `.env*`.
3. **Step 3 — CI/CD Prebuilt Artifact Poisoning (`POST /v2/files` Upload):** If a CI build step or reusable workflow generates `.vercel/output` and hands it to a deployment job running `vercel deploy --prebuilt --token $VERCEL_TOKEN`, any `../../../../etc/passwd` or `~/.aws/credentials` entry in `filePathMap` is SHA-1 hashed and uploaded to Vercel's `/v2/files` deployment API.

### Vulnerable Code Snippet
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

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Default `vercel build && vercel deploy --prebuilt` `.env.local` Secret Leakage
A developer adds `.env*` to `.vercelignore` expecting local secrets to stay off the deployment server, but `filePathMap` pulls `.next/required-server-files.json` containing `DATABASE_URL` and `STRIPE_SECRET_KEY` into the uploaded function bundle.

### Scenario B — Split CI/CD Pipeline (`build` PR Artifact -> `deploy --prebuilt` Privileged Job) Host Credential Exfiltration
An unprivileged PR build job outputs `.vercel/output` as a workflow artifact with `filePathMap: { "leaked.txt": "/home/runner/.npmrc" }`. The privileged deploy job runs `vercel deploy --prebuilt`, uploading the runner's credentials into the deployed function.

### Scenario C — Monorepo Shared Cache / Turborepo Remote Cache Poisoning
A poisoned `.vc-config.json` restored from a shared build cache exfiltrates CI environment files during prebuilt deployment.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Inspect filesFromFilePathMap in published @vercel/client@18.10.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/client/dist/utils/hashes.js | sed -n '85,145p'

# 2. Run the Live @vercel/client@18.10.0 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-08-client-prebuilt-path-and-symlink-confinement.patch
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Vercel & Next.js Live npm Tarball Verification Suite (see [`vercel-real-world-impact-e2e-20261029.json`](../vercel-real-world-impact-e2e-20261029.json)):

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

### Unified Diff Patch (`git apply --check` clean)
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
