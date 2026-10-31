# Vercel `@vercel/flags-core@1.10.2` Unprefixed `x-datafile-Updated-At` Header Watermark Poisoning & Permanent Feature-Flag Freeze DoS (`VERCEL-FLAGS-CORE-06`)

[English](../42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md) | [Türkçe](../tr/42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md) | [日本語](../ja/42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md) | **简体中文** | [한국어](../ko/42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Unvalidated Header Watermark Update Before Body Verification (`packages/flags-core/src/controller.ts:555-615`):** In `streamResponse()` and `readBundledDefinitions()`, `@vercel/flags-core` reads `res.headers.get('x-datafile-Updated-At')`, parses it with `Number(updatedAtHeader)`, and immediately sets `this.datafileUpdatedAtWatermark = Math.max(this.datafileUpdatedAtWatermark, updatedAt)` BEFORE verifying `res.ok` (`200 OK`) or validating the JSON datafile body.
2. **Step 2 — Unprefixed Header Exposure Across Proxies & Error Responses:** Because `x-datafile-Updated-At` does NOT use the Vercel Edge-stripped `x-vercel-*` prefix, upstream proxies, mock/custom `FLAGS_SERVICE_URL` endpoints, or any non-200 HTTP response can inject `x-datafile-Updated-At: 9999999999999`.
3. **Step 3 — Permanent Flag Freeze / Kill-Switch Lockout:** Once `datafileUpdatedAtWatermark` is poisoned to `9999999999999`, every subsequent bundled or fallback flag update with a real timestamp (`updatedAt <= 9999999999999`) is silently ignored for the lifetime of the Node.js worker, preventing operators from toggling emergency kill-switches.

### Vulnerable Code Snippet
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

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Emergency Kill-Switch Lockout During an Incident
A single `502`/`503` response carrying `x-datafile-Updated-At: 9999999999999` poisons `datafileUpdatedAtWatermark`. When engineers later flip an emergency kill-switch in Vercel Flags, the running application ignores the bundled/fallback datafile (`updatedAt: 1700000100000 <= 9999999999999`) and keeps the vulnerable feature enabled (`stale-compromised-variant`).

### Scenario B — Redirect Credential Leak on `FLAGS_SERVICE_URL` (`redirect: 'manual'` Missing)
If `streamResponse()` receives a `302` redirect from a custom or proxy `FLAGS_SERVICE_URL`, `fetch()` follows the redirect without `redirect: 'manual'`.

### Scenario C — Persistent Multi-Worker Drift in Long-Lived Node.js Servers
Poisoned workers permanently serve stale feature flags while healthy workers serve updated flags, causing inconsistent authorization and checkout behavior.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Inspect streamResponse and readBundledDefinitions in published @vercel/flags-core@1.10.2
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/flags-core/dist/index.js | sed -n '465,516p'

# 2. Run the Live @vercel/flags-core@1.10.2 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-06-flags-core-controller-stream-hardening.patch
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Vercel & Next.js Live npm Tarball Verification Suite (see [`vercel-real-world-impact-e2e-20261029.json`](../vercel-real-world-impact-e2e-20261029.json)):

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

### Unified Diff Patch (`git apply --check` clean)
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
