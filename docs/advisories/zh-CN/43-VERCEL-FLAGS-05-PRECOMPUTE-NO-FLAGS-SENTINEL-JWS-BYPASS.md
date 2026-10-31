# Vercel `flags@4.4.0` `deserialize()` Unauthenticated `__no_flags__` Sentinel Early-Return Bypassing Compact JWS Signature Verification (`VERCEL-FLAGS-05`)

[English](../43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md) | [Türkçe](../tr/43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md) | [日本語](../ja/43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md) | **简体中文** | [한국어](../ko/43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Unconditional Early Return Before JWS Verification (`packages/flags/src/next/precompute.ts:206-214`):** `serialize()` returns `'__no_flags__'` only when `flags.length === 0`. However, `deserialize(flags, code, secret)` checks `if (code === '__no_flags__') return {};` at the very top of the function WITHOUT checking `if (flags.length === 0)` and BEFORE invoking `compactVerify(code, encodedSecret)`.
2. **Step 2 — Direct URL Segment Access in Next.js App Router (`app/[code]/...`):** In Next.js applications using Flags SDK precomputation (`app/[code]/checkout/page.tsx`), the `[code]` route parameter is normally generated and JWS-signed by Edge Middleware (`serialize(flags, values, secret)`). Because `[code]` is a URL path segment, an unauthenticated user can directly request `/__no_flags__/checkout` (or bypass middleware via path/header conditions).
3. **Step 3 — Fallback `flag.decide()` Execution Without Edge Context:** When `deserialize()` returns `{}` for `code = '__no_flags__'`, `getPrecomputed(flag, precomputeGroup, code)` sees `parsed[flag.key] === undefined` and falls back to re-running `flag.decide()` inside the Node/Page render context (where Edge geo/IP/middleware overrides are absent), flipping Edge-blocked flags (`true` instead of Edge-precomputed `false`).

### Vulnerable Code Snippet
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

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Bypassing Edge Middleware Geo/WAF Gating in Precomputed Routes
Edge Middleware precomputes `vipCheckoutFlag = false` for an untrusted IP/region and signs it into a Compact JWS `[code]` segment. The client navigates directly to `/__no_flags__/checkout`, causing `deserialize()` to skip JWS verification, return `{}`, and trigger the page-level `decide()` fallback (`true`).

### Scenario B — A/B Price & Promotion Tier Manipulation
A user locked into a control pricing cohort by Edge Middleware replaces the signed JWS segment in the URL or rewrite header with `__no_flags__`, forcing re-evaluation without a valid `FLAGS_SECRET` signature.

### Scenario C — Cache-Key Fragmentation & Origin Re-Decide Amplification
Requesting `/__no_flags__/...` across precomputed ISR routes forces `getPrecomputed()` to execute asynchronous `flag.decide()` calls on every render instead of reading O(1) signed precomputed values.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Inspect deserialize in published flags@4.4.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/flags/dist/next/index.js | sed -n '115,155p'

# 2. Run the Live flags@4.4.0 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-05-flags-precompute-no-flags-sentinel-bypass.patch
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Vercel & Next.js Live npm Tarball Verification Suite (see [`vercel-real-world-impact-e2e-20261029.json`](../vercel-real-world-impact-e2e-20261029.json)):

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

### Unified Diff Patch (`git apply --check` clean)
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
