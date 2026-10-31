# Next.js `/_next/image` (`fetchExternalImage`) `3xx` Redirect `remotePatterns` Allowlist Bypass & `isPrivateIp()` Fail-Open Loopback/Internal SSRF (`VERCEL-NEXT-09` / HackerOne `#4152265`)

[English](../40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md) | [Türkçe](../tr/40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md) | [日本語](../ja/40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md) | **简体中文** | [한국어](../ko/40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Initial-Hop-Only `remotePatterns` Verification (`image-optimizer.js:586-615`):** `validateParams()` checks `hasMatch(domains, remotePatterns, href)` only once on the initial `/_next/image?url=...` parameter. When the allowlisted origin returns a `301`/`302`/`307`/`308` redirect, `fetchExternalImage()` resolves the new `Location` URL and calls `validateUrl(parsedRedirectUrl)` without re-evaluating `hasMatch(domains, remotePatterns, parsedRedirectUrl)`. This bypasses both **same-host pathname/search restrictions** (`/public-avatars/**` -> `/private-kyc-docs/passport-scan.png`) and **cross-host domain restrictions**.
2. **Step 2 — Mounted HackerOne Comment #1 (`RE-EVALUATION-COMMENT-4152265`): Why No Compromised Host Is Required on Hop 1:** Standard allowlisted image/avatar providers (Gravatar `https://www.gravatar.com/avatar/0000?d=https%3A%2F%2F...`, Cloudinary fetch URLs, and multi-tenant S3 / R2 / Supabase Storage / Vercel Blob buckets) natively return `302` redirects or allow any tenant to upload an image with `WebsiteRedirectLocation` (`301`), pivoting `fetchExternalImage()` to any external or internal host.
3. **Step 3 — Mounted HackerOne Comment #1 (`RE-EVALUATION-COMMENT-4152265`): Direct Linux Kernel TCP Socket Connection to `127.0.0.1` Without NAT64 via `isPrivateIp()` Fail-Open (`if (!ipaddr.isValid(ip)) return false`):** `next/dist/compiled/ipaddr.js` defines the IPv6 `zoneIndex` regex as `const o = "%[0-9a-z]{1,}"`, which only permits lowercase alphanumeric characters (`[0-9a-z]`) and rejects hyphens (`-`), underscores (`_`), and dots (`.`). On standard Linux / Docker / Kubernetes hosts with hyphenated network interfaces (`br-1a49f5828144`, `docker_gwbridge`, `cni-podman0`, `flannel.1`), `dns.promises.lookup("::ffff:127.0.0.1%br-1a49f5828144", { all: true })` succeeds in the Linux kernel (`getaddrinfo()`), `ipaddr.isValid()` returns `false`, `isPrivateIp()` fails open (`return false`), and Node's `http.get` opens a real TCP socket directly to `127.0.0.1` (`::ffff:127.0.0.1`)!
4. **Step 4 — Mounted HackerOne Comment #1 & #2 (`ADDENDUM-SCENARIOS-4152265`): WHATWG `URL` vs. `ipaddr.js` RFC 4291 `::7f00:1` Parser Differential & RFC 8215 `64:ff9b:1::/48` NAT64 Bypass:** When `fetchExternalImage` parses `Location: http://[::127.0.0.1]:8080/internal.png`, Node's WHATWG `new URL()` rewrites `::127.0.0.1` into hex `::7f00:1`. Both `0:0:0:0:0:0:127.0.0.1` and `::7f00:1` (as well as `::a9fe:a9fe` for `169.254.169.254` and `64:ff9b:1::a9fe:a9fe`) return `ipaddr.parse(ip).range() === "unicast"`, so `isPrivateIp()` returns `false`!

### Vulnerable Code Snippet
```javascript
// 1. Missing matchRemotePattern / hasMatch check on 3xx redirects in fetchExternalImage()
// File: node_modules/next/dist/esm/server/image-optimizer.js (lines 586-615)
if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
    if (redirectCount >= maxRedirects) {
        throw new ImageError(400, '"url" parameter reached maxRedirects');
    }
    const redirectUrl = new URL(res.headers.get('location'), href).href;
    const parsedRedirectUrl = new URL(redirectUrl);
    // BUG 1 (09A): Only calls validateUrl(parsedRedirectUrl); NEVER re-checks hasMatch(domains, remotePatterns, parsedRedirectUrl)!
    await validateUrl(parsedRedirectUrl);
    return fetchExternalImage(redirectUrl, dangerouslyAllowLocalIP, redirectCount + 1);
}

// 2. isPrivateIp() fails open on hyphenated Linux IPv6 zone indices & RFC 4291 / RFC 8215 ranges
// File: node_modules/next/dist/esm/server/lib/find-root.js
function isPrivateIp(ip) {
    if (!ipaddr.isValid(ip)) {
        return false; // BUG 2 (09B): Fail-open! "::ffff:127.0.0.1%br-1a49f5828144" -> isValid=false -> returns false!
    }
    const addr = ipaddr.parse(ip);
    const range = addr.range(); // BUG 3 (09B): "::7f00:1" and "64:ff9b:1::a9fe:a9fe" -> range="unicast" -> returns false!
    return PRIVATE_IP_RANGES.includes(range);
}
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Same-Host Pathname & Query-String Bypass (`/public-avatars/` -> `/private-kyc-docs/passport-scan.png`) (Mounted HackerOne `#4152265` Addendum Scenario A)
A Next.js app restricts `remotePatterns` to `{ hostname: 'storage.company.example', pathname: '/public-avatars/**' }`. An attacker requests `/_next/image?url=https://storage.company.example/public-avatars/redir&w=64&q=75`, which returns `302 Found` -> `Location: /private-kyc-docs/passport-scan.png`. `fetchExternalImage()` follows the redirect and returns the sensitive image (`200 OK`, `image/png`) despite the `/public-avatars/**` pathname restriction.

### Scenario B — Cross-Host Domain Allowlist Bypass via Standard Avatar/Storage Redirector (Mounted HackerOne `#4152265` Re-Evaluation Comment #1 & Addendum Scenario B)
A Next.js app allowlists Gravatar or a multi-tenant S3/Supabase/R2 bucket. The attacker uses a standard redirect URL (`?d=https://...` or S3 `WebsiteRedirectLocation`) to pivot `fetchExternalImage()` off the allowlisted domain onto an arbitrary unapproved host (`https://unapproved-internal-partner.example/diagram.png`).

### Scenario C — Chained `09A -> 09B` Direct Linux `127.0.0.1` Loopback Socket Connection & Cloud Metadata SSRF (Mounted HackerOne `#4152265` Re-Evaluation Comment #1 & Addendum Scenario C)
The allowlisted host redirects to `http://[::ffff:127.0.0.1%25br-1a49f5828144]:45829/admin-badge.png` (or `http://[::127.0.0.1]/...` -> `::7f00:1` or `http://[64:ff9b:1::a9fe:a9fe]/...`). `dns.promises.lookup` resolves the address in the Linux kernel, `isPrivateIp()` returns `false` (fail-open on `%br-...` or `unicast` on `::7f00:1` / `64:ff9b:1::/48`), and `fetchExternalImage()` opens a real TCP socket to `127.0.0.1` (`remoteAddress: "::ffff:127.0.0.1"`) and exfiltrates the internal image!

---

## 3. Example Execution & Verification Commands

```bash
# 1. Inspect fetchExternalImage and isPrivateIp in next@16.4.3
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/server/image-optimizer.js | sed -n '586,615p'
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/server/lib/find-root.js | sed -n '100,145p'

# 2. Run the Live next@16.4.3 End-to-End Verification Harness (09A + 09B + Linux Loopback Socket Proof)
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-09-nextjs-image-optimizer-redirect-and-nat64-ssrf.patch
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Vercel & Next.js Live npm Tarball Verification Suite (see [`vercel-real-world-impact-e2e-20261029.json`](../vercel-real-world-impact-e2e-20261029.json)):

```json
{
  "VERCEL-NEXT-09": {
    "RED": {
      "package_tested": "next@16.4.3",
      "hackerone_report": "#4152265 (with 2 follow-up comments mounted)",
      "same_host_pathname_bypass_status": 200,
      "cross_host_allowlist_bypass_status": 200,
      "scoped_loopback_input": "::ffff:127.0.0.1%br-1a49f5828144",
      "ipaddr_isValid": false,
      "nextjs_isPrivateIp_returned": false,
      "loopback_server_hit": true,
      "remote_address_seen_by_server": "::ffff:127.0.0.1",
      "rfc4291_ipv4_compatible_isPrivateIp": false,
      "rfc8215_local_nat64_isPrivateIp": false
    },
    "GREEN": {
      "redirect_hop_rechecks_hasMatch_remotePatterns": true,
      "invalid_or_hyphenated_zone_ip_fails_closed": true,
      "rfc4291_and_rfc8215_blocked": true,
      "loopback_server_hit": false
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/packages/next/src/server/image-optimizer.ts
+++ b/packages/next/src/server/image-optimizer.ts
@@ -714,6 +714,9 @@ export async function fetchExternalImage(
       const redirectUrl = new URL(location, href).href
       const parsedRedirectUrl = new URL(redirectUrl)
+      if (!hasMatch(domains, remotePatterns, parsedRedirectUrl)) {
+        throw new ImageError(400, '"url" parameter redirect is not allowed')
+      }
       await validateUrl(parsedRedirectUrl)
--- a/packages/next/src/server/lib/validate-url.ts
+++ b/packages/next/src/server/lib/validate-url.ts
@@ -18,7 +18,10 @@ export function isPrivateIp(ip: string): boolean {
+  const cleanIp = ip.split('%')[0]
+  if (!ipaddr.isValid(cleanIp)) {
+    return true
+  }
+  if (cleanIp.toLowerCase().startsWith('64:ff9b:1:')) {
+    return true
+  }
```

---

## 5. Mounted HackerOne Follow-Up Comments (2 Comments Integrated)

### Mounted HackerOne Report `#4152265` Follow-Up Comment #1 (`RE-EVALUATION-COMMENT-4152265.md`)

1. **No Compromised Host Needed for `remotePatterns` Bypass (`FINDING-09A`):**
   - **Vector A (Same-Host Pathname Restriction Bypass):** Bypasses `pathname: '/public-avatars/**'` on the exact same allowlisted domain to read `/private-kyc-docs/passport-scan.png`.
   - **Vector B (Built-In Open Redirectors on Popular Allowlisted Image Hosts):** Gravatar (`?d=https%3A%2F%2F...`), Cloudinary, and multi-tenant S3 / R2 / Supabase Storage / Vercel Blob buckets natively issue `301`/`302` redirects without any server compromise.
2. **No NAT64 Needed — Direct Linux Kernel TCP Socket Connection to `127.0.0.1` via `isPrivateIp()` Fail-Open (`if (!ipaddr.isValid(ip)) return false`):**
   - In `next/dist/compiled/ipaddr.js`, the IPv6 `zoneIndex` regex is `const o = "%[0-9a-z]{1,}"`, which rejects hyphens (`-`), underscores (`_`), and dots (`.`).
   - On standard Linux / Docker / Kubernetes hosts with hyphenated interfaces (`br-1a49f5828144`, `docker_gwbridge`, `cni-podman0`, `flannel.1`, `virbr0-nic`), `dns.promises.lookup("::ffff:127.0.0.1%br-1a49f5828144", { all: true })` succeeds in the Linux kernel (`getaddrinfo()`), `ipaddr.isValid()` returns `false`, `isPrivateIp()` returns `false` (fail-open!), and Node's `http.get` connects a real TCP socket directly to `127.0.0.1`!
3. **WHATWG `URL` vs. `ipaddr.js` Parser Differential on RFC 4291 IPv4-Compatible IPv6 (`::7f00:1` & `0:0:0:0:0:0:127.0.0.1`):**
   - Node's WHATWG `new URL('http://[::127.0.0.1]')` normalizes the hostname to `::7f00:1`. Both `ipaddr.parse('::7f00:1').range()` and `ipaddr.parse('0:0:0:0:0:0:127.0.0.1').range()` return `"unicast"`, so `isPrivateIp()` returns `false`!

### Mounted HackerOne Report `#4152265` Follow-Up Comment #2 (`ADDENDUM-SCENARIOS-4152265.md`)

- **Scenario A (Same-Host Pathname Bypass):** Verified `/public-avatars/redirect-to-private` -> `/private-kyc-docs/passport-scan.png` (`200 OK`, `68 bytes`).
- **Scenario B (Cross-Host Allowlist Bypass):** Verified `allowed-cdn.example` -> `unapproved-internal.example` (`200 OK`).
- **Scenario C (2-Step Chained Redirect `09A -> 09B` to `127.0.0.1` Loopback Socket):** Verified live TCP loopback connection on `next@16.4.3` (`loopback_server_hit: true`, `remote_address_seen_by_server: "::ffff:127.0.0.1"`, `status: 200`, `bytes_exfiltrated: 68`).
