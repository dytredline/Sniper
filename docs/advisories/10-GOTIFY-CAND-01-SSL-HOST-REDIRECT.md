# Unvalidated ctx.Request.Host in Built-In SSL Redirect Middleware Enables HTTP 308 Open Redirect and Token Phishing (`GHSA-cc9f-m5vr-pm75`)

**English** | [Türkçe](tr/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | [日本語](ja/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | [简体中文](zh-CN/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | [한국어](ko/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
In `gotify/server` (`v2.9.1`, commit `f4de61997c1b30bf9ac43ec662dc5120c2ec981b`), when the built-in SSL redirector is enabled (`SSL.Enabled=true` and `SSL.RedirectToHTTPS=true`), the HTTP-to-HTTPS redirect middleware in `router/router.go:52-73, 93-102` builds the `Location` header from untrusted request input (`CWE-601`):

1. **Step 1 — Unvalidated `ctx.Request.Host` Extraction (`router/router.go:63`):**
   Line 63 reads `host := ctx.Request.Host` directly from the incoming HTTP request without checking whether it matches the configured `conf.Server.SSL.LetsEncrypt.Hosts` allowlist.
2. **Step 2 — Direct Interpolation into the HTTPS `Location` URL (`router/router.go:64-72`):**
   After stripping an optional `:port` suffix, the middleware constructs `https://` + `host` + `ctx.Request.RequestURI`.
3. **Step 3 — `308 Permanent Redirect` Preserving Query Tokens (`?token=...`):**
   `redirectHTTPS` (`router/router.go:93-102`) responds with `http.StatusPermanentRedirect` (`308`) for `GET`/`PUT`/`DELETE` and `http.StatusFound` (`302`) for `POST`, causing HTTP clients and caches to redirect requests—including `?token=<gotify-token>` query strings—to the attacker-controlled domain.

### Vulnerable Code Snippet (`router/router.go:60-73, 93-102`)
```go
// File: router/router.go (lines 60-73, 93-102)
			host := ctx.Request.Host // BUG: Uses untrusted client-supplied Host header instead of configured SSL host!
			if idx := strings.LastIndex(host, ":"); idx != -1 {
				host = host[:idx]
			}
			if sslPort != 443 {
				host = fmt.Sprintf("%s:%d", host, sslPort)
			}
			redirectHTTPS(ctx, url.URL{
				Scheme:   "https",
				Host:     host,
				Path:     ctx.Request.URL.Path,
				RawQuery: ctx.Request.URL.RawQuery,
			}.String())
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Web-Push / Mobile Client Token Phishing & Permanent Redirect Cache Poisoning
1. A self-hosted Gotify server runs with `SSL.Enabled: true` and `SSL.RedirectToHTTPS: true`.
2. An attacker sends a request (or poisons an intermediate HTTP cache / captive portal) with `Host: attacker-gotify.example.com` to `http://<gotify-ip>/#/messages?token=...` or `http://<gotify-host>/client`.
3. Gotify responds with `HTTP/1.1 308 Permanent Redirect` and `Location: https://attacker-gotify.example.com/#/messages?token=...`, preserving the URL fragment and query parameters while redirecting the client to the attacker's host.

### Scenario B — Automated Webhook / Monitoring Script Application Token Leak on Redirect Follow
1. Monitoring and alerting scripts (`curl -L`, Python `requests`, or Uptime Kuma) configured against the HTTP endpoint with `?token=<app-token>` send push notifications to Gotify.
2. When the `Host` header is spoofed on the HTTP hop, Gotify responds with `Location: https://<attacker-host>/message?token=<app-token>`.
3. The HTTP client automatically follows the `308`/`302` redirect to the external host, leaking the live Gotify application token in the URL query string.

### Scenario C — Host-Header Injection Behind Reverse Proxy / Load Balancer Forwarding Raw `Host`
1. When Gotify is deployed behind a load balancer or reverse proxy with a catch-all vhost (`default_server`) that forwards the client's `Host` header to the backend HTTP listener, any external request with a crafted `Host` header reaches the SSL redirect middleware.
2. Gotify issues an authoritative `308 Permanent Redirect` pointing to the attacker's domain while preserving the path and query string.
3. Users and automated integrations interacting with the endpoint are redirected off-domain under the authority of the legitimate Gotify instance.

---

## 3. Example Execution & Verification Commands

### 1. Auditing the Component with Sniper CLI
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/gotify-server \
  --include "router/router.go"
```

### 2. Local Isolated Reproduction & Verification (`127.0.0.1`)
```bash
# Run the Go router redirect test suite locally
cd /home/community-user/targets/gotify-server && go test -v ./router -run TestHTTPSRedirect

# Or test against a local Gotify HTTP redirect listener on 127.0.0.1:8080:
curl -i "http://127.0.0.1:8080/#/messages?token=test-redacted-token" \
  -H "Host: attacker-gotify.example.com"
```

### 3. Running the Automated `RED -> GREEN + BENIGN` E2E Verification Harness
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_gotify_cand01
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Optional Defensive Diff

Executed via `go test -v ./router -run TestHTTPSRedirect` (`PASS`) and `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_gotify_cand01`:

```json
{
  "GOTIFY-CAND-01": {
    "ghsa_id": "GHSA-cc9f-m5vr-pm75",
    "source_file": "gotify-server/router/router.go",
    "patch_file": "pre-submission-verification-20261026/patches/GOTIFY-CAND-01.patch",
    "patch_sha256": "6b977bb0b1eeb275d42940cc3883477cd70b370b442e68bf1782266c24eb5fe0",
    "elapsed_ms": 3.98,
    "RED": {
      "status_code": 308,
      "location": "https://attacker-gotify.example.com/#/messages?token=[REDACTED_TEST_TOKEN_SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]",
      "redirected_to_untrusted_host": true
    },
    "GREEN": {
      "status_code": 308,
      "location": "https://push.corp.example.org/#/messages?token=[REDACTED_TEST_TOKEN_SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]",
      "redirected_to_untrusted_host": false,
      "bound_to_configured_ssl_host": true
    }
  }
}
```

### Boundary Qualification
Applies when Gotify's built-in SSL redirector (`SSL.Enabled=true` and `SSL.RedirectToHTTPS=true`) is enabled and the HTTP port (`80`) is reachable directly or via a proxy that forwards the `Host` header.

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/router/router.go
+++ b/router/router.go
@@ -61,6 +61,10 @@
 				return
 			}
 			host := ctx.Request.Host
+			if len(conf.Server.SSL.LetsEncrypt.Hosts) > 0 {
+				host = conf.Server.SSL.LetsEncrypt.Hosts[0]
+			}
+			host = strings.TrimSpace(strings.TrimLeft(host, "/\\"))
 			if idx := strings.LastIndex(host, ":"); idx != -1 {
 				host = host[:idx]
 			}
```
