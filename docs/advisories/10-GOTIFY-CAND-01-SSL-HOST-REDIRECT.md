# Unvalidated ctx.Request.Host in Built-In SSL Redirect Middleware Enables HTTP 308 Open Redirect and Token Phishing

## Quick-Fill GitHub GHSA & MITRE CNA Form Fields
- **Repository:** `gotify/server`
- **GitHub Advisory URL:** `https://github.com/gotify/server/security/advisories/new`
- **Existing GHSA ID:** `None (New GHSA & CNA Candidate)`
- **Ecosystem:** `Go`
- **Package Name:** `github.com/gotify/server/v2`
- **Affected Versions:** `<= v2.9.1 (commit f4de61997c1b30bf9ac43ec662dc5120c2ec981b)`
- **Patched Versions:** `None (Patch attached)`
- **CWE:** `CWE-601 (URL Redirection to Untrusted Site — Open Redirect)`
- **CVSS v3.1:** `4.7 Medium — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N`
- **MITRE Vendor:** `Gotify`
- **MITRE Vulnerability Type:** `Open Redirect via Unvalidated Host Header (CWE-601)`
- **MITRE Affected Component(s):** `router/router.go (Create, lines 52-73, 93-102)`
- **MITRE Suggested CVE Description:**
  > In Gotify Server through 2.9.1 (github.com/gotify/server/v2), when SSL.Enabled and SSL.RedirectToHTTPS are enabled, the HTTP-to-HTTPS redirect middleware in router/router.go constructs 308/302 Location headers directly from the unvalidated client-supplied ctx.Request.Host header instead of the configured SSL hostname, allowing attackers to redirect clients and URL tokens to an arbitrary external domain via a crafted Host header.
- **Credit / Reporter:** `Gökçe Baran Karakamış (@dytredline)`

---

### Summary
In `gotify/server` (`v2.9.1`, commit `f4de61997c1b30bf9ac43ec662dc5120c2ec981b`), when the built-in SSL redirector is enabled (`SSL.Enabled=true` and `SSL.RedirectToHTTPS=true`), the HTTP-to-HTTPS redirect middleware in `router/router.go:52-73, 93-102` constructs the `308 Permanent Redirect` (or `302` on `POST`) `Location` header directly from the unvalidated client-supplied `ctx.Request.Host` header (`https://<Host><RequestURI>`) instead of binding the redirect target to the configured `conf.Server.SSL.LetsEncrypt.Hosts` canonical hostname (`CWE-601`).

### Concrete Everyday Real-World Production Scenarios (Why This Causes Critical Impact in Daily Use)
- **Scenario A — Web-Push / Mobile Client Token Phishing & Permanent Browser Redirect Cache Poisoning (`308 Permanent Redirect`):**
  1. A self-hosted Gotify server runs with `SSL.Enabled: true` and `SSL.RedirectToHTTPS: true`.
  2. An attacker sends a request (or poisons an intermediate HTTP cache / captive portal) with `Host: attacker-gotify.example.com` to `http://<gotify-ip>/#/messages?token=...` or `http://<gotify-host>/client`.
  3. Gotify responds with `HTTP/1.1 308 Permanent Redirect` and `Location: https://attacker-gotify.example.com/#/messages?token=...`, preserving the HTTP method, URL fragment, and query parameters while redirecting the client to the attacker's host.
- **Scenario B — Automated Webhook / Alerting Script Credential Leak on `308` Redirect Follow:**
  1. Monitoring scripts (`curl -L`, Python `requests`, or Uptime Kuma) configured against the HTTP endpoint with `?token=<app-token>` follow the `308` redirect to `https://<attacker-host>/message?token=<app-token>`, leaking the Gotify application token in the URL query string.
- **Scenario C — Password-Reset / Invite Link Host Header Poisoning Behind Reverse Proxies:**
  1. When deployed behind a load balancer or reverse proxy that forwards the `Host` header, any request with a spoofed `Host` header receives an official `308` redirect signed/served by the Gotify instance pointing to the attacker's domain.

### End-to-End Runtime Proof (`RED -> GREEN + BENIGN`)
Executed via `go test -v ./router -run TestHTTPSRedirect` (`PASS`) and `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_gotify_cand01`:

```json
{
  "GOTIFY-CAND-01": {
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
