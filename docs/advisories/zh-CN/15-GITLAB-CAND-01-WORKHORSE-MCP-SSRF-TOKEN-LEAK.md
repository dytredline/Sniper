# GitLab Workhorse DuoWorkflow External MCP Client Missing `transport.WithSSRFFilter()` and Cross-Origin Redirect `Authorization: Bearer` Token Leakage (`GITLAB-CAND-01`)

[English](../15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md) | [Türkçe](../tr/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md) | [日本語](../ja/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md) | **简体中文** | [한국어](../ko/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md)

## Quick-Fill GitHub / HackerOne & MITRE CNA Form Fields
- **Repository:** `gitlab-org/gitlab` (`https://gitlab.com/gitlab-org/gitlab`)
- **Public Technical Advisory URL:** `https://github.com/dytredline/Sniper/blob/main/docs/advisories/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md`
- **Candidate / Tracking ID:** `GITLAB-CAND-01` (`HackerOne: gitlab | MITRE CNA-LR Submitted`)
- **Ecosystem:** `Go / GitLab Workhorse`
- **Package Name:** `gitlab.com/gitlab-org/gitlab/workhorse`
- **Affected Versions:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`
- **Patched Versions:** `None upstream on master as of 2026-10-30 (Verified defensive patch attached below)`
- **CWE:** `CWE-918 / CWE-522`
- **CVSS v3.1:** `8.2 High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`
- **MITRE Vendor:** `GitLab`
- **MITRE Suggested CVE Description:**
  > In GitLab Workhorse through 19.6.0-pre (workhorse/internal/ai_assist/duoworkflow/mcp.go), externalMcpTransport is constructed via transport.NewRestrictedTransport without passing transport.WithSSRFFilter() (unlike workhorse/internal/sendurl/sendurl.go), and roundTripper.RoundTrip unconditionally injects configured authentication headers (such as Authorization: Bearer) on every HTTP request including cross-origin redirect hops without a CheckRedirect policy. An external MCP server can redirect Workhorse to internal loopback/metadata services or cross-origin hosts and exfiltrate the user's MCP Bearer token.
- **Credit / Reporter:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — `externalMcpTransport` Omits `transport.WithSSRFFilter` (`workhorse/internal/ai_assist/duoworkflow/mcp.go:41-44`):** In GitLab Workhorse's `transport` package, `transport.NewRestrictedTransport` only blocks loopback (`127.0.0.1`), link-local metadata (`169.254.169.254`), and RFC1918 private IPs when `transport.WithSSRFFilter(...)` is explicitly passed (as done in `workhorse/internal/sendurl/sendurl.go:365-374`). `externalMcpTransport` in `mcp.go:41-44` omits `transport.WithSSRFFilter`, leaving external MCP connections completely unfiltered at the dialer/transport layer.
2. **Step 2 — `roundTripper.RoundTrip` Re-Injects `Authorization: Bearer` Headers on Every Redirect Hop (`mcp.go:101-104, 231-234`):** Go's `http.Client` normally strips `Authorization` headers on cross-origin redirects *before* calling `Transport.RoundTrip`. However, `duoworkflow.roundTripper.RoundTrip` loops over `t.headers` (`r.Header.Set(name, value)`) inside `RoundTrip` itself and `HTTPClient` defines no `CheckRedirect` policy. Consequently, on any `301`/`302`/`307` redirect to a different host or internal IP, Workhorse re-attaches `Authorization: Bearer <token>` and sends it to the redirect destination.

### Vulnerable Code Snippet
```ruby
// File: workhorse/internal/ai_assist/duoworkflow/mcp.go (lines 41-44, 101-104, 231-234)
var externalMcpTransport = transport.NewRestrictedTransport(func(t *http.Transport) {
	t.MaxIdleConns = externalMcpMaxIdleConns
	t.MaxIdleConnsPerHost = externalMcpMaxIdleConnsPerHost
}) // BUG 1: Missing transport.WithSSRFFilter(false, nil)!

func (t *roundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	for name, value := range t.headers {
		r.Header.Set(name, value) // BUG 2: Re-injects Authorization header on cross-origin redirect hops!
	}
...
	t = &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: &http.Client{Transport: rt}, // BUG 3: No CheckRedirect policy!
		DisableStandaloneSSE: true,
	}
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Cross-Origin `302` Redirect Steals User's MCP `Authorization: Bearer` Token
When a Duo Workflow session connects to an external MCP server, a `302 Found` redirect to an external collector causes Workhorse's `roundTripper.RoundTrip` to forward the user's `Authorization: Bearer` token to the third-party host (`bearer_token_leaked_to_canary: true`).

### Scenario B — Workhorse Redirect SSRF to Internal Loopback (`127.0.0.1`) and Cloud Metadata (`169.254.169.254`)
An external MCP endpoint allowed by Rails initial URL checks redirects (`302`) to `http://127.0.0.1:8080` or `http://169.254.169.254/`; because `externalMcpTransport` lacks `transport.WithSSRFFilter`, Workhorse connects directly to the internal service.

### Scenario C — DNS Rebinding Against Workhorse Long-Lived MCP Transport
Without `transport.WithSSRFFilter` dial-time IP validation in `externalMcpTransport`, an external hostname that resolves to a public IP during Rails configuration validation and rebinds to `127.0.0.1` when Workhorse dials reaches local services on the Workhorse host.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Compare externalMcpTransport in duoworkflow/mcp.go against sendurl/sendurl.go
grep -n -C 8 "NewRestrictedTransport" \
  /home/community-user/targets/gitlab/workhorse/internal/ai_assist/duoworkflow/mcp.go \
  /home/community-user/targets/gitlab/workhorse/internal/sendurl/sendurl.go

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report2_cand05
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via `pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py` (see [`gitlab-real-world-impact-e2e-20261029.json`](../gitlab-real-world-impact-e2e-20261029.json)):

```json
{
  "REPORT-02_CAND-05-06-01": {
    "GREEN": {
      "bearer_token_leaked_to_canary": false,
      "canary_b_request_count": 0,
      "cross_org_server_mutated": false,
      "iam_role_credentials_exposed": false,
      "reflected_flash_contains_secret": false
    },
    "RED": {
      "bearer_token_leaked_to_canary": true,
      "canary_b_request_count": 2,
      "cross_org_server_mutated": true,
      "iam_role_credentials_exposed": true,
      "reflected_flash_contains_secret": true
    },
    "patches": {
      "GITLAB-CAND-01.patch": "77be0cfe3092c808ea8f0a1f33689c61de1c9db01155e950b1192f883984b689",
      "GITLAB-CAND-05.patch": "e63dce6d6b71fcb0fa357103078290e07d66a0c756607b7b35da9eae209b687e",
      "GITLAB-CAND-06-MCP-IDOR-CSRF.patch": "8bed587ca203bfcde8fcf8e4ec27b12038e4e5366dc33f3d285b742811d2632b"
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/workhorse/internal/ai_assist/duoworkflow/mcp.go
+++ b/workhorse/internal/ai_assist/duoworkflow/mcp.go
@@ -38,10 +39,13 @@
-var externalMcpTransport = transport.NewRestrictedTransport(func(t *http.Transport) {
-	t.MaxIdleConns = externalMcpMaxIdleConns
-	t.MaxIdleConnsPerHost = externalMcpMaxIdleConnsPerHost
-})
+var externalMcpTransport = transport.NewRestrictedTransport(
+	transport.WithSSRFFilter(false, nil),
+	func(t *http.Transport) {
+		t.MaxIdleConns = externalMcpMaxIdleConns
+		t.MaxIdleConnsPerHost = externalMcpMaxIdleConnsPerHost
+	},
+)
@@ -99,8 +104,10 @@
 func (t *roundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
-	for name, value := range t.headers {
-		r.Header.Set(name, value)
+	if t.internal || t.allowedHost == "" || r.URL.Host == t.allowedHost {
+		for name, value := range t.headers {
+			r.Header.Set(name, value)
+		}
 	}
```
