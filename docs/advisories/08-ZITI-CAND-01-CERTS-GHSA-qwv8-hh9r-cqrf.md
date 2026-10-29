# AreCertsTrusted() Unconditionally Sets InsecureSkipVerify: true, Disabling TLS Certificate Verification During ziti edge login (`GHSA-qwv8-hh9r-cqrf`)

**English** | [Türkçe](tr/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | [日本語](ja/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | [简体中文](zh-CN/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | [한국어](ko/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
In `openziti/ziti` (`github.com/openziti/ziti/v2`, commit `236f351a5149fe68328fc8083bebe514f0307d0c`), `ziti edge login` (`ziti/cmd/edge/login.go:511, 535-549`) fetches the controller's CA bundle from `/.well-known/est/cacerts` and calls `util.AreCertsTrusted(host, wellKnownCerts, httpClient)` (`ziti/util/certs.go:91-103`) to verify that the server's leaf TLS certificate is actually signed by that CA bundle before sending credentials. A fatal flaw in `InsecureClient` disables this verification entirely (`CWE-295`):

1. **Step 1 — Intended `x509.UnknownAuthorityError` Check in `AreCertsTrusted` (`ziti/util/certs.go:91-103`):**
   `AreCertsTrusted` performs an HTTPS `GET` to `host` and checks `if ue, ok := err.(*url.Error); ok && errors.As(ue.Err, &x509.UnknownAuthorityError{}) { return false, nil }` at lines 95-98.
2. **Step 2 — Unconditional `InsecureSkipVerify: true` in `InsecureClient` (`ziti/util/certs.go:199-208`):**
   `AreCertsTrusted` builds its HTTP client via `InsecureClient(&client, certs)`. Even when `len(certs) > 0` and the certificates are appended to `tlsConfig.RootCAs`, line 202 hardcodes `InsecureSkipVerify: true`.
3. **Step 3 — Complete Bypass of `RootCAs` Verification During `ziti edge login`:**
   In Go's `crypto/tls`, setting `InsecureSkipVerify: true` skips certificate chain validation against `RootCAs` completely. As a result, `x509.UnknownAuthorityError` is never raised, line 96 is unreachable dead code, `AreCertsTrusted` always returns `true, nil` for any untrusted MITM certificate, and `login.go:511` prints `"Verified that server supplied certificates are trusted by server"` before transmitting administrator credentials to the attacker.

### Vulnerable Code Snippet (`ziti/util/certs.go:91-103, 199-208`)
```go
// File: ziti/util/certs.go (lines 91-103, 199-208)
func AreCertsTrusted(host string, certs []byte, httpClient *http.Client) (bool, error) {
	client := *httpClient
	resp, err := InsecureClient(&client, certs).Get(host)
	if err != nil {
		if ue, ok := err.(*url.Error); ok && errors.As(ue.Err, &x509.UnknownAuthorityError{}) {
			return false, nil // DEAD CODE: Never reached because InsecureSkipVerify is unconditionally true!
		}
		return false, err
	}
	_ = resp.Body.Close()
	return true, nil
}
...
func InsecureClient(client *http.Client, certs []byte) *http.Client {
	tlsConfig := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		InsecureSkipVerify: true, // BUG: Should be len(certs) == 0 so RootCAs is actually enforced!
	}
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — DevOps Engineer Runs `ziti edge login` Over Wi-Fi / VPN and Sends Admin Credentials to a Rogue MITM Controller
1. An administrator runs `ziti edge login https://ziti-controller.internal:1280 -u admin -p <AdminPassword>` from a workstation.
2. An active network attacker (via ARP spoofing, rogue Wi-Fi, or DNS hijack) intercepts the connection using an untrusted self-signed TLS certificate while serving a valid-looking CA bundle on `/.well-known/est/cacerts`.
3. Because `AreCertsTrusted` leaves `InsecureSkipVerify: true`, Go's `crypto/tls` never verifies that the server's TLS certificate was signed by the `/.well-known/est/cacerts` pool; `login.go:511` falsely prints `"Verified that server supplied certificates are trusted by server"` and sends the administrator's password or token directly to the MITM attacker.

### Scenario B — Automated CI/CD & Kubernetes Zero-Trust Enrollment Pipeline Compromised via Untrusted TLS Leaf Certificate
1. An automated CI/CD pipeline or Kubernetes init job runs `ziti edge login --yes` to bootstrap zero-trust service identities and router policies.
2. An attacker on the network path presents an arbitrary untrusted leaf TLS certificate that is not signed by the controller's EST CA bundle.
3. Because `AreCertsTrusted()` unconditionally returns `true, nil`, the pipeline persists the untrusted certificate chain and transmits privileged enrollment credentials over the compromised connection.

### Scenario C — Silent Acceptance of Expired, Self-Signed, or Wrong-Environment Controller Certificates in Multi-Cluster Operations
1. In a multi-cluster enterprise running separate `dev`, `staging`, and `prod` OpenZiti environments behind ingress proxies, a proxy fronts the controller with an expired, self-signed, or mismatched leaf TLS certificate not signed by the controller's EST CA.
2. Instead of triggering the intended warning at `login.go:545` (`"Server supplied certs are not trusted by server"`), `AreCertsTrusted()` falsely reports that the certificate chain is verified, causing operators to authenticate production credentials against an untrusted endpoint.

---

## 3. Example Execution & Verification Commands

### 1. Auditing the Component with Sniper CLI
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/ziti \
  --include "ziti/util/certs.go"
```

### 2. Local Isolated Reproduction & Verification (`127.0.0.1`)
```bash
# Run the Go unit test proving AreCertsTrusted behavior against a local 127.0.0.1 TLS server
cd /home/community-user/targets/ziti && go test -v -run TestRealOpenZitiAreCertsTrusted ./ziti/util
```

### 3. Running the Automated `RED -> GREEN + BENIGN` E2E Verification Harness
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_ziti_cand01
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Optional Defensive Diff

Verified both via `go test -v -run TestRealOpenZitiAreCertsTrusted ./ziti/util` (`PASS` in `0.014s`) and `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_ziti_cand01`:

```json
{
  "ZITI-CAND-01": {
    "ghsa_id": "GHSA-qwv8-hh9r-cqrf",
    "source_file": "ziti/ziti/util/certs.go",
    "login_caller_file": "ziti/ziti/cmd/edge/login.go",
    "elapsed_ms": 0.719,
    "RED": {
      "insecure_skip_verify": true,
      "rogue_mitm_cert_accepted_as_trusted": true,
      "admin_credentials_sent_to_mitm": true
    },
    "GREEN": {
      "insecure_skip_verify": false,
      "rogue_mitm_cert_accepted_as_trusted": false,
      "tls_error": "x509.UnknownAuthorityError: certificate signed by unknown authority"
    },
    "BENIGN": {
      "valid_ca_signed_controller_trusted": true
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/ziti/util/certs.go
+++ b/ziti/util/certs.go
@@ -199,7 +199,7 @@
 func InsecureClient(client *http.Client, certs []byte) *http.Client {
 	tlsConfig := &tls.Config{
 		RootCAs:            x509.NewCertPool(),
-		InsecureSkipVerify: true,
+		InsecureSkipVerify: len(certs) == 0,
 	}
 
 	if len(certs) > 0 {
```
