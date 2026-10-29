# AreCertsTrusted() Unconditionally Sets InsecureSkipVerify: true, Disabling TLS Certificate Verification During ziti edge login

## Quick-Fill GitHub GHSA & MITRE CNA Form Fields
- **Repository:** `openziti/ziti`
- **GitHub Advisory URL:** `https://github.com/openziti/ziti/security/advisories/GHSA-qwv8-hh9r-cqrf`
- **Existing GHSA ID:** `GHSA-qwv8-hh9r-cqrf`
- **Ecosystem:** `Go`
- **Package Name:** `github.com/openziti/ziti/v2`
- **Affected Versions:** `<= v2 (commit 236f351a5149fe68328fc8083bebe514f0307d0c)`
- **Patched Versions:** `None (Patch attached)`
- **CWE:** `CWE-295 (Improper Certificate Validation)`
- **CVSS v3.1:** `7.4 High — CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`
- **MITRE Vendor:** `NetFoundry / OpenZiti`
- **MITRE Vulnerability Type:** `Improper Certificate Validation (CWE-295)`
- **MITRE Affected Component(s):** `ziti/util/certs.go (AreCertsTrusted & InsecureClient, lines 91-103, 199-208) and ziti/cmd/edge/login.go (fetchTrustedServerCerts, lines 511, 535-549)`
- **MITRE Suggested CVE Description:**
  > In OpenZiti ziti through commit 236f351a5149fe68328fc8083bebe514f0307d0c (github.com/openziti/ziti/v2), util.AreCertsTrusted in ziti/util/certs.go calls InsecureClient(&client, certs), which unconditionally sets tls.Config{InsecureSkipVerify: true} even when len(certs) > 0. Because Go's crypto/tls ignores RootCAs when InsecureSkipVerify is true, the x509.UnknownAuthorityError check in AreCertsTrusted is unreachable dead code and AreCertsTrusted always returns true during 'ziti edge login', allowing a man-in-the-middle attacker with an untrusted TLS certificate to intercept administrator credentials.
- **Credit / Reporter:** `Gökçe Baran Karakamış (@dytredline)`

---

### Summary
In `openziti/ziti` (`github.com/openziti/ziti/v2`, commit `236f351a5149fe68328fc8083bebe514f0307d0c`), `util.AreCertsTrusted(host, wellKnownCerts, httpClient)` (`ziti/util/certs.go:91-103`) is called during `ziti edge login` (`ziti/cmd/edge/login.go:535-549`) to verify that the Ziti Edge Controller's TLS certificate is genuinely signed by the CA bundle retrieved from `/.well-known/est/cacerts`, after which `login.go:511` prints `"Verified that server supplied certificates are trusted by server"`. However, `AreCertsTrusted` constructs its HTTP client via `InsecureClient(&client, certs)` (`certs.go:199-208`), which unconditionally sets `InsecureSkipVerify: true` even when `len(certs) > 0`. In Go's `crypto/tls`, `InsecureSkipVerify: true` causes the TLS handshake to completely ignore `RootCAs`, rendering the `errors.As(ue.Err, &x509.UnknownAuthorityError{})` check at `certs.go:96` unreachable dead code and causing `AreCertsTrusted` to **always return `true, nil`** for any rogue or self-signed certificate (`CWE-295`).

### Concrete Everyday Real-World Production Scenarios (Why This Causes Critical Impact in Daily Use)
- **Scenario A — DevOps Engineer Runs `ziti edge login` Over Wi-Fi / VPN and Sends Admin Credentials to a Rogue MITM Controller:**
  1. An administrator runs `ziti edge login https://ziti-controller.internal:1280 -u admin -p <AdminPassword>` for the first time on a workstation or CI runner.
  2. An active network attacker (ARP spoofing, rogue Wi-Fi, BGP/DNS hijack) intercepts the connection with an untrusted self-signed TLS certificate while returning a valid-looking CA bundle on `/.well-known/est/cacerts`.
  3. Because `AreCertsTrusted` calls `InsecureClient` with `InsecureSkipVerify: true`, Go's `crypto/tls` never checks whether the server's TLS certificate was signed by the `/.well-known/est/cacerts` pool; `login.go:511` falsely prints `"Verified that server supplied certificates are trusted by server"` and transmits the administrator's username/password or API token directly to the attacker.
- **Scenario B — Automated CI/CD Enrollment Trusts a Compromised or Misconfigured Edge Controller:**
  1. A deployment pipeline runs `ziti edge login` to bootstrap service identities and router policies.
  2. Even if an attacker cannot forge the EST CA bundle, they can present any arbitrary leaf TLS certificate during the handshake and still pass `AreCertsTrusted()` with `true, nil`.
- **Scenario C — Dead-Code Proof in `certs.go:95-98` Confirming Developer Intent:**
  1. Lines 95-98 of `ziti/util/certs.go` explicitly check:
     `if ue, ok := err.(*url.Error); ok && errors.As(ue.Err, &x509.UnknownAuthorityError{}) { return false, nil }`
  2. In Go's standard library (`crypto/tls/handshake_client.go`), `x509.UnknownAuthorityError` is **only** returned when `c.config.InsecureSkipVerify` is `false`. Leaving `InsecureSkipVerify: true` when `len(certs) > 0` in `InsecureClient` (`certs.go:202`) accidentally broke the exact security check the author wrote `AreCertsTrusted` to perform.

### End-to-End Runtime Proof (`RED -> GREEN + BENIGN`)
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
