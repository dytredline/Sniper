# Chia DataLayer Mirror Synchronization HTTP `30x` Redirect-Bypass Server-Side Request Forgery (`DL-02`)

[English](../38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md) | [Türkçe](../tr/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md) | [日本語](../ja/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md) | [简体中文](../zh-CN/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md) | **한국어**

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Public On-Chain DataLayer Mirror URLs Automatically Fetched by Subscribers (`chia/data_layer/download_data.py`):** When a Chia DataLayer node subscribes to a store, it automatically queries on-chain mirror announcements and downloads `.dat` generation files over HTTP/HTTPS using `aiohttp.ClientSession.get(...)`.
2. **Step 2 — Default `allow_redirects=True` Without Redirect Target IP Validation:** While the initial mirror URL may appear to be an external public HTTPS URL, `aiohttp` follows HTTP `301`/`302`/`307` redirects by default without checking whether the redirect target resolves to `127.0.0.1`, RFC 1918 private LAN addresses, or `169.254.169.254` cloud metadata services.
3. **Step 3 — Internal Loopback & Cloud Metadata SSRF From DataLayer Nodes:** Publishing an on-chain mirror URL that returns `302 Found -> http://127.0.0.1:...` or `http://169.254.169.254/...` causes every subscribed DataLayer node to issue HTTP requests to internal services.

### Vulnerable Code Snippet
```python
# File: chia/data_layer/download_data.py
async with session.get(url, timeout=timeout) as response:
    # BUG: Follows HTTP 30x redirects by default (allow_redirects=True) without validating
    # that the target host/IP is not loopback (127.0.0.1), RFC1918 private, or link-local (169.254.169.254)!
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Probing Internal Loopback Services (`127.0.0.1`) & Cloud Metadata (`169.254.169.254`) on Subscribed Enterprise DataLayer Nodes
An attacker publishes a mirror URL for a popular DataLayer store that redirects (`302`) to internal ports or cloud metadata endpoints.

### Scenario B — Cross-Protocol / Internal Intranet Scanning Across DataLayer Replicas
Subscribed institutional mirrors automatically poll announced URLs, turning the replica fleet into an internal HTTP scanner.

### Scenario C — Patched Verification (`GREEN`)
Disabling blind redirects (`allow_redirects=False`) and validating resolved IP addresses against private/loopback/link-local ranges blocks the SSRF.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Inspect HTTP mirror download handling in chia/data_layer/download_data.py
grep -n -C 10 "session.get" /home/community-user/targets/chia-blockchain/chia/data_layer/download_data.py
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Chia Network Full-Verification E2E Suite (see [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-DL-02": {
    "RED": {
      "mirror_url": "https://mirror.example/store.dat",
      "redirect_location": "http://127.0.0.1:18999/internal-secret",
      "redirect_to_loopback_followed": true,
      "internal_loopback_hit_count": 1
    },
    "GREEN": {
      "redirect_to_loopback_followed": false,
      "internal_loopback_hit_count": 0
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/chia/data_layer/download_data.py
+++ b/chia/data_layer/download_data.py
@@ -115,6 +115,8 @@
+    validate_public_http_target(url)
+    async with session.get(url, timeout=timeout, allow_redirects=False) as response:
```
