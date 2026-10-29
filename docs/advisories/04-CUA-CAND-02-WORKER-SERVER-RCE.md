# 0.0.0.0:8001 Worker Server Wildcard CORS + Fail-Open OSGYM_ALLOWED_IPS + Unauthenticated POST /reset Arbitrary Module Execution

## Quick-Fill GitHub GHSA & MITRE CNA Form Fields
- **Repository:** `trycua/cua`
- **GitHub Advisory URL:** `https://github.com/trycua/cua/security/advisories/new`
- **Existing GHSA ID:** `trycua/cua Advisory Candidate (cua-bench-rl / cua-bench)`
- **Ecosystem:** `pip`
- **Package Name:** `cua-bench-rl (and cua-bench)`
- **Affected Versions:** `<= 0.1.0 (cua-bench <= 0.3.1, commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **Patched Versions:** `None (Patch attached)`
- **CWE:** `CWE-94 (Improper Control of Generation of Code) / CWE-942 (Overly Permissive Cross-domain Whitelist)`
- **CVSS v3.1:** `8.8 High — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
- **MITRE Vendor:** `TryCua`
- **MITRE Vulnerability Type:** `Dynamic Code Execution via Wildcard CORS and Fail-Open IP Filter (CWE-94 / CWE-942)`
- **MITRE Affected Component(s):** `libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py (lines 79-108, 338-360, 499) and libs/cua-bench/cua_bench/core.py (make, lines 25-51)`
- **MITRE Suggested CVE Description:**
  > In TryCua cua-bench-rl through 0.1.0 and cua-bench through 0.3.1 (trycua/cua), worker_server.py binds to 0.0.0.0:8001 without authentication, enables CORSMiddleware with allow_origins=['*'], and uses an ip_filter_middleware that allows cross-origin browser requests to 127.0.0.1 and fails open to all remote IPs when OSGYM_ALLOWED_IPS is set to an empty string. An attacker can invoke POST /reset with an arbitrary env_path parameter, causing cua_bench.core.make to execute <env_path>/main.py on the host via spec.loader.exec_module.
- **Credit / Reporter:** `Gökçe Baran Karakamış (@dytredline)`

---

### Summary
In `trycua/cua` (`cua-bench-rl` PyPI package `<= 0.1.0` and `cua-bench`, commit `e754cfec69c41400eb2aabde716c27d15607b2f0`), `libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py` binds by default to `0.0.0.0:8001` (`worker_server.py:499-500`) without authentication, configures `CORSMiddleware(allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])` (`worker_server.py:79-85`), and implements a flawed `ip_filter_middleware` (`worker_server.py:89-108`) that (1) trusts `127.0.0.1` regardless of browser `Origin` and (2) fails open to all external IP addresses when `OSGYM_ALLOWED_IPS=""` (`if allowed_ips:` evaluates to `False` at line 102). Its unauthenticated `POST /reset` endpoint (`worker_server.py:338-360`) passes caller-controlled `request.env_path` directly to `cb.make(request.env_path)` (`libs/cua-bench/cua_bench/core.py:25-51`), which dynamically imports and executes `<env_path>/main.py` on the host via `spec.loader.exec_module(module)` (`CWE-94` / `CWE-942`).

### Concrete Everyday Real-World Production Scenarios (Why This Causes Critical Impact in Daily Use)
- **Scenario A — ML Engineer Running RL Training Workers Gets Compromised via Browser Tab (`POST /reset` -> `exec_module`):**
  1. An AI researcher runs `cua-bench-rl` workers locally (`127.0.0.1:8001`) while downloading dataset artifacts or browsing model leaderboards.
  2. A webpage issues `fetch("http://127.0.0.1:8001/reset", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ env_path: "/home/community-user/Downloads/untrusted_bundle" }) })`.
  3. Because the request arrives on loopback (`127.0.0.1`) and `CORSMiddleware` allows `*`, `ip_filter_middleware` permits the request and `cua_bench.core.make` immediately executes `/home/community-user/Downloads/untrusted_bundle/main.py` in the host Python process via `spec.loader.exec_module`.
- **Scenario B — GPU Cluster / Docker Compose Deployment with Empty `OSGYM_ALLOWED_IPS=""` Fails Open to Entire Network:**
  1. In Kubernetes/Helm or Docker Compose templates where `OSGYM_ALLOWED_IPS: ""` is passed as an empty string environment variable, `allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]` produces `[]`.
  2. Line 102 checks `if allowed_ips and client_ip not in allowed_ips:` — because `bool([])` is `False`, the IP check is completely bypassed and every node on the network can call `/reset`, `/step`, and `/screenshot` directly on `0.0.0.0:8001`.
- **Scenario C — Silent Desktop Surveillance & Input Injection via `/screenshot` and `/step`:**
  1. Even without creating a file on disk, any cross-origin webpage or LAN peer can poll `GET /screenshot` to capture Base64 screenshots of the active environment and call `POST /step` to inject arbitrary keyboard commands (`xdotool` / OS actions) into the running desktop session.

### End-to-End Runtime Proof (`RED -> GREEN + BENIGN`)
Executed against the real `cua_bench.core.make` implementation via `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand02`:

```json
{
  "CUA-CAND-02": {
    "source_file": "cua/libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py",
    "core_file": "cua/libs/cua-bench/cua_bench/core.py",
    "elapsed_ms": 16.323,
    "RED": {
      "cross_origin_reset_status": 200,
      "empty_allowed_ips_remote_lan_status": 200,
      "arbitrary_env_path_exec_module_rce": true
    },
    "GREEN": {
      "cross_origin_reset_status": 403,
      "empty_allowed_ips_remote_lan_status": 403,
      "outside_env_path_status": 400,
      "arbitrary_env_path_exec_module_rce": false
    },
    "BENIGN": {
      "loopback_valid_task_reset_status": 200
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py
+++ b/libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py
@@ -78,12 +78,6 @@
-app.add_middleware(
-    CORSMiddleware,
-    allow_origins=["*"],
-    allow_credentials=True,
-    allow_methods=["*"],
-    allow_headers=["*"],
-)
-
 @app.middleware("http")
 async def ip_filter_middleware(request: Request, call_next):
+    if request.headers.get("origin"):
+        return JSONResponse(status_code=403, content={"detail": "Cross-origin browser requests forbidden"})
     allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
-    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
+    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()] or ["127.0.0.1"]
@@ -102,3 +96,3 @@
-    if allowed_ips and client_ip not in allowed_ips:
+    if client_ip not in allowed_ips:
         return JSONResponse(status_code=403, content={"detail": f"Access denied for IP: {client_ip}"})
```
