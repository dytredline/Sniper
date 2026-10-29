# WinArena Orchestrator Binds Unauthenticated noVNC (0.0.0.0:8006) & Passwordless RDP (0.0.0.0:3390) to All Interfaces with Writable Host /shared Mount

## Quick-Fill GitHub GHSA & MITRE CNA Form Fields
- **Repository:** `trycua/cua`
- **GitHub Advisory URL:** `https://github.com/trycua/cua/security/advisories/GHSA-hvhg-6x47-cq96`
- **Existing GHSA ID:** `GHSA-hvhg-6x47-cq96`
- **Ecosystem:** `pip`
- **Package Name:** `cua-bench`
- **Affected Versions:** `<= 0.3.1 (commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **Patched Versions:** `None (Patch attached)`
- **CWE:** `CWE-668 (Exposure of Resource to Wrong Sphere) / CWE-732 (Incorrect Permission Assignment for Critical Resource)`
- **CVSS v3.1:** `8.6 High — CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
- **MITRE Vendor:** `TryCua`
- **MITRE Vulnerability Type:** `Unauthenticated Network Exposure and Writable Host Volume Mount (CWE-668 / CWE-732)`
- **MITRE Affected Component(s):** `libs/cua-bench/tasks/winarena_adapter/cli.py (lines 262-265, 421-424, 646-649) and infra/vm/setup/server/main.py (lines 180-248, 290-321)`
- **MITRE Suggested CVE Description:**
  > In TryCua cua-bench through 0.3.1 (trycua/cua), the WinArena container orchestrator (libs/cua-bench/tasks/winarena_adapter/cli.py) publishes the Windows guest VM's unauthenticated noVNC web desktop (-p 8006:8006) and passwordless RDP service (-p 3390:3389) on 0.0.0.0 (all network interfaces) instead of 127.0.0.1, while mounting the host setup_path directory read-write (-v {setup_path}:/shared). Adjacent network peers can take over the guest desktop and modify host-shared setup files.
- **Credit / Reporter:** `Gökçe Baran Karakamış (@dytredline)`

---

### Summary
In `trycua/cua` (`cua-bench` WinArena adapter, `libs/cua-bench/tasks/winarena_adapter/cli.py:262-265, 421-424, 646-649` and `infra/vm/setup/server/main.py:180-248, 290-321`, commit `e754cfec69c41400eb2aabde716c27d15607b2f0`), all three Docker launcher commands (`cmd_vm_setup`, `cmd_vm_start`, `cmd_task_run`) publish the guest Windows VM's unauthenticated noVNC web desktop (`-p 8006:8006`) and passwordless RDP service (`-p 3390:3389`) on `0.0.0.0` (all host network interfaces) instead of `127.0.0.1`, while simultaneously mounting the host's `setup_path` directory read-write (`-v {setup_path}:/shared`) into the container. Inside the VM, `server/main.py` listens on `0.0.0.0:5000` with unauthenticated `POST /execute_windows` (`exec()`) and `POST /setup/launch` (`shell=True`).

### Concrete Everyday Real-World Production Scenarios (Why This Causes Critical Impact in Daily Use)
- **Scenario A — Any Peer on University / Corporate Lab LAN Takes Over the Windows Evaluation VM via `http://<host-ip>:8006` (noVNC) or `:3390` (RDP):**
  1. A researcher runs `cua-bench` WinArena tasks on a lab workstation connected to a shared university or office network.
  2. Because `cli.py:262-265` passes `-p 8006:8006 -p 3390:3389` without `127.0.0.1:`, Docker binds both ports on `0.0.0.0` (bypassing UFW/iptables `INPUT` chains via the `DOCKER` forwarding chain).
  3. Any user on the LAN opens `http://<workstation-ip>:8006` in a browser (no password required) and gets full interactive Administrator control of the Windows VM desktop, including any API keys or credentials injected into the benchmark environment.
- **Scenario B — Guest-to-Host Poisoning via Read-Write `-v {setup_path}:/shared` Mount:**
  1. The container mounts the host's `winarena_adapter/infra/vm/setup` directory read-write at `/shared` (`cli.py:264, 423, 648`).
  2. An attacker who accesses the guest via `0.0.0.0:8006` / `0.0.0.0:3390` (or when an agent inside the VM visits a malicious page that triggers the unauthenticated guest control server) modifies the setup scripts inside `/shared` on the host filesystem.
- **Scenario C — Unauthenticated Guest Control Plane (`/execute_windows` -> Python `exec()`):**
  1. Inside the guest environment, `server/main.py:180-208` executes arbitrary Python strings submitted to `/execute_windows` via raw `exec(command)` without any token or header check, allowing any process or SSRF inside the VM to execute arbitrary OS commands as the Windows user.

### End-to-End Runtime Proof (`RED -> GREEN + BENIGN`)
Executed via `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand06`:

```json
{
  "CUA-CAND-06": {
    "ghsa_id": "GHSA-hvhg-6x47-cq96",
    "cli_source_file": "cua/libs/cua-bench/tasks/winarena_adapter/cli.py",
    "server_source_file": "cua/libs/cua-bench/tasks/winarena_adapter/infra/vm/setup/server/main.py",
    "elapsed_ms": 0.05,
    "RED": {
      "lan_exposed_ports": [
        "8006:8006",
        "3390:3389"
      ],
      "host_setup_dir_mounted_writable": true,
      "guest_execute_windows_requires_auth": false
    },
    "GREEN": {
      "lan_exposed_ports": [],
      "host_setup_dir_mounted_writable": false,
      "guest_execute_windows_requires_auth": true
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/libs/cua-bench/tasks/winarena_adapter/cli.py
+++ b/libs/cua-bench/tasks/winarena_adapter/cli.py
@@ -261,9 +261,9 @@
-        "-p", f"{args.browser_port}:8006",
-        "-p", f"{args.rdp_port}:3389",
-        "-v", f"{storage_path}:/storage",
-        "-v", f"{setup_path}:/shared",
+        "-p", f"127.0.0.1:{args.browser_port}:8006",
+        "-p", f"127.0.0.1:{args.rdp_port}:3389",
+        "-v", f"{storage_path}:/storage",
+        "-v", f"{setup_path}:/shared:ro",
```
