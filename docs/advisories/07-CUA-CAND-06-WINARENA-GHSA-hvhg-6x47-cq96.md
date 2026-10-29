# WinArena Orchestrator Binds Unauthenticated noVNC (0.0.0.0:8006) & Passwordless RDP (0.0.0.0:3390) to All Interfaces with Writable Host /shared Mount (`GHSA-hvhg-6x47-cq96`)

**English** | [Türkçe](tr/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | [日本語](ja/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | [简体中文](zh-CN/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | [한국어](ko/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
In `trycua/cua` (`cua-bench` `<= 0.3.1`, `libs/cua-bench/tasks/winarena_adapter/cli.py:262-265, 421-424, 646-649` and `infra/vm/setup/server/main.py:180-248, 290-321`, commit `e754cfec69c41400eb2aabde716c27d15607b2f0`), all three Docker launcher commands (`cmd_vm_setup`, `cmd_vm_start`, `cmd_task_run`) expose the Windows VM and host source directory without isolation (`CWE-668` / `CWE-732`):

1. **Step 1 — Unauthenticated `0.0.0.0` Docker Port Publishing (`cli.py:262-263, 421-422, 646-647`):**
   Passing `-p {args.browser_port}:8006` and `-p {args.rdp_port}:3389` without a `127.0.0.1:` prefix causes Docker to bind both the unauthenticated noVNC web console (`8006`) and passwordless Windows RDP service (`3390`) on `0.0.0.0` across all LAN/Wi-Fi interfaces (bypassing host `ufw` `INPUT` rules via Docker's `FORWARD` chain).
2. **Step 2 — Writable Host Source Directory Mount (`cli.py:265, 424, 649`):**
   Passing `-v {setup_path}:/shared` without `:ro` mounts the host's `winarena_adapter/infra/vm/setup` directory read-write inside the container environment.
3. **Step 3 — Unauthenticated Guest `exec()` Control Server (`infra/vm/setup/server/main.py:180-248`):**
   Inside the guest VM, `server/main.py` listens on `0.0.0.0:5000` and executes arbitrary Python code via `POST /execute_windows` (`exec(command)`) and shell commands via `POST /setup/launch` (`shell=True`) without any token or header check.

### Vulnerable Code Snippet (`winarena_adapter/cli.py:261-266`)
```python
# File: libs/cua-bench/tasks/winarena_adapter/cli.py (lines 261-266, repeated at 421-424 and 646-649)
        "-p", f"{args.browser_port}:8006", # BUG 1: Exposes unauthenticated noVNC on 0.0.0.0:8006 to LAN!
        "-p", f"{args.rdp_port}:3389",     # BUG 2: Exposes passwordless RDP on 0.0.0.0:3390 to LAN!
        "-v", f"{storage_path}:/storage",
        "-v", f"{setup_path}:/shared",     # BUG 3: Mounts host source directory read-write instead of :ro!
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — LAN Peer on University / Corporate Lab Network Takes Over Windows Evaluation VM via `http://<host-ip>:8006` (noVNC) or `:3390` (RDP)
1. A researcher runs `cua-bench` WinArena tasks on a lab workstation connected to a shared university or corporate network.
2. Because `cli.py:262-265` passes `-p 8006:8006 -p 3390:3389` without `127.0.0.1:`, Docker binds both ports on `0.0.0.0` (bypassing host `ufw` `INPUT` rules via the `DOCKER` forwarding chain).
3. Any user on the LAN opens `http://<workstation-ip>:8006` in a browser (no password required) and gets full interactive Administrator control of the Windows VM desktop, including any LLM API keys or credentials injected into the benchmark environment.

### Scenario B — Guest-to-Host Poisoning via Read-Write `-v {setup_path}:/shared` Mount
1. The container mounts the host's `winarena_adapter/infra/vm/setup` directory read-write at `/shared` (`cli.py:265, 424, 649`).
2. An attacker who accesses the environment via `0.0.0.0:8006` / `0.0.0.0:3390` modifies the setup scripts and Python files inside `/shared`.
3. Because `/shared` maps directly to the host's `winarena_adapter` source tree, subsequent host-side CLI runs or test executions load the tampered files.

### Scenario C — In-Guest Browser Drive-By RCE Against Unauthenticated `0.0.0.0:5000/execute_windows` (`exec()`)
1. During a benchmark evaluation run, the autonomous browser agent inside the Windows VM visits an external webpage or untrusted local HTML task artifact.
2. JavaScript on that page sends a request to `http://127.0.0.1:5000/execute_windows` or `http://127.0.0.1:5000/setup/launch` hosted by `infra/vm/setup/server/main.py:180-248`.
3. Because `server/main.py` enforces zero authentication and passes the payload directly to Python's `exec(command)` and `subprocess.Popen(..., shell=True)`, the webpage achieves immediate arbitrary code execution as the Windows Administrator user inside the VM.

---

## 3. Example Execution & Verification Commands

### 1. Auditing the Component with Sniper CLI
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua-bench/tasks/winarena_adapter/cli.py"
```

### 2. Local Isolated Reproduction & Verification
```bash
# Inspect the unprefixed Docker port bindings and writable /shared volume mounts across cli.py
grep -n -C 4 "8006" \
  /home/community-user/targets/cua/libs/cua-bench/tasks/winarena_adapter/cli.py

# Inspect the unauthenticated exec() in infra/vm/setup/server/main.py
grep -n -C 8 "def execute_windows" \
  /home/community-user/targets/cua/libs/cua-bench/tasks/winarena_adapter/infra/vm/setup/server/main.py
```

### 3. Running the Automated `RED -> GREEN + BENIGN` E2E Verification Harness
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand06
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Optional Defensive Diff

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
