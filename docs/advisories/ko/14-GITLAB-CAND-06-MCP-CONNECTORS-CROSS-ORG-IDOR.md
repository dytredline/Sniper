# `Oauth::McpConnectorsAuthController`, `ConnectService`, and `Gitlab::Oauth::ClientState` Missing Organization Isolation (`in_organization`), Unauthorized DCR Client Overwrite, and Unbound OAuth State (`GITLAB-CAND-06`)

[English](../14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md) | [Türkçe](../tr/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md) | [日本語](../ja/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md) | [简体中文](../zh-CN/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md) | **한국어**

## Quick-Fill GitHub / HackerOne & MITRE CNA Form Fields
- **Repository:** `gitlab-org/gitlab` (`https://gitlab.com/gitlab-org/gitlab`)
- **Public Technical Advisory URL:** `https://github.com/dytredline/Sniper/blob/main/docs/advisories/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md`
- **Candidate / Tracking ID:** `GITLAB-CAND-06` (`HackerOne: gitlab | MITRE CNA-LR Submitted`)
- **Ecosystem:** `RubyGems / GitLab EE`
- **Package Name:** `gitlab-ee`
- **Affected Versions:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`
- **Patched Versions:** `None upstream on master as of 2026-10-30 (Verified defensive patch attached below)`
- **CWE:** `CWE-639 / CWE-862`
- **CVSS v3.1:** `8.1 High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **MITRE Vendor:** `GitLab`
- **MITRE Suggested CVE Description:**
  > In GitLab EE through 19.6.0-pre, Oauth::McpConnectorsAuthController (ee/app/controllers/oauth/mcp_connectors_auth_controller.rb) loads Ai::Catalog::McpServer records via global Ai::Catalog::McpServer.find(params[:id]) without scoping to .in_organization(Current.organization), Ai::Catalog::McpServers::ConnectService (connect_service.rb) mutates oauth_client_id and oauth_client_secret via Dynamic Client Registration while checking only read_ai_catalog_mcp_server instead of update_ai_catalog_mcp_server, and Gitlab::Oauth::ClientState.from_state (ee/lib/gitlab/oauth/client_state.rb) discards the signed data payload when reconstructing state tokens. An authenticated low-privileged user can access or overwrite MCP server OAuth credentials across organization boundaries and replay OAuth callback states.
- **Credit / Reporter:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Unscoped Global `Ai::Catalog::McpServer.find` Across Organizations (`mcp_connectors_auth_controller.rb:19, 38, 63, 71-73`):** `Oauth::McpConnectorsAuthController` checks `can?(current_user, :read_ai_catalog_mcp_server, Current.organization)` against the caller's own organization, and then calls `::Ai::Catalog::McpServer.find(mcp_server_params[:id])` without `.in_organization(Current.organization)`. Any user in Organization A can target an `McpServer` belonging to Organization B by ID.
2. **Step 2 — Unauthorized Dynamic Client Registration (DCR) Credential Mutation with Read-Only Permission (`connect_service.rb:16-39, 60-79`):** When `mcp_server.oauth_client_id.blank?` is true, `ConnectService#execute` calls `register_oauth_client`, which overwrites `mcp_server.update!(oauth_client_id: ..., oauth_client_secret: ...)` without verifying `Ability.allowed?(current_user, :update_ai_catalog_mcp_server, mcp_server)`.
3. **Step 3 — `Gitlab::Oauth::ClientState.from_state` Discards `data` Binding (`client_state.rb:17-23`) and `callback` Accepts Missing PKCE Verifiers:** `ClientState.from_state(state)` calls `new(salt: salt, token: token, return_to: return_to)` without passing `data:`, so `@data` defaults to `{}` and the HMAC check verifies only `return_to` without binding `user_id`, `organization_id`, or `mcp_server_id`.

### Vulnerable Code Snippet
```ruby
// File: ee/app/controllers/oauth/mcp_connectors_auth_controller.rb (lines 18-65)
    def connect
      mcp_server = ::Ai::Catalog::McpServer.find(mcp_server_params[:id]) # BUG 1: Missing .in_organization(Current.organization)
      result = ::Ai::Catalog::McpServers::ConnectService.new(
        mcp_server: mcp_server,
        redirect_uri: oauth_mcp_connectors_callback_url,
        return_to: mcp_server_params[:return_to] || root_path
      ).execute # BUG 2: Mutates oauth_client_id/secret without checking :update_ai_catalog_mcp_server!

// File: ee/lib/gitlab/oauth/client_state.rb (lines 19-23)
      def self.from_state(state)
        salt, token, return_to = state.to_s.split(':', 3)
        new(salt: salt, token: token, return_to: return_to) # BUG 3: Omits data: binding!
      end
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Cross-Organization MCP Server DCR Credential Hijack
A low-privileged user in Organization A invokes `POST /oauth/mcp_connectors/:id/connect` targeting an unconfigured `McpServer` in Organization B, triggering `register_oauth_client` and overwriting Organization B's `oauth_client_id` and `oauth_client_secret` (`cross_org_server_mutated: true`).

### Scenario B — Non-Maintainer Member Overwrites Project/Org MCP Server Credentials
A regular developer with only `read_ai_catalog_mcp_server` triggers DCR registration on an internal MCP connector before a maintainer finishes configuring it.

### Scenario C — OAuth Callback State Replay / Login CSRF Across Sessions
Because `ClientState.from_state` drops `data` and `callback` only attaches `code_verifier` if present in the session, an attacker can replay a valid `state` token across sessions to bind their external MCP account to a victim's `McpServerUserConnection`.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Inspect unscoped McpServer.find in McpConnectorsAuthController and ConnectService
grep -n -C 8 "McpServer.find" \
  /home/community-user/targets/gitlab/ee/app/controllers/oauth/mcp_connectors_auth_controller.rb

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
--- a/ee/app/controllers/oauth/mcp_connectors_auth_controller.rb
+++ b/ee/app/controllers/oauth/mcp_connectors_auth_controller.rb
@@ -96,6 +104,13 @@
+    def find_mcp_server!(id)
+      server = ::Ai::Catalog::McpServer.in_organization(Current.organization).find(id)
+      raise ActiveRecord::RecordNotFound unless can?(current_user, :read_ai_catalog_mcp_server, server)
+
+      server
+    end
--- a/ee/lib/gitlab/oauth/client_state.rb
+++ b/ee/lib/gitlab/oauth/client_state.rb
@@ -19,9 +19,9 @@
-      def self.from_state(state)
+      def self.from_state(state, data: {})
         salt, token, return_to = state.to_s.split(':', 3)
-        new(salt: salt, token: token, return_to: return_to)
+        new(salt: salt, token: token, return_to: return_to, data: data)
       end
```
