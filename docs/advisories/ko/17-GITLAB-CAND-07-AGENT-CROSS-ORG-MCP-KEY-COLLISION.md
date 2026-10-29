# AI Catalog Agent Unscoped `McpServer` Global ID Binding and `McpConfigService#execute` Built-in `:gitlab` Key Collision Bypassing Workhorse `withheld_server_tools` (`allToolsAvailable = true`) (`GITLAB-CAND-07`)

[English](../17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md) | [Türkçe](../tr/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md) | [日本語](../ja/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md) | [简体中文](../zh-CN/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md) | **한국어**

## Quick-Fill GitHub / HackerOne & MITRE CNA Form Fields
- **Repository:** `gitlab-org/gitlab` (`https://gitlab.com/gitlab-org/gitlab`)
- **Public Technical Advisory URL:** `https://github.com/dytredline/Sniper/blob/main/docs/advisories/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md`
- **Candidate / Tracking ID:** `GITLAB-CAND-07` (`HackerOne: gitlab | MITRE CNA-LR Submitted`)
- **Ecosystem:** `RubyGems & Go / GitLab EE & Workhorse`
- **Package Name:** `gitlab-ee`
- **Affected Versions:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`
- **Patched Versions:** `None upstream on master as of 2026-10-30 (Verified defensive patch attached below)`
- **CWE:** `CWE-863 / CWE-639`
- **CVSS v3.1:** `8.1 High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`
- **MITRE Vendor:** `GitLab`
- **MITRE Suggested CVE Description:**
  > In GitLab EE through 19.6.0-pre, Ai::DuoWorkflows::McpConfigService#execute (ee/app/services/ai/duo_workflows/mcp_config_service.rb:57-64) merges ai_catalog_mcp_servers.except(:orbit) after gitlab_mcp_server(denied) without excluding the ':gitlab' key, while Mutations::Ai::Catalog::Agent::Create/Update and Ai::Catalog::McpServers::ListService resolve McpServer IDs without .in_organization scoping. Attaching an Ai::Catalog::McpServer named 'GitLab' (server_key => :gitlab, Tools: nil) overwrites the built-in ':gitlab' MCP server configuration and causes GitLab Workhorse (workhorse/internal/ai_assist/duoworkflow/mcp.go:254) to evaluate 'allToolsAvailable := s.cfg.Tools == nil' as true, bypassing withheld_server_tools restrictions.
- **Credit / Reporter:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — `McpConfigService#execute` Protects `:orbit` with `.except(:orbit)` But Forgets `:gitlab` (`mcp_config_service.rb:59-63`):** `McpConfigService#execute` builds the Workhorse MCP configuration hash via `gitlab_mcp_server(denied).merge(orbit_mcp_server).merge(ai_catalog_mcp_servers.except(:orbit))`. Because `.except(:orbit)` omits `:gitlab`, any `Ai::Catalog::McpServer` named `"GitLab"` (which normalizes to `server_key => :gitlab`) overwrites the built-in `:gitlab` entry produced by `gitlab_mcp_server(denied)`.
2. **Step 2 — Workhorse Evaluates `allToolsAvailable := s.cfg.Tools == nil` as `true` (`workhorse/internal/ai_assist/duoworkflow/mcp.go:254`):** `Ai::Catalog::McpServers::ConfigService#execute` (`config_service.rb:22-30`) builds catalog server entries as `{ URL: server.url, Headers: ... }` with no `:Tools` key (`s.cfg.Tools == nil`). When the `:gitlab` key is overwritten by a catalog server entry, Workhorse still routes `serverName == "gitlab"` to the internal `/api/v4/mcp` endpoint (`internal := serverName == "gitlab" || serverName == "orbit"` at `mcp.go:210`), but sets `allToolsAvailable := s.cfg.Tools == nil` (`true` at `mcp.go:254`), completely disabling the `withheld_server_tools(denied)` filter!
3. **Step 3 — Cross-Organization `McpServer` GID Binding (`agent/create.rb:61-65`, `agent/update.rb:65-69`, `list_service.rb:14-24`):** GraphQL agent mutations and `ListService#execute` resolve `mcp_servers` IDs via `::Ai::Catalog::McpServer.id_in(server_ids)` without `.in_organization(...)`.

### Vulnerable Code Snippet
```ruby
// File: ee/app/services/ai/duo_workflows/mcp_config_service.rb (lines 59-63)
        gitlab_mcp_server(denied)
          .merge(orbit_mcp_server)
          .merge(ai_catalog_mcp_servers.except(:orbit)) # BUG 1: Forgot :gitlab! Overwrites gitlab_mcp_server(denied)[:gitlab]
          .merge(slack_mcp_server)

// File: workhorse/internal/ai_assist/duoworkflow/mcp.go (lines 210, 254)
	internal := serverName == "gitlab" || serverName == "orbit"
...
	allToolsAvailable := s.cfg.Tools == nil // BUG 2: Catalog entry has Tools == nil -> allToolsAvailable becomes true!
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Bypassing `withheld_server_tools(denied)` on Built-in GitLab MCP Server (`allToolsAvailable = true`)
An AI Catalog Agent attaches an `McpServer` named `"GitLab"` (`server_key => :gitlab`). During a Duo Workflow run, `ai_catalog_mcp_servers.except(:orbit)` overwrites `:gitlab` with `Tools: nil`, causing Workhorse (`mcp.go:254`) to set `allToolsAvailable = true` and expose denied built-in GitLab MCP tools (`workhorse_all_tools_available: true`).

### Scenario B — Cross-Organization `McpServer` GID Attachment via GraphQL `aiCatalogAgentCreate` / `Update`
A maintainer in Organization A passes a `gid://gitlab/Ai::Catalog::McpServer/<id>` belonging to Organization B into `aiCatalogAgentCreate`; `ListService` resolves it across organization boundaries because `.in_organization` is missing.

### Scenario C — Built-in GitLab MCP `401 Unauthorized` Denial of Service When Unconnected
If an agent with a colliding `"GitLab"` catalog MCP server is executed by a user without a `McpServerUserConnection`, `Headers` is overwritten with `{}` (stripping `X-Gitlab-Oauth-Token`), causing all built-in `/api/v4/mcp` calls to fail with `401 Unauthorized`.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Inspect .except(:orbit) in McpConfigService and allToolsAvailable in Workhorse mcp.go
grep -n -C 5 "except(:orbit)" /home/community-user/targets/gitlab/ee/app/services/ai/duo_workflows/mcp_config_service.rb
grep -n -C 5 "allToolsAvailable :=" /home/community-user/targets/gitlab/workhorse/internal/ai_assist/duoworkflow/mcp.go

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report4_cand07
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via `pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py` (see [`gitlab-real-world-impact-e2e-20261029.json`](../gitlab-real-world-impact-e2e-20261029.json)):

```json
{
  "REPORT-04_CAND-07": {
    "GREEN": {
      "builtin_gitlab_overwritten": false,
      "effective_gitlab_url": "http://127.0.0.1/api/v4/mcp",
      "effective_tools_filter": [
        "get_issue",
        "list_commits"
      ],
      "workhorse_all_tools_available": false
    },
    "RED": {
      "builtin_gitlab_overwritten": true,
      "effective_gitlab_url": "https://attacker-controlled-mcp.example/sse",
      "effective_tools_filter": null,
      "workhorse_all_tools_available": true
    },
    "patches": {
      "GITLAB-CAND-07-AGENT-MCP-CROSS-ORG-AND-KEY-COLLISION.patch": "8fc8646b4681d8d558cf25d2adc1c9ccd89363809243f17e9a79134956567f60"
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/ee/app/services/ai/duo_workflows/mcp_config_service.rb
+++ b/ee/app/services/ai/duo_workflows/mcp_config_service.rb
@@ -59,7 +59,7 @@
         gitlab_mcp_server(denied)
           .merge(orbit_mcp_server)
-          .merge(ai_catalog_mcp_servers.except(:orbit))
+          .merge(ai_catalog_mcp_servers.except(:gitlab, :orbit, :slack))
           .merge(slack_mcp_server)
       end
```
