# Duo Workflow `/ws` and `McpConfigService#item_version` Missing `:read_ai_catalog_item` Authorization and Unvalidated `workflow_definition` Override Allowing Private Agent Write-Tool Injection (`GITLAB-CAND-08`)

**English** | [Türkçe](tr/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md) | [日本語](ja/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md) | [简体中文](zh-CN/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md) | [한국어](ko/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md)

## Quick-Fill GitHub / HackerOne & MITRE CNA Form Fields
- **Repository:** `gitlab-org/gitlab` (`https://gitlab.com/gitlab-org/gitlab`)
- **Public Technical Advisory URL:** `https://github.com/dytredline/Sniper/blob/main/docs/advisories/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md`
- **Candidate / Tracking ID:** `GITLAB-CAND-08` (`HackerOne: gitlab | MITRE CNA-LR Submitted`)
- **Ecosystem:** `RubyGems / GitLab EE`
- **Package Name:** `gitlab-ee`
- **Affected Versions:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`
- **Patched Versions:** `None upstream on master as of 2026-10-30 (Verified defensive patch attached below)`
- **CWE:** `CWE-862 / CWE-639`
- **CVSS v3.1:** `7.7 High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`
- **MITRE Vendor:** `GitLab`
- **MITRE Suggested CVE Description:**
  > In GitLab EE through 19.6.0-pre, Ai::DuoWorkflows::McpConfigService#item_version (ee/app/services/ai/duo_workflows/mcp_config_service.rb:131-135) resolves Ai::Catalog::ItemVersion.find_by_id(ai_catalog_item_version_id) without checking Ability.allowed?(current_user, :read_ai_catalog_item, item_version) (which is enforced at line 334 of the same file), while API::Ai::DuoWorkflows::Workflows (ee/lib/api/ai/duo_workflows/workflows.rb:341-344, 1065) and ConnectionConfigService#mcp_config_service (ee/app/services/ai/duo_workflows/connection_config_service.rb:220-228) allow callers on GET /api/v4/ai/duo_workflows/ws to override workflow_definition and supply arbitrary ai_catalog_item_version_id values from private cross-project/cross-organization AI Catalog items, injecting unapproved opt-in write tools into the Duo Workflow MCP tool configuration.
- **Credit / Reporter:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — In-File Authorization Inconsistency in `McpConfigService` (`mcp_config_service.rb:134` vs. `334`):** In `ee/app/services/ai/duo_workflows/mcp_config_service.rb`, `ai_catalog_mcp_servers` (line 334) explicitly enforces `return {} unless Ability.allowed?(current_user, :read_ai_catalog_item, item_version)`. However, in the exact same file, `item_version` (line 134), `agent_mcp_tools` (line 297), and `built_in_tool_ids` (line 318) call `::Ai::Catalog::ItemVersion.find_by_id(ai_catalog_item_version_id)` without any `Ability.allowed?` check.
2. **Step 2 — `GET /api/v4/ai/duo_workflows/ws` (`workflows.rb:1065`) Bypasses the Developer's Security Rule at Line 1426:** At `workflows.rb:1426-1433`, a developer comment states: `# The definition comes off the record for the same reason: it selects the MCP tool set and the minted token's feature, so the body must not be able to swap in another flow's.` Yet `get :ws` (`workflows.rb:1065`) omits `workflow_definition: workflow.workflow_definition` and `ConnectionConfigService#mcp_config_service` (`connection_config_service.rb:220-228`) reads `request_metadata.workflow_definition` and `request_metadata.ai_catalog_item_version_id` directly from user query parameters.
3. **Step 3 — Injection of Foreign Private Agent Opt-In Write Tools:** By passing a foreign private (`public: false`) agent's `ai_catalog_item_version_id` and overriding `workflow_definition` on `/ws`, an authenticated caller injects opt-in write tools (`create_issue`, `create_merge_request`) into `x-gitlab-duo-workflow-mcp-servers` and discloses the private agent's configured tool set.

### Vulnerable Code Snippet
```ruby
// File: ee/app/services/ai/duo_workflows/mcp_config_service.rb (lines 131-135 vs 330-335)
      def item_version
        return unless ai_catalog_item_version_id.present?

        ::Ai::Catalog::ItemVersion.find_by_id(ai_catalog_item_version_id) # BUG 1: Missing Ability.allowed?(current_user, :read_ai_catalog_item, version)!
      end
      ...
      def ai_catalog_mcp_servers
        return {} unless item_version
        return {} unless Ability.allowed?(current_user, :read_ai_catalog_item, item_version) # Enforced here at line 334, but omitted at line 134!

// File: ee/app/services/ai/duo_workflows/connection_config_service.rb (lines 222-228)
      def mcp_config_service
        ::Ai::DuoWorkflows::McpConfigService.new(
          current_user,
          gitlab_token,
          workflow_definition: request_metadata.workflow_definition, # BUG 2: Uses unvalidated request_metadata instead of workflow record!
          ai_catalog_item_version_id: request_metadata.ai_catalog_item_version_id,
          namespace: project&.project_namespace || enforcement_namespace
        )
      end
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Injecting Write Tools into a Restricted `chat` Workflow via `/ws` Parameter Override
A user starts a read-only `chat` workflow (`workflow.workflow_definition == 'chat'`), then connects to `GET /api/v4/ai/duo_workflows/ws` with an overridden `workflow_definition` and a foreign private `ai_catalog_item_version_id`, enabling write tools (`create_issue`) that were withheld from the workflow record (`unapproved_write_tool_injected: true`).

### Scenario B — Cross-Project / Cross-Organization Private AI Agent Tool Reconnaissance
An attacker iterates `ai_catalog_item_version_id` values on `/ws` (or `POST /api/v4/ai/duo_workflows/workflows`) to read the configured `def_tools` and `def_mcp_tools` of private (`public: false`) AI Catalog agents belonging to other organizations.

### Scenario C — Automated Write Tool Execution Without Expected Workflow Definition Restrictions
During a Duo Workflow WebSocket session, tools injected via unvalidated `item_version` / `workflow_definition` parameters execute state-changing actions in accessible projects.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Compare line 134 vs line 334 in ee/app/services/ai/duo_workflows/mcp_config_service.rb
sed -n '130,136p;330,337p' \
  /home/community-user/targets/gitlab/ee/app/services/ai/duo_workflows/mcp_config_service.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report3_cand08
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via `pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py` (see [`gitlab-real-world-impact-e2e-20261029.json`](gitlab-real-world-impact-e2e-20261029.json)):

```json
{
  "REPORT-03_CAND-08": {
    "GREEN": {
      "automated_issue_created_without_prompt": false,
      "downstream_victim_project_tools_call_status": 404,
      "unapproved_write_tool_injected": false,
      "workflow_definition_overridden": false
    },
    "RED": {
      "automated_issue_created_without_prompt": true,
      "downstream_victim_project_tools_call_status": 404,
      "unapproved_write_tool_injected": true,
      "workflow_definition_overridden": true
    },
    "patches": {
      "GITLAB-CAND-08-WORKFLOW-ITEM-VERSION-AUTHZ.patch": "d40f6e104c2fba0e8900cab8d45ddfb4cf9c49a60c8bb12e3aa573ddb1228704"
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/ee/app/services/ai/duo_workflows/mcp_config_service.rb
+++ b/ee/app/services/ai/duo_workflows/mcp_config_service.rb
@@ -131,7 +131,10 @@
       def item_version
         return unless ai_catalog_item_version_id.present?
 
-        ::Ai::Catalog::ItemVersion.find_by_id(ai_catalog_item_version_id)
+        version = ::Ai::Catalog::ItemVersion.find_by_id(ai_catalog_item_version_id)
+        return unless version && Ability.allowed?(current_user, :read_ai_catalog_item, version)
+
+        version
       end
```
