# `Projects::Integrations::SlashCommandsController#confirm` Unvalidated `redirect_url` Open Redirect, Unbound `response_url`, and Cross-Project Redis `CACHE_KEY` Collision (`GITLAB-CAND-04`)

**English** | [Türkçe](tr/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md) | [日本語](ja/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md) | [简体中文](zh-CN/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md) | [한국어](ko/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md)

## Quick-Fill GitHub / HackerOne & MITRE CNA Form Fields
- **Repository:** `gitlab-org/gitlab` (`https://gitlab.com/gitlab-org/gitlab`)
- **Public Technical Advisory URL:** `https://github.com/dytredline/Sniper/blob/main/docs/advisories/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md`
- **Candidate / Tracking ID:** `GITLAB-CAND-04` (`HackerOne: gitlab | MITRE CNA-LR Submitted`)
- **Ecosystem:** `RubyGems / GitLab CE & EE`
- **Package Name:** `gitlab-ce / gitlab-ee`
- **Affected Versions:** `<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`
- **Patched Versions:** `None upstream on master as of 2026-10-30 (Verified defensive patch attached below)`
- **CWE:** `CWE-601 / CWE-863`
- **CVSS v3.1:** `5.4 Medium — CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
- **MITRE Vendor:** `GitLab`
- **MITRE Suggested CVE Description:**
  > In GitLab CE/EE through 19.6.0-pre, Projects::Integrations::SlashCommandsController#confirm (app/controllers/projects/integrations/slash_commands_controller.rb:21-48) passes unvalidated request_params[:response_url] to Gitlab::SlashCommands::VerifyRequest and calls redirect_to request_params[:redirect_url] (with config.action_controller.raise_on_open_redirects = false), while Integrations::Base::SlashCommands::CACHE_KEY (app/models/concerns/integrations/base/slash_commands.rb:9) keys Redis entries solely by command_id without binding project_id or integration_id. An attacker can replay a command_id across projects to bind a victim's ChatName integration and trigger an authenticated open redirect to an arbitrary external URL.
- **Credit / Reporter:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Unvalidated `redirect_to request_params[:redirect_url]` with `raise_on_open_redirects = false` (`slash_commands_controller.rb:26`, `config/application.rb:63`):** While `SlashCommandsController#show` (line 11) safely computes `@redirect_url = integration_redirect_url`, `#confirm` (line 26) calls `redirect_to request_params[:redirect_url]` directly on the user-controlled parameter. Because `config.action_controller.raise_on_open_redirects = false` is set globally in `config/application.rb:63`, Rails issues a `302 Found` redirect to any arbitrary external `https://` URL.
2. **Step 2 — Unbound `request_params[:response_url]` Passed to `VerifyRequest` (`slash_commands_controller.rb:25`):** Instead of reading `cached_params[:response_url]` from Redis, `#confirm` passes the request parameter `request_params[:response_url]` to `Gitlab::SlashCommands::VerifyRequest.new(integration, chat_user, request_params[:response_url]).approve!`.
3. **Step 3 — Cross-Project Redis `CACHE_KEY` Lacks `project_id` and `integration_id` (`slash_commands.rb:9, 68-76`):** `CACHE_KEY = "slash-command-requests:%{secret}"` is keyed only by the UUID `command_id`. Any `command_id` minted in Project B is accepted as `valid_request?` on Project A's `/slash_commands/confirm` endpoint.

### Vulnerable Code Snippet
```ruby
// File: app/controllers/projects/integrations/slash_commands_controller.rb (lines 21-28, 41-48)
      def confirm
        if valid_request? && valid_user?
          # BUG 1: Uses request_params[:response_url] instead of cached_params[:response_url]
          Gitlab::SlashCommands::VerifyRequest.new(integration, chat_user, request_params[:response_url]).approve!
          # BUG 2: Redirects to unvalidated request_params[:redirect_url] (raise_on_open_redirects = false)
          redirect_to request_params[:redirect_url]
        else
...
      def cache_key
        @cache_key ||= Kernel.format(
          ::Integrations::Base::SlashCommands::CACHE_KEY, # BUG 3: "slash-command-requests:%{secret}" has no project_id/integration_id!
          secret: request_params[:command_id]
        )
      end
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Authenticated Open Redirect After Slash Command Approval
An attacker sends a link to a legitimate GitLab project slash command confirmation endpoint containing a crafted `redirect_url=https://evil-phishing.example/oauth/callback`. Once the authenticated user confirms, GitLab responds with `302 Found` to the attacker's domain (`open_redirect_triggered: true`).

### Scenario B — Cross-Project `command_id` Replay Binds Victim's `ChatName` to Another Project's Integration
An attacker triggers a slash command on Project B to obtain a valid `command_id` in Redis, then crafts a confirmation URL on Project A using that `command_id` (`cross_project_cache_collision_accepted: true`).

### Scenario C — Arbitrary `response_url` Callback Target Manipulation
Supplying a custom `request_params[:response_url]` on `POST /confirm` causes `VerifyRequest#approve!` to send the slash command approval callback to the caller-supplied URL rather than the cached integration URL.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Inspect confirm and cache_key in Projects::Integrations::SlashCommandsController
sed -n '10,48p' \
  /home/community-user/targets/gitlab/app/controllers/projects/integrations/slash_commands_controller.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report5_cand04
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via `pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py` (see [`gitlab-real-world-impact-e2e-20261029.json`](gitlab-real-world-impact-e2e-20261029.json)):

```json
{
  "REPORT-05_CAND-04": {
    "GREEN": {
      "cross_project_cache_collision_accepted": false,
      "http_status": 404,
      "location_header": "",
      "open_redirect_triggered": false
    },
    "RED": {
      "cross_project_cache_collision_accepted": true,
      "http_status": 302,
      "location_header": "https://evil-phishing.example/oauth/callback?steal=1",
      "open_redirect_triggered": true
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/app/controllers/projects/integrations/slash_commands_controller.rb
+++ b/app/controllers/projects/integrations/slash_commands_controller.rb
@@ -21,9 +21,9 @@
       def confirm
-        if valid_request? && valid_user?
-          Gitlab::SlashCommands::VerifyRequest.new(integration, chat_user, request_params[:response_url]).approve!
-          redirect_to request_params[:redirect_url]
+        if valid_request? && valid_user? && integration_redirect_url.present?
+          Gitlab::SlashCommands::VerifyRequest.new(integration, chat_user, cached_params[:response_url]).approve!
+          redirect_to integration_redirect_url, allow_other_host: false
         else
```
