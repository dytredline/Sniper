# OAuth 2.0 Device Authorization Grant (`Oauth::DeviceAuthorizationsController` & `Oauth::TokensController`) Policy Bypass of `disable_admin_oauth_scopes`, Email Confirmation Gate, and Organization Maintenance Mode (`GITLAB-CAND-02A / 02B / 02C`)

[English](../12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md) | [Türkçe](../tr/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md) | **日本語** | [简体中文](../zh-CN/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md) | [한국어](../ko/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md)

## Quick-Fill GitHub / HackerOne & MITRE CNA Form Fields
- **Repository:** `gitlab-org/gitlab` (`https://gitlab.com/gitlab-org/gitlab`)
- **Public Technical Advisory URL:** `https://github.com/dytredline/Sniper/blob/main/docs/advisories/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md`
- **Candidate / Tracking ID:** `GITLAB-CAND-02 (CAND-02A + CAND-02B + CAND-02C)` (`HackerOne: gitlab | MITRE CNA-LR Submitted`)
- **Ecosystem:** `RubyGems / GitLab CE & EE`
- **Package Name:** `gitlab-ce / gitlab-ee`
- **Affected Versions:** `<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`
- **Patched Versions:** `None upstream on master as of 2026-10-30 (Verified defensive patch attached below)`
- **CWE:** `CWE-863 / CWE-285`
- **CVSS v3.1:** `8.1 High — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`
- **MITRE Vendor:** `GitLab`
- **MITRE Suggested CVE Description:**
  > In GitLab CE/EE through 19.6.0-pre (and verified on live 19.5.1-ce.0), Oauth::DeviceAuthorizationsController (app/controllers/oauth/device_authorizations_controller.rb) and Oauth::TokensController (app/controllers/oauth/tokens_controller.rb) omit the verify_admin_allowed!, verify_confirmed_email!, set_current_organization, and enforce_organization_maintenance_mode before_action guards enforced by the sibling Oauth::AuthorizationsController. This allows untrusted user-created OAuth applications to mint full-privilege admin ('api' / 'admin_mode') access tokens when disable_admin_oauth_scopes is enabled (true by default), allows unconfirmed accounts (confirmed_at: nil) to mint persistent OAuth tokens, and allows OAuth device token issuance and state-changing API writes to proceed while an organization is locked in maintenance mode.
- **Credit / Reporter:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Missing `verify_admin_allowed!` Bypasses Default `disable_admin_oauth_scopes` (`CAND-02A`, `device_authorizations_controller.rb:4-42`):** In `Oauth::AuthorizationsController` (`authorizations_controller.rb:18, 274-296`), `before_action :verify_admin_allowed!` blocks any untrusted OAuth application (`trusted: false`) from connecting to an administrator account with dangerous scopes (`api`, `read_api`, `admin_mode`, `sudo`, `write_repository`) whenever `Gitlab::CurrentSettings.disable_admin_oauth_scopes` is `true` (the default GitLab security setting). Because `Oauth::DeviceAuthorizationsController` inherits directly from `Doorkeeper::DeviceAuthorizationGrant::DeviceAuthorizationsController` without adding `before_action :verify_admin_allowed!`, any regular user can create an untrusted OAuth app (`trusted: false, device_code_enabled: true, scopes: 'api admin_mode'`) and obtain a full-privilege admin access token when an admin approves a `user_code` on `/oauth/device`.
2. **Step 2 — Missing `verify_confirmed_email!` Allows Unconfirmed Accounts to Mint Persistent OAuth Tokens (`CAND-02B`, `device_authorizations_controller.rb:4-42`):** GitLab allows newly registered or reconfirming users (`confirmed_at: nil`) an active web session within `allow_unconfirmed_access_for = 3.days` (`config/initializers/8_devise.rb:75, 103`), but `Oauth::AuthorizationsController` blocks them from minting OAuth tokens via `before_action :verify_confirmed_email!` (`403 Forbidden`). `Oauth::DeviceAuthorizationsController` omits `verify_confirmed_email!`, allowing unconfirmed accounts to mint persistent `access_token` and `refresh_token` credentials via `/oauth/device/authorize`.
3. **Step 3 — Missing `enforce_organization_maintenance_mode` and `device_code` Organization Lookup (`CAND-02C`, `tokens_controller.rb:42-70` & `device_authorizations_controller.rb:4-42`):** `Oauth::TokensController#organization_for_token_request` checks `refresh_token` and `authorization_code` grants against organization maintenance freezes (`migration` -> `503 Service Unavailable`, `legal` -> `403 Forbidden`), but omits `when 'urn:ietf:params:oauth:grant-type:device_code'`, while `Oauth::DeviceAuthorizationsController` omits both `set_current_organization` and `enforce_organization_maintenance_mode`.

### Vulnerable Code Snippet
```ruby
// File: app/controllers/oauth/device_authorizations_controller.rb (lines 4-35)
module Oauth
  class DeviceAuthorizationsController < Doorkeeper::DeviceAuthorizationGrant::DeviceAuthorizationsController
    include RequestPayloadLogger

    layout 'minimal'
    # BUG: Missing before_action :verify_confirmed_email!, :verify_admin_allowed!
    # BUG: Missing prepend_before_action :set_current_organization
    # BUG: Missing before_action :enforce_organization_maintenance_mode

// File: app/controllers/oauth/tokens_controller.rb (lines 42-52)
  def organization_for_token_request
    token_params = params.permit(:grant_type, :refresh_token, :code)
    case token_params[:grant_type]
    when 'refresh_token'
      OauthAccessToken.by_refresh_token(token_params[:refresh_token])&.organization
    when 'authorization_code'
      OauthAccessGrant.by_token(token_params[:code])&.organization
    # BUG: Missing when 'urn:ietf:params:oauth:grant-type:device_code'
    end
  end
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Untrusted User-Created OAuth App Mints Full Admin `api` / `admin_mode` Token Despite `disable_admin_oauth_scopes=true`
A regular GitLab user registers an untrusted OAuth application (`POST /oauth/applications` with `scopes: "api admin_mode"`, `device_code_enabled: true`) and shares a CLI/device login code (`user_code`). When an administrator approves the code on `/oauth/device`, GitLab bypasses `disable_admin_oauth_scopes` and issues a full-privilege admin `access_token` capable of querying `/api/v4/admin/Sidekiq_queues` and administering the instance.

### Scenario B — Unconfirmed Account (`confirmed_at: nil`) Mints Persistent API & Refresh Tokens
An attacker registers an account with an unverified email address (`confirmed_at: nil`). While `/oauth/authorize` rejects the session with `403 Forbidden (unconfirmed_email)`, the attacker completes `/oauth/device/authorize` + `/oauth/token` (`grant_type=urn:ietf:params:oauth:grant-type:device_code`) and obtains persistent API tokens before email verification.

### Scenario C — State-Changing Repository Writes During Organization Migration / Legal Maintenance Freeze
While an enterprise organization is locked in `migration` (`503`) or `legal` (`403`) maintenance mode to prevent state mutations, a client exchanges a `device_code` at `/oauth/token` and commits changes (`POST /api/v4/projects/1/repository/commits` -> `201 Created`) during the freeze window.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Inspect missing before_action guards in DeviceAuthorizationsController vs AuthorizationsController
grep -n -C 6 "verify_admin_allowed!" \
  /home/community-user/targets/gitlab/app/controllers/oauth/authorizations_controller.rb \
  /home/community-user/targets/gitlab/app/controllers/oauth/device_authorizations_controller.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report1_cand02
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via `pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py` (see [`gitlab-real-world-impact-e2e-20261029.json`](../gitlab-real-world-impact-e2e-20261029.json)):

```json
{
  "REPORT-01_CAND-02A-02B-02C": {
    "GREEN": {
      "device_authorize_status": 503,
      "maintenance_mode_write_succeeded": false,
      "post_token_admin_action_succeeded": false,
      "redacted_token_sample": null,
      "standard_oauth_blocked": true,
      "token_exchange_status": 503,
      "token_minted_admin_mode": false
    },
    "RED": {
      "device_authorize_status": 200,
      "maintenance_mode_write_succeeded": true,
      "post_token_admin_action_succeeded": true,
      "redacted_token_sample": "[REDACTED_TEST_TOKEN_SHA256:91ba3cabf8cbd392]",
      "standard_oauth_blocked": true,
      "token_exchange_status": 200,
      "token_minted_admin_mode": true
    },
    "patches": {
      "GITLAB-CAND-02-COMBINED.patch": "33f6cf48a91be9d564f3964e9b9c7a4c6d412b6814ebfa71356102767bddc698",
      "GITLAB-CAND-02C-MAINTENANCE-MODE.patch": "80bfc7b3ee0e328487e4de303a9d707e575989f848d778914b359494fac90aa8"
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/app/controllers/oauth/device_authorizations_controller.rb
+++ b/app/controllers/oauth/device_authorizations_controller.rb
@@ -4,6 +4,10 @@ module Oauth
   class DeviceAuthorizationsController < Doorkeeper::DeviceAuthorizationGrant::DeviceAuthorizationsController
     include RequestPayloadLogger
 
+    prepend_before_action :set_current_organization
+    before_action :enforce_organization_maintenance_mode
+    before_action :verify_confirmed_email!, :verify_admin_allowed!, only: [:confirm, :authorize]
+
     layout 'minimal'
--- a/app/controllers/oauth/tokens_controller.rb
+++ b/app/controllers/oauth/tokens_controller.rb
@@ -40,13 +40,15 @@
   def organization_for_token_request
-    token_params = params.permit(:grant_type, :refresh_token, :code)
+    token_params = params.permit(:grant_type, :refresh_token, :code, :device_code)
 
     case token_params[:grant_type]
     when 'refresh_token'
       OauthAccessToken.by_refresh_token(token_params[:refresh_token])&.organization
     when 'authorization_code'
       OauthAccessGrant.by_token(token_params[:code])&.organization
+    when 'urn:ietf:params:oauth:grant-type:device_code'
+      Doorkeeper::DeviceAuthorizationGrant::DeviceGrant.by_device_code(token_params[:device_code])&.organization
     end
   end
```
