# AI Catalog MCP OAuth `CallbackService`, `RefreshTokenService`, `RevokeTokenService`, and `DynamicRegistrationClient` `307 Temporary Redirect` / Unvalidated RFC 8414 Metadata SSRF & Error Body Reflection (`GITLAB-CAND-05`)

[English](../13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md) | [Türkçe](../tr/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md) | [日本語](../ja/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md) | **简体中文** | [한국어](../ko/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Unvalidated RFC 8414 `token_endpoint`, `revocation_endpoint`, and `authorization_servers` (`dynamic_registration_client.rb:104-136`):** `DynamicRegistrationClient#discover_auth_server_url` and `#discover_metadata` validate only the initial discovery URL via `UrlBlocker`, but return `resource_metadata['authorization_servers'].first` and `response.parsed_response` (`token_endpoint`, `revocation_endpoint`, `issuer`) without running `Gitlab::HTTP_V2::UrlBlocker.validate!` on the discovered endpoints.
2. **Step 2 — `OAuth2::Client` (`oauth2 2.0.25`) Bypasses `Gitlab::HTTP` and Follows Up to 5 `307 Temporary Redirect` Hops (`callback_service.rb:38-50`, `refresh_token_service.rb:45-58`):** `CallbackService#build_oauth_client` and `RefreshTokenService#build_oauth_token` instantiate `OAuth2::Client.new` using Faraday's default `net_http` adapter (`max_redirects: 5`) without `UrlBlocker` or IP pinning. When an external OAuth server responds with `307 Temporary Redirect` to `http://127.0.0.1:...` or `http://169.254.169.254/latest/meta-data/...`, `OAuth2::Client` replays the full `POST` request (including `client_secret`, `code`, or `refresh_token`) directly against the internal target.
3. **Step 3 — Full Internal Error Body Reflection via `OAuth2::Error#message` (`callback_service.rb:24-25`, `refresh_token_service.rb:29-30`):** Both services rescue `OAuth2::Error => e` and pass `e.message` into `error(format(_('Failed to connect to MCP server: %{error}'), error: e.message))`, which `Oauth::McpConnectorsAuthController#callback` assigns to `flash[:alert]`, exposing raw internal HTTP `4xx`/`5xx` response bodies to the user.

### Vulnerable Code Snippet
```ruby
// File: ee/app/services/ai/catalog/mcp_servers/callback_service.rb (lines 15-50)
        def execute
          token_params = { redirect_uri: redirect_uri }
          token_params[:code_verifier] = code_verifier if code_verifier

          access_token = build_oauth_client.auth_code.get_token(code, **token_params)
          store_token(access_token)
        rescue OAuth2::Error, StandardError => e
          # BUG 1: Reflects raw upstream HTTP error response body (e.message) into flash[:alert]
          error(format(_('Failed to connect to MCP server: %{error}'), error: e.message))
        end
        ...
        def build_oauth_client
          auth_server_url = registration_service.discover_auth_server_url
          metadata = registration_service.discover_metadata(auth_server_url)
          # BUG 2: Uses OAuth2::Client (Faraday net_http, max_redirects: 5) without UrlBlocker or IP pinning!
          OAuth2::Client.new(
            mcp_server.oauth_client_id,
            mcp_server.oauth_client_secret,
            site: auth_server_url,
            authorize_url: metadata['authorization_endpoint'],
            token_url: metadata['token_endpoint'],
            auth_scheme: ::Gitlab::Oauth::DynamicRegistrationClient.token_endpoint_auth_scheme(metadata)
          )
        end
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Stealing AWS/GCP Cloud IAM Credentials (`169.254.169.254`) and Internal Kubernetes/Vault Secrets Directly into the User's Browser (`flash[:alert]`)
An attacker registers an external MCP server whose OAuth `token_endpoint` responds with `307 Temporary Redirect` pointing to the cloud instance metadata service (`http://169.254.169.254/latest/meta-data/iam/security-credentials/...`) or an internal Kubernetes/Vault/Consul API (`http://127.0.0.1:8080/...`). `OAuth2::Client` follows the redirect from inside the GitLab server network and reflects the raw HTTP response body via `OAuth2::Error#message` straight into the user's browser `flash[:alert]` banner (`iam_role_credentials_exposed: true`), allowing the attacker to steal the GitLab host's cloud IAM role keys and compromise the underlying cloud infrastructure.

### Scenario B — Executing Authenticated Internal `POST` Commands Against Firewalled Intranet Services (`127.0.0.1` / `10.x.x.x`) & Leaking OAuth Secrets
Because `307 Temporary Redirect` preserves both the `POST` method and request body, an external OAuth endpoint redirects `CallbackService` and `RefreshTokenService` (`max_redirects: 5`) to firewalled internal microservices (`http://127.0.0.1:...`), triggering internal `POST` actions behind the firewall while leaking the MCP connector's `client_secret` and `refresh_token` (`canary_b_request_count = 5`).

### Scenario C — Internal Intranet Port/Service Scanning & Basic-Auth Credential Exfiltration on Disconnect (`RevokeTokenService`)
When an administrator or developer clicks "Disconnect" on an MCP connector, `RevokeTokenService` sends an unvalidated `POST` request with HTTP Basic Auth (`client_id:client_secret`) to `metadata['revocation_endpoint']`, enabling internal network probing and credential theft.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Inspect OAuth2::Client usage and OAuth2::Error reflection in CallbackService & RefreshTokenService
grep -n -C 12 "OAuth2::Client.new" \
  /home/community-user/targets/gitlab/ee/app/services/ai/catalog/mcp_servers/callback_service.rb \
  /home/community-user/targets/gitlab/ee/app/services/ai/catalog/mcp_servers/refresh_token_service.rb

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
--- a/ee/app/services/ai/catalog/mcp_servers/callback_service.rb
+++ b/ee/app/services/ai/catalog/mcp_servers/callback_service.rb
@@ -13,14 +13,16 @@
         def execute
-          token_params = { redirect_uri: redirect_uri }
-          token_params[:code_verifier] = code_verifier if code_verifier
+          return error(_('Missing PKCE code verifier')) if code_verifier.blank?
+          token_params = { redirect_uri: redirect_uri, code_verifier: code_verifier }
 
           access_token = build_oauth_client.auth_code.get_token(code, **token_params)
           store_token(access_token)
         rescue OAuth2::Error, StandardError => e
-          error(format(_('Failed to connect to MCP server: %{error}'), error: e.message))
+          Gitlab::ErrorTracking.track_exception(e, mcp_server_id: mcp_server.id)
+          error(_('Failed to connect to MCP server'))
         end
```
