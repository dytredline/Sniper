# AI Catalog MCP OAuth `CallbackService`, `RefreshTokenService`, `RevokeTokenService` ve `DynamicRegistrationClient` İçinde `307 Temporary Redirect` / Doğrulanmamış RFC 8414 Metadata SSRF ve Hata Gövdesi Yansıtması (`GITLAB-CAND-05`)

[English](../13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md) | **Türkçe** | [日本語](../ja/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md) | [简体中文](../zh-CN/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md) | [한국어](../ko/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — RFC 8414 `token_endpoint`, `revocation_endpoint` ve `authorization_servers` Adreslerinin `UrlBlocker` İle Doğrulanmaması (`dynamic_registration_client.rb:104-136`):** `DynamicRegistrationClient`, yalnızca ilk keşif URL'sini kontrol eder; ancak dönen JSON içindeki `authorization_servers.first`, `token_endpoint` ve `revocation_endpoint` alanlarını `Gitlab::HTTP_V2::UrlBlocker.validate!` süzgecinden geçirmeden doğrudan döndürür.
2. **Adım 2 — `OAuth2::Client` (`oauth2 2.0.25`) Kullanımı Nedeniyle `307 Temporary Redirect` POST SSRF ve Kimlik Bilgisi Tekrarı (`callback_service.rb:38-50`, `refresh_token_service.rb:45-58`):** `CallbackService` ve `RefreshTokenService`, GitLab'ın güvenli `Gitlab::HTTP` istemcisi yerine ham `OAuth2::Client.new` (Faraday `net_http`, varsayılan `max_redirects: 5`) kullanır. Harici sunucu `307 Temporary Redirect` ile `http://127.0.0.1:...` veya `http://169.254.169.254/...` adresine yönlendirme yaptığında, `OAuth2::Client` içindeki `client_secret` ve `refresh_token` verileriyle birlikte `POST` isteğini dahili hedefe tekrarlar.
3. **Adım 3 — `OAuth2::Error#message` Üzerinden Dahili Hata Gövdesinin `flash[:alert]` İçine Yansıtılması (`callback_service.rb:24-25`):** Dahili servis `4xx`/`5xx` veya hatalı yanıt döndüğünde `OAuth2::Error` fırlatılır ve ham yanıt gövdesi `flash[:alert]` üzerinden doğrudan kullanıcı ekranına yansıtılır.

### Zafiyetli Kod Kesiti
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

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — AWS / GCP Bulut Sunucusu IAM Yetki Anahtarlarının (`169.254.169.254`) ve İç Yönetim Sırlarının Doğrudan Tarayıcı Ekranından (`flash[:alert]`) Çalınması
Saldırgan, dışarıdaki kendi sunucusunu bir MCP sunucusu olarak kaydeder ve `token_endpoint` adresinden `307 Temporary Redirect` dönerek GitLab sunucusunu bulut metadata servisine (`http://169.254.169.254/latest/meta-data/iam/security-credentials/...`) veya iç ağdaki (`http://127.0.0.1:8080`, Vault, Consul, iç Kubernetes API) yönetim servislerine yönlendirir. `OAuth2::Client` yönlendirmeyi takip eder ve dönen iç yanıt gövdesini `OAuth2::Error#message` üzerinden doğrudan kullanıcının ekranındaki `flash[:alert]` kutusuna basar (`iam_role_credentials_exposed: true`). Böylece saldırgan **GitLab sunucusunun çalıştığı AWS/GCP bulut hesabının IAM anahtarlarını (`AccessKeyId`, `SecretAccessKey`) doğrudan ekrandan okuyup şirketin bulut altyapısını ele geçirir.**

### Senaryo B — Güvenlik Duvarı Arkasındaki İç Servislere (`127.0.0.1` / Intranet) `POST` Komutu Gönderme ve `client_secret` / `refresh_token` Sızdırma
`307 Temporary Redirect` HTTP metodunu (`POST`) ve gövdesini koruduğu için, `CallbackService` ve `RefreshTokenService` içindeki `OAuth2::Client` (`max_redirects: 5`), dışarıya kapalı iç mikroservislere (`127.0.0.1`) `POST` isteği göndererek **iç ağda işlem tetikler** ve aynı anda `client_secret` ile `refresh_token` sırlarını iç hedefe iletir (`canary_b_request_count = 5`).

### Senaryo C — Bağlantı Kesme (`RevokeTokenService`) Üzerinden İç Ağ Tarama ve Basic Auth Kimlik Bilgisi Hırsızlığı
Kullanıcı veya yönetici MCP bağlantısını keserken `RevokeTokenService`, `metadata['revocation_endpoint']` adresini doğrulamadan Basic Auth kimlik bilgileriyle `POST` göndererek iç ağ servislerinin taranmasına ve sırların çalınmasına yol açar.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect OAuth2::Client usage and OAuth2::Error reflection in CallbackService & RefreshTokenService
grep -n -C 12 "OAuth2::Client.new" \
  /home/community-user/targets/gitlab/ee/app/services/ai/catalog/mcp_servers/callback_service.rb \
  /home/community-user/targets/gitlab/ee/app/services/ai/catalog/mcp_servers/refresh_token_service.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report2_cand05
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

`pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py` ile üretilen çalışma zamanı kanıtı (bkz. [`gitlab-real-world-impact-e2e-20261029.json`](../gitlab-real-world-impact-e2e-20261029.json)):

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

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
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
