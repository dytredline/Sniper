# `Oauth::McpConnectorsAuthController`, `ConnectService` ve `Gitlab::Oauth::ClientState` İçinde Organizasyon İzolasyonu (`in_organization`), `update_ai_catalog_mcp_server` Yetkisi ve `state` Bağlaması Eksikliği (`GITLAB-CAND-06`)

[English](../14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md) | **Türkçe** | [日本語](../ja/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md) | [简体中文](../zh-CN/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md) | [한국어](../ko/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md)

## GitHub / HackerOne ve MITRE CNA Hızlı Doldurma Alanları
- **Depo (Repository):** `gitlab-org/gitlab` (`https://gitlab.com/gitlab-org/gitlab`)
- **Açık Teknik Danışma (Advisory) URL'si:** `https://github.com/dytredline/Sniper/blob/main/docs/advisories/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md`
- **Aday / İzleme Kimliği:** `GITLAB-CAND-06` (`HackerOne: gitlab | MITRE CNA-LR Submitted`)
- **Ekosistem:** `RubyGems / GitLab EE`
- **Paket Adı:** `gitlab-ee`
- **Etkilenen Sürümler:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`
- **Yamalı Sürümler:** `Yok (30.10.2026 itibarıyla upstream master üzerinde yamasız; savunma yaması aşağıda sunulmuştur)`
- **CWE:** `CWE-639 / CWE-862`
- **CVSS v3.1:** `8.1 High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **MITRE Üreticisi:** `GitLab`
- **MITRE Önerilen CVE Açıklaması:**
  > In GitLab EE through 19.6.0-pre, Oauth::McpConnectorsAuthController (ee/app/controllers/oauth/mcp_connectors_auth_controller.rb) loads Ai::Catalog::McpServer records via global Ai::Catalog::McpServer.find(params[:id]) without scoping to .in_organization(Current.organization), Ai::Catalog::McpServers::ConnectService (connect_service.rb) mutates oauth_client_id and oauth_client_secret via Dynamic Client Registration while checking only read_ai_catalog_mcp_server instead of update_ai_catalog_mcp_server, and Gitlab::Oauth::ClientState.from_state (ee/lib/gitlab/oauth/client_state.rb) discards the signed data payload when reconstructing state tokens. An authenticated low-privileged user can access or overwrite MCP server OAuth credentials across organization boundaries and replay OAuth callback states.
- **Bildiren / Araştırmacı:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — `.in_organization(Current.organization)` Olmadan Global `Ai::Catalog::McpServer.find` Çağrısı (`mcp_connectors_auth_controller.rb:19, 38, 63, 71-73`):** Denetleyici, yetki kontrolünü çağrıyı yapanın kendi organizasyonu (`Current.organization`) üzerinde yaptıktan sonra `::Ai::Catalog::McpServer.find(mcp_server_params[:id])` ile tüm veritabanında arama yapar. Böylece Organizasyon A'daki bir kullanıcı Organizasyon B'ye ait bir `McpServer` kaydına doğrudan erişebilir.
2. **Adım 2 — Yalnızca Okuma Yetkisiyle (`read_ai_catalog_mcp_server`) DCR İstemci Kimlik Bilgilerinin Üzerine Yazılması (`connect_service.rb:16-39`):** `ConnectService#execute`, `update_ai_catalog_mcp_server` yetkisini kontrol etmeden `register_oauth_client` çağırarak hedef `McpServer` kaydının `oauth_client_id` ve `oauth_client_secret` sütunlarını günceller.
3. **Adım 3 — `ClientState.from_state` İçinde `data` Bağlamasının Düşürülmesi (`client_state.rb:17-23`):** `ClientState.from_state` metodu `data:` parametresini iletmediği için HMAC doğrulaması `user_id` veya `organization_id` bağlamasını kontrol etmez.

### Zafiyetli Kod Kesiti
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

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Organizasyonlar Arası (`Cross-Org`) MCP Sunucusu DCR Kimlik Bilgisi Ele Geçirme
Organizasyon A'daki düşük yetkili bir kullanıcı, Organizasyon B'deki bir `McpServer` kimliğini hedef alarak `connect` aksiyonunu çağırır ve `oauth_client_id` / `oauth_client_secret` alanlarını kendi DCR kaydıyla ezer (`cross_org_server_mutated: true`).

### Senaryo B — Maintainer Olmayan Kullanıcının DCR Kaydını Tetiklemesi
Yalnızca okuma yetkisine (`read_ai_catalog_mcp_server`) sahip sıradan bir üye, `update_ai_catalog_mcp_server` kontrolü olmadığı için sunucu kimlik bilgilerini değiştirir.

### Senaryo C — Oturumlar Arası OAuth `state` Tekrarı (Login CSRF)
`ClientState.from_state` içinde kullanıcı ve organizasyon bağlaması doğrulanmadığı için üretilen `state` parametresi farklı bir oturumda tekrar oynatılabilir.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect unscoped McpServer.find in McpConnectorsAuthController and ConnectService
grep -n -C 8 "McpServer.find" \
  /home/community-user/targets/gitlab/ee/app/controllers/oauth/mcp_connectors_auth_controller.rb

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
