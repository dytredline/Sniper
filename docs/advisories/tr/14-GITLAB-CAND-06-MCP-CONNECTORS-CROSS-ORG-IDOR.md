# `Oauth::McpConnectorsAuthController`, `ConnectService` ve `Gitlab::Oauth::ClientState` İçinde Organizasyon İzolasyonu (`in_organization`), `update_ai_catalog_mcp_server` Yetkisi ve `state` Bağlaması Eksikliği (`GITLAB-CAND-06`)

[English](../14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md) | **Türkçe** | [日本語](../ja/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md) | [简体中文](../zh-CN/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md) | [한국어](../ko/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md)

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

### Senaryo A — Başka Bir Şirketin / Organizasyonun (`Cross-Org`) Kurumsal Yapay Zeka (MCP) Konnektörünü Ele Geçirme
Çok kiracılı (multi-organization) bir GitLab sisteminde Organizasyon A'daki saldırgan, `McpConnectorsAuthController` içinde `.in_organization(Current.organization)` kontrolü olmadığı için Organizasyon B'ye ait bir `McpServer` kimliğini hedef alır. `ConnectService` içinde yazma yetkisi (`update_ai_catalog_mcp_server`) kontrol edilmediğinden, saldırgan Dinamik İstemci Kaydı (DCR) başlatarak **kurban şirketin `oauth_client_id` ve `oauth_client_secret` kimlik bilgilerini kendi kontrolündeki OAuth bilgileriyle ezer (`cross_org_server_mutated: true`) ve kurban şirketin AI bağlantılarını ele geçirir.**

### Senaryo B — Şirket İçinde Salt-Okunur (Guest/Reporter) Kullanıcının Üretim AI Konnektör Kimlik Bilgilerini Ezmesi
Yalnızca okuma yetkisine (`read_ai_catalog_mcp_server`) sahip düşük yetkili bir kullanıcı, Maintainer yetkisi (`update_ai_catalog_mcp_server`) aranmadığı için şirketin MCP sunucusunun `oauth_client_id` / `oauth_client_secret` ayarlarını değiştirerek tüm ekibin AI entegrasyonunu kendi sahte istemcisine yönlendirir veya sabote eder.

### Senaryo C — Bağsız `ClientState` Jetonuyla Kurban Geliştiricinin GitLab Hesabını Saldırganın AI Hesabına Bağlama (Login CSRF)
`ClientState.from_state` içinde kullanıcı ve organizasyon (`data`) doğrulaması düşürüldüğü için, saldırgan kendi ürettiği OAuth `state` bağlantısını kurban geliştiriciye tıklatarak kurbanın `McpServerUserConnection` kaydını saldırganın harici MCP hesabına bağlar; kurbanın AI asistanıyla yaptığı işlemler saldırganın hesabına akar.

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
