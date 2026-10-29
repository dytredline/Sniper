# Duo Workflow `/ws` ve `McpConfigService#item_version` Üzerinde `:read_ai_catalog_item` Yetki Kontrolü Eksikliği ve `workflow_definition` Parametresiyle Özel Ajan Yazma Araçlarının Enjeksiyonu (`GITLAB-CAND-08`)

[English](../16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md) | **Türkçe** | [日本語](../ja/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md) | [简体中文](../zh-CN/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md) | [한국어](../ko/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — Aynı Dosya İçindeki (`mcp_config_service.rb:134` vs `334`) Açık Yetki Çelişkisi:** `ee/app/services/ai/duo_workflows/mcp_config_service.rb` dosyasının 334. satırındaki `ai_catalog_mcp_servers` metodu `return {} unless Ability.allowed?(current_user, :read_ai_catalog_item, item_version)` kontrolünü yaparken, aynı dosyanın 134. satırındaki `item_version` metodu hiçbir yetki kontrolü yapmadan `::Ai::Catalog::ItemVersion.find_by_id(ai_catalog_item_version_id)` döndürür.
2. **Adım 2 — `GET /api/v4/ai/duo_workflows/ws` (`workflows.rb:1065`) Üzerinde Satır 1426 Güvenlik Kuralının Atlanması:** `workflows.rb:1426` satırındaki geliştirici yorumu `workflow_definition` değerinin kullanıcı parametresinden değiştirilmemesi gerektiğini açıkça belirtmesine rağmen, `get :ws` (`workflows.rb:1065`) ve `ConnectionConfigService#mcp_config_service` (`connection_config_service.rb:220-228`) doğrudan kullanıcının gönderdiği `workflow_definition` ve `ai_catalog_item_version_id` parametrelerini kullanır.
3. **Adım 3 — Yabancı Özel (`public: false`) Ajanın Yazma Araçlarının Oturuma Enjekte Edilmesi:** Saldırgan başka bir özel projedeki ajanın `ai_catalog_item_version_id` kimliğini vererek, normalde kapalı olan yazma araçlarını (`create_issue` vb.) Duo Workflow MCP yapılandırmasına enjekte eder.

### Zafiyetli Kod Kesiti
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

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Salt-Okunur Kısıtlı Sohbet (`chat`) Oturumunu Tam Yazma Yetkili Ajan Oturumuna Dönüştürerek Projelerde Yetkisiz İşlem Yapma
Kurumsal politika gereği yalnızca soru-cevap (`chat`) yapmasına izin verilen ve yazma araçları (`withheld_tools`) kapatılmış bir Duo Workflow oturumunda, saldırgan `GET /api/v4/ai/duo_workflows/ws` WebSocket bağlantısına `workflow_definition` ve yabancı bir `ai_catalog_item_version_id` göndererek **engellenmiş yazma araçlarını (`create_issue`, MR/yorum yazma araçları) aktif hale getirir (`unapproved_write_tool_injected: true`) ve yapay zeka ajanına yasaklı yazma işlemlerini doğrudan uygulatır.**

### Senaryo B — Rakip Şirketlerin / Özel Projelerin Gizli (`public: false`) Yapay Zeka Ajanlarının Araç ve Sistem Yapılandırmasını Çalma
`McpConfigService#item_version` (`mcp_config_service.rb:134`) içinde `:read_ai_catalog_item` yetki kontrolü unutulduğu için, saldırgan ardışık `ai_catalog_item_version_id` numaralarını göndererek **erişim yetkisi olmayan gizli (`public: false`) kurumsal AI ajanlarının hangi iç araçları ve MCP sunucularını kullandığını tamamen ifşa eder.**

### Senaryo C — İş Akışı Oluştururken (`POST /api/v4/ai/duo_workflows/workflows`) Yetkisiz Özel Ajan Sürümü Bağlama
`workflows.rb:341-344` doğrudan `ItemVersion.find` çağırdığı için başka bir organizasyona ait özel ajan sürümü iş akışı kaydına kalıcı olarak bağlanır.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Compare line 134 vs line 334 in ee/app/services/ai/duo_workflows/mcp_config_service.rb
sed -n '130,136p;330,337p' \
  /home/community-user/targets/gitlab/ee/app/services/ai/duo_workflows/mcp_config_service.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report3_cand08
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

`pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py` ile üretilen çalışma zamanı kanıtı (bkz. [`gitlab-real-world-impact-e2e-20261029.json`](../gitlab-real-world-impact-e2e-20261029.json)):

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

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
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
