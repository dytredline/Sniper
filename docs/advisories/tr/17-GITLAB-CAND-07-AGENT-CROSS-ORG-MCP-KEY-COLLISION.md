# AI Catalog Agent Üzerinde Organizasyon Kapsamsız `McpServer` GID Bağlama ve `McpConfigService#execute` Yerleşik `:gitlab` Anahtar Çarpışmasıyla Workhorse `withheld_server_tools` (`allToolsAvailable = true`) Kısıtlamasının Aşılması (`GITLAB-CAND-07`)

[English](../17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md) | **Türkçe** | [日本語](../ja/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md) | [简体中文](../zh-CN/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md) | [한국어](../ko/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — `McpConfigService#execute` İçinde `.except(:orbit)` Kullanılıp `:gitlab` Anahtarının Unutulması (`mcp_config_service.rb:59-63`):** `McpConfigService#execute`, `gitlab_mcp_server(denied).merge(orbit_mcp_server).merge(ai_catalog_mcp_servers.except(:orbit))` çağrısıyla MCP yapılandırmasını oluşturur. Geliştirici `:orbit` anahtarını ezilmeye karşı korurken `:gitlab` anahtarını (`.except(:gitlab, :orbit, :slack)`) unutmuştur. Bu nedenle adı `"GitLab"` (`server_key => :gitlab`) olan bir `Ai::Catalog::McpServer` kaydı, yerleşik `:gitlab` yapılandırmasını ve `:Tools` izin listesini tamamen ezer.
2. **Adım 2 — Workhorse İçinde `s.cfg.Tools == nil` Nedeniyle `allToolsAvailable = true` Olması (`mcp.go:210, 254`):** Katalog MCP sunucuları `:Tools` anahtarı içermediği (`nil`) için, Workhorse `serverName == "gitlab"` olduğunda yine dahili `/api/v4/mcp` uç noktasına bağlanır ancak `mcp.go:254` satırında `allToolsAvailable := s.cfg.Tools == nil` (`true`) hesaplayarak `withheld_server_tools(denied)` araç yasağını tamamen devre dışı bırakır.
3. **Adım 3 — Organizasyon Kapsamsız (`in_organization` Eksik) `McpServer` GID Bağlama (`list_service.rb:14-24`):** `Agent::Create`, `Agent::Update` ve `ListService`, `McpServer` kimliklerini `.in_organization` kontrolü yapmadan çözer.

### Zafiyetli Kod Kesiti
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

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — `"GitLab"` Adlı Katalog Sunucusuyla Tüm Yerleşik GitLab AI Güvenlik Kısıtlamalarını (`withheld_server_tools`) Sıfırlama (`allToolsAvailable = true`)
GitLab Duo Workflow, yerleşik `:gitlab` MCP sunucusunda tehlikeli araçları `withheld_server_tools(denied)` listesiyle engeller. Ancak `McpConfigService#execute` yalnızca `.except(:orbit)` kullanıp `:gitlab` anahtarını korumadığı için, saldırgan `"GitLab"` adında (`server_key => :gitlab`, `Tools: nil`) bir katalog sunucusu bağladığında yerleşik `:gitlab` kaydının üzerine yazılır. Workhorse (`mcp.go:254`) `Tools == nil` gördüğü için **`allToolsAvailable = true` yapar ve yerleşik GitLab MCP sunucusundaki TÜM araç kısıtlamalarını kaldırarak yasaklı araçların tamamını kullanıma açar (`workhorse_all_tools_available: true`).**

### Senaryo B — GraphQL `aiCatalogAgentCreate` / `Update` İle Başka Organizasyonun Özel `McpServer` Sunucularını Kendi Ajanına Bağlama
`ListService` ve GraphQL mutasyonlarında `.in_organization` kontrolü olmadığı için saldırgan başka bir organizasyona ait `gid://gitlab/Ai::Catalog::McpServer/<ID>` kaydını kendi ajanına bağlayarak organizasyon izolasyonunu deler.

### Senaryo C — Yerleşik `:gitlab` Kimlik Başlıklarını (`X-Gitlab-Oauth-Token`) Ezerek Tüm Duo Workflow Hizmetini Çökertme (`401` DoS)
Çarpışan `:gitlab` kaydı `X-Gitlab-Oauth-Token` başlığını `{}` ile ezdiği için yerleşik `/api/v4/mcp` çağrılarının tamamı `401 Unauthorized` hatasıyla çöker.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect .except(:orbit) in McpConfigService and allToolsAvailable in Workhorse mcp.go
grep -n -C 5 "except(:orbit)" /home/community-user/targets/gitlab/ee/app/services/ai/duo_workflows/mcp_config_service.rb
grep -n -C 5 "allToolsAvailable :=" /home/community-user/targets/gitlab/workhorse/internal/ai_assist/duoworkflow/mcp.go

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report4_cand07
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

`pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py` ile üretilen çalışma zamanı kanıtı (bkz. [`gitlab-real-world-impact-e2e-20261029.json`](../gitlab-real-world-impact-e2e-20261029.json)):

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

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
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
