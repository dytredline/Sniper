# `Projects::Integrations::SlashCommandsController#confirm` Üzerinde Doğrulanmamış `redirect_url` Açık Yönlendirmesi, Bağlamsız `response_url` ve Projeler Arası Redis `CACHE_KEY` Çarpışması (`GITLAB-CAND-04`)

[English](../18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md) | **Türkçe** | [日本語](../ja/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md) | [简体中文](../zh-CN/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md) | [한국어](../ko/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md)

## GitHub / HackerOne ve MITRE CNA Hızlı Doldurma Alanları
- **Depo (Repository):** `gitlab-org/gitlab` (`https://gitlab.com/gitlab-org/gitlab`)
- **Açık Teknik Danışma (Advisory) URL'si:** `https://github.com/dytredline/Sniper/blob/main/docs/advisories/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md`
- **Aday / İzleme Kimliği:** `GITLAB-CAND-04` (`HackerOne: gitlab | MITRE CNA-LR Submitted`)
- **Ekosistem:** `RubyGems / GitLab CE & EE`
- **Paket Adı:** `gitlab-ce / gitlab-ee`
- **Etkilenen Sürümler:** `<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`
- **Yamalı Sürümler:** `Yok (30.10.2026 itibarıyla upstream master üzerinde yamasız; savunma yaması aşağıda sunulmuştur)`
- **CWE:** `CWE-601 / CWE-863`
- **CVSS v3.1:** `5.4 Medium — CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
- **MITRE Üreticisi:** `GitLab`
- **MITRE Önerilen CVE Açıklaması:**
  > In GitLab CE/EE through 19.6.0-pre, Projects::Integrations::SlashCommandsController#confirm (app/controllers/projects/integrations/slash_commands_controller.rb:21-48) passes unvalidated request_params[:response_url] to Gitlab::SlashCommands::VerifyRequest and calls redirect_to request_params[:redirect_url] (with config.action_controller.raise_on_open_redirects = false), while Integrations::Base::SlashCommands::CACHE_KEY (app/models/concerns/integrations/base/slash_commands.rb:9) keys Redis entries solely by command_id without binding project_id or integration_id. An attacker can replay a command_id across projects to bind a victim's ChatName integration and trigger an authenticated open redirect to an arbitrary external URL.
- **Bildiren / Araştırmacı:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — `raise_on_open_redirects = false` Ayarıyla Doğrudan `redirect_to request_params[:redirect_url]` Çağrılması (`slash_commands_controller.rb:26`):** `show` aksiyonu (satır 11) yönlendirme adresini güvenli `integration_redirect_url` metodundan hesaplarken, `confirm` aksiyonu (satır 26) doğrudan kullanıcıdan gelen `request_params[:redirect_url]` parametresine `redirect_to` yapar.
2. **Adım 2 — Redis'teki `cached_params[:response_url]` Yerine `request_params[:response_url]` Kullanılması (`slash_commands_controller.rb:25`):** `VerifyRequest.new` çağrısına önbellekteki değer yerine doğrudan form/sorgu parametresi olan `request_params[:response_url]` verilir.
3. **Adım 3 — Redis `CACHE_KEY` İçinde `project_id` ve `integration_id` Bağlamasının Olmaması (`slash_commands.rb:9`):** `CACHE_KEY = "slash-command-requests:%{secret}"` yalnızca `command_id` ile anahtarlandığından, Proje B'de üretilen bir `command_id` Proje A'nın `/slash_commands/confirm` uç noktasında geçerli kabul edilir.

### Zafiyetli Kod Kesiti
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

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Slash Command Onayı Sonrası Kimlik Doğrulamalı Açık Yönlendirme (Open Redirect)
Kullanıcı güvenilir bir GitLab projesindeki slash command onay bağlantısını onayladığında, `request_params[:redirect_url]` üzerinden `302 Found` ile saldırganın kimlik avı sayfasına yönlendirilir (`open_redirect_triggered: true`).

### Senaryo B — Projeler Arası `command_id` Çarpışmasıyla `ChatName` Bağlama
Saldırgan Proje B'de ürettiği geçerli `command_id` değerini Proje A'nın onay URL'sinde kullanarak önbellek doğrulamasını geçer (`cross_project_cache_collision_accepted: true`).

### Senaryo C — `request_params[:response_url]` Manipülasyonu
Onay isteğinde gönderilen `response_url` parametresi Redis'teki orijinal değer yerine `VerifyRequest#approve!` tarafından kullanılır.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect confirm and cache_key in Projects::Integrations::SlashCommandsController
sed -n '10,48p' \
  /home/community-user/targets/gitlab/app/controllers/projects/integrations/slash_commands_controller.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report5_cand04
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

`pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py` ile üretilen çalışma zamanı kanıtı (bkz. [`gitlab-real-world-impact-e2e-20261029.json`](../gitlab-real-world-impact-e2e-20261029.json)):

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

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
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
