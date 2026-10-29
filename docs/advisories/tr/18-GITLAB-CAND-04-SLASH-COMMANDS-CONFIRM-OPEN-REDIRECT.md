# `Projects::Integrations::SlashCommandsController#confirm` Üzerinde Doğrulanmamış `redirect_url` Açık Yönlendirmesi, Bağlamsız `response_url` ve Projeler Arası Redis `CACHE_KEY` Çarpışması (`GITLAB-CAND-04`)

[English](../18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md) | **Türkçe** | [日本語](../ja/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md) | [简体中文](../zh-CN/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md) | [한국어](../ko/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md)

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

### Senaryo A — Güvenilir Şirket GitLab Onay Ekranı Üzerinden Geliştirici Şifre ve 2FA Kodu Çalma (`302 Found` Açık Yönlendirme)
Bir geliştirici Slack/Mattermost üzerinden gelen Slash komutunu onaylamak için resmi şirket GitLab bağlantısına (`https://gitlab.sirket.com/.../slash_commands/confirm?command_id=...&redirect_url=https://sahte-gitlab-sso.example/login`) tıklayıp **Onayla** düğmesine bastığı anda, GitLab `redirect_url` parametresini doğrulamadan (`raise_on_open_redirects = false`) kullanıcıyı doğrudan saldırganın sahte SSO giriş ekranına (`302 Found`) yönlendirir (`open_redirect_triggered: true`). Geliştirici resmi GitLab akışında olduğunu sanarak kurumsal şifresini ve 2FA kodunu saldırgana kaptırır.

### Senaryo B — Projeler Arası (`Project B -> Project A`) Redis Anahtarı Çarpışmasıyla Kurbanın ChatOps Hesabını Hedef Projeye Bağlama
Redis `CACHE_KEY` anahtarı `project_id` ve `integration_id` içermediği için, saldırgan kendi projesinde (`Project B`) ürettiği geçerli `command_id` değerini üretim projesinin (`Project A`) onay URL'sinde kullanır (`cross_project_cache_collision_accepted: true`) ve kurban onay verdiğinde `ChatName` kimliği hedef projeye bağlanır.

### Senaryo C — `request_params[:response_url]` Manipülasyonuyla ChatOps Onay Geri Çağrısını Saldırgan Sunucusuna Yönlendirme
`confirm` aksiyonu Redis'teki `cached_params[:response_url]` yerine istekten gelen `request_params[:response_url]` parametresini `VerifyRequest#approve!` metoduna ilettiği için, onaylanan ChatOps bildirimi orijinal Slack/Mattermost kanalı yerine saldırganın sunucusuna gönderilir.

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
