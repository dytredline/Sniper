# OAuth 2.0 Cihaz Yetkilendirme Akışında (`Oauth::DeviceAuthorizationsController` & `Oauth::TokensController`) `disable_admin_oauth_scopes`, E-Posta Doğrulama Kapısı ve Organizasyon Bakım Modu Kısıtlamalarının Atlanması (`GITLAB-CAND-02A / 02B / 02C`)

[English](../12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md) | **Türkçe** | [日本語](../ja/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md) | [简体中文](../zh-CN/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md) | [한국어](../ko/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md)

## GitHub / HackerOne ve MITRE CNA Hızlı Doldurma Alanları
- **Depo (Repository):** `gitlab-org/gitlab` (`https://gitlab.com/gitlab-org/gitlab`)
- **Açık Teknik Danışma (Advisory) URL'si:** `https://github.com/dytredline/Sniper/blob/main/docs/advisories/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md`
- **Aday / İzleme Kimliği:** `GITLAB-CAND-02 (CAND-02A + CAND-02B + CAND-02C)` (`HackerOne: gitlab | MITRE CNA-LR Submitted`)
- **Ekosistem:** `RubyGems / GitLab CE & EE`
- **Paket Adı:** `gitlab-ce / gitlab-ee`
- **Etkilenen Sürümler:** `<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`
- **Yamalı Sürümler:** `Yok (30.10.2026 itibarıyla upstream master üzerinde yamasız; savunma yaması aşağıda sunulmuştur)`
- **CWE:** `CWE-863 / CWE-285`
- **CVSS v3.1:** `8.1 High — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`
- **MITRE Üreticisi:** `GitLab`
- **MITRE Önerilen CVE Açıklaması:**
  > In GitLab CE/EE through 19.6.0-pre (and verified on live 19.5.1-ce.0), Oauth::DeviceAuthorizationsController (app/controllers/oauth/device_authorizations_controller.rb) and Oauth::TokensController (app/controllers/oauth/tokens_controller.rb) omit the verify_admin_allowed!, verify_confirmed_email!, set_current_organization, and enforce_organization_maintenance_mode before_action guards enforced by the sibling Oauth::AuthorizationsController. This allows untrusted user-created OAuth applications to mint full-privilege admin ('api' / 'admin_mode') access tokens when disable_admin_oauth_scopes is enabled (true by default), allows unconfirmed accounts (confirmed_at: nil) to mint persistent OAuth tokens, and allows OAuth device token issuance and state-changing API writes to proceed while an organization is locked in maintenance mode.
- **Bildiren / Araştırmacı:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — `verify_admin_allowed!` Eksikliği Nedeniyle Varsayılan `disable_admin_oauth_scopes` Korumasının Atlanması (`CAND-02A`, `device_authorizations_controller.rb:4-42`):** Kardeş denetleyici `Oauth::AuthorizationsController` (`authorizations_controller.rb:18, 274-296`), `before_action :verify_admin_allowed!` muhafızı ile `Gitlab::CurrentSettings.disable_admin_oauth_scopes == true` (varsayılan güvenlik ayarı) iken güvenilmeyen (`trusted: false`) OAuth uygulamalarının yöneticilere `api`, `admin_mode`, `sudo` gibi tehlikeli kapsamlarla bağlanmasını `403 Forbidden` ile engeller. Ancak `Oauth::DeviceAuthorizationsController` bu kontrolü tamamen unuttuğu için, sıradan bir kullanıcının oluşturduğu `trusted: false, device_code_enabled: true, scopes: 'api admin_mode'` uygulama `/oauth/device` üzerinden tam yetkili yönetici (`is_admin: true`) erişim jetonu üretebilir.
2. **Adım 2 — `verify_confirmed_email!` Eksikliği Nedeniyle E-Postası Doğrulanmamış Hesapların Kalıcı OAuth Token Üretmesi (`CAND-02B`, `device_authorizations_controller.rb:4-42`):** GitLab'da e-postasını henüz doğrulamamış (`confirmed_at: nil`) kullanıcılar `/oauth/authorize` üzerinde `403 unconfirmed_email` ile engellenirken, `/oauth/device/authorize` üzerinde `verify_confirmed_email!` bulunmadığı için `200 OK` ile kalıcı `access_token` ve `refresh_token` alabilir.
3. **Adım 3 — `enforce_organization_maintenance_mode` ve `device_code` Organizasyon Çözümlemesi Eksikliği (`CAND-02C`, `tokens_controller.rb:42-70`):** Bir organizasyon `migration` (`503`) veya `legal` (`403`) bakım modunda kilitlendiğinde standart OAuth akışları durdurulurken, `TokensController#organization_for_token_request` içinde `urn:ietf:params:oauth:grant-type:device_code` dalı yer almadığı için cihaz jetonu basımı ve API üzerinden depo yazma (`POST /api/v4/projects/:id/repository/commits`) işlemleri kesintisiz devam eder.

### Zafiyetli Kod Kesiti
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

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — `disable_admin_oauth_scopes=true` Aktifken Güvenilmeyen Kullanıcı Uygulamasının Tam Yetkili Admin (`api` / `admin_mode`) Jetonu Üretmesi
Sıradan bir kullanıcı `POST /oauth/applications` ile `scopes: "api admin_mode", device_code_enabled: true` ayarlı güvenilmeyen (`trusted: false`) bir uygulama oluşturur. Bir yönetici `/oauth/device` ekranında `user_code` onayladığında, `disable_admin_oauth_scopes` engeli atlanır ve `/api/v4/admin/Sidekiq_queues` dahil yönetici API'lerine erişen tam yetkili admin token üretilir.

### Senaryo B — E-Postası Doğrulanmamış (`confirmed_at: nil`) Hesabın Kalıcı API ve Refresh Token Üretmesi
E-posta doğrulamasını tamamlamamış bir hesap `/oauth/authorize` üzerinde `403 unconfirmed_email` ile reddedilirken, `/oauth/device/authorize` üzerinden `200 OK` alarak kalıcı `access_token` ve `refresh_token` elde eder.

### Senaryo C — Organizasyon Göç/Hukuki Bakım Modu (`migration` / `legal`) Sırasında Token Basımı ve Depo Yazma İşlemi
Organizasyon bakım moduna alınarak tüm standart OAuth ve web yazma işlemleri `503`/`403` ile kilitlenmişken, `grant_type=urn:ietf:params:oauth:grant-type:device_code` ile yeni token basılır ve `POST /api/v4/projects/1/repository/commits` (`201 Created`) ile depoya commit yazılır.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect missing before_action guards in DeviceAuthorizationsController vs AuthorizationsController
grep -n -C 6 "verify_admin_allowed!" \
  /home/community-user/targets/gitlab/app/controllers/oauth/authorizations_controller.rb \
  /home/community-user/targets/gitlab/app/controllers/oauth/device_authorizations_controller.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report1_cand02
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

`pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py` ile üretilen çalışma zamanı kanıtı (bkz. [`gitlab-real-world-impact-e2e-20261029.json`](../gitlab-real-world-impact-e2e-20261029.json)):

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

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
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
