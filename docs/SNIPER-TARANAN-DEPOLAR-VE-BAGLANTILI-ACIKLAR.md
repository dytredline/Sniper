# Gökçe Baran Karakamış — Sniper macOS Kurulum Doğrulaması, Taranan Depolar ve Muhtemel Bağlantılı Açıklar

**Yazar / Güvenlik Araştırmacısı:** **Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline))

Bu teknik rapor iki ana bölümden oluşmaktadır:
1. **macOS (Apple Silicon) Gerçek Donanım Kurulum ve Çalışma Doğrulama Raporu:** Sniper Community'nin gerçek macOS donanımı üzerinde hem **yerel kaynak kurulumu (`--core-only`)** hem de **Docker Desktop beş motorlu (`community-tools`)** kurulumu ile uçtan uca test ve doğrulama sonuçları.
2. **Sniper ile Taranan 8 Açık Kaynak Depo ve Kanıt Denetimi:** **Gökçe Baran Karakamış** tarafından **Sniper** statik analiz (SAST), altyapı (IaC) ve bağımlılık (SCA) denetim motoru ile taranan **8 açık kaynak deponun** kaynak kodu düzeyinde incelenmesi, yanlış pozitif ayrımı, tek başına kritiklik düzeyi ve saldırı zinciri (*chaining*) analizi.

---

## Bölüm I — macOS (Apple Silicon) Gerçek Donanım Kurulum ve Doğrulama Raporu (2026-10-24)

macOS (Apple Silicon) üzerinde Sniper kurulumu **deneysel değildir**; hem **yerel kaynak kurulumu (`--core-only`)** hem de **Docker Desktop beş motorlu kurulumu** gerçek macOS donanımı üzerinde test edilmiş, doğrulanmış ve desteklenmektedir:

| Kurulum Yolu | Komut | Gerçek macOS Donanımında Doğrulanan Kapsam | Durum |
| :--- | :--- | :--- | :---: |
| **1. Yerel macOS Kaynak Kurulumu (Native Source Setup)** | `python3 scripts/setup-community --core-only` | `.venv` (CPython 3.12) oluşturma, kilitli çalışma zamanı paketlerinin (`requirements-runtime.lock` + `pip check`) kurulumu, `scripts/sniper-mcp --help`, `scripts/sniper-project-audit --help`, `cli_reports.py --help`, yerel loopback web arayüzü (`127.0.0.1:8787`), yerel SQLite veri dizini başlatma ve örnek proje üzerinde gerçek yerel SAST/veri akışı denetimi (`audit_id: prj_162d09c47587`, `baseline_id: prj_497a1c478d97` — `app.py:4` üzerinde `[critical] Doğrulanmış veri akışı: istek girdisi SQL sorgusuna ulaşıyor (SQL enjeksiyonu)` tespiti ve bildirim kaydı). | **DOĞRULANDI VE DESTEKLENİYOR** |
| **2. macOS Apple Silicon + Docker Desktop Beş Motorlu Kurulum** | `./scripts/deploy-community-tools --accept-third-party-licenses` | SHA-256 özet kilitli 5 yerel motorun (**Nuclei 3.11.1**, **Trivy 0.75.0**, **Gitleaks 8.30.1**, **TruffleHog 3.99.0**, **Opengrep 1.30.1**) çalışma zamanı hazırlık kontrolleri (`precheck_passed`), Türkçe/çok dilli web arayüzü, `./scripts/import-community-project` ile kalıcı proje hacmine (`sniper_projects`) aktarım, 5 motorun tamamında yerel duman testleri ve tam test paketi (**2.826 unittest: 0 hata; 203 pytest geçti; 432 Node testi geçti**). | **DOĞRULANDI VE DESTEKLENİYOR** |

Ayrıntılı İngilizce doğrulama kayıtları için [VALIDATION.md](../VALIDATION.md) ve platform kurulum rehberi için [DEPLOYMENT.md](../DEPLOYMENT.md) belgelerine bakabilirsiniz.

---

## Bölüm II — Sniper ile Taranan 8 Açık Kaynak Depo ve Muhtemel Bağlantılı Açıklar

Her depo için bulgular **(A) Doğrulanmış Tehlikeli Primitive / Sertleştirme Açığı**, **(B) Bağlama/Koşula Bağlı Bulgu ve Bağımlılık (SCA) Kayıtları** ve **(C) Kesin Yanlış Pozitif (Yanlış Alarm)** olarak ayrıştırılmış; her bulgunun **nelere yol açabileceği**, **tek başına kritiklik düzeyi** ve **diğer bulgularla birleşip birleşmediği (muhtemel bağlantılı açıklar / saldırı zinciri / *chaining*)** ortaya konulmuştur.

> **Önemli Metodoloji ve Sorumlu Bildirim Notu:** Statik analizde tehlikeli bir fonksiyonun (`exec`, `pickle.loads`, `subprocess.Popen`) veya CI/CD deseninin varlığı tek başına doğrulanmış bir ürün CVE'si anlamına gelmez. Bir bulgunun istismar edilebilir açık sayılması için varsayılan/desteklenen dağıtımda **erişilebilirlik**, **güven sınırı (trust boundary) aşımı** ve **saldırgan önkoşulları** birlikte kanıtlanmalıdır. Koordine güvenlik bildirimi (Coordinated Vulnerability Disclosure / CVE-GHSA) süreci devam eden projelere ait bulgular, sorumlu bildirim ilkeleri gereği yamalar yayınlanana kadar bu halka açık listede paylaşılmamaktadır.

---

## 1. AutoGPT (`autogpt`)
* **SAST/IaC/SCA Özeti:** Politika eşiğini aşan `93` bulgu (`2 kritik, 39 yüksek, 34 orta, 16 düşük, 2 bilgi`); toplam `142` triyaj kaydı (`3 likely_false, 139 uncertain`).

### A. Doğrulanmış Sertleştirme ve Yapılandırma Bulguları
1. **Docker Compose Test/Yerel Ortam Dosyalarında Sabit Sırlar (`CWE-798`):**
   * `autogpt_platform/backend/docker-compose.test.yaml:85` (`RABBITMQ_DEFAULT_PASS`), `docker-compose.journeys.yml:22,29` ve `docker-compose.yml:161`.
2. **Konteyner Güvenlik Sertleştirmesi Eksiklikleri (`CWE-250`, `CWE-1104`):**
   * `autogpt_platform/backend/Dockerfile:1`: Ayrıcalıksız `USER` tanımı olmaması (root olarak çalışma) ve `docker-compose.platform.yml:148` / `docker-compose.yml:121` üzerinde `:latest` imaj etiketleri.

### B. Bağlama Bağlı / İkincil Zincir Bulguları
1. **Veritabanından `pickle.loads` ile Zamanlayıcı Durumu Çözme (`CWE-502`):**
   * `autogpt_platform/backend/backend/executor/jobstore_backfill.py:99`: APScheduler'ın `apscheduler_jobs.job_state` sütunundaki ikili (binary) veriyi `pickle.loads(row.job_state)` ile belleğe yükler.
2. **Sözleşme Sapması (OpenAPI vs Kod):**
   * `autogpt_platform/frontend/src/app/api/openapi.json:3589` ve `backend/api/features/chat/share.py:170,186`: Paylaşılan sohbet uç noktaları (`/{share_token}`) kasıtlı olarak halka açıktır (`public_router`), ancak OpenAPI şemasıyla senkronize değildir.

### C. Kesin Yanlış Pozitifler (`Yanlış Alarm`)
1. **2 Kritiğin İkisi de Yanlış Pozitif (`obj.execute` SQLi Sanılmış):**
   * `autogpt_platform/backend/backend/api/external/v1/routes.py:131` ve `autogpt_platform/backend/backend/api/features/blocks/routes.py:151` — `obj.execute(data, ...)` SQL sorgusu değil, AutoGPT `Block` sınıfının Python metodudur.
2. **JWT Doğrulama Alarmları (`jwt.get_unverified_header`):**
   * `autogpt_platform/autogpt_libs/autogpt_libs/auth/jwt_utils.py:96`, `backend/integrations/webhooks/step_webhooks/service.py:57` ve `backend/copilot/bot/adapters/teams/auth.py:100` — Üçü de `alg` alanını katı izin listesine (`RS256`) karşı doğrulayıp `jwt.decode()` ile tam imza kontrolü yapıyor.
3. **Sözde "Korumasız Rota" Alarmları:**
   * `codex.py:48,70`, `integrations/router.py:942` ve `orgs/team_routes.py:102,168,224,246` — Hepsinde FastAPI `Security(get_user_id)` veya `Security(get_request_context)` + `_authorize_team_management` yetki kontrolü mevcut.
4. **Sözde Sır ve Günlükleme Alarmları:**
   * `autogpt_platform/backend/backend/copilot/tools/ayrshare_managed.py:44` (`NO_API_KEY` İngilizce açıklama metni), `autogpt_platform/single-container/Dockerfile:29` (`BETTER_AUTH_SECRET=build-only-placeholder-not-used-at-runtime`), `oauth.py:452` ve `token_tracking.py:193` (loglara token değeri değil, harcanan LLM kelime/token sayısı `prompt_tokens` yazılıyor).

### Tek Başına ve Birlikte Kritiklik / Birleşme (Chaining) Analizi
* **Tek Başına Kritiklik:** **Düşük / Orta.** Raporlanan 2 kritik SQLi tamamen yanlış pozitiftir; doğrulanmış bir dış RCE/SQLi açığı yoktur.
* **Birleşiyor mu? (Koşullu Saldırı Hipotezi — Birlikte Kritiklik: ORTA / YÜKSEK [Yalnızca DB Yazma Erişimi Varsa]):**
  * `jobstore_backfill.py:99` içindeki `pickle.loads` doğrudan dış kullanıcı girdisi almaz. Yalnızca saldırganın veritabanındaki `apscheduler_jobs` tablosuna yazma erişimi elde ettiği bir senaryoda (örneğin varsayılan compose parolalarının iç ağa açık bırakılması veya ayrı bir DB sızıntısı), `job_state` sütununa yazılan pickle verisi `root` konteyner içinde kod çalıştırmaya dönüşebilir.

---

## 2. Zitadel (`zitadel`)
* **SAST/IaC/SCA Özeti:** Politika eşiğini aşan `67` bulgu (`8 kritik, 42 yüksek, 5 orta, 11 düşük, 1 bilgi`); toplam `286` triyaj kaydı (`3 likely_true, 283 uncertain`).

### A. Doğrulanmış Sertleştirme ve Örnek Dağıtım Bulguları
1. **Örnek Compose Dosyalarında Docker Soket Bağlama (`docker.sock`):**
   * `deploy/compose/` altındaki üç compose varyantında `/var/run/docker.sock` bağlaması bulunmaktadır (tek bir kök nedenin üç varyantta tekrarı).
2. **Dokümantasyon Ters Vekil Örneğinde `NODE_TLS_REJECT_UNAUTHORIZED=0` ve Başlangıç Yoklaması:**
   * `apps/docs/content/self-hosting/manage/reverseproxy/docker-compose.yaml:154` içinde `NODE_TLS_REJECT_UNAUTHORIZED=0` tanımlıdır (dokümantasyon örneği; `deploy/compose/` dosyalarından ayrıdır).
   * `apps/login/scripts/server.mjs:45`: `pollReady()` yerel başlangıç sağlık kontrolünde `rejectUnauthorized: false` kullanılıyor.

### B. Bağlama Bağlı Bulgular
* **İsteğe Bağlı Şifresiz OpenTelemetry (OTLP) gRPC/HTTP İhracı (`CWE-319`):**
   * `logger.go:94,110`, `metric.go:269,290` ve `tracing.go:214,230`: Yalnızca yönetici yapılandırmada `cfg.Insecure = true` seçerse `WithInsecure()` etkinleşir.

### C. Kesin Yanlış Pozitifler (`Yanlış Alarm`)
1. **8 Kritiğin Tamamı Yanlış Pozitif:**
   * `backend/v3/storage/database/dialect/postgres/conn.go:46`, `pool.go:54`, `tx.go:59`: `pgx` veritabanı sürücüsünün parametreli `QueryRow(ctx, sql, args...)` sarmalayıcılarıdır. HTTP log ara katmanındaki `r.Method` değeri genel `Info()`/`Add()` metot isimleri üzerinden yanlışlıkla buraya bağlanmıştır.
   * `cmd/initialise/helper.go:12` ve `cmd/initialise/verify_database.go:79`: Başlangıç veritabanı kurulumundaki `exec(ctx, db, ...)` SQL yardımcı fonksiyonudur; dinamik kod çalıştırma (`eval`/`exec`) değildir.
2. **Yüksek Önemli "SQL Sorgusunda Veri Birleştirme" Alarmları:**
   * `internal/api/grpc/user/query.go:125`, `v2/convert/user.go:169,175,181` ve `intent_test.go:296`: Protobuf arama nesnelerini (`AndQuery`, `OrQuery`, `NotQuery`) iç sorgu yapılarına dönüştüren Go fonksiyonlarıdır; ortada SQL string birleştirme yoktur (`intent_test.go:296`'da ise `authUrl.Scheme+"://"+authUrl.Host` URL birleştirmesi SQL sanılmıştır).
3. **Test Dosyalarındaki Sabit Parola Test Verileri:** `password-complexity.test.tsx`, `validators.test.ts`, `password_test.go` içindeki parola karmaşıklığı birim testi dizgileridir.

### Tek Başına ve Birlikte Kritiklik / Birleşme (Chaining) Analizi
* **Tek Başına Kritiklik:** **Düşük / Orta.** Zitadel çekirdek Go/TypeScript kodunda istismar edilebilir SQLi veya RCE yoktur.
* **Birleşiyor mu?** `docker.sock` bağlaması (`deploy/compose/`) ile `NODE_TLS_REJECT_UNAUTHORIZED=0` (`apps/docs/.../reverseproxy/docker-compose.yaml`) **farklı compose örneklerindedir**; dolayısıyla varsayılan olarak tek bir dosyada birleşmezler. Ancak bir operatör kendi üretim ortamında bu örnekleri birleştirerek `docker.sock` bağlarsa, konteyner ele geçirildiğinde konak makinede root yetkisine yükselme riski doğar.

---

## 3. Nextcloud MCP Server (`nextcloud-mcp-v0.201.0-8064f66`)
* **SAST/IaC/SCA Özeti:** Politika eşiğini aşan `59` bulgu (`SAST: 1 kritik, 6 yüksek, 36 orta, 2 düşük` · `IaC: 7 yüksek, 1 bilgi` · `SCA: 5 kritik, 40 yüksek, 30 orta`).

### A. Doğrulanmış Sertleştirme Bulguları
1. **CI/CD `.github/workflows/pact.yml:93` Dal Adı Kabuk İnterpolasyonu (`CWE-78` — Aynı-Repo Sınırlı Sertleştirme):**
   * `.github/workflows/pact.yml:93` satırında `--branch "${{ github.head_ref || github.ref_name }}"` doğrudan `run:` kabuk betiğine yazılmıştır.
   * **Kanıt Denetimi Düzeltmesi:** İş akışı `pull_request_target` **kullanmamaktadır** (tetikleyici `pull_request` ve `push`'tur) ve `satır 35` ile `102`'de `if: ${{ github.event_name == 'push' || github.event.pull_request.head.repo.full_name == github.repository }}` kontrolü bulunduğu için **dış çatal (fork) PR'larda çalışmaz**. Dolayısıyla dış saldırganın fork PR üzerinden sır çalma zinciri yoktur; yalnızca depo içi dal adları için kabuk sertleştirmesi konusudur.

### B. Bağlama Bağlı Bulgular ve SCA Kayıtları
* **Test/Geliştirme Ortamı Sabit Sırları:** `docker-compose.yml` ve `app-hooks/post-installation/15-setup-keycloak-provider.sh` / `scripts/provision-greenmail-account.sh` yerel test/geliştirme ortamı kurulum betikleridir.
* **SCA Bağımlılık Kayıtları (`uv.lock`):** `pillow 11.3.0`, `pyjwt 2.13.0`, `certifi 2026.6.17`, `cryptography 49.0.0`, `fsspec 2026.4.0` kayıtları.

### C. Kesin Yanlış Pozitifler (`Yanlış Alarm`)
1. **Login Flow v2 `poll.endpoint` SSRF Alarmı (`login_flow.py:192` — Uçtan Uca Çağrı Zinciriyle Yanlış Pozitif Olduğu Kanıtlandı):**
   * `nextcloud_mcp_server/auth/login_flow.py:173-195` içindeki `poll(self, poll_endpoint: str, poll_token: str)` metodunun tüm depodaki tek çağrıcıları `provision_routes.py:102` (`_poll_and_store`) ve `server/auth_tools.py:304` (`nc_auth_check_status`) fonksiyonlarıdır.
   * Her iki çağrıcı da `poll_endpoint` değerini dış kullanıcı girdisinden değil, `flow_client.initiate()` çıktısından (`login_flow.py:125-151`) alır.
   * `initiate()` metodu ise `login_flow.py:130` satırında **`poll_endpoint = self._rewrite_to_nextcloud_host(raw_poll_endpoint)`** çağrısıyla URL'nin `scheme` ve `netloc` (`host:port`) alanlarını sunucu yapılandırmasındaki sabit `self.nextcloud_host` ile **zorla üzerine yazmaktadır** (`rewrite_url_origin`). Dolayısıyla `poll()` metodunun başka bir sunucuya/iç IP'ye SSRF isteği göndermesi imkansızdır.
2. **JWT İmza Doğrulaması Alarmı (`token_utils.py:178`):** `nextcloud_mcp_server/auth/token_utils.py:178-205` — `jwt.get_unverified_header(id_token)` yalnızca JWKS anahtar kümesinden `kid` seçmek için kullanılmakta, hemen ardından OIDC algoritma izin listesiyle tam imza doğrulaması yapılmaktadır.

### Tek Başına ve Birlikte Kritiklik / Birleşme (Chaining) Analizi
* **Tek Başına ve Birlikte Kritiklik:** **Düşük (Sertleştirme).** Hem `pact.yml` dış fork'lara kapalıdır hem de `login_flow.py:192` `initiate()` aşamasında `self.nextcloud_host` origin'ine sabitlendiği için SSRF oluşturmaz. Depoda birleşen veya dışarıdan istismar edilebilen bir SAST açığı yoktur.

---

## 4. MCPJam Inspector (`mcpjam-inspector-v3.9.2-eda1fd1`)
* **SAST/IaC/SCA Özeti:** Politika eşiğini aşan `122` bulgu (`SAST: 12 kritik, 8 yüksek, 74 orta, 6 düşük` · `IaC: 2 orta, 3 bilgi` · `SCA: 6 kritik, 96 yüksek, 197 orta, 40 düşük`).

### A. Doğrulanmış Sertleştirme Bulguları
1. **CI/CD `.github/workflows/pr-preview.yml:116` Dal Adı Kabuk İnterpolasyonu (`Aynı-Repo Sınırlı`):**
   * `.github/workflows/pr-preview.yml:116` satırında `echo "branch=${{ github.event.pull_request.head.ref }}" >> "$GITHUB_OUTPUT"` doğrudan kabuk içinde çalıştırılmaktadır.
   * **Kanıt Denetimi Düzeltmesi:** `pr-preview.yml` içinde `pull_request_target` **yoktur** (tetikleyici `pull_request` ve `repository_dispatch`'tir) ve `satır 65-69`'da `github.event.pull_request.head.repo.full_name == github.repository` ile `dependabot[bot]` dışlaması mevcuttur. Yani dış çatal (fork) PR'lar bu işi tetikleyemez; yalnızca aynı depoda dal açma yetkisi olan kullanıcılar için geçerli bir kabuk sertleştirmesidir.

### B. Bağlama Bağlı Bulgular ve SCA Kayıtları
* **`dependabot-auto-merge.yml:25` (`pull_request_target`):** `.github/workflows/dependabot-auto-merge.yml:15-40` dosyasında `pull_request_target` kullanılmaktadır; ancak dosya içindeki açık güvenlik yorumunda da belirtildiği üzere **hiçbir `actions/checkout` adımı yoktur** ve `if: github.event.pull_request.user.login == 'dependabot[bot]'` ile sınırlandırılmıştır.
* **SCA Bağımlılık Kayıtları (`package-lock.json`):** `handlebars 4.7.9`, `shell-quote 1.10.0`, `tinypool 1.1.1`, `@modelcontextprotocol/sdk` kayıtları.

### C. Kesin Yanlış Pozitifler (`Yanlış Alarm — 20 Kritik/Yüksek SAST Bulgusunun 18'i`)
1. **Yorum Satırlarındaki `eval (` ve `exec (` Kelimeleri (11 Kritik + 3 Yüksek Yanlış Alarm):**
   * `mcpjam-inspector/client/src/lib/webmcp/groups/swarms.ts:22`, `evals-runner.ts:4261,6501`, `drive-hosted-eval-turn.ts:497,777,867`, `step-executor.ts:367`, `mcp-app-browser-harness.ts:1010`, `sandbox-proxy-csp.ts:7` ve `seed-host-template.ts:645,902` konumlarındaki **11 kritik `Dinamik kod çalıştırma`** uyarısının tamamı çalışan kod değil, İngilizce JSDoc/yorum satırlarında geçen `"eval ("` veya `"eval()"` ifadeleridir (ör. `// Browser-rendered MCP App eval (PR 14):`).
   * `mcpjam-inspector/server/routes/web/computers.ts:16` (`* POST /exec (bearer)`), `e2b-sandbox-provider.ts:15` (`* exec (run) / spawn`) ve `materialize-skill-files.ts:37` (`* binary write + exec (for stale-file prune)`) konumlarındaki **3 yüksek `Kabuk üzerinden komut çalıştırma`** uyarısı da JSDoc yorum satırıdır.
2. **Üretilmiş `.d.ts` Tip Dosyası (2 Yüksek Yanlış Alarm):** `mcp/worker-configuration.d.ts:3072,11962` — Cloudflare Wrangler tarafından üretilmiş TypeScript arayüz tanımıdır, çalışan kod değildir.
3. **Arayüz Etiket Metni ve UI Dizgi Birleştirmesi (2 Yüksek Yanlış Alarm):** `ServerUrlChangeHistory.tsx:60` (`client_secret: "OAuth client secret"` arayüz etiketi) ve `useToolExecution.ts:571` (istemci tarafı UI dizgi birleştirmesi; SQL sorgusu değildir).

### Tek Başına ve Birlikte Kritiklik / Birleşme (Chaining) Analizi
* **Tek Başına ve Birlikte Kritiklik:** **Düşük / Orta (Sertleştirme).** 20 kritik/yüksek SAST bulgusunun 18'i kesin yanlış pozitiftir; kalan 2 CI iş akışı bulgusu ise dış fork'ları engellediği ve PR kodunu checkout etmediği için dış saldırganın tetikleyebileceği bir CI/CD sır çalma zinciri oluşturmaz.

---

## 5. Codebase Memory MCP (`codebase-memory-mcp-v0.9.0-b637e33`)
* **SAST/IaC/SCA Özeti:** Politika eşiğini aşan `32` bulgu (`SAST: 17 kritik, 7 yüksek, 88 orta, 9 düşük` · `IaC: 5 orta, 1 düşük, 5 bilgi` · `SCA: 8 yüksek, 10 orta, 1 düşük`).

### A. Doğrulanmış Yerel Servis Tasarım Sınırı
1. **Yerel UI Dizin Gezinme Uç Noktası (`GET /api/browse?path=...`):**
   * `src/ui/http_server.c:668-730`: `--ui` modunda çalışan yerel sunucu (`127.0.0.1`), grafik arayüzündeki klasör seçici (file picker) için verilen `path` parametresindeki alt dizin adlarını listeler.
   * **Kanıt Denetimi Düzeltmesi (CORS & DNS Rebinding Koruması):** `src/ui/http_server.c:78-93` içindeki `update_cors()` fonksiyonu **`Access-Control-Allow-Origin: *` KULLANMAMAKTADIR**. Yalnızca `http://localhost:*` ve `http://127.0.0.1:*` origin'lerini yansıtır; yabancı web sitelerinden gelen çapraz kökenli isteklere CORS başlığı dönmez ve `Host` başlığını `localhost`/`127.0.0.1`/`::1` ile sınırlandırarak yabancı host/DNS-rebinding isteklerini `403` ile reddeder. Dolayısıyla uzaktaki bir web sitesinden CORS üzerinden yerel kaynak kod sızıntısı zinciri **geçersizdir**.

### B. Bağlama Bağlı Bulgular ve Vendored Kod Uyarıları
* **Vendored C Kütüphaneleri ve Gramerler:** `vendored/yyjson`, `vendored/tre`, `internal/cbm/vendored/grammars/*` ve Windows uyumluluk katmanı (`src/foundation/compat.c:84,109`) içindeki klasik C `strcpy` uyarıları.
* **SCA Kayıtları (`graph-ui/package-lock.json`):** `nanoid`, `postcss`, `browserslist` geliştirme/önyüz paket uyarıları.

### C. Kesin Yanlış Pozitifler (`Yanlış Alarm`)
1. **Kritik SQL Enjeksiyonu Alarmı (`src/store/store.c:2864`):** `src/store/store.c:2845-2877` incelendiğinde, `snprintf` ile kurulan özyinelemeli BFS sorgusunda `start_id`, `max_depth`, `max_results` değerlerinin tam sayı (`%lld`, `%d`), `join_cond` ve `next_id` değerlerinin sabit C dizgisi olduğu, `edge_types` değerlerinin ise `?` yer tutucularıyla `bind_text()` üzerinden parametreli bağlandığı doğrulandı (kesin yanlış pozitif).
2. **Yorum Satırı ve Güvenlik Betiği Alarmları (`c_lsp.h:54`, `security-install.sh:132`):** `internal/cbm/lsp/c_lsp.h:54` C yorum satırında geçen `sprintf("%s.%s")` ifadesidir; `scripts/security-install.sh:132` ise zararlı desenleri arayan denetim betiğinin kendi `for pattern in 'system(' 'eval(' 'exec('` satırıdır.
3. **Boyutu Önceden Hesaplanmış Tamponlarda `strcpy`/`strcat` Alarmları (`kotlin_lsp.c:1541-1542`, `py_lsp.c:2055`, `store.c:4482-4484`):** `kotlin_lsp.c` ve `py_lsp.c` içinde tampon hemen bir üst satırda `strlen(...) + 1` ile tam boyutta ayrılmaktadır; `store.c:4482-4484` içinde ise `split_path_parts` fonksiyonu `tmp[CBM_SZ_512]` üzerinde yerinde bölme yaptığı için `dir[CBM_SZ_512]` tamponunun taşması matematiksel olarak imkansızdır.
4. **Sözde Use-After-Free (`vendored/tre/xmalloc.c:347`) ve Sabit URL `curl` (`src/mcp/mcp.c:5997`):** `xmalloc.c:347` `realloc` sonrası eski adres değerini belleğe erişmeden debug hash tablosundan anahtar olarak siler (`hash_table_del`); `mcp.c:5997` ise kullanıcı girdisi olmadan sabit `UPDATE_CHECK_URL` adresine `curl` çağrısı yapar.
5. **Yüksek Önemli `_cli.py` Alarmları:** `pkg/pypi/src/codebase_memory_mcp/_cli.py:57,70` — Paket kurulum/başlatma sarmalayıcısıdır.

### Tek Başına ve Birlikte Kritiklik / Birleşme (Chaining) Analizi
* **Tek Başına ve Birlikte Kritiklik:** **Düşük.** Localhost CORS izin listesi ve Host başlığı doğrulaması sayesinde tarayıcı üzerinden uzaktan yerel RPC/kod okuma zinciri oluşmaz.

---

## 6. GitLab MCP Server (`gitlab-mcp-server-v3.3.0-f92ed3e`)
* **SAST/IaC/SCA Özeti:** `5` bulgu (`0 kritik, 4 yüksek, 0 orta, 1 düşük`).

### A. Doğrulanmış Açıklar
* Doğrudan istismar edilebilir varsayılan bir kod açığı yoktur.

### B. Bağlama Bağlı Bulgular
1. **Ortam Değişkeniyle Açılan TLS Doğrulama Atlama (`CWE-295`):**
   * `internal/gitlab/client.go:1416`: Yalnızca kullanıcı `GITLAB_MCP_SKIP_TLS_VERIFY=true` ortam değişkenini açıkça tanımlarsa `InsecureSkipVerify: true` etkinleşir.
2. **GitHub Actions `pull_request_target`:** PR başlığı/etiket doğrulaması.

### C. Kesin Yanlış Pozitifler (`Yanlış Alarm`)
1. **Go `os.Create` Yol Aşımı Alarmı (`recorder.go:84`):** `cmd/gen_orbit_record/recorder.go:84` — Geliştirici CLI aracında `--out` bayrağıyla verilen yerel çıktı dosyasını açar.
2. **Go `exec.Command` Komut Enjeksiyonu Alarmı (`make.go:35`):** `cmd/audit_supply_chain/make.go:35` — Sabit `"git"` ikilisini argüman dizisiyle (`exec.Command("git", args...)`, kabuksuz) çalıştıran tedarik zinciri denetim betiğidir.

### Tek Başına ve Birlikte Kritiklik / Birleşme (Chaining) Analizi
* **Tek Başına ve Birlikte Kritiklik:** **Düşük.** Yalnızca kullanıcı `GITLAB_MCP_SKIP_TLS_VERIFY=true` ayarını güvensiz bir ağda açarsa MITM riski oluşur; birleşen bir açık yoktur.

---

## 7. Apktool MCP (`apktool-mcp-V3.0.2-12bb331`)
* **SAST/IaC/SCA Özeti:** Politika eşiğini aşan **`16` bulgu**:
  * **Kod (SAST):** `0 kritik, 0 yüksek, 1 orta` (Aday dosyasında tekrarlı XML varlık genişletme uyarısı ve `health_result` değişken adını sağlık verisi sanan 2 yanlış pozitif gizlilik kaydı).
  * **Bağımlılık Açığı (SCA — `uv.lock`):** **`4 kritik, 12 yüksek, 10 orta, 1 düşük`** (`anyio 4.9.0`, `certifi 2025.1.31`, `fastmcp 2.2.0`, `h11 0.14.0`, `mcp 1.6.0`, `starlette 0.46.2`).
* **Tek Başına ve Birlikte Kritiklik / Birleşme Analizi:** Doğrulanmış bir birinci-parti kaynak kodu (SAST) açığı yoktur; ancak projeye "0 bulgu / temiz" denemez. `uv.lock` içindeki `fastmcp 2.2.0`, `mcp 1.6.0` ve `starlette 0.46.2` bağımlılıklarının güncellenmesi gerekir (**SCA Bakım / Bağımlılık Riski: Orta**).

---

## 8. JADX MCP (`jadx-mcp-main-a8e5b7d`)
* **SAST/IaC/SCA Özeti:** Politika eşiğini aşan **`32` bulgu**:
  * **Kod (SAST):** `0 kritik, 0 yüksek, 3 orta` (doğrulanmış kritik/yüksek kaynak kodu açığı yoktur).
  * **Bağımlılık Açığı (SCA — `uv.lock`):** **`6 kritik, 26 yüksek, 24 orta, 5 düşük`** (`anyio 4.10.0`, `authlib 1.6.8`, `certifi 2025.8.3`, `cryptography 46.0.5`, `fastmcp 3.0.2`, `pyjwt 2.11.0`, `mcp 1.26.0`, `python-multipart 0.0.20`, `starlette 0.47.3`, `urllib3 2.5.0`).
* **Tek Başına ve Birlikte Kritiklik / Birleşme Analizi:** Doğrulanmış bir birinci-parti SAST açığı gösterilmemiştir; ancak `uv.lock` içinde `32` adet yüksek/kritik SCA bağımlılık kaydı mevcuttur (**SCA Bakım / Bağımlılık Riski: Orta**).

---

## Özet Karşılaştırma Tablosu: Tek Başına vs. Birlikte (Saldırı Zinciri) Kritiklik ve Kanıt Durumu

| Repo | Sniper SAST / IaC / SCA Özeti | Doğrulanmış Kaynak Kanıtı (Gerçek vs. Yanlış Pozitif) | Tek Başına Kritiklik | Bulgular Birleşiyor mu? (Saldırı Zinciri / Chaining) | Birlikte (Zincir) Kritiklik ve Yayın Durumu |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **1. `autogpt`** | `93` eşik aşan (`2K / 39Y`); `142` triyaj | **2 kritik SQLi (`obj.execute`), JWT ve FastAPI `Security()` tamamen yanlış pozitif**; `jobstore_backfill.py` `pickle.loads` + Compose sabit parola + Root Dockerfile gerçek | **Düşük / Orta** | **KOŞULLU HİPOTEZ:** Yalnızca saldırgan DB `apscheduler_jobs` tablosuna yazma erişimi kazanırsa `pickle.loads` + Root konteyner birleşir | **ORTA / YÜKSEK (Koşullu)** *(Doğrulanmış doğrudan açık yok; derinlemesine savunma sertleştirmesi)* |
| **2. `zitadel`** | `67` eşik aşan (`8K / 42Y`); `286` triyaj | **8 kritik SQLi/`exec` tamamen yanlış pozitif**; `deploy/compose/` altında 3 `docker.sock` bağlaması ve dokümantasyon örneğinde `TLS_REJECT=0` gerçek | **Düşük / Orta** | **HAYIR (Farklı Örnekler):** `docker.sock` (`deploy/compose/`) ile `TLS_REJECT=0` (`apps/docs/...`) farklı compose dosyalarındadır | **DÜŞÜK / ORTA** *(Geliştirme/örnek dağıtım sertleştirmesi; ürün CVE'si değil)* |
| **3. `nextcloud-mcp`** | `59` eşik aşan (`SAST 1K/6Y`, `IaC 7Y`, `SCA 5K/40Y`) | **`login_flow.py:192` SSRF (`initiate()` içinde `_rewrite_to_nextcloud_host` var) ve `token_utils.py` JWT yanlış pozitif**; `pact.yml` `same-repo` korumalı | **Düşük** | **HAYIR:** `pact.yml` dış fork PR'lara kapalıdır; `poll_endpoint` ise `initiate()` aşamasında `self.nextcloud_host` origin'ine sabitlenmektedir | **DÜŞÜK** *(Doğrulanmış SAST açığı yok; iç CI sertleştirmesi)* |
| **4. `mcpjam-inspector`** | `122` eşik aşan (`SAST 12K/8Y`, `SCA 6K/96Y`) | **20 K/Y SAST bulgusunun 18'i kesin yanlış pozitif** (14 yorum satırı `eval (`/ `exec (`, 2 `.d.ts`, 1 UI etiket, 1 UI concat); `pr-preview.yml` `same-repo` korumalı | **Düşük** | **HAYIR:** Dış fork PR'lar engellenmiştir; aynı-repo dal adı interpolasyonu sertleştirilmelidir | **DÜŞÜK / ORTA** *(İç CI sertleştirmesi ve SCA güncellemesi)* |
| **5. `codebase-memory-mcp`** | `32` eşik aşan (`SAST 17K/7Y`, `SCA 8Y`) | **`store.c:2864` SQLi, `c_lsp.h:54` yorum, `kotlin_lsp.c`/`py_lsp.c`/`store.c:4482` boyutlu tampon, `xmalloc.c` ve `mcp.c` yanlış pozitif**; `http_server.c` `localhost` CORS + `Host` (403) korumalı | **Düşük** | **HAYIR:** `http_server.c` yabancı origin'lere CORS başlığı dönmez ve DNS rebinding'i reddeder | **DÜŞÜK** *(Yerel kod sızıntısı zinciri geçersiz)* |
| **6. `gitlab-mcp-server`** | `5` eşik aşan (`0K / 4Y`) | `recorder.go` ve `make.go` yanlış pozitif; `GITLAB_MCP_SKIP_TLS_VERIFY=true` yalnızca kullanıcı seçerse aktif | **Düşük** | **HAYIR:** Birleşen bulgu yoktur | **DÜŞÜK** *(Opsiyonel ayar)* |
| **7. `apktool-mcp`** | `16` eşik aşan (`SAST 1 Orta`, `SCA 4K / 12Y`) | SAST gizlilik uyarıları yanlış pozitif; **`uv.lock` içinde 4 kritik, 12 yüksek SCA bağımlılık kaydı var** | **Düşük / Orta (SCA)** | **HAYIR:** Doğrulanmış birinci-parti kod zinciri yoktur; bağımlılık güncellemeleri incelenmelidir | **DÜŞÜK / ORTA (SCA)** *(SAST temiz, SCA kayıtları mevcut)* |
| **8. `jadx-mcp`** | `32` eşik aşan (`SAST 3 Orta`, `SCA 6K / 26Y`) | Doğrulanmış kritik/yüksek SAST açığı yok; **`uv.lock` içinde 6 kritik, 26 yüksek SCA bağımlılık kaydı var** | **Düşük / Orta (SCA)** | **HAYIR:** Doğrulanmış birinci-parti kod zinciri yoktur; bağımlılık güncellemeleri incelenmelidir | **DÜŞÜK / ORTA (SCA)** *(SAST kritik/yüksek yok, SCA kayıtları mevcut)* |
