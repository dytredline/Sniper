# Sniper — Kullanım Kılavuzu (2026-10, sürüm 2.0.1-r27)

Sniper, **çevrimdışı** çalışan yerel bir uygulama güvenliği aracıdır. Kaynak kodunu, bağımlılıkları,
altyapı tanımlarını (IaC), konteyner imajlarını ve SBOM dosyalarını analiz eder. Bulguları zaman içinde izler,
rapor üretir ve CI'da kapı olarak çalışır. Hiçbir veri dışarı gönderilmez. Varsayılan adres:
`http://127.0.0.1:8787/`.

Komutlar `~/.local/share/sniper/app` dizininden çalıştırılır. Örneklerdeki `cli_reports.py`,
`python3 ~/.local/share/sniper/app/cli_reports.py` anlamına gelir.

Ayrıntılı konu belgeleri:
- [kurulum.md](kurulum.md)
- [OSV-CEVRIMDISI.md](OSV-CEVRIMDISI.md)
- [SBOM.md](SBOM.md)
- [KONTEYNER-TARAMA.md](KONTEYNER-TARAMA.md)
- [IAC-MOTORU.md](IAC-MOTORU.md)
- [CI-KAPISI.md](CI-KAPISI.md)
- [LSP.md](LSP.md)
- [RUST-C-TAINT.md](RUST-C-TAINT.md)
- [GO-RUBY-TAINT.md](GO-RUBY-TAINT.md)
- [ARAC-SABITLEME.md](ARAC-SABITLEME.md)

---

## 1. Kurulum ve güncelleme

Ayrıntı: [kurulum.md](kurulum.md).

| İş | Komut |
|---|---|
| Community source update | Yeni arşivi ve SHA-256 manifestini inceleyip kaynak ağacını değiştirin |

**İmza:** `~/.config/sniper/release-signing.pub` varsa imzasız ya da başka anahtarla imzalanmış paket reddedilir.

**Güncelleme adımları:**
1. Paket doğrulanır: SHA-256 manifesti ve imza.
2. Yedek alınır: `<prefix>/backups/<zaman>-<eski sürüm>/` altına `app.tar.gz` ve SQLite çevrimiçi yedeği.
3. `app.new` → `app` yer değişimi yapılır.
4. Şema göçü yapılır ve denetim kaydına sürüm olayı yazılır.
5. `systemctl --user restart sniper.service` çalıştırılır.
6. Sağlık denetimi yapılır. Başarısızsa güncelleme **otomatik geri döner** (çıkış kodu 3).

**Giriş açıkken** güncelleme aracı sürüm uç noktasını oturumsuz okuyamaz. Bu durumda yalnız `/api/health`
denetlenir ve "sürüm doğrulanamadı" uyarısı verilir. Bu beklenen bir durumdur.

**Arayüzden güncelleme yapılamaz.** İşlem geçmişi › "Sürüm ve güncelleme" kartı yalnız bilgi verir. Bu bilinçli
bir güvenlik kararıdır.

---

## 2. Giriş, roller ve iki adımlı doğrulama

`auth.db` yoksa giriş kapalıdır; yalnız yerel ya da tünel erişimi vardır.

| İş | Komut / yer |
|---|---|
| Yönetici oluştur + girişi aç | `cli_reports.py users create-admin -u <ad> --data-dir ~/.local/share/sniper/data` (parola sorulur; `--password-stdin` de var) |
| Parola sıfırlama | `cli_reports.py users reset-password -u <ad> …` |
| Listeleme / kilit açma | `users list`, `users unlock -u <ad>` |
| Girişi kapatma / açma | `users disable-auth`, `users enable-auth` |
| TOTP | Arayüzde kullanıcı kutusundaki **Hesap** düğmesi › "İki adımlı doğrulama (TOTP)" › Kurulumu başlat ile açılır (`/api/auth/totp/begin` ve `confirm`). Kurtarma kodları bir kez gösterilir. |
| TOTP alan anahtarı | `cryptography==41.0.7` zorunlu/pinlidir. `users totp-key-status` yalnız metadata gösterir; `users rotate-totp-key` cross-process kilit altında seed/pending alanlarını açık yeni anahtarla tekrar şifreler. `auth.db` ile uygulama ağacı dışındaki 0600 keyring birlikte yedeklenmelidir. Eski düz metin DB için önce `users totp-migration-status`, sonra en çok bir saatlik `users open-totp-migration --migration-seconds 900` kullanılır; pencere dışında veya daha önce mühürlenmiş satırdaki düz metin reddedilir. |

**Roller:**

| Rol | Yetki |
|---|---|
| `reader` (okuyucu) | Yalnız okur. |
| `analyst` (analist) | Analiz başlatır; triyaj, atama ve yorum yapar; dışa aktarır. |
| `admin` (yönetici) | Kullanıcıları, politikaları, saklama/yedek ayarlarını ve araç çalıştırmayı yönetir. |

**Oturum güvenliği:** Oturum çerezi HttpOnly ve SameSite=Strict'tir. Durum değiştiren her istekte
`X-Sniper-CSRF` başlığı zorunludur.

**Öz sağlık uyarısı:** Panodaki giriş denetimi, TOTP'si kapalı yönetici hesaplarını uyarı olarak gösterir.

---

## 3. Proje analizi

**Başlatma:** Arayüzde "Uygulama analizi" görünümünden proje yolu verilir. API: `POST /api/project-audits` (`{"project_path": …}`).
- Analiz iş kuyruğunda çalışır: ilerleme çubuğu, aşama bilgisi ve **İptal** düğmesi vardır.
- Sayfa kapansa da sürer; bitince "analiz bitti" bildirimi gelir.
- Süre bütçesi aşılırsa sonuç kısmi olur: kalan dosyalar atlanır ve uyarı verilir. Atlanan dosyalardaki eski
  bulgular yanlışlıkla "düzeldi" sayılmaz.

**Kapsam modları** (`/api/scan-scope`, analiz isteğinde `scope`):

| Mod | Anlamı |
|---|---|
| Kayıtlı kapsam (`default`) | Test/vendor/paket/derleme dizinleri atlanır; dosya 1 MB, toplam 150 MB, 10.000 dosya sınırı. |
| Tümünü dahil ederek (`preset: all`) | Atlanan dizin grupları (`tests`, `vendor`, `packages`, `build`), üretilmiş ve UTF-8 olmayan dosyalar dahil. |
| Yalnız atlananlar (`preset: skipped`) | Normal taramanın dışında kalan dosyalar; önceki analiz `base_audit_id` ile bağlanır. |
| Yalnız değişenler (git) | `changed_only` + `base_ref` (ör. `HEAD`, `origin/main`, ya da `prj_…` analiz kimliği). |

**Monorepo:** Alt projeler ayrı özetlenir: dosya, dil, önem ve bağımlılık envanteri. Tanınan biçimler:
- npm/yarn workspaces, pnpm, lerna;
- `go.work`, Cargo `members`;
- Maven `<modules>`, Gradle `include`;
- `.sln`.

**Dil desteği** (hızlı, derleyici gerektirmeyen veri akışı motorları; Java/C#/PHP için Joern ayrıca derin analiz aracıdır):

| Dil | Kapsam |
|---|---|
| Python | İşlevler/dosyalar arası özetler; Flask, Django, FastAPI, aiohttp, Tornado, Falcon, Chalice, Lambda; Jinja/Django şablonları |
| JavaScript / TypeScript | Sabitlenmiş Babel ayrıştırıcısı; Express, Koa, Fastify, Hono, NestJS, Next.js, React prop'ları, MCP sunucuları; EJS/Pug/Handlebars/Nunjucks |
| Java / JSP | Servlet, Spring MVC/WebFlux, Struts2, JSP scriptlet/EL, Thymeleaf, JDBC/JPA/MyBatis |
| Kotlin | Java motoru üzerinden; Spring, Ktor, Javalin, http4k, gRPC, Android kaynakları |
| C# | ASP.NET Core (controller, minimal API, Razor Pages, Blazor), Razor görünümleri, WebForms (.aspx), ASMX/WCF, EF/ADO.NET |
| PHP | Süper küreseller, PDO/mysqli, Twig/Smarty, Laravel/Symfony/CodeIgniter/Slim; WordPress'te yönetici bağlamı ayrımı |
| Go | net/http, gin, echo, fiber, chi; işlev değerleri; kayıtlı veri (database/sql, GORM) |
| Ruby | Rails, Sinatra, Grape, Hanami, Roda/Sequel; ActiveRecord kayıtlı veri |
| Rust | actix-web, axum, rocket, warp; `unsafe`/FFI bilgi notu |
| C / C++ | argv, getenv, stdin, ağ ve CGI kaynakları → komut, biçim dizgesi, bellek taşması, SQL, yol |

**Doğrulanmış ve olası akış:**
- **Doğrulanmış veri akışı:** kaynaktan hedefe kesin yol.
- **Olası veri akışı:** iki ya da daha çok çağrılık zincir; ayrı katmandır.
- **Yönetici yetkisi:** Yetki/nonce denetimli yöntemlerdeki akışlar "YÖNETİCİ YETKİSİ" rozetiyle düşük önemli not
  olarak gösterilir.

**IaC** (Trivy gerektirmez; ayrıntı [IAC-MOTORU.md](IAC-MOTORU.md)):
- **Desteklenenler:** Terraform (AWS/GCP/Azure; değişken varsayılanları, tfvars, locals, yerel modül
  çıktı zincirleri), Kubernetes ve Helm (değerlerle ve bilinmeyen koşul varyantlarıyla render), Dockerfile,
  docker-compose ve GitHub Actions/GitLab CI veri akışları. Kubernetes proje grafiği Ingress veya aynı
  namespace'te, `All` dinleyicisinde ya da statik Namespace etiketleri `allowedRoutes.namespaces.from: Selector`
  koşulunu karşılayan başka namespace'teki Gateway API
  HTTPRoute/GRPCRoute/TCPRoute/TLSRoute/UDPRoute, protokolü uyumlu dinleyici üzerinden aynı namespace'teki ya da hedef namespace'te route türüne özgü geçerli `ReferenceGrant` ile izin verilen Service; ayrıca doğrudan NodePort/LoadBalancer veya genel `externalIPs` taşıyan Service,
  Workload, ServiceAccount ve Role ilişkisini dosyalar arasında kurar; GitHub Actions iş
  kapsamındaki `GITHUB_ENV` aktarımını sonraki adımlara taşır.
- **Kural kimlikleri:** Her kontrolde CWE ve Checkov eşdeğeri kimlik bulunur.
- **"(varsayılan ayar)" bulguları:** Sağlayıcı varsayılanı güvensiz olup hiç yazılmamış ayarlardır; düşük ya da
  orta önemdedir.

**Ek denetimler:**
- Rota yetki envanteri: korumasız rota (CWE-862) ve IDOR adayı (CWE-639).
- STRIDE tehdit modeli.
- OpenAPI sözleşmesi ↔ kod rotaları karşılaştırması: gölge uç ve kimlik doğrulama uyuşmazlığı.
- Lisans uyumu.
- Tedarik zinciri: kötü amaçlı paket, npm kurulum betikleri ve bağımlılık karışıklığı ipuçları.

---

## 4. Bağımlılık güvenliği (SCA)

### 4.1 Çevrimdışı OSV veritabanı

Ayrıntı: [OSV-CEVRIMDISI.md](OSV-CEVRIMDISI.md).

- **Konum:** Resmî OSV arşivleri `~/.local/state/sniper/osv-db` altına indirilir. Manifestler yerel anahtarla
  imzalıdır; arşiv ve dizin SHA-256 ile doğrulanır.
- **Liste:** `ecosystems.json` dosyası, `SNIPER_OSV_ECOSYSTEMS` değişkeni ya da varsayılan 10 dil ekosistemi:
  npm, PyPI, Go, Maven, RubyGems, crates.io, Packagist, NuGet, Pub ve Hex.
- **Bu kurulumdaki liste:** 16 ekosistem; işletim sistemi ekosistemleri de ekli (Debian 12/11, Ubuntu 24.04/22.04 LTS,
  Alpine 3.20/3.19).
- **Güncelleme:**
  ```
  python3 scripts/osv_refresh.py            # yapılandırılmış tüm ekosistemler
  python3 scripts/osv_refresh.py --status   # ekosistem başına durum
  python3 scripts/osv_refresh.py --ecosystem PyPI   # tek ekosistem
  ```
- **Zamanlayıcı:** `sniper-osv-refresh.timer` aynı komutu düzenli çalıştırır. 7 günden eski veri "bayat" uyarısı
  verir; `osv_db_stale` bildirimi de gönderilir.

### 4.2 Tarama

**Nasıl çalıştırılır:**
- **Arayüz:** Uygulama analizi › SBOM ve bağımlılık açıkları › "Çevrimdışı OSV ile tara".
- **API:** `POST /api/dependency-security/offline-scan` `{"project_path": …, "confirm_local": true}`.
- **CLI:** `cli_reports.py osv-offline <proje> [--no-save]`.

**Okunan dosyalar (envanter):**
- npm: package-lock v1/v2/v3, shrinkwrap, yarn, pnpm; kilit yoksa kesin sürümler ve güvenli yerel `node_modules` kurulumu ile doğrulanan `^`, `~` veya karşılaştırma aralıkları. `^1.2`, `^0.2`, `~1`, `~1.2`, `>=1.2` ve `<=1.2` gibi eksik bileşenli npm aralıkları kendi alt/üst wildcard sınırlarıyla değerlendirilir; `>= 1.2.3` biçimindeki yasal karşılaştırıcı boşlukları da aynı yerel sürüm kanıtıyla çözülür.
  `takma-ad: "npm:gerçek-paket@sürüm"` bağımlılıklarında gerçek paket OSV ve doğrudanlık kimliği olarak,
  takma ad ise JavaScript/TypeScript içe aktarma kimliği olarak kullanılır; çalışma alanında çakışan takma ad eşleşmez.
- Python: `requirements.txt`, pip-tools `requirements.in` ve `requirements/*.{in,txt}` (proje kökü içindeki en fazla 8 düzey/100 dosyalık `-r` içermeleri, devam satırları, hash'ler), `setup.py`, `setup.cfg`, tox `testenv` bağımlılıkları, Nox oturumlarındaki sabit `session.install(...)` paketleri, Conda `environment.yml/.yaml` ana ve iç içe pip bağımlılıkları, PEP 723 `# /// script` bağımlılık blokları, Pipfile/Pipfile.lock, poetry, uv, pdm. Tox `deps`, Nox kurulumları ve Conda iç içe pip listelerindeki proje içi `-r` dosyaları aynı kök/depth sınırlarıyla izlenir; komut, `-c` kısıt ve ortam ayarları paket sayılmaz. Nox dosyaları çalıştırılmaz; yalnız `@nox.session` ilk parametresindeki sabit install argümanları okunur. PEP 723 taraması 1.000 Python dosyası ve toplam 8 MB ile sınırlıdır. Pipfile doğrudanlığı yalnız `[packages]` ve `[dev-packages]` tablolarından okunur; kaynak ve çalışma zamanı tabloları paket sayılmaz. Doğrudanlık
  sınıflandırması `pyproject.toml` içindeki PEP 621 ana/isteğe bağlı bağımlılıklarını, PEP 735
  `dependency-groups` dizelerindeki paketleri, Poetry ana/eski geliştirme/adlandırılmış grup tablolarını ve
  PDM/uv geliştirme bağımlılığı gruplarını, Hatch ortam bağımlılıklarını, Rye geliştirme bağımlılıklarını,
  eski Flit `tool.flit.metadata` ana/ekstra gereksinimlerini ve
  `setup.py` içindeki statik `setuptools`/`distutils` `setup()` çağrısının literal ana/ekstra listelerini ve
  yalnız bir kez atanmış üst düzey literal liste/sözlük bağlarını, ayrıca
  `setup.cfg` ana/ekstra gereksinim listelerini, eski `setup_requires`/`tests_require` listelerini ve proje köküyle sınırlı tek satır ya da devam bloklu `file:` gereksinim dosyalarını kapsar; bozuk `setup.cfg`/`tox.ini` kapalı kalır, dinamik Python ifadeleri çalıştırılmaz ve tahmin edilmez;
  en az 10 sabit sürümlü satırdan oluşan `.txt` pip-freeze çıktısı envanter sayılırken `.in` dosyası doğrudan bildirim olarak kalır;
  PEP 735 `include-group` kayıtları paket adı sayılmaz ve yanlış TOML değer türleri kapalı kalır.
- Go: go.mod/go.sum (replace dahil).
- Maven ve Gradle: proje içi üst POM; isteğe bağlı `SNIPER_MAVEN_REPOSITORY` altındaki çevrimdışı üst POM/import BOM; Gradle ve version catalog.
- Diğerleri: Gemfile.lock, Cargo.lock, composer.lock, NuGet ve Hex `mix.lock`.
- Alt dizinlerdeki manifestler de okunur.
- Doğrudan manifest başına en çok 2 MB okunur; bu sınırı aşan dosya paket kökeni üretmez.

**Sınırlar:**
- Yerel kurulumla doğrulanamayan npm aralıkları ve desteklenmeyen belirsiz sürümler atlanır ve sayılır.
- Maven üst POM ve BOM'ları yalnız açıkça ayarlanan çevrimdışı depodan okunur; ağ veya örtük `~/.m2` kullanılmaz.

### 4.3 Erişilebilirlik ve öncelik

- **Paket kullanımı:** kullanılıyor / kullanılmıyor / yalnız geçişli / bilinmiyor. Kanıt dosya:satır olarak verilir.
- **İşlev düzeyi erişilebilirlik:** Python, JavaScript, Go, Rust, Java/JVM ve .NET kaynaklarında içe aktarma ile
  sınıf/işlev çağrıları bağlanır. Java generic/diamond kurucuları, Java açık generic çağrı/yöntem başvuruları,
  Kotlin generic çağrıları ve C# generic/target typed `new()` örnekleri yöntem alıcısına taşınır; C#/VB generic
  yöntem çağrıları ve kapalı generic yöntem grupları sembol kimliğini korur. Aynı adlı yerel .NET türü dış paket
  türü sayılmaz. Visual Basic tek tırnak
  ve `REM` yorumları çağrı kanıtından ayrılır ve yorumdan sonraki gerçek çağrılar korunur; F# iç içe blok yorumları
  ile generic `'T` işaretleri birbirinden ayrılır. Razor `@* … *@` ve HTML yorumları da sembol kanıtı sayılmaz.
  Go içe aktarımları yorumlardan arındırılmış fakat yol dizeleri korunmuş görünümden, sembol çağrıları ise yorum,
  yorum içi sahte içe aktarma, normal dize ve ham ters tırnak dizeleri maskelenmiş görünümden çıkarılır.
  Rust iç içe blok yorumlarını, normal/byte/ham dizeleri ve karakter değişmezlerini sembol kanıtından ayırır;
  yaşam süreleri (`'a`) ve etiketler (`'retry`) kod olarak korunur. `use … as …` ile yeniden adlandırılan işlev
  ve makro çağrıları özgün sembole bağlanır; yalnız içe aktarmak kesin çağrı kanıtı sayılmaz, işlev parametresi
  ve basit `let` gölgeleri dış paket çağrısı olarak yazılmaz.
  Cargo bildirimindeki `{ package = "gerçek-ad" }` yeniden adlandırmaları kilit/OSV paket kimliğini korurken
  Rust kaynağındaki yerel crate adına bağlanır; aynı çalışma alanında birden çok pakete verilen çakışan takma
  adlar erişilebilirlik kanıtı sayılmaz.
  Yerel OSV sembolleri ve
  danışma metnindeki açık yöntem adları kullanılır.
- **Öncelik puanı (0–100):** önem × erişilebilirlik × düzeltme var mı × doğrudan/geçişli.
  - Katmanlar: **Önce düzelt** (≥45), **Planla** (≥20), **İzle**.
  - Kötü amaçlı paketlerin puanı her zaman 100'dür.
- **Maven ve NuGet:** "Kullanılmıyor" olarak görünen paketin önemi düşürülmez; yansıma ve otomatik yapılandırma
  ile yüklenebilir.

### 4.4 Kötü amaçlı paket

- **Kaynaklar:** OpenSSF `MAL-` kayıtları ve GitHub "malware" danışmaları.
- **Bulgu:** "Kötü amaçlı paket", kritik, CWE-506.
- **Öneri:** Paketi kaldırın, kimlik bilgilerini döndürün, sistemleri inceleyin. **Sürüm yükseltmek yetmez.**
- **Özel depo durumu:** Paket kilit dosyasında özel depodan çözülüyorsa ve herkese açık depoda aynı adlı kötü amaçlı
  paket varsa, bu "bağımlılık karışıklığı riski" olarak raporlanır (yüksek, CWE-427).
- **Ayrıca:**
  - npm kurulum betikleri statik olarak okunur, çalıştırılmaz. Şüpheli kalıp varsa önem yükselir.
  - Özel kayıt deposu yapılandırma dosyalarının yalnız var olup olmadığı denetlenir, içeriği okunmaz.

### 4.5 Lisans politikası

- **Kaynaklar:** Lisanslar yerel dosyalardan ve paket önbelleklerinden okunur: `~/.m2`, cargo, nuget, Go modül
  önbelleği ve gem. Ağ kullanılmaz.
- **Kategoriler:** izinli / dikkat / yasak. Bilinmeyen lisans "inceleme" sayılır.
- **Politika dosyası:** `$SNIPER_DATA_DIR/license-policy.json`.
- **API:** `GET /api/license-policy` herkese açık. `POST` yönetici yetkisi ve `confirm` ister.

### 4.6 SBOM ve VEX

Ayrıntı: [SBOM.md](SBOM.md).

| İş | Komut / uç |
|---|---|
| CycloneDX 1.5 / SPDX 2.3 dışa aktarma | `cli_reports.py sbom export <proje> -o dosya [--format spdx]` · `GET /api/dependency-sboms/<id>?format=spdx` |
| Dış SBOM tarama | `cli_reports.py sbom scan <dosya> [--save] [--vex openvex --vex-out …] [--fail-on high]` · `POST /api/dependency-security/sbom-scan` (`confirm`) |
| Proje VEX | `cli_reports.py vex <proje> -o vex.json [--format openvex|cyclonedx] [--dev-not-affected]` |
| VEX kararları / tedarikçi VEX'i | `/api/dependency-security/vex-decisions`, `/api/dependency-security/vex-import` |

**Dış SBOM tarama:**
- Okunan biçimler: CycloneDX JSON ve XML, SPDX JSON ve tag-value.
- XML'de `DOCTYPE`/`ENTITY` reddedilir.
- Sınırlar: 32 MB, 50.000 bileşen.

**VEX'te "etkilenmiyor" (`not_affected`) yalnız şu durumlarda verilir:**
- analist kararı (gerekçeli);
- tedarikçinin VEX belgesi;
- paket kilit dosyasında hiç yoksa.

Açıklı işlevin çağrılmaması tek başına yetmez; "inceleniyor" kalır.

---

## 5. Konteyner imajı ve rootfs taraması

Ayrıntı: [KONTEYNER-TARAMA.md](KONTEYNER-TARAMA.md). Docker daemon gerekmez.

**Komut:**
```
cli_reports.py image <docker-save.tar | OCI dizini/tar | rootfs dizini> [--save] [--sbom cdx.json]
                     [--ignore-unfixed] [--fail-on high] [--view json]
```
API: `POST /api/container-images` (analist). İsteğe bağlı `dockerfile_path`, çok aşamalı Dockerfile'ın
son aşamasında kurulan paketleri gerçek imaj envanteriyle ilişkilendirir.

**Okunan paket veritabanları:**
- İşletim sistemi: dpkg (distroless `status.d` dahil), apk, rpm sqlite.
- Dil paketleri: Python, npm, jar.

**Eşleme:**
- İşletim sistemi paketleri, dağıtımın OSV arşiviyle (Debian/Ubuntu/Alpine, Alma/Rocky,
  Red Hat Enterprise Linux, Amazon Linux, SLES/openSUSE) eşlenir.
- Dil paketleri çevrimdışı çok ekosistemli OSV ile eşlenir.

**Güvenlik:** Katmanlar diske açılmaz. Yol aşımı, kökten çıkan sembolik bağ ve aygıt dosyası reddedilir.
Zstd katmanlar yalnız root sahipli, grup/dünya tarafından yazılamayan sabit `/usr/bin/zstd` ile akış halinde
çözülür; bu decoder yoksa hazırlık sözleşmesi açık neden verir ve tarama kapalı kalır.

---

## 6. Bulgu takibi, portföy ve dışa aktarma

### Bulgu takibi

Arayüzde "Bulgu takibi" görünümü; API `/api/finding-tracking/…`.

**Tüm kaynaklar:** Aynı görünümdeki bu sekme, `GET /api/findings/unified` üzerinden proje analizi, elle girilen
denetim ve ağ taraması bulgularını tek salt okunur listede birleştirir. `source`, `status`, `severity` ve `limit`
filtreleri kullanılabilir. Kaynağa özgü ham kanıt, gizli metin, hedef URL'si ve ağ bulgusu özetleri döndürülmez;
yalnız ortak başlık, önem, durum, kapsam, konum, sorumlu, son tarih ve sınırlı triyaj kararı gösterilir.

**Parmak izi:** Bulgular satır kaymasına dayanıklı bir parmak iziyle analizler arasında eşlenir. Kararlı iç sıralama
sayesinde aynı kod her çalıştırmada aynı kanıtı ve parmak izini üretir.

**Durumlar:**
- yeni, açık, sürüyor;
- düzeldi, yeniden açıldı;
- yanlış alarm, risk kabulü (bitiş tarihli).

Triyaj kararları sonraki analizlere taşınır. Risk kabulünün süresi dolunca bulgu yeniden açılır.

**İş birliği:**
- Sorumlu atama ve son tarih.
- Yorumlar, düz metin olarak.
- "Bana atananlar" görünümü.
- Gecikme ve son tarih bildirimleri.

### Portföy ve SLA

`GET /api/portfolio`.

- **İçerik:** Projeler arası risk puanı, alan bazında etkin bulgular (kod / bağımlılık / IaC / konteyner…),
  haftalık eğilim, MTTR.
- **SLA politikası:** Önem başına gün; yönetici ayarlar. Yeni bulgulara otomatik son tarih verilebilir;
  varsayılan kapalıdır. Politika `sla-policy.json` dosyasındadır.

### Dışa aktarma

`GET /api/portfolio/export`, analist yetkisi.

- **Biçimler:** `defectdojo` (Generic Findings JSON), `jira` (CSV) ve `csv`.
- **Güvenlik:** CSV formül enjeksiyonu önlenir (`= + - @` ile başlayan hücreler).

---

## 7. Raporlar

**Proje raporu:** `GET /api/project-audits/<id>/report.html`.
- Bulgular alanlara göre gruplanır: Kod, Bağımlılıklar, Lisans, Altyapı (IaC), Konteyner, API, Tedarik zinciri.
- Bağımlılık tablosunda kötü amaçlı paketler en üsttedir.

**Yönetici özeti:** `GET /api/project-audits/<id>/executive-summary.html`. JSON için `…/executive-summary`.
- "Alanlara göre durum" tablosu, her alan için en önemli 5 madde ve önerilen eylem.
- Sayılar tek kaynaktan hesaplanır; kötü amaçlı paket iki kaynakta görünse de bir kez sayılır.

**İngilizce ve PDF:**
- `?lang=en` İngilizce rapor verir.
- `?format=pdf` PDF verir: pinli Chromium, bwrap yalıtımı, ağsız, JavaScript kapalı. Sınırlar: HTML 8 MB,
  PDF 25 MB, varsayılan 60 sn (`SNIPER_PDF_TIMEOUT_SECONDS`).
- PDF, tarama raporu için de vardır.

**Arayüz dili:** Başlıktaki seçiciyle Türkçe ya da İngilizce seçilir.

**CSP:** Rapor sayfalarının CSP'sinde `unsafe-inline` yoktur; yalnız stil özetleri izinlidir.

---

## 8. CI kapısı

Ayrıntı ve şablonlar: [CI-KAPISI.md](CI-KAPISI.md), `docs/ci/` (GitHub Actions, GitLab CI, Jenkins, pre-commit).

**Komut:**
```
cli_reports.py ci <proje> [--policy .sniper-policy.json] [--sarif sniper.sarif] [--gitlab-dir out/]
                          [--summary özet.md] [--baseline-sarif önceki.sarif | --baseline-audit prj_… |
                          --baseline-ref origin/main] [--no-sca] [--store] [--json karar.json]
```

**Ne yapar:**
- Proje analizini ve çevrimdışı SCA'yı tek çalıştırmada, ağsız yürütür.
- SARIF 2.1.0 üretir: kararlı kural kimlikleri, `partialFingerprints` = bulgu takibi parmak izi.
- GitLab `gl-sast-report.json` ve `gl-dependency-scanning-report.json` dosyalarını üretir.

**Politika dosyası** (`.sniper-policy.json|yml`; örnek: `docs/ci/sniper-policy.example.json`):
- **Anahtarlar:**
  - `fail_on`: grup başına eşik. Gruplar: code, iac, sca, malicious, license, supply_chain, container, api.
  - `new_only`, `license_denied`, `sla_breach`, `sca_fix_first`, `iac_fix_first`, `require_osv`.
  - `exceptions`: kimlik, gerekçe (en az 10 karakter), bitiş tarihi zorunlu; isteğe bağlı yol kalıbı.
- **Kötü amaçlı paket her zaman başarısızdır:** istisnayla ya da `fail_on` ile susturulamaz.

**Çıkış kodları:**
- 0: geçti;
- 1: politika ihlali;
- 2: yapılandırma hatası;
- 3: analiz ya da doğrulama hatası.

---

## 9. Editör entegrasyonu (LSP)

Ayrıntı: [LSP.md](LSP.md). VS Code ve Neovim örnekleri orada.

- **Çalıştırma:** `scripts/sniper-lsp` (stdio). Dosya açıldığında ya da kaydedildiğinde aynı motorla analiz edilir.
- **Tanılama:** CWE ya da IaC kimliği ve bulgu takibi parmak izi içerir.
- **Hızlı düzeltme:** `taint_autofix` dönüşümü önerilir; düzenlemeyi editör uygular.
- **Ağ ve dosya:** Ağ yok. Önbellek dışında hiçbir şey yazılmaz (`~/.cache/sniper-lsp`).

---

## 10. İşletim

### Bildirimler

Ayarlar: Bildirimler görünümü; API `/api/notification-settings`.

**Kanallar:** uygulama içi, masaüstü (`notify-send`), SMTP (varsayılan kapalı) ve webhook (yalnız geri döngü ya da özel ağ adresine).

**Olaylar:**
- Bulgu ve tarama: yeni / düzelen bulgu, tarama hatası, analiz bitti.
- Takip: bulgu atandı, son tarih, SLA ihlali, risk kabulü bitti.
- Bağımlılık ve konteyner: kötü amaçlı paket, "önce düzelt" SCA, kritik konteyner açığı, yasak lisans.
- Sistem: öz sağlık, bayat OSV verisi.

**Davranış:**
- Kötü amaçlı paket bildirimi sessiz saatleri atlar.
- Aynı bulgu tekrar bildirilmez.

### Zamanlanmış görevler

İşlem geçmişi › Zamanlanmış taramalar; API `/api/schedules`.

**Plan türleri:**
- proje analizi, yalnız değişenler;
- SBOM, OSV-Scanner;
- gitleaks, TruffleHog;
- çevrimdışı OSV taraması, konteyner imajı ya da rootfs taraması, SBOM dosyası taraması.

**Sıklık:** `hourly`, `daily HH:MM`, `weekly <gün> HH:MM` ya da 5 alanlı cron. Varsayılan saat dilimi
Europe/Istanbul.

**Kural:** Yalnız yerel yollar zamanlanabilir; uzak hedefli araçlar listede yoktur.

### Öz sağlık panosu

`GET /api/system/health-report`, analist yetkisi. Denetimler:
- Disk, veritabanı (`quick_check`).
- Yedek yaşı ve birikimi.
- OSV: ekosistem başına tazelik ve zamanlayıcının son sonucu.
- Malware ve lisans önbellekleri.
- Zamanlanmış taramalar, iş kuyruğu, denetim zinciri.
- Araç sabitlemeleri, sürüm.
- `sniper.service` çalışma ve kullanıcı oturumunda otomatik başlatma durumu.
- Giriş: TOTP'siz yönetici.

Pano hiçbir şeyi silmez ya da düzeltmez; yalnız önerir.

### Saklama ve yedek döndürme

İşlem geçmişi › Saklama ve yedekler; API `/api/system/retention` ve `/api/system/backups`, yönetici yetkisi.

**Politika:**
- Varsayılan **kapalı**.
- Önce önizleme yapılır; yürütme için politikanın açık olması, `confirm` ve önizlemedeki `plan_id` gerekir.
- Kategoriler: DB yedekleri (son N + günlük + haftalık), eski analizler, okunmuş bildirimler, bitmiş işler,
  geçici dosyalar, önbellekler.

**Asla silinmeyenler:**
- `audit_log` ve bulgu takibi;
- en yeni yedek;
- son 1 saatte oluşan dosyalar.

**Etiketli yedekler:** Elle alınmış etiketli yedekler (`*-claude-*` gibi) yalnız `include_named` açıkken kapsama
girer.

**Yedek alma ve geri yükleme:**
- Arayüzden "Şimdi yedek al" mümkündür.

### Araç sabitleme

Ayrıntı: [ARAC-SABITLEME.md](ARAC-SABITLEME.md).

- Dış ikili dosyalar SHA-256 ile sabitlenir: gitleaks, trufflehog, opengrep, Joern JDK, k6, bwrap, node, chromium,
  playwright-core.
- Durum: `/api/tooling/readiness`.

---

## 11. Güvenlik modeli

- **Çevrimdışı:** Analizler ağ kullanmaz. Ağa çıkan tek iş OSV veritabanı güncellemesidir; yalnız resmî OSV
  deposundan, açıkça çalıştırıldığında ya da zamanlayıcıyla yapılır.
- **Yalnız izinli ve yerel hedefler:** Proje, imaj ve SBOM yolları izinli kökler içinde olmalıdır.
  - Aktif araçlar (k6, Schemathesis, Playwright) yalnız loopback ya da sahipliği doğrulanmış hedeflere çalışır.
  - Dış hedefe tarama başlatılmaz.
- **Yalıtım:**
  - Harici araçlar ve PDF üretimi bwrap ad alanları, ağsız ortam ve seccomp ile çalışır.
  - Chromium iç sandbox'ı bwrap içinde kapalıdır (`--no-sandbox`); yerine seccomp ve ad alanları vardır.
- **Web güvenliği:**
  - Sıkı CSP: satır içi betik ve stil yoktur.
  - Oturum çerezleri HttpOnly ve SameSite=Strict'tir; CSRF başlığı zorunludur.
  - API hız sınırı dakikada 240 istektir; statik varlıklar sınırın dışındadır.
- **Denetim kaydı:** HMAC çapalı karma zincirdir. `GET /api/audit-log/verify` ile doğrulanır.
- **Sırlar:** Raporlara sır değeri ve kaynak satırı kopyalanmaz.

---

## 12. Doğruluk ve ölçüm

**Yöntem:** Sniper bağımsız setlerle ölçülür.
- Her set, daha önce hiç kullanılmamış açıklı projelerden kurulur.
- Zemin gerçeği araç çıktısına bakılmadan yazılır.
- CodeQL 2.27.1 ile karşılaştırılır.
- Bir sete bakılarak motor ayarı yapıldıysa o set **"ayar görmüş"** sayılır ve dürüst ölçüm bir sonraki setle yapılır.

**Güncel dürüst sonuç (10. set, 2026-10-21, sürüm r19–r21):**

| | Sniper | CodeQL 2.27.1 |
|---|---|---|
| Kod açıkları, doğrulanmış akış (27 proje, 184 açık) | **141/184 (%77)** | 81/184 (%44) |
| Kesinlik (tartışmalılar yanlış sayılarak) | 0,87 | — |
| Bağımlılık açıkları (SCA, 7 proje, 31 paket@sürüm) | **30/31 (%97)** | — |

**Ayar görmüş setler:** 5–9. setler ve 8. set bu turlarda ayar için kullanıldı. Bu setlerdeki daha yüksek sayılar
(ör. 7. set 112/118, 9. set 111/133) **genelleme kanıtı değildir**.

**Gözlem:** Bilinen setlerin kaçırmalarından türetilen kurallar, görülmemiş sette çok az kazanç getirdi. Gerçek
kazanç yeni yeteneklerden geldi: çok ekosistemli çevrimdışı SCA, IaC motoru ve yeni dil motorları.

**Ürün içi ölçüm hattı:** `scripts/eval_pipeline.py`, sonuç geçmişini ve gerileme çıkış kodunu üretir. Arayüzde
doğruluk panosu: `/api/eval/latest`.

**Kör ground-truth kapısı:** `scripts/prepare_ground_truth.py prepare`, analiz motorunu çalıştırmadan seçilen dil
profillerindeki kaynak yolları, satır sayıları ve SHA-256 değerlerinden bir inceleme manifesti ve boş etiket şablonu
üretir. `--source-profile` birden çok kez verilebilir; C/C++, Python, JavaScript/TypeScript, JVM, .NET, Go, Ruby,
PHP ve Rust desteklenir, seçim yapılmazsa C/C++ kullanılır. İnsan etiketlemesinden sonra `validate` kaynağın
değişmediğini, etiket satırlarını ve bağımsız inceleme beyanını doğrular; eski C/C++ v1 manifestleri geçerlidir.
`eval_pipeline` yapılandırmasındaki `require_blinded_ground_truth: true` ve `review_manifest`, bu doğrulama geçmeden
analizi başlatmaz. İsteğe bağlı `quality_gate`, set başına asgari proje/etiket, duyarlılık/kesinlik, azami yanlış
pozitif oranı ve azami analiz hatası sınırı koyar. Kaynak ağacındaki küçük `tests/fixtures/c-reference-set1` seti bu sözleşmenin çalışan örneğidir;
geniş bağımsız korpusun yerini almaz.

---

## 13. Bilinen sınırlar

- **Canlı kanıt kapsamı dar:** Statik açık yönlendirme, CWE-79/HTML yansıma, CWE-942 kimlik bilgili CORS
  yansıması ve CWE-1021 clickjacking başlık bulguları yalnız `runtime_proof`
  izni verilmiş kritik olmayan `127.0.0.1` hedefinde tek GET ile doğrulanabilir. Yönlendirme izlenmez; HTML
  profilinde betik çalıştırılmaz; CORS ve clickjacking profillerinde gövde okunmaz ve otomatik triyaj kararı
  verilmez. Clickjacking eksikliği yalnız gövde taşıyabilen 2xx HTML/XHTML yanıtta doğrulanır; ayrı CSP başlıkları
  ayrı politika kalır, bozuk `frame-ancestors` kaynakları koruma sayılmaz, 204/205 ve açıkça sıfır uzunluklu
  yanıtlar doğrulanmaz. Diğer web bulgu sınıfları için genel
  DAST bağlantısı yoktur.
- **MCP ajan triyajı var; yerleşik model çıkarımı yok:** MCP bulguları okuyup öneri kaydedebilir. Tarama kataloğu ve
  bekleyen tarama isteği araçları kullanıcı belirteci ister; istek ayrı yönetici API onayı olmadan çalışmaz.
  Yönetici bekleyen satırı yetki kutusundan bağımsız reddedebilir; başlamış/çalışan satırdaki iptal, bağlı iş
  kuyruğu işi veya başlamış Nuclei iç işi iptali gerçekten kabul ettikten sonra kaydedilir. Nuclei alt işi yarışta
  zaten `completed`/`failed` olmuşsa terminal sonuç iptal kabulü gibi yorumlanmaz ve MCP `cancelled` yapılmaz.
  Burp'ın yürütmesiz
  `approved` elle devir satırı kaybolmaz; arayüzdeki **Kapat** eylemiyle terminal duruma geçirilir. Kalıcı dış iş
  `cancelled` olup servis MCP geçişinden önce kesilirse sonraki okuma durumu yine `cancelled` olarak kurtarır.
  200 satırlık sınırda
  etkin işler atılmaz; yalnız en eski terminal kayıtlar budanır ve tüm satırlar etkinse yeni istek reddedilir.
  Tamamlanan kayıtlı veya insan onaylı doğrudan Nuclei işi, ham rapor ve hedef bilgisi olmadan en çok 200 maskeli
  tekil bulguyu kalıcı tarama kaydına taşır; doğrudan koşuda yalnız `target_sha256` saklanır ve sahte hedef/denetim
  oluşturulmaz. Toplamlar ve kesilme bilgisi `triage_summary` alanında kalır. MCP ajanı bunlar için yalnız
  `pending` öneri kaydedebilir; uzman kararı otomatik verilmez. Nuclei dışı doğrudan işlerin sonuç özeti de yalnız
  araç kimliğine bağlı sabit alanlardan oluşur; hedef/ham/dinamik alanlar kopyalanmaz ve bozuk sonuç açıkça
  `summary_unavailable` görünür.
- **ASan öz sınaması ve proje kanıtı:** Öz sınama sabit temiz/UAF fikstürleriyle araç zincirini
  doğrular. İkili kanıtı yalnız desteklenen bellek bulgusuna bağlı, önceden ASan ile derlenmiş tek ELF'i
  argümansız ve ağsız bwrap içinde çalıştırır. Kaynak kanıtı aynı bulgunun tek C/C++ dosyasını sabit derleyici
  ve bayraklarla derleyip aynı yalıtımda çalıştırır. Compile-database profili, insanın seçtiği tek
  `arguments`/`-c` girdisindeki sınırlı makro/include/standart seçeneklerini özel ve boyut sınırlı C/C++
  kaynak/header snapshot'ına uygular; ilgisiz boş header'lar atlanır ama seçili boş çeviri birimi reddedilir.
  Shell `command`, dış include, ek çeviri birimi, link planı, response
  dosyası ve proje derleme betiği çalıştırılmaz; bu nedenle özel link adımlı bütün proje derlemelerinin yerini almaz.
- **Ölçülmemiş ya da zayıf diller:**
  - Kotlin ve C/C++ için bağımsız ölçüm sınırlı; `c-reference-set1` yalnız iki etiketten oluşan sözleşme örneğidir.
    Kaynak SHA'ları sabit `engine-quality-reference-r58` sentetik kapısı C++ `std::function`, Kotlin sabit
    `val ad = ::yöntem` ve Ruby sabit dize/sembol yansımalı çağrılarında 3/3 pozitif etiketi ile ayrıca tehlikeli
    adayı olmayan bir C++ negatif projeyi denetler; insan-kör bağımsız ölçüm iddiası taşımaz.
    Geniş, görülmemiş C/C++ setinde recall ve precision henüz ölçülmemiştir.
  - Ruby'de kayıtlı veri modeli dar.
- **İşlev düzeyi erişilebilirlik:** JavaScript, Python, Java, .NET, Go ve Rust için statik çağrı kanıtı üretilir;
  Kotlin'de değiştirilemez niteliksiz callable reference ve Ruby'de sabit dize/sembol `send`/`__send__` ile
  yalnız public hedeflere giden `public_send` dar ve kesin olarak çözülür. Ruby yöntem görünürlüğü ayrıştırıcı
  modelinde izlenir; ActiveSupport `try`/`try!` bu çağrıların eşdeğeri sayılmaz. Dinamik çağrılar, alıcıya bağlı
  callable reference, interpolasyonlu yansıma ve çalışma zamanında üretilen adlar her zaman çözülemez.
- **Envanter sınırları:** npm aralığı yalnız eşleşen, düzenli ve sembolik bağ olmayan yerel kurulumdan çözülür.
  Maven üst POM/BOM için `SNIPER_MAVEN_REPOSITORY` açıkça ayarlanmalıdır; uzak depo kullanılmaz. Çevrimdışı Maven
  etkin modeli, parent şablonlarında çocuk özellik ezmesini korur; içe aktarılan her BOM'un özellikleri kendi
  modelinde çözülür ve başka BOM'a sızmaz. GAV doğrulaması da POM'un yerel özellikleri çözüldükten sonra yapılır;
  model sayısı veya beş düzey parent/BOM sınırı aşılırsa envanter kısmi olarak işaretlenir. `dependencyManagement`
  ve BOM girdileri sürüm seçer ancak doğrudan proje bağımlılığı yoksa kurulu bileşen diye envantere yazılmaz. Hex
  envanteri yalnız `mix.lock` haritasının üst düzeyindeki `:hex` tuple kayıtlarını kapsar; iç içe görünen tuple'lar
  paket sayılmaz. Eski üç alanlı tuple, güncel uzun tuple, çıplak/alıntılı atom ve string paket adı okunur.
  Yinelenen map anahtarında son değer geçerlidir; skaler üst düzey kayıt, eksik ayıraç, bozuk/dengesiz belge ve
  kayıt bütçesi aşımı kapalı başarısız olur.
  Git ve path bağımlılıkları paket sürümü sayılmaz.
- **Konteyner:** Eski BerkeleyDB/NDB rpm veritabanı paketleri henüz ayrıştırılmaz. Algılanan eski RPM
  veritabanı veya eksik paket envanteri `os_packages: na` ve yapılandırılmış
  `container.package_inventory` nedeni döndürür; OSV arşivi var diye yanlışlıkla `pass` verilmez. Zstd için
  güvenilir `/usr/bin/zstd` gerekir.
- **IaC:** Uzak modüllerin içi yalnız bilinen terraform-aws-modules girdileriyle değerlendirilir. Helm bilinmeyen
  koşulları en çok altı kontrol noktasında ayrı varyantlara açar; daha büyük şablonlarda kalan noktalar
  bilinmeyen kalır. Kubernetes proje ilişkileri dinamik/Helm şablonlarında kesin bağ iddiasında bulunmaz.
