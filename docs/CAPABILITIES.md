# Sniper Community v1 yetenekleri

Sniper Community, sahibi olduğunuz veya inceleme yetkinizin bulunduğu uygulama, API, web sitesi ve yazılım
tedarik zinciri için yerel-öncelikli bir savunma güvenliği araç takımıdır. Kaynak kodunu, yapılandırmayı,
bağımlılıkları, SBOM dosyalarını, konteyner arşivlerini ve desteklenen kayıtlı araç raporlarını inceler; sonuçları
CLI, loopback web arayüzü veya stdio MCP üzerinden insan incelemesine sunar.

Bu sayfa **v1.0.0 kaynak sözleşmesini** açıklar. Bir özelliğin katalogda bulunması, gerekli motorun veya verinin o
makinede hazır olduğu ya da bir dış hedef için izin bulunduğu anlamına gelmez.

## Yetenek etiketleri

| Etiket | Anlamı |
| --- | --- |
| **Yerleşik** | Kaynak ağacındaki Sniper kodu ve kurallarıyla çalışır; ayrı bir üçüncü taraf tarayıcı ikilisi gerektirmez. |
| **İsteğe bağlı yerel motor** | `COMMUNITY-TOOLS.lock.json` içindeki beş SHA-256 kontrollü motordan biridir. Kurulum, lisans kabulü ve çalışma zamanı hazırlığı gerekir. |
| **Önkoşullu** | Yerel OSV veritabanı, Nuclei kataloğu, ayrı bir araç, sentetik hesap, loopback servis veya yazılı hedef yetkisi gibi ek kanıt gerekir. Hazır değilse özellik kullanılabilir gösterilmez. |
| **Kayıtlı rapor** | Daha önce üretilmiş, desteklenen bir raporu sınırlar içinde ayrıştırır. Kaynak aracı çalıştırmaz ve rapordaki iddiaları bağımsız olarak doğrulamaz. |
| **İnsan/harici** | Katalog kontrolü uzman incelemesi veya Sniper dışında yürütülen yetkili bir çalışma ister. Otomatik Sniper sonucu değildir. |

## Kimler için

| Kullanıcı | Sniper ile yapabilecekleri | Uygun başlangıç girdisi |
| --- | --- | --- |
| Uygulama sahipleri | Kaynak kodu, sır kalıpları, veri akışları, kimlik/yetki kontrolleri, bağımlılıklar, lisanslar, IaC ve konteynerleri yerelde incelemek | İnceleme yetkinizin bulunduğu yerel proje klasörü |
| API sahipleri | Kod rotalarını ve OpenAPI sözleşmesini karşılaştırmak; kimlik doğrulama/yetkilendirme ipuçlarını, API şemasını ve desteklenen kayıtlı test raporlarını değerlendirmek | Kaynak kodu, OpenAPI/GraphQL şeması ve yalnız sentetik test verisi |
| Web sitesi sahipleri | Kaynak ve dağıtım yapılandırmasını incelemek; düşük etkili web/TLS kanıtını veya kayıtlı ZAP, Nuclei, TLS ve tarayıcı raporlarını değerlendirmek | Sahiplik ve yazılı kapsamı doğrulanmış hedef veya kayıtlı rapor |
| Geliştiriciler | CLI, LSP ve CI kalite kapısıyla değişiklikleri kontrol etmek; SARIF/GitLab raporu, SBOM ve VEX üretmek | Çalışma kopyası, kilit dosyaları ve proje politikası |
| Güvenlik ekipleri | Bulguları tekilleştirmek, karşılaştırmak, önceliklendirmek, sahip/son tarih atamak, tehdit modeli ve saldırı yolu üretmek, kayıtlı araç kanıtını bir araya getirmek | Yerel proje kanıtı, kayıtlı raporlar ve açık insan kararları |
| AI destekli inceleme yapan ekipler | MCP ile bulguları sorgulatmak ve öneri hazırlatmak; durum değiştiren işlerde aynı konuşmada tam planı görüp onaylamak | Güvenilir MCP istemcisi, gözden geçirilmiş veri paylaşım politikası ve ayrı Community verisi |

## Yerleşik proje analizi

### Kaynak kodu ve veri akışı

Sniper'ın hızlı veri akışı motorları derleyici gerektirmeden çalışır. Sonuçlar statik analiz önerisidir; çalışma
zamanı davranışının veya güvenliğin kanıtı değildir.

| Tür | Dil ve doğrulanmış çerçeve kapsamı | İncelenen akış ve yüzeyler |
| --- | --- | --- |
| **Yerleşik** | Python: Flask, Django, FastAPI, aiohttp, Tornado, Falcon, Chalice, Lambda; Jinja/Django şablonları | İşlevler ve dosyalar arası istek girdisi, saklanan veri ve şablon çıktıları |
| **Yerleşik** | JavaScript/TypeScript: Express, Koa, Fastify, Hono, NestJS, Next.js, React, MCP sunucuları; EJS/Pug/Handlebars/Nunjucks | Sabitlenmiş Babel ayrıştırıcısıyla sunucu/istemci girdileri ve tehlikeli hedefler |
| **Yerleşik** | Java/JSP: Servlet, Spring MVC/WebFlux, Struts2, JSP, Thymeleaf, JDBC/JPA/MyBatis | Rota, sorgu, şablon ve sunucu tarafı veri akışları |
| **Yerleşik** | Kotlin: Spring, Ktor, Javalin, http4k, gRPC, Android | Java motoru üzerinden kaynak-hedef akışları |
| **Yerleşik** | C#: ASP.NET Core, minimal API, Razor Pages/Blazor, WebForms, ASMX/WCF, EF/ADO.NET | Rota, görünüm, veri erişimi ve genel tür/çağrı bağlamı |
| **Yerleşik** | PHP: süper küreseller, PDO/mysqli, Twig/Smarty, Laravel, Symfony, CodeIgniter, Slim, WordPress | İstek girdisi, SQL/çıktı hedefleri ve WordPress yönetici bağlamı |
| **Yerleşik** | Go: `net/http`, gin, echo, fiber, chi, `database/sql`, GORM | İşlev değerleri dahil dosyalar arası akış ve saklanan veri |
| **Yerleşik** | Ruby: Rails, Sinatra, Grape, Hanami, Roda/Sequel, ActiveRecord | Rota, sorgu, görünüm ve saklanan veri akışları |
| **Yerleşik** | Rust: actix-web, axum, rocket, warp | Web girdileri, tehlikeli hedefler ve `unsafe`/FFI bilgi notları |
| **Yerleşik** | C/C++: `argv`, `getenv`, stdin, ağ ve CGI kaynakları | Komut, biçim dizgesi, SQL, yol ve bellek kopyalama/taşma hedefleri |

Kaynak-hedef sınıfları SQL ve komut enjeksiyonu, dinamik kod/eval, XSS/HTML, dosya yolu, SSRF, açık yönlendirme,
güvensiz serileştirme, XXE/ifade dili ve LDAP gibi desteklenen hedefleri kapsar. C/C++ ve Rust için hızlı bellek
güvenliği kontrolleri de bulunur. Sniper doğrulanmış akışları olası çok çağrılı akışlardan ayırır; akış yolu uygun
olduğunda SARIF `codeFlows` içinde taşınır. Yetki veya nonce kontrolü görülen yöntemler ayrıca işaretlenir.

### Kimlik, yetki, sır ve uzman denetçileri

| Tür | Denetim alanı | Neye bakar |
| --- | --- | --- |
| **Yerleşik** | Rota/yetki envanteri | Korumasız rota adayları (CWE-862), nesne kimliği kullanan IDOR adayları (CWE-639), rol ve nonce bağlamı |
| **Yerleşik** | Sır istihbaratı | Sağlayıcı kalıpları, entropi ve kaynak/yapılandırmadaki olası kimlik bilgileri; kanıtta sır değerini açık etmeden sınıflandırma |
| **Yerleşik** | Gizlilik veri akışı | Kişisel veri kaynaklarından günlük, yanıt, depolama veya üçüncü taraf hedeflerine giden KVKK/GDPR odaklı akışlar |
| **Yerleşik** | Ana makine sertleştirme | `sshd`, `sysctl`, `sudoers` ve desteklenen CIS yapılandırma sinyalleri |
| **Yerleşik** | DoS/ReDoS | Kaynak tüketimi, sınırsız işlem ipuçları ve felaket geri izlemeye açık düzenli ifadeler |
| **Yerleşik** | Denetim günlüğü | Güvenlik olayı kapsamı, günlük enjeksiyonu ve desteklenen hash-zinciri bütünlük örüntüleri |
| **Yerleşik** | Tarayıcı eklentisi/PWA | Manifest V3, Service Worker ve desteklenen tarayıcı ayrıcalık/yüzey yapılandırmaları |
| **Yerleşik** | Zero-trust/mesh | Kubernetes NetworkPolicy ile Istio, Linkerd ve Envoy yapılandırma ipuçları |
| **Yerleşik** | İş mantığı | İş akışı, yarış durumu/TOCTOU ve finansal bütünlük ipuçları; gerçek iş kuralı yine insan bağlamı ister |
| **Yerleşik** | Veritabanı güvenliği | SQL/ORM şeması, PostgreSQL RLS, PII ve şifreleme yapılandırma ipuçları |
| **Yerleşik** | Kripto/CBOM/PQC | Kriptografik envanter, algoritma/kullanım sinyalleri ve post-quantum hazırlık değerlendirmesi |
| **Yerleşik** | Web3/IoT | Solidity ve desteklenen gömülü sistem/firmware güvenlik örüntüleri |
| **Yerleşik** | AI/LLM | AI, RAG ve MCP kaynak/yapılandırmalarında OWASP LLM Top 10 odaklı ipuçları |
| **Yerleşik** | Bulut IAM/RBAC | AWS/GCP/Azure IAM, Kubernetes RBAC ve PodSecurity yapılandırma sinyalleri |
| **Yerleşik** | Protokol güvenliği | gRPC, WebSocket ve Webhook yapılandırma/uygulama örüntüleri |
| **Yerleşik** | Kimlik protokolleri | JWT, OAuth 2.0/OIDC ve SAML 2.0 artefaktları ve doğrulama ayarları |
| **Yerleşik** | OpenAPI güvenliği | Şema kontrolleri; kod rotasıyla karşılaştırıldığında gölge uç ve kimlik doğrulama uyuşmazlığı |
| **Yerleşik** | Masaüstü | Electron ve Tauri güvenlik yapılandırmaları |
| **Yerleşik** | Tedarik zinciri/SLSA | Derleme bütünlüğü, bağımlılık karışıklığı/typosquatting ve lisans ipuçları |
| **Yerleşik** | Mobil | Android, iOS, Flutter ve React Native manifest/yapılandırma yüzeyi; OWASP MASVS/Mobile Top 10 eşlemesi |
| **Yerleşik** | Web altyapısı | Kaynakta bulunan DNS ve e-posta güvenlik yapılandırma kanıtı |
| **Yerleşik** | Risk ve ilişkilendirme | CVSS 3.1/4.0 ve CISA SSVC önceliği, STRIDE/LINDDUN tehdit modeli, saldırı yolu korelasyonu ve savunma kuralı taslakları |

Bu denetçiler kaynak ve yapılandırmada gördükleri statik kanıta göre sonuç üretir. Örneğin “iş mantığı” satırı,
uygulamanın bütün iş kurallarının otomatik olarak anlaşıldığı anlamına gelmez.

### Altyapı kodu, bulut ve CI

| Tür | Girdi | Doğrulanmış kontrol alanları |
| --- | --- | --- |
| **Yerleşik** | Terraform ve yerel modüller | AWS/GCP/Azure ve belgelenmiş diğer sağlayıcılarda genel güvenlik duvarı/ACL, depolama görünürlüğü, bekleyen veri şifrelemesi, IMDSv2, herkese açık veritabanı, geniş IAM/`Principal`, KMS döndürme, CloudFront HTTP/eski TLS, CloudTrail, EKS/GKE/AKS, Lambda URL, seri konsol ve sabit sır ipuçları; değişken, tfvars, locals ve sınırlı yerel modül çıktı çözümü |
| **Yerleşik** | Kubernetes YAML ve kısmi Helm render | `privileged`, privilege escalation, host namespace/hostPath, tehlikeli capability, root UID, seccomp/AppArmor, sabitlenmemiş imaj, ortam sırrı, sertleştirme eksikleri, geniş RBAC ve cluster-admin bağları |
| **Yerleşik** | Kubernetes proje grafiği | Ingress/Gateway API route → Service → Workload → ServiceAccount → Role ilişkisi; NodePort/LoadBalancer/genel `externalIPs`, listener protokolü, namespace seçicisi ve `ReferenceGrant` koşulları |
| **Yerleşik** | Dockerfile/Containerfile | Sabitlenmemiş taban, `curl | sh`, root kullanıcı, uzak `ADD`, `sudo`, ENV/ARG sırrı, `chmod 777`, TLS/imza doğrulamasını kapatma, SSH portu ve HEALTHCHECK bilgisi |
| **Yerleşik** | docker-compose | Ayrıcalıklı/host ağ-PID-IPC, Docker soketi, capability, unconfined seccomp/AppArmor, ortam sırrı, sabitlenmemiş imaj ve root kullanıcı |
| **Yerleşik** | GitHub Actions/GitLab CI | Güvenilmeyen olay verisinin `GITHUB_ENV`, step/job output veya GitLab dotenv üzerinden sonraki komuta taşınması |
| **İsteğe bağlı yerel motor** | Trivy yapılandırma profilleri | Dockerfile, Terraform ve Kubernetes yanlış yapılandırma bulguları; yalnız motor hazırsa çalışır |

Yerleşik motor dosyaları çalıştırmaz ve ağ açmaz. Dinamik veya çözülemeyen Terraform/Helm değerlerini güvenli
varsaymak yerine bilinmeyen/kısmi olarak bırakır; desteklenmeyen sözdizimi “temiz” sonucu kanıtlamaz.

### Bağımlılıklar, SBOM, lisans ve tedarik zinciri

| Tür | Yetenek | Kapsam ve sınır |
| --- | --- | --- |
| **Yerleşik** | Bağımlılık envanteri | npm/yarn/pnpm; Python requirements, pip-tools, PEP 621/723/735, Poetry, uv, PDM, Pipfile, Conda, tox/Nox ve desteklenen paketleme biçimleri; Go modules; Maven/Gradle; RubyGems, Cargo, Composer, NuGet ve Hex kilitleri; alt dizin manifestleri |
| **Yerleşik + önkoşullu** | Çevrimdışı açık eşleme | Yerel, bütünlüğü doğrulanan OSV veritabanıyla npm, PyPI, Go, Maven, RubyGems, crates.io, Packagist, NuGet, Pub, Hex ve yapılandırılmış işletim sistemi ekosistemleri. Tarama ağsızdır; veri tabanı ayrıca hazırlanmalı ve bayatlık durumu izlenmelidir. |
| **Yerleşik** | Erişilebilirlik | Python, JavaScript, Go, Rust, Java/JVM ve .NET için içe aktarma ve çağrı kanıtıyla kullanılıyor/kullanılmıyor/geçişli/bilinmiyor bağlamı; yansıma ve otomatik yapılandırma nedeniyle Maven/NuGet sonucu kesin “etkisiz” sayılmaz. |
| **Yerleşik** | Öncelik | Önem, erişilebilirlik, düzeltme sürümü ve doğrudan/geçişli durumuyla 0–100 öncelik; kötü amaçlı paket daima 100 |
| **Yerleşik + önkoşullu veri** | Kötü amaçlı paket | Yerel OpenSSF `MAL-` ve GitHub malware kayıtları; bağımlılık karışıklığı, npm kurulum betiği ve özel kayıt deposu varlık sinyalleri |
| **Yerleşik + önkoşullu önbellek** | Lisans | Yerel manifest/paket önbelleklerinden lisans envanteri; izinli/dikkat/yasak/bilinmiyor politikası |
| **Yerleşik** | SBOM | CycloneDX 1.5 ve SPDX 2.3 JSON dışa aktarma; CycloneDX JSON/XML ve SPDX JSON/tag-value içe alma; dış SBOM için 32 MB ve 50.000 bileşen sınırı |
| **Yerleşik** | VEX | OpenVEX/CycloneDX VEX; `not_affected` ancak gerekçeli analist kararı, tedarikçi VEX'i veya paketin kilitte bulunmamasıyla verilir |
| **Kayıtlı rapor** | Harici SCA kanıtı | Trivy, OSV, npm audit ve Dependabot çıktılarının sınırlandırılmış özeti; rapor kaynağını yeniden çalıştırmaz |

### Konteyner ve artefakt analizi

| Tür | Girdi | İncelenen alan |
| --- | --- | --- |
| **Yerleşik + önkoşullu OSV verisi** | `docker save` tar, OCI image layout/tar, açılmış rootfs veya rootfs tar | Docker daemon ve ağ olmadan katman/manifest bütünlüğü; dpkg, apk ve desteklenen RPM SQLite paket envanteri; Debian, Ubuntu, Alpine/Wolfi/Chainguard, Alma/Rocky, RHEL, Amazon Linux, SLES/openSUSE eşlemesi |
| **Yerleşik** | Aynı konteyner girdileri | PyPI metadata, npm paketleri ve jar/war içindeki Maven bileşenleri; CycloneDX SBOM üretimi |
| **Yerleşik** | OCI/tar katmanları | SHA-256 ve boyut doğrulama; whiteout/opaque dizin semantiği; kök dışına çıkma, aygıt/FIFO ve güvensiz sembolik bağ engeli; dosya, katman ve toplam boyut bütçeleri |
| **Yerleşik** | İsteğe bağlı Dockerfile | Son aşamada kurulan/kaldırılan paketleri gerçek imaj envanteriyle ilişkilendirme |
| **İsteğe bağlı yerel motor + önkoşullu DB** | Trivy image profile | Ayrı sabitlenmiş çevrimdışı Trivy veritabanı hazırsa imaj zafiyet profili |

Eski BerkeleyDB/NDB RPM veritabanları tam ayrıştırılmıyorsa işletim sistemi paket kontrolü `pass` olmaz; neden
`na`/sınırlama olarak kalır.

### Web, API ve TLS

| Tür | Yetenek | Girdi ve kesin sınır |
| --- | --- | --- |
| **Yerleşik + yetkili hedef** | Sniper temel web taraması | TLS, HTTP güvenlik başlıkları, çerezler ve dönen sayfa üzerinde düşük etkili kontroller; yalnız sahip olunan veya açıkça yetkilendirilmiş hedef |
| **Yerleşik** | API sözleşme karşılaştırması | Yerel OpenAPI belgesi ile kaynak rotaları arasında gölge uç ve kimlik doğrulama uyuşmazlığı |
| **Önkoşullu** | Şema tabanlı API kanıtı | Schemathesis için sentetik loopback fixture veya operatörün izin verdiği yerel API'de sınırlandırılmış GET; motor hazır değilse yalnız kayıtlı JUnit özeti |
| **Yerleşik/önkoşullu** | Loopback TLS/X.509 | Sabitlenmiş CA ile `127.0.0.1` eşini doğrulayan açık onaylı OpenSSL yolu ve kayıtlı X.509 özetleri |
| **Önkoşullu + yetkili hedef** | Doğrudan X.509 | `POST /api/tool-runs/openssl-x509-authorized`, tam `{"confirm_authorized":true,"target":"https://HOST[:PORT]"}` gövdesi ve `authorized-tls-target-v1` onayı; sahiplik ve yazılı kapsam ayrıca gerekir |
| **Önkoşullu** | Diğer aktif web/TLS araçları | ZAP, testssl/SSLyze, Nmap, tarayıcı otomasyonu ve benzeri profiller yalnız ayrı çalışma zamanı hazırlığı ve hedef yetkisiyle görünür; beşli Community yerel motor profiline dahil değildir |
| **Yerleşik, bulguya bağlı** | Runtime proof | ASan öz testi ile yalnız desteklenen open-redirect, reflected-HTML, ASan binary ve compile-database bulgu rotaları; genel exploit çalıştırıcısı veya “temiz” güvenlik onayı değildir |

## 161 kontrol kataloğu nasıl okunur

Kamu kataloğu 19 başlıktaki **161 metodoloji kontrolünü** yerleşik denetim, isteğe bağlı/önkoşullu motor, kayıtlı
rapor veya insan incelemesine eşler. Aşağıdaki sayı, metodoloji envanteridir; tek bir analizde 161 otomatik kontrolün
çalıştığı, geçtiği veya hedefin güvenli olduğu anlamına gelmez.

| Tür | Kategori | Kontrol | Katalogdaki ana yürütme biçimi | Gerekli bağlam |
| --- | --- | ---: | --- | --- |
| **Katalog; karışık** | Bilgi toplama | 8 | Hibrit | Kapsam envanteri ve uygulama akışları |
| **Katalog; karışık** | Yapılandırma ve dağıtım | 9 | Yüksek otomasyon | URL, DNS, altyapı veya IaC erişimi |
| **Katalog; insan ağırlıklı** | Kimlik yönetimi | 5 | Uzman destekli | Sentetik kullanıcı ve kayıt/davet akışları |
| **Katalog; karışık** | Kimlik doğrulama | 13 | Hibrit | Sentetik hesap, MFA ve kurtarma senaryoları |
| **Katalog; insan ağırlıklı** | Yetkilendirme | 8 | Uzman destekli | En az iki rol, iki kullanıcı ve sentetik nesneler |
| **Katalog; karışık** | Oturum yönetimi | 8 | Hibrit | Sentetik oturumlar ve güvenli test verisi |
| **Katalog; yerleşik/opsiyonel/harici** | Girdi doğrulama | 15 | Yüksek otomasyon | Giriş noktaları, kaynak kodu ve API şeması |
| **Katalog; karışık** | Sunucu tarafı etkileşimler | 10 | Hibrit | Kaynak kodu, kontrollü test uçları ve gerektiğinde staging |
| **Katalog; karışık** | Hata yönetimi | 3 | Hibrit | Sentetik hata senaryoları ve günlük erişimi |
| **Katalog; yerleşik/opsiyonel/harici** | Zayıf kriptografi | 7 | Yüksek otomasyon | TLS uçları ve tercihen kaynak kodu |
| **Katalog; insan ağırlıklı** | Veri koruma ve mahremiyet | 9 | Uzman destekli | Veri sınıflandırması, sentetik veri ve kaynak kodu |
| **Katalog; insan ağırlıklı** | İş mantığı | 8 | Manuel ağırlıklı | Beklenen iş kuralları ve sentetik işlemler |
| **Katalog; karışık** | İstemci tarafı | 9 | Hibrit | Tarayıcı akışları ve istemci kaynak kodu |
| **Katalog; yerleşik/opsiyonel/harici** | API güvenliği | 13 | Yüksek otomasyon | OpenAPI/GraphQL şeması ve sentetik yetkilendirme |
| **Katalog; yerleşik/opsiyonel/harici** | Altyapı ve alan adı | 9 | Yüksek otomasyon | Kapsam içi ana makineler, DNS ve IaC |
| **Katalog; yerleşik/opsiyonel/rapor** | Tedarik zinciri | 8 | Yüksek otomasyon | Depo, kilit dosyaları, SBOM ve CI |
| **Katalog; önkoşullu/insan** | Kaynak ve dayanıklılık | 8 | Staging gerekli | Staging/lab, SLO ve gözlemlenebilirlik |
| **Katalog; yerleşik/rapor/insan** | Kayıt ve olay müdahalesi | 8 | Savunma sistemi gerekli | Uygulama, WAF, kimlik günlükleri ve alarm erişimi |
| **Katalog; harici/insan** | Özel onaylı doğrulamalar | 3 | Harici kanıt | Sentetik hesap veya staging; yalnız maskeli sonuç |

## Beş isteğe bağlı yerel motor

`python3 scripts/setup-community --accept-third-party-licenses` uygun Linux ARM64/x86-64 sistemlerde aşağıdaki
kilitli profili kurmayı dener. İndirilen artefakt tam SHA-256 değeriyle doğrulanır; doğrulanmamış veya eksik motor
“kurulu” gösterilmez. Üçüncü taraf lisansları Sniper'ın Apache-2.0 lisansından bağımsızdır.

### Nuclei 3.11.1 — MIT

- **Tür:** İsteğe bağlı yerel motor; geniş HTTP kullanımı ayrıca önkoşullu ve yetkili hedeftir.
- **Görev:** Şablon tabanlı HTTP/web denetimi.
- **Girdi:** Yerleşik profil için yalnız `127.0.0.1:<port>`; ayrı yetkili iş akışı için kapsamı onaylanmış HTTP(S)
  hedefi.
- **Önkoşul:** SHA-256 doğrulanmış ikili. Kurulumla gelen sabitlenmiş tek loopback şablonu yalnız yerel profil içindir;
  geniş HTTP çalışması ayrıca sabitlenmiş bir Nuclei kataloğu, çalışma zamanı hazırlığı ve açık insan onayı ister.
- **Çıktı sınırı:** Doğrulanmış JSONL kayıtlarından sınırlı özet ve rapor hash'i; kayıtlı JSONL ayrıca ayrıştırılabilir.
  Varsayılan kurulum geniş bir internet şablon koleksiyonu veya her zafiyet sınıfının tarandığı anlamına gelmez.

### Trivy 0.75.0 — Apache-2.0

- **Tür:** İsteğe bağlı yerel motor; zafiyet profilleri önkoşulludur.
- **Görev:** Bağımlılık/kilit dosyası, sır, image archive ve Dockerfile/Terraform/Kubernetes yapılandırma profilleri.
- **Girdi:** İzinli yerel proje kopyası, desteklenen kilit/manifest, yerel imaj arşivi veya IaC dosyası.
- **Önkoşul:** SHA-256 doğrulanmış ikili. Yapılandırma profilleri ikiliyle kullanılabilir; zafiyet profilleri ayrıca
  sabitlenmiş çevrimdışı Trivy veritabanı ister.
- **Çıktı sınırı:** Sınırlandırılmış JSON özeti, sayımlar ve rapor hash'i; sır içeriği ham biçimde yayımlanmaz.
  İkili tek başına güncel zafiyet kapsamı sağlamaz ve kayıtlı rapor özeti bulguları yeniden doğrulamaz.

### Gitleaks 8.30.1 — MIT

- **Tür:** İsteğe bağlı yerel motor.
- **Görev:** Yerel proje dosyalarında veya yerel Git geçmişinde sır kalıbı arama.
- **Girdi:** Kullanıcının HOME alanındaki açıkça seçilmiş proje; dosya profili sınırlandırılmış özel kopyayı, Git
  profili güvenli hazırlanmış yerel Git metaverisini inceler.
- **Önkoşul:** SHA-256 doğrulanmış ikili, ayrı yerel girdi onayı ve özel veri/lock dizini.
- **Çıktı sınırı:** Yüzde 100 redaksiyonla sayım, tetiklenen kural, etkilenen dosya ve rapor SHA-256 özeti; ham sır
  değeri veya ham rapor saklanmaz/döndürülmez. Dosya profilinde en çok 2.000 dosya, dosya başına 1 MB ve toplam
  25 MB hazırlama bütçesi uygulanır.

### TruffleHog 3.99.0 — AGPL-3.0

- **Tür:** İsteğe bağlı yerel motor.
- **Görev:** Yerel dosya sistemi veya güvenli hazırlanmış yerel Git geçmişinde sır adayları.
- **Girdi:** Açıkça onaylanan yerel proje ya da Git deposu.
- **Önkoşul:** SHA-256 doğrulanmış ikili, yerel girdi onayı ve hazır çalışma zamanı.
- **Çıktı sınırı:** Maskeli ve boyut sınırlı özet/rapor hash'i. Profil çevrimdışı çalışır ve bulunan kimlik
  bilgisini sağlayıcıya göndererek doğrulamaz; “doğrulandı” sonucu üretmez.

### Opengrep 1.30.1 — LGPL-2.1-only

- **Tür:** İsteğe bağlı yerel motor.
- **Görev:** Sniper'ın 39 kurallı yerel paketini kullanarak Python, JavaScript/TypeScript, Go ve Java kaynaklarında
  SQL/komut/kod enjeksiyonu, SSTI, yol aşımı, SSRF, açık yönlendirme, XSS, güvensiz serileştirme, zayıf
  hash/şifre, kapalı TLS doğrulaması, JWT imza hatası, sabit sır ve debug modu örüntülerini aramak.
- **Girdi:** İzinli yerel proje kaynakları.
- **Önkoşul:** SHA-256 doğrulanmış ikili ve değişmeden duran yerleşik kural paketi.
- **Çıktı sınırı:** En çok 200 bulguluk sınırlandırılmış özet; dosya yolları proje köküne göre göreli, ileti/CWE/kategori
  yerleşik kural paketinden gelir. `--taint-intrafile` aynı dosyadaki işlevler arasında akış izler; bu profil tam
  program veya bütün diller için derin veri akışı kanıtı değildir.

## Kayıtlı rapor içe alma

Bu yolların tamamı **Kayıtlı rapor** türündedir. Dosya şemasını, boyutunu ve kayıt sayısını sınırlar; uygun yerde
hash, sayım veya maskeli özet üretir. Hedefe bağlanmaz ve aşağıdaki araçları başlatmaz.

| Tür | Kaynak kanıt | Sniper'ın okuduğu yüzey |
| --- | --- | --- |
| **Kayıtlı rapor** | OWASP ZAP | Kayıtlı rapor özeti ve Automation Framework plan önizlemesi |
| **Kayıtlı rapor** | Burp Suite | Site map, handoff manifest ve Logger CSV özeti |
| **Kayıtlı rapor** | Semgrep/Opengrep | Native JSON özeti, kural envanteri ve TLS doğrulama filtresi |
| **Kayıtlı rapor** | CodeQL / OSV-Scanner | SARIF özeti |
| **Kayıtlı rapor** | Trivy | Native JSON ve çevrimdışı veritabanı tazelik özeti |
| **Kayıtlı rapor** | Schemathesis | JUnit XML özeti |
| **Kayıtlı rapor** | testssl.sh / SSLyze | Rapor ve hedef-sınırı sözleşmesi özeti |
| **Kayıtlı rapor** | Nmap | Kayıtlı tarama özeti |
| **Kayıtlı rapor** | Nuclei | JSONL ve doğrulama kapsamı özeti |
| **Kayıtlı rapor** | Gitleaks | JSON özeti |
| **Kayıtlı rapor** | TruffleHog | JSONL ve sır doğrulama paketi yapısal özeti |
| **Kayıtlı rapor** | npm audit | JSON özeti ve salt-okunur bağımlılık düzeltme planı |
| **Kayıtlı rapor** | Dependabot | Kaydedilmiş uyarı ve çevrimdışı senkronizasyon özeti |
| **Kayıtlı rapor** | SSL Labs | Kaydedilmiş ana makine JSON'u ve önbellek sözleşmesi |
| **Kayıtlı rapor** | OpenSSL | Tekli/toplu X.509 özeti |
| **Kayıtlı rapor** | Playwright | JSON özeti |
| **Kayıtlı rapor** | k6 | Klasik `handleSummary` veya machine-readable v1 JSON özeti |
| **Kayıtlı rapor** | SIEM | ECS JSONL kanıt özeti |

## Bulgular, raporlar ve kalite kapıları

| Tür | Yetenek | Çıktı |
| --- | --- | --- |
| **Yerleşik** | Bulgu takibi | Satır kaymasına dayanıklı parmak izi; yeni/açık/sürüyor/düzeldi/yeniden açıldı/yanlış alarm/risk kabulü; sahip, son tarih ve yorum |
| **Yerleşik** | Analiz farkı ve “yalnız değişenler” | Git referansı veya önceki analiz tabanı; yeni/değişmeyen bulgu bağlamı ve kısmi tarama uyarısı |
| **Yerleşik** | Raporlama | JSON, HTML; desteklenen yerel PDF yolu; Türkçe/İngilizce proje ve yönetici özeti |
| **Yerleşik** | CI kalite kapısı | Ağsız proje analizi + çevrimdışı SCA; SARIF 2.1.0, GitLab SAST/dependency JSON, Markdown/JSON karar; grup eşiği, `new_only`, süreli istisna ve baseline |
| **Yerleşik** | SBOM/VEX | CycloneDX, SPDX, OpenVEX ve CycloneDX VEX |
| **Yerleşik** | Portföy/SLA | Projeler arası alan riski, haftalık eğilim, MTTR ve önem tabanlı son tarih politikası |
| **Yerleşik** | Editör yolu | stdio LSP ile tanılama, CWE/IaC kimliği, parmak izi ve editörün uygulayacağı sınırlı hızlı düzeltme önerisi |

CI kapısının `0` çıkışı yalnız tanımlı politikanın o koşuda karşılandığını söyler; güvenlik sertifikası değildir.

## AI-first MCP, CLI ve yerel web

### MCP ile AI destekli kullanım

MCP sunucusu newline-delimited JSON-RPC'yi yalnız alt sürecin stdin/stdout hattında konuşur; HTTP/TCP dinleyicisi
açmaz. Community modu varsayılan olarak ayrı kullanıcı verisi oluşturur:

```text
command: /ABSOLUTE/PATH/TO/Sniper/.venv/bin/python
args: /ABSOLUTE/PATH/TO/Sniper/scripts/sniper-mcp --mode community
```

AI bulguları ve sınırlı proje bağlamını inceleyebilir, öneri hazırlayabilir ve desteklenen eylemler için plan
oluşturabilir. Durum değiştiren işlem iki çağrılıdır:

1. `prepare_action` değişmez planı, kapsamı, etkileri, son kullanımı ve `plan_sha256` değerini döndürür.
2. İnsan aynı konuşmada gösterilen tam planı açıkça onaylarsa istemci aynı plan/hash ile `execute_action` ve
   `user_confirmed: true` gönderir.

Plan tek kullanımlı ve sürelidir. Ancak `user_confirmed: true`, MCP hostunun beyanıdır; Sniper konuşmayı
kriptografik olarak göremez. Kötü niyetli bir istemci yalan söyleyebilir. Bu yüzden yalnız güvenilir istemci kullanın;
model çıktısını otomatik onaylamayın ve hedef sahipliğini ayrıca doğrulayın.

MCP sürecinin yerel olması modelin yerel olduğu anlamına gelmez. İstemci kaynak parçalarını, bulguları ve
metadata'yı sağlayıcıya gönderebilir. Kurumsal kaynak paylaşım kuralını ve sağlayıcının saklama/eğitim ayarını önce
inceleyin; token, özel anahtar, müşteri verisi veya üretim veritabanı paylaşmayın.

### Manuel CLI

AI istemcisi zorunlu değildir:

```bash
.venv/bin/python scripts/sniper-project-audit /ABSOLUTE/PATH/TO/YOUR_PROJECT
.venv/bin/python cli_reports.py --help
```

İlk komut yerel projeyi analiz eder ve doğrulanabilir JSON raporunu stdout'a yazar. Daha geniş CLI; proje analizi,
SBOM/VEX, image/rootfs, çevrimdışı OSV, CI kapısı, kayıtlı bulgu/rapor ve uzman denetçi komutlarını listeler.

### Loopback web arayüzü

Ayrı bir veri diziniyle yalnız loopback üzerinde başlatın:

```bash
export SNIPER_DATA_DIR="$PWD/.local-data"
.venv/bin/python server.py
```

Arayüz varsayılan olarak `http://127.0.0.1:8787` adresindedir. Motor kartları ve formlar çalışma zamanı hazırlığına
göre üretilir; eksik, doğrulanmamış veya desteklenmeyen motor kullanılabilir görünmez. Portu genel arayüze
yayınlamayın. Uzaktan erişim gerekiyorsa önce Sniper kimlik doğrulamasını açın ve incelenmiş TLS reverse proxy veya
kimliği doğrulanmış tünel kullanın.

## Güvenli hızlı başlangıç

Önkoşul: Python 3.12, incelenmiş bir kaynak checkout'u ve yalnız size ait/yetkili bir test projesi.

1. Üçüncü taraf lisanslarını [`COMMUNITY-TOOLS.lock.json`](../COMMUNITY-TOOLS.lock.json) içinde inceleyin. Ardından
   köksüz ortamı kurun:

   ```bash
   python3 scripts/setup-community --accept-third-party-licenses
   ```

   Bu komut `.venv` oluşturur, tam sürümlü Python kilitlerini ve beşli yerel motor profilini kurar/doğrular, MCP ve
   proje-audit yardım girişlerini sınar. Veritabanı açmaz, web sunucusu veya tarayıcı başlatmaz. Hava boşluklu
   kurulumda hazırlanmış `--wheelhouse` ve `--tool-cache-dir` kullanın.

2. Kurulumu ve komut yüzeyini dış hedefe bağlanmadan kontrol edin:

   ```bash
   .venv/bin/python scripts/sniper-mcp --help
   .venv/bin/python scripts/sniper-project-audit --help
   ```

3. Yalnız açıkça yetkili yerel proje klasörünü analiz edin:

   ```bash
   .venv/bin/python scripts/sniper-project-audit /ABSOLUTE/PATH/TO/YOUR_PROJECT
   ```

4. İsterseniz MCP istemcinize [`examples/mcp/stdio-community.json`](examples/mcp/stdio-community.json) örneğini
   uyarlayın veya yukarıdaki loopback web yolunu kullanın. AI eylem planını çalıştırmadan önce hedefi, kapsamı,
   etkileri ve veri paylaşımını okuyun.

Kurulum veya yardım kontrolü bir tarama değildir. Bir web sitesi, API ya da IP üzerinde işlem yapmadan önce sahiplik,
yazılı kapsam, zaman aralığı, hız sınırı, veri işleme ve durdurma koşullarını doğrulayın.

## Doğrulama kanıtı

[`VALIDATION.md`](../VALIDATION.md) içindeki **2026-10-24** Community v1.0.0 yayın adayı anlık görüntüsü:

| Kanıt kapısı | Gözlenen sonuç |
| --- | --- |
| Community metadata/yayın yüzeyi | PASS — 43 gerekli yayın dosyası |
| Deterministik kaynak oluşturma ve release-tree taraması | PASS |
| Python `unittest` launcher | 2.812 test, 0 hata, 0 başarısızlık |
| Python `pytest` modülleri | 204 geçti |
| JavaScript/Node testleri | 432 geçti, 0 başarısızlık |
| Kilitli araç kurulumu smoke | PASS — Linux ARM64 için beş araç çevrimdışı cache'den kurulup yeniden doğrulandı; tarayıcı çalıştırılmadı |
| Tek komut çevrimdışı setup smoke | PASS — parse edilebilir JSON, beş köken-bağlı araç ve iki gerçek help entrypoint |
| Beş dilli gerçek Chromium düzeni | PASS — masaüstü/mobil 10/10 görünüm |
| Platform ve yayın-sırrı kapıları | PASS — Linux/macOS/Windows politika yolları ile `.env`/anahtar dışlama sözleşmeleri |
| Compose yapılandırması | Varsayılan ve lisans-kapılı tools override yerelde PASS |
| Community container build | Önceki main core build PASS; bu aday başlığı için yeni PR CI bekleniyor |
| CodeQL | PR #7 Actions, JavaScript/TypeScript ve Python işleri PASS; dal ve PR ref'lerinde açık alarm 0 |

Bu sayılar ürünün bulduğu açık sayısı değildir ve yalnız o kaynak anlık görüntüsü/fixture'ları için geçerlidir.
Gelecek commitler test toplamlarını değiştirebilir; bir motorun CI'da veya başka mimaride atlanması o motora ilişkin
çalışma kanıtı değildir.

## Sniper'ın yapmadığı ve garanti etmediği şeyler

- Her güvenlik açığını bulduğunu, yanlış alarm üretmediğini veya temiz sonucun güvenlik sertifikası olduğunu garanti
  etmez.
- 161 katalog kontrolünü tek komutta otomatik olarak çalıştırmış veya geçmiş saymaz; bazı kontroller ayrı motor,
  kayıtlı rapor, sentetik hesap, staging ya da uzman kararı ister.
- Eksik ikiliyi, katalogu veya zafiyet veritabanını hazırmış gibi göstermez. Trivy ikilisi veritabanının; Nuclei
  ikilisi geniş şablon kataloğunun yerine geçmez.
- Rapor içe almak kaynak aracı çalıştırmaz, hedef yetkisi oluşturmaz veya rapordaki bulgunun gerçekliğini kanıtlamaz.
- İnsan onay kutusu ya da MCP plan onayı yasal hedef yetkisi oluşturmaz. İzniniz olmayan sistemleri taramayın.
- stdio MCP'yi ağsız model garantisi olarak sunmaz; dış AI istemcisi veriyi sağlayıcısına gönderebilir.
- Sınırlı runtime-proof rotalarını genel exploit motoru veya açık bulunmadığına dair kanıt olarak kullanmaz.
- Bilinmeyen/dinamik IaC, ayrıştırılamayan bağımlılık veya desteklenmeyen paket veritabanını “temiz” kabul etmez;
  sınırlama, kısmi sonuç veya `na` olarak raporlar.
- AI önerisini uzman kararı yerine koymaz. Bulguyu güvenli bir ortamda yeniden üretin ve düzeltme kararını yetkili
  bir insanın incelemesinden geçirin.

## Sözleşme kaynakları

- Genel ürün ve güvenlik sınırı: [`README.md`](../README.md)
- Yeniden üretilebilir kanıt: [`VALIDATION.md`](../VALIDATION.md)
- Kilitli motorlar ve lisanslar: [`COMMUNITY-TOOLS.lock.json`](../COMMUNITY-TOOLS.lock.json) ve
  [`COMMUNITY-TOOLS.md`](COMMUNITY-TOOLS.md)
- MCP onay/gizlilik sözleşmesi: [`COMMUNITY-MCP.md`](COMMUNITY-MCP.md)
- Kullanıcı, API ve format sözleşmeleri: [`KULLANIM-KILAVUZU.md`](KULLANIM-KILAVUZU.md)
- IaC, konteyner ve SBOM ayrıntıları: [`IAC-MOTORU.md`](IAC-MOTORU.md),
  [`KONTEYNER-TARAMA.md`](KONTEYNER-TARAMA.md), [`SBOM.md`](SBOM.md)
- CI kalite kapısı: [`CI-KAPISI.md`](CI-KAPISI.md)
- Yerel dağıtım: [`DEPLOYMENT.md`](../DEPLOYMENT.md)
- Katalog ve gerçek rota sözleşmeleri: [`methodology.py`](../methodology.py), [`tool_catalog.py`](../tool_catalog.py)
  ve [`server.py`](../server.py)
- Çalıştırılabilir regresyon sözleşmeleri: [`tests/`](../tests/)
- Güvenlik açığı bildirim süreci: [`SECURITY.md`](../SECURITY.md)
