# Sniper Community

[English](../README.md) | **Türkçe** | [日本語](README.ja.md) | [简体中文](README.zh-CN.md) | [한국어](README.ko.md)

[ConverserAI proje özeti](https://converserai.com/#sniper) · [Yetenekler](CAPABILITIES.md) · [Kurulum](#kaynak-koddan-kurulum) · [Sık sorulan sorular](#sık-sorulan-sorular)

Sniper Community; uygulama, API ve web sitesi geliştiren, sahibi olan veya bunları inceleyen ekipler için açık kaynak,
yerel öncelikli ve savunma amaçlı bir uygulama güvenliği araç setidir. Desteklenen kaynak kodları statik uygulama
güvenliği testi (SAST) ile, bağımlılık manifestlerini ve SBOM dosyalarını yazılım bileşen analizi (SCA) ile, konteyner
çıktılarını, kod olarak altyapıyı (IaC), CI yapılandırmasını ve kaydedilmiş güvenlik raporlarını tek bir inceleme
akışında birleştirir. Size ait veya açıkça yetkilendirilmiş bir web/API hedefi için insan incelemesine sunulmak üzere
kapsamı sınırlandırılmış çalışma zamanı eylem planları hazırlayabilir. Sonuçlara yerel stdio MCP üzerinden bir yapay zekâ
istemcisiyle, komut satırı (CLI) aracılığıyla veya yerel loopback web arayüzünden ulaşabilirsiniz.

## Yetenek etiketleri

`Uygulama Güvenliği` · `SAST` · `SCA` · `SBOM` · `IaC Güvenliği` · `API Güvenliği` · `Web Sitesi Güvenliği` ·
`Mobil Güvenlik` · `Android` · `iOS` · `IDOR` · `Yetkilendirme` · `GraphQL` · `Rails` · `Spring` · `ASP.NET` ·
`Kubernetes` · `Helm` · `Terraform` · `Konteyner Güvenliği` · `CI/CD Güvenliği` · `Yazılım Tedarik Zinciri` ·
`SLSA` · `OCI Kökeni` · `Syft` · `Grype` · `Fuzzing` · `Bellek Güvenliği` · `MCP` · `Yapay Zekâ Güvenliği` ·
`SARIF` · `OpenVEX` · `GHSA` · `CVSS` · `SSVC` · `Sır Tespiti` · `Gizlilik` · `Statik Analiz` ·
`Çalışma Zamanı Kanıtı` · `Çoklu Depo Analizi` · `Güven Grafikleri` · `Artifact Kökeni` · `Protokol Güvenliği` ·
`Arşiv ve Sembolik Bağ Güvenliği` · `İkili Sertleştirme` · `DevSecOps` · `Yerel Öncelikli`

Sniper Community v1.1 şu alanlarda daha derin ve incelenebilir kapsam ekler:

- **Çerçeveler arası erişim denetimi:** Desteklenen Rails kalıtımını, Spring ve ASP.NET rotalarını, GraphQL
  resolver'larını, nesne kimliklerini, yetkilendirme anotasyonlarını, ilkeleri, rolleri, sahipleri ve kiracıya bağlı
  sorguları ilişkilendirir.
- **Çoklu depo güven grafikleri:** Desteklenen HTTP/OpenAPI, webhook, Kafka, kimlik doğrulama sözleşmesi, GraphQL,
  tam PyPI bağımlılığı, CI artifact'i ve yeniden kullanılabilir iş akışı ilişkilerini özel uç noktaları veya kimlik
  bilgilerini döndürmeden haritalar.
- **Sınırlandırılmış fuzz ve çalışma zamanı kanıtı:** C/C++, Rust, Go, Python, Java ve JavaScript/TypeScript için
  incelenebilir fuzz hedefleri hazırlar; desteklenen isteğe bağlı yürütme yollarında açık runtime sabitlemeleri, ağ
  yalıtımı, kaynak sınırları ve kapalı kalan hazırlık durumları uygular.
- **Tedarik zinciri ve platform incelemesi:** Desteklenen OCI/SLSA kökenini, SBOM/VEX kanıtını, Kubernetes, Helm,
  Terraform, konteyner, şema migration, CI/CD güveni, arşiv, sembolik bağ, protokol ve ikili sertleştirme sinyallerini
  inceler.
- **Yapay zekâ destekli savunma akışları:** Durum değiştiren eylemleri gösterilen plan ve açık insan onayı
  sözleşmesinin arkasında tutarken yerel stdio MCP ile yanıt karşılaştırma, yetki matrisi, token sıralama, trafik
  çözümleme, GHSA/OpenVEX hazırlama ve bounty hazırlık incelemesi sunar.
- **Kanıta dayalı önceliklendirme:** Desteklenen bulguları SARIF kod akışları, CVSS 3.1/4.0, CISA SSVC,
  erişilebilirlik, saldırı yolları, sahiplik, baseline ve iyileştirme odaklı kalite kapılarıyla ilişkilendirir.

## Yayına çıkmadan önce inceleyin

**Güçlü ve açık kaynak bir araç setiyle web sitenizdeki güvenlik açıklarını bulun.** Yetkilendirilmiş web sitesi ve API
taramalarını yerel kaynak kod ve bağımlılık incelemesiyle birleştirin; bulguları önceliklendirilmiş bir iyileştirme
planına dönüştürün. Harici taramalar ilgili motorları, verileri, hazırlık kontrollerini ve açık kapsam onayını
gerektirir; sınırsız bir tarama servisi değildir. Bkz. [web sitesi ve API inceleme yolu](USE-CASES.md#plan-an-authorized-website-or-api-action).

Yayın öncesinde uygulamanızı incelemesi için bir yapay zekâ asistanından destek alın. Sniper'ın yerel stdio MCP akışı
sayesinde yapay zekâ desteklenen güvenlik incelemesine rehberlik edebilir, bulguları kod kanıtlarıyla açıklayabilir ve
düzeltme önceliklendirmesine yardımcı olabilir; aynı sonuçlar web arayüzünde, CLI'da ve CI çıktılarında da
kullanılabilir kalır.

Android, iOS, Flutter ve React Native projelerinde desteklenen kaynak kodunu, mobil manifestleri, API yollarını,
sırları, bağımlılıkları, SBOM verilerini ve CI yapılandırmasını tek bir yayın öncesi kontrol görünümünde bir araya
getirin. İster **App Store veya Google Play gönderimi**, ister **web sitesi veya API lansmanı**, isterse **pull request**
hazırlıyor olun; Sniper kullanıcılar sürümü almadan önce tamamlanması gereken güvenlik çalışmalarını görünür kılar.

## Sniper neleri incelemenize yardımcı olur?

| Alan | Sniper'ın yanıtlamanıza yardımcı olduğu sorular |
| --- | --- |
| Kaynak kod ve yapılandırma | Hangi desteklenen kod yolları, güvenlik örüntüleri, sırlar ve yapılandırma tercihleri insan incelemesi gerektiriyor? |
| Yetkilendirme ve IDOR incelemesi | Desteklenen hangi Python veya JavaScript/TypeScript rotalarında yetkilendirme kontrolü eksik olabilir (CWE-862) veya görünür bir kullanıcı/rol bağlaması olmadan nesne kimliği yüklenerek IDOR incelemesi gerekiyor (CWE-639)? |
| Bağımlılıklar ve SBOM | Hangi bileşenler mevcut, birbirleriyle nasıl ilişkili ve yerel güvenlik açığı kanıtları ne söylüyor? |
| Konteynerler ve yazılım tedarik zinciri | Desteklenen yerel çıktılarda hangi paketler, katmanlar, manifestler, köken sinyalleri ve riskli derleme tercihleri görülüyor? |
| Altyapı ve CI/CD | Desteklenen Terraform, Kubernetes, Helm, Dockerfile, Compose, bulut IAM veya CI iş akışı girdileri bilinen riskli ayarları açıkta bırakıyor mu? |
| Kaydedilmiş güvenlik raporları | Desteklenen SARIF ve araç raporları doğrulanıp sınırlandırılarak tek bir inceleme akışında özetlenebilir mi? |
| Yetkilendirilmiş web sitesi ve TLS iş akışları | Harici bir işlemden önce insan tarafından doğrulanması gereken tam hedef, kapsam, onay, hazırlık ve durdurma koşulları nelerdir? |

Kanıt bağlantılı tam envanter [Yetenekler ve güvenlik kontrolleri](CAPABILITIES.md) belgesindedir. Uygulama, API, web
sitesi, platform ve güvenlik ekipleri için pratik inceleme yolları [Kullanım senaryoları](USE-CASES.md) belgesinde yer
alır. Yapay zekâ sistemleri kompakt [LLM proje dizini](../llms.txt) ile başlayabilir; kullanıcılar ise en güncel
[doğrulama kanıtlarını](../VALIDATION.md) inceleyebilir.

## Güvenlik incelemesi öne çıkanları

- **Yüksek etkili veri akışlarını izleyin:** SQL ve komut enjeksiyonu, XSS/HTML, SSRF, açık yönlendirme (open redirect),
  dizin aşımı (path traversal), güvensiz seriden çıkarma (unsafe deserialization), XXE, ifade dili (EL) ve LDAP riskleri
  için desteklenen kaynaktan-hedefe (source-to-sink) akışları takip edin. Desteklenen akış kanıtları geliştirici
  araçlarında incelenmek üzere SARIF `codeFlows` çıktısıyla taşınabilir.
- **Erişim kontrolü testlerine odaklanın:** Rotaları, nesne kimliklerini, rolleri ve görünür sahiplik kontrollerini
  yetkilendirilmiş manuel sızma testleri için önceliklendirilmiş CWE-862 ve IDOR (CWE-639) aday listesine dönüştürün.
- **Açığa çıkmış sırları ve gizlilik yollarını bulun:** Sağlayıcı desenlerini ve entropi sinyallerini loglara, yanıtlara,
  depolamaya ve üçüncü taraf hedeflere giden gizlilik odaklı veri akışlarıyla birleştirirken sır değerlerini maskelenmiş
  (redacted) tutun.
- **Bağımlılıkları ve yazılım tedarik zincirini anlayın:** Doğrudan ve geçişli bileşenlerin envanterini çıkarın,
  CycloneDX/SPDX SBOM üretin veya içe aktarın, VEX ile çalışın, erişilebilirlik (reachability) bağlamını inceleyin ve
  yerel güvenlik açığı kanıtlarını yayın kararlarına dahil edin.
- **Konteynerleri, bulutu ve teslimat hatlarını sıkılaştırın:** Desteklenen konteyner arşivlerini, Dockerfile, Terraform,
  Kubernetes, Helm, Compose, bulut IAM, CI iş akışları, tarayıcı eklentileri, mobil manifestler ve masaüstü uygulama
  güvenlik yapılandırmalarını tek bir inceleme yüzeyinden denetleyin.
- **API'leri, web sitelerini ve TLS'i inceleyin:** Yerel OpenAPI sözleşmelerini kaynak kod rotalarıyla karşılaştırın,
  kimlik doğrulama uyumsuzluklarını inceleyin, desteklenen web güvenliği sinyallerini değerlendirin ve size ait veya
  yetkilendirilmiş hedefler için kapsamı sınırlandırılmış eylemler hazırlayın.
- **Önemli işleri önceliklendirin:** Bulguları CVSS 3.1 ve CVSS 4.0, CISA SSVC, saldırı yolu korelasyonu, sahiplik, son
  tarihler, temel çizgiler (baselines) ve kalite kapıları (quality gates) ile zenginleştirerek kanıttan iyileştirmeye
  hızla geçin.
- **Size uygun iş akışını seçin:** JSON, HTML, SARIF, GitLab, SBOM, VEX ve desteklenen PDF çıktılarıyla yerel loopback
  web arayüzünü, betiklenebilir CLI'ı, CI çıktılarını veya yapay zekâ destekli inceleme için stdio MCP'yi kullanın.

## IDOR ve manuel sızma testi desteği

Sniper, desteklenen kaynak kodunu yetkilendirilmiş manuel sızma testleri için odaklanmış bir kontrol listesine
dönüştürür. Yerleşik rota ve yetkilendirme envanteri, korumasız rota adaylarını (CWE-862) ve olası Güvensiz Doğrudan
Nesne Referansı (IDOR) yollarını (CWE-639) işaretleyerek incelemeciyi ilgili dosyaya, rotaya ve kod satırına
yönlendirir. Böylece test uzmanı yapılandırılmamış bir uç nokta listesinden başlamak yerine ayrı test kullanıcıları,
roller ve sentetik nesnelerle uygulamalı kontrolleri önceliklendirebilir.

Her aday kanıt odaklı manuel doğrulama için paketlenir. Yetkilendirilmiş test kapsamı dahilinde incelemeciler; ağ
geçidi (gateway), ara katman (middleware), politika servisi ve iş mantığı kontrollerini dikkate alarak farklı
kullanıcılar ve roller arasındaki çalışma zamanı davranışını doğrulayabilir.

Sniper kaynak ağacında yerleşik analizörleri ve rapor ayrıştırıcılarını içerir. Root yetkisi gerektirmeyen yerel profili
ek olarak sürümü sabitlenmiş beş isteğe bağlı üçüncü taraf motoru kurabilir: **Nuclei**, **Trivy**, **Gitleaks**,
**TruffleHog** ve **Opengrep**. Yerleşik analizler bağımsız olarak kullanılabilir; isteğe bağlı bir motor veya profil
yalnızca çalışma zamanı, veri ve lisans hazırlık kontrollerini geçtikten sonra kullanılabilir olarak gösterilir.

Yerel loopback arayüzü ve HTML raporları kaynak dil olarak Türkçeyi kullanır ve İngilizce temel paketin yanı sıra
genişletilmiş Japonca, Basitleştirilmiş Çince ve Korece paketleri sunar. Eksik bir CJK girdisi varsa önce İngilizceye,
yoksa özgün Türkçe kaynağa döner. CJK düzenleri masaüstü ve mobil Chromium görünümlerinde test edilmiştir. Bkz.
[yerelleştirme kapsamı ve dil paketi güncellemeleri](LOCALIZATION.md).

Bu depo Community yayın yüzeyini sunar. Kurumsal (Enterprise) özel teslimat kodu desteklenen bir Community ürün yüzeyi
olarak dahil edilmemiştir. Ticari hizmetler, barındırılan operasyon, destek taahhütleri, müşteriye bağlı lisanslama,
özel yükleyiciler ve yerel ikili teslimat uygulaması Community kapsamı dışındadır.

## Sürüm durumu

Bu depo Sniper Community v1.1.0 kaynak sürümüdür. `COMMUNITY_VERSION` kaynak sürüm işaretçisidir; yayınlanan etiketler
bununla `v<sürüm>` biçiminde eşleşmelidir. Kaynak kodu Apache License 2.0 altında lisanslanmıştır. Bkz.
[LICENSE](../LICENSE).

## Neler dahildir?

- Desteklenen kaynak kod, altyapı, bağımlılık ve konteyner girdileri için yerel proje analizi.
- Yerel raporlar ve kalite kapısı (quality-gate) komutları.
- Bulguları incelemek ve öneriler sunmak için yapay zekâ öncelikli stdio MCP iş akışı.
- Durum değiştiren yapay zekâ eylemleri için sohbet aracılı insan onay sınırı.
- Döngüde bir yapay zekâ istemcisi istemeyen kullanıcılar için manuel CLI ve yerel web seçenekleri.
- Testler, depoya dahil kural/veri varlıkları ve katkıcı belgeleri.

Sniper savunma amaçlı bir yardımcıdır; bir sistemin tamamen güvenli olduğunun kanıtı değildir. Bulgular, temiz sonuçlar
ve yapay zekâ önerileri insan incelemesi gerektirir.

## Kaynak koddan kurulum

**macOS Apple Silicon** üzerinde hem **yerel kaynak kurulumu (`python3 scripts/setup-community --core-only`)** hem de
**beş motorlu Docker Desktop profili (`./scripts/deploy-community-tools --accept-third-party-licenses`)** gerçek macOS
donanımında test edilmiş, doğrulanmış ve desteklenmektedir (macOS kurulumu deneysel değildir). Kaynak koddan kullanım
için test edilen yorumlayıcı Python 3.12'dir. Tam yerel Community v1 kurulumu ve kilitli beş isteğe bağlı motoru Linux
ARM64 ve Linux x86-64 üzerinde desteklenir. **Windows** üzerinde Sniper; yerel `--core-only` kaynak kurulumunu
(`python3 scripts/setup-community --core-only`), WSL2'yi ve Docker Desktop Linux konteynerlerini destekler. Bu kaynak
sürümü pip ile kurulan bir paket değildir; depoya dahil giriş noktalarını depo kök dizininden çalıştırın. Root yetkisi
gerektirmeyen kurulum komutu `.venv` oluşturur, tam sürümlü çalışma zamanı bağımlılıklarını ve kilitli yerel araç
profilini kurar, ardından Sniper'ı veya bir tarayıcıyı başlatmadan gerçek MCP ve proje denetimi yardım giriş noktalarını
doğrular:

```bash
python3 scripts/setup-community --accept-third-party-licenses
```

Bu bayrak `COMMUNITY-TOOLS.lock.json` içinde kayıtlı üçüncü taraf lisanslarını incelediğinizi onaylar; kurulum bunları
hiçbir zaman örtük olarak kabul etmez. Hazırlanmış çevrimdışı girdiler için `--wheelhouse` ve `--tool-cache-dir`
kullanın. Kurulum bir veritabanı açmaz, web servisini başlatmaz veya tarama çalıştırmaz.

İsteğe bağlı Linux motor ikilileri olmadan Linux, macOS veya Windows yerel çekirdek (`--core-only`) kaynak kurulumu için:

```bash
python3 scripts/setup-community --core-only
```

Windows/macOS Docker Desktop veya WSL2 için varsayılan Compose dosyası çekirdek imajı derler. İsteğe bağlı beş motorlu
imaj, derlenmesi üçüncü taraf lisans onayını gerektiren ayrı ve açık bir profildir:

```bash
docker compose build sniper
python3 scripts/build-community-tools-image --accept-third-party-licenses
```

Her iki derleme komutu da bir tarayıcı başlatmaz. Tam sınırlar için [dağıtım ve platform desteğine](../DEPLOYMENT.md)
bakın. macOS üzerinde beş yerel motor ön kontrolünün tamamını derleyen, başlatan ve doğrulayan kontrollü başlangıç için
`./scripts/deploy-community-tools --accept-third-party-licenses` komutunu çalıştırın; bir Mac kaynak projesini kalıcı
Docker hacmine kopyalamak için `./scripts/import-community-project /mutlak/proje/yolu --name proje-adi` komutunu
kullanın.

Kurulumdan sonra MCP yardım giriş noktası doğrudan şu şekilde kullanılabilir:

```bash
.venv/bin/python scripts/sniper-mcp --help
```

Mevcut bir Python ortamı içinde yalnızca desteklenen yerel araçları yönetmek için:

```bash
python3 scripts/install-community-tools --profile local --accept-third-party-licenses
```

Dahil edilen motorlar, çevrimdışı önbellek kullanımı ve ayrı çalışma zamanı veya lisans gereksinimleri karşılanana kadar
kullanılamaz kalması gereken profiller için [docs/COMMUNITY-TOOLS.md](COMMUNITY-TOOLS.md) belgesine bakın.

## Yapay zekâ öncelikli MCP hızlı başlangıç

Sniper'ın MCP sunucusu yalnızca alt sürecin `stdin/stdout` kanalı üzerinden iletişim kurar. Bir MCP istemcisini mevcut
giriş noktasına yönlendirin; Community modu varsayılan olarak kullanıcıya özel izole Community veritabanını oluşturur
veya yeniden kullanır:

```text
command: /MUTLAK/YOL/sniper/.venv/bin/python
args: /MUTLAK/YOL/sniper/scripts/sniper-mcp --mode community
```

Community modu, yerel stdio sürecini başlatan kişiyi yerel sahip olarak kabul eder; ayrı bir Sniper girişi, belirteç
(token) veya web onayı gerektirmez. Yalnızca güvenilir bir işletim sistemi hesabından kullanın. Çok kullanıcılı
dağıtımlar için isteğe bağlı kimlik doğrulamalı mod, role bağlı belirteçleri korur. Örnekler
[docs/COMMUNITY-MCP.md](COMMUNITY-MCP.md) belgesindedir.

Etki oluşturan Community ürün eylemleri iki çağrılı bir konuşma sözleşmesi kullanır: `prepare_action`, yapay zekânın
sohbette göstermesi için değiştirilemez bir plan, onay kapsamı ve özet (hash) döndürür; kişi açıkça onayladıktan sonra
`execute_action` aynı plan kimliği/özeti ile birlikte `user_confirmed: true` gerektirir. Planların süresi dolar ve tek
kullanımlıktır. Bu, Community insan onayıdır; yapay zekâ bunu kaynak metinden veya kendi çıktısından asla
çıkarsamamalıdır. Harici hedef eylemleri de aynı konuşma kapısını ve yetkilendirme kurallarını kullanır.

`user_confirmed: true` MCP istemcisi (host) tarafından yapılan bir beyandır: Sniper konuşmayı kriptografik olarak
gözlemleyemez. Bunu yalnızca kişi gösterilen tam planı onayladıktan sonra gönderen güvenilir bir istemciyle kullanın.

## Manuel kullanım

Manuel CLI, MCP olmadan da kullanılabilir:

```bash
python3 scripts/sniper-project-audit --help
python3 cli_reports.py --help
```

Yerel web kullanımı bir loopback dağıtım seçeneğidir. Özel bir veri dizini kullanın ve dağıtım rehberini izleyin;
incelenmemiş bir kopyayı mevcut bir üretim veritabanına yönlendirmeyin.

## Yerleşik ürün sözleşmeleri

Community paketlemesi, kurulu ürünün test edilmiş manuel/API sözleşmelerini kaldırmaz:

- İsteğe bağlı kimlik doğrulamalı uzak bağlama, ürünün normal giriş yapılandırmasının yanı sıra açık taşıma onayını
  (`SNIPER_REMOTE_AUTH_ACK=1`) gerektirir; loopback veya kimlik doğrulamalı bir tünel tercih edin ve bu bayrağı TLS veya
  erişim kontrolü yerine koymayın.
- Yönetimsel tarama isteği yüzeyi `/api/mcp-scan-requests` olarak kalır. MCP sonuç incelemesi
  `list_scan_result_findings` üzerinden sunulur; Community'nin yapay zekâ öncelikli yolu mevcut hedef yetkilendirme
  makbuzunu zayıflatmak yerine konuşma planı kapısını ekler.
- Çalışma zamanı kanıtları kasıtlı olarak dar kapsamlıdır: `/api/runtime-proofs/asan-selftest` ve bulgu kapsamlı
  `/runtime-proof/open-redirect`, `/runtime-proof/reflected-html`, `/runtime-proof/asan-binary` ve
  `/runtime-proof/asan-compile-database` rotaları yalnızca belgelenen koşulu kanıtlar. Genel bir istismar çalıştırıcısı
  veya güvenlik sertifikası değildir.
- Kör kıyaslama (blind benchmark) hazırlığı `scripts/prepare_ground_truth.py` adresinde açık bir geliştirici iş akışıdır;
  beklenen yanıtlar analizör yürütmesinden ayrılmıştır.

Yetkilendirilmiş OpenSSL sözleşmesi, tam olarak `{"confirm_authorized":true,"target":"https://HOST[:PORT]"}` istek biçimi
ve `authorized-tls-target-v1` onay sürümü ile `POST /api/tool-runs/openssl-x509-authorized` rotasıdır. Gerçek rotayı
kullanmak sahiplik, yazılı kapsam ve yukarıdaki açık insan onayını gerektirir.

## Veri gizliliği

Sniper uygulama durumunu yerel olarak saklar ve MCP sürecinin kendisi ağ dinleyicisi açmaz. Bu, harici bir yapay zekâ iş
akışının çevrimdışı olduğu anlamına **gelmez**: bir MCP istemcisi bulguları, kaynak kod kesitlerini, istemleri ve üst
verileri kendi model sağlayıcısına gönderebilir. Proje erişimini etkinleştirmeden önce sağlayıcının veri saklama
politikasını ve kurumunuzun kaynak paylaşım kurallarını inceleyin. Sorun bildirimlerine (issues) asla belirteç, parola,
özel anahtar, müşteri verisi veya üretim veritabanı dosyaları eklemeyin.

## Sorumlu güvenlik kullanımı

Sniper'ı yalnızca size ait olan veya değerlendirme için açıkça yetkilendirildiğiniz sistemlerde kullanın. Harici hedef
eylemlerinden önce hedef sahipliğini, yazılı kapsamı, zamanlamayı, hız sınırlarını, veri işleme kurallarını ve durdurma
koşullarını doğrulayın. Bir insan bu gerçekleri doğrulayıp sohbet aracılı onayı verene kadar yapay zekâ tarafından
oluşturulan istekleri çalıştırmayın.

Güvenlik Sorumlusu (Security Maintainer): **Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline)). Özel
güvenlik açığı bildirimi için [SECURITY.md](../SECURITY.md), rol sözleşmesi için
[SECURITY-MAINTAINERS.md](../SECURITY-MAINTAINERS.md) ve geliştirme kuralları için
[CONTRIBUTING.md](../CONTRIBUTING.md) belgelerine bakın. Topluluk yardım sınırları [SUPPORT.md](../SUPPORT.md), halka
açık değişiklikler [CHANGELOG.md](../CHANGELOG.md) ve araştırma atıf bilgileri [CITATION.cff](../CITATION.cff)
içindedir.

### Gökçe Baran Karakamış — macOS Kurulum Doğrulaması ve Sniper ile Taranan Depolar Raporu

**Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline)) tarafından gerçekleştirilen **macOS (Apple Silicon) gerçek donanım kurulum ve çalışma doğrulaması** (hem yerel kaynak kurulumu `python3 scripts/setup-community --core-only` hem de 5 motorlu Docker Desktop kurulumu `./scripts/deploy-community-tools --accept-third-party-licenses`) ile **Sniper** tarafından taranan **8 açık kaynak deponun** ayrıntılı kanıt denetimi, yanlış pozitif ayrımı ve saldırı zinciri (*chaining*) analizi aşağıda özetlenmiş ve tam rapor olarak [SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md](SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md) ve [VALIDATION.md](../VALIDATION.md) belgelerinde yayınlanmıştır.

> **Önemli Metodoloji ve Sorumlu Bildirim Notu:** Statik analizde tehlikeli bir fonksiyonun (`exec`, `pickle.loads`, `subprocess.Popen`) veya CI/CD deseninin varlığı tek başına doğrulanmış bir ürün CVE'si anlamına gelmez. Bir bulgunun istismar edilebilir açık sayılması için varsayılan/desteklenen dağıtımda **erişilebilirlik**, **güven sınırı (trust boundary) aşımı** ve **saldırgan önkoşulları** birlikte kanıtlanmalıdır. Koordine güvenlik bildirimi (Coordinated Vulnerability Disclosure / CVE-GHSA) süreci devam eden projelere ait bulgular, sorumlu bildirim ilkeleri gereği yamalar yayınlanana kadar bu halka açık listede paylaşılmamaktadır.

| Repo | Sniper SAST / IaC / SCA Özeti | Doğrulanmış Kaynak Kanıtı & Kodda Zafiyete Dönüşüm Analizi | Günlük Hayat Senaryoları (`Senaryo A / B / C`) & Birleşme (Chaining) | Birlikte Kritiklik & Doğrulama Komutu |
| :--- | :--- | :--- | :--- | :--- |
| **1. `autogpt`** | `93` eşik aşan (`2K / 39Y`); `142` triyaj | **2 kritik SQLi (`obj.execute`), JWT ve FastAPI `Security()` yanlış pozitif**; `jobstore_backfill.py:99` `pickle.loads(row.job_state)` + Compose sabit parola (`RABBITMQ_DEFAULT_PASS`) + Root Dockerfile gerçek | **A)** İç ağda varsayılan Compose parolasıyla DB'ye erişen saldırgan `apscheduler_jobs.job_state` sütununa zararlı pickle yükü yazar ve root konteynerde RCE elde eder.<br/>**B)** Yedek/göç (migration) veritabanı dosyasının değiştirilmesiyle geri yükleme anında `jobstore_backfill.py` üzerinden kod çalıştırılır.<br/>**C)** `:latest` imaj etiketi ve root konteyner birleşimiyle yan kanal sızıntısı büyür. | **ORTA / YÜKSEK (Koşullu — DB Yazma Varsa)**<br/>`python3 scripts/sniper-project-audit ./autogpt` |
| **2. `zitadel`** | `67` eşik aşan (`8K / 42Y`); `286` triyaj | **8 kritik SQLi/`exec` yanlış pozitif** (`pgx` parametreli sarmalayıcı); `deploy/compose/` altında 3 `docker.sock` bağlaması, dokümantasyon ters vekil örneğinde `NODE_TLS_REJECT_UNAUTHORIZED=0` ve `WithInsecure()` gerçek | **A)** Operatör `deploy/compose/` örneğini üretimde `/var/run/docker.sock` bağlı bırakırsa konteyner ele geçirildiğinde konak makinede root yetkisine çıkılır.<br/>**B)** Ters vekil örneğindeki `NODE_TLS_REJECT_UNAUTHORIZED=0` ayarının üretime kopyalanmasıyla OIDC/OAuth oturum trafiğine MITM yapılır.<br/>**C)** `cfg.Insecure = true` ile açık bırakılan OTLP telemetri hattından iç izleme verileri şifresiz akar. | **DÜŞÜK / ORTA (Örnek Dağıtım Sertleştirmesi)**<br/>`python3 scripts/sniper-project-audit ./zitadel` |
| **3. `nextcloud-mcp`** | `59` eşik aşan (`SAST 1K/6Y`, `IaC 7Y`, `SCA 5K/40Y`) | **`token_utils.py` JWT ve `login_flow.py:192` `poll_endpoint` SSRF %100 yanlış pozitif** (`initiate()` satır 130 `_rewrite_to_nextcloud_host` ile origin'i sabitler); `pact.yml:93` `--branch "${{ github.head_ref }}"` `same-repo` korumalı | **A)** Depoda dal açma yetkisi olan bir hesap özel karakterli dal adıyla `pact.yml:93` içinde kabuk komutu çalıştırabilir (dış fork'lara kapalıdır).<br/>**B)** Yerel geliştirme ortamındaki sabit Keycloak/Greenmail kurulum sırları dış ağa açılırsa test hesapları ele geçirilir.<br/>**C)** `uv.lock` içindeki eski `pillow`/`cryptography`/`pyjwt` bağımlılıkları üzerinden bilinen CVE'ler tetiklenir. | **DÜŞÜK / ORTA (İç CI & SCA)**<br/>`python3 scripts/sniper-project-audit ./nextcloud-mcp` |
| **4. `mcpjam-inspector`** | `122` eşik aşan (`SAST 12K/8Y`, `SCA 6K/96Y`) | **20 K/Y SAST bulgusunun 18'i (%90) yanlış pozitif** (14 JSDoc yorumu, 2 `.d.ts`, 2 UI etiketi); `pr-preview.yml:116` `echo "branch=${{ github.event.pull_request.head.ref }}"` `same-repo` korumalı | **A)** Depo içi yazma/dal açma yetkisi olan bir hesap `pr-preview.yml:116` üzerinden `$GITHUB_OUTPUT` ve kabuk ortamını manipüle edebilir (dış fork PR'lar engellidir).<br/>**B)** Değerlendirme (eval) çalıştırıcısındaki dinamik işlevlerin izole edilmemesi halinde kiracı ortamında kod çalışır.<br/>**C)** `package-lock.json` içindeki `handlebars` ve `shell-quote` bağımlılık açıkları zincirlenir. | **DÜŞÜK / ORTA (İç CI & SCA)**<br/>`python3 scripts/sniper-project-audit ./mcpjam-inspector` |
| **5. `codebase-memory-mcp`** | `32` eşik aşan (`SAST 17K/7Y`, `SCA 8Y`) | **`store.c:2864` SQLi, `c_lsp.h:54` yorum, `kotlin_lsp.c`/`py_lsp.c` boyutlu tampon yanlış pozitif**; `http_server.c:668` `GET /api/browse?path=...` yalnız `localhost` CORS ve `Host` (403) korumalı | **A)** `--ui` modu açıkken aynı makinedeki başka bir yerel süreç `http://127.0.0.1:<port>/api/browse?path=/` ile dizin yapısını listeleyebilir (tarayıcıdan yabancı site erişimi CORS/Host ile engellidir).<br/>**B)** SSH tüneli veya ters vekil ile `--ui` portu yanlışlıkla dış ağa açılırsa sunucu dizin ağacı görünür olur.<br/>**C)** `graph-ui/package-lock.json` içindeki önyüz paketlerinin güncellenmemesi geliştirme ortamı riski oluşturur. | **DÜŞÜK (Yerel Servis Sınırı)**<br/>`python3 scripts/sniper-project-audit ./codebase-memory-mcp` |
| **6. `gitlab-mcp-server`** | `5` eşik aşan (`0K / 4Y`) | `recorder.go:84` ve `make.go:35` yanlış pozitif (`exec.Command("git", args...)` kabuksuz); `internal/gitlab/client.go:1416` `GITLAB_MCP_SKIP_TLS_VERIFY=true` yalnızca kullanıcı seçerse aktif | **A)** Geliştirici kendi imzalı (self-signed) kurum içi GitLab sunucusu için `GITLAB_MCP_SKIP_TLS_VERIFY=true` açtığında ortak Wi-Fi/VPN ağında MITM ile GitLab PAT token'ı çalınır.<br/>**B)** CI/CD ortamında bu bayrak kalıcı bırakıldığında sahte GitLab API yanıtlarıyla MCP ajanına zararlı veri enjekte edilir.<br/>**C)** PR etiket iş akışında `pull_request_target` yapılandırması ileride `checkout` eklenirse risk oluşturur. | **DÜŞÜK (Opsiyonel Ayar)**<br/>`python3 scripts/sniper-project-audit ./gitlab-mcp-server` |
| **7. `apktool-mcp`** | `16` eşik aşan (`SAST 1 Orta`, `SCA 4K / 12Y`) | SAST gizlilik uyarıları yanlış pozitif; **`uv.lock` içinde 4 kritik, 12 yüksek SCA bağımlılık kaydı var** (`starlette 0.46.2`, `h11 0.14.0`, `fastmcp 2.2.0`, `mcp 1.6.0`) | **A)** Zararlı/bozuk APK analiz edilirken eski `starlette`/`h11` HTTP ayrıştırıcı açıkları üzerinden MCP sunucusunda hizmet reddi (DoS) veya istek kaçakçılığı yaşanır.<br/>**B)** Eski `mcp`/`fastmcp` sürümlerindeki oturum ve doğrulama eksiklikleri yerel ajan köprüsünü etkiler.<br/>**C)** Güncellenmemiş `certifi`/`anyio` paketleri taşıma katmanı güvenilirliğini düşürür. | **DÜŞÜK / ORTA (SCA Bağımlılık Riski)**<br/>`python3 scripts/sniper-project-audit ./apktool-mcp` |
| **8. `jadx-mcp`** | `32` eşik aşan (`SAST 3 Orta`, `SCA 6K / 26Y`) | Doğrulanmış kritik/yüksek SAST açığı yok; **`uv.lock` içinde 6 kritik, 26 yüksek SCA bağımlılık kaydı var** (`authlib 1.6.8`, `cryptography 46.0.5`, `pyjwt 2.11.0`, `python-multipart 0.0.20`, `starlette 0.47.3`, `urllib3 2.5.0`) | **A)** Çok parçalı (multipart) dosya/APK yükleme uç noktalarında eski `python-multipart` ve `starlette` sürümleri üzerinden bellek/CPU tükenmesi (DoS) tetiklenir.<br/>**B)** Eski `authlib` ve `pyjwt` sürümlerindeki doğrulama zafiyetleri kimlik doğrulamalı MCP dağıtımlarında token kontrolünü zayıflatır.<br/>**C)** `urllib3` yönlendirme başlığı sızıntısı ve `cryptography` CVE'leri dış bağlantıları riske atar. | **DÜŞÜK / ORTA (SCA Bağımlılık Riski)**<br/>`python3 scripts/sniper-project-audit ./jadx-mcp` |

Her deponun dosya/satır düzeyindeki tam kanıt incelemesi, `Senaryo A / B / C` ayrıntıları, örnek çalıştırma komutları ve macOS doğrulama detayları için: [SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md](SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md).

#### Kendi Sniper Taramamızda Bulduğumuz Doğrulanmış Açıklar

**Sniper** statik/dinamik analiz motoru ile yürüttüğümüz güvenlik taramalarında tespit edilen, **Açığın Kodda Nasıl Oluştuğu ve Zafiyete Dönüştüğü**, **Adım Adım 3 Farklı Günlük Hayat Kritik Senaryosu (`Senaryo A / B / C`)**, **Örnek Çalıştırma Komutları** ve **Uçtan Uca Çalışma Zamanı Kanıtları (`RED -> GREEN + BENIGN`)** ile kanıtlanan **11 güvenlik açığı** ([advisories/README.tr.md](advisories/README.tr.md) ve [SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md](SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md)) aşağıda yayımlanmıştır:

| # | Açık / Advisory & Upstream GHSA | Hedef Proje & Bileşen | CWE & CVSS v3.1 | Açığın Kodda Nasıl Oluştuğu & Günlük Hayatta Yol Açtığı 3 Kritik Senaryo (`Senaryo A / B / C`) | Çalışma Zamanı Kanıtı (`RED -> GREEN`) & Örnek Komut |
| :-: | :--- | :--- | :--- | :--- | :--- |
| **01** | [`01-STIRLING-CAND-02-SYMLINK.md`](advisories/tr/01-STIRLING-CAND-02-SYMLINK.md)<br/>`GHSA-hpc7-xx5r-gc44` | **Stirling-Tools/Stirling-PDF** (`<= 3.2.2`)<br/>`FolderInputSource.java:337-377`<br/>`FolderOutputSink.java:338-345` | `CWE-59` / `CWE-61`<br/>**7.1 High** | **Kodda Oluşumu:** Varsayılan `recursive=false` modunda `Files.isRegularFile(entry)` (`LinkOption.NOFOLLOW_LINKS` olmadan) sembolik bağları takip ederken, `FolderAccessGuard.isProtected` yalnızca sembolik bağın sözcüksel (lexical) yolunu kontrol eder.<br/>**Senaryo A:** Kurumsal SMB/NFS ortak tarayıcı klasörüne bırakılan `invoice.pdf -> ../configs/settings.yml` sembolik bağı üzerinden admin parolası ve OAuth sırları ortak çıktı klasörüne sızdırılır.<br/>**Senaryo B:** SFTP/Nextcloud dış iş ortağı yükleme klasöründeki sembolik bağ ile sunucu `.env` veya SSH anahtarları okunur.<br/>**Senaryo C:** Çok kiracılı (multi-tenant) paylaşımlı hacimde departmanlar arası gizli belgeler ve yerel H2 veritabanı sızdırılır. | `RED`: `symlink_accepted: true, protected_settings_exfiltrated: true`<br/>`GREEN`: `symlink_accepted: false`<br/>`pytest -k test_stirling_cand02` |
| **02** | [`02-STIRLING-CAND-01-WEASYPRINT-SSRF.md`](advisories/tr/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)<br/>`GHSA-ff6j-8xch-j8r6` | **Stirling-Tools/Stirling-PDF** (`<= 3.2.2`)<br/>`ConvertWebsiteToPDF.java:116-143` | `CWE-918`<br/>**8.6 High** | **Kodda Oluşumu:** `CVE-2026-71270` yaması `FileToPdf.java` içinde WeasyPrint'i `--allowed-protocols data` ile kısıtlarken, `/api/v1/convert/url/pdf` (`ConvertWebsiteToPDF.java`) hâlâ `--allowed-protocols data,http,https` kullanır ve `customHtmlSanitizer` çağırmaz.<br/>**Senaryo A:** Fatura/makbuz URL'sini PDF'e çeviren SaaS özelliğine verilen dış sayfadaki `<link rel="stylesheet" href="http://169.254.169.254/...">` bulut IAM anahtarlarını PDF içine basar.<br/>**Senaryo B:** Kurumsal intranet üzerindeki iç mikroservis (`http://127.0.0.1:8080/actuator/env`) yanıtları üretilen PDF üzerinden dışarı sızdırılır.<br/>**Senaryo C:** Otomatik uyumluluk/arşivleme iş akışlarında üçüncü taraf sayfasındaki alt kaynaklar üzerinden iç ağ verileri arşivlenen PDF'e gömülür. | `RED`: `internal_data_embedded_in_pdf: true`<br/>`GREEN`: `internal_loopback_hit_count: 0`<br/>`pytest -k test_stirling_cand01` |
| **03** | [`03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md`](advisories/tr/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)<br/>`GHSA-cp36-x5hg-3gg8` | **trycua/cua** (`npm: cuabot <= 1.0.16`)<br/>`libs/cuabot/src/cuabotd.ts` | `CWE-306` / `CWE-942`<br/>**9.6 Critical** | **Kodda Oluşumu:** `cuabotd.ts` arka planda `0.0.0.0:7842` portunu kimlik doğrulamasız açar, tüm yanıtlara `Access-Control-Allow-Origin: *` ekler ve konak `~/.cuabot/user/.claude` dizinini yazılabilir bağlar.<br/>**Senaryo A:** Geliştirici `cuabot` açıkken herhangi bir web sitesini ziyaret ettiğinde sayfadaki JS `fetch("http://localhost:7842/bash")` ile komut çalıştırıp Claude OAuth kimlik bilgilerini çalar.<br/>**Senaryo B:** Ziyaret edilen web sayfası `ws://localhost:7842/?command=...` (CSWSH) üzerinden `.claude/settings.json` içine kalıcı `PreToolUse` kancası (hook) yerleştirir.<br/>**Senaryo C:** Kafe, ortak çalışma alanı veya ofis Wi-Fi ağındaki (`0.0.0.0:7842`) herhangi bir cihaz doğrudan `http://<lan-ip>:7842/bash` ve `/screenshot` çağırarak bilgisayarı ele geçirir. | `RED`: `http_status: 200, mounted_host_claude_credentials_exfiltrated: true`<br/>`GREEN`: `http_status: 403`<br/>`pytest -k test_cua_cand01` |
| **04** | [`04-CUA-CAND-02-WORKER-SERVER-RCE.md`](advisories/tr/04-CUA-CAND-02-WORKER-SERVER-RCE.md)<br/>`GHSA-xm8w-gj3g-4f25` | **trycua/cua** (`pip: cua-bench-rl <= 0.1.0`)<br/>`worker_server.py:79-108, 338-360` | `CWE-94` / `CWE-942`<br/>**8.8 High** | **Kodda Oluşumu:** `worker_server.py` `allow_origins=["*"]` kullanır, `ip_filter_middleware` tarayıcıdan `127.0.0.1`'e gelen çapraz kökenli istekleri engellemez ve `OSGYM_ALLOWED_IPS=""` boş olduğunda filtre fail-open olur; `POST /reset` ise verilen `env_path/main.py` dosyasını `spec.loader.exec_module` ile çalıştırır.<br/>**Senaryo A:** Araştırmacı tarayıcıda bir web sayfası açtığında `fetch("http://127.0.0.1:8001/reset")` ile indirilen bir klasördeki `main.py` konak Python sürecinde çalıştırılır.<br/>**Senaryo B:** Kubernetes/Docker Compose ortamında `OSGYM_ALLOWED_IPS=""` boş bırakıldığında tüm küme/LAN üzerinden `0.0.0.0:8001/reset` ile uzaktan kod çalıştırılır.<br/>**Senaryo C:** `/screenshot` ve `/step` uç noktaları üzerinden masaüstü ekran görüntüleri izlenir ve klavye/fare komutları enjekte edilir. | `RED`: `arbitrary_env_path_exec_module_rce: true`<br/>`GREEN`: `403 / 400, rce: false`<br/>`pytest -k test_cua_cand02` |
| **05** | [`05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md`](advisories/tr/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)<br/>`GHSA-3x8g-6h2v-8qx9` | **trycua/cua** (`cargo: cua-compat <= 0.8.0`)<br/>`daytona/objectstore.rs:320-422` | `CWE-22`<br/>**8.1 High** | **Kodda Oluşumu:** `object_path(&key)` anahtar üzerinde `..` kontrolü yaparken `?uploadId=` parametresi doğrulanmaz ve `Method::DELETE` dalı `uploads.remove(&id)` sonucuna bakmadan `tokio::fs::remove_dir_all(root.join("uploads").join(&id))` çalıştırır.<br/>**Senaryo A:** Çok kiracılı (multi-tenant) ortamda tek bir sandbox kiracısı `DELETE /daytona/x?uploadId=../objects` göndererek tüm kurumun sandbox imajlarını tek istekle siler.<br/>**Senaryo B:** `?uploadId=../../...` ile `d.objects.root` dışına çıkılarak `cua-spacesd` sürecinin yazabildiği konak dizinleri ve veritabanı dosyaları silinir.<br/>**Senaryo C:** `Method::PUT` (`UploadPart`) üzerinde `?uploadId=..&partNumber=1` kullanılarak üst dizinlere keyfi parça dosyaları yazılır. | `RED`: `objects_store_wiped_without_prior_upload: true`<br/>`GREEN`: `objects_store_preserved: true`<br/>`pytest -k test_cua_cand03` |
| **06** | [`06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md`](advisories/tr/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)<br/>`GHSA-54v9-fxw3-36mm` | **trycua/cua** (`cargo: cua-media-codec <= 0.8.0`)<br/>`videotoolbox/mod.rs:308-420` | `CWE-125` / `CWE-190`<br/>**5.5 Medium** | **Kodda Oluşumu:** Safe Rust `VtEncoder::encode` -> `pixel_buffer_for` içinde `FrameData::Nv12` (`y` ve `uv` dilimleri) ve `FrameData::Bgra` üzerinde dilim boyutu kontrol edilmeden `unsafe { std::ptr::copy_nonoverlapping }` çağrılır.<br/>**Senaryo A:** macOS uzak masaüstü yayınında pencere/çözünürlük değişimi sırasında kısa kalan `NV12` tamponu yüzünden bitişik heap belleğindeki `960` baytlık sırlar H.264 video karesine kopyalanıp karşı tarafa yayınlanır.<br/>**Senaryo B:** Bozuk veya boş bir `VideoFrame` geldiğinde `cua-spacesd` medya servisi `SIGSEGV` ile çökerek tüm uzak masaüstü oturumlarını düşürür.<br/>**Senaryo C:** Küçük `y_stride < width` / `uv_stride < row_bytes` değerleriyle yanlış hizalanmış bellek okunarak yığın verileri video akışına sızdırılır. | `RED`: `oob_bytes_read: 960, adjacent_heap_secret_copied_to_video_frame: true`<br/>`GREEN`: `oob_bytes_read: 0`<br/>`pytest -k test_cua_vt01` |
| **07** | [`07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md`](advisories/tr/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)<br/>`GHSA-hvhg-6x47-cq96` | **trycua/cua** (`pip: cua-bench <= 0.3.1`)<br/>`winarena_adapter/cli.py:262-265` | `CWE-668` / `CWE-732`<br/>**8.6 High** | **Kodda Oluşumu:** `cli.py` Docker konteynerini başlatırken `-p 8006:8006` (şifresiz noVNC) ve `-p 3390:3389` (parolasız RDP) portlarını `0.0.0.0` üzerinde açar ve konak `setup_path` dizinini `-v {setup_path}:/shared` olarak yazılabilir bağlar.<br/>**Senaryo A:** Üniversite/ofis ağındaki herhangi bir kişi `http://<ip>:8006` adresini tarayıcıda açarak Windows VM masaüstünü ve içindeki API anahtarlarını şifresiz ele geçirir.<br/>**Senaryo B:** VM içine giren saldırgan `/shared` (`setup_path`) bağlaması üzerinden konak makinedeki kurulum betiklerini değiştirerek konak işletim sistemine sıçrar.<br/>**Senaryo C:** VM içindeki `server/main.py:180` (`POST /execute_windows` -> `exec()`) kimlik doğrulamasız çalıştığı için ajan zararlı bir sayfa açtığında VM içinde tam komut çalıştırılır. | `RED`: `lan_exposed_ports: ["8006:8006", "3390:3389"]`<br/>`GREEN`: `lan_exposed_ports: []`<br/>`pytest -k test_cua_cand06` |
| **08** | [`08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md`](advisories/tr/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)<br/>`GHSA-qwv8-hh9r-cqrf` | **openziti/ziti** (`github.com/openziti/ziti/v2`)<br/>`ziti/util/certs.go:91-103, 199-208` | `CWE-295`<br/>**7.4 High** | **Kodda Oluşumu:** `ziti edge login` içindeki `AreCertsTrusted()`, `InsecureClient(&client, certs)` içinde koşulsuz `InsecureSkipVerify: true` bıraktığı için Go `crypto/tls` `RootCAs` havuzunu yok sayar ve `x509.UnknownAuthorityError` kontrolünü ölü kod (dead code) haline getirir.<br/>**Senaryo A:** Yönetici `ziti edge login` çalıştırdığında araya giren (MITM) saldırganın sahte sertifikası *"Verified that server supplied certificates are trusted"* mesajıyla kabul edilir ve admin parolası saldırgana gönderilir.<br/>**Senaryo B:** CI/CD boru hattında otomatik sıfır-güven kimlik kaydı yapan iş yükleri sahte Edge Controller'a bağlanarak üretim servis token'larını sızdırır.<br/>**Senaryo C:** Çoklu ortam (`dev`/`staging`/`prod`) operasyonlarında süresi dolmuş veya yanlış CA imzalı kontrolcü sertifikası uyarı vermeden kabul edilir. | `RED`: `rogue_mitm_cert_accepted_as_trusted: true`<br/>`GREEN`: `x509.UnknownAuthorityError`<br/>`pytest -k test_ziti_cand01` |
| **09** | [`09-N8N-CAND-01-WEBHOOK-REDOS.md`](advisories/tr/09-N8N-CAND-01-WEBHOOK-REDOS.md)<br/>`n8n-io/n8n` | **n8n-io/n8n** (`npm: n8n-workflow <= 2.45.0`)<br/>`string-extensions.ts:94, 326, 375` | `CWE-1333`<br/>**5.3 Medium** | **Kodda Oluşumu:** `string-extensions.ts` içindeki `isEmail()`, `extractDomain()` ve `extractEmail()` fonksiyonları uzunluk sınırı olmadan başlangıç çıpasız ve iç içe nicelleyicili regex'leri tek iş parçacıklı Node.js ana döngüsünde çalıştırır.<br/>**Senaryo A:** Dışa açık müşteri iletişim/kayıt Webhook'una gönderilen 20 KB'lık tek bir JSON isteği Node.js olay döngüsünü ~832 ms kilitleyerek aynı sunucudaki tüm Stripe ödeme ve Slack webhook'larını durdurur.<br/>**Senaryo B:** Gelen destek e-postalarını veya sohbet mesajlarını `{{ $json.text.extractEmail() }}` ile ayrıştıran akış kilitlenip Kubernetes sağlık kontrolü zaman aşımıyla konteyneri yeniden başlatır.<br/>**Senaryo C:** CRM / B2B veri zenginleştirme hattında bozuk URL listesiyle `extractDomain()` üzerinden işleme kuyruğu tamamen tıkanır. | `RED`: `regex_stall_ms: 165.035, concurrent_webhook_starved: true`<br/>`GREEN`: `regex_stall_ms: 0.017`<br/>`pytest -k test_n8n_cand01` |
| **10** | [`10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md`](advisories/tr/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)<br/>`GHSA-cc9f-m5vr-pm75` | **gotify/server** (`<= v2.9.1`)<br/>`router/router.go:52-73, 93-102` | `CWE-601`<br/>**4.7 Medium** | **Kodda Oluşumu:** `SSL.Enabled=true` ve `SSL.RedirectToHTTPS=true` açıkken `router.go` içindeki yönlendirme ara katmanı `Location` başlığını yapılandırılmış `LetsEncrypt.Hosts` yerine doğrudan doğrulanmamış `ctx.Request.Host` başlığından (`308 Permanent Redirect`) üretir.<br/>**Senaryo A:** Saldırgan `Host: phish-gotify.example` başlığıyla `308 Permanent Redirect` yanıtını önbelleğe zehirleyerek kullanıcı tarayıcılarını kalıcı olarak sahte giriş sayfasına yönlendirir.<br/>**Senaryo B:** `http://gotify-sunucu/message?token=<app-token>` adresine istek atan ve yönlendirmeleri takip eden (`curl -L` / bildirim betikleri) istemciler `308` yanıtıyla uygulama token'ını saldırganın sunucusuna sızdırır.<br/>**Senaryo C:** Ters vekil arkasında `Host` başlığını ileten kurulumlarda bildirim ve istemci bağlantıları saldırganın alan adına yönlendirilir. | `RED`: `status_code: 308, redirected_to_untrusted_host: true`<br/>`GREEN`: `redirected_to_untrusted_host: false`<br/>`pytest -k test_gotify_cand01` |
| **11** | [`11-XROAD-CAND-01-RUNNER-INJECTION.md`](advisories/tr/11-XROAD-CAND-01-RUNNER-INJECTION.md)<br/>`GHSA-4fcw-7xqx-fjv5` | **nordic-institute/X-Road** (`38cd99ec0ebb`)<br/>`_build-and-package.yml:84-91` | `CWE-78`<br/>**8.5 High** | **Kodda Oluşumu:** `build.yaml` (`secrets: inherit`, `packages: write`) tarafından çağrılan ve kalıcı `xrd-runner-8c` self-hosted runner üzerinde çalışan `_build-and-package.yml`, `${{ github.head_ref }}` değerini doğrudan çift tırnaklı bash `run:` bloğuna gömer.<br/>**Senaryo A:** Özel hazırlanmış dal adıyla (`feat";...;#`) açılan PR, kod incelemesi başlamadan önce kalıcı `xrd-runner-8c` sunucusunda kabuk komutu çalıştırır.<br/>**Senaryo B:** `build.yaml` `secrets: inherit` ve `packages: write` yetkilerini devrettiği için enjekte edilen komut GHCR paket yazma token'ına ve depo sırlarına erişir.<br/>**Senaryo C:** Kalıcı `xrd-runner-8c` derleme sunucusundaki yerel Gradle/Docker önbelleği zehirlenerek sonraki resmi X-Road sürüm paketlerine arka kapı yerleştirilir. | `RED`: `arbitrary_command_executed_on_self_hosted_runner: true`<br/>`GREEN`: `env_var_parameterized: true`<br/>`pytest -k test_xroad_cand01` |
| **12** | [`12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md`](advisories/tr/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md)<br/>`GITLAB-CAND-02`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/oauth/device_authorizations_controller.rb:4-50`<br/>`app/controllers/oauth/tokens_controller.rb:42-75` | `CWE-863 / CWE-285`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` | **Kodda Oluşumu:** `Oauth::DeviceAuthorizationsController` (`device_authorizations_controller.rb:4-50`) ve `Oauth::TokensController` (`tokens_controller.rb:42-75`), kardeş `Oauth::AuthorizationsController` içinde zorunlu olan `verify_admin_allowed!`, `verify_confirmed_email!`, `set_current_organization` ve `enforce_organization_maintenance_mode` kontrollerini içermez.<br/>**Senaryo A (Tam Sunucu / Admin Ele Geçirme):** Normal kullanıcının oluşturduğu güvenilmeyen (`trusted: false`) uygulama, `disable_admin_oauth_scopes=true` açıkken bile `/oauth/device` üzerinden tam yetkili `api admin_mode` jetonu üreterek tüm özel depoların, CI/CD sırlarının ve GitLab sunucusunun ele geçirilmesini sağlar.<br/>**Senaryo B (E-Posta Onaysız Kalıcı API Arka Kapısı):** E-postası doğrulanmamış (`confirmed_at: nil`) hesap `/oauth/device` üzerinden kalıcı `access_token` ve `refresh_token` alır.<br/>**Senaryo C (Adli İnceleme / Göç Kilidinde Dondurulmuş Depoya Kod Enjeksiyonu):** Organizasyon `migration` (`503`) veya `legal` (`403`) bakım kilidindeyken cihaz token basılır ve dondurulmuş depoya commit (`201 Created`) atılır. | `RED`: `token_minted_admin_mode: true, post_token_admin_action_succeeded: true`<br/>`GREEN`: `503 / 403, token_minted_admin_mode: false`<br/>`pytest -k test_report1_cand02` |
| **13** | [`13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md`](advisories/tr/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md)<br/>`GITLAB-CAND-05`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/catalog/mcp_servers/callback_service.rb:17-50, 87-129`<br/>`refresh_token_service.rb:18-70`<br/>`dynamic_registration_client.rb:104-136` | `CWE-918 / CWE-209`<br/>**8.5 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **Kodda Oluşumu:** `CallbackService`, `RefreshTokenService`, `RevokeTokenService` ve `DynamicRegistrationClient`, RFC 8414 `token_endpoint`/`revocation_endpoint` adreslerini doğrulamaz ve `UrlBlocker` olmayan `OAuth2::Client` (`max_redirects: 5`) kullanarak `OAuth2::Error` gövdelerini `flash[:alert]` içine yansıtır.<br/>**Senaryo A (Bulut IAM Anahtarlarının `flash[:alert]` İle Çalınması):** `token_endpoint` üzerindeki `307` yönlendirmesiyle `169.254.169.254` / `127.0.0.1` hedeflerine ulaşılır ve bulut IAM yetki anahtarları doğrudan `flash[:alert]` içinde ekrandan okunur.<br/>**Senaryo B (İç Ağa `POST` SSRF ve Sır Sızıntısı):** `POST` gövdesindeki `client_secret` ve `refresh_token` güvenlik duvarı arkasındaki iç servise iletilir.<br/>**Senaryo C (`RevokeTokenService` SSRF):** Bağlantı kesilirken Basic Auth bilgileri doğrulanmamış `revocation_endpoint` adresine gönderilir. | `RED`: `canary_b_request_count: 5, iam_role_credentials_exposed: true`<br/>`GREEN`: `canary_b_request_count: 0, iam_role_credentials_exposed: false`<br/>`pytest -k test_report2_cand05` |
| **14** | [`14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md`](advisories/tr/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md)<br/>`GITLAB-CAND-06`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/controllers/oauth/mcp_connectors_auth_controller.rb:16-78`<br/>`ee/app/services/ai/catalog/mcp_servers/connect_service.rb:16-79`<br/>`ee/lib/gitlab/oauth/client_state.rb:17-23` | `CWE-639 / CWE-862`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | **Kodda Oluşumu:** `Oauth::McpConnectorsAuthController` `.in_organization(Current.organization)` olmadan global `McpServer.find` çağırır, `ConnectService` `update_ai_catalog_mcp_server` kontrolü yapmadan DCR kimlik bilgilerini yazar ve `ClientState.from_state` `data` bağlamasını düşürür.<br/>**Senaryo A (Rakip Organizasyonun AI Konnektörünü Ele Geçirme):** Organizasyon A'daki saldırgan Organizasyon B'ye ait `McpServer` kaydının `oauth_client_id` ve `oauth_client_secret` bilgilerini kendi OAuth istemcisiyle ezer.<br/>**Senaryo B (Salt-Okunur Kullanıcının Üretim Ayarlarını Ezmesi):** Yalnızca okuma yetkili kullanıcı şirketin MCP OAuth kimlik bilgilerini değiştirir.<br/>**Senaryo C (Kurban Oturumunu Saldırganın MCP Hesabına Bağlama):** Bağlanmamış `state` jetonuyla kurban geliştiricinin GitLab hesabı saldırganın MCP hesabına bağlanır. | `RED`: `cross_org_server_mutated: true`<br/>`GREEN`: `cross_org_server_mutated: false (404 RecordNotFound)`<br/>`pytest -k test_report2_cand05` |
| **15** | [`15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md`](advisories/tr/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md)<br/>`GITLAB-CAND-01`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:25-60, 101-112, 220-239` | `CWE-918 / CWE-522`<br/>**8.2 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **Kodda Oluşumu:** `workhorse/internal/ai_assist/duoworkflow/mcp.go:41-44` içindeki `externalMcpTransport` `transport.WithSSRFFilter()` kullanmaz ve `roundTripper.RoundTrip` (`mcp.go:101-104`) her yönlendirme adımında `Authorization: Bearer` başlığını yeniden ekler.<br/>**Senaryo A (Canlı Bearer Token Hırsızlığı ve Özel Depo Ele Geçirme):** Harici MCP sunucusundan dönen `302` yönlendirmesinde kurbanın canlı `Authorization: Bearer` jetonu saldırgan sunucusuna sızdırılır.<br/>**Senaryo B (Workhorse İç Ağ ve Bulut Metadata SSRF):** Yönlendirme üzerinden Workhorse sürecinden `127.0.0.1` ve `169.254.169.254` adreslerine doğrudan bağlanılır.<br/>**Senaryo C (DNS Rebinding ile İç Ağa Sızma):** Soket seviyesinde `WithSSRFFilter` olmadığı için DNS Rebinding ile şirket iç ağına erişilir. | `RED`: `bearer_token_leaked_to_canary: true`<br/>`GREEN`: `bearer_token_leaked_to_canary: false, ssrfFilterError: disallowlist`<br/>`pytest -k test_report2_cand05` |
| **16** | [`16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md`](advisories/tr/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md)<br/>`GITLAB-CAND-08`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:131-135`<br/>`ee/lib/api/ai/duo_workflows/workflows.rb:341-344, 1065`<br/>`connection_config_service.rb:220-228` | `CWE-862 / CWE-639`<br/>**7.7 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **Kodda Oluşumu:** `McpConfigService#item_version` (`mcp_config_service.rb:134`) aynı dosyanın 334. satırında bulunan `Ability.allowed?(current_user, :read_ai_catalog_item, item_version)` kontrolünü atlar ve `workflows.rb:1065` (`GET /ws`) `workflow_definition` ile `ai_catalog_item_version_id` ezilmesine izin verir.<br/>**Senaryo A (Salt-Okunur `chat` Oturumundan Yazma Aracı Çalıştırma):** `/ws` üzerinde `workflow_definition` ve `ai_catalog_item_version_id` değiştirilerek yasaklı yazma araçları (`create_issue`) etkinleştirilir.<br/>**Senaryo B (Gizli `public: false` Ajan Yapılandırmasını Çalma):** Başka organizasyonlara ait özel AI ajanlarının araç listesi sızdırılır.<br/>**Senaryo C (Yetkisiz Özel Ajan Sürümü Bağlama):** `POST /workflows` ile özel ajan sürümleri yetki kontrolsüz bağlanır. | `RED`: `unapproved_write_tool_injected: true, workflow_definition_overridden: true`<br/>`GREEN`: `unapproved_write_tool_injected: false`<br/>`pytest -k test_report3_cand08` |
| **17** | [`17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md`](advisories/tr/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md)<br/>`GITLAB-CAND-07`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:57-64`<br/>`ee/app/services/ai/catalog/mcp_servers/list_service.rb:14-24`<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:254` | `CWE-863 / CWE-639`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L` | **Kodda Oluşumu:** `McpConfigService#execute` (`mcp_config_service.rb:61`) `.except(:orbit)` kullanırken `:gitlab` anahtarını dışlamaz ve `ListService`/`Agent::Create` `.in_organization` kontrolü yapmaz.<br/>**Senaryo A (Tüm Yerleşik GitLab AI Araç Kısıtlamalarını Sıfırlama):** Adı `"GitLab"` (`:gitlab`, `Tools: nil`) olan katalog sunucusu yerleşik `:gitlab` kaydını ezerek Workhorse'ta (`mcp.go:254`) `allToolsAvailable = true` yapar ve tüm `withheld_server_tools` yasaklarını kaldırır.<br/>**Senaryo B (Başka Organizasyonun MCP Sunucusunu Bağlama):** GraphQL mutasyonlarıyla başka organizasyondaki `McpServer` GID'si ajana bağlanır.<br/>**Senaryo C (Duo Workflow `401` DoS):** `:gitlab` üzerindeki `Headers` ezilerek `/api/v4/mcp` çağrıları çökertilir. | `RED`: `builtin_gitlab_overwritten: true, workhorse_all_tools_available: true`<br/>`GREEN`: `builtin_gitlab_overwritten: false, workhorse_all_tools_available: false`<br/>`pytest -k test_report4_cand07` |
| **18** | [`18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md`](advisories/tr/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md)<br/>`GITLAB-CAND-04`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/projects/integrations/slash_commands_controller.rb:21-48`<br/>`app/models/concerns/integrations/base/slash_commands.rb:6-10, 68-76` | `CWE-601 / CWE-863`<br/>**5.4 Medium**<br/>`AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | **Kodda Oluşumu:** `SlashCommandsController#confirm` (`slash_commands_controller.rb:23-48`) doğrulanmamış `request_params[:redirect_url]` adresine yönlendirme yapar, `request_params[:response_url]` kullanır ve Redis `CACHE_KEY` içinde `project_id`/`integration_id` bağlamaz.<br/>**Senaryo A (Güvenilir GitLab Onay Ekranı Üzerinden Şifre/2FA Avı):** Slash komutu onaylandığı anda kullanıcı `302 Found` ile harici sahte SSO giriş sayfasına yönlendirilir.<br/>**Senaryo B (Projeler Arası ChatOps Hesap Bağlama):** Proje B'de üretilen `command_id` Proje A'nın onay uç noktasında geçerli kabul edilir.<br/>**Senaryo C (ChatOps Geri Çağrı Yönlendirmesi):** `request_params[:response_url]` önbellekteki URL'nin yerine kullanılarak onay yanıtı saldırgana yönlendirilir. | `RED`: `http_status: 302, open_redirect_triggered: true, cross_project_cache_collision_accepted: true`<br/>`GREEN`: `404, open_redirect_triggered: false`<br/>`pytest -k test_report5_cand04` |
| **19** | [`19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md`](advisories/tr/19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md)<br/>Üst Akış Duplicate: `CVE-2026-40295`<br/>*(Yalnızca GitHub — MITRE'ye Gönderilmedi)* | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`lib/gitlab/devise_failure.rb:4-18`<br/>`lib/gitlab/auth/session_expire_from_init_enforcer.rb:44-62`<br/>`app/controllers/oauth/authorizations_controller.rb:316-330` | `CWE-601 / CWE-345`<br/>**5.4 Medium (Upstream CVE-2026-40295 Duplicate)**<br/>`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | **[ÜST AKIŞ DUPLICATE: `CVE-2026-40295` — Yalnızca GitHub'da Yayımlandı, MITRE'ye Gönderilmedi]**<br/>**Kodda Oluşumu:** `Gitlab::DeviseFailure`, `Devise 5.0.3` (`CVE-2026-40295`) içindeki `redirect_url` metodunu miras alarak `GET` dışı `:timeout` hatalarında harici `Referer` başlığına yönlendirme yapar; `CAND-03` ise çalışma zamanında `Doorkeeper 5.9.3` tarafından engellenir.<br/>**Senaryo A/B/C:** `lib/gitlab/devise_failure.rb` içinde `extract_path_from_location(request.referrer)` ürün yaması ve PKCE savunma derinliği yaması. | `DUPLICATE OF CVE-2026-40295` *(Not submitted to MITRE)*<br/>`RED`: `external_referer_redirect: true`<br/>`GREEN`: `path_extracted_only: true` |

#### Kendi Sniper Taramamızda Bulduğumuz Doğrulanmış Açıklar (Vulnerabilities Discovered by Our Sniper Scanner)

**Sniper** statik/dinamik analiz motoru ile yürüttüğümüz güvenlik taramalarında tespit edilen, **Adım Adım Günlük Hayat Kritik Senaryoları (`Scenario A / B / C`)**, **Uçtan Uca Çalışma Zamanı Kanıtları (`RED -> GREEN + BENIGN`)** ve **Doğrulanmış Savunma Yamaları (`git diff`)** ile kanıtlanan **11 güvenlik açığı** ([advisories/README.md](advisories/README.md)) aşağıda yayımlanmıştır:

| # | Açık / Advisory Bağlantısı | Hedef Proje & Bileşen | CWE & CVSS v3.1 | Günlük Hayatta Yol Açtığı Kritik Senaryolar (`Scenario A / B / C`) | Çalışma Zamanı Kanıtı (`RED -> GREEN`) |
| :-: | :--- | :--- | :--- | :--- | :--- |
| **01** | [`01-STIRLING-CAND-02-SYMLINK.md`](advisories/01-STIRLING-CAND-02-SYMLINK.md) | **Stirling-Tools/Stirling-PDF** (`v3.2.2`)<br/>`FolderInputSource.java:337-377`<br/>`FolderOutputSink.java:338-345` | `CWE-59` / `CWE-61`<br/>**7.1 High** | **A)** Ortak belge/tarayıcı klasörüne bırakılan `invoice.pdf -> ../configs/settings.yml` sembolik bağı, varsayılan `recursive=false` modunda `FolderAccessGuard` kontrolünü aşarak admin/OAuth ayarlarını sızdırır.<br/>**B)** `FolderOutputSink.archiveOriginal()` hedef dosyayı taşır. | `RED`: `symlink_accepted: true, protected_settings_exfiltrated: true`<br/>`GREEN`: `symlink_accepted: false` |
| **02** | [`02-STIRLING-CAND-01-WEASYPRINT-SSRF.md`](advisories/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | **Stirling-Tools/Stirling-PDF** (`v3.2.2`)<br/>`ConvertWebsiteToPDF.java:116-143` | `CWE-918`<br/>**8.6 High** | **A)** `CVE-2026-71270` eksik yaması: `/api/v1/convert/url/pdf` içinde WeasyPrint `--allowed-protocols data,http,https` ile çalıştığından, dış HTML sayfasındaki `<link rel="stylesheet" href="http://127.0.0.1:.../secrets.css">` veya `169.254.169.254` alt kaynağı doğrudan üretilen PDF içine basılır. | `RED`: `internal_data_embedded_in_pdf: true`<br/>`GREEN`: `internal_loopback_hit_count: 0` |
| **03** | [`03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md`](advisories/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | **trycua/cua** (`npm: cuabot <= 1.0.16`)<br/>`libs/cuabot/src/cuabotd.ts` | `CWE-306` / `CWE-942`<br/>**9.6 Critical** | **A)** `cuabot` açıkken ziyaret edilen herhangi bir web sayfası `fetch("http://localhost:7842/bash")` (`Access-Control-Allow-Origin: *`) ile komut çalıştırıp bağlanmış `~/.cuabot/user/.claude` kimlik bilgilerini çalar.<br/>**B)** `0.0.0.0:7842` yüzünden aynı LAN'daki herkes erişebilir. | `RED`: `http_status: 200, mounted_host_claude_credentials_exfiltrated: true`<br/>`GREEN`: `http_status: 403` |
| **04** | [`04-CUA-CAND-02-WORKER-SERVER-RCE.md`](advisories/04-CUA-CAND-02-WORKER-SERVER-RCE.md) | **trycua/cua** (`pip: cua-bench-rl <= 0.3.1`)<br/>`worker_server.py:79-108, 338-360` | `CWE-94` / `CWE-942`<br/>**8.8 High** | **A)** Tarayıcıdan `http://127.0.0.1:8001/reset` (`allow_origins=["*"]`) çağrıldığında `ip_filter_middleware` geçilir ve `spec.loader.exec_module` ile konakta keyfi `<env_path>/main.py` çalıştırılır.<br/>**B)** `OSGYM_ALLOWED_IPS=""` boş verildiğinde filtre fail-open olup tüm ağa açılır. | `RED`: `arbitrary_env_path_exec_module_rce: true`<br/>`GREEN`: `403 / 400, rce: false` |
| **05** | [`05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md`](advisories/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | **trycua/cua** (`cargo: cua-compat <= 0.9.0`)<br/>`daytona/objectstore.rs:320-422` | `CWE-22`<br/>**8.1 High** | **A)** `DELETE /daytona/x?uploadId=../objects` isteği (önceden multipart yükleme başlatmadan), `uploads.remove(&id)` dönüş değeri kontrol edilmediği için `tokio::fs::remove_dir_all` ile tüm `objects/` deposunu siler. | `RED`: `objects_store_wiped_without_prior_upload: true`<br/>`GREEN`: `objects_store_preserved: true` |
| **06** | [`06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md`](advisories/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | **trycua/cua** (`cargo: cua-media-codec <= 0.9.0`)<br/>`videotoolbox/mod.rs:308-420` | `CWE-125` / `CWE-190`<br/>**5.5 Medium** | **A)** Safe Rust `VtEncoder::encode` -> `pixel_buffer_for` içinde `FrameData::Nv12` dilim boyutu kontrol edilmeden `unsafe { std::ptr::copy_nonoverlapping }` çağrılır; kısa dilimde bitişik heap belleğindeki `960` bayt video karesine kopyalanır veya `SIGSEGV` üretir. | `RED`: `oob_bytes_read: 960, adjacent_heap_secret_copied_to_video_frame: true`<br/>`GREEN`: `oob_bytes_read: 0` |
| **07** | [`07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md`](advisories/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | **trycua/cua** (`pip: cua-bench <= 0.3.1`)<br/>`winarena_adapter/cli.py:262-265` | `CWE-306` / `CWE-668`<br/>**8.6 High** | **A)** WinArena `0.0.0.0:8006` (şifresiz noVNC) ve `0.0.0.0:3390` (parolasız RDP) portlarını tüm yerel ağa açar ve konak `setup` dizinini `-v {setup_path}:/shared` olarak yazılabilir bağlar. | `RED`: `lan_exposed_ports: ["8006:8006", "3390:3389"]`<br/>`GREEN`: `lan_exposed_ports: []` |
| **08** | [`08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md`](advisories/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | **openziti/ziti** (`github.com/openziti/ziti/v2`)<br/>`ziti/util/certs.go:91-103, 199-208` | `CWE-295`<br/>**7.4 High** | **A)** `ziti edge login` içindeki `AreCertsTrusted`, `InsecureClient` içinde koşulsuz `InsecureSkipVerify: true` bıraktığı için `RootCAs` havuzunu yok sayar ve sahte MITM sertifikasını *"Verified that server supplied certificates are trusted"* diyerek kabul eder. | `RED`: `rogue_mitm_cert_accepted_as_trusted: true`<br/>`GREEN`: `x509.UnknownAuthorityError` |
| **09** | [`09-N8N-CAND-01-WEBHOOK-REDOS.md`](advisories/09-N8N-CAND-01-WEBHOOK-REDOS.md) | **n8n-io/n8n** (`npm: n8n-workflow <= 2.45.0`)<br/>`string-extensions.ts:94, 326, 375` | `CWE-1333`<br/>**5.3 Medium** | **A)** Dışa açık n8n Webhook ifadelerinde kullanılan `isEmail()`, `extractDomain()` ve `extractEmail()` fonksiyonlarındaki uzunluk kontrolsüz iç içe nicelleyiciler, 10–20 KB'lık tek bir istekle Node.js ana olay döngüsünü yüzlerce milisaniye kilitler. | `RED`: `regex_stall_ms: 165.035, concurrent_webhook_starved: true`<br/>`GREEN`: `regex_stall_ms: 0.017` |
| **10** | [`10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md`](advisories/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | **gotify/server** (`v2.9.1`)<br/>`router/router.go:52-73, 93-102` | `CWE-601`<br/>**4.7 Medium** | **A)** `SSL.RedirectToHTTPS=true` açıkken `SslMiddleware` içinde `AllowedHosts` boş bırakıldığı için sahte `Host` başlığı `308 Permanent Redirect` ile saldırganın alan adına yönlendirilir. | `RED`: `status_code: 308, redirected_to_untrusted_host: true`<br/>`GREEN`: `redirected_to_untrusted_host: false` |
| **11** | [`11-XROAD-CAND-01-RUNNER-INJECTION.md`](advisories/11-XROAD-CAND-01-RUNNER-INJECTION.md) | **nordic-institute/X-Road** (`38cd99ec0ebb`)<br/>`_build-and-package.yml:84-91` | `CWE-78`<br/>**8.5 High** | **A)** `build.yaml` (`secrets: inherit`, `packages: write`) tarafından çağrılan ve kalıcı `xrd-runner-8c` self-hosted runner üzerinde çalışan iş akışında `${{ github.head_ref }}` doğrudan bash `run:` bloğuna gömülerek komut çalıştırmaya yol açar. | `RED`: `arbitrary_command_executed_on_self_hosted_runner: true`<br/>`GREEN`: `env_var_parameterized: true` |

## Doğrulama ve testler

Halka açık yetenek özeti, tekrarlanabilir en güncel Community doğrulama anlık görüntüsü, kanıt sınırları ve yorumlama
rehberi için [VALIDATION.md](../VALIDATION.md) belgesine bakın.

Community belge/üst veri kapısı çevrimdışı ve salt okunurdur:

```bash
python3 .github/scripts/validate-community-release.py
```

İncelenebilir kaynak dağıtımını bu çalışma dizininin dışında yeni bir dizine oluşturun, ardından oluşturulan ağacı
doğrulayın:

```bash
python3 scripts/build-community-source.py --output /MUTLAK/YOL/sniper-community-source
python3 .github/scripts/validate-community-release.py \
  --root /MUTLAK/YOL/sniper-community-source --scan-release-tree
```

Deponun tam yerel test çalıştırıcısı:

```bash
python3 -m pip install --no-deps -r requirements-runtime.lock -r requirements-test.lock
python3 scripts/run_all_tests.py
```

Bazı isteğe bağlı motorlar ayrı olarak kurulan, sürümü sabitlenmiş yerel araçlar gerektirir. Atlanan bir isteğe bağlı
entegrasyon, o motorun makinenizde çalıştığının kanıtı değildir.

## Sık sorulan sorular

### Sniper Community nedir?

Sniper Community; yetkilendirilmiş kaynak kod, bağımlılık, SBOM, konteyner, altyapı, web sitesi ve API incelemesi için
Apache-2.0 lisanslı açık kaynak bir uygulama güvenliği araç setidir. Yerel analizörleri ve kaydedilmiş rapor iş
akışlarını bir CLI, yerel loopback web arayüzü ve Model Context Protocol (MCP) üzerinden isteğe bağlı yapay zekâ
destekli inceleme ile birleştirir. [Yetenek haritası](CAPABILITIES.md) yerleşik kontrolleri isteğe bağlı motorlardan ve
manuel incelemeden ayırır.

### Yapay zekâ aboneliği olmadan Sniper'ı kullanabilir miyim?

Evet. CLI ve yerel web arayüzü bir yapay zekâ istemcisi gerektirmez. İsteğe bağlı bir MCP istemcisi kendi model
sağlayıcısına bağlanabilir; bu sağlayıcının erişilebilirliği, gizlilik kuralları ve ücretleri Sniper'ın kaynak
lisansından ayrıdır. Yerel donanım ve isteğe bağlı üçüncü taraf araçların da kendi gereksinimleri vardır.

### Windows, macOS ve Linux üzerinde kullanılabilir mi?

Evet. Python 3.12 test edilen yorumlayıcıdır. Tam yerel beş motorlu kurulum Linux ARM64 ve x86-64 üzerinde desteklenir.
**macOS (Apple Silicon)** üzerinde hem yerel kaynak kurulumu (`python3 scripts/setup-community --core-only`) hem de beş
motorlu Docker Desktop profili (`./scripts/deploy-community-tools --accept-third-party-licenses`) gerçek macOS
donanımında test edilmiş, doğrulanmış ve desteklenmektedir (deneysel değildir). **Windows** üzerinde Sniper; yerel
`--core-only` kaynak kurulumunu (`python3 scripts/setup-community --core-only`), WSL2'yi ve Docker Desktop üzerinden
Linux konteynerlerini destekler. Ayrıntılar için [dağıtım rehberine](../DEPLOYMENT.md) ve
[doğrulama kanıtlarına](../VALIDATION.md) bakın.

### Sniper bir web sitesini güvenlik açıklarına karşı tarayabilir mi?

Evet, size ait olan veya değerlendirme için açıkça yetkilendirildiğiniz web siteleri ve API'ler için. Desteklenen iş
akışları kapsamı sınırlandırılmış harici hedef eylemleri hazırlar, web ve TLS kanıtlarını yerel kaynak analiziyle
birleştirir ve incelenebilir bulgular üretir. İlgili motorların, sabitlenmiş katalogların veya güvenlik açığı
verilerinin, çalışma zamanı hazırlığının ve insan onayının mevcut olması gerekir. Bkz.
[web sitesi/API iş akışı](USE-CASES.md#plan-an-authorized-website-or-api-action) ve
[yetenek sınırları](CAPABILITIES.md); hiçbir araç her güvenlik açığının bulunacağını garanti edemez.

### Mobil uygulama güvenlik açıklarını bulup kapatmaya yardımcı olur mu?

Sniper; ekiplerin desteklenen Android, iOS, Flutter ve React Native kodunu, manifestlerini, bağımlılıklarını, API
yollarını ve yayın yapılandırmasını incelemesine yardımcı olur. Bir App Store veya Google Play sürümünden önce kanıtları
önceliklendirilmiş düzeltme çalışmalarına dönüştürür. Geliştiriciler değişiklikleri hazırlamak ve incelemek için
bulguları ve yapay zekâ destekli açıklamaları kullanabilir. Kapsam desteklenen girdilere bağlıdır: bu her mobil ikili
dosyanın evrensel olarak taranması, her açığın otomatik onarılması veya mağaza onayı garantisi anlamına gelmez. Bkz.
[mobil yayın öncesi kontrol](#yayına-çıkmadan-önce-inceleyin) ve [yetenek haritası](CAPABILITIES.md).

### Sniper bir sızma testinin yerini alır mı veya güvenli bir sürümü garanti eder mi?

Hayır. Olası yetkilendirme ve IDOR sorunları dahil olmak üzere kanıtlar ve inceleme adayları üretir. Nitelikli bir
incelemecinin önemli bulguları doğrulaması, yetkilendirilmiş kapsam dahilinde çalışma zamanı kontrollerini test etmesi ve
nelerin düzeltileceğine karar vermesi gerekir. Temiz bir tarama güvenlik sertifikası değildir. Bkz.
[doğrulama kanıtları](../VALIDATION.md).

### Resmi kaynak kod ve kurulum talimatları nerede?

Kaynak deposu [dytredline/Sniper](https://github.com/dytredline/Sniper) adresindedir. Platformunuz için
[kaynak koddan kurulum](#kaynak-koddan-kurulum) ve [dağıtım rehberi](../DEPLOYMENT.md) ile başlayın. Proje
[ConverserAI](https://converserai.com/#sniper) üzerinde tanıtılmaktadır; yetenekler, platform desteği, lisans koşulları
ve sürüm kanıtları için doğruluk kaynağı bu depodur. Araştırma veya yayınlanmış çalışmalarda yazılıma atıf yaparken
[CITATION.cff](../CITATION.cff) dosyasını kullanın.

## Lisans

Sniper Community, Apache License 2.0 (`Apache-2.0`) altında lisanslanmıştır. Tam koşullar için [LICENSE](../LICENSE)
dosyasına bakın. Üçüncü taraf bileşenler ve isteğe bağlı araçlar kendi lisanslarına tabidir.
