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

| Repo | Sniper SAST / IaC / SCA Özeti | Doğrulanmış Kaynak Kanıtı (Gerçek vs. Yanlış Pozitif) | Tek Başına Kritiklik | Bulgular Birleşiyor mu? (Saldırı Zinciri / Chaining) | Birlikte (Zincir) Kritiklik ve Yayın Durumu |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **1. `autogpt`** | `93` eşik aşan (`2K / 39Y`); `142` triyaj | **2 kritik SQLi (`obj.execute`), JWT ve FastAPI `Security()` tamamen yanlış pozitif**; `jobstore_backfill.py` `pickle.loads` + Compose sabit parola + Root Dockerfile gerçek | **Düşük / Orta** | **KOŞULLU HİPOTEZ:** Yalnızca saldırgan DB `apscheduler_jobs` tablosuna yazma erişimi kazanırsa `pickle.loads` + Root konteyner birleşir | **ORTA / YÜKSEK (Koşullu)** *(Doğrulanmış doğrudan açık yok; derinlemesine savunma sertleştirmesi)* |
| **2. `zitadel`** | `67` eşik aşan (`8K / 42Y`); `286` triyaj | **8 kritik SQLi/`exec` tamamen yanlış pozitif**; `deploy/compose/` altında 3 `docker.sock` bağlaması ve dokümantasyon örneğinde `TLS_REJECT=0` gerçek | **Düşük / Orta** | **HAYIR (Farklı Örnekler):** `docker.sock` (`deploy/compose/`) ile `TLS_REJECT=0` (`apps/docs/...`) farklı compose dosyalarındadır | **DÜŞÜK / ORTA** *(Geliştirme/örnek dağıtım sertleştirmesi; ürün CVE'si değil)* |
| **3. `nextcloud-mcp`** | `59` eşik aşan (`SAST 1K/6Y`, `IaC 7Y`, `SCA 5K/40Y`) | **`token_utils.py` JWT ve `login_flow.py:192` `poll_endpoint` SSRF %100 yanlış pozitif** (`initiate()` satır 130 `_rewrite_to_nextcloud_host` ile origin'i sabitler); `pact.yml` `pull_request` + `same-repo` korumalı | **Düşük / Orta (SCA)** | **HAYIR:** Tüm birinci-parti SAST/CI bulguları ya yanlış pozitif ya da `same-repo` korumalıdır; yalnız `uv.lock` SCA kayıtları mevcuttur | **DÜŞÜK / ORTA (SCA)** *(Doğrulanmış birinci-parti kod açığı yok)* |
| **4. `mcpjam-inspector`** | `122` eşik aşan (`SAST 12K/8Y`, `SCA 6K/96Y`) | **20 K/Y SAST bulgusunun 18'i (%90) yanlış pozitif** (14 JSDoc yorumu, 2 `.d.ts`, 2 UI etiketi); 2'si kasıtlı `new Function` / E2B; `pr-preview.yml` `same-repo` korumalı | **Düşük / Orta** | **HAYIR:** Dış fork PR'lar engellendiği için dış saldırgan CI/CD zinciri oluşmaz; aynı-repo dal adı interpolasyonu sertleştirilmelidir | **DÜŞÜK / ORTA** *(İç CI sertleştirmesi ve SCA güncellemesi)* |
| **5. `codebase-memory-mcp`** | `32` eşik aşan (`SAST 17K/7Y`, `SCA 8Y`) | **24 K/Y SAST bulgusunun tamamı (%100) yanlış pozitif veya kontrollü iç çağrı** (`store.c` statik DDL, `c_lsp.h` yorum, `mcp.c` `git` argv); `http_server.c` `localhost` CORS/Host korumalı | **Düşük** | **HAYIR:** `http_server.c` yabancı origin'lere CORS başlığı dönmez ve DNS rebinding'i reddeder | **DÜŞÜK** *(Doğrulanmış birinci-parti kod açığı yok)* |
| **6. `gitlab-mcp-server`** | `5` eşik aşan (`0K / 4Y`) | `recorder.go` ve `make.go` yanlış pozitif; `GITLAB_MCP_SKIP_TLS_VERIFY=true` yalnızca kullanıcı seçerse aktif | **Düşük** | **HAYIR:** Birleşen bulgu yoktur | **DÜŞÜK** *(Opsiyonel ayar)* |
| **7. `apktool-mcp`** | `16` eşik aşan (`SAST 1 Orta`, `SCA 4K / 12Y`) | SAST gizlilik uyarıları yanlış pozitif; **`uv.lock` içinde 4 kritik, 12 yüksek SCA bağımlılık kaydı var** | **Düşük / Orta (SCA)** | **HAYIR:** Doğrulanmış birinci-parti kod zinciri yoktur; bağımlılık güncellemeleri incelenmelidir | **DÜŞÜK / ORTA (SCA)** *(SAST temiz, SCA kayıtları mevcut)* |
| **8. `jadx-mcp`** | `32` eşik aşan (`SAST 3 Orta`, `SCA 6K / 26Y`) | Doğrulanmış kritik/yüksek SAST açığı yok; **`uv.lock` içinde 6 kritik, 26 yüksek SCA bağımlılık kaydı var** | **Düşük / Orta (SCA)** | **HAYIR:** Doğrulanmış birinci-parti kod zinciri yoktur; bağımlılık güncellemeleri incelenmelidir | **DÜŞÜK / ORTA (SCA)** *(SAST kritik/yüksek yok, SCA kayıtları mevcut)* |

Her deponun dosya/satır düzeyindeki tam kanıt incelemesi ve macOS doğrulama detayları için: [SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md](SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md).

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
