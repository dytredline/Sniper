# Sniper Community — açık kaynak uygulama güvenliği

**Türkçe** | [English](../README.md) | [日本語](README.ja.md) | [简体中文](README.zh-CN.md) | [한국어](README.ko.md)

Sniper Community; web sitesi, API ve mobil uygulama geliştiren ekiplerin yetkili güvenlik incelemeleri için
geliştirilmiş, yerel öncelikli ve Apache-2.0 lisanslı açık kaynak bir uygulama güvenliği araç setidir.
Web sitenizdeki güvenlik açıklarını bulmak için güçlü, açık kaynak bir çözüm sunar: kapsamı onaylı
web sitesi ve API taramalarını kaynak kod incelemesiyle birleştirir. Harici taramalar için ilgili
motorların kurulumu, verileri ve hazırlık kontrollerinin tamamlanması gerekir.
Desteklenen kaynak kodu, bağımlılıkları, yazılım bileşen listesini (SBOM), konteynerleri ve altyapı
yapılandırmalarını inceler. Sonuçları komut satırında, yerel web arayüzünde veya Model Context Protocol
(MCP) üzerinden bir yapay zekâ asistanıyla değerlendirebilirsiniz.

[GitHub kaynak kodu](https://github.com/dytredline/Sniper) · [ConverserAI proje tanıtımı](https://converserai.com/#sniper) · [Kurulum rehberi](../README.md#source-checkout-setup)

## Neleri inceleyebilirsiniz?

| İnceleme alanı | Sunulan destek |
| --- | --- |
| Web sitesi ve API taraması | Size ait veya izinli hedeflerde, gerekli motorlar hazır olduğunda kapsamı sınırlandırılmış taramalar; web ve TLS bulgularının değerlendirilmesi. |
| Kaynak kod güvenliği (SAST) | Desteklenen kod yollarında SQL/komut enjeksiyonu, XSS, SSRF, dosya yolu ve benzeri risk örüntülerine ilişkin kanıtlar. |
| Yetkilendirme ve IDOR | Desteklenen Python ve JavaScript/TypeScript yollarında erişim kontrolü ve nesne sahipliği açısından elle doğrulanması gereken adaylar. |
| Bağımlılıklar ve SBOM (SCA) | Bileşen envanteri, CycloneDX/SPDX, VEX ve yapılandırılmış yerel güvenlik açığı verileriyle değerlendirme. |
| Altyapı ve teslim süreçleri | Desteklenen Docker, Terraform, Kubernetes, Helm, bulut IAM ve CI/CD yapılandırmalarının incelemesi. |
| Mobil uygulama yayına hazırlığı | Android, iOS, Flutter ve React Native projelerinde desteklenen kod, manifest, bağımlılık ve API girdileri. |
| Raporlar ve yapay zekâ | CLI, yerel web ve stdio MCP akışları; JSON, HTML, SARIF ve desteklenen diğer rapor biçimleri. |

Ayrıntılı [yetenek haritası](CAPABILITIES.md), yerleşik analizleri, isteğe bağlı motorları, ön koşulları ve
insan değerlendirmesi gereken kontrolleri ayrı gösterir. Listede bulunması, bir kontrolün projenizde
çalıştırıldığı veya geçtiği anlamına gelmez.

## Sık sorulan sorular

### Sniper ücretsiz mi? Yapay zekâ aboneliği gerekiyor mu?

Community kaynak kodu Apache-2.0 lisanslıdır. CLI ve yerel web arayüzü yapay zekâ aboneliği gerektirmez.
İsteğe bağlı bir MCP istemcisi kullanırsanız model sağlayıcısının ücretleri ve veri politikaları ayrıdır.
Donanım kaynakları ve üçüncü taraf araçların kendi lisans koşulları geçerlidir.

### Sniper bilgisayarımdaki projeyi nasıl inceler?

İnceleme izniniz olan yerel kaynak kodu ve desteklenen girdileri analiz akışına verirsiniz. Yapay zekâ
istemcisi stdio MCP üzerinden bulguları okuyabilir ve önerilen işlemleri hazırlayabilir. Etki oluşturan
işlemler için önce kapsamı ve etkileri gösterilen bir plan hazırlanır; yalnızca açık insan onayından
sonra uygulanır. [MCP rehberi](COMMUNITY-MCP.md) güven sınırlarını ve kurulumu açıklar.

### Windows, macOS ve Linux üzerinde kullanılabilir mi?

Python 3.12 test edilen yorumlayıcıdır. Tam yerel beş motorlu kurulum Linux ARM64 ve x86-64 üzerinde
desteklenir. **macOS Apple Silicon üzerinde hem yerel kaynak kurulumu (`python3 scripts/setup-community --core-only`)
hem de beş motorlu Docker Desktop profili (`./scripts/deploy-community-tools --accept-third-party-licenses`)
gerçek macOS donanımında test edilmiş, doğrulanmış ve desteklenmektedir** (macOS kurulumu deneysel değildir).
Yerel macOS kurulumu `.venv`, yerleşik SAST/SCA/IaC analizörlerini, `sniper-mcp`, `sniper-project-audit` ve
yerel loopback web arayüzünü doğrudan çalıştırır; beş isteğe bağlı motor ise Docker Desktop profili ile
kullanılır. Windows'ta WSL2 veya Linux konteynerleri kullanılır; Windows/WSL2 sözleşme testlerinin sınırı
[dağıtım rehberinde](../DEPLOYMENT.md) ve macOS doğrulama kanıtları [doğrulama kayıtlarında](../VALIDATION.md)
ve [macOS doğrulama ve taranan depolar raporunda](SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md) belirtilir.
Güncel komutlar için [ana kurulum bölümünü](../README.md#source-checkout-setup) kullanın.

### Mobil uygulama güvenlik açıklarını bulup kapatmaya yardımcı olur mu?

Evet. Android, iOS, Flutter ve React Native projelerinde desteklenen kod, manifest, bağımlılık,
API ve yayın yapılandırmalarını inceleyerek açıkları gidermek için öncelikli düzeltme adımları
oluşturmanıza yardımcı olur. Bulgular ve yapay zekâ destekli açıklamalar geliştiricinin düzeltme
çalışmasını destekler. Her mobil uygulama ikilisinin tarandığı, bütün açıkların otomatik kapatıldığı
veya mağaza onayının garanti edildiği anlamına gelmez; kapsam desteklenen girdilere bağlıdır.

### Güvenlik açığı bulamazsa sistem tamamen güvenli midir?

Hayır. Desteklenmeyen girdiler, çalıştırılmamış kontroller ve çalışma zamanı davranışları olabilir.
Bulgular ve temiz sonuçlar insan değerlendirmesi gerektirir. Sniper, yetkili manuel sızma testini veya
uzman kararının tümüyle yerini almaz. [Doğrulama kayıtları](../VALIDATION.md) hangi testlerin
yapıldığını ve kanıt sınırlarını gösterir.

### Kaynak kodum bir yapay zekâ sağlayıcısına gider mi?

Sniper uygulama durumunu yerel tutar; stdio MCP sunucusu ağ dinleyicisi açmaz. Bununla birlikte harici
bir yapay zekâ istemcisi, seçilen kod parçalarını veya bulguları kendi model sağlayıcısına gönderebilir.
İstemcinin paylaşım ve saklama politikalarını kontrol edin; özel anahtar ve müşteri verilerini paylaşmayın.

## Kaynaklar, lisans ve güvenli kullanım

- [Kaynak kod ve sürümler](https://github.com/dytredline/Sniper)
- [macOS Apple Silicon kurulum doğrulaması ve Sniper ile taranan 8 açık kaynak depo raporu](SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md)
- [Doğrulama kanıtları (macOS yerel + Docker Desktop)](../VALIDATION.md) ve [dağıtım rehberi](../DEPLOYMENT.md)
- [Kullanım senaryoları](USE-CASES.md) ve [yetenekler](CAPABILITIES.md)
- [İsteğe bağlı motorlar](COMMUNITY-TOOLS.md): Nuclei, Trivy, Gitleaks, TruffleHog ve Opengrep; kurulum, lisans ve hazırlık kontrollerine tabidir.
- [Apache-2.0 lisansı](../LICENSE), [katkı rehberi](../CONTRIBUTING.md) ve [yazılıma atıf bilgileri](../CITATION.cff)
- [Özel güvenlik açığı bildirimi](../SECURITY.md)

Yalnızca size ait veya açık inceleme izniniz olan sistemleri değerlendirin. Harici hedeflerde kapsam,
hız sınırları, veri işleme kuralları ve durdurma koşulları önceden belirlenmelidir. Bu sayfa Türkçe
tanıtımdır; güncel teknik kapsam ve platform koşulları bağlantı verilen sürüm belgelerinden doğrulanmalıdır.
