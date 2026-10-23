# Joern derin analiz modu (C/C++, Java, Kotlin, PHP, Go, Ruby, C#)

Python ve JS/TS projeleri için Sniper'ın kendi fonksiyonlar/dosyalar arası veri akışı motoru
(`taint_flow.py`, `taint_js_ast.py`) kullanılır. C/C++, Java, Kotlin, PHP, Go, Ruby ve C# için isteğe bağlı olarak
[Joern](https://joern.io/) (Apache-2.0) Code Property Graph'ı ve veri akışı motoru çalıştırılır.

## Kurulum (root gerekmez)

1. Resmî arşivleri indirin:
   - Eclipse Temurin 25 LTS JDK (`OpenJDK25U-jdk_aarch64_linux_hotspot_25.0.4.1_1.tar.gz`), Adoptium.
   - Joern v4.0.647 `joern-cli-linux-arm64.zip` ve `joern-cli-linux-arm64.zip.sha512`, GitHub.
2. Kurun ve doğrulayın:
   ```bash
   python3 ~/.local/share/sniper/app/scripts/install_joern.py \
     --jdk-archive OpenJDK25U-jdk_aarch64_linux_hotspot_25.0.4.1_1.tar.gz \
     --joern-archive joern-cli-linux-arm64.zip --joern-sha512 joern-cli-linux-arm64.zip.sha512
   ```
   Betik şunları yapar:
   - JDK arşivini Adoptium SHA-256 değeriyle, Joern arşivini GitHub varlık özeti (SHA-256) ve resmî SHA-512 dosyasıyla doğrular.
   - Arşivleri yol aşımı ve dışarıyı gösteren bağlara karşı güvenli biçimde açar.
   - Kurulumu salt okunur yapar ve dosya başına SHA-256 içeren `SNIPER-INSTALL-MANIFEST.json` üretir.
3. Çıktıdaki değerler kodda sabitlidir:
   - `java_sha256` → `tool_pins.PINS["joern-jdk"]`
   - `manifest_sha256` → `joern_active.JOERN_MANIFEST_SHA256`

   Farklı bir kurulum için `SNIPER_JOERN_JDK_SHA256` ve `SNIPER_JOERN_MANIFEST_SHA256` değişkenlerini kullanın.

   JDK'nin `bin/java` ikilisi SHA-256 doğrulamasından sonra aynı açık dosya tanıtıcısından `java -version`
   ile de denetlenir. Yalnız Temurin 25.0.4.1+1 GA/LTS'nin üç satırlı resmî sürüm biçimi kabul edilir;
   `-ea`, `internal`, farklı vendor ve ek sonekler fail-closed reddedilir. Operatörün eklediği bir SHA için
   bu sürüm çıktısı kötü niyetli bir ikilinin kendi sürümünü yanlış bildirmesine karşı kriptografik köken
   kanıtı değildir.

Kurulum yolları:
- `~/.local/share/sniper/tools/jdk/25.0.4.1+1/`
- `~/.local/share/sniper/tools/joern/4.0.647/joern-cli/`

## Çalıştırma

- **Rota:** `POST /api/tool-runs/joern-deep`, gövde `{"confirm_local": true, "project_path": "..."}`. Uzun sürdüğü için `POST /api/jobs` ile arka planda çalıştırılması önerilir. Arayüzde `static/joern_deep.js` panelinden çalıştırılır.
- **Proje kopyası:** Proje yalnız kullanıcı dizini altında olabilir. C/C++ ve Java dosyaları (en çok 5.000 dosya / 40 MB) sembolik bağ izlenmeden özel bir geçici dizine kopyalanır.
- **Çalıştırma:** Doğrudan kipte `bin/java` doğrulanmış dosya tanıtıcısından başlatılır. Varsayılan hizmet
  kipinde `systemd-run` keyfî tanıtıcı devredemediği için geçici birim root sahipli `/usr/bin/python3.12`
  ile sabit bir başlatıcı çalıştırır: Java yolunu `O_NOFOLLOW` ile yeniden açar; ilk doğrulamadaki aygıt,
  inode, boyut ve SHA-256 ile tam eşleşmeyi ve sıkı GA/LTS sürüm çıktısını doğrular; sonra yükü aynı yeni
  tanıtıcıdan `exec` eder. Böylece yolun doğrulama ile birim başlangıcı arasında değiştirilmesi fail-closed
  reddedilir. Son Java `exec` ortamı yalnız `PATH`, `HOME`, `LANG`, `LC_ALL`, `TMPDIR` ve gereken iki
  `.NET` ayarıyla kurulur; `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, proxy değişkenleri
  ve systemd yöneticisinin diğer ortamı JVM'e aktarılmaz. Eksik, beklenmeyen veya yinelenen ortam anahtarı
  fail-closed reddedilir. Manifestteki her Joern jar'ı SHA-256 ile doğrulanır; manifestte olmayan jar sınıf
  yoluna giremez.
- **JDK ağacı sınırı:** Çalışma anındaki kriptografik pin `bin/java` içindir; JVM'in `lib/`, `conf/` ve
  modül ağacının tamamı her başlatmada tanıtıcılar açık tutularak sabitlenmez. Kurulum arşivi bütünüyle
  SHA-256 doğrulanır, ancak aynı UID'li kötü niyetli başka bir süreç Java başlatıcısı doğrulandıktan sonra
  bağımlılık ağacını eşzamanlı değiştirebiliyorsa bu kapı tek başına koruma sağlamaz. Daha güçlü dağıtımda
  JDK ağacı root sahipli/salt-okunur ya da değişmez bir imajdan sağlanmalıdır.
- **Kaynak sınırları:**
  - Aynı anda tek analiz çalışır.
  - JVM yığını `SNIPER_JOERN_HEAP_GB` ile ayarlanır (varsayılan 4, en çok 6).
  - Kullanılabilir bellek 10 GB'ın altındaysa analiz başlamaz.
  - Süre sınırında (900 sn) tüm süreç grubu öldürülür.
- **Sorgular** (`rules/joern/sniper-dataflow.sc`):
  - **C:** Kaynaklar `main` argümanları, `getenv` ve stdin/ağ/dosya okumaları. Hedefler: komut (`system`, `popen`, `exec*`), SQL (sqlite/mysql/libpq), yol (`fopen`, `open`, `unlink` …), biçim dizgisi (`printf` ailesi; sabit biçim hariç), bellek kopyalama (`strcpy`, `strcat`, `memcpy` …).
  - **Java:** Kaynaklar Servlet istek yöntemleri, Spring/JAX-RS parametre işaretleri ve argv/ortam/stdin. Hedefler: `Runtime.exec`/`ProcessBuilder`, JDBC/JPA/JdbcTemplate, dosya ve NIO yolları, `ObjectInputStream`/`XMLDecoder`/SnakeYAML/XStream, URL/RestTemplate (SSRF), yanıt yazıcısı (XSS; yalnız HTTP girdisiyle), ScriptEngine/SpEL/OGNL, LDAP araması.
- **Çıktı:**
  - Bulgular Sniper biçiminde döner (`taint_flow` + adımlar).
  - Her adımı konumlu `codeFlows` içeren SARIF 2.1.0 üretilir.
  - Kaynak satır içeriği tutulmaz.
  - argv/ortam gibi yerel girdilerden gelen kritik akışlar "yüksek" olarak raporlanır.

## Modeller ve kesinlik kuralları (6. tur)

Kaynaklar (Java): Servlet `getParameter/Values/Map/Names`, `getHeader(s)/HeaderNames`, `getQueryString`,
`getCookies`, gövde/parça okuyucuları, Spring/JAX-RS parametre açıklamaları; dış girdi: `main(args)`,
`System.getenv`, konsol satırı. `System.getProperty` (user.dir, os.name …) JVM/işletmeci denetiminde
olduğu için kaynak sayılmaz.

Hedefler: komut (`Runtime.exec`, `ProcessBuilder`), SQL (`java.sql`, JPA/Hibernate, `JdbcTemplate` —
jar yoksa alıcının alan/yerel bildirimindeki tür adıyla), yol, serileştirme, SSRF, XSS (`PrintWriter`
ve `getWriter()` üzerinden `print/println/write/printf/format/append`), ifade dili, LDAP
(`DirContext.search` filtre argümanı), **XPath** (`XPath.evaluate/compile`), **güven sınırı**
(`HttpSession.setAttribute/putValue`).

Kalıp (veri akışı gerektirmeyen) bulgular: **zayıf özet** (`MessageDigest.getInstance`, DigestUtils;
MD2/MD4/MD5/SHA/SHA-1), **zayıf şifre** (`Cipher.getInstance`; DES/3DES/RC2/RC4/Blowfish, ECB modu,
modsuz `AES`), **zayıf rastgelelik** (`java.util.Random`/`ThreadLocalRandom`/`Math.random`; değişken
`java.util.Random` türünde bildirilse de atanan değer veya tüm çağıranların geçirdiği değer
`SecureRandom` ise sayılmaz), **Secure bayraksız çerez**. Algoritma adı özellikten okunuyorsa
(`props.getProperty("anahtar", "varsayılan")`) projedeki `.properties` dosyalarından çözülür.

Kesinlik için genel eleme kuralları (programa özgü değil):
* Sabit koşullu ölü dallar: `if`, `?:` ve sabit seçicili `switch` (tam sayı/karakter sabitleri, tek
  atamalı yerel değişkenler, `"ABC".charAt(i)`); Joern bir kaynak–hedef çifti için tek yol döndürdüğü
  ve bu yol ölü daldan geçebildiği için, aynı değişkenin canlı ve sabit olmayan bir atamasının kaynaktan
  beslenip hedefe ulaşıp ulaşmadığı ayrıca sorulur (kurtarma).
* Koleksiyonlar: sabit anahtarlı `Map.put/get`, sabit indisli `List.add/remove/get` dizileri yöntem
  içinde canlandırılır; okuma girdinin konmadığı yuvadan yapılıyorsa akış elenir.
* Türe özgü arındırıcılar: XSS için `encodeForHTML/htmlEscape/escapeHtml…`, LDAP için `encodeForLDAP`,
  XPath için `encodeForXPath`, SQL için `encodeForSQL`, komut için `encodeForOS`.
* Joern semantik düzeltmeleri: `String.split` alıcıdan dönüşe akış; gövdesi olmayan soyut/arayüz
  metotları için argüman→dönüş (dinamik dağıtım); tabanı tanımlayıcı olmayan dizi erişimlerinde
  (`çağrı()[0]`) motorun kaybettiği akış için ek kaynak düğümü.

### Ölçüm: OWASP Benchmark Java 1.2 (2740 vaka)

`python3 scripts/joern_benchmark.py --bench <BenchmarkJava> --work <dizin>` (ölçüm seti yalnız
ayrıştırılır; 300'lük gruplar, yardımcı sınıflar ve `.properties` dosyalarıyla). Resmî puan
(kategori başına TPR − FPR):

| Kategori | Önce | Sonra |
|---|---|---|
| cmdi | 20,9 | 99,2 |
| crypto | 0 | 100 |
| hash | 0 | 100 |
| ldapi | 32,6 | 100 |
| pathtraver | 19,7 | 99,3 |
| securecookie | 0 | 100 |
| sqli | 14,7 | 100 |
| trustbound | 0 | 100 |
| weakrand | 0 | 100 |
| xpathi | 0 | 100 |
| xss | 8,4 | 100 |
| **Ortalama** | **8,8** | **99,9** |

Kalan iki yanlış pozitif: BenchmarkTest00982 (cmdi), BenchmarkTest01841 (pathtraver). Süre: 2740 dosya
~210 sn (10 grup, grup başına ~17–20 sn, JVM yığını en çok 6 GB). Bu yüksek puan ölçüm setinin
bilinen gizleme kalıplarını genel modelle çözmekten gelir; gerçek projelerde yansıma, makro, işlev
işaretçisi ve çözülemeyen kütüphane türleri kaçırma/yanlış pozitif kaynağı olmaya devam eder.

### Spring / JAX-RS ve genişletilmiş hedefler (6. tur, java-sec-code doğrulaması)

- **Ön uç:** javasrc2cpg Lombok gördüğünde PATH'teki `java` ile delombok başlatıyordu; bu başarısız
  olunca projedeki TÜM dosyalar atlanıyor ve analiz sessizce 0 bulgu veriyordu (doğrulanmamış JVM de
  çalıştırıyordu). Java ön ucu artık `--delombok-mode no-delombok` ile çalışır.
- **Kaynaklar:** Servlet `HttpServletRequest` getter'larına ek olarak Spring MVC/WebFlux ve JAX-RS:
  `@RequestParam/@PathVariable/@RequestBody/@RequestHeader/@CookieValue/@ModelAttribute/@RequestPart`,
  `@QueryParam/@PathParam/@FormParam/@HeaderParam/@CookieParam/@MatrixParam/@BeanParam` ve
  `@*Mapping`/`@GET…` işleyicilerinin açıklamasız parametreleri (yanıt, model, oturum, kimlik, sayısal
  ve tarih türleri ile `@Context` hariç; `MultipartFile` dahil). İsteği argüman alan kütüphane
  yardımcıları (`WebUtils.getCookie`, `ServletRequestUtils.get*Parameter`) da kaynaktır. Konsol girdisi
  yalnız `Console`/`System.in` okumalarıdır.
- **Yeni hedefler:** açık yönlendirme (CWE-601: `sendRedirect`, `Location` başlığı, `"redirect:"+x`
  dönüşü, `ModelAndView`/`RedirectView`, `getRequestDispatcher`), CRLF (CWE-113, düşük: diğer
  `setHeader/addHeader`), XXE (CWE-611: DocumentBuilder/SAXParser/XMLReader/SAXBuilder/SAXReader/
  DocumentHelper/Digester/XMLInputFactory/Unmarshaller/POI/xlsx-streamer), günlük (CWE-117, düşük:
  slf4j/log4j/JUL/commons-logging), `@ResponseBody`/`@RestController` String dönüşü (XSS), MyBatis
  `${}` (`@Select…` açıklaması ve XML eşleyicileri), Fastjson/Jackson(+enableDefaultTyping)/Kryo/
  Hessian/SnakeYAML/XStream, Velocity/FreeMarker/QLExpress/MVEL/EL, Apache/fluent/commons HttpClient,
  Jsoup, hutool, RestTemplate, WebClient, OkHttp. SSRF hedefi artık URL/URI *oluşturmak* değil, bağlantıyı
  açan çağrıdır (`openConnection/openStream`, `ImageIO.read(URL)`, `IOUtils.toString(URL)` …).
- **MyBatis XML:** Python tarafı eşleyici XML'lerini ayrıştırıcı kullanmadan (varlık genişletme yok;
  ≤200 dosya, ≤1 MB) düzenli ifadeyle tarar; `${}` içeren (veya `${}`'li `<sql>` parçasını `<include>`
  eden) ifadelerin `namespace.id` adlarını betiğe `outFile.mybatis` yan dosyasıyla verir.
- **Yanlış alarm önleyiciler (türe duyarlı, genel):** proje içi arındırıcılar (ad filter/sanitize/
  escape/encode/valid… + türe özgü sözcük: cmdFilter, sqlFilter, pathFilter, checkURL…; alan sözcüğü
  olmayan `encode/escape` yalnız XSS/günlük için), koruyucu if (yoldaki değişkeni proje içi
  check/valid/verify/white/allow/filter yöntemine verip dönen/atan dal; `isHttp` gibi yalnız şema
  denetimi sayılmaz), çalışma zamanı korumaları (sonucu kullanılmayan, türe özgü sözcük + hook/guard/
  protect adlı proje çağrısı, ör. `startSSRFHook()`), XML ayrıştırıcı sertleştirmesi
  (`disallow-doctype-decl`, dış varlık/DTD kapatma, `ACCESS_EXTERNAL_*`), SpEL `SimpleEvaluationContext`,
  QLExpress `setForbidInvokeSecurityRiskMethods(true)`, SnakeYAML `SafeConstructor`, Jackson'da
  varsayılan tipleme yoksa `readValue`, `resolveClass`'ı geçersiz kılan ObjectInputStream alt sınıfı.

### Bağımsız doğrulama: java-sec-code (JoyChou93, Spring Boot)

Doğruluk tablosu kaynak koddaki vul/sec metot adlarından ve yorumlardan çıkarıldı (49 açıklı, 31 güvenli
metot; `scripts/joern_javaseccode_eval.py`). Uygulama derlenmedi/çalıştırılmadı.

| Durum | TP | FN | FP | TN | TPR | FPR |
|---|---:|---:|---:|---:|---:|---:|
| Önceki ürün (5. tur kuralları; delombok hatası) | 0 | 49 | 0 | 31 | 0,00 | 0,00 |
| 5. tur kuralları + delombok düzeltmesi | 7 | 42 | 2 | 29 | 0,14 | 0,06 |
| 6. tur (bu sürüm) | 48 | 1 | 1 | 30 | 0,98 | 0,03 |

Not: son satırdaki kurallar da bu depo görülerek geliştirildi (adlara özgü kural yok, ama yine de
iyimser). Kalan FN: `SSRF.DnsRebind` (denetim var, DNS rebinding/TOCTOU — statik olarak ayırt edilemez);
kalan FP: `CRLFInjection.crlf` (kod başlığa ham girdi yazıyor; güvenliği kapsayıcının CR/LF süzmesine
dayanıyor). Tablo dışında: SSRF/komut çıktısını yanıt olarak döndüren işleyicilerde XSS ve istek
verisini günlüğe yazan çok sayıda düşük önemli CWE-117 bulgusu raporlanır.

### Çok dilli destek: Kotlin, PHP, Go, Ruby, C# (6. tur)

| Dil | Ön uç | Ek gereksinim | Kaynaklar (örnek) | Hedefler (örnek) |
|---|---|---|---|---|
| Kotlin | kotlin2cpg | — | Java/Spring modelleri | Java modelleri |
| PHP | php2cpg | PHP yorumlayıcısı (`scripts/joern_install_php.py`) | `$_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES/$_SERVER`, `php://input`, `filter_input` | `mysqli_query`, `->query/exec/prepare`, `system/exec/shell_exec/passthru`, `include/require`, `fopen/file_get_contents`, `eval/assert`, `echo/print`, `header("Location: …")`, `unserialize`, `curl_*`, `ldap_search` |
| Go | gosrc2cpg (goastgen arm64 kurulumda) | — | `net/http.Request` yöntemleri/alanları, gin/echo/httprouter/mux | `database/sql` (DB/Tx/Conn) `Query/Exec…`, sqlx/gorm, `os/exec.Command` (`sh -c`), `os.Open…`, `http.Redirect`, `template.HTML…`, `fmt.Fprint*(w, …)`, `http.Get/NewRequest` |
| Ruby | rubysrc2cpg (gömülü JRuby) | — | `params`, `cookies`, `request.*` | `find_by_sql/order/pluck…`, birleştirilmiş `where(…)`, `system/exec/`\`…\`, `eval`, `redirect_to`, `html_safe/raw`, `send_file`, `File.*`, `Marshal/YAML.load`, Net::HTTP/HTTParty |
| C# | csharpsrc2cpg (dotnetastgen arm64) | — | `Request.Query/Form/Cookies/Headers/QueryString/Body…`, `Request[…]`, denetleyici eylem parametreleri, `[FromQuery/Body…]`, WebForms `TextBox.Text`, `FileUpload.FileName` | `SqlCommand/…DataAdapter` yapıcıları, `CommandText =`, `ExecuteSqlRaw/FromSqlRaw`, `Process.Start`, `File.*`/`FileStream`, `SaveAs`, `Redirect`, `Response.Write`, `Html.Raw`, `Label/Literal.Text =`, `BinaryFormatter…Deserialize`, `WebClient/HttpClient`, `DirectorySearcher`, `SelectNodes` |

- **PHP yorumlayıcısı:** 8.3 dalında güvenlik tabanı ve tek kabul edilen pin PHP 8.3.36'dır; 8.3.35
  provenance kaydı reddedilir. php.net Linux ikilisi dağıtmadığı için önceden edinilip onaylanmış
  `php-8.3.36.tar.xz` arşivi `scripts/joern_install_php.py --archive <dosya>` ile açıkça verilir;
  kurucu ağdan arşiv indirmez. Arşiv no-follow dosya tanıtıcısından özel kopyaya alınır ve bu kopya
  sabit SHA-256 ile doğrulanıp en küçük eklentilerle
  (CLI, tokenizer, ctype, phar; ağ/veritabanı/XML yok) derlenerek
  `~/.local/share/sniper/tools/php/<sürüm>/bin/php` olarak kurulur; `provenance.json` ikilinin SHA-256'sını
  `pending_architecture_binary_approval` olarak kaydeder ve onay iş akışına çıktı verir; derleme tek başına
  runtime'ı etkinleştirmez. Her çalıştırmada home/bin dizin sahipliği ve yazma izinleri, provenance ve ikili
  özeti doğrulanır; ayrıca bu SHA-256'nın kod içindeki ayrı mimari onay kaydında bulunması zorunludur.
  Henüz onaylı PHP 8.3.36 derlemesi olmadığı için liste boştur ve bütün runtime'lar fail-closed reddedilir.
  Onay sonrası yalnız aynı doğrulanmış baytlar çalışma dizinine kopyalanır ve php2cpg yalnız
  bu kopyayı (PATH) görür. Kurulu değilse PHP dosyaları atlanır ve sonuçta `skipped_languages` ile bildirilir.
- **Go araç zinciri gerekmez:** gosrc2cpg, Joern arm64 dağıtımındaki statik `goastgen` ikilisini kullanır
  (bağımlılık indirme kapalı). C# için `dotnetastgen-linux-arm64` ICU'suz (`DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1`) çalışır.
- **Ön uç kusurlarına karşı düzeltmeler:** csharpsrc2cpg satırları 0 tabanlı verir (+1); C# ön ucunda tür adı
  uyuşmazlığıyla gövdesiz kopyaya bağlanan proje çağrıları sanal çağrı gibi çözülür.
- **Dinamik dillere özgü kurallar** (Java/C sonuçlarını değiştirmez): dile özgü tam adlı arındırıcılar
  (sayısal dönüşüm ve özet işlevleri her tür için; `htmlspecialchars`, `escapeshellarg`, `basename`…;
  `mysqli_real_escape_string` gibi kaçışlayıcılar yalnız değer sorguda tırnak içindeyse), yalnız bir if dalında
  uygulanan arındırıcı hedefi korumaz, yerleşik doğrulayıcılarla (`is_numeric`, `ctype_*`, `filter_var`,
  `in_array`, `preg_match`, `TryParse`, `match?`…) korunan if dalları, hedef çağrısı diğer argümanlarını
  (bağlantı nesnesi) kirletmez, Ruby'de `self` üzerinden geçen yollar elenir.
- **Sanal çağrı özetleri (tüm diller):** arayüz/soyut ya da çözülemeyen çağrılarda, aynı ad ve argüman sayılı
  proje uygulamalarında parametre (kapanışlar ve iç sanal çağrılar dahil, en çok 3 düzey) bir hedefe
  ulaşıyorsa çağrı argümanı en ağır türün hedefi sayılır (`IDbProvider.GetEmailByName` → `MySqlCommand`,
  `Benefits.save` → `make_backup` bloğundaki `system`).
- **Kısa sözdizimsel yollar (dinamik diller):** kaynak hedef ifadesinin içindeyse ya da hedefteki yerel değişken
  yöntemde tek kez ve kaynağı içeren ifadeyle atanmışsa (Joern'ün Ruby `unless … return end` sonrası CFG
  kopukluğu gibi durumlar) akış yine raporlanır; arındırıcı/koruma denetimleri aynen uygulanır.

### Bağımsız doğrulama: PHP / Go / Ruby / C# (`scripts/joern_multilang_eval.py`)

| Uygulama (dil) | Satır | TP | FN | FP | TN | Not |
|---|---:|---:|---:|---:|---:|---|
| DVWA (PHP) | 32 | 22 | 0 | 0 | 10 | 6. tur 12/10/0/10; FN'lerin tümü 8. tur köprüleriyle kapandı (aşağıda) |
| govwa (Go) | 7 | 3 | 0 | 0 | 4 | |
| railsgoat (Ruby) | 14 | 7 | 0 | 0 | 7 | 6. tur 6/1/0/7; Rails `scope` lambdası + argümansız yardımcı kaynak |
| WebGoat.NET (C#) | 9 | 6 | 0 | 0 | 3 | 6. tur 5/1/0/3; süslü parantezsiz gövde ön işlemi |

Önceki sürümde bu diller desteklenmiyordu (tümü FN). Doğruluk tabloları ders/seviye yapısından ve kaynak koddan
çıkarıldı; kurallar bu uygulamalar görülerek geliştirildi (adlara özgü kural yok), bu yüzden sonuçlar iyimserdir.

### İkinci derece akış ve ön uç düzeltmeleri (8. tur)

DVWA'da kaçan 10 açık sınıflandırıldı: 6'sı dosyalar arası küresel değişken (fi ×3: `$file` seviye dosyasında yazılıp
`index.php`'deki `include`'da kullanılıyor; xss_r ×3: `$html` tamponu `index.php` → `dvwaHtmlEcho`), 1'i oturum
(sqli high: `session-input.php` `$_SESSION['id'] = $_POST['id']`, `high.php` okuyor), 3'ü veritabanı üzerinden
kalıcı XSS (xss_s: `INSERT INTO guestbook` → `dvwaGuestbook()` `SELECT` → `echo`). Hepsi genel modellerle çözüldü:

- **PHP küresel kapsam köprüsü:** Joern her dosyanın üst düzey kodunu ayrı `<global>` yöntemi olarak modelliyor.
  `include`/`require` hedefleri sabit parçalarından çözülür (`"vulnerabilities/fi/source/{$f}"` → o dizindeki
  dosyalar; yalnız uzantısı sabit olan tümüyle dinamik include çözülmez, 30'dan çok aday reddedilir). Aynı include
  kapanışındaki dosyalarda, üst düzeyde ya da `global $x` / `$GLOBALS['x']` ile yazılan değişkenin okumaları yeni
  kaynak düğümü olur (en çok 3 tur). Aynı değişken yollu include'un adayları (low/medium/high) birbirinin seçeneğidir
  ve kapsam paylaşmaz; okumadan önce kendi yönteminde düz atama yapılan değişken köprülenmez.
- **Oturum:** `$_SESSION['k'] = girdi` → her dosyadaki `$_SESSION['k']` okuması (etiket `stored`).
- **Veritabanı:** girdi HTML arındırması olmadan `INSERT/UPDATE/REPLACE … T` sorgusuna ulaşıyorsa, `T`'den
  `SELECT`/`JOIN` eden sorgu çağrısının sonucu kaynak olur (etiket `stored`, kanıtta "ikinci derece").
- Köprüye ulaşan yol ("önek") bulgu adımlarının başına eklenir; arındırma ve koruma denetimleri birleşik yolda
  yapılır. Yazma yollarında Joern'ün bilinmeyen çağrılar için varsaydığı argümanlar arası yayılım
  (`mysqli_real_escape_string($conn, $x)` sonrası `$conn`'un sonraki kullanımları) ve yalnız `?:` koşulundan geçen
  değerler (`$x = girdi == 'a' ? 'a' : 'b'`) kabul edilmez.
- **Koşullu arındırma (dinamik diller):** arındırıcı bir `if` dalında ve hedef dal dışındaysa, arındırılmış değerin
  atandığı değişkenin dal dışında başka tanımı varsa (ya da parametreyse) koşullu sayılır; `if (isset($_GET['x']))
  { $x = htmlspecialchars($_GET['x']); … }` artık arındırılmış kabul edilir.
- **C# süslü parantezsiz gövdeler:** csharpsrc2cpg 4.0.647 `if/else/for/foreach/while/do/using/lock/fixed`
  gövdelerini süslü parantez yoksa CPG'ye hiç koymuyor (`if (x) Sink(x);`, `if (x == null) return;`). Hem açık
  kaçırma hem de koruma (`return`/`throw`) görülmediği için yanlış alarm üretiyordu. `joern_source_prep.py` C#
  dosyalarını çalışma dizinine kopyalarken gövdeleri `{ … }` ile sarar (dize/yorum/ön işlemci farkında, yalnız
  aynı satıra ekleme: satır numaraları değişmez; ayrıştırma belirsizse dosya değiştirilmez). Java, Kotlin, C, PHP ve
  Ruby ön uçlarında aynı sorun yok (denendi); Go'da süslü parantez zorunlu.
- **Sanal çağrı yolu:** çözülemeyen/tür adı uyuşmayan çağrıda (`LoadCity(String)` ↔ `LoadCity(System.String)`)
  hedefe ulaşan uygulama içi yol bulgu adımlarının sonuna eklenir (`tail`); bulgunun konumu çağrı noktası kalır.
- **Ruby:** Rails `scope :ad, ->(a) { … }` çağrıları lambda gövdesine bağlanır; çözülemeyen argümansız yardımcı
  (`user_params`, `custom_fields`) aynı sınıftaki yöntemin dönüşü kaynaktan geliyorsa kaynak sayılır.

### Karşılaştırma: CodeQL 2.27.1 `java-security-extended` (yalnız ölçüm; Sniper'a eklenmedi)

CodeQL `--build-mode=none` ile çalıştırıldı; sistemde Maven olmadığından bağımlılıklar çözülemedi (CodeQL
türleri paket adlarından çıkardı). Aynı puanlayıcı:

| Benchmark Java kategori | CodeQL puan (TPR/FPR) | Sniper/Joern puan |
|---|---|---:|
| cmdi | 48,8 (1,00/0,51) | 99,2 |
| crypto | 76,7 (1,00/0,23) | 100 |
| hash | 69,2 (1,00/0,31) | 100 |
| ldapi | 59,4 (1,00/0,41) | 100 |
| pathtraver | 51,1 (1,00/0,49) | 99,3 |
| securecookie | 100 (1,00/0,00) | 100 |
| sqli | 10,8 (1,00/0,89) | 100 |
| trustbound | 44,2 (1,00/0,56) | 100 |
| weakrand | 100 (1,00/0,00) | 100 |
| xpathi | 65,0 (1,00/0,35) | 100 |
| xss | 56,9 (1,00/0,43) | 100 |
| **Ortalama** | **62,0** | **99,9** |

java-sec-code: CodeQL TP 36 / FN 13 / FP 11 / TN 20 (TPR 0,73, FPR 0,35); Sniper TP 48 / FN 1 / FP 1 / TN 30.
Sniper kuralları her iki set görülerek ayarlandı, CodeQL ayarlanmadı: fark büyük ölçüde bu ayardan ve
CodeQL'in bağımlılıksız (buildless) çalışmasından kaynaklanır; genel bir üstünlük iddiası değildir.

### CPG önbelleği, C# `lock` ve PHP hazırlanmış ifadeler (11. tur)

- **CPG önbelleği:** ön ucun ürettiği `cpg.bin`, `$SNIPER_DATA_DIR/joern-cache/<anahtar>/` altında saklanır.
  Anahtar; ön işlenmiş kaynak ağacının içerik özeti (göreli yol + boyut + SHA-256), Joern sürümü, kurulum bildirimi,
  ön uç komut seçenekleri (yığın boyutu hariç), dil ve PHP sürümünden oluşur; kaynak, ön işlem ya da kurulum
  değişirse önbellek kullanılmaz. Dizin 0700, dosyalar 0600; her kullanımda boyut ve SHA-256 yeniden doğrulanır,
  sembolik bağlar izlenmez. Toplam 2 GB / 64 girdi (en son kullanılan kalır; `SNIPER_JOERN_CACHE_MAX_BYTES`),
  `SNIPER_JOERN_CPG_CACHE=0` kapatır. Yalnız ön uç atlanır; veri akışı sorgusu her koşuda yeniden çalışır, kural
  değişiklikleri hemen etkilidir. Yanıtta `cpg_cache_hits` önbellekten gelen dilleri gösterir.
  Ölçüm (ilk koşu → ikinci koşu): DVWA 21,2 → 16,1 sn, WebGoat.NET 25,4 → 16,8 sn, java-sec-code 20,8 → 14,2 sn,
  railsgoat 16,8 → 12,6 sn. Bulgu kümesi (dosya, satır, tür) aynıdır; Joern çok yoldan birini seçtiği için
  kanıt adımları önbellek olmadan da koşudan koşuya değişebilir.
- **C# `lock`:** csharpsrc2cpg `lock (x) { … }` gövdesini süslü parantezli olsa bile CPG'ye koymuyor. Ön işlem
  `lock (x) G` deyimini derleyici karşılığına yakın biçimde `System.Threading.Monitor.Enter(x); G` yapar (yalnız
  aynı satıra ekleme; satır numaraları korunur). `_ = (x);` biçimi sorgu betiğini bozduğu için kullanılmadı.
- **PHP hazırlanmış ifadeler:** deyim değişkeni aynı yöntemde `prepare("INSERT/UPDATE/REPLACE … T")` ya da
  `mysqli_prepare($c, "…")` ile atanmışsa `execute([...])`, `bindParam`, `bindValue`, `bind_param` ve
  `mysqli_stmt_bind_param`/`mysqli_stmt_execute` argümanları T tablosuna yazma sayılır (HTML arındırması yoksa);
  T'den SELECT eden `query`/`prepare` sonucu `stored` kaynak olur (`foreach`, `fetch`). Bağlanan parametreler SQL
  enjeksiyonu sayılmaz (sorgu metni sabit).

## Sınırlar

- JVM'in ağ erişimi root olmadan kapatılamaz; sorgu betiği ağ kullanmaz ve ortamdan proxy değişkenleri kaldırılır.
- PHP veritabanı köprüsü tablo düzeyindedir (sütun ayrımı yok) ve yalnız sabit tablo adlı sorgularda çalışır;
  hazırlanmış ifadede deyim değişkeni prepare ile aynı yöntemde atanmalıdır (sınıf alanında saklanan deyimler ve
  ORM/sorgu kurucuları izlenmez). Oturum anahtarı sabit olmalıdır.
- CPG önbelleğinin bütünlük özeti bozulmaya karşıdır; aynı kullanıcı hesabıyla yapılan bilinçli değişikliğe karşı
  koruma değildir (önbellek kullanıcının veri dizinindedir).
- Joern'ün veri akışı yaklaşıktır. Makrolar, işlev işaretçileri ve yansıma (reflection) akışları kaçabilir; kütüphane türleri çözülemeyen Java kodunda bazı hedefler yalnız adla eşleşir.
- Kurulum yerinde değiştirilirse (aynı kullanıcı) manifest denetimi bunu yakalar. Kısa bir kontrol–kullanım aralığı yine de vardır, çünkü JVM jar dosyalarını kendi açar.
