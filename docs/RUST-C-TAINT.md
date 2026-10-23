# Rust ve C/C++ hızlı veri akışı (taint) analizi

`taint_rust.py`, `taint_cfamily.py` ve ortak çekirdek `taint_native_core.py` — proje analizine bağlı, saf Python,
belirteç tabanlı dosyalar arası motorlar (derleyici, cargo, clang ya da harici ikili gerekmez). Joern derin analiz
olarak kalır; Joern C bulguları hızlı motorla eşleşiyorsa `also_in_project_analysis: true` ile işaretlenir.

## Yöntem

* Her fonksiyon simgesel parametre kökenleri (`param:i`) ve gerçek kaynaklarla birlikte bir kez yürütülür; hedefe
  ulaşan parametre kökenleri özete (param → hedef, param → dönüş, param → çıkış parametresi) yazılır. Özetler ve
  küresel değişken kirliliği bağımlılığı değişen fonksiyonlar yeniden yürütülerek sabit noktaya getirilir.
* Akışa duyarsız, dal içinde zayıf güncelleme; if/while koşulundaki sınır denetimi yalnız gövdeyi korur (gövde
  return/goto/break ile çıkıyorsa bloğun geri kalanını).
* Sayısal köken (atoi/strtol/sscanf %d, `parse::<i32>()`) yalnız dizi indeksi ve kopyalama uzunluğu hedeflerinde
  geçerlidir; dize hedeflerinde (SQL, komut, yol…) sayısal değer etkisizdir. `strlen`/`.len()` saldırganın seçtiği
  bir sayı sayılmaz.
* Kesinlik sınırları: yerel girdi en çok 2, ağ/istek girdisi en çok 3 fonksiyon sınırı (bağlama duyarsız uzun
  zincirler gerçek kodda yanıltıcı); 2 ve daha derin zincirler "Olası veri akışı" olarak bir derece düşük önemde.
  C++ yöntem çağrıları alıcının sınıfı bilinmiyor ve ad birden çok sınıfta tanımlıysa ad eşleşmesiyle bağlanmaz;
  Rust'ta ad çözümlemesi crate içinde kalır.

## C/C++

* Kaynaklar — ağ (`request`): `recv/recvfrom/SSL_read/SSL_read_ex/SSL_read_early_data/SSL_peek/SSL_peek_ex/BIO_read/BIO_read_ex/BIO_gets/gnutls_record_recv/gnutls_record_recv_early_data/gnutls_record_recv_seq/mbedtls_ssl_read/mbedtls_ssl_read_early_data/wolfSSL_read/wolfSSL_read_ex/wolfSSL_read_early_data/wolfSSL_recv/wolfSSL_peek/wolfSSL_peek_ex`, soket adlı tanımlayıcıdan `read()`/`pread()`, CGI ortam
  değişkenleri (`QUERY_STRING`, `REQUEST_URI`, `HTTP_*`…), CGI'da stdin. Yerel (`local`): `argv`, `getenv`,
  stdin'den `fgets/gets/gets_s/scanf/scanf_s/getline`, `std::cin >>`, `std::getline(std::cin, …)` ve `std::cin.get/getline/read/readsome`; yerel dosya/tanımlayıcıdan `read`/`pread`, `fgets/getline`, `fread` ve
  `fscanf`/`fscanf_s`; türü doğrulanmış `std::ifstream`/`fstream` için `>>`, `std::getline`, `.get`, `.getline`, `.read` ve `.readsome`.
  `fdopen` ile kanıtlanmış soket akışındaki `fscanf` ailesi ağ girdisi olarak korunur; atama bastırmalı dönüşümler, POSIX numaralı `%2$s` çıktı başvuruları ve güvenli CRT tampon-boyutu argümanları doğru hedefe eşlenir. `vscanf`/`vfscanf`/`vsscanf` ve geniş karakterli eşleri, çıktı hedefleri `va_list` içinde dinamik kaldığı için imlecin kendisini veri tamponu saymaz.
  Çağrı kapsamından çözülebilen proje işlevleri dış kütüphane kaynak modelini gölgeler ve normal işlev özetiyle çözülür; başka dosyadaki `static` işlev dış çağrıyı gölgelemez.
  `ofstream`, bellek akışları ve yerel aynı adlı sınıflar dosya girdisi sayılmaz. Yerel girdi yalnız bellek ve biçim dizgesi hedeflerinde raporlanır.
* Hedefler: komut (`system/popen`, `exec*`/`spawn*` yolu ya da `sh -c` argümanı, `CreateProcess`), biçim dizgesi
  (printf ailesi, biçim argümanı değişken), bellek (`strcpy/strcat/gets`, `sprintf` `%s`, `scanf` `%s`, heap'e
  ayrılmış hedef hariç), kopyalama uzunluğu (`memcpy/strncpy/...`), dizi indeksi (alt+üst sınır denetimi yoksa;
  işaretsiz türde alt sınır gerekmez), SQL (`sqlite3_exec/prepare`, `mysql_query`, `PQexec`, `SQLExecDirect`), yol
  (`fopen/open/ifstream…`; yalnız ağ girdisi), SSRF (`curl_easy_setopt(CURLOPT_URL)`), LDAP filtresi, CGI XSS.
  `SSL_read_ex`, `SSL_read_early_data`, `SSL_peek_ex`, `BIO_read_ex`, `BIO_gets`, `gnutls_record_recv`, `gnutls_record_recv_early_data`, `gnutls_record_recv_seq`, `mbedtls_ssl_read`, `mbedtls_ssl_read_early_data`, `wolfSSL_read`, `wolfSSL_read_ex`, `wolfSSL_read_early_data`, `wolfSSL_recv`, `wolfSSL_peek` ve `wolfSSL_peek_ex` için boyut argümanındaki saldırgan kökenli okunacak bayt sayısı da diğer sınırlı okuma çağrıları gibi
  `memory_len` hedefidir; sabit veya kanıtlanmış güvenli boyut bu bulguyu üretmez.
* Arındırıcılar: sayısal dönüşüm, `mysql_real_escape_string`/`PQescape*`, `sqlite3_mprintf("%q")`, sınır denetimleri.
* Önişlemci: `_WIN32/_MSC_VER` dalları kapalı, bilinmeyen koşulda ilk dal; tek belirteçli nesne makroları yerine
  konur, proje başlık dosyalarındaki makrolar onları `#include` eden dosyalara uygulanır. Statik küresel değişkenler
  dosyaya özgü, küresel yapı alanları alan duyarlı tutulur. Dış ağ okuma işlevlerinin yerel ve küresel işlev işaretçisi takma adları kaynak modelini korur. Diğer işlev işaretçisi takma adları doğrudan, parantezli,
  üçlü işleçli, açık/typedef işlev işaretçisi cast'li ve statik fabrika dönüşlerinde en çok 16 hedefle izlenir;
  `std::function<imza> ad = koşul ? hedef1 : hedef2` bildirimleri de aynı sınırlı aday kümesine girer;
  çözülmeyen koşulsuz üzerine yazma eski kesin hedefi siler, yerel aynı adlı işaretçi proje işlevini gölgeler ve
  sınır aşımı kısmi analiz olarak bildirilir.
  `goto` etiketleri, C++
  sanal çağrı (somut sınıf: `T obj;`, `new T`, `Base &b = Derived()`), kurucu/yıkıcı üye alanları desteklenir.
* Desen kuralı (gets/strcpy) aynı satırda doğrulanmış akış varsa tekrar raporlanmaz; istek girdisi ulaşmıyorsa
  düşük öncelikli gözden geçirme notuna iner.

* 17. tur eklemeleri:
  * İşaretçi takma adları: `char *p = buf;`, `(char *)buf + n`, `&x[i]`, `strchr(buf, c)` → `*p = …`/`recv(s, p, …)`
    yazımları işaret edilen tampona (çoğu zaman çıkış parametresine) aktarılır; `p = başka` takma adı kaldırır.
  * Ham okunan yapılar: `recv(fd, &hdr, sizeof hdr)` (ya da sarmalayıcı çıkış parametresiyle) okunan yapının
    tamsayı alanları (`hdr.len`) saldırganın seçtiği sayıdır; struct tanımları proje genelinden okunur. Yalnız
    yapının kendisi okunduysa: bir alanına veri yazılmış yapının (`conn->buf`) sayaç alanları program durumudur.
    Çok baytlı ham yorum (`int n = *(int *)buf;`) da sayısaldır; tek bayt okuma ve hesaplama (karma) sayılmaz.
  * Soket tanımlayıcıları: `fd = accept(...)`/`socket(...)` atanmış değişkenden `read()` ağ girdisidir.
  * Okuma uzunluğu: `read/recv/recvfrom/fread/fgets` uzunluğu kirli sayıysa ve işlevde hiç sınırla
    karşılaştırılmıyorsa `memory_len`; tampon aynı uzunlukla ayrıldıysa (`b = malloc(n); read(fd, b, n)`) güvenli.
  * Sabit boyutlu yığın ayırma (`malloc(8)`, `calloc(REQSZ, 1)`) ve yapının dizi alanı (`d->name`) sınırsız
    kopyalamada sabit tampon sayılır; boyutu değişkene bağlı ayırma (`malloc(strlen(s) + 1)`) muaftır.
  * `n += snprintf(buf + n, sizeof buf - n, "%s", kirli)`: `n` üst sınırla karşılaştırılmıyorsa dönüş değeri
    birikimi (`memory_len`).
  * Dosyadan sınırsız `fscanf(f, "%s", yığın_tamponu)`: yerel dosya kökenli taşma; sınırlandırılmış okumalar da
    biçim dizgesi kullanımına `local` köken taşır.
  * CGI: `Content-type: text/html` basan ve QUERY_STRING/ortam ya da standart girdiden (POST gövdesi: `gets`,
    `fgets(stdin)`, `read(0)`) okuyan program; `cgi-bin/` altındaki dosyalar. Kirli biçim dizgesi (`printf(user)`),
    `write(1, …)` ve `fwrite(…, stdout)` da HTML çıktısıdır.
  * Üçlü işleç (`c ? a : b`) değeri a ∪ b; koşuldaki karşılaştırma değeri boşaltmaz.

## Rust

* Kaynaklar: actix-web/axum/rocket/warp/poem/iron çıkarıcıları (`Query/Path/Json/Form/TypedHeader/Multipart`…;
  sayısal jenerik türler hariç, yapı alanı türleri `struct` tanımından okunur), istek nesneleri (`HttpRequest`,
  `&mut Request`), kayıtlı işleyicilerin (`.to(f)`, `get(f)`, `routes![…]`, `#[get]`) `String/Bytes/HeaderMap`
  parametreleri, rocket rota parametreleri (yalnız dize türleri), warp süzgeç kapanışları.
* Hedefler: SQL (`sqlx::query/query_as`, diesel `sql_query/sql::<T>`, rusqlite/postgres/mysql `execute/query/prepare`,
  sea-orm; `query!` makroları ve `.bind()` güvenli), komut (`Command::new(kirli)` ya da `sh -c` ile kirli argüman),
  yol (`fs::*`, `File::open/create`, `NamedFile`; `starts_with`/`canonicalize` ya da doğrulama fonksiyonu denetimi
  arındırır), SSRF (reqwest/ureq/surf/awc/isahc; sabit ana makine → kısmi SSRF), XSS (`Html/RawHtml`,
  `text/html` içerik türlü yanıt gövdesi, içerik türsüz gövdede HTML kalıplı `format!`), açık yönlendirme
  (`Redirect::*`, Location başlığı), SSTI (`Tera::one_off`, `render_str`, handlebars `render_template`),
  sınırsız `bincode` seri çözme, XPath (`sxd_xpath`), LDAP filtresi (`ldap3`), `unsafe` uzunluk/indeks.
* Adlı şablon işleme (`render("x.html", ctx)`) otomatik kaçışlı sayılır; ammonia/html_escape arındırıcıdır.
* Dosya başına (proje başına en çok 10 dosya) bilgi notu: `unsafe` blok/işlev ve `extern "C"` (FFI) kullanımı.

## Bilinen sınırlar

* Yerel dosya içeriği yalnız bellek ve biçim dizgesi hedeflerinde kaynak sayılır; komut, yol, SQL gibi hedeflerde
  yerel aracın olağan dosya kullanımı olarak kalır. `fread(&yapı)` yapının tamamını kirletir; alanlar ayrı ayrı
  kanıtlanmadığı için yapı dize alanları bağlama duyarsız biçimde aynı `local` kökeni paylaşır.
* Bağlam duyarsız yapı kirliliği: yapının bir alanı kirlenirse diğer dize alanları da kirli görünür (alan duyarlılığı yalnız küresel yapılarda).
* Bağlama duyarsız özetler: aynı yardımcıyı farklı bağlamlarda çağıran kodda kaynak gösterimi birleşebilir.

## C/C++ bellek güvenliği motoru (26. tur: `memsafety_c`, `memsafety_clang`, `memsafety_rust`)

Taint motoru yalnız dış girdinin hedefe ulaştığı akışları bulur; kaynaksız bellek hataları (sabit boyut taşması,
use-after-free, double free) için ayrı bir motor vardır. Proje analizinde her C/C++ dosyasında (`.c .h .cc .cpp .cxx
.c++ .hpp .hh .hxx .ipp .inl .ino`) çalışır; dosyanın `#include "x.h"` ettiği proje başlıklarındaki makro/typedef/
yapı tanımları modele katılır.

* Yöntem: `taint_cfamily` önişlemcisi ve fonksiyon çıkarımı üzerine fonksiyon içi, akışa duyarlı soyut yorumlama
  (if/else, for/while/do — iki tur, switch, ileri `goto`; geri `goto` hedefinde değerler bilinmez kabul edilir).
  Nesneler: yığın dizileri, öbek ayırmaları (`malloc/calloc/realloc/new[]/alloca/strdup`; her yürütmede yeni
  kuşak), yapı dizi alanları, dizgi değişmezleri, `argv/getenv`. Kapasite bayt cinsinden sabit, aralık ya da
  simgesel (`strlen(s)+k`, `n × sizeof(T)`); içerik dizgi uzunluğu aralığı (`memset`+sonlandırıcı, değişmez kopyası,
  `fgets` sınırı) ve dış girdi kirliliği izlenir. Koşullar sabit katlanır; NULL denetimi, `p != q` ve tamsayı
  karşılaştırmaları dalları daraltır (çelişen dal ölü).
* Aynı dosyadaki çağrılanlar gerçek argümanlarla satır içi yürütülür (derinlik 2, kök başına en çok 60); C++
  referans parametreleri ve küresel değişkenler taşınır. Büyük çağrılanlar için özet: parametreyi serbest bırakma,
  parametreyi kullanma, parametreden sabit yerel tampona sınırsız kopya, parametre uzunluğuyla sınırlı döngüyle
  parametre tampona yazma (`url_decode(src, dst, max)`), parametre biçim dizgesi.
* "Doğrulanmış bellek hatası" (kesin): boyutlar sabit/simgesel karşılaştırılabilir ve taşma her yolda oluşur;
  tek hedefe kesin use-after-free/double free; dış girdi (argv, stdin, dosya, ağ, ortam) denetimsiz sabit tampona.
  Yalnız bazı yollarda oluşanlar "Olası bellek hatası" (orta/düşük önem; doğrulanmış akış sayılmaz).
* Kanıt alanı: kaynak satırı (girdi ya da free), tampon tanımı satırı ve boyutu, hedef satırı; `memory_safety`
  alanında yapılandırılmış biçimde (`kind, cwe, sink_line, buffer, buffer_line, capacity, source, source_line`).
* Güvenli kalıplar bulgu vermez: doğru boyutla `strncpy/snprintf/strlcpy`, `if (strlen(s) < sizeof buf)` denetimi,
  sabit dizgi kopyası (sığıyorsa), `calloc`, üst sınırı denetlenen sayı. gets/strcpy desen kuralı yalnız C ailesi
  dosyalarında çalışır; motorun boyutları sınırlı kanıtladığı satırda düşük öncelikli nota iner, motor bulgusu
  olan satırda motor bulgusuyla birleşir.
* Ek analizör: `clang --analyze` (varsayılan: `/usr/bin/clang` varsa açık; `SNIPER_CLANG_ANALYZER=0` kapatır,
  `SNIPER_CLANG_BUDGET` toplam saniye, `SNIPER_CLANG_MAX_FILES`). Derleme komutu gerekmez; tek dosya + proje başlık
  dizinleri. Yerel motorla aynı satırdaki bulgu yalnız `clang_confirmed` teyidi alır; yalnız clang'ın bulduğu
  `unix.Malloc`/`cplusplus.NewDelete`/`unix.MismatchedDeallocator` sonuçları "Olası … (clang)" olarak eklenir; alpha
  denetleyicileri yalnız teyit içindir. Kaynak satırı yankılanmaz (`-fno-caret-diagnostics`), proje dışı yollar atılır.
* Rust `unsafe`: `slice::from_raw_parts(X.as_ptr(), n)` (n, `X.len()` ile sınırlanmıyor), denetimsiz
  `get_unchecked`, aynı işaretçiyle iki kez `Box/Vec::from_raw` — yalnız "olası".
* Bilinen sınırlar: dosyalar arası akış (Juliet 22/51+ çok dosyalı varyantlar) yok; yapı alanlarının değerleri
  (memset ile sıfırlanmış bayrak) izlenmez; bayrakla ilişkili koşullar (`if (need_free) free(p)`) "olası" kalır;
  tamsayı aritmetik taşması (ayırma dışı, Juliet CWE-190) ve CWE-170 (sonlandırıcısız dizgi) hedeflenmez;
  geniş dizgi değişmezleri (`L".."`) belirteç çözücüde ayırt edilmediğinden değişmez kaynaklı aşırı okuma raporlanmaz.
