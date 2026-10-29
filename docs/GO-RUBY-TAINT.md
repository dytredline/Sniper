# Go ve Ruby hızlı veri akışı (taint) analizi

`taint_goruby.py` — proje analizine (Uygulama analizi) bağlı, saniyeler içinde çalışan dosyalar arası motor.
Joern derin analiz olarak kalır; Joern Go/Ruby bulguları hızlı motorla eşleşiyorsa `fast_engine_match: true`
ile işaretlenir (aynı açık iki ayrı yeni bulgu gibi görünmez).

## Ayrıştırıcı kararı

Saf Python belirteç + yapı ayrıştırıcısı; harici ikili ya da kütüphane yok. Gerekçe:

* Ruby çalışma zamanı ve tree-sitter sistemde yok; yeni ikili servis sandbox'ında ek pin ve yürütme yüzeyi demek.
* Go araç zinciri var ama pinli değil; `go/ast` için her taramada derlenmiş yardımcı çalıştırmak gerekirdi.
* Go'nun otomatik noktalı virgül kuralı ve Ruby'nin `def`/`end` derinliği deyim sınırlarını güvenilir verir;
  ihtiyaç duyulan şey ifade düzeyinde iz yayılımı (tam tür denetimi değil).

## Kapsam

* **Go:** `net/http` (`*http.Request`, Go 1.22 `PathValue` ve `BasicAuth` kimlik bilgileri dahil), gin, echo, fiber, httprouter, gorilla/mux, chi kaynakları; `database/sql`,
  sqlx, gorm (yalnız dize birleştirme), `os/exec` (ad ya da `sh -c` betiği), `html/template` tür dönüşümleri,
  `http.ResponseWriter` yazımı (Content-Type HTML dışıysa değil), `text/template`, `http.Get/NewRequest` (sabit
  ana makine + yol → `ssrf_partial`), `os`/`ioutil` dosya işlemleri, `http.Redirect` (göreli sabit önek güvenli),
  `template.Parse`. Arındırıcılar: `strconv`, `html.EscapeString`, `url.QueryEscape`, `filepath.Base`,
  hazır ifadeler (`Prepare` → `stmt.Query(args)`), serileştiriciler (`json.Marshal`, `ToRss`). İşlev değerli yapı
  alanları yapı türü, alan adı ve yerel örnek değerine göre ayrılır; anahtarlı, konumsal ve gömülü yapı
  değişmezlerindeki yükseltilmiş işlev alanları desteklenir. Gerçek `type A = B` takma adları paket kimliğiyle
  çözülür; yeni tanımlı `type A B` türleri alttaki türün yöntemlerini devralmış sayılmaz. Anonim gömülü değer ve
  işaretçi türlerinin yükseltilmiş yöntemleri, yöntem değerleri ve düz akıştaki somut interface atamaları kesin
  alıcı türüne bağlanır. Tür/gömme yürüyüşü 6 düzey ve 256 alıcı türüyle sınırlıdır; sınır aşılırsa analiz
  `go-method-receivers` kısıtıyla kısmi işaretlenir. Aday sınırı aşıldığında güvenlik etkili geç hedefler korunur.
  Bilinen dış Go türleri içe aktarma takma adları çözüldükten sonra sınıflandırılır; `*http.Request.Clone` ve
  `WithContext` dönüşleri istek alıcı türünü korur, böylece yeni değer üzerindeki `FormValue`, `BasicAuth` ve
  diğer istek kaynakları izlenmeye devam eder. `net/http` `RemoteAddr`, Gin `ClientIP`, Echo `RealIP` ve Fiber `IP`/`IPs` istemci adresleri
  istek kaynağıdır. Gin `ContentType`, Echo `Scheme` ve Fiber `Protocol` da doğrulanmış çatı alıcısında istek meta verisi kaynağıdır. Gin `ShouldBindBodyWithJSON/XML/YAML/TOML/Plain` kolaylıkları ile
  `BindTOML`, `BindPlain` ve `ShouldBindPlain` hedef yapıya istek gövdesi kökenini taşır. Fiber v3 `c.Bind()` zincirindeki `Body`, `Query`, `URI`, `Header`,
  `Cookie` ve `All` bağlayıcıları da yalnız doğrulanmış `*fiber.Ctx` alıcısında hedef yapıya istek kökenini taşır.
  `net/http` `ParseMultipartForm` yalnız isteğin form durumunu hazırlar; döndürdüğü `error` istek verisi sayılmaz,
  sonraki `FormValue`/`PostFormValue` erişimleri kaynak olmaya devam eder.
  Türü doğrulanmış `*http.Request.Method`, `Proto` ve `TransferEncoding` alanları da gelen istek kaynağıdır; yerel aynı adlı yapı alanları kaynak sayılmaz.
  Hemen çağrılan anonim işlevlerde normal, `go` ve `defer` çağrı argümanları anonim işlev parametrelerine taşınır;
  sabit argümanlar istek kökeni üretmez.
* **Ruby/Rails/Sinatra:** `params`, `request.*` (`ip`/`remote_ip`/`remote_addr` istemci adresleri, `forwarded_for` zinciri, `get_header`/`fetch_header` ve başlıktan gelebilen `request_id`/`uuid`/`media_type`/`content_mime_type`/`format`/`formats`/`protocol`/`scheme`/`port`/`server_protocol`/`server_name` dahil), `cookies` (denetleyici, yardımcı, görünüm, `app/api`, Sinatra);
  ActiveRecord dize koşulları (`where("…#{x}")`, `order`, `pluck`, eski `find(:all, :conditions => …)`),
  `connection.execute`, `Arel.sql`; `system`/`exec`/ters tırnak/`%x`/`Open3`/`IO.popen`/`Kernel#open`; `eval`,
  `constantize`, `send(x)`, `render inline:`; `html_safe`, `raw`, `<%== %>`, `link_to` adresi, `render text:`;
  `redirect_to` (Rails 7+ `raise_on_open_redirects` açıkken yalnız `allow_other_host: true`); `send_file`,
  `File.*`, `render file:/dinamik şablon`; `Net::HTTP`, HTTParty, Faraday …; `Marshal.load`, `YAML.load`
  (`safe: true` hariç), `Oj.load` (güvenli modlar hariç). Denetleyici `@değişken`leri ERB görünümlerine
  (örtük ve açık `render`) ve `before_action` sırası (prepend/append/skip, only/except) taşınır. ActiveSupport
  concern'leriyle `include` edilen callback'ler sınıf ve üst sınıf sırasına katılır. Callback filtreleri sembol,
  dize ve `%i/%w` biçimlerini; anonim `do … end` ve `{ … }` callback bloklarını; konumsal `-> { … }`,
  `lambda { … }`, `proc { … }` ve `Proc.new { … }` çağrılabilir filtrelerini kapsar. Aynı sınıfta veya üst
  düzeyde lambda/proc değerine bağlanan sabitler de konumsal filtre olarak izlenir; doğrudan yeniden atamada son
  değer kazanır, koşullu yeniden atamalarda olası çağrılabilir gövdeler birleştirilir. Başka bir sınıfın aynı adlı
  sabiti kullanılmaz. `if:`/`unless:` koşul lambdaları callback gövdesi olarak yürütülmez.
* **Kesinlik önlemleri:** iç bloklarda zayıf güncelleme; üçlü işleç ve karşılaştırma koşullarının izi değere
  geçmez; izin listesi korumaları (`return … unless LISTE.include?(x)`, `if LISTE.include?(x)`); karma
  argümanlar (`params.permit(...)`, parantezli veya parantezsiz karma şemalı Rails 8 `params.expect`/`params.expect!`, `where(anahtar: x)`);
  skaler `params.expect(:anahtar)`, `params.expect :anahtar` ve bunların `expect!` biçimleri SQL parçası olarak izlenmeye devam eder; model sorgularının sonucu istek verisi sayılmaz;
  denetleyici/iş yöntemleri ada göre başka sınıflara bağlanmaz.
  Go'da gerçek `path/filepath` içe aktarmasının `!filepath.IsLocal(ad)` koşulu yalnız olumsuz dal işlev
  düzeyinde kesin `return` ile bittiğinde, sonraki dosya hedefleri için `ad` değişkenini yol bakımından
  arındırır. Takma adlı içe aktarma desteklenir. Pozitif/karmaşık koşullar, dönmeyen dallar, yalnız iç bloktan
  dönen dallar ve gölgelenmiş paket adları kanıt sayılmaz; doğrulamadan sonraki yeniden atama arındırmayı taşımaz.

## Ölçüm (13. tur, scratchpad `gr_eval.py`, `gr_joern_score.py`)

Zemin gerçeği: govwa/railsgoat (Joern çok dilli tablo), go-dvwa (elle), Brakeman test uygulamaları rails3–rails8
(`assert_warning` açık / `assert_no_warning` güvenli; yalnız params/cookies/request kaynaklı taint türleri).

| Küme | TP | FN | Güvenlide FP | TN | Süre |
|---|---|---|---|---|---|
| Hızlı motor, 12 uygulama | 137 | 109 | 1 | 160 | toplam ≈0,2 sn |
| Hızlı motor, Joern ile ortak 5 uygulama | 55 | 12 | 1 | 68 | ≈0,1 sn |
| Joern, aynı 5 uygulama (soğuk önbellek) | 33 | 34 | 9 | 60 | ≈63 sn |

Kalan FN'lerin çoğu: modellerde `params` (gerçekçi değil), kayıtlı model verisinden XSS (`raw @user.name`),
eski Rails CVE'lerine özgü kalıplar (`content_tag`, `select_tag`, dinamik bulucular), HAML, işlev değeri
gönderimi (go-test-bench).

Ruby'de `send`/`__send__` için sabit sembol veya interpolasyonsuz sabit dize yöntem adı, private/protected
yöntemler dahil proje yöntemine çözülür. `public_send` aynı kesin çözümlemeyi yalnız ayrıştırıcının public
olarak izlediği yöntemlere uygular; `private`, `protected`, `public` ve adlandırılmış görünürlük değiştiricileri
modelde tutulur. Aynı sınıf ve yöntem yeniden açılıp tanımlandığında kaynak yükleme sırasındaki son koşulsuz
tanım etkin olur; koşullu tanımlar ise önceki olası tanımla birlikte korunur. `if true/false` ve
`unless true/false` altındaki tanımlar kesin çalışan/çalışmayan olarak ayrılır. `elsif`/`else` zincirleri
önceki dallardan kalan yolları birikimli izler; kesin alınmış bir dal sonraki dalları erişilemez yapar ve tüm
erişilebilir kollar aynı yöntemi yeniden tanımlıyorsa eski tanım etkin adaylardan çıkarılır. İç içe zincirlerde
yalnız en yakın dal kaydı güncellenir. Bare ve adlandırılmış görünürlük değiştiricileri de aynı dal kesinliğine
tabidir: erişilemeyen kollar state değiştirmez, kesin kollar tek sonuç üretir, bilinmeyen erişilebilir kolların
görünürlükleri ise zincir sonunda olası alternatifler olarak birleşir. Aynı üç durumlu kural `private if false`,
`public :method if condition` ve `unless` kullanan postfix görünürlük çağrılarına da uygulanır. Sabit alıcılı yansıtmalı çağrı,
çağıranın lexical namespace'indeki tam sınıfa bağlanır; birden çok namespace'de kalan kısa ad tahmin edilmez.
`public_send` hedef çözümü bare/self veya bu tam lexical sabit alıcılarla sınırlıdır; türü bilinmeyen değişken
alıcısı yöntem adına göre başka sınıfa bağlanmaz.
ActiveSupport `try`/`try!`,
nil/arity/block semantiği ayrıca modellenmeden `send` eşdeğeri
sayılmaz. İnterpolasyonlu ya da istekten gelen yöntem adı tahmin edilmez ve kesin çağrı modeliyle hedefe bağlanmaz.

Olgun projelerde yanlış alarm (doğrulanmış akış): writefreely 0, gogs 0, memos 0 (Go); lobsters 0,
rubygems.org 0, mastodon 0 (Ruby). Proje analizinin tamamı mastodon'da (5.064 dosya) ≈20 sn.
