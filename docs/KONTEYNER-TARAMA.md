# Konteyner imajı / rootfs taraması (18. tur)

Docker daemon olmadan, ağsız işletim sistemi paket açığı taraması.

## Girdiler
- `docker save` tar dosyası (`manifest.json` + katmanlar; birden çok imaj varsa ilki)
- OCI imaj düzeni: dizin ya da tar (`oci-layout`, `index.json`, `blobs/sha256`; çok platformlu dizinde
  makinenin Linux mimarisi ve ARM varyantı seçilir). Eşleşme yoksa ilk taranabilir imaj kullanılır;
  attestasyon, imza, SBOM, OCI artifact ve config descriptor'ları imaj seçimi dışında tutulur. Bir index en
  çok 4.096 descriptor ve sekiz iç içe index düzeyiyle sınırlıdır; descriptor döngüsü veya bildirilen
  manifest/index medya türüyle uyuşmayan içerik açık hatayla reddedilir. Manifest/index blob'larının ve
  katmanların SHA-256 özeti, varsa descriptor boyutu da okunurken doğrulanır; katman özeti sıkıştırılmış akış
  üzerinden hesaplanır ve katman belleğe alınmaz. Katmanlar tar, gzip veya zstd
  olabilir. Zstd, yalnız güvenilir sabit `/usr/bin/zstd` decoder'i hazırsa akış halinde çözülür; yoksa tarama
  açık nedenle reddedilir. Decoder besleme ya da tar açma hatasında alt süreç ve besleme akışı kapatılır.
  Yerel OCI artifact manifestindeki tek ve sınırlandırılmış in-toto/SLSA DSSE payload'u ayrıca seçilen imajın
  descriptor SHA-256 özeti, artifact `subject`/Docker reference lineage ve isteğe bağlı beklenen builder kimliğiyle
  eşlenir. Builder kimliği ham olarak rapora yazılmaz, yalnız SHA-256 parmak izi tutulur. Yerel Ed25519 PEM güven
  kökü hem no-follow okunur hem operator tarafından verilen tam SHA-256 ile sabitlenirse DSSE PAE imzası gerçek
  `cryptography` doğrulamasından geçebilir. Güven kökü yoksa sonuç dürüstçe `structural_only` ve kriptografi
  `not_run` olur; `cosign`, `gh` veya başka bir komut adının metinde bulunması doğrulama sayılmaz.
- Açılmış rootfs dizini ya da tek katmanlı rootfs tar'ı (`docker export`)

Yol, proje analizindeki kuralla yalnız kullanıcı dizini ya da bağlı yerel disk içinde olabilir.

## Güvenlik
Katmanlar diske açılmaz; tar akışı bellekte okunur, yalnız os-release, paket veritabanları ve dil paketi meta
verileri sınırlı boyutta tutulur. `..` içeren adlar, aygıt dosyaları ve FIFO'lar yok sayılır; sembolik bağlar sanal
kök içinde çözülür (kökten yukarı çıkılamaz, 40 atlama sınırı). Whiteout (`.wh.ad`) ve opak dizin
(`.wh..wh..opq`) OCI kurallarıyla uygulanır. Üst katmanda dizin aynı yoldaki alt dosya veya bağı kaldırır;
dosya, bağ ya da özel girdi ise aynı yoldaki alt dizin ağacını gölgeler. Katman (128), girdi (2 milyon), tutulan bayt (768 MB) ve dosya
boyutu bütçeleri vardır. Açılmış rootfs'te ilgi çekici bir meta veri yolu içerideki başka bir normal dosyaya
sembolik bağsa hedef aynı aygıt, kök sınırı ve aynı boyut bütçeleri doğrulanarak okunur; kök dışına çıkan bağlar
yalnız kaydedilir ve içerikleri okunmaz.

## Paket veritabanları
| Dağıtım | Veritabanı | OSV ekosistemi |
|---|---|---|
| Debian | `var/lib/dpkg/status`, distroless `status.d/*` | `Debian:12` … |
| Ubuntu | `var/lib/dpkg/status` | `Ubuntu:24.04:LTS`, `Ubuntu:24.10` … |
| Alpine / Wolfi / Chainguard | `lib/apk/db/installed` | `Alpine:v3.19` …, `Wolfi`, `Chainguard` |
| AlmaLinux / Rocky | `var/lib/rpm/rpmdb.sqlite` | `AlmaLinux:9`, `Rocky Linux:9` (indirme: taban arşiv `AlmaLinux` / `Rocky Linux`) |
| RHEL | `var/lib/rpm/rpmdb.sqlite`, `usr/lib/sysimage/rpm/rpmdb.sqlite` | `Red Hat Enterprise Linux:8`, `:9` … |
| Amazon Linux | rpm sqlite | `Amazon Linux:2`, `Amazon Linux:2023` |
| SLES / openSUSE Leap | rpm sqlite | `SUSE Linux Enterprise Server:15.5`, `openSUSE Leap:15.6` … |

RPM SQLite okuyucu yalnız gerçek `Packages` tablosunu kabul eder; view/sanal tabloyu reddeder, satırları akışla
ve 100.000 paket sınırıyla okur. Standart rpm `8e ad e8` magic/version önekli Header export satırları ile eski
öneksiz satırları ayrıştırır; bozuk tür/başlık satırını ve NUL sonlandırıcısı olmayan string etiketini güvenli
biçimde atlar. Eski BerkeleyDB/NDB rpm veritabanı paketleri henüz ayrıştırılmaz. BerkeleyDB, DB_HASH
metadata magic/sürüm/sayfa boyutu birlikte doğrulanarak; `Packages.db` ise doğrulanmış NDB magic'i
bulunmadığı için yalnız `ndb_candidate` olarak raporlanır. Bu durumda ve desteklenen paket veritabanının
bulunmadığı diğer durumlarda `os_packages` kontrolü **pass olmaz**; `na` ve
`container.package_inventory.reason` (`legacy_rpmdb_unsupported` / `package_database_missing`) döner.
`var/lib/rpm` ile `usr/lib/sysimage/rpm` altındaki `Packages` / `Packages.db` yolları kapsanır. Sürüm uzantılı
arşivi olmayan ailelerde (AlmaLinux,
Rocky, LTS olmayan Ubuntu) taban arşiv indirilir; kayıtlar yine tam ekosistem adıyla süzülür. RHEL türevi hata
düzeltme/iyileştirme duyuruları (ALBA/ALEA/RLBA/RLEA) güvenlik açığı sayılmaz. Açıklar kaynak paket adı ve kaynak sürümüyle eşlenir
(Debian/Ubuntu OSV kayıtları kaynak paket adını kullanır). Sürüm karşılaştırmaları: `os_versions.py` (dpkg — gerçek
`dpkg --compare-versions` ile 1861 çiftte birebir; apk; rpm).

Önem: Ubuntu önceliği → Debian aciliyeti (`unimportant` → bilgi) → CVSS v3 → yoksa orta. Dağıtım duyuruları
(USN/DSA/DLA) CVE'leri aynı pakette ayrı kayıtla raporlanıyorsa ayrıca bulgu olmaz.

## OSV veritabanını indirme
```
python3 scripts/osv_refresh.py --ecosystem Debian:12 --ecosystem Ubuntu:24.04:LTS --ecosystem Alpine:v3.19
```
Boyutlar (2026-10): Alpine:v3.19 6,5 MB, Debian:12 43 MB, Ubuntu:24.04:LTS 142 MB. Arşiv SHA-256'sı manifestle
doğrulanır; ilk taramada kurulan paket dizini `index-cache/` altında arşiv özetine bağlı önbelleklenir.

## Kullanım
- Arayüz: Uygulama analizi → "Konteyner imajını yerelde incele". Sonuç proje analizi olarak kaydedilir
  (`audit_kind: container`): bulgu takibi, portföy, yönetici özeti, HTML/PDF rapor aynı yoldan çalışır. Paket
  yükseltilince kaybolan açık "düzeldi" sayılır (paket veritabanı okunduysa).
- API: `POST /api/container-images {"image_path": "...", "dockerfile_path": "...", "ignore_unfixed": false,
  "expected_provenance_identity": "...", "provenance_public_key_path": "...",
  "provenance_public_key_sha256": "<64-hex>"}`
  (analist; iş kuyruğunda da çalışır). `dockerfile_path` isteğe bağlıdır; en çok 1 MB, UTF-8 ve sembolik
  bağ olmayan yerel dosya olmalıdır. Çok aşamalı Dockerfile'ın yalnız son aşamasından miras alınan/kurulan
  apt/apt-get/aptitude/apk/dnf/dnf5/tdnf/yum/microdnf/pacman/pkg/rpm-ostree/zypper/eopkg paketleri imaj envanteriyle eşlenir. `RUN` için kabuk ve JSON exec biçimleri
  desteklenir; `env`/`command`/`exec` sarmalayıcılarının sınırlı güvenli seçenekleri izlenir ve paket yöneticisi
  yalnız gerçek komut konumundayken kurulum sayılır. Kabuk biçiminde ve JSON içindeki `sh -c` komutunda alıntı
  dışındaki sözcük başı `#` işaretinden sonrası yorumdur; sözcük içindeki, kaçırılmış veya alıntılanmış `#`
  komutu kesmez. APT/RPM `reinstall`, açık paketli APK `fix`/`upgrade`, RPM yöneticilerinin `upgrade/update` ve dnf/yum `distro-sync`, zypper `update/up` ve eopkg `upgrade/up` işlemleri paket varlığını kurar; APT `remove/purge/autoremove`, APK `del`, RPM yöneticilerinin `remove/erase` ve zypper
  `remove/rm`, rpm-ostree `uninstall` ve eopkg `remove` işlemleri Dockerfile sırasıyla uygulanır; sonradan kaldırılan açık paket adı son aşama bağına girmez.
  APK `--virtual`/`-t` gruplarının sabit üyeleri aşama ve tam kök aşama kopyası boyunca izlenir; yinelenen grup eklemeleri birleştirilir. Aynı `RUN` içindeki komutlar sırasıyla uygulanır. Grup `apk del` ile kaldırıldığında yalnız başka bir sanal gruba veya açık doğrudan kuruluma ait olmayan üyeler son imaj paket bağından çıkarılır.
  Aşama kapsamındaki en fazla 32 güvenli literal tokenden oluşan sabit `ENV` ve literal varsayılanlı `ARG` değerleri shell biçimli `RUN` ve JSON
  `sh -c` içinde paket adına genişletilir ve taban alınan adlandırılmış aşamaya miras kalır. `ENV`, aynı aşamadaki
  bir `ARG` değerini yakalayabilir ve `RUN` sırasında aynı adlı `ARG` değerinin önüne geçer. Doğrudan JSON exec,
  tek tırnaklı, kabuk meta karakterli, sınırı aşan veya yeniden bilinmeyen değere atanmış değişkenler paket kökeni üretmez.
  Shell biçimindeki `${AD:-literal}` ve `${AD-literal}` varsayılanları yalnız güvenli ve tek-token literal için
  çözülür. Bilinen boş değer `-` için ayarlanmış sayılır, `:-` için varsayılanı seçer; dolu görünen değer iki
  işleçte de varsayılanın önüne geçer. Dinamik/iç içe varsayılanlar tahmin edilmez.
  RPM yöneticilerinde `paket.x86_64`, `paket.aarch64` veya
  `paket.noarch` gibi sabit bilinen mimari seçicileri envanterdeki paket adına indirgenir. Açık mimarili ve
  sayısal sürüm kanıtlı `name-[epoch:]version-release.arch` NEVRA belirtimi de paket adına bağlanır; mimarisiz
  ya da belirsiz tireli belirtim tahmin edilmez, bilinmeyen noktalı ekler ve `python3.12` gibi gerçek noktalı
  adlar korunur. APT yöneticilerinde `paket:amd64=sürüm` gibi yalnız bilinen Debian mimarili çoklu mimari
  belirtimleri ile `paket/dağıtım` seçicileri envanter adına indirgenir; bilinmeyen mimari ekleri korunur.
  APK yöneticisinde `paket=sürüm`, `paket>=sürüm`, `paket~sürüm` ve `paket~=sürüm` gibi sabit sürüm
  karşılaştırmaları ile `paket@repo` depo etiketi kurulu Alpine paket adına indirgenir; boş depo etiketi veya
  bozuk karşılaştırma envanter adına bağlanmaz.
  Adlandırılmış aşamadan
  `COPY --from=<aşama> / /` ile tam kök dosya sistemi scratch son aşamasına taşınırsa paket kökeni de miras alınır;
  `/`, `/.` ve `/./` kök eşdeğerleri kabuk ve JSON biçiminde tanınır, dar dosya kopyaları bütün aşama paketlerini
  miras almaz. İlk `FROM` öncesindeki güvenli literal varsayılanlı global `ARG`, sonraki `FROM` ifadesinde daha
  önceki bir aşamayı seçiyorsa bu aşamanın paket bağı korunur. Global `ARG` değeri `RUN` içinde ancak aşamada
  yeniden bildirildiğinde görünür. Güvenli tek-token literal tırnaklıysa Dockerfile sözcük kurallarıyla çözülür;
  varsayılanı olmayan ve daha önce görünür değeri bulunmayan ya da çözülemeyen build argümanlarından paket bağı çıkarılmaz.
  SBOM: `GET /api/container-images/<analiz>/sbom`.
- CLI: `python3 cli_reports.py image <yol> [--dockerfile Dockerfile] [--view json] [--sbom çıktı.json]
  [--provenance-identity ID] [--provenance-public-key key.pem]
  [--provenance-public-key-sha256 <64-hex>] [--save] [--ignore-unfixed] [--fail-on high]`.
  `--provenance-public-key` ve özeti birlikte verilmelidir; anahtar yolu izin verilen yerel kökte normal dosya
  olmalı ve hiçbir sembolik bağ bileşeni içermemelidir. `--dockerfile`, API ile aynı yerel dosya ve sembolik bağ
  kontrollerini kullanır; JSON görünümünde paket bağı `container.build_context` alanında döner.

## Dil paketleri
PyPI (`*.dist-info/METADATA`), npm (`node_modules/*/package.json`) ve Maven (jar/war içindeki `pom.properties`,
bir düzey iç jar) bileşenleri çıkarılır ve SBOM'a girer. Açık eşleştirmesi çok ekosistemli OSV eşleyicisine
bırakılmıştır: `container_scan.set_language_matcher(fn)` — `fn(bileşenler) → bulgular`.
