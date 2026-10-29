# Yalnız değişenler (git) ve CI

Sniper, bir git deposundaki **değişen/eklenen** dosyaları ve bunlardan etkilenebilen çağıran dosyaları analiz
edip taban sürümle karşılaştırarak **bu değişikliğin getirdiği yeni bulguları** raporlar. Böylece bir veri
kaynağı değiştiğinde, değişmeyen çağıran dosyada yeni oluşan dosyalar-arası akış gözden kaçmaz.

## Kullanım
- Arayüz: *Uygulama analizi* → Mod: **Yalnız değişenler (git)** → Taban: `HEAD` (kaydedilmemiş değişiklikler),
  `HEAD~1`, `origin/main`, bir commit ya da kayıtlı analiz kimliği `prj_…`.
- API: `POST /api/project-audits` gövdesi `{"project_path": "...", "scope": {"changed_only": true, "base_ref": "origin/main"}}`.
  Sonuçta `changed_scan` özeti (değişen dosyalar, yeni bulgu sayısı, düzelen bulgular ve `incremental_plan`
  telemetrisi) ve her bulguda `is_new`, `in_changed_lines`, `context_fingerprint` alanları bulunur.
- CLI: `python3 /ABSOLUTE/PATH/TO/sniper/cli_reports.py auto-scan <proje> --changed-since origin/main --sarif out.sarif --fail-on high [--no-store]`
  Eşik (`--fail-on`) yalnız değişenler modunda yalnız YENİ bulguları sayar; aşılırsa çıkış kodu 1.
  SARIF 2.1.0 çıktısında `baselineState` (new/unchanged) ve `partialFingerprints.sniperContext/v1` dolu.
- Örnekler: `docs/ci/pre-commit-sniper.sh` (pre-commit kancası), `docs/ci/github-actions-sniper.yml` (kendi
  barındırılan çalıştırıcı için iş akışı). İkisi de yalnız örnektir; Sniper hiçbir şeyi yayınlamaz.

## Nasıl çalışır
1. Taban başvurusu `git rev-parse --verify` ile commit'e çözülür (aralık `..` ve `-` ile başlayan değer reddedilir).
2. Taban ağacı `git ls-tree` ile listelenir; çalışma ağacındaki dosyalar Sniper tarafından ham git blob özetiyle
   karşılaştırılır (eklenen/değişen/silinen; içeriği aynı yeniden adlandırma değişiklik sayılmaz; `.gitignore`
   ile yok sayılan izlenmeyen dosyalar hariç).
3. Sniper kaynak envanterinden sınırlı ve döngü-güvenli bir ters bağımlılık konisi çıkarır. Bulgular değişen
   dosyalar ile bunların geçişli çağıranları için üretilir; doğrudan değişmemiş çağıran bulgusunda
   `in_changed_lines=false` olur. Proje geneli "eksik denetim" bulguları bu modda çalışmaz.
4. Planlayıcı en fazla 10.000 aday, dosya başına 1 MB, toplam 64 MB ve 32 bağımlılık adımı işler. Envanter
   tamamlanamaz veya derinlik sınırı koniyi keserse kısmi sonuca güvenmez; aynı karşılaştırma içinde tam taramaya
   düşer. Sembolik bağlar izlenmez.
5. Seçilen koninin taban hâlleri (`git cat-file --batch`, ham blob) geçici dizine çıkarılıp aynı motorla analiz
   edilir; bulgular **kural + kategori + dosya + başlık + normalize edilmiş kod satırı** parmak iziyle eşlenir
   (satır numarası kullanılmaz → yukarıya satır eklemek "yeni" bulgu üretmez). Eşleşmeyen tabandaki bulgular "düzeldi".
6. Taban kayıtlı bir analiz (`prj_…`) ise tam analiz yapılır ve kayıtlı bulgularla kural + kategori + dosya + başlık
   çoklu kümesiyle karşılaştırılır (eski kayıtlarda kod bağlamı yoktur).

`changed_scan.incremental_plan` alanı koni biçim sürümünü, aday/değişen/bağımlı/atlanmış/taranmış dosya
sayılarını, taranan baytı, koni küçülme oranını ve deterministik `content_sha256`, `config_sha256`,
`tool_sha256`, `invalidation_sha256` özetlerini taşır. Bu alan kaynak metni, dosya başına özet, sır veya dosya
yolu yayımlamaz.

## Güvenlik
Taranan depo güvenilmez kabul edilir. git yalnız nesne veritabanını okuyan komutlarla, kabuksuz, genel/sistem
yapılandırması kapalı (`GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`), `core.fsmonitor=false`,
`core.hooksPath=/dev/null`, `protocol.allow=never` ile çalışır. Çalışma ağacı karşılaştırmasını git değil Sniper
yaptığı için deponun tanımlayabileceği clean/smudge süzgeçleri, textconv/harici diff ve fsmonitor komutları çalışmaz.

## Sınırlamalar
- Değiştirilip yeniden adlandırılan dosya "yeni dosya" sayılır (içerik aynıysa yeniden adlandırma tanınır).
- Bağımlılık konisi statik, sınırlı bir içe aktarma/tanım/çağrı modelidir. Dinamik yükleme veya çalışma zamanında
  kurulan çağrılar kesin çözülemeyebilir; envanter/derinlik güvence sınırı aşıldığında tam tarama geri dönüşü
  kullanılır.
- Alt modüller ve sembolik bağlar izlenmez. Depo başka bir kullanıcıya aitse git `safe.directory` nedeniyle reddeder.
