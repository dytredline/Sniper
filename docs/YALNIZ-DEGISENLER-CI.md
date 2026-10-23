# Yalnız değişenler (git) ve CI

Sniper, bir git deposundaki projenin yalnız **değişen/eklenen** dosyalarını analiz edip taban sürümle
karşılaştırarak **bu değişikliğin getirdiği yeni bulguları** raporlar.

## Kullanım
- Arayüz: *Uygulama analizi* → Mod: **Yalnız değişenler (git)** → Taban: `HEAD` (kaydedilmemiş değişiklikler),
  `HEAD~1`, `origin/main`, bir commit ya da kayıtlı analiz kimliği `prj_…`.
- API: `POST /api/project-audits` gövdesi `{"project_path": "...", "scope": {"changed_only": true, "base_ref": "origin/main"}}`.
  Sonuçta `changed_scan` özeti (değişen dosyalar, yeni bulgu sayısı, düzelen bulgular) ve her bulguda
  `is_new`, `in_changed_lines`, `context_fingerprint` alanları bulunur.
- CLI: `python3 ~/.local/share/sniper/app/cli_reports.py auto-scan <proje> --changed-since origin/main --sarif out.sarif --fail-on high [--no-store]`
  Eşik (`--fail-on`) yalnız değişenler modunda yalnız YENİ bulguları sayar; aşılırsa çıkış kodu 1.
  SARIF 2.1.0 çıktısında `baselineState` (new/unchanged) ve `partialFingerprints.sniperContext/v1` dolu.
- Örnekler: `docs/ci/pre-commit-sniper.sh` (pre-commit kancası), `docs/ci/github-actions-sniper.yml` (kendi
  barındırılan çalıştırıcı için iş akışı). İkisi de yalnız örnektir; Sniper hiçbir şeyi yayınlamaz.

## Nasıl çalışır
1. Taban başvurusu `git rev-parse --verify` ile commit'e çözülür (aralık `..` ve `-` ile başlayan değer reddedilir).
2. Taban ağacı `git ls-tree` ile listelenir; çalışma ağacındaki dosyalar Sniper tarafından ham git blob özetiyle
   karşılaştırılır (eklenen/değişen/silinen; içeriği aynı yeniden adlandırma değişiklik sayılmaz; `.gitignore`
   ile yok sayılan izlenmeyen dosyalar hariç).
3. Bulgular yalnız değişen dosyalar için üretilir; dosyalar arası taint bağlamı tüm projeden gelir. Proje geneli
   "eksik denetim" bulguları bu modda çalışmaz.
4. Değişen dosyaların taban hâlleri (`git cat-file --batch`, ham blob) geçici dizine çıkarılıp aynı motorla analiz
   edilir; bulgular **kural + kategori + dosya + başlık + normalize edilmiş kod satırı** parmak iziyle eşlenir
   (satır numarası kullanılmaz → yukarıya satır eklemek "yeni" bulgu üretmez). Eşleşmeyen tabandaki bulgular "düzeldi".
5. Taban kayıtlı bir analiz (`prj_…`) ise tam analiz yapılır ve kayıtlı bulgularla kural + kategori + dosya + başlık
   çoklu kümesiyle karşılaştırılır (eski kayıtlarda kod bağlamı yoktur).

## Güvenlik
Taranan depo güvenilmez kabul edilir. git yalnız nesne veritabanını okuyan komutlarla, kabuksuz, genel/sistem
yapılandırması kapalı (`GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`), `core.fsmonitor=false`,
`core.hooksPath=/dev/null`, `protocol.allow=never` ile çalışır. Çalışma ağacı karşılaştırmasını git değil Sniper
yaptığı için deponun tanımlayabileceği clean/smudge süzgeçleri, textconv/harici diff ve fsmonitor komutları çalışmaz.

## Sınırlamalar
- Değiştirilip yeniden adlandırılan dosya "yeni dosya" sayılır (içerik aynıysa yeniden adlandırma tanınır).
- Aynı satırda kod değişmeden yalnız taint kaynağı başka dosyada değişirse bulgu "değişmedi" sayılabilir
  (bulgu dosyası değişmediği için raporlanmaz); bu durumlar tam taramada görünür.
- Alt modüller ve sembolik bağlar izlenmez. Depo başka bir kullanıcıya aitse git `safe.directory` nedeniyle reddeder.
