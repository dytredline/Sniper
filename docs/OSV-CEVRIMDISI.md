# Çevrimdışı OSV — çok ekosistem (18. tur)

Bağımlılık açıkları, resmî OSV deposundan indirilmiş yerel arşivlerle **ağa çıkmadan** eşlenir.

| Ekosistem | Envanter kaynakları |
|---|---|
| npm | package-lock.json, pnpm-lock.yaml, yarn.lock |
| PyPI | requirements.txt (yalnız `==`), pyproject.toml, poetry.lock, Pipfile.lock, uv.lock |
| Go | go.mod + go.sum (go.mod'da olmayan modüller, en yüksek sürüm) |
| Maven | pom.xml, gradle.lockfile, build.gradle(.kts) |
| RubyGems | Gemfile.lock (platform eki atılır) |
| crates.io | Cargo.lock |
| Packagist | composer.lock |
| NuGet | packages.lock.json, kökteki *.csproj / Directory.Packages.props, packages.config |
| Pub | pubspec.lock |
| Hex | mix.lock (`:hex` kayıtları) |

## Güncelleme

```
python3 /ABSOLUTE/PATH/TO/sniper/scripts/osv_refresh.py            # yapılandırılmış tüm ekosistemler
python3 /ABSOLUTE/PATH/TO/sniper/scripts/osv_refresh.py --status   # ekosistem başına durum
```

Liste: `SNIPER_OSV_ECOSYSTEMS=npm,PyPI,Go` ya da `~/.local/state/sniper/osv-db/ecosystems.json`
(`{"ecosystems": ["npm", "PyPI"]}`); yoksa varsayılan liste (npm, PyPI, Go, Maven, RubyGems, crates.io,
Packagist, NuGet, Pub, Hex). Bir ekosistem başarısız olsa diğerleri güncellenir. `sniper-osv-refresh.timer`
haftada iki kez aynı komutu çalıştırır. Toplam indirme ≈300 MB (npm ≈220 MB).

## Güven

* Her manifest yerel denetim anahtarıyla HMAC imzalıdır (npm için ayrıca systemd SHA-256 pini).
* Arşivin SHA-256'sı ve güncelleme sırasında üretilen paket dizininin (`package-index.json.gz`) SHA-256'sı
  imzalı manifesttedir; uyuşmazlıkta o ekosistem atlanır ve uyarı verilir.
* 7 günden eski veri kullanılır ama "bayat" uyarısı verilir.

## Tarama

* Arayüz: Uygulama analizi › SBOM ve bağımlılık açıkları › "Çevrimdışı OSV ile tara (tüm ekosistemler)".
* API: `POST /api/dependency-security/offline-scan` `{"project_path": "...", "confirm_local": true}`;
  durum: `GET /api/dependency-security/offline-db`.
* CLI: `python3 cli_reports.py osv-offline <proje> [--no-save]`.

Sürüm karşılaştırma: SEMVER (npm, Go, crates.io, Pub, Hex), PEP 440, Maven ComparableVersion, RubyGems,
NuGet, Composer; GIT aralıkları kullanılmaz. Takma adlar (PYSEC/GHSA/GO/CVE) tek bulguya indirilir; Go'da
sembol bilgisi taşıyan GO- kaydı temsilcidir (VEX/erişilebilirlik sembolleri kullanır).

Kök ve alt proje manifestleri okunur. Kilitsiz npm aralıkları yalnız sembolik bağ olmayan yerel `node_modules`
paket sürümü aralığa uyuyorsa kullanılır. Maven proje dışı üst POM ve import BOM'ları yalnız açıkça ayarlanan
`SNIPER_MAVEN_REPOSITORY` deposundan, ağsız okunur. Çözülemeyen `${…}`, `dev-main` ve desteklenmeyen aralıklar atlanır.
