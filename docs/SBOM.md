# SBOM: dışa aktarma, içe aktarma ve tarama (20. tur)

Ağ kullanılmaz; tüm eşleşmeler yerel (imzalı) OSV veritabanıyla yapılır.

## Dışa aktarma

* **CycloneDX 1.5** (kayıtlı biçim): purl, lisans (`license.id` / `expression` / `name`), araç bilgisi
  (`metadata.tools`), kök bileşen (`bom-ref: sniper-root`) ve kilit dosyalarından **bağımlılık ilişkileri**
  (`dependencies`). Belge deterministiktir; zaman damgası indirirken kaydın oluşturulma anından eklenir.
* **SPDX 2.3 JSON**: aynı içerikten dönüştürülür — paketler (`externalRefs` purl), `licenseDeclared` (SPDX
  ifadesi; yalnız adı bilinen lisans `LicenseRef-…` + `hasExtractedLicensingInfos`), `DESCRIBES` ve `DEPENDS_ON`
  ilişkileri, `creationInfo` (araç, kuruluş, zaman).
* İlişkiler: `package-lock.json` v1/v2/v3 (iç içe `node_modules` çözümlemesi), `npm-shrinkwrap.json`,
  `Cargo.lock`, `poetry.lock`, `composer.lock` (+ `composer.json` doğrudanları), `Gemfile.lock`, `go.mod`
  (yalnız doğrudan / `// indirect` ayrımı). İlişkisi bilinmeyen bileşenler köke bağlanır.
* Doğrulama yapısaldır (`sbom_formats.validate_cyclonedx` / `validate_spdx`): zorunlu alanlar, kimlik biçimleri,
  başvuru bütünlüğü. Resmî JSON Schema dosyaları ve `jsonschema` çevrimdışı kurulu olmadığından vendored şema yok.

| Nerede | Nasıl |
|---|---|
| API | `GET /api/dependency-sboms/<id>?format=spdx` (varsayılan `cyclonedx`); konteyner: `GET /api/container-images/<id>/sbom?format=spdx` |
| CLI | `cli_reports.py sbom export <proje> -o bom.json [--format spdx]` (eski `sbom <proje> -o` da geçerli) |
| Arayüz | SBOM ve bağımlılık açıkları panelinde her SBOM bağlantısının yanında **SPDX** |

## Dış SBOM tarama

CycloneDX (JSON/XML) ya da SPDX (JSON/tag-value) dosyası yüklenir; bileşenler purl'lerine göre ayrılır:

* dil paketleri (`pkg:npm`, `pypi`, `maven`, `golang`, `gem`, `cargo`, `composer`, `nuget`, `pub`, `hex`) →
  çevrimdışı çok ekosistemli OSV;
* işletim sistemi paketleri (`pkg:deb` / `apk` / `rpm` + `distro=debian-12` / `ubuntu-22.04` / `alpine-3.19`) →
  konteyner taramasının OSV dizini.

Sonuç `audit_kind: sbom` olan bir analiz olarak kaydedilir (bulgu takibi, portföy). Ayrı bir istekte SBOM'dan
kaybolan açık "düzeldi" sayılır. VEX (OpenVEX / CycloneDX) bu taramadan üretilir; kaynak kod olmadığı için
erişilebilirlik ve "paket yok" kanıtı kullanılmaz (durum `affected` ya da `under_investigation`).

Güvenlik: dosya ≤ 32 MB, ≤ 50.000 bileşen; XML'de `DOCTYPE`/`ENTITY` reddedilir; sembolik bağ ve izinli kökler dışı
reddedilir.

| Nerede | Nasıl |
|---|---|
| API | `POST /api/dependency-security/sbom-scan` `{"sbom_path": "...", "confirm": true}` (analist); VEX: `GET /api/dependency-security/sbom-scans/<id>/vex?format=openvex\|cyclonedx` |
| CLI | `cli_reports.py sbom scan bom.json [--save] [--vex openvex --vex-out vex.json] [--fail-on high]` |
| Arayüz | SBOM paneli → "Dış SBOM dosyası" formu (onay kutusu), sonuçta VEX indirme bağlantıları |

## Lisans (yerel paket önbellekleri)

Projede bulunmayan lisanslar şu yerel önbelleklerden, koordinattan hesaplanan tam yolla okunur (yalnız okuma,
sembolik bağla kök dışına çıkılmaz, bütçeli): Maven `~/.m2/repository` (pom ve üst pom zinciri), Cargo
`~/.cargo/registry/src`, NuGet `~/.nuget/packages` (`.nuspec`), Go modül önbelleği (açılmış dizin ya da
`cache/download` zip'i), kurulu gem `specifications`. Ayrıca projedeki üst `pom.xml` (relativePath) ve alt
dizinlerdeki `composer.lock`. `SNIPER_LICENSE_CACHE_HOME=""` önbellekleri kapatır. `poetry.lock`/`uv.lock`
lisans bilgisi taşımadığından Python lisansları yalnız kurulu `dist-info` ile bulunur.
