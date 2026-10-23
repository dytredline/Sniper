# CI/CD güvenlik kapısı (21. tur)

`cli_reports.py ci <proje>` tek çalıştırmada — **ağsız** — proje analizini (taint akışları, desen kuralları,
IaC, lisans, tedarik zinciri/kötü amaçlı paket, API sözleşmesi) ve çevrimdışı çok ekosistemli SCA'yı
(yerel OSV + kullanım/öncelik) yapar, politikaya göre karar verir ve raporları üretir.

```
python3 cli_reports.py ci . --sarif sniper.sarif --gitlab-dir . --summary ozet.md --json karar.json \
    [--policy .sniper-policy.json] [--baseline-sarif onceki.sarif | --baseline-audit prj_… | --baseline-ref origin/main] \
    [--no-sca] [--store]
```

| Çıkış kodu | Anlamı |
|---|---|
| 0 | Geçti |
| 1 | Politika ihlali (eşik aşıldı, kötü amaçlı paket, yasak lisans, SLA …) |
| 2 | Yapılandırma/kullanım hatası (politika dosyası, taban bulunamadı, git tabanı çözülemedi) |
| 3 | Analiz hatası (proje okunamadı, `require_osv` iken OSV yok, üretilen rapor geçersiz) |

Proje yolunu operatör açıkça verdiği için izinli kök projenin üst dizinidir (CI çalışma dizinleri kullanıcı dizini
dışında olabilir). `--store` verilmedikçe veritabanına yazılmaz.

## Çıktılar
* **SARIF 2.1.0** (GitHub code scanning): tüm gruplar tek çalıştırmada; kararlı kural kimlikleri
  `sniper/<grup>/<kimlik>` (IaC denetim kimliği, `taint-<hedef türü>`, CWE ya da OSV/GHSA kimliği);
  `partialFingerprints.sniperTrack/v1` = bulgu takibi parmak izi (SCA'da ekosistem+paket+sürüm+açık);
  `security-severity`, etiketler (`security`, grup, `external/cwe/cwe-N`), taint akışlarında `codeFlows`,
  tabana göre `baselineState`, istisnalarda `suppressions`. SCA konumu bildirim/kilit dosyasındaki satırdır.
  Üretilen belge yayımlanmadan önce yapısal olarak doğrulanır (`ci_gate.validate_sarif`).
* **GitLab** (güvenlik raporu şeması 15.x): `gl-sast-report.json` (kod, IaC, lisans, tedarik zinciri, API) ve
  `gl-dependency-scanning-report.json` (SCA + `dependency_files`). Konteyner imajı taraması ayrı komuttur (`image`).
* **Markdown özeti**: `--summary` ya da `$GITHUB_STEP_SUMMARY` (varsa ona eklenir).

## Politika (`.sniper-policy.json` / `.yml`)
Proje kökünde aranır ya da `--policy` ile verilir; bilinmeyen anahtar hatadır. Örnek: `docs/ci/sniper-policy.example.json`.

| Anahtar | Varsayılan | Açıklama |
|---|---|---|
| `fail_on` | `{"default": "high"}` | Önem eşiği; gruba göre: `code`, `iac`, `sca`, `license`, `supply_chain`, `container`, `api` (`null`/`"none"` = kapalı). |
| `new_only` | `false` | Taban varsa yalnız **yeni** bulgular değerlendirilir. |
| `baseline` | — | `{"sarif": yol}` · `{"audit_id": "prj_…"}` · `{"git_ref": "origin/main"}` (CLI seçenekleri önceliklidir). |
| `license_denied` | `true` | Politika "yasak" lisans → başarısız. |
| `sla_breach` | `false` | Bulgu takibinde SLA'sı geçmiş etkin bulgu → başarısız (veritabanı gerekir). |
| `sca_fix_first` | `false` | SCA "Önce düzelt" katmanı (önem × kullanım × düzeltme × doğrudanlık) → başarısız. |
| `iac_fix_first` | `false` | IaC'de açıkça yazılmış yüksek/kritik ayar → başarısız ("varsayılan ayar" notları hariç). |
| `require_osv` | `false` | Yerel OSV yoksa 3 ile çık (aksi hâlde uyarı). |
| `exceptions` | `[]` | `{"id", "reason" (≥10 kr), "expires" (zorunlu), "path" (isteğe bağlı kalıp)}`. |

* **Kötü amaçlı paket her zaman başarısızdır**; eşik (`fail_on.malicious` reddedilir) ve istisna bunu değiştiremez.
* İstisna kimliği: SARIF parmak izi, kural kimliği (`sniper/…` ya da son parçası), CWE/başvuru, OSV/GHSA/CVE kimliği
  ya da `package:<ad>`. Süresi geçmiş istisna uygulanmaz ve uyarı verilir; süresiz istisna yoktur.
* Arayüzde yanlış alarm/risk kabulü verilmiş bulgular (triyaj) kapıda sayılmaz.

## Taban türleri
* **SARIF**: önceki çalıştırmanın `sniperTrack/v1` parmak izleri; satır kaymasına dayanıklı (motor deterministik).
* **Kayıtlı analiz** (`prj_…`): tam analiz + kayıtlı analizle karşılaştırma (yerel veritabanı).
* **Git ref**: tam analiz yapılır (proje geneli akışlar kaçmasın); değişen dosyalardaki bulgular ve değişen
  kilit/bildirim dosyalarındaki SCA bulguları "yeni" sayılır.

## Şablonlar (`docs/ci/`)
`github-actions-sniper-gate.yml`, `gitlab-ci-sniper.yml`, `Jenkinsfile.sniper`, `pre-commit-sniper-gate.sh`.
Hepsi çevrimdışıdır: Sniper ve `SNIPER_OSV_DB_ROOT` (imzalı OSV arşivleri, `scripts/osv_refresh.py` ile hazırlanır)
çalıştırıcıya önceden kopyalanır.
