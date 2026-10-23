# Araç ikilisi sabitleme (SHA-256 pin) ve doğrulanmış çalıştırma

Sniper, Gitleaks, TruffleHog ve Semgrep/Opengrep'i yalnız SHA-256 değeri sabitlenmiş
ikililerle çalıştırır. Kaynak: `tool_pins.py` (tablo), `verified_exec.py` (çalıştırma).

## Nasıl çalışır
1. İkili `O_NOFOLLOW` ile açılır; normal dosya, çalıştırılabilir, grup/diğerleri
   tarafından yazılamaz ve sahibi kullanıcı ya da root olmalıdır.
2. SHA-256 bu açık tanıtıcıdan hesaplanır ve `tool_pins.PINS` (mimariye göre) ile
   `SNIPER_<ARAÇ>_SHA256` ortam değişkenindeki operatör sabitlemeleriyle karşılaştırılır.
3. Uyuşursa araç `/proc/self/fd/N` üzerinden, yani hashlenen inode'un kendisinden
   çalıştırılır (`pass_fds`). Hash ile çalıştırma arasında yolun başka dosyaya
   çevrilmesi (TOCTOU) etkisizdir.
4. Uyuşmazsa ya da sabitleme yoksa araç **çalıştırılmaz**; API Türkçe sebep döndürür.
   `/api/tooling/readiness` yanıtındaki `binary_pins` ve araç kartları durumu gösterir
   (`pinned`, `mismatch`, `unpinned`, `unavailable`).

Sınır: Aynı kullanıcı kimliğine sahip bir saldırgan dosyayı yerinde değiştirebilir;
bu yüzden araç dizinleri `0700`, ikililer `0500/0700` tutulmalıdır.

## Gömülü sabitlemeler (aarch64)
| Araç | Sürüm | Kabul edilen ikili | Köken |
|---|---|---|---|
| Gitleaks | 8.30.1 | `00e91bbe…823b` | Resmi arşiv, `checksums.txt` ile doğrulandı |
| Gitleaks | 8.30.1-stdlib | `a56a1107…01a9` | v8.30.1 etiketinden yerel derleme (`BUILD-MANIFEST.json`) |
| TruffleHog | 3.99.0 | `6f668188…eb00` | Resmi arşiv, cosign imzalı checksums ile doğrulandı |
| TruffleHog | 3.99.0 (açılmış) | `4cdfed41…0a93` | Resmi UPX paketinin `upx -d` ile açılmış hali |
| Opengrep | 1.30.1 | `a730f6fd…16ee` | GitHub varlık özeti + cosign imzası (sertifika kimliği: opengrep/opengrep `rolling-release.yml`) |

Opengrep `~/.local/share/sniper/tools/opengrep/1.30.1/opengrep` yoluna kurulur
(`PROVENANCE.json`, `.sig`, `.cert` yanında). `SNIPER_OPENGREP_BINARY` ile başka bir
yol verilebilir; içerik yine sabitlemeye uymalıdır.

## Semgrep / Opengrep motor seçimi
`semgrep_active.active_engine()` sırası:
1. `SNIPER_OPENGREP_BINARY` verilmişse Opengrep,
2. `SNIPER_SEMGREP_BINARY` + `SNIPER_SEMGREP_SHA256` verilmişse (operatör sabitlemesi) Semgrep,
3. Sniper araç dizininde sabitli Opengrep varsa Opengrep,
4. aksi halde sabitlenmemiş Semgrep — **reddedilir**.

Semgrep bir Python paketidir; giriş betiğinin hash'i sanal ortamın tamamını
korumaz. Bu yüzden varsayılan motor Opengrep'tir.

## Kural paketi
`rules/opengrep/sniper-core.yaml` — Sniper için yazılmış 39 kural (Python, JS/TS, Go,
Java): SQL/komut/kod enjeksiyonu, SSTI, yol aşımı, SSRF, açık yönlendirme, XSS,
güvensiz seri çözme, zayıf hash/şifre, TLS doğrulamasının kapatılması, JWT imza
hataları, sabit sırlar, hata ayıklama modu. Her kuralda CWE, kategori ve Türkçe ileti
vardır. Semgrep Registry kuralları lisans nedeniyle **kullanılmaz**.

Taramada `--taint-intrafile` açıktır: veri akışı aynı dosyadaki fonksiyonlar arasında
izlenir. Kural başına olumlu/olumsuz örnekler `tests/fixtures/opengrep_rules/`,
testler `tests/test_opengrep_rulepack.py`.

Yanıttaki `findings` listesinde (en çok 200) ileti, CWE ve kategori kural paketinden
alınır; raporun ileti alanı (kod parçası taşıyabilir) kullanılmaz. Dosya yolu proje
köküne göre görelidir. Sonuç saklanmaz.

## Yeni sürüme geçiş
1. Resmi sürüm sayfasından ikili ve checksum/imza dosyasını boş bir dizine indirin.
2. Checksum'ı (ve varsa cosign imzasını) doğrulayın.
3. `tool_pins.PINS` içine yeni sha256 ve kökeni ekleyin; eski değeri geçiş bitince kaldırın.
4. `python3 scripts/run_all_tests.py`.
