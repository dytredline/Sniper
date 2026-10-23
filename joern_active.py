"""Joern ile isteğe bağlı "derin analiz" modu (C/C++, Java, Kotlin, PHP, Go, Ruby, C#; isteğe bağlı JS/TS ve
Python; dosyalar arası veri akışı).

Bu modül Joern'ün (Apache-2.0) Code Property Graph'ını ve veri akışı motorunu çalıştırır. Python ve JS/TS için
birincil motor Sniper'ın kendi fonksiyonlar arası taint motorudur (:mod:`taint_flow`, proje analizinde çalışır);
Joern'ün jssrc2cpg/pysrc2cpg ön uçları yalnız ``scripting=True`` (ya da ``SNIPER_JOERN_SCRIPTING=1``) ile açılır
ve hızlı motorun tamamlayıcısıdır: her JS/Python bulgusu hızlı motorla eşleştirilir (aynısı doğrulanmış mı,
hızlı motor hedefi "belirsiz/olası" mı bıraktı, yoksa yalnız Joern mi buldu). Süre veya bellek sınırında
o ana kadar bulunan akışlar açık bir uyarıyla (``partial: true``) döndürülür.

Güvenlik ve kaynak sınırları:

* Joern ve JDK, Sniper'a ait araç dizinine resmî sürümlerden kurulur
  (``scripts/install_joern.py``): JDK'nin ``bin/java`` ikilisi SHA-256 ve sıkı
  Temurin GA/LTS sürüm çıktısıyla sabitlenir (``tool_pins.PINS["joern-jdk"]``).
  Doğrudan kip aynı doğrulanmış tanıtıcıyı kullanır; systemd kipindeki sabit,
  root sahipli Python başlatıcısı yolu yeniden açıp beklenen aygıt/inode/boyut,
  özet ve sürümü doğruladıktan sonra aynı yeni tanıtıcıdan, yalnız sabitlenmiş
  yedi ortam anahtarını geçirerek exec eder; Java seçenekleri, proxy ve systemd
  yöneticisinin diğer ortamı JVM'e aktarılmaz;
  Joern kurulumu, kurulumda üretilen dosya manifesti ile denetlenir (manifestin
  SHA-256'sı ``JOERN_MANIFEST_SHA256`` içinde sabit; her dosya boyut/izin/sahip ve
  SHA-256 ile doğrulanır, manifestte olmayan jar sınıf yoluna giremez).
* Proje kaynakları sembolik bağ izlenmeden, yalnız desteklenen uzantılı normal dosyalar
  olarak özel bir geçici çalışma dizinine kopyalanır; Joern projeye doğrudan erişmez.
* Aynı anda tek Joern (``joern.lock``), JVM yığını en çok ``SNIPER_JOERN_HEAP_GB`` (varsayılan
  4, üst sınır 6) GB, kullanılabilir bellek ``MIN_AVAILABLE_GB`` altındaysa çalışılmaz,
  süre sınırında tüm süreç grubu öldürülür.
* Sonuçlarda kaynak kod satırı tutulmaz: yalnız dosya/satır, kaynak ve hedef çağrı adları.

Sınır: JVM'in ağ erişimi root olmadan kapatılamaz (ayrıcalıksız ağ ad alanı bu sistemde
AppArmor ile kısıtlı); sorgu betiği ağ kullanmaz, ortamdan proxy ayarları temizlenir.
Kriptografik çalışma pini ``bin/java`` içindir; kurulum arşivi bütünü doğrulansa da
JVM'in bağımlı ``lib/conf/modules`` ağacı her çalıştırmada açık tanıtıcılarla kilitlenmez.
Aynı UID'li kötü niyetli bir süreç bu ağacı doğrulamadan sonra yarışla değiştirebiliyorsa
root sahipli/değişmez JDK ağacı olmadan tam ağaç kimliği iddia edilmez.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from typing import Any, Callable, Iterable
import uuid

from process_group_runner import run_in_process_group
from project_analyzer import ProjectRejected, SKIP_DIRS, validate_project_path
from joern_source_prep import prepare_source
from tool_pins import PINS, SNIPER_TOOLS_DIR, open_pinned, pin_status
from verified_exec import VerificationError

JOERN_VERSION = "4.0.647"
JOERN_SOURCE_URL = "https://github.com/joernio/joern/releases/tag/v4.0.647"
JOERN_HOME_DEFAULT = SNIPER_TOOLS_DIR / "joern" / JOERN_VERSION / "joern-cli"
MANIFEST_NAME = "SNIPER-INSTALL-MANIFEST.json"
# Kurulum manifestinin sabit SHA-256 değerleri (scripts/install_joern.py çıktısı; resmî
# zip'in GitHub varlık özeti ve .sha512 dosyasıyla doğrulandıktan sonra üretildi).
JOERN_MANIFEST_SHA256: dict[str, str] = {
    "233d1a8dc83d18bfc6deb19bb28a26df442e4b7f7e34b169dacecd7ba9d4ae77":
        "joern-cli-linux-arm64.zip v4.0.647 (GitHub varlık özeti 1ac7d162…1cab ve resmî .sha512 ile doğrulandı); "
        "scripts/install_joern.py çıktısı",
}
QUERY_SCRIPT = Path(__file__).resolve().parent / "rules" / "joern" / "sniper-dataflow.sc"

LANGUAGE_EXTENSIONS = {
    "c": frozenset({".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".c++", ".h++"}),
    "java": frozenset({".java"}),
    "kotlin": frozenset({".kt"}),
    "php": frozenset({".php"}),
    "go": frozenset({".go"}),
    "ruby": frozenset({".rb"}),
    "csharp": frozenset({".cs"}),
    "javascript": frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}),
    "python": frozenset({".py"}),
}
# Hızlı motorun (taint_flow) birincil olduğu diller: Joern'de yalnız istenince (scripting) analiz edilir.
SCRIPTING_LANGUAGES = frozenset({"javascript", "python"})
# Tür bildirimleri, küçültülmüş/paketlenmiş JS ve kaynak haritaları ön uca verilmez.
_SKIPPED_SCRIPT_SUFFIXES = (".d.ts", ".d.mts", ".d.cts", ".min.js", ".bundle.js", ".min.mjs", ".chunk.js")
# JS/Python dosyaları ayrı bütçeyle sayılır: aşılırsa proje reddedilmez, fazlası uyarıyla atlanır.
MAX_SCRIPT_FILES = 3_000
MAX_SCRIPT_BYTES = 25_000_000
# Dil → Joern ön ucu (frontends/<ad>/lib/io.joern.<ad>-<sürüm>-launcher.jar ile "java -jar").
FRONTENDS = {"c": "c2cpg", "java": "javasrc2cpg", "kotlin": "kotlin2cpg", "php": "php2cpg",
             "go": "gosrc2cpg", "ruby": "rubysrc2cpg", "csharp": "csharpsrc2cpg",
             "javascript": "jssrc2cpg", "python": "pysrc2cpg"}
# Ön ucun kendi başlattığı yardımcı ikililer (kurulum manifestiyle doğrulanır).
FRONTEND_HELPERS = {
    "go": "frontends/gosrc2cpg/bin/astgen/goastgen-linux-arm64",
    "csharp": "frontends/csharpsrc2cpg/bin/astgen/dotnetastgen-linux-arm64",
    "php": "frontends/php2cpg/bin/php-parser/php-parser-4.15.10.phar",
    # jssrc2cpg'nin paketlenmiş astgen'i (Node.js tek dosya ikilisi, ELF aarch64). pysrc2cpg saf JVM'dir.
    "javascript": "frontends/jssrc2cpg/bin/astgen/astgen-linux-arm",
}
LANGUAGE_NAMES = {"c": "C/C++", "java": "Java", "kotlin": "Kotlin", "php": "PHP", "go": "Go", "ruby": "Ruby", "csharp": "C#",
                  "javascript": "JavaScript/TypeScript", "python": "Python"}
# php2cpg, PHP ayrıştırıcısını (php-parser.phar) bir "php" yorumlayıcısıyla çalıştırır. Resmî php.net
# kaynak arşivi (SHA-256 aşağıda sabit) scripts/joern_install_php.py ile en küçük eklentilerle (ağ ve
# veritabanı eklentisi yok) derlenir; kurulumdaki provenance.json ikilinin SHA-256'sını kaydeder.
# 8.3 dalında 8.3.36 güvenlik tabanıdır; daha eski bir provenance hiçbir koşulda kabul edilmez.
PHP_MINIMUM_SAFE_VERSION = "8.3.36"
PHP_VERSION = PHP_MINIMUM_SAFE_VERSION
PHP_SOURCE_SHA256 = "dd54693aa334c5c4d72e9aee96b082c2473750a18a6c1d105789c93a3b1692fd"  # php-8.3.36.tar.xz
PHP_ACCOUNT_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
PHP_HOME_DEFAULT = PHP_ACCOUNT_HOME / ".local" / "share" / "sniper" / "tools" / "php" / PHP_VERSION
# Kaynak arşivi pininden ayrı aktivasyon sınırı: anahtar derlenmiş ikili SHA-256, değer mimari/onay kanıtıdır.
# Henüz onaylanmış 8.3.36 derlemesi yok; boş liste bütün PHP runtime'larını fail-closed reddeder.
PHP_APPROVED_BINARY_SHA256: dict[str, str] = {}
MAX_PHP_BYTES = 100_000_000
MAX_FILES = 5_000
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 40_000_000
MAX_FINDINGS = 200
MAX_STEPS = 40
MAX_TAIL_STEPS = 12
MAX_OUTPUT_BYTES = 8_000_000
DEFAULT_TIMEOUT_SECONDS = 900
MIN_AVAILABLE_GB = 10
DEFAULT_HEAP_GB = 4
MAX_HEAP_GB = 6
# CPG önbelleği: aynı (ön işlenmiş) kaynak + Joern/ön uç sürümü için ön uç çıktısı yeniden kullanılır.
CPG_CACHE_FORMAT = 1
CPG_CACHE_DIRNAME = "joern-cache"
CPG_CACHE_MAX_BYTES = 2_000_000_000
CPG_CACHE_MAX_ENTRIES = 64
CPG_CACHE_STALE_TMP_SECONDS = 3600
_CACHE_KEY_RE = re.compile(r"[0-9a-f]{64}\Z")

KIND_RULES: dict[str, tuple[str, str, str, str, str]] = {
    # tür: (CWE, önem, başlık, öneri, kategori)
    "command": ("CWE-78", "critical", "Derin analiz: dış girdi komut çalıştırmaya ulaşıyor (komut enjeksiyonu)",
                "Kabuk kullanmayın; argüman dizisiyle sabit programı çalıştırın ve girdileri allowlist ile sınırlandırın.",
                "command_data"),
    "sql": ("CWE-89", "critical", "Derin analiz: dış girdi SQL sorgusuna ulaşıyor (SQL enjeksiyonu)",
            "Hazır sorgu (PreparedStatement / parametre bağlama) kullanın; sorgu metnini birleştirmeyin.",
            "data_query"),
    "path": ("CWE-22", "high", "Derin analiz: dış girdi dosya yoluna ulaşıyor (yol aşımı)",
             "Yolu kanonikleştirip izinli kök dizin altında kaldığını doğrulayın; dosya adını allowlist ile seçin.",
             "command_data"),
    "format": ("CWE-134", "high", "Derin analiz: dış girdi biçim dizgisi olarak kullanılıyor (format string)",
               "Biçim dizgisini sabit tutun: printf(\"%s\", girdi).",
               "command_data"),
    "overflow": ("CWE-120", "high", "Derin analiz: dış girdi sınır denetimsiz bellek kopyalamasına ulaşıyor",
                 "Boyutu denetlenen işlevler (snprintf, strlcpy, memcpy öncesi uzunluk kontrolü) kullanın.",
                 "command_data"),
    "deserialize": ("CWE-502", "critical", "Derin analiz: dış girdi güvensiz nesne serileştirme çözücüsüne ulaşıyor",
                    "Güvenilmeyen veriyi ObjectInputStream/XMLDecoder ile açmayın; JSON ve sınıf allowlist'i kullanın.",
                    "command_data"),
    "ssrf": ("CWE-918", "high", "Derin analiz: dış girdi giden ağ isteğinin adresine ulaşıyor (SSRF)",
             "Hedef ana makineyi allowlist ile sınırlandırın; iç ağ ve meta veri adreslerini engelleyin.",
             "ssrf"),
    "xss": ("CWE-79", "high", "Derin analiz: HTTP istek girdisi yanıta kaçışsız yazılıyor (XSS)",
            "Çıktıyı bağlama uygun biçimde kaçışlayın (OWASP Java Encoder) veya şablon motorunun otomatik kaçışını kullanın.",
            "web_hardening"),
    "eval": ("CWE-95", "critical", "Derin analiz: dış girdi kod/ifade değerlendirmesine ulaşıyor",
             "Girdiyi ScriptEngine/SpEL/OGNL ifadesi olarak değerlendirmeyin; işlemleri açık eşlemeyle seçin.",
             "command_data"),
    "ldap": ("CWE-90", "high", "Derin analiz: dış girdi LDAP sorgusuna ulaşıyor (LDAP enjeksiyonu)",
             "LDAP filtre değerlerini RFC 4515'e göre kaçışlayın.",
             "data_query"),
    "xpath": ("CWE-643", "high", "Derin analiz: dış girdi XPath ifadesine ulaşıyor (XPath enjeksiyonu)",
              "XPath ifadesini sabit tutun; değerleri XPathVariableResolver ile bağlayın veya kaçışlayın.",
              "data_query"),
    "trustbound": ("CWE-501", "medium", "Derin analiz: HTTP istek girdisi doğrulanmadan oturuma (session) yazılıyor (güven sınırı ihlali)",
                   "Oturuma yalnız doğrulanmış/normalize edilmiş değerleri yazın; ham istek girdisini güvenilir veriyle karıştırmayın.",
                   "web_hardening"),
    "xxe": ("CWE-611", "high", "Derin analiz: dış girdi dış varlıkları kapatılmamış XML ayrıştırıcısına ulaşıyor (XXE)",
            "Ayrıştırıcıda disallow-doctype-decl'i açın, dış genel/parametre varlıklarını ve dış DTD yüklemeyi kapatın.",
            "command_data"),
    "ssti": ("CWE-1336", "critical", "Derin analiz: dış girdi şablon metni olarak işleniyor (sunucu tarafı şablon enjeksiyonu)",
             "Şablon metnini girdiden oluşturmayın; sabit şablona değişken olarak geçirin (render_template + bağlam).",
             "command_data"),
    "redirect": ("CWE-601", "medium", "Derin analiz: HTTP istek girdisi yönlendirme adresine ulaşıyor (açık yönlendirme)",
                 "Yönlendirme hedefini sabit eşlemeden veya izinli alan adı listesinden seçin; göreli yolları normalleştirin.",
                 "web_hardening"),
    "crlf": ("CWE-113", "low", "Derin analiz: HTTP istek girdisi yanıt başlığına yazılıyor (CRLF / başlık bölme)",
             "Başlık değerinden CR/LF karakterlerini ayıklayın; güncel sunucu kütüphaneleri çoğunu reddeder ama açıkça doğrulayın.",
             "web_hardening"),
    "log": ("CWE-117", "low", "Derin analiz: HTTP istek girdisi kaçışsız günlüğe yazılıyor (günlük sahteciliği / Log4Shell bağlamı)",
            "Günlüğe yazmadan önce CR/LF'yi ayıklayın; parametreli günlük kullanın ve Log4j'yi 2.17.1+ sürümünde tutun.",
            "web_hardening"),
    # Kalıp (veri akışı gerektirmeyen) bulgular
    "weakhash": ("CWE-328", "medium", "Derin analiz: zayıf özet algoritması (MD5/SHA-1 vb.)",
                 "Bütünlük için SHA-256/512, parola için Argon2id/scrypt/PBKDF2 kullanın.",
                 "crypto"),
    "weakcipher": ("CWE-327", "high", "Derin analiz: zayıf veya kırık şifreleme algoritması/modu (DES, 3DES, RC4, ECB vb.)",
                   "AES-GCM veya ChaCha20-Poly1305 gibi kimlik doğrulamalı şifreleme kullanın; ECB modundan kaçının.",
                   "crypto"),
    "weakrand": ("CWE-330", "medium", "Derin analiz: güvenlik bağlamında kriptografik olmayan rastgele sayı üreteci (java.util.Random/Math.random)",
                 "Belirteç, oturum ve anahtar üretiminde java.security.SecureRandom kullanın.",
                 "crypto"),
    "insecurecookie": ("CWE-614", "medium", "Derin analiz: Secure bayrağı olmayan çerez",
                       "Çerezlerde setSecure(true) (ve HttpOnly, SameSite) kullanın.",
                       "web_hardening"),
}
PATTERN_KINDS = frozenset({"weakhash", "weakcipher", "weakrand", "insecurecookie"})
SOURCE_LABELS = frozenset({"request", "external", "stored", "pattern"})
WEAK_HASHES = frozenset({"MD2", "MD4", "MD5", "SHA", "SHA1", "SHA-1", "SHA-0"})
_WEAK_CIPHER_RE = re.compile(r"^(DES|DESEDE|TRIPLEDES|3DES|RC2|RC4|ARCFOUR|BLOWFISH)\b|/ECB(/|$)|^AES$", re.IGNORECASE)
# Yalnız HTTP isteğinden gelen girdi için anlamlı türler.
REQUEST_ONLY_KINDS = frozenset({"xss", "trustbound", "redirect", "crlf", "log"})
MAX_MYBATIS_FILES = 200
MAX_MYBATIS_BYTES = 1_000_000
_MYBATIS_NAMESPACE_RE = re.compile(r"<mapper\b[^>]*\bnamespace\s*=\s*[\"']([\w.$]{1,250})[\"']")
_MYBATIS_STATEMENT_RE = re.compile(
    r"<(select|update|insert|delete|sql)\b[^>]*?\bid\s*=\s*[\"']([\w$]{1,100})[\"'][^>]*>(.*?)</\1\s*>", re.DOTALL)
_MYBATIS_INCLUDE_RE = re.compile(r"<include\b[^>]*\brefid\s*=\s*[\"']([\w$.]{1,200})[\"']")
MAX_PROPERTY_FILES = 50
MAX_PROPERTY_BYTES = 200_000
# Algoritma/özellik adları (ör. "DES/CBC/PKCS5Padding", "cryptoAlg1"): yalnız bu karakterler tutulur.
_DETAIL_UNSAFE = re.compile(r"[^A-Za-z0-9/_.+-]")
_SAFE_NAME = re.compile(r"[^\w.:<>$\[\]-]+")


class JoernUnavailable(RuntimeError):
    """Joern/JDK kurulu değil, sabitleme doğrulanamadı veya kaynak yetersiz."""


class JoernBusy(RuntimeError):
    """Başka bir Joern analizi sürüyor."""


class JoernExecutionError(RuntimeError):
    """Joern çalıştırması başarısız oldu veya zaman aşımına uğradı."""


class JoernTimeout(JoernExecutionError):
    """Süre bütçesi bitti (kısmi sonuç döndürülebilir)."""


# ---------------------------------------------------------------------------
# Proje dosyalarının toplanması
# ---------------------------------------------------------------------------


def collect_sources(root: Path, *, scripting: bool = False,
                    warnings: list[str] | None = None) -> dict[str, list[Path]]:
    """Desteklenen dillerdeki normal dosyaları (bağ izlemeden) dile göre topla.

    JS/TS ve Python dosyaları yalnız ``scripting`` ile ve ayrı bir bütçeyle toplanır: bütçe aşılırsa proje
    reddedilmez, fazlası atlanır ve ``warnings`` listesine açıklama eklenir."""
    found: dict[str, list[Path]] = {language: [] for language in LANGUAGE_EXTENSIONS}
    total_files = 0
    total_bytes = 0
    script_files = 0
    script_bytes = 0
    script_dropped = 0
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name for name in directories
            if name.casefold() not in SKIP_DIRS and not (Path(current) / name).is_symlink()
        )
        for name in sorted(files):
            path = Path(current) / name
            suffix = path.suffix.lower()
            language = next((lang for lang, exts in LANGUAGE_EXTENSIONS.items() if suffix in exts), None)
            if language is None or (language in SCRIPTING_LANGUAGES and not scripting):
                continue
            if language in SCRIPTING_LANGUAGES and name.lower().endswith(_SKIPPED_SCRIPT_SUFFIXES):
                continue
            try:
                info = path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
                continue
            if language in SCRIPTING_LANGUAGES:
                if script_files >= MAX_SCRIPT_FILES or script_bytes + info.st_size > MAX_SCRIPT_BYTES:
                    script_dropped += 1
                    continue
                script_files += 1
                script_bytes += info.st_size
                found[language].append(path)
                continue
            total_files += 1
            total_bytes += info.st_size
            if total_files > MAX_FILES or total_bytes > MAX_TOTAL_BYTES:
                raise ProjectRejected(
                    f"Derin analiz sınırı aşıldı (en çok {MAX_FILES} dosya / {MAX_TOTAL_BYTES // 1_000_000} MB kaynak)."
                )
            found[language].append(path)
    if script_dropped and warnings is not None:
        warnings.append(f"JS/TS ve Python dosya bütçesi aşıldı (en çok {MAX_SCRIPT_FILES} dosya / "
                        f"{MAX_SCRIPT_BYTES // 1_000_000} MB): {script_dropped} dosya derin analize alınmadı.")
    return {language: paths for language, paths in found.items() if paths}


def _copy_sources(root: Path, paths: Iterable[Path], destination: Path, language: str = "") -> int:
    """Kaynakları O_NOFOLLOW ile okuyup çalışma dizinine kopyala (göreli yol korunur).

    Dile özgü, satır numaralarını koruyan ön işlem uygulanır (C#: süslü parantezsiz gövdeler sarılır;
    bkz. joern_source_prep)."""
    copied = 0
    for path in paths:
        relative = path.relative_to(root)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError:
            continue
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
                continue
            data = os.read(fd, MAX_FILE_BYTES + 1)
        finally:
            os.close(fd)
        if len(data) > MAX_FILE_BYTES:
            continue
        with open(target, "xb") as handle:
            handle.write(prepare_source(language, data))
        copied += 1
    return copied


# ---------------------------------------------------------------------------
# Joern çıktısının ayrıştırılması ve dönüştürülmesi
# ---------------------------------------------------------------------------


def _clean_name(value: Any, limit: int = 120) -> str:
    text = _SAFE_NAME.sub("", str(value or ""))
    return text[:limit]


def _relative_file(value: Any, workspace: Path | None) -> str | None:
    raw = str(value or "")
    if not raw or "\x00" in raw or len(raw) > 1024:
        return None
    path = PurePosixPath(raw)
    if path.is_absolute():
        if workspace is None:
            return None
        try:
            path = PurePosixPath(os.path.relpath(raw, str(workspace)))
        except ValueError:
            return None
    if any(part == ".." for part in path.parts) or not path.parts:
        return None
    return str(path)


def _line(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 10_000_000:
        return None
    return value


def parse_joern_flows(text: str, *, workspace: Path | None = None, language: str = "") -> list[dict[str, Any]]:
    """Sorgu betiğinin JSONL çıktısını doğrulanmış akış kayıtlarına çevir.

    Geçersiz/eksik alanlı, çalışma dizini dışına çıkan veya bilinmeyen türdeki satırlar
    atlanır; aynı (tür, hedef, kaynak) akışlar tekilleştirilir.
    """
    flows: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for raw_line in text.splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            record = json.loads(raw_line)
        except (json.JSONDecodeError, RecursionError):
            continue
        if not isinstance(record, dict):
            continue
        kind = record.get("kind")
        label = record.get("label")
        if kind not in KIND_RULES or label not in SOURCE_LABELS:
            continue
        if (kind in PATTERN_KINDS) != (label == "pattern"):
            continue
        if kind in REQUEST_ONLY_KINDS and label not in ("request", "stored"):
            continue
        steps = _parse_steps(record.get("steps"), workspace, language)
        if len(steps) < 1:
            continue
        if len(steps) > MAX_STEPS:
            steps = steps[: MAX_STEPS // 2] + steps[-MAX_STEPS // 2:]
        source, sink = steps[0], steps[-1]
        # Sanal çağrı hedefi: çağrılan uygulamadaki yol (parametre … gerçek hedef). Bulgunun konumu çağrı
        # noktası kalır; yol adımların sonuna eklenir.
        tail = [entry for entry in _parse_steps(record.get("tail"), workspace, language)[:MAX_TAIL_STEPS]
                if entry != sink]
        key = (kind, sink["file"], sink["line"], source["file"], source["line"])
        if key in seen:
            continue
        flow_language = language or str(record.get("language") or "")
        if kind == "redirect" and flow_language in SCRIPTING_LANGUAGES and \
                _PATH_ONLY_SOURCE_RE.match(_clean_name(record.get("source"))):
            # İsteğin kendi yolu (request.path, req.originalUrl) ya da yüklenen dosya: hedef aynı sunucuda kalır.
            continue
        seen.add(key)
        detail = record.get("detail") if isinstance(record.get("detail"), dict) else {}
        flows.append({
            "detail": {k: _DETAIL_UNSAFE.sub("", v)[:120] for k, v in detail.items()
                       if k in {"literal", "property", "default"} and isinstance(v, str)},
            "kind": kind,
            "label": label,
            "language": language or str(record.get("language") or ""),
            "source": _clean_name(record.get("source")) or "girdi",
            "sink": _clean_name(record.get("sink")) or "hedef",
            "steps": steps,
            **({"tail": tail} if tail else {}),
        })
    return flows


def _parse_steps(raw: Any, workspace: Path | None, language: str) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    if not isinstance(raw, list):
        return steps
    for step in raw[: MAX_STEPS * 50]:
        if not isinstance(step, (list, tuple)) or len(step) < 2:
            continue
        file = _relative_file(step[0], workspace)
        line = _line(step[1])
        if line is not None and language == "csharp":
            line += 1   # csharpsrc2cpg (4.0.647) satırları 0 tabanlı verir
        if file is None or line is None:
            continue
        entry = {"file": file, "line": line}
        if len(step) > 2 and step[2]:
            entry["method"] = _clean_name(step[2], 80)
        if not steps or steps[-1] != entry:
            steps.append(entry)
    return steps


def mybatis_unsafe_statements(root: Path) -> list[str]:
    """MyBatis XML eşleyicilerinde ${} (doğrudan metin yerleştirme) içeren ifadelerin nitelikli adları.

    XML ayrıştırıcısı kullanılmaz (varlık genişletme / XML bombası riski yok); sınırlı düzenli ifade taraması.
    <sql> parçalarındaki ${} de <include refid> ile içeren ifadelere taşınır.
    """
    names: list[str] = []
    count = 0
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(d for d in directories if d.casefold() not in SKIP_DIRS and not (Path(current) / d).is_symlink())
        for name in sorted(files):
            if not name.endswith(".xml") or count >= MAX_MYBATIS_FILES:
                continue
            path = Path(current) / name
            if path.is_symlink():
                continue
            try:
                raw, _ = _read_regular(path, MAX_MYBATIS_BYTES)
            except (OSError, JoernUnavailable):
                continue
            text = raw.decode("utf-8", "replace")
            namespace = _MYBATIS_NAMESPACE_RE.search(text)
            if namespace is None:
                continue
            count += 1
            statements = _MYBATIS_STATEMENT_RE.findall(text)
            unsafe_fragments = {ident for tag, ident, body in statements if tag == "sql" and "${" in body}
            for tag, ident, body in statements:
                if tag == "sql":
                    continue
                includes = {ref.rsplit(".", 1)[-1] for ref in _MYBATIS_INCLUDE_RE.findall(body)}
                if "${" in body or includes & unsafe_fragments:
                    names.append(f"{namespace.group(1)}.{ident}")
    return sorted(set(names))


def load_properties(root: Path) -> dict[str, str]:
    """Projedeki .properties dosyalarından anahtar=değer (yapılandırma sabitleri; sınırlı)."""
    values: dict[str, str] = {}
    count = 0
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(d for d in directories if d.casefold() not in SKIP_DIRS and not (Path(current) / d).is_symlink())
        for name in sorted(files):
            if not name.endswith(".properties"):
                continue
            path = Path(current) / name
            if path.is_symlink() or count >= MAX_PROPERTY_FILES:
                continue
            count += 1
            try:
                raw, _ = _read_regular(path, MAX_PROPERTY_BYTES)
            except (OSError, JoernUnavailable):
                continue
            for line in raw.decode("utf-8", "replace").splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "!")):
                    continue
                match = re.match(r"([^=:\s]+)\s*[=:]\s*(.*)", line)
                if match:
                    values.setdefault(match.group(1), match.group(2).strip())
    return values


def resolve_algorithm(detail: dict[str, Any], properties: dict[str, str]) -> str | None:
    if detail.get("literal"):
        return str(detail["literal"])
    key = detail.get("property")
    if key and key in properties:
        return properties[key]
    return str(detail["default"]) if detail.get("default") else None


def _pattern_applies(flow: dict[str, Any], properties: dict[str, str]) -> bool:
    kind = flow["kind"]
    if kind in {"weakrand", "insecurecookie"}:
        return True
    algorithm = resolve_algorithm(flow.get("detail") or {}, properties)
    if algorithm is None:
        return False
    if kind == "weakhash":
        return algorithm.strip().upper() in WEAK_HASHES
    if kind == "weakcipher":
        return bool(_WEAK_CIPHER_RE.search(algorithm.strip()))
    return False


def flows_to_findings(flows: list[dict[str, Any]], limit: int = MAX_FINDINGS,
                      properties: dict[str, str] | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    properties = properties or {}
    flows = [flow for flow in flows if flow["label"] != "pattern" or _pattern_applies(flow, properties)]
    for flow in flows[:limit]:
        if flow["label"] == "pattern":
            findings.append(_pattern_finding(flow, properties))
            continue
        cwe, severity, title, recommendation, category = KIND_RULES[flow["kind"]]
        source, sink = flow["steps"][0], flow["steps"][-1]
        if flow["label"] == "external" and severity == "critical":
            # Komut satırı/ortam/dosya girdisi: istismar bağlama (setuid, servis) bağlı.
            severity = "high"
        cross = source["file"] != sink["file"]
        where = f"{source['file']} satır {source['line']}" if cross else f"satır {source['line']}"
        via = [f"{step['file']}:{step['line']}" for step in flow["steps"][1:-1]][:8]
        label_text = {"request": "HTTP istek girdisi",
                      "stored": "oturuma/veritabanına yazılmış HTTP girdisi (ikinci derece)"}.get(
            flow["label"], "dış girdi (argv/ortam/stdin/ağ/dosya)")
        findings.append({
            "category": category,
            "severity": severity,
            "title": title,
            "file": sink["file"],
            "line": sink["line"],
            "evidence": (
                f"Veri akışı ({flow['language']}, {label_text}): {flow['source']} ({where})"
                + (f" → {len(flow['steps']) - 2} ara adım" if len(flow["steps"]) > 2 else "")
                + f" → {flow['sink']} (satır {sink['line']}); kaynak satır içeriği kaydedilmedi."
            ),
            "recommendation": recommendation,
            "reference": cwe,
            "control_id": f"SNIPER-JOERN-{flow['kind'].upper()}",
            "taint_flow": {
                "sink_kind": flow["kind"],
                "sink": flow["sink"],
                "sink_line": sink["line"],
                "source": flow["source"],
                "source_label": flow["label"],
                "source_line": source["line"],
                "via": via,
                **({"source_file": source["file"]} if cross else {}),
            },
            "steps": flow["steps"] + flow.get("tail", []),
        })
    return findings


_FAST_KIND = {"xss": "html"}
_PATH_ONLY_SOURCE_RE = re.compile(r"(self\.)?(request|req|ctx)\.(path|path_info|full_path|originalUrl|url|baseUrl|FILES|files|file)\Z")


def annotate_fast_engine_matches(root: Path, sources: dict[str, list[Path]], findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Go/Ruby: Joern bulgularını hızlı motorun (taint_goruby, proje analizindeki "Doğrulanmış veri akışı")
    akışlarıyla eşleştir. Eşleşen bulguya ``fast_engine_match: true`` yazılır; böylece aynı açık proje analizi ve
    derin analizde iki ayrı yeni bulgu gibi görünmez. Hızlı motor yalnız Joern'ün zaten okuduğu dosyalarda çalışır."""
    import taint_goruby

    summary: dict[str, Any] = {}
    fast_keys: set[tuple[str, str, int]] = set()
    for language in ("go", "ruby"):
        paths = [p for p in sources.get(language, []) if p.suffix.lower() in taint_goruby.GORUBY_SUFFIXES]
        if not paths:
            continue
        files: dict[str, str] = {}
        for path in paths:
            if path.name.endswith("_test.go"):
                continue
            try:
                raw, _ = _read_regular(path, MAX_FILE_BYTES)
            except (OSError, JoernUnavailable):
                continue
            files[path.relative_to(root).as_posix()] = raw.decode("utf-8", "replace")
        mod = root / "go.mod"
        if language == "go" and mod.is_file() and not mod.is_symlink():
            try:
                files["go.mod"] = mod.read_text(encoding="utf-8", errors="replace")[:20_000]
            except OSError:
                pass
        try:
            results = taint_goruby.analyze_files(files, language)
        except (RecursionError, MemoryError):
            continue
        count = 0
        for rel, analysis in results.items():
            for flow in analysis.flows:
                fast_keys.add((_FAST_KIND.get(flow.sink_kind, flow.sink_kind), rel, flow.line))
                count += 1
        summary[language] = {"fast_flows": count}
    if not summary:
        return None
    matched = 0
    for finding in findings:
        kind = (finding.get("taint_flow") or {}).get("sink_kind")
        if not kind:
            continue
        kind = _FAST_KIND.get(kind, kind)
        if any((kind, finding["file"], finding["line"] + delta) in fast_keys for delta in (-1, 0, 1)):
            finding["fast_engine_match"] = True
            matched += 1
    summary["matched_findings"] = matched
    summary["joern_only_findings"] = sum(1 for f in findings if f.get("taint_flow") and not f.get("fast_engine_match"))
    return summary


def mark_fast_engine_overlap(root: Path, sources: dict[str, list[Path]], findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Hızlı Java/C#/PHP (taint_clike) ve C/C++ (taint_cfamily) motorlarıyla (proje analizinde çalışır) tekilleştirme bilgisi.

    Aynı CWE + dosya + hedef satırı (±1) olan Joern bulgusu ``also_in_project_analysis: true`` ile işaretlenir; böylece
    arayüz ve raporlar aynı açığı iki kez saymaz. Sayılar: ikisinde, yalnız Joern'de, yalnız hızlı motorda. Hata
    Joern çalıştırmasını asla bozmaz (sonuç ``available: false``)."""
    try:
        import taint_clike
        from project_analyzer import TAINT_FLOW_RULES
        from safe_file_read import read_text_bounded

        import taint_cfamily

        files: dict[str, str] = {}
        c_files: dict[str, str] = {}
        for paths in sources.values():
            for path in paths:
                suffix = path.suffix.lower()
                target = files if suffix in taint_clike.SUFFIXES else c_files if suffix in taint_cfamily.SUFFIXES else None
                if target is not None:
                    text = read_text_bounded(path, MAX_FILE_BYTES)
                    if text is not None:
                        target[path.relative_to(root).as_posix()] = text
        if not files and not c_files:
            return {"available": True, "both": 0, "joern_only": len(findings), "fast_only": 0}
        fast: set[tuple[str, str, int]] = set()
        analyses = list(taint_clike.analyze_files(files).values()) if files else []
        if c_files:
            analyses += list(taint_cfamily.analyze_files(c_files).values())
        for analysis in analyses:
            for flow in analysis.flows:
                rule = TAINT_FLOW_RULES.get(flow.sink_kind)
                if rule and flow.source_label in ("request", "stored", "local"):
                    fast.add((rule[4], flow.file, flow.line))
        matched: set[tuple[str, str, int]] = set()
        both = 0
        for finding in findings:
            key = (str(finding.get("reference", "")), str(finding.get("file", "")), int(finding.get("line") or 0))
            hit = next(((key[0], key[1], key[2] + d) for d in (0, -1, 1) if (key[0], key[1], key[2] + d) in fast), None)
            if hit is not None:
                finding["also_in_project_analysis"] = True
                matched.add(hit)
                both += 1
        return {"available": True, "both": both, "joern_only": len(findings) - both, "fast_only": len(fast - matched)}
    except Exception:  # tekilleştirme yardımcıdır; Joern sonucunu etkilemez
        return {"available": False}


_SCRIPT_SUFFIXES = {suffix: language for language in SCRIPTING_LANGUAGES for suffix in LANGUAGE_EXTENSIONS[language]}


def annotate_scripting_fast_engine(root: Path, sources: dict[str, list[Path]],
                                   findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    """JS/TS ve Python: Joern bulgularını hızlı motorla (taint_flow; proje analizinin "Doğrulanmış veri akışı"
    kaynağı) karşılaştır — Joern burada tamamlayıcıdır.

    Aynı tür + dosya + hedef satırı (±1) için:
      * hızlı motor da akış bulduysa ``fast_engine_match: true`` (proje analizinde zaten var; yeni değil),
      * hızlı motor hedefi "belirsiz" bıraktıysa (girdi izi modellenmemiş bir çağrıda kayboldu; proje analizinde
        "olası" düzeyinde kalır) ``fast_engine_uncertain: true`` — Joern'ün asıl katkısı,
      * hızlı motor hedefi değerlendirip temiz bulduysa ``fast_engine_clean: true`` (iki motor çelişiyor; elle
        gözden geçirin),
      * aksi hâlde yalnız Joern'de (``joern_only: true``).
    Hata Joern sonucunu bozmaz (``available: false``)."""
    languages = [language for language in ("python", "javascript") if sources.get(language)]
    if not languages:
        return None
    try:
        import taint_flow
        from project_analyzer import SKIP_DIRS
        from safe_file_read import read_text_bounded

        taint_flow.activate_project_js_handlers(root, SKIP_DIRS)
        state = taint_flow._ProjectState(root, frozenset(SKIP_DIRS))
        verified: set[tuple[str, str, int]] = set()
        uncertain: set[tuple[str, str, int]] = set()
        evaluated: set[tuple[str, str, int]] = set()
        summary: dict[str, Any] = {"available": True}
        for language in languages:
            _digests, results = state._build_python(None) if language == "python" else state._build_js(None)
            if results is None and language == "javascript":
                # Node/AST motoru yoksa proje analizindeki gibi dosya başına belirteç motoru.
                results = {}
                for path in sources[language]:
                    text = read_text_bounded(path, MAX_FILE_BYTES)
                    rel = path.relative_to(root).as_posix()
                    analysis = taint_flow.analyze_javascript(text, filename=rel) if text is not None else None
                    if analysis is not None:
                        results[rel] = analysis
            if results is None:
                summary[language] = {"available": False}
                continue
            flows = 0
            for rel, analysis in results.items():
                for flow in analysis.flows:
                    verified.add((flow.sink_kind, rel, flow.line))
                    flows += 1
                uncertain.update((kind, rel, line) for kind, line in analysis.uncertain_sinks)
                evaluated.update((kind, rel, line) for kind, line in analysis.evaluated_sinks)
            summary[language] = {"available": True, "fast_flows": flows}
    except Exception:  # tekilleştirme yardımcıdır; Joern sonucunu etkilemez
        return {"available": False}

    def near(keys: set[tuple[str, str, int]], kind: str, file: str, line: int) -> bool:
        # Hızlı motor şablon derlemesini (Template(girdi)) kod değerlendirme (eval) türünde raporlayabilir.
        kinds = {kind, "eval"} if kind == "ssti" else {kind}
        return any((k, file, line + delta) in keys for k in kinds for delta in (-1, 0, 1))

    counts = {"matched": 0, "confirmed_uncertain": 0, "conflicting": 0, "joern_only": 0}
    for finding in findings:
        flow = finding.get("taint_flow") or {}
        file = str(finding.get("file") or "")
        if not flow or _SCRIPT_SUFFIXES.get(PurePosixPath(file).suffix.lower()) is None:
            continue
        kind = _FAST_KIND.get(flow.get("sink_kind", ""), flow.get("sink_kind", ""))
        line = int(finding.get("line") or 0)
        if near(verified, kind, file, line):
            finding["fast_engine_match"] = True
            counts["matched"] += 1
        elif near(uncertain, kind, file, line):
            finding["fast_engine_uncertain"] = True
            finding["evidence"] += " Hızlı motor bu hedefte girdi izini kaybetmişti (olası); Joern akışı doğruluyor."
            counts["confirmed_uncertain"] += 1
        elif near(evaluated, kind, file, line):
            finding["fast_engine_clean"] = True
            finding["evidence"] += " Hızlı motor bu hedefi temiz buldu; iki motor çelişiyor, elle gözden geçirin."
            counts["conflicting"] += 1
        else:
            finding["joern_only"] = True
            counts["joern_only"] += 1
    summary.update(counts)
    return summary


def _pattern_finding(flow: dict[str, Any], properties: dict[str, str]) -> dict[str, Any]:
    cwe, severity, title, recommendation, category = KIND_RULES[flow["kind"]]
    location = flow["steps"][-1]
    algorithm = resolve_algorithm(flow.get("detail") or {}, properties)
    origin = ""
    if flow.get("detail", {}).get("property") and flow["detail"]["property"] in properties:
        origin = f" (yapılandırma: {flow['detail']['property']})"
    evidence = f"{flow['sink']} çağrısı" + (f": algoritma {algorithm}{origin}" if algorithm else "") + "; kaynak satır içeriği kaydedilmedi."
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "file": location["file"],
        "line": location["line"],
        "evidence": evidence,
        "recommendation": recommendation,
        "reference": cwe,
        "control_id": f"SNIPER-JOERN-{flow['kind'].upper()}",
        "steps": flow["steps"],
    }


SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}


def _sarif_location(file: str, line: int, message: str | None = None) -> dict[str, Any]:
    location: dict[str, Any] = {
        "physicalLocation": {"artifactLocation": {"uri": file}, "region": {"startLine": max(1, line)}}
    }
    if message:
        location["message"] = {"text": message[:200]}
    return location


def render_sarif(findings: list[dict[str, Any]], *, engine: dict[str, Any] | None = None) -> dict[str, Any]:
    """Bulguları, her adımı konumlu threadFlow içeren SARIF 2.1.0'a çevir (CodeQL biçimi)."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = finding["control_id"]
        cwe_number = finding["reference"].split("-", 1)[-1]
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": finding["title"][:120],
            "shortDescription": {"text": finding["title"]},
            "help": {"text": finding["recommendation"]},
            "properties": {
                "security-severity": SECURITY_SEVERITY.get(finding["severity"], "3.0"),
                "tags": ["security", f"external/cwe/cwe-{cwe_number}"],
            },
        })
        steps = finding.get("steps") or [{"file": finding["file"], "line": finding["line"]}]
        flow = finding.get("taint_flow")
        thread = []
        for index, step in enumerate(steps):
            if flow and index == 0:
                message = f"Kaynak: {flow['source']}"
            elif flow and index == len(steps) - 1:
                message = f"Hedef: {flow['sink']}"
            else:
                message = step.get("method") or None
            thread.append({"location": _sarif_location(step["file"], step["line"], message)})
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": "error" if finding["severity"] in {"critical", "high"} else "warning",
            "message": {"text": f"{finding['title']}: {finding['evidence']}"},
            "locations": [_sarif_location(finding["file"], finding["line"])],
        }
        if flow:
            result["codeFlows"] = [{"threadFlows": [{"locations": thread}]}]
        results.append({
            **result,
            "partialFingerprints": {
                "sniperJoern/v1": hashlib.sha256(
                    f"{rule_id}|{finding['file']}|{finding['line']}|{steps[0]['file']}|{steps[0]['line']}".encode()
                ).hexdigest()[:32],
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Sniper Joern Deep Analysis",
                "version": (engine or {}).get("version", JOERN_VERSION),
                "informationUri": "https://joern.io/",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


# ---------------------------------------------------------------------------
# Çalışma zamanı doğrulaması
# ---------------------------------------------------------------------------

_MANIFEST_CACHE: dict[tuple[int, int, int, int, int], dict[str, Any]] = {}
_FILE_CACHE: dict[tuple[int, int, int, int, int], str] = {}
_CACHE_LOCK = threading.Lock()


def joern_home() -> Path:
    raw = os.environ.get("SNIPER_JOERN_HOME", "").strip()
    return Path(raw) if raw else JOERN_HOME_DEFAULT


def accepted_manifest_digests() -> set[str]:
    accepted = set(JOERN_MANIFEST_SHA256)
    for raw in os.environ.get("SNIPER_JOERN_MANIFEST_SHA256", "").split(","):
        value = raw.strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", value):
            accepted.add(value)
    return accepted


def _read_regular(path: Path, limit: int) -> tuple[bytes, os.stat_result]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise JoernUnavailable("Joern kurulum manifesti geçersiz.")
        return os.read(fd, limit + 1), info
    finally:
        os.close(fd)


def _file_digest(path: Path) -> tuple[str, os.stat_result]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise JoernUnavailable("Joern kurulumunda normal olmayan dosya var.")
        if info.st_mode & 0o022 or info.st_uid not in (0, os.getuid()):
            raise JoernUnavailable("Joern kurulum dosyaları başkalarınca yazılabilir veya yabancı sahipli.")
        key = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        with _CACHE_LOCK:
            cached = _FILE_CACHE.get(key)
        if cached is not None:
            return cached, info
        digest = hashlib.sha256()
        offset = 0
        while True:
            chunk = os.pread(fd, 1 << 20, offset)
            if not chunk:
                break
            digest.update(chunk)
            offset += len(chunk)
        value = digest.hexdigest()
        with _CACHE_LOCK:
            if len(_FILE_CACHE) > 20_000:
                _FILE_CACHE.clear()
            _FILE_CACHE[key] = value
        return value, info
    finally:
        os.close(fd)


def verify_joern_install(home: Path | None = None) -> dict[str, Any]:
    """Kurulum manifestinin sabit hash'ini ve listelenen her dosyayı doğrula."""
    home = home or joern_home()
    accepted = accepted_manifest_digests()
    if not accepted:
        raise JoernUnavailable("Joern kurulum manifesti için sabitlenmiş SHA-256 yok; çalıştırılmadı.")
    try:
        raw, info = _read_regular(home / MANIFEST_NAME, 8_000_000)
    except (OSError, JoernUnavailable) as exc:
        raise JoernUnavailable("Joern kurulu değil veya kurulum manifesti okunamadı.") from exc
    if hashlib.sha256(raw).hexdigest() not in accepted:
        raise JoernUnavailable("Joern kurulum manifestinin SHA-256 değeri sabitlenmiş değerle uyuşmuyor.")
    key = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    manifest = json.loads(raw)
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise JoernUnavailable("Joern kurulum manifesti geçersiz.")
    with _CACHE_LOCK:
        verified_at = _MANIFEST_CACHE.get(key)
    # Sınıf yoluna giren dizinlerde manifestte olmayan jar bulunmamalı.
    for lib in CLASSPATH_DIRS:
        listed = {name for name in files if name.startswith(lib + "/") and "/" not in name[len(lib) + 1:]}
        try:
            present = {f"{lib}/{name}" for name in os.listdir(home / lib)}
        except OSError as exc:
            raise JoernUnavailable("Joern kitaplık dizini okunamadı.") from exc
        if present != listed:
            raise JoernUnavailable("Joern kitaplık dizininde manifestte olmayan veya eksik dosya var.")
    for relative, expected in files.items():
        if not isinstance(relative, str) or ".." in PurePosixPath(relative).parts or relative.startswith("/"):
            raise JoernUnavailable("Joern kurulum manifesti geçersiz yol içeriyor.")
        try:
            digest, _info = _file_digest(home / relative)
        except OSError as exc:
            raise JoernUnavailable("Joern kurulum dosyası eksik veya okunamıyor.") from exc
        if digest != expected:
            raise JoernUnavailable("Joern kurulum dosyası manifestle uyuşmuyor; çalıştırılmadı.")
    if verified_at is None:
        with _CACHE_LOCK:
            _MANIFEST_CACHE[key] = {"verified": time.time()}
    return manifest


CLASSPATH_DIRS = ("lib", *(f"frontends/{name}/lib" for name in FRONTENDS.values()))


def available_memory_gb() -> float:
    try:
        with open("/proc/meminfo", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / (1024 * 1024)
    except (OSError, ValueError, IndexError):
        pass
    return 0.0


def heap_gb() -> int:
    try:
        value = int(os.environ.get("SNIPER_JOERN_HEAP_GB", str(DEFAULT_HEAP_GB)))
    except ValueError:
        value = DEFAULT_HEAP_GB
    return max(1, min(MAX_HEAP_GB, value))


def readiness() -> dict[str, Any]:
    """Hazırlık özeti (yol içermez)."""
    status: dict[str, Any] = {"tool": "joern", "version": JOERN_VERSION, "source_url": JOERN_SOURCE_URL}
    jdk = pin_status("joern-jdk")
    status["jdk"] = {k: jdk[k] for k in ("state", "reason_code", "version") if k in jdk}
    try:
        verify_joern_install()
    except JoernUnavailable as exc:
        status.update(state="unavailable", reason=str(exc))
        return status
    if jdk.get("state") != "pinned":
        status.update(state="unavailable", reason="JDK sabitlemesi doğrulanamadı.")
        return status
    status.update(state="ready", heap_gb=heap_gb(), min_available_gb=MIN_AVAILABLE_GB,
                  languages={language: language_status(language)[1] for language in FRONTENDS})
    return status


def php_home() -> Path:
    return PHP_HOME_DEFAULT


def _validate_php_directory_fd(fd: int) -> None:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
        raise JoernUnavailable("PHP kurulum dizini başkalarınca yazılabilir veya yabancı sahipli.")


def _trusted_php_directory_fd(path: Path) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _validate_php_directory_fd(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_php_regular_at(directory_fd: int, name: str, limit: int) -> tuple[bytes, os.stat_result]:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise JoernUnavailable("PHP kurulum dosyası geçersiz.")
        content = bytearray()
        while True:
            block = os.read(fd, min(1 << 20, limit + 1 - len(content)))
            if not block:
                break
            content.extend(block)
            if len(content) > limit:
                raise JoernUnavailable("PHP kurulum dosyası boyut sınırını aşıyor.")
        return bytes(content), info
    finally:
        os.close(fd)


def verified_php() -> bytes:
    """php2cpg için güvenilir zincirden okunan ve mimari SHA-256 onayı bulunan ikili baytları."""
    home = php_home()
    parent_fd = -1
    home_fd = -1
    bin_fd = -1
    try:
        parent_fd = _trusted_php_directory_fd(home.parent)
        home_fd = os.open(
            home.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        _validate_php_directory_fd(home_fd)
        bin_fd = os.open("bin", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=home_fd)
        _validate_php_directory_fd(bin_fd)
        raw, provenance_info = _read_php_regular_at(home_fd, "provenance.json", 64_000)
        if provenance_info.st_mode & 0o022 or provenance_info.st_uid not in (0, os.getuid()):
            raise JoernUnavailable("PHP kurulumu başkalarınca yazılabilir.")
        provenance = json.loads(raw)
        data, binary_info = _read_php_regular_at(bin_fd, "php", MAX_PHP_BYTES)
    except (OSError, ValueError) as exc:
        raise JoernUnavailable("PHP yorumlayıcısı kurulu değil (scripts/joern_install_php.py).") from exc
    finally:
        if bin_fd >= 0:
            os.close(bin_fd)
        if home_fd >= 0:
            os.close(home_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
    if not isinstance(provenance, dict) or provenance.get("version") != PHP_VERSION \
            or provenance.get("source_sha256") != PHP_SOURCE_SHA256:
        raise JoernUnavailable("PHP kurulum kaydı beklenen resmî kaynak arşiviyle eşleşmiyor.")
    if binary_info.st_mode & 0o022 or binary_info.st_uid not in (0, os.getuid()):
        raise JoernUnavailable("PHP ikilisi başkalarınca yazılabilir veya yabancı sahipli.")
    binary_sha256 = hashlib.sha256(data).hexdigest()
    if binary_sha256 != provenance.get("binary_sha256"):
        raise JoernUnavailable("PHP ikilisinin SHA-256 değeri kurulum kaydıyla eşleşmiyor.")
    approval = PHP_APPROVED_BINARY_SHA256.get(binary_sha256)
    if not isinstance(approval, str) or not approval.strip():
        raise JoernUnavailable("PHP ikilisinin ayrı mimari onayı yok; çalışma zamanı etkin değil.")
    return data


def language_status(language: str, manifest: dict[str, Any] | None = None) -> tuple[bool, str]:
    """(hazır mı, kısa durum) — ön uç jar'ı ve yardımcı ikililer kurulum manifestinde mi."""
    try:
        files = (manifest or verify_joern_install())["files"]
    except JoernUnavailable as exc:
        return False, str(exc)
    name = FRONTENDS[language]
    if f"frontends/{name}/lib/io.joern.{name}-{JOERN_VERSION}-launcher.jar" not in files:
        return False, "Joern ön ucu kurulumda yok"
    helper = FRONTEND_HELPERS.get(language)
    if helper and helper not in files:
        return False, "ön uç yardımcı ikilisi (arm64) kurulumda yok"
    if language == "php":
        try:
            verified_php()
        except JoernUnavailable as exc:
            return False, str(exc)
    return True, "hazır"


# ---------------------------------------------------------------------------
# Çalıştırma
# ---------------------------------------------------------------------------


def _classpath(home: Path, manifest: dict[str, Any]) -> str:
    jars = sorted(name for name in manifest["files"] if name.startswith("lib/") and name.endswith(".jar"))
    return ":".join(str(home / name) for name in jars)


def _jvm_options(work: Path) -> list[str]:
    return [
        f"-Xmx{heap_gb()}g", "-Xss16m", "-XX:+UseG1GC", "-Djava.awt.headless=true",
        "-Djava.net.useSystemProxies=false", "-Dfile.encoding=UTF-8", f"-Djava.io.tmpdir={work}",
    ]


def _environment(work: Path, path: str = "/usr/bin:/bin") -> dict[str, str]:
    # JAVA_TOOL_OPTIONS / _JAVA_OPTIONS / JDK_JAVA_OPTIONS ve proxy değişkenleri bilerek verilmez.
    # .NET AST üreticisi (C#) ICU olmadan ve telemetri göndermeden çalışsın.
    return {"PATH": path, "HOME": str(work), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TMPDIR": str(work),
            "DOTNET_SYSTEM_GLOBALIZATION_INVARIANT": "1", "DOTNET_CLI_TELEMETRY_OPTOUT": "1"}


def _frontend_command(java: str, home: Path, manifest: dict[str, Any], language: str, src: Path,
                      cpg: Path, work: Path) -> list[str]:
    name = FRONTENDS[language]
    launcher = f"frontends/{name}/lib/io.joern.{name}-{JOERN_VERSION}-launcher.jar"
    if launcher not in manifest["files"]:
        raise JoernUnavailable("Joern ön ucu kurulumda bulunamadı.")
    command = [java, *_jvm_options(work), "-jar", str(home / launcher), str(src), "--output", str(cpg)]
    if language == "java":
        # Lombok kullanan projelerde javasrc2cpg varsayılan olarak PATH'teki "java" ile delombok başlatır;
        # bu hem doğrulanmamış bir JVM çalıştırır hem de başarısız olunca TÜM dosyaları atlar (sessizce
        # 0 bulgu). Delombok kapalı: kaynaklar olduğu gibi ayrıştırılır.
        command += ["--delombok-mode", "no-delombok"]
    return command


def _script_params(cpg: Path, out: Path, max_flows: int = MAX_FINDINGS) -> list[str]:
    return [f"cpgFile={cpg}", f"outFile={out}", f"maxFlows={max_flows}"]


def _capture_command(java: str, home: Path, manifest: dict[str, Any], cpg: Path, out: Path, work: Path,
                     max_flows: int = MAX_FINDINGS) -> list[str]:
    command = [java, *_jvm_options(work), "-cp", _classpath(home, manifest), SCRIPT_MAIN,
               "--script", str(QUERY_SCRIPT), "--nocolors"]
    for param in _script_params(cpg, out, max_flows):
        command += ["--param", param]
    return command


def _write_capture_shim(work: Path) -> tuple[Path, Path]:
    """ReplBridge'in betik için başlattığı alt JVM komutunu (çalıştırmadan) kaydeden "java"."""
    shim_dir = work / "capture-bin"
    shim_dir.mkdir(mode=0o700)
    args_file = work / "fork-args.bin"
    shim = shim_dir / "java"
    shim.write_text(f"#!/bin/sh\nprintf '%s\\0' \"$@\" > '{args_file}'\n", encoding="utf-8")
    os.chmod(shim, 0o500)
    return shim_dir, args_file


def _validated_fork_args(raw: bytes, home: Path, manifest: dict[str, Any], cpg: Path, out: Path,
                         max_flows: int = MAX_FINDINGS) -> list[str]:
    """Yakalanan alt JVM argümanlarını doğrula: yalnız manifestteki jar'lar, beklenen ana
    sınıf, Sniper'ın sorgu betiği ve parametreleri."""
    if len(raw) > 2_000_000:
        raise JoernExecutionError("Joern betik çalıştırıcısı argümanları beklenmedik boyutta.")
    args = raw.decode("utf-8", "strict").split("\0")
    if args and args[-1] == "":
        args.pop()
    if len(args) < 4 or args[0] not in {"-classpath", "-cp"} or args[2] != "replpp.scripting.NonForkingScriptRunner":
        raise JoernExecutionError("Joern betik çalıştırıcısı beklenmeyen komut üretti.")
    for entry in (part for part in args[1].split(":") if part):
        try:
            relative = Path(entry).relative_to(home).as_posix()
        except ValueError as exc:
            raise JoernExecutionError("Joern betik sınıf yolu kurulum dışına çıkıyor.") from exc
        if relative not in manifest["files"]:
            raise JoernExecutionError("Joern betik sınıf yolunda doğrulanmamış dosya var.")
    script_positions = [i for i, value in enumerate(args) if value == "--script"]
    if len(script_positions) != 1 or args[script_positions[0] + 1] != str(QUERY_SCRIPT):
        raise JoernExecutionError("Joern betik çalıştırıcısı beklenmeyen betik içeriyor.")
    params = [args[i + 1] for i, value in enumerate(args[:-1]) if value == "--param"]
    if params != _script_params(cpg, out, max_flows):
        raise JoernExecutionError("Joern betik parametreleri beklenmeyen değerler içeriyor.")
    if any(value.startswith("-javaagent") or value.startswith("-agentpath") for value in args):
        raise JoernExecutionError("Joern betik çalıştırıcısı ajan seçeneği içeriyor.")
    return args


SCRIPT_MAIN = "io.joern.joerncli.console.ReplBridge"


def _lock() -> int:
    data_dir = os.environ.get("SNIPER_DATA_DIR", "")
    if not data_dir:
        raise JoernUnavailable("Sniper veri dizini yapılandırılmamış.")
    path = Path(data_dir) / "joern.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise JoernBusy("Joern kilit dosyası geçersiz.")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise JoernBusy("Başka bir Joern derin analizi sürüyor.") from exc
    except BaseException:
        os.close(fd)
        raise
    return fd


Runner = Callable[[list[str], float, dict[str, str], Path, tuple[int, ...]], subprocess.CompletedProcess]


def _default_runner(cmd: list[str], timeout: float, env: dict[str, str], cwd: Path,
                    pass_fds: tuple[int, ...]) -> subprocess.CompletedProcess:
    return run_in_process_group(
        cmd, timeout=timeout, env=env, cwd=str(cwd), pass_fds=pass_fds, close_fds=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
SYSTEM_PYTHON = Path("/usr/bin/python3.12")
SYSTEMD_JAVA_ENV_KEYS = (
    "PATH", "HOME", "LANG", "LC_ALL", "TMPDIR",
    "DOTNET_SYSTEM_GLOBALIZATION_INVARIANT", "DOTNET_CLI_TELEMETRY_OPTOUT",
)

# ``systemd-run`` arbitrary bir dosya tanıtıcısını geçici birime aktaramaz. Bu sabit
# kod root sahipli sistem Python'u içinde çalışır: az önce doğrulanan Java yolunu
# O_NOFOLLOW ile yeniden açar, beklenen inode/özet/sürümü tekrar doğrular ve yükü
# aynı açık tanıtıcıdan, yalnız açık ortam izin listesini kullanarak exec eder.
# Böylece systemd yöneticisinin yolu daha sonra çözmesiyle oluşan rename/symlink
# TOCTOU aralığı ve JAVA_TOOL_OPTIONS/JDK_JAVA_OPTIONS enjeksiyonu kapanır.
_SYSTEMD_JAVA_FD_LAUNCHER = r'''
import hashlib
import os
import re
import stat
import subprocess
import sys

def refuse():
    sys.stderr.write("verified Java launcher refused runtime identity\n")
    raise SystemExit(126)

try:
    path, raw_dev, raw_ino, raw_size, expected_sha256, version_pattern, raw_env_count, *remaining = sys.argv[1:]
    allowed_env_keys = (
        "PATH", "HOME", "LANG", "LC_ALL", "TMPDIR",
        "DOTNET_SYSTEM_GLOBALIZATION_INVARIANT", "DOTNET_CLI_TELEMETRY_OPTOUT",
    )
    env_count = int(raw_env_count)
    if env_count != len(allowed_env_keys) or len(remaining) < env_count + 1:
        refuse()
    raw_environment = remaining[:env_count]
    separator = remaining[env_count]
    java_args = remaining[env_count + 1:]
    workload_env = {}
    for entry in raw_environment:
        key, marker, value = entry.partition("=")
        if (
            marker != "=" or key not in allowed_env_keys or key in workload_env
            or any(control in value for control in ("\x00", "\r", "\n"))
        ):
            refuse()
        workload_env[key] = value
    if set(workload_env) != set(allowed_env_keys):
        refuse()
    if separator != "--" or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        refuse()
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or not info.st_mode & 0o111
        or info.st_mode & 0o022
        or (info.st_dev, info.st_ino, info.st_size) != (int(raw_dev), int(raw_ino), int(raw_size))
    ):
        refuse()
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(fd, 1 << 20, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    if digest.hexdigest() != expected_sha256:
        refuse()
    fd_path = "/proc/self/fd/" + str(fd)
    probe = subprocess.run(
        [fd_path, "-version"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=5, check=False, pass_fds=(fd,), close_fds=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    output = probe.stdout or b""
    if probe.returncode != 0 or len(output) > 8192:
        refuse()
    text = output.decode("utf-8", "replace")
    if re.search(version_pattern, text) is None:
        refuse()
    # Sürüm yoklamasından sonra aynı inode'u tekrar özetle; path bir daha çözülmez.
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(fd, 1 << 20, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    if digest.hexdigest() != expected_sha256:
        refuse()
    os.set_inheritable(fd, True)
    os.execve(fd_path, [fd_path, *java_args], workload_env)
except (OSError, ValueError, subprocess.SubprocessError):
    refuse()
'''.strip()


def launch_mode() -> str:
    """JVM nasıl başlatılır: sniper.service MemoryDenyWriteExecute=yes ile çalıştığı için JVM
    (JIT, W+X bellek) servis içinde başlayamaz; servis altında kendi sertleştirmeli geçici
    systemd kullanıcı birimine (systemd-run --user) taşınır. SNIPER_JOERN_LAUNCH=direct|systemd-run."""
    value = os.environ.get("SNIPER_JOERN_LAUNCH", "auto").strip().lower()
    if value in {"direct", "systemd-run"}:
        return value
    return "systemd-run" if os.environ.get("INVOCATION_ID") and SYSTEMD_RUN.is_file() else "direct"


def _work_parent() -> str | None:
    """systemd-run birimi servisin özel /tmp'sini göremez: çalışma alanı veri dizininde."""
    if launch_mode() != "systemd-run":
        return None
    raw = os.environ.get("SNIPER_DATA_DIR", "")
    data_dir = Path(raw)
    if not raw or data_dir.is_symlink() or not data_dir.is_dir() or data_dir.stat().st_uid != os.getuid():
        raise JoernUnavailable("Sniper veri dizini kullanılamıyor (Joern çalışma alanı).")
    return str(data_dir)


def _trusted_system_python() -> str:
    try:
        info = os.lstat(SYSTEM_PYTHON)
    except OSError as exc:
        raise JoernUnavailable("Sistem Java doğrulama başlatıcısı bulunamadı.") from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
            or not info.st_mode & 0o111):
        raise JoernUnavailable("Sistem Java doğrulama başlatıcısı güvenilir değil.")
    return str(SYSTEM_PYTHON)


def _systemd_runner(jdk: Any) -> Runner:
    """systemd geçici biriminde Java kimliğini yeniden doğrulayıp aynı fd'den çalıştır."""
    try:
        expected = os.fstat(jdk.fd)
    except (AttributeError, OSError) as exc:
        raise JoernUnavailable("Doğrulanmış Java tanıtıcısı kullanılamıyor.") from exc
    java_path = str(jdk.path)
    java_fd_path = str(jdk.argv0)
    java_sha256 = str(jdk.sha256)
    version_pattern = PINS["joern-jdk"].version_pattern
    system_python = _trusted_system_python()

    def runner(cmd: list[str], timeout: float, env: dict[str, str], cwd: Path,
               pass_fds: tuple[int, ...]) -> subprocess.CompletedProcess:
        if not cmd or cmd[0] != java_fd_path or jdk.fd not in pass_fds:
            raise JoernExecutionError("Joern systemd çalıştırıcısı doğrulanmış Java tanıtıcısını almadı.")
        if set(env) != set(SYSTEMD_JAVA_ENV_KEYS) or any(
                not isinstance(env[key], str) or any(char in env[key] for char in ("\x00", "\r", "\n"))
                for key in env):
            raise JoernExecutionError("Joern systemd çalıştırıcısı beklenmeyen ortam sözleşmesini reddetti.")
        unit = "sniper-joern-" + uuid.uuid4().hex[:20]
        heap = heap_gb()
        command = [
            str(SYSTEMD_RUN), "--user", "--wait", "--collect", "--pipe", "--quiet", "--unit=" + unit,
            "--working-directory=" + str(cwd),
            "-p", "PrivateTmp=yes", "-p", "ProtectSystem=strict", "-p", "ProtectHome=read-only",
            "-p", "ReadWritePaths=" + str(cwd), "-p", "NoNewPrivileges=yes", "-p", "RestrictSUIDSGID=yes",
            "-p", "LockPersonality=yes", "-p", "RestrictRealtime=yes", "-p", "RestrictAddressFamilies=AF_UNIX",
            "-p", f"MemoryMax={heap + 2}G", "-p", "TasksMax=512", "-p", "CPUQuota=400%",
            "-p", f"RuntimeMaxSec={max(30, int(timeout))}",
        ]
        for key in SYSTEMD_JAVA_ENV_KEYS:
            command += ["-E", f"{key}={env[key]}"]
        command += [
            system_python, "-I", "-c", _SYSTEMD_JAVA_FD_LAUNCHER,
            java_path, str(expected.st_dev), str(expected.st_ino), str(expected.st_size),
            java_sha256, version_pattern, str(len(SYSTEMD_JAVA_ENV_KEYS)),
            *(f"{key}={env[key]}" for key in SYSTEMD_JAVA_ENV_KEYS), "--", *cmd[1:],
        ]
        finished = False
        try:
            completed = run_in_process_group(
                command, timeout=timeout + 15, cwd=str(cwd), close_fds=True,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                     "XDG_RUNTIME_DIR": os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")},
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            finished = completed.returncode == 0
            return completed
        finally:
            if not finished:
                # Zaman aşımı/iptal/hata: geçici birim de durdurulur (yalnız istemci öldürülmez).
                subprocess.run([str(SYSTEMCTL), "--user", "stop", unit], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20, check=False)
    return runner



# ---------------------------------------------------------------------------
# CPG önbelleği
# ---------------------------------------------------------------------------
# Anahtar: ön uca verilen (ön işlenmiş) kaynak ağacının içerik özeti + Joern sürümü + kurulum bildirimi +
# ön uç komut şablonu (seçenekler; yığın boyutu hariç) + PHP sürümü. Değer: ön ucun ürettiği cpg.bin ve
# üretildiği kaynak kökü (CPG'deki mutlak dosya adlarını göreli yapmak için). Her kullanımda boyut ve SHA-256
# yeniden doğrulanır; dizin 0700, dosyalar 0600, sembolik bağ ve başka sahipli girdiler reddedilir.
# SNIPER_JOERN_CPG_CACHE=0 kapatır; SNIPER_JOERN_CACHE_MAX_BYTES toplam boyut sınırı.


def _cache_limit() -> int:
    raw = os.environ.get("SNIPER_JOERN_CACHE_MAX_BYTES", "")
    try:
        value = int(raw) if raw else CPG_CACHE_MAX_BYTES
    except ValueError:
        value = CPG_CACHE_MAX_BYTES
    return max(0, min(value, 50_000_000_000))


def cpg_cache_dir() -> Path | None:
    """Önbellek dizini (yoksa 0700 oluşturulur); kapalı, veri dizini yok ya da güvensizse None."""
    if os.environ.get("SNIPER_JOERN_CPG_CACHE", "1") == "0" or _cache_limit() == 0:
        return None
    raw = os.environ.get("SNIPER_DATA_DIR", "")
    if not raw:
        return None
    data_dir = Path(raw)
    try:
        info = os.lstat(data_dir)
    except OSError:
        return None
    if not data_dir.is_absolute() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        return None
    cache = data_dir / CPG_CACHE_DIRNAME
    try:
        os.mkdir(cache, 0o700)
    except FileExistsError:
        pass
    except OSError:
        return None
    try:
        info = os.lstat(cache)
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        return None
    return cache


def source_tree_digest(src: Path) -> str:
    """Göreli yol + boyut + içerik özeti (sıralı); sembolik bağ ve normal olmayan dosyalar atlanır."""
    digest = hashlib.sha256()
    for current, directories, files in os.walk(src, followlinks=False):
        directories.sort()
        for name in sorted(files):
            path = Path(current) / name
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            except OSError:
                continue
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    continue
                file_hash = hashlib.sha256()
                while chunk := os.read(fd, 1 << 20):
                    file_hash.update(chunk)
            finally:
                os.close(fd)
            relative = path.relative_to(src).as_posix()
            digest.update(f"{relative}\0{info.st_size}\0{file_hash.hexdigest()}\n".encode("utf-8", "surrogateescape"))
    return digest.hexdigest()


def cpg_cache_key(language: str, src: Path, manifest: dict[str, Any]) -> str:
    template = [part for part in _frontend_command("<java>", Path("/<home>"), manifest, language, Path("/<src>"),
                                                   Path("/<cpg>"), Path("/<work>")) if not part.startswith("-Xmx")]
    header = {
        "format": CPG_CACHE_FORMAT, "joern": JOERN_VERSION, "language": language, "frontend": template,
        "manifest": hashlib.sha256(json.dumps(manifest, sort_keys=True, default=str).encode()).hexdigest(),
        "php": PHP_VERSION if language == "php" else "",
    }
    digest = hashlib.sha256(json.dumps(header, sort_keys=True).encode())
    digest.update(source_tree_digest(src).encode())
    return digest.hexdigest()


def _hash_file(path: Path, limit: int) -> tuple[str, int] | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 \
                or info.st_size > limit:
            return None
        digest = hashlib.sha256()
        while chunk := os.read(fd, 1 << 20):
            digest.update(chunk)
        return digest.hexdigest(), info.st_size
    finally:
        os.close(fd)


def cpg_cache_lookup(cache: Path, key: str, destination: Path) -> str | None:
    """Doğrulanmış önbellek girdisini destination'a kopyala; üretildiği kaynak kökünü döndür."""
    if not _CACHE_KEY_RE.fullmatch(key):
        return None
    entry = cache / key
    try:
        info = os.lstat(entry)
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        return None
    meta_path = entry / "meta.json"
    try:
        raw, _ = _read_regular(meta_path, 64_000)
        meta = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, JoernUnavailable, UnicodeDecodeError):
        return None
    if not isinstance(meta, dict) or meta.get("format") != CPG_CACHE_FORMAT or meta.get("key") != key \
            or not isinstance(meta.get("src_root"), str) or not isinstance(meta.get("sha256"), str):
        return None
    checked = _hash_file(entry / "cpg.bin", _cache_limit())
    if checked is None or checked != (meta["sha256"], meta.get("size")):
        return None
    shutil.copyfile(entry / "cpg.bin", destination, follow_symlinks=False)
    os.chmod(destination, 0o600)
    if _hash_file(destination, _cache_limit()) != checked:
        destination.unlink(missing_ok=True)
        return None
    now = time.time()
    os.utime(meta_path, (now, now), follow_symlinks=False)
    return meta["src_root"]


def cpg_cache_store(cache: Path, key: str, cpg: Path, src_root: Path, language: str) -> bool:
    """Ön uç çıktısını atomik olarak önbelleğe koy, sonra boyut/adet sınırına göre en eskileri sil."""
    if not _CACHE_KEY_RE.fullmatch(key):
        return False
    try:
        info = os.lstat(cpg)
    except OSError:
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > _cache_limit():
        return False
    tmp = Path(tempfile.mkdtemp(prefix=".tmp-", dir=cache))
    try:
        os.chmod(tmp, 0o700)
        target = tmp / "cpg.bin"
        shutil.copyfile(cpg, target, follow_symlinks=False)
        os.chmod(target, 0o600)
        checked = _hash_file(target, _cache_limit())
        if checked is None:
            return False
        meta = {"format": CPG_CACHE_FORMAT, "key": key, "sha256": checked[0], "size": checked[1],
                "src_root": str(src_root), "language": language, "joern": JOERN_VERSION, "created": int(time.time())}
        fd = os.open(tmp / "meta.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(meta, handle)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.rename(tmp, cache / key)
        except OSError:
            return False   # aynı anahtar zaten var (eşzamanlı koşu) — mevcut girdi kalır
        tmp = None
        return True
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)
        cpg_cache_prune(cache)


def cpg_cache_prune(cache: Path, *, max_bytes: int | None = None, max_entries: int = CPG_CACHE_MAX_ENTRIES) -> None:
    """En son kullanılana göre (meta.json mtime) sınır aşılana dek en eskileri sil; eski geçici dizinleri temizle."""
    limit = _cache_limit() if max_bytes is None else max_bytes
    entries: list[tuple[float, int, Path]] = []
    now = time.time()
    try:
        children = list(os.scandir(cache))
    except OSError:
        return
    for child in children:
        path = Path(child.path)
        try:
            info = os.lstat(path)
        except OSError:
            continue
        if child.name.startswith(".tmp-"):
            if stat.S_ISDIR(info.st_mode) and now - info.st_mtime > CPG_CACHE_STALE_TMP_SECONDS:
                shutil.rmtree(path, ignore_errors=True)
            continue
        if not _CACHE_KEY_RE.fullmatch(child.name):
            continue
        if stat.S_ISLNK(info.st_mode):
            path.unlink(missing_ok=True)   # bağı izlemeden kaldır; girdi bir sonraki koşuda yeniden üretilir
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            continue
        try:
            used = os.lstat(path / "meta.json").st_mtime
            size = os.lstat(path / "cpg.bin").st_size
        except OSError:
            shutil.rmtree(path, ignore_errors=True)
            continue
        entries.append((used, size, path))
    entries.sort()
    total = sum(size for _used, size, _path in entries)
    while entries and (total > limit or len(entries) > max_entries):
        _used, size, path = entries.pop(0)
        shutil.rmtree(path, ignore_errors=True)
        total -= size


def scripting_default() -> bool:
    """JS/TS ve Python için Joern varsayılanı (SNIPER_JOERN_SCRIPTING=1 açar; ölçümde katkı düşük, varsayılan kapalı)."""
    return os.environ.get("SNIPER_JOERN_SCRIPTING", "0").strip().lower() in {"1", "true", "yes", "on"}


def run_joern_deep(project_path: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS,
                   runner: Runner | None = None, max_findings: int = MAX_FINDINGS,
                   allowed_roots: tuple[Path, ...] | None = None,
                   scripting: bool | None = None) -> dict[str, Any]:
    """Projeyi Joern ile analiz et ve bulguları (+ SARIF) döndür.

    ``scripting``: JS/TS ve Python dosyalarını da analiz et (None → :func:`scripting_default`). ``timeout`` süre
    bütçesidir: bir dil bitmeden süre ya da bellek tükenirse o ana kadarki akışlar ``partial: true`` ve
    ``warnings`` ile döner (hiçbir dil sonuç vermediyse hata yükseltilir)."""
    root = validate_project_path(project_path, allowed_roots=allowed_roots)
    if scripting is None:
        scripting = scripting_default()
    warnings: list[str] = []
    sources = collect_sources(root, scripting=scripting, warnings=warnings)
    if not sources:
        if scripting:
            raise ProjectRejected("Projede Joern'ün desteklediği dillerde (C/C++, Java, Kotlin, PHP, Go, Ruby, C#, "
                                  "JavaScript/TypeScript, Python) kaynak dosyası bulunamadı.")
        if collect_sources(root, scripting=True):
            raise ProjectRejected("Projede C/C++, Java, Kotlin, PHP, Go, Ruby veya C# kaynak dosyası bulunamadı; yalnız "
                                  "JavaScript/TypeScript veya Python var: bunlar için derin analizde \"JS/TS ve Python dahil\" "
                                  "seçeneğini açın (birincil motor proje analizidir).")
        raise ProjectRejected("Projede C/C++, Java, Kotlin, PHP, Go, Ruby veya C# kaynak dosyası bulunamadı "
                              "(Python/JS için proje analizini kullanın).")
    home = joern_home()
    manifest = verify_joern_install(home)
    if not QUERY_SCRIPT.is_file():
        raise JoernUnavailable("Joern sorgu betiği bulunamadı.")
    if available_memory_gb() < MIN_AVAILABLE_GB:
        raise JoernUnavailable(
            f"Kullanılabilir bellek {MIN_AVAILABLE_GB} GB'ın altında; Joern derin analizi şimdi çalıştırılmadı."
        )
    started = time.monotonic()
    deadline = started + timeout
    lock_fd = _lock()
    try:
        try:
            jdk = open_pinned("joern-jdk")
        except VerificationError as exc:
            raise JoernUnavailable(str(exc)) from exc
        if runner is None:
            runner = _systemd_runner(jdk) if launch_mode() == "systemd-run" else _default_runner
        with jdk, tempfile.TemporaryDirectory(prefix="sniper-joern-", dir=_work_parent()) as tmp:
            work = Path(tmp)
            os.chmod(work, 0o700)
            all_flows: list[dict[str, Any]] = []
            languages: dict[str, int] = {}
            skipped: dict[str, str] = {}
            cache_hits: list[str] = []
            partial = False
            completed_languages: list[str] = []
            for language, paths in sources.items():
                ready, reason = language_status(language, manifest)
                if not ready:
                    skipped[language] = reason
                    continue
                if partial:
                    skipped[language] = "süre/bellek bütçesi bittiği için analiz edilmedi"
                    continue
                if completed_languages and available_memory_gb() < MIN_AVAILABLE_GB:
                    partial = True
                    skipped[language] = "kullanılabilir bellek azaldığı için analiz edilmedi"
                    warnings.append(f"Kullanılabilir bellek {MIN_AVAILABLE_GB} GB'ın altına düştü; "
                                    f"{LANGUAGE_NAMES[language]} ve sonraki diller analiz edilmedi (kısmi sonuç).")
                    continue
                if deadline - time.monotonic() <= 5:
                    partial = True
                    skipped[language] = "süre bütçesi bittiği için analiz edilmedi"
                    warnings.append(f"Süre bütçesi bitti; {LANGUAGE_NAMES[language]} ve sonraki diller analiz edilmedi "
                                    "(kısmi sonuç).")
                    continue
                if language == "php":
                    php_dir = work / "php-bin"
                    php_dir.mkdir(mode=0o700)
                    php = php_dir / "php"
                    with open(os.open(php, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700), "wb") as handle:
                        handle.write(verified_php())
                src = work / f"src-{language}"
                src.mkdir(mode=0o700)
                languages[language] = _copy_sources(root, paths, src, language)
                cpg = work / f"{language}.cpg.bin"
                out = work / f"{language}.flows.jsonl"
                if language == "java":
                    # Betik, ${} içeren MyBatis XML ifadelerini outFile + ".mybatis" yan dosyasından okur.
                    unsafe = mybatis_unsafe_statements(root)
                    if unsafe:
                        (work / f"{out.name}.mybatis").write_text("\n".join(unsafe) + "\n", encoding="utf-8")

                def step(cmd: list[str], env: dict[str, str], name: str) -> None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 5:
                        raise JoernTimeout("Joern derin analizi zaman aşımına uğradı.")
                    try:
                        completed = runner(cmd, remaining, env, work, (jdk.fd,))
                    except subprocess.TimeoutExpired as exc:
                        raise JoernTimeout("Joern derin analizi zaman aşımına uğradı.") from exc
                    if completed.returncode != 0:
                        raise JoernExecutionError(
                            f"Joern adımı başarısız oldu ({language}, {name}, çıkış kodu {completed.returncode})."
                        )

                workspace_box: list[Path] = [src]
                try:
                    _analyze_language(step, language, src, cpg, out, work, home, manifest, jdk, max_findings,
                                      cache_hits, workspace_box)
                except JoernTimeout:
                    # Süre bütçesi: sorgu betiği akışları satır satır yazar; o ana kadar bulunanlar kullanılır.
                    partial = True
                    warnings.append(f"Süre bütçesi {LANGUAGE_NAMES[language]} analizi sırasında bitti; "
                                    "bulunan akışlar gösteriliyor, sonraki diller analiz edilmedi (kısmi sonuç).")
                    if not (out.is_file() and cpg.is_file()):
                        skipped[language] = "süre bütçesi bittiği için tamamlanamadı"
                        languages.pop(language, None)
                        continue
                except JoernExecutionError as exc:
                    if language not in SCRIPTING_LANGUAGES:
                        raise
                    # JS/Python tamamlayıcıdır: başarısızlığı diğer dillerin sonucunu düşürmez.
                    skipped[language] = str(exc)
                    languages.pop(language, None)
                    warnings.append(f"{LANGUAGE_NAMES[language]} derin analizi tamamlanamadı: {exc}")
                    continue
                if out.is_file():
                    raw, _ = _read_regular(out, MAX_OUTPUT_BYTES)
                    all_flows.extend(parse_joern_flows(raw.decode("utf-8", "replace"), workspace=workspace_box[0],
                                                       language=language))
                completed_languages.append(language)
            if not languages and not all_flows:
                if partial:
                    raise JoernExecutionError("Joern derin analizi zaman aşımına uğradı.")
                raise JoernUnavailable("Desteklenen dillerin hiçbiri için ön uç hazır değil: " +
                                       "; ".join(f"{LANGUAGE_NAMES[k]}: {v}" for k, v in skipped.items()))
            findings = flows_to_findings(all_flows, max_findings, load_properties(root))
            fast_overlap = mark_fast_engine_overlap(root, sources, findings)
            engine = {"tool": "joern", "version": JOERN_VERSION, "jdk_sha256": jdk.sha256,
                      "provenance": jdk.provenance}
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    fast_engine = annotate_fast_engine_matches(root, sources, findings)
    scripting_fast = annotate_scripting_fast_engine(root, sources, findings) if scripting else None
    try:
        import eval_metrics

        eval_metrics.annotate_corroboration(findings)
    except (TypeError, ValueError):
        pass
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return {
        "format": "sniper-joern-deep-v1",
        "project_name": root.name,
        "engine": engine,
        "languages": languages,
        "skipped_languages": {LANGUAGE_NAMES[k]: v for k, v in skipped.items()},
        "scripting": bool(scripting),
        "partial": partial,
        "warnings": warnings,
        "finding_count": len(findings),
        "findings_truncated": len(all_flows) > max_findings,
        "severity_counts": counts,
        "duration_seconds": round(time.monotonic() - started, 1),
        "cpg_cache_hits": sorted(cache_hits),
        **({"fast_engine": fast_engine} if fast_engine else {}),
        **({"scripting_fast_engine": scripting_fast} if scripting_fast else {}),
        "fast_engine_overlap": fast_overlap,
        "findings": findings,
        "sarif": render_sarif(findings, engine=engine),
    }


def _analyze_language(step: Callable[[list[str], dict[str, str], str], None], language: str, src: Path, cpg: Path,
                      out: Path, work: Path, home: Path, manifest: dict[str, Any], jdk: Any, max_findings: int,
                      cache_hits: list[str], workspace_out: list[Path]) -> None:
    """Tek dil: ön uç (önbellekli) → betik komutunu yakala → sorgu. CPG'deki dosya adlarının kökü
    ``workspace_out`` içine yazılır (zaman aşımında kısmi çıktıyı çözmek için de gerekir)."""
    frontend_path = f"{work / 'php-bin'}:/usr/bin:/bin" if language == "php" else "/usr/bin:/bin"
    # 1) Ön uç: kaynak → CPG (doğrulanmış JDK tanıtıcısından); aynı kaynak için önbellekten.
    workspace_out[:] = [src]
    cache = cpg_cache_dir()
    key = cpg_cache_key(language, src, manifest) if cache is not None else ""
    cached_root = cpg_cache_lookup(cache, key, cpg) if cache is not None else None
    if cached_root is not None:
        # CPG'deki mutlak dosya adları önbelleğe alındığı koşunun kaynak köküne göredir.
        workspace_out[:] = [Path(cached_root)]
        cache_hits.append(language)
    else:
        step(_frontend_command(jdk.argv0, home, manifest, language, src, cpg, work),
             _environment(work, frontend_path), "ön uç")
        if cache is not None:
            cpg_cache_store(cache, key, cpg, src, language)
    # 2) ReplBridge betik için alt JVM başlatır; komutu yalnız kaydeden "java" ile yakala.
    shim_dir, args_file = _write_capture_shim(work)
    try:
        step(_capture_command(jdk.argv0, home, manifest, cpg, out, work, max_findings),
             _environment(work, f"{shim_dir}:/usr/bin:/bin"), "hazırlık")
        try:
            raw_args, _ = _read_regular(args_file, 2_000_000)
        except (OSError, JoernUnavailable) as exc:
            raise JoernExecutionError("Joern betik çalıştırıcısı komutu yakalanamadı.") from exc
    finally:
        # Başarısız JS/Python adımından sonra sonraki dil yeni bir yakalama dizini kurabilsin.
        args_file.unlink(missing_ok=True)
        shutil.rmtree(shim_dir, ignore_errors=True)
    fork_args = _validated_fork_args(raw_args, home, manifest, cpg, out, max_findings)
    # 3) Doğrulanan argümanlarla sorgu betiği, yine doğrulanmış JDK tanıtıcısından.
    step([jdk.argv0, *_jvm_options(work), *fork_args], _environment(work), "sorgu")
