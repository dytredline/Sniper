from __future__ import annotations

import ast
import contextlib
import gc
import io
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import posixpath
import re
import threading
import time
import tokenize
from typing import Any

from scanner import utc_now
import api_spec_routes
import authz_routes
import iac_engine
import iac_k8s_project
import iac_tf_project
import monorepo
import project_progress
import scan_scope
import taint_flow
import threat_model
from project_tree import ProjectFile, ProjectTree, ProjectTreeError



class _NeverRegex:
    """Hiç eşleşmeyen düzenli ifade yerine geçer (ön süzgeçte elenen satır kuralları)."""

    @staticmethod
    def search(_text: str) -> None:
        return None


_NEVER_RX = _NeverRegex()
# Mobil/WebView satır kuralları (sıra: satır döngüsündeki mobile_rx[k] kullanımı).
_MOBILE_LINE_RX = [re.compile(p) for p in (
    r"(?:addJavascriptInterface\s*\(|setAllowFileAccessFromFileURLs\s*\(\s*true|setAllowUniversalAccessFromFileURLs\s*\(\s*true|\bUIWebView\b|originWhitelist\s*=\s*\{\s*\[\s*['\"]\*['\"])",
    r"(?i)(?:\bMODE_WORLD_READABLE\b|\bMODE_WORLD_WRITEABLE\b|\bkSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b|\b(?:SharedPreferences|UserDefaults\.standard|AsyncStorage)\b[^\n]*(?:password|token|secret|jwt|pin|cvv|private_?key))",
    r"\bLAContext\b[^\n]*evaluatePolicy|\bevaluatePolicy\s*\(\s*\.(?:deviceOwnerAuthenticationWithBiometrics|deviceOwnerAuthentication)",
    r"\bBiometricPrompt\b[^\n]*authenticate\s*\(\s*promptInfo\s*\)",
    r"\bauthenticate\s*\(\s*promptInfo\s*\)",
    r"(?:badCertificateCallback\s*[:=]\s*\([^)]*\)\s*=>\s*true|onReceivedSslError[^\n]*\.proceed\s*\()",
    r"\blistenUsingInsecureRfcommWithServiceRecord\b",
    r"\bVISIBILITY_PUBLIC\b",
    r'(?i)\bPlayerPrefs\.Set(?:Int|Float|String)\s*\(\s*["\'](?:coins|gems|gold|diamonds|high_?score|is_?premium|is_?vip)["\']',
    r"\b(?:minifyEnabled\s+false|isMinifyEnabled\s*=\s*false)\b",
)]

def _env_limit(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        return max(minimum, min(maximum, int(os.environ.get(name, default))))
    except ValueError:
        return default


# Büyük kod tabanları: varsayılan 10.000 dosya / 150 MB (ölçüm: Django 2.818 dosya ≈ 15 sn, 0,7 GB);
# SNIPER_PROJECT_MAX_FILES / SNIPER_PROJECT_MAX_BYTES ile değiştirilebilir.
MAX_FILES = _env_limit("SNIPER_PROJECT_MAX_FILES", 10_000, 100, 50_000)
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = _env_limit("SNIPER_PROJECT_MAX_BYTES", 150_000_000, 1_000_000, 1_000_000_000)

SOURCE_EXTENSIONS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".dart",
    ".swift", ".kt", ".kts", ".java", ".go", ".rs", ".php", ".rb",
    ".cs", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".hxx", ".ino", ".sh", ".sql",
    ".html", ".htm", ".vue", ".svelte", ".yaml", ".yml", ".toml",
    ".json", ".xml", ".gradle", ".tf", ".tfvars", ".conf", ".htaccess",
    ".plist", ".entitlements", ".xcprivacy", ".pro", ".m", ".mm",
    ".proto", ".sol", ".prisma", ".erb", ".jsp", ".jspf", ".cshtml", ".razor",
    ".aspx", ".ascx", ".master", ".asmx", ".ashx",
}

MANIFEST_NAMES = {
    "requirements.txt", "pyproject.toml", "poetry.lock", "pipfile",
    "pipfile.lock", "package.json", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "pubspec.yaml", "pubspec.lock", "cargo.toml",
    "cargo.lock", "go.mod", "go.sum", "gemfile", "gemfile.lock",
    "composer.json", "composer.lock", "pom.xml", "build.gradle",
    "gradle.lockfile", "podfile", "podfile.lock", "package.resolved",
    "docker-compose.yml", "docker-compose.yaml", ".gitlab-ci.yml",
    "androidmanifest.xml", "info.plist", "network_security_config.xml",
    "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
}

# Atlanan dizinler etkin tarama kapsamına göre değişir (scan_scope: testler, vendor, paketler, derleme
# çıktıları isteğe bağlı dahil edilebilir); varsayılan küme önceki sabit listeyle aynıdır.
SKIP_DIRS = scan_scope.ScopedSkipDirs()

LANGUAGES = {
    ".py": "Python", ".js": "JavaScript", ".mjs": "JavaScript",
    ".cjs": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".jsx": "JavaScript", ".dart": "Dart", ".swift": "Swift",
    ".kt": "Kotlin", ".kts": "Kotlin", ".java": "Java", ".jsp": "Java", ".jspf": "Java", ".go": "Go",
    ".rs": "Rust", ".php": "PHP", ".rb": "Ruby", ".erb": "Ruby", ".cs": "C#", ".cshtml": "C#", ".razor": "C#",
    ".aspx": "C#", ".ascx": "C#", ".master": "C#", ".asmx": "C#", ".ashx": "C#",
    ".c": "C/C++", ".cc": "C/C++", ".cpp": "C/C++", ".h": "C/C++",
    ".hpp": "C/C++", ".cxx": "C/C++", ".hh": "C/C++", ".hxx": "C/C++", ".ino": "C/C++", ".sh": "Shell", ".html": "Web", ".htm": "Web",
    ".vue": "Web", ".svelte": "Web", "dockerfile": "Container",
    "containerfile": "Container", ".tf": "Terraform", ".tfvars": "Terraform",
    ".conf": "ServerConfig", ".htaccess": "ServerConfig",
    ".plist": "MobileConfig", ".entitlements": "MobileConfig",
    ".xcprivacy": "MobileConfig", ".gradle": "Gradle",
    ".m": "Objective-C", ".mm": "Objective-C", ".proto": "Protobuf",
    ".sol": "Solidity", ".prisma": "Prisma",
}

AUTHZ_MAX_BYTES = 60_000_000  # rota yetki envanteri için toplanan kaynak üst sınırı
SEVERITY_WEIGHT = {"critical": 24, "high": 14, "medium": 7, "low": 3, "info": 0}


class ProjectRejected(ValueError):
    pass


def _is_containerfile_name(normalized_name: str) -> bool:
    return (
        normalized_name == "dockerfile"
        or normalized_name.startswith("dockerfile.")
        or normalized_name == "containerfile"
        or normalized_name.startswith("containerfile.")
    )


def _allowed_roots() -> tuple[Path, ...]:
    home = Path.home().resolve()
    roots = [home]
    for candidate in (Path("/media") / home.name, Path("/mnt")):
        try:
            if candidate.is_dir():
                roots.append(candidate.resolve())
        except OSError:
            continue
    return tuple(roots)


def validate_project_path(value: str, allowed_roots: tuple[Path, ...] | None = None) -> Path:
    if not isinstance(value, str):
        raise ProjectRejected("Geçerli bir yerel proje klasörü girin.")
    raw = value.strip()
    if not raw or len(raw) > 1_024:
        raise ProjectRejected("Geçerli bir yerel proje klasörü girin.")
    candidate = Path(os.path.expandvars(os.path.expanduser(raw)))
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ProjectRejected("Proje klasörü bulunamadı veya okunamıyor.") from exc
    if not resolved.is_dir():
        raise ProjectRejected("Kaynak kod analizi için bir klasör seçin.")
    roots = allowed_roots if allowed_roots is not None else _allowed_roots()
    if not any(resolved != root and root in resolved.parents for root in roots):
        raise ProjectRejected("Proje yalnızca kullanıcı dizini veya bağlı yerel disk içinde olabilir.")
    return resolved


# Üretilmiş/küçültülmüş paketler: kaynak analizi için gürültü (bağımlılık taraması ayrı yapılır).
GENERATED_SUFFIXES = scan_scope.GENERATED_SUFFIXES


def _iter_files(root: Path, max_files: int = MAX_FILES, skipped: dict[str, int] | None = None,
                scope: "scan_scope.ScanScope | None" = None, stats: dict[str, int] | None = None):
    """Analiz edilecek dosyalar. Boyut sınırları projeyi reddetmez: tek dosya sınırını aşan, üretilmiş
    (``*.min.js`` vb.) ya da UTF-8 olmayan dosyalar atlanır; toplam bayt bütçesi aşılırsa en büyük kaynak
    dosyaları atlanır. Atlananlar ``skipped`` sözlüğüne sayılır (uyarı olarak raporlanır). İstenen dosya
    sayısı sınırı (``max_files``) aşılırsa proje yine reddedilir. Kapsam (``scope``) seçenekleri bu
    atlamaları kapatabilir ve sınırları yükseltebilir; atlanan dizin grupları da ``dir_<grup>`` olarak sayılır.

    ``scope.skipped_only``: yalnız varsayılan kapsamın atlayacağı dosyalar (isteğe bağlı dizinler, üretilmiş,
    büyük, bütçe dışı, UTF-8 olmayan) döner; normal taramada incelenenler ``already_scanned`` olarak sayılır."""
    counts = skipped if skipped is not None else {}
    scope = scope or scan_scope.current()
    skip_dirs = scope.skip_dirs
    max_file_bytes, max_total_bytes = _byte_limits(scope)

    def bump(key: str, size: int = 0) -> None:
        counts[key] = counts.get(key, 0) + 1
        if size:
            counts[key + "_bytes"] = counts.get(key + "_bytes", 0) + size

    # (mantıksal_yol, descriptor ile gözlenen dosya, tür, boyut, varsayılan_atlardı)
    # tür: secret_file | manifest | source
    candidates: list[tuple[Path, ProjectFile, str, int, bool]] = []

    try:
        with ProjectTree(root) as tree:
            walk_limit = min(10_000_000, max(100_000, max_files * 100))
            for walked in tree.walk(
                skip_dirs=skip_dirs,
                max_entries=walk_limit,
                reject_unsafe=False,
            ):
                for skipped_dir in walked.skipped_directories:
                    group = scan_scope.dir_group(skipped_dir.name)
                    if group:
                        bump("dir_" + group)
                for included_dir in walked.directories:
                    group = scan_scope.dir_group(included_dir.name)
                    if group:
                        bump("included_dir_" + group)

                rel_dir = () if walked.directory.as_posix() == "." else walked.directory.parts
                in_default_skipped_dir = any(
                    part.casefold() in scan_scope.DEFAULT_SKIP_DIRS for part in rel_dir
                )
                for observed in walked.files:
                    path = root / observed.path
                    normalized = observed.name.casefold()
                    is_secret = normalized == ".env" or normalized.startswith(".env.")
                    if not is_secret:
                        is_containerfile = _is_containerfile_name(normalized)
                        is_server_config = normalized == ".htaccess" or normalized in {
                            "nginx.conf", "apache2.conf", "httpd.conf",
                        }
                        if (
                            path.suffix.casefold() not in SOURCE_EXTENSIONS
                            and normalized not in MANIFEST_NAMES
                            and not is_containerfile
                            and not is_server_config
                        ):
                            continue
                    if is_secret:
                        candidates.append((path, observed, "secret_file", 0, in_default_skipped_dir))
                        continue
                    kind = "manifest" if normalized in MANIFEST_NAMES else "source"
                    generated = kind == "source" and normalized.endswith(GENERATED_SUFFIXES)
                    if generated and not scope.include_generated:
                        bump("generated", observed.size)
                        continue
                    if observed.size > max_file_bytes:
                        bump("large", observed.size)
                        continue
                    default_skips = in_default_skipped_dir or generated or observed.size > MAX_FILE_BYTES
                    candidates.append((path, observed, kind, observed.size, default_skips))

            def budget_order(items):
                # Önce bildirimler ve .env işaretleri, sonra kaynaklar küçükten büyüğe (en büyükler atlanır).
                return sorted(items, key=lambda item: (item[2] == "source", item[3], str(item[0])))

            recheck_encoding: set[Path] = set()
            if scope.skipped_only:
                # Varsayılan kapsamın bütçesi dışında kalan en büyük kaynaklar da "atlanmış" sayılır.
                previously: set[Path] = set()
                used_bytes = 0
                for path, _observed, _kind, size, _default_skips in budget_order(
                    [candidate for candidate in candidates if not candidate[4]]
                ):
                    if used_bytes + size <= MAX_TOTAL_BYTES:
                        used_bytes += size
                        previously.add(path)
                if scope.include_non_utf8:
                    recheck_encoding = {
                        path for path in previously if not path.name.casefold().startswith(".env")
                    }
                counts["already_scanned"] = len(previously) - len(recheck_encoding)
                candidates = [
                    candidate for candidate in candidates
                    if candidate[0] not in previously or candidate[0] in recheck_encoding
                ]

            if scope.only_paths is not None:
                # Yalnız değişenler: bulgu yalnız bu dosyalar için üretilir; taint bağlamı tüm projeden gelir.
                before = len(candidates)
                candidates = [
                    candidate for candidate in candidates
                    if candidate[0].relative_to(root).as_posix() in scope.only_paths
                ]
                counts["unchanged"] = before - len(candidates)

            if len(candidates) - len(recheck_encoding) > max_files:
                raise ProjectRejected(
                    f"Proje analiz sınırını aşıyor ({len(candidates)} dosya > {max_files} dosya sınırı). "
                    "Kapsam seçeneklerinden dosya sınırını yükseltin veya dahil edilen dizin gruplarını azaltın."
                )
            keep: set[Path] = set()
            used_bytes = 0
            for path, _observed, _kind, size, _default_skips in budget_order(candidates):
                if used_bytes + size > max_total_bytes:
                    bump("budget", size)
                    continue
                used_bytes += size
                keep.add(path)
            if stats is not None:
                stats["total"] = len(keep)
            project_progress.report("files", 0, len(keep), force=True)

            for path, observed, kind, _size, _default_skips in candidates:
                if path not in keep:
                    continue
                if kind == "secret_file":
                    yield path, None, "secret_file", tree
                    continue
                try:
                    raw = tree.read_bytes(observed, max_file_bytes, allow_empty=True)
                except ProjectTreeError:
                    continue
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    if not scope.include_non_utf8:
                        bump("encoding", observed.size)
                        continue
                    text = raw.decode("utf-8", errors="replace")
                    bump("decoded_lossy")
                else:
                    if path in recheck_encoding:
                        counts["already_scanned"] = counts.get("already_scanned", 0) + 1
                        continue
                yield path, text, kind, tree
    except ProjectTreeError as exc:
        raise ProjectRejected("Proje ağacı güvenli biçimde açılamadı veya tarama sırasında değişti.") from exc


def _time_budget_seconds() -> float | None:
    """İsteğe bağlı analiz süre bütçesi (``SNIPER_PROJECT_TIME_BUDGET_SECONDS``; 0/boş = sınırsız, önceki davranış).
    İş kuyruğu, iş süre sınırından önce kısmi sonuç kaydedebilmek için bu değeri iş sürecine verir."""
    raw = os.environ.get("SNIPER_PROJECT_TIME_BUDGET_SECONDS", "").strip()
    try:
        value = float(raw) if raw else 0.0
    except ValueError:
        return None
    return min(value, 24 * 3600.0) if value > 0 else None


def _byte_limits(scope: "scan_scope.ScanScope") -> tuple[int, int]:
    """(tek dosya, toplam) bayt sınırları: kapsam değeri varsayılansa modül ayarı (ortam değişkeni) geçerlidir."""
    file_bytes = MAX_FILE_BYTES if scope.max_file_bytes == scan_scope.DEFAULT_MAX_FILE_BYTES else scope.max_file_bytes
    total_bytes = MAX_TOTAL_BYTES if scope.max_total_bytes == scan_scope.DEFAULT_MAX_TOTAL_BYTES else scope.max_total_bytes
    return file_bytes, total_bytes


def _read_fd(fd: int, size: int) -> bytes:
    """Dosyayı sonuna kadar oku (büyük dosyalarda tek ``os.read`` kısa dönebilir)."""
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = os.read(fd, min(remaining, 8 * 1024 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


SKIPPED_HINTS = {
    "large": "max_file_mb",
    "generated": "include_generated",
    "encoding": "include_non_utf8",
    "budget": "max_total_mb",
}


def _skipped_warnings(skipped: dict[str, int], scope: "scan_scope.ScanScope | None" = None) -> list[str]:
    """Atlanan dosyalar için kullanıcıya gösterilecek uyarılar (proje reddedilmedi)."""
    scope = scope or scan_scope.current()
    max_file_bytes, max_total_bytes = _byte_limits(scope)
    labels = {
        "large": f"tek dosya sınırını ({max_file_bytes // 1_000_000} MB) aşan",
        "generated": "üretilmiş/küçültülmüş (*.min.js, *.bundle.js vb.)",
        "encoding": "UTF-8 olmayan",
        "budget": f"toplam boyut bütçesini ({max_total_bytes // 1_000_000} MB) aşan en büyük",
    }
    warnings = []
    for group, label in scan_scope.DIR_GROUP_LABELS.items():
        count = skipped.get("dir_" + group, 0)
        if count:
            warnings.append(f"{count} {label} dizini atlandı (kapsam seçeneklerinden dahil edilebilir).")
    for key, label in labels.items():
        count = skipped.get(key, 0)
        if count:
            size = skipped.get(key + "_bytes", 0)
            extra = f", toplam {size / 1_000_000:.1f} MB" if size else ""
            warnings.append(f"{count} {label} dosya analiz dışında bırakıldı{extra}.")
    if skipped.get("time_budget"):
        warnings.insert(0, f"Süre bütçesi aşıldı: {skipped['time_budget']} dosya analiz edilmeden kaldı; sonuç kısmidir "
                           "(proje geneli eksiklik denetimleri yapılmadı). Büyük projelerde kapsamı daraltın ya da "
                           "SNIPER_PROJECT_TIME_BUDGET_SECONDS değerini artırın.")
    if scope.skipped_only:
        warnings.insert(0, f"Yalnız atlananlar modu: normal taramada incelenen {skipped.get('already_scanned', 0)} dosya "
                           "yeniden taranmadı; proje geneli eksiklik denetimleri ve puan yalnız bu dosyaları yansıtır.")
    if skipped.get("decoded_lossy"):
        warnings.append(f"{skipped['decoded_lossy']} UTF-8 olmayan dosya kayıplı çözülerek analiz edildi.")
    if skipped.get("included_dir_tests"):
        warnings.append("Test dizinleri dahil edildi: bu dizinlerdeki bulgular üretim kodu olmayabilir.")
    if skipped.get("included_dir_vendor") or skipped.get("included_dir_packages"):
        warnings.append("Üçüncü taraf kod dahil edildi: bulgular bağımlılıklara ait olabilir; tarama uzun sürebilir.")
    return warnings


DOM_XSS_RULE_TITLE = "DOM tabanlı XSS / güvensiz HTML bağlama yüzeyi"
ELECTRON_RULE_TITLES = frozenset({
    "Electron penceresinde nodeIntegration: true etkin (Uzaktan Kod Çalıştırma riski)",
    "Electron penceresinde contextIsolation devre dışı",
})
SOLIDITY_RULE_TITLES = frozenset({
    "Solidity akıllı sözleşmesinde Reentrancy (yeniden giriş) riski (.call{value:})",
    "Solidity akıllı sözleşmesinde tx.origin ile kimlik doğrulama",
})
ZIP_SLIP_RULE_TITLE = "Arşiv açmada dizin geçişi (Zip Slip) riski"
# Python'da AST kuralıyla (filter= değeri dahil) değerlendirilir; dize içerikleri boşaltılmış satırda
# filter="data" görünmediği için satır kuralı yanlış alarm verirdi.
# Python şablon işleme hedefi açıklaması: "render('ad') → şablon:satır {{ … }}".
_PY_TEMPLATE_SINK_RE = re.compile(r"^\w+\('[^']*'\) → \S+:\d+ \{\{")
_PY_TEMPLATE_LOC_RE = re.compile(r" → (\S+):(\d+) \{\{")
_PICKLE_SESSION_RE = re.compile(r"""^\s*SESSION_SERIALIZER\s*=\s*["'][\w.]*PickleSerializer["']""")
NON_PYTHON_RULE_TITLES = frozenset({
    DOM_XSS_RULE_TITLE,
    ZIP_SLIP_RULE_TITLE,
    "Sunucu tarafı şablon enjeksiyonu (SSTI) riski",
    *ELECTRON_RULE_TITLES,
    *SOLIDITY_RULE_TITLES,
})

# Satır kuralı ön süzgeci (yalnız hız): her kuralın HER eşleşmesinde geçmek zorunda olan küçük harfli, boşluksuz
# sabit parçalar. Dosyanın casefold metninde hiçbiri yoksa kural o dosyanın hiçbir satırında eşleşemez; satır
# döngüsünden çıkarılır, sonuç değişmez. Python satırlarındaki dizge/yorum maskelemesi karakterleri yalnız boşlukla
# değiştirdiği için boşluksuz parça maskeli satırda varsa ham metinde de vardır. Listede olmayan başlık: süzgeç yok.
_LINE_RULE_LITERALS: dict[str, tuple[str, ...]] = {
    "Güvensiz nesne serileştirme (Deserialization)": (
        "pickle", "marshal", "dill", "shelve", "yaml", "unserialize", "objectinputstream", "readobject", "node-serialize"),
    DOM_XSS_RULE_TITLE: ("dangerouslysetinnerhtml", "v-html", "bypasssecuritytrust", "innerhtml", "outerhtml", "document.write"),
    "JWT imza doğrulaması devre dışı veya alg:none izni": ("verify_signature", "algorithms", "jwt"),
    ZIP_SLIP_RULE_TITLE: ("extractall",),
    "Sunucu tarafı şablon enjeksiyonu (SSTI) riski": ("render_template_string", "template"),
    "XML ayrıştırıcıda dış varlık (XXE) işleme açık": (
        "resolve_entities", "load_dtd", "no_network", "feature_external_general_entities", "feature_disallow_doctype_decl",
        "libxml_noent", "libxml_dtdload"),
    "Güvenlik değerinde zayıf rastgele sayı üreteci (PRNG)": ("random",),
    "Electron penceresinde nodeIntegration: true etkin (Uzaktan Kod Çalıştırma riski)": ("nodeintegration",),
    "Electron penceresinde contextIsolation devre dışı": ("contextisolation",),
    "Yapay zeka / PyTorch model yüklemesinde güvensiz serileştirme (torch.load)": ("torch.load",),
    "Şifresiz (cleartext) gRPC kanal bağlantısı": ("insecure_channel", "useplaintext", "withinsecure"),
    "Solidity akıllı sözleşmesinde Reentrancy (yeniden giriş) riski (.call{value:})": (".call",),
    "Solidity akıllı sözleşmesinde tx.origin ile kimlik doğrulama": ("tx.origin",),
    "C/C++ bellek taşması (Buffer Overflow) riski taşıyan güvensiz fonksiyon (gets/strcpy)": ("gets", "strcpy", "strcat", "sprintf"),
    "Kaynak kodda sabit sır olasılığı": ("api", "client", "private", "password", "passwd"),
    "Dinamik kod çalıştırma": ("eval", "exec"),
    "Kabuk üzerinden komut çalıştırma": ("shell", "os.system", "popen"),
    "SQL sorgusunda veri birleştirme": ("execute", "query"),
    "Zayıf kriptografik özet": ("hashlib", "messagedigest"),
    "TLS sertifika doğrulaması kapalı": ("verify", "rejectunauthorized", "cert_none"),
    "ASP.NET istek doğrulaması kapalı": ("validaterequest", "validateinput", "requestvalidationmode"),
    "Servis tüm ağ arayüzlerinde dinliyor": ("0.0.0.0", "host"),
    "Geniş CORS izni": ("allow_origins", "access-control-allow-origin"),
    "Günlüğe hassas veri yazma olasılığı": ("log", "print"),
}


def _fold_for_literals(lower: str) -> str:
    """``re.IGNORECASE`` 'ı' ve 'İ' harflerini 'i' ile eşler; casefold bunları tek 'i'ye indirmez."""
    if "ı" in lower or "\u0307" in lower:
        return lower.replace("ı", "i").replace("\u0307", "")
    return lower


def _rules_present(rules: tuple, folded: str) -> tuple:
    """Ön süzgeçten geçen kurallar (sıra korunur)."""
    out = []
    for rule in rules:
        literals = _LINE_RULE_LITERALS.get(rule[2])
        if literals is None or any(literal in folded for literal in literals):
            out.append(rule)
    return tuple(out)
_JS_COOKIE_CALL = re.compile(r"\b(?:res|response|reply|ctx\.cookies)\.(?:cookie|set|setCookie)\s*\(")
DYNAMIC_CODE_SUFFIXES = frozenset({
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte", ".html", ".htm",
    ".php", ".rb", ".pl", ".pm", ".lua", ".sh", ".bash", ".zsh", ".ps1", ".groovy", ".kts",
})
JS_FAMILY_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte", ".html", ".htm", ".json"})
_SLASH_COMMENT_SUFFIXES = frozenset({
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte",
    ".go", ".java", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".rs",
    ".cs", ".kt", ".kts", ".php", ".sol", ".groovy", ".scala", ".swift", ".dart",
})
_HASH_COMMENT_SUFFIXES = frozenset({
    ".rb", ".pl", ".pm", ".sh", ".bash", ".zsh", ".ps1", ".php", ".yaml", ".yml", ".toml", ".conf",
})
_LLM_TOKEN_METRIC_RE = re.compile(
    r"(?i)\b(?:(?:prompt|completion|total|max|input|output|cached|reasoning|num)[_-]?tokens?|token[_-]?(?:count|usage|limit|budget)s?|tokens[_-]?used)\b"
)
_BENIGN_SECRET_LITERAL_RE = re.compile(
    r"(?i)^(?:placeholder.*|changeme.*|your[_\s-].*|example.*|dummy.*|no[_-]?api[_-]?key.*|"
    r"not[_-]?used[_-]?at[_-]?runtime|build[_-]?only|oauth\s+client\s+secret.*|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\})$"
)
_SQL_CONTEXT_LINE_RE = re.compile(
    r"(?i)(?:\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|INTO|VALUES|CREATE|ALTER|DROP|TABLE|SET|UNION)\b"
    r"|\b(?:db|sql|conn|connection|cursor|cur|stmt|pool|tx|session|engine|knex|sequelize|prisma|repo|store)\s*\.(?:\w+\s*\.)?\s*(?:execute|query)\s*\()"
)
_JWT_INSECURE_OPTION_RE = re.compile(
    r"(?i)(?:verify\s*=\s*false|verify_signature[\"']?\s*[:=]\s*false)"
)
_JWT_ALGORITHMS_OPEN_RE = re.compile(r"(?i)algorithms\s*[:=]\s*\[")
_JWT_NONE_LITERAL_RE = re.compile(r"(?i)[\"']none[\"']")


def _jwt_none_algorithm(text: str) -> bool:
    """Find a quoted none algorithm before the next ']' without rescanning a long list."""
    offset = 0
    while match := _JWT_ALGORITHMS_OPEN_RE.search(text, offset):
        close = text.find("]", match.end())
        end = len(text) if close == -1 else close
        if _JWT_NONE_LITERAL_RE.search(text, match.end(), end):
            return True
        if close == -1:
            return False
        offset = close + 1
    return False


def _has_unsafe_jwt_option(text: str) -> bool:
    return bool(_JWT_INSECURE_OPTION_RE.search(text)) or _jwt_none_algorithm(text)


def _non_python_code_only_lines(text: str, suffix: str) -> list[str]:
    """Blank line/block comments in non-Python source files while preserving line count and column positions."""
    has_slash = suffix in _SLASH_COMMENT_SUFFIXES
    has_hash = suffix in _HASH_COMMENT_SUFFIXES
    if not has_slash and not has_hash:
        return text.splitlines()
    out: list[str] = []
    n = len(text)
    i = 0
    in_block_comment = False
    in_quote: str | None = None
    buf: list[str] = []
    while i < n:
        ch = text[i]
        if ch == "\n":
            out.append("".join(buf))
            buf = []
            if in_quote in ('"', "'"):
                in_quote = None
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and i + 1 < n and text[i + 1] == "/":
                buf.append("  ")
                in_block_comment = False
                i += 2
            else:
                buf.append(" ")
                i += 1
            continue
        if in_quote is not None:
            if ch == "\\" and i + 1 < n:
                buf.append(ch)
                if text[i + 1] != "\n":
                    buf.append(text[i + 1])
                    i += 2
                    continue
            elif ch == in_quote:
                in_quote = None
            buf.append(ch)
            i += 1
            continue
        if ch in ('"', "'", "`"):
            in_quote = ch
            buf.append(ch)
            i += 1
            continue
        if has_slash and ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                while i < n and text[i] != "\n":
                    buf.append(" ")
                    i += 1
                continue
            if nxt == "*":
                buf.append("  ")
                in_block_comment = True
                i += 2
                continue
        if has_hash and ch == "#":
            while i < n and text[i] != "\n":
                buf.append(" ")
                i += 1
            continue
        buf.append(ch)
        i += 1
    if buf or text.endswith("\n"):
        if buf:
            out.append("".join(buf))
    return out


def _python_code_only_lines(text: str) -> list[str]:
    """Return source lines with string-literal and comment contents blanked.

    Multi-language regex rules must not fire on pattern strings, docstrings or
    remediation text inside Python files (for example a detector that stores
    ``"innerHTML ="`` as a regex). Column positions and line count are kept.
    Falls back to the raw lines when the file cannot be tokenized.
    """
    lines = text.splitlines()
    masked = [list(line) for line in lines]
    blank_types = {tokenize.STRING, tokenize.COMMENT}
    for name in ("FSTRING_MIDDLE",):
        token_type = getattr(tokenize, name, None)
        if token_type is not None:
            blank_types.add(token_type)
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return lines
    for token in tokens:
        if token.type not in blank_types:
            continue
        (start_row, start_col), (end_row, end_col) = token.start, token.end
        for row in range(start_row, end_row + 1):
            index = row - 1
            if index >= len(masked):
                break
            first = start_col if row == start_row else 0
            last = min(end_col if row == end_row else len(masked[index]), len(masked[index]))
            if last > first:  # 19. tur hız: karakter döngüsü yerine dilim ataması (aynı sonuç)
                masked[index][first:last] = " " * (last - first)
    return ["".join(chars) for chars in masked]


_DOM_ESCAPER_PATTERN = re.compile(
    r"\b(?:esc|escapeHtml|escapeHTML|htmlEscape|sanitizeHtml|DOMPurify\.sanitize|sanitize)\s*\("
)


_JS_DYNAMIC_CODE_PATTERN = re.compile(r"(?<![\w$.])eval\s*\(")
_JS_SHELL_EXEC_PATTERN = re.compile(r"(?<![\w$.])exec(?:Sync)?\s*\(|\b(?:child_process|childProcess|cp)\.exec(?:Sync)?\s*\(")


def _is_constant_expr(node: ast.AST) -> bool:
    """Yalnız sabit dizgelerden oluşan ifade (ör. "SELECT " + "1"); veri birleştirme değildir."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.BinOp):
        return _is_constant_expr(node.left) and _is_constant_expr(node.right)
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(value, ast.Constant) for value in node.values)
    return False


_DOM_SINK_PATTERN = re.compile(r"\b(?:innerHTML|outerHTML)\s*=(?!=)")
DOM_REVIEW_MARKER = "sniper-reviewed: html-safe"


_INLINE_DOM_SOURCE_RE = re.compile(r"\blocation\b|document\.(?:URL|documentURI|referrer|cookie)|window\.name|"
                                   r"URLSearchParams|\.data\b|postMessage")
_INLINE_DOM_SINK_RE = re.compile(r"innerHTML|outerHTML|document\.write|insertAdjacentHTML|\beval\s*\(|"
                                 r"setTimeout|setInterval|new\s+Function|\.html\s*\(|\.append\s*\(|\bsrc\b|\bhref\b")
_INLINE_TEMPLATE_DELIMITERS = {"{{": "}}", "{%": "%}", "{#": "#}", "<%": "%>"}


def _mask_inline_template_tags(text: str) -> str:
    """Mask complete Jinja/Django/EJS tags in bounded linear time.

    The output has exactly the same length and newline positions as ``text``.
    Missing closers are memoized by delimiter, so a run of attacker-controlled
    openers cannot cause a fresh suffix search for every two characters.
    """
    parts: list[str] = []
    missing_closers: set[str] = set()
    copied_until = 0
    index = 0
    length = len(text)
    while index + 1 < length:
        opener = text[index:index + 2]
        closer = _INLINE_TEMPLATE_DELIMITERS.get(opener)
        if closer is None or closer in missing_closers:
            index += 1
            continue
        closing = text.find(closer, index + 2)
        if closing < 0:
            missing_closers.add(closer)
            # Bir sonraki karakter başka bir açıcının başlangıcı olabilir (``{{#``
            # içinde ikinci ``{`` ile başlayan ``{#`` gibi). Aynı kapatıcı yeniden aranmaz.
            index += 1
            continue
        end = closing + 2
        tag = text[index:end]
        parts.append(text[copied_until:index])
        # Tek ``0`` geçerli bir JS ifadesidir; kalan karakterleri boşlukla maskelemek hem
        # uzunluğu hem de tag'in ilk dört karakterine düşebilen satır sonlarını korur.
        parts.append("0" + "".join("\n" if char == "\n" else " " for char in tag[1:]))
        copied_until = end
        index = end
    parts.append(text[copied_until:])
    return "".join(parts)


def _inline_script_analysis(text: str, relpath: str) -> Any:
    """HTML şablonundaki satır içi <script> blokları (src'siz, JS türü): DOM tabanlı veri akışı (location.hash →
    document.write …). Blok dışı metin boşlukla, şablon etiketleri (Django/Jinja/EJS) ``null`` ile değiştirilir;
    satır numaraları korunur."""
    import taint_js_views

    blocks = [(m.start(1), m.end(1)) for m in taint_js_views._SCRIPT_BLOCK_RE.finditer(text)
              if _INLINE_DOM_SOURCE_RE.search(m.group(1)) and _INLINE_DOM_SINK_RE.search(m.group(1))]
    if not blocks:
        return None  # ön süzgeç: DOM kaynağı ve tehlikeli hedef birlikte yoksa motor çalıştırılmaz
    out = []
    k = 0
    for lo, hi in blocks:
        out.append(re.sub(r"[^\n]", " ", text[k:lo]))
        out.append(_mask_inline_template_tags(text[lo:hi]))
        k = hi
    out.append(re.sub(r"[^\n]", " ", text[k:]))
    return taint_flow.analyze_javascript("".join(out), filename=relpath + ".inline.js")


def _dom_sink_is_safe(lines: list[str], index: int) -> bool:
    """Treat literal-only or explicitly escaped HTML assignments as reviewed.

    The statement is read from the sink to the point where brackets balance and
    a ``;`` (or end of line with balanced brackets) closes it, at most 40 lines.
    Heuristic: an escaper call anywhere in that statement marks it reviewed.
    """
    line = lines[index]
    if DOM_REVIEW_MARKER in line:
        return True
    sink = _DOM_SINK_PATTERN.search(line)
    if sink is None:
        return False
    rhs_parts = [line[sink.end():]]
    depth = 0
    for offset in range(index, min(len(lines), index + 40)):
        chunk = rhs_parts[0] if offset == index else lines[offset]
        if offset != index:
            rhs_parts.append(chunk)
        for char in chunk:
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
        if depth <= 0 and (chunk.rstrip().endswith((";", "}")) or depth < 0):
            break
    rhs = "\n".join(rhs_parts).strip()
    first_statement = rhs.split(";", 1)[0].strip()
    if first_statement[:1] in {"'", '"', "`"} and "${" not in first_statement and "+" not in first_statement:
        return True
    return bool(_DOM_ESCAPER_PATTERN.search(rhs))


# Taint (kaynak → hedef) akışı doğrulanmış bulgular: hedef türü → (kategori, önem, başlık, öneri, referans)
TAINT_FLOW_RULES: dict[str, tuple[str, str, str, str, str]] = {
    "sql": (
        "data_query", "critical", "Doğrulanmış veri akışı: istek girdisi SQL sorgusuna ulaşıyor (SQL enjeksiyonu)",
        "Sorguyu sabit metin olarak tutun ve değerleri parametre bağlama (?, %s, $1) ile geçirin; "
        "tablo/sütun adlarını allowlist ile seçin.",
        "CWE-89",
    ),
    "command": (
        "command_data", "critical", "Doğrulanmış veri akışı: istek girdisi kabuk komutuna ulaşıyor (komut enjeksiyonu)",
        "Kabuk kullanmayın (argüman dizisi, shell=False); izin verilen komut/argümanları allowlist ile sınırlandırın.",
        "CWE-78",
    ),
    "eval": (
        "command_data", "critical", "Doğrulanmış veri akışı: istek girdisi eval/exec'e ulaşıyor (kod enjeksiyonu)",
        "Kullanıcı girdisini kod olarak yorumlamayın; işlemleri açık bir eşleme/allowlist ile seçin.",
        "CWE-95",
    ),
    "html": (
        "web_hardening", "high", "Doğrulanmış veri akışı: istek/URL girdisi HTML bağlamına ulaşıyor (XSS)",
        "Girdiyi metin olarak bağlayın (textContent) veya DOMPurify/escape ile arındırın; şablonda otomatik kaçışı kapatmayın.",
        "CWE-79",
    ),
    "path": (
        "command_data", "high", "Doğrulanmış veri akışı: istek girdisi dosya yoluna ulaşıyor (yol aşımı)",
        "Dosya adını os.path.basename/secure_filename ile indirgeyin, çözümlenmiş yolun izinli kök dizin "
        "altında kaldığını (realpath + commonpath) doğrulayın veya kimlikten dosyaya allowlist eşlemesi kullanın.",
        "CWE-22",
    ),
    "ssrf": (
        "ssrf", "high", "Doğrulanmış veri akışı: istek girdisi giden HTTP isteğinin adresine ulaşıyor (SSRF)",
        "Hedef ana makineyi allowlist ile sınırlandırın; şema/port denetleyin, iç ağ ve bulut meta veri "
        "adreslerine (169.254.169.254, 127.0.0.0/8, 10/8 vb.) yönlendirmeyi DNS çözümünden sonra engelleyin.",
        "CWE-918",
    ),
    "deserialize": (
        "data_query", "critical", "Doğrulanmış veri akışı: istek girdisi güvensiz serileştirme çözücüsüne ulaşıyor",
        "Güvenilmeyen veriyi pickle/marshal/yaml.load ile açmayın; JSON veya yaml.safe_load kullanın, "
        "gerekiyorsa veriyi imzalayıp (HMAC) doğrulamadan çözmeyin.",
        "CWE-502",
    ),
    "redirect": (
        "web_hardening", "medium", "Doğrulanmış veri akışı: istek girdisi yönlendirme adresine ulaşıyor (açık yönlendirme)",
        "Yalnız göreli yollara veya allowlist'teki ana makinelere yönlendirin "
        "(ör. url_has_allowed_host_and_scheme); kullanıcıdan tam URL kabul etmeyin.",
        "CWE-601",
    ),
}


def _regex_word_char(char: str) -> bool:
    """Python ``\\w`` sınıfını tek karakter için regex çalıştırmadan yaklaşıkla."""
    return char == "_" or char.isalnum()


def _starts_with_word(text: str, prefix: str) -> bool:
    return text.startswith(prefix) and (
        len(text) == len(prefix) or not _regex_word_char(text[len(prefix)])
    )


def _yaml_line_entry(raw_line: str) -> tuple[int, str, str] | None:
    """Basit ``[-] key: value`` satırını tek geçişte ayır.

    Bu yardımcı bir YAML çözücü değildir; aşağıdaki güvenlik ön süzgeçlerinin
    önceki kabul kümesini korurken ardışık ``\\s*`` regexlerinin geri izleme
    maliyetini ortadan kaldırır.
    """
    length = len(raw_line)
    index = 0
    while index < length and raw_line[index].isspace():
        index += 1
    indent = index
    if index < length and raw_line[index] == "-":
        index += 1
        while index < length and raw_line[index].isspace():
            index += 1
    key_start = index
    while index < length and raw_line[index] != ":" and not raw_line[index].isspace():
        index += 1
    key = raw_line[key_start:index]
    while index < length and raw_line[index].isspace():
        index += 1
    if not key or index >= length or raw_line[index] != ":":
        return None
    index += 1
    while index < length and raw_line[index].isspace():
        index += 1
    return indent, key, raw_line[index:]


def _yaml_entry_starts_word(
    entry: tuple[int, str, str] | None, key: str, value: str
) -> bool:
    if entry is None or entry[1].casefold() != key.casefold():
        return False
    return _starts_with_word(entry[2].casefold(), value.casefold())


def _has_rule_pack_yaml_shape(text: str) -> bool:
    has_rules_root = False
    has_rule_key = False
    for raw_line in text.splitlines():
        if raw_line.startswith("rules:") and not raw_line[len("rules:"):].strip():
            has_rules_root = True
        entry = _yaml_line_entry(raw_line)
        if entry is None:
            continue
        content = entry[1] + ":" + entry[2]
        # ``pattern`` ilk alternatiftir: eski regex pattern-either gibi bütün
        # tireli Semgrep anahtarlarını da bu kelime sınırından kabul ediyordu.
        if _starts_with_word(content, "pattern") or _starts_with_word(content, "patterns"):
            has_rule_key = True
        elif entry[1] == "mode" and _starts_with_word(entry[2], "taint"):
            has_rule_key = True
        if has_rules_root and has_rule_key:
            return True
    return False


_GHA_UNTRUSTED_EVENT_PREFIXES = (
    "issue.title", "issue.body",
    "pull_request.title", "pull_request.body", "pull_request.head.ref",
    "pull_request.head.label", "pull_request.head.repo.default_branch",
    "comment.body", "review.body", "review_comment.body",
    "head_commit.message", "head_commit.author.email", "head_commit.author.name",
    "discussion.title", "discussion.body",
    "workflow_run.head_branch", "workflow_run.display_title", "workflow_run.head_commit.message",
)


def _gha_suffix_is_untrusted(suffix: str) -> bool:
    if suffix.startswith("head_ref"):
        return True
    if not suffix.startswith("event."):
        return False
    event = suffix[len("event."):]
    if event.startswith(_GHA_UNTRUSTED_EVENT_PREFIXES):
        return True
    if event.startswith("pages."):
        return event.find(".page_name", len("pages.")) >= 0
    if event.startswith("commits."):
        start = len("commits.")
        return any(event.find(field, start) >= 0 for field in (
            ".message", ".author.email", ".author.name",
        ))
    return False


def _gha_expression_has_untrusted_field(expression: str) -> bool:
    """Kapalı bir GitHub Actions ifade gövdesindeki riskli alanı doğrusal ara."""
    cursor = 0
    needle = "github."
    while True:
        found = expression.find(needle, cursor)
        if found < 0:
            return False
        if (found == 0 or not _regex_word_char(expression[found - 1])) and _gha_suffix_is_untrusted(
            expression[found + len(needle):]
        ):
            return True
        cursor = found + len(needle)


def _has_untrusted_gha_expression(raw_line: str) -> bool:
    """Tam ``${{ ... }}`` segmentlerini yeniden taramadan tek geçişte denetle."""
    segment_start = 0
    cursor = 0
    length = len(raw_line)
    while cursor < length:
        closing = raw_line.find("}", cursor)
        if closing < 0:
            return False
        if closing + 1 < length and raw_line[closing + 1] == "}":
            segment = raw_line[segment_start:closing]
            opening = segment.find("${{")
            if opening >= 0 and _gha_expression_has_untrusted_field(segment[opening + 3:]):
                return True
            cursor = closing + 2
            segment_start = cursor
        else:
            cursor = closing + 1
            segment_start = cursor
    return False


def _is_detection_rule_pack(suffix: str, text: str) -> bool:
    """Semgrep/Opengrep YAML kural paketi veya Sniper taint model JSON'u mu?"""
    if suffix in {".yaml", ".yml"}:
        return _has_rule_pack_yaml_shape(text)
    if suffix == ".json":
        head = text[:400]
        return '"sniper-taint-models-v1"' in head or '"sniper-iac-rules-v1"' in head or (
            head.lstrip().startswith("{") and '"rules"' in head and '"pattern' in text[:20_000]
        )
    return False


TAINT_FLOW_RULES.update({
    "ldap": (
        "data_query", "high", "Doğrulanmış veri akışı: istek girdisi LDAP arama filtresine ulaşıyor (LDAP enjeksiyonu)",
        "Filtre değerlerini escape_filter_chars ile kaçışlayın veya izinli karakter allowlist'i uygulayın.",
        "CWE-90",
    ),
    "xpath": (
        "data_query", "high", "Doğrulanmış veri akışı: istek girdisi XPath ifadesine ulaşıyor (XPath enjeksiyonu)",
        "İfadeyi sabit tutun; değerleri XPath değişkenleriyle (ör. lxml .xpath('…$ad', ad=deger)) bağlayın.",
        "CWE-643",
    ),
    "xxe": (
        "data_query", "high", "Doğrulanmış veri akışı: istek girdisi dış varlıkları çözen XML ayrıştırıcısına ulaşıyor (XXE)",
        "Dış varlık çözümünü kapatın (feature_external_ges/pes False, resolve_entities=False) veya defusedxml kullanın.",
        "CWE-611",
    ),
    "session": (
        "auth", "medium", "Doğrulanmış veri akışı: doğrulanmamış istek girdisi oturuma yazılıyor (güven sınırı ihlali)",
        "Oturuma yalnız doğrulanmış/normalize edilmiş değerleri yazın; kullanıcı girdisini güvenilir oturum verisinden ayrı tutun.",
        "CWE-501",
    ),
})
TAINT_FLOW_RULES.update({
    "jsonp": (
        "web_hardening", "low", "JSONP geri çağırma yansıması (CSP atlatma riski)",
        "Geri çağırma adını katı bir desenle doğrulayın (ör. ^[A-Za-z_$][\\w$.]{0,63}$) ya da JSONP yerine CORS ile "
        "JSON kullanın; JSONP uç noktası kimlik doğrulamalı veri döndürmesin. Yansıyan ad, CSP'deki güvenilir "
        "kaynaktan saldırgan betiği çalıştırmak (CSP atlatma) ve kimlik bilgili veriyi sızdırmak için kullanılabilir.",
        "CWE-79",
    ),
    "nosql_expr": (
        "data_query", "high", "Doğrulanmış veri akışı: istek girdisi DynamoDB sorgu ifadesine/tablo adına ulaşıyor (NoSQL enjeksiyonu)",
        "İfade metnini sabit tutun; alan adlarını ExpressionAttributeNames (#ad), değerleri ExpressionAttributeValues "
        "(:deger) ile bağlayın; tablo/alan adı ve karşılaştırma işlecini allowlist ile seçin.",
        "CWE-943",
    ),
    "nosql": (
        "data_query", "high", "Doğrulanmış veri akışı: istek girdisi NoSQL sorgu nesnesine ulaşıyor (operatör enjeksiyonu)",
        "Sorgu değerlerinin dize/sayı olduğunu doğrulayın (typeof/String()), $ ile başlayan anahtarları reddedin "
        "(mongo-sanitize) ve kimlikleri ObjectId olarak ayrıştırın.",
        "CWE-943",
    ),
    "prototype": (
        "data_query", "high", "Doğrulanmış veri akışı: istek anahtarları nesne birleştirme/atamasına ulaşıyor (prototip kirletme)",
        "__proto__/constructor/prototype anahtarlarını reddedin, Object.create(null) veya Map kullanın, "
        "derin birleştirmede anahtar allowlist'i uygulayın.",
        "CWE-1321",
    ),
    "template_object": (
        "command_data", "high", "Doğrulanmış veri akışı: bütün istek nesnesi şablon yerellerine (res.render) veriliyor",
        "res.render'a req.body/req.query nesnesini doğrudan vermeyin; yalnız gereken alanları açıkça seçin "
        "({ ad: req.body.ad }). EJS'de settings/outputFunctionName gibi seçenekler yerellerden okunabilir "
        "(sunucu tarafı şablon/kod enjeksiyonu); şablon motorunu güncel tutun.",
        "CWE-94",
    ),
    "angular_html": (
        "web_hardening", "low", "Doğrulanmış veri akışı: istek girdisi Angular [innerHTML] bağlamasına ulaşıyor (varsayılan arındırma etkin)",
        "Angular bu bağlamayı arındırır (betik/olay öznitelikleri atılır) ancak HTML/bağlantı enjeksiyonu mümkündür; "
        "metni {{ }} ile bağlayın, HTML gerekiyorsa allowlist ile arındırın ve bypassSecurityTrust* kullanmayın.",
        "CWE-79",
    ),
})
TAINT_FLOW_RULES.update({
    "ssti": (
        "command_data", "critical", "Doğrulanmış veri akışı: istek girdisi şablon metninin kendisine ulaşıyor (sunucu tarafı şablon enjeksiyonu)",
        "Kullanıcı girdisini şablon kaynağına eklemeyin; sabit şablonu yükleyip girdiyi yalnız bağlam değişkeni olarak "
        "verin (render(ad=girdi)). Jinja2'de gerekiyorsa SandboxedEnvironment kullanın.",
        "CWE-1336",
    ),
})
TAINT_FLOW_RULES.update({
    "ssrf_partial": (
        "ssrf", "low", "Doğrulanmış veri akışı: istek girdisi sabit ana makineli giden isteğin yol/sorgu bölümüne ulaşıyor (kısmi SSRF)",
        "Ana makine sabit olsa da yol/sorgu enjeksiyonu (../, ?, #, &) hedef API'de beklenmeyen uç noktaya erişim sağlayabilir; "
        "değerleri urllib.parse.quote(değer, safe='') / encodeURIComponent ile kodlayın veya allowlist/tür doğrulaması uygulayın.",
        "CWE-918",
    ),
})
TAINT_FLOW_RULES.update({
    # 27. tur — C/C++: istek verisi yorumlayıcıya ya da derlenecek/yorumlanacak kaynak dosyasına (kod enjeksiyonu)
    "code": (
        "command_data", "critical", "Doğrulanmış veri akışı: istek girdisi derlenen/yorumlanan koda gömülüyor (kod enjeksiyonu)",
        "Kullanıcı girdisini kaynak koda, betiğe ya da yorumlayıcıya (luaL_dostring, PyRun_*, dlopen) vermeyin; gerekli "
        "işlemleri sabit kodda allowlist ile seçin, veri olarak ayrı dosya/argüman ile geçirin.",
        "CWE-94",
    ),
    # Rust / C / C++ (taint_rust, taint_cfamily)
    "format_string": (
        "command_data", "high", "Doğrulanmış veri akışı: istek girdisi printf biçim dizgesine ulaşıyor (biçim dizgesi açığı)",
        "Biçim dizgesini sabit tutun ve veriyi argüman olarak geçirin: printf(\"%s\", veri); kullanıcı verisini asla "
        "biçim argümanı olarak kullanmayın (-Wformat-security ile derleyin).",
        "CWE-134",
    ),
    "memory": (
        "command_data", "critical", "Doğrulanmış veri akışı: istek girdisi sınır denetimsiz bellek kopyalamasına ulaşıyor (arabellek taşması)",
        "Boyut sınırlı işlevler kullanın (snprintf, strlcpy/strncpy + sonlandırma, fgets); hedef arabellek boyutunu "
        "kopyalamadan önce doğrulayın; scanf'te genişlik belirtin (%63s).",
        "CWE-120",
    ),
    "memory_len": (
        "command_data", "high", "Doğrulanmış veri akışı: istek girdisi bellek kopyalama uzunluğuna ulaşıyor (arabellek taşması)",
        "Uzunluğu hedef arabellek boyutuyla sınırlandırın (if (n > sizeof(buf)) hata; MIN(n, sizeof buf)) ve "
        "işaretsiz/negatif değer dönüşümlerini denetleyin.",
        "CWE-805",
    ),
    "memory_index": (
        "command_data", "high", "Doğrulanmış veri akışı: istek girdisi denetimsiz dizi indeksine ulaşıyor (sınır dışı bellek erişimi)",
        "İndeksi hem alt (>= 0) hem üst (< dizi boyutu) sınıra göre doğrulayın; işaretsiz tür (size_t) kullanın.",
        "CWE-129",
    ),
    "deserialize_unbounded": (
        "data_query", "medium", "Doğrulanmış veri akışı: istek girdisi boyut sınırsız ikili seri çözücüye ulaşıyor (bellek tükenmesi)",
        "bincode için boyut sınırı ayarlayın (bincode::options().with_limit(N) / config.with_limit::<N>()) ve istek "
        "gövdesi boyutunu çatı düzeyinde sınırlandırın.",
        "CWE-789",
    ),
})
# Yerel girdi (komut satırı, ortam değişkeni, standart girdi) akışlarının raporlandığı hedefler: bellek güvenliği ve
# biçim dizgesi hataları yerel girdiyle de sömürülebilir (setuid/CGI/servis betikleri); komut/yol/SQL hedeflerinde
# yerel girdi CLI aracının olağan davranışıdır ve raporlanmaz (motor bu akışları üretmez).
LOCAL_FLOW_KINDS = frozenset({"format_string", "memory", "memory_len", "memory_index"})
NATIVE_FLOW_LANGUAGES = frozenset({"rust", "c", "cpp"})
WEAK_RANDOM_FLOW_RULE = (
    "crypto", "medium", "Güvenlik değerinde zayıf rastgele sayı: random modülü değeri oturuma/çereze yazılıyor",
    "Oturum, çerez ve belirteç değerleri için secrets (token_urlsafe, randbelow) veya os.urandom kullanın.",
    "CWE-330",
)


# Dosya başına aynı başlıklı doğrulanmış akış bulgusu sınırı (desen kuralları için sınır 4).
MAX_FLOW_FINDINGS_PER_RULE_FILE = 25
# C/C++ bellek güvenliği (26. tur): gets/strcpy desen kuralı yalnız C ailesi dosyalarında çalışır (önceden PHP/JS
# dosyalarındaki strcpy( / sprintf( metinleri de eşleşiyordu); yerel motor (memsafety_c) ve isteğe bağlı clang.
C_OVERFLOW_RULE_TITLE = "C/C++ bellek taşması (Buffer Overflow) riski taşıyan güvensiz fonksiyon (gets/strcpy)"
C_FAMILY_SUFFIXES = frozenset({".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".ipp", ".inl",
                               ".ino", ".m", ".mm"})
MEMSAFETY_MAX_PER_FILE = 20
MEM_FMT_CWES = frozenset({"119", "120", "121", "122", "124", "125", "126", "127", "129", "131", "134", "170", "190",
                          "193", "242", "415", "416", "590", "676", "680", "761", "762", "787", "788", "805", "806"})


def _clang_summary(result: dict[str, Any]) -> dict[str, Any]:
    """Analiz özeti için clang durumu ve derleme bilgisi kaynakları (27. tur; kaynak satırı içermez)."""
    return {"status": result.get("status"), "files": result.get("files", 0), "seconds": result.get("seconds", 0.0),
            "findings": len(result.get("findings") or []), "build": result.get("build")}


def _add_clang_findings(root: Path, files: list[Path], findings: list[dict[str, Any]], add: Any) -> dict[str, Any] | None:
    """clang --analyze (isteğe bağlı, çevrimdışı): yerel motorla aynı dosya+satır+sınıfta bulgu varsa yalnız teyit
    notu eklenir (iki kez raporlanmaz); yalnız clang'ın bulduğu satırlar düşük/orta önemde "olası" olarak eklenir.
    Dönen: analiz özeti (durum, dosya sayısı, derleme bilgisi kaynakları) ya da None."""
    try:
        import memsafety_c
        import memsafety_clang

        # Öncelik: yerel bellek motorunun / gets-strcpy kuralının aday bulduğu dosyalar (bütçe dolarsa önce bunlar)
        priority = sorted({root / str(f.get("file")) for f in findings
                           if f.get("file") and (f.get("memory_safety") or f.get("title") == C_OVERFLOW_RULE_TITLE)})
        result = memsafety_clang.analyze_files(root, files, priority=priority)
    except Exception:  # noqa: BLE001 - ek analizör hatası proje analizini etkilemez
        return None
    summary = _clang_summary(result)
    if not result.get("findings"):
        return summary
    by_loc: dict[tuple[str, int, str], dict[str, Any]] = {}
    for f in findings:
        cls = _mem_class(_mem_cwe(f.get("reference")))
        if cls:
            by_loc.setdefault((str(f.get("file")), int(f.get("line") or 0), cls), f)
    per_file: dict[str, int] = {}
    for c in result["findings"]:
        cls = "mem"
        rel = str(Path(c["file"]))
        existing = by_loc.get((rel, c["line"], cls))
        if existing is not None:
            ms = existing.setdefault("memory_safety", {})
            if isinstance(ms, dict):
                ms["clang_confirmed"] = c["checker"]
                ms["clang_build_info"] = c.get("build_info", "yok")
                if c.get("stub_headers"):
                    ms["clang_stub_headers"] = list(c["stub_headers"])
            continue
        if per_file.get(rel, 0) >= MEMSAFETY_MAX_PER_FILE:
            continue
        if c["checker"].startswith("alpha."):
            continue  # alpha (deneysel) denetleyiciler yalnız teyit için; tek başına bulgu üretmez (yapı hilesi gürültüsü)
        if memsafety_clang.author_suppressed(root, rel, c["line"], c["kind"]):
            continue  # yazar bilerek işaretlemiş (ör. -Wuse-after-free bastırması: işaretçi yalnız anahtar olarak)
        per_file[rel] = per_file.get(rel, 0) + 1
        kind = c["kind"]
        title = memsafety_c.title_for(kind, False) + " (clang)"  # her zaman "olası"
        before = len(findings)
        stub = list(c.get("stub_headers") or [])
        stub_note = (f"Yer tutucu başlıkla analiz edildi (eksik üretilen başlık: {', '.join(stub[:3])}). " if stub else "")
        severity = "medium" if kind in ("uaf", "double_free", "overflow") and not stub else "low"
        add("command_data", severity, title, root / rel,
            c["line"], f"Clang Static Analyzer ({c['checker']}): {c['message']}. Derleme bilgisi: "
            f"{c.get('build_info', 'yok')}. {stub_note}Yerel motor bu satırı doğrulamadı; gözden geçirin. Kaynak satır "
            "içeriği kaydedilmedi.",
            memsafety_c.recommendation_for(kind), memsafety_c._CWE.get(kind) or ("CWE-787" if kind == "overflow" else "CWE-119"))
        if len(findings) > before:
            findings[-1]["memory_safety"] = {"kind": kind, "engine": "clang-analyzer", "checker": c["checker"],
                                             "certain": False, "sink_line": c["line"],
                                             "build_info": c.get("build_info", "yok")}
            if stub:
                findings[-1]["memory_safety"]["stub_headers"] = stub
    return summary


MAX_PROJECT_HEADERS = 3000
MAX_HEADERS_PER_FILE = 12


def _project_headers(
    root: Path,
    path: Path,
    text: str,
    index: dict[str, Any],
    project_tree: ProjectTree,
) -> list[tuple[str, str]]:
    """Dosyanın ``#include "x.h"`` ettiği proje başlıkları: önce aynı dizin, sonra proje genelinde ad eşleşmesi."""
    import memsafety_c

    names = memsafety_c.INCLUDE_RE.findall(text)[:40]
    if not names:
        return []
    if "by_name" not in index:
        by_name: dict[str, list[ProjectFile]] = {}
        by_path: dict[str, ProjectFile] = {}
        seen = 0
        for observed in project_tree.iter_files(
            skip_dirs=SKIP_DIRS,
            max_entries=max(100_000, MAX_PROJECT_HEADERS * 100),
            reject_unsafe=False,
        ):
            parents = observed.path.parts[:-1]
            if any(part.startswith(".") for part in parents):
                continue
            if observed.name.lower().endswith((".h", ".hh", ".hpp", ".hxx")):
                by_name.setdefault(observed.name, []).append(observed)
                by_path[observed.path.as_posix()] = observed
                seen += 1
            if seen > MAX_PROJECT_HEADERS:
                break
        index["by_name"] = by_name
        index["by_path"] = by_path
        index["texts"] = {}
    out = []
    source_relative = PurePosixPath(path.relative_to(root).as_posix())
    for inc in names:
        if not isinstance(inc, str) or not inc or inc.startswith(("/", "\\")) or "\\" in inc or "\x00" in inc:
            continue
        combined = posixpath.normpath((source_relative.parent / inc).as_posix())
        if combined in ("", ".", "..") or combined.startswith("../"):
            candidates: list[ProjectFile] = []
        else:
            same_directory = index["by_path"].get(combined)
            candidates = [same_directory] if same_directory is not None else index["by_name"].get(
                inc.rsplit("/", 1)[-1], []
            )[:1]
        for header in candidates:
            key = str(root / header.path)
            htext = index["texts"].get(key)
            if htext is None:
                try:
                    htext = project_tree.read_text(
                        header,
                        MAX_FILE_BYTES,
                        errors="replace",
                        allow_empty=True,
                    )
                except ProjectTreeError:
                    htext = ""
                index["texts"][key] = htext
            if htext:
                out.append((key, htext))
        if len(out) >= MAX_HEADERS_PER_FILE:
            break
    return out


def _memsafety_budget_seconds() -> float:
    try:
        return max(5.0, min(3600.0, float(os.environ.get("SNIPER_MEMSAFETY_BUDGET", "120"))))
    except ValueError:
        return 120.0


def _mem_cwe(reference: Any) -> str | None:
    m = re.match(r"CWE-(\d+)", str(reference or ""))
    return m.group(1) if m and m.group(1) in MEM_FMT_CWES else None


def _mem_class(cwe: str | None) -> str | None:
    return None if cwe is None else ("fmt" if cwe == "134" else "mem")


def _memsafety_evidence(f: Any) -> str:
    refs = []
    src_file = getattr(f, "source_file", "")
    if f.source_line:
        refs.append(f"kaynak {src_file + ' ' if src_file else ''}satır {f.source_line}" +
                    (f" ({f.source})" if f.source and f.source not in ("free()",) else
                     " (free)" if f.source == "free()" else ""))
    chain = getattr(f, "chain", ())
    if chain:
        refs.append("zincir: " + " → ".join(chain))
    if f.buffer_line:
        refs.append(f"tampon `{f.buffer}` tanımı satır {f.buffer_line}" + (f" ({f.capacity})" if f.capacity else ""))
    refs.append(f"hedef satır {f.line}")
    return f"Bellek güvenliği analizi ({f.function}): {f.evidence}. Kanıt: {'; '.join(refs)}; kaynak satır içeriği kaydedilmedi."


def _proven_native_chain(flow: Any) -> bool:
    """27. tur düzeltmesi (C/C++): iki ve daha derin özet zinciri ancak her adımı modelce kanıtlıysa doğrulanmış
    sayılır: her çağrı doğrudan ve tek adaylı (aynı dosyada ya da projede o adla tek tanım), işlev işaretçisi/tablo,
    bilinmeyen işlevden geçiş, küresel/yapı alanı modeli ya da yalnız ad örüntüsüyle tanınan soket yok
    (``Flow.weak`` False) ve bağlama duyarsız çağrı derinliği (yardımcı dönüş/çıkış parametresi aktarımları hariç)
    sınır içinde. Bellek sınıfları (taşma/uzunluk/indeks) yükseltilmez: yardımcının parametre hedefindeki kopyalamada
    çağrı yerindeki hedef kabın boyutu özetle kanıtlanmaz."""
    if flow.language not in ("c", "cpp") or getattr(flow, "weak", True):
        return False
    if flow.sink_kind in ("memory", "memory_len", "memory_index"):
        return False
    return len(flow.via) - int(getattr(flow, "xfer", 0) or 0) <= 3


MODEL_MEM_FLOW_PREFIX = "Olası veri akışı (dosyalar arası model, kapasite kanıtlanmadı)"
_MODEL_HOP_MARKS = ("alanına yazım", "tablosu", "kaydı", "yönlendirme")


def _is_model_flow(flow: Any) -> bool:
    """Akış dosyalar arası modelden mi geliyor (başka dosyadaki kaynak, yapı alanı yazımı, yönlendirme tablosu)?"""
    if not isinstance(flow, dict):
        return False
    chain = flow.get("chain") or []
    return bool(flow.get("source_file")) or any(any(m in h for m in _MODEL_HOP_MARKS) for h in chain)


MIXED_FIELD_FLOW_PREFIX = "Olası veri akışı (karışık yapı alanı)"
_FIELD_HOP_RE = re.compile(r" (\w+)\.(\w+) alanına yazım$")


def _downgrade_unproven_model_flows(findings: list[dict[str, Any]], start: int,
                                    mixed_fields: set | frozenset = frozenset()) -> None:
    """27. tur: C bellek sınıfı veri akışı yalnız dosyalar arası modelden (yapı alanı, yönlendirme tablosu, başka
    dosyadaki kaynak) geliyorsa ve bellek motoru kapasiteyi kanıtlayamadıysa "olası" olarak bir derece düşük raporlanır
    (doğrulanmış bellek hatası yalnız kirlilik ve kapasite kanıtlıyken). Zincirindeki yapı alanına projede başka yerde
    temiz/sabit değer de yazılıyorsa (alan duyarlı model bağlamı karıştırır) her sınıfta "olası" raporlanır."""
    for f in findings[start:]:
        flow = f.get("taint_flow")
        if not isinstance(flow, dict) or f.get("memory_safety") or not str(f.get("title", "")).startswith(
                "Doğrulanmış veri akışı"):
            continue
        if mixed_fields:
            mixed = [m.group(1) + "." + m.group(2) for h in (flow.get("chain") or [])
                     for m in [_FIELD_HOP_RE.search(h)] if m and (m.group(1), m.group(2)) in mixed_fields]
            if mixed:
                f["title"] = f["title"].replace("Doğrulanmış veri akışı", MIXED_FIELD_FLOW_PREFIX, 1)
                f["severity"] = {"critical": "high", "high": "medium", "medium": "low"}.get(f.get("severity"),
                                                                                           f.get("severity"))
                f["evidence"] = (f.get("evidence", "") + f" `{mixed[0]}` alanına projede başka yerde sabit/temiz "
                                 "değer de yazılıyor; bu okumada değerin dış girdi olduğu kesin değil.").strip()
                continue
        if flow.get("sink_kind") not in ("memory", "memory_len", "memory_index") or not _is_model_flow(flow):
            continue
        f["title"] = f["title"].replace("Doğrulanmış veri akışı", MODEL_MEM_FLOW_PREFIX, 1)
        f["severity"] = {"critical": "high", "high": "medium", "medium": "low"}.get(f.get("severity"), f.get("severity"))
        f["evidence"] = (f.get("evidence", "") + " Bellek motoru hedef kapasitesini ya da girdinin ulaşabileceği "
                         "uzunluğu kanıtlayamadı; gözden geçirin.").strip()


def _add_memsafety_findings(findings: list[dict[str, Any]], start: int, mem_findings: list[Any], path: Path,
                            add: Any, safe_lines: set[int] | frozenset[int] = frozenset()) -> None:
    """Yerel bellek motoru bulguları: aynı satırda aynı sınıfta taint akışı varsa tekrar raporlanmaz;
    aynı satırdaki gets/strcpy desen bulgusu bu bulguyla birleşir (desen bulgusu düşer). Motorun boyutları sınırlı
    kanıtladığı satırdaki desen bulgusu düşük öncelikli gözden geçirme notuna iner."""
    for f in findings[start:]:
        if f.get("title") == C_OVERFLOW_RULE_TITLE and f.get("line") in safe_lines and not f.get("taint_verdict"):
            f["severity"] = "low"
            f["taint_verdict"] = "memsafety_bounded"
            f["evidence"] = (f"{f.get('evidence', '')} Bellek güvenliği analizi: hedef tampon boyutu ve yazılan en çok "
                             "uzunluk bilinmektedir, taşma yok; düşük öncelikli gözden geçirme.").strip()
    covered: dict[tuple, dict[str, Any]] = {}
    for f in findings[start:]:
        cls = _mem_class(_mem_cwe(f.get("reference")))
        if cls and f.get("taint_flow"):
            covered.setdefault((f.get("line"), cls), f)
    added_lines = set()
    replaced: list[dict[str, Any]] = []
    count = 0
    for m in mem_findings:
        cls = "fmt" if m.kind == "format" else "mem"
        flow_f = covered.get((m.line, cls))
        if flow_f is not None and not (m.certain and str(path).lower().endswith(tuple(C_FAMILY_SUFFIXES)) and
                                       _is_model_flow(flow_f.get("taint_flow"))):
            continue
        if count >= MEMSAFETY_MAX_PER_FILE:
            continue
        if flow_f is not None:
            # 27. tur: kapasitesi kanıtlanmış (doğrulanmış) bellek hatası aynı satırdaki veri akışı bulgusunun yerini
            # alır; akış (kaynak→hedef zinciri) bellek bulgusuna eklenir
            replaced.append(flow_f)
        import memsafety_c

        before = len(findings)
        add("command_data", m.severity, m.title, path, m.line, _memsafety_evidence(m),
            memsafety_c.recommendation_for(m.kind), m.cwe)
        if len(findings) > before:
            findings[-1]["memory_safety"] = m.as_dict()
            if flow_f is not None:
                findings[-1]["taint_flow"] = flow_f.get("taint_flow")
            added_lines.add(m.line)
            count += 1
        elif flow_f is not None:
            replaced.pop()
    if replaced:
        drop = {id(x) for x in replaced}
        findings[start:] = [f for f in findings[start:] if id(f) not in drop]

    if added_lines:
        findings[start:] = [f for f in findings[start:]
                            if not (f.get("title") == C_OVERFLOW_RULE_TITLE and f.get("line") in added_lines)]

# İkinci derece (kayıtlı veri) akışlarının raporlandığı hedef türleri (SQL/günlük/regex hariç:
# veritabanı değerleri bu hedeflerde olağan ve çoğunlukla güvenli kullanılır).
STORED_FLOW_KINDS = frozenset({"eval", "command", "html", "deserialize", "ssti"})
# 25. tur — ortak kalıcı depo modeli: yazma kanıtı olan kayıtlı veri (istek verisinin projede o depoya/sütuna
# yazıldığı motorca kanıtlanmış: Go/C#/Java/PHP tablo ve sütun yazımları, ActiveRecord öznitelikleri, Python'da
# istek verisiyle yazılan model alanları, oturum anahtarları) ikinci derece SQL/NoSQL, yol, yönlendirme ve sorgu
# dili hedeflerinde de raporlanır. Yazma kanıtı olmayan veritabanı okumaları eski (dar) kümeye tabidir.
STORED_EVIDENCED_FLOW_KINDS = STORED_FLOW_KINDS | frozenset({"sql", "nosql", "nosql_expr", "path", "redirect", "xpath",
                                                               "ldap"})
STORED_EVIDENCE_MARKS = ("(kayıtlı veri)",)


def stored_has_write_evidence(source: str) -> bool:
    """Kayıtlı veri kökeninin açıklaması motorun yazma kanıtı işaretini taşıyor mu?"""
    return any(mark in (source or "") for mark in STORED_EVIDENCE_MARKS) or \
        taint_flow.USER_WRITTEN_FIELD_MARK in (source or "")
# İkinci derece (üçüncü taraf HTTP yanıtı) akışları: yalnız kod/komut/seri çözme/SQL hedeflerinde, düşük önemde ve
# "Doğrulanmış veri akışı" sayımına girmeyen ayrı başlıkla raporlanır. Etiketler: JS "second_order", Python "remote".
SECOND_ORDER_FLOW_KINDS = frozenset({"eval", "command", "deserialize", "sql"})
REMOTE_FLOW_KINDS = SECOND_ORDER_FLOW_KINDS
SECOND_ORDER_LABELS = frozenset({"second_order", "remote"})
# Yetkili bağlam (yetki/nonce denetimli yöntem) akışlarının başlık öneki; doğrulanmış akış sayımına girmez.
PRIVILEGED_FLOW_PREFIX = "Yetkili bağlamda veri akışı (yönetici yetkisi gerekli)"


# Tehlikeli API kullanımı (hotspot) kuralları → taint hedef türü. Veri akışı analizi bu çağrıyı
# değerlendirip istek girdisinin ulaşmadığını gösterdiyse bulgu silinmez, düşük öncelikli
# gözden geçirme notuna indirilir (dış girdi modelinde olmayan kaynaklar için iz kalır).
HOTSPOT_TAINT_KINDS = {"CWE-95": "eval", "CWE-78": "command", "CWE-89": "sql", "CWE-502": "deserialize", "CWE-79": "html",
                       "CWE-120": "memory"}
_TAINT_FLOW_TITLES = frozenset(rule[2] for rule in TAINT_FLOW_RULES.values())


def _downgrade_unreached_hotspots(file_findings: list[dict[str, Any]], analysis: taint_flow.Analysis) -> None:
    for finding in file_findings:
        kind = HOTSPOT_TAINT_KINDS.get(str(finding.get("reference", "")))
        if kind is None or finding.get("taint_flow") or finding.get("title") in _TAINT_FLOW_TITLES:
            continue
        if analysis.is_unreached_sink(kind, int(finding.get("line") or 0)):
            finding["severity"] = "low"
            finding["taint_verdict"] = "no_request_flow"
            finding["evidence"] = (
                f"{finding.get('evidence', '')} Veri akışı analizi: bu çağrıya istek girdisi ulaşmıyor "
                "(fonksiyonlar arası izleme dahil); düşük öncelikli gözden geçirme."
            ).strip()


def _drop_hotspots_covered_by_flows(findings: list[dict[str, Any]], start: int) -> None:
    """C/C++/Rust: aynı satırda aynı türde doğrulanmış akış bulgusu varsa desen (hotspot) bulgusu tekrar sayılmaz."""
    flow_lines = {(f.get("line"), (f.get("taint_flow") or {}).get("sink_kind")) for f in findings[start:] if f.get("taint_flow")}
    if not flow_lines:
        return
    kinds_by_line: dict[Any, set[str]] = {}
    for line, kind in flow_lines:
        kinds_by_line.setdefault(line, set()).add({"memory_len": "memory", "memory_index": "memory"}.get(kind, kind))
    keep = []
    for f in findings[start:]:
        kind = HOTSPOT_TAINT_KINDS.get(str(f.get("reference", "")))
        if kind and not f.get("taint_flow") and kind in kinds_by_line.get(f.get("line"), ()):
            continue
        keep.append(f)
    findings[start:] = keep


# unsafe notu en çok bu kadar dosyada gösterilir (çalışma zamanı/kütüphane kodunda yüzlerce olabilir).
RUST_UNSAFE_NOTE_FILES = 10
_RUST_UNSAFE_RE = re.compile(r"\bunsafe\s*(?:\{|fn\b|impl\b)|\bextern\s+\"C\"\s*\{")


def _rust_unsafe_note(text: str, path: Path, add: Any) -> bool:
    """Rust: dosya başına tek bilgi notu — unsafe blok/işlev ve FFI (extern "C") kullanımı."""
    matches = list(_RUST_UNSAFE_RE.finditer(text))
    if not matches:
        return False
    unsafe_n = sum(1 for m in matches if not m.group(0).startswith("extern"))
    ffi_n = len(matches) - unsafe_n
    line = text.count("\n", 0, matches[0].start()) + 1
    add(
        "command_data", "info", "Rust unsafe/FFI kullanımı (bellek güvenliği denetimi devre dışı)", path, line,
        f"Dosyada {unsafe_n} unsafe blok/işlev ve {ffi_n} extern \"C\" (FFI) bloğu görüldü; derleyicinin bellek "
        "güvenliği garantileri bu bölgelerde geçerli değildir.",
        "unsafe bölgeleri en aza indirin ve her birine güvenlik gerekçesi (// SAFETY:) yazın; işaretçi/uzunluk "
        "değerlerinin geçerliliğini denetleyin, cargo miri ve cargo geiger ile gözden geçirin.",
        "CWE-119",
    )
    return True


# Çöp toplayıcı: analiz milyonlarca uzun ömürlü düğüm (AST, rota envanteri, tehdit modeli) tutar; varsayılan
# eşiklerle (700/10/10) tam toplama defalarca tüm yığını tarıyordu (django ~0,8 sn, saleor ~1,4 sn). Analiz
# boyunca eşikler yükseltilir (toplayıcı açık kalır, döngüsel çöp yine toplanır); son çıkan analiz eski
# eşikleri geri yükler (eşzamanlı analizlerde sayaçla).
_GC_RELAXED_THRESHOLD = (50_000, 50, 100)
_gc_lock = threading.Lock()
_gc_depth = 0
_gc_saved: tuple[int, int, int] | None = None


@contextlib.contextmanager
def _relaxed_gc():
    global _gc_depth, _gc_saved
    with _gc_lock:
        if _gc_depth == 0:
            saved = gc.get_threshold()
            if saved[0] > 0:  # eşik 0: toplayıcı bilerek kapatılmış, dokunma
                _gc_saved = saved
                gc.set_threshold(*(max(a, b) for a, b in zip(saved, _GC_RELAXED_THRESHOLD)))
        _gc_depth += 1
    try:
        yield
    finally:
        with _gc_lock:
            _gc_depth -= 1
            if _gc_depth == 0 and _gc_saved is not None:
                gc.set_threshold(*_gc_saved)
                _gc_saved = None


@taint_flow.project_context
def analyze_project(
    value: str,
    *,
    allowed_roots: tuple[Path, ...] | None = None,
    max_files: int | None = None,
    scope: "scan_scope.ScanScope | None" = None,
) -> dict[str, Any]:
    """Proje analizi. ``scope`` verilmezse istek bağlamındaki kapsam (varsayılan: önceki davranış) kullanılır;
    verilirse analiz boyunca etkinleşir, böylece taint ve dosya yürüyüşü aynı dizinleri görür."""
    scope = scope or scan_scope.current()
    if scope.changed_only and scope.only_paths is None:
        import changed_scan  # git tabanlı artımlı tarama; değişen dosyaları belirleyip buraya only_paths ile döner

        return changed_scan.analyze_changed(value, allowed_roots=allowed_roots, max_files=max_files, scope=scope)
    with scan_scope.scan_scope(scope), _relaxed_gc():
        return _analyze_project(value, allowed_roots=allowed_roots, max_files=max_files, scope=scope)


def _analyze_project(
    value: str,
    *,
    allowed_roots: tuple[Path, ...] | None,
    max_files: int | None,
    scope: "scan_scope.ScanScope",
) -> dict[str, Any]:
    limit = max(MAX_FILES, scope.max_files)
    if max_files is None:
        max_files = MAX_FILES if scope.max_files == scan_scope.DEFAULT_MAX_FILES else scope.max_files
    if not isinstance(max_files, int) or isinstance(max_files, bool) or not 1 <= max_files <= limit:
        raise ProjectRejected(f"Dosya sınırı 1 ile {limit} arasında olmalıdır.")
    root = validate_project_path(value, allowed_roots)
    # Kısmi tarama (yalnız atlananlar / yalnız değişenler): proje geneli yokluk denetimleri anlamsız.
    partial_scan = scope.skipped_only or scope.only_paths is not None
    try:
        with ProjectTree(root) as activation_tree:
            taint_flow.activate_project_js_handlers(root, SKIP_DIRS, project_tree=activation_tree)
    except ProjectTreeError as exc:
        raise ProjectRejected("Proje ağacı güvenli biçimde açılamadı veya doğrulamadan sonra değişti.") from exc
    findings: list[dict[str, Any]] = []
    finding_keys: set[tuple[str, str, int]] = set()
    file_count = 0
    bytes_scanned = 0
    language_counts: dict[str, int] = {}
    manifests: list[str] = []
    signals: set[str] = set()
    combined_parts: list[str] = []

    relative_cache: dict[Path, str] = {}  # bulgu başına relative_to yerine yol başına bir kez

    def add(
        category: str,
        severity: str,
        title: str,
        path: Path | None,
        line: int,
        evidence: str,
        recommendation: str,
        reference: str,
    ) -> None:
        if path:
            relative = relative_cache.get(path)
            if relative is None:
                relative = relative_cache[path] = str(path.relative_to(root))
        else:
            relative = "Proje geneli"
        key = (title, relative, line)
        if key in finding_keys:
            return
        finding_keys.add(key)
        findings.append({
            "category": category,
            "severity": severity,
            "title": title,
            "file": relative,
            "line": line,
            "evidence": evidence,
            "recommendation": recommendation,
            "reference": reference,
        })

    extra_line_rules = (
        (
            "command_data", "high", "Güvensiz nesne serileştirme (Deserialization)",
            re.compile(
                r"(?i)(\b(?:pickle|cPickle|_pickle|marshal|dill|jsonpickle)\.(?:loads?|Unpickler)\s*\("
                r"|\bshelve\.open\s*\("
                r"|\byaml\.(?:unsafe_load|full_load)\s*\("
                r"|\byaml\.load\s*\((?![^\n)]*(?:CSafeLoader|SafeLoader|safe_load))"
                r"|\bunserialize\s*\("
                r"|\bObjectInputStream\s*\("
                r"|\.readObject\s*\("
                r"|\bnode-serialize\b)"
            ),
            "Güvensiz nesne serileştirme veya geri yükleme çağrısı görüldü.",
            "Güvenilmeyen veride pickle/marshal/unserialize kullanmayın; JSON veya SafeLoader tercih edin.",
            "CWE-502",
        ),
        (
            "web_hardening", "medium", "DOM tabanlı XSS / güvensiz HTML bağlama yüzeyi",
            re.compile(
                r"(?i)(dangerouslySetInnerHTML|\bv-html\s*="
                r"|bypassSecurityTrust(?:Html|Script|ResourceUrl)"
                r"|\b(?:innerHTML|outerHTML)\s*=\s*(?![\"']\s*[\"'])"
                r"|document\.write\s*\()"
            ),
            "Güvensiz HTML/DOM enjeksiyon yüzeyi (innerHTML, dangerouslySetInnerHTML, v-html veya document.write) görüldü.",
            "Kullanıcı girdisini metin olarak bağlayın (textContent) veya DOMPurify gibi bir arındırıcı kullanın.",
            "CWE-79",
        ),
        (
            "crypto", "high", "JWT imza doğrulaması devre dışı veya alg:none izni",
            re.compile(
                r"(?i)(verify_signature[\"']?\s*[:=]\s*false"
                r"|jwt\.decode\s*\([^\n]*verify\s*=\s*false"
                r"|jwt\.get_unverified_(?:claims|header)\s*\()"
            ),
            "JWT doğrulamasında imza kontrolünün kapatıldığı veya 'none' algoritmasına izin verildiği görüldü.",
            "JWT imzalarını her zaman doğrulayın ve izin verilen algoritmaları sabit bir güvenli listeyle sınırlandırın.",
            "CWE-347",
        ),
        (
            "command_data", "high", "Arşiv açmada dizin geçişi (Zip Slip) riski",
            re.compile(r"(?i)\b(?:tarfile|zipfile|archive|tar|zip|jar|admzip)[^\n]*\.extractall\s*\((?![^\n)]*filter\s*=\s*[\"']data[\"'])"),
            "Doğrudan extractall çağrısı ile arşiv içeriğinin hedef dizin kontrolü olmadan çıkartıldığı görüldü.",
            "Arşiv üyelerinin hedef yollarını resolve() ile doğrulayın ve hedef klasör dışına çıkan (../) girdileri reddedin.",
            "CWE-22",
        ),
        (
            "command_data", "high", "Sunucu tarafı şablon enjeksiyonu (SSTI) riski",
            re.compile(r"(\brender_template_string\s*\(|\b(?:jinja2\.)?Template\s*\(\s*(?:f[\"']|[^\n)]*(?:\.format\(|\+)))"),
            "Şablon motoruna dinamik dizge veya doğrudan render_template_string çağrısı verildiği görüldü.",
            "Kullanıcı girdisini şablon kaynak metnine birleştirmeyin; sabit şablon dosyaları ve bağlam parametreleri kullanın.",
            "CWE-1336",
        ),
        (
            "data_query", "high", "XML ayrıştırıcıda dış varlık (XXE) işleme açık",
            re.compile(
                r"(?i)(resolve_entities\s*=\s*true|load_dtd\s*=\s*true|no_network\s*=\s*false"
                r"|FEATURE_EXTERNAL_GENERAL_ENTITIES[^\n]*true"
                r"|FEATURE_DISALLOW_DOCTYPE_DECL[^\n]*false"
                r"|LIBXML_NOENT|LIBXML_DTDLOAD)"
            ),
            "XML ayrıştırıcıda dış varlık (external entity) veya DTD yükleme özelliğinin etkinleştirildiği görüldü.",
            "DTD ve dış varlık çözümlemesini kapatın; Python'da defusedxml veya güvenli XML ayrıştırıcı ayarlarını kullanın.",
            "CWE-611",
        ),
        (
            "crypto", "medium", "Güvenlik değerinde zayıf rastgele sayı üreteci (PRNG)",
            re.compile(
                r"(?i)\b(token|secret|otp|nonce|password|passwd|api_?key|reset_?code|session_?id)\b"
                r"[^\n]*\b(random\.(?:random|randint|choice|choices|randrange)|Math\.random)\s*\("
            ),
            "Güvenlik duyarlı bir değer için kriptografik olmayan rastgele sayı üreteci kullanıldığı görüldü.",
            "Güvenlik belirteçleri ve tek kullanımlık kodlar için kriptografik CSPRNG (secrets, crypto.getRandomValues) kullanın.",
            "CWE-338",
        ),
        (
            "web_hardening", "critical", "Electron penceresinde nodeIntegration: true etkin (Uzaktan Kod Çalıştırma riski)",
            re.compile(r"\bnodeIntegration\s*:\s*true\b"),
            "Electron BrowserWindow yapılandırmasında nodeIntegration: true görüldü.",
            "nodeIntegration: false ayarlayın ve yalnızca güvenli contextBridge API'lerini preload üzerinden açın.",
            "CWE-250",
        ),
        (
            "web_hardening", "high", "Electron penceresinde contextIsolation devre dışı",
            re.compile(r"\bcontextIsolation\s*:\s*false\b"),
            "Electron BrowserWindow yapılandırmasında contextIsolation: false görüldü.",
            "contextIsolation: true ayarını zorunlu kılın ve iletişim için contextBridge.exposeInMainWorld kullanın.",
            "CWE-668",
        ),
        (
            "command_data", "high", "Yapay zeka / PyTorch model yüklemesinde güvensiz serileştirme (torch.load)",
            re.compile(r"\btorch\.load\s*\((?![^\n)]*weights_only\s*=\s*True)"),
            "torch.load çağrısında weights_only=True parametresi olmadan pickle tabanlı model yükleme görüldü.",
            "Model ağırlıklarını safetensors formatında yükleyin veya torch.load(..., weights_only=True) zorunlu kılın.",
            "CWE-502",
        ),
        (
            "transport", "high", "Şifresiz (cleartext) gRPC kanal bağlantısı",
            re.compile(r"\b(?:grpc\.insecure_channel\s*\(|usePlaintext\s*\(|WithInsecure\s*\()"),
            "gRPC kanalında TLS şifrelemesini devre dışı bırakan insecure_channel / usePlaintext / WithInsecure çağrısı görüldü.",
            "gRPC iletişiminde TLS veya mTLS (ssl_channel_credentials) zorunlu kılın.",
            "CWE-319",
        ),
        (
            "command_data", "critical", "Solidity akıllı sözleşmesinde Reentrancy (yeniden giriş) riski (.call{value:})",
            re.compile(r"\.call\s*(?:\{\s*value\s*:|\.value\s*\()"),
            "Harici sözleşme çağrısında (.call{value:}) durum güncellemesi öncesi ETH gönderimi (SWC-107) görüldü.",
            "Checks-Effects-Interactions (CEI) desenini uygulayın ve OpenZeppelin ReentrancyGuard (nonReentrant) kullanın.",
            "CWE-841",
        ),
        (
            "crypto", "high", "Solidity akıllı sözleşmesinde tx.origin ile kimlik doğrulama",
            re.compile(r"\btx\.origin\b"),
            "Akıllı sözleşme yetkilendirmesinde oltalama (phishing) saldırılarına açık tx.origin kullanımı (SWC-115) görüldü.",
            "Yetkilendirme kontrollerinde tx.origin yerine msg.sender kullanın.",
            "CWE-477",
        ),
        (
            "command_data", "critical", "C/C++ bellek taşması (Buffer Overflow) riski taşıyan güvensiz fonksiyon (gets/strcpy)",
            re.compile(r"(?<![A-Za-z0-9_])(?:gets|strcpy|strcat|sprintf|vsprintf)\s*\("),
            "Sınır kontrolü yapmayan güvensiz C/C++ bellek/dizge fonksiyonu (gets, strcpy, strcat, sprintf) çağrısı görüldü.",
            "Boyut sınırı zorunlu güvenli alternatifleri (fgets, strncpy/strlcpy, snprintf) kullanın.",
            "CWE-120",
        ),
    )

    line_rules = (
        (
            "secrets", "high", "Kaynak kodda sabit sır olasılığı",
            re.compile(r"(?i)\b(api[_-]?key|client[_-]?secret|private[_-]?key|password|passwd)\b\s*[:=]\s*[\"'][^\"']{8,}[\"']"),
            "Sır adı ve sabit değer ataması görüldü; değer güvenlik nedeniyle kaydedilmedi.",
            "Sırları işletim sistemi anahtarlığı veya çalışma zamanı secret store içinde tutun.",
            "CWE-798",
        ),
        (
            "command_data", "critical", "Dinamik kod çalıştırma",
            re.compile(r"(?<![A-Za-z0-9_])(eval|exec)\s*\("),
            "eval/exec çağrısı görüldü; kaynak satır içeriği kaydedilmedi.",
            "Veriyi koddan ayırın; izin verilen işlemleri açık bir eşleme ile seçin.",
            "CWE-95",
        ),
        (
            "command_data", "high", "Kabuk üzerinden komut çalıştırma",
            re.compile(r"(?i)(shell\s*=\s*true|os\.system\s*\(|popen\s*\([^\n]*[+{])"),
            "Kabuk yorumlaması veya dinamik komut birleştirme sinyali görüldü.",
            "Argüman dizisi kullanın, shell modunu kapatın ve izin verilen komutları sınırlandırın.",
            "CWE-78",
        ),
        (
            "data_query", "high", "SQL sorgusunda veri birleştirme",
            re.compile(r"(?i)(?<![A-Za-z0-9_])(execute|query)\s*\(\s*(f[\"']|[^\n]*(\.format\(|\+))"),
            "SQL çağrısında biçimlendirme/birleştirme görüldü; sorgu değeri kaydedilmedi.",
            "Hazır sorgu ve parametre bağlama kullanın; tablo/sütun adlarını allowlist ile seçin.",
            "CWE-89",
        ),
        (
            "crypto", "medium", "Zayıf kriptografik özet",
            re.compile(r"(?i)(hashlib\.(md5|sha1)\s*\(|messageDigest\.getInstance\s*\(\s*[\"']SHA-?1)"),
            "MD5 veya SHA-1 kullanımı görüldü.",
            "Bütünlük için SHA-256/512; parola için Argon2id, scrypt veya uygun PBKDF2 kullanın.",
            "CWE-327",
        ),
        (
            "transport", "high", "TLS sertifika doğrulaması kapalı",
            re.compile(r"(?i)(verify\s*=\s*false|rejectUnauthorized\s*:\s*false|CERT_NONE)"),
            "TLS doğrulamasını kapatan ayar görüldü.",
            "Sertifika ve ana makine doğrulamasını etkinleştirin; geliştirme istisnasını üretime taşımayın.",
            "CWE-295",
        ),
        (
            "web_hardening", "medium", "ASP.NET istek doğrulaması kapalı",
            re.compile(r"(?i)(\bvalidateRequest\s*=\s*[\"']?false\b|\[\s*ValidateInput\s*\(\s*false\s*\)"
                       r"|\brequestValidationMode\s*=\s*[\"']?2\.0\b)"),
            "Sayfa yönergesinde validateRequest=\"false\", eylemde [ValidateInput(false)] ya da requestValidationMode=2.0 "
            "görüldü: ASP.NET'in HTML/betik içeren istek değerlerini reddeden ön denetimi bu yüzeyde kapalı.",
            "İstek doğrulamasını açık tutun; zengin metin gerekiyorsa yalnız ilgili alanda [AllowHtml] kullanın ve çıktıyı "
            "HTML kodlayın (Server.HtmlEncode / <%: %>).",
            "CWE-16",
        ),
        (
            "ports", "medium", "Servis tüm ağ arayüzlerinde dinliyor",
            re.compile(r"(?i)([\"']0\.0\.0\.0[\"']|host\s*[:=]\s*[\"']::[\"'])"),
            "Genel ağ bind adresi görüldü.",
            "Gerekmiyorsa 127.0.0.1 üzerinde dinleyin; gerekiyorsa güvenlik duvarı ve kimlik doğrulama ekleyin.",
            "CWE-284",
        ),
        (
            "web_hardening", "medium", "Geniş CORS izni",
            re.compile(r"(?i)(allow_origins\s*=\s*\[[^\]]*[\"']\*[\"']|Access-Control-Allow-Origin[^\n]*\*)"),
            "Tüm origin'lere izin veren CORS ayarı görüldü.",
            "Üretim origin listesini açıkça sınırlandırın ve kimlik bilgili isteklerde joker kullanmayın.",
            "CWE-942",
        ),
        (
            "logging", "medium", "Günlüğe hassas veri yazma olasılığı",
            re.compile(r"(?i)(log(?:ger)?\.(?:info|debug|warning|error)|print)\s*\([^\n]*(password|token|secret|authorization)"),
            "Hassas alan adı ile günlük çağrısı aynı satırda görüldü; değer kaydedilmedi.",
            "Alanı maskeleyin; sırları, oturum belirteçlerini ve kişisel veriyi günlükten çıkarın.",
            "CWE-532",
        ),
        *extra_line_rules,
    )

    postmessage_pattern = re.compile(r"(?i)addEventListener\s*\(\s*[\"']message[\"']")
    origin_check_pattern = re.compile(r"\.origin\b")

    skipped_files: dict[str, int] = {}
    rust_unsafe_files = [0]
    # rota yetki envanteri için Python/JS kaynakları; Python dosyasının ayrıştırılmış ağacı da eklenir (ikinci ayrıştırma yok)
    authz_sources: list[tuple[str, str] | tuple[str, str, ast.Module, list[ast.AST]]] = []
    spec_sources: list[tuple[str, str]] = []  # OpenAPI/Swagger sözleşmeleri (api_spec_routes)
    authz_bytes = 0
    threat_collector = threat_model.ThreatModelCollector(root.name)
    # İlerleme (iş kuyruğu) ve isteğe bağlı süre bütçesi: aşılırsa kalan dosyalar analiz edilmez, sonuç kısmi olur.
    project_progress.report("walk", force=True)
    walk_stats: dict[str, int] = {}
    files_done = 0
    time_budget = _time_budget_seconds()
    deadline = time.monotonic() + time_budget if time_budget else None
    partial_info: dict[str, Any] | None = None
    # alt proje (monorepo) özeti için analiz edilen dosyalar: (göreli yol, dil)
    file_index: list[tuple[str, str]] = []
    iac_project_cache: dict[str, Any] = {}  # Terraform proje bağlamı sonuçları (ilk .tf dosyasında kurulur)
    iac_analysis_warnings: set[str] = set()
    c_family_files: list[Path] = []
    header_index: dict[str, Any] = {}
    memsafety_deadline_box: list[float] = []  # ilk C/C++/Rust dosyasında kurulur (diğer projelerde saat çağrısı yok)

    def memsafety_deadline() -> float:
        if not memsafety_deadline_box:
            memsafety_deadline_box.append(time.monotonic() + _memsafety_budget_seconds())
        return memsafety_deadline_box[0]

    memsafety_skipped = [0]
    for path, text, kind, project_tree in _iter_files(
        root,
        max_files=max_files,
        skipped=skipped_files,
        scope=scope,
        stats=walk_stats,
    ):
        total_files = walk_stats.get("total", 0)
        if deadline is not None and time.monotonic() > deadline:
            remaining = max(0, total_files - files_done)
            skipped_files["time_budget"] = remaining
            partial_info = {"reason": "time_budget", "budget_seconds": time_budget,
                            "analyzed_files": files_done, "total_files": total_files}
            break
        files_done += 1
        file_rel_path = path.relative_to(root)  # dosya başına bir kez (19. tur hız)
        file_rel_posix, file_rel_str = file_rel_path.as_posix(), str(file_rel_path)
        project_progress.report("files", files_done, total_files)
        # .py dosyası bir kez ayrıştırılır; ağaç tehdit modeli rota çıkarımı ve aşağıdaki kurallar/yetki envanteriyle
        # paylaşılır (19. tur hız; önceden aynı metin iki kez ayrıştırılıyordu).
        py_tree: ast.Module | None = None
        py_parsed = kind != "secret_file" and text is not None and path.suffix.casefold() == ".py"
        if py_parsed:
            try:
                py_tree = ast.parse(text)
            except SyntaxError:
                py_tree = None
        try:
            if py_parsed:
                threat_collector.add(file_rel_posix, text, kind, py_tree)
            else:
                threat_collector.add(file_rel_posix, text, kind)
        except Exception:  # tehdit modeli toplayıcısı analizi hiçbir koşulda durdurmaz
            pass
        if kind == "secret_file":
            add(
                "secrets", "low", "Yerel ortam sır dosyası mevcut", path, 0,
                "Bir .env türü dosya bulundu; içeriği okunmadı ve kaydedilmedi.",
                "Sürüm kontrolünden çıkarıldığını, izinlerinin 0600 olduğunu ve örnek dosyada gerçek değer bulunmadığını doğrulayın.",
                "CWE-522",
            )
            continue
        assert text is not None
        file_count += 1
        bytes_scanned += len(text.encode("utf-8", errors="ignore"))
        normalized_name = path.name.casefold()
        is_containerfile = _is_containerfile_name(normalized_name)
        suffix = path.suffix.casefold()
        language = (
            "Container"
            if is_containerfile
            else ("ServerConfig" if normalized_name == ".htaccess" else LANGUAGES.get(suffix))
        )
        if language:
            language_counts[language] = language_counts.get(language, 0) + 1
        file_index.append((file_rel_posix, language or ""))
        if (
            suffix in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".htm", ".vue", ".svelte", ".conf", ".htaccess"}
            or normalized_name == ".htaccess"
        ):
            signals.add("web_surface")
        if (
            suffix in {".kt", ".kts", ".swift", ".m", ".mm", ".dart", ".plist", ".entitlements", ".xcprivacy", ".gradle", ".pro"}
            or normalized_name in {
                "androidmanifest.xml", "info.plist", "network_security_config.xml",
                "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
                "pubspec.yaml", "podfile",
            }
        ):
            signals.add("mobile_surface")
        if kind == "manifest":
            manifests.append(file_rel_str)
        if suffix in api_spec_routes.SPEC_SUFFIXES and len(spec_sources) < api_spec_routes.MAX_SPECS * 4 \
                and api_spec_routes.looks_like_spec(file_rel_posix, text):
            spec_sources.append((file_rel_posix, text))
        if suffix in authz_routes.PY_SUFFIXES + authz_routes.JS_SUFFIXES and authz_bytes < AUTHZ_MAX_BYTES \
                and len(text) <= authz_routes.MAX_SOURCE_BYTES and not (suffix != ".py" and taint_flow.is_minified_js(text)):
            authz_index = len(authz_sources)
            authz_sources.append((file_rel_posix, text))
            authz_bytes += len(text)
        else:
            authz_index = -1
        lower = text.casefold()
        combined_parts.append(lower[:250_000])
        if (
            suffix not in {".tf", ".tfvars", ".conf", ".htaccess", ".plist", ".entitlements", ".xcprivacy", ".pro", ".gradle"}
            and normalized_name not in {
                ".htaccess", "androidmanifest.xml", "info.plist", "network_security_config.xml",
                "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
            }
        ):
            for signal, pattern in {
                "auth": r"password|passwd|login|sign[_ -]?in|authenticate|authorization",
                "crypto": r"cryptography|aesgcm|argon2|bcrypt|scrypt|pbkdf2|cipher|encrypt",
                "argon2": r"argon2",
                "password_kdf": r"argon2|bcrypt|scrypt|pbkdf2",
                "aead": r"aesgcm|chacha20poly1305|aes[_ -]?gcm|fernet",
                "outbound": r"requests\.(get|post|request)|httpx\.|urllib\.request|fetch\(|urlsession|dio\.",
                "ssrf_guard": r"ipaddress|is_private|is_loopback|allowlist|whitelist|resolve_public|link_local",
                "qr": r"qrcode|qr_code|qrkit|zxing|barcode",
                "qr_ttl": r"expires|expiry|ttl|nonce|one[_ -]?time|used_at",
                "qr_integrity": r"hmac|signature|sign\(|aesgcm|fernet|chacha20poly1305",
                "logging": r"\blogging\b|\blogger\b|security_event|audit_log|sentry|siem",
                "sql": r"sqlite|postgres|mysql|sqlalchemy|\.execute\(",
            }.items():
                if re.search(pattern, lower):
                    signals.add(signal)

        per_rule_count: dict[str, int] = {}
        file_findings_start = len(findings)
        if suffix == ".py":
            tree = py_tree  # yukarıda bir kez ayrıştırıldı (suffix == ".py" ⇔ py_parsed)
            # Düğüm listesi bir kez çıkarılır (ast.walk sırası) ve rota yetki envanterinin ön geçişiyle paylaşılır.
            tree_nodes = list(taint_flow.fast_walk(tree)) if tree is not None else []
            if tree is not None and authz_index >= 0:
                # ağaç ve düğüm listesi salt okunur paylaşılır (ikinci ayrıştırma/yürüyüş yok)
                authz_sources[authz_index] = (authz_sources[authz_index][0], text, tree, tree_nodes)

            def dotted_name(node: ast.AST) -> str:
                if isinstance(node, ast.Name):
                    return node.id
                if isinstance(node, ast.Attribute):
                    parent = dotted_name(node.value)
                    return f"{parent}.{node.attr}" if parent else node.attr
                return ""

            def keyword_value(node: ast.Call, name: str) -> ast.AST | None:
                return next((item.value for item in node.keywords if item.arg == name), None)

            if tree is not None:
                # Bare ``Template(...)`` and ``render_template_string(...)`` are common local helper names.
                # Treat them as SSTI sinks only when this file actually binds the name from Jinja/Flask.
                # Aliases are included so the precision guard does not reduce recall for ordinary imports.
                ssti_template_calls: set[str] = set()
                ssti_render_calls: set[str] = set()
                for import_node in tree_nodes:
                    if isinstance(import_node, ast.Import):
                        for alias in import_node.names:
                            module = alias.name.casefold()
                            bound = (alias.asname or alias.name.split(".", 1)[0]).casefold()
                            if module == "jinja2" or module.startswith("jinja2."):
                                ssti_template_calls.add(f"{bound}.template")
                            if module == "flask" or module.startswith("flask."):
                                ssti_render_calls.add(f"{bound}.render_template_string")
                    elif isinstance(import_node, ast.ImportFrom):
                        module = (import_node.module or "").casefold()
                        for alias in import_node.names:
                            imported = alias.name.casefold()
                            bound = (alias.asname or alias.name).casefold()
                            if (module == "jinja2" or module.startswith("jinja2.")) \
                                    and imported in {"template", "*"}:
                                ssti_template_calls.add("template" if imported == "*" else bound)
                            if (module == "flask" or module.startswith("flask.")) \
                                    and imported in {"render_template_string", "*"}:
                                ssti_render_calls.add("render_template_string" if imported == "*" else bound)
                for node in tree_nodes:
                    if isinstance(node, (ast.Assign, ast.AnnAssign)):
                        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                        value = node.value
                        for target in targets:
                            variable = dotted_name(target).casefold()
                            if (
                                re.search(r"(api_?key|client_?secret|private_?key|password|passwd)$", variable)
                                and isinstance(value, ast.Constant) and isinstance(value.value, (str, bytes))
                                and len(value.value) >= 8
                                and not (
                                    isinstance(value.value, str)
                                    and _BENIGN_SECRET_LITERAL_RE.match(value.value.strip())
                                )
                            ):
                                add(
                                    "secrets", "high", "Kaynak kodda sabit sır olasılığı", path, node.lineno,
                                    "Sır adı ve sabit değer ataması görüldü; değer güvenlik nedeniyle kaydedilmedi.",
                                    "Sırları işletim sistemi anahtarlığı veya çalışma zamanı secret store içinde tutun.", "CWE-798",
                                )
                            if value is not None and re.search(
                                r"(token|secret|otp|nonce|password|passwd|api_?key|reset_?code|session_?id)",
                                variable,
                            ):
                                for sub in ast.walk(value):
                                    if isinstance(sub, ast.Call) and dotted_name(sub.func).casefold() in {
                                        "random.random", "random.randint", "random.choice",
                                        "random.choices", "random.randrange",
                                    }:
                                        add(
                                            "crypto", "medium", "Güvenlik değerinde zayıf rastgele sayı üreteci (PRNG)",
                                            path, node.lineno,
                                            "Güvenlik duyarlı bir değer için kriptografik olmayan rastgele sayı üreteci kullanıldığı görüldü.",
                                            "Güvenlik belirteçleri ve tek kullanımlık kodlar için kriptografik CSPRNG (secrets, crypto.getRandomValues) kullanın.",
                                            "CWE-338",
                                        )
                    if not isinstance(node, ast.Call):
                        continue
                    name = dotted_name(node.func).casefold()
                    if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
                        add(
                            "command_data", "critical", "Dinamik kod çalıştırma", path, node.lineno,
                            "eval/exec çağrısı görüldü; kaynak satır içeriği kaydedilmedi.",
                            "Veriyi koddan ayırın; izin verilen işlemleri açık bir eşleme ile seçin.", "CWE-95",
                        )
                    shell_value = keyword_value(node, "shell")
                    if name == "os.system" or (
                        name in {"subprocess.run", "subprocess.call", "subprocess.popen", "popen", "subprocess.check_output", "subprocess.check_call"}
                        and isinstance(shell_value, ast.Constant) and shell_value.value is True
                    ):
                        add(
                            "command_data", "high", "Kabuk üzerinden komut çalıştırma", path, node.lineno,
                            "Kabuk yorumlaması etkin bir komut çağrısı görüldü.",
                            "Argüman dizisi kullanın, shell modunu kapatın ve izin verilen komutları sınırlandırın.", "CWE-78",
                        )
                    if name.endswith((".execute", ".query")) and node.args and not re.search(
                        r"(?:^|\.)(?:block|agent|tool|task|job|workflow|step|action|runner|plugin|pipeline|graph)s?\.(?:execute|query)$",
                        name,
                    ):
                        query = node.args[0]
                        if (isinstance(query, (ast.JoinedStr, ast.BinOp)) and not _is_constant_expr(query)) or (
                            isinstance(query, ast.Call) and dotted_name(query.func).endswith(".format")
                        ):
                            add(
                                "data_query", "medium", "SQL sorgusunda dinamik tanımlayıcı/veri", path, node.lineno,
                                "SQL çağrısında dinamik biçimlendirme görüldü; sorgu değeri kaydedilmedi.",
                                "Değerleri parametreyle bağlayın; tablo/sütun adları gerekiyorsa sabit allowlist kullanıldığını doğrulayın.", "CWE-89",
                            )
                    if name.endswith(".set_cookie") or name == "set_cookie":
                        secure_val = keyword_value(node, "secure")
                        httponly_val = keyword_value(node, "httponly")
                        if isinstance(secure_val, ast.Constant) and secure_val.value is False:
                            add(
                                "session", "medium", "Çerez Secure bayrağı kapalı (secure=False)", path, node.lineno,
                                "Çerez HTTPS dışında da gönderilebilecek biçimde ayarlanmış.",
                                "Oturum ve kimlik çerezlerinde secure=True (ve httponly=True, samesite) kullanın.", "CWE-614",
                            )
                        elif secure_val is None:
                            add(
                                "session", "low", "Çerezde Secure bayrağı belirtilmemiş", path, node.lineno,
                                "set_cookie çağrısında secure parametresi yok (varsayılan: kapalı).",
                                "Hassas çerezlerde secure=True ayarlayın.", "CWE-614",
                            )
                        if isinstance(httponly_val, ast.Constant) and httponly_val.value is False:
                            add(
                                "session", "low", "Çerez HttpOnly bayrağı kapalı (httponly=False)", path, node.lineno,
                                "Çerez istemci tarafı betiklerden okunabilir.",
                                "Oturum çerezlerinde httponly=True kullanın.", "CWE-1004",
                            )
                    weak_hash_new = (
                        name == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant)
                        and str(node.args[0].value).casefold() in {"md5", "sha1"}
                    )
                    not_for_security = keyword_value(node, "usedforsecurity")
                    if (name in {"hashlib.md5", "hashlib.sha1"} or weak_hash_new) and not (
                        isinstance(not_for_security, ast.Constant) and not_for_security.value is False
                    ):
                        add(
                            "crypto", "medium", "Zayıf kriptografik özet", path, node.lineno,
                            "MD5 veya SHA-1 kullanımı görüldü.",
                            "Bütünlük için SHA-256/512; parola için Argon2id, scrypt veya uygun PBKDF2 kullanın.", "CWE-327",
                        )
                    if name in {
                        "pickle.loads", "pickle.load", "pickle.unpickler",
                        "_pickle.loads", "_pickle.load", "cpickle.loads", "cpickle.load",
                        "marshal.loads", "marshal.load", "shelve.open",
                        "dill.loads", "dill.load", "jsonpickle.decode",
                        "yaml.unsafe_load", "yaml.full_load",
                    }:
                        add(
                            "command_data", "high", "Güvensiz nesne serileştirme (Deserialization)", path, node.lineno,
                            "Güvensiz nesne serileştirme veya geri yükleme çağrısı görüldü.",
                            "Güvenilmeyen veride pickle/marshal/unserialize kullanmayın; JSON veya SafeLoader tercih edin.",
                            "CWE-502",
                        )
                    elif name == "yaml.load":
                        loader_val = keyword_value(node, "Loader")
                        loader_name = dotted_name(loader_val).casefold() if loader_val is not None else ""
                        if not any(safe in loader_name for safe in ("safeloader", "csafeloader")):
                            add(
                                "command_data", "high", "Güvensiz nesne serileştirme (Deserialization)", path, node.lineno,
                                "Güvensiz nesne serileştirme veya geri yükleme çağrısı görüldü.",
                                "Güvenilmeyen veride pickle/marshal/unserialize kullanmayın; JSON veya SafeLoader tercih edin.",
                                "CWE-502",
                            )
                    if name.endswith(".extractall") or name == "extractall":
                        filter_val = keyword_value(node, "filter")
                        safe_filter = (isinstance(filter_val, ast.Constant) and filter_val.value in {"data", "tar"}) or (
                            dotted_name(filter_val).endswith(("data_filter", "tar_filter")) if filter_val is not None else False
                        )
                        if not safe_filter:
                            add(
                                "command_data", "high", "Arşiv açmada dizin geçişi (Zip Slip) riski", path, node.lineno,
                                "Doğrudan extractall çağrısı ile arşiv içeriğinin hedef dizin kontrolü olmadan çıkartıldığı görüldü.",
                                "Arşiv üyelerinin hedef yollarını resolve() ile doğrulayın ve hedef klasör dışına çıkan (../) girdileri reddedin.",
                                "CWE-22",
                            )
                    if name in ssti_render_calls:
                        add(
                            "command_data", "high", "Sunucu tarafı şablon enjeksiyonu (SSTI) riski", path, node.lineno,
                            "Şablon motoruna dinamik dizge veya doğrudan render_template_string çağrısı verildiği görüldü.",
                            "Kullanıcı girdisini şablon kaynak metnine birleştirmeyin; sabit şablon dosyaları ve bağlam parametreleri kullanın.",
                            "CWE-1336",
                        )
                    elif name in ssti_template_calls and node.args and not isinstance(node.args[0], ast.Constant):
                        add(
                            "command_data", "high", "Sunucu tarafı şablon enjeksiyonu (SSTI) riski", path, node.lineno,
                            "Şablon motoruna dinamik dizge veya doğrudan render_template_string çağrısı verildiği görüldü.",
                            "Kullanıcı girdisini şablon kaynak metnine birleştirmeyin; sabit şablon dosyaları ve bağlam parametreleri kullanın.",
                            "CWE-1336",
                        )
                    resolve_entities = keyword_value(node, "resolve_entities")
                    load_dtd = keyword_value(node, "load_dtd")
                    no_network = keyword_value(node, "no_network")
                    if (
                        (isinstance(resolve_entities, ast.Constant) and resolve_entities.value is True)
                        or (isinstance(load_dtd, ast.Constant) and load_dtd.value is True)
                        or (isinstance(no_network, ast.Constant) and no_network.value is False)
                    ):
                        add(
                            "data_query", "high", "XML ayrıştırıcıda dış varlık (XXE) işleme açık", path, node.lineno,
                            "XML ayrıştırıcıda dış varlık (external entity) veya DTD yükleme özelliğinin etkinleştirildiği görüldü.",
                            "DTD ve dış varlık çözümlemesini kapatın; Python'da defusedxml veya güvenli XML ayrıştırıcı ayarlarını kullanın.",
                            "CWE-611",
                        )
                    verify_value = keyword_value(node, "verify")
                    if isinstance(verify_value, ast.Constant) and verify_value.value is False:
                        if "jwt" in name:
                            add(
                                "crypto", "high", "JWT imza doğrulaması devre dışı veya alg:none izni", path, node.lineno,
                                "JWT doğrulamasında imza kontrolünün kapatıldığı veya 'none' algoritmasına izin verildiği görüldü.",
                                "JWT imzalarını her zaman doğrulayın ve izin verilen algoritmaları sabit bir güvenli listeyle sınırlandırın.",
                                "CWE-347",
                            )
                        else:
                            add(
                                "transport", "high", "TLS sertifika doğrulaması kapalı", path, node.lineno,
                                "TLS doğrulamasını kapatan çağrı görüldü.",
                                "Sertifika ve ana makine doğrulamasını etkinleştirin; geliştirme istisnasını üretime taşımayın.", "CWE-295",
                            )
                    jwt_algorithms = keyword_value(node, "algorithms")
                    if isinstance(jwt_algorithms, (ast.List, ast.Tuple, ast.Set)) and any(
                        isinstance(item, ast.Constant) and isinstance(item.value, str) and item.value.casefold() == "none"
                        for item in jwt_algorithms.elts
                    ):
                        add(
                            "crypto", "high", "JWT imza doğrulaması devre dışı veya alg:none izni", path, node.lineno,
                            "JWT doğrulamasında imza kontrolünün kapatıldığı veya 'none' algoritmasına izin verildiği görüldü.",
                            "JWT imzalarını her zaman doğrulayın ve izin verilen algoritmaları sabit bir güvenli listeyle sınırlandırın.",
                            "CWE-347",
                        )
                    jwt_options = keyword_value(node, "options")
                    if isinstance(jwt_options, ast.Dict):
                        for k_node, v_node in zip(jwt_options.keys, jwt_options.values):
                            if (
                                isinstance(k_node, ast.Constant)
                                and k_node.value == "verify_signature"
                                and isinstance(v_node, ast.Constant)
                                and v_node.value is False
                            ):
                                add(
                                    "crypto", "high", "JWT imza doğrulaması devre dışı veya alg:none izni", path, node.lineno,
                                    "JWT doğrulamasında imza kontrolünün kapatıldığı veya 'none' algoritmasına izin verildiği görüldü.",
                                    "JWT imzalarını her zaman doğrulayın ve izin verilen algoritmaları sabit bir güvenli listeyle sınırlandırın.",
                                    "CWE-347",
                                )
                    host_value = keyword_value(node, "host")
                    if isinstance(host_value, ast.Constant) and host_value.value in {"0.0.0.0", "::"}:
                        add(
                            "ports", "medium", "Servis tüm ağ arayüzlerinde dinliyor", path, node.lineno,
                            "Genel ağ bind adresi görüldü.",
                            "Gerekmiyorsa 127.0.0.1 üzerinde dinleyin; gerekiyorsa güvenlik duvarı ve kimlik doğrulama ekleyin.", "CWE-284",
                        )
                    allow_origins = keyword_value(node, "allow_origins")
                    if isinstance(allow_origins, (ast.List, ast.Tuple)) and any(
                        isinstance(item, ast.Constant) and item.value == "*" for item in allow_origins.elts
                    ):
                        add(
                            "web_hardening", "medium", "Geniş CORS izni", path, node.lineno,
                            "Tüm origin'lere izin veren CORS ayarı görüldü.",
                            "Üretim origin listesini açıkça sınırlandırın ve kimlik bilgili isteklerde joker kullanmayın.", "CWE-942",
                        )
                    if name in {"builtins.print", "print", "sys.stdout.write", "sys.stderr.write"} or any(part in name for part in ("logger.", "logging.")):
                        argument_names = {dotted_name(child).casefold() for argument in node.args for child in ast.walk(argument)}
                        sensitive_arg_names = {
                            item for item in argument_names
                            if re.search(r"password|token|secret|authorization", item)
                            and not _LLM_TOKEN_METRIC_RE.search(item)
                        }
                        if sensitive_arg_names:
                            add(
                                "logging", "medium", "Günlüğe hassas veri yazma olasılığı", path, node.lineno,
                                "Hassas alan değişkeni günlük çağrısına veriliyor; değer kaydedilmedi.",
                                "Alanı maskeleyin; sırları, oturum belirteçlerini ve kişisel veriyi günlükten çıkarın.", "CWE-532",
                            )
            if "PickleSerializer" in text:
                for line_number, line in enumerate(text.splitlines(), 1):
                    if _PICKLE_SESSION_RE.match(line):
                        add(
                            "command_data", "medium", "Django oturumu PickleSerializer ile çözülüyor", path, line_number,
                            "SESSION_SERIALIZER PickleSerializer: oturum verisi pickle ile çözülür; signed_cookies motoru "
                            "veya sızan SECRET_KEY ile birlikte uzaktan kod çalıştırmaya açılır.",
                            "Varsayılan JSONSerializer'ı kullanın (Django 4.1'de PickleSerializer kaldırıldı); SECRET_KEY'i gizli tutun.",
                            "CWE-502",
                        )
            has_verified_jwt_in_file = bool(
                re.search(r"(?i)\b(?:jwt\.decode|PyJWKClient|get_signing_key|jwk)\b", text)
                and not _has_unsafe_jwt_option(text)
            )
            python_rules = tuple(rule for rule in _rules_present(extra_line_rules, _fold_for_literals(lower))
                                 if rule[2] not in NON_PYTHON_RULE_TITLES)
            # Uygulanabilir kural yoksa dizge/yorum maskelemesi (tokenize) gereksiz.
            python_code_lines = _python_code_only_lines(text) if python_rules else ()
            for line_number, line in enumerate(python_code_lines, 1):
                for category, severity, title, pattern, evidence, recommendation, reference in python_rules:
                    if per_rule_count.get(title, 0) >= 4:
                        continue
                    if not pattern.search(line) and not (
                        title == "JWT imza doğrulaması devre dışı veya alg:none izni"
                        and _jwt_none_algorithm(line)
                    ):
                        continue
                    if (
                        title == "JWT imza doğrulaması devre dışı veya alg:none izni"
                        and has_verified_jwt_in_file
                        and re.search(r"(?i)jwt\.get_unverified_header\s*\(", line)
                        and not re.search(r"(?i)jwt\.get_unverified_claims\s*\(", line)
                    ):
                        continue
                    per_rule_count[title] = per_rule_count.get(title, 0) + 1
                    add(category, severity, title, path, line_number, evidence, recommendation, reference)
        elif _is_detection_rule_pack(suffix, text):
            # Semgrep/Opengrep kural paketi veya Sniper taint modeli: içindeki desenler tespit
            # verisidir, çalışan kod değildir; kod kuralları uygulanmaz.
            signals.add("detection_rules")
        else:
            has_origin_check = bool(origin_check_pattern.search(text))
            has_verified_jwt_in_file = bool(
                re.search(r"(?i)\b(?:jwt\.decode|PyJWKClient|get_signing_key|jwk|jwtVerify)\b", text)
                and not _has_unsafe_jwt_option(text)
            )
            folded = _fold_for_literals(lower)
            active_rules = () if normalized_name.endswith(".d.ts") else tuple(
                rule for rule in _rules_present(line_rules, folded)
                if not (rule[2] in SOLIDITY_RULE_TITLES and suffix != ".sol")
                and not (rule[2] in ELECTRON_RULE_TITLES and suffix not in JS_FAMILY_SUFFIXES)
                and not (rule[2] == C_OVERFLOW_RULE_TITLE and suffix not in C_FAMILY_SUFFIXES)
            )
            check_postmessage = not normalized_name.endswith(".d.ts") and not has_origin_check and "addeventlistener" in folded
            raw_source_lines = text.splitlines() if active_rules or check_postmessage else []
            source_lines = _non_python_code_only_lines(text, suffix) if active_rules or check_postmessage else []
            for line_number, line in enumerate(source_lines, 1):
                raw_line_text = raw_source_lines[line_number - 1] if line_number - 1 < len(raw_source_lines) else line
                for category, severity, title, pattern, evidence, recommendation, reference in active_rules:
                    if per_rule_count.get(title, 0) >= 4:
                        continue
                    if not pattern.search(line) and not (
                        title == "JWT imza doğrulaması devre dışı veya alg:none izni"
                        and _jwt_none_algorithm(line)
                    ):
                        continue
                    if title == DOM_XSS_RULE_TITLE and _dom_sink_is_safe(raw_source_lines, line_number - 1):
                        continue
                    if (
                        title == "JWT imza doğrulaması devre dışı veya alg:none izni"
                        and has_verified_jwt_in_file
                        and re.search(r"(?i)jwt\.get_unverified_header\s*\(", line)
                        and not re.search(r"(?i)jwt\.get_unverified_claims\s*\(", line)
                    ):
                        continue
                    if title == "SQL sorgusunda veri birleştirme" and not _SQL_CONTEXT_LINE_RE.search(raw_line_text):
                        continue
                    if title == "Kaynak kodda sabit sır olasılığı":
                        m_sec = re.search(
                            r"(?i)\b(?:api[_-]?key|client[_-]?secret|private[_-]?key|password|passwd)\b\s*[:=]\s*[\"']([^\"']{8,})[\"']",
                            line,
                        )
                        if m_sec and _BENIGN_SECRET_LITERAL_RE.match(m_sec.group(1).strip()):
                            continue
                    if title == "Günlüğe hassas veri yazma olasılığı" and not pattern.search(_LLM_TOKEN_METRIC_RE.sub("", line)):
                        continue
                    if title == "Dinamik kod çalıştırma" and suffix not in DYNAMIC_CODE_SUFFIXES:
                        continue  # YAML/JSON/belge içindeki "exec(" metni kod değildir (ör. SEMVER.exec)
                    if title == "Dinamik kod çalıştırma" and suffix in JS_FAMILY_SUFFIXES and not _JS_DYNAMIC_CODE_PATTERN.search(line):
                        # JS'te exec( dinamik kod değildir: regex.exec( güvenli, child_process exec( kabuk komutudur.
                        shell_title = "Kabuk üzerinden komut çalıştırma"
                        if _JS_SHELL_EXEC_PATTERN.search(line) and per_rule_count.get(shell_title, 0) < 4:
                            per_rule_count[shell_title] = per_rule_count.get(shell_title, 0) + 1
                            add(
                                "command_data", "high", shell_title, path, line_number,
                                "child_process exec çağrısı komutu kabuk üzerinden yorumlar; kaynak satır içeriği kaydedilmedi.",
                                "execFile/spawn ile argüman dizisi kullanın (shell: false) ve izin verilen komutları sınırlandırın.",
                                "CWE-78",
                            )
                        continue
                    per_rule_count[title] = per_rule_count.get(title, 0) + 1
                    add(category, severity, title, path, line_number, evidence, recommendation, reference)
                if check_postmessage and postmessage_pattern.search(line):
                    pm_title = "postMessage dinleyicisinde köken (origin) doğrulaması eksik"
                    if per_rule_count.get(pm_title, 0) < 4:
                        per_rule_count[pm_title] = per_rule_count.get(pm_title, 0) + 1
                        add(
                            "web_hardening", "medium", pm_title, path, line_number,
                            "Mesaj dinleyicisi (message event) tanımlanmış ancak dosyada event.origin kontrolü görülmedi.",
                            "Alınan mesajları işlemeden önce event.origin değerini güvenilir origin allowlist'i ile doğrulayın.",
                            "CWE-345",
                        )

        if suffix in taint_flow.JS_SUFFIXES and not taint_flow.is_minified_js(text):
            # Express/Koa çerez seçenekleri (Python set_cookie kuralının karşılığı).
            for match in _JS_COOKIE_CALL.finditer(text):
                window = text[match.end(): match.end() + 400]
                window = window[: window.find(";")] if ";" in window else window
                line_number = text.count("\n", 0, match.start()) + 1
                if re.search(r"\bsecure\s*:\s*false\b", window):
                    add("session", "medium", "Çerez Secure bayrağı kapalı (secure: false)", path, line_number,
                        "Çerez HTTPS dışında da gönderilebilecek biçimde ayarlanmış.",
                        "Oturum ve kimlik çerezlerinde secure: true (ve httpOnly: true, sameSite) kullanın.", "CWE-614")
                if re.search(r"\bhttpOnly\s*:\s*false\b", window):
                    add("session", "low", "Çerez HttpOnly bayrağı kapalı (httpOnly: false)", path, line_number,
                        "Çerez istemci tarafı betiklerden okunabilir.",
                        "Oturum çerezlerinde httpOnly: true kullanın.", "CWE-1004")
        if suffix in taint_flow.JS_SUFFIXES and taint_flow.is_minified_js(text):
            # Küçültülmüş/paketlenmiş (çoğunlukla üçüncü taraf) dosya: tehlikeli API notları
            # kaynak kod eşleşmesi değildir; gözden geçirme notu olarak düşük öncelikte kalır.
            for finding in findings[file_findings_start:]:
                if finding.get("reference") in HOTSPOT_TAINT_KINDS:
                    finding["severity"] = "low"
                    finding["taint_verdict"] = "minified_bundle"
        inline_js = suffix in {".html", ".htm"} and "<script" in text.lower()
        if (suffix in taint_flow.PY_SUFFIXES or suffix in taint_flow.JS_SUFFIXES or suffix in taint_flow.GO_SUFFIXES
                or suffix in taint_flow.RUBY_SUFFIXES or suffix in taint_flow.CLIKE_SUFFIXES
                or suffix in taint_flow.NATIVE_SUFFIXES or inline_js):
            analysis = _inline_script_analysis(text, file_rel_posix) if inline_js else \
                taint_flow.analyze_source(text, file_rel_posix)
            flow_items = [] if analysis is None else (
                [(f, False) for f in analysis.flows] + [(f, True) for f in getattr(analysis, "privileged_flows", ())])
            for flow, privileged in flow_items:
                rule = TAINT_FLOW_RULES.get(flow.sink_kind)
                if flow.source_label == "weakrand":
                    rule = WEAK_RANDOM_FLOW_RULE if flow.sink_kind in {"session", "cookie"} else None
                if rule is None or flow.source_label not in {"request", "stored", "weakrand", "local"} | SECOND_ORDER_LABELS:
                    continue
                if flow.source_label == "local" and flow.sink_kind not in LOCAL_FLOW_KINDS:
                    continue
                category, severity, title, recommendation, reference = rule
                if flow.source_label == "local":
                    # Yerel girdi (argv/ortam/stdin): saldırganın önce yerel erişimi gerekir; bir derece düşük önem.
                    severity = {"critical": "high", "high": "medium"}.get(severity, severity)
                    title = title.replace("istek girdisi", "yerel girdi (komut satırı/ortam/standart girdi)")
                if flow.source_label in SECOND_ORDER_LABELS:
                    if flow.sink_kind not in SECOND_ORDER_FLOW_KINDS:
                        continue
                    severity = "low"
                    title = title.replace("Doğrulanmış veri akışı:", "İkinci derece veri akışı:").replace(
                        "istek girdisi", "üçüncü taraf HTTP yanıtı").replace("istek/URL girdisi", "üçüncü taraf HTTP yanıtı")
                    if "üçüncü taraf HTTP yanıtı" not in title:
                        title += " (üçüncü taraf HTTP yanıtı)"
                emit_path, emit_line = path, flow.line
                if flow.source_label == "stored" and rule is not WEAK_RANDOM_FLOW_RULE:
                    # İkinci derece: veri önce kalıcı depoya yazılıp sonra okunuyor; saldırgan denetimi
                    # dolaylı olduğundan bir derece düşük önem.
                    allowed = STORED_EVIDENCED_FLOW_KINDS if stored_has_write_evidence(flow.source) else STORED_FLOW_KINDS
                    if flow.sink_kind not in allowed:
                        continue
                    template_loc = _PY_TEMPLATE_LOC_RE.search(flow.sink) if flow.language == "python" else None
                    if template_loc is not None and (taint_flow.USER_WRITTEN_FIELD_MARK in flow.source
                                                     or "kullanıcı kaydı" in flow.source) \
                            and _PY_TEMPLATE_SINK_RE.match(flow.sink):
                        # Kaçışsız basılan alan, projede istek verisiyle yazılan bir kayıt alanı (ya da kayıtta kullanıcının
                        # seçtiği ad/e-posta, 25. tur): kalıcı XSS doğrulanmış; bulgu kaçışsız çıktının bulunduğu şablon
                        # satırında raporlanır.
                        relative_template = Path(template_loc.group(1))
                        if not relative_template.is_absolute() and ".." not in relative_template.parts:
                            try:
                                candidate = (root / relative_template).resolve(strict=True)
                                resolved_root = root.resolve(strict=True)
                            except (OSError, RuntimeError, ValueError):
                                candidate = None
                            if candidate is not None and candidate.is_relative_to(resolved_root) \
                                    and candidate.is_file():
                                emit_path, emit_line = candidate, int(template_loc.group(2))
                    elif flow.language == "python" and flow.sink_kind == "html" and _PY_TEMPLATE_SINK_RE.match(flow.sink) \
                            and "kullanıcı kaydı" not in flow.source:
                        # Kayıtlı veri |safe / autoescape off ile basılıyor: zengin içerik (yönetici HTML'i, oEmbed,
                        # arama vurgusu) kasıtlı olabilir; doğrulanmış akış değil, gözden geçirme notu.
                        title = "Kaçışsız şablon çıktısında kayıtlı veri (gözden geçirin)"
                        if per_rule_count.get(title, 0) >= 4 or (title, file_rel_str, flow.line) in finding_keys:
                            continue
                        per_rule_count[title] = per_rule_count.get(title, 0) + 1
                        add(
                            "web_hardening", "low", title, path, flow.line,
                            f"Veri akışı: {flow.describe()}; veritabanındaki değer kaçışsız basılıyor. Değer kullanıcı "
                            "tarafından yazılabiliyorsa kalıcı XSS'tir; kaynak satır içeriği kaydedilmedi.",
                            "Kullanıcının yazabildiği alanları |safe / autoescape off ile basmayın; zengin metin gerekiyorsa "
                            "kaydetmeden önce allowlist tabanlı arındırın (bleach/nh3).",
                            "CWE-79",
                        )
                        continue
                    severity = {"critical": "high", "high": "medium"}.get(severity, severity)
                    title = title.replace("Doğrulanmış veri akışı:", "Doğrulanmış veri akışı (kayıtlı veri):").replace(
                        "istek girdisi", "veritabanından okunan veri").replace("istek/URL girdisi", "veritabanından okunan veri")
                if privileged:
                    # Yetki/nonce denetimli yöntemde (yönetici yüzeyi) akış: saldırganın önce yetki alması gerekir;
                    # doğrulanmış akış sayılmaz, düşük önemli ayrı not olarak raporlanır.
                    severity = "low"
                    title = (title.replace("Doğrulanmış veri akışı", PRIVILEGED_FLOW_PREFIX, 1)
                             if title.startswith("Doğrulanmış veri akışı") else f"{PRIVILEGED_FLOW_PREFIX}: {title}")
                elif flow.language in ("java", "csharp", "php", "kotlin", "rust", "c", "cpp") and len(flow.via) >= 2 \
                        and not _proven_native_chain(flow):
                    # Hızlı Java/C#/PHP motoru: iki ve daha derin özet zinciri büyük kod tabanlarında daha az kesin;
                    # "olası" olarak bir derece düşük önemde raporlanır (doğrulanmış akış sayılmaz).
                    severity = {"critical": "high", "high": "medium", "medium": "low"}.get(severity, severity)
                    title = title.replace("Doğrulanmış veri akışı", f"Olası veri akışı (dosyalar arası, {len(flow.via)} çağrı)", 1)
                # Doğrulanmış akışlar desen kurallarından ayrı ve daha yüksek dosya başı sınırla raporlanır: her biri
                # ayrı bir kaynak→hedef yoludur (4 sınırı aynı dosyadaki diğer açıkları gizliyordu).
                if per_rule_count.get(title, 0) >= MAX_FLOW_FINDINGS_PER_RULE_FILE or (title, str(emit_path.relative_to(root)), emit_line) in finding_keys:
                    continue
                per_rule_count[title] = per_rule_count.get(title, 0) + 1
                before = len(findings)
                add(
                    category, severity, title, emit_path, emit_line,
                    f"Veri akışı: {flow.describe()}; kaynak satır içeriği kaydedilmedi.",
                    recommendation, reference,
                )
                if len(findings) > before:
                    # SARIF codeFlows ve arayüz için yapılandırılmış akış (kod parçası içermez).
                    findings[-1]["taint_flow"] = flow.as_dict()
                    if privileged:
                        findings[-1]["privileged"] = True
                        findings[-1]["taint_flow"]["privileged"] = True
                        findings[-1]["evidence"] += (" Akış yetki/nonce denetimi yapılan bir yöntemde: yalnız yetkili "
                                                     "(yönetici) kullanıcı tetikleyebilir.")
                    elif len(flow.via) >= 2 and title.startswith("Doğrulanmış veri akışı") and _proven_native_chain(flow):
                        # 27. tur düzeltmesi: derin C zinciri neden doğrulanmış sayıldı (kanıt özeti)
                        xf = int(getattr(flow, "xfer", 0) or 0)
                        findings[-1]["taint_flow"]["proven_chain"] = True
                        findings[-1]["evidence"] += (
                            f" Zincirin her adımı modelce kanıtlı: {len(flow.via) - xf} doğrudan, tek adaylı çağrı"
                            + (f" ve {xf} yardımcı aktarımı (dönüş/çıkış parametresi)" if xf else "")
                            + "; işlev işaretçisi, küresel/yapı alanı modeli ya da bilinmeyen işlevden geçiş yok.")
            if analysis is not None:
                _downgrade_unreached_hotspots(findings[file_findings_start:], analysis)
                if suffix in taint_flow.NATIVE_SUFFIXES:
                    _drop_hotspots_covered_by_flows(findings, file_findings_start)
        if suffix == ".rs" and isinstance(text, str) and "unsafe" in text and time.monotonic() < memsafety_deadline():
            import memsafety_rust

            try:
                rust_mem = memsafety_rust.analyze_text(text, file_rel_posix)
            except (RecursionError, MemoryError):
                rust_mem = []
            if rust_mem:
                _add_memsafety_findings(findings, file_findings_start, rust_mem, path, add)
        if suffix in C_FAMILY_SUFFIXES and suffix not in (".m", ".mm") and isinstance(text, str) and kind != "secret_file":
            import memsafety_c

            c_family_files.append(path)
            deadline_ = memsafety_deadline()
            if time.monotonic() < deadline_:
                try:
                    try:
                        mem_facts = taint_flow.cfamily_facts(file_rel_posix, text)
                    except Exception:  # noqa: BLE001 — model kurulamazsa bellek motoru dosya içi çalışır
                        mem_facts = None
                    mem_findings, safe_lines = memsafety_c.analyze_text_ex(
                        text, file_rel_posix, deadline=min(deadline_, time.monotonic() + memsafety_c.FILE_BUDGET_S),
                        headers=_project_headers(root, path, text, header_index, project_tree), facts=mem_facts)
                except (RecursionError, MemoryError):
                    mem_findings, safe_lines = [], set()
                if mem_findings or safe_lines:
                    _add_memsafety_findings(findings, file_findings_start, mem_findings, path, add, safe_lines)
            else:
                memsafety_skipped[0] += 1
            try:
                mixed = (taint_flow.cfamily_facts(file_rel_posix, text) or {}).get("clean_field_writes") or set()
            except Exception:  # noqa: BLE001
                mixed = set()
            _downgrade_unproven_model_flows(findings, file_findings_start, mixed)
        if suffix in taint_flow.RUST_SUFFIXES and rust_unsafe_files[0] < RUST_UNSAFE_NOTE_FILES:
            if _rust_unsafe_note(text, path, add):
                rust_unsafe_files[0] += 1

        # Yerleşik IaC motoru (Terraform, Kubernetes/Helm, Dockerfile, compose). Dosya ayrıştırılamazsa ya da motor
        # beklenmedik biçimde hata verirse aşağıdaki eski desen kuralları devreye girer.
        iac_result = None
        if is_containerfile or suffix in iac_engine.IAC_SUFFIXES:
            rel_iac = path.relative_to(root).as_posix()
            try:
                if suffix == ".tf":
                    # 19. tur: Terraform proje bağlamında (değişken varsayılanları, tfvars, locals, yerel modüller)
                    if "terraform" not in iac_project_cache:
                        try:
                            iac_project_cache["terraform"] = iac_tf_project.scan_tree(
                                root, scope.skip_dirs, project_tree=project_tree,
                            )
                            scan_result = iac_project_cache["terraform"]
                            if not getattr(scan_result, "analysis_complete", True):
                                limits = ", ".join(getattr(scan_result, "limitations", ())) or "analiz bütçesi"
                                iac_analysis_warnings.add(
                                    f"Terraform proje analizi kısmi kaldı ({limits}).")
                        except Exception:  # noqa: BLE001 — proje bağlamı kurulamazsa dosya başına analiz
                            iac_project_cache["terraform"] = {}
                    iac_result = iac_project_cache["terraform"].get(rel_iac)
                if iac_result is None:
                    helm_values = iac_engine.helm_values_for(root, rel_iac) if "{{" in text else None
                    iac_result = iac_engine.analyze(rel_iac, text, helm_values)
                if suffix in (".yaml", ".yml") and "{{" not in text:
                    if "kubernetes_relations" not in iac_project_cache:
                        try:
                            iac_project_cache["kubernetes_relations"] = iac_k8s_project.scan_tree(
                                root, scope.skip_dirs, project_tree=project_tree,
                            )
                            scan_result = iac_project_cache["kubernetes_relations"]
                            if not getattr(scan_result, "analysis_complete", True):
                                limits = ", ".join(getattr(scan_result, "limitations", ())) or "analiz bütçesi"
                                iac_analysis_warnings.add(
                                    f"Kubernetes ilişki analizi kısmi kaldı ({limits}).")
                        except Exception:  # noqa: BLE001 — proje grafiği kurulamazsa dosya analizi korunur
                            iac_project_cache["kubernetes_relations"] = {}
                    related = iac_project_cache["kubernetes_relations"].get(rel_iac)
                    if related is not None:
                        if iac_result is None:
                            iac_result = iac_engine.IacResult("kubernetes")
                        existing = {(item["id"], item["line"], item["resource"]) for item in iac_result.findings}
                        iac_result.findings.extend(item for item in related.findings
                                                   if (item["id"], item["line"], item["resource"]) not in existing)
            except Exception:  # noqa: BLE001 — analiz hiçbir IaC dosyası yüzünden düşmez
                iac_result = None
        if iac_result is not None:
            signals.add("container_iac")
            if not iac_result.analysis_complete:
                iac_analysis_warnings.add(
                    f"{rel_iac}: IaC analizi kısmi kaldı ({iac_result.note or 'analiz bütçesi'}).")
            for item in iac_result.findings:
                before = len(findings)
                add(item["category"], item["severity"], item["title"], path, item["line"], item["evidence"],
                    item["recommendation"], item["reference"])
                if len(findings) > before:
                    findings[-1]["iac"] = {"check": item["id"], "framework": item["framework"],
                                           "resource": item["resource"], "checkov": item["checkov"]}
        iac_manifest = iac_result is not None and iac_result.framework in {"kubernetes", "compose"}

        if is_containerfile and iac_result is None:
            signals.add("container_iac")
            stage_aliases: set[str] = set()
            has_from = False
            user_directives: list[tuple[int, str]] = []
            pipe_sh_pattern = re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|da|z|k)?sh\b")
            for line_number, raw_line in enumerate(text.splitlines(), 1):
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                from_match = re.match(
                    r"(?i)^FROM\s+(?:--\S+\s+)*([^\s#]+)(?:\s+AS\s+([^\s#]+))?",
                    stripped,
                )
                if from_match:
                    image_ref = from_match.group(1).strip()
                    alias = from_match.group(2)
                    if alias:
                        stage_aliases.add(alias.casefold())
                    image_lower = image_ref.casefold()
                    if image_lower != "scratch" and image_lower not in stage_aliases:
                        has_from = True
                        if image_lower.endswith(":latest") or (
                            ":" not in image_ref and "@" not in image_ref and not image_ref.startswith("$")
                        ):
                            add(
                                "container", "low", "Konteyner taban imajı sabitlenmemiş (:latest)",
                                path, line_number,
                                "Dockerfile içinde :latest etiketli veya sürümü sabitlenmemiş taban imajı (FROM) görüldü.",
                                "Tekrarlanabilir ve güvenli derlemeler için taban imajını belirli bir sürüm etiketine veya SHA-256 özetine sabitleyin.",
                                "CWE-1104",
                            )
                user_match = re.match(r"(?i)^USER\s+([^\s#]+)", stripped)
                if user_match:
                    user_directives.append((line_number, user_match.group(1).strip()))
                if pipe_sh_pattern.search(stripped):
                    add(
                        "container", "high",
                        "Konteyner derlemesinde doğrulanmamış uzaktan betik çalıştırma (curl | sh)",
                        path, line_number,
                        "Konteyner derleme adımlarında ağdan indirilen betiğin doğrudan kabuğa (sh/bash) aktarıldığı görüldü.",
                        "İndirilen kurulum dosyalarının kriptografik özetini (SHA-256) doğrulamadan doğrudan kabukta çalıştırmayın.",
                        "CWE-829",
                    )
            if has_from:
                if not user_directives:
                    add(
                        "container", "medium", "Konteyner ayrıcalıklı (root) kullanıcıyla çalışıyor",
                        path, 1,
                        "Dockerfile içinde ayrıcalıksız USER yönergesi bulunmadı; konteyner varsayılan olarak root ile çalışır.",
                        "Konteyner çalışma zamanı için ayrıcalıksız bir kullanıcı oluşturun ve USER yönergesiyle root olmayan kullanıcıya geçin.",
                        "CWE-250",
                    )
                else:
                    last_line, last_user = user_directives[-1]
                    primary_user = last_user.split(":", 1)[0].strip().casefold()
                    if primary_user in {"root", "0"}:
                        add(
                            "container", "medium", "Konteyner ayrıcalıklı (root) kullanıcıyla çalışıyor",
                            path, last_line,
                            "Dockerfile içinde etkin USER yönergesinin root/0 olarak bırakıldığı görüldü.",
                            "Konteyner çalışma zamanı için ayrıcalıksız bir kullanıcı oluşturun ve USER yönergesiyle root olmayan kullanıcıya geçin.",
                            "CWE-250",
                        )

        if suffix in {".yml", ".yaml"}:
            rel_posix = str(path.relative_to(root)).replace("\\", "/").casefold()
            is_cicd = ".github/workflows" in rel_posix or normalized_name == ".gitlab-ci.yml"
            if is_cicd or normalized_name in {"docker-compose.yml", "docker-compose.yaml"} or re.search(
                r"(?i)\b(apiVersion|kind|services|containers)\s*:", text
            ):
                signals.add("container_iac")
            # İfade yalnız run:/script: (kabuk veya github-script) içinde enjeksiyon riski taşır;
            # env:/with:/concurrency içinde kullanmak önerilen güvenli yoldur.
            has_checkout = bool(re.search(r"(?i)\buses\s*:\s*[\"']?actions/checkout\b", text)) if is_cicd else False
            has_same_repo_guard = bool(re.search(r"head\.repo\.full_name\s*==\s*github\.repository", text)) if is_cicd else False
            has_prt_trigger = bool(re.search(r"\bpull_request_target\b", text)) if is_cicd else False
            has_pr_trigger = bool(re.search(r"\bpull_request\b(?!_target)", text)) if is_cicd else False
            script_indent: int | None = None
            for line_number, raw_line in enumerate(text.splitlines(), 1):
                indent = len(raw_line) - len(raw_line.lstrip())
                if script_indent is not None and raw_line.strip() and indent <= script_indent:
                    script_indent = None
                yaml_entry = _yaml_line_entry(raw_line)
                script_entry = (
                    yaml_entry if yaml_entry is not None and yaml_entry[1] in {"run", "script"} else None
                )
                script_value = script_entry[2].strip() if script_entry is not None else None
                in_script = script_indent is not None or bool(
                    script_entry is not None and script_value not in {"", "|", ">", "|-", ">-"}
                )
                if script_entry is not None and script_value in {"", "|", ">", "|-", ">-", "|+", ">+"}:
                    script_indent = script_entry[0]
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if iac_manifest:
                    pass  # Kubernetes/compose dosyası IaC motorunca yapısal olarak denetlendi
                elif _yaml_entry_starts_word(yaml_entry, "privileged", "true"):
                    add(
                        "container", "high", "Konteyner/Pod privileged (tam yetkili) modda çalışıyor",
                        path, line_number,
                        "Yapılandırmada privileged: true ayarı ile konteynere tam ana makine yetkisi verildiği görüldü.",
                        "privileged modunu kapatın; yalnızca gerçekten gereken Linux yeteneklerini (capabilities) tek tek tanımlayın.",
                        "CWE-250",
                    )
                network_host = False
                if yaml_entry is not None:
                    yaml_key = yaml_entry[1].casefold()
                    yaml_value = yaml_entry[2].casefold()
                    if yaml_key == "network_mode":
                        if yaml_value.startswith(("\"", "'")):
                            yaml_value = yaml_value[1:]
                        network_host = _starts_with_word(yaml_value, "host")
                    elif yaml_key == "hostnetwork":
                        network_host = _starts_with_word(yaml_value, "true")
                if not iac_manifest and network_host:
                    add(
                        "container", "medium", "Konteyner/Pod ana makine ağ uzayını (hostNetwork) paylaşıyor",
                        path, line_number,
                        "Yapılandırmada hostNetwork: true veya network_mode: host kullanımı görüldü.",
                        "Konteyner ağ yalıtımını koruyun; yalnızca gerekli portları açıkça yayınlayın.",
                        "CWE-284",
                    )
                if not iac_manifest and "/var/run/docker.sock" in raw_line:
                    add(
                        "container", "critical", "Konteyner içine docker.sock soketi bağlanmış",
                        path, line_number,
                        "Ana makine Docker daemon soketinin (/var/run/docker.sock) konteynere bağlandığı görüldü.",
                        "docker.sock soketini konteynerlere bağlamayın; bu erişim ana makine üzerinde root yetkisine eşdeğerdir.",
                        "CWE-250",
                    )
                if not iac_manifest and _yaml_entry_starts_word(
                    yaml_entry, "allowPrivilegeEscalation", "true"
                ):
                    add(
                        "container", "medium", "Kubernetes iş yükünde yetki yükseltme (allowPrivilegeEscalation) açık",
                        path, line_number,
                        "Pod/Container securityContext içinde allowPrivilegeEscalation: true ayarı görüldü.",
                        "securityContext altında allowPrivilegeEscalation: false ve runAsNonRoot: true ayarlarını zorunlu kılın.",
                        "CWE-250",
                    )
                if is_cicd:
                    if re.search(r"\bpull_request_target\b", raw_line):
                        prt_severity = "high" if has_checkout else "low"
                        add(
                            "supplychain", prt_severity, "CI/CD iş akışında riskli pull_request_target tetikleyicisi",
                            path, line_number,
                            "İş akışında ayrıcalıklı bağlamda çalışan pull_request_target tetikleyicisi görüldü.",
                            "Çatal (fork) PR kodunu pull_request_target içinde doğrudan çalıştırmayın; salt okunur pull_request tetikleyicisini tercih edin.",
                            "CWE-829",
                        )
                    if (
                        has_pr_trigger
                        and has_checkout
                        and not has_same_repo_guard
                        and re.search(r"(?i)\bruns-on\s*:[^\n#]*\bself-hosted\b", raw_line)
                    ):
                        add(
                            "supplychain", "high", "CI/CD iş akışında self-hosted runner üzerinde çatal (fork) PR kodu çalıştırma riski",
                            path, line_number,
                            "pull_request tetikleyicili iş akışının depo kökeni kısıtlaması olmadan self-hosted runner üzerinde çalıştığı ve PR kodunu checkout ettiği görüldü.",
                            "Self-hosted runner işlerinde github.event.pull_request.head.repo.full_name == github.repository koşulunu zorunlu kılın veya ephemeral GitHub-hosted runner kullanın.",
                            "CWE-829",
                        )
                    # Yalnız saldırganın serbest metin olarak denetleyebildiği alanlar
                    # (GitHub Security Lab listesi); sha/number/id gibi değerler enjekte edilemez.
                    if in_script and _has_untrusted_gha_expression(raw_line):
                        gha_severity = "low" if (has_same_repo_guard and not has_prt_trigger) else "critical"
                        add(
                            "supplychain", gha_severity, "CI/CD iş akışında güvenilmeyen etkinlik verisiyle komut enjeksiyonu riski",
                            path, line_number,
                            "CI/CD betiğinde github.event alanının doğrudan ${{ ... }} ile komut satırına yerleştirildiği görüldü.",
                            "Güvenilmeyen etkinlik alanlarını doğrudan run satırına yazmayın; önce ortam değişkenine (env:) atayıp kabukta tırnak içinde okuyun.",
                            "CWE-78",
                        )
                    if re.search(r"(?i)\bpermissions\s*:\s*[\"']?write-all[\"']?\b", raw_line):
                        add(
                            "supplychain", "medium", "CI/CD iş akışında aşırı geniş GITHUB_TOKEN izni (write-all)",
                            path, line_number,
                            "İş akışında GITHUB_TOKEN için write-all (tüm yazma izinleri) tanımlandığı görüldü.",
                            "Varsayılan izinleri contents: read olarak daraltın ve yalnızca gereken iş adımlarına en az ayrıcalık ilkesiyle izin verin.",
                            "CWE-250",
                        )

        if suffix in {".tf", ".tfvars"} and iac_result is None:
            signals.add("container_iac")
            has_tf_fw_context = bool(
                re.search(
                    r"(?i)\b(?:ingress|aws_security_group|aws_vpc_security_group_ingress_rule|google_compute_firewall|azurerm_network_security_rule)\b",
                    text,
                )
            )
            for line_number, raw_line in enumerate(text.splitlines(), 1):
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                    continue
                if has_tf_fw_context and re.search(r"(?:0\.0\.0\.0/0|::/0)", raw_line):
                    add(
                        "container", "high",
                        "Terraform güvenlik grubunda dünyaya açık (0.0.0.0/0) ağ erişimi",
                        path, line_number,
                        "Güvenlik duvarı veya güvenlik grubu kuralında 0.0.0.0/0 veya ::/0 üzerinden geniş/kritik port erişimi tanımlanmış.",
                        "Yönetim ve veritabanı portlarını yalnız güvenilir CIDR bloklarıyla sınırlandırın.",
                        "CWE-284",
                    )
                if re.search(
                    r'(?i)\bacl\s*=\s*["\']public-read(?:-write)?["\']|\bblock_public_acls\s*=\s*false|\bblock_public_policy\s*=\s*false|\bpublic_network_access_enabled\s*=\s*true',
                    raw_line,
                ):
                    add(
                        "container", "high",
                        "Terraform bulut depolama kaynağında herkese açık erişim",
                        path, line_number,
                        "Bulut nesne deposu veya veri kaynağında public-read ACL ya da açık genel erişim ayarı bulundu.",
                        "Bulut depolama kaynaklarında genel erişimi kapatın ve block_public_acls = true uygulayın.",
                        "CWE-732",
                    )
                if re.search(r"(?i)\b(?:storage_encrypted|encrypted|enable_https_traffic_only)\s*=\s*false", raw_line):
                    add(
                        "crypto", "medium",
                        "Terraform altyapı kaynağında şifreleme devre dışı (encrypted = false)",
                        path, line_number,
                        "Veritabanı veya disk kaynağında yerleşik şifreleme açıkça devre dışı bırakılmış.",
                        "Tüm bulut disk ve veritabanı kaynaklarında KMS tabanlı şifrelemeyi (encrypted = true) zorunlu kılın.",
                        "CWE-311",
                    )
                if re.search(r'(?i)\bhttp_tokens\s*=\s*["\']optional["\']', raw_line):
                    add(
                        "ssrf", "medium",
                        "Terraform sunucu örneğinde IMDSv2 zorunluluğu kapalı (http_tokens = optional)",
                        path, line_number,
                        "Bulut sanal makinesinde IMDSv1 açık bırakılmış; SSRF üzerinden metadata kimlik bilgisi çalınabilir.",
                        'metadata_options bloğunda http_tokens = "required" ayarını zorunlu kılın.',
                        "CWE-918",
                    )

        if suffix in {".conf", ".htaccess"} or normalized_name == ".htaccess":
            for line_number, raw_line in enumerate(text.splitlines(), 1):
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if re.search(r"(?i)\bautoindex\s+on\b|\bOptions\b[^\n]*\+?\bIndexes\b", raw_line) and not re.search(
                    r"(?i)-Indexes\b", raw_line
                ):
                    add(
                        "web_hardening", "medium",
                        "Web sunucusu yapılandırmasında dizin listeleme (autoindex/Indexes) açık",
                        path, line_number,
                        "Sunucu yapılandırmasında dizin içeriğinin listelenmesine izin verilmiş.",
                        "Nginx'te autoindex off; Apache'de Options -Indexes kullanın.",
                        "CWE-548",
                    )
                if re.search(
                    r"(?i)\b(?:ssl_protocols|SSLProtocol)\b[^\n]*(?<![-\w])(?:SSLv2|SSLv3|TLSv1(?:\.0|\.1)?)(?![.\w])",
                    raw_line,
                ):
                    add(
                        "transport", "high",
                        "Web sunucusu yapılandırmasında eski TLS protokolü (TLSv1.0/1.1) etkin",
                        path, line_number,
                        "Sunucu yapılandırmasında kullanımdan kaldırılmış SSL/TLS protokol sürümü etkinleştirilmiş.",
                        "Yalnızca TLSv1.2 ve TLSv1.3 protokollerine izin verin.",
                        "CWE-327",
                    )
                if re.search(r"(?i)\bserver_tokens\s+on\b|\bServerSignature\s+On\b", raw_line):
                    add(
                        "web_hardening", "low",
                        "Web sunucusu sürüm bilgisi ifşası (server_tokens on) açık",
                        path, line_number,
                        "Sunucu hata sayfalarında ve üstbilgilerde tam sürüm bilgisi paylaşılıyor.",
                        "server_tokens off ve ServerSignature Off ayarlarını kullanın.",
                        "CWE-200",
                    )

        if suffix == ".xml" or normalized_name in {"androidmanifest.xml", "network_security_config.xml"}:
            if re.search(r"(?i)\b(?:android:|<\s*manifest\b|<\s*network-security-config\b)", text):
                signals.add("mobile_surface")
            for line_number, raw_line in enumerate(text.splitlines(), 1):
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("<!--"):
                    continue
                if re.search(r'(?i)\bandroid:debuggable\s*=\s*["\']true["\']', raw_line):
                    add(
                        "mobile_security", "high",
                        "Android uygulamasında debuggable=true açık bırakılmış",
                        path, line_number,
                        'AndroidManifest.xml içinde android:debuggable="true" ayarı görüldü.',
                        "Üretim derlemelerinde android:debuggable ayarını kapatın veya tamamen kaldırın.",
                        "CWE-489",
                    )
                if re.search(r'(?i)\bandroid:allowBackup\s*=\s*["\']true["\']', raw_line):
                    add(
                        "mobile_security", "medium",
                        "Android uygulama verisi yedeklemeye (allowBackup) açık",
                        path, line_number,
                        'AndroidManifest.xml içinde android:allowBackup="true" ayarı görüldü.',
                        'Hassas veri içeren uygulamalarda android:allowBackup="false" ayarlayın veya yedekleme kurallarını kısıtlayın.',
                        "CWE-530",
                    )
                if re.search(
                    r'(?i)\b(?:android:usesCleartextTraffic|cleartextTrafficPermitted)\s*=\s*["\']true["\']',
                    raw_line,
                ):
                    signals.add("mobile_surface")
                    add(
                        "transport", "high",
                        "Mobil uygulamada şifresiz HTTP (Cleartext Traffic) izni açık",
                        path, line_number,
                        "Manifest veya ağ güvenlik yapılandırmasında şifresiz HTTP trafiğine izin verildiği görüldü.",
                        "usesCleartextTraffic ve cleartextTrafficPermitted ayarlarını false yapın; yalnızca HTTPS bağlantılarına izin verin.",
                        "CWE-319",
                    )
                if re.search(r'(?i)<\s*certificates\b[^>]*\bsrc\s*=\s*["\']user["\']', raw_line):
                    signals.add("mobile_surface")
                    add(
                        "transport", "high",
                        "Android ağ yapılandırmasında kullanıcı sertifikalarına güveniliyor",
                        path, line_number,
                        'network_security_config içinde kullanıcı tarafından yüklenen CA sertifikalarına (<certificates src="user"/>) güvenildiği görüldü.',
                        "Üretim ortamında yalnızca sistem (system) veya sabitlenmiş (pinned) sertifikalara güvenin.",
                        "CWE-295",
                    )
                if re.search(
                    r"\b(?:READ_SMS|RECEIVE_SMS|READ_CALL_LOG|QUERY_ALL_PACKAGES|SYSTEM_ALERT_WINDOW|BIND_ACCESSIBILITY_SERVICE|REQUEST_INSTALL_PACKAGES)\b",
                    raw_line,
                ):
                    add(
                        "mobile_security", "medium",
                        "Android manifest içinde yüksek riskli sistem izni",
                        path, line_number,
                        "AndroidManifest.xml içinde yüksek riskli veya suistimale açık bir sistem izni tanımlandığı görüldü.",
                        "Yalnızca uygulamanın temel işlevi için zorunlu olan en az ayrıcalıklı izinleri talep edin.",
                        "CWE-250",
                    )

        if suffix in {".plist", ".entitlements", ".xcprivacy"} or normalized_name == "info.plist":
            pending_plist_key: tuple[str, int] | None = None
            for line_number, raw_line in enumerate(text.splitlines(), 1):
                stripped = raw_line.strip()
                if not stripped:
                    continue
                key_match = re.search(
                    r"<\s*key\s*>\s*(NSAllowsArbitraryLoads|NSExceptionAllowsInsecureHTTPLoads|get-task-allow)\s*<\s*/\s*key\s*>",
                    raw_line,
                )
                if key_match:
                    matched_key = key_match.group(1)
                    if re.search(r"<\s*true\s*/\s*>", raw_line[key_match.end():]):
                        if matched_key == "get-task-allow":
                            add(
                                "mobile_security", "high",
                                "iOS Entitlements içinde get-task-allow (hata ayıklama) açık",
                                path, line_number,
                                "Entitlements dosyasında get-task-allow anahtarı true olarak bırakılmış.",
                                "Üretim/dağıtım profillerinde get-task-allow değerini false yapın veya kaldırın.",
                                "CWE-489",
                            )
                        else:
                            add(
                                "transport", "high",
                                "iOS App Transport Security (ATS) şifresiz bağlantıya izin veriyor",
                                path, line_number,
                                "Info.plist içinde NSAllowsArbitraryLoads veya NSExceptionAllowsInsecureHTTPLoads değeri true olarak ayarlanmış.",
                                "ATS kısıtlamalarını devre dışı bırakmayın; tüm sunucu bağlantılarında TLS 1.2+ zorunlu kılın.",
                                "CWE-319",
                            )
                        pending_plist_key = None
                    else:
                        pending_plist_key = (matched_key, line_number)
                    continue
                if pending_plist_key is not None:
                    matched_key, key_line = pending_plist_key
                    if re.search(r"<\s*true\s*/\s*>", raw_line):
                        if matched_key == "get-task-allow":
                            add(
                                "mobile_security", "high",
                                "iOS Entitlements içinde get-task-allow (hata ayıklama) açık",
                                path, key_line,
                                "Entitlements dosyasında get-task-allow anahtarı true olarak bırakılmış.",
                                "Üretim/dağıtım profillerinde get-task-allow değerini false yapın veya kaldırın.",
                                "CWE-489",
                            )
                        else:
                            add(
                                "transport", "high",
                                "iOS App Transport Security (ATS) şifresiz bağlantıya izin veriyor",
                                path, key_line,
                                "Info.plist içinde NSAllowsArbitraryLoads veya NSExceptionAllowsInsecureHTTPLoads değeri true olarak ayarlanmış.",
                                "ATS kısıtlamalarını devre dışı bırakmayın; tüm sunucu bağlantılarında TLS 1.2+ zorunlu kılın.",
                                "CWE-319",
                            )
                        pending_plist_key = None
                    elif re.search(r"<\s*(?:false\s*/|key\b)", raw_line):
                        pending_plist_key = None

        if suffix in {
            ".kt", ".kts", ".java", ".swift", ".m", ".mm", ".dart",
            ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".cs", ".gradle",
        } or normalized_name in {"build.gradle", "build.gradle.kts"}:
            has_sec_access_control = "SecAccessControl" in text
            has_biometric_prompt = "BiometricPrompt" in text
            has_crypto_object = "CryptoObject" in text
            # 19. tur hız: her satır kuralı önce tüm metinde aranır; metinde hiç eşleşmeyen kural hiçbir satırda da
            # eşleşemez (desenlerde ^/$ çapası yok), satır döngüsünde atlanır. Hiçbiri yoksa döngü hiç çalışmaz.
            mobile_rx = [rx if rx.search(text) else _NEVER_RX for rx in _MOBILE_LINE_RX]
            for line_number, raw_line in enumerate(text.splitlines() if any(rx is not _NEVER_RX for rx in mobile_rx) else (), 1):
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("//") or stripped.startswith("#"):
                    continue
                if mobile_rx[0].search(raw_line):
                    signals.add("mobile_surface")
                    add(
                        "mobile_security", "high",
                        "Mobil WebView içinde güvensiz JS köprüsü veya yerel dosya erişimi",
                        path, line_number,
                        "WebView yapılandırmasında güvensiz JavaScript köprüsü, yerel dosya erişimi veya eski UIWebView kullanımı görüldü.",
                        "addJavascriptInterface ve evrensel dosya erişimini kapatın; WKWebView ve katı origin allowlist kullanın.",
                        "CWE-749",
                    )
                if mobile_rx[1].search(raw_line):
                    signals.add("mobile_surface")
                    add(
                        "mobile_security", "high",
                        "Mobil cihazda hassas verinin şifresiz yerel depolamada saklanması",
                        path, line_number,
                        "Hassas kimlik veya oturum verisinin şifresiz yerel depolama (SharedPreferences/UserDefaults/AsyncStorage) veya güvensiz erişim moduyla saklandığı görüldü.",
                        "Hassas verileri Android Keystore / EncryptedSharedPreferences veya iOS Keychain (kSecAttrAccessibleWhenUnlockedThisDeviceOnly) içinde saklayın.",
                        "CWE-312",
                    )
                if (
                    (
                        not has_sec_access_control
                        and mobile_rx[2].search(raw_line)
                    )
                    or (
                        not has_crypto_object
                        and (
                            mobile_rx[3].search(raw_line)
                            or (has_biometric_prompt and mobile_rx[4].search(raw_line))
                        )
                    )
                ):
                    signals.add("mobile_surface")
                    add(
                        "mobile_security", "medium",
                        "Biyometrik doğrulamada kriptografik anahtar (CryptoObject / Keychain) bağlaması eksik",
                        path, line_number,
                        "Biyometrik doğrulama çağrısının CryptoObject veya SecAccessControl kriptografik anahtar bağlaması olmadan kullanıldığı görüldü.",
                        "Biyometrik doğrulamayı Keystore CryptoObject veya Keychain SecAccessControl korumalı bir kriptografik işlemle bağlayın.",
                        "CWE-287",
                    )
                if mobile_rx[5].search(raw_line):
                    signals.add("mobile_surface")
                    add(
                        "transport", "critical",
                        "Mobil istemcide TLS sertifika hatası koşulsuz yoksayılıyor",
                        path, line_number,
                        "badCertificateCallback => true veya onReceivedSslError içinde proceed() ile geçersiz TLS sertifikalarının kabul edildiği görüldü.",
                        "Sertifika doğrulama hatalarını yoksaymayın; geçersiz sertifikalarda bağlantıyı derhal sonlandırın.",
                        "CWE-295",
                    )
                if mobile_rx[6].search(raw_line):
                    signals.add("mobile_surface")
                    add(
                        "mobile_security", "high",
                        "Bluetooth (BLE/RFCOMM) üzerinde şifresiz bağlantı kanalı",
                        path, line_number,
                        "Bluetooth iletişiminde kimlik doğrulamasız ve şifresiz RFCOMM kanalı kullanımı görüldü.",
                        "listenUsingRfcommWithServiceRecord ve eşleştirme/şifreleme zorunlu BLE karakteristiklerini kullanın.",
                        "CWE-319",
                    )
                if mobile_rx[7].search(raw_line):
                    signals.add("mobile_surface")
                    add(
                        "mobile_security", "low",
                        "Kilit ekranında hassas bildirim görünürlüğü (VISIBILITY_PUBLIC)",
                        path, line_number,
                        "Bildirim yapılandırmasında VISIBILITY_PUBLIC kullanılarak içeriğin kilit ekranında açık gösterildiği görüldü.",
                        "Hassas bildirimlerde VISIBILITY_PRIVATE veya VISIBILITY_SECRET kullanın ve setPublicVersion ile maskeli özet sağlayın.",
                        "CWE-200",
                    )
                if mobile_rx[8].search(raw_line):
                    signals.add("mobile_surface")
                    add(
                        "mobile_security", "medium",
                        "Oyun/Uygulama içi bakiye veya yetki durumu şifresiz PlayerPrefs içinde tutuluyor",
                        path, line_number,
                        "Oyun içi para birimi, skor veya premium üyelik durumunun istemci tarafında korumasız PlayerPrefs ile saklandığı görüldü.",
                        "Bakiye, satın alma (IAP) makbuzu ve yetki durumunu sunucu tarafında doğrulayın ve saklayın.",
                        "CWE-602",
                    )
                if (
                    suffix in {".gradle", ".kts"} or normalized_name in {"build.gradle", "build.gradle.kts"}
                ) and mobile_rx[9].search(raw_line):
                    signals.add("mobile_surface")
                    add(
                        "mobile_security", "low",
                        "Android derlemesinde kod karartma (R8 / ProGuard minifyEnabled) devre dışı",
                        path, line_number,
                        "Gradle derleme yapılandırmasında minifyEnabled / isMinifyEnabled değerinin false olarak bırakıldığı görüldü.",
                        "Üretim (release) derlemelerinde R8/ProGuard kod karartma ve küçültmeyi (minifyEnabled true) etkinleştirin.",
                        "CWE-693",
                    )

        if path.name.casefold() == "requirements.txt":
            def _extract_req(row):
                esc = False
                q = None
                for i, c in enumerate(row):
                    if q is None:
                        if c == '#':
                            if i > 0 and row[i-1].isspace():
                                return row[:i]
                        if c == ';':
                            return row[:i]
                        if c == '"' or c == "'":
                            q = c
                            esc = False
                    else:
                        if esc:
                            esc = False
                            continue
                        if c == '\\':
                            esc = True
                            continue
                        if c == q:
                            q = None
                            esc = False
                return row
            unpinned = []
            for row in text.splitlines():
                if not row.strip() or row.lstrip().startswith("#") or row.lstrip().startswith("-"):
                    continue
                req = _extract_req(row)
                if not re.search(r"(==|===|@\s*(?:https|file):)", req):
                    unpinned.append(row)
            if unpinned:
                add(
                    "components", "medium", "Python bağımlılıkları sabitlenmemiş", path, 0,
                    f"{len(unpinned)} bağımlılık kesin sürüme sabitlenmemiş; paket adları/değerleri kaydedilmedi.",
                    "Kilit dosyası ve hash doğrulaması kullanın; OSV/Trivy ile güncel zafiyet taraması çalıştırın.",
                    "CWE-1104",
                )
        elif path.name.casefold() == "package.json":
            try:
                package = json.loads(text)
            except json.JSONDecodeError:
                raise ProjectRejected("Geçersiz package.json: JSON ayrıştırma hatası. Güvenlik analizi iptal edildi.")
            if not isinstance(package, dict):
                package = {}
            deps = package.get("dependencies")
            dev_deps = package.get("devDependencies")
            if deps is not None and not isinstance(deps, dict):
                raise ProjectRejected("Bağımlılık alanı bir nesne olmalıdır, liste veya string kabul edilmez.")
            if dev_deps is not None and not isinstance(dev_deps, dict):
                raise ProjectRejected("Geliştirici bağımlılık alanı bir nesne olmalıdır, liste veya string kabul edilmez.")
            if not isinstance(deps, dict):
                deps = {}
            if not isinstance(dev_deps, dict):
                dev_deps = {}
            dependencies = {**deps, **dev_deps}
            def is_floating(version_str):
                v = str(version_str).strip()
                if v in {"*", "latest", ""}:
                    return True
                if v.startswith("^") or v.startswith("~") or v.startswith(">=") or v.startswith(">") or v.startswith("<") or v.startswith("<=") or v.startswith("!="):
                    return True
                if "," in v or " " in v:
                    return True
                return False
            floating = [name for name, version in dependencies.items() if is_floating(version)]
            if floating:
                add(
                    "components", "medium", "JavaScript bağımlılıkları kayan sürüm kullanıyor", path, 0,
                    f"{len(floating)} bağımlılık kayan sürüm kullanıyor; adlar kaydedilmedi.",
                    "Kilit dosyasını depoya alın ve OSV/npm audit ile güncel zafiyet doğrulaması yapın.",
                    "CWE-1104",
                )

    if partial_info is not None:
        partial_scan = True  # süre bütçesi aşıldı: proje geneli yokluk denetimleri anlamsız
    project_progress.report("routes", force=True)
    route_inventory = None
    authz = None
    if authz_sources:
        try:
            authz = authz_routes.analyze_sources(authz_sources)
        except RecursionError:
            authz = None
        if authz is not None:
            route_inventory = authz_routes.inventory(authz["routes"])
            for item in authz["findings"]:
                add("authz", item["severity"], item["title"], root / item["file"], item["line"],
                    item["evidence"], item["recommendation"], item["reference"])
    # OpenAPI sözleşmesi ↔ rota envanteri (17. tur): kısmi taramada (yalnız değişenler/atlananlar/süre bütçesi) yapılmaz.
    api_contract = None
    api_contract_findings = 0
    if spec_sources and not partial_scan:
        try:
            api_contract = api_spec_routes.analyze(spec_sources, authz["routes"] if authz else [], authz_sources)
        except (RecursionError, ValueError, TypeError):
            api_contract = None
        if api_contract is not None:
            for item in api_contract.pop("findings"):
                add(item["category"], item["severity"], item["title"], root / item["file"], item["line"],
                    item["evidence"], item["recommendation"], item["reference"])
                api_contract_findings += 1
    del authz_sources, spec_sources

    if file_count == 0:
        if partial_info is not None:
            raise ProjectRejected("Süre bütçesi hiçbir dosya analiz edilmeden doldu; SNIPER_PROJECT_TIME_BUDGET_SECONDS değerini artırın.")
        if scope.only_paths is not None:
            raise ProjectRejected("Değişen dosyalar arasında analiz edilebilir kaynak yok.")
        if scope.skipped_only:
            raise ProjectRejected("Normal taramanın dışında kalan dosya yok: tüm dosyalar varsayılan kapsamda zaten inceleniyor.")
        if skipped_files:
            raise ProjectRejected("Analiz edilebilir dosya kalmadı: " + " ".join(_skipped_warnings(skipped_files, scope)))
        raise ProjectRejected("Desteklenen kaynak kod veya bağımlılık bildirimi bulunamadı.")

    if not partial_scan and "auth" in signals and "password_kdf" not in signals:
        add(
            "crypto", "medium", "Parola işleme için yavaş KDF doğrulanamadı", None, 0,
            "Kimlik doğrulama/parola sinyali var; Argon2id, scrypt, bcrypt veya PBKDF2 kullanımı görülmedi.",
            "Gerçek parola saklanıyorsa Argon2id tercih edin; üçüncü taraf kimlik sağlayıcı kullanılıyorsa bunu belgeleyin.",
            "OWASP ASVS V2.4",
        )
    if not partial_scan and "crypto" in signals and "aead" not in signals:
        add(
            "crypto", "low", "Kimlik doğrulamalı şifreleme doğrulanamadı", None, 0,
            "Kriptografi sinyali var; AES-GCM veya eşdeğer AEAD kullanımı görülmedi.",
            "Gizli veri şifreleniyorsa AES-256-GCM veya ChaCha20-Poly1305 ve güvenli anahtar yönetimi kullanın.",
            "CWE-327",
        )
    if not partial_scan and "outbound" in signals and "ssrf_guard" not in signals:
        add(
            "ssrf", "high", "Dış isteklerde SSRF koruması doğrulanamadı", None, 0,
            "Dış HTTP isteği sinyali var; özel/link-local IP engeli veya hedef allowlist görülmedi.",
            "URL şemasını ve DNS sonucunu doğrulayın; özel, loopback, link-local ve metadata adreslerini engelleyin; yönlendirmeyi tekrar denetleyin.",
            "CWE-918",
        )
    if not partial_scan and "qr" in signals and "qr_ttl" not in signals:
        add(
            "qr", "medium", "QR verisinde süre/tek kullanım kontrolü doğrulanamadı", None, 0,
            "QR üretim/okuma sinyali var; TTL, nonce veya tek kullanım kaydı görülmedi.",
            "Hassas işlem QR'larını kısa süreli nonce ile üretin ve sunucu tarafında tek kullanımı uygulayın.",
            "CWE-613",
        )
    if not partial_scan and "qr" in signals and "qr_integrity" not in signals:
        add(
            "qr", "high", "QR parametresinde bütünlük koruması doğrulanamadı", None, 0,
            "QR sinyali var; imza/HMAC veya kimlik doğrulamalı şifreleme görülmedi.",
            "QR yükünü sunucu anahtarıyla imzalayın; Base64'ü şifreleme olarak kabul etmeyin.",
            "CWE-345",
        )
    if not partial_scan and "auth" in signals and "logging" not in signals:
        add(
            "logging", "medium", "Kimlik doğrulama güvenlik olayı kaydı doğrulanamadı", None, 0,
            "Kimlik doğrulama sinyali var; audit/security event kaydı görülmedi.",
            "Başarısız giriş, kilitlenme, yetki reddi ve yönetici değişikliklerini maskeli ve değiştirilemez biçimde kaydedin.",
            "OWASP A09:2021",
        )

    # Bağımlılık lisans uyumu (yalnız yerel dosyalar; kısmi taramada yapılmaz). Hata analizi etkilemez.
    licenses = None
    project_progress.report("licenses", force=True)
    if not partial_scan:
        try:
            import license_compliance

            licenses = license_compliance.analyze(root, manifests)
            for item in license_compliance.findings(licenses):
                add(item["category"], item["severity"], item["title"], root / item["file"], item["line"],
                    item["evidence"], item["recommendation"], item["reference"])
        except Exception:  # noqa: BLE001
            licenses = None

    # 20. tur: tedarik zinciri (kötü amaçlı paket — yerel OSV MAL-, npm kurulum betikleri, bağımlılık karışıklığı).
    # Yalnız yerel dosyalar; kod çalıştırılmaz. Kısmi taramada yapılmaz; hata analizi etkilemez.
    supply = None
    if not partial_scan:
        try:
            import supply_chain

            supply = supply_chain.analyze(root, skip_dirs=scope.skip_dirs)
            for item in supply["findings"]:
                add(item["category"], item["severity"], item["title"], (root / item["file"]) if item["file"] else None,
                    item["line"], item["evidence"], item["recommendation"], item["reference"])
        except Exception:  # noqa: BLE001
            supply = None

    clang_analysis = None
    if c_family_files and not partial_info:
        clang_analysis = _add_clang_findings(root, c_family_files, findings, add)

    findings.sort(
        key=lambda item: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[item["severity"]],
            item["file"], item["line"], item["title"],
        )
    )
    category_findings: dict[str, list[dict[str, Any]]] = {}
    for item in findings:
        category_findings.setdefault(item["category"], []).append(item)
    penalty = 0
    for items in category_findings.values():
        highest = max(SEVERITY_WEIGHT[item["severity"]] for item in items)
        penalty += highest + min(6, max(0, len(items) - 1))
    score = max(0, 100 - min(100, penalty))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "E"
    counts = {severity: sum(1 for item in findings if item["severity"] == severity) for severity in SEVERITY_WEIGHT}
    project_progress.report("threat", force=True)
    try:
        threat = threat_collector.build(findings, partial=scope.skipped_only)
    except Exception:
        threat = None
    if threat and route_inventory:
        # Tehdit modeli rotalarına yetki envanterinin koruma bilgisi (aynı dosya:satır).
        # Eşleme sırası: aynı dosya:satır → işleyici adı + normalleştirilmiş yol → (tekse) yalnız işleyici adı.
        # Django'da tehdit modeli urls.py satırını, yetki envanteri görünüm fonksiyonunun satırını tutar.
        def _norm_path(value: Any) -> str:
            return str(value or "").strip("^$/ ").replace("$", "").casefold()

        def _handler_name(value: Any) -> str:
            return str(value or "").rsplit(".", 1)[-1].casefold()

        authz_routes_list = route_inventory.get("routes") or []
        by_location = {(r["file"], r["line"]): r for r in authz_routes_list}
        by_handler_path = {(_handler_name(r.get("handler")), _norm_path(r.get("path"))): r for r in authz_routes_list}
        handler_counts: dict[str, int] = {}
        for r in authz_routes_list:
            handler_counts[_handler_name(r.get("handler"))] = handler_counts.get(_handler_name(r.get("handler")), 0) + 1
        by_handler = {_handler_name(r.get("handler")): r for r in authz_routes_list
                      if handler_counts[_handler_name(r.get("handler"))] == 1}
        for route in threat.get("routes") or []:
            name = _handler_name(route.get("handler"))
            match = (by_location.get((route.get("file"), route.get("line")))
                     or by_handler_path.get((name, _norm_path(route.get("path"))))
                     or (by_handler.get(name) if name else None))
            if match is not None:
                route["protection"] = match.get("protection") or None
                route["protected"] = bool(match.get("protection"))
                route["idor_candidate"] = bool(match.get("idor_candidate"))
    checks = [
        {"id": "crypto", "label": "Kriptografi ve parola saklama", "status": "review" if any(f["category"] == "crypto" for f in findings) else ("pass" if "crypto" in signals or "auth" in signals else "na")},
        {"id": "query", "label": "Hazır sorgu ve komut/veri ayrımı", "status": "review" if any(f["category"] in {"data_query", "command_data"} for f in findings) else "pass"},
        {"id": "ssrf", "label": "SSRF ve dış istek sınırları", "status": "review" if any(f["category"] == "ssrf" for f in findings) else ("pass" if "outbound" in signals else "na")},
        {"id": "qr", "label": "Dinamik QR, süre ve bütünlük", "status": "review" if any(f["category"] == "qr" for f in findings) else ("pass" if "qr" in signals else "na")},
        {"id": "components", "label": "Bağımlılık ve sürüm bildirimi", "status": "review" if any(f["category"] == "components" for f in findings) else ("pass" if manifests else "na")},
        {"id": "logging", "label": "Güvenlik günlüğü ve hassas veri", "status": "review" if any(f["category"] == "logging" for f in findings) else ("pass" if "logging" in signals else "na")},
        {"id": "ports", "label": "Port ve ağ yüzeyi", "status": "review" if any(f["category"] == "ports" for f in findings) else "pass"},
        {"id": "secrets", "label": "Sır ve yapılandırma yönetimi", "status": "review" if any(f["category"] == "secrets" for f in findings) else "pass"},
        {"id": "web_hardening", "label": "İstemci yüzeyi, CORS ve DOM güvenliği", "status": "review" if any(f["category"] == "web_hardening" for f in findings) else ("pass" if "web_surface" in signals else "na")},
        {"id": "container_iac", "label": "Konteyner, Kubernetes ve CI/CD güvenliği", "status": "review" if any(f["category"] in {"container", "supplychain"} for f in findings) else ("pass" if "container_iac" in signals else "na")},
        {"id": "authz", "label": "Rota yetkilendirme ve nesne düzeyi erişim", "status": "review" if any(f["category"] == "authz" for f in findings) else ("pass" if route_inventory and route_inventory["summary"]["protected"] else "na")},
        {"id": "mobile_masvs", "label": "Mobil uygulama güvenliği (iOS, Android, Flutter, RN ve MASVS)", "status": "review" if any(f["category"] == "mobile_security" for f in findings) else ("pass" if "mobile_surface" in signals else "na")},
        {"id": "api_contract", "label": "API sözleşmesi ve rota uyumu", "status": "review" if api_contract_findings else ("pass" if api_contract and any(spec["coverage"] >= 0.5 for spec in api_contract["specs"]) else "na")},
        {"id": "licenses", "label": "Bağımlılık lisans uyumu", "status": "review" if any(f["category"] == "license" for f in findings) else ("pass" if licenses else "na")},
        {"id": "supply_chain", "label": "Tedarik zinciri: kötü amaçlı paket, kurulum betiği, bağımlılık karışıklığı", "status": "review" if any(f["category"] == "supply_chain" for f in findings) else ("pass" if supply and manifests else "na")},
    ]
    project_progress.report("subprojects", force=True)
    try:  # alt proje (monorepo) özeti; hata analizi etkilemez
        subprojects = monorepo.summarize(root, manifests, file_index, findings)
    except Exception:  # noqa: BLE001
        subprojects = None
    del file_index
    measurement = None
    try:  # ölçüm geçmişi yoksa ya da okunamazsa analiz etkilenmez
        import eval_metrics

        eval_metrics.annotate_confidence(findings)
        eval_metrics.annotate_corroboration(findings)
        latest = eval_metrics.latest_class_precision()
        if latest:
            measurement = {"label": latest.get("label"), "created_at": latest.get("created_at")}
    except Exception:  # noqa: BLE001
        measurement = None
    taint_analysis_warnings = {
        f"Veri akışı analizi kısmi kaldı ({limitation})."
        for limitation in taint_flow.project_limitations()
    }
    return {
        "created_at": utc_now(),
        "project_path": str(root),
        "project_name": root.name,
        "score": score,
        "grade": grade,
        "file_count": file_count,
        "bytes_scanned": bytes_scanned,
        "skipped_files": dict(sorted(skipped_files.items())),
        "warnings": _skipped_warnings(skipped_files, scope) + sorted(iac_analysis_warnings | taint_analysis_warnings),
        "scope": scope.public(),
        "partial": partial_info,
        "subprojects": subprojects,
        "measurement": measurement,
        "route_inventory": route_inventory,
        "api_contract": api_contract,
        "licenses": licenses,
        "supply_chain": ({"summary": supply["summary"], "warnings": supply["warnings"]} if supply else None),
        "clang_analysis": clang_analysis,
        "languages": dict(sorted(language_counts.items(), key=lambda item: (-item[1], item[0]))),
        "manifests": sorted(manifests),
        "finding_counts": counts,
        "findings": findings,
        "threat_model": threat,
        "checks": checks,
        "limitations": [
            "Bu sonuç statik ve düşük etkili bir ön incelemedir; çalışan uygulama davranışını kanıtlamaz.",
            "Bağımlılıkların güncel CVE durumu çevrimdışı kaynak analiziyle doğrulanmaz; OSV/Trivy gibi güncel veri kaynağı gerekir.",
            "Sır değerleri ve kaynak satırları rapora kopyalanmaz; yalnız dosya, satır ve kural adı saklanır.",
            "Test, fixture, bağımlılık ve derleme klasörleri üretim sinyallerini bozmamak için atlanır.",
        ],
    }
