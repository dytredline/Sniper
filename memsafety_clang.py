"""Clang Static Analyzer (``clang --analyze``) ile isteğe bağlı çevrimdışı bellek güvenliği ek analizi.

Her C/C++ dosyası tek başına çözümlenir. 27. turdan beri dosya başına derleme bilgisi (``c_build``: hazır
``compile_commands.json`` → ``CMakeLists.txt`` metni → ``Makefile``/``*.mk`` metni) varsa yalnız güvenli bayrakları
(-I/-isystem/-iquote/-D/-U/-std/-include, izinli -f/-m) eklenir; derleme sistemi ya da proje betiği ASLA çalıştırılmaz.
Bayraklarla derleme başarısız olursa (ör. üretilmemiş config.h) dosya bir kez bayraksız (bugünkü davranış) denenir.
Proje içindeki başlık dizinleri her durumda ``-I`` ile (derleme bilgisinden sonra) verilir. Eksik başlık ya da derleme
hatası olan dosya sessizce atlanır. Bilgi kaynağı (compile_commands / cmake-metin / make-metin / yok) bulguya ve özete
yazılır.

Güvenlik ve kaynak sınırları:
  * Ağ kullanılmaz; clang yalnız kaynak dosyayı okur (çalıştırma yok). Süreç ayrı oturumda, boş ortamla,
    stdin=/dev/null, geçici çalışma dizininde, CPU/bellek sınırlı (RLIMIT_CPU, RLIMIT_AS) çalışır.
  * Tanılama satırlarında kaynak kod yankılanmaz (``-fno-caret-diagnostics``); yalnız proje kökü altındaki
    dosyalara ait ``dosya:satır: warning: ileti [denetleyici]`` satırları alınır, kaynak içeriği saklanmaz.
  * Dosya başı zaman aşımı, toplam süre bütçesi ve dosya sayısı sınırı vardır (büyük projede yavaşlamaz).

Ortam değişkenleri: ``SNIPER_CLANG_ANALYZER`` (0/off: kapalı; varsayılan: clang varsa açık),
``SNIPER_CLANG_BINARY`` (varsayılan /usr/bin/clang), ``SNIPER_CLANG_BUDGET`` (toplam saniye, varsayılan 60),
``SNIPER_CLANG_MAX_FILES`` (varsayılan 300).
"""
from __future__ import annotations

import concurrent.futures
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from typing import Any, Iterable

DEFAULT_BINARY = "/usr/bin/clang"
PER_FILE_TIMEOUT = 20
DEFAULT_BUDGET = 60
DEFAULT_MAX_FILES = 300
MAX_INCLUDE_DIRS = 40
MAX_OUTPUT = 512_000
C_SOURCE_SUFFIXES = frozenset({".c"})
CPP_SOURCE_SUFFIXES = frozenset({".cc", ".cpp", ".cxx", ".c++", ".ino"})
HEADER_SUFFIXES = frozenset({".h", ".hh", ".hpp", ".hxx"})
CHECKERS = ("alpha.unix.cstring.OutOfBounds", "alpha.unix.cstring.BufferOverlap", "unix.MismatchedDeallocator")

_DIAG_RE = re.compile(r"^(?P<file>.+?):(?P<line>\d+):(?P<col>\d+): warning: (?P<msg>.+?) \[(?P<checker>[\w.]+)\]\s*$")

# (ileti deseni, denetleyici öneki) → (tür, kesin mi)
_RULES: tuple[tuple[re.Pattern[str], str, str, bool], ...] = (
    (re.compile(r"Use of memory after it is (freed|released)|Use of memory allocated with size zero"), "unix.Malloc", "uaf", True),
    (re.compile(r"Use of memory after it is (freed|released)"), "cplusplus.NewDelete", "uaf", True),
    (re.compile(r"Attempt to (free|release) released memory"), "unix.Malloc", "double_free", True),
    (re.compile(r"Attempt to (free|release) released memory"), "cplusplus.NewDelete", "double_free", True),
    (re.compile(r"Argument to (free|delete)\(\) is (the address of|a constant address|.*not memory allocated)"), "unix.Malloc", "free_nonheap", True),
    (re.compile(r"Argument to (free|delete)\(\) is (the address of|a constant address|.*not memory allocated)"), "cplusplus.NewDelete", "free_nonheap", True),
    (re.compile(r"Argument to (free|delete).* is offset by"), "unix.Malloc", "free_offset", True),
    (re.compile(r"Argument to (free|delete).* is offset by"), "cplusplus.NewDelete", "free_offset", True),
    (re.compile(r"should be deallocated by"), "unix.MismatchedDeallocator", "mismatch_free", True),
    (re.compile(r"overflows the destination buffer|accesses out-of-bound array element.*destination|Out of bound memory access.*destination"),
     "alpha.unix.cstring.OutOfBounds", "overflow", True),
    (re.compile(r"accesses out-of-bound array element|Out of bound"), "alpha.unix.cstring.OutOfBounds", "overread", False),
)


def binary() -> str | None:
    """Kullanılacak clang yolu; kapalıysa ya da yoksa None."""
    if os.environ.get("SNIPER_CLANG_ANALYZER", "").strip().lower() in {"0", "off", "false", "no", "kapali", "kapalı"}:
        return None
    path = os.environ.get("SNIPER_CLANG_BINARY", DEFAULT_BINARY)
    try:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    except OSError:
        return None
    return None


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(os.environ.get(name, default))))
    except (TypeError, ValueError):
        return default


def include_dirs(root: Path, files: Iterable[Path]) -> list[Path]:
    """Proje içinde başlık bulunan dizinler (kök, include/, src/ öncelikli; sınırlı)."""
    dirs: list[Path] = []
    seen: set[Path] = set()

    def add(d: Path) -> None:
        if d not in seen and d.is_dir() and len(dirs) < MAX_INCLUDE_DIRS:
            seen.add(d)
            dirs.append(d)

    for name in ("", "include", "src", "lib", "inc"):
        add(root / name if name else root)
    for f in files:
        if f.suffix.lower() in HEADER_SUFFIXES:
            add(f.parent)
            add(f.parent.parent)
    # Juliet benzeri ortak destek dizinleri (kardeş *support* dizinleri)
    try:
        for child in sorted(root.iterdir()):
            if child.is_dir() and "support" in child.name.lower():
                add(child)
    except OSError:
        pass
    return dirs


def _limit_child(pid: int) -> None:
    """Çocuk sürece CPU/bellek/çekirdek dökümü sınırı (preexec_fn iş parçacıklı ortamda güvensiz olduğundan prlimit)."""
    try:
        import resource

        resource.prlimit(pid, resource.RLIMIT_CPU, (PER_FILE_TIMEOUT + 5, PER_FILE_TIMEOUT + 5))
        resource.prlimit(pid, resource.RLIMIT_AS, (2 << 30, 2 << 30))
        resource.prlimit(pid, resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError, AttributeError):
        pass


def _command(clang: str, path: Path, incs: list[Path], flags: list[str] | None = None,
             stub_dir: str | None = None) -> list[str]:
    """clang komutu. ``flags`` c_build'in süzdüğü güvenli bayraklardır (dil -std'si varsayılanı geçersiz kılar);
    tanılama/çıktı bayrakları (-fno-caret-diagnostics, -o /dev/null) sabittir ve süzgeç bunları değiştiremez.

    Sezgisel başlık dizinleri her durumda -idirafter ile (sistem başlıklarından SONRA) aranır: proje içindeki
    uyumluluk kopyaları (ör. jemalloc msvc_compat/C99/stdint.h) sistem başlıklarını gölgelemez. Yer tutucu dizini
    (yalnız eksik üretilen başlıklar) en sona eklenir."""
    suffix = path.suffix.lower()
    lang = ["-x", "c++", "-std=gnu++17"] if suffix in CPP_SOURCE_SUFFIXES else ["-x", "c", "-std=gnu11"]
    cmd = [clang, "--analyze", "-o", "/dev/null", "-fno-caret-diagnostics", "-fno-color-diagnostics", "-w",
           "-ferror-limit=1", "-Xclang", "-analyzer-checker=" + ",".join(CHECKERS)]
    cmd += lang + list(flags or [])
    for d in incs:
        cmd += ["-idirafter", str(d)]
    if stub_dir:
        cmd += ["-idirafter", stub_dir]
    return cmd + [str(path)]


def classify(message: str, checker: str) -> tuple[str, bool] | None:
    for pattern, prefix, kind, certain in _RULES:
        if checker.startswith(prefix) and pattern.search(message):
            return kind, certain
    return None


def parse_output(text: str, root: Path) -> list[dict[str, Any]]:
    out = []
    root_s = str(root.resolve())
    for line in text.splitlines():
        m = _DIAG_RE.match(line.strip())
        if not m:
            continue
        cls = classify(m.group("msg"), m.group("checker"))
        if cls is None:
            continue
        try:
            fpath = Path(m.group("file")).resolve()
        except (OSError, RuntimeError):
            continue
        if not str(fpath).startswith(root_s + os.sep):
            continue  # proje dışı (sistem başlığı vb.)
        out.append({"file": fpath.relative_to(root_s).as_posix(), "line": int(m.group("line")), "kind": cls[0],
                    "certain": cls[1], "checker": m.group("checker"), "message": m.group("msg")[:200]})
    return out


def _run_one(clang: str, path: Path, root: Path, incs: list[Path], deadline: float,
             flags: list[str] | None = None) -> list[dict[str, Any]]:
    return _invoke(clang, path, root, incs, deadline, flags)[0]


_MISSING_RE = re.compile(r"^(?P<file>.+?):(?P<line>\d+):\d+: fatal error: '(?P<hdr>[^']{1,200})' file not found", re.M)
MAX_STUBS_PER_FILE = 3


def _invoke(clang: str, path: Path, root: Path, incs: list[Path], deadline: float,
            flags: list[str] | None = None, stub_dir: str | None = None,
            missing: list[tuple[str, int, str]] | None = None) -> tuple[list[dict[str, Any]], str]:
    """Tek dosya çözümlemesi. Dönen: (bulgular, durum) — durum: ok | failed (derleme hatası) | timeout | error.
    ``missing`` verilirse bulunamayan başlık (dosya, satır, ad) oraya eklenir."""
    remaining = deadline - time.monotonic()
    if remaining <= 1:
        return [], "timeout"
    timeout = min(PER_FILE_TIMEOUT, remaining)
    with tempfile.TemporaryDirectory(prefix="sniper-clang-") as work:
        try:
            with subprocess.Popen(  # noqa: S603 - sabit ikili, kabuk yok, argümanlar liste
                    _command(clang, path, incs, flags, stub_dir), cwd=work, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                    start_new_session=True) as proc:
                _limit_child(proc.pid)
                try:
                    out, err = proc.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    import process_group_runner

                    process_group_runner.kill_process_group(proc)
                    try:
                        proc.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                    return [], "timeout"
                rc = proc.returncode
        except (OSError, ValueError):
            return [], "error"
    text = ((err or b"")[:MAX_OUTPUT] + b"\n" + (out or b"")[:MAX_OUTPUT]).decode("utf-8", "replace")
    if "fatal error:" in text and "warning:" not in text:
        if missing is not None:
            m = _MISSING_RE.search(text)
            if m:
                missing.append((m.group("file"), int(m.group("line")), m.group("hdr")))
        return [], "failed"
    found = parse_output(text, root)
    if rc != 0 and not found and "error:" in text:
        return [], "failed"  # ayrıştırma hatası: çözümleyici çalışmadı
    return found, "ok"


class _StubDir:
    """Eksik ÜRETİLEN başlıklar için boş yer tutucular (geçici dizinde; proje dosyalarına asla yazılmaz)."""

    CONTENT = "/* Sniper yer tutucu: derleme sirasinda uretilen baslik (icerik bilinmiyor) */\n"

    def __init__(self, root: Path, info: Any) -> None:
        import threading

        self.root = root
        self.info = info
        self.path: str | None = None
        self.names: set[str] = set()
        self.lock = threading.Lock()

    def _quoted_include(self, including: str, line: int, name: str) -> bool:
        """Hata satırındaki yönerge ``#include "ad"`` mı (sistem/dış bağımlılık <...> başlıkları yer tutucu almaz)."""
        try:
            fpath = Path(including).resolve()
        except (OSError, RuntimeError):
            return False
        if not str(fpath).startswith(str(self.root.resolve()) + os.sep):
            return False
        try:
            import c_build

            text = c_build._read_text(fpath, 8 << 20)
        except Exception:  # noqa: BLE001
            return False
        lines = (text or "").splitlines()
        if not 0 < line <= len(lines):
            return False
        return bool(re.match(r'\s*#\s*include\s*"' + re.escape(name) + '"', lines[line - 1]))

    def provide(self, including: str, line: int, name: str) -> bool:
        if self.info is None or not self._quoted_include(including, line, name):
            return False
        try:
            if not self.info.generated_header(name):
                return False
        except Exception:  # noqa: BLE001
            return False
        with self.lock:
            if name in self.names:
                return True
            if self.path is None:
                self.path = tempfile.mkdtemp(prefix="sniper-clang-stub-")
            target = Path(self.path) / name
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(self.CONTENT, encoding="ascii")
            except OSError:
                return False
            self.names.add(name)
            return True

    def cleanup(self) -> None:
        if self.path:
            import shutil

            shutil.rmtree(self.path, ignore_errors=True)


def _run_with_build(clang: str, path: Path, root: Path, incs: list[Path], deadline: float,
                    build: Any, stubs: _StubDir | None = None) -> tuple[list[dict[str, Any]], str, str]:
    """Derleme bayraklarıyla dene; derleme hatasında bir kez bayraksız (bugünkü davranış) dene; yine eksik ÜRETİLEN
    başlık yüzünden derlenemiyorsa boş yer tutucu başlıkla dene (bulgular ``stub_headers`` ile işaretlenir).
    Dönen: (bulgular, kullanılan bilgi kaynağı, sonuç: flags | fallback | plain | stub | failed | timeout)."""
    missing: list[tuple[str, int, str]] = []

    def done(found, source, result):
        for f in found:
            f["build_info"] = source
        return found, source, result

    flags = build.args if build is not None and build.args else None
    source = build.source if flags else "yok"
    found, status = _invoke(clang, path, root, incs, deadline, flags, missing=missing)
    if status == "ok":
        return done(found, source, "flags" if flags else "plain")
    if status != "failed":
        return [], source, "timeout" if status == "timeout" else "failed"
    if flags:  # yer tutucu denemesi bayraklı denemenin eksik başlığıyla sürer
        found, status = _invoke(clang, path, root, incs, deadline)
        if status == "ok":
            return done(found, "yok", "fallback")
        if status != "failed":
            return [], "yok", "timeout" if status == "timeout" else "failed"
    if stubs is None or not missing:
        return [], source, "failed"
    used: list[str] = []
    for _ in range(MAX_STUBS_PER_FILE):
        including, line, name = missing[-1]
        if name in used or not stubs.provide(including, line, name):
            break
        used.append(name)
        missing.clear()
        found, status = _invoke(clang, path, root, incs, deadline, flags, stubs.path, missing=missing)
        if status == "ok":
            for f in found:
                f["stub_headers"] = list(used)
            return done(found, source, "stub")
        if status != "failed" or not missing:
            break
    return [], source, "timeout" if status == "timeout" else "failed"


_INPUT_RE = re.compile(rb"\b(recv|recvfrom|recvmsg|read|readv|pread|fread|fgets|getline|getdelim|gets|scanf|fscanf|"
                       rb"sscanf|getenv|accept|SSL_read|BIO_read|fgetc|getc|getchar)\s*\(")
MAX_PRIORITY_SCAN_BYTES = 256_000
MAX_PRIORITY_SCAN_FILES = 5000


def _reads_input(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return bool(_INPUT_RE.search(fh.read(MAX_PRIORITY_SCAN_BYTES)))
    except OSError:
        return False


_SUPPRESS_RE = re.compile(r'diagnostic\s+ignored\s+"-Wuse-after-free|NOLINT|__clang_analyzer__')
SUPPRESS_LOOKBACK = 8


def author_suppressed(root: Path, rel: str, line: int, kind: str) -> bool:
    """Yazar bu satırdaki serbest bırakma sonrası kullanımı bilerek işaretlemiş mi? (ör. GCC
    ``#pragma GCC diagnostic ignored "-Wuse-after-free"`` — işaretçi yalnız değer/anahtar olarak kullanılıyor —,
    ``NOLINT`` ya da ``__clang_analyzer__`` koruması). Yalnız uaf/double_free için; satırın kendisi ve üstündeki
    birkaç satır okunur (kaynak saklanmaz)."""
    if kind not in ("uaf", "double_free"):
        return False
    try:
        import c_build

        text = c_build._read_text((root / rel), 8 << 20)
    except Exception:  # noqa: BLE001
        return False
    lines = (text or "").splitlines()
    if not 0 < line <= len(lines):
        return False
    return bool(_SUPPRESS_RE.search("\n".join(lines[max(0, line - 1 - SUPPRESS_LOOKBACK):line])))


def analyze_files(root: Path, files: list[Path], *, budget: float | None = None,
                  max_files: int | None = None, workers: int | None = None,
                  build_info: Any = None, priority: Iterable[Path] = (), stubs: bool = True) -> dict[str, Any]:
    """Proje dosyalarını clang ile çözümle. Dönen: {"status", "files", "seconds", "findings": [...], "build": {...}}.

    ``build_info``: c_build.BuildInfo (verilmezse proje kökünden metin olarak okunur; False: kullanılmaz).
    ``priority``: önce çözümlenecek dosyalar (ör. yerel bellek motorunun aday bulduğu dosyalar). Sıra: öncelikli
    dosyalar → ağ/girdi okuyan dosyalar → diğerleri; her grupta küçükler önce (bütçe dolarsa en değerli dosyalar).
    ``stubs``: eksik üretilen başlık için yer tutucu denemesi (derleme bilgisi okunabildiyse)."""
    clang = binary()
    if clang is None:
        return {"status": "unavailable", "files": 0, "seconds": 0.0, "findings": [], "build": None}
    started = time.monotonic()
    budget = float(budget if budget is not None else _env_int("SNIPER_CLANG_BUDGET", DEFAULT_BUDGET, 5, 3600))
    max_files = max_files if max_files is not None else _env_int("SNIPER_CLANG_MAX_FILES", DEFAULT_MAX_FILES, 1, 100000)
    sources = [f for f in files if f.suffix.lower() in C_SOURCE_SUFFIXES | CPP_SOURCE_SUFFIXES]
    prio: set[str] = set()
    for q in priority or ():
        try:
            prio.add(str(Path(q).resolve()))
        except (OSError, RuntimeError):
            continue

    scan_inputs = len(sources) <= MAX_PRIORITY_SCAN_FILES

    def _rank(p: Path) -> tuple[int, int]:
        size = p.stat().st_size if p.exists() else 0
        try:
            if str(p.resolve()) in prio:
                return 0, size
        except (OSError, RuntimeError):
            pass
        return (1 if scan_inputs and _reads_input(p) else 2), size

    sources.sort(key=_rank)  # öncelikli → girdi okuyan → diğer; her grupta küçükler önce
    truncated = len(sources) > max_files
    sources = sources[:max_files]
    if not sources:
        return {"status": "no_sources", "files": 0, "seconds": 0.0, "findings": [], "build": None}
    incs = include_dirs(root, files)
    deadline = started + budget
    info = None
    if build_info is not False:
        info = build_info
        if info is None:
            try:
                import c_build

                info = c_build.load(root, max_seconds=min(10.0, max(1.0, budget / 6)))
            except Exception:  # noqa: BLE001 - derleme bilgisi okunamazsa bugünkü davranış
                info = None
    stub_dir = _StubDir(root, info) if stubs and info is not None else None
    per_file_build: list[Any] = []
    for p in sources:
        try:
            per_file_build.append(info.flags_for(p) if info is not None else None)
        except Exception:  # noqa: BLE001
            per_file_build.append(None)
    workers = workers or max(1, min(4, (os.cpu_count() or 2) // 2))
    findings: list[dict[str, Any]] = []
    done = 0
    by_source: dict[str, int] = {}
    outcome: dict[str, int] = {}
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_run_with_build, clang, p, root, incs, deadline, b, stub_dir)
                    for p, b in zip(sources, per_file_build)]
            for fut, b in zip(futs, per_file_build):
                try:
                    found, used, result = fut.result()
                except Exception:  # noqa: BLE001 - tek dosya hatası analizi durdurmaz
                    continue
                findings += found
                done += 1
                src = b.source if b is not None else "yok"
                by_source[src] = by_source.get(src, 0) + 1
                outcome[result] = outcome.get(result, 0) + 1
    except RuntimeError:
        return {"status": "error", "files": done, "seconds": round(time.monotonic() - started, 1), "findings": findings,
                "build": None}
    finally:
        if stub_dir is not None:
            stub_dir.cleanup()
    status = "budget" if time.monotonic() > deadline else ("truncated" if truncated else "ok")
    build_summary = {
        "files_by_source": dict(sorted(by_source.items())),  # dosyanın derleme bilgisi kaynağı
        "analyzed_with_flags": outcome.get("flags", 0),  # gerçek bayraklarla başarıyla çözümlenen dosya
        "fallback_without_flags": outcome.get("fallback", 0),  # bayraklarla derlenemedi, bayraksız çözümlendi
        "analyzed_plain": outcome.get("plain", 0),
        "analyzed_with_stub_headers": outcome.get("stub", 0),  # eksik üretilen başlık yer tutucuyla çözümlendi
        "stub_headers": sorted(stub_dir.names)[:50] if stub_dir is not None else [],
        "priority_files": sum(1 for p in sources if str(p.resolve()) in prio),
        "failed": outcome.get("failed", 0),  # derleme hatası (eksik/üretilen başlık vb.): çözümlenemedi
        "timeout": outcome.get("timeout", 0),  # dosya süresi ya da toplam bütçe doldu
        "inputs": info.summary() if info is not None else None,
    }
    # aynı satırda aynı tür bir kez
    seen: set[tuple[str, int, str]] = set()
    unique = []
    for f in sorted(findings, key=lambda x: (x["file"], x["line"], x["kind"])):
        key = (f["file"], f["line"], f["kind"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return {"status": status, "files": done, "seconds": round(time.monotonic() - started, 1), "findings": unique,
            "build": build_summary}
