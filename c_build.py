"""C/C++ projeleri için "derleme bilgisi" (include yolları, makro tanımları, dil standardı) — yalnız METİN okuyarak.

27. tur: ``clang --analyze`` dosya başına doğru bayraklarla çalışsın diye projenin derleme bilgisi çıkarılır.
Kaynaklar, dosya başına öncelik sırasıyla:

  1. ``compile_commands.json`` (proje kökü altında herhangi bir dizinde; sembolik bağlar izlenmez),
  2. ``CMakeLists.txt`` metin ayrıştırması (``cmake-metin``),
  3. ``Makefile`` / ``GNUmakefile`` / ``*.mk`` metin ayrıştırması (``make-metin``),
  4. hiçbiri yoksa ``yok`` (çağıran bugünkü başlık dizini sezgisini kullanır).

Kesin sınır: taranan projenin hiçbir kodu, betiği ya da derleme sistemi ÇALIŞTIRILMAZ. Bu modül süreç başlatmaz
(``subprocess``/``os.system`` kullanılmaz); ``$(shell …)``, ``!=``, ``execute_process`` gibi ifadeler yok sayılır.

Güvenlik: yalnız izinli bayraklar geçer (``-I``, ``-isystem``, ``-iquote``, ``-D``, ``-U``, ``-std``, ``-include``,
izinli ``-f*`` dil bayrakları, ``-m*`` hedef bayrakları). Çıktı/eklenti/yükleme/yanıt dosyası bayrakları (``-o``,
``-Xclang …``, ``-fplugin``, ``-B``, ``--sysroot``, ``@dosya`` …) atılır. Proje kökü dışını gösteren include yolları
(sistem dizinleri hariç) ve ``-include`` dosyaları reddedilir; yollar ``resolve`` ile (sembolik bağ sonrası) denetlenir.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import time
from typing import Any, Callable, Iterable

from project_tree import ProjectFile, ProjectTree, ProjectTreeError

SOURCE_COMPILE_COMMANDS = "compile_commands"
SOURCE_CMAKE = "cmake-metin"
SOURCE_MAKE = "make-metin"
SOURCE_NONE = "yok"
SOURCES = (SOURCE_COMPILE_COMMANDS, SOURCE_CMAKE, SOURCE_MAKE, SOURCE_NONE)

MAX_COMPILE_DB_BYTES = 64 << 20
MAX_BUILD_FILE_BYTES = 1 << 20
MAX_COMPILE_DBS = 8
MAX_COMPILE_ENTRIES = 200_000
MAX_CMAKE_FILES = 400
MAX_MAKE_FILES = 400
MAX_WALK_DIRS = 20_000
MAX_INCLUDES = 48
MAX_DEFINES = 200
MAX_VALUE_LEN = 300
DEFAULT_LOAD_SECONDS = 5.0
SKIP_WALK_DIRS = frozenset({"node_modules", "__pycache__", ".git", ".hg", ".svn", ".tox", ".venv", "venv"})
MAKE_NAMES = ("GNUmakefile", "makefile", "Makefile")
# Üretilen başlık kanıtı için okunan (yalnız metin) yapılandırma dosyaları
GENERATOR_NAMES = frozenset({"Makefile.in", "Makefile.am", "configure.ac", "configure.in", "meson.build"})
HEADER_SUFFIXES = (".h", ".hh", ".hpp", ".hxx")
MAX_GENERATOR_FILES = 300
MAX_HEADER_NAMES = 200_000
_STUB_NAME_RE = re.compile(r"^[A-Za-z0-9_+-][A-Za-z0-9_.+-]{0,80}(/[A-Za-z0-9_+-][A-Za-z0-9_.+-]{0,80}){0,4}\.(h|hh|hpp|hxx)$")
_HEADER_TOKEN_RE = re.compile(r"([A-Za-z0-9_+-]+\.(?:h|hh|hpp|hxx))(?![A-Za-z0-9_])")
# Okunan Make değişkenleri (görev: CFLAGS, CPPFLAGS, CXXFLAGS, INCLUDES, DEFS; yaygın eşdeğerleri de)
MAKE_C_VARS = ("CPPFLAGS", "CFLAGS", "INCLUDES", "INCLUDE", "INCS", "DEFS", "DEFINES", "AM_CPPFLAGS", "AM_CFLAGS",
               "FINAL_CFLAGS", "ALL_CFLAGS")
MAKE_CXX_VARS = ("CPPFLAGS", "CXXFLAGS", "INCLUDES", "INCLUDE", "INCS", "DEFS", "DEFINES", "AM_CPPFLAGS",
                 "AM_CXXFLAGS", "FINAL_CXXFLAGS", "ALL_CXXFLAGS")
CXX_SUFFIXES = frozenset({".cc", ".cpp", ".cxx", ".c++", ".ino", ".hpp", ".hh", ".hxx", ".mm"})
# Proje kökü dışında yalnız bu sistem dizinlerine izin verilir (resolve sonrası).
SYSTEM_INCLUDE_PREFIXES = ("/usr/include", "/usr/local/include", "/usr/lib/gcc/", "/usr/lib/clang/", "/usr/lib/llvm-")

_MACRO_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\([A-Za-z0-9_, .]*\))?(=.*)?$", re.S)
_STD_RE = re.compile(r"^(c|gnu|iso9899:)[0-9a-z:x]+$|^(c\+\+|gnu\+\+)[0-9a-z]+$")
# İzinli -f dil/lehçe bayrakları (no- önekli biçimleriyle). Tanılama, eklenti, profil, modül önbelleği vb. dışarıda.
_F_ALLOWED = frozenset("""
signed-char unsigned-char ms-extensions ms-compatibility borland-extensions declspec blocks exceptions cxx-exceptions
rtti gnu89-inline gnu-keywords asm gnu-inline-asm common short-enums short-wchar wrapv trapv strict-aliasing
strict-overflow builtin pic PIC pie PIE freestanding hosted openmp char8_t coroutines coroutines-ts permissive
dollars-in-identifiers delayed-template-parsing threadsafe-statics operator-names access-control elide-constructors
sized-deallocation aligned-allocation aligned-new digraphs trigraphs inline inline-functions omit-frame-pointer
stack-protector stack-protector-strong stack-protector-all visibility-inlines-hidden objc-arc objc-exceptions
lax-vector-conversions zero-initialized-in-bss math-errno fast-math finite-math-only strict-enums
double-square-bracket-attributes gnu-folding-constant ms-volatile cuda-allow-variadic-functions
unsafe-math-optimizations function-sections data-sections strict-vtable-pointers new-infallible
""".split())
_F_VALUE_RE = re.compile(r"^-f(visibility=(default|hidden|protected|internal)|ms-compatibility-version=[0-9.]+"
                         r"|lax-vector-conversions=(none|integer|all)|(constexpr|template|bracket)-depth=[0-9]{1,5}"
                         r"|(input|exec)-charset=[A-Za-z0-9_-]{1,20}|max-type-align=[0-9]{1,4})$")
_M_RE = re.compile(r"^-m[a-z0-9][a-z0-9_.=+-]{0,40}$")
_M_DENY = ("llvm", "file", "path", "dir", "plugin", "load")
# Ayrı argüman alan ve atılan bayraklar: argümanları da atılır (ör. -Xclang -load -Xclang x.so).
_DROP_WITH_ARG = frozenset({
    "-o", "-MF", "-MT", "-MQ", "-MJ", "-Xclang", "-Xpreprocessor", "-Xassembler", "-Xlinker", "-Xanalyzer", "-mllvm",
    "-x", "-arch", "-target", "--target", "-B", "--sysroot", "-isysroot", "-idirafter", "-imacros", "-iprefix",
    "-iwithprefix", "-iwithprefixbefore", "-include-pch", "-ivfsoverlay", "-imultilib", "-cxx-isystem", "-L", "-l",
    "-T", "-u", "-z", "-gcc-toolchain", "--gcc-toolchain", "-main-file-name", "-working-directory", "-Xcuda-ptxas",
    "-Xopenmp-target", "-aux-target", "-dependency-file", "-serialize-diagnostics", "--serialize-diagnostics",
    "-fplugin-arg", "-load", "-Xarch_host", "-Xarch_device", "--config", "-resource-dir", "-module-file-info",
    "-split-dwarf-file", "-fmodule-file", "-fmodules-cache-path",
})


def _is_within(path: Path, base: Path) -> bool:
    return path == base or str(path).startswith(str(base) + os.sep)


def _lexical_absolute(path: Path, *, base: Path | None = None) -> Path | None:
    """Return a normalized absolute path without consulting the filesystem."""
    raw = str(path)
    if not path.is_absolute():
        if base is None:
            return None
        raw = os.path.join(str(base), raw)
    normalized = os.path.normpath(raw)
    if not os.path.isabs(normalized):
        return None
    return Path(normalized)


@dataclass
class FileFlags:
    """Bir kaynak dosya için güvenli clang argümanları ve bilginin kaynağı."""

    args: list[str]
    source: str
    origin: str = ""  # bilginin okunduğu dosya (proje köküne göre)


@dataclass
class _Flags:
    includes: list[tuple[str, str]] = field(default_factory=list)  # (-I|-isystem|-iquote, mutlak yol)
    defines: list[str] = field(default_factory=list)  # "-DX=1" | "-UX"
    std: list[str] = field(default_factory=list)  # "-std=..."
    lang: list[str] = field(default_factory=list)  # izinli -f / -m bayrakları
    forced: list[str] = field(default_factory=list)  # -include mutlak dosya yolu

    def empty(self) -> bool:
        return not (self.includes or self.defines or self.std or self.lang or self.forced)

    def merged(self, other: "_Flags") -> "_Flags":
        out = _Flags(list(self.includes), list(self.defines), list(self.std), list(self.lang), list(self.forced))
        for inc in other.includes:
            if inc not in out.includes:
                out.includes.append(inc)
        out.defines += [d for d in other.defines if d not in out.defines]
        out.std += other.std
        out.lang += [x for x in other.lang if x not in out.lang]
        out.forced += [x for x in other.forced if x not in out.forced]
        return out

    def to_args(self, suffix: str) -> list[str]:
        cxx = suffix.lower() in CXX_SUFFIXES
        args: list[str] = []
        stds = [s for s in self.std if ("++" in s) == cxx]
        if stds:
            args.append(stds[-1])
        args += self.lang[:40]
        for d in self.defines[:MAX_DEFINES]:
            args.append(d)
        seen: set[tuple[str, str]] = set()
        for kind, path in self.includes:
            if (kind, path) in seen or len(seen) >= MAX_INCLUDES:
                continue
            seen.add((kind, path))
            args += [kind, path]
        for f in self.forced[:8]:
            args += ["-include", f]
        return args


class _PathPolicy:
    """Include yolu / -include dosyası kabul kuralı: proje kökü içinde ya da sistem dizini; var olmalı."""

    def __init__(self, root: Path, *, directories: set[str] | None = None,
                 files: set[str] | None = None) -> None:
        normalized = _lexical_absolute(root)
        if normalized is None:
            raise ValueError("Proje kok yolu mutlak olmali.")
        self.root = normalized
        if directories is None or files is None:
            directories, files = {"."}, set()
            try:
                with ProjectTree(str(self.root)) as tree:
                    for entry in tree.walk(skip_dirs=SKIP_WALK_DIRS, reject_unsafe=False):
                        directories.add(entry.directory.as_posix())
                        directories.update(path.as_posix() for path in entry.directories)
                        files.update(item.path.as_posix() for item in entry.files)
            except ProjectTreeError:
                pass
        self.directories = frozenset(directories)
        self.files = frozenset(files)

    def _project_relative(self, raw: str, base: Path) -> tuple[Path, str] | None:
        candidate = _lexical_absolute(Path(raw), base=base)
        if candidate is None or not _is_within(candidate, self.root):
            return None
        try:
            relative = candidate.relative_to(self.root).as_posix()
        except ValueError:
            return None
        return candidate, relative or "."

    def include_dir(self, raw: str, base: Path) -> str | None:
        if not raw or "\x00" in raw or "$" in raw or len(raw) > 4096:
            return None
        project = self._project_relative(raw, base)
        if project is not None:
            candidate, relative = project
            return str(candidate) if relative in self.directories else None
        r = _lexical_absolute(Path(raw), base=base)
        if r is None:
            return None
        if any(str(r) == pre.rstrip("/") or str(r).startswith(pre if pre.endswith(("/", "-")) else pre + "/")
               for pre in SYSTEM_INCLUDE_PREFIXES):
            return str(r) if r.is_dir() else None
        return None

    def forced_file(self, raw: str, base: Path) -> str | None:
        if not raw or "\x00" in raw or "$" in raw:
            return None
        project = self._project_relative(raw, base)
        if project is None:
            return None
        candidate, relative = project
        return str(candidate) if relative in self.files else None


def _valid_define(value: str) -> bool:
    return bool(value) and len(value) <= MAX_VALUE_LEN and "\n" not in value and "\x00" not in value \
        and bool(_MACRO_RE.match(value))


def _f_allowed(arg: str) -> bool:
    if _F_VALUE_RE.match(arg):
        return True
    name = arg[2:]
    if name.startswith("no-"):
        name = name[3:]
    return name in _F_ALLOWED


def _m_allowed(arg: str) -> bool:
    return bool(_M_RE.match(arg)) and not any(word in arg for word in _M_DENY)


def filter_args(argv: Iterable[str], base: Path, policy: _PathPolicy, *,
                translate: Callable[[str], str] | None = None, allow_defines: bool = True,
                allow_std: bool = True) -> _Flags:
    """Derleyici argümanlarından yalnız güvenli bayrakları süz (görevdeki izin listesi)."""
    out = _Flags()
    items = [str(a) for a in argv]
    tr = translate or (lambda s: s)
    i = 0
    n = len(items)
    while i < n:
        a = items[i]
        i += 1
        if not a.startswith("-"):
            continue  # derleyici adı, kaynak dosya, @yanıt-dosyası vb.
        if a in _DROP_WITH_ARG:
            i += 1
            continue
        for flag, kind in (("-isystem", "-isystem"), ("-iquote", "-iquote"), ("-I", "-I")):
            if a.startswith(flag):
                val = a[len(flag):]
                if not val and i < n:
                    val = items[i]
                    i += 1
                path = policy.include_dir(tr(val), base)
                if path:
                    out.includes.append((kind, path))
                break
        else:
            if a == "-include" or (a.startswith("-include") and not a.startswith("-include-")):
                val = a[len("-include"):]
                if not val and i < n:
                    val = items[i]
                    i += 1
                path = policy.forced_file(tr(val), base)
                if path:
                    out.forced.append(path)
            elif a.startswith("-D") or a.startswith("-U"):
                val = a[2:]
                if not val and i < n:
                    val = items[i]
                    i += 1
                if allow_defines and _valid_define(val) and (a[1] == "D" or "=" not in val):
                    out.defines.append(a[:2] + val)
            elif a.startswith("-std="):
                if allow_std and _STD_RE.match(a[5:]):
                    out.std.append(a)
            elif a.startswith("-f"):
                if _f_allowed(a):
                    out.lang.append(a)
            elif a.startswith("-m"):
                if _m_allowed(a):
                    out.lang.append(a)
            # diğer her şey (-o, -W*, -O*, -g, -c, -B…, --sysroot=…, -fplugin=…) atılır
    return out


# ----------------------------------------------------------------------------------------------- compile_commands


def _remap_prefix(entries: list[dict[str, Any]], root: Path, files: frozenset[str]) -> tuple[str, str] | None:
    """compile_commands başka makinede üretilmişse özgün kök → tarama kökü eşlemesi (dosya sonekinden)."""
    votes: Counter[str] = Counter()
    inside = 0
    for e in entries[:300]:
        f = os.path.normpath(os.path.join(str(e.get("directory") or ""), str(e.get("file") or "")))
        if _is_within(Path(f), root):
            inside += 1
            continue
        parts = PurePosixPath(f).parts
        for k in range(1, min(len(parts), 40)):
            rel = parts[k:]
            if rel and PurePosixPath(*rel).as_posix() in files:
                votes[str(PurePosixPath(*parts[:k]))] += 1
                break
    if not votes:
        return None
    prefix, count = votes.most_common(1)[0]
    if count <= inside or prefix in ("/", ""):
        return None
    return prefix, str(root)


def _load_compile_db(text: str, path: Path, root: Path, policy: _PathPolicy,
                     out: dict[str, _Flags]) -> int:
    try:
        data = json.loads(text)
    except ValueError:
        return 0
    if not isinstance(data, list):
        return 0
    entries = [e for e in data[:MAX_COMPILE_ENTRIES] if isinstance(e, dict) and isinstance(e.get("file"), str)]
    remap = _remap_prefix(entries, root, policy.files)

    def translate(p: str) -> str:
        if remap and os.path.isabs(p):
            q = os.path.normpath(p)
            if q == remap[0] or q.startswith(remap[0] + "/"):
                return remap[1] + q[len(remap[0]):]
        return p

    added = 0
    for e in entries:
        directory = translate(str(e.get("directory") or str(path.parent)))
        if not os.path.isabs(directory):
            directory = str(path.parent / directory)
        argv = e.get("arguments")
        if not isinstance(argv, list):
            cmd = e.get("command")
            if not isinstance(cmd, str) or len(cmd) > 200_000:
                continue
            try:
                argv = shlex.split(cmd)
            except ValueError:
                continue
        file_s = translate(str(e["file"]))
        fpath = Path(file_s) if os.path.isabs(file_s) else Path(directory) / file_s
        normalized = _lexical_absolute(fpath)
        if normalized is None:
            continue
        key = str(normalized)
        try:
            relative = normalized.relative_to(root).as_posix()
        except ValueError:
            continue
        if relative not in policy.files or key in out:
            continue
        out[key] = filter_args(argv, Path(directory), policy, translate=translate)
        added += 1
    return added


# ------------------------------------------------------------------------------------------------------- CMake

_CMAKE_SIMPLE_VARS = ("CMAKE_CURRENT_SOURCE_DIR", "CMAKE_CURRENT_LIST_DIR", "CMAKE_SOURCE_DIR",
                      "PROJECT_SOURCE_DIR", "CMAKE_HOME_DIRECTORY")
_CMAKE_REF_RE = re.compile(r"\$\{([A-Za-z0-9_]+)\}")
_GENEX_BUILD_RE = re.compile(r"^\$<BUILD_INTERFACE:(.*)>$")
_CMAKE_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_CMAKE_BRACKET_RE = re.compile(r"\[(=*)\[")
_CMAKE_BRACKET_COMMENT_RE = re.compile(r"#\[(=*)\[")


def cmake_commands(text: str, limit: int = 50_000) -> list[tuple[str, list[str]]]:
    """CMake dilinin küçük bir alt kümesi: ``ad(argümanlar)`` çağrıları; yorum, tırnak ve köşeli argüman desteği."""
    out: list[tuple[str, list[str]]] = []
    i, n = 0, len(text)
    while i < n and len(out) < limit:
        c = text[i]
        if c == "#":
            m = _CMAKE_BRACKET_COMMENT_RE.match(text, i)
            if m:
                end = text.find("]" + m.group(1) + "]", i)
                i = n if end < 0 else end + len(m.group(1)) + 2
            else:
                end = text.find("\n", i)
                i = n if end < 0 else end + 1
            continue
        m = _CMAKE_IDENT_RE.match(text, i)
        if not m:
            i += 1
            continue
        name = m.group(0)
        j = m.end()
        while j < n and text[j] in " \t":
            j += 1
        if j >= n or text[j] != "(":
            i = m.end()
            continue
        # argümanlar
        args: list[str] = []
        depth = 1
        j += 1
        cur: list[str] = []
        has_cur = False
        while j < n and depth > 0:
            c = text[j]
            if c == '"':
                k = j + 1
                buf = []
                while k < n and text[k] != '"':
                    if text[k] == "\\" and k + 1 < n:
                        buf.append(text[k + 1] if text[k + 1] in '"\\$;' else ("\n" if text[k + 1] == "n" else text[k + 1]))
                        k += 2
                        continue
                    buf.append(text[k])
                    k += 1
                cur.append("".join(buf))
                has_cur = True
                j = k + 1
                continue
            if c == "[" and not has_cur:
                bm = _CMAKE_BRACKET_RE.match(text, j)
                if bm:
                    end = text.find("]" + bm.group(1) + "]", j)
                    end = n if end < 0 else end
                    cur.append(text[j + len(bm.group(0)):end])
                    has_cur = True
                    j = end + len(bm.group(1)) + 2
                    continue
            if c == "#":
                end = text.find("\n", j)
                j = n if end < 0 else end
                continue
            if c == "(":
                depth += 1
                cur.append(c)
                has_cur = True
            elif c == ")":
                depth -= 1
                if depth > 0:
                    cur.append(c)
                    has_cur = True
            elif c.isspace():
                if has_cur:
                    args.append("".join(cur))
                    cur, has_cur = [], False
            else:
                cur.append(c)
                has_cur = True
            j += 1
        if has_cur:
            args.append("".join(cur))
        out.append((name.lower(), args))
        i = j
    return out


@dataclass
class _CMakeDir:
    flags: _Flags
    public_includes: list[tuple[str, str]]
    project_dir: bool
    origin: str
    extensions: tuple[bool, bool] = (True, True)  # CMAKE_C_EXTENSIONS / CMAKE_CXX_EXTENSIONS (alt dizine geçer)


def _cmake_expand(arg: str, env: dict[str, str]) -> str | None:
    """Yalnız basit yerleşik değişkenler; kalan ${…}, $<…>, $ENV{…} varsa argüman atılır."""
    m = _GENEX_BUILD_RE.match(arg)
    if m:
        arg = m.group(1)
    if arg.startswith("$<INSTALL_INTERFACE:"):
        return None
    out = _CMAKE_REF_RE.sub(lambda mm: env.get(mm.group(1), "\x00"), arg)
    if "\x00" in out or "$" in out:
        return None
    return out


def parse_cmake(text: str, cdir: Path, root: Path, project_source_dir: Path, policy: _PathPolicy,
                origin: str = "", extensions: tuple[bool, bool] = (True, True)) -> _CMakeDir:
    flags = _Flags()
    public: list[tuple[str, str]] = []
    cmds = cmake_commands(text)
    project_dir = any(name == "project" for name, _ in cmds)
    psd = cdir if project_dir else project_source_dir
    env = {"CMAKE_CURRENT_SOURCE_DIR": str(cdir), "CMAKE_CURRENT_LIST_DIR": str(cdir), "CMAKE_SOURCE_DIR": str(root),
           "PROJECT_SOURCE_DIR": str(psd), "CMAKE_HOME_DIRECTORY": str(root)}
    cond = 0  # if/foreach/while derinliği: koşullu bloklarda yalnız include yolları alınır
    skip = 0  # function/macro gövdeleri (çağrılmadıkça çalışmaz): tümüyle yok sayılır
    ext_c, ext_cxx = extensions
    std_c = std_cxx = None
    for name, raw in cmds:
        if name in ("function", "macro"):
            skip += 1
            continue
        if name in ("endfunction", "endmacro"):
            skip = max(0, skip - 1)
            continue
        if skip:
            continue
        if name in ("if", "foreach", "while"):
            cond += 1
            continue
        if name in ("endif", "endforeach", "endwhile"):
            cond = max(0, cond - 1)
            continue
        args = [a for a in (_cmake_expand(x, env) for x in raw) if a is not None]

        def add_inc(values: list[str], system: bool, publish: bool = False) -> None:
            for v in values:
                for part in v.split(";"):
                    path = policy.include_dir(part.strip(), cdir)
                    if path:
                        item = ("-isystem" if system else "-I", path)
                        flags.includes.append(item)
                        if publish:
                            public.append(item)

        def add_defs(values: list[str], dash_required: bool) -> None:
            if cond:
                return
            for v in values:
                for part in v.split(";"):
                    part = part.strip()
                    if part.startswith(("-D", "-U")):
                        kind, val = part[:2], part[2:]
                    elif dash_required or not part:
                        continue
                    else:
                        kind, val = "-D", part
                    if _valid_define(val) and (kind == "-D" or "=" not in val):
                        flags.defines.append(kind + val)

        if name == "include_directories":
            system = "SYSTEM" in args
            add_inc([a for a in args if a not in ("AFTER", "BEFORE", "SYSTEM")], system)
        elif name == "target_include_directories" and len(args) >= 2:
            system = "SYSTEM" in args[1:]
            scope = "PRIVATE"
            for a in args[1:]:
                if a in ("SYSTEM", "AFTER", "BEFORE"):
                    continue
                if a in ("PRIVATE", "PUBLIC", "INTERFACE"):
                    scope = a
                    continue
                add_inc([a], system, publish=scope in ("PUBLIC", "INTERFACE"))
        elif name == "add_definitions":
            add_defs(args, True)
        elif name == "add_compile_definitions":
            add_defs(args, False)
        elif name == "target_compile_definitions" and len(args) >= 2:
            add_defs([a for a in args[1:] if a not in ("PRIVATE", "PUBLIC", "INTERFACE")], False)
        elif name == "set_property" and len(args) >= 4 and args[0] == "DIRECTORY" and args[1] in ("APPEND", "PROPERTY"):
            try:
                k = args.index("PROPERTY")
            except ValueError:
                continue
            if k + 1 < len(args):
                prop, values = args[k + 1], args[k + 2:]
                if prop == "INCLUDE_DIRECTORIES":
                    add_inc(values, False)
                elif prop == "COMPILE_DEFINITIONS":
                    add_defs(values, False)
        elif name == "set" and len(args) >= 2 and not cond:
            var, val = args[0], args[1]
            if var == "CMAKE_C_STANDARD" and val in ("90", "99", "11", "17", "23"):
                std_c = val
            elif var == "CMAKE_CXX_STANDARD" and val in ("98", "11", "14", "17", "20", "23", "26"):
                std_cxx = val
            elif var == "CMAKE_C_EXTENSIONS":
                ext_c = val.upper() not in ("OFF", "FALSE", "NO", "0", "N")
            elif var == "CMAKE_CXX_EXTENSIONS":
                ext_cxx = val.upper() not in ("OFF", "FALSE", "NO", "0", "N")
    if std_c:
        flags.std.append(f"-std={'gnu' if ext_c else 'c'}{std_c}")
    if std_cxx:
        flags.std.append(f"-std={'gnu++' if ext_cxx else 'c++'}{std_cxx}")
    return _CMakeDir(flags, public, project_dir, origin, (ext_c, ext_cxx))


# -------------------------------------------------------------------------------------------------------- Make

_MAKE_ASSIGN_RE = re.compile(r"^(?:(?:override|export|private)\s+)*([A-Za-z_][A-Za-z0-9_.-]*)\s*(::?=|:::=|\+=|\?=|!=|=)\s*(.*)$")
_MAKE_REF_RE = re.compile(r"\$(?:\(([^()$\s:]+)\)|\{([^{}$\s:]+)\})")


def _make_logical_lines(text: str) -> list[str]:
    lines: list[str] = []
    buf = ""
    for raw in text.splitlines():
        if raw.endswith("\\"):
            buf += raw[:-1] + " "
            continue
        lines.append(buf + raw)
        buf = ""
    if buf:
        lines.append(buf)
    return lines


def _strip_make_comment(line: str) -> str:
    out = []
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            out.append(line[i:i + 2])
            i += 2
            continue
        if c == "#":
            break
        out.append(c)
        i += 1
    return "".join(out)


def parse_make_vars(text: str, variables: dict[str, list[tuple[str, bool]]] | None = None) -> dict[str, list[tuple[str, bool]]]:
    """Makefile değişken atamaları: ad → [(ham değer, koşullu mu)]. ``!=`` (kabuk ataması), tarif satırları ve
    ``define`` blokları yok sayılır; hiçbir ifade çalıştırılmaz ya da değerlendirilmez."""
    out = variables if variables is not None else {}
    cond = 0
    in_define = False
    for line in _make_logical_lines(text):
        if line.startswith("\t"):
            continue  # tarif (recipe) satırı
        s = _strip_make_comment(line).strip()
        if not s:
            continue
        word = s.split(None, 1)[0]
        if in_define:
            if word == "endef":
                in_define = False
            continue
        if word in ("define",) or (word in ("override", "export") and s.split()[1:2] == ["define"]):
            in_define = True
            continue
        if word in ("ifeq", "ifneq", "ifdef", "ifndef"):
            cond += 1
            continue
        if word == "endif":
            cond = max(0, cond - 1)
            continue
        if word == "else":
            continue
        m = _MAKE_ASSIGN_RE.match(s)
        if not m:
            continue
        name, op, value = m.group(1), m.group(2), m.group(3).strip()
        if op == "!=":
            continue  # kabuk ataması: asla çalıştırılmaz
        conditional = cond > 0
        if op in ("=", ":=", "::=", ":::=") and not conditional:
            out[name] = [(value, False)]
        elif op == "?=" and name in out:
            continue
        else:
            out.setdefault(name, []).append((value, conditional))
    return out


class _MakeExpander:
    def __init__(self, variables: dict[str, list[tuple[str, bool]]], builtins: dict[str, str]) -> None:
        self.vars = variables
        self.builtins = builtins

    def _scalar(self, name: str, depth: int) -> str | None:
        """Gömülü başvuru (ör. -I$(TOP)/inc) için tek değer; çözülemezse None (belirteç atılır)."""
        if name in self.builtins:
            return self.builtins[name]
        parts = self.vars.get(name)
        if not parts or depth > 6 or any(c for _, c in parts):
            return None
        text = " ".join(v for v, _ in parts).strip()
        if "$(" in text or "${" in text:
            replaced = self._embed(text, depth + 1)
            if replaced is None:
                return None
            text = replaced
        if not text or " " in text or "$" in text:
            return None
        return text

    def _embed(self, word: str, depth: int) -> str | None:
        failed = False

        def sub(m: re.Match[str]) -> str:
            nonlocal failed
            v = self._scalar(m.group(1) or m.group(2), depth)
            if v is None:
                failed = True
                return ""
            return v

        out = _MAKE_REF_RE.sub(sub, word)
        if failed or "$" in out:
            return None
        return out

    def tokens(self, name: str, depth: int = 0, conditional: bool = False) -> list[tuple[str, bool]]:
        if depth > 8:
            return []
        out: list[tuple[str, bool]] = []
        for value, cond in self.vars.get(name, []):
            out += self._value_tokens(value, depth, conditional or cond)
        return out

    def _value_tokens(self, value: str, depth: int, conditional: bool) -> list[tuple[str, bool]]:
        # İşlev çağrıları ($(shell …), $(wildcard …), $(addprefix …) …) içeriğiyle birlikte atılır: değerlendirilmez.
        value = _drop_make_functions(value)
        try:
            words = shlex.split(value, posix=True)
        except ValueError:
            words = value.split()
        out: list[tuple[str, bool]] = []
        for w in words:
            if "\x00" in w:
                continue  # ör. -DV=$(shell …): değer bilinmiyor, tanım uydurulmaz
            m = _MAKE_REF_RE.fullmatch(w)
            if m:
                out += self.tokens(m.group(1) or m.group(2), depth + 1, conditional)
                continue
            if "$" in w:
                e = self._embed(w, depth + 1)
                if e is None:
                    continue
                w = e
            out.append((w, conditional))
        return out


def _drop_make_functions(value: str) -> str:
    """``$(ad argüman…)`` / ``${ad argüman…}`` biçimli tüm Make işlev çağrılarını (iç içe dahil) metinden çıkarır."""
    out = []
    i, n = 0, len(value)
    while i < n:
        if value[i] == "$" and i + 1 < n and value[i + 1] in "({":
            close = ")" if value[i + 1] == "(" else "}"
            j = i + 2
            depth = 1
            while j < n and depth:
                if value[j] == value[i + 1]:
                    depth += 1
                elif value[j] == close:
                    depth -= 1
                j += 1
            inner = value[i + 2:j - 1]
            if re.search(r"[\s,]", inner) or "$" in inner:
                out.append("\x00")  # işlev çağrısı ya da iç içe başvuru: içinde geçtiği belirteç bütünüyle atılır
            else:
                out.append(value[i:j])
            i = j
            continue
        out.append(value[i])
        i += 1
    return "".join(out)


def make_flags(variables: dict[str, list[tuple[str, bool]]], mdir: Path, policy: _PathPolicy, cxx: bool) -> _Flags:
    exp = _MakeExpander(variables, {"CURDIR": str(mdir), "srcdir": ".", "top_srcdir": str(policy.root),
                                    "abs_srcdir": str(mdir), "abs_top_srcdir": str(policy.root)})
    flags = _Flags()
    for var in (MAKE_CXX_VARS if cxx else MAKE_C_VARS):
        toks = exp.tokens(var)
        plain = [t for t, c in toks if not c]
        condi = [t for t, c in toks if c]
        flags = flags.merged(filter_args(plain, mdir, policy))
        # koşullu (ifeq/ifdef) bloklardaki atamalardan yalnız include yolları alınır (-D/-std çelişebilir)
        flags = flags.merged(filter_args(condi, mdir, policy, allow_defines=False, allow_std=False))
    flags.lang = []  # Make metninden yalnız -I/-D/-std (görev kapsamı)
    flags.forced = []
    return flags


# ------------------------------------------------------------------------------------------------------- yükleme


class BuildInfo:
    """Proje derleme bilgisi; ``flags_for(dosya)`` dosya başına güvenli argümanları ve kaynağı verir."""

    def __init__(self, root: Path, *, directories: set[str] | None = None,
                 files: set[str] | None = None) -> None:
        self.root = root
        self.policy = _PathPolicy(root, directories=directories, files=files)
        self.compile_db: dict[str, _Flags] = {}
        self.compile_db_files: list[str] = []
        self.cmake_dirs: dict[str, _CMakeDir] = {}
        self.cmake_public: list[tuple[str, str]] = []
        self.make_files: dict[str, list[Path]] = {}
        self._make_cache: dict[tuple[str, bool], _Flags] = {}
        self._cmake_cache: dict[str, _Flags | None] = {}
        self.truncated = False
        self.seconds = 0.0
        self.header_names: set[str] = set()  # projedeki başlık dosyası adları (taban ad)
        self.template_names: set[str] = set()  # X.in / X.cmake şablonlarından üretilen başlık adları
        self.generator_files: list[Path] = []
        self._mentioned: set[str] = set()

    # --- derlemede üretilen (eksik) başlık
    def generated_header(self, name: str) -> bool:
        """``name`` derleme sırasında üretilen ve projede bulunmayan bir başlık mı? Kanıt yalnız metinden:
        aynı adlı başlık projede yok VE (X.in/X.cmake şablonu var YA DA ad bir yapı dosyasında geçiyor)."""
        if not _STUB_NAME_RE.match(name or "") or ".." in name.split("/"):
            return False
        base = name.rsplit("/", 1)[-1]
        if base in self.header_names:
            return False
        if base in self.template_names:
            return True
        return base in self._mentioned

    # --- dosya başına
    def flags_for(self, path: Path) -> FileFlags:
        rp = _lexical_absolute(path)
        if rp is None:
            return FileFlags([], SOURCE_NONE)
        if not _is_within(rp, self.root):
            return FileFlags([], SOURCE_NONE)
        try:
            if rp.relative_to(self.root).as_posix() not in self.policy.files:
                return FileFlags([], SOURCE_NONE)
        except ValueError:
            return FileFlags([], SOURCE_NONE)
        rel_origin = ""
        entry = self.compile_db.get(str(rp))
        if entry is not None:  # derleme komutu biliniyor: (boş olsa da) metin ayrıştırmaya düşülmez
            return FileFlags(entry.to_args(rp.suffix), SOURCE_COMPILE_COMMANDS,
                             self.compile_db_files[0] if len(self.compile_db_files) == 1 else "")
        cm = self._cmake_for(rp.parent)
        if cm is not None and not cm.empty():
            args = cm.to_args(rp.suffix)
            if args:
                return FileFlags(args, SOURCE_CMAKE, rel_origin)
        mk = self._make_for(rp.parent, rp.suffix.lower() in CXX_SUFFIXES)
        if mk is not None:
            flags, origin = mk
            args = flags.to_args(rp.suffix)
            if args:
                return FileFlags(args, SOURCE_MAKE, origin)
        return FileFlags([], SOURCE_NONE)

    def _ancestors(self, d: Path) -> list[Path]:
        chain = []
        cur = d
        while _is_within(cur, self.root):
            chain.append(cur)
            if cur == self.root:
                break
            cur = cur.parent
        return list(reversed(chain))

    def _cmake_for(self, d: Path) -> _Flags | None:
        key = str(d)
        if key in self._cmake_cache:
            return self._cmake_cache[key]
        flags: _Flags | None = None
        for anc in self._ancestors(d):
            cd = self.cmake_dirs.get(str(anc))
            if cd is None:
                continue
            flags = cd.flags if flags is None else flags.merged(cd.flags)
        if flags is not None and self.cmake_public:
            flags = flags.merged(_Flags(includes=list(self.cmake_public)))
        self._cmake_cache[key] = flags
        return flags

    def _make_for(self, d: Path, cxx: bool) -> tuple[_Flags, str] | None:
        for anc in reversed(self._ancestors(d)):
            files = self.make_files.get(str(anc))
            if not files:
                continue
            ck = (str(anc), cxx)
            if ck not in self._make_cache:
                return None
            flags = self._make_cache[ck]
            if flags.empty():
                return None  # en yakın Makefile bayrak vermiyorsa üst dizine çıkılmaz (başka bir derleme birimi)
            return flags, os.path.relpath(files[0], self.root)
        return None

    def summary(self) -> dict[str, Any]:
        return {
            "compile_commands": self.compile_db_files[:MAX_COMPILE_DBS],
            "compile_commands_entries": len(self.compile_db),
            "cmake_files": len(self.cmake_dirs),
            "make_files": sum(len(v) for v in self.make_files.values()),
            "truncated": self.truncated,
            "seconds": round(self.seconds, 2),
        }


def load(root: Path, *, max_seconds: float = DEFAULT_LOAD_SECONDS,
         project_tree: ProjectTree | None = None) -> BuildInfo:
    """Proje kökünü (sembolik bağ izlemeden) gezip derleme bilgisini metin olarak okur. Hiçbir şey çalıştırılmaz."""
    started = time.monotonic()
    normalized = _lexical_absolute(Path(root))
    if normalized is None:
        raise ValueError("Proje kok yolu mutlak olmali.")
    root = normalized
    if project_tree is not None and _lexical_absolute(project_tree.root) != root:
        raise ProjectTreeError("Proje ağacı derleme bilgisi köküyle eşleşmiyor.")
    deadline = started + max_seconds
    dbs: list[ProjectFile] = []
    cmakes: list[ProjectFile] = []
    makes: dict[str, list[ProjectFile]] = {}
    generators: list[ProjectFile] = []
    make_count = 0
    walked = 0
    owned_tree = project_tree.duplicate() if project_tree is not None else ProjectTree(str(root)).open()
    try:
        directories: set[str] = {"."}
        files: set[str] = set()
        entries = owned_tree.walk(skip_dirs=SKIP_WALK_DIRS, reject_unsafe=False)
        observed: list[ProjectFile] = []
        for entry in entries:
            walked += 1
            if walked > MAX_WALK_DIRS or time.monotonic() > deadline:
                break
            # Eski os.walk sözleşmesi: noktayla başlayan dizinler (.build dışında) atlanır.
            if any(part.startswith(".") and part != ".build" for part in entry.directory.parts):
                continue
            directories.add(entry.directory.as_posix())
            directories.update(path.as_posix() for path in entry.directories
                               if not (path.name.startswith(".") and path.name != ".build"))
            observed.extend(entry.files)
            files.update(item.path.as_posix() for item in entry.files)
        truncated = walked > MAX_WALK_DIRS or time.monotonic() > deadline
        info = BuildInfo(root, directories=directories, files=files)
        info.truncated = truncated
        for item in observed:
            fname = item.name
            absolute = root / item.path
            directory = str(absolute.parent)
            if fname.endswith(HEADER_SUFFIXES) and len(info.header_names) < MAX_HEADER_NAMES:
                info.header_names.add(fname)
            elif fname.endswith((".in", ".cmake")):
                stem = fname[:-3] if fname.endswith(".in") else fname[:-6]
                for cand in (stem, stem.replace("-cmake", "").replace(".cmake", "")):
                    if cand.endswith(HEADER_SUFFIXES):
                        info.template_names.add(cand)
                if fname.endswith(".cmake") and len(generators) < MAX_GENERATOR_FILES:
                    generators.append(item)
            if fname in GENERATOR_NAMES and len(generators) < MAX_GENERATOR_FILES:
                generators.append(item)
            if fname == "compile_commands.json" and len(dbs) < MAX_COMPILE_DBS:
                dbs.append(item)
            elif fname == "CMakeLists.txt" and len(cmakes) < MAX_CMAKE_FILES:
                cmakes.append(item)
            elif (fname in MAKE_NAMES or fname.endswith(".mk")) and make_count < MAX_MAKE_FILES:
                makes.setdefault(directory, []).append(item)
                make_count += 1

        def read_text(item: ProjectFile, limit: int) -> str | None:
            if item.size > limit:
                return None
            return owned_tree.read_text(item, limit, errors="replace", allow_empty=True)

        # 1) compile_commands.json (köke yakın olan önce)
        for db in sorted(dbs, key=lambda item: (len(item.path.parts), item.path.as_posix())):
            if time.monotonic() > deadline + 5:
                info.truncated = True
                break
            text = read_text(db, MAX_COMPILE_DB_BYTES)
            path = root / db.path
            if text is not None and _load_compile_db(text, path, root, info.policy, info.compile_db):
                info.compile_db_files.append(db.path.as_posix())

        # 2) CMakeLists.txt (üstten alta; PROJECT_SOURCE_DIR en yakın project() dizini)
        project_dirs: dict[str, Path] = {}
        for cm in sorted(cmakes, key=lambda item: (len(item.path.parts), item.path.as_posix())):
            text = read_text(cm, MAX_BUILD_FILE_BYTES)
            if text is None:
                continue
            cm_path = root / cm.path
            cdir = cm_path.parent
            psd = root
            ext = (True, True)
            parents = list(reversed(info._ancestors(cdir.parent))) if cdir != root else []
            for anc in parents:
                if str(anc) in project_dirs:
                    psd = project_dirs[str(anc)]
                    break
            for anc in parents:
                if str(anc) in info.cmake_dirs:
                    ext = info.cmake_dirs[str(anc)].extensions
                    break
            parsed = parse_cmake(text, cdir, root, psd, info.policy, cm.path.as_posix(), ext)
            if parsed.project_dir:
                project_dirs[str(cdir)] = cdir
            info.cmake_dirs[str(cdir)] = parsed
            for inc in parsed.public_includes:
                if inc not in info.cmake_public and len(info.cmake_public) < MAX_INCLUDES:
                    info.cmake_public.append(inc)

        # Yapı dosyalarındaki üretilen başlık kanıtı, açık tanıtıcı kapanmadan çıkarılır.
        combined_generators = generators + cmakes + [item for group in makes.values() for item in group]
        seen_generators: set[str] = set()
        for item in combined_generators:
            rel = item.path.as_posix()
            if rel in seen_generators or len(info.generator_files) >= MAX_GENERATOR_FILES:
                continue
            seen_generators.add(rel)
            info.generator_files.append(root / item.path)
            text = read_text(item, MAX_BUILD_FILE_BYTES)
            if text:
                info._mentioned.update(_HEADER_TOKEN_RE.findall(text))

        # 3) Makefile / *.mk: metin açık descriptor üzerinden bir kez okunur ve iki dil için önceden ayrıştırılır.
        for directory, group in makes.items():
            group.sort(key=lambda item: (0 if item.name in MAKE_NAMES else 1, item.name))
            paths = [root / item.path for item in group]
            info.make_files[directory] = paths
            variables: dict[str, list[tuple[str, bool]]] = {}
            for item in group:
                text = read_text(item, MAX_BUILD_FILE_BYTES)
                if text is not None:
                    parse_make_vars(text, variables)
            for cxx in (False, True):
                info._make_cache[(directory, cxx)] = make_flags(variables, Path(directory), info.policy, cxx)
        info.seconds = time.monotonic() - started
        return info
    finally:
        owned_tree.close()
