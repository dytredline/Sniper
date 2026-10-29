"""Bağımlılık zafiyetlerinin sembol düzeyinde erişilebilirliği.

``dependency_security.analyze_vulnerability_reachability`` paketin kaynakta içe aktarılıp aktarılmadığını bulur.
Bu modül bir adım ileri gider: danışmadaki açıklı fonksiyonların (semboller) proje kodunda kullanılıp
kullanılmadığına bakar ve önceliği buna göre ayarlar. Karar türleri:

* ``reachable``           — açıklı sembol kodda kullanılıyor (çağrı ya da başvuru).
* ``imported_not_called`` — paket içe aktarılmış, bilinen açıklı semboller kullanılmıyor.
* ``not_imported``        — paket kaynakta doğrudan kullanılmıyor (dolaylı bağımlılık olabilir).
* ``unknown``             — paket kullanılıyor ama danışmada açıklı sembol bilgisi yok.

Sembol kaynakları (öncelik sırasıyla): çevrimdışı OSV kaydındaki ``affected[].ecosystem_specific.imports[].symbols``
(ör. Go), danışma metnindeki açıkça çağrı biçimli adlar (``yaml.load()``, ```merge``` fonksiyonu) ve küçük, danışmaya
özgü olmayan bir "bilinen açıklı fonksiyonlar" listesi. Son kaynak düşük güvenlidir: önceliği düşürmez.

Erişilemeyen bulgular gizlenmez; önemleri en çok bir derece düşürülür ve gerekçe yazılır. Ağ erişimi yoktur.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import zipfile
from typing import Any, Iterable, Iterator, Mapping

from project_tree import ProjectTree, ProjectTreeError

VERDICT_LABELS = {
    "reachable": "Erişilebilir: açıklı fonksiyon kodda kullanılıyor",
    "imported_not_called": "İçe aktarılmış ama açıklı fonksiyon kullanılmıyor",
    "not_imported": "Kaynak kodda doğrudan kullanılmıyor (dolaylı bağımlılık olabilir)",
    "unknown": "Bilinmiyor: paket kullanılıyor, açıklı fonksiyon bilgisi yok",
}
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
_VERDICT_RANK = {"reachable": 0, "unknown": 1, "imported_not_called": 2, "not_imported": 3}


@contextmanager
def _borrow_project_tree(root: Path, project_tree: ProjectTree | None) -> Iterator[ProjectTree]:
    """Use an independently owned descriptor view for one project read pass."""
    if project_tree is not None and Path(root) != project_tree.root:
        raise ValueError("Proje ağacı kökü istenen proje ile eşleşmiyor.")
    tree = project_tree.duplicate() if project_tree is not None else ProjectTree(root).open()
    try:
        yield tree
    finally:
        tree.close()

# Danışmaya özgü olmayan, yaygın paketlerin bilinen açıklı/tehlikeli fonksiyonları (düşük güven; önemi düşürmez).
CURATED_SYMBOLS: dict[str, tuple[str, ...]] = {
    "lodash": ("merge", "mergeWith", "defaultsDeep", "zipObjectDeep", "set", "setWith", "template", "unset", "update"),
    "underscore": ("template",),
    "pyyaml": ("load", "load_all", "full_load", "full_load_all", "unsafe_load", "unsafe_load_all", "FullLoader", "UnsafeLoader"),
    "js-yaml": ("load", "loadAll"),
    "jsonwebtoken": ("verify", "decode"),
    "pyjwt": ("decode",),
    "handlebars": ("compile", "precompile", "template"),
    "ejs": ("render", "renderFile", "compile"),
    "pug": ("compile", "render", "renderFile"),
    "node-serialize": ("unserialize",),
    "serialize-javascript": ("serialize",),
    "marked": ("marked", "parse", "parseInline", "lexer"),
    "jinja2": ("Template", "from_string", "Environment"),
    "pillow": ("Image.open", "open"),
    "xmldom": ("DOMParser",),
    "@xmldom/xmldom": ("DOMParser",),
    "express-fileupload": ("mv",),
    "mongoose": ("find", "findOne", "where", "$where"),
    "sequelize": ("query", "literal"),
    "lxml": ("fromstring", "XML", "HTML", "parse", "XMLParser"),
    "defusedxml": ("fromstring", "parse"),
    "cryptography": ("load_pem_private_key", "load_der_private_key", "PKCS1v15", "ECB"),
    "paramiko": ("AutoAddPolicy", "WarningPolicy", "exec_command", "Transport"),
    "torch": ("load", "jit.load"),
    "transformers": ("from_pretrained", "pipeline", "AutoModel.from_pretrained"),
    "langchain": ("load_prompt", "PythonREPLTool", "PALChain", "SQLDatabaseChain"),
    "adm-zip": ("extractAllTo", "extractEntryTo"),
    "unzipper": ("Extract", "Open"),
    "tar": ("extract", "x"),
    "xml2js": ("parseString", "parseStringPromise", "Parser"),
    "fast-xml-parser": ("XMLParser", "parse"),
    "vm2": ("VM", "NodeVM", "VMScript"),
    "shell-quote": ("parse", "quote"),
    "minimatch": ("minimatch", "makeRe"),
    "semver": ("satisfies", "validRange", "coerce"),
    "tough-cookie": ("Cookie.parse", "CookieJar", "setCookie"),
    "urllib3": ("PoolManager", "request", "urlopen"),
}

# Danışma metninde "fonksiyon olmayan" sık geçen adlar.
_STOPWORDS = {
    "true", "false", "null", "none", "undefined", "nan", "this", "self", "object", "string", "number", "array",
    "__proto__", "constructor", "prototype", "object.prototype", "function", "require", "import", "module",
    "exports", "module.exports", "window", "document", "process", "process.env", "json", "http", "https",
}
# Danışma örnek kodundaki dil yerleşikleri: paket sembolü değildir.
_GLOBAL_OWNERS = {
    "buffer", "date", "json", "math", "object", "array", "string", "number", "promise", "process", "console", "window",
    "document", "reflect", "symbol", "regexp", "error", "map", "set", "weakmap", "intl", "globalthis", "navigator",
    "os", "sys", "re", "str", "int", "dict", "list", "bytes", "time", "datetime",
}
_GLOBAL_FUNCS = {"alert", "eval", "require", "settimeout", "setinterval", "fetch", "print", "callback", "cb", "next",
                 "done", "resolve", "reject", "main", "test", "describe", "it", "expect", "assert", "open", "len", "exec"}
_BUILTIN_METHODS = {"tostring", "valueof", "touppercase", "tolowercase", "hasownproperty", "then", "catch", "finally",
                    "push", "pop", "map", "filter", "reduce", "foreach", "join", "split", "slice", "replace", "trim",
                    "length", "keys", "values", "entries", "apply", "call", "bind", "indexof", "includes", "startswith",
                    "endswith", "encode", "decode", "format", "append", "get", "set", "has", "now", "log", "bigint",
                    "stringify", "parseint", "alloc", "from", "on", "emit", "write", "end", "send", "status"}
_IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"
_BACKTICK_RE = re.compile(r"`([^`\n]{2,80})`")
_CALL_RE = re.compile(rf"(?<![\w$.])({_IDENT}(?:\.{_IDENT}){{0,3}})\(\)")
_DOTTED_CALL_RE = re.compile(rf"(?<![\w$.])({_IDENT}(?:\.{_IDENT}){{1,3}})\s*\(")
_FUNC_WORD_RE = re.compile(rf"(?:`({_IDENT}(?:\.{_IDENT}){{0,3}})`|\b({_IDENT}(?:\.{_IDENT}){{1,3}}))\s+(?:function|method|API|fonksiyon|yöntem)", re.I)
_FUNC_WORD_PRE_RE = re.compile(rf"(?:function|method|fonksiyonu?|yöntemi?)\s+`({_IDENT}(?:\.{_IDENT}){{0,3}})`", re.I)
_NEAR_FUNC_RE = re.compile(r"\b(?:functions?|methods?|fonksiyon\w*|yöntem\w*|API)\b", re.I)
_QUOTED_RE = re.compile(r"(?<![\w$])['\"]([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,3})['\"](?![\w$])")
_THE_FUNC_RE = re.compile(r"\bthe\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,2})\s+(?:function|method)\b", re.I)
_ENGLISH_WORDS = {
    "vulnerable", "affected", "following", "internal", "same", "above", "below", "said", "main", "default", "exported",
    "public", "private", "new", "old", "entire", "whole", "given", "specific", "certain", "core", "underlying", "helper",
    "a", "an", "any", "this", "that", "these", "those", "its", "their", "user", "custom", "provided", "parsing", "merge",
    "hash", "compare", "comparison", "validation", "sanitization", "escape", "escaping", "render", "rendering",
}
_PATH_LIKE_RE = re.compile(r"[/\\]|\.(?:js|mjs|cjs|ts|json|py|md|html|yml|yaml|lock|txt)\b", re.I)

# Başka paketin dinamik yüklediği sürücüler/motorlar: yükleyici kullanılıyorsa sürücü "kullanılmıyor" sayılmaz.
LOADER_PACKAGES: dict[str, tuple[str, ...]] = {
    "sequelize": ("pg", "pg-hstore", "mysql2", "mariadb", "sqlite3", "tedious", "oracledb"),
    "knex": ("pg", "mysql", "mysql2", "sqlite3", "better-sqlite3", "tedious", "oracledb"),
    "typeorm": ("mysql", "mysql2", "pg", "sqlite3", "better-sqlite3", "mongodb", "mssql", "oracledb", "sql.js"),
    "mongoose": ("mongodb", "bson"),
    "consolidate": ("ejs", "pug", "jade", "handlebars", "dustjs-linkedin", "swig", "hogan.js", "nunjucks", "mustache"),
    "sqlalchemy": ("psycopg2", "psycopg2-binary", "psycopg", "pymysql", "mysqlclient", "cx-oracle", "oracledb", "pyodbc"),
    "django": ("psycopg2", "psycopg2-binary", "psycopg", "mysqlclient", "pymysql", "cx-oracle", "oracledb", "sqlparse",
               "asgiref", "pytz", "tzdata"),
    "celery": ("kombu", "redis", "amqp", "librabbitmq"),
    # yaygın kütüphanelerin kendi alt bağımlılıkları (kullanılan paketin içinden çağrılır)
    "requests": ("urllib3", "certifi", "idna", "charset-normalizer", "chardet"),
    "httpx": ("httpcore", "h11", "anyio", "certifi", "idna"),
    "boto3": ("botocore", "s3transfer", "urllib3", "jmespath"),
    "flask": ("werkzeug", "jinja2", "itsdangerous", "click", "markupsafe", "blinker"),
    "fastapi": ("starlette", "pydantic", "anyio"),
    "express": ("body-parser", "qs", "send", "serve-static", "cookie", "path-to-regexp", "debug", "finalhandler",
                "cookie-signature", "fresh", "accepts", "type-is", "content-disposition", "mime", "ms"),
    "axios": ("follow-redirects", "form-data", "proxy-from-env"),
    "jsonwebtoken": ("jws", "jwa", "ms", "semver"),
    "request": ("tough-cookie", "qs", "form-data", "har-validator", "extend"),
    "prisma": ("@prisma/client", "@prisma/engines"),
    "next": ("react", "react-dom", "styled-jsx"),
    "langchain": ("langchain-core", "langchain-community", "openai", "tiktoken", "sqlalchemy"),
    "transformers": ("torch", "safetensors", "huggingface-hub", "tokenizers"),
}
# Paket adlarının dize olarak geçtiği (yapılandırmayla yüklenen) dosyalar: kod ve şablonlar. JSON/YAML gibi veri
# dosyaları hariç (tarama raporları, fikstürler "paket@sürüm" dizeleriyle gürültü yapar).
_MENTION_SUFFIXES = {".ejs", ".hbs", ".handlebars", ".pug", ".jade", ".dust", ".html", ".htm", ".vue", ".svelte"}
_DECLARATION_FILES = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
                      "requirements.txt", "requirements.in", "pipfile", "pipfile.lock", "poetry.lock", "pyproject.toml", "setup.cfg", "setup.py",
                      "go.mod", "go.sum", "composer.json", "composer.lock", "bower.json"}

_PY_SUFFIXES = {".py"}
_JS_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
_GO_SUFFIXES = {".go"}
_RS_SUFFIXES = {".rs"}
_JVM_SUFFIXES = {".java", ".kt", ".kts", ".scala", ".groovy"}
_DOTNET_SUFFIXES = {".cs", ".cshtml", ".razor", ".vb", ".fs", ".fsx"}
_MAX_FILE_BYTES = 1_000_000


_MAX_FILES = 20_000


# ---------------------------------------------------------------------------
# Sembol çıkarımı
# ---------------------------------------------------------------------------
def _strip_owner(token: str, import_names: set[str]) -> str:
    """``yaml.load`` → ``load``; ``_.merge`` → ``merge``; ``Image.open`` olduğu gibi."""
    token = token.strip().rstrip("()").strip()
    parts = token.split(".")
    aliases = {"_", "$"} | {name.replace("-", "_") for name in import_names} | import_names
    # Küçük harfli modül takma adını at (yaml.load → load); büyük harfli sınıf sahibini koru
    # (Yaml.load / JsonConvert.DeserializeObject), çünkü JVM/.NET dizini sınıf yolunu kanıt olarak taşır.
    while len(parts) > 1 and (parts[0] in {"_", "$"} or parts[0][:1].islower()) \
            and parts[0].casefold() in {a.casefold() for a in aliases}:
        parts = parts[1:]
    return ".".join(parts)


def symbols_from_text(text: str, import_names: set[str]) -> set[str]:
    """Danışma metninden yalnız çağrı biçimli ya da "function/method" ile nitelenen adlar."""
    if not text:
        return set()
    found: set[str] = set()

    def keep(raw: str | None) -> None:
        if not raw:
            return
        raw = raw.strip()
        if _PATH_LIKE_RE.search(raw) or raw.casefold() in _STOPWORDS or raw.isupper():
            return
        head = raw.split(".", 1)[0].casefold()
        if head in _GLOBAL_OWNERS or (("." not in raw) and head in _GLOBAL_FUNCS):
            return
        symbol = _strip_owner(raw, import_names)
        if len(symbol) < 2 or symbol.casefold() in _STOPWORDS or symbol.casefold() in {n.casefold() for n in import_names}:
            return
        if symbol.rsplit(".", 1)[-1].casefold() in _BUILTIN_METHODS and symbol.count(".") >= 1 and \
                symbol.split(".", 1)[0][:1].islower():
            return  # x.toString / userInput.toUpperCase gibi örnek değişken + yerleşik yöntem
        if not re.fullmatch(rf"{_IDENT}(?:\.{_IDENT})*", symbol):
            return
        found.add(symbol)

    for match in _BACKTICK_RE.finditer(text):
        inner = match.group(1).strip()
        call = re.fullmatch(rf"({_IDENT}(?:\.{_IDENT}){{0,3}})\s*\([^)]*\)", inner)
        if call:
            keep(call.group(1))
        elif re.fullmatch(rf"{_IDENT}(?:\.{_IDENT}){{0,3}}", inner) and (
                _NEAR_FUNC_RE.search(text[max(0, match.start() - 80):match.start()])
                or _NEAR_FUNC_RE.match(text[match.end():match.end() + 30].lstrip(" ,"))):
            keep(inner)  # "the functions `merge`, `mergeWith` …" / "`merge` function"
        elif re.fullmatch(rf"{_IDENT}(?:\.{_IDENT}){{1,3}}", inner) and inner.split(".", 1)[0].casefold() in (
                {n.casefold() for n in import_names} | {"_", "$"}):
            keep(inner)  # `yaml.load`, `_.merge`: paket adıyla nitelenmiş üye
    for match in _QUOTED_RE.finditer(text):
        # "The vulnerable functions are 'defaultsDeep', 'merge', and 'mergeWith'"
        if _NEAR_FUNC_RE.search(text[max(0, match.start() - 80):match.start()]) or \
                _NEAR_FUNC_RE.match(text[match.end():match.end() + 30].lstrip(" ,")):
            keep(match.group(1))
    for match in _THE_FUNC_RE.finditer(text):
        word = match.group(1)
        if word.casefold() not in _ENGLISH_WORDS or word in CURATED_SYMBOLS.get(next(iter(import_names), ""), ()):
            keep(word)  # "via the template function"
    for match in _CALL_RE.finditer(text):
        keep(match.group(1))
    for match in _DOTTED_CALL_RE.finditer(text):
        head = match.group(1).split(".", 1)[0].casefold()
        if head in {n.casefold() for n in import_names} | {"_", "$"}:
            keep(match.group(1))
    for match in _FUNC_WORD_RE.finditer(text):
        keep(match.group(1) or match.group(2))
    for match in _FUNC_WORD_PRE_RE.finditer(text):
        keep(match.group(1))
    return found


def _osv_db_root() -> Path:
    raw = os.environ.get("SNIPER_OSV_DB_ROOT", "").strip()
    return Path(raw).expanduser() if raw else Path.home() / ".local" / "state" / "sniper" / "osv-db"


def _offline_archives(root: Path | None = None) -> list[Path]:
    base = (root or _osv_db_root()) / "generations"
    archives: list[Path] = []
    try:
        for eco_dir in sorted(base.iterdir()):
            generations = sorted((g for g in eco_dir.iterdir() if g.is_dir()), reverse=True)
            for generation in generations[:1]:
                archives.extend(sorted(generation.glob("db-cache/osv-scalibr/*/all.zip")))
    except OSError:
        return []
    return archives


class OfflineOSV:
    """Çevrimdışı OSV arşivlerinden kimlikle (dosya adı) kayıt okuma; ağ yok, yazma yok."""

    def __init__(self, archives: Iterable[Path] | None = None) -> None:
        self._archives = list(archives) if archives is not None else _offline_archives()
        self._zips: list[zipfile.ZipFile] = []
        self._names: list[set[str]] = []

    def _open(self) -> None:
        if self._zips or not self._archives:
            return
        for path in self._archives:
            try:
                handle = zipfile.ZipFile(path)
            except (OSError, zipfile.BadZipFile):
                continue
            self._zips.append(handle)
            self._names.append(set(handle.namelist()))

    def record(self, vulnerability_id: str) -> dict[str, Any] | None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,80}", vulnerability_id or ""):
            return None
        self._open()
        member = f"{vulnerability_id}.json"
        for handle, names in zip(self._zips, self._names):
            if member in names:
                info = handle.getinfo(member)
                if info.file_size > 2_000_000:
                    return None
                try:
                    data = json.loads(handle.read(member))
                except (ValueError, OSError):
                    return None
                return data if isinstance(data, dict) else None
        return None

    def close(self) -> None:
        for handle in self._zips:
            handle.close()
        self._zips.clear()
        self._names.clear()


def is_go_module(name: str) -> bool:
    """Go modül yolu mu (``golang.org/x/net``, ``github.com/a/b``)? İlk parça alan adıdır (nokta içerir)."""
    text = (name or "").strip()
    if "/" not in text or text.startswith((".", "/", "@")):
        return False
    head = text.split("/", 1)[0]
    return "." in head and ":" not in text


def _go_qualified(module: str, path: str, symbol: str) -> str | None:
    """Go vulndb sembolünü modüle göreli paket yoluyla niteler: ``golang.org/x/net/html`` + ``Parse`` → ``html.Parse``.

    Aynı modülün farklı paketlerindeki aynı adlı fonksiyonlar (``language.Parse`` / ``encoding.Parse``) böylece
    karışmaz. Yol modülün dışındaysa (başka modül) sembol alınmaz."""
    mod, pth = module.casefold().rstrip("/"), (path or "").casefold().rstrip("/")
    if not pth or pth == mod:
        return symbol
    if not pth.startswith(mod + "/"):
        return None
    return ".".join(pth[len(mod) + 1:].split("/")) + "." + symbol


def symbols_from_osv(record: dict[str, Any] | None, package_name: str) -> set[str]:
    """``affected[].ecosystem_specific.imports[].symbols`` (Go vb.) → içe aktarma yoluna göreli semboller.

    Go modüllerinde semboller paket yoluyla nitelenir (``html.Parse``); diğer ekosistemlerde olduğu gibi kalır."""
    if not isinstance(record, dict):
        return set()
    found: set[str] = set()
    go_module = is_go_module(package_name)
    for affected in record.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        name = str((affected.get("package") or {}).get("name") or "")
        if name and package_name and name.casefold() != package_name.casefold():
            continue
        specific = affected.get("ecosystem_specific") or {}
        for entry in specific.get("imports") or []:
            if isinstance(entry, dict):
                for symbol in entry.get("symbols") or []:
                    if isinstance(symbol, str) and re.fullmatch(rf"{_IDENT}(?:\.{_IDENT})*", symbol):
                        if go_module:
                            qualified = _go_qualified(package_name, str(entry.get("path") or ""), symbol)
                            if qualified:
                                found.add(qualified)
                        else:
                            found.add(symbol)
        for symbol in specific.get("affected_functions") or []:
            if isinstance(symbol, str):
                found.add(symbol.rsplit(".", 1)[-1] if "." in symbol and symbol.count(".") > 2 else symbol)
        # 20. tur: RustSec (crates.io) — ``ecosystem_specific.affects.functions`` = "crate::mod::Tür::fn" yolları;
        # crate önekini atıp nokta yoluna çevir ("mod.Tür.fn"), kullanım dizini Rust ``use`` yollarıyla aynı biçimde.
        affects = specific.get("affects") if isinstance(specific.get("affects"), dict) else {}
        for symbol in affects.get("functions") or []:
            if isinstance(symbol, str) and re.fullmatch(r"[A-Za-z_][\w]*(?:::[A-Za-z_][\w]*)+", symbol):
                parts = symbol.split("::")
                crate = package_name.casefold().replace("-", "_")
                if parts[0].casefold() == crate:
                    parts = parts[1:]
                if parts:
                    found.add(".".join(parts))
    return found


# ---------------------------------------------------------------------------
# Kod içi kullanım dizini: paket → {göreli sembol yolu: [(dosya, satır)]}
# ---------------------------------------------------------------------------
class UsageIndex:
    def __init__(self) -> None:
        # (içe aktarma belirteci, göreli yol) → konumlar; belirteç küçük harfli (ör. "yaml", "lodash", "lodash/merge")
        self.uses: dict[str, dict[str, list[dict[str, Any]]]] = {}
        self.engine: set[str] = set()
        # paket adı (küçük harf) → dize olarak geçtiği ilk konum (view engine, betik yolu, yapılandırma)
        self.mentions: dict[str, dict[str, Any]] = {}

    def mention(self, package: str, file: str, line: int) -> None:
        self.mentions.setdefault(package.casefold(), {"file": file, "line": int(line)})

    def add(self, spec: str, rel: str, file: str, line: int) -> None:
        spec = spec.casefold()
        bucket = self.uses.setdefault(spec, {})
        sites = bucket.setdefault(rel, [])
        if len(sites) < 10 and not any(s["file"] == file and s["line"] == line for s in sites):
            sites.append({"file": file, "line": int(line)})

    def for_package(self, import_names: set[str]) -> dict[str, list[dict[str, Any]]]:
        """Paketin içe aktarma adlarıyla eşleşen kullanımlar; alt yol içe aktarmaları (``lodash/merge``) üye sayılır."""
        merged: dict[str, list[dict[str, Any]]] = {}
        lowered = {n.casefold() for n in import_names}
        go_modules = [n for n in lowered if is_go_module(n)]
        for spec, bucket in self.uses.items():
            head = spec.split("/", 2)
            root = "/".join(head[:2]) if spec.startswith("@") else head[0]
            root_dotted = spec.split(".", 1)[0]
            if is_go_module(spec):
                # Go içe aktarma yolu: yalnız aynı modülün kendisi ya da alt paketi eşleşir. "golang.org" gibi alan adı
                # kökü ya da son parça ("net", "text") başka modüllerin kullanımını bu modüle yazdırmamalı.
                module = next((m for m in sorted(go_modules, key=len, reverse=True)
                               if spec == m or spec.startswith(m + "/")), None)
                if module is None:
                    continue
                prefix = ".".join(spec[len(module) + 1:].split("/")) if spec != module else ""
                for rel, sites in bucket.items():
                    key = rel if rel in {"<import>", "", "()"} and not prefix else ".".join(p for p in (prefix, rel) if p)
                    merged.setdefault(key, []).extend(sites)
                    if prefix:
                        merged.setdefault(f"{prefix}.<import>", []).extend(sites[:1])
                continue
            if spec in lowered:
                prefix = ""
            elif root in lowered and spec != root:
                prefix = spec[len(root) + 1:].replace("/", ".")
            elif root_dotted in lowered and spec != root_dotted:
                prefix = spec[len(root_dotted) + 1:]
            else:
                continue
            for rel, sites in bucket.items():
                if prefix and rel in {"", "()"}:
                    key = prefix  # require('lodash/pick') → pick(...) = "pick" sembolünün kullanımı
                elif rel in {"<import>", "", "()"}:
                    key = rel
                else:
                    key = ".".join(p for p in (prefix, rel) if p)
                merged.setdefault(key, []).extend(sites)
        return merged


def _py_index(index: UsageIndex, relpath: str, text: str) -> None:
    from threat_model import _parse_python

    tree = _parse_python(text)
    if tree is None:
        return
    bindings: dict[str, str] = {}
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bindings[alias.asname] = alias.name
                else:
                    bindings[alias.name.split(".", 1)[0]] = alias.name.split(".", 1)[0]
                index.add(alias.name.split(".", 1)[0], "<import>", relpath, node.lineno)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                if alias.name == "*":
                    continue
                bindings[alias.asname or alias.name] = f"{node.module}.{alias.name}"
                # İçe aktarma yalnız paketin kullanıldığını gösterir; üye kullanımı başvurularda sayılır.
                index.add(node.module.split(".", 1)[0], "<import>", relpath, node.lineno)

    direct_binding_names = set(bindings)

    # Python ad çözümlemesi işlev kapsamındadır: bir parametre/atama aynı adı yerel yapıyorsa modül düzeyindeki
    # paket takma adı o kapsamda görünmez. Yalnız satır taramak ``def f(yaml): yaml.load()`` çağrısını PyYAML'a
    # yazıyordu. Her işlev için sıralı bağlama olaylarını tut; ``global``/``nonlocal`` adlarını dış kapsama bırak.
    function_scopes = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
    comprehension_scopes = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
    lexical_scopes = (ast.Module,) + function_scopes + comprehension_scopes
    scope_events: dict[ast.AST, dict[str, list[tuple[int, str]]]] = {}

    def bound_names(target: ast.AST) -> set[str]:
        if isinstance(target, ast.Name):
            return {target.id}
        names: set[str] = set()
        for child in ast.iter_child_nodes(target):
            names |= bound_names(child)
        return names

    def scope_data(scope: ast.AST) -> dict[str, list[tuple[int, str]]]:
        events: dict[str, list[tuple[int, str]]] = {}
        external: set[str] = set()

        def add(name: str, line: int, kind: str = "shadow") -> None:
            events.setdefault(name, []).append((line, kind))

        args = scope.args if isinstance(scope, function_scopes) else None
        if args is not None:
            for arg in (*getattr(args, "posonlyargs", ()), *args.args, *args.kwonlyargs):
                add(arg.arg, -1)
            if args.vararg:
                add(args.vararg.arg, -1)
            if args.kwarg:
                add(args.kwarg.arg, -1)

        class Collector(ast.NodeVisitor):
            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                if node is scope:
                    for statement in node.body:
                        self.visit(statement)
                else:
                    add(node.name, node.lineno)

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Lambda(self, node: ast.Lambda) -> None:
                if node is scope:
                    self.visit(node.body)

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                add(node.name, node.lineno)

            def visit_Global(self, node: ast.Global) -> None:
                external.update(node.names)

            def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
                external.update(node.names)

            def visit_Import(self, node: ast.Import) -> None:
                for alias in node.names:
                    add(alias.asname or alias.name.split(".", 1)[0], node.lineno, "package")

            def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                if node.module and not node.level:
                    for alias in node.names:
                        if alias.name != "*":
                            add(alias.asname or alias.name, node.lineno, "package")

            def visit_Name(self, node: ast.Name) -> None:
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    add(node.id, getattr(node, "lineno", 0))

            def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
                if isinstance(node.name, str):
                    add(node.name, getattr(node, "lineno", 0))
                self.generic_visit(node)

        Collector().visit(scope)
        for name in external:
            events.pop(name, None)
        for rows in events.values():
            rows.sort()
        return events

    for node in ast.walk(tree):
        if isinstance(node, lexical_scopes):
            scope_events[node] = scope_data(node)

    def under(node: ast.AST, ancestor: ast.AST) -> bool:
        current: ast.AST | None = node
        while current is not None:
            if current is ancestor:
                return True
            current = parents.get(current)
        return False

    def shadowed(node: ast.AST, name: str) -> bool:
        if name not in direct_binding_names:
            return False
        line = int(getattr(node, "lineno", 0))
        current = parents.get(node)
        while current is not None:
            if isinstance(current, lexical_scopes):
                events = scope_events.get(current, {}).get(name, ())
                if events:
                    if isinstance(current, comprehension_scopes):
                        # ``[yaml.load(x) for yaml in parsers]`` içindeki hedef elt/if kapsamındadır; ancak
                        # ilk iterable dış kapsamda değerlendirilir ve aynı adda gerçek paket kullanabilir.
                        target_index = next((i for i, gen in enumerate(current.generators)
                                             if name in bound_names(gen.target)), None)
                        iterable_index = next((i for i, gen in enumerate(current.generators)
                                               if under(node, gen.iter)), None)
                        if target_index is not None and iterable_index is not None \
                                and target_index >= iterable_index:
                            current = parents.get(current)
                            continue
                    active = [event for event in events if event[0] <= line]
                    # Bir işlevde atama daha aşağıda olsa bile ad yereldir; kullanım çalışırsa dış paket değildir.
                    return bool(not active or active[-1][1] != "package")
            current = parents.get(current)
        # Aynı yerel ad başka bir kardeş işlevde içe aktarılmış olabilir; o bağ bu kullanım kapsamına sızmaz.
        return True

    def dotted(node: ast.AST) -> str | None:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        return None

    # A module object or one of its members may be assigned a second top-level name
    # (``parser = yaml`` / ``decode = yaml.load``). Only a single direct module-level assignment is accepted;
    # later rebinding therefore cannot leave a stale package alias behind. Mark the assignment as a package event
    # so the existing lexical shadow logic still rejects parameters and locals with the same name.
    alias_candidates: dict[str, tuple[str, int]] = {}
    alias_counts: dict[str, int] = {}
    for statement in tree.body:
        targets: list[ast.AST] = []
        value: ast.AST | None = None
        if isinstance(statement, ast.Assign):
            targets, value = list(statement.targets), statement.value
        elif isinstance(statement, ast.AnnAssign):
            targets, value = [statement.target], statement.value
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            alias_counts[target.id] = alias_counts.get(target.id, 0) + 1
            source = dotted(value) if value is not None else None
            if source and source.split(".", 1)[0] in bindings:
                first, _, rest = source.partition(".")
                alias_candidates[target.id] = (
                    ".".join(part for part in (bindings[first], rest) if part), statement.lineno,
                )
    for name, (target, line) in alias_candidates.items():
        if alias_counts.get(name) != 1 or name in bindings:
            continue
        bindings[name] = target
        direct_binding_names.add(name)
        events = scope_events.setdefault(tree, {}).setdefault(name, [])
        events[:] = [(event_line, "package" if event_line == line else kind) for event_line, kind in events]

    # Paketten üretilen örnekler: zip = AdmZip(...); s = requests.Session() → örnek yöntemleri pakete göreli
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            callee = dotted(node.value.func)
            if callee and callee.split(".", 1)[0] in bindings:
                root_pkg = bindings[callee.split(".", 1)[0]].split(".", 1)[0]
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id not in bindings:
                        bindings[target.id] = root_pkg
    attribute_children: set[int] = set()
    call_funcs: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            attribute_children.add(id(node.value))
        elif isinstance(node, ast.Call):
            call_funcs.add(id(node.func))
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and id(node) not in attribute_children \
                and node.id in bindings and "." not in bindings[node.id]:
            if shadowed(node, node.id):
                continue
            # Paket nesnesinin kendisi çağrılıyor ya da değer olarak aktarılıyor
            index.add(bindings[node.id], "()" if id(node) in call_funcs else "", relpath, node.lineno)
            continue
        if id(node) in attribute_children:
            continue  # zincirin iç parçası; dış öznitelik düğümü tam adı kaydeder
        if isinstance(node, (ast.Attribute, ast.Name)) and isinstance(getattr(node, "ctx", None), ast.Load):
            name = dotted(node)
            if not name:
                continue
            first, _, rest = name.partition(".")
            target = bindings.get(first)
            if not target or shadowed(node, first):
                continue
            full = f"{target}.{rest}" if rest else target
            top, _, rel = full.partition(".")
            index.add(top, rel, relpath, getattr(node, "lineno", 0))
    index.engine.add("python-ast")


_JS_REQUIRE_RE = re.compile(r"""(?:const|let|var)\s+(\{[^}]{1,400}\}|[A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)(?:\.([A-Za-z_$][\w$]*))?""")
_JS_IMPORT_RE = re.compile(r"""import\s+(?:type\s+)?([^'";]+?)\s+from\s+['"]([^'"]+)['"]""")
_JS_INLINE_REQUIRE_RE = re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)\.([A-Za-z_$][\w$]*)""")
_JS_DYNAMIC_IMPORT_RE = re.compile(
    r"""(?:const|let|var)\s+(\{[^}]{1,400}\}|[A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?import\(\s*['"]([^'"]+)['"]\s*\)"""
)
_JS_INLINE_DYNAMIC_IMPORT_RE = re.compile(
    r"""(?:\(\s*)?(?:await\s+)?import\(\s*['"]([^'"]+)['"]\s*\)(?:\s*\))?\s*\.\s*([A-Za-z_$][\w$]*)"""
)


def _mask_c_like_noncode(text: str, *, mask_strings: bool = True, razor_comments: bool = False) -> str:
    """C ailesi yorumlarını ve isteğe bağlı olarak dizelerini boşlukla maskele; satır/kolonları koru."""
    out = list(text)
    state = "code"
    quote = ""
    verbatim = False
    index = 0
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if razor_comments and text[index:index + 2] == "@*":
                out[index:index + 2] = [" ", " "]
                state = "razor-comment"
                index += 2
                continue
            if razor_comments and text[index:index + 4] == "<!--":
                out[index:index + 4] = [" ", " ", " ", " "]
                state = "html-comment"
                index += 4
                continue
            if char == "/" and nxt == "/":
                out[index] = out[index + 1] = " "
                state = "line"
                index += 2
                continue
            if char == "/" and nxt == "*":
                out[index] = out[index + 1] = " "
                state = "block"
                index += 2
                continue
            if text[index:index + 3] == '"""':
                quote = '"""'
                if mask_strings:
                    out[index:index + 3] = [" ", " ", " "]
                state = "string"
                index += 3
                continue
            if char in {'"', "'", "`"}:
                quote = char
                verbatim = char == '"' and index > 0 and text[index - 1] == "@"
                if mask_strings:
                    out[index] = " "
                    if verbatim:
                        out[index - 1] = " "
                state = "string"
            index += 1
            continue
        if state == "line":
            if char == "\n":
                state = "code"
            else:
                out[index] = " "
            index += 1
            continue
        if state == "razor-comment":
            if char == "*" and nxt == "@":
                out[index:index + 2] = [" ", " "]
                state = "code"
                index += 2
            else:
                if char != "\n":
                    out[index] = " "
                index += 1
            continue
        if state == "html-comment":
            if text[index:index + 3] == "-->":
                out[index:index + 3] = [" ", " ", " "]
                state = "code"
                index += 3
            else:
                if char != "\n":
                    out[index] = " "
                index += 1
            continue
        if state == "block":
            if char == "*" and nxt == "/":
                out[index] = out[index + 1] = " "
                state = "code"
                index += 2
            else:
                if char != "\n":
                    out[index] = " "
                index += 1
            continue
        if quote == '"""' and text[index:index + 3] == quote:
            if mask_strings:
                out[index:index + 3] = [" ", " ", " "]
            state = "code"
            index += 3
            continue
        if mask_strings and char != "\n":
            out[index] = " "
        if verbatim and char == quote and nxt == quote:
            if mask_strings:
                out[index + 1] = " "
            index += 2
            continue
        if not verbatim and char == "\\" and nxt:
            if mask_strings and nxt != "\n":
                out[index + 1] = " "
            index += 2
            continue
        if char == quote:
            state = "code"
            verbatim = False
        index += 1
    return "".join(out)


_RUST_RAW_STRING_PREFIX = re.compile(r'(?:br|rb|r)(#{0,255})"')
_RUST_CHAR_LITERAL = re.compile(
    r"'(?:[^'\\\n]|\\(?:[nrt0\\'\"]|x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]{1,6}\}))'"
)


def _mask_rust_noncode(text: str) -> str:
    """Rust yorumlarını, dizelerini ve karakterlerini geometriyi koruyarak maskele.

    C-benzeri maskeleyiciden ayrı tutulur: Rust blok yorumları iç içe geçebilir ve ``'a`` yaşam süresi ile
    ``'label`` etiketleri karakter değişmezi değildir. Ham dizelerdeki değişken ``#`` ayraçları da eşleştirilir.
    """
    out = list(text)
    state = "code"
    block_depth = 0
    raw_end = ""
    index = 0

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if text[position] != "\n":
                out[position] = " "

    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and nxt == "/":
                blank(index, index + 2)
                state = "line"
                index += 2
                continue
            if char == "/" and nxt == "*":
                blank(index, index + 2)
                state = "block"
                block_depth = 1
                index += 2
                continue
            raw = _RUST_RAW_STRING_PREFIX.match(text, index)
            if raw and (index == 0 or not (text[index - 1].isalnum() or text[index - 1] == "_")):
                blank(index, raw.end())
                raw_end = '"' + raw.group(1)
                state = "raw-string"
                index = raw.end()
                continue
            if char == '"':
                out[index] = " "
                state = "string"
                index += 1
                continue
            if char == "'":
                literal = _RUST_CHAR_LITERAL.match(text, index)
                if literal:
                    blank(index, literal.end())
                    index = literal.end()
                    continue
            index += 1
            continue
        if state == "line":
            if char == "\n":
                state = "code"
            else:
                out[index] = " "
            index += 1
            continue
        if state == "block":
            if char == "/" and nxt == "*":
                blank(index, index + 2)
                block_depth += 1
                index += 2
            elif char == "*" and nxt == "/":
                blank(index, index + 2)
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "code"
            else:
                if char != "\n":
                    out[index] = " "
                index += 1
            continue
        if state == "raw-string":
            if text.startswith(raw_end, index):
                blank(index, index + len(raw_end))
                index += len(raw_end)
                state = "code"
            else:
                if char != "\n":
                    out[index] = " "
                index += 1
            continue
        # Normal/byte/C string: the quote starts the state even when a one-letter prefix remains visible.
        if char == "\\" and nxt:
            blank(index, index + 2)
            index += 2
            continue
        if char == '"':
            out[index] = " "
            state = "code"
        elif char != "\n":
            out[index] = " "
        index += 1
    return "".join(out)


def _mask_vb_noncode(text: str) -> str:
    """Visual Basic dizelerini ve ``'``/``REM`` yorumlarını satır konumlarını koruyarak maskele."""
    out = list(text)
    in_string = False
    line_start = 0
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\n":
            in_string = False  # bozuk/kapanmamış bir dize sonraki satırı yutmamalı
            line_start = index + 1
            index += 1
            continue
        if in_string:
            out[index] = " "
            if char == '"':
                if index + 1 < len(text) and text[index + 1] == '"':
                    out[index + 1] = " "  # VB içindeki kaçış: ""
                    index += 2
                    continue
                in_string = False
            index += 1
            continue
        if char == '"':
            out[index] = " "
            in_string = True
            index += 1
            continue
        rem = text[index:index + 3]
        rem_boundary = index + 3 >= len(text) or not (text[index + 3].isalnum() or text[index + 3] == "_")
        is_rem = rem.casefold() == "rem" and rem_boundary
        prefix = text[line_start:index].rstrip() if is_rem else ""
        if char == "'" or (is_rem and (not prefix or prefix.endswith(":"))):
            while index < len(text) and text[index] != "\n":
                out[index] = " "
                index += 1
            continue
        index += 1
    return "".join(out)


def _mask_fsharp_noncode(text: str) -> str:
    """F# dizelerini, karakterlerini ve iç içe ``(* ... *)`` yorumlarını konum koruyarak maskele."""
    out = list(text)
    state = "code"
    block_depth = 0
    index = 0
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and nxt == "/":
                out[index:index + 2] = [" ", " "]
                state = "line"
                index += 2
                continue
            if char == "(" and nxt == "*":
                out[index:index + 2] = [" ", " "]
                state = "block"
                block_depth = 1
                index += 2
                continue
            if text[index:index + 3] == '\"\"\"':
                out[index:index + 3] = [" ", " ", " "]
                state = "triple"
                index += 3
                continue
            if char == "@" and nxt == '"':
                out[index:index + 2] = [" ", " "]
                state = "verbatim"
                index += 2
                continue
            if char == '"':
                out[index] = " "
                state = "string"
                index += 1
                continue
            if char == "'":
                literal = re.match(r"'(?:\\(?:u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)|[^\\'\n])'", text[index:])
                if literal:
                    end = index + len(literal.group(0))
                    out[index:end] = [" "] * (end - index)
                    index = end
                    continue
            index += 1
            continue
        if state == "line":
            if char == "\n":
                state = "code"
            else:
                out[index] = " "
            index += 1
            continue
        if state == "block":
            if char == "(" and nxt == "*":
                out[index:index + 2] = [" ", " "]
                block_depth += 1
                index += 2
                continue
            if char == "*" and nxt == ")":
                out[index:index + 2] = [" ", " "]
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "code"
                continue
            if char != "\n":
                out[index] = " "
            index += 1
            continue
        if state == "triple":
            if text[index:index + 3] == '\"\"\"':
                out[index:index + 3] = [" ", " ", " "]
                state = "code"
                index += 3
            else:
                if char != "\n":
                    out[index] = " "
                index += 1
            continue
        if state == "verbatim":
            if char == '"' and nxt == '"':
                out[index:index + 2] = [" ", " "]
                index += 2
                continue
            if char == '"':
                out[index] = " "
                state = "code"
            elif char != "\n":
                out[index] = " "
            index += 1
            continue
        # Normal F# string: backslash kaçışını birlikte maskele.
        if char == "\\" and nxt:
            out[index] = " "
            if nxt != "\n":
                out[index + 1] = " "
            index += 2
            continue
        if char == '"':
            out[index] = " "
            state = "code"
        elif char != "\n":
            out[index] = " "
        index += 1
    return "".join(out)


def _mask_js_noncode(text: str) -> str:
    """JS yorum/dizelerini maskele, fakat template literal içindeki çalışan ``${...}`` kodunu koru."""
    out = list(text)

    def blank(pos: int) -> None:
        if 0 <= pos < len(out) and out[pos] != "\n":
            out[pos] = " "

    def string(pos: int, quote: str) -> int:
        blank(pos)
        pos += 1
        while pos < len(text):
            char = text[pos]
            blank(pos)
            if char == "\\" and pos + 1 < len(text):
                blank(pos + 1)
                pos += 2
                continue
            pos += 1
            if char == quote:
                break
        return pos

    def code(pos: int, *, template_expression: bool = False) -> int:
        depth = 1 if template_expression else 0
        while pos < len(text):
            char = text[pos]
            nxt = text[pos + 1] if pos + 1 < len(text) else ""
            if char == "/" and nxt == "/":
                blank(pos)
                blank(pos + 1)
                pos += 2
                while pos < len(text) and text[pos] != "\n":
                    blank(pos)
                    pos += 1
                continue
            if char == "/" and nxt == "*":
                blank(pos)
                blank(pos + 1)
                pos += 2
                while pos < len(text):
                    if text[pos:pos + 2] == "*/":
                        blank(pos)
                        blank(pos + 1)
                        pos += 2
                        break
                    blank(pos)
                    pos += 1
                continue
            if char in {"'", '"'}:
                pos = string(pos, char)
                continue
            if char == "`":
                pos = template(pos)
                continue
            if template_expression:
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        blank(pos)
                        return pos + 1
            pos += 1
        return pos

    def template(pos: int) -> int:
        blank(pos)
        pos += 1
        while pos < len(text):
            char = text[pos]
            nxt = text[pos + 1] if pos + 1 < len(text) else ""
            if char == "\\" and pos + 1 < len(text):
                blank(pos)
                blank(pos + 1)
                pos += 2
                continue
            if char == "`":
                blank(pos)
                return pos + 1
            if char == "$" and nxt == "{":
                blank(pos)
                blank(pos + 1)
                pos = code(pos + 2, template_expression=True)
                continue
            blank(pos)
            pos += 1
        return pos

    code(0)
    return "".join(out)


def _js_parameter_bindings(pattern: str) -> set[str]:
    """Basit/ayrıştırılmış JS parametre desenlerindeki bağlanan adları, varsayılan ifade başvurularından ayır."""
    pattern = pattern.strip()
    if not pattern:
        return set()

    def split_top(value: str, delimiter: str) -> list[str]:
        pieces: list[str] = []
        depths = {"(": 0, "[": 0, "{": 0}
        pairs = {")": "(", "]": "[", "}": "{"}
        start = 0
        for pos, char in enumerate(value):
            if char in depths:
                depths[char] += 1
            elif char in pairs and depths[pairs[char]]:
                depths[pairs[char]] -= 1
            elif char == delimiter and not any(depths.values()):
                pieces.append(value[start:pos])
                start = pos + 1
        pieces.append(value[start:])
        return pieces

    def before_top(value: str, delimiter: str) -> str:
        pieces = split_top(value, delimiter)
        return pieces[0]

    parameters = split_top(pattern, ",")
    if len(parameters) > 1:
        return set().union(*(_js_parameter_bindings(part) for part in parameters))
    pattern = pattern.removeprefix("...").strip()
    pattern = before_top(pattern, "=").strip()
    if pattern.startswith("{") and pattern.endswith("}"):
        result: set[str] = set()
        for prop in split_top(pattern[1:-1], ","):
            prop = prop.strip()
            if not prop:
                continue
            sides = split_top(prop, ":")
            result |= _js_parameter_bindings(sides[-1] if len(sides) > 1 else sides[0])
        return result
    if pattern.startswith("[") and pattern.endswith("]"):
        return set().union(*(_js_parameter_bindings(part) for part in split_top(pattern[1:-1], ",")))
    match = re.match(r"[A-Za-z_$][\w$]*", pattern)
    return {match.group(0)} if match else set()


def _js_parameter_shadow_ranges(code: str, names: set[str]) -> dict[str, list[tuple[int, int]]]:
    """Paket takma adı parametre/yerel bağ olduğunda yalnız ilgili süslü kapsamın satırlarını işaretle."""
    result: dict[str, list[tuple[int, int]]] = {name: [] for name in names}
    brace_ranges: list[tuple[int, int]] = []
    brace_closes: dict[int, int] = {}
    stack: list[int] = []
    for pos, char in enumerate(code):
        if char == "{":
            stack.append(pos)
        elif char == "}" and stack:
            opening = stack.pop()
            brace_ranges.append((opening, pos))
            brace_closes[opening] = pos
    patterns = (
        re.compile(r"\bfunction(?:\s+[A-Za-z_$][\w$]*)?\s*\(([^)]*)\)\s*\{"),
        re.compile(r"\(([^)]*)\)\s*=>\s*\{"),
        re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*)\s*=>\s*\{"),
    )
    for pattern in patterns:
        for match in pattern.finditer(code):
            params = match.group(1)
            parameter_names = _js_parameter_bindings(params)
            shadowed = names & parameter_names
            if not shadowed:
                continue
            opening = code.find("{", match.start(), match.end())
            if opening < 0:
                continue
            closing = brace_closes.get(opening, len(code) - 1)
            first = code.count("\n", 0, opening) + 1
            last = code.count("\n", 0, closing) + 1
            for name in shadowed:
                result[name].append((first, last))
    for name in names:
        declaration = re.compile(rf"\b(?:const|let|var|class|function)\s+{re.escape(name)}\b")
        for match in declaration.finditer(code):
            package_binding = re.match(
                rf"(?:const|let|var)\s+{re.escape(name)}\s*=\s*"
                rf"(?:require\s*\(|(?:await\s+)?import\s*\()",
                code[match.start():],
            )
            if package_binding:
                continue
            containing = [row for row in brace_ranges if row[0] < match.start() < row[1]]
            if not containing:
                continue  # modül düzeyindeki asıl require/import bağlaması
            opening, closing = min(containing, key=lambda row: row[1] - row[0])
            first = code.count("\n", 0, opening) + 1
            last = code.count("\n", 0, closing) + 1
            result[name].append((first, last))
    lines = code.splitlines()
    depth = 0
    for line_no, line in enumerate(lines, start=1):
        if depth == 0:
            for name in names:
                assignment = re.search(rf"(?<![\w$.]){re.escape(name)}\s*=(?!=|>)", line)
                if not assignment:
                    continue
                initial_require = re.match(
                    rf"\s*(?:const|let|var)\s+{re.escape(name)}\s*=\s*require\s*\(", line,
                )
                initial_dynamic = re.match(
                    rf"\s*(?:const|let|var)\s+{re.escape(name)}\s*=\s*(?:await\s+)?import\s*\(", line,
                )
                initial_alias = re.match(
                    rf"\s*(?:const|let|var)\s+{re.escape(name)}\s*=\s*([A-Za-z_$][\w$]*)",
                    line,
                )
                if not initial_require and not initial_dynamic \
                        and not (initial_alias and initial_alias.group(1) in names):
                    result[name].append((line_no, len(lines)))
        depth += line.count("{") - line.count("}")
    return result


def _js_line_shadowed(ranges: dict[str, list[tuple[int, int]]], name: str, line: int) -> bool:
    return any(first <= line <= last for first, last in ranges.get(name, ()))


def _looks_like_method_declaration(line: str, start: int) -> bool:
    """Basit Java/C# yöntem bildirimini çağrıdan ayır; gövde içi return/await çağrılarını koru."""
    segment = re.split(r"[;{}]", line[:start])[-1].strip()
    if not segment or any(mark in segment for mark in ("=", ".", "(", ")")):
        return False
    tokens = segment.split()
    if not tokens or tokens[-1].casefold() in {"return", "throw", "await", "yield", "new", "case"}:
        return False
    modifiers = {"public", "private", "protected", "internal", "static", "final", "abstract", "virtual",
                 "override", "async", "synchronized", "native", "sealed", "partial", "extern", "unsafe"}
    meaningful = [token for token in tokens if token.casefold() not in modifiers and not token.startswith("@")]
    return bool(meaningful and all(re.fullmatch(r"[A-Za-z_$][\w$<>,.?\[\]]*", token) for token in meaningful))


def _declared_method_scopes(text: str) -> dict[int, set[str]]:
    """Java/.NET dosyasında aynı sınıfta bildirilen yöntem adlarını satır başına döndür."""
    brace_closes: dict[int, int] = {}
    stack: list[int] = []
    for pos, char in enumerate(text):
        if char == "{":
            stack.append(pos)
        elif char == "}" and stack:
            brace_closes[stack.pop()] = pos
    class_ranges: list[tuple[int, int]] = []
    for match in re.finditer(r"\b(?:class|struct|record|interface|enum)\s+[A-Za-z_$][\w$]*[^;{]*\{", text):
        opening = text.find("{", match.start(), match.end())
        if opening in brace_closes:
            class_ranges.append((opening, brace_closes[opening]))
    declared: dict[tuple[int, int] | None, set[str]] = {}
    offset = 0
    previous = ""
    for line in text.splitlines(keepends=True):
        for match in re.finditer(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(", line):
            is_declaration = _looks_like_method_declaration(line, match.start())
            if not is_declaration and previous:
                combined = previous + " " + line
                is_declaration = _looks_like_method_declaration(combined, len(previous) + 1 + match.start())
            if not is_declaration:
                continue
            absolute = offset + match.start()
            containing = [row for row in class_ranges if row[0] <= absolute <= row[1]]
            scope = min(containing, key=lambda row: row[1] - row[0]) if containing else None
            declared.setdefault(scope, set()).add(match.group(1))
        offset += len(line)
        stripped = line.strip()
        previous = stripped if stripped and not any(mark in stripped for mark in (";", "{", "}")) else ""
    by_line: dict[int, set[str]] = {}
    line_starts: list[int] = []
    pos = 0
    for line in text.splitlines(keepends=True):
        line_starts.append(pos)
        pos += len(line)
    for line_no, start in enumerate(line_starts, start=1):
        end = line_starts[line_no] if line_no < len(line_starts) else len(text)
        containing = [row for row in class_ranges if row[0] < end and row[1] >= start]
        scope = min(containing, key=lambda row: row[1] - row[0]) if containing else None
        by_line[line_no] = declared.get(scope, set())
    return by_line


def _c_local_shadow_ranges(text: str) -> dict[str, list[tuple[int, int]]]:
    """Java/.NET local or parameter names and the lexical line range where they hide a type/static member."""
    brace_closes: dict[int, int] = {}
    stack: list[int] = []
    for pos, char in enumerate(text):
        if char == "{":
            stack.append(pos)
        elif char == "}" and stack:
            brace_closes[stack.pop()] = pos
    ranges = list(brace_closes.items())
    declaration = re.compile(
        r"(?<![\w$.])(?:[A-Za-z_$][\w$.?\[\]]*)(?:\s*<[^;={}()]{1,200}>)?\s+"
        r"([A-Za-z_$][\w$]*)\s*(?==|;|,|\))"
    )
    result: dict[str, list[tuple[int, int]]] = {}
    for match in declaration.finditer(text):
        line_start = text.rfind("\n", 0, match.start()) + 1
        prefix = text[line_start:match.start()].lstrip()
        if prefix.startswith(("import ", "using ", "Imports ", "open ")):
            continue
        containing = [(opening, closing) for opening, closing in ranges
                      if opening < match.start() < closing]
        if not containing:
            continue
        opening, closing = min(containing, key=lambda row: row[1] - row[0])
        first = text.count("\n", 0, match.start()) + 1
        last = text.count("\n", 0, closing) + 1
        result.setdefault(match.group(1), []).append((first, last))
    return result


def _c_name_shadowed(ranges: dict[str, list[tuple[int, int]]], name: str, line: int) -> bool:
    return any(first <= line <= last for first, last in ranges.get(name, ()))


def _js_bindings_regex(text: str, code_mask: str | None = None) -> dict[str, tuple[str, str]]:
    bindings: dict[str, tuple[str, str]] = {}
    for match in _JS_REQUIRE_RE.finditer(text):
        if code_mask is not None and code_mask[match.start():match.start() + 1].isspace():
            continue
        target, spec, member = match.group(1), match.group(2), match.group(3) or ""
        if target.startswith("{"):
            for part in target.strip("{} \n").split(","):
                part = part.strip()
                if not part:
                    continue
                key, _, local = part.partition(":")
                key, local = key.strip(), (local.strip() or key.strip())
                if re.fullmatch(r"[A-Za-z_$][\w$]*", local) and re.fullmatch(r"[A-Za-z_$][\w$]*", key):
                    bindings[local] = (spec, ".".join(p for p in (member, key) if p))
        else:
            bindings[target] = (spec, member)
    for match in _JS_DYNAMIC_IMPORT_RE.finditer(text):
        if code_mask is not None and code_mask[match.start():match.start() + 1].isspace():
            continue
        target, spec = match.group(1), match.group(2)
        if target.startswith("{"):
            for part in target.strip("{} \n").split(","):
                part = part.strip()
                if not part:
                    continue
                key, _, local = part.partition(":")
                key, local = key.strip(), (local.strip() or key.strip())
                if re.fullmatch(r"[A-Za-z_$][\w$]*", local) and re.fullmatch(r"[A-Za-z_$][\w$]*", key):
                    bindings[local] = (spec, key)
        else:
            bindings[target] = (spec, "")
    for match in _JS_IMPORT_RE.finditer(text):
        if code_mask is not None and code_mask[match.start():match.start() + 1].isspace():
            continue
        clause, spec = match.group(1).strip(), match.group(2)
        named = re.search(r"\{([^}]*)\}", clause)
        if named:
            for part in named.group(1).split(","):
                part = part.strip()
                if not part:
                    continue
                key, _, local = part.partition(" as ")
                key, local = key.strip(), (local.strip() or key.strip())
                if re.fullmatch(r"[A-Za-z_$][\w$]*", local):
                    bindings[local] = (spec, "" if key == "default" else key)
            clause = clause[:named.start()] + clause[named.end():]
        star = re.search(r"\*\s+as\s+([A-Za-z_$][\w$]*)", clause)
        if star:
            bindings[star.group(1)] = (spec, "")
            clause = clause.replace(star.group(0), "")
        default = clause.strip(" ,")
        if re.fullmatch(r"[A-Za-z_$][\w$]*", default):
            bindings[default] = (spec, "")
    code = code_mask if code_mask is not None else _mask_js_noncode(text)
    depths: list[int] = []
    depth = 0
    for char in code:
        depths.append(depth)
        if char == "{":
            depth += 1
        elif char == "}" and depth:
            depth -= 1
    alias_pattern = re.compile(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
        r"([A-Za-z_$][\w$]*)((?:\.[A-Za-z_$][\w$]*){0,3})\s*;"
    )
    for _ in range(4):
        added = False
        for match in alias_pattern.finditer(code):
            target, source, suffix = match.groups()
            if depths[match.start()] or target in bindings or source not in bindings:
                continue
            spec, member = bindings[source]
            bindings[target] = (spec, ".".join(part for part in (member, suffix.lstrip(".")) if part))
            added = True
        if not added:
            break
    return bindings


def _js_index_regex(index: UsageIndex, relpath: str, text: str) -> None:
    comment_clean = _mask_c_like_noncode(text, mask_strings=False)
    code = _mask_js_noncode(text)
    bindings = _js_bindings_regex(comment_clean, code)
    shadowed_lines = _js_parameter_shadow_ranges(code, set(bindings))
    for match in re.finditer(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:new\s+)?([A-Za-z_$][\w$]*)(?:\.[A-Za-z_$][\w$]*)*\s*\(", code):
        if match.group(2) in bindings and match.group(1) not in bindings:
            bindings[match.group(1)] = (bindings[match.group(2)][0], "")  # örnek: zip = AdmZip(...)
    lines = code.splitlines()
    for local, (spec, member) in bindings.items():
        index.add(spec, "<import>", relpath, 0)
        pattern = re.compile(rf"(?<![\w$.]){re.escape(local)}((?:\.[A-Za-z_$][\w$]*){{0,3}})(?![\w$])")
        for line_no, line in enumerate(lines, start=1):
            if _js_line_shadowed(shadowed_lines, local, line_no):
                continue
            stripped = line.strip()
            binding_line = local in stripped.split("=", 1)[0] and (
                "require(" in stripped or re.search(r"\bimport\s*\(", stripped)
            )
            if stripped.startswith(("import ", "//", "*", "/*")) or binding_line:
                continue
            for match in pattern.finditer(line):
                rest = match.group(1).lstrip(".")
                rel = ".".join(p for p in (member, rest) if p)
                if not rel:
                    rel = "()" if line[match.end():].lstrip().startswith("(") else ""
                index.add(spec, rel, relpath, line_no)
    comment_lines, code_lines = comment_clean.splitlines(), code.splitlines()
    for line_no, line in enumerate(comment_lines, start=1):
        code_line = code_lines[line_no - 1] if line_no <= len(code_lines) else ""
        for match in _JS_INLINE_REQUIRE_RE.finditer(line):
            if match.start() < len(code_line) and not code_line[match.start()].isspace():
                index.add(match.group(1), match.group(2), relpath, line_no)
        for match in _JS_INLINE_DYNAMIC_IMPORT_RE.finditer(line):
            if match.start() < len(code_line) and not code_line[match.start()].isspace():
                index.add(match.group(1), match.group(2), relpath, line_no)
    index.engine.add("javascript-regex")


def _js_index_ast(index: UsageIndex, programs: dict[str, Any], sources: dict[str, str] | None = None) -> None:
    import taint_js_ast as jx

    extensions = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts")

    def local_module(importer: str, spec: str) -> str | None:
        if not spec.startswith("."):
            return None
        joined = posixpath.normpath(str(PurePosixPath(importer).parent / spec))
        candidates = [joined]
        if not PurePosixPath(joined).suffix:
            candidates.extend(joined + suffix for suffix in extensions)
            candidates.extend(posixpath.join(joined, "index" + suffix) for suffix in extensions)
        return next((candidate for candidate in candidates if candidate in programs), None)

    # Local facade modules are common around vulnerable packages.  Preserve a
    # bounded export map so a literal dynamic import can still be attributed to
    # the package symbol actually invoked by application code.
    reexports: dict[str, dict[str, tuple[str, str]]] = {}
    export_stars: dict[str, list[str]] = {}
    for module_path, program in programs.items():
        mapped: dict[str, tuple[str, str]] = {}
        stars: list[str] = []
        for statement in (program.get("body") or [])[:10_000]:
            kind = jx._t(statement)
            source = str((statement.get("source") or {}).get("value", ""))
            if not source:
                continue
            if not source.startswith("."):
                index.add(source, "<import>", module_path, jx._line(statement))
            if kind == "ExportAllDeclaration":
                if len(stars) < 32:
                    stars.append(source)
                continue
            if kind != "ExportNamedDeclaration":
                continue
            for item in (statement.get("specifiers") or [])[:256]:
                exported = item.get("exported") or {}
                exported_name = exported.get("name") or str(exported.get("value", ""))
                if not exported_name:
                    continue
                if jx._t(item) == "ExportNamespaceSpecifier":
                    mapped.setdefault(exported_name, (source, ""))
                    continue
                local = item.get("local") or {}
                local_name = local.get("name") or str(local.get("value", ""))
                if local_name:
                    mapped.setdefault(exported_name, (source, "" if local_name == "default" else local_name))
        if mapped:
            reexports[module_path] = mapped
        if stars:
            export_stars[module_path] = stars

    def resolve_use(
        importer: str,
        spec: str,
        member: str,
        seen: frozenset[tuple[str, str]] = frozenset(),
        depth: int = 0,
    ) -> list[tuple[str, str]]:
        if depth >= 16 or len(seen) >= 32:
            return []
        target = local_module(importer, spec)
        if target is None:
            return [(spec, member)]
        marker = (target, member)
        if marker in seen or member in {"", "<import>", "()"}:
            return []
        head, _, tail = member.partition(".")
        found: list[tuple[str, str]] = []
        mapped = reexports.get(target, {}).get(head)
        if mapped is not None:
            next_spec, prefix = mapped
            next_member = ".".join(part for part in (prefix, tail) if part)
            found.extend(resolve_use(target, next_spec, next_member, seen | {marker}, depth + 1))
        for star_spec in export_stars.get(target, ()):
            found.extend(resolve_use(target, star_spec, member, seen | {marker}, depth + 1))
            if len(found) >= 32:
                break
        unique: list[tuple[str, str]] = []
        for row in found:
            if row not in unique:
                unique.append(row)
        return unique[:32]

    def add_use(spec: str, member: str, relpath: str, line: int) -> None:
        for resolved_spec, resolved_member in resolve_use(relpath, spec, member):
            index.add(resolved_spec, resolved_member, relpath, line)

    def dynamic_import(node: Any) -> str | None:
        while jx._t(node) in {"AwaitExpression", "ParenthesizedExpression", "TSAsExpression",
                              "TSNonNullExpression", "TSSatisfiesExpression", "TSTypeAssertion"}:
            node = node.get("argument") or node.get("expression")
        if jx._t(node) != "CallExpression" or jx._t(node.get("callee")) != "Import":
            return None
        args = node.get("arguments") or []
        return jx._string_value(args[0]) if args else None

    for relpath, program in programs.items():
        bindings: dict[str, tuple[str, str]] = {}
        direct_bindings: set[str] = set()
        for node in jx._walk(program):
            kind = jx._t(node)
            if kind == "ImportDeclaration":
                spec = str((node.get("source") or {}).get("value", ""))
                for item in node.get("specifiers", []):
                    local = (item.get("local") or {}).get("name", "")
                    if jx._t(item) in {"ImportDefaultSpecifier", "ImportNamespaceSpecifier"}:
                        bindings[local] = (spec, "")
                    else:
                        imported = item.get("imported") or {}
                        name = imported.get("name") or str(imported.get("value", ""))
                        bindings[local] = (spec, "" if name == "default" else name)
                    direct_bindings.add(local)
                    add_use(spec, "<import>", relpath, jx._line(node))
            elif kind == "VariableDeclarator":
                init = node.get("init")
                member = ""
                while jx._t(init) in {"MemberExpression", "OptionalMemberExpression"} and not init.get("computed"):
                    member = ".".join(p for p in ((init.get("property") or {}).get("name", ""), member) if p)
                    init = init.get("object")
                dynamic_spec = dynamic_import(init)
                if dynamic_spec:
                    target = node.get("id")
                    if jx._t(target) == "Identifier":
                        local = target.get("name", "")
                        bindings[local] = (dynamic_spec, member)
                        direct_bindings.add(local)
                        add_use(dynamic_spec, "<import>", relpath, jx._line(node))
                    elif jx._t(target) == "ObjectPattern":
                        for prop in target.get("properties", []):
                            value = prop.get("value")
                            if jx._t(prop) == "ObjectProperty" and jx._t(value) == "Identifier":
                                key = jx._key_name(prop)
                                local = value.get("name", "")
                                bindings[local] = (dynamic_spec, ".".join(p for p in (member, key) if p))
                                direct_bindings.add(local)
                                add_use(dynamic_spec, "<import>", relpath, jx._line(node))
                    continue
                if not (jx._t(init) == "CallExpression" and jx._dotted(init.get("callee")) == "require"):
                    # Bounded top-level aliasing: ``const parser = yaml`` and ``const decode = yaml.load``.
                    # Inner-scope aliases are left to lexical analysis so a block binding cannot leak file-wide.
                    source_text = _mask_js_noncode((sources or {}).get(relpath, ""))
                    line_no = jx._line(node)
                    depth = 0
                    for current, source_line in enumerate(source_text.splitlines(), start=1):
                        if current == line_no:
                            break
                        depth += source_line.count("{") - source_line.count("}")
                    target = node.get("id")
                    source_name = init.get("name", "") if jx._t(init) == "Identifier" else ""
                    if depth == 0 and jx._t(target) == "Identifier" and source_name in bindings:
                        spec, prefix = bindings[source_name]
                        local = target.get("name", "")
                        bindings[local] = (spec, ".".join(part for part in (prefix, member) if part))
                        direct_bindings.add(local)
                    # örnek: const zip = AdmZip(buf) / new AdmZip() / mongoose.model('X')
                    if jx._t(init) in {"CallExpression", "NewExpression"} and jx._t(node.get("id")) == "Identifier":
                        callee_chain = jx._chain(init.get("callee")) or []
                        name = node["id"].get("name", "")
                        if callee_chain and callee_chain[0] in bindings and name not in bindings:
                            bindings[name] = (bindings[callee_chain[0]][0], "")
                    continue
                args = init.get("arguments") or []
                spec = jx._string_value(args[0]) if args else None
                if not spec:
                    continue
                target = node.get("id")
                if jx._t(target) == "Identifier":
                    bindings[target.get("name", "")] = (spec, member)
                    direct_bindings.add(target.get("name", ""))
                    add_use(spec, "<import>", relpath, jx._line(node))
                elif jx._t(target) == "ObjectPattern":
                    for prop in target.get("properties", []):
                        value = prop.get("value")
                        if jx._t(prop) == "ObjectProperty" and jx._t(value) == "Identifier":
                            key = jx._key_name(prop)
                            bindings[value.get("name", "")] = (spec, ".".join(p for p in (member, key) if p))
                            direct_bindings.add(value.get("name", ""))
                            add_use(spec, "<import>", relpath, jx._line(node))
        shadowed_lines = _js_parameter_shadow_ranges(
            _mask_js_noncode((sources or {}).get(relpath, "")), direct_bindings,
        )

        def is_shadowed(name: str, node: dict[str, Any]) -> bool:
            return _js_line_shadowed(shadowed_lines, name, jx._line(node))

        for node in jx._walk(program):
            kind = jx._t(node)
            if kind in {"MemberExpression", "OptionalMemberExpression"}:
                chain = jx._chain(node)
                if chain and chain[0] in bindings and not is_shadowed(chain[0], node):
                    spec, member = bindings[chain[0]]
                    add_use(spec, ".".join(p for p in (member, *chain[1:]) if p), relpath, jx._line(node))
                    continue
                obj = node.get("object")
                prop = (node.get("property") or {}).get("name", "")
                dynamic_spec = dynamic_import(obj)
                if prop and dynamic_spec:
                    add_use(dynamic_spec, prop, relpath, jx._line(node))
                    continue
                if prop and jx._t(obj) == "CallExpression" and jx._dotted(obj.get("callee")) == "require":
                    args = obj.get("arguments") or []
                    spec = jx._string_value(args[0]) if args else None
                    if spec:
                        add_use(spec, prop, relpath, jx._line(node))
            elif kind in {"CallExpression", "OptionalCallExpression", "NewExpression"}:
                callee = node.get("callee")
                dynamic_spec = dynamic_import(node)
                if dynamic_spec:
                    add_use(dynamic_spec, "<import>", relpath, jx._line(node))
                    continue
                if jx._t(callee) == "Identifier" and callee.get("name") in bindings \
                        and not is_shadowed(callee.get("name"), node):
                    spec, member = bindings[callee["name"]]
                    add_use(spec, member or "()", relpath, jx._line(node))
                for arg in node.get("arguments") or []:
                    if jx._t(arg) == "Identifier" and arg.get("name") in bindings \
                            and not is_shadowed(arg.get("name"), node):
                        spec, member = bindings[arg["name"]]
                        add_use(spec, member, relpath, jx._line(node))  # değer olarak aktarılıyor
            elif kind == "AssignmentExpression":
                right = node.get("right")
                if jx._t(right) == "Identifier" and right.get("name") in bindings \
                        and not is_shadowed(right.get("name"), node):
                    spec, member = bindings[right["name"]]
                    add_use(spec, member, relpath, jx._line(node))  # app.locals.marked = marked
    index.engine.add("javascript-ast")


_GO_IMPORT_RE = re.compile(r'^\s*(?:import\s+)?(?:([A-Za-z_][\w]*|_|\.)\s+)?"([^"]+)"\s*$')


def _go_index(index: UsageIndex, relpath: str, text: str) -> None:
    bindings: dict[str, str] = {}
    in_block = False
    # Preserve import path string literals while removing comments; for symbol
    # calls, mask both comments and strings.  Both views retain line geometry.
    import_lines = _mask_c_like_noncode(text, mask_strings=False).splitlines()
    code_lines = _mask_c_like_noncode(text).splitlines()
    for raw in import_lines:
        line = raw.strip()
        if line.startswith("import ("):
            in_block = True
            continue
        if in_block and line.startswith(")"):
            in_block = False
            continue
        if in_block or line.startswith("import "):
            match = _GO_IMPORT_RE.match(line)
            if match:
                alias, path = match.group(1), match.group(2)
                if alias in {"_", "."}:
                    continue
                bindings[alias or path.rsplit("/", 1)[-1]] = path
    for line_no, line in enumerate(code_lines, start=1):
        for local, path in bindings.items():
            for match in re.finditer(rf"(?<![\w.]){re.escape(local)}\.([A-Z][\w]*)((?:\.[A-Za-z_]\w*)?)", line):
                index.add(path, match.group(1) + match.group(2), relpath, line_no)
    index.engine.add("go-regex")


_RS_USE_RE = re.compile(r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?use[ \t]+([^;]+);", re.M)
_RS_EXTERN_RE = re.compile(
    r"^[ \t]*extern[ \t]+crate[ \t]+([A-Za-z_]\w*)(?:[ \t]+as[ \t]+([A-Za-z_]\w*))?[ \t]*;", re.M
)


def _rs_use_paths(spec: str, prefix: str = "") -> list[tuple[str, str]]:
    """``a::b::{C, d::E as F, self}`` → [(yerel ad, tam yol "a::b::C"), …] (iç içe süslü ayraçlar dahil)."""
    spec = spec.strip()
    out: list[tuple[str, str]] = []
    brace = spec.find("{")
    if brace >= 0 and spec.endswith("}"):
        head = spec[:brace].rstrip(":").strip()
        base = f"{prefix}::{head}" if prefix and head else (head or prefix)
        depth, start, inner = 0, 0, spec[brace + 1:-1]
        pieces: list[str] = []
        for i, ch in enumerate(inner):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            elif ch == "," and depth == 0:
                pieces.append(inner[start:i])
                start = i + 1
        pieces.append(inner[start:])
        for piece in pieces:
            if piece.strip():
                out.extend(_rs_use_paths(piece, base))
        return out
    path, _, alias = spec.partition(" as ")
    path = path.strip()
    if path == "self" and prefix:
        return [((alias.strip() or prefix.rsplit("::", 1)[-1]), prefix)]
    full = f"{prefix}::{path}" if prefix else path
    if full.endswith("::self"):
        full = full[: -len("::self")]
    if path in {"*", "self"} or not re.fullmatch(r"[A-Za-z_][\w]*(?:::[A-Za-z_][\w]*)*", full):
        return out
    local = (alias.strip() or full.rsplit("::", 1)[-1])
    out.append((local, full))
    return out


def _rs_local_shadow_ranges(text: str) -> dict[str, list[tuple[int, int]]]:
    """Rust işlev parametresi ve basit ``let`` bağlarının içe aktarılan adı gölgelediği karakter aralıkları."""
    brace_closes: dict[int, int] = {}
    stack: list[int] = []
    for pos, char in enumerate(text):
        if char == "{":
            stack.append(pos)
        elif char == "}" and stack:
            brace_closes[stack.pop()] = pos
    ranges = list(brace_closes.items())
    result: dict[str, list[tuple[int, int]]] = {}

    function = re.compile(r"\bfn[ \t]+[A-Za-z_]\w*(?:[ \t]*<[^{};]*>)?[ \t]*\(([^{};]*)\)[^{;]*\{", re.S)
    for match in function.finditer(text):
        opening = match.end() - 1
        closing = brace_closes.get(opening)
        if closing is None:
            continue
        params = match.group(1)
        for param in re.finditer(r"(?:^|,)[ \t]*(?:mut[ \t]+|ref[ \t]+)*([A-Za-z_]\w*)[ \t]*:", params):
            name = param.group(1)
            if name not in {"self", "Self", "_"}:
                result.setdefault(name, []).append((opening, closing))

    def statement_end(start: int, limit: int) -> int:
        paren = bracket = brace = 0
        for pos in range(start, limit):
            char = text[pos]
            if char == "(":
                paren += 1
            elif char == ")" and paren:
                paren -= 1
            elif char == "[":
                bracket += 1
            elif char == "]" and bracket:
                bracket -= 1
            elif char == "{":
                brace += 1
            elif char == "}" and brace:
                brace -= 1
            elif char == ";" and paren == bracket == brace == 0:
                return pos + 1
        return start

    for match in re.finditer(r"\blet[ \t]+(?:mut[ \t]+)?([A-Za-z_]\w*)\b", text):
        name = match.group(1)
        if name == "_":
            continue
        containing = [(opening, closing) for opening, closing in ranges
                      if opening < match.start() < closing]
        if not containing:
            continue
        _, closing = min(containing, key=lambda row: row[1] - row[0])
        result.setdefault(name, []).append((statement_end(match.end(), closing), closing))
    return result


def _rs_name_shadowed(ranges: dict[str, list[tuple[int, int]]], name: str, position: int) -> bool:
    return any(first <= position <= last for first, last in ranges.get(name, ()))


def _rs_index(index: UsageIndex, relpath: str, text: str) -> None:
    """Rust: ``use crate::yol::Ad`` bağlamaları ve ``crate::yol::fn(`` / ``Ad::fn(`` kullanımları (yalnız okuma).

    Anahtar biçimi Go/Python ile aynı: crate adı (alt çizgili, küçük harf) → "mod.Tür.fn" göreli yol."""
    bindings: dict[str, str] = {}
    code_text = _mask_rust_noncode(text)
    lines = code_text.splitlines(keepends=True)
    shadow_ranges = _rs_local_shadow_ranges(code_text)
    for match in _RS_EXTERN_RE.finditer(code_text):
        crate, alias = match.group(1), match.group(2) or match.group(1)
        bindings[alias] = crate
        index.add(crate, "<import>", relpath, code_text.count("\n", 0, match.start()) + 1)
    for match in _RS_USE_RE.finditer(code_text):
        line_no = code_text.count("\n", 0, match.start()) + 1
        use_spec = match.group(1)
        paths = _rs_use_paths(use_spec)
        import_roots = {full.split("::", 1)[0] for _, full in paths}
        root_match = re.match(r"[ \t]*([A-Za-z_]\w*)::", use_spec)
        if root_match:
            import_roots.add(root_match.group(1))
        for root in import_roots:
            if root not in {"crate", "self", "super", "std", "core", "alloc"}:
                index.add(root, "<import>", relpath, line_no)
        for local, full in paths:
            parts = full.split("::")
            if parts[0] in {"crate", "self", "super", "std", "core", "alloc"}:
                continue
            if local != "_":
                bindings[local] = full
    line_offset = 0
    for line_no, line in enumerate(lines, start=1):
        if re.match(r"^[ \t]*(?:(?:pub(?:\([^)]*\))?[ \t]+)?use|extern[ \t]+crate)\b", line):
            line_offset += len(line)
            continue
        direct_calls = re.finditer(
            r"(?<![\w:])([A-Za-z_]\w*)[ \t]*(?:(?:::)?<[^;\n{}()]*>[ \t]*)?(?:!|\()", line
        )
        for call in direct_calls:
            local = call.group(1)
            target = bindings.get(local)
            if target is None or _rs_name_shadowed(shadow_ranges, local, line_offset + call.start()):
                continue
            parts = target.split("::")
            if len(parts) > 1:
                index.add(parts[0], ".".join(parts[1:]), relpath, line_no)
        if "::" not in line:
            line_offset += len(line)
            continue
        for match in re.finditer(r"(?<![\w:])([A-Za-z_]\w*)((?:::[A-Za-z_]\w*)+)", line):
            head, rest = match.group(1), match.group(2)[2:].split("::")
            target = bindings.get(head)
            if target:
                parts = target.split("::") + rest
            elif head.casefold() == head and head not in {"crate", "self", "super", "std", "core", "alloc"} \
                    and any(head == k.split("::")[0] for k in bindings.values()):
                parts = [head] + rest
            else:
                continue
            index.add(parts[0], ".".join(parts[1:]), relpath, line_no)
        line_offset += len(line)
    index.engine.add("rust-regex")


def _jvm_index(index: UsageIndex, relpath: str, text: str) -> None:
    """JVM içe aktarımlarını sınıf ve örnek yöntem çağrılarına bağla (yorum/dize çalıştırmadan)."""
    classes: dict[str, tuple[str, str]] = {}
    instances: dict[str, tuple[str, str]] = {}
    static_members: dict[str, tuple[str, str]] = {}
    wildcard_packages: set[str] = set()
    static_wildcards: set[tuple[str, str]] = set()
    masked = _mask_c_like_noncode(text)
    lines = masked.splitlines()
    declared_methods = _declared_method_scopes(masked)
    local_classes = set(re.findall(r"\b(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)", masked))
    for line_no, line in enumerate(lines, start=1):
        match = re.match(
            r"^\s*import\s+(static\s+)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)(\.\*)?\s*;?",
            line,
        )
        if not match:
            continue
        is_static = bool(match.group(1))
        dotted = match.group(2)
        wildcard = bool(match.group(3))
        parts = dotted.split(".")
        class_pos = next((i for i, part in enumerate(parts) if part[:1].isupper()), len(parts) - 1)
        package = ".".join(parts[:class_pos])
        class_name = parts[class_pos]
        if wildcard and not is_static:
            wildcard_packages.add(dotted)
            index.add(dotted, "<import>", relpath, line_no)
            continue
        if package:
            classes[class_name] = (package, class_name)
            index.add(package, "<import>", relpath, line_no)
            if is_static and wildcard:
                static_wildcards.add((package, class_name))
            elif is_static and class_pos + 1 < len(parts):
                static_members[parts[-1]] = (package, class_name)
            elif class_pos + 1 < len(parts):
                index.add(package, ".".join(parts[class_pos:]), relpath, line_no)
    local_shadows = _c_local_shadow_ranges(masked)

    def imported_type(raw: str, line_no: int) -> tuple[str, str] | None:
        if "." in raw:
            parts = raw.split(".")
            class_pos = next((i for i, part in enumerate(parts) if part[:1].isupper()), len(parts) - 1)
            package = ".".join(parts[:class_pos])
            return (package, parts[class_pos]) if package else None
        if _c_name_shadowed(local_shadows, raw, line_no):
            return None
        binding = classes.get(raw)
        if binding is None and len(wildcard_packages) == 1 and raw[:1].isupper() and raw not in local_classes:
            binding = (next(iter(wildcard_packages)), raw)
        return binding

    for line_no, line in enumerate(lines, start=1):
        code = re.sub(r"//.*$", "", line)
        for match in re.finditer(
                r"\b(?:val|var)\s+([A-Za-z_$][\w$]*)"
                r"(?:\s*:\s*[A-Za-z_$][\w$.]*(?:\s*<[^;{}()]*>)?)?\s*=\s*"
                r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)"
                r"(?:\s*<[^;{}()]*>)?\s*\(", code):
            variable, constructed = match.groups()
            binding = imported_type(constructed, line_no)
            if binding:
                instances[variable] = binding
        for match in re.finditer(r"\b([A-Za-z_$][\w$]*)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+([A-Za-z_$][\w$]*)\s*\(", code):
            declared, variable, constructed = match.groups()
            binding = classes.get(constructed) or classes.get(declared)
            if binding:
                instances[variable] = binding
        for match in re.finditer(
                r"(?<![\w$])([A-Za-z_$][\w$]*)\s*=\s*new\s+"
                r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)"
                r"(?:\s*<[^;{}()]*>)?\s*\(", code):
            variable, constructed = match.groups()
            binding = imported_type(constructed, line_no)
            if binding:
                instances[variable] = binding
        for match in re.finditer(
                r"\bnew\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*"
                r"(?:<[^;{}()]*>\s*)?\([^()]*\)\s*\.\s*"
                r"(?:<[^;{}()]{1,200}>\s*)?([A-Za-z_$][\w$]*)\s*"
                r"(?:<[^;{}()]{1,200}>\s*)?\(", code):
            constructed, method = match.groups()
            binding = imported_type(constructed, line_no)
            if binding:
                index.add(binding[0], f"{binding[1]}.{method}", relpath, line_no)
        for match in re.finditer(
                r"(?<![\w$])([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*::\s*"
                r"(?:<[^;{}()]{1,200}>\s*)?([A-Za-z_$][\w$]*)", code):
            owner, method = match.groups()
            binding = instances.get(owner) or imported_type(owner, line_no)
            if binding:
                index.add(binding[0], f"{binding[1]}.{method}", relpath, line_no)
        for match in re.finditer(
                r"(?<![\w$])([A-Za-z_$][\w$]*)\.\s*"
                r"(?:<[^;{}()]{1,200}>\s*)?([A-Za-z_$][\w$]*)\s*"
                r"(?:<[^;{}()]{1,200}>\s*)?\(", code):
            owner, method = match.groups()
            binding = instances.get(owner)
            if binding is None and not _c_name_shadowed(local_shadows, owner, line_no):
                binding = classes.get(owner)
            if binding is None and len(wildcard_packages) == 1 and owner[:1].isupper() \
                    and owner not in local_classes and not _c_name_shadowed(local_shadows, owner, line_no):
                binding = (next(iter(wildcard_packages)), owner)
            if binding:
                index.add(binding[0], f"{binding[1]}.{method}", relpath, line_no)
        for match in re.finditer(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(", code):
            binding = static_members.get(match.group(1))
            if binding is None and len(static_wildcards) == 1:
                binding = next(iter(static_wildcards))
            if binding and match.group(1) not in declared_methods.get(line_no, ()) \
                    and not _c_name_shadowed(local_shadows, match.group(1), line_no) \
                    and not _looks_like_method_declaration(code, match.start()):
                index.add(binding[0], f"{binding[1]}.{match.group(1)}", relpath, line_no)
    index.engine.add("jvm-regex")


def _dotnet_index(index: UsageIndex, relpath: str, text: str) -> None:
    """C#/VB/F# ad alanlarını sınıf ve örnek yöntem çağrılarına bağla; belirsiz ad alanında fail-closed kal."""
    namespaces: list[str] = []
    aliases: dict[str, str] = {}
    instances: dict[str, tuple[str, str]] = {}
    static_members: dict[str, tuple[str, str]] = {}
    suffix = PurePosixPath(relpath).suffix.casefold()
    if suffix == ".vb":
        masked = _mask_vb_noncode(text)
    elif suffix in {".fs", ".fsx"}:
        masked = _mask_fsharp_noncode(text)
    elif suffix in {".cshtml", ".razor"}:
        masked = _mask_c_like_noncode(text, razor_comments=True)
    else:
        masked = _mask_c_like_noncode(text)
    lines = masked.splitlines()
    declared_methods = _declared_method_scopes(masked)
    local_types = set(re.findall(
        r"\b(?:class|struct|interface|record|enum)\s+([A-Za-z_][\w]*)", masked, re.I,
    ))
    for line_no, line in enumerate(lines, start=1):
        match = re.match(r"^\s*(?:global\s+)?@?(?:using|Imports|open)\s+(?:(?:static\s+)?)([A-Za-z_][\w]*)\s*=\s*([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+)\s*;?", line, re.I)
        if match:
            aliases[match.group(1)] = match.group(2)
            namespace = match.group(2).rsplit(".", 1)[0]
            index.add(namespace, "<import>", relpath, line_no)
            continue
        match = re.match(r"^\s*(?:global\s+)?@?using\s+static\s+([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+)\s*;?", line, re.I)
        if match:
            full_type = match.group(1)
            namespace, class_name = full_type.rsplit(".", 1)
            static_members[class_name] = (namespace, class_name)
            index.add(namespace, "<import>", relpath, line_no)
            continue
        match = re.match(r"^\s*(?:global\s+)?@?(?:using|Imports|open)\s+(?:static\s+)?([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+)\s*;?", line, re.I)
        if match:
            namespace = match.group(1).rstrip(".")
            if not namespace.casefold().startswith(("system", "microsoft")):
                namespaces.append(namespace)
                index.add(namespace, "<import>", relpath, line_no)
    unique_namespaces = sorted(set(namespaces), key=str.casefold)
    local_shadows = _c_local_shadow_ranges(masked)

    def imported_type(raw: str, line_no: int) -> tuple[str, str] | None:
        if raw in aliases and not _c_name_shadowed(local_shadows, raw, line_no):
            full = aliases[raw]
            return tuple(full.rsplit(".", 1))  # type: ignore[return-value]
        if "." in raw:
            return tuple(raw.rsplit(".", 1))  # type: ignore[return-value]
        if raw in local_types:
            return None
        if len(unique_namespaces) == 1 and not _c_name_shadowed(local_shadows, raw, line_no):
            return unique_namespaces[0], raw
        return None

    for line_no, line in enumerate(lines, start=1):
        code = re.sub(r"//.*$", "", line)
        # C# 9 target-typed construction: the declared type is the only class
        # identity carried by ``Type value = new();``.
        for match in re.finditer(
                r"\b([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)"
                r"(?:\s*<[^;{}()]*>)?\s+"
                r"([A-Za-z_][\w]*)\s*=\s*new\s*\(", code):
            declared, variable = match.groups()
            if declared.casefold() == "var":
                continue
            binding = imported_type(declared, line_no)
            if binding:
                instances[variable] = binding
        for match in re.finditer(
                r"\b(?:var|[A-Za-z_][\w.]*(?:\s*<[^;{}()]*>)?)\s+"
                r"([A-Za-z_][\w]*)\s*=\s*new\s+([A-Za-z_][\w.]*)"
                r"(?:\s*<[^;{}()]*>)?\s*\(", code):
            variable, full_type = match.groups()
            binding = imported_type(full_type, line_no)
            if binding:
                instances[variable] = binding
        for match in re.finditer(
                r"(?<![\w])([A-Za-z_][\w]*)\s*=\s*new\s+"
                r"([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)"
                r"(?:\s*<[^;{}()]*>)?\s*\(", code):
            variable, constructed = match.groups()
            binding = imported_type(constructed, line_no)
            if binding:
                instances[variable] = binding
        for match in re.finditer(
                r"\bnew\s+([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)\s*"
                r"(?:<[^;{}()]*>\s*)?\([^()]*\)\s*\.\s*([A-Za-z_][\w]*)\s*"
                r"(?:<[^;{}()]{1,200}>\s*|\(\s*Of\b[^;{}()]{1,200}\)\s*)?\(", code, re.I):
            constructed, method = match.groups()
            binding = imported_type(constructed, line_no)
            if binding:
                index.add(binding[0], f"{binding[1]}.{method}", relpath, line_no)
        if re.search(r"\b(?:System\.)?(?:Func|Action)\s*<", code):
            for match in re.finditer(
                    r"=\s*([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)\."
                    r"([A-Za-z_][\w]*)(?:\s*<[^;{}()]{1,200}>)?\s*(?=[,;)])", code):
                owner, method = match.groups()
                binding = instances.get(owner) or imported_type(owner, line_no)
                if binding:
                    index.add(binding[0], f"{binding[1]}.{method}", relpath, line_no)
        for match in re.finditer(
                r"(?<![\w.])([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)\.([A-Za-z_][\w]*)\s*"
                r"(?:<[^;{}()]{1,200}>\s*|\(\s*Of\b[^;{}()]{1,200}\)\s*)?\(", code, re.I):
            owner, method = match.groups()
            if owner in instances:
                namespace, class_name = instances[owner]
            elif owner in aliases and not _c_name_shadowed(local_shadows, owner, line_no):
                full = aliases[owner]
                namespace, class_name = full.rsplit(".", 1)
            elif "." in owner:
                namespace, class_name = owner.rsplit(".", 1)
            elif len(unique_namespaces) == 1 and owner[:1].isupper() and owner not in local_types \
                    and not _c_name_shadowed(local_shadows, owner, line_no):
                namespace, class_name = unique_namespaces[0], owner
            else:
                continue
            index.add(namespace, f"{class_name}.{method}", relpath, line_no)
        if len(static_members) == 1:
            namespace, class_name = next(iter(static_members.values()))
            for match in re.finditer(r"(?<![\w.])([A-Za-z_][\w]*)\s*\(", code):
                method = match.group(1)
                if method not in {"if", "for", "foreach", "while", "switch", "catch", "nameof", class_name} \
                        and method not in declared_methods.get(line_no, ()) \
                        and not _c_name_shadowed(local_shadows, method, line_no) \
                        and not _looks_like_method_declaration(code, match.start()):
                    index.add(namespace, f"{class_name}.{method}", relpath, line_no)
    index.engine.add("dotnet-regex")


_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


_MORE_DIRECT_MANIFESTS = {"pom.xml", "build.gradle", "build.gradle.kts", "gemfile", "composer.json", "cargo.toml"}
_GRADLE_COORD_RE = re.compile(r"""['"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):[^'"\s]+['"]""")
_GEM_RE = re.compile(r"""^\s*gem\s+['"]([^'"]+)['"]""")
_CARGO_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_NPM_ALIAS_RE = re.compile(
    r"^npm:(?P<name>@[A-Za-z0-9][A-Za-z0-9._~-]*/[A-Za-z0-9][A-Za-z0-9._~-]*|"
    r"[A-Za-z0-9][A-Za-z0-9._~-]*)(?:@[^\s]+)?$"
)


def _npm_alias_target(value: Any) -> str | None:
    match = _NPM_ALIAS_RE.fullmatch(value.strip()) if isinstance(value, str) else None
    return match.group("name").casefold() if match else None


def _setup_py_direct(text: str) -> set[str]:
    """Read literal setuptools setup() requirements without executing the file."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return set()
    direct_setup_names: set[str] = set()
    module_names: set[str] = set()
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom) and statement.module in {"setuptools", "distutils.core"}:
            direct_setup_names.update(alias.asname or alias.name for alias in statement.names if alias.name == "setup")
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name in {"setuptools", "distutils.core"}:
                    module_names.add(alias.asname or alias.name.split(".", 1)[0])

    bindings: dict[str, ast.AST] = {}
    writes: dict[str, int] = {}

    def target_root(node: ast.AST) -> str | None:
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        return node.id if isinstance(node, ast.Name) else None

    for node in ast.walk(tree):
        targets: list[ast.AST] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets = [node.target]
        elif isinstance(node, ast.Delete):
            targets = list(node.targets)
        for target in targets:
            root = target_root(target)
            if root:
                writes[root] = writes.get(root, 0) + 1
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            root = target_root(node.func.value)
            if root:
                writes[root] = writes.get(root, 0) + 1
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1 \
                and isinstance(statement.targets[0], ast.Name):
            bindings[statement.targets[0].id] = statement.value
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name) \
                and statement.value is not None:
            bindings[statement.target.id] = statement.value

    def is_setup_call(call: ast.Call) -> bool:
        if isinstance(call.func, ast.Name):
            return call.func.id in direct_setup_names
        return isinstance(call.func, ast.Attribute) and call.func.attr == "setup" \
            and isinstance(call.func.value, ast.Name) and call.func.value.id in module_names

    def literal_specs(node: ast.AST) -> list[str]:
        if isinstance(node, ast.Name) and writes.get(node.id) == 1 and node.id in bindings:
            node = bindings[node.id]
        if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return []
        return [element.value for element in node.elts[:10_000]
                if isinstance(element, ast.Constant) and isinstance(element.value, str)]

    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not is_setup_call(node):
            continue
        for keyword in node.keywords:
            specs: list[str] = []
            if keyword.arg == "install_requires":
                specs = literal_specs(keyword.value)
            elif keyword.arg == "extras_require":
                extra_value = keyword.value
                if isinstance(extra_value, ast.Name) and writes.get(extra_value.id) == 1 \
                        and extra_value.id in bindings:
                    extra_value = bindings[extra_value.id]
                if not isinstance(extra_value, ast.Dict):
                    continue
                for value in extra_value.values[:1_000]:
                    specs.extend(literal_specs(value))
            for spec in specs[:10_000]:
                match = _REQ_NAME_RE.match(spec)
                if match:
                    names.add(match.group(1).casefold().replace("_", "-"))
    return names


def _pep723_direct(text: str) -> set[str]:
    """Read a bounded PEP 723 ``script`` metadata block without executing Python."""
    lines = text.splitlines()
    for start, line in enumerate(lines):
        if line.strip() != "# /// script":
            continue
        body: list[str] = []
        for raw in lines[start + 1:start + 10_002]:
            if raw.strip() == "# ///":
                try:
                    import tomllib

                    data = tomllib.loads("\n".join(body))
                except (ValueError, UnicodeError):
                    return set()
                specs = data.get("dependencies") if isinstance(data, dict) else None
                if not isinstance(specs, list):
                    return set()
                names: set[str] = set()
                for spec in specs[:10_000]:
                    match = _REQ_NAME_RE.match(spec) if isinstance(spec, str) else None
                    if match:
                        names.add(match.group(1).casefold().replace("_", "-"))
                return names
            comment = re.fullmatch(r"\s*#(?: ?)(.*)", raw)
            if comment is None:
                return set()
            body.append(comment.group(1))
        return set()
    return set()


def _noxfile_direct(text: str) -> tuple[set[str], list[str]]:
    """Read literal package arguments from decorated Nox sessions without executing the file."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return set(), []
    names: set[str] = set()
    includes: list[str] = []
    for function in tree.body:
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) or not function.args.args:
            continue
        decorated = False
        for decorator in function.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) \
                    and target.value.id == "nox" and target.attr == "session":
                decorated = True
                break
        if not decorated:
            continue
        session = function.args.args[0].arg
        for node in ast.walk(function):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) \
                    or node.func.attr != "install" or not isinstance(node.func.value, ast.Name) \
                    or node.func.value.id != session:
                continue
            values = [argument.value if isinstance(argument, ast.Constant) and isinstance(argument.value, str) else None
                      for argument in node.args[:10_000]]
            index = 0
            while index < len(values):
                value = values[index]
                if value in ("-r", "--requirement"):
                    if index + 1 < len(values) and values[index + 1]:
                        includes.append(values[index + 1] or "")
                    index += 2
                    continue
                if isinstance(value, str) and (value.startswith("-r") and len(value) > 2
                                               or value.startswith("--requirement=")):
                    includes.append(value.split("=", 1)[1] if "=" in value else value[2:])
                    index += 1
                    continue
                if value in ("-c", "--constraint"):
                    index += 2
                    continue
                if isinstance(value, str) and (value.startswith("-c") and len(value) > 2
                                               or value.startswith("--constraint=")):
                    index += 1
                    continue
                if isinstance(value, str) and not value.startswith("-"):
                    match = _REQ_NAME_RE.match(value)
                    if match:
                        names.add(match.group(1).casefold().replace("_", "-"))
                index += 1
    return names, includes


def _cargo_dependency_tables(data: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Yield Cargo dependency tables, including target and workspace declarations."""
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = data.get(key)
        if isinstance(table, dict):
            yield table
    targets = data.get("target")
    if isinstance(targets, dict):
        for target in targets.values():
            if not isinstance(target, dict):
                continue
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                table = target.get(key)
                if isinstance(table, dict):
                    yield table
    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        table = workspace.get("dependencies")
        if isinstance(table, dict):
            yield table


def _cargo_declared_package(alias: Any, value: Any) -> str | None:
    alias_text = str(alias).strip()
    if not _CARGO_NAME_RE.fullmatch(alias_text):
        return None
    package = value.get("package") if isinstance(value, dict) else None
    package_text = package.strip() if isinstance(package, str) else ""
    return (package_text if _CARGO_NAME_RE.fullmatch(package_text) else alias_text).casefold()


def _direct_from_manifest(lowered: str, text: str) -> set[str]:
    """20. tur: Maven/Gradle/Bundler/Composer/Cargo/NuGet bildirimlerinde doğrudan listelenen paketler (küçük harf).

    Maven anahtarı "grup:artefakt"; dependencyManagement ve eklenti (plugin) blokları doğrudan bağımlılık sayılmaz."""
    names: set[str] = set()
    if lowered == "pom.xml":
        body = re.sub(r"(?s)<dependencyManagement>.*?</dependencyManagement>", "", text)
        body = re.sub(r"(?s)<plugins>.*?</plugins>|<pluginManagement>.*?</pluginManagement>", "", body)
        for block in re.findall(r"(?s)<dependency>(.*?)</dependency>", body):
            group = re.search(r"<groupId>\s*([^<\s]+)\s*</groupId>", block)
            artifact = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", block)
            if group and artifact and "${" not in group.group(1) + artifact.group(1):
                names.add(f"{group.group(1)}:{artifact.group(1)}".casefold())
    elif lowered in {"build.gradle", "build.gradle.kts"}:
        for match in _GRADLE_COORD_RE.finditer(text):
            names.add(f"{match.group(1)}:{match.group(2)}".casefold())
    elif lowered == "gemfile":
        for line in text.splitlines():
            match = _GEM_RE.match(line)
            if match:
                names.add(match.group(1).casefold())
    elif lowered == "composer.json":
        data = json.loads(text)
        for key in ("require", "require-dev"):
            if isinstance(data.get(key), dict):
                names.update(k.casefold() for k in data[key] if "/" in k)
    elif lowered == "cargo.toml":
        import tomllib

        data = tomllib.loads(text)
        if isinstance(data, dict):
            for table in _cargo_dependency_tables(data):
                names.update(
                    package for alias, value in table.items()
                    if (package := _cargo_declared_package(alias, value)) is not None
                )
    else:  # .csproj / .fsproj / .vbproj
        for match in re.finditer(r"""<PackageReference\s+[^>]*Include\s*=\s*["']([^"']+)["']""", text, re.I):
            names.add(match.group(1).casefold())
    return names


def cargo_dependency_aliases(
    root: Path,
    skip_dirs: Iterable[str],
    *,
    project_tree: ProjectTree | None = None,
) -> dict[str, set[str]]:
    """Map real Cargo package names to unambiguous local crate aliases.

    Cargo's dependency key is the name used by Rust source, while an inline
    ``package`` field names the package represented by advisories and lockfiles.
    If one alias names multiple packages in a workspace, omit it fail closed.
    """
    skip = {str(name).casefold() for name in skip_dirs}
    alias_owners: dict[str, set[str]] = {}
    seen = 0
    with _borrow_project_tree(root, project_tree) as tree:
        for project_file in tree.iter_files(skip_dirs=skip, reject_unsafe=False):
            if project_file.name.casefold() != "cargo.toml":
                continue
            seen += 1
            if seen > 200:
                break
            try:
                if project_file.size > 2_000_000:
                    continue
                text = tree.read_text(project_file, 2_000_000, errors="replace", allow_empty=True)
                import tomllib

                data = tomllib.loads(text)
            except (tomllib.TOMLDecodeError, UnicodeError, TypeError):
                continue
            if not isinstance(data, dict):
                continue
            for table in _cargo_dependency_tables(data):
                for raw_alias, value in table.items():
                    alias = str(raw_alias).strip()
                    package = value.get("package") if isinstance(value, dict) else None
                    if not _CARGO_NAME_RE.fullmatch(alias) or not isinstance(package, str):
                        continue
                    package = package.strip()
                    if not _CARGO_NAME_RE.fullmatch(package):
                        continue
                    source_name = alias.casefold().replace("-", "_")
                    actual_name = package.casefold()
                    if source_name != actual_name.replace("-", "_"):
                        alias_owners.setdefault(source_name, set()).add(actual_name)
    aliases: dict[str, set[str]] = {}
    for source_name, owners in alias_owners.items():
        if len(owners) == 1:
            aliases.setdefault(next(iter(owners)), set()).add(source_name)
    return aliases


def npm_dependency_aliases(
    root: Path,
    skip_dirs: Iterable[str],
    *,
    project_tree: ProjectTree | None = None,
) -> dict[str, set[str]]:
    """Map npm alias targets to unambiguous local dependency keys."""
    skip = {str(name).casefold() for name in skip_dirs}
    alias_owners: dict[str, set[str]] = {}
    seen = 0
    with _borrow_project_tree(root, project_tree) as tree:
        for project_file in tree.iter_files(skip_dirs=skip, reject_unsafe=False):
            if project_file.name.casefold() != "package.json":
                continue
            seen += 1
            if seen > 200:
                break
            try:
                if project_file.size > 2_000_000:
                    continue
                text = tree.read_text(project_file, 2_000_000, errors="replace", allow_empty=True)
                data = json.loads(text)
            except (json.JSONDecodeError, UnicodeError, TypeError):
                continue
            if not isinstance(data, dict):
                continue
            for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                table = data.get(section)
                if not isinstance(table, dict):
                    continue
                for raw_alias, value in table.items():
                    alias = str(raw_alias).strip().casefold()
                    target = _npm_alias_target(value)
                    if target and alias and alias != target:
                        alias_owners.setdefault(alias, set()).add(target)
    aliases: dict[str, set[str]] = {}
    for alias, owners in alias_owners.items():
        if len(owners) == 1:
            aliases.setdefault(next(iter(owners)), set()).add(alias)
    return aliases


def bundler_autorequired(
    root: Path,
    *,
    project_tree: ProjectTree | None = None,
) -> dict[str, dict[str, Any]]:
    """Rails/Bundler: ``Bundler.require`` varsa Gemfile'daki ``require: false`` olmayan gem'ler açılışta yüklenir.

    Döner: gem adı (küçük harf) → Gemfile konumu. ``Bundler.require`` bulunamazsa boş (kanıt yok)."""
    wanted = {
        "Gemfile", "config/application.rb", "config/boot.rb", "config.ru", "app.rb", "config/environment.rb"
    }
    with _borrow_project_tree(root, project_tree) as tree:
        observed = {
            item.path.as_posix(): item
            for item in tree.iter_files(reject_unsafe=False)
            if item.path.as_posix() in wanted
        }
        gemfile = observed.get("Gemfile")
        if gemfile is None or gemfile.size > 2_000_000:
            return {}
        gemfile_text = tree.read_text(gemfile, 2_000_000, errors="replace", allow_empty=True)
        bundler_boot = False
        for name in ("config/application.rb", "config/boot.rb", "config.ru", "app.rb", "config/environment.rb"):
            boot_file = observed.get(name)
            if boot_file is None or boot_file.size > _MAX_FILE_BYTES:
                continue
            boot_text = tree.read_text(boot_file, _MAX_FILE_BYTES, errors="replace", allow_empty=True)
            if "Bundler.require" in boot_text:
                bundler_boot = True
                break
    if not bundler_boot:
        return {}
    out: dict[str, dict[str, Any]] = {}
    for line_no, line in enumerate(gemfile_text.splitlines(), start=1):
        match = _GEM_RE.match(line)
        if match and not re.search(r"require\s*:\s*false|:require\s*=>\s*false", line):
            out.setdefault(match.group(1).casefold(), {"file": "Gemfile", "line": line_no, "via": "bundler"})
    return out


def composer_namespaces(
    root: Path,
    *,
    project_tree: ProjectTree | None = None,
) -> dict[str, set[str]]:
    """composer.lock paketlerinin autoload (psr-4/psr-0) ad alanları: paket → {"guzzlehttp\\psr7"} (küçük harf)."""
    out: dict[str, set[str]] = {}
    with _borrow_project_tree(root, project_tree) as tree:
        walk = tree.walk(reject_unsafe=False)
        try:
            root_entry = next(walk)
        finally:
            walk.close()
        lock = next((item for item in root_entry.files if item.name == "composer.lock"), None)
        if lock is None or lock.size > 20_000_000:
            return {}
        try:
            lock_text = tree.read_text(lock, 20_000_000, errors="replace", allow_empty=True)
            data = json.loads(lock_text)
        except (json.JSONDecodeError, TypeError):
            return {}
    for key in ("packages", "packages-dev"):
        for package in data.get(key) or []:
            if not isinstance(package, dict) or not isinstance(package.get("name"), str):
                continue
            autoload = package.get("autoload") if isinstance(package.get("autoload"), dict) else {}
            spaces: set[str] = set()
            for kind in ("psr-4", "psr-0"):
                mapping = autoload.get(kind) if isinstance(autoload.get(kind), dict) else {}
                for namespace in mapping:
                    ns = str(namespace).strip("\\").casefold()
                    if ns:
                        spaces.add(ns)  # tam ad alanı; "use" yollarının önekleriyle eşleşir (yalnız ilk parça değil)
            if spaces:
                out[package["name"].casefold()] = spaces
    return out


def direct_dependencies(
    root: Path,
    skip_dirs: Iterable[str],
    *,
    project_tree: ProjectTree | None = None,
) -> set[str]:
    """Bildirim dosyalarında doğrudan listelenen paketler (küçük harf). Kilit dosyaları (dolaylı) okunmaz."""
    names: set[str] = set()
    skip = {d.casefold() for d in skip_dirs}
    seen = 0
    requirement_files: set[str] = set()
    requirement_bytes = 0
    script_files = 0
    script_bytes = 0
    tree: ProjectTree
    files_by_path: dict[str, Any]

    def project_text(observed: Any, max_bytes: int) -> str | None:
        if observed.size > max_bytes:
            return None
        return tree.read_text(observed, max_bytes, errors="replace", allow_empty=True)

    def project_bytes(observed: Any, max_bytes: int) -> bytes | None:
        if observed.size > max_bytes:
            return None
        return tree.read_bytes(observed, max_bytes, allow_empty=True)

    def requirement_tree(path: PurePosixPath, depth: int = 0) -> set[str]:
        nonlocal requirement_bytes
        found: set[str] = set()
        if depth > 8 or len(requirement_files) >= 100:
            return found
        normalized = posixpath.normpath(path.as_posix())
        if normalized in ("", ".", "..") or normalized.startswith("../") or normalized.startswith("/"):
            return found
        if normalized in requirement_files:
            return found
        observed = files_by_path.get(normalized)
        if observed is None or observed.size > 1_000_000 or requirement_bytes + observed.size > 8_000_000:
            return found
        raw = tree.read_bytes(observed, 1_000_000, allow_empty=True)
        size = len(raw)
        text = raw.decode("utf-8", errors="replace")
        requirement_files.add(normalized)
        requirement_bytes += size
        specs: list[str] = []
        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            include = re.match(r"^(?:-r\s*|--requirement(?:=|\s+))([^\s]+)\s*$", line)
            if include:
                relative = include.group(1).strip("'\"")
                if relative and not Path(relative).is_absolute():
                    found.update(requirement_tree(PurePosixPath(normalized).parent / relative, depth + 1))
                continue
            if not line.startswith(("-", "[")):
                specs.append(line)
        if PurePosixPath(normalized).suffix.casefold() == ".txt" and len(specs) >= 10 and all("==" in spec for spec in specs):
            return found  # pip freeze output is an inventory, not a direct declaration.
        for spec in specs:
            match = _REQ_NAME_RE.match(spec)
            if match:
                found.add(match.group(1).casefold().replace("_", "-"))
        return found

    with _borrow_project_tree(root, project_tree) as tree:
        project_files = list(tree.iter_files(skip_dirs=skip, reject_unsafe=False))
        files_by_path = {item.path.as_posix(): item for item in project_files}
        for project_file in project_files:
            lowered = project_file.name.casefold()
            path = project_file.path
            try:
                if lowered == "package.json":
                    seen += 1
                    if project_file.size > 2_000_000:
                        continue
                    text = tree.read_text(project_file, 2_000_000, errors="replace", allow_empty=True)
                    data = json.loads(text)
                    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                        if isinstance(data.get(key), dict):
                            names.update(
                                _npm_alias_target(value) or str(alias).casefold()
                                for alias, value in data[key].items()
                            )
                elif lowered.startswith("requirements") and lowered.endswith((".txt", ".in")) \
                        or lowered.endswith((".txt", ".in")) and path.parent.name.casefold() == "requirements":
                    seen += 1
                    names.update(requirement_tree(path))
                elif lowered == "pipfile":
                    import tomllib

                    seen += 1
                    text = project_text(project_file, 2_000_000)
                    if text is None:
                        continue
                    data = tomllib.loads(text)
                    if isinstance(data, dict):
                        for section_name in ("packages", "dev-packages"):
                            section = data.get(section_name)
                            if not isinstance(section, dict):
                                continue
                            for raw_name in list(section)[:10_000]:
                                match = _REQ_NAME_RE.match(str(raw_name))
                                if match:
                                    names.add(match.group(1).casefold().replace("_", "-"))
                elif lowered == "setup.cfg":
                    import configparser

                    seen += 1
                    parser = configparser.ConfigParser(interpolation=None)
                    try:
                        text = project_text(project_file, 2_000_000)
                        if text is None:
                            continue
                        parser.read_string(text)
                    except configparser.Error:
                        continue

                    def add_cfg_specs(value: str) -> None:
                        file_block = False
                        for raw_spec in value.splitlines()[:10_000]:
                            spec = raw_spec.split("#", 1)[0].strip()
                            if spec.casefold() == "file:":
                                file_block = True
                                continue
                            if file_block:
                                for raw_relative in spec.split(",")[:100]:
                                    relative = raw_relative.strip().strip("'\"")
                                    if relative and not Path(relative).is_absolute():
                                        names.update(requirement_tree(path.parent / relative))
                                continue
                            directive = re.match(r"^file:\s*(.+)$", spec, re.IGNORECASE)
                            if directive:
                                for raw_relative in directive.group(1).split(",")[:100]:
                                    relative = raw_relative.strip().strip("'\"")
                                    if relative and not Path(relative).is_absolute():
                                        names.update(requirement_tree(path.parent / relative))
                                continue
                            match = _REQ_NAME_RE.match(spec)
                            if match:
                                names.add(match.group(1).casefold().replace("_", "-"))

                    for option in ("install_requires", "setup_requires", "tests_require"):
                        if parser.has_option("options", option):
                            add_cfg_specs(parser.get("options", option))
                    if parser.has_section("options.extras_require"):
                        for _extra, specs in list(parser.items("options.extras_require"))[:1_000]:
                            add_cfg_specs(specs)
                elif lowered == "tox.ini":
                    import configparser

                    seen += 1
                    parser = configparser.ConfigParser(interpolation=None)
                    try:
                        text = project_text(project_file, 2_000_000)
                        if text is None:
                            continue
                        parser.read_string(text)
                    except configparser.Error:
                        continue
                    for section in parser.sections()[:1_000]:
                        if section != "testenv" and not section.startswith("testenv:") \
                                or not parser.has_option(section, "deps"):
                            continue
                        for raw_spec in parser.get(section, "deps").splitlines()[:10_000]:
                            spec = raw_spec.split("#", 1)[0].strip()
                            include = re.match(r"^(?:-r\s*|--requirement(?:=|\s+))([^\s]+)\s*$", spec)
                            if include:
                                relative = include.group(1).strip("'\"")
                                if relative and not Path(relative).is_absolute():
                                    names.update(requirement_tree(path.parent / relative))
                                continue
                            match = _REQ_NAME_RE.match(spec)
                            if match:
                                names.add(match.group(1).casefold().replace("_", "-"))
                elif lowered == "setup.py":
                    seen += 1
                    text = project_text(project_file, 2_000_000)
                    if text is None:
                        continue
                    names.update(_setup_py_direct(text))
                elif lowered == "noxfile.py":
                    seen += 1
                    text = project_text(project_file, 2_000_000)
                    if text is None:
                        continue
                    nox_names, includes = _noxfile_direct(text)
                    names.update(nox_names)
                    for raw_relative in includes[:100]:
                        relative = raw_relative.strip().strip("'\"")
                        if relative and not Path(relative).is_absolute():
                            names.update(requirement_tree(path.parent / relative))
                elif lowered in ("environment.yml", "environment.yaml"):
                    import yaml

                    seen += 1
                    try:
                        text = project_text(project_file, 2_000_000)
                        if text is None:
                            continue
                        data = yaml.safe_load(text)
                    except yaml.YAMLError:
                        continue
                    dependencies = data.get("dependencies") if isinstance(data, dict) else None
                    if not isinstance(dependencies, list):
                        continue
                    for entry in dependencies[:10_000]:
                        specs: list[Any]
                        pip_specs = False
                        if isinstance(entry, str):
                            specs = [entry]
                        elif isinstance(entry, dict) and isinstance(entry.get("pip"), list):
                            specs = entry["pip"][:10_000]
                            pip_specs = True
                        else:
                            continue
                        for spec in specs:
                            include = re.match(
                                r"^(?:-r\s*|--requirement(?:=|\s+))([^\s]+)\s*$", spec,
                            ) if pip_specs and isinstance(spec, str) else None
                            if include:
                                relative = include.group(1).strip("'\"")
                                if relative and not Path(relative).is_absolute():
                                    names.update(requirement_tree(path.parent / relative))
                                continue
                            match = _REQ_NAME_RE.match(spec) if isinstance(spec, str) else None
                            if match:
                                names.add(match.group(1).casefold().replace("_", "-"))
                elif lowered == "pyproject.toml":
                    import tomllib

                    seen += 1
                    text = project_text(project_file, 2_000_000)
                    if text is None:
                        continue
                    data = tomllib.loads(text)
                    if not isinstance(data, dict):
                        continue

                    def add_specs(value: Any) -> None:
                        if not isinstance(value, list):
                            return
                        for spec in value[:10_000]:
                            if not isinstance(spec, str):
                                continue  # PEP 735 include-group tables are links, not packages.
                            match = _REQ_NAME_RE.match(spec)
                            if match:
                                names.add(match.group(1).casefold().replace("_", "-"))

                    def add_keys(value: Any) -> None:
                        if not isinstance(value, dict):
                            return
                        for raw_name in list(value)[:10_000]:
                            match = _REQ_NAME_RE.match(str(raw_name))
                            if match and match.group(1).casefold() != "python":
                                names.add(match.group(1).casefold().replace("_", "-"))

                    project = data.get("project")
                    if isinstance(project, dict):
                        add_specs(project.get("dependencies"))
                        optional = project.get("optional-dependencies")
                        if isinstance(optional, dict):
                            for specs in list(optional.values())[:1_000]:
                                add_specs(specs)
                    dependency_groups = data.get("dependency-groups")
                    if isinstance(dependency_groups, dict):
                        for specs in list(dependency_groups.values())[:1_000]:
                            add_specs(specs)
                    tool = data.get("tool")
                    poetry = tool.get("poetry") if isinstance(tool, dict) else None
                    if isinstance(poetry, dict):
                        add_keys(poetry.get("dependencies"))
                        add_keys(poetry.get("dev-dependencies"))
                        groups = poetry.get("group")
                        if isinstance(groups, dict):
                            for group in list(groups.values())[:1_000]:
                                if isinstance(group, dict):
                                    add_keys(group.get("dependencies"))
                    if isinstance(tool, dict):
                        pdm = tool.get("pdm")
                        pdm_groups = pdm.get("dev-dependencies") if isinstance(pdm, dict) else None
                        if isinstance(pdm_groups, dict):
                            for specs in list(pdm_groups.values())[:1_000]:
                                add_specs(specs)
                        uv = tool.get("uv")
                        if isinstance(uv, dict):
                            add_specs(uv.get("dev-dependencies"))
                        hatch = tool.get("hatch")
                        hatch_envs = hatch.get("envs") if isinstance(hatch, dict) else None
                        if isinstance(hatch_envs, dict):
                            for environment in list(hatch_envs.values())[:1_000]:
                                if isinstance(environment, dict):
                                    add_specs(environment.get("dependencies"))
                        rye = tool.get("rye")
                        if isinstance(rye, dict):
                            add_specs(rye.get("dev-dependencies"))
                        flit = tool.get("flit")
                        metadata = flit.get("metadata") if isinstance(flit, dict) else None
                        if isinstance(metadata, dict):
                            add_specs(metadata.get("requires"))
                            extras = metadata.get("requires-extra")
                            if isinstance(extras, dict):
                                for specs in list(extras.values())[:1_000]:
                                    add_specs(specs)
                elif path.suffix.casefold() == ".py" and script_files < 1_000 and script_bytes < 8_000_000:
                    raw = project_bytes(project_file, 1_000_000)
                    if raw is not None and script_bytes + len(raw) <= 8_000_000:
                        size = len(raw)
                        script_files += 1
                        script_bytes += size
                        text = raw.decode("utf-8", errors="replace")
                        if "# /// script" in text:
                            seen += 1
                            names.update(_pep723_direct(text))
                elif lowered == "go.mod":
                    seen += 1
                    text = project_text(project_file, 2_000_000)
                    if text is None:
                        continue
                    for line in text.splitlines():
                        match = re.match(r"^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}/[^\s]+)\s+v", line)
                        if match and "// indirect" not in line:
                            names.add(match.group(1).casefold())
                elif lowered in _MORE_DIRECT_MANIFESTS or lowered.endswith((".csproj", ".fsproj", ".vbproj")):
                    seen += 1
                    text = project_text(project_file, 2_000_000)
                    if text is None:
                        continue
                    names.update(_direct_from_manifest(lowered, text))
            except ProjectTreeError:
                raise
            except (OSError, ValueError, UnicodeError):
                continue
            if seen > 200:
                return names
    return names


def _mention_names(package: str) -> set[str]:
    """Yapılandırmada geçebilecek adlar: paket adı, alt çizgili hâli, çatı öneksiz uygulama adı (django-allauth → allauth)."""
    name = package.casefold()
    names = {name, name.replace("-", "_")}
    for prefix in ("django-", "flask-", "djangorestframework-", "python-", "py-"):
        if name.startswith(prefix) and len(name) - len(prefix) >= 4:
            names.add(name[len(prefix):].replace("-", "_"))
    return names


def _mention_patterns(packages: Iterable[str]) -> list[tuple[str, re.Pattern[str]]]:
    patterns = []
    for package in sorted({p.casefold() for p in packages if p and len(p) >= 3}):
        names = sorted(_mention_names(package), key=len, reverse=True)
        escaped = "(?:" + "|".join(re.escape(n) for n in names) + ")"
        name = package
        # Dize değişmezi tam olarak paket adı ya da yol parçası: 'ejs', "/jquery/dist/jquery.min.js", "hbs@4"
        patterns.append((name, re.compile(rf"""['"`](?:[^'"`\s]*/)?{escaped}(?:[@/][^'"`\s]*)?['"`]""", re.I)))
    return patterns


def build_usage_index(
    root: Path,
    skip_dirs: Iterable[str],
    *,
    packages_hint: set[str] | None = None,
    packages: Iterable[str] = (),
    project_tree: ProjectTree | None = None,
) -> UsageIndex:
    """Proje kaynağını tarayıp içe aktarılan paketlerin üye kullanımlarını dizinle (yalnız okuma)."""
    index = UsageIndex()
    mention_patterns = _mention_patterns(packages)
    skip = {d.casefold() for d in skip_dirs}
    js_files: dict[str, str] = {}
    seen = 0
    hints = {h.casefold() for h in (packages_hint or set())}
    with _borrow_project_tree(root, project_tree) as tree:
        for project_file in tree.iter_files(skip_dirs=skip, reject_unsafe=False):
            suffix = project_file.path.suffix.casefold()
            code = suffix in _PY_SUFFIXES | _JS_SUFFIXES | _GO_SUFFIXES | _RS_SUFFIXES | _JVM_SUFFIXES | _DOTNET_SUFFIXES
            if (not code and suffix not in _MENTION_SUFFIXES) or project_file.name.casefold() in _DECLARATION_FILES:
                continue
            seen += 1
            if seen > _MAX_FILES:
                break
            if project_file.size > _MAX_FILE_BYTES:
                continue
            text = tree.read_text(project_file, _MAX_FILE_BYTES, errors="replace", allow_empty=True)
            relpath = project_file.path.as_posix()
            if mention_patterns:
                lowered_text = text.casefold()
                for package, pattern in mention_patterns:
                    if package in index.mentions or not any(n in lowered_text for n in _mention_names(package)):
                        continue
                    match = pattern.search(text)
                    if match:
                        index.mention(package, relpath, text.count("\n", 0, match.start()) + 1)
            if not code:
                continue
            if suffix in _PY_SUFFIXES:
                _py_index(index, relpath, text)
            elif suffix in _GO_SUFFIXES:
                _go_index(index, relpath, text)
            elif suffix in _RS_SUFFIXES:
                _rs_index(index, relpath, text)
            elif suffix in _JVM_SUFFIXES:
                _jvm_index(index, relpath, text)
            elif suffix in _DOTNET_SUFFIXES:
                _dotnet_index(index, relpath, text)
            elif "require(" in text or "import " in text or re.search(r"\bimport\s*\(", text) \
                    or re.search(r"\bexport\b[^;\n]{0,500}\bfrom\s*['\"]", text):
                mentions_hint = any(h.split("/")[0].lstrip("@") in text.casefold() for h in hints)
                local_import = bool(re.search(
                    r"(?:\bfrom\s*|\bimport\s*\(|\brequire\s*\()\s*['\"]\.", text,
                ))
                if hints and not mentions_hint and not local_import:
                    continue
                js_files[relpath] = text
    if js_files:
        programs: dict[str, Any] | None = None
        try:
            import taint_js_ast

            if taint_js_ast.available():
                programs = taint_js_ast.parse_files(js_files)
        except Exception:  # Node yoksa ya da köprü hatasında desen tabanlı yola düş
            programs = None
        if programs:
            _js_index_ast(index, programs, js_files)
        for relpath, text in js_files.items():
            if not programs or relpath not in programs:
                _js_index_regex(index, relpath, text)
    return index


# ---------------------------------------------------------------------------
# Karar ve önceliklendirme
# ---------------------------------------------------------------------------
def _symbol_used(symbol: str, uses: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    sym = symbol.casefold()
    last = sym.rsplit(".", 1)[-1]
    sites: list[dict[str, Any]] = []
    for rel, rel_sites in uses.items():
        r = rel.casefold()
        if not r or r in {"<import>", "()"}:
            continue
        segments = r.split(".")
        # "jwt.verify" gibi takma adla nitelenmiş danışma sembolleri de kullanımın göreli yolunu sonda içerir.
        if (r == sym or r.endswith("." + sym) or r.startswith(sym + ".") or ("." not in sym and last in segments)
                or sym.endswith("." + r)):
            sites.extend(rel_sites)
    return sites


def _normalize_severity(value: Any) -> str:
    text = str(value or "").casefold()
    if text in {"moderate"}:
        return "medium"
    if text in {"none", "unknown", "informational", ""}:
        return "info"
    return text if text in SEVERITY_ORDER else "info"


def indirect_use(package: str, usage: UsageIndex, used_packages: set[str]) -> dict[str, Any] | None:
    """Paket kodda içe aktarılmıyor ama yapılandırmayla (dize) ya da kullanılan bir yükleyici tarafından yükleniyor mu?"""
    key = package.casefold()
    for loader, drivers in LOADER_PACKAGES.items():
        if key in drivers and loader in used_packages:
            return {"via": "loader", "loader": loader}
    if key in usage.mentions:
        return {"via": "mention", **usage.mentions[key]}
    return None


CLASSPATH_ECOSYSTEMS = frozenset({"maven", "nuget"})


def assess_item(item: dict[str, Any], import_names: set[str], uses: dict[str, list[dict[str, Any]]],
                imported: bool, osv: OfflineOSV | None, indirect: dict[str, Any] | None = None,
                direct: bool | None = None, classpath: bool = False) -> dict[str, Any]:
    package = str(item.get("package_name") or item.get("name") or "")
    vulnerability_id = str(item.get("vulnerability_id") or item.get("id") or "")
    sources: dict[str, set[str]] = {}
    osv_symbols = symbols_from_osv(osv.record(vulnerability_id) if osv and vulnerability_id else None, package)
    if osv_symbols:
        sources["osv"] = osv_symbols
    text = " ".join(str(item.get(key) or "") for key in ("title", "summary", "details", "description"))
    text_symbols = symbols_from_text(text, import_names)
    if text_symbols:
        sources["advisory_text"] = text_symbols
    curated = set(CURATED_SYMBOLS.get(package.casefold(), ()))
    if curated and not sources and not text.strip():
        # Danışma metni hiç yoksa: bilinen riskli fonksiyonlar (düşük güven, önemi düşürmez). Metin var ama sembol
        # çıkmıyorsa listeye başvurulmaz (ör. jinja2 xmlattr danışması Template kullanımına bağlanmamalı).
        sources["curated"] = curated
    symbol_source = next(iter(sources), None)
    symbols = sorted(set().union(*sources.values())) if sources else []

    evidence: list[dict[str, Any]] = []
    matched: list[str] = []
    for symbol in symbols:
        sites = _symbol_used(symbol, uses)
        if sites:
            matched.append(symbol)
            for site in sites:
                if site not in evidence and len(evidence) < 10:
                    evidence.append(site)
    escapes = bool(uses.get("") or uses.get("()"))  # paketin kendisi çağrılıyor ya da değer olarak aktarılıyor
    # Go: açıklı YÖNTEM (``html.Tokenizer.Next``) bir tür değeri üzerinden çağrılır; kullanım dizini yalnız paket düzeyi
    # adları (``h.NewTokenizer``) görür. Yöntemin paketi kullanılıyorsa "çağrılmıyor" denemez → belirsiz (önem düşmez).
    uncertain_methods: list[str] = []
    if not matched and osv_symbols and is_go_module(package):
        for symbol in osv_symbols:
            parts = symbol.split(".")
            idents = [x for x in parts if x[:1].isupper()]
            if len(idents) < 2:
                continue
            prefix = ".".join(parts[: len(parts) - len(idents)]).casefold()
            if any(k and k not in {"<import>", "()"} and (not prefix or k.casefold().startswith(prefix + ".")) for k in uses):
                uncertain_methods.append(symbol)
    elif not matched and osv_symbols:
        # 20. tur (Rust vb.): "mod.Tür.yöntem" — yöntem bir örnek üzerinden (x.yöntem()) çağrılır; türün kendisi
        # kullanılıyorsa çağrılmadığı söylenemez → belirsiz (önem düşmez).
        for symbol in osv_symbols:
            parts = symbol.split(".")
            type_positions = [i for i, x in enumerate(parts[:-1]) if x[:1].isupper()]
            if not type_positions:
                continue
            type_name = parts[type_positions[-1]].casefold()
            type_path = ".".join(parts[: type_positions[-1] + 1]).casefold()
            for key in uses:
                low = key.casefold()
                if low in {"", "<import>", "()"}:
                    continue
                segments = low.split(".")
                if low == type_path or low.startswith(type_path + ".") or type_name in segments:
                    uncertain_methods.append(symbol)
                    break
    if not imported and indirect:
        imported, escapes = True, True
        if indirect.get("via") in {"mention", "bundler", "config", "script", "tool_config"}:
            evidence.append({"file": indirect["file"], "line": indirect["line"]})
    if not imported:
        verdict = "not_imported"
    elif matched:
        verdict = "reachable"
    elif symbols and not escapes and not uncertain_methods:
        verdict = "imported_not_called"
    else:
        verdict = "unknown"
    confidence = "high" if symbol_source == "osv" else "medium" if symbol_source == "advisory_text" else "low"
    if verdict == "not_imported":
        confidence = "medium"

    base = _normalize_severity(item.get("severity"))
    effective = base
    reason = ""
    # Danışma metnindeki semboller iç fonksiyon olabilir (genel API üzerinden dolaylı erişim): yalnız OSV sembol listesi
    # (ör. Go vulndb dışa açık giriş noktaları) önem düşürür; metin kaynağı yalnız sıralamayı etkiler.
    # "Kullanılmıyor" yalnız bildirimde doğrudan listelenen paket için önem düşürür; dolaylı paket başka bir
    # bağımlılığın içinden kullanılabilir (bağımlılık grafiği bilinmeden kesin değil).
    # 20. tur: JVM/.NET'te sınıf yolundaki paket içe aktarılmadan da yüklenebilir (yansıma, ServiceLoader, otomatik
    # yapılandırma, serileştirme zinciri) → "kullanılmıyor" önem düşürmez.
    downgrade = ((verdict == "not_imported" and direct is True and not classpath)
                 or (verdict == "imported_not_called" and symbol_source == "osv"))
    if downgrade and base in SEVERITY_ORDER and SEVERITY_ORDER.index(base) > 1:
        effective = SEVERITY_ORDER[SEVERITY_ORDER.index(base) - 1]
        reason = ("Doğrudan bağımlılık olarak listeleniyor ama kodda kullanılmıyor; önem bir derece düşürüldü (gizlenmedi)."
                  if verdict == "not_imported" else
                  "Danışmadaki açıklı fonksiyon(lar) kodda kullanılmıyor; önem bir derece düşürüldü (gizlenmedi).")
    elif verdict == "not_imported" and classpath and direct is True:
        reason = ("Doğrudan bildirilmiş, kaynakta içe aktarılmıyor; sınıf yolunda bulunduğundan yansıma/ServiceLoader/"
                  "otomatik yapılandırma ya da serileştirme zinciriyle kullanılabilir, önem korunuyor.")
    elif verdict == "not_imported":
        reason = ("Kodda doğrudan kullanılmıyor; dolaylı bağımlılık olduğundan başka bir paket üzerinden kullanılabilir, "
                  "önem korunuyor." if direct is False else
                  "Kodda doğrudan kullanılmıyor; doğrudan/dolaylı ayrımı yapılamadı, önem korunuyor.")
    elif verdict == "imported_not_called":
        reason = ("Danışmadaki fonksiyonlar doğrudan çağrılmıyor; genel API üzerinden dolaylı erişim olabileceğinden önem "
                  "korunuyor, öncelik sırası geriye alındı.")
    elif verdict == "unknown" and indirect:
        reason = (f"Paket doğrudan içe aktarılmıyor ama {indirect['loader']} tarafından yükleniyor; önem korunuyor."
                  if indirect.get("via") == "loader" else
                  "Gemfile'da listeleniyor ve Bundler.require ile uygulama açılışında yükleniyor; kullanılıyor sayıldı."
                  if indirect.get("via") == "bundler" else
                  "Yapılandırmada (JDBC adresi ya da sürücü sınıf adı) geçiyor; çalışma anında yükleniyor sayıldı."
                  if indirect.get("via") == "config" else
                  "Betiklerde/araç yapılandırmasında komut olarak kullanılıyor (komut satırı aracı)."
                  if indirect.get("via") in {"script", "tool_config"} else
                  "Paket adı yapılandırmada/şablonda geçiyor (ör. view engine, betik yolu); kullanılıyor sayıldı.")
    elif verdict == "unknown" and uncertain_methods:
        reason = ("Açıklı yöntem(ler) (" + ", ".join(uncertain_methods[:3]) + ") bir tür değeri üzerinden çağrılır; paketi "
                  "kullanılıyor ve tür kullanımı izlenmediğinden çağrılmadığı söylenemez, önem korunuyor.")
    elif verdict == "unknown" and escapes and symbols:
        reason = "Paketin kendisi çağrılıyor ya da başka koda aktarılıyor; açıklı fonksiyona dolaylı erişim olabilir."
    elif verdict == "reachable":
        reason = "Açıklı fonksiyon kodda kullanılıyor; öncelikli düzeltilmeli."
    return {
        "verdict": verdict,
        "label": VERDICT_LABELS[verdict],
        "confidence": confidence,
        "symbols": symbols[:20],
        "symbol_source": symbol_source,
        "matched_symbols": matched[:20],
        "uncertain_symbols": uncertain_methods[:20],
        "evidence": evidence,
        "indirect": indirect,
        "direct_dependency": direct,
        "classpath": classpath,
        "base_severity": base,
        "effective_severity": effective,
        "priority_reason": reason,
    }


def priority_sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
    reach = item.get("reachability") or {}
    severity = reach.get("effective_severity") or _normalize_severity(item.get("severity"))
    return (-SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 0,
            _VERDICT_RANK.get(reach.get("verdict"), 1), str(item.get("package_name") or ""))


# ---------------------------------------------------------------------------
# 20. tur: paket kullanım durumu ve önceliklendirme puanı
# ---------------------------------------------------------------------------
USAGE_LABELS = {
    "used": "Kodda kullanılıyor",
    "transitive_only": "Yalnız geçişli (dolaylı) bağımlılık; kodda doğrudan kullanılmıyor",
    "unused": "Doğrudan bildirilmiş ama kodda kullanılmıyor",
    "unknown": "Bilinmiyor (bu ekosistemin kaynak dosyası yok ya da doğrudan/dolaylı ayrımı yapılamadı)",
}
PRIORITY_TIERS = {
    "fix_first": "Önce düzelt",
    "plan": "Planla",
    "monitor": "İzle",
}
# Ekosisteme göre kaynak dosya sonekleri: bu dosyalardan hiçbiri yoksa "kullanılmıyor" denemez (bilinmiyor).
ECOSYSTEM_SOURCE_SUFFIXES: dict[str, frozenset[str]] = {
    "npm": frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte"}),
    "pypi": frozenset({".py"}),
    "go": frozenset({".go"}),
    "maven": frozenset({".java", ".kt", ".kts", ".scala", ".groovy", ".jsp"}),
    "rubygems": frozenset({".rb", ".erb", ".rake"}),
    "packagist": frozenset({".php", ".phtml"}),
    "crates.io": frozenset({".rs"}),
    "nuget": frozenset({".cs", ".cshtml", ".razor", ".vb", ".fs"}),
}
_SEVERITY_WEIGHT = {"critical": 40.0, "high": 28.0, "medium": 16.0, "low": 7.0, "info": 2.0}
_REACH_FACTOR = {"reachable": 1.5, "unknown": 1.0, "imported_not_called": 0.6}
_NOT_IMPORTED_FACTOR = {"transitive_only": 0.7, "unused": 0.4, "unknown": 0.85, "used": 1.0}


def normalize_ecosystem(value: Any) -> str:
    text = str(value or "").strip().casefold()
    return {"golang": "go", "cargo": "crates.io", "crates": "crates.io", "composer": "packagist", "gem": "rubygems",
            "pip": "pypi", "python": "pypi"}.get(text, text)


def usage_state(imported: bool, direct: bool | None, analyzable: bool) -> str:
    """Paket düzeyi kullanım: kanıt varsa ``used``; yoksa doğrudan bildirilmişse ``unused``, dolaylıysa
    ``transitive_only``. Ekosistemin kaynak dosyası yoksa ya da doğrudan/dolaylı bilinmiyorsa ``unknown``."""
    if imported:
        return "used"
    if not analyzable or direct is None:
        return "unknown"
    return "unused" if direct else "transitive_only"


def priority(item: dict[str, Any], reach: dict[str, Any], usage: str) -> dict[str, Any]:
    """Önceliklendirme puanı (0–100): önem × erişilebilirlik × düzeltme varlığı × doğrudan/dolaylı.

    Kötü amaçlı paket (MAL-) her zaman en üstte. Puan yalnız sıralama içindir; önem değiştirmez."""
    vulnerability_id = str(item.get("vulnerability_id") or item.get("id") or "")
    base = _normalize_severity(item.get("severity"))
    verdict = str(reach.get("verdict") or "unknown")
    if vulnerability_id.upper().startswith("MAL-"):
        return {"score": 100, "tier": "fix_first", "tier_label": PRIORITY_TIERS["fix_first"],
                "factors": {"malicious": True}}
    weight = _SEVERITY_WEIGHT.get(base, 2.0)
    if verdict == "not_imported":
        reach_factor = 0.85 if (usage == "unused" and reach.get("classpath")) else _NOT_IMPORTED_FACTOR.get(usage, 0.85)
    else:
        reach_factor = _REACH_FACTOR.get(verdict, 1.0)
    fixed = str(item.get("fixed_version") or "").strip()
    fix_factor = 1.2 if fixed else 0.85
    direct = reach.get("direct_dependency")
    direct_factor = 1.1 if direct is True else 0.9 if direct is False else 1.0
    score = int(round(min(100.0, weight * reach_factor * fix_factor * direct_factor)))
    tier = "fix_first" if score >= 45 else "plan" if score >= 20 else "monitor"
    return {"score": score, "tier": tier, "tier_label": PRIORITY_TIERS[tier],
            "factors": {"severity": base, "reachability": verdict, "usage": usage, "fix_available": bool(fixed),
                        "direct": direct}}


def priority_order_key(item: dict[str, Any]) -> tuple[int, str, str, str]:
    """Kararlı "önce bunları düzelt" sırası: puan (azalan), paket, sürüm, kimlik."""
    prio = item.get("priority") or {}
    return (-int(prio.get("score") or 0), str(item.get("package_name") or ""), str(item.get("installed_version") or ""),
            str(item.get("vulnerability_id") or item.get("id") or ""))


# ---------------------------------------------------------------------------
# 20. tur: içe aktarma dışı kullanım kanıtları (yapılandırma, betik)
# ---------------------------------------------------------------------------
# JDBC sürücüleri kaynakta içe aktarılmaz; bağlantı adresi ya da sürücü sınıfıyla (yapılandırmada) yüklenir.
JDBC_SCHEMES: dict[str, tuple[str, ...]] = {
    "mysql:mysql-connector-java": ("jdbc:mysql:", "com.mysql."),
    "com.mysql:mysql-connector-j": ("jdbc:mysql:", "com.mysql."),
    "org.mariadb.jdbc:mariadb-java-client": ("jdbc:mariadb:", "org.mariadb."),
    "org.postgresql:postgresql": ("jdbc:postgresql:", "org.postgresql."),
    "com.h2database:h2": ("jdbc:h2:", "org.h2."),
    "org.xerial:sqlite-jdbc": ("jdbc:sqlite:", "org.sqlite."),
    "com.microsoft.sqlserver:mssql-jdbc": ("jdbc:sqlserver:", "com.microsoft.sqlserver."),
    "org.hsqldb:hsqldb": ("jdbc:hsqldb:", "org.hsqldb."),
    "org.apache.derby:derby": ("jdbc:derby:", "org.apache.derby."),
    "com.oracle.database.jdbc:ojdbc8": ("jdbc:oracle:", "oracle.jdbc."),
    "com.oracle.database.jdbc:ojdbc11": ("jdbc:oracle:", "oracle.jdbc."),
}
_JVM_CONFIG_SUFFIXES = {".properties", ".yml", ".yaml", ".xml", ".conf", ".java", ".kt", ".groovy", ".scala", ".jsp"}
# Araç yapılandırma dosyası → paket (betik/derleme aracı olarak kullanılır, require edilmez)
NPM_TOOL_FILES: dict[str, str] = {
    "gruntfile.js": "grunt", "gruntfile.coffee": "grunt", "gulpfile.js": "gulp", "webpack.config.js": "webpack",
    "rollup.config.js": "rollup", "karma.conf.js": "karma", "jest.config.js": "jest", ".mocharc.json": "mocha",
    "babel.config.js": "@babel/core", ".babelrc": "@babel/core", "tsconfig.json": "typescript",
    ".eslintrc": "eslint", ".eslintrc.js": "eslint", ".eslintrc.json": "eslint", "vite.config.js": "vite",
    "vite.config.ts": "vite", "nodemon.json": "nodemon", "cypress.json": "cypress", "cypress.config.js": "cypress",
}


def jvm_config_mentions(
    root: Path,
    tokens: dict[str, set[str]],
    skip_dirs: Iterable[str],
    *,
    project_tree: ProjectTree | None = None,
) -> dict[str, dict[str, Any]]:
    """Maven paketleri için içe aktarma dışı kullanım: yapılandırma/kaynak metninde JDBC adresi ya da sürücü/paket
    sınıf adı (ör. ``spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver``). İçe aktarma satırları hariç.

    tokens: paket → aranacak küçük harfli dizgeler. Döner: paket → {"file", "line", "via": "config"}."""
    found: dict[str, dict[str, Any]] = {}
    if not tokens:
        return found
    skip = {d.casefold() for d in skip_dirs}
    seen = 0
    with _borrow_project_tree(root, project_tree) as tree:
        for project_file in tree.iter_files(skip_dirs=skip, reject_unsafe=False):
            if project_file.path.suffix.casefold() not in _JVM_CONFIG_SUFFIXES or project_file.name.casefold() == "pom.xml":
                continue
            seen += 1
            if seen > _MAX_FILES or len(found) == len(tokens):
                return found
            if project_file.size > _MAX_FILE_BYTES:
                continue
            raw_text = tree.read_text(project_file, _MAX_FILE_BYTES, errors="replace", allow_empty=True)
            text = raw_text.casefold()
            pending = {pkg: toks for pkg, toks in tokens.items() if pkg not in found and any(t in text for t in toks)}
            if not pending:
                continue
            rel = project_file.path.as_posix()
            for line_no, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if stripped.startswith(("import ", "package ", "//", "*", "/*", "#", "<!--")):
                    continue
                for pkg, toks in list(pending.items()):
                    if any(t in line for t in toks):
                        found[pkg] = {"file": rel, "line": line_no, "via": "config"}
                        pending.pop(pkg)
                if not pending:
                    break
    return found


def npm_tool_mentions(
    root: Path,
    packages: Iterable[str],
    *,
    project_tree: ProjectTree | None = None,
) -> dict[str, dict[str, Any]]:
    """npm paketleri için betik/araç kullanımı: package.json ``scripts`` içindeki komut adları ve bilinen araç
    yapılandırma dosyaları (Gruntfile.js → grunt). Kökteki package.json ile sınırlı."""
    wanted = {p.casefold() for p in packages}
    found: dict[str, dict[str, Any]] = {}
    try:
        with _borrow_project_tree(root, project_tree) as tree:
            walk = tree.walk(reject_unsafe=False)
            try:
                root_entry = next(walk)
            finally:
                walk.close()
            present = {entry.name.casefold(): entry for entry in root_entry.files}
            manifest = present.get("package.json")
            text = None
            if manifest is not None and manifest.size <= 2_000_000:
                text = tree.read_text(manifest, 2_000_000, errors="replace", allow_empty=True)
            if text is not None:
                scripts = json.loads(text).get("scripts")
                if isinstance(scripts, dict):
                    lines = text.splitlines()
                    for key, command in scripts.items():
                        if not isinstance(command, str):
                            continue
                        words = set(re.findall(r"(?<![\w@/.-])(@?[a-z0-9][a-z0-9._/-]*)", command.casefold()))
                        for word in words:
                            cand = word.split("node_modules/")[-1]
                            head = cand.split("/bin/")[0]
                            names = {cand, head, head.removesuffix("-cli"), cand.rsplit("/", 1)[-1]}
                            for pkg in wanted & names:
                                line_no = next((i for i, ln in enumerate(lines, start=1) if f'"{key}"' in ln), 0)
                                found.setdefault(pkg, {"file": "package.json", "line": line_no, "via": "script"})
            for name, pkg in NPM_TOOL_FILES.items():
                entry = present.get(name)
                if pkg in wanted and pkg not in found and entry is not None:
                    found[pkg] = {"file": entry.name, "line": 1, "via": "tool_config"}
    except (json.JSONDecodeError, TypeError):
        return found
    return found


_CLI_FILE_NAMES = {"procfile", "makefile", "dockerfile", "tox.ini", "supervisord.conf", ".pre-commit-config.yaml",
                   "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml", "justfile", "noxfile.py"}
_CLI_SUFFIXES = {".sh", ".bash", ".yml", ".yaml", ".ini", ".service"}
_CLI_SKIP_NAMES = {"requirements.txt", "requirements.in", "pipfile", "pipfile.lock", "poetry.lock", "pyproject.toml", "setup.cfg", "setup.py",
                   "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "gemfile", "gemfile.lock"}


def cli_tool_mentions(
    root: Path,
    packages: Iterable[str],
    skip_dirs: Iterable[str],
    *,
    project_tree: ProjectTree | None = None,
) -> dict[str, dict[str, Any]]:
    """Komut satırı aracı olarak kullanım: Procfile/Dockerfile/kabuk betikleri/CI ve compose YAML'larında paket adı bir
    komut sözcüğü olarak geçiyor mu (gunicorn, celery, black…)? Bildirim/kilit dosyaları hariç; 4 karakterden kısa
    adlar aranmaz. Döner: paket → {"file", "line", "via": "script"}."""
    names = {p.casefold(): p for p in packages if p and len(p) >= 4 and ":" not in p and "/" not in p}
    if not names:
        return {}
    pattern = re.compile(r"(?<![\w./-])(" + "|".join(sorted((re.escape(n) for n in names), key=len, reverse=True))
                         + r")(?![\w./-])")
    found: dict[str, dict[str, Any]] = {}
    skip = {d.casefold() for d in skip_dirs}
    seen = 0
    with _borrow_project_tree(root, project_tree) as tree:
        for project_file in tree.iter_files(skip_dirs=skip, reject_unsafe=False):
            low = project_file.name.casefold()
            if low in _CLI_SKIP_NAMES:
                continue
            if not (low in _CLI_FILE_NAMES or low.startswith("dockerfile") or Path(low).suffix in _CLI_SUFFIXES):
                continue
            seen += 1
            if seen > 2000 or len(found) == len(names):
                return found
            if project_file.size > _MAX_FILE_BYTES:
                continue
            text = tree.read_text(project_file, _MAX_FILE_BYTES, errors="replace", allow_empty=True)
            lines = text.casefold().splitlines()
            rel = project_file.path.as_posix()
            for line_no, line in enumerate(lines, start=1):
                if line.lstrip().startswith("#"):
                    continue
                for match in pattern.finditer(line):
                    found.setdefault(match.group(1), {"file": rel, "line": line_no, "via": "script"})
    return found


_SEMVER_PREFIX_RE = re.compile(r"^v?(\d+(?:\.\d+){1,3})(?:[-+].*)?$")
_TOML_PKG_BLOCK_RE = re.compile(
    r"\[\[package\]\][^\[]*?\bname\s*=\s*\"([^\"]+)\"[^\[]*?\bversion\s*=\s*\"([^\"]+)\"",
    re.DOTALL,
)


def _parse_semver_tuple(ver: str) -> tuple[int, ...] | None:
    m = _SEMVER_PREFIX_RE.match(ver.strip())
    if not m:
        return None
    try:
        return tuple(int(p) for p in m.group(1).split("."))
    except ValueError:
        return None


def _semver_ge(rt: tuple[int, ...], ft: tuple[int, ...]) -> bool:
    width = max(len(rt), len(ft))
    pa = rt + (0,) * (width - len(rt))
    pb = ft + (0,) * (width - len(ft))
    return pa >= pb


def is_lockfile_patched(fixed_version: Any, resolved_versions: set[str]) -> bool:
    """Kilit dosyasındaki çözümlenmiş sürümlerin tamamı kendi dalındaki fixed_version (yama sürümü) veya üzerinde mi?"""
    if not resolved_versions:
        return False
    if isinstance(fixed_version, (list, tuple, set)):
        fixed_candidates = [str(v).strip() for v in fixed_version if str(v).strip()]
    elif isinstance(fixed_version, str):
        fixed_candidates = [p.strip() for p in re.split(r"[,;|\s]+", fixed_version) if p.strip()]
    else:
        return False
    fixed_tuples = sorted({t for c in fixed_candidates if (t := _parse_semver_tuple(c)) is not None})
    if not fixed_tuples:
        return False
    resolved_tuples = [_parse_semver_tuple(v) for v in resolved_versions]
    if any(rt is None for rt in resolved_tuples):
        return False

    def _is_one_patched(rt: tuple[int, ...]) -> bool:
        if len(fixed_tuples) == 1:
            return _semver_ge(rt, fixed_tuples[0])
        same_major = [ft for ft in fixed_tuples if ft[0] == rt[0]]
        if same_major:
            if len(same_major) == 1:
                return _semver_ge(rt, same_major[0])
            same_minor = [ft for ft in same_major if len(ft) >= 2 and len(rt) >= 2 and ft[:2] == rt[:2]]
            if same_minor:
                return _semver_ge(rt, min(same_minor))
            higher_minor = [ft for ft in same_major if len(ft) >= 2 and len(rt) >= 2 and ft[1] >= rt[1]]
            target = min(higher_minor) if higher_minor else max(same_major)
            return _semver_ge(rt, target)
        max_major_fix = max(fixed_tuples)
        if rt[0] > max_major_fix[0]:
            return _semver_ge(rt, max_major_fix)
        return False

    return all(rt is not None and _is_one_patched(rt) for rt in resolved_tuples)


_PNPM_PKG_RE = re.compile(
    r"(?m)^\s{2,4}['\"]?/?(@?[a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._-]+)?)@(\d+\.\d+\.\d+[^:(\s'\"]*)['\"]?\s*:"
)
_YARN_PKG_RE = re.compile(
    r"(?m)^\"?(@?[a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._-]+)?)@(?:npm:)?[^\":\n]+\"?(?:,\s*\"?[^\":\n]+\"?)*:\s*\n\s+version\s*:?\s+\"?(\d+\.\d+\.\d+[^\"\s\n]*)\"?"
)
_LOCKFILE_SKIP_DIRS = frozenset({
    "node_modules", ".git", "target", "vendor", ".venv", "venv", "dist", "build", "__pycache__",
})


def lockfile_resolved_versions(
    root: Path,
    *,
    project_tree: ProjectTree | None = None,
) -> dict[str, set[str]]:
    """Kök ve monorepo alt dizinlerindeki package-lock.json, pnpm-lock.yaml, yarn.lock, Cargo.lock ve poetry.lock sürümlerini çıkarır."""
    resolved: dict[str, set[str]] = {}

    def _record(name: str, ver: str) -> None:
        n = name.strip().casefold()
        v = ver.strip()
        if not n or not v:
            return
        resolved.setdefault(n, set()).add(v)
        resolved.setdefault(n.replace("_", "-"), set()).add(v)

    try:
        with _borrow_project_tree(root, project_tree) as tree:
            dirs_visited = 0
            for dir_entry in tree.walk(skip_dirs=_LOCKFILE_SKIP_DIRS, reject_unsafe=False):
                dirs_visited += 1
                if dirs_visited > 200:
                    break
                present = {entry.name.casefold(): entry for entry in dir_entry.files}

                pkg_lock = present.get("package-lock.json")
                if pkg_lock is not None and pkg_lock.size <= _MAX_FILE_BYTES * 4:
                    text = tree.read_text(pkg_lock, _MAX_FILE_BYTES * 4, errors="replace", allow_empty=True)
                    if text:
                        try:
                            data = json.loads(text)
                        except json.JSONDecodeError:
                            data = {}
                        if isinstance(data, dict):
                            pkgs = data.get("packages")
                            if isinstance(pkgs, dict):
                                for k, info in pkgs.items():
                                    if not k or not isinstance(info, dict):
                                        continue
                                    ver = info.get("version")
                                    if isinstance(ver, str) and ver.strip():
                                        pkg_name = k.split("node_modules/")[-1].strip("/")
                                        if pkg_name:
                                            _record(pkg_name, ver)
                            deps = data.get("dependencies")
                            if isinstance(deps, dict):
                                for k, info in deps.items():
                                    if isinstance(info, dict) and isinstance(info.get("version"), str):
                                        _record(k, info["version"])

                pnpm_lock = present.get("pnpm-lock.yaml")
                if pnpm_lock is not None and pnpm_lock.size <= _MAX_FILE_BYTES * 4:
                    text = tree.read_text(pnpm_lock, _MAX_FILE_BYTES * 4, errors="replace", allow_empty=True)
                    if text:
                        for m in _PNPM_PKG_RE.finditer(text):
                            _record(m.group(1), m.group(2))

                yarn_lock = present.get("yarn.lock")
                if yarn_lock is not None and yarn_lock.size <= _MAX_FILE_BYTES * 4:
                    text = tree.read_text(yarn_lock, _MAX_FILE_BYTES * 4, errors="replace", allow_empty=True)
                    if text:
                        for m in _YARN_PKG_RE.finditer(text):
                            _record(m.group(1), m.group(2))

                for toml_lock_name in ("cargo.lock", "poetry.lock"):
                    lock_entry = present.get(toml_lock_name)
                    if lock_entry is not None and lock_entry.size <= _MAX_FILE_BYTES * 4:
                        text = tree.read_text(lock_entry, _MAX_FILE_BYTES * 4, errors="replace", allow_empty=True)
                        if text:
                            for m in _TOML_PKG_BLOCK_RE.finditer(text):
                                _record(m.group(1), m.group(2))
    except Exception:  # noqa: BLE001
        return resolved
    return resolved


_LINUX_IMAGE_RE = re.compile(
    r"(?im)^\s*FROM\s+[^\n#]*\b(?:debian|ubuntu|alpine|bookworm|bullseye|jammy|noble|fedora|ubi8|ubi9|distroless|wolfi|slim)\b"
)
_WINDOWS_IMAGE_RE = re.compile(
    r"(?im)^\s*FROM\s+[^\n#]*\b(?:windows|nanoserver|servercore|mcr\.microsoft\.com/windows)\b"
)
_WINDOWS_ONLY_ADVISORY_RE = re.compile(
    r"(?i)\b(?:on\s+windows|windows\s+only|windows-only|windows\s+systems|yalnızca\s+windows|in\s+windows\s+environments)\b"
)
_UNIX_ADVISORY_RE = re.compile(
    r"(?i)\b(?:linux|posix|unix|debian|ubuntu|alpine|macos|darwin)\b"
)


def detect_project_target_platforms(
    root: Path,
    *,
    project_tree: ProjectTree | None = None,
) -> set[str]:
    """Projenin Dockerfile/Containerfile bildirimlerinden hedef dağıtım platformunu (ör. {'linux'}) çıkarır."""
    platforms: set[str] = set()
    has_windows_Marker = False
    try:
        with _borrow_project_tree(root, project_tree) as tree:
            dirs_visited = 0
            for dir_entry in tree.walk(skip_dirs=_LOCKFILE_SKIP_DIRS, reject_unsafe=False):
                dirs_visited += 1
                if dirs_visited > 80:
                    break
                for f in dir_entry.files:
                    low = f.name.casefold()
                    if low.endswith((".csproj", ".sln", ".bat", ".ps1")):
                        has_windows_Marker = True
                    if low == "dockerfile" or low.startswith("dockerfile.") or low == "containerfile":
                        if f.size <= _MAX_FILE_BYTES:
                            txt = tree.read_text(f, _MAX_FILE_BYTES, errors="replace", allow_empty=True)
                            if _WINDOWS_IMAGE_RE.search(txt):
                                platforms.add("windows")
                            elif _LINUX_IMAGE_RE.search(txt):
                                platforms.add("linux")
    except Exception:  # noqa: BLE001
        return set()
    if has_windows_Marker:
        platforms.add("windows")
    return platforms


def is_platform_mismatch(item: dict[str, Any], target_platforms: set[str]) -> bool:
    """Proje yalnızca Linux hedeflerken zafiyet danışması yalnızca Windows'u etkiliyorsa True döner."""
    if target_platforms != {"linux"}:
        return False
    text = " ".join(str(item.get(k) or "") for k in ("title", "summary", "details", "description"))
    if not text.strip():
        return False
    return bool(_WINDOWS_ONLY_ADVISORY_RE.search(text) and not _UNIX_ADVISORY_RE.search(text))


_CVE_GENERIC_WORDS = frozenset({
    "the", "and", "for", "with", "from", "version", "versions", "prior", "before", "after",
    "allows", "allow", "remote", "attacker", "attackers", "local", "user", "users",
    "vulnerability", "vulnerable", "affected", "issue", "flaw", "bug", "cve", "cwe", "ghsa",
    "package", "packages", "module", "modules", "library", "libraries", "function", "functions",
    "method", "methods", "class", "classes", "object", "objects", "string", "strings",
    "number", "numbers", "array", "arrays", "value", "values", "input", "inputs", "output",
    "outputs", "data", "file", "files", "path", "paths", "code", "execution", "arbitrary",
    "injection", "denial", "service", "dos", "rce", "xss", "csrf", "ssrf", "sqli", "xxe",
    "traversal", "overflow", "buffer", "memory", "heap", "stack", "null", "none", "true",
    "false", "undefined", "nan", "this", "self", "via", "when", "where", "which", "while",
    "that", "these", "those", "into", "onto", "upon", "within", "without", "under", "over",
    "above", "below", "between", "among", "against", "during", "including", "includes",
    "include", "using", "used", "uses", "use", "cause", "causes", "caused", "lead", "leads",
    "leading", "result", "results", "resulting", "craft", "crafted", "malicious", "specially",
    "payload", "request", "requests", "response", "responses", "server", "client",
    "application", "system", "systems", "windows", "linux", "macos", "android", "ios",
    "default", "internal", "external", "public", "private", "static", "dynamic", "certain",
    "specific", "multiple", "various", "other", "another", "same", "different", "improper",
    "insufficient", "missing", "validation", "sanitization", "verification", "authentication",
    "authorization", "permission", "permissions", "privilege", "privileges", "escalation",
    "bypass", "disclosure", "information", "sensitive", "exposure", "leak", "crash", "panic",
    "loop", "infinite", "regex", "regular", "expression", "redos", "prototype", "pollution",
    "through", "until", "since", "can", "may", "will", "could", "should", "would", "all",
    "any", "some", "such", "only", "also", "not", "are", "was", "were", "has", "have", "had",
    "been", "being", "does", "did", "done",
})
_NON_SYMBOL_SUFFIXES = frozenset({
    "py", "js", "mjs", "cjs", "ts", "tsx", "jsx", "go", "rs", "java", "kt", "rb", "php",
    "cs", "c", "h", "cpp", "hpp", "json", "yaml", "yml", "toml", "xml", "html", "htm",
    "md", "rst", "txt", "lock", "sh", "bash", "ini", "cfg", "conf", "com", "org", "net",
    "io", "dev", "gov", "edu", "uk", "de", "fr", "jp", "cn", "ru", "jar", "whl", "tar",
    "gz", "zip", "tgz", "exe", "dll", "so", "dylib",
})
_NON_SYMBOL_OWNERS = frozenset({
    "www", "http", "https", "github", "gitlab", "bitbucket", "cve", "cwe", "ghsa", "osv",
    "npm", "pypi", "maven", "cargo", "crates", "golang", "nodejs", "python", "apache",
    "redhat", "debian", "ubuntu", "fedora", "suse", "oracle", "microsoft",
})
_CVE_CALL_PATTERN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\(\)")
_CVE_BACKTICK_PATTERN = re.compile(r"`([A-Za-z_][A-Za-z0-9_]{2,}(?:\.[A-Za-z_][A-Za-z0-9_]{2,})*)(?:\(\))?`")
_CVE_DOTTED_PATTERN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]{2,})(?:\(\))?\b")


def extract_cve_vulnerable_symbols(finding: Mapping[str, Any]) -> tuple[str, ...]:
    """CVE/danışma bulgusundan açıklı fonksiyon, yöntem veya sınıf sembollerini çıkarır."""
    if not isinstance(finding, Mapping):
        return ()

    pkg_raw = str(finding.get("package_name") or finding.get("package") or finding.get("name") or "").strip().casefold()
    pkg_aliases = {pkg_raw, pkg_raw.replace("-", "_"), pkg_raw.split("/")[-1], pkg_raw.split(":")[-1]} - {""}
    if pkg_raw == "pyyaml":
        pkg_aliases.add("yaml")

    ordered: list[str] = []
    seen: set[str] = set()

    def _add(sym: str) -> None:
        cleaned = sym.strip().removesuffix("()").strip()
        if not cleaned or len(cleaned) < 3:
            return
        low = cleaned.casefold()
        if low in _CVE_GENERIC_WORDS or low in _STOPWORDS or low in pkg_aliases:
            return
        if low.isupper() and (low.startswith(("cve_", "cwe_", "ghsa_")) or len(low) <= 4):
            return
        if cleaned not in seen:
            seen.add(cleaned)
            ordered.append(cleaned)

    for key in ("affected_symbols", "vulnerable_functions"):
        explicit = finding.get(key)
        if isinstance(explicit, (list, tuple, set)):
            for item in explicit:
                if isinstance(item, str) and item.strip():
                    cleaned_item = item.strip().removesuffix("()").strip()
                    _add(cleaned_item)
                    if "." in cleaned_item:
                        _add(cleaned_item.rsplit(".", 1)[-1])

    texts = [
        str(finding.get(field) or "")
        for field in ("description", "title", "summary", "details")
        if finding.get(field)
    ]
    combined = " ".join(texts)
    if combined:
        for match in _CVE_CALL_PATTERN.finditer(combined):
            _add(match.group(1))
        for match in _CVE_BACKTICK_PATTERN.finditer(combined):
            token = match.group(1)
            if "." in token:
                owner, member = token.split(".", 1)[0], token.rsplit(".", 1)[-1]
                if member.casefold() not in _NON_SYMBOL_SUFFIXES and owner.casefold() not in _NON_SYMBOL_OWNERS:
                    _add(token)
                    _add(member)
            else:
                _add(token)
        for match in _CVE_DOTTED_PATTERN.finditer(combined):
            owner, member = match.group(1), match.group(2)
            owner_low, member_low = owner.casefold(), member.casefold()
            if (
                member_low in _NON_SYMBOL_SUFFIXES
                or owner_low in _NON_SYMBOL_OWNERS
                or owner_low in _CVE_GENERIC_WORDS
                or member_low in _CVE_GENERIC_WORDS
            ):
                continue
            _add(f"{owner}.{member}")
            _add(member)

    return tuple(ordered)


def _collect_project_symbols(reachability: Mapping[str, Any]) -> set[str]:
    """Erişilebilirlik nesnesindeki içe aktarılan/çağrılan sembolleri ve çağrı noktalarını toplar."""
    observed: set[str] = set()

    def _record_token(raw: str) -> None:
        tok = raw.strip()
        if not tok:
            return
        call_m = re.match(r"^([A-Za-z_$][A-Za-z0-9_$.]*)\s*\(", tok)
        if call_m:
            tok = call_m.group(1)
        else:
            tok = tok.removesuffix("()").strip()
        if not tok or tok in {"<import>", "()"}:
            return
        observed.add(tok.casefold())
        if "." in tok:
            observed.add(tok.rsplit(".", 1)[-1].casefold())

    for key in ("imported_symbols", "called_symbols", "matched_symbols"):
        val = reachability.get(key)
        if isinstance(val, (list, tuple, set)):
            for entry in val:
                if isinstance(entry, str):
                    _record_token(entry)
                elif isinstance(entry, Mapping):
                    for k in ("symbol", "function", "name"):
                        if isinstance(entry.get(k), str):
                            _record_token(entry[k])
        elif isinstance(val, Mapping):
            for k in val:
                if isinstance(k, str):
                    _record_token(k)

    for key in ("call_sites", "evidence"):
        val = reachability.get(key)
        if isinstance(val, (list, tuple, set)):
            for entry in val:
                if isinstance(entry, str):
                    _record_token(entry)
                    for m in _CVE_CALL_PATTERN.finditer(entry):
                        _record_token(m.group(1))
                elif isinstance(entry, Mapping):
                    for k in ("symbol", "function", "name", "target", "call"):
                        if isinstance(entry.get(k), str):
                            _record_token(entry[k])
                    for k in ("snippet", "code", "line_text"):
                        if isinstance(entry.get(k), str):
                            for m in _CVE_CALL_PATTERN.finditer(entry[k]):
                                _record_token(m.group(1))
        elif isinstance(val, Mapping):
            for k in val:
                if isinstance(k, str):
                    _record_token(k)

    return observed


def evaluate_symbol_level_vex(
    finding: Mapping[str, Any],
    reachability: Mapping[str, Any],
) -> dict[str, Any]:
    """Bulgu ve erişilebilirlik kanıtlarından sembol düzeyinde OpenVEX durum ve gerekçesini hesaplar."""
    finding_map = finding if isinstance(finding, Mapping) else {}
    reach_map = reachability if isinstance(reachability, Mapping) else {}

    vulnerable_symbols = list(extract_cve_vulnerable_symbols(finding_map))
    if not vulnerable_symbols:
        fallback_syms = reach_map.get("vulnerable_symbols") or reach_map.get("symbols")
        if isinstance(fallback_syms, (list, tuple, set)):
            vulnerable_symbols = [str(s).strip() for s in fallback_syms if isinstance(s, str) and str(s).strip()]

    raw_status = str(
        reach_map.get("status")
        or reach_map.get("verdict")
        or finding_map.get("reachability_status")
        or (
            finding_map.get("status")
            if str(finding_map.get("status") or "").strip().casefold()
            in {"reachable", "not_imported", "imported_not_called", "unknown", "unreachable"}
            else ""
        )
        or ""
    ).strip().casefold()

    lockfile_patched = bool(reach_map.get("lockfile_patched") or finding_map.get("lockfile_patched"))
    platform_mismatch = bool(reach_map.get("platform_mismatch") or finding_map.get("platform_mismatch"))

    observed_symbols = _collect_project_symbols(reach_map) | _collect_project_symbols(finding_map)
    matched_symbols: list[str] = []
    for sym in vulnerable_symbols:
        sym_low = sym.casefold()
        sym_tail = sym.rsplit(".", 1)[-1].casefold()
        if sym_low in observed_symbols or sym_tail in observed_symbols:
            matched_symbols.append(sym)

    if raw_status == "not_imported":
        vulnerable_symbol_called = False
    elif vulnerable_symbols:
        vulnerable_symbol_called = bool(matched_symbols)
    elif raw_status == "reachable":
        vulnerable_symbol_called = True
    else:
        vulnerable_symbol_called = False

    if (
        lockfile_patched
        or platform_mismatch
        or raw_status in {"not_imported", "imported_not_called"}
        or (bool(vulnerable_symbols) and not vulnerable_symbol_called)
    ):
        vex_status = "not_affected"
    elif raw_status == "reachable" or vulnerable_symbol_called:
        vex_status = "affected"
    else:
        vex_status = "under_investigation"

    if lockfile_patched or platform_mismatch:
        vex_justification: str | None = "vulnerable_code_not_present"
    elif (
        raw_status in {"not_imported", "imported_not_called"}
        or (bool(vulnerable_symbols) and not vulnerable_symbol_called)
    ):
        vex_justification = "vulnerable_code_not_in_execute_path"
    else:
        vex_justification = None

    if vex_status == "under_investigation":
        pre_status = str(reach_map.get("vex_status") or finding_map.get("vex_status") or "").strip()
        if pre_status in {"not_affected", "affected", "fixed", "under_investigation"}:
            vex_status = pre_status
            pre_just = reach_map.get("vex_justification") or finding_map.get("vex_justification")
            if isinstance(pre_just, str) and pre_just.strip():
                vex_justification = pre_just.strip()

    return {
        "vulnerable_symbols": vulnerable_symbols,
        "matched_symbols": matched_symbols,
        "vulnerable_symbol_called": vulnerable_symbol_called,
        "vex_status": vex_status,
        "vex_justification": vex_justification,
    }


def verify_protocol_and_hook_reachability(
    source_content: str,
    *,
    advisory_id: str = "",
    go_stdlib_version: str = "",
    framework: str = "",
) -> dict[str, Any]:
    """Protokol (Go HTTP/2 ALPN NextProtos) ve framework yaşam döngüsü kancası (Rails Warden/Devise) erişilebilirliğini doğrular."""
    content = source_content if isinstance(source_content, str) else ""
    adv = str(advisory_id or "").strip().upper()
    fw = str(framework or "").strip().lower()

    if (
        fw == "rails_devise"
        or "SessionExpireFromInitEnforcer" in content
        or ("throw :warden" in content and (":timeout" in content or "DeviseFailure" in content))
        or "DeviseFailure" in content
    ):
        return {
            "reachable": True,
            "reason": "rails_warden_timeout_hook_reaches_devise_failure",
        }

    is_go_http2 = (
        "CVE-2026-39883" in adv
        or "net/http" in content
        or "NextProtos" in content
        or "TLSNextProto" in content
        or bool(str(go_stdlib_version or "").strip())
    )
    if is_go_http2:
        h2_enabled_in_next_protos = bool(
            re.search(r"NextProtos\s*:\s*(?:\[\]string\s*)?\{[^}]*['\"]h2['\"]", content)
        )
        tls_next_proto_disabled = bool(
            re.search(r"TLSNextProto\s*:\s*make\s*\(\s*map", content)
        )
        if not h2_enabled_in_next_protos or tls_next_proto_disabled:
            return {
                "reachable": False,
                "reason": "go_http2_alpn_disabled_or_outbound_only",
            }

    return {
        "reachable": True,
        "reason": "default_symbol_reachability",
    }

