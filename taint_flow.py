"""Çevrimdışı kaynak → hedef (taint) veri akışı analizi.

Satır tabanlı dedektörlerin kaçırdığı veya yanlış işaretlediği akışları ayırt etmek için
kullanılır:

* Python: standart ``ast`` ile akışa duyarlı (atama sırası, if/else birleştirme,
  döngüler) izleme. **Fonksiyonlar arası ve dosyalar arası** analiz: her fonksiyon için
  bir özet (hangi parametre hangi hedefe ulaşıyor, hangisi dönüş değerine akıyor, dönüş
  değeri hangi kaynağı taşıyor) çıkarılır ve çağrı yerlerinde uygulanır. Çağrılar aynı
  modüldeki fonksiyonlara, ``import``/``from … import`` ile (göreli içe aktarma dahil)
  proje modüllerine, ``self.metot`` / ``Sınıf.metot`` ve basit tür izlemeyle
  (``s = Servis(); s.calistir(x)``) metotlara çözülür. Doğrulama koşulları (``if x not in
  IZINLI: abort()``, ``x.isdigit()``, ``re.fullmatch``, ``startswith``) ve sonlanan dallar
  (return/raise/abort) arındırıcı bariyer sayılır.
* JavaScript/TypeScript: yorum, dize, şablon dizesi (``${}``) ve düzenli ifade
  sabitlerini ayıran bir belirteçleyici üzerinde deklarasyon/atama izleme;
  ``const {a} = req.body`` yapısı, Express/Koa işleyicileri ve dosyalar arası
  ``router.post('/x', ctrl.create)`` işleyici adları desteklenir.

Kaynak etiketleri: ``request`` (HTTP istek girdisi, tarayıcı URL/çerez girdisi) ve
isteğe bağlı ``pii`` (çağıranın verdiği sınıflandırıcıya göre kişisel veri alanları).
Hedef türleri: ``log``, ``sql``, ``command``, ``eval``, ``html``, ``regex``, ``path``,
``ssrf``, ``deserialize``, ``redirect``. Veri tabanlı hedef/arındırıcı modelleri
``rules/taint/*.json`` dosyalarındadır (bkz. :mod:`taint_models`).

Analiz yaklaşıktır (sound değildir): çözülemeyen Python çağrıları taint taşımaz, JS'te
ise taşır. Ağ erişimi, alt süreç veya dosya yazımı yoktur.
"""

from __future__ import annotations

import ast
from contextlib import contextmanager
import contextvars
from contextvars import ContextVar
import dataclasses
from dataclasses import dataclass, field
import functools
import gc
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tomllib
from typing import Any, Callable, Iterator

from safe_file_read import read_text_bounded
import scan_scope
import taint_py_views
import taint_models


SINK_KINDS = (
    "log", "sql", "command", "eval", "html", "regex", "path", "ssrf", "deserialize", "redirect",
    "ldap", "xpath", "xxe", "session", "cookie",
    # Kısmi SSRF: ana makine sabit, yalnız yol/sorgu girdiden (ayrı, düşük önemli sınıf; tam SSRF ile karışmaz).
    "ssrf_partial",
    # NoSQL operatör enjeksiyonu (Python: yalnız JSON/gövde kaynaklı değerler; form/sorgu dizeleri nesne olamaz)
    # ve sunucu tarafı şablon enjeksiyonu (şablon metninin kendisi girdiden).
    "nosql", "ssti",
    # DynamoDB ifade/tablo enjeksiyonu: FilterExpression/KeyConditionExpression/PartiQL metni, tablo adı veya
    # eski tip ScanFilter anahtarı/işleci girdiden (değerler ExpressionAttributeValues ile bağlanmalı).
    "nosql_expr",
    # JSONP: istekten gelen geri çağırma adı JavaScript/JSON yanıtının başına yansıyor (CSP atlatma; HTML XSS değil).
    "jsonp",
)
PY_SUFFIXES = frozenset({".py"})
JS_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts"})
GO_SUFFIXES = frozenset({".go"})
RUBY_SUFFIXES = frozenset({".rb", ".erb", ".haml"})
# Java / C# / PHP: hafif dosyalar arası motor (taint_clike); Joern derin analizi ayrı araçtır.
# Kotlin (.kt): taint_kotlin Java benzeri metne çevirir, aynı motor "kotlin" lehçesiyle çalışır.
# Klasik ASP.NET: WebForms işaretlemesi (.aspx/.ascx/.master) ve ASMX/ASHX işleyicileri de C# motorunda.
CLIKE_SUFFIXES = frozenset({".java", ".cs", ".php", ".phtml", ".jsp", ".jspf", ".kt", ".cshtml", ".razor",
                            ".aspx", ".ascx", ".master", ".asmx", ".ashx"})
_CLIKE_LANGUAGE = {".java": "java", ".cs": "csharp", ".php": "php", ".phtml": "php", ".jsp": "java", ".jspf": "java",
                   ".kt": "kotlin", ".cshtml": "csharp", ".razor": "csharp", ".aspx": "csharp", ".ascx": "csharp",
                   ".master": "csharp", ".asmx": "csharp", ".ashx": "csharp"}
# Rust ve C/C++: saf Python belirteç tabanlı dosyalar arası motorlar (taint_rust, taint_cfamily; derleyici gerekmez).
RUST_SUFFIXES = frozenset({".rs"})
CFAMILY_SUFFIXES = frozenset({".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx"})
_CPP_SUFFIXES = frozenset({".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx"})
NATIVE_SUFFIXES = RUST_SUFFIXES | CFAMILY_SUFFIXES
MAX_SOURCE_BYTES = 1_000_000
MAX_ORIGINS = 8
# Proje geneli analiz sınırları (project_analyzer ile aynı ortam değişkenleri).
MAX_PROJECT_FILES = max(100, min(50_000, int(os.environ.get("SNIPER_PROJECT_MAX_FILES", "10000") or 10000)))
MAX_PROJECT_BYTES = max(1_000_000, min(1_000_000_000, int(os.environ.get("SNIPER_PROJECT_MAX_BYTES", "150000000") or 150000000)))

PiiClassifier = Callable[[str], bool]


def _source_limit() -> int:
    """Tek dosya taint sınırı: tarama kapsamı yükseltmişse onu, değilse modül ayarını kullan."""
    scope = scan_scope.current()
    return MAX_SOURCE_BYTES if scope.max_file_bytes == scan_scope.DEFAULT_MAX_FILE_BYTES else scope.max_file_bytes


def _project_bytes_limit() -> int:
    scope = scan_scope.current()
    return MAX_PROJECT_BYTES if scope.max_total_bytes == scan_scope.DEFAULT_MAX_TOTAL_BYTES else scope.max_total_bytes


def _project_files_limit() -> int:
    scope = scan_scope.current()
    return MAX_PROJECT_FILES if scope.max_files == scan_scope.DEFAULT_MAX_FILES else scope.max_files

_ENABLED: ContextVar[bool] = ContextVar("sniper_taint_enabled", default=True)
_PROJECT_JS_HANDLERS: ContextVar[frozenset[str]] = ContextVar("sniper_taint_js_handlers", default=frozenset())
_PROJECT: ContextVar["_ProjectState | None"] = ContextVar("sniper_taint_project", default=None)
_PROJECT_CONTEXT_DEPTH: ContextVar[int] = ContextVar("sniper_taint_project_context_depth", default=0)


def is_enabled() -> bool:
    """``SNIPER_TAINT_ANALYSIS=0`` ortam değişkeni veya :func:`disabled` ile kapatılabilir."""
    return _ENABLED.get() and os.environ.get("SNIPER_TAINT_ANALYSIS", "1") != "0"


@contextmanager
def disabled() -> Iterator[None]:
    token = _ENABLED.set(False)
    try:
        yield
    finally:
        _ENABLED.reset(token)


@contextmanager
def js_handler_scope(names: frozenset[str]) -> Iterator[None]:
    """Proje taraması boyunca dosyalar arası Express işleyici adlarını etkinleştir."""
    token = _PROJECT_JS_HANDLERS.set(frozenset(names))
    try:
        yield
    finally:
        _PROJECT_JS_HANDLERS.reset(token)


def project_context(func: Callable[..., Any]) -> Callable[..., Any]:
    """Proje taraması fonksiyonunu kopyalanmış bağlamda çalıştır; içeride etkinleştirilen
    işleyici adları çağrı bitince (istisnada da) sızmaz."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        caller_depth = _PROJECT_CONTEXT_DEPTH.get()
        context = contextvars.copy_context()

        def isolated() -> Any:
            # Kopyalanan bağlam bir dış proje analizinden gelebilir. İç çağrı temiz başlar,
            # bitince token reset'i kopyadaki dış değeri geri getirir; çağıranın bağlamına
            # hiçbir yazım yapılmadığından iç içe ve eşzamanlı taramalar birbirini silmez.
            project_token = _PROJECT.set(None)
            handlers_token = _PROJECT_JS_HANDLERS.set(frozenset())
            depth_token = _PROJECT_CONTEXT_DEPTH.set(caller_depth + 1)
            try:
                return func(*args, **kwargs)
            finally:
                _PROJECT_CONTEXT_DEPTH.reset(depth_token)
                _PROJECT_JS_HANDLERS.reset(handlers_token)
                _PROJECT.reset(project_token)

        try:
            return context.run(isolated)
        finally:
            # Eski/çıplak activate_project çağrısı üst düzey çağıranın bağlamına sızmışsa onu temizle.
            # İç içe project_context çağrısında caller_depth > 0 olur; dış projenin bağlamı korunur.
            if caller_depth == 0:
                _PROJECT.set(None)
                _PROJECT_JS_HANDLERS.set(frozenset())

    return wrapper


def activate_project(root: Path, skip_dirs: set[str] | frozenset[str]) -> None:
    """Proje taramasını etkinleştir: dosyalar arası JS işleyici adları ve (ilk Python
    dosyası analiz edilirken tembel olarak kurulan) proje geneli Python analizi.

    Yalnızca :func:`project_context` ile sarılmış fonksiyon içinde, doğrulanmış kökle çağırın.
    """
    _PROJECT_JS_HANDLERS.set(project_js_handler_names(root, skip_dirs))
    _PROJECT.set(_ProjectState(Path(root), frozenset(skip_dirs)))


# Geriye uyumluluk: denetçiler bu adla çağırır.
activate_project_js_handlers = activate_project


@dataclass(frozen=True)
class Flow:
    language: str
    sink_kind: str
    sink: str
    line: int
    source: str
    source_label: str
    source_line: int
    via: tuple[str, ...] = ()
    # Proje analizinde hedefin ve kaynağın dosyası (göreli yol); tek dosyada boş olabilir.
    file: str = ""
    source_file: str = ""
    # 27. tur (C): dosya:satır kanıt zinciri (çağrı yerleri, yapı alanı yazımları, yönlendirme tabloları)
    hops: tuple[str, ...] = ()
    # 27. tur düzeltmesi (C/C++): zincirde modelce kanıtlanmamış adım var mı (belirsiz çağrı çözümlemesi, işlev
    # işaretçisi, bilinmeyen işlevden geçiş, küresel/yapı alanı modeli, ad örüntüsüyle tanınan soket) ve via içindeki
    # aktarım adımı (yardımcının dönüş/çıkış parametresi) sayısı. Diğer motorlarda varsayılan değerde kalır.
    weak: bool = False
    xfer: int = 0

    @property
    def cross_file(self) -> bool:
        return bool(self.source_file) and self.source_file != self.file

    def describe(self) -> str:
        chain = " → ".join(self.via)
        middle = f" → {chain}" if chain else ""
        where = f"{self.source_file} satır" if self.cross_file else "satır"
        text = f"{self.source} ({where} {self.source_line}){middle} → {self.sink} (satır {self.line})"
        if self.hops:
            text += f"; kanıt zinciri: {' → '.join(self.hops)}"
        return text

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "sink_kind": self.sink_kind,
            "sink": self.sink,
            "sink_line": self.line,
            "source": self.source,
            "source_label": self.source_label,
            "source_line": self.source_line,
            "via": list(self.via),
        }
        if self.cross_file:
            data["source_file"] = self.source_file
        if self.hops:
            data["chain"] = list(self.hops)
        return data


@dataclass
class Analysis:
    language: str
    flows: list[Flow] = field(default_factory=list)
    # Motorun değerlendirdiği hedef çağrıları: (tür, satır)
    evaluated_sinks: set[tuple[str, int]] = field(default_factory=set)
    # Belirsiz hedefler: girdi, modellenmemiş bir çağrıdan (ör. open(yol).read(), bilinmeyen
    # kütüphane fonksiyonu) geçerken iz kaybedildi; "temiz" hükmü verilemez.
    uncertain_sinks: set[tuple[str, int]] = field(default_factory=set)
    # Yetkili bağlam (yetki/nonce denetimli yöntem) akışları: doğrulanmış akış sayılmaz, ``flows`` içinde değildir;
    # proje analizi bunları düşük önemli "yönetici yetkisi gerekli" notu olarak raporlar.
    privileged_flows: list[Flow] = field(default_factory=list)
    # Kaynak sınırı, sabit nokta veya ayrıştırma bütçesi aşıldığında sonuç güvenli biçimde
    # "temiz" sayılmamalı. Sınırlama kodları kullanıcıya proje uyarısı olarak da taşınır.
    analysis_complete: bool = True
    limitations: tuple[str, ...] = ()

    def mark_incomplete(self, *reasons: str) -> "Analysis":
        self.analysis_complete = False
        self.limitations = tuple(dict.fromkeys((*self.limitations, *(r for r in reasons if r))))
        return self

    def is_unreached_sink(self, kind: str, line: int) -> bool:
        """Hedef değerlendirildi, istek akışı yok ve girdi izi modellenmemiş bir çağrıda kaybolmadı."""
        return self.analysis_complete and self.is_clean_sink(kind, line, "request") \
            and (kind, line) not in self.uncertain_sinks

    def flows_of(self, kind: str, label: str | None = None) -> list[Flow]:
        return [f for f in self.flows if f.sink_kind == kind and (label is None or f.source_label == label)]

    def is_clean_sink(self, kind: str, line: int, label: str | None = None) -> bool:
        """Hedef bu satırda değerlendirildi ve (etikete göre) arındırılmamış akış yok."""
        return self.analysis_complete and (kind, line) in self.evaluated_sinks and not any(
            f.sink_kind == kind and f.line == line and (label is None or f.source_label == label)
            for f in self.flows
        )


@dataclass(frozen=True)
class _Origin:
    label: str
    source: str
    line: int
    via: tuple[str, ...]
    cleaned: frozenset[str] = frozenset()
    file: str = ""


Taint = tuple[_Origin, ...]
_EMPTY: Taint = ()
# Fonksiyon özeti çıkarılırken parametreleri temsil eden sembolik kaynak etiketi.
_PARAM = "§param"
# Modellenmemiş bir çağrıda izi kaybolan girdi (akış raporlanmaz, hedef "belirsiz" sayılır).
_UNCERTAIN = "§uncertain"
# Metot özetinde "self.<alan>" değerini temsil eden sembolik kaynak (alan duyarlı akış).
_FIELD = "§field"
# Serbest yardımcı işlev özetinde ``parametre.<alan>`` değeri.
_PARAM_FIELD = "§param_field"
_ORIGIN_PRIORITY = {_PARAM: 0, _FIELD: 0, _PARAM_FIELD: 0, _UNCERTAIN: 2}
MAX_VIA = 8


def _union(*parts: Taint) -> Taint:
    # Hızlı yol: tek boş olmayan parça zaten normal biçimdedir (benzersiz anahtar, ≤ MAX_ORIGINS):
    # tüm taint değerleri _union, tekil köken veya anahtar koruyan dönüşümlerle (_via/_clean) üretilir.
    single: Taint | None = None
    for part in parts:
        if part:
            if single is not None:
                break
            single = part
    else:
        return single if single is not None else _EMPTY
    seen: dict[tuple[str, str, int, str], _Origin] = {}
    for part in parts:
        for origin in part:
            key = (origin.label, origin.source, origin.line, origin.file)
            existing = seen.get(key)
            if existing is None:
                seen[key] = origin
            elif existing.cleaned != origin.cleaned:
                # Aynı kaynağın temizlenmemiş bir kopyası varsa temizlik kesişimi alınır.
                seen[key] = _Origin(
                    existing.label, existing.source, existing.line, existing.via,
                    existing.cleaned & origin.cleaned, existing.file,
                )
    values = list(seen.values())
    if len(values) > MAX_ORIGINS:
        # Sembolik parametre kaynakları özet doğruluğu için öncelikli tutulur.
        values = sorted(values, key=lambda o: _ORIGIN_PRIORITY.get(o.label, 1))[:MAX_ORIGINS]
    return tuple(values)


def _clean(taint: Taint, kinds: frozenset[str]) -> Taint:
    return tuple(_Origin(o.label, o.source, o.line, o.via, o.cleaned | kinds, o.file) for o in taint)


def _uncleaned(taint: Taint) -> Taint:
    return tuple(_Origin(o.label, o.source, o.line, o.via, frozenset(), o.file) if o.cleaned else o for o in taint)


def _via(taint: Taint, name: str) -> Taint:
    return tuple(
        _Origin(o.label, o.source, o.line, (o.via + (name,))[-MAX_VIA:], o.cleaned, o.file) for o in taint
    )


# MongoDB: değeri JavaScript olarak çalışan operatörler (dize kaynak da kod enjeksiyonu yapar).
_MONGO_CODE_OPERATORS = frozenset({"$where", "$function", "$accumulator"})


def _lxml_parser_unsafe(call: ast.Call) -> bool:
    """lxml ``XMLParser`` dış varlık/DTD yüklemeyi açıkça etkinleştiriyor mu?"""
    for kw in call.keywords:
        value = kw.value.value if isinstance(kw.value, ast.Constant) else None
        if kw.arg in ("resolve_entities", "load_dtd", "dtd_validation", "huge_tree") and value is True and \
                kw.arg != "huge_tree":
            return True
        if kw.arg == "no_network" and value is False:
            return True
    return False


def _constructed_arg(call: Any, index: int) -> bool:
    """Çağrının ``index``. konumsal argümanı yerinde kurulmuş bir metin mi (f-dize, +/% birleştirme, .format())?"""
    args = getattr(call, "args", None) or []
    if not isinstance(call, ast.Call) or index >= len(args):
        return False
    a = args[index]
    if isinstance(a, ast.Await):
        a = a.value
    if isinstance(a, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in a.values)
    if isinstance(a, ast.BinOp) and isinstance(a.op, (ast.Add, ast.Mod)):
        return True
    return isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) and a.func.attr == "format"
_NOSQL_OPERATOR_MARK = " (sorgu anahtarı/operatörü)"


def _operator_marked(taint: Taint) -> Taint:
    """Kökeni "sorgu anahtarı/operatörü" olarak işaretle: dize kaynak da operatör/ifade seçebilir (bkz. _live)."""
    return tuple(o if o.source.endswith(_NOSQL_OPERATOR_MARK) or o.label in (_PARAM, _UNCERTAIN) else
                 _Origin(o.label, o.source + _NOSQL_OPERATOR_MARK, o.line, o.via, o.cleaned, o.file) for o in taint)


def _live(taint: Taint, kind: str) -> list[_Origin]:
    if kind == "nosql_key":
        return [o for o in taint if "nosql" not in o.cleaned]
    if kind == "nosql":
        # Python istek dizeleri (form/sorgu/başlık/yol parametresi) sözlük olamaz: operatör enjeksiyonu yalnız
        # JSON/gövde kaynaklı değerlerle (JS kökenleri ayrı modellenir: qs sorgu dizesinden nesne üretir).
        return [o for o in taint if kind not in o.cleaned and not (
            o.label == "request" and o.file.endswith(".py") and not _JSON_CAPABLE_SOURCE_RE.search(o.source)
            and not o.source.endswith(_NOSQL_OPERATOR_MARK))]
    return [o for o in taint if kind not in o.cleaned]


_JSON_CAPABLE_SOURCE_RE = re.compile(
    r"json|get_data|\.data\b|\.body\b|media|bounded_stream|\.stream\b|parametre:(?:event|body|payload|data|input|json)\b",
    re.IGNORECASE,
)


_ALL_KINDS = frozenset(SINK_KINDS)
_GENERIC_SANITIZER_RE = re.compile(r"sanitiz|escape|clean|strip_control|purify|xss|validat", re.IGNORECASE)
_LOG_MASK_RE = re.compile(r"mask|redact|hash|hmac|anonymi[sz]|pseudonymi[sz]|tokeni[sz]|encrypt|obfuscat", re.IGNORECASE)


def _named_sanitizer_kinds(name: str) -> frozenset[str] | None:
    """Ada göre arındırıcı: hangi hedef türleri için temizler (None: arındırıcı değil)."""
    lowered = name.lower()
    if lowered in {"re.escape", "regex.escape", "escaperegexp", "_.escaperegexp", "lodash.escaperegexp", "escape_regex", "escape_string_regexp", "escapestringregexp"}:
        return frozenset({"regex"})
    if lowered in {"shlex.quote", "pipes.quote", "shellescape", "shell_quote", "shell-quote"}:
        return frozenset({"command"})
    if lowered in {"repr", "json.dumps", "json.stringify", "ascii"}:
        return frozenset({"log"})
    if lowered in {"encodeuricomponent", "encodeuri", "urllib.parse.quote", "quote", "quote_plus", "urllib.parse.quote_plus"}:
        return frozenset({"log", "html", "command", "ssrf_partial"})
    last = lowered.rsplit(".", 1)[-1]
    if _LOG_MASK_RE.search(last):
        return frozenset({"log"})
    if _GENERIC_SANITIZER_RE.search(last):
        return _ALL_KINDS - {"eval"}
    return None


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

_PY_REQUEST_ROOTS = frozenset({"request", "self.request", "flask.request"})  # "req": urllib giden istek nesnesi (yanlış pozitif)
_PY_REQUEST_ATTRS = frozenset({
    "args", "form", "json", "values", "data", "cookies", "headers", "files", "GET", "POST", "body",
    "query_params", "path_params", "get_json", "get_data", "META", "FILES", "COOKIES", "query_string",
    "stream", "view_args", "match_info", "query", "rel_url", "content", "path_info", "raw_path",
    "remote_addr", "access_route", "user_agent", "host", "referrer", "method",
    "url", "base_url", "host_url", "full_path", "scheme", "url_root", "script_root",
    "content_type", "mimetype", "accept_mimetypes", "authorization",
})
# Yalnız tip açıklamasıyla bilinen istek nesnelerinde (Azure Functions HttpRequest): giden
# ``requests`` isteğinin ``request.params`` alanı kaynak sayılmasın diye ayrı tutulur.
_PY_TYPED_REQUEST_ATTRS = frozenset({
    "params", "route_params", "get_body",
    "_params", "media", "bounded_stream",  # Falcon Request
})
# Yalnız tip/giriş noktasıyla bilinen istek nesnelerinde okunan metotlar (Falcon).
_PY_TYPED_REQUEST_METHODS = frozenset({
    "get_param", "get_param_as_list", "get_header", "get_media", "get_cookie_values", "get_header_as_datetime",
})
# Falcon kaynak sınıfı yanıtlayıcıları: on_get(self, req, resp, **uri_alanları), on_post_ek(...).
_FALCON_RESPONDER_RE = re.compile(r"^on_(?:get|post|put|patch|delete|head|options)(?:_\w+)?$")
# aiohttp/Starlette: await request.post() / request.json() / request.form() vb.
_PY_REQUEST_METHODS = frozenset({"get_json", "get_data", "post", "json", "text", "read", "form", "body", "multipart", "stream",
                                 "readline", "readlines", "recv", "recvfrom"})
# İçe aktarma ile istek nesnesi olan adlar (``from connexion import request as r``, ``connexion.request``).
_PY_REQUEST_IMPORT_ROOTS = frozenset({"flask.request", "connexion.request", "quart.request"})
# Standart kütüphane HTTP/soket sunucu işleyicileri: alt sınıfta self.path/headers/rfile istek verisidir.
_PY_STDLIB_HANDLER_BASES = frozenset({
    "http.server.BaseHTTPRequestHandler", "http.server.SimpleHTTPRequestHandler", "http.server.CGIHTTPRequestHandler",
    "BaseHTTPServer.BaseHTTPRequestHandler", "SimpleHTTPServer.SimpleHTTPRequestHandler",
    "CGIHTTPServer.CGIHTTPRequestHandler", "socketserver.BaseRequestHandler", "socketserver.StreamRequestHandler",
    "socketserver.DatagramRequestHandler", "SocketServer.BaseRequestHandler", "SocketServer.StreamRequestHandler",
    "wsgiref.simple_server.WSGIRequestHandler",
})
_PY_STDLIB_HANDLER_ATTRS = frozenset({"path", "headers", "requestline", "raw_requestline"})
# WTForms / Flask-WTF form sınıfları: Form(request.form) alanları (form.x.data) istek verisidir; FlaskForm()
# argümansız kurulduğunda request.form'u kendisi bağlar.
_WTFORMS_BASES = frozenset({"wtforms.Form", "wtforms.form.Form", "flask_wtf.FlaskForm", "flask_wtf.Form",
                            "flask_wtf.form.FlaskForm"})
_FLASK_WTF_BASES = frozenset({"flask_wtf.FlaskForm", "flask_wtf.Form", "flask_wtf.form.FlaskForm"})
# İsteğin kendi yolu/adresi (request.path, full_path, url): bağlantıyla saldırgan belirleyebilir (yansıtılmış
# XSS/SSTI/SQL); yönlendirme/SSRF/dosya yolu ve günlük için istemcinin kendi isteğidir.
_PY_REQUEST_URL_ATTRS = frozenset({"path", "full_path", "url", "scheme"})
_PY_REQUEST_URL_SAFE = frozenset({"redirect", "ssrf", "ssrf_partial", "path", "log"})
_TORNADO_HANDLER_BASES = frozenset({"tornado.web.RequestHandler", "tornado.websocket.WebSocketHandler"})
_TORNADO_ARG_METHODS = frozenset({"get_argument", "get_arguments", "get_query_argument", "get_query_arguments",
                                  "get_body_argument", "get_body_arguments", "get_cookie", "decode_argument"})
_TORNADO_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "on_message", "open"})
# İkinci derece (kayıtlı) veri: veritabanından okunan değerler "stored" etiketli kaynaktır.
_PY_DB_FETCH_METHODS = frozenset({"fetchone", "fetchall", "fetchmany"})
_PY_ORM_READ_METHODS = frozenset({
    "get", "filter", "first", "last", "all", "values", "values_list", "get_or_none", "one", "one_or_none",
    "scalar", "scalars", "scalar_one", "scalar_one_or_none", "find_one", "find",
})
_PY_ORM_WRITE_CALLS = frozenset({"create", "update", "get_or_create", "update_or_create", "insert", "insert_one",
                                  "update_one", "values"})
# Kayıtlı veri |safe ile şablonda basılıyor ve alan kullanıcının yazdığı bir alan: kalıcı XSS (project_analyzer).
USER_WRITTEN_FIELD_MARK = "kullanıcının yazdığı alan"
_TEMPLATE_EXPR_RE = re.compile(r"\{\{-?\s*([A-Za-z_][\w.]*)")
_PY_FULL_SANITIZERS = frozenset({
    "int", "float", "bool", "len", "abs", "round", "complex", "hash", "id", "ord",
    "uuid.UUID", "UUID", "isinstance", "callable", "datetime.fromisoformat", "date.fromisoformat",
    "ipaddress.ip_address", "ipaddress.ip_network", "decimal.Decimal", "Decimal",
})
_PY_PROPAGATING_CALLS = frozenset({
    "str", "bytes", "list", "tuple", "set", "frozenset", "dict", "sorted", "reversed", "min", "max",
    "sum", "format", "next", "iter", "enumerate", "zip", "map", "filter", "getattr", "vars",
    "json.loads", "urllib.parse.unquote", "unquote", "unquote_plus", "base64.b64decode",
    "markupsafe.Markup", "Markup", "copy.copy", "copy.deepcopy",
})
_PY_STRING_METHODS = frozenset({
    "strip", "lstrip", "rstrip", "lower", "upper", "casefold", "title", "capitalize", "split", "rsplit",
    "splitlines", "join", "format", "format_map", "replace", "encode", "decode", "get", "getlist",
    "pop", "items", "values", "keys", "copy", "removeprefix", "removesuffix", "center", "ljust",
    "rjust", "zfill", "partition", "rpartition", "expandtabs", "translate", "to_dict", "dict",
    "model_dump", "first", "all", "read", "readline", "readlines",
})
_PY_LOG_METHODS = frozenset({"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "log"})
_PY_SQL_METHODS = frozenset({"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query", "mogrify"})
_PY_SUBPROCESS = frozenset({
    "subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_output",
    "subprocess.check_call", "call", "run", "Popen", "check_output", "check_call",
})
_PY_REGEX_FUNCS = frozenset({"compile", "match", "search", "fullmatch", "findall", "finditer", "sub", "subn", "split"})
_PY_ROUTE_DECORATORS = frozenset({"get", "post", "put", "patch", "delete", "route", "api_route", "websocket", "options", "head"})
_PY_SAFE_ANNOTATIONS = frozenset({
    "int", "float", "bool", "UUID", "uuid.UUID", "datetime", "date", "datetime.datetime", "datetime.date",
    "Decimal", "decimal.Decimal", "PositiveInt", "conint",
})
# Gelen HTTP isteği türleri (tip açıklamasıyla işaretlenen parametre istek kökü sayılır). Giden istek
# sınıfları (requests.Request, urllib.request.Request) bilinçli olarak yok.
_PY_REQUEST_TYPES = frozenset({
    "fastapi.Request", "fastapi.requests.Request", "starlette.requests.Request", "starlette.requests.HTTPConnection",
    "flask.Request", "flask.wrappers.Request", "werkzeug.Request", "werkzeug.wrappers.Request",
    "werkzeug.wrappers.request.Request", "quart.Request", "django.http.HttpRequest", "django.http.request.HttpRequest",
    "django.core.handlers.wsgi.WSGIRequest", "rest_framework.request.Request", "aiohttp.web.Request",
    "aiohttp.web_request.Request", "aiohttp.web.BaseRequest", "sanic.Request", "sanic.request.Request",
    "tornado.httputil.HTTPServerRequest", "falcon.Request", "litestar.Request", "bottle.BaseRequest",
    "azure.functions.HttpRequest", "azure.functions._http.HttpRequest", "azure.functions.http.HttpRequest",
})
# Çatı giriş noktaları (dekoratör/rota tablosu dışında çağrılan işleyiciler). Kaynak sayılmayan parametreler:
# GraphQL ``info``/kök nesne, Connexion güvenlik parametreleri, sunucusuz ``context``.
_PY_ENTRY_NON_SOURCE = frozenset({"self", "cls", "info", "root", "parent", "obj", "_obj", "_", "_root", "_parent",
                                  "context", "ctx", "_context", "_ctx", "user", "token_info"})
# Chalice olay dekoratörleri (S3/zamanlanmış olaylar dış kullanıcı girdisi taşımaz, kapsam dışı).
_CHALICE_EVENT_DECORATORS = frozenset({"on_sns_message", "on_sqs_message", "on_ws_message", "lambda_function"})
# Lambda/benzeri sunucusuz işleyici adları ((event, context) imzasıyla birlikte aranır).
_PY_SERVERLESS_NAME_RE = re.compile(r"(?:^|_)handler$|^lambda_handler$|^main$|^handle$")
# Giriş noktası dinamik dağıtımla bulunan çatılar: bu modüllerde projede çağrılmayan fonksiyonun
# parametresinden hedefe giden akış "ulaşılamıyor" sayılmaz (giriş noktası modellenmemiş olabilir).
_PY_DYNAMIC_ENTRY_MODULES = frozenset({
    "connexion", "graphene", "graphene_django", "strawberry", "ariadne", "functions_framework", "azure",
    "chalice", "mangum", "aws_lambda_powertools", "zappa", "flask_restful", "flask_restx", "falcon", "pyramid",
    "tornado", "cherrypy", "bottle", "nameko", "flask_socketio", "socketio", "channels", "grpc", "spyne",
})
_OPENAPI_OPERATION_RE = re.compile(r"""^\s*["']?operationId["']?\s*:\s*["']?([A-Za-z_][\w.]{0,200})["']?\s*,?\s*$""", re.M)
_OPENAPI_CONTROLLER_RE = re.compile(r"""^\s*["']?x-openapi-router-controller["']?\s*:\s*["']?([A-Za-z_][\w.]{0,200})["']?\s*,?\s*$""", re.M)
_SERVERLESS_HANDLER_RE = re.compile(r"""^\s*["']?[Hh]andler["']?\s*:\s*["']?([\w./-]{1,200})\.([A-Za-z_]\w{0,100})["']?\s*,?\s*$""", re.M)
_ENTRY_CONFIG_SUFFIXES = frozenset({".yml", ".yaml", ".json"})
_ENTRY_CONFIG_MAX_FILES = 400
_ENTRY_CONFIG_MAX_BYTES = 2_000_000
# Tip açıklamasında sarmalayıcılar: Optional[X] / Annotated[X, …] → X; kaplar → öğe türü.
_ANNOTATION_UNWRAP = frozenset({"Optional", "Annotated", "Final", "ClassVar", "Required", "NotRequired", "ReadOnly"})
_ANNOTATION_ELEMENT = frozenset({
    "list", "List", "set", "Set", "frozenset", "FrozenSet", "Sequence", "MutableSequence", "Iterable", "Iterator",
    "Collection", "AbstractSet", "MutableSet", "deque", "Deque", "AsyncIterable", "AsyncIterator", "Generator",
    "AsyncGenerator", "tuple", "Tuple",
})
_FLASK_TYPED_PARAM_RE = re.compile(r"<(?:int|float|uuid):(\w+)>")
_PRINTF_RE = re.compile(r"%(?:\(\w+\))?[-#0 +]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[hlL]?([diouxXeEfFgGcrsa%])")
_LOG_NON_MESSAGE_KWARGS = frozenset({"extra", "exc_info", "stack_info", "stacklevel"})
_PY_PARAM_EXCLUDE = frozenset({"self", "cls", "request", "req", "db", "session", "response", "background_tasks", "current_user", "user"})


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else ""
    if isinstance(node, ast.Call):
        inner = _dotted(node.func)
        return f"{inner}()" if inner else ""
    return ""


_PY_GUARD_PREDICATES = frozenset({"isdigit", "isnumeric", "isdecimal", "isalnum", "isidentifier", "isalpha"})
_PY_TERMINATOR_CALLS = frozenset({"abort", "flask.abort", "sys.exit", "exit", "quit", "os._exit", "os.abort"})
_FILE_TYPE_VALIDATOR_RE = re.compile(r"file|ext|mime|type", re.IGNORECASE)
_PY_VALIDATOR_RE = re.compile(
    r"(?:^|_)(?:is_?)?(?:valid|safe|allow|allowed|permitted|whitelisted|allowlisted|trusted|public)(?:_|$)"
    r"|^validate|^check_(?:safe|allowed)|has_allowed_host",
    re.IGNORECASE,
)
_PY_SAFE_TYPES = frozenset({"int", "float", "bool", "uuid.UUID", "UUID", "Decimal", "decimal.Decimal"})
_ALLOWLIST_NAME_RE = re.compile(r"allow|valid|white|permit|known|supported|accepted|choices|options", re.IGNORECASE)
# Yalnız uygulama içi yol üreten URL kurucuları: argümanlar yol/sorgu bileşenine kodlanır.
_PY_URL_BUILDERS = frozenset({"reverse", "reverse_lazy", "url_for"})
_URL_FIXED_HOST_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/{}\s%]+/")
_HTML_LITERAL_RE = re.compile(r"<[a-zA-Z/!]")
_PREFIX_KINDS = frozenset({"path", "ssrf", "redirect"})
_PATH_TRAVERSAL_LITERALS = frozenset({"..", "../", "..\\", "/", "\\"})
_PY_FILE_STEPS = 200_000
_PY_STEPS_PER_PROJECT_FILE = 40_000

Guard = list[tuple[str, frozenset[str]]]

# Listeyi/kümeyi/sözlüğü yerinde değiştiren metotlar: alıcı değişken argümanların taint'ini taşır.
_PY_MUTATORS = frozenset({"append", "extend", "insert", "add", "update", "appendleft", "extendleft"})
_SHELL_PROGRAMS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "/bin/sh", "/bin/bash", "/usr/bin/bash", "cmd", "cmd.exe", "powershell", "pwsh"})
_SHELL_FLAGS = frozenset({"-c", "/c", "/C", "-Command", "-command"})
# Doğrulaması kaynak değeri de doğrulayan türetmeler (url = urlparse(x); if url.netloc in IZINLI …).
_DERIVING_CALLS = frozenset({
    "urlparse", "urllib.parse.urlparse", "urlsplit", "urllib.parse.urlsplit",
    "os.path.realpath", "os.path.abspath", "os.path.normpath", "Path", "pathlib.Path",
})
# Ad tabanlı (tür bilinmeyen alıcı) metot çözümünde kullanılmayacak yaygın adlar.
_DISPATCH_EXCLUDED = frozenset({
    "get", "set", "run", "save", "update", "close", "open", "read", "write", "send", "execute", "query", "search",
    "find", "load", "loads", "dump", "dumps", "start", "stop", "call", "process", "handle", "parse", "render",
    "add", "remove", "delete", "create", "items", "keys", "values", "copy", "clear", "format", "join", "split",
})
_CONST_UNKNOWN: Any = object()
# Ortam değişkeninden gelen değer (os.environ / os.getenv): operatör ayarı, çözülemez → belirsiz.
_ENV_VALUE: Any = object()
# Aynı köken taban URL'si üreten istek öznitelikleri (Flask/Starlette) ve çağrıları (Django).
_PY_SAME_ORIGIN_ATTRS = frozenset({"host_url", "url_root", "base_url"})
_PY_SAME_ORIGIN_CALLS = frozenset({"build_absolute_uri"})
_MAX_CONST_STR = 10_000
_PY_SANITIZER_VERSION_MINIMUMS = {"bleach": (5, 0, 0)}
_PY_EXACT_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def _python_sanitizer_version_scopes(files: dict[str, str]) -> dict[str, dict[str, bool]]:
    """Extract exact sanitizer versions by nearest Python package root."""
    evidence: dict[str, list[bool]] = {}
    total = 0
    seen = 0
    for relpath, text in sorted(files.items()):
        path = PurePosixPath(relpath)
        name = path.name.lower()
        requirement_file = name.endswith(".txt") and (
            name.startswith("requirements") or "requirements" in {part.lower() for part in path.parts[:-1]}
        )
        lock_file = name in {"poetry.lock", "uv.lock"}
        pipfile_lock = name == "pipfile.lock"
        if not (requirement_file or lock_file or pipfile_lock) or not isinstance(text, str):
            continue
        size = len(text.encode("utf-8", "ignore"))
        total += size
        seen += 1
        parent = path.parent
        if requirement_file and parent.name.lower() == "requirements":
            parent = parent.parent
        scope = str(parent)
        scope = "" if scope == "." else scope.strip("/")
        if seen > 256 or size > 1_000_000 or total > 16_000_000:
            if lock_file or pipfile_lock or re.search(
                    r"(?im)^\s*(?:name\s*=\s*['\"]bleach['\"]|bleach\s*==)", text[:1_000_000]):
                evidence.setdefault(scope, []).append(False)
            continue
        if pipfile_lock:
            try:
                payload = json.loads(text)
            except (json.JSONDecodeError, RecursionError, MemoryError):
                evidence.setdefault(scope, []).append(False)
                continue
            found = False
            if isinstance(payload, dict):
                for group, packages in payload.items():
                    if group == "_meta" or not isinstance(packages, dict):
                        continue
                    package = packages.get("bleach")
                    if not isinstance(package, dict):
                        continue
                    found = True
                    raw = package.get("version")
                    exact = re.fullmatch(r"==\s*(\d+\.\d+\.\d+)", raw) if isinstance(raw, str) else None
                    trusted_source = not any(
                        key in package for key in ("path", "file", "editable", "git", "ref", "url")
                    )
                    evidence.setdefault(scope, []).append(bool(
                        trusted_source and exact
                            and tuple(map(int, exact.group(1).split("."))) >= _PY_SANITIZER_VERSION_MINIMUMS["bleach"]
                    ))
            if not found:
                evidence.setdefault(scope, []).append(False)
            continue
        if lock_file:
            try:
                payload = tomllib.loads(text)
            except (tomllib.TOMLDecodeError, RecursionError, MemoryError):
                evidence.setdefault(scope, []).append(False)
                continue
            packages = payload.get("package") if isinstance(payload, dict) else None
            if not isinstance(packages, list):
                evidence.setdefault(scope, []).append(False)
                continue
            found = False
            for package in packages:
                if not isinstance(package, dict) or str(package.get("name", "")).lower() != "bleach":
                    continue
                found = True
                value = package.get("version")
                source = package.get("source")
                match = _PY_EXACT_VERSION_RE.fullmatch(value) if isinstance(value, str) else None
                trusted_source = not isinstance(source, dict) or not any(
                    key in source for key in ("path", "editable", "git", "url", "workspace", "directory")
                )
                evidence.setdefault(scope, []).append(bool(
                    trusted_source and match
                    and tuple(map(int, match.groups())) >= _PY_SANITIZER_VERSION_MINIMUMS["bleach"]
                ))
            if not found:
                evidence.setdefault(scope, []).append(False)
            continue
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not re.match(r"(?i)^bleach(?:\[[^\]]+\])?(?:\s|[<>=!~@]|$)", line):
                continue
            exact = re.fullmatch(
                r"(?i)bleach(?:\[[^\]]+\])?\s*==\s*(\d+\.\d+\.\d+)\s*(?:;\s*[^#]+)?", line
            )
            value = exact.group(1) if exact else ""
            match = _PY_EXACT_VERSION_RE.fullmatch(value)
            supported = bool(match and tuple(map(int, match.groups())) >= _PY_SANITIZER_VERSION_MINIMUMS["bleach"])
            evidence.setdefault(scope, []).append(supported)
    return {scope: {"bleach": all(values)} for scope, values in evidence.items() if values}


def _python_sanitizer_versions(files: dict[str, str]) -> dict[str, bool]:
    """Root-package compatibility wrapper."""
    return _python_sanitizer_version_scopes(files).get("", {})


def _is_db_read(name: str, last: str) -> bool:
    """Veritabanı okuması mı? (cursor.fetch*, Django .objects., SQLAlchemy query().first, pymongo find_one)."""
    if last in _PY_DB_FETCH_METHODS:
        return True
    if last not in _PY_ORM_READ_METHODS:
        return False
    if "scalars()." in name or "execute()." in name and last in {"scalars", "all", "first", "one", "one_or_none",
                                                                   "scalar", "scalar_one", "scalar_one_or_none"}:
        return True  # SQLAlchemy 2.0: session.scalars(select(...)).all(), session.execute(select(...)).scalars()
    if last in {"scalar", "scalars"} and re.search(r"(?:^|\.)(?:db|session)\.\w+$", name):
        return True  # g.db.scalar(select(...)), db.session.scalars(...)
    return ".objects." in f".{name}" or ".objects()" in name or "query()." in name or (
        last in {"find_one", "find"} and ("collection" in name.lower() or name.startswith(("db.", "mongo")))
    ) or (".session." in f".{name}" and last == "get")


def _guard_names(node: ast.AST) -> list[str]:
    """Koşul ifadesinde denetlenen değişken adları (çağrılan fonksiyon adları hariç)."""
    callees = {id(child.func) for child in fast_walk(node) if isinstance(child, ast.Call)}
    names: list[str] = []
    for child in fast_walk(node):
        if id(child) in callees:
            continue
        if isinstance(child, ast.Name):
            names.append(child.id)
        elif isinstance(child, ast.Attribute):
            dotted = _dotted(child)
            if dotted and "()" not in dotted:
                names.append(dotted)
    return names


def _is_constant_collection(node: ast.AST) -> bool:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return bool(node.elts) and all(isinstance(element, ast.Constant) for element in node.elts)
    if isinstance(node, ast.Dict):
        return bool(node.keys) and all(isinstance(key, ast.Constant) for key in node.keys)
    if isinstance(node, (ast.Name, ast.Attribute)):
        last = _dotted(node).rsplit(".", 1)[-1]
        return bool(last) and (last.isupper() or bool(_ALLOWLIST_NAME_RE.search(last)))
    if isinstance(node, ast.Call):
        name = _dotted(node.func)
        if name in {"set", "frozenset", "tuple", "list"} and node.args:
            return _is_constant_collection(node.args[0])
        if isinstance(node.func, ast.Attribute) and node.func.attr == "keys":
            return _is_constant_collection(node.func.value)
    return False


def _literal(node: ast.AST) -> str:
    if isinstance(node, ast.Constant):
        return str(node.value)
    return _dotted(node)


def _terminates(body: list[ast.stmt]) -> bool:
    """Dal, akışı sonraki deyime taşımadan bitiyor mu (return/raise/abort/continue)?"""
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        name = _dotted(last.value.func)
        return name in _PY_TERMINATOR_CALLS or name.rsplit(".", 1)[-1] == "abort"
    if isinstance(last, ast.If):
        return bool(last.orelse) and _terminates(last.body) and _terminates(last.orelse)
    return False


def _has_html_literal(node: ast.AST) -> bool:
    return any(
        isinstance(child, ast.Constant) and isinstance(child.value, str) and _HTML_LITERAL_RE.search(child.value)
        for child in fast_walk(node)
    )


def _fixed_url_prefix(node: ast.AST | None) -> bool:
    """URL sabit şema+ana makine ile başlıyorsa (yalnız yol/sorgu değişken: kısmi SSRF)."""
    if node is None:
        return False
    first: ast.AST | None = None
    if isinstance(node, ast.JoinedStr) and node.values:
        first = node.values[0]
    elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        first = node.left
        while isinstance(first, ast.BinOp) and isinstance(first.op, ast.Add):
            first = first.left
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        first = node.func.value
    return isinstance(first, ast.Constant) and isinstance(first.value, str) and bool(_URL_FIXED_HOST_RE.match(first.value))


_PREFIX_SUMMARY_KINDS = ("redirect", "ssrf")

# HTML gövdeli yanıt nesneleri (bkz. _PyScope._check_html_response).
_PY_THREAD_STARTERS = frozenset({
    "threading.Thread", "threading.Timer", "multiprocessing.Process", "multiprocessing.context.Process",
})
_PY_EXECUTOR_TYPES = frozenset({
    "concurrent.futures.Executor", "concurrent.futures.ThreadPoolExecutor",
    "concurrent.futures.ProcessPoolExecutor", "concurrent.futures.InterpreterPoolExecutor",
})
_PY_MULTIPROCESS_POOL_TYPES = frozenset({
    "multiprocessing.Pool", "multiprocessing.pool.Pool",
})
_PY_ASYNCIO_LOOP_FACTORIES = frozenset({
    "asyncio.get_running_loop", "asyncio.get_event_loop", "asyncio.new_event_loop",
})
_PY_ASYNCIO_LOOP_CALLBACKS = {
    "call_soon": 0,
    "call_soon_threadsafe": 0,
    "call_later": 1,
    "call_at": 1,
    "run_in_executor": 1,
}
_PY_BACKGROUND_TASK_TYPES = frozenset({
    "fastapi.BackgroundTasks", "starlette.background.BackgroundTasks",
})
_PY_SINGLE_BACKGROUND_TASK_TYPES = frozenset({
    "starlette.background.BackgroundTask",
})
_DJANGO_HTML_RESPONSES = frozenset({
    "HttpResponse", "HttpResponseBadRequest", "HttpResponseNotFound", "HttpResponseForbidden",
    "HttpResponseServerError", "HttpResponseNotAllowed", "HttpResponseGone",
})
_AIOHTTP_RESPONSES = frozenset({"aiohttp.web.Response", "aiohttp.web_response.Response"})
_FALCON_HTML_TYPES = frozenset({"falcon.MEDIA_HTML", "falcon.constants.MEDIA_HTML"})


def _is_html_content_type(node: ast.AST) -> bool:
    """Sabit içerik türü HTML mi? Sabit olmayan değer bilinmez → HTML sayılmaz (yanlış alarm yerine kaçırma)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return "html" in node.value.lower()
    return _dotted(node).rsplit(".", 1)[-1] == "MEDIA_HTML"


def _non_html_header(key: ast.AST, value: ast.AST) -> bool:
    """``r["Content-Disposition"] = "attachment…"`` ya da ``r["Content-Type"] = "application/json"`` (sabit)."""
    if not (isinstance(key, ast.Constant) and isinstance(key.value, str)
            and isinstance(value, ast.Constant) and isinstance(value.value, str)):
        return False
    name, text = key.value.strip().lower(), value.value.strip().lower()
    if name == "content-disposition":
        return text.startswith("attachment")
    if name == "content-type":
        return bool(text) and "html" not in text and "xml" not in text
    return False


def _non_html_response_calls(func: ast.AST) -> set[int]:
    """İşlevde ``ad = Yanıt(...)`` ile kurulup sonra ``ad[başlık] = …`` / ``ad.headers[başlık] = …`` /
    ``ad.content_type = …`` ile ek ya da HTML dışı içerik türü atanan yanıtların kurucu çağrıları (id)."""
    return _non_html_from_assigns([stmt for stmt in fast_walk(func) if isinstance(stmt, ast.Assign)])


def _non_html_from_assigns(assigns: list[ast.Assign]) -> set[int]:
    """``_non_html_response_calls`` çekirdeği: işlevin atamaları (ast.walk sırasıyla) üzerinden."""
    marked: set[str] = set()
    builders: dict[str, list[ast.Call]] = {}
    for stmt in assigns:
        for target in stmt.targets:
            if isinstance(target, ast.Name) and isinstance(stmt.value, ast.Call):
                builders.setdefault(target.id, []).append(stmt.value)
            elif isinstance(target, ast.Subscript):
                owner = target.value
                if isinstance(owner, ast.Attribute) and owner.attr == "headers":
                    owner = owner.value
                if isinstance(owner, ast.Name) and _non_html_header(target.slice, stmt.value):
                    marked.add(owner.id)
            elif isinstance(target, ast.Attribute) and target.attr in {"content_type", "mimetype"} \
                    and isinstance(target.value, ast.Name) and isinstance(stmt.value, ast.Constant) \
                    and _non_html_header(ast.Constant("content-type"), stmt.value):
                marked.add(target.value.id)
    return {id(call) for name in marked for call in builders.get(name, ())}


def _annotation_target(annotation: ast.AST | None, depth: int = 0) -> tuple[bool, str] | None:
    """Tip açıklamasının gösterdiği tek sınıf adı: (öğe türü mü, nokta yolu) ya da None.

    ``"Cursor"`` (dize), ``Optional[X]``, ``X | None``, ``Union[X, None]``, ``Annotated[X, …]`` → X;
    ``list[X]`` / ``Sequence[X]`` / ``Iterable[X]`` / ``tuple[X, ...]`` → (öğe, X). Birden çok olası
    sınıf (``A | B``) belirsizdir (None)."""
    if annotation is None or depth > 6:
        return None
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        text = annotation.value.strip()
        if not text or len(text) > 200:
            return None
        try:
            parsed = ast.parse(text, mode="eval").body
        except (SyntaxError, ValueError, MemoryError, RecursionError):
            return None
        return _annotation_target(parsed, depth + 1)
    if isinstance(annotation, (ast.Name, ast.Attribute)):
        dotted = _dotted(annotation)
        return (False, dotted) if dotted else None
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        members = [annotation.left, annotation.right]
        flat: list[ast.AST] = []
        while members:
            member = members.pop()
            if isinstance(member, ast.BinOp) and isinstance(member.op, ast.BitOr):
                members.extend([member.left, member.right])
            elif not (isinstance(member, ast.Constant) and member.value is None) and _dotted(member) != "None":
                flat.append(member)
        return _annotation_target(flat[0], depth + 1) if len(flat) == 1 else None
    if isinstance(annotation, ast.Subscript):
        base = _dotted(annotation.value).rsplit(".", 1)[-1]
        items = annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
        if base in _ANNOTATION_UNWRAP and items:
            return _annotation_target(items[0], depth + 1)
        if base == "Union":
            real = [item for item in items if not (isinstance(item, ast.Constant) and item.value is None) and _dotted(item) != "None"]
            return _annotation_target(real[0], depth + 1) if len(real) == 1 else None
        if base in _ANNOTATION_ELEMENT and items:
            if base in {"tuple", "Tuple"} and not (len(items) == 2 and isinstance(items[1], ast.Constant) and items[1].value is Ellipsis):
                return None  # sabit uzunluklu demet: öğe türleri farklı olabilir
            inner = _annotation_target(items[0], depth + 1)
            return (True, inner[1]) if inner is not None and not inner[0] else None
    return None


def _is_env_lookup(module: Any, node: ast.AST) -> bool:
    """``os.environ["X"]``, ``os.environ.get("X")``, ``os.getenv("X")`` (``from os import environ/getenv`` dahil)."""
    def canonical(expr: ast.AST) -> str:
        dotted = _dotted(expr)
        head, _, rest = dotted.partition(".")
        target = module.imports.get(head) if module is not None else None
        return f"{target}.{rest}" if target and rest else (target or dotted)
    if isinstance(node, ast.Subscript):
        return canonical(node.value) == "os.environ"
    if isinstance(node, ast.Call):
        return canonical(node.func) in {"os.getenv", "os.environ.get", "os.environ.__getitem__"}
    return False


def _url_parts(node: ast.AST) -> list[ast.AST] | None:
    """Adres şablonunun parçaları: f-dize değerleri ya da + zincirinin işlenenleri (soldan sağa)."""
    if isinstance(node, ast.JoinedStr):
        return [value.value if isinstance(value, ast.FormattedValue) else value for value in node.values]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        parts: list[ast.AST] = []
        stack = [node]
        while stack:
            item = stack.pop()
            if isinstance(item, ast.BinOp) and isinstance(item.op, ast.Add):
                stack.extend([item.right, item.left])
            else:
                parts.append(item)
        return parts
    return None


def _first_component(node: ast.AST) -> ast.AST:
    """Dize/adres ifadesinin ilk bileşeni (f-dize ilk parçası, + / % zincirinin solu, .format alıcısı)."""
    if isinstance(node, ast.JoinedStr) and node.values:
        first = node.values[0]
        return first.value if isinstance(first, ast.FormattedValue) else first
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        first = node.left
        while isinstance(first, ast.BinOp) and isinstance(first.op, ast.Add):
            first = first.left
        return first
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return node.func.value
    return node


def _clean_prefix_text(text: str, kind: str) -> bool:
    """Sabit önek güvenli mi? Yönlendirme: "/x" (ama "//" veya "/\\" değil) ya da sabit şema+ana makine;
    SSRF: sabit şema+ana makine+"/" (girdi yalnız yol/sorguyu etkiler)."""
    if _URL_FIXED_HOST_RE.match(text):
        return True
    return kind == "redirect" and len(text) > 1 and text[0] == "/" and text[1] not in "/\\"


def _default_for(fnode: ast.FunctionDef | ast.AsyncFunctionDef, index: int) -> ast.AST | None:
    """index. parametrenin varsayılan değer düğümü (yoksa None)."""
    positional = [*fnode.args.posonlyargs, *fnode.args.args]
    if index < len(positional):
        offset = index - (len(positional) - len(fnode.args.defaults))
        return fnode.args.defaults[offset] if offset >= 0 else None
    kw_index = index - len(positional)
    if kw_index < len(fnode.args.kw_defaults):
        return fnode.args.kw_defaults[kw_index]
    return None


@dataclass(frozen=True)
class _ParamSink:
    index: int
    kind: str
    sink: str
    file: str
    line: int
    via: tuple[str, ...]
    # index == -1: self.<field>; index >= 0: o parametrenin seçili alanı hedefe ulaşıyor.
    field: str = ""
    # Yönlendirme/SSRF hedefinde adresin ilk bileşeni bu parametrenin değeri: çağrı yerinde o
    # argüman güvenli önekse (ör. "/app/", "https://sabit.ana.makine/") hedef bastırılır.
    prefix_param: int = -1


class _PySummary:
    """Bir fonksiyonun veri akışı özeti (parametre → hedef / dönüş, dönüşteki kaynaklar)."""

    MAX_SINKS = 64

    def __init__(self, params: tuple[str, ...]) -> None:
        self.params = params
        self.ret_params: dict[int, frozenset[str]] = {}
        self.ret_sources: Taint = _EMPTY
        self.sinks: dict[tuple[int, str, str, int, str], _ParamSink] = {}
        # Alan duyarlı özet: metodun self.<alan> yazdığı taint, dönüşe akan alanlar, alan türleri.
        self.field_writes: dict[str, Taint] = {}
        self.ret_fields: dict[str, frozenset[str]] = {}
        self.param_field_writes: dict[tuple[int, str], Taint] = {}
        self.param_field_strong_writes: set[tuple[int, str]] = set()
        self.ret_param_fields: dict[tuple[int, str], frozenset[str]] = {}
        # Parameters whose object identity may be returned (``return value``).
        # This lets the caller keep per-field state through small identity/
        # fluent helpers without tainting safe sibling fields.
        self.ret_object_params: set[int] = set()
        self.field_types: dict[str, tuple["_PyModule", str]] = {}
        self.ret_class: tuple["_PyModule", str] | None = None
        # Dönüş biçimi: demet öğeleri / sabit anahtarlı sözlük (None: henüz yok, False: tutarsız).
        self.ret_tuple: list[Taint] | bool | None = None
        self.ret_dict: dict[str, Taint] | bool | None = None
        # `global X` ile yazılan modül değişkenleri (sembolik kökenler çağrı yerinde eşlenir).
        self.global_writes: dict[str, Taint] = {}
        # Özetin (çağırdığı özetler dahil) okuduğu global anahtarları: artımlı yeniden geçiş için.
        self.global_reads: set[tuple[str, str]] = set()
        # Dönüş değerinin önek durumu (yönlendirme/SSRF): "clean" (her dönüş güvenli önekle başlar),
        # k (her dönüş k. parametrenin değeriyle başlar) veya None (bilinmiyor).
        self.ret_prefix: dict[str, Any] = {}

    def add_return_shape(self, value: Any, parts: list[Taint] | dict[str, Taint] | None) -> None:
        """Dönüş ifadesinin biçimini kaydet; demet/sözlük olmayan dönüş biçimi geçersiz kılar."""
        if isinstance(value, ast.Constant) and value.value is None or value is None:
            return
        if isinstance(parts, list):
            if self.ret_tuple is None:
                self.ret_tuple = list(parts)
            elif isinstance(self.ret_tuple, list) and len(self.ret_tuple) == len(parts):
                self.ret_tuple = [_union(a, b) for a, b in zip(self.ret_tuple, parts)]
            else:
                self.ret_tuple = False
        else:
            self.ret_tuple = False
        if isinstance(parts, dict):
            if self.ret_dict is None:
                self.ret_dict = dict(parts)
            elif isinstance(self.ret_dict, dict) and set(self.ret_dict) == set(parts):
                self.ret_dict = {k: _union(self.ret_dict[k], parts[k]) for k in parts}
            else:
                self.ret_dict = False
        else:
            self.ret_dict = False

    def add_global_write(self, name: str, taint: Taint) -> None:
        if taint:
            self.global_writes[name] = _union(self.global_writes.get(name, _EMPTY), taint)

    def add_return(self, taint: Taint) -> None:
        real: list[_Origin] = []
        for origin in taint:
            if origin.label == _PARAM:
                index = int(origin.source)
                previous = self.ret_params.get(index)
                self.ret_params[index] = origin.cleaned if previous is None else previous & origin.cleaned
            elif origin.label == _FIELD:
                previous = self.ret_fields.get(origin.source)
                self.ret_fields[origin.source] = origin.cleaned if previous is None else previous & origin.cleaned
            elif origin.label == _PARAM_FIELD:
                raw_index, _, field = origin.source.partition(":")
                if raw_index.isdigit() and field:
                    key = (int(raw_index), field)
                    previous = self.ret_param_fields.get(key)
                    self.ret_param_fields[key] = origin.cleaned if previous is None else previous & origin.cleaned
            else:
                real.append(origin)
        if real:
            self.ret_sources = _union(self.ret_sources, tuple(real))

    def add_field_write(self, field: str, taint: Taint) -> None:
        self.field_writes[field] = _union(self.field_writes.get(field, _EMPTY), taint)

    def add_param_field_write(self, index: int, field: str, taint: Taint, *, strong: bool = False) -> None:
        key = (index, field)
        if strong:
            self.param_field_writes[key] = taint
            self.param_field_strong_writes.add(key)
        else:
            self.param_field_writes[key] = _union(self.param_field_writes.get(key, _EMPTY), taint)
            self.param_field_strong_writes.discard(key)

    def add_return_prefix(self, kind: str, state: Any) -> None:
        if kind not in self.ret_prefix:
            self.ret_prefix[kind] = state
            return
        previous = self.ret_prefix[kind]
        if previous == state or previous is None:
            return
        if previous == "clean" and isinstance(state, int):
            self.ret_prefix[kind] = state
        elif not (state == "clean" and isinstance(previous, int)):
            self.ret_prefix[kind] = None

    def add_sink(self, sink: _ParamSink) -> None:
        key = (sink.index, sink.kind, sink.file, sink.line, sink.field)
        existing = self.sinks.get(key)
        if existing is None:
            if len(self.sinks) < self.MAX_SINKS:
                self.sinks[key] = sink
        elif existing.prefix_param != sink.prefix_param and existing.prefix_param != -1:
            # Aynı hedefe farklı önek koşullarıyla ulaşılıyor: koşulsuz (temkinli) kabul edilir.
            self.sinks[key] = _ParamSink(existing.index, existing.kind, existing.sink, existing.file, existing.line,
                                         existing.via, existing.field)


class _PyModule:
    """Bir Python dosyasının dizini: fonksiyonlar, sınıflar ve içe aktarma takma adları."""

    def __init__(self, relpath: str, tree: ast.Module) -> None:
        self.relpath = relpath
        self.tree = tree
        parts = [part for part in relpath.replace("\\", "/").split("/") if part and part != "."]
        if parts and parts[-1].endswith(".py"):
            parts[-1] = parts[-1][:-3]
        self.is_package = bool(parts) and parts[-1] == "__init__"
        if self.is_package:
            parts = parts[:-1]
        self.modname = ".".join(parts)
        self.package = self.modname if self.is_package else self.modname.rpartition(".")[0]
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.classes: dict[str, ast.ClassDef] = {}
        self.imports: dict[str, str] = {}
        self.star_imports: list[str] = []
        self._index(tree.body, None)
        self._index_imports()
        # Modül düzeyinde atanan adlar (global değişkenler).
        self.top_names: set[str] = set()
        for stmt in tree.body:
            if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.For, ast.With)):
                for child in fast_walk(stmt):
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                        self.top_names.add(child.id)

    _url_rule_views: frozenset[str] | None = None
    _global_ctors: dict[str, str] | None = None

    def global_ctors(self) -> dict[str, str]:
        """Modül düzeyinde bir kez ``AD = çağrı(...)`` ile kurulan nesnelerin kurucu adları (ör. HTTP = urllib3.PoolManager());
        birden çok kez atanan adlar belirsiz sayılıp dışarıda bırakılır."""
        if self._global_ctors is None:
            seen: dict[str, str | None] = {}
            for stmt in self.tree.body:
                targets = stmt.targets if isinstance(stmt, ast.Assign) else []
                for target in targets:
                    if isinstance(target, ast.Name):
                        value = _dotted(stmt.value.func) if isinstance(stmt.value, ast.Call) else ""
                        seen[target.id] = value if target.id not in seen and value else None
            self._global_ctors = {name: value for name, value in seen.items() if value}
        return self._global_ctors

    def is_chalice_app(self, name: str) -> bool:
        """Modül düzeyinde ``ad = Chalice(...)`` / ``ad = Blueprint(...)`` (chalice) ile kurulan uygulama mı?"""
        ctor = self.global_ctors().get(name)
        if not ctor:
            return False
        head, _, rest = ctor.partition(".")
        target = self.imports.get(head, "")
        canonical = f"{target}.{rest}" if target and rest else (target or ctor)
        return canonical in {"chalice.Chalice", "chalice.Blueprint", "chalice.app.Chalice", "chalice.app.Blueprint"}

    def url_rule_views(self) -> frozenset[str]:
        """Flask/Quart ``x.add_url_rule(kural, uç, görünüm)`` / ``view_func=görünüm`` ile kaydedilen fonksiyon adları
        (dekoratörsüz görünümler; iç içe tanımlı olanlar dahil). Yalnız flask/quart içe aktaran modülde."""
        if self._url_rule_views is None:
            names: set[str] = set()
            if any(target.split(".")[0] in {"flask", "quart"} for target in self.imports.values()):
                for node in fast_walk(self.tree):
                    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                            and node.func.attr == "add_url_rule"):
                        continue
                    view = next((kw.value for kw in node.keywords if kw.arg == "view_func"), None)
                    if view is None and len(node.args) > 2:
                        view = node.args[2]
                    if isinstance(view, ast.Name):
                        names.add(view.id)
            self._url_rule_views = frozenset(names)
        return self._url_rule_views

    def top_loads(self) -> set[str]:
        """Modül düzeyi kodda (fonksiyon gövdeleri hariç) okunan global adlar."""
        names: set[str] = set()
        stack: list[ast.AST] = list(self.tree.body)
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                stack.extend(node.decorator_list if not isinstance(node, ast.Lambda) else [])
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in self.top_names:
                names.add(node.id)
            stack.extend(ast.iter_child_nodes(node))
        return names

    def _index(self, body: list[ast.stmt], class_name: str | None) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[f"{class_name}.{node.name}" if class_name else node.name] = node
            elif class_name is not None:
                continue
            elif isinstance(node, ast.ClassDef):
                self.classes[node.name] = node
                self._index(node.body, node.name)
            elif isinstance(node, ast.If):
                self._index(node.body, None)
                self._index(node.orelse, None)
            elif isinstance(node, ast.Try) or type(node).__name__ == "TryStar":
                self._index(node.body, None)
                for handler in node.handlers:
                    self._index(handler.body, None)
                self._index(node.orelse, None)
                self._index(node.finalbody, None)

    def _absolute(self, module: str | None, level: int) -> str:
        if level == 0:
            return module or ""
        base = self.package.split(".") if self.package else []
        if level > 1:
            base = base[: max(0, len(base) - (level - 1))]
        return ".".join([*base, *([module] if module else [])])

    def _index_imports(self) -> None:
        for node in _walk_statements(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.imports[alias.asname] = alias.name
                    else:
                        head = alias.name.split(".")[0]
                        self.imports.setdefault(head, head)
            elif isinstance(node, ast.ImportFrom):
                base = self._absolute(node.module, node.level)
                for alias in node.names:
                    if alias.name == "*":
                        if base:
                            self.star_imports.append(base)
                        continue
                    self.imports[alias.asname or alias.name] = f"{base}.{alias.name}" if base else alias.name


def fast_walk(node: ast.AST) -> Iterator[ast.AST]:
    """``ast.walk`` ile birebir aynı düğümler ve aynı (genişlik öncelikli) sıra; ``iter_child_nodes``/``iter_fields``
    üreteç katmanları olmadan (~%35 daha hızlı). Çocuklar düğüm verilmeden önce kuyruğa alınır (ast.walk gibi)."""
    from collections import deque

    todo = deque([node])
    pop, push = todo.popleft, todo.append
    ast_type = ast.AST
    while todo:
        node = pop()
        for name in node._fields:
            try:
                value = getattr(node, name)
            except AttributeError:
                continue
            if isinstance(value, ast_type):
                push(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, ast_type):
                        push(item)
        yield node


_STATEMENT_CONTAINERS = (ast.stmt, ast.excepthandler, *((ast.match_case,) if hasattr(ast, "match_case") else ()))


def _walk_statements(tree: ast.AST) -> Iterator[ast.AST]:
    """``ast.walk`` ile aynı (genişlik öncelikli) sırada yalnız deyimler ve deyim kapları (except/case).

    İçe aktarmalar yalnız deyim listelerinde bulunabildiği için ifade alt ağaçlarına inilmez; ata
    zinciri kapalı alt küme olduğundan göreli sıra ``ast.walk`` ile aynıdır."""
    from collections import deque

    todo = deque([tree])
    while todo:
        node = todo.popleft()
        for name in node._fields:
            value = getattr(node, name, None)
            if isinstance(value, list):
                todo.extend(item for item in value if isinstance(item, _STATEMENT_CONTAINERS))
        yield node


def _function_scope_stores(node: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    """Names rebound by this function body, excluding nested Python scopes."""
    names: set[str] = set()
    stack: list[ast.AST] = list(node.body)
    nested_scopes = (
        ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda,
        ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
    )
    while stack:
        child = stack.pop()
        if isinstance(child, nested_scopes):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(child.name)
            continue
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
            names.add(child.id)
        elif isinstance(child, ast.ExceptHandler) and isinstance(child.name, str):
            names.add(child.name)
        elif isinstance(child, ast.MatchAs) and child.name:
            names.add(child.name)
        elif isinstance(child, ast.MatchStar) and child.name:
            names.add(child.name)
        stack.extend(ast.iter_child_nodes(child))
    return frozenset(names)


_SLIM_CLASSES: dict[type, type] = {}


def _slim_class(cls: type) -> type:
    """``ast`` düğüm sınıfının aynı adlı, ``__slots__``'lu alt sınıfı (alanlar + ``lineno``)."""
    slim = _SLIM_CLASSES.get(cls)
    if slim is None:
        slots = tuple(cls._fields) + (("lineno",) if "lineno" in cls._attributes else ())
        slim = type(cls.__name__, (cls,), {"__slots__": slots, "__module__": __name__})
        _SLIM_CLASSES[cls] = slim
    return slim


def _slim_tree(tree: ast.AST, ints: dict[int, int]) -> ast.AST:
    """Büyük projelerde bellek: ayrıştırılan ağacın sözlüksüz (``__slots__``) kopyası.

    Her ``ast`` düğümü öznitelikleri için ayrı bir sözlük taşır (düğüm başına ~240 bayt; django'da
    ağaçlar tepe belleğin ~%85'iydi). Kopya düğümler aynı adlı alt sınıflardır (``isinstance``,
    ``type(...).__name__``, ``ast.walk`` aynı davranır); alanlar ve ``lineno`` korunur, motorun
    kullanmadığı sütun/bitiş konumları atılır, satır numarası nesneleri paylaşılır. Bağlam/işleç
    tekilleri (Load, Add …) olduğu gibi kalır."""

    def slim(node: ast.AST) -> ast.AST:
        cls = type(node)
        if not cls._fields and not cls._attributes:
            return node
        target = _slim_class(cls)
        copy = target.__new__(target)
        todo.append((node, copy, target.__slots__))
        return copy

    todo: list[tuple[ast.AST, ast.AST, tuple[str, ...]]] = []
    root = slim(tree)
    while todo:
        node, copy, slots = todo.pop()
        data = node.__dict__
        for name in slots:
            value = data.get(name)
            if isinstance(value, ast.AST):
                value = slim(value)
            elif isinstance(value, list):
                value = [slim(item) if isinstance(item, ast.AST) else item for item in value]
            elif name == "lineno" and value is not None:
                value = ints.setdefault(value, value)
            setattr(copy, name, value)
    return root


# Çağrı hedefi: (modül, nitelikli ad, fonksiyon düğümü, parametre kayması, sınıf adı)
_CallTarget = tuple[_PyModule, str, "ast.FunctionDef | ast.AsyncFunctionDef", int, "str | None"]


class _PyProject:
    """Bir veya daha çok Python modülü üzerinde fonksiyonlar arası analiz."""

    MAX_DEPTH = 30

    def __init__(self, pii: PiiClassifier | None, *, max_steps: int = _PY_FILE_STEPS,
                 entrypoints: frozenset[str] = frozenset()) -> None:
        self.pii = pii
        self.models = taint_models.models_for("python")
        # Kullanıcının yazabildiği kayıt alanları: istek verisiyle kurulan/güncellenen nesne öznitelikleri
        # (Model(alan=istek), nesne.alan = istek, objects.create(alan=istek)). Şablonda |safe ile basılan kayıtlı
        # veri bu alanlardan biriyse kalıcı XSS doğrulanmış sayılır.
        self.user_written_attrs: set[str] = set()
        self._model_form_fields: dict[str, frozenset[str]] | None = None
        # 25. tur: kullanıcının yazdığı alan → ilk yazıldığı yer (göreli yol, satır); kanıtta gösterilir.
        self.user_written_sites: dict[str, tuple[str, int]] = {}
        # Yapılandırmadan gelen giriş noktaları "modül:nitelikli_ad" ve proje içinde çağrılan fonksiyonlar.
        self.entrypoints = entrypoints
        self.called: set[int] = set()
        self._set_field_names: dict[str, frozenset[str]] = {}
        # strawberry ``field(resolver=f)`` ve ariadne sözlük haritalarıyla bağlanan çözücüler: (relpath, qual) → çatı.
        self._resolver_refs: dict[tuple[str, str], str] | None = None
        self._module_constants: dict[tuple[str, str], Any] = {}
        self._django_settings: dict[str, Any] = {}
        self._stdlib_handlers: dict[tuple[str, str, bool], bool] = {}
        self.modules: dict[str, _PyModule] = {}
        self.by_name: dict[str, _PyModule] = {}
        # Alt kaynak kökü takma adları (app/apis/x.py → "apis.x"): yalnız tam ad bulunamazsa; çakışan ad None.
        self.alias_by_name: dict[str, _PyModule | None] = {}
        self.flows: dict[str, list[Flow]] = {}
        self.clean: dict[str, set[tuple[str, int]]] = {}
        self.uncertain: dict[str, set[tuple[str, int]]] = {}
        self.summaries: dict[int, _PySummary] = {}
        self.extra: list[tuple[_PyModule, str, ast.FunctionDef | ast.AsyncFunctionDef, str | None]] = []
        self._emitted: dict[str, set[tuple[str, int, str, int, str]]] = {}
        self._active: set[int] = set()
        self._done_modules: set[str] = set()
        self._depth = 0
        self.steps = 0
        self.max_steps = max_steps
        # Global değişken taint'leri (modül yolu, ad) → yalnız gerçek kökenler; değişirse yeniden geçiş.
        self.globals: dict[tuple[str, str], Taint] = {}
        self.globals_version = 0
        # Bu geçişte okunan global anahtarları; okunduktan SONRA değişen anahtar varsa geçiş bayattır.
        self._read_keys: set[tuple[str, str]] = set()
        self._stale = False
        self._stale_keys: set[tuple[str, str]] = set()
        self._deps_stack: list[set[tuple[str, str]]] = []
        self._module_deps: dict[str, set[tuple[str, str]]] = {}
        self._skip_top_level: set[str] = set()
        self._spec_counts: dict[int, int] = {}
        self._subclass_index: dict[tuple[str, str], list[tuple[_PyModule, str]]] | None = None
        self._test_params: dict[int, frozenset[str]] = {}
        self._fn_scans: dict[int, tuple[frozenset[str], frozenset[str], frozenset[str], frozenset[int]]] = {}
        self._field_annotations: dict[tuple[str, str], dict[str, tuple[str, Any]]] = {}
        # Sınıf alanı kap açıklamalarının öğe türleri (``self.items: list[Repo]`` → items: Repo).
        self._field_elem_annotations: dict[tuple[str, str], dict[str, tuple[str, Any]]] = {}
        self._annotation_cache: dict[int, tuple[bool, tuple[str, Any]] | None] = {}
        self.passes = 0
        # Sunucu tarafı şablonlar (Django/Jinja2): {göreli yol: metin}; kaçışsız çıktı ayrıştırma önbelleği.
        self.templates: dict[str, str] = {}
        self.template_inventory: frozenset[str] = frozenset()
        self._template_cache: dict[str, Any] = {}
        self._django_url_params: dict[tuple[str, str], frozenset[str]] | None = None
        self._global_names: dict[int, tuple[ast.AST, frozenset[str]]] = {}  # modül ağacı → global bildirilen adlar
        self._uses_mongo: bool | None = None
        self.implicit_user_outputs: dict[tuple[str, int], tuple[str, int]] = {}
        self.sanitizer_versions: dict[str, bool] = {}
        self.sanitizer_version_scopes: dict[str, dict[str, bool]] = {}

    def sanitizer_version(self, module: _PyModule, package: str) -> bool | None:
        parent = str(PurePosixPath(module.relpath).parent)
        parent = "" if parent == "." else parent.strip("/")
        matches = [
            scope for scope, versions in self.sanitizer_version_scopes.items()
            if package in versions and (not scope or parent == scope or parent.startswith(scope + "/"))
        ]
        if matches:
            scope = max(matches, key=lambda value: (value.count("/"), len(value)))
            return self.sanitizer_version_scopes[scope][package]
        return self.sanitizer_versions.get(package)

    def _route_body_replaced(self, module: _PyModule, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Whether an inner project decorator replaces a route with a constant wrapper.

        This intentionally recognizes only the bounded, unambiguous shape
        ``decorator(fn) -> local wrapper`` where the wrapper never references
        ``fn``.  Other decorators remain conservative.
        """
        route_indexes = [
            index for index, decorator in enumerate(node.decorator_list)
            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr in _PY_ROUTE_DECORATORS
        ]
        if not route_indexes:
            return False
        # Every route decorator registers the value produced by decorators
        # below it.  The original body is unreachable only when even the
        # innermost route has a replacing decorator below it.  Looking below
        # the outermost route loses an endpoint when another route sits closer
        # to the function.
        inner_route = max(route_indexes)
        for decorator in node.decorator_list[inner_route + 1:]:
            func = decorator.func if isinstance(decorator, ast.Call) else decorator
            dotted = _dotted(func)
            resolved = self.resolve(module, dotted) if dotted else None
            if resolved is None or resolved[0] != "func":
                continue
            owner, qual = resolved[1], resolved[2]
            definition = owner.functions.get(qual)
            if definition is None:
                continue
            params = [*definition.args.posonlyargs, *definition.args.args]
            if not params:
                continue
            wrapped_name = params[0].arg
            locals_by_name = {
                child.name: child for child in definition.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            # Dekoratör gövdesinin tüm denetim yollarındaki dönüşleri gör; yerel
            # wrapper gövdesindeki dönüşler dekoratörün kendi dönüşü değildir.
            pending: list[ast.AST] = list(definition.body)
            returns: list[ast.Return] = []
            while pending:
                child = pending.pop()
                if isinstance(child, ast.Return):
                    returns.append(child)
                    continue
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                    continue
                pending.extend(ast.iter_child_nodes(child))
            if not returns:
                continue
            replacement = True
            for returned in returns:
                value = returned.value
                if isinstance(value, ast.Name) and value.id == wrapped_name:
                    replacement = False
                    break
                wrapper = locals_by_name.get(value.id) if isinstance(value, ast.Name) else None
                if wrapper is None or any(isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
                                          and child.id == wrapped_name for child in fast_walk(wrapper)):
                    replacement = False
                    break
            if replacement:
                return True
        return False

    MAX_PASSES = 3
    MAX_SPECIALIZATIONS = 8

    def add_global(self, relpath: str, name: str, taint: Taint) -> None:
        real = tuple(o for o in taint if o.label not in {_PARAM, _FIELD})
        if not real:
            return
        key = (relpath, name)
        old = self.globals.get(key, _EMPTY)
        new = _union(old, real)
        if set(new) != set(old):
            self.globals[key] = new
            self.globals_version += 1
            if key in self._read_keys:
                self._stale = True
                self._stale_keys.add(key)

    def read_global(self, relpath: str, name: str) -> Taint:
        self._read_keys.add((relpath, name))
        if self._deps_stack:
            self._deps_stack[-1].add((relpath, name))
        return self.globals.get((relpath, name), _EMPTY)

    def global_ref(self, module: _PyModule, name: str) -> tuple[str, str] | None:
        """Ad bir modül global'i mi? (aynı modül veya ``from mod import AD``)."""
        if name in module.top_names:
            return (module.relpath, name)
        target = module.imports.get(name)
        if target and "." in target:
            owner, _, attr = target.rpartition(".")
            for candidate in (owner, f"{module.package}.{owner}" if module.package else owner):
                other = self.module_named(candidate)
                if other is not None and attr in other.top_names:
                    return (other.relpath, attr)
        return None

    def module_global_attr(self, module: _PyModule, alias: str, attr: str) -> tuple[str, str] | None:
        """``import mod; mod.AD`` biçimi."""
        target = module.imports.get(alias)
        if not target:
            return None
        for candidate in (target, f"{module.package}.{target}" if module.package else target):
            other = self.module_named(candidate)
            if other is not None and attr in other.top_names:
                return (other.relpath, attr)
        return None

    def subclasses(self, module: _PyModule, class_name: str) -> list[tuple[_PyModule, str]]:
        """Proje genelinde (geçişli) alt sınıflar."""
        if self._subclass_index is None:
            index: dict[tuple[str, str], list[tuple[_PyModule, str]]] = {}
            for mod in self.modules.values():
                for cls, cnode in mod.classes.items():
                    for base in cnode.bases:
                        dotted = _dotted(base)
                        resolved = self.resolve(mod, dotted) if dotted else None
                        if resolved is not None and resolved[0] == "class":
                            index.setdefault((resolved[1].relpath, resolved[2]), []).append((mod, cls))
            self._subclass_index = index
        found: list[tuple[_PyModule, str]] = []
        stack = [(module.relpath, class_name)]
        seen: set[tuple[str, str]] = set()
        while stack and len(found) < 32:
            key = stack.pop()
            for sub in self._subclass_index.get(key, []):
                sub_key = (sub[0].relpath, sub[1])
                if sub_key not in seen:
                    seen.add(sub_key)
                    found.append(sub)
                    stack.append(sub_key)
        return found

    def _fn_scan(self, node: ast.AST) -> tuple[frozenset[str], frozenset[str], frozenset[str], frozenset[int]]:
        """İşlev düğümünün tek yürüyüşte çıkarılan özeti (19. tur; düğüm başına bir kez): ``global`` bildirimleri,
        atanan adlar, koşul ifadelerindeki adlar ve HTML dışı yanıt kurucuları. Önceden dört ayrı tam yürüyüştü."""
        cached = self._fn_scans.get(id(node))
        if cached is None:
            decls: set[str] = set()
            stored: set[str] = set()
            tests: list[ast.AST] = []
            assigns: list[ast.Assign] = []
            for child in fast_walk(node):
                if isinstance(child, ast.Name):
                    if isinstance(child.ctx, ast.Store):
                        stored.add(child.id)
                elif isinstance(child, ast.Global):
                    decls.update(child.names)
                elif isinstance(child, ast.Assign):
                    assigns.append(child)
                if isinstance(child, (ast.If, ast.IfExp, ast.While, ast.Assert)):
                    test = getattr(child, "test", None)
                    if test is not None:
                        tests.append(test)
                elif type(child).__name__ == "Match":
                    tests.append(child.subject)
            names: set[str] = set()
            for test in tests:
                names.update(n.id for n in fast_walk(test) if isinstance(n, ast.Name))
            cached = (frozenset(decls), frozenset(stored), frozenset(names), frozenset(_non_html_from_assigns(assigns)))
            self._fn_scans[id(node)] = cached
        return cached

    def non_html_response_calls(self, node: ast.AST) -> frozenset[int]:
        return self._fn_scan(node)[3]

    def test_params(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
        """Koşul ifadelerinde (if/while/üçlü/match) kullanılan adlar: sabit argümanla özelleştirme adayı."""
        return self._fn_scan(node)[2]

    def annotated_type(self, module: _PyModule, dotted: str) -> tuple[str, Any] | None:
        """Tip açıklamasındaki adın türü: ("class", (modül, sınıf)) proje sınıfı, ("request", ad) gelen
        istek nesnesi veya ("ext", tanım yolu) modeli bilinen dış sınıf."""
        if not dotted:
            return None
        resolved = self.resolve(module, dotted)
        if resolved is not None:
            return ("class", (resolved[1], resolved[2])) if resolved[0] == "class" else None
        head, _, rest = dotted.partition(".")
        target = module.imports.get(head)
        canonical = f"{target}.{rest}" if target and rest else (target or dotted)
        if canonical in _PY_REQUEST_TYPES or dotted in _PY_REQUEST_TYPES:
            return ("request", canonical)
        if canonical in _PY_BACKGROUND_TASK_TYPES:
            return ("ext", canonical)
        ext = self.models.class_of(canonical) or self.models.class_of(dotted)
        return ("ext", ext) if ext else None

    def class_field_types(self, module: _PyModule, class_name: str, depth: int = 0) -> dict[str, tuple[str, Any]]:
        """Sınıf düzeyi alan açıklamaları (dataclass/pydantic ``alan: T``) ve ``self.alan: T`` açıklamaları;
        proje içi taban sınıflarınkiler dahil (alt sınıf önceliklidir)."""
        key = (module.relpath, class_name)
        cached = self._field_annotations.get(key)
        if cached is not None:
            return cached
        result: dict[str, tuple[str, Any]] = {}
        elements: dict[str, tuple[str, Any]] = {}
        self._field_annotations[key] = result  # döngüsel kalıtıma karşı
        self._field_elem_annotations[key] = elements
        cnode = module.classes.get(class_name)
        if cnode is None:
            return result
        if depth < 4:
            for base in cnode.bases:
                resolved = self.resolve(module, _dotted(base)) if _dotted(base) else None
                if resolved is not None and resolved[0] == "class":
                    result.update(self.class_field_types(resolved[1], resolved[2], depth + 1))
                    elements.update(self._field_elem_annotations.get((resolved[1].relpath, resolved[2]), {}))
        found: list[tuple[str, ast.AST]] = []
        for stmt in cnode.body:
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                found.append((stmt.target.id, stmt.annotation))
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name == "__init__":
                for child in fast_walk(stmt):
                    if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Attribute) \
                            and isinstance(child.target.value, ast.Name) and child.target.value.id == "self":
                        found.append((child.target.attr, child.annotation))
        for name, annotation in found:
            target = _annotation_target(annotation)
            if target is not None:
                kind = self.annotated_type(module, target[1])
                if kind is not None:
                    (elements if target[0] else result)[name] = kind
        return result

    def class_field_element_types(self, module: _PyModule, class_name: str) -> dict[str, tuple[str, Any]]:
        """Kap türlü sınıf alanlarının öğe türleri (``list[X]`` / ``Sequence[X]`` …)."""
        self.class_field_types(module, class_name)
        return self._field_elem_annotations.get((module.relpath, class_name), {})

    def function_names(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[frozenset[str], frozenset[str]]:
        """Fonksiyondaki ``global`` bildirimleri ve atanan adlar (düğüm başına bir kez; yeniden geçişte/özelleştirmede tekrar yürünmez)."""
        scan = self._fn_scan(node)
        return scan[0], scan[1]

    def tick(self) -> None:
        self.steps += 1
        if self.steps > self.max_steps:
            raise RecursionError("taint adım sınırı")

    # -- modüller ------------------------------------------------------------------
    def add_module(self, relpath: str, tree: ast.Module) -> _PyModule:
        module = _PyModule(relpath, tree)
        self.modules[relpath] = module
        self.flows.setdefault(relpath, [])
        self.clean.setdefault(relpath, set())
        names = [module.modname]
        if module.modname.startswith("src."):
            names.append(module.modname[4:])
        for name in names:
            if name:
                self.by_name.setdefault(name, module)
        # app/, backend/ gibi alt kökten çalışan projeler (`from apis.admin.utils import …`): baştan en çok iki
        # dizin kırpılmış, en az iki parçalı takma ad. Birden çok modüle uyan takma ad belirsizdir (kullanılmaz).
        parts = module.modname.split(".")
        for strip in (1, 2):
            if len(parts) - strip < 2:
                break
            alias = ".".join(parts[strip:])
            previous = self.alias_by_name.get(alias, module)
            self.alias_by_name[alias] = module if previous is module else None
        return module

    def module_named(self, name: str) -> _PyModule | None:
        module = self.by_name.get(name)
        if module is None:
            module = self.alias_by_name.get(name)
        return module

    def run(self) -> None:
        """Analizi çalıştır; global değişken taint'i okuma sonrası değiştiyse yeniden geçiş (sabit nokta)."""
        for attempt in range(self.MAX_PASSES):
            self.passes = attempt + 1
            self._read_keys = set()
            self._stale = False
            self._stale_keys = set()
            self._run_once()
            # Yalnız okunmuş bir global okunduktan sonra değiştiyse yeniden geçiş gerekir
            # (yalnız yazılan ya da okunmadan önce son değerine ulaşan globaller için gerekmez).
            if not self._stale or attempt == self.MAX_PASSES - 1:
                return
            self._invalidate_stale()

    def _run_once(self) -> None:
        for module in list(self.modules.values()):
            self._analyze_module(module)
        while self.extra:
            module, qual, node, class_name = self.extra.pop(0)
            self.summary(module, qual, node, class_name)

    def _invalidate_stale(self) -> None:
        """Artımlı yeniden geçiş: yalnız bayat globali (doğrudan/dolaylı) okuyan özetler yeniden hesaplanır.

        Global taint'leri yalnız büyür (birleşim), bu yüzden önceki geçişin akışları ve değerlendirilen
        hedefleri geçerli kalır; yeni geçiş yalnız ekler (yinelenen akışlar _emitted ile süzülür)."""
        stale = self._stale_keys
        self.summaries = {key: summary for key, summary in self.summaries.items()
                          if not (summary.global_reads & stale)}
        self._spec_counts = {}
        for key in self.summaries:
            if isinstance(key, tuple):
                self._spec_counts[key[0]] = self._spec_counts.get(key[0], 0) + 1
        self.extra = []
        self._done_modules = set()
        # Modül düzeyi kodu bayat globale (doğrudan/özetler üzerinden) bağlı değilse yeniden yürütülmez.
        self._skip_top_level = {relpath for relpath, deps in self._module_deps.items() if not deps & stale}

    def _analyze_module(self, module: _PyModule) -> None:
        if module.relpath in self._done_modules:
            return
        self._done_modules.add(module.relpath)
        if module.relpath not in self._skip_top_level:
            scope = _PyScope(self, module, {}, qual="<module>")
            for (relpath, name), taint in self.globals.items():
                if relpath == module.relpath:
                    scope.env[name] = taint
            self._deps_stack.append(set())
            try:
                scope.block(module.tree.body)
            finally:
                deps = self._deps_stack.pop()
            for name, taint in scope.env.items():
                if name in module.top_names and taint:
                    self.add_global(module.relpath, name, taint)
            # Modül düzeyi kodun okuduğu adlar: sonradan (fonksiyonlarca) değişirlerse modül yeniden çözümlenmeli.
            loads = {(module.relpath, name) for name in module.top_loads()}
            self._read_keys.update(loads)
            self._module_deps[module.relpath] = deps | loads
        for qual, node in list(module.functions.items()):
            self.summary(module, qual, node, qual.split(".")[0] if "." in qual else None)

    def analysis_for(self, relpath: str) -> Analysis:
        return Analysis(
            "python", list(self.flows.get(relpath, [])), set(self.clean.get(relpath, set())),
            set(self.uncertain.get(relpath, set())),
        )

    # -- kayıt -----------------------------------------------------------------------
    def add_flow(self, flow: Flow) -> None:
        key = (flow.sink_kind, flow.line, flow.source, flow.source_line, flow.source_file)
        emitted = self._emitted.setdefault(flow.file, set())
        if key in emitted:
            return
        emitted.add(key)
        self.flows.setdefault(flow.file, []).append(flow)

    def mark_evaluated(self, relpath: str, kind: str, line: int) -> None:
        self.clean.setdefault(relpath, set()).add((kind, line))

    # -- ad çözümleme -------------------------------------------------------------------
    def resolve(self, module: _PyModule, dotted: str, depth: int = 0) -> tuple[str, _PyModule, str] | None:
        """``f`` / ``Sinif`` / ``Sinif.metot`` / ``takma_ad.f`` adını proje tanımına çöz."""
        if depth > 6 or not dotted:
            return None
        head, _, rest = dotted.partition(".")
        if not rest:
            if head in module.functions:
                return ("func", module, head)
            if head in module.classes:
                return ("class", module, head)
        elif head in module.classes:
            found = self.find_method(module, head, rest, depth + 1) if "." not in rest else None
            return ("func", *found) if found else None
        target = module.imports.get(head)
        if target is not None:
            return self.resolve_absolute(f"{target}.{rest}" if rest else target, module, depth + 1)
        if not rest:
            for star in module.star_imports:
                found_star = self.resolve_absolute(f"{star}.{head}", module, depth + 1)
                if found_star is not None:
                    return found_star
        return None

    def resolve_absolute(self, name: str, importer: _PyModule, depth: int) -> tuple[str, _PyModule, str] | None:
        candidates = [name]
        if importer.package:
            # Betik dizini sys.path'te olduğundan kardeş modüller mutlak adla da içe aktarılabilir.
            candidates.append(f"{importer.package}.{name}")
        for candidate in candidates:
            parts = candidate.split(".")
            for size in range(len(parts), 0, -1):
                module = self.module_named(".".join(parts[:size]))
                if module is None:
                    continue
                rest = ".".join(parts[size:])
                if not rest:
                    return ("module", module, "")
                return self.resolve(module, rest, depth)
        return None

    def methods_named(self, method: str) -> list[tuple[_PyModule, str]]:
        index = getattr(self, "_method_index", None)
        if index is None:
            index = {}
            for module in self.modules.values():
                for qual in module.functions:
                    if "." in qual and qual.split(".")[0] in module.classes:
                        index.setdefault(qual.rsplit(".", 1)[1], []).append((module, qual))
            self._method_index = index
        return index.get(method, [])

    def find_method(self, module: _PyModule, class_name: str, method: str, depth: int = 0) -> tuple[_PyModule, str] | None:
        qual = f"{class_name}.{method}"
        if qual in module.functions:
            return module, qual
        node = module.classes.get(class_name)
        if node is None or depth > 6:
            return None
        for base in node.bases:
            dotted = _dotted(base)
            resolved = self.resolve(module, dotted, depth + 1) if dotted else None
            if resolved is not None and resolved[0] == "class":
                found = self.find_method(resolved[1], resolved[2], method, depth + 1)
                if found is not None:
                    return found
        return None

    # -- özetler ---------------------------------------------------------------------------
    def summary(self, module: _PyModule, qual: str, node: ast.FunctionDef | ast.AsyncFunctionDef,
                class_name: str | None, consts: tuple[tuple[int, Any], ...] = ()) -> _PySummary:
        if not consts and class_name is None and _is_route_function(node) \
                and self._route_body_replaced(module, node):
            key = id(node)
            cached = self.summaries.get(key)
            if cached is None:
                arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                cached = self.summaries[key] = _PySummary(tuple(arg.arg for arg in arguments))
            return cached
        if consts:
            # Bağlam duyarlılığı: koşullarda kullanılan parametrelere sabit argüman geçen çağrılar için
            # özelleştirilmiş özet (fonksiyon başına en çok MAX_SPECIALIZATIONS).
            spec_key: Any = (id(node), consts)
            cached = self.summaries.get(spec_key)
            if cached is not None:
                if self._deps_stack:
                    self._deps_stack[-1] |= cached.global_reads
                return cached
            if self._spec_counts.get(id(node), 0) >= self.MAX_SPECIALIZATIONS or spec_key in self._active:
                return self.summary(module, qual, node, class_name)
            self._spec_counts[id(node)] = self._spec_counts.get(id(node), 0) + 1
            self._active.add(spec_key)
            self._depth += 1
            self._deps_stack.append(set())
            try:
                summary = self._analyze_function(module, qual, node, class_name, consts)
            finally:
                self._active.discard(spec_key)
                self._depth -= 1
                deps = self._deps_stack.pop()
            summary.global_reads = deps
            if self._deps_stack:
                self._deps_stack[-1] |= deps
            self.summaries[spec_key] = summary
            return summary
        key = id(node)
        cached = self.summaries.get(key)
        if cached is not None:
            if self._deps_stack:
                self._deps_stack[-1] |= cached.global_reads
            return cached
        if key in self._active or self._depth > self.MAX_DEPTH:
            # Özyineleme veya çok derin zincir: bu çağrı yerinde özet bilinmiyor sayılır.
            return _PySummary(())
        self._active.add(key)
        self._depth += 1
        self._deps_stack.append(set())
        try:
            summary = self._analyze_function(module, qual, node, class_name)
        finally:
            self._active.discard(key)
            self._depth -= 1
            deps = self._deps_stack.pop()
        summary.global_reads = deps
        if self._deps_stack:
            self._deps_stack[-1] |= deps
        self.summaries[key] = summary
        return summary

    def _analyze_function(self, module: _PyModule, qual: str, node: ast.FunctionDef | ast.AsyncFunctionDef,
                          class_name: str | None, consts: tuple[tuple[int, Any], ...] = ()) -> _PySummary:
        arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        params = tuple(arg.arg for arg in arguments)
        summary = _PySummary(params)
        env: dict[str, Taint] = {}
        url_rule_view = class_name is None and node.name in module.url_rule_views()
        is_route = _is_route_function(node) or url_rule_view
        annotated = {arg.arg: self._param_type(module, arg.annotation) for arg in arguments if arg.annotation is not None}
        if is_route:
            typed = _typed_route_params(node)
            for arg in arguments:
                # 18. tur: "user" adlı ama proje modeliyle (pydantic gövde) açıklanmış parametre istek gövdesidir;
                # kimlik doğrulama bağımlılığı (Depends/Security) aşağıda ayrıca düşürülür.
                model_body = arg.arg in ("user", "req", "current_user") and \
                    (annotated.get(arg.arg) or (None, ("",)))[1][0] == "class"
                if (arg.arg in _PY_PARAM_EXCLUDE and not model_body) or arg.arg in typed:
                    continue
                if arg.annotation is not None and _dotted(arg.annotation) in _PY_SAFE_ANNOTATIONS:
                    continue
                if annotated.get(arg.arg) is not None and annotated[arg.arg][1][0] == "request":
                    continue  # istek nesnesinin kendisi değil, okunan alanları kaynak (aşağıda istek kökü)
                env[arg.arg] = (_Origin("request", f"parametre:{arg.arg}", node.lineno, (), frozenset(), module.relpath),)
            for default, arg in zip(reversed(node.args.defaults), reversed(node.args.args)):
                if isinstance(default, ast.Call) and _dotted(default.func).rsplit(".", 1)[-1] in ("Depends", "Security"):
                    env.pop(arg.arg, None)
        else:
            for index, arg in enumerate(arguments):
                if index == 0 and class_name is not None and arg.arg in {"self", "cls"}:
                    continue
                if arg.annotation is not None and _dotted(arg.annotation) in _PY_SAFE_ANNOTATIONS:
                    continue
                env[arg.arg] = (_Origin(_PARAM, str(index), node.lineno, (), frozenset(), module.relpath),)
        entry = None if is_route or consts else self.entry_sources(module, qual, node, class_name)
        if entry is not None:
            # Çatı giriş noktası: parametreler istek girdisidir (GraphQL argümanları, Lambda event, Connexion gövdesi …).
            _kind, sources, request_params = entry
            for name in sources:
                label = "stored" if _kind == "celery" else "request"
                source = f"görev kuyruğu parametresi:{name}" if label == "stored" else f"parametre:{name}"
                env[name] = (_Origin(label, source, node.lineno, (), frozenset(), module.relpath),)
            for name in request_params:
                env.pop(name, None)
                annotated[name] = (False, ("request", "flask.Request"))
        for index, value in consts:
            if index < len(arguments):
                env.pop(arguments[index].arg, None)
        scope = _PyScope(self, module, env, summary=summary, class_name=class_name, qual=qual, is_route=is_route)
        scope.html_route = is_route and (url_rule_view or _is_html_route(node, module))
        scope.path_reflects = _path_reflects(node)
        if entry is not None and entry[0] == "falcon":
            resp_name = arguments[2].arg
            # Falcon varsayılan içerik türü JSON'dur; resp.text/body yalnız HTML içerik türü atanmışsa XSS hedefi.
            if any(isinstance(stmt, ast.Assign) and any(
                    isinstance(t, ast.Attribute) and t.attr == "content_type" and _dotted(t.value) == resp_name
                    for t in stmt.targets) and _is_html_content_type(stmt.value) for stmt in fast_walk(node)):
                scope.falcon_html_resp = resp_name
        scope.non_html_response_calls = self.non_html_response_calls(node)
        for index, value in consts:
            if index < len(arguments):
                scope.consts[arguments[index].arg] = value
        if class_name is not None and arguments and arguments[0].arg in {"self", "cls"}:
            scope.self_name = arguments[0].arg
        global_decls, stored = self.function_names(node)
        scope.global_decls = set(global_decls)
        scope.local_names = (stored | set(params)) - scope.global_decls
        scope.local_rebindings = (set(_function_scope_stores(node)) | set(params)) - scope.global_decls
        if not is_route and entry is None:
            # Gövdede yeniden atanmayan parametreler: önek durumu çağrı yerinde argümana göre çözülür.
            scope.prefix_params = {
                arg.arg: index for index, arg in enumerate(arguments)
                if arg.arg not in stored and arg.arg not in scope.global_decls
                and not (index == 0 and class_name is not None and arg.arg in {"self", "cls"})
            }
        for name, info in annotated.items():
            if info is not None:
                scope.apply_type(name, *info)
        scope.block(node.body)
        return summary

    def _configured_entry(self, module: _PyModule, qual: str) -> bool:
        if not self.entrypoints or not module.modname:
            return False
        names = {module.modname}
        if module.modname.startswith("src."):
            names.add(module.modname[4:])
        for target in self.entrypoints:
            mod, _, func = target.partition(":")
            if func == qual and any(name == mod or name.endswith("." + mod) for name in names):
                return True
        return False

    def _module_set_field_names(self, module: _PyModule) -> frozenset[str]:
        """ariadne ``tip.set_field("alan", fonksiyon)`` ile bağlanan çözücü adları."""
        cached = self._set_field_names.get(module.relpath)
        if cached is None:
            names: set[str] = set()
            for node in fast_walk(module.tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "set_field" \
                        and len(node.args) >= 2 and isinstance(node.args[1], ast.Name):
                    names.add(node.args[1].id)
            cached = frozenset(names)
            self._set_field_names[module.relpath] = cached
        return cached

    def _const_expr(self, module: _PyModule, node: ast.AST | None, depth: int = 0) -> Any:
        """Modül/sınıf düzeyi sabit ifadesinin dize değeri, _ENV_VALUE ya da None (çözülemez)."""
        if node is None or depth > 4:
            return None
        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, str) else None
        if _is_env_lookup(module, node):
            return _ENV_VALUE
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._const_expr(module, node.left, depth + 1)
            right = self._const_expr(module, node.right, depth + 1)
            if left is _ENV_VALUE:
                return _ENV_VALUE
            return left + right if isinstance(left, str) and isinstance(right, str) else None
        if isinstance(node, ast.JoinedStr):
            text = ""
            for value in node.values:
                part = self._const_expr(module, value.value if isinstance(value, ast.FormattedValue) else value, depth + 1)
                if part is _ENV_VALUE and not text:
                    return _ENV_VALUE
                if not isinstance(part, str):
                    return None
                text += part
            return text
        if isinstance(node, ast.Name):
            ref = self.global_ref(module, node.id)
            return self.module_constant(ref[0], ref[1], depth + 1) if ref else None
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return self.attribute_constant(module, node.value.id, node.attr, depth + 1)
        return None

    def module_constant(self, relpath: str, name: str, depth: int = 0) -> Any:
        """Modül düzeyinde bir kez atanan sabit (ör. ``API_BASE = "https://api.x/"``); başka yerde yeniden
        atanıyorsa ya da ``global`` ile değiştiriliyorsa None."""
        key = (relpath, name)
        cache = self._module_constants
        if key in cache:
            return cache[key]
        cache[key] = None  # döngüye karşı
        module = self.modules.get(relpath)
        if module is None:
            return None
        values = []
        for stmt in module.tree.body:
            if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in stmt.targets):
                values.append(stmt.value)
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.target.id == name:
                values.append(stmt.value)
            elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name) and stmt.target.id == name:
                return None
        mutated = len(values) == 1 and name in self._module_global_names(module)  # yalnız gerektiğinde, modül başına bir yürüyüş
        result = self._const_expr(module, values[0], depth) if len(values) == 1 and not mutated else None
        cache[key] = result
        return result

    def _module_global_names(self, module: _PyModule) -> frozenset[str]:
        """Modülün herhangi bir yerinde ``global`` ile bildirilen adlar (modül başına bir kez)."""
        tree = module.tree
        cached = self._global_names.get(id(tree))
        if cached is None or cached[0] is not tree:
            names = frozenset(n for node in fast_walk(tree) if isinstance(node, ast.Global) for n in node.names)
            cached = (tree, names)
            self._global_names[id(tree)] = cached
        return cached[1]

    def class_constant(self, module: _PyModule, class_name: str, name: str, depth: int = 0) -> Any:
        cnode = module.classes.get(class_name)
        if cnode is None:
            return None
        values = [stmt.value for stmt in cnode.body
                  if (isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in stmt.targets))
                  or (isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.target.id == name)]
        return self._const_expr(module, values[0], depth) if len(values) == 1 else None

    def django_setting(self, name: str, depth: int = 0) -> Any:
        """``django.conf.settings.AD``: projedeki settings modüllerinde (settings.py, settings/*.py) tanımlı
        değerler; tümü aynıysa o değer, herhangi biri ortam değişkeniyse _ENV_VALUE, çelişirse None."""
        cache = self._django_settings
        if name in cache:
            return cache[name]
        found: list[Any] = []
        for module in self.modules.values():
            parts = module.modname.split(".")
            if "settings" not in parts and "settings" not in parts[-1]:
                continue
            if name in module.top_names:
                found.append(self.module_constant(module.relpath, name, depth + 1))
        if any(value is _ENV_VALUE for value in found):
            result = _ENV_VALUE
        elif found and all(isinstance(value, str) for value in found) and len(set(found)) == 1:
            result = found[0]
        else:
            result = None
        cache[name] = result
        return result

    def attribute_constant(self, module: _PyModule, owner: str, attr: str, depth: int = 0) -> Any:
        """``ayarlar.AD`` / ``config.AD`` / ``Sinif.AD``: proje modülü, Django settings ya da sınıf sabiti."""
        if depth > 4:
            return None
        if module.imports.get(owner) in {"django.conf.settings"}:
            return self.django_setting(attr, depth)
        ref = self.module_global_attr(module, owner, attr)
        if ref is not None:
            return self.module_constant(ref[0], ref[1], depth + 1)
        found = self.resolve(module, owner)
        if found is not None and found[0] == "class":
            return self.class_constant(found[1], found[2], attr, depth + 1)
        return None

    def is_tornado_handler(self, module: _PyModule, class_name: str) -> bool:
        """Sınıf (geçişli) ``tornado.web.RequestHandler``'dan mı türüyor?"""
        return self.is_stdlib_handler(module, class_name, bases=_TORNADO_HANDLER_BASES)

    def is_stdlib_handler(self, module: _PyModule, class_name: str, depth: int = 0,
                          bases: frozenset[str] | None = None) -> bool:
        """Sınıf (geçişli) http.server / socketserver / wsgiref istek işleyicisinden mi türüyor?"""
        bases = _PY_STDLIB_HANDLER_BASES if bases is None else bases
        cache = self._stdlib_handlers
        key = (module.relpath, class_name, bases)  # taban kümesi başına (tornado / WTForms sorguları karışmasın)
        if key in cache:
            return cache[key]
        cache[key] = False  # döngüsel kalıtıma karşı
        cnode = module.classes.get(class_name)
        result = False
        if cnode is not None and depth < 6:
            for base in cnode.bases:
                dotted = _dotted(base)
                if not dotted:
                    continue
                if self._canonical_call(module, base) in bases:
                    result = True
                    break
                found = self.resolve(module, dotted)
                if found is not None and found[0] == "class" and self.is_stdlib_handler(found[1], found[2], depth + 1, bases):
                    result = True
                    break
        cache[key] = result
        return result

    def _canonical_call(self, module: _PyModule, func: ast.AST) -> str:
        dotted = _dotted(func)
        head, _, rest = dotted.partition(".")
        target = module.imports.get(head)
        return f"{target}.{rest}" if target and rest else (target or dotted)

    def set_templates(self, templates: dict[str, str]) -> None:
        self.templates = templates
        self.template_inventory = frozenset(templates)

    def template_outputs(self, relpath: str, module: _PyModule) -> list[Any]:
        return taint_py_views.template_outputs(relpath, module.relpath, self.template_inventory,
                                              self.templates.get, self._template_cache)

    def model_form_fields(self) -> dict[str, frozenset[str]]:
        """25. tur: Django ModelForm sınıfları (iç ``Meta`` sınıfında ``model`` ve sabit ``fields`` listesi) → alan
        adları. Form istek verisiyle kurulup kaydedilirse bu alanlar kullanıcının yazdığı kayıt alanlarıdır."""
        if self._model_form_fields is None:
            found: dict[str, frozenset[str]] = {}
            for module in self.modules.values():
                for node in fast_walk(module.tree):
                    if not isinstance(node, ast.ClassDef):
                        continue
                    meta = next((b for b in node.body if isinstance(b, ast.ClassDef) and b.name == "Meta"), None)
                    if meta is None:
                        continue
                    names: dict[str, ast.AST] = {}
                    for stmt in meta.body:
                        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                            names[stmt.targets[0].id] = stmt.value
                    fields = names.get("fields")
                    if "model" in names and isinstance(fields, (ast.Tuple, ast.List)):
                        values = frozenset(e.value for e in fields.elts
                                           if isinstance(e, ast.Constant) and isinstance(e.value, str))
                        if values:
                            found[node.name] = found.get(node.name, frozenset()) | values
            self._model_form_fields = found
        return self._model_form_fields

    def uses_mongo(self) -> bool:
        """Projede MongoDB sürücüsü (pymongo/motor/flask_pymongo/mongoengine) içe aktarılıyor mu?"""
        if self._uses_mongo is None:
            self._uses_mongo = any(
                target.split(".")[0] in _PY_MONGO_PACKAGES
                for module in self.modules.values() for target in module.imports.values()
            )
        return self._uses_mongo

    def django_url_params(self) -> dict[tuple[str, str], frozenset[str]]:
        """Django URLconf (``path``/``re_path``/``url``) ile bağlanan fonksiyon görünümleri ve serbest metin
        URL parametreleri: (modül yolu, ad) → parametre adları. ``<int:x>``/``<slug:x>``/``<uuid:x>`` ve yalnız
        rakam/kelime karakteri kabul eden ``(?P<x>\\d+)`` grupları metin taşıyamaz (kaynak sayılmaz)."""
        if self._django_url_params is None:
            found: dict[tuple[str, str], set[str]] = {}
            for module in self.modules.values():
                if not any(target.split(".")[0] == "django" for target in module.imports.values()):
                    continue
                for node in fast_walk(module.tree):
                    if not isinstance(node, ast.Call) or len(node.args) < 2:
                        continue
                    canonical = self._canonical_call(module, node.func)
                    if canonical not in _DJANGO_URL_FUNCS:
                        continue
                    pattern = node.args[0]
                    if not (isinstance(pattern, ast.Constant) and isinstance(pattern.value, str)):
                        continue
                    view = _dotted(node.args[1])
                    if not view or "(" in view:
                        continue
                    resolved = self.resolve(module, view)
                    if resolved is None or resolved[0] != "func":
                        continue
                    _, target_module, qual = resolved
                    names = _django_route_text_params(pattern.value, canonical.endswith(".path"))
                    found.setdefault((target_module.relpath, qual), set()).update(names)
            self._django_url_params = {key: frozenset(value) for key, value in found.items()}
        return self._django_url_params

    def resolver_refs(self) -> dict[tuple[str, str], str]:
        """Dolaylı bağlanan GraphQL çözücüleri (proje genelinde bir kez):

        * strawberry: ``strawberry.field(resolver=f)`` / ``mutation(resolver=…)`` / ``subscription(resolver=…)``;
        * ariadne: ``ObjectType("Query", {"x": f})``, ``QueryType/MutationType(... {..})``, ``make_executable_schema``
          sözlük argümanı ve ``{"Query": {"x": f}}`` biçimli modül düzeyi sözlükler (proje ariadne kullanıyorsa).
        Değer olarak verilen ad/öznitelik proje fonksiyonuna çözülür (dosyalar arası içe aktarma dahil)."""
        if self._resolver_refs is not None:
            return self._resolver_refs
        refs: dict[tuple[str, str], str] = {}
        uses_ariadne = any(target.split(".")[0] == "ariadne" for m in self.modules.values() for target in m.imports.values())

        def add(module: _PyModule, value: ast.AST, framework: str) -> None:
            dotted = _dotted(value) if isinstance(value, (ast.Name, ast.Attribute)) else ""
            found = self.resolve(module, dotted) if dotted else None
            if found is not None and found[0] == "func":
                refs.setdefault((found[1].relpath, found[2]), framework)

        def module_dict(module: _PyModule, name: str) -> ast.Dict | None:
            for stmt in module.tree.body:
                if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Dict) and any(
                        isinstance(t, ast.Name) and t.id == name for t in stmt.targets):
                    return stmt.value
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.value, ast.Dict) \
                        and isinstance(stmt.target, ast.Name) and stmt.target.id == name:
                    return stmt.value
            return None

        def field_map(module: _PyModule, value: ast.AST | None, depth: int = 0) -> None:
            """{"alan": f, ...} ya da {"Query": {"alan": f}} (ad başvurusu da çözülür)."""
            if value is None or depth > 3:
                return
            if isinstance(value, ast.Name):
                local = module_dict(module, value.id)
                if local is not None:
                    field_map(module, local, depth + 1)
                    return
                target = module.imports.get(value.id)
                if target and "." in target:
                    owner = self.module_named(target.rpartition(".")[0])
                    if owner is not None:
                        field_map(owner, module_dict(owner, target.rpartition(".")[2]), depth + 1)
                return
            if not isinstance(value, ast.Dict):
                return
            for key, item in zip(value.keys, value.values):
                if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
                    continue
                if isinstance(item, (ast.Dict, ast.Name)) and not (
                        isinstance(item, ast.Name) and self.resolve(module, item.id) is not None
                        and self.resolve(module, item.id)[0] == "func"):
                    field_map(module, item, depth + 1)
                else:
                    add(module, item, "ariadne")

        for module in self.modules.values():
            heads = {target.split(".")[0] for target in module.imports.values()}
            if "strawberry" in heads or "ariadne" in heads:
                for node in fast_walk(module.tree):
                    if not isinstance(node, ast.Call):
                        continue
                    canonical = self._canonical_call(module, node.func)
                    head, _, last = canonical.partition(".")
                    last = canonical.rsplit(".", 1)[-1]
                    if head == "strawberry" and last in {"field", "mutation", "subscription"}:
                        for keyword in node.keywords:
                            if keyword.arg == "resolver":
                                add(module, keyword.value, "strawberry")
                    elif head == "ariadne" and last in {"ObjectType", "QueryType", "MutationType", "SubscriptionType",
                                                        "InterfaceType", "UnionType"}:
                        for arg in [*node.args, *(k.value for k in node.keywords if k.arg == "fields")]:
                            if isinstance(arg, (ast.Dict, ast.Name)):
                                field_map(module, arg)
                    elif head == "ariadne" and last == "make_executable_schema":
                        for arg in [*node.args[1:], *(k.value for k in node.keywords if k.arg != "type_defs")]:
                            if isinstance(arg, (ast.Dict, ast.Name)):
                                field_map(module, arg)
                            elif isinstance(arg, (ast.List, ast.Tuple)):
                                for element in arg.elts:
                                    if isinstance(element, (ast.Dict, ast.Name)):
                                        field_map(module, element)
            if uses_ariadne:
                # Modül düzeyi {"Query": {...}} / {"Mutation": {...}} çözücü haritaları (ayrı dosyada tanımlanabilir).
                for stmt in module.tree.body:
                    value = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign)) else None
                    if isinstance(value, ast.Dict) and any(
                            isinstance(k, ast.Constant) and k.value in {"Query", "Mutation", "Subscription"} for k in value.keys):
                        field_map(module, value)
        self._resolver_refs = refs
        return refs

    def entry_sources(self, module: _PyModule, qual: str, node: ast.FunctionDef | ast.AsyncFunctionDef,
                      class_name: str | None) -> tuple[str, frozenset[str], frozenset[str]] | None:
        """Çatı giriş noktası mı? (tür, kaynak parametreler, istek nesnesi parametreleri) ya da None.

        Connexion/serverless yapılandırması, Lambda ``(event, context)`` işleyicisi, Google Cloud
        Functions, graphene ``resolve_*``/``mutate``, strawberry ``@strawberry.field``/``mutation`` ve
        ariadne ``@tip.field("x")``/``set_field`` çözücüleri."""
        arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        names = [arg.arg for arg in arguments]
        extra = [a.arg for a in (node.args.vararg, node.args.kwarg) if a is not None]
        heads = {target.split(".")[0] for target in module.imports.values()}
        short = qual.rsplit(".", 1)[-1]

        def all_but(skip_first: bool) -> frozenset[str]:
            chosen = names[1:] if skip_first and names else names
            return frozenset(n for n in [*chosen, *extra] if n not in _PY_ENTRY_NON_SOURCE)

        decorators = []
        for decorator in node.decorator_list:
            func = decorator.func if isinstance(decorator, ast.Call) else decorator
            dotted = _dotted(func)
            head, _, rest = dotted.partition(".")
            target = module.imports.get(head)
            decorators.append((decorator, f"{target}.{rest}" if target and rest else (target or dotted)))
        if class_name is not None and "tornado" in heads and short in _TORNADO_VERBS and names \
                and self.is_tornado_handler(module, class_name):
            # Tornado işleyicisi: URL deseni grupları metot parametreleri olarak gelir.
            return ("tornado", all_but(True), frozenset())
        if class_name is None and "django" in heads and names and names[0] in {"request", "req"}:
            django_params = self.django_url_params().get((module.relpath, qual))
            if django_params is not None:
                # Django URLconf'a bağlı fonksiyon görünümü: serbest metin URL parametreleri istek girdisidir.
                return ("django", frozenset(n for n in names[1:] if n in django_params), frozenset())
        if class_name is not None and "falcon" in heads and len(names) >= 3 and _FALCON_RESPONDER_RE.match(short):
            # Falcon: req istek nesnesi, resp yanıt; kalan parametreler URI şablon alanlarıdır.
            return ("falcon", frozenset(n for n in names[3:] if n not in _PY_ENTRY_NON_SOURCE), frozenset({names[1]}))
        if self._configured_entry(module, qual):
            serverless = len(names) >= 2 and names[0] == "event"
            return ("config", frozenset({"event"}) if serverless else all_but(class_name is not None), frozenset())
        if class_name is None and len(names) == 2 and names[1] == "start_response":
            # Ham WSGI uygulaması (wsgiref / gunicorn): environ (QUERY_STRING, wsgi.input, HTTP_*) istek verisidir.
            return ("wsgi", frozenset({names[0]}), frozenset())
        if class_name is None and len(names) == 2 and names[0] == "event" \
                and names[1] in {"context", "ctx", "_context", "_ctx", "lambda_context"} and _PY_SERVERLESS_NAME_RE.search(short):
            return ("serverless", frozenset({"event"}), frozenset())
        for decorator, canonical in decorators:
            func = decorator.func if isinstance(decorator, ast.Call) else decorator
            if class_name is None and canonical in {"celery.shared_task", "celery.app.shared_task"}:
                bind = isinstance(decorator, ast.Call) and any(
                    kw.arg == "bind" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in decorator.keywords
                )
                return ("celery", all_but(bind), frozenset())
            if class_name is None and isinstance(func, ast.Attribute) and func.attr == "task" \
                    and isinstance(func.value, ast.Name):
                ctor = module.global_ctors().get(func.value.id, "")
                head, _, rest = ctor.partition(".")
                target = module.imports.get(head, "")
                canonical_ctor = f"{target}.{rest}" if target and rest else (target or ctor)
                if canonical_ctor in {"celery.Celery", "celery.app.Celery"}:
                    bind = isinstance(decorator, ast.Call) and any(
                        kw.arg == "bind" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                        for kw in decorator.keywords
                    )
                    return ("celery", all_but(bind), frozenset())
            if class_name is None and names and isinstance(func, ast.Attribute) and func.attr in _CHALICE_EVENT_DECORATORS \
                    and isinstance(func.value, ast.Name) and module.is_chalice_app(func.value.id):
                # Chalice SNS/SQS/WebSocket/Lambda işleyicisi: olay gövdesi (message, body, json_body) dış girdidir.
                return ("serverless", frozenset({names[0]}), frozenset())
            if canonical in {"functions_framework.http"} and names:
                return ("gcf", frozenset(), frozenset({names[0]}))
            if canonical in {"functions_framework.cloud_event"} and names:
                return ("gcf", frozenset({names[0]}), frozenset())
            if canonical in {"strawberry.field", "strawberry.mutation", "strawberry.subscription"} or (
                    canonical.rsplit(".", 1)[-1] in {"field", "mutation", "subscription"} and canonical.startswith("strawberry")):
                return ("graphql", all_but(class_name is not None), frozenset())
            if "ariadne" in heads and isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) \
                    and decorator.func.attr == "field" and decorator.args and isinstance(decorator.args[0], ast.Constant) \
                    and isinstance(decorator.args[0].value, str):
                return ("graphql", all_but(True), frozenset())
        if class_name is not None and heads & {"graphene", "graphene_django"} and (short.startswith("resolve_") or short == "mutate"):
            return ("graphql", all_but(True), frozenset())
        if class_name is None and "ariadne" in heads and short in self._module_set_field_names(module):
            return ("graphql", all_but(True), frozenset())
        bound = self.resolver_refs().get((module.relpath, qual))
        if bound == "ariadne":
            return ("graphql", all_but(True), frozenset())
        if bound == "strawberry":
            # strawberry: root/self/info özel (zaten kaynak dışı); kalan tüm argümanlar alan argümanlarıdır.
            return ("graphql", all_but(class_name is not None), frozenset())
        return None

    def mark_unknown_entry_sinks(self) -> None:
        """Dinamik dağıtımlı çatıyı içe aktaran modülde, projede hiç çağrılmayan fonksiyonun parametresinden
        hedefe giden akış: giriş noktası modellenmemiş olabilir → hedef "belirsiz" (ulaşılamıyor denmez)."""
        for module in self.modules.values():
            heads = {target.split(".")[0] for target in module.imports.values()}
            if not heads & _PY_DYNAMIC_ENTRY_MODULES:
                continue
            for node in module.functions.values():
                if id(node) in self.called:
                    continue
                summary = self.summaries.get(id(node))
                if summary is None:
                    continue
                for sink in summary.sinks.values():
                    if sink.index >= 0:
                        self.uncertain.setdefault(sink.file, set()).add((sink.kind, sink.line))

    def _param_type(self, module: _PyModule, annotation: ast.AST) -> tuple[bool, tuple[str, Any]] | None:
        """Tip açıklamasının türü (öğe türü mü, tür); açıklama düğümü başına bir kez çözülür."""
        key = id(annotation)
        if key in self._annotation_cache:
            return self._annotation_cache[key]
        target = _annotation_target(annotation)
        kind = self.annotated_type(module, target[1]) if target is not None else None
        result = (target[0], kind) if target is not None and kind is not None else None
        self._annotation_cache[key] = result
        return result


class _PyScope:
    def __init__(
        self,
        project: _PyProject,
        module: _PyModule,
        env: dict[str, Taint],
        *,
        summary: _PySummary | None = None,
        class_name: str | None = None,
        qual: str = "<module>",
        is_route: bool = False,
    ) -> None:
        self.p = project
        self.m = module
        self.env = env
        self.summary = summary
        self.class_name = class_name
        self.qual = qual
        self.is_route = is_route
        self.types: dict[str, tuple[_PyModule, str]] = {}
        self.ctors: dict[str, str] = {}
        # Model türü bilinen dış nesneler: değişken → sınıf tanım yolu (ör. requests.sessions.Session).
        self.ext_types: dict[str, str] = {}
        # Tip açıklamasıyla gelen istek nesnesi olduğu bilinen adlar (request.args gibi okunur).
        self.request_roots: set[str] = set()
        # Kap değişkenlerinin öğe türü (list[Repo] → for r in repos: r.find(x)).
        self.elem_types: dict[str, tuple[str, Any]] = {}
        # Değişkenin son atandığı değerin biçimi: "container" (dict/list/jsonify …) → JSON yanıtı.
        self.shapes: dict[str, str] = {}
        self.unsafe_xml_parsers: set[str] = set()
        # Sabit değer izleme (ölü dalların ayıklanması) ve sabit liste öğeleri (kabuk çağrısı tespiti).
        self.consts: dict[str, Any] = {}
        self.list_consts: dict[str, set[str]] = {}
        self.derived: dict[str, str] = {}
        # Yalnız sabit anahtarlarla yazılan sözlükler (alan duyarlı izleme).
        self.dict_fields: set[str] = set()
        # Anahtarı girdiden gelen sözlükler ({x: v}, d[x] = v): MongoDB filtresinde operatör enjeksiyonu ($where/$ne).
        self.dict_key_taint: dict[str, Taint] = {}
        # Alan duyarlı akış: metodun self adı ve yerel nesnelerin alan taint'leri.
        self.self_name: str | None = None
        # Düz dize dönüşü HTML olarak sunulan rota mı (Flask tarzı; FastAPI JSON döndürür).
        self.html_route = False
        # request.path saldırgan belirleyebilir mi: hata işleyicisi / istek kancası / değişkenli rota (aksi halde yol
        # rota kalıbının kendisidir, ör. Flask '/ara' rotasında request.path hep '/ara').
        self.path_reflects = False
        self.falcon_html_resp: str | None = None
        # Gövdesi sonradan ek (Content-Disposition: attachment) ya da HTML dışı içerik türü atanan yanıt nesnelerini
        # kuran çağrılar (id): ``r = HttpResponse(x); r["Content-Disposition"] = "attachment; …"`` → XSS değil.
        self.non_html_response_calls: set[int] = set()
        # İlk bileşeni temiz (sabit yol / temiz değişken) URL'ler: yalnız yol/sorgu kirli olabilir.
        self.prefix_clean: set[str] = set()
        # Parametreye bağlı önek: değişkenin ilk bileşeni k. parametrenin değeri (fonksiyonlar arası
        # önek özeti); SSRF için sabit şema+ana makineyle başlayan değişkenler.
        self.prefix_params: dict[str, int] = {}
        self.host_fixed: set[str] = set()
        # Ortam değişkeni önekli adlar (base = os.environ["API"]): SSRF/yönlendirmede belirsiz.
        self.env_prefixed: set[str] = set()
        # Proje içi çağrıların argüman düğümleri (parametre indeksi → düğüm) ve hedef fonksiyonu.
        self.call_args: dict[int, tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[int, ast.AST], _PyModule]] = {}
        self.obj_fields: dict[str, dict[str, Taint]] = {}
        self.obj_aliases: set[str] = set()
        # Local names that still denote one of this function's argument
        # objects. The set is bounded by the function's parameter count and
        # preserves field identity through a local alias return.
        self.object_param_aliases: dict[str, frozenset[int]] = {
            name: frozenset({index}) for index, name in enumerate(summary.params)
        } if summary is not None else {}
        # Çağrı etkisi: (özet, bağlı argümanlar, etiket, alıcı alanları [kurucuda None], self çağrısı mı)
        self.call_effects: dict[int, tuple[_PySummary, dict[int, Taint], str, dict[str, Taint] | None, bool]] = {}
        # Yalnız append/pop/insert ile değiştirilen listelerin öğe bazlı taint'i.
        self.list_items: dict[str, list[Taint]] = {}
        self.local_funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        # Global değişkenler: `global` bildirimleri ve fonksiyonun yerel adları (None: modül kapsamı).
        self.global_decls: set[str] = set()
        self.local_names: set[str] | None = None
        self.local_rebindings: set[str] = set()
        # Çağrılabilir değerler: değişkene atanmış lambda ve functools.partial.
        self.lambdas: dict[str, ast.Lambda] = {}
        self._invoke_depth = 0
        self.partials: dict[str, tuple[ast.AST, list[Taint], dict[str, Taint]]] = {}
        self.control_depth = 0

    # -- ifadeler ---------------------------------------------------------
    def expr(self, node: ast.AST | None) -> Taint:
        if node is None:
            return _EMPTY
        method = getattr(self, f"_e_{type(node).__name__}", None)
        if method is not None:
            return method(node)
        parts = [self.expr(child) for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)]
        return _union(*parts)

    def _source(self, label: str, source: str, line: int) -> Taint:
        return (_Origin(label, source, line, (), frozenset(), self.m.relpath),)

    def _lost(self, taint: Taint, line: int) -> Taint:
        """Modellenmemiş çağrı: girdi taşıyorsa sonucu belirsiz işaretle (akış değil)."""
        if any(origin.label in {"request", _PARAM, _UNCERTAIN} for origin in taint):
            return (_Origin(_UNCERTAIN, "?", line, (), frozenset(), self.m.relpath),)
        return _EMPTY

    def _pii_name(self, name: str, line: int) -> Taint:
        if self.p.pii and self.p.pii(name):
            return self._source("pii", name, line)
        return _EMPTY

    def apply_type(self, name: str, element: bool, info: tuple[str, Any]) -> None:
        """Adın türünü kaydet (tip açıklaması / öğe türü): proje sınıfı, dış model sınıfı veya istek nesnesi."""
        if element:
            self.elem_types[name] = info
            return
        kind, value = info
        if kind == "class":
            self.types[name] = value
        elif kind == "ext":
            self.ext_types[name] = value
        elif kind == "request":
            self.request_roots.add(name)

    def _element_type(self, iterable: ast.AST) -> tuple[str, Any] | None:
        """Yinelenen kabın öğe türü: açıklamalı değişken ya da dönüşü ``list[X]`` açıklamalı proje çağrısı."""
        if isinstance(iterable, ast.Name):
            return self.elem_types.get(iterable.id)
        if isinstance(iterable, ast.Attribute) and isinstance(iterable.value, ast.Name):
            # self.items: list[Repo] → for r in self.items: r.metot()
            base = iterable.value.id
            cls = (self.m, self.class_name) if base == self.self_name and self.class_name else self.types.get(base)
            if cls is not None:
                return self.p.class_field_element_types(*cls).get(iterable.attr)
        if isinstance(iterable, ast.Call) and id(iterable) in self.call_args:
            fnode, _args, owner = self.call_args[id(iterable)]
            info = self.p._param_type(owner, fnode.returns) if fnode.returns is not None else None
            if info is not None and info[0]:
                return info[1]
        return None

    def _is_request_root(self, base: str) -> bool:
        if base in _PY_REQUEST_ROOTS:
            if base in self.env and base not in self.request_roots \
                    and not any(origin.label in {"request", _PARAM, _UNCERTAIN} for origin in self.env[base]):
                return False
            return True
        if bool(self.request_roots) and base in self.request_roots:
            return True
        if not base:
            return False
        head, _, rest = base.partition(".")
        if head in self.env and base not in self.request_roots \
                and not any(origin.label in {"request", _PARAM, _UNCERTAIN} for origin in self.env[head]):
            return False
        target = self.m.imports.get(head)
        if target and (f"{target}.{rest}" if rest else target) in _PY_REQUEST_IMPORT_ROOTS:
            return True
        # http.server / socketserver işleyicisi: self.rfile (gövde) ve self.request (soket) istek verisidir.
        return base in {f"{self.self_name}.rfile", f"{self.self_name}.request", f"{self.self_name}.connection"} \
            and self._in_stdlib_handler()

    def _is_chalice_app(self, name: str) -> bool:
        return name not in self.env and self.m.is_chalice_app(name)

    def _in_stdlib_handler(self) -> bool:
        return bool(self.class_name) and self.p.is_stdlib_handler(self.m, self.class_name)

    def _field_type(self, owner: ast.AST) -> tuple[str, Any] | None:
        """``self.alan`` / ``nesne.alan`` ifadesinin tür açıklaması (sınıf alanı açıklamalarından)."""
        if not (isinstance(owner, ast.Attribute) and isinstance(owner.value, ast.Name)):
            return None
        base = owner.value.id
        if base == self.self_name and self.class_name:
            cls: tuple[_PyModule, str] | None = (self.m, self.class_name)
        else:
            cls = self.types.get(base)
        if cls is None:
            return None
        return self.p.class_field_types(*cls).get(owner.attr)

    def _e_Name(self, node: ast.Name) -> Taint:
        value = self.env.get(node.id)
        if value is None and self.local_names is not None and node.id not in self.local_names:
            ref = self.p.global_ref(self.m, node.id)
            if ref is not None:
                value = self.p.read_global(*ref)
        if self.p.pii is None:
            return value or _EMPTY
        return _union(value or _EMPTY, self._pii_name(node.id, node.lineno))

    def _global_target(self, name: str) -> tuple[str, str] | None:
        """Bu kapsamda yazılan ad bir modül global'i mi?"""
        if self.local_names is None:
            return None  # modül kapsamı: modül sonunda toplanır
        if name in self.global_decls or name not in self.local_names:
            return self.p.global_ref(self.m, name)
        return None

    def _write_global(self, name: str, taint: Taint) -> None:
        ref = self._global_target(name)
        if ref is None or not taint:
            return
        self.p.add_global(*ref, taint)
        if self.summary is not None and ref[0] == self.m.relpath:
            self.summary.add_global_write(name, tuple(o for o in taint if o.label in {_PARAM, _FIELD}))

    def _e_Attribute(self, node: ast.Attribute) -> Taint:
        dotted = _dotted(node)
        if isinstance(node.value, ast.Name) and node.value.id in self.obj_aliases:
            # Per-object field maps are shared by aliases.  Prefer that current
            # state over an older dotted-name snapshot such as ``a.value``
            # after the same object was updated through alias ``b``.
            fields = self.obj_fields.get(node.value.id)
            if fields is not None and node.attr in fields:
                return fields[node.attr]
        if dotted in self.env:
            return self.env[dotted]
        if dotted and self.p.models.source_attributes:
            # İşletmeci modelinde tanımlı öznitelik kaynağı (ör. sirket.istek.govde).
            label = self.p.models.attribute_source_for(dotted) or self.p.models.attribute_source_for(self._canonical(dotted))
            if label:
                self.expr(node.value)
                return self._source(label, dotted, node.lineno)
        base = _dotted(node.value)
        if node.attr == "current_request" and isinstance(node.value, ast.Name) and self._is_chalice_app(node.value.id):
            # Chalice: app.current_request (json_body, raw_body, query_params, uri_params, headers …) istek verisidir.
            return self._source("request", dotted, node.lineno)
        if isinstance(node.value, ast.Attribute) and node.value.attr == "current_request" \
                and isinstance(node.value.value, ast.Name) and self._is_chalice_app(node.value.value.id):
            return self._source("request", dotted, node.lineno)
        if node.attr in _PY_REQUEST_URL_ATTRS and base in ("request", "flask.request") and self._is_request_root(base) \
                and (node.attr != "path" or self.path_reflects):
            # full_path/url sorgu dizesini içerir (her zaman saldırgan belirler); path yalnız değişkenli rota ve hata
            # işleyicilerinde/kancalarda serbesttir.
            return _clean(self._source("request", dotted, node.lineno), _PY_REQUEST_URL_SAFE)
        if node.attr in _PY_REQUEST_ATTRS and self._is_request_root(base):
            return self._source("request", dotted, node.lineno)
        if node.attr in _PY_TYPED_REQUEST_ATTRS and base in self.request_roots:
            return self._source("request", dotted, node.lineno)
        if node.attr in _PY_STDLIB_HANDLER_ATTRS and isinstance(node.value, ast.Name) \
                and node.value.id == self.self_name and self._in_stdlib_handler():
            return self._source("request", dotted, node.lineno)
        if isinstance(node.value, ast.Name) and dotted not in _PY_REQUEST_ROOTS:
            owner = node.value.id
            if owner == self.self_name and self.summary is not None:
                # Metot içinde self.<alan>: çağıranın nesne durumuna göre çözülecek sembolik kaynak.
                return (_Origin(_FIELD, node.attr, node.lineno, (), frozenset(), self.m.relpath),)
            if self.summary is not None and owner in self.summary.params:
                # ``def take(box): return box.value``: the object itself is not
                # tainted, but its selected field can be.  Preserve the field
                # in the summary so a caller does not merge sibling fields.
                # Keep the ordinary parameter and PII origins as well: typed
                # request/event parameters intentionally taint the whole
                # object, while the field marker is only an extra symbolic
                # refinement for call sites that track object fields.
                index = self.summary.params.index(owner)
                return _union(
                    self.expr(node.value),
                    (_Origin(_PARAM_FIELD, f"{index}:{node.attr}", node.lineno, (), frozenset(), self.m.relpath),),
                    self._pii_name(node.attr, node.lineno),
                )
            fields = self.obj_fields.get(owner)
            if fields is not None and node.attr in fields:
                return fields[node.attr]
            if owner not in self.env:
                ref = self.p.module_global_attr(self.m, owner, node.attr)
                if ref is not None:
                    return self.p.read_global(*ref)
        value = self.expr(node.value)
        if isinstance(node.value, ast.Call):
            returned_fields = self._returned_object_fields(node.value)
            if returned_fields:
                value = _union(value, *(fields.get(node.attr, _EMPTY) for fields in returned_fields))
        if any(o.label == "stored" and o.source.endswith("()") for o in value):
            # 25. tur: kayıt düzeyindeki veritabanı okumasının (db.get(Report, id)) sütunu kaynağa eklenir; yazma
            # kanıtı sütun adıyla eşlenir (bkz. _mark_user_written_stored_flows).
            value = tuple(dataclasses.replace(o, source=f"{o.source}.{node.attr}")
                          if o.label == "stored" and o.source.endswith("()") else o for o in value)
        return _union(value, self._pii_name(node.attr, node.lineno))

    def _e_Subscript(self, node: ast.Subscript) -> Taint:
        if isinstance(node.value, ast.Call):
            whole = self.expr(node.value)
            part = self._call_part(node.value, self._const(node.slice))
            return whole if part is None else part
        container = _dotted(node.value)
        key_value = self._const(node.slice)
        if container in self.list_items and isinstance(key_value, int):
            items = self.list_items[container]
            self.expr(node.value)
            return items[key_value] if -len(items) <= key_value < len(items) else _EMPTY
        if container in self.dict_fields and isinstance(key_value, str):
            # Sabit anahtarlı sözlük: yalnız o anahtara yazılan değerin taint'i.
            self.expr(node.value)
            return self.env.get(f"{container}[{key_value!r}]", _EMPTY)
        taint = self.expr(node.value)
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            taint = _union(taint, self._pii_name(key.value, node.lineno))
        return taint

    def _e_Constant(self, node: ast.Constant) -> Taint:
        return _EMPTY

    def _e_Compare(self, node: ast.Compare) -> Taint:
        self.expr(node.left)
        for item in node.comparators:
            self.expr(item)
        return _EMPTY

    def _e_UnaryOp(self, node: ast.UnaryOp) -> Taint:
        taint = self.expr(node.operand)
        return _EMPTY if isinstance(node.op, ast.Not) else taint

    def _e_JoinedStr(self, node: ast.JoinedStr) -> Taint:
        return _union(*(self.expr(value) for value in node.values))

    def _e_FormattedValue(self, node: ast.FormattedValue) -> Taint:
        taint = self.expr(node.value)
        if node.conversion == ord("r") or node.conversion == ord("a"):
            taint = _clean(taint, frozenset({"log"}))
        return taint

    def _e_Lambda(self, node: ast.Lambda) -> Taint:
        return _EMPTY

    def _e_Yield(self, node: ast.Yield) -> Taint:
        # Üreteç: verilen değer çağıranın yineleme değişkenine akar (dönüş gibi).
        taint = self.expr(node.value)
        if self.summary is not None:
            self.summary.add_return(taint)
            for kind in _PREFIX_SUMMARY_KINDS:
                self.summary.add_return_prefix(kind, None)
        return _EMPTY

    _e_YieldFrom = _e_Yield

    def _call_part(self, call: ast.Call, key: Any) -> Taint | None:
        """f()[i] / f()["k"]: özetteki demet/sözlük öğesi (bilinmiyorsa None)."""
        effect = self.call_effects.get(id(call))
        if effect is None or key is _CONST_UNKNOWN:
            return None
        summary = effect[0]
        if isinstance(key, int) and isinstance(summary.ret_tuple, list) and -len(summary.ret_tuple) <= key < len(summary.ret_tuple):
            return self._map_call_part(summary.ret_tuple[key], effect)
        if isinstance(key, str) and isinstance(summary.ret_dict, dict):
            return self._map_call_part(summary.ret_dict.get(key, _EMPTY), effect)
        return None

    def _map_call_part(self, part: Taint, effect: tuple) -> Taint:
        _summary, bound, label, fields, self_call = effect
        return self._map_effect(part, bound, None if self_call else (fields or {}), label)

    def _invoke_lambda(self, lam: ast.Lambda, taints: list[Taint],
                       kw_taints: dict[str, Taint] | None = None) -> Taint:
        saved = self.env
        self.env = dict(saved)
        positional = [*lam.args.posonlyargs, *lam.args.args]
        params = [*positional, *lam.args.kwonlyargs]
        for param, taint in zip(positional, taints):
            self.env[param.arg] = _via(taint, param.arg) if taint else _EMPTY
        by_name = {param.arg: param for param in params}
        for name, taint in (kw_taints or {}).items():
            if name in by_name:
                self.env[name] = _via(taint, name) if taint else _EMPTY
        try:
            return self.expr(lam.body)
        finally:
            self.env = saved

    def _invoke(self, func: ast.AST, taints: list[Taint],
                kw_taints: dict[str, Taint] | None = None) -> Taint:
        """Geri çağırma (callback) olarak verilen fonksiyonu argüman taint'leriyle çağır."""
        if self._invoke_depth >= 4:
            return _union(*taints, *(kw_taints or {}).values())
        self._invoke_depth += 1
        try:
            return self._invoke_inner(func, taints, kw_taints or {})
        finally:
            self._invoke_depth -= 1

    def _invoke_inner(self, func: ast.AST, taints: list[Taint], kw_taints: dict[str, Taint]) -> Taint:
        if isinstance(func, ast.Lambda):
            return self._invoke_lambda(func, taints, kw_taints)
        if isinstance(func, ast.Name) and func.id in self.lambdas:
            return self._invoke_lambda(self.lambdas[func.id], taints, kw_taints)
        if isinstance(func, ast.Name) and func.id in self.partials:
            target, prefix, bound_keywords = self.partials[func.id]
            return self._invoke(target, [*prefix, *taints], {**bound_keywords, **kw_taints})
        partial = self._partial_call(func)
        if partial is not None:
            target, bound_args, bound_keywords = partial
            return self._invoke(
                target,
                [*(self.expr(arg) for arg in bound_args), *taints],
                {
                    **{keyword.arg: self.expr(keyword.value) for keyword in bound_keywords
                       if keyword.arg is not None},
                    **kw_taints,
                },
            )
        keys = [f"\x00cb{index}_{id(func)}" for index in range(len(taints))]
        keyword_keys = {name: f"\x00cbkw_{name}_{id(func)}" for name in kw_taints}
        for key, taint in [*zip(keys, taints), *((keyword_keys[name], taint) for name, taint in kw_taints.items())]:
            self.env[key] = taint
        call = ast.Call(
            func=func,
            args=[ast.Name(id=key, ctx=ast.Load()) for key in keys],
            keywords=[
                ast.keyword(arg=name, value=ast.Name(id=key, ctx=ast.Load()))
                for name, key in keyword_keys.items()
            ],
        )
        ast.copy_location(call, func)
        for arg in [*call.args, *(keyword.value for keyword in call.keywords)]:
            ast.copy_location(arg, func)
        try:
            return self.expr(call)
        finally:
            for key in [*keys, *keyword_keys.values()]:
                self.env.pop(key, None)

    def _e_IfExp(self, node: ast.IfExp) -> Taint:
        self.expr(node.test)
        decided = self._const(node.test)
        if decided is not _CONST_UNKNOWN:
            return self.expr(node.body if decided else node.orelse)
        when_true, when_false = self._guard(node.test)
        results = []
        for branch, guard in ((node.body, when_true), (node.orelse, when_false)):
            saved = dict(self.env)
            self._apply_guard(guard)
            results.append(self.expr(branch))
            self.env = saved
        return _union(*results)

    def _comprehension(self, node: Any, elements: list[ast.AST]) -> Taint:
        saved = dict(self.env)
        for generator in node.generators:
            self.assign(generator.target, self.expr(generator.iter))
            for condition in generator.ifs:
                self.expr(condition)
        taint = _union(*(self.expr(element) for element in elements))
        self.env = saved
        return taint

    def _e_ListComp(self, node: ast.ListComp) -> Taint:
        return self._comprehension(node, [node.elt])

    _e_SetComp = _e_ListComp
    _e_GeneratorExp = _e_ListComp

    def _e_DictComp(self, node: ast.DictComp) -> Taint:
        return self._comprehension(node, [node.key, node.value])

    def _e_NamedExpr(self, node: ast.NamedExpr) -> Taint:
        taint = self.expr(node.value)
        self.assign(node.target, taint)
        return taint

    def _e_Call(self, node: ast.Call) -> Taint:
        name = _dotted(node.func)
        if isinstance(node.func, ast.Name):
            if node.func.id in self.lambdas:
                return self._invoke_lambda(self.lambdas[node.func.id], [self.expr(arg) for arg in node.args])
            if node.func.id in self.partials:
                func, prefix, bound_keywords = self.partials[node.func.id]
                call_keywords = {
                    keyword.arg: self.expr(keyword.value)
                    for keyword in node.keywords if keyword.arg is not None
                }
                unpacked = [self.expr(keyword.value) for keyword in node.keywords if keyword.arg is None]
                result = self._invoke(
                    func,
                    [*prefix, *(self.expr(arg) for arg in node.args)],
                    {**bound_keywords, **call_keywords},
                )
                return _union(result, self._lost(_union(*unpacked), node.lineno))
        if name and self.p.models.source_calls:
            # İşletmeci modelinde tanımlı çağrı kaynağı: dönüş değeri kaynak (argümanlar yine değerlendirilir).
            label = self.p.models.source_for(name) or self.p.models.source_for(self._canonical(name))
            if label:
                for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                    self.expr(arg)
                return self._source(label, f"{name}()", node.lineno)
        callback = self._callback_call(node, name)
        if callback is not None:
            return callback
        arg_taints = [self.expr(arg) for arg in node.args]
        kw_taints = {kw.arg: self.expr(kw.value) for kw in node.keywords}
        receiver: Taint = _EMPTY
        if isinstance(node.func, ast.Attribute):
            receiver = self.expr(node.func.value)
        target = self._resolve_call(node)
        if target is None:
            # Proje içinde tanımlı bir fonksiyona çözülen çağrı ada göre hedef sayılmaz
            # (ör. kendi ``self.execute`` metodu); davranışı özetinden gelir.
            self._check_sink(node, name, arg_taints, kw_taints, receiver)
            self._check_special_sinks(node, name, arg_taints, kw_taints, receiver)
        self._track_xml_parser(node)
        all_args = _union(*arg_taints, *kw_taints.values())
        if isinstance(node.func, ast.Attribute):
            last = node.func.attr
        else:
            last = name.rsplit(".", 1)[-1] if name else ""
        base = name.rsplit(".", 1)[0] if "." in name else ""
        models = self.p.models

        if node.keywords and (isinstance(node.func, ast.Name) and node.func.id[:1].isupper()
                              or isinstance(node.func, ast.Attribute) and (node.func.attr[:1].isupper() or node.func.attr in
                                                                           _PY_ORM_WRITE_CALLS)):
            for kw in node.keywords:
                if kw.arg and any(o.label == "request" for o in kw_taints.get(kw.arg, _EMPTY)):
                    self.p.user_written_attrs.add(kw.arg)  # Model(alan=istek) / objects.create(alan=istek)
                    self.p.user_written_sites.setdefault(kw.arg, (self.m.relpath, node.lineno))
        if (node.args or node.keywords) and last[:1].isupper():
            form_fields = self.p.model_form_fields().get(last)
            data = arg_taints[0] if node.args else kw_taints.get("data", _EMPTY)
            if form_fields and any(o.label == "request" for o in data):
                self.p.user_written_attrs.update(form_fields)  # ModelForm(request.POST).save(): Meta.fields yazılır
                for field in form_fields:
                    self.p.user_written_sites.setdefault(field, (self.m.relpath, node.lineno))
        form_kind = self._wtforms_class(node.func) if target is None else None
        if form_kind is not None:
            if form_kind == "flask_wtf" and not node.args and "formdata" not in kw_taints:
                return self._source("request", f"{name}() (Flask-WTF form, request.form)", node.lineno)
            return _union(*arg_taints, kw_taints.get("formdata", _EMPTY))

        if target is not None:
            # Proje içinde tanımlı fonksiyon/metot: ad tabanlı kısayollar (str.find → int, ORM .get →
            # kayıtlı veri …) uygulanmaz; davranış özetten gelir. Ad, arındırıcı adıysa ek temizlik.
            # Sanal çağrı: alt sınıfların geçersiz kıldığı metotlar da birleştirilir (önce onlar, en son
            # statik hedef: çağrı etkisi statik hedefinki kalır).
            extra = [self._apply_summary(node, other, arg_taints, kw_taints) for other in self._override_targets(node, target)]
            result = _union(self._apply_summary(node, target, arg_taints, kw_taints), *extra)
            named = _named_sanitizer_kinds(name) if name else None
            return _clean(result, named) if named is not None else result
        if name in _PY_FULL_SANITIZERS or last in {"isdigit", "isnumeric", "isalnum", "startswith", "endswith", "count", "index", "find"}:
            return _EMPTY
        if last in _PY_DECODING_CALLS and (base in {"", "urllib.parse", "parse", "urllib", "html"} or name in _PY_DECODING_CALLS):
            # URL/HTML çözme: önceki denetim/arındırma (ör. '../' içermiyor) çözülmüş değerde geçersizdir.
            return _uncleaned(all_args)
        if last in _PY_REQUEST_METHODS and self._is_request_root(base):
            return self._source("request", name + "()", node.lineno)
        if last in _TORNADO_ARG_METHODS and base and base == self.self_name and self.class_name \
                and self.p.is_tornado_handler(self.m, self.class_name):
            return self._source("request", name + "()", node.lineno)
        if last in _PY_TYPED_REQUEST_METHODS and base in self.request_roots:
            return self._source("request", name + "()", node.lineno)
        if self._is_weak_random(name, last):
            # Kriptografik olmayan rastgele değer: oturum/çereze yazılırsa bulgu (bkz. project_analyzer).
            return _union(self._source("weakrand", name + "()", node.lineno), all_args)
        if isinstance(node.func, ast.Attribute) and last in {
            "get", "get_many", "mget", "hget", "hgetall", "lpop", "rpop", "blpop", "brpop", "xread",
            "dequeue", "receive", "receive_message",
        }:
            owner_ctor = ""
            raw_ctor = ""
            if isinstance(node.func.value, ast.Name):
                raw_ctor = self.ctors.get(node.func.value.id, "") or self.m.global_ctors().get(node.func.value.id, "")
                owner_ctor = self._canonical(raw_ctor)
            canonical_base = self._canonical(base)
            secondary_roots = ("redis.", "pymemcache.", "memcache.", "django.core.cache", "kombu.", "celery.")
            raw_root = (raw_ctor or base).split(".", 1)[0]
            import_target = self.m.imports.get(raw_root, raw_root).split(".", 1)[0]
            project_shadow = self.p.module_named(import_target) is not None
            if not project_shadow and (owner_ctor.startswith(secondary_roots) or canonical_base.startswith(secondary_roots)):
                # Cache/queue reads cross a persistence boundary just like a
                # database read.  Their keys are not data propagation; the
                # returned payload is a second-order source.
                return self._source("stored", name + "()", node.lineno)
        if isinstance(node.func, ast.Attribute) and _is_db_read(name, last):
            return _union(self._source("stored", name + "()", node.lineno), receiver)
        if isinstance(node.func, ast.Attribute) and last == "get" and re.fullmatch(r"(?:\w+\.)*(?:db|session)", base) \
                and node.args and isinstance(node.args[0], ast.Name) and node.args[0].id[:1].isupper():
            # 25. tur: SQLAlchemy 1.4+/2.0 birincil anahtarla okuma: db.get(Model, pk) / session.get(Model, pk)
            return self._source("stored", name + "()", node.lineno)
        if last != "Request" and self._is_http_client_call(node, name):
            # Giden HTTP isteğinin yanıtı: üçüncü taraf/uzak sunucu verisi (ikinci derece kaynak, "remote").
            # İstek girdisi URL'yi belirliyorsa yanıt eskisi gibi belirsiz de sayılır (akış değil).
            return _union(self._source("remote", name + "()", node.lineno), self._lost(_union(all_args, receiver), node.lineno))
        if base in {"re", "regex"} and last in _PY_REGEX_FUNCS:
            # Desen hedef olarak yukarıda değerlendirildi; sonuç işlenen dizeyi taşır.
            return _union(*arg_taints[1:], *(t for k, t in kw_taints.items() if k in {"string", "repl"}))
        if isinstance(node.func, ast.Attribute) and last in _PY_REGEX_FUNCS and not receiver and not self._is_request_root(base):
            # Derlenmiş desen: DESEN.sub(repl, s) / DESEN.match(s)
            return all_args
        model_names = self._model_names(node, name)
        model_kinds = next((k for k in map(models.sanitizer_kinds, model_names) if k is not None), None)
        if model_kinds is not None:
            if "bleach.clean" in model_names and self.p.sanitizer_version(self.m, "bleach") is False:
                return _union(receiver, all_args)
            return _clean(_union(receiver, all_args), model_kinds)
        if last == "urlencode":
            # urlencode / QueryDict.urlencode(): değerler yüzde kodlanır (HTML/günlük için güvenli).
            return _clean(_union(receiver, all_args), frozenset({"html", "log"}))
        if isinstance(node.func, ast.Attribute) and last == "replace" and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str) and any(c in first.value for c in "\r\n"):
                return _clean(receiver, frozenset({"log"}))
            second = node.args[1] if len(node.args) > 1 else None
            if isinstance(first, ast.Constant) and first.value in {"'", '"'} and isinstance(second, ast.Constant) \
                    and isinstance(second.value, str) and first.value not in second.value:
                # Tırnak karakterini kaldıran değiştirme: değer tırnaklı XPath değişmezinden taşamaz.
                return _clean(_union(receiver, *arg_taints[1:]), frozenset({"xpath"}))
        config_owner = isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) \
            and self.ctors.get(node.func.value.id, "").rsplit(".", 1)[-1] in {"ConfigParser", "RawConfigParser", "SafeConfigParser"}
        if config_owner and last in {"set", "read_string", "read_dict"}:
            owner = node.func.value.id
            if all_args:
                self.env[owner] = _union(self.env.get(owner, _EMPTY), _via(all_args, owner))
            return _EMPTY
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id in self.list_items:
            items = self.list_items[node.func.value.id]
            index = self._const(node.args[0]) if node.args else -1
            if last == "append" and len(node.args) == 1:
                items.append(arg_taints[0])
            elif last == "pop" and isinstance(index, int) and -len(items) <= index < len(items):
                return items.pop(index)
            elif last == "insert" and len(node.args) == 2 and isinstance(index, int):
                items.insert(index, arg_taints[1])
            else:
                del self.list_items[node.func.value.id]
        if isinstance(node.func, ast.Attribute) and last in _PY_MUTATORS and target is None:
            owner = _dotted(node.func.value)
            self.dict_fields.discard(owner)
            if owner and "()" not in owner:
                if all_args:
                    self.env[owner] = _union(self.env.get(owner, _EMPTY), _via(all_args, owner))
                    if "." not in owner:
                        self._write_global(owner, all_args)
                for arg in node.args:
                    for item in (arg.elts if isinstance(arg, (ast.List, ast.Tuple)) else [arg]):
                        if isinstance(item, ast.Constant) and isinstance(item.value, str):
                            self.list_consts.setdefault(owner, set()).add(item.value)
                return _EMPTY
        kinds = _named_sanitizer_kinds(name) if name else None
        if name in _PY_PROPAGATING_CALLS:
            return all_args
        if kinds is None and any(models.propagates(alias) for alias in model_names):
            return _union(all_args, receiver)
        if target is not None:
            result = self._apply_summary(node, target, arg_taints, kw_taints)
            return _clean(result, kinds) if kinds is not None else result
        if kinds is not None:
            return _clean(_union(receiver, all_args), kinds)
        dispatched = self._dispatch_by_name(node, arg_taints, kw_taints)
        if dispatched is not None:
            return dispatched
        if isinstance(node.func, ast.Attribute) and (last in _PY_STRING_METHODS or receiver):
            return _union(receiver, all_args) if last in _PY_STRING_METHODS else receiver
        return self._lost(all_args, node.lineno)

    def _wtforms_class(self, func: ast.AST) -> str | None:
        """Çağrılan proje sınıfı WTForms formu mu? "flask_wtf" (istek verisini kendisi bağlar) / "wtforms" / None."""
        found = self._resolve_class(func)
        if found is None:
            return None
        module, cls = found
        if self.p.is_stdlib_handler(module, cls, bases=_FLASK_WTF_BASES):
            return "flask_wtf"
        if self.p.is_stdlib_handler(module, cls, bases=_WTFORMS_BASES):
            return "wtforms"
        return None

    def _callback_call(self, node: ast.Call, name: str) -> Taint | None:
        """map/filter/sorted(key=)/min/max(key=): geri çağırmayı öğe taint'iyle çalıştır.

        Ayrıca iş parçacığı/süreç başlatma: ``threading.Thread(target=f, args=(a,))``, ``Process(...)``,
        ``Timer(s, f, args=…)``, ``yürütücü.submit(f, a)`` ve ``yürütücü.map(f, xs)`` — hedef fonksiyon
        argümanlarla çağrılmış sayılır."""
        canonical = self._canonical(name) if name else ""
        root = name.partition(".")[0] if name else ""
        root_shadowed = bool(root and root in self.local_rebindings)

        if canonical in _PY_SINGLE_BACKGROUND_TASK_TYPES and not root_shadowed:
            callback = node.args[0] if node.args else next(
                (keyword.value for keyword in node.keywords if keyword.arg == "func"), None
            )
            callback_args = node.args[1:] if node.args else []
            callback_keywords = [keyword for keyword in node.keywords if keyword.arg != "func"]
            if callback is not None and self._is_local_callable(callback) \
                    and not any(isinstance(arg, ast.Starred) for arg in callback_args) \
                    and all(keyword.arg is not None for keyword in callback_keywords):
                self._invoke(
                    callback,
                    [self.expr(arg) for arg in callback_args],
                    {keyword.arg: self.expr(keyword.value) for keyword in callback_keywords if keyword.arg is not None},
                )
                return _EMPTY

        if canonical == "asyncio.to_thread" and not root_shadowed and node.args \
                and self._is_local_callable(node.args[0]) \
                and not any(isinstance(arg, ast.Starred) for arg in node.args[1:]) \
                and all(keyword.arg is not None for keyword in node.keywords):
            return self._invoke(
                node.args[0],
                [self.expr(arg) for arg in node.args[1:]],
                {keyword.arg: self.expr(keyword.value) for keyword in node.keywords if keyword.arg is not None},
            )

        if isinstance(node.func, ast.Attribute) and node.func.attr in _PY_ASYNCIO_LOOP_CALLBACKS:
            owner = node.func.value
            owner_factory = ""
            if isinstance(owner, ast.Name):
                owner_factory = self._canonical(self.ctors.get(owner.id, ""))
            elif isinstance(owner, ast.Call):
                owner_factory = self._canonical(_dotted(owner.func))
            callback_index = _PY_ASYNCIO_LOOP_CALLBACKS[node.func.attr]
            if owner_factory in _PY_ASYNCIO_LOOP_FACTORIES and callback_index < len(node.args):
                callback = node.args[callback_index]
                callback_args = node.args[callback_index + 1:]
                if self._is_local_callable(callback) and not any(
                        isinstance(arg, ast.Starred) for arg in callback_args):
                    self.expr(owner)
                    for arg in node.args[:callback_index]:
                        self.expr(arg)
                    for keyword in node.keywords:
                        self.expr(keyword.value)
                    return self._invoke(callback, [self.expr(arg) for arg in callback_args])

        if isinstance(node.func, ast.Attribute) and node.func.attr == "add_task" \
                and isinstance(node.func.value, ast.Name) \
                and self.ext_types.get(node.func.value.id) in _PY_BACKGROUND_TASK_TYPES \
                and node.args and self._is_local_callable(node.args[0]) \
                and not any(isinstance(arg, ast.Starred) for arg in node.args[1:]) \
                and all(keyword.arg is not None for keyword in node.keywords):
            self.expr(node.func.value)
            return self._invoke(
                node.args[0],
                [self.expr(arg) for arg in node.args[1:]],
                {keyword.arg: self.expr(keyword.value) for keyword in node.keywords if keyword.arg is not None},
            )

        if canonical in _PY_THREAD_STARTERS and name not in self.env:
            timer = canonical.endswith("Timer")
            func_index, args_index, kwargs_index = ((1, 2, 3) if timer else (1, 3, 4))
            func = next((kw.value for kw in node.keywords if kw.arg in {"target", "function"}), None)
            if func is None and len(node.args) > func_index:
                func = node.args[func_index]
            argv = next((kw.value for kw in node.keywords if kw.arg == "args"), None)
            if argv is None and len(node.args) > args_index:
                argv = node.args[args_index]
            kwargv = next((kw.value for kw in node.keywords if kw.arg == "kwargs"), None)
            if kwargv is None and len(node.args) > kwargs_index:
                kwargv = node.args[kwargs_index]
            for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                self.expr(arg)
            if func is not None:
                if isinstance(argv, (ast.Tuple, ast.List)):
                    elements = list(argv.elts)
                    callback_args = [] if any(isinstance(e, ast.Starred) for e in elements) \
                        else [self.expr(e) for e in elements]
                elif argv is None:
                    callback_args = []
                else:
                    unknown_args = self.expr(argv)
                    callback_args = [unknown_args] * 8 if unknown_args else []
                callback_keywords: dict[str, Taint] = {}
                if isinstance(kwargv, ast.Dict) and all(
                        isinstance(key, ast.Constant) and isinstance(key.value, str) for key in kwargv.keys):
                    callback_keywords = {
                        str(key.value): self.expr(value)
                        for key, value in zip(kwargv.keys, kwargv.values)
                    }
                elif kwargv is not None:
                    unknown_keywords = self.expr(kwargv)
                    if unknown_keywords:
                        callback_args = [
                            _union(value, unknown_keywords) for value in (callback_args or [_EMPTY] * 8)
                        ]
                self._invoke(func, callback_args, callback_keywords)
            return _EMPTY
        executor_type = ""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            executor_type = self._canonical(self.ctors.get(node.func.value.id, ""))
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
            executor_type = self._canonical(_dotted(node.func.value.func))
        known_executor = executor_type in _PY_EXECUTOR_TYPES
        known_process_pool = executor_type in _PY_MULTIPROCESS_POOL_TYPES
        pool_method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        pool_map_options = {
            "map": {"chunksize"},
            "map_async": {"chunksize", "callback", "error_callback"},
            "imap": {"chunksize"},
            "imap_unordered": {"chunksize"},
            "starmap": {"chunksize"},
            "starmap_async": {"chunksize", "callback", "error_callback"},
        }
        if known_process_pool and pool_method in pool_map_options and len(node.args) >= 2 \
                and name not in self.env and self._is_local_callable(node.args[0]) \
                and not any(isinstance(arg, ast.Starred) for arg in node.args) \
                and all(keyword.arg in pool_map_options[pool_method] for keyword in node.keywords):
            self.expr(node.func.value)
            for keyword in node.keywords:
                self.expr(keyword.value)
            iterable = node.args[1]
            if pool_method.startswith("starmap"):
                rows = list(iterable.elts) if isinstance(iterable, (ast.List, ast.Tuple, ast.Set)) else []
                static_rows = bool(rows) and all(
                    isinstance(row, (ast.List, ast.Tuple))
                    and not any(isinstance(item, ast.Starred) for item in row.elts)
                    for row in rows
                )
                if static_rows:
                    width = max((len(row.elts) for row in rows), default=0)
                    callback_args = [
                        _union(*(self.expr(row.elts[index]) for row in rows if index < len(row.elts)))
                        for index in range(width)
                    ]
                else:
                    # Unknown tuple shape: any iterable element may occupy any
                    # bounded positional parameter in the worker.
                    element_taint = self.expr(iterable)
                    callback_args = [element_taint] * 8
            else:
                callback_args = [self.expr(iterable)]
            result = self._invoke(node.args[0], callback_args)
            return result if pool_method in {"map", "imap", "imap_unordered", "starmap"} else _EMPTY
        if known_process_pool and pool_method in {"apply", "apply_async"} and name not in self.env:
            callback = node.args[0] if node.args else next(
                (keyword.value for keyword in node.keywords if keyword.arg == "func"), None
            )
            allowed = {"func", "args", "kwds"} | ({"callback", "error_callback"} if pool_method == "apply_async" else set())
            if callback is not None and self._is_local_callable(callback) \
                    and not any(isinstance(arg, ast.Starred) for arg in node.args) \
                    and all(keyword.arg in allowed for keyword in node.keywords):
                args_node = node.args[1] if len(node.args) >= 2 else next(
                    (keyword.value for keyword in node.keywords if keyword.arg == "args"), None
                )
                kwds_node = node.args[2] if len(node.args) >= 3 else next(
                    (keyword.value for keyword in node.keywords if keyword.arg == "kwds"), None
                )
                if isinstance(args_node, (ast.List, ast.Tuple)) \
                        and not any(isinstance(item, ast.Starred) for item in args_node.elts):
                    callback_args = [self.expr(item) for item in args_node.elts]
                elif args_node is None:
                    callback_args = []
                else:
                    unknown_args = self.expr(args_node)
                    callback_args = [unknown_args] * 8
                callback_keywords: dict[str, Taint] = {}
                if isinstance(kwds_node, ast.Dict) and all(
                        isinstance(key, ast.Constant) and isinstance(key.value, str) for key in kwds_node.keys
                ):
                    callback_keywords = {
                        str(key.value): self.expr(value)
                        for key, value in zip(kwds_node.keys, kwds_node.values)
                    }
                elif kwds_node is not None:
                    unknown_keywords = self.expr(kwds_node)
                    if unknown_keywords:
                        callback_args = [_union(value, unknown_keywords) for value in (callback_args or [_EMPTY] * 8)]
                self.expr(node.func.value)
                for argument in node.args[3:]:
                    self.expr(argument)
                for keyword in node.keywords:
                    if keyword.arg not in {"func", "args", "kwds"}:
                        self.expr(keyword.value)
                result = self._invoke(callback, callback_args, callback_keywords)
                return result if pool_method == "apply" else _EMPTY
        if isinstance(node.func, ast.Attribute) and node.func.attr == "map" and len(node.args) >= 2 \
                and known_executor and name not in self.env \
                and not any(isinstance(arg, ast.Starred) for arg in node.args[1:]) \
                and all(keyword.arg in {"timeout", "chunksize", "buffersize"} for keyword in node.keywords) \
                and self._is_local_callable(node.args[0]):
            self.expr(node.func.value)
            for keyword in node.keywords:
                self.expr(keyword.value)
            return self._invoke(node.args[0], [self.expr(arg) for arg in node.args[1:]])
        if isinstance(node.func, ast.Attribute) and node.func.attr == "submit" and node.args and name not in self.env \
                and (not node.keywords or known_executor) \
                and all(keyword.arg is not None for keyword in node.keywords) \
                and not any(isinstance(a, ast.Starred) for a in node.args) \
                and self._is_local_callable(node.args[0]):
            self.expr(node.func.value)
            self._invoke(
                node.args[0],
                [self.expr(arg) for arg in node.args[1:]],
                {keyword.arg: self.expr(keyword.value) for keyword in node.keywords if keyword.arg is not None},
            )
            return _EMPTY
        if canonical not in {"map", "filter", "sorted", "min", "max"} or name in self.env:
            return None
        if canonical == "map" and len(node.args) >= 2:
            elements = _union(*(self.expr(arg) for arg in node.args[1:]))
            return self._invoke(node.args[0], [elements] * (len(node.args) - 1))
        if canonical == "filter" and len(node.args) == 2:
            elements = self.expr(node.args[1])
            if not (isinstance(node.args[0], ast.Constant) and node.args[0].value is None):
                self._invoke(node.args[0], [elements])
            return elements
        key = next((kw.value for kw in node.keywords if kw.arg == "key"), None)
        if key is None:
            return None
        elements = _union(*(self.expr(arg) for arg in node.args))
        self._invoke(key, [elements])
        return elements

    def _is_http_client_call(self, node: ast.Call, name: str) -> bool:
        """Çağrı, SSRF hedef modeli olan bir HTTP istemci çağrısı mı? (requests/httpx/urlopen/urllib3 …)"""
        if not name:
            return False
        return any(model.kind == "ssrf" for alias in self._model_names(node, name) for model in self.p.models.sinks_for(alias))

    def _is_local_callable(self, func: ast.AST) -> bool:
        """Proje içinde tanımlı fonksiyon/metot ya da lambda mı? (yürütücü.submit hedefi için)"""
        if isinstance(func, ast.Lambda) or (isinstance(func, ast.Name) and func.id in self.lambdas):
            return True
        if isinstance(func, ast.Name) and func.id in self.partials:
            return self._is_local_callable(self.partials[func.id][0])
        partial = self._partial_call(func)
        if partial is not None:
            return self._is_local_callable(partial[0])
        probe = ast.Call(func=func, args=[], keywords=[])
        ast.copy_location(probe, func)
        return self._resolve_call(probe) is not None

    def _partial_call(self, value: ast.AST) \
            -> tuple[ast.AST, list[ast.AST], list[ast.keyword]] | None:
        """Doğrulanmış ``functools.partial`` çağrısının hedefini ve bağlı argümanlarını döndür."""
        if not isinstance(value, ast.Call) or not value.args or \
                any(isinstance(arg, ast.Starred) for arg in value.args[1:]) or \
                any(keyword.arg is None for keyword in value.keywords):
            return None
        name = _dotted(value.func)
        root = name.partition(".")[0]
        if self._canonical(name) != "functools.partial" or (root and root in self.local_rebindings):
            return None
        return value.args[0], list(value.args[1:]), list(value.keywords)

    def _override_targets(self, node: ast.Call, target: _CallTarget) -> list[_CallTarget]:
        """Alt sınıfların geçersiz kıldığı metotlar (self / türü bilinen alıcı üzerinde)."""
        module, qual, fnode, offset, class_name = target
        if offset != 1 or class_name is None or not isinstance(node.func, ast.Attribute) or qual.endswith(".__init__"):
            return []
        owner = node.func.value
        static: tuple[_PyModule, str] | None = None
        if isinstance(owner, ast.Name) and owner.id == self.self_name and self.class_name:
            static = (self.m, self.class_name)
        elif isinstance(owner, ast.Name) and owner.id in self.types:
            static = self.types[owner.id]
        if static is None:
            return []
        method = node.func.attr
        targets: list[_CallTarget] = []
        for sub_module, sub_class in self.p.subclasses(*static):
            sub_qual = f"{sub_class}.{method}"
            sub_node = sub_module.functions.get(sub_qual)
            if sub_node is not None and sub_node is not fnode:
                targets.append((sub_module, sub_qual, sub_node, 1, sub_class))
            if len(targets) >= 5:
                break
        return targets

    def _super_method(self, method: str) -> tuple[_PyModule, str] | None:
        cnode = self.m.classes.get(self.class_name or "")
        for base in cnode.bases if cnode is not None else []:
            dotted = _dotted(base)
            resolved = self.p.resolve(self.m, dotted) if dotted else None
            if resolved is not None and resolved[0] == "class":
                found = self.p.find_method(resolved[1], resolved[2], method)
                if found is not None:
                    return found
        return None

    def _const_args(self, node: ast.Call, offset: int, fnode: ast.FunctionDef | ast.AsyncFunctionDef,
                    params: tuple[str, ...]) -> tuple[tuple[int, Any], ...]:
        """Koşulda kullanılan parametrelere geçen sabit argümanlar (bağlam duyarlı özet anahtarı)."""
        interesting = self.p.test_params(fnode)
        if not interesting:
            return ()
        found: list[tuple[int, Any]] = []
        pairs = [(position + offset, arg) for position, arg in enumerate(node.args) if not isinstance(arg, ast.Starred)]
        pairs += [(params.index(kw.arg), kw.value) for kw in node.keywords if kw.arg in params]
        for index, arg in pairs:
            if index >= len(params) or params[index] not in interesting:
                continue
            value = self._const(arg)
            if isinstance(value, (bool, int, type(None))) or (isinstance(value, str) and len(value) <= 64):
                found.append((index, value))
        return tuple(sorted(found, key=lambda item: item[0]))

    # -- fonksiyonlar arası -------------------------------------------------------
    def _resolve_class(self, func: ast.AST) -> tuple[_PyModule, str] | None:
        dotted = _dotted(func)
        if not dotted or "()" in dotted:
            return None
        resolved = self.p.resolve(self.m, dotted)
        if resolved is not None and resolved[0] == "class":
            return resolved[1], resolved[2]
        return None

    def _resolve_call(self, node: ast.Call) -> _CallTarget | None:
        func = node.func
        resolved: tuple[str, _PyModule, str] | None = None
        bound = False
        if isinstance(func, ast.Name):
            local = self.local_funcs.get(func.id)
            if local is not None:
                return (self.m, f"{self.qual}.<locals>.{func.id}", local, 0, None)
            # Python determines locals for the whole function.  An assignment
            # or parameter with the same name therefore shadows a module
            # import; resolving the imported function would invent a call.
            if func.id in self.local_rebindings:
                return None
            resolved = self.p.resolve(self.m, func.id)
        elif isinstance(func, ast.Attribute):
            owner = func.value
            found: tuple[_PyModule, str] | None = None
            if isinstance(owner, ast.Name) and owner.id in {"self", "cls"} and self.class_name:
                found = self.p.find_method(self.m, self.class_name, func.attr)
            elif isinstance(owner, ast.Name) and owner.id in self.types:
                owner_module, owner_class = self.types[owner.id]
                found = self.p.find_method(owner_module, owner_class, func.attr)
            elif isinstance(owner, ast.Attribute) and isinstance(owner.value, ast.Name) and owner.value.id == self.self_name \
                    and self.class_name:
                # self.repo.find(x): alanın türü sınıfın __init__ özetinden.
                init = self.p.find_method(self.m, self.class_name, "__init__")
                if init is not None:
                    field_type = self.p.summary(init[0], init[1], init[0].functions[init[1]], self.class_name).field_types.get(owner.attr)
                    if field_type is not None:
                        found = self.p.find_method(field_type[0], field_type[1], func.attr)
                if found is None:
                    # Alan tip açıklaması (dataclass/pydantic alanı veya self.alan: T).
                    annotated = self._field_type(owner)
                    if annotated is not None and annotated[0] == "class":
                        found = self.p.find_method(annotated[1][0], annotated[1][1], func.attr)
            elif isinstance(owner, ast.Attribute) and isinstance(owner.value, ast.Name) and owner.value.id in self.types:
                # nesne.alan.metot(x): türü bilinen nesnenin açıklamalı alanı.
                annotated = self._field_type(owner)
                if annotated is not None and annotated[0] == "class":
                    found = self.p.find_method(annotated[1][0], annotated[1][1], func.attr)
            elif isinstance(owner, ast.Call) and _dotted(owner.func) == "super" and self.class_name:
                # super().metot(): taban sınıfın metodu, aynı nesne üzerinde.
                found = self._super_method(func.attr)
            elif isinstance(owner, ast.Call):
                # Servis().calistir(x): sınıf örneği aynı ifadede oluşturuluyor.
                cls = self._resolve_class(owner.func)
                if cls is not None:
                    found = self.p.find_method(cls[0], cls[1], func.attr)
            else:
                dotted = _dotted(func)
                if dotted and "()" not in dotted and dotted.split(".")[0] not in self.env:
                    resolved = self.p.resolve(self.m, dotted)
            if found is not None:
                resolved = ("func", found[0], found[1])
                bound = True
        if resolved is None:
            return None
        kind, module, qual = resolved
        if kind == "class":
            init = self.p.find_method(module, qual, "__init__")
            if init is None:
                return None
            module, qual = init
            bound = True
        elif kind != "func":
            return None
        fnode = module.functions.get(qual)
        if fnode is None:
            return None
        class_name = qual.split(".")[0] if "." in qual else None
        decorators = {_dotted(d) for d in fnode.decorator_list}
        if class_name is None or "staticmethod" in decorators:
            offset = 0
        elif "classmethod" in decorators:
            offset = 1
        else:
            offset = 1 if bound else 0
        return (module, qual, fnode, offset, class_name)

    def _receiver_fields(self, node: ast.Call) -> tuple[str, dict[str, Taint] | None]:
        """Çağrının alıcısı: ("self", None) | ("var:<ad>", alanlar) | ("new", alanlar) | ("", None)."""
        func = node.func
        if not isinstance(func, ast.Attribute):
            return "", None
        owner = func.value
        if isinstance(owner, ast.Call) and _dotted(owner.func) == "super" and self.self_name and self.summary is not None:
            return "self", None
        if isinstance(owner, ast.Name):
            if owner.id == self.self_name and self.summary is not None:
                return "self", None
            return f"var:{owner.id}", self.obj_fields.setdefault(owner.id, {}) if owner.id in self.types or owner.id in self.obj_fields else None
        if isinstance(owner, ast.Call) and id(owner) in self.call_effects:
            summary, bound, label, receiver, _self_call = self.call_effects[id(owner)]
            if receiver is None:
                return "new", {field: self._map_effect(t, bound, {}, label) for field, t in summary.field_writes.items()}
        return "", None

    def _map_effect(self, taint: Taint, bound: dict[int, Taint], fields: dict[str, Taint] | None, label: str) -> Taint:
        """Özet içindeki sembolik kökenleri çağrı yerindeki değerlere eşle."""
        parts: list[Taint] = []
        for origin in taint:
            if origin.label == _PARAM:
                value = bound.get(int(origin.source))
                if value:
                    parts.append(_via(_clean(value, origin.cleaned), label))
            elif origin.label == _FIELD:
                if fields is None:
                    parts.append((origin,))  # self.m(): aynı nesne, sembolik kalır
                elif fields.get(origin.source):
                    parts.append(_via(_clean(fields[origin.source], origin.cleaned), label))
            elif origin.label == _PARAM_FIELD:
                # Parametre-alanı kökeni yalnız ``ret_param_fields`` ve
                # ``param_field_writes`` üzerinden alan-duyarlı eşlenir.  Onu
                # gerçek bir kullanıcı kaynağı gibi dışarı sızdırma.
                continue
            else:
                parts.append((origin,))
        return _union(*parts)

    def _apply_summary(self, node: ast.Call, target: _CallTarget, arg_taints: list[Taint],
                       kw_taints: dict[str | None, Taint]) -> Taint:
        module, qual, fnode, offset, class_name = target
        arguments = [*fnode.args.posonlyargs, *fnode.args.args, *fnode.args.kwonlyargs]
        consts = self._const_args(node, offset, fnode, tuple(a.arg for a in arguments))
        self.p.called.add(id(fnode))
        summary = self.p.summary(module, qual, fnode, class_name, consts)
        label = qual.replace(".<locals>", "") + "()"
        receiver_kind, receiver_fields = self._receiver_fields(node) if qual.rsplit(".", 1)[-1] != "__init__" or not isinstance(node.func, ast.Name) else ("", None)
        is_constructor = qual.rsplit(".", 1)[-1] == "__init__" and not (isinstance(node.func, ast.Attribute) and receiver_kind == "self")
        bound: dict[int, Taint] = {}
        for position, (arg_node, taint) in enumerate(zip(node.args, arg_taints)):
            if isinstance(arg_node, ast.Starred):
                break
            index = position + offset
            if index < len(summary.params) and taint:
                bound[index] = taint
        for key, taint in kw_taints.items():
            if key is not None and key in summary.params and taint:
                bound[summary.params.index(key)] = taint
        arg_nodes: dict[int, ast.AST] = {}
        for position, arg_node in enumerate(node.args):
            if isinstance(arg_node, ast.Starred):
                break
            arg_nodes[position + offset] = arg_node
        for keyword in node.keywords:
            if keyword.arg is not None and keyword.arg in summary.params:
                arg_nodes[summary.params.index(keyword.arg)] = keyword.value
        arg_fields: dict[int, dict[str, Taint]] = {}
        for index, arg_node in arg_nodes.items():
            if isinstance(arg_node, ast.Name) and (arg_node.id in self.obj_fields or arg_node.id in self.types):
                arg_fields[index] = self.obj_fields.setdefault(arg_node.id, {})
        self.call_args[id(node)] = (fnode, arg_nodes, module)
        self.call_effects[id(node)] = (summary, bound, label, None if is_constructor else (receiver_fields or {}),
                                       receiver_kind == "self")
        for gname, written in summary.global_writes.items():
            # Çağrılan fonksiyonun `global` yazımı: parametre kökenleri çağrı yerindeki değerlerle.
            mapped = self._map_effect(written, bound, None if receiver_kind == "self" else (receiver_fields or {}), label)
            self.p.add_global(module.relpath, gname, mapped)
            if self.summary is not None and module is self.m:
                self.summary.add_global_write(gname, tuple(o for o in mapped if o.label in {_PARAM, _FIELD}))
        for (index, field), written in summary.param_field_writes.items():
            fields_for_arg = arg_fields.get(index)
            if fields_for_arg is None:
                continue
            mapped = self._map_effect(written, bound, {}, label)
            if (index, field) in summary.param_field_strong_writes and self.control_depth == 0:
                fields_for_arg[field] = mapped
            else:
                fields_for_arg[field] = _union(fields_for_arg.get(field, _EMPTY), mapped)
        if receiver_kind == "self" or receiver_fields is not None:
            # Metodun alana yazdıkları: aynı nesne (self) veya izlenen yerel nesne.
            for field, written in summary.field_writes.items():
                mapped = self._map_effect(written, bound, receiver_fields, label)
                if receiver_kind == "self":
                    if self.summary is not None:
                        self.summary.add_field_write(field, mapped)
                elif receiver_fields is not None:
                    receiver_fields[field] = _union(receiver_fields.get(field, _EMPTY), mapped)
        field_values: dict[str, Taint] = {}
        if receiver_kind == "self":
            field_values = {s.field: (_Origin(_FIELD, s.field, s.line, (), frozenset(), self.m.relpath),)
                            for s in summary.sinks.values() if s.index == -1}
        elif receiver_fields:
            field_values = receiver_fields
        if not bound and not field_values and not summary.ret_param_fields and not arg_fields:
            returned_fields = [self._map_effect(((_Origin(_FIELD, f, 0, (), c, self.m.relpath)),), bound,
                                                None if receiver_kind == "self" else (receiver_fields or {}), label)
                               for f, c in summary.ret_fields.items()]
            return _union(summary.ret_sources, *returned_fields)
        for sink in summary.sinks.values():
            if sink.index == -1:
                taint = field_values.get(sink.field)
            elif sink.field:
                taint = arg_fields.get(sink.index, {}).get(sink.field)
            else:
                taint = bound.get(sink.index)
            if not taint:
                continue
            prefix_param = -1
            kind = sink.kind
            if sink.prefix_param >= 0:
                state = self._arg_prefix_state(node, sink.prefix_param, sink.kind)
                if state == "clean":
                    if sink.kind != "ssrf":
                        continue  # adresin ilk bileşeni çağıranın verdiği güvenli önek
                    kind = "ssrf_partial"  # sabit ana makine çağırandan: girdi yalnız yol/sorguda (kısmi SSRF)
                elif state == "env":
                    self.p.uncertain.setdefault(sink.file, set()).add((sink.kind, sink.line))
                    continue
                elif isinstance(state, int):
                    prefix_param = state
            for origin in _live(taint, kind):
                via = (origin.via + (label,) + sink.via)[-MAX_VIA:]
                if origin.label == _UNCERTAIN:
                    self.p.uncertain.setdefault(sink.file, set()).add((kind, sink.line))
                elif origin.label == _PARAM:
                    if self.summary is not None:
                        self.summary.add_sink(_ParamSink(int(origin.source), kind, sink.sink, sink.file, sink.line, via,
                                                         prefix_param=prefix_param))
                elif origin.label == _FIELD:
                    if self.summary is not None:
                        self.summary.add_sink(_ParamSink(-1, kind, sink.sink, sink.file, sink.line, via, origin.source))
                elif origin.label == _PARAM_FIELD:
                    raw_index, _, field = origin.source.partition(":")
                    if self.summary is not None and raw_index.isdigit() and field:
                        self.summary.add_sink(_ParamSink(
                            int(raw_index), kind, sink.sink, sink.file, sink.line, via, field,
                            prefix_param=prefix_param,
                        ))
                    continue
                else:
                    self.p.add_flow(Flow(
                        "python", kind, sink.sink, sink.line, origin.source, origin.label, origin.line,
                        via, sink.file, origin.file,
                    ))
                    if kind in ("sql", "command", "nosql") and sink.index >= 0 and \
                            _constructed_arg(node, sink.index) and getattr(node, "lineno", 0) != sink.line:
                        # 18. tur: sorgu/komut metni ÇAĞRI YERİNDE istek verisiyle kuruluyor (run_sql(f"… {x}")):
                        # enjeksiyon noktası çağrı satırıdır; sarmalayıcıdaki hedef bulgusuna ek olarak raporlanır.
                        self.p.add_flow(Flow(
                            "python", kind, f"{label}() → {sink.sink}", node.lineno, origin.source, origin.label,
                            origin.line, via, self.m.relpath, origin.file,
                        ))
        returned = [
            _via(_clean(bound[index], cleaned), label)
            for index, cleaned in summary.ret_params.items()
            if index in bound
        ]
        returned += [
            self._map_effect((_Origin(_FIELD, field, 0, (), cleaned, self.m.relpath),), bound,
                             None if receiver_kind == "self" else (receiver_fields or {}), label)
            for field, cleaned in summary.ret_fields.items()
        ]
        returned += [
            _via(_clean(arg_fields[index].get(field, _EMPTY), cleaned), label)
            for (index, field), cleaned in summary.ret_param_fields.items()
            if index in arg_fields
        ]
        return _union(*returned, summary.ret_sources)

    # -- hedefler -------------------------------------------------------------
    def _emit(self, kind: str, sink: str, line: int, taint: Taint, prefix_param: int = -1) -> None:
        self.p.mark_evaluated(self.m.relpath, kind, line)
        for origin in _live(taint, kind):
            if origin.label == _UNCERTAIN:
                self.p.uncertain.setdefault(self.m.relpath, set()).add((kind, line))
                continue
            if origin.label == _PARAM:
                if self.summary is not None:
                    self.summary.add_sink(_ParamSink(int(origin.source), kind, sink, self.m.relpath, line, origin.via,
                                                     prefix_param=prefix_param))
                continue
            if origin.label == _FIELD:
                if self.summary is not None:
                    self.summary.add_sink(_ParamSink(-1, kind, sink, self.m.relpath, line, origin.via, origin.source))
                continue
            if origin.label == _PARAM_FIELD:
                raw_index, _, field = origin.source.partition(":")
                if self.summary is not None and raw_index.isdigit() and field:
                    self.summary.add_sink(_ParamSink(
                        int(raw_index), kind, sink, self.m.relpath, line, origin.via, field,
                        prefix_param=prefix_param,
                    ))
                continue
            self.p.add_flow(Flow(
                "python", kind, sink, line, origin.source, origin.label, origin.line, origin.via,
                self.m.relpath, origin.file,
            ))

    def _is_shell_argv(self, node: ast.AST) -> bool:
        if isinstance(node, (ast.List, ast.Tuple)):
            items = {item.value for item in node.elts if isinstance(item, ast.Constant) and isinstance(item.value, str)}
        elif isinstance(node, ast.Name):
            items = self.list_consts.get(node.id, set())
        else:
            return False
        return bool(items & _SHELL_PROGRAMS) and bool(items & _SHELL_FLAGS)

    def _dispatch_by_name(self, node: ast.Call, arg_taints: list[Taint], kw_taints: dict[str | None, Taint]) -> Taint | None:
        """Türü bilinmeyen alıcıda obj.m(x): projede m'yi tanımlayan en çok 3 sınıf varsa
        özetlerin birleşimi (sınıf hiyerarşisi analizi benzeri; yaygın adlar hariç)."""
        if not isinstance(node.func, ast.Attribute):
            return None
        method = node.func.attr
        if method.startswith("_") or method in _DISPATCH_EXCLUDED or method in _PY_STRING_METHODS or method in _PY_MUTATORS:
            return None
        owner = node.func.value
        if isinstance(owner, ast.Name) and (owner.id in self.m.imports or owner.id in self.m.functions or owner.id in self.m.classes):
            return None
        candidates = self.p.methods_named(method)
        if not 1 <= len(candidates) <= 3:
            return None
        results = []
        for module, qual in candidates:
            fnode = module.functions[qual]
            decorators = {_dotted(d) for d in fnode.decorator_list}
            offset = 0 if "staticmethod" in decorators else 1
            results.append(self._apply_summary(node, (module, qual, fnode, offset, qual.split(".")[0]), arg_taints, kw_taints))
        return _union(*results)

    # -- sabit değerlendirme --------------------------------------------------------
    def _const(self, node: ast.AST | None, depth: int = 0) -> Any:
        """Güvenli, sınırlı sabit değerlendirici (ölü dal ayıklama); bilinmiyorsa _CONST_UNKNOWN."""
        if node is None or depth > 25:
            return _CONST_UNKNOWN
        unknown = _CONST_UNKNOWN
        if isinstance(node, ast.Constant):
            value = node.value
            if isinstance(value, (int, float, bool, type(None))) or (isinstance(value, str) and len(value) <= _MAX_CONST_STR):
                return value
            return unknown
        if isinstance(node, ast.Name):
            return self.consts.get(node.id, unknown)
        try:
            if isinstance(node, ast.BinOp):
                left, right = self._const(node.left, depth + 1), self._const(node.right, depth + 1)
                if left is unknown or right is unknown:
                    return unknown
                ops = {ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b, ast.Mult: lambda a, b: a * b,
                       ast.Mod: lambda a, b: a % b, ast.FloorDiv: lambda a, b: a // b}
                op = ops.get(type(node.op))
                if op is None or (isinstance(node.op, ast.Mult) and isinstance(left, str) | isinstance(right, str)
                                  and (isinstance(left, int) and left > 100 or isinstance(right, int) and right > 100)):
                    return unknown
                value = op(left, right)
                if isinstance(value, str) and len(value) > _MAX_CONST_STR or isinstance(value, int) and abs(value) > 10**15:
                    return unknown
                return value
            if isinstance(node, ast.UnaryOp):
                value = self._const(node.operand, depth + 1)
                if value is unknown:
                    return unknown
                if isinstance(node.op, ast.Not):
                    return not value
                if isinstance(node.op, ast.USub):
                    return -value
                return unknown
            if isinstance(node, ast.Compare):
                left = self._const(node.left, depth + 1)
                if left is unknown:
                    return unknown
                for op, comparator in zip(node.ops, node.comparators):
                    right = self._const(comparator, depth + 1)
                    if right is unknown:
                        return unknown
                    table = {ast.Eq: lambda a, b: a == b, ast.NotEq: lambda a, b: a != b, ast.Lt: lambda a, b: a < b,
                             ast.LtE: lambda a, b: a <= b, ast.Gt: lambda a, b: a > b, ast.GtE: lambda a, b: a >= b,
                             ast.In: lambda a, b: a in b, ast.NotIn: lambda a, b: a not in b,
                             ast.Is: lambda a, b: a is b, ast.IsNot: lambda a, b: a is not b}
                    fn = table.get(type(op))
                    if fn is None or not fn(left, right):
                        return False if fn is not None else unknown
                    left = right
                return True
            if isinstance(node, ast.BoolOp):
                values = [self._const(v, depth + 1) for v in node.values]
                if isinstance(node.op, ast.And):
                    for value in values:
                        if value is unknown:
                            return unknown
                        if not value:
                            return value
                    return values[-1]
                for value in values:
                    if value is unknown:
                        return unknown
                    if value:
                        return value
                return values[-1]
            if isinstance(node, ast.Subscript):
                container = self._const(node.value, depth + 1)
                if not isinstance(container, (str, tuple)):
                    return unknown
                key = node.slice
                if isinstance(key, ast.Slice):
                    parts = [self._const(part, depth + 1) if part is not None else None for part in (key.lower, key.upper, key.step)]
                    if any(part is unknown for part in parts):
                        return unknown
                    return container[slice(*parts)]
                index = self._const(key, depth + 1)
                return container[index] if isinstance(index, int) else unknown
            if isinstance(node, ast.Call) and _dotted(node.func) == "len" and len(node.args) == 1:
                value = self._const(node.args[0], depth + 1)
                return len(value) if isinstance(value, (str, tuple)) else unknown
            if isinstance(node, ast.IfExp):
                test = self._const(node.test, depth + 1)
                if test is unknown:
                    return unknown
                return self._const(node.body if test else node.orelse, depth + 1)
        except Exception:
            return unknown
        return unknown

    def _record_const(self, target: ast.AST, value: ast.AST | None) -> None:
        if not isinstance(target, ast.Name):
            return
        result = self._const(value) if value is not None else _CONST_UNKNOWN
        if result is _CONST_UNKNOWN:
            self.consts.pop(target.id, None)
        else:
            self.consts[target.id] = result
        if isinstance(value, (ast.List, ast.Tuple)):
            items = {item.value for item in value.elts if isinstance(item, ast.Constant) and isinstance(item.value, str)}
            self.list_consts[target.id] = items
        else:
            self.list_consts.pop(target.id, None)
        self.derived.pop(target.id, None)
        if isinstance(value, ast.List) and not any(isinstance(e, ast.Starred) for e in value.elts):
            self.list_items[target.id] = [self.expr(e) for e in value.elts]
        else:
            self.list_items.pop(target.id, None)
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div) and isinstance(value.left, ast.Name) and value.left.id in self.ctors:
            # p = Path(...) / x → p de Path nesnesi.
            self.ctors[target.id] = self.ctors[value.left.id]
        if isinstance(value, ast.Dict) and all(isinstance(k, ast.Constant) and isinstance(k.value, str) for k in value.keys):
            self.dict_fields.add(target.id)
            for k, v in zip(value.keys, value.values):
                self.env[f"{target.id}[{k.value!r}]"] = self.expr(v)
        else:
            self.dict_fields.discard(target.id)
        key_taint = self._mongo_operator_taint(value) if isinstance(value, ast.Dict) else _EMPTY
        if key_taint:
            self.dict_key_taint[target.id] = key_taint
        else:
            self.dict_key_taint.pop(target.id, None)
        if isinstance(value, ast.Call) and _dotted(value.func) in _DERIVING_CALLS and value.args and isinstance(value.args[0], ast.Name):
            self.derived[target.id] = value.args[0].id

    def _match_case(self, node: Any) -> list[ast.stmt] | None:
        """Sabit konulu match: eşleşen tek dalın gövdesi; karar verilemezse None."""
        subject = self._const(node.subject)
        if subject is _CONST_UNKNOWN:
            return None

        def matches(pattern: Any) -> bool | None:
            if isinstance(pattern, ast.MatchValue):
                value = self._const(pattern.value)
                return None if value is _CONST_UNKNOWN else value == subject
            if isinstance(pattern, ast.MatchSingleton):
                return pattern.value is subject
            if isinstance(pattern, ast.MatchOr):
                results = [matches(p) for p in pattern.patterns]
                return True if any(r is True for r in results) else (None if None in results else False)
            if isinstance(pattern, ast.MatchAs) and pattern.pattern is None:
                return True
            return None

        for case in node.cases:
            result = matches(case.pattern)
            if result is None or (result and case.guard is not None):
                return None
            if result:
                return case.body
        return []

    def _value_class(self, node: ast.AST) -> str | None:
        """Model türü bilinen dış nesne mi? (``s = requests.Session()``, ``requests.Session()``, ``db.cursor()``)"""
        if isinstance(node, ast.Name):
            return self.ext_types.get(node.id)
        if isinstance(node, ast.Call):
            return self._call_class(node.func)
        if isinstance(node, ast.Attribute):
            annotated = self._field_type(node)
            if annotated is not None and annotated[0] == "ext":
                return annotated[1]
        return None

    def _call_class(self, func: ast.AST) -> str | None:
        models = self.p.models
        if not models.returns:
            return None
        if isinstance(func, ast.Attribute):
            owner = self._value_class(func.value)
            if owner:
                return models.class_of(f"{owner}.{func.attr}")
        name = _dotted(func)
        if not name or (isinstance(func, ast.Name) and self.env.get(func.id)):
            return None
        return models.class_of(self._canonical(name)) or models.class_of(name)

    def _model_names(self, node: ast.Call, name: str) -> list[str]:
        """Model sorguları için adlar: yazıldığı gibi, içe aktarma ile kanonik ve alıcı türüyle (Sınıf.metot)."""
        names = [name] if name else []
        canonical = self._canonical(name) if name else ""
        if canonical and canonical != name:
            names.append(canonical)
        if isinstance(node.func, ast.Attribute):
            owner = self._value_class(node.func.value)
            if owner:
                names.append(f"{owner}.{node.func.attr}")
            value = node.func.value
            if isinstance(value, ast.Name) and value.id not in self.env and value.id not in self.ctors \
                    and (self.local_names is None or value.id not in self.local_names):
                ctor = self.m.global_ctors().get(value.id)
                if ctor:
                    names.append(f"{self._canonical(ctor)}.{node.func.attr}")
        return names

    def _canonical(self, name: str) -> str:
        head, _, rest = name.partition(".")
        target = self.m.imports.get(head)
        return f"{target}.{rest}" if target and rest else (target or name)

    def _is_weak_random(self, name: str, last: str) -> bool:
        if not name or "SystemRandom" in name:
            return False
        canonical = self._canonical(name)
        return canonical.startswith(("random.", "numpy.random.")) and last not in {"seed", "Random", "SystemRandom", "getstate", "setstate"}

    def _check_special_sinks(self, node: ast.Call, name: str, args: list[Taint], kwargs: dict[str | None, Taint],
                             receiver: Taint) -> None:
        """LDAP filtresi, XXE (dış varlıkları açık ayrıştırıcı) ve çerez değeri hedefleri."""
        line = node.lineno
        last = name.rsplit(".", 1)[-1]
        base = name.rsplit(".", 1)[0] if "." in name else ""
        lowered = base.lower()
        if last in {"search", "search_s", "search_st", "search_ext", "search_ext_s", "search_paged"} and base \
                and base not in {"re", "regex"} and ("ldap" in lowered or "conn" in lowered):
            index, keyword = (1, "search_filter") if last in {"search", "search_paged"} else (2, "filterstr")
            if index < len(args):
                self._emit("ldap", name, line, args[index])
            elif keyword in kwargs:
                self._emit("ldap", name, line, kwargs[keyword])
        if last in {"set_cookie"} and isinstance(node.func, ast.Attribute):
            value = args[1] if len(args) > 1 else kwargs.get("value", _EMPTY)
            self._emit("cookie", name, line, value)
        if last in {"parseString", "parse", "fromstring", "XML", "iterparse"} and args:
            parser_node = node.args[1] if len(node.args) > 1 else next((kw.value for kw in node.keywords if kw.arg == "parser"), None)
            unsafe = isinstance(parser_node, ast.Name) and parser_node.id in self.unsafe_xml_parsers
            if not unsafe and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                unsafe = node.func.value.id in self.unsafe_xml_parsers and last in {"parse", "feed"}
            if unsafe:
                self._emit("xxe", name, line, args[0])
        if isinstance(node.func, ast.Attribute):
            self._check_method_sinks(node, name, last, args, kwargs, receiver)
        canonical = self._canonical(name)
        if canonical in _PY_SSTI_CALLS and (args or kwargs.get("source")):
            # Şablon metninin kendisi girdiden: sunucu tarafı şablon enjeksiyonu (Jinja2/Tornado/Mako ifadeleri kod çalıştırır).
            self._emit("ssti", name, line, args[0] if args else kwargs.get("source", _EMPTY))
        elif canonical.rsplit(".", 1)[-1] == "RawSQL" and canonical.startswith("django.") and args:
            self._emit("sql", name, line, args[0])

    def _mongo_operator_taint(self, node: ast.Dict, depth: int = 0) -> Taint:
        """Sözlük değişmezinde girdiden gelen anahtarlar ve $where/$function değerleri (iç içe sözlükler dahil)."""
        parts: list[Taint] = []
        for key, value in zip(node.keys, node.values):
            if key is None:
                continue  # **d açılımı
            if not isinstance(key, ast.Constant):
                live = _live(self.expr(key), "nosql_key")
                if live:
                    parts.append(_operator_marked(tuple(live)))
            elif key.value in _MONGO_CODE_OPERATORS:
                live = _live(self.expr(value), "nosql_key")
                if live:
                    parts.append(_operator_marked(tuple(live)))
            if isinstance(value, ast.Dict) and depth < 3:
                parts.append(self._mongo_operator_taint(value, depth + 1))
        return _union(*parts) if parts else _EMPTY

    def _check_method_sinks(self, node: ast.Call, name: str, last: str, args: list[Taint],
                            kwargs: dict[str | None, Taint], receiver: Taint) -> None:
        """Alıcı türüne bağlı hedefler: MongoDB sorgu filtresi, Django ``QuerySet.extra`` ve yüklenen dosyanın
        ``save(yol)`` çağrısı."""
        line = node.lineno
        if last in _DYNAMO_METHODS and node.keywords and self._uses_boto():
            self._check_dynamo_call(node, name)
        if last in _PY_MONGO_METHODS and args and self.p.uses_mongo() and (
                last != "find" or isinstance(node.args[0], ast.Dict)
                or (isinstance(node.args[0], ast.Name) and (node.args[0].id in self.dict_fields
                                                            or (self.summary is not None and node.args[0].id in self.summary.params)))):
            # 18. tur: find(param) — filtreyi parametre olarak alan yardımcı (get_users(query) → coll.find(query));
            # dize kaynaklar _live ile elenir (operatör nesnesi yalnız JSON/sözlük kaynaktan gelebilir).
            # Filtre sözlüğü: JSON gövdesinden gelen değer {"$ne": …} gibi operatör nesnesi olabilir (bkz. _live).
            self._emit("nosql", name, line, args[0])
        if last in _PY_MONGO_METHODS and node.args and self.p.uses_mongo():
            # Anahtarı girdiden gelen filtre ({girdi: v}) ya da $where/$function içine giren dize: dize kaynaklar da
            # (form/sorgu) operatör ve JavaScript ifadesi seçebilir.
            first = node.args[0]
            operator = self._mongo_operator_taint(first) if isinstance(first, ast.Dict) else (
                self.dict_key_taint.get(first.id, _EMPTY) if isinstance(first, ast.Name) else _EMPTY)
            if operator:
                self._emit("nosql", name, line, operator)
        elif last == "extra" and (kwargs.keys() & {"select", "where", "tables", "order_by"} or len(node.args) >= 2) \
                and (".objects" in name or "queryset" in name.lower() or any(
                    target.split(".")[0] == "django" for target in self.m.imports.values())):
            # QuerySet.extra(select={…: "… %s" % x}, where=[…]): ham SQL parçaları (params= bağlı değerdir).
            parts = [args[i] for i in (0, 1, 3, 4) if i < len(args)]
            parts += [kwargs[key] for key in ("select", "where", "tables", "order_by") if key in kwargs]
            self._emit("sql", name, line, _union(*parts))
        elif last == "save" and args and any(
                o.label == "request" and _UPLOAD_SOURCE_RE.search(o.source) for o in receiver):
            # Yüklenen dosya nesnesi (request.files[...] / FileStorage): save(hedef_yol) yolu belirler.
            self._emit("path", name, line, args[0])

    def _uses_boto(self) -> bool:
        return any(target.split(".")[0] in {"boto3", "aioboto3", "botocore"} for target in self.m.imports.values())

    def _check_dynamo_call(self, node: ast.Call, name: str) -> None:
        """DynamoDB: ifade metinleri (dize olarak kurulmuşsa), PartiQL deyimi, tablo adı ve eski tip
        ScanFilter/QueryFilter/KeyConditions sözlüğünün anahtarları ile ComparisonOperator değerleri.
        Karşılaştırılan değerler (AttributeValueList, ExpressionAttributeValues) bağlı parametredir, hedef değil."""
        for keyword in node.keywords:
            if keyword.arg in _DYNAMO_EXPRESSION_KWARGS:
                if _is_string_building(keyword.value):
                    self._emit("nosql_expr", f"{name}({keyword.arg})", node.lineno, self.expr(keyword.value))
            elif keyword.arg == "TableName":
                self._emit("nosql_expr", f"{name}(TableName)", node.lineno, self.expr(keyword.value))
            elif keyword.arg in _DYNAMO_LEGACY_FILTERS and isinstance(keyword.value, ast.Dict):
                parts: list[Taint] = []
                for key, value in zip(keyword.value.keys, keyword.value.values):
                    if key is not None:
                        parts.append(self.expr(key))
                    if isinstance(value, ast.Dict):
                        parts += [self.expr(v) for k, v in zip(value.keys, value.values)
                                  if isinstance(k, ast.Constant) and k.value == "ComparisonOperator"]
                self._emit("nosql_expr", f"{name}({keyword.arg})", node.lineno, _union(*parts))

    def _track_xml_parser(self, node: ast.Call) -> None:
        """Dış varlık çözümünü açan ayrıştırıcı yapılandırmalarını izle."""
        if isinstance(node.func, ast.Attribute) and node.func.attr == "setFeature" and isinstance(node.func.value, ast.Name) \
                and len(node.args) == 2:
            feature = _dotted(node.args[0]).rsplit(".", 1)[-1]
            enabled = isinstance(node.args[1], ast.Constant) and node.args[1].value is True
            if feature in {"feature_external_ges", "feature_external_pes"}:
                if enabled:
                    self.unsafe_xml_parsers.add(node.func.value.id)

    def _redirect_prefix_clean(self, node: ast.AST | None) -> bool:
        """Yönlendirme adresinin ilk bileşeni temiz mi? (girdi yalnız yol/sorgu kısmını etkiler)

        Temiz ilk bileşen: "/" ile başlayan (ama "//" olmayan) sabit yol, sabit şema+ana makine,
        taint taşımayan ifade (ör. reverse(...)) veya böyle atanıp yalnız += ile uzatılmış değişken."""
        if node is None:
            return False
        if self._same_origin_prefix(node):
            return True
        first: ast.AST | None = None
        if isinstance(node, ast.JoinedStr) and node.values:
            first = node.values[0]
            if isinstance(first, ast.FormattedValue):
                first = first.value
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            first = node.left
            while isinstance(first, ast.BinOp) and isinstance(first.op, ast.Add):
                first = first.left
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            first = node.func.value
        elif isinstance(node, ast.Name):
            return node.id in self.prefix_clean
        elif isinstance(node, ast.Call):
            first = node
        else:
            return False
        if isinstance(first, ast.Call):
            func = first.func
            builder = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
            if builder in _PY_URL_BUILDERS:
                return True
            if first is node:
                return False
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            text = first.value
            # "/" tek başına temiz değil: "/" + "/evil.com" → "//evil.com" (protokole göreli adres)
            return (len(text) > 1 and text[0] == "/" and text[1] not in "/\\") or bool(_URL_FIXED_HOST_RE.match(text))
        if isinstance(first, ast.Name) and first.id in self.prefix_clean:
            return True
        if isinstance(first, ast.Call) and isinstance(first.func, ast.Attribute) and \
                first.func.attr in _PY_MUTATORS | {"pop", "popleft", "popitem", "setdefault"}:
            return False  # yan etkili çağrı ikinci kez değerlendirilmez
        return first is not None and not isinstance(first, ast.Constant) and not self.expr(first)

    def _leading_value(self, part: ast.AST) -> Any:
        """Adres parçasının sabit değeri: dize, _ENV_VALUE ya da None. Yerel sabitler, modül/sınıf sabitleri
        ve Django settings çözülür (``settings.API_BASE + yol``)."""
        if isinstance(part, ast.Constant):
            return part.value if isinstance(part.value, str) else None
        if _is_env_lookup(self.m, part):
            return _ENV_VALUE
        if isinstance(part, ast.Name):
            if part.id in self.env_prefixed:
                return _ENV_VALUE
            value = self.consts.get(part.id, _CONST_UNKNOWN)
            if isinstance(value, str):
                return value
            if self.local_names is not None and part.id in self.local_names:
                return None
            ref = self.p.global_ref(self.m, part.id)
            return self.p.module_constant(*ref) if ref else None
        if isinstance(part, ast.Attribute) and isinstance(part.value, ast.Name) and part.value.id != self.self_name \
                and part.value.id not in self.env:
            return self.p.attribute_constant(self.m, part.value.id, part.attr)
        return None

    def _leading_text(self, node: ast.AST) -> Any:
        """Adresin baştan çözülebilen sabit kısmı (ilk çözülemeyen parçada durur); ilk parça ortam
        değişkeniyse _ENV_VALUE. Hiçbir parça çözülemezse None."""
        parts = _url_parts(node) or [node]
        text = ""
        for index, part in enumerate(parts[:6]):
            value = self._leading_value(part)
            if value is _ENV_VALUE:
                return _ENV_VALUE if index == 0 else (text or None)
            if not isinstance(value, str):
                break
            text += value
        return text or None

    def _same_origin_prefix(self, node: ast.AST) -> bool:
        """Adres isteğin kendi kökeniyle başlıyor mu? ``request.build_absolute_uri(...)``, Flask/Starlette
        ``request.host_url``/``url_root``/``base_url``, ``request.scheme + "://" + request.get_host()`` ve
        istek verisi taşımayan ayrıştırılmış adresten ``p.scheme + "://" + p.netloc``. Girdi yalnız yolu etkiler:
        açık yönlendirme / ana makine değiştiren SSRF değildir."""
        parts = _url_parts(node) or [node]
        first = parts[0]
        if isinstance(first, ast.Call) and isinstance(first.func, ast.Attribute) \
                and first.func.attr in _PY_SAME_ORIGIN_CALLS and isinstance(first.func.value, ast.Name) \
                and self._is_request_root(first.func.value.id):
            return True
        if isinstance(first, ast.Attribute) and first.attr in _PY_SAME_ORIGIN_ATTRS \
                and isinstance(first.value, ast.Name) and self._is_request_root(first.value.id):
            return True
        if len(parts) < 3 or not (isinstance(first, ast.Attribute) and first.attr == "scheme"):
            return False
        sep, host = parts[1], parts[2]
        if not (isinstance(sep, ast.Constant) and isinstance(sep.value, str) and sep.value.startswith("://")):
            return False
        if sep.value != "://":
            return False  # "://" sonrası sabit metin ana makineyi değiştirir
        owner = first.value
        if not isinstance(owner, ast.Name):
            return False
        if self._is_request_root(owner.id):
            if isinstance(host, ast.Call) and isinstance(host.func, ast.Attribute) and host.func.attr == "get_host" \
                    and isinstance(host.func.value, ast.Name) and self._is_request_root(host.func.value.id):
                return True
            return isinstance(host, ast.Attribute) and host.attr in {"host", "netloc"} \
                and isinstance(host.value, ast.Name) and self._is_request_root(host.value.id)
        if isinstance(host, ast.Attribute) and host.attr in {"netloc", "hostname"} \
                and isinstance(host.value, ast.Name) and host.value.id == owner.id:
            labels = {origin.label for origin in self.env.get(owner.id, _EMPTY)}
            return labels <= {_UNCERTAIN}
        return False

    def _pre_query_taint(self, node: ast.AST) -> Taint | None:
        """Adres şablonunda "?" / "#" öncesinin taint'i: sorgu/parça kısmı hedef ana makine ve yolu belirlemez.
        Bölünme yoksa ya da önceki parçalardan biri çağrı/yan etkili ifadeyse None (yeniden değerlendirilmez)."""
        parts = _url_parts(node)
        if not parts:
            return None
        before: list[ast.AST] = []
        for part in parts:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                if "?" in part.value or "#" in part.value:
                    if any(isinstance(n, (ast.Call, ast.NamedExpr, ast.Await, ast.Yield, ast.YieldFrom))
                           for p in before for n in fast_walk(p)):
                        return None
                    return _union(*(self.expr(p) for p in before)) if before else _EMPTY
                continue
            before.append(part)
        return None

    def _prefix_state(self, node: ast.AST | None, kind: str, depth: int = 0) -> Any:
        """Adresin ilk bileşeni (yönlendirme/SSRF için): "clean" (güvenli sabit önek), k (k. parametrenin
        değeri; çağrı yerinde çözülür) veya None. Yalnız yapısal: ifadeleri yeniden değerlendirmez."""
        if node is None or depth > 8:
            return None
        if self._same_origin_prefix(node):
            return "clean"
        lead = self._leading_text(node)
        if lead is _ENV_VALUE:
            return "env"
        if isinstance(lead, str) and _clean_prefix_text(lead, kind):
            return "clean"
        first = _first_component(node)
        if isinstance(first, ast.Constant):
            return "clean" if isinstance(first.value, str) and _clean_prefix_text(first.value, kind) else None
        if isinstance(first, ast.Name):
            if first.id in self.prefix_params:
                return self.prefix_params[first.id]
            if (first.id in self.prefix_clean) if kind == "redirect" else (first.id in self.host_fixed):
                return "clean"
            if first.id in self.env_prefixed:
                return "env"
            value = self.consts.get(first.id, _CONST_UNKNOWN)
            return "clean" if isinstance(value, str) and _clean_prefix_text(value, kind) else None
        if isinstance(first, ast.Call):
            func = first.func
            builder = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
            if kind == "redirect" and builder in _PY_URL_BUILDERS:
                return "clean"
            effect = self.call_effects.get(id(first))
            if effect is None:
                return None
            state = effect[0].ret_prefix.get(kind)
            if isinstance(state, int):
                return self._arg_prefix_state(first, state, kind, depth + 1)
            return state
        return None

    def _arg_prefix_state(self, call: ast.Call, index: int, kind: str, depth: int = 0) -> Any:
        """Proje içi çağrıda index. parametreye verilen argümanın (yoksa sabit varsayılanın) önek durumu."""
        info = self.call_args.get(id(call))
        if info is None:
            return None
        fnode, arg_nodes, _module = info
        arg = arg_nodes.get(index)
        if arg is None:
            arg = _default_for(fnode, index)
            if not isinstance(arg, ast.Constant):
                return None
        return self._prefix_state(arg, kind, depth)

    def _record_prefix(self, target: ast.AST, value: ast.AST) -> None:
        """Atamada önek bilgisi: parametreye bağlı önek, SSRF sabit ana makine, güvenli önekli çağrı dönüşü."""
        if not isinstance(target, ast.Name):
            return
        redirect = self._prefix_state(value, "redirect")
        ssrf = self._prefix_state(value, "ssrf")
        if isinstance(redirect, int) and redirect == ssrf:
            self.prefix_params[target.id] = redirect
        if ssrf == "clean":
            self.host_fixed.add(target.id)
        if redirect == "clean":
            self.prefix_clean.add(target.id)
        if ssrf == "env" or redirect == "env":
            self.env_prefixed.add(target.id)

    def _prefix_snapshot(self) -> tuple[dict[str, int], set[str]]:
        return dict(self.prefix_params), set(self.host_fixed)

    def _merge_prefix(self, start: tuple[dict[str, int], set[str]],
                      results: list[tuple[dict[str, int], set[str]]]) -> None:
        """Dallar birleşirken yalnız tüm canlı dallarda aynı kalan önek bilgisi korunur."""
        if not results:
            self.prefix_params, self.host_fixed = dict(start[0]), set(start[1])
            return
        params = dict(results[0][0])
        for other, _hosts in results[1:]:
            params = {name: index for name, index in params.items() if other.get(name) == index}
        hosts = set(results[0][1])
        for _other, other_hosts in results[1:]:
            hosts &= other_hosts
        self.prefix_params, self.host_fixed = params, hosts

    def _is_str_expr(self, value: ast.AST | None) -> bool:
        """İfadenin dize ürettiği biliniyor mu? (sabit dize, f-dize, dize birleştirme, .format/.join)."""
        if isinstance(value, ast.Constant):
            return isinstance(value.value, str)
        if isinstance(value, ast.JoinedStr):
            return True
        if isinstance(value, ast.BinOp) and isinstance(value.op, (ast.Add, ast.Mod)):
            return self._is_str_expr(value.left) or (isinstance(value.op, ast.Add) and self._is_str_expr(value.right))
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and value.func.attr in {"format", "join"}:
            return True
        if isinstance(value, ast.Call) and _dotted(value.func) == "str":
            return True
        if isinstance(value, ast.Name):
            return self.shapes.get(value.id) == "str"
        return False

    def _html_response_body(self, value: ast.AST) -> ast.AST | None:
        """Rota dönüşü HTML olarak sunulan bir dize mi? (Flask/FastAPI'de düz str → text/html).

        dict/list/jsonify/render_template dönüşleri (JSON veya otomatik kaçışlı şablon) hariç."""
        if isinstance(value, ast.Tuple) and value.elts:
            return self._html_response_body(value.elts[0])
        if isinstance(value, (ast.JoinedStr, ast.BinOp)):
            return value
        if isinstance(value, ast.Call):
            name = _dotted(value.func)
            last = name.rsplit(".", 1)[-1]
            if last in {"make_response", "HttpResponse"} and value.args:
                return self._html_response_body(value.args[0])
            if isinstance(value.func, ast.Attribute) and value.func.attr == "format":
                return value
            return None
        if isinstance(value, ast.Name):
            # Biçimi bilinmeyen ad dönüşü (ör. FastAPI modeli) hedef değil; yalnız dize olduğu biliniyorsa.
            return value if self.shapes.get(value.id) == "str" else None
        return None

    def _receiver_matches(self, model: taint_models.SinkModel, owner: ast.AST) -> bool:
        if not model.receiver_calls:
            return True
        while isinstance(owner, ast.BinOp) and isinstance(owner.op, ast.Div):
            owner = owner.left
        if isinstance(owner, ast.Call):
            return _dotted(owner.func) in model.receiver_calls
        if isinstance(owner, ast.Name):
            return self.ctors.get(owner.id, "") in model.receiver_calls
        return False

    def _check_model_sinks(self, node: ast.Call, name: str, args: list[Taint],
                           kwargs: dict[str | None, Taint], receiver: Taint) -> None:
        models: list[taint_models.SinkModel] = []
        for alias in self._model_names(node, name):
            models.extend(model for model in self.p.models.sinks_for(alias) if model not in models)
        for model in models:
            keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}
            if any(_literal(value) in model.safe_keyword_values[key]
                   for key, value in keywords.items() if key in model.safe_keyword_values):
                continue
            if model.safe_keyword_values and any(
                _literal(arg) in values for arg in node.args[1:] for values in model.safe_keyword_values.values()
            ):
                continue
            if model.required_keyword_values and not all(
                key in keywords and _literal(keywords[key]) in values
                for key, values in model.required_keyword_values.items()
            ):
                continue
            parts: list[Taint] = []
            arg_nodes: list[ast.AST] = []
            for index in model.args:
                if index < len(args) and not any(isinstance(a, ast.Starred) for a in node.args[: index + 1]):
                    parts.append(args[index])
                    arg_nodes.append(node.args[index])
            for key in model.keywords:
                if key in kwargs:
                    parts.append(kwargs[key])
                    arg_nodes.append(keywords[key])
            if model.receiver:
                if not isinstance(node.func, ast.Attribute) or not self._receiver_matches(model, node.func.value):
                    continue
                parts.append(receiver)
            if not parts:
                continue
            full_taint = _union(*parts)
            if model.kind in _PREFIX_SUMMARY_KINDS:
                for position, arg_node in enumerate(arg_nodes):
                    before_query = self._pre_query_taint(arg_node)
                    if before_query is not None:
                        parts[position] = before_query
            taint = _union(*parts)
            if model.kind == "redirect" and arg_nodes and all(self._redirect_prefix_clean(arg) for arg in arg_nodes):
                taint = _EMPTY
            partial = False
            if model.kind == "ssrf" and arg_nodes and all(_fixed_url_prefix(arg) for arg in arg_nodes):
                taint = _EMPTY
                partial = True
            prefix_param = -1
            if (taint or partial) and model.kind in _PREFIX_SUMMARY_KINDS and arg_nodes:
                states = {self._prefix_state(arg, model.kind) for arg in arg_nodes}
                params = {state for state in states if isinstance(state, int)}
                if states == {"clean"}:
                    partial = partial or (model.kind == "ssrf" and bool(taint))
                    taint = _EMPTY  # güvenli önek döndüren yardımcı / sabit ana makineli değişken
                elif "env" in states and states <= {"clean", "env"}:
                    # Ana makine ortam değişkeninden (operatör ayarı): doğrulanamaz → belirsiz hedef.
                    taint = (_Origin(_UNCERTAIN, "?", node.lineno, (), frozenset(), self.m.relpath),)
                elif None not in states and len(params) == 1:
                    prefix_param = params.pop()
            if partial and not taint:
                # Ana makine sabit; girdi yalnız yol/sorgu bileşeninde (kısmi SSRF). Tam SSRF olarak
                # değerlendirildi (hotspot düşürme), akış ayrı sınıfta raporlanır.
                self.p.mark_evaluated(self.m.relpath, "ssrf", node.lineno)
                self._emit("ssrf_partial", name, node.lineno, full_taint)
                continue
            self._emit(model.kind, name, node.lineno, taint, prefix_param)

    def _check_sink(self, node: ast.Call, name: str, args: list[Taint], kwargs: dict[str | None, Taint],
                    receiver: Taint = _EMPTY) -> None:
        if not name:
            return
        line = node.lineno
        last = name.rsplit(".", 1)[-1]
        base = name.rsplit(".", 1)[0] if "." in name else ""
        if last in _PY_LOG_METHODS and base and "log" in base.lower():
            offset = 1 if last == "log" else 0
            nodes = node.args[offset:]
            values = list(args[offset:])
            fmt = nodes[0] if nodes else None
            if isinstance(fmt, ast.Constant) and isinstance(fmt.value, str) and len(values) > 1:
                conversions = [c for c in _PRINTF_RE.findall(fmt.value) if c != "%"]
                for position, conversion in enumerate(conversions, 1):
                    # %r/%a repr uygular, sayısal dönüşümler metin enjeksiyonuna izin vermez.
                    if position < len(values) and conversion != "s":
                        values[position] = _clean(values[position], frozenset({"log"}))
            message_kwargs = [taint for key, taint in kwargs.items() if key not in _LOG_NON_MESSAGE_KWARGS]
            self._emit("log", name, line, _union(*values, *message_kwargs))
        elif name == "print":
            self._emit("log", name, line, _union(*args))
        elif last in _PY_SQL_METHODS and base:
            if args:
                self._emit("sql", name, line, args[0])
        elif name in {"text", "sqlalchemy.text", "sql.text"} and args:
            self._emit("sql", name, line, args[0])
        elif name in {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput"} and args:
            self._emit("command", name, line, args[0])
        elif name in _PY_SUBPROCESS and args:
            shell = next((kw for kw in node.keywords if kw.arg == "shell"), None)
            if shell is not None and isinstance(shell.value, ast.Constant) and shell.value.value is True:
                self._emit("command", name, line, args[0])
            elif self._is_shell_argv(node.args[0]):
                # ["sh", "-c", komut] biçimi: kabuk yorumlaması shell=True ile eşdeğer.
                self._emit("command", name, line, args[0])
        elif name in {"eval", "exec"} and args:
            self._emit("eval", name, line, args[0])
        elif name in {"Markup", "markupsafe.Markup", "mark_safe", "django.utils.safestring.mark_safe"} and args:
            self._emit("html", name, line, args[0])
        elif base in {"re", "regex"} and last in _PY_REGEX_FUNCS and args:
            self._emit("regex", name, line, args[0])
        else:
            self._check_html_response(node, name, args, kwargs)
        self._check_template_render(node, name)
        self._check_model_sinks(node, name, args, kwargs, receiver)

    def _render_target(self, node: ast.Call, name: str) -> tuple[str, ast.AST | None, ast.AST | None, bool] | None:
        """Şablon işleme çağrısı mı? (çatı, şablon adı düğümü, bağlam düğümü, istek bağlamı var mı)."""
        canonical = self._canonical(name)
        spec = _DJANGO_RENDER_CALLS.get(canonical)
        if spec is not None:
            name_index, context_index, with_request = spec
            template = node.args[name_index] if len(node.args) > name_index else next(
                (kw.value for kw in node.keywords if kw.arg in {"template_name", "template"}), None)
            context = node.args[context_index] if len(node.args) > context_index else next(
                (kw.value for kw in node.keywords if kw.arg in {"context", "dictionary"}), None)
            return ("django", template, context, with_request)
        if canonical in _FLASK_RENDER_CALLS:
            template = node.args[0] if node.args else next(
                (kw.value for kw in node.keywords if kw.arg == "template_name_or_list"), None)
            return ("flask", template, None, True)
        return None

    def _context_taints(self, context: ast.AST | None) -> dict[str, Taint] | None:
        """Şablon bağlamı: anahtar → taint (anahtarları bilinmeyen bağlam için None)."""
        if context is None:
            return {}
        if isinstance(context, ast.Dict):
            result: dict[str, Taint] = {}
            for key, value in zip(context.keys, context.values):
                if key is None:
                    spread = self._context_taints(value)
                    if spread is None:
                        return None
                    result.update(spread)
                elif isinstance(key, ast.Constant) and isinstance(key.value, str):
                    result[key.value] = self._context_value(value)
                else:
                    return None
            return result
        if isinstance(context, ast.Name) and context.id in self.dict_fields:
            prefix = f"{context.id}["
            return {
                key[len(prefix):-1].strip("'\""): taint for key, taint in self.env.items()
                if key.startswith(prefix) and key.endswith("]")
            }
        if isinstance(context, ast.Call) and _dotted(context.func) == "locals" and not context.args:
            return {key: taint for key, taint in self.env.items() if "." not in key and "[" not in key}
        if isinstance(context, ast.Call) and _dotted(context.func) == "dict" and not context.args:
            return {kw.arg: self._context_value(kw.value) for kw in context.keywords if kw.arg}
        return None

    def _context_value(self, value: ast.AST) -> Taint:
        dotted = _dotted(value)
        if dotted and dotted.rsplit(".", 1)[0] in _PY_REQUEST_ROOTS and dotted.endswith(".user"):
            # Oturum açmış kullanıcı nesnesi: ad/e-posta alanları kayıt sırasında kullanıcıdan gelir (saklı veri).
            return self._source("stored", f"{dotted} (kullanıcı kaydı)", getattr(value, "lineno", 0))
        return self.expr(value)

    def _check_template_render(self, node: ast.Call, name: str) -> None:
        """Django ``render``/``TemplateResponse``/``render_to_string`` ve Flask/Quart ``render_template``: şablonda
        kaçışsız basılan (``|safe``, ``autoescape off``) bağlam değişkenine ulaşan istek/saklı veri (XSS)."""
        if not self.p.template_inventory or not name:
            return
        target = self._render_target(node, name)
        if target is None:
            return
        framework, template_node, context_node, with_request = target
        template = self._const(template_node) if template_node is not None else None
        if not isinstance(template, str) or not template:
            return
        relpath = taint_py_views.resolve_template(template, self.m.relpath, self.p.template_inventory)
        if relpath is None:
            return
        outputs = self.p.template_outputs(relpath, self.m)
        if not outputs:
            return
        if framework == "flask":
            context: dict[str, Taint] | None = {}
            for keyword in node.keywords:
                if keyword.arg is None:
                    spread = self._context_taints(keyword.value)
                    if spread is None:
                        context = None
                        break
                    context.update(spread)
                elif keyword.arg != "template_name_or_list":
                    context[keyword.arg] = self._context_value(keyword.value)
        else:
            context = self._context_taints(context_node)
        if context is None:
            return
        short = name.rsplit(".", 1)[-1]
        for tpl, tline, shown, paths, url_only in outputs:
            taint: Taint = _EMPTY
            for path in paths:
                root = path[0]
                if root in context:
                    part = context[root]
                elif root == "request" and with_request and len(path) > 1 and path[1] in _TEMPLATE_REQUEST_ATTRS:
                    part = self._source("request", f"şablonda request.{path[1]}", node.lineno)
                elif root == "user" and framework == "django" and with_request and len(path) > 1 \
                        and path[1] in _USER_TEXT_FIELDS:
                    part = self._source("stored", "request.user (kullanıcı kaydı, bağlam işlemcisi)", node.lineno)
                else:
                    continue
                if any(o.label == "stored" and "kullanıcı kaydı" in o.source for o in part) and \
                        (len(path) < 2 or path[1] not in _USER_TEXT_FIELDS):
                    part = tuple(o for o in part if not (o.label == "stored" and "kullanıcı kaydı" in o.source))
                taint = _union(taint, part)
            if url_only:
                # Kaçışlı URL özniteliği (javascript: adresi): yalnız doğrudan istek verisi.
                taint = tuple(o for o in taint if o.label in {"request", _PARAM, _FIELD})
            if taint and all(o.label == "stored" and "kullanıcı kaydı" in o.source for o in taint):
                # Oturumdaki kullanıcı adı ortak (base) şablonda basılıyorsa her görünüm aynı açığı tekrarlar:
                # şablon satırı başına projede bir kez (ilk görünüm) raporlanır.
                first = self.p.implicit_user_outputs.setdefault((tpl, tline), (self.m.relpath, node.lineno))
                if first != (self.m.relpath, node.lineno):
                    continue
            if taint:
                self._emit("html", f"{short}('{template}') → {tpl}:{tline} {shown}", node.lineno, taint)

    def _check_html_response(self, node: ast.Call, name: str, args: list[Taint], kwargs: dict[str | None, Taint]) -> None:
        """Yanıt gövdesi text/html olan yanıt nesneleri (yansıtılmış XSS):

        * Django ``HttpResponse(icerik)`` ve 4xx/5xx türevleri — varsayılan içerik türü text/html; içerik türü
          HTML dışı bir sabitse (JSON, düz metin) hedef değil;
        * aiohttp ``web.Response(text=…/body=…, content_type="text/html")`` — yalnız açık HTML içerik türüyle
          (aiohttp ``text=`` varsayılanı text/plain)."""
        canonical = self._canonical(name)
        last = canonical.rsplit(".", 1)[-1]
        if id(node) in self.non_html_response_calls:
            return  # yanıta sonradan ek/HTML dışı içerik türü atanıyor: tarayıcı belgeyi HTML olarak işlemez
        if last in _DJANGO_HTML_RESPONSES and canonical.startswith("django."):
            content_type = node.args[1] if len(node.args) > 1 else next(
                (kw.value for kw in node.keywords if kw.arg == "content_type"), None)
            if content_type is not None and not _is_html_content_type(content_type):
                return
            body = args[0] if node.args and not isinstance(node.args[0], ast.Starred) else kwargs.get("content")
            if body:
                self._emit("html", last, node.lineno, body)
        elif canonical in _AIOHTTP_RESPONSES:
            content_type = next((kw.value for kw in node.keywords if kw.arg == "content_type"), None)
            if content_type is None or not _is_html_content_type(content_type):
                return
            body = _union(kwargs.get("text", _EMPTY), kwargs.get("body", _EMPTY))
            if body:
                self._emit("html", "web.Response", node.lineno, body)

    # -- doğrulama koşulları (bariyerler) -------------------------------------------
    def _guard(self, test: ast.AST) -> tuple[Guard, Guard]:
        """(koşul doğruysa, koşul yanlışsa) arındırılan adlar ve hedef türleri."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            when_true, when_false = self._guard(test.operand)
            return when_false, when_true
        if isinstance(test, ast.BoolOp):
            if isinstance(test.op, ast.And):
                return [entry for value in test.values for entry in self._guard(value)[0]], []
            when_false = [entry for value in test.values for entry in self._guard(value)[1]]
            return [], when_false + self._quoted_literal_guard(test.values)
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            op, left, right = test.ops[0], test.left, test.comparators[0]
            if isinstance(op, (ast.In, ast.NotIn)) and isinstance(left, ast.Constant) and left.value in {"'", '"'}:
                # Tırnak içermeyen değer, aynı tırnakla sınırlanmış XPath değişmezinden taşamaz.
                entry = [(name, frozenset({"xpath"})) for name in _guard_names(right)]
                return ([], entry) if isinstance(op, ast.In) else (entry, [])
            if isinstance(op, (ast.In, ast.NotIn)):
                if _is_constant_collection(right):
                    entry = [(name, _ALL_KINDS) for name in _guard_names(left)]
                    return (entry, []) if isinstance(op, ast.In) else ([], entry)
                if isinstance(left, ast.Constant) and left.value in _PATH_TRAVERSAL_LITERALS:
                    entry = [(name, frozenset({"path"})) for name in _guard_names(right)]
                    return ([], entry) if isinstance(op, ast.In) else (entry, [])
            if isinstance(op, (ast.Eq, ast.NotEq)) and (isinstance(right, ast.Constant) or isinstance(left, ast.Constant)):
                other = left if isinstance(right, ast.Constant) else right
                entry = [(name, _ALL_KINDS) for name in _guard_names(other)]
                return (entry, []) if isinstance(op, ast.Eq) else ([], entry)
            return [], []
        if isinstance(test, ast.Call):
            fname = _dotted(test.func)
            last = fname.rsplit(".", 1)[-1] if fname else ""
            if isinstance(test.func, ast.Attribute):
                if last in _PY_GUARD_PREDICATES:
                    return [(name, _ALL_KINDS) for name in _guard_names(test.func.value)], []
                if last == "startswith":
                    return [(name, _PREFIX_KINDS) for name in _guard_names(test.func.value)], []
                if last == "fullmatch" and test.args and fname not in {"re.fullmatch", "regex.fullmatch"}:
                    return [(name, _ALL_KINDS) for name in _guard_names(test.args[0])], []
            if fname in {"re.fullmatch", "regex.fullmatch"} and len(test.args) >= 2:
                return [(name, _ALL_KINDS) for name in _guard_names(test.args[1])], []
            if fname in {"re.match", "regex.match"} and len(test.args) >= 2:
                pattern = test.args[0]
                if isinstance(pattern, ast.Constant) and isinstance(pattern.value, str) and pattern.value.endswith(("$", r"\Z", r"\z")):
                    return [(name, _ALL_KINDS) for name in _guard_names(test.args[1])], []
            if fname == "isinstance" and len(test.args) == 2:
                types = test.args[1].elts if isinstance(test.args[1], ast.Tuple) else [test.args[1]]
                if types and all(_dotted(t) in _PY_SAFE_TYPES for t in types):
                    return [(name, _ALL_KINDS) for name in _guard_names(test.args[0])], []
            values = [*test.args, *(kw.value for kw in test.keywords)]
            if last and _PY_VALIDATOR_RE.search(last) and values:
                # Dosya adı/uzantı denetimi (allowed_file, valid_extension): türü doğrular, yol aşımını (../) değil.
                kinds = _ALL_KINDS - {"path"} if _FILE_TYPE_VALIDATOR_RE.search(last) else _ALL_KINDS
                return [(name, kinds) for arg in values for name in _guard_names(arg)], []
        return [], []

    @staticmethod
    def _quoted_literal_guard(values: list[ast.AST]) -> Guard:
        """``not x.startswith(Q) or not x.endswith(Q) or Q in x[1:-1]`` → (yanlışsa) x tırnaklı düz
        bir dize değişmezidir: eval/exec yalnız bu dizeyi üretir (kod çalıştıramaz)."""
        starts: dict[str, set[str]] = {}
        ends: dict[str, set[str]] = {}
        inner: dict[str, set[str]] = {}
        for value in values:
            negated = isinstance(value, ast.UnaryOp) and isinstance(value.op, ast.Not)
            core = value.operand if negated else value
            if negated and isinstance(core, ast.Call) and isinstance(core.func, ast.Attribute) and core.func.attr in {"startswith", "endswith"} \
                    and len(core.args) == 1 and isinstance(core.args[0], ast.Constant) and core.args[0].value in {"'", '"'}:
                target = _dotted(core.func.value)
                (starts if core.func.attr == "startswith" else ends).setdefault(target, set()).add(core.args[0].value)
            elif not negated and isinstance(core, ast.Compare) and len(core.ops) == 1 and isinstance(core.ops[0], ast.In) \
                    and isinstance(core.left, ast.Constant) and core.left.value in {"'", '"'} and isinstance(core.comparators[0], ast.Subscript):
                target = _dotted(core.comparators[0].value)
                inner.setdefault(target, set()).add(core.left.value)
        return [(name, frozenset({"eval"})) for name in starts
                if name and starts[name] & ends.get(name, set()) & inner.get(name, set())]

    def _apply_guard(self, entries: Guard) -> None:
        for name, kinds in entries:
            taint = self.env.get(name)
            if taint:
                self.env[name] = _clean(taint, kinds)
            # url = urlparse(x) / p = realpath(x) doğrulandıysa x de yol/SSRF/yönlendirme için doğrulanmıştır.
            source = self.derived.get(name.split(".")[0])
            if source and self.env.get(source):
                self.env[source] = _clean(self.env[source], kinds & _PREFIX_KINDS or kinds & frozenset({"path", "ssrf", "redirect"}))

    # -- atama ve deyimler ------------------------------------------------------
    def assign(self, target: ast.AST, taint: Taint) -> None:
        if isinstance(target, ast.Name):
            self.prefix_params.pop(target.id, None)
            self.host_fixed.discard(target.id)
            self.env_prefixed.discard(target.id)
            self.env[target.id] = _via(taint, target.id) if taint else _EMPTY
            self._write_global(target.id, taint)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.assign(element, taint)
        elif isinstance(target, ast.Starred):
            self.assign(target.value, taint)
        elif isinstance(target, ast.Attribute):
            dotted = _dotted(target)
            if dotted:
                self.env[dotted] = _via(taint, dotted) if taint else _EMPTY
            if any(o.label == "request" for o in taint) and not (
                    isinstance(target.value, ast.Name) and target.value.id in ("request", "session", "g", "response")):
                self.p.user_written_attrs.add(target.attr)
                self.p.user_written_sites.setdefault(target.attr, (self.m.relpath, getattr(target, "lineno", 0)))
            if isinstance(target.value, ast.Name):
                owner = target.value.id
                if owner == self.self_name and self.summary is not None:
                    self.summary.add_field_write(target.attr, _via(taint, dotted) if taint else _EMPTY)
                elif self.summary is not None and owner in self.summary.params:
                    self.summary.add_param_field_write(
                        self.summary.params.index(owner), target.attr,
                        _via(taint, dotted) if taint else _EMPTY,
                        strong=self.control_depth == 0,
                    )
                elif owner in self.obj_fields or owner in self.types:
                    self.obj_fields.setdefault(owner, {})[target.attr] = taint
        elif isinstance(target, ast.Subscript):
            container = _dotted(target.value)
            key_value = self._const(target.slice)
            if container in self.dict_fields:
                if isinstance(key_value, str):
                    self.env[f"{container}[{key_value!r}]"] = _via(taint, container) if taint else _EMPTY
                else:
                    self.dict_fields.discard(container)
            if container and "." not in container and key_value is _CONST_UNKNOWN and not isinstance(target.slice, ast.Slice):
                # d[girdi] = v: sözlük anahtarı girdiden (Mongo filtresinde alan/operatör adı saldırganın).
                key_taint = _live(self.expr(target.slice), "nosql_key")
                if key_taint:
                    self.dict_key_taint[container] = _union(self.dict_key_taint.get(container, _EMPTY),
                                                            _operator_marked(tuple(key_taint)))
            elif container and isinstance(key_value, str) and key_value in _MONGO_CODE_OPERATORS and taint:
                self.dict_key_taint[container] = _union(self.dict_key_taint.get(container, _EMPTY), _operator_marked(taint))
            if container and container.lower().rsplit(".", 1)[-1].endswith("session"):
                # Oturuma yazma (değer veya anahtar): güven sınırı / zayıf rastgele değer hedefi.
                self._emit("session", f"{container}[…]", getattr(target, "lineno", 0), _union(taint, self.expr(target.slice)))
            if container and taint:
                self.env[container] = _union(self.env.get(container, _EMPTY), _via(taint, container))
                if "." not in container:
                    self._write_global(container, taint)

    def _returned_object_fields(self, value: ast.Call) -> list[dict[str, Taint]]:
        """Tracked caller object maps returned by a project helper call."""
        effect = self.call_effects.get(id(value))
        call = self.call_args.get(id(value))
        if effect is None or call is None:
            return []
        returned: list[dict[str, Taint]] = []
        for index in sorted(effect[0].ret_object_params):
            argument = call[1].get(index)
            if isinstance(argument, ast.Name) and argument.id in self.obj_fields:
                returned.append(self.obj_fields[argument.id])
        if 0 in effect[0].ret_object_params and 0 not in call[1] \
                and isinstance(value.func, ast.Attribute) \
                and isinstance(value.func.value, ast.Name) \
                and value.func.value.id in self.obj_fields:
            returned.append(self.obj_fields[value.func.value.id])
        unique: list[dict[str, Taint]] = []
        seen: set[int] = set()
        for fields in returned:
            if id(fields) not in seen:
                seen.add(id(fields))
                unique.append(fields)
        return unique

    def _object_param_origins(self, value: ast.AST | None, depth: int = 0) -> frozenset[int]:
        """Function parameters whose object identity the expression retains."""
        if value is None or depth > 6:
            return frozenset()
        if isinstance(value, ast.Name):
            return self.object_param_aliases.get(value.id, frozenset())
        if isinstance(value, ast.IfExp):
            return self._object_param_origins(value.body, depth + 1) | self._object_param_origins(
                value.orelse, depth + 1
            )
        if not isinstance(value, ast.Call):
            return frozenset()
        effect = self.call_effects.get(id(value))
        call = self.call_args.get(id(value))
        if effect is None or call is None:
            return frozenset()
        origins: set[int] = set()
        arguments = call[1]
        for inner_index in effect[0].ret_object_params:
            argument = arguments.get(inner_index)
            if argument is not None:
                origins.update(self._object_param_origins(argument, depth + 1))
                continue
            # A bound instance method does not carry self in call.args.
            # Map its parameter zero back to the receiver expression.
            if inner_index == 0 and isinstance(value.func, ast.Attribute):
                origins.update(self._object_param_origins(value.func.value, depth + 1))
        return frozenset(origins)

    def _record_constructor(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == self.self_name \
                and self.summary is not None and isinstance(value, ast.Call):
            cls = self._resolve_class(value.func)
            if cls is not None:
                self.summary.field_types[target.attr] = cls
        if not isinstance(target, ast.Name):
            return
        object_params = self._object_param_origins(value)
        self.object_param_aliases.pop(target.id, None)
        if object_params:
            self.object_param_aliases[target.id] = object_params
        alias_fields = self.obj_fields.get(value.id) if isinstance(value, ast.Name) else None
        alias_type = self.types.get(value.id) if isinstance(value, ast.Name) else None
        alias_ext_type = self.ext_types.get(value.id) if isinstance(value, ast.Name) else None
        alias_ctor = self.ctors.get(value.id) if isinstance(value, ast.Name) else None
        alias_element = self.elem_types.get(value.id) if isinstance(value, ast.Name) else None
        alias_request = isinstance(value, ast.Name) and value.id in self.request_roots
        self.obj_aliases.discard(target.id)
        self.obj_fields.pop(target.id, None)
        if alias_fields is not None:
            # Python assignment aliases the object; sharing the exact field map
            # also makes later strong writes visible through every alias.
            self.obj_fields[target.id] = alias_fields
            self.obj_aliases.update((target.id, value.id))
        elif isinstance(value, ast.Call) and id(value) in self.call_effects:
            summary, bound, label, receiver, _self_call = self.call_effects[id(value)]
            if receiver is None:  # kurucu: __init__'in yazdığı alanlar yeni nesnenin durumu
                self.obj_fields[target.id] = {
                    field: self._map_effect(taint, bound, {}, label) for field, taint in summary.field_writes.items()
                }
            if summary.ret_object_params:
                call = self.call_args.get(id(value))
                returned = self._returned_object_fields(value)
                if len(returned) == 1:
                    self.obj_fields[target.id] = returned[0]
                    self.obj_aliases.add(target.id)
                    if call is not None:
                        for index in summary.ret_object_params:
                            arg = call[1].get(index)
                            if isinstance(arg, ast.Name) and self.obj_fields.get(arg.id) is returned[0]:
                                self.obj_aliases.add(arg.id)
                elif returned:
                    fields: dict[str, Taint] = {}
                    for item in returned:
                        for field, taint in item.items():
                            fields[field] = _union(fields.get(field, _EMPTY), taint)
                    self.obj_fields[target.id] = fields
        container = isinstance(value, (ast.Dict, ast.List, ast.DictComp, ast.ListComp, ast.Set, ast.Tuple)) or (
            isinstance(value, ast.Call) and _dotted(value.func).rsplit(".", 1)[-1] in {"jsonify", "dict", "list", "render_template", "JSONResponse"}
        )
        if container:
            self.shapes[target.id] = "container"
        elif self._is_str_expr(value):
            self.shapes[target.id] = "str"
        else:
            self.shapes.pop(target.id, None)
        self.ctors.pop(target.id, None)
        self.types.pop(target.id, None)
        self.ext_types.pop(target.id, None)
        self.request_roots.discard(target.id)
        self.elem_types.pop(target.id, None)
        if alias_type is not None:
            self.types[target.id] = alias_type
        if alias_ext_type is not None:
            self.ext_types[target.id] = alias_ext_type
        if alias_ctor is not None:
            self.ctors[target.id] = alias_ctor
        if alias_element is not None:
            self.elem_types[target.id] = alias_element
        if alias_request:
            self.request_roots.add(target.id)
        if isinstance(value, ast.Call):
            self.ctors[target.id] = _dotted(value.func)
            ext = self._call_class(value.func)
            if ext:
                self.ext_types[target.id] = ext
            cls = self._resolve_class(value.func)
            if cls is not None:
                self.types[target.id] = cls
            elif id(value) in self.call_effects and self.call_effects[id(value)][0].ret_class is not None:
                # Fabrika/yardımcı fonksiyonun döndürdüğü sınıf (dönüş türü çıkarımı).
                self.types[target.id] = self.call_effects[id(value)][0].ret_class
            elif id(value) in self.call_args and not ext:
                # Proje fonksiyonunun dönüş tip açıklaması (-> Session / -> list[Repo]).
                fnode, _args, owner = self.call_args[id(value)]
                info = self.p._param_type(owner, fnode.returns) if fnode.returns is not None else None
                if info is not None:
                    self.apply_type(target.id, *info)

    def _record_callable(self, target: ast.AST, value: ast.AST) -> None:
        if not isinstance(target, ast.Name):
            return
        self.lambdas.pop(target.id, None)
        self.partials.pop(target.id, None)
        if isinstance(value, ast.Lambda):
            self.lambdas[target.id] = value
        elif isinstance(value, ast.Name) and value.id in self.lambdas:
            self.lambdas[target.id] = self.lambdas[value.id]
        elif isinstance(value, ast.Name) and value.id in self.partials:
            self.partials[target.id] = self.partials[value.id]
        else:
            partial = self._partial_call(value)
            if partial is not None and not (isinstance(partial[0], ast.Name) and partial[0].id == target.id):
                func, bound_args, bound_keywords = partial
                self.partials[target.id] = (
                    func,
                    [self.expr(arg) for arg in bound_args],
                    {keyword.arg: self.expr(keyword.value) for keyword in bound_keywords
                     if keyword.arg is not None},
                )

    def _assign_call_shape(self, target: ast.AST, value: ast.AST) -> None:
        """x, y = f() / d = f() (sabit anahtarlı sözlük): öğe düzeyinde atama."""
        effect = self.call_effects.get(id(value)) if isinstance(value, ast.Call) else None
        if effect is None:
            return
        summary = effect[0]
        if isinstance(target, (ast.Tuple, ast.List)) and isinstance(summary.ret_tuple, list) \
                and len(target.elts) == len(summary.ret_tuple) and not any(isinstance(e, ast.Starred) for e in target.elts):
            for element, part in zip(target.elts, summary.ret_tuple):
                self.assign(element, self._map_call_part(part, effect))
        elif isinstance(target, ast.Name) and isinstance(summary.ret_dict, dict):
            self.dict_fields.add(target.id)
            for key, part in summary.ret_dict.items():
                self.env[f"{target.id}[{key!r}]"] = self._map_call_part(part, effect)

    def _forget_loop_consts(self, node: ast.stmt) -> bool:
        """Döngüde yeniden atanan veya değiştirilen adlar sabit/öğe bazlı sayılmaz (birden çok yineleme)."""
        for child in fast_walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                self.consts.pop(child.id, None)
                self.list_items.pop(child.id, None)
            elif isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and isinstance(child.func.value, ast.Name):
                self.list_items.pop(child.func.value.id, None)
        return True

    def block(self, statements: list[ast.stmt]) -> None:
        for statement in statements:
            self.stmt(statement)

    @staticmethod
    def _merge(envs: list[dict[str, Taint]]) -> dict[str, Taint]:
        merged: dict[str, Taint] = {}
        for result in envs:
            for key, value in result.items():
                merged[key] = _union(merged.get(key, _EMPTY), value)
        return merged

    def _branch(self, *bodies: list[ast.stmt]) -> None:
        start = dict(self.env)
        start_prefix = self._prefix_snapshot()
        start_objects = dict(self.object_param_aliases)
        results = []
        prefixes = []
        object_results = []
        for body in bodies:
            self.env = dict(start)
            self.prefix_params, self.host_fixed = dict(start_prefix[0]), set(start_prefix[1])
            self.object_param_aliases = dict(start_objects)
            self.control_depth += 1
            try:
                self.block(body)
            finally:
                self.control_depth -= 1
            results.append((self.env, _terminates(body)))
            prefixes.append((self._prefix_snapshot(), _terminates(body)))
            object_results.append((dict(self.object_param_aliases), _terminates(body)))
        live = [env for env, terminated in results if not terminated] or [env for env, _ in results]
        self.env = self._merge(live)
        self._merge_prefix(start_prefix, [p for p, terminated in prefixes if not terminated] or [p for p, _ in prefixes])
        live_objects = [values for values, terminated in object_results if not terminated] or [
            values for values, _ in object_results
        ]
        self.object_param_aliases = {
            name: frozenset().union(*(values.get(name, frozenset()) for values in live_objects))
            for name in set().union(*(set(values) for values in live_objects))
        }

    def _if(self, node: ast.If) -> None:
        self.expr(node.test)
        decided = self._const(node.test)
        if decided is not _CONST_UNKNOWN:
            # Sabit koşul: yalnız çalışan dal (ölü dal ayıklama).
            self.block(node.body if decided else node.orelse)
            return
        when_true, when_false = self._guard(node.test)
        start_consts = dict(self.consts)
        start = dict(self.env)
        start_prefix = self._prefix_snapshot()
        start_objects = dict(self.object_param_aliases)
        results = []
        const_results = []
        prefixes = []
        object_results = []
        for body, guard in ((node.body, when_true), (node.orelse, when_false)):
            self.env = dict(start)
            self.consts = dict(start_consts)
            self.prefix_params, self.host_fixed = dict(start_prefix[0]), set(start_prefix[1])
            self.object_param_aliases = dict(start_objects)
            self._apply_guard(guard)
            self.control_depth += 1
            try:
                self.block(body)
            finally:
                self.control_depth -= 1
            results.append((self.env, _terminates(body)))
            const_results.append((self.consts, _terminates(body)))
            prefixes.append((self._prefix_snapshot(), _terminates(body)))
            object_results.append((dict(self.object_param_aliases), _terminates(body)))
        live = [env for env, terminated in results if not terminated] or [env for env, _ in results]
        self.env = self._merge(live)
        self._merge_prefix(start_prefix, [p for p, terminated in prefixes if not terminated] or [p for p, _ in prefixes])
        live_objects = [values for values, terminated in object_results if not terminated] or [
            values for values, _ in object_results
        ]
        self.object_param_aliases = {
            name: frozenset().union(*(values.get(name, frozenset()) for values in live_objects))
            for name in set().union(*(set(values) for values in live_objects))
        }
        live_consts = [c for c, terminated in const_results if not terminated] or [c for c, _ in const_results]
        self.consts = {k: v for k, v in live_consts[0].items() if all(k in c and c[k] == v for c in live_consts[1:])}

    def stmt(self, node: ast.stmt) -> None:
        self.p.tick()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if self.qual not in {"<module>", "<class>"}:
                # İç içe fonksiyon: adıyla yerel olarak çözülür, ayrıca kendi başına analiz edilir.
                self.local_funcs[node.name] = node
                self.p.extra.append((self.m, f"{self.qual}.<locals>.{node.name}", node, None))
            return
        if isinstance(node, ast.ClassDef):
            if self.qual == "<module>":
                _PyScope(self.p, self.m, {}, class_name=node.name, qual="<class>").block(node.body)
            else:
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.p.extra.append((self.m, f"{self.qual}.<locals>.{node.name}.{child.name}", child, None))
            return
        if isinstance(node, ast.Assign):
            taint = self.expr(node.value)
            for target in node.targets:
                if self.falcon_html_resp and isinstance(target, ast.Attribute) and target.attr in {"text", "body", "data"} \
                        and _dotted(target.value) == self.falcon_html_resp:
                    self._emit("html", f"resp.{target.attr}", node.lineno, taint)
                self.assign(target, taint)
                if isinstance(target, ast.Name) and isinstance(node.value, ast.Call) and \
                        _dotted(node.value.func).rsplit(".", 1)[-1] == "XMLParser" and _lxml_parser_unsafe(node.value):
                    # 18. tur: lxml XMLParser(resolve_entities=True / no_network=False / load_dtd / dtd_validation)
                    self.unsafe_xml_parsers.add(target.id)
                self._record_constructor(target, node.value)
                self._record_const(target, node.value)
                self._record_callable(target, node.value)
                self._assign_call_shape(target, node.value)
                if isinstance(target, ast.Name):
                    clean_call = isinstance(node.value, ast.Call) and not taint
                    if clean_call or self._redirect_prefix_clean(node.value):
                        self.prefix_clean.add(target.id)
                    else:
                        self.prefix_clean.discard(target.id)
                    self._record_prefix(target, node.value)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self.assign(node.target, self.expr(node.value))
                self._record_constructor(node.target, node.value)
                self._record_callable(node.target, node.value)
            if isinstance(node.target, ast.Name) and self.qual not in {"<module>", "<class>"}:
                info = self.p._param_type(self.m, node.annotation)
                if info is not None:
                    self.apply_type(node.target.id, *info)
            elif isinstance(node.target, ast.Attribute) and isinstance(node.target.value, ast.Name) \
                    and node.target.value.id == self.self_name and self.summary is not None \
                    and node.target.attr not in self.summary.field_types:
                info = self.p._param_type(self.m, node.annotation)
                if info is not None and not info[0] and info[1][0] == "class":
                    self.summary.field_types[node.target.attr] = info[1][1]
        elif isinstance(node, ast.AugAssign):
            taint = self.expr(node.value)
            current = self.expr(node.target)
            kept = self._prefix_snapshot() if isinstance(node.op, ast.Add) and isinstance(node.target, ast.Name) else None
            self.assign(node.target, _union(current, taint))
            if kept is not None:
                # x += y: ilk bileşen değişmez.
                name = node.target.id
                if name in kept[0]:
                    self.prefix_params[name] = kept[0][name]
                if name in kept[1]:
                    self.host_fixed.add(name)
            if isinstance(node.target, ast.Name) and not isinstance(node.op, ast.Add):
                self.shapes.pop(node.target.id, None)
                self.prefix_clean.discard(node.target.id)
            elif isinstance(node.target, ast.Name) and self._is_str_expr(node.value):
                # x += "<p>" + y: x dizedir (liste += dize nadir; HTML dönüşü tespiti için biçim).
                self.shapes[node.target.id] = "str"
            if isinstance(node.target, ast.Name):
                folded = self._const(ast.BinOp(left=node.target, op=node.op, right=node.value))
                if folded is _CONST_UNKNOWN:
                    self.consts.pop(node.target.id, None)
                else:
                    self.consts[node.target.id] = folded
        elif isinstance(node, ast.Return):
            parts: list[Taint] | dict[str, Taint] | None = None
            if isinstance(node.value, ast.Tuple) and not any(isinstance(e, ast.Starred) for e in node.value.elts):
                parts = [self.expr(element) for element in node.value.elts]
                taint = _union(*parts)
            elif isinstance(node.value, ast.Dict) and node.value.keys and all(
                    isinstance(k, ast.Constant) and isinstance(k.value, str) for k in node.value.keys):
                parts = {k.value: self.expr(v) for k, v in zip(node.value.keys, node.value.values)}
                taint = _union(*parts.values())
            else:
                taint = self.expr(node.value)
            if self.summary is not None:
                self.summary.add_return(taint)
                self.summary.add_return_shape(node.value, parts)
                # Keep argument-object identity through local aliases, fluent
                # receiver returns and chains of project helpers.
                self.summary.ret_object_params.update(self._object_param_origins(node.value))
                if node.value is not None and not (isinstance(node.value, ast.Constant) and node.value.value is None):
                    for kind in _PREFIX_SUMMARY_KINDS:
                        self.summary.add_return_prefix(kind, self._prefix_state(node.value, kind))
                returned_class = None
                if isinstance(node.value, ast.Call):
                    returned_class = self._resolve_class(node.value.func)
                elif isinstance(node.value, ast.Name):
                    returned_class = self.types.get(node.value.id)
                if returned_class is not None:
                    self.summary.ret_class = returned_class
            if self.html_route and node.value is not None:
                body = self._html_response_body(node.value)
                if body is not None:
                    self._emit("html", "return (HTML yanıt)", node.lineno, self.expr(body) if body is not node.value else taint)
        elif isinstance(node, ast.Assert):
            self.expr(node.test)
            self._apply_guard(self._guard(node.test)[0])
        elif isinstance(node, ast.If):
            self._if(node)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self._forget_loop_consts(node)
            iter_taint = self.expr(node.iter)
            # Döngüden taşınan taint için gövde, ortam değiştiyse bir kez daha işlenir
            # (her iç içe seviyede koşulsuz iki geçiş üstel büyürdü).
            element = self._element_type(node.iter)
            for _ in range(2):
                before = dict(self.env)
                self.assign(node.target, iter_taint)
                if element is not None and isinstance(node.target, ast.Name):
                    self.apply_type(node.target.id, False, element)
                self._branch(node.body, [])
                if self.env == before:
                    break
            self.block(node.orelse)
        elif isinstance(node, ast.While):
            self._forget_loop_consts(node)
            for _ in range(2):
                before = dict(self.env)
                self.expr(node.test)
                self._branch(node.body, [])
                if self.env == before:
                    break
            self.block(node.orelse)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                taint = self.expr(item.context_expr)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, taint)
                    self._record_constructor(item.optional_vars, item.context_expr)
            self.block(node.body)
        elif isinstance(node, ast.Try) or type(node).__name__ == "TryStar":
            self.block(node.body)
            self._branch(*([handler.body for handler in node.handlers] or [[]]), node.orelse)
            self.block(node.finalbody)
        elif isinstance(node, ast.Match if hasattr(ast, "Match") else ()):
            self.expr(node.subject)
            chosen = self._match_case(node)
            if chosen is not None:
                self.block(chosen)
            else:
                self.consts = {}
                self._branch(*[case.body for case in node.cases])
        else:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self.expr(child)
                elif isinstance(child, ast.stmt):
                    self.stmt(child)


# Şablon işleme çağrıları: kanonik ad → (şablon adı konumu, bağlam konumu, istek bağlamı/bağlam işlemcileri).
_DJANGO_RENDER_CALLS = {
    "django.shortcuts.render": (1, 2, True),
    "django.shortcuts.render_to_response": (0, 1, False),
    "django.template.response.TemplateResponse": (1, 2, True),
    "django.template.response.SimpleTemplateResponse": (0, 1, False),
    "django.template.loader.render_to_string": (0, 1, False),
}
_FLASK_RENDER_CALLS = frozenset({
    "flask.render_template", "flask.templating.render_template", "quart.render_template", "quart.templating.render_template",
})
_TEMPLATE_REQUEST_ATTRS = frozenset({
    "args", "form", "values", "GET", "POST", "path", "full_path", "url", "path_info", "query_string", "cookies",
    "COOKIES", "headers", "META", "get_full_path", "data", "json",
})
_USER_TEXT_FIELDS = frozenset({"username", "first_name", "last_name", "email", "get_full_name", "get_short_name",
                               "get_username", "name", "full_name", "display_name"})
# jinja2.Template / Environment.from_string mevcut "eval" modelinde (rules/taint/python.json); burada diğer motorlar.
_PY_SSTI_CALLS = frozenset({
    "tornado.template.Template", "mako.template.Template", "django.template.Template", "chameleon.PageTemplate",
    "chameleon.zpt.template.PageTemplate",
    # Flask: şablon metninin kendisi girdiden (render_template_string(f"…{request.path}"); jinja2.Template ayrıca
    # kod çalıştırma kuralıyla yakalanır)
    "flask.render_template_string", "render_template_string",
})
_UPLOAD_SOURCE_RE = re.compile(r"\bfiles\b|FILES|\.file\b|getlist", re.IGNORECASE)
_PY_DECODING_CALLS = frozenset({"unquote", "unquote_plus", "unquote_to_bytes", "unescape", "urllib.parse.unquote",
                                 "urllib.parse.unquote_plus", "html.unescape"})
_DJANGO_URL_FUNCS = frozenset({
    "django.urls.path", "django.urls.re_path", "django.conf.urls.url", "django.conf.urls.re_path",
    "django.urls.conf.path", "django.urls.conf.re_path",
})
_DJANGO_PATH_PARAM_RE = re.compile(r"<(?:(\w+):)?(\w+)>")
_REGEX_GROUP_RE = re.compile(r"\(\?P<(\w+)>((?:[^()\\]|\\.|\([^()]*\))*)\)")
# Yalnız rakam/kelime/tire karakteri kabul eden grup: HTML/SQL/yol metakarakteri taşıyamaz.
_SAFE_GROUP_RE = re.compile(r"^(?:\\d|\\w|\[[\w\\-]*\]|[\w-])+[+*]?(?:\{\d+(?:,\d*)?\})?$|^(?:\\d|\[0-9\])[+*]?$")
_PY_MONGO_PACKAGES = frozenset({"pymongo", "motor", "flask_pymongo", "mongoengine", "mongomock", "montydb"})
# DynamoDB istemci/tablo metotları ve metin olarak kurulduğunda enjeksiyona açık anahtar sözcükler.
_DYNAMO_METHODS = frozenset({
    "scan", "query", "get_item", "put_item", "update_item", "delete_item", "batch_get_item", "batch_write_item",
    "execute_statement", "batch_execute_statement", "execute_transaction", "transact_write_items", "transact_get_items",
})
_DYNAMO_EXPRESSION_KWARGS = frozenset({
    "FilterExpression", "KeyConditionExpression", "ConditionExpression", "UpdateExpression", "ProjectionExpression",
    "Statement",
})
_DYNAMO_LEGACY_FILTERS = frozenset({"ScanFilter", "QueryFilter", "KeyConditions"})


def _is_string_building(node: ast.AST) -> bool:
    """Dize birleştirme/biçimlendirme ifadesi mi? (f-dize, + / % ile birleştirme, .format) — koşul kurucu
    nesneler (boto3.dynamodb.conditions.Key('id').eq(x)) değerleri bağlar, hedef sayılmaz."""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return any(isinstance(side, (ast.Constant, ast.JoinedStr)) and not isinstance(getattr(side, "value", ""), (int, float))
                   or _is_string_building(side) for side in (node.left, node.right))
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format" \
        and isinstance(node.func.value, ast.Constant)
_PY_MONGO_METHODS = frozenset({
    "find_one", "find_one_and_update", "find_one_and_delete", "find_one_and_replace", "update_one", "update_many",
    "delete_one", "delete_many", "replace_one", "count_documents", "find",
})


def _django_route_text_params(pattern: str, is_path: bool) -> set[str]:
    """Django rota desenindeki serbest metin parametreleri."""
    names: set[str] = set()
    if is_path:
        for converter, name in _DJANGO_PATH_PARAM_RE.findall(pattern):
            if converter in {"", "str", "path"}:
                names.add(name)
        return names
    for name, group in _REGEX_GROUP_RE.findall(pattern):
        if not _SAFE_GROUP_RE.match(group):
            names.add(name)
    return names


def collect_python_templates(root: Path, skip_dirs: set[str] | frozenset[str]) -> dict[str, str]:
    """Proje içindeki ``templates``/``jinja2`` dizinlerinde bulunan sunucu tarafı şablonlar (sınırlı)."""
    found: dict[str, str] = {}
    total = 0
    try:
        for path in _walk_project_files(Path(root), frozenset(skip_dirs), frozenset(taint_py_views.TEMPLATE_EXTS)):
            relpath = path.relative_to(root).as_posix()
            if not any(part.lower() in taint_py_views.TEMPLATE_DIR_NAMES for part in PurePosixPath(relpath).parts[:-1]):
                continue
            if len(found) >= _MAX_PY_TEMPLATES:
                break
            text = read_text_bounded(path, 1_000_000)
            if text is None or "{{" not in text and "{%" not in text:
                continue
            total += len(text)
            if total > _MAX_PY_TEMPLATE_BYTES:
                break
            found[relpath] = text
    except (OSError, ValueError):
        pass
    return found


_MAX_PY_TEMPLATES = 4_000
_MAX_PY_TEMPLATE_BYTES = 40_000_000


def _typed_route_params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Flask ``<int:x>`` / ``<uuid:x>`` dönüştürücülü (metin olmayan) rota parametreleri."""
    names: set[str] = set()
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call):
            for arg in decorator.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    names.update(_FLASK_TYPED_PARAM_RE.findall(arg.value))
    return names


def _is_html_route(node: ast.FunctionDef | ast.AsyncFunctionDef, module: "_PyModule") -> bool:
    """Düz dize dönüşü text/html olan rota mı? Flask/Quart ``@x.route`` (ve Flask modülünde
    ``@app.get``) evet; FastAPI/Starlette (``@app.get``, ``api_route``, APIRouter) JSON döndürür,
    yalnız ``response_class=HTMLResponse`` ile HTML."""
    imports = set(module.imports.values())
    # FastAPI/Starlette ve Chalice: dize/sözlük dönüşü JSON'dur (Chalice varsayılan içerik türü application/json).
    fastapi = any(target.split(".")[0] in {"fastapi", "starlette", "chalice"} for target in imports)
    for decorator in node.decorator_list:
        if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)):
            continue
        response_class = next((kw.value for kw in decorator.keywords if kw.arg == "response_class"), None)
        if response_class is not None and _dotted(response_class).rsplit(".", 1)[-1] in {"HTMLResponse", "PlainTextResponse"}:
            return _dotted(response_class).endswith("HTMLResponse")
        attr = decorator.func.attr
        if attr == "route" and not fastapi:
            return True
        if attr in _PY_ROUTE_DECORATORS and attr != "api_route" and not fastapi and any(
                target.split(".")[0] in {"flask", "quart"} for target in imports):
            return True
    return False


def _is_route_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
            if decorator.func.attr in _PY_ROUTE_DECORATORS and _dotted(decorator.func.value):
                return True
    return False


def analyze_python(text: str, *, pii: PiiClassifier | None = None, filename: str = "") -> Analysis | None:
    """Tek dosyayı (dosya içi fonksiyonlar arası) analiz et.

    Python kaynağı ayrıştırılamazsa veya adım sınırı aşılırsa None döner (çağıran satır
    tabanlı moda düşer).
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return None
    project = _PyProject(pii)
    module = project.add_module(filename or "<inline>.py", tree)
    try:
        project.run()
    except RecursionError:
        return None
    project.mark_unknown_entry_sinks()
    return project.analysis_for(module.relpath)


_FLOW_FIELDS = ("language", "sink_kind", "sink", "line", "source", "source_label", "source_line", "via", "file", "source_file")


def _analyses_to_json(results: dict[str, Analysis]) -> dict[str, Any]:
    return {relpath: {
        "language": a.language,
        "flows": [[getattr(f, name) if name != "via" else list(f.via) for name in _FLOW_FIELDS] for f in a.flows],
        "evaluated": sorted([kind, line] for kind, line in a.evaluated_sinks),
        "uncertain": sorted([kind, line] for kind, line in a.uncertain_sinks),
        "analysis_complete": a.analysis_complete,
        "limitations": list(a.limitations),
    } for relpath, a in results.items()}


def _analyses_from_json(payload: Any, files: dict[str, str]) -> dict[str, Analysis] | None:
    """Önbellek kaydını doğrulayarak nesnelere çevir; biçim tutmazsa None (kayıt yok sayılır)."""
    def pairs(items: Any) -> set[tuple[str, int]]:
        if not isinstance(items, list) or not all(
                isinstance(i, list) and len(i) == 2 and isinstance(i[0], str) and type(i[1]) is int for i in items):
            raise ValueError
        return {(i[0], i[1]) for i in items}

    if not isinstance(payload, dict) or not set(payload) <= set(files):
        return None
    results: dict[str, Analysis] = {}
    try:
        for relpath, item in payload.items():
            if not isinstance(item, dict) or not isinstance(item.get("language"), str):
                return None
            flows = []
            for raw in item.get("flows", []):
                if not isinstance(raw, list) or len(raw) != len(_FLOW_FIELDS):
                    return None
                values = dict(zip(_FLOW_FIELDS, raw))
                if not all(type(values[k]) is int for k in ("line", "source_line")) or not isinstance(values["via"], list) \
                        or not all(isinstance(values[k], str) for k in _FLOW_FIELDS if k not in {"line", "source_line", "via"}) \
                        or not all(isinstance(v, str) for v in values["via"]):
                    return None
                values["via"] = tuple(values["via"])
                flows.append(Flow(**values))
            complete = item.get("analysis_complete", True)
            limitations = item.get("limitations", [])
            if not isinstance(complete, bool) or not isinstance(limitations, list) \
                    or not all(isinstance(value, str) for value in limitations):
                return None
            results[relpath] = Analysis(
                item["language"], flows, pairs(item.get("evaluated", [])), pairs(item.get("uncertain", [])), [],
                complete, tuple(limitations))
    except (ValueError, TypeError):
        return None
    return results


def analyze_python_files(files: dict[str, str], *, pii: PiiClassifier | None = None,
                         entrypoints: frozenset[str] = frozenset(),
                         templates: dict[str, str] | None = None) -> dict[str, Analysis] | None:
    """Birden çok dosyayı birlikte (dosyalar arası) analiz et: {göreli yol: kaynak}.

    PII sınıflandırıcısı verilmediğinde sonuç içerik özetiyle anahtarlanan disk önbelleğine
    (taint_cache) yazılır ve değişmemiş projede oradan okunur (sonuçlar özdeş)."""
    cache_key = None
    if pii is None:
        try:
            import taint_cache

            settings = {"file_steps": _PY_FILE_STEPS, "per_file": _PY_STEPS_PER_PROJECT_FILE,
                        "passes": _PyProject.MAX_PASSES, "specs": _PyProject.MAX_SPECIALIZATIONS,
                        "entrypoints": sorted(entrypoints),
                        "templates": hashlib.sha256(json.dumps(sorted((templates or {}).items())).encode(
                            "utf-8", errors="surrogatepass")).hexdigest()}
            if taint_cache.cache_dir(create=False) is not None or os.environ.get("SNIPER_DATA_DIR"):
                cache_key = taint_cache.project_key("python", files, settings)
                cached = _analyses_from_json(taint_cache.load(cache_key), files)
                if cached is not None:
                    return cached
        except Exception:  # önbellek hiçbir koşulda analizi bozmaz
            cache_key = None
    results = _analyze_python_files_uncached(files, pii, entrypoints, templates)
    if cache_key is not None and results is not None:
        try:
            import taint_cache

            taint_cache.store(cache_key, _analyses_to_json(results))
        except Exception:
            pass
    return results


_PATH_REFLECT_DECORATORS = frozenset({"errorhandler", "before_request", "after_request", "before_app_request",
                                      "after_app_request", "app_errorhandler", "teardown_request"})


def _path_reflects(fnode: ast.AST) -> bool:
    """Fonksiyonda request.path saldırgan denetiminde mi (hata işleyicisi, istek kancası, değişkenli rota)?"""
    for decorator in getattr(fnode, "decorator_list", ()):
        call = decorator if isinstance(decorator, ast.Call) else None
        name = _dotted(call.func if call is not None else decorator).rsplit(".", 1)[-1]
        if name in _PATH_REFLECT_DECORATORS:
            return True
        if call is not None and name in ("route", "get", "post", "put", "patch", "delete", "api_route") and call.args:
            rule = call.args[0]
            if isinstance(rule, ast.Constant) and isinstance(rule.value, str) and "<" in rule.value:
                return True
    return False


# Sayısal/tarih/kimlik sütunları istek verisiyle yazılsa da enjeksiyon taşımaz (tür dönüşümünden geçer).
_PY_CLEAN_COLUMN_RE = re.compile(r"(?:^id|_id|_at|_on|_date|_time|_count|_num|_number|^count|^created|^updated|"
                                 r"^age|^price|^amount|^quantity|^year|^month|^day)$")
_PY_STORED_COLUMN_RE = re.compile(r"\(\)\.(\w+)$")


def _user_written_note(attr: str, sites: dict[str, tuple[str, int]] | None) -> str:
    site = (sites or {}).get(attr)
    where = f"; yazıldığı yer: {site[0]}:{site[1]}" if site and site[1] else ""
    return f"{USER_WRITTEN_FIELD_MARK}: {attr}{where}"


def _mark_user_written_stored_flows(results: dict[str, "Analysis"], attrs: set[str],
                                    sites: dict[str, tuple[str, int]] | None = None) -> None:
    """25. tur: şablon dışı kayıtlı veri akışı (db.get(Report, id).name → SQL/komut/yol): okunan sütun projede istek
    verisiyle yazılan bir alansa (Report(name=istek)) akışa yazma kanıtı işareti konur (ikinci derece hedefler)."""
    for analysis in results.values():
        if analysis is None:
            continue
        changed = False
        for index, flow in enumerate(analysis.flows):
            if flow.source_label != "stored" or USER_WRITTEN_FIELD_MARK in flow.source:
                continue
            m = _PY_STORED_COLUMN_RE.search(flow.source)
            if not m:
                continue
            if m.group(1) in attrs and not _PY_CLEAN_COLUMN_RE.search(m.group(1)):
                source = f"{flow.source} ({_user_written_note(m.group(1), sites)})"
            else:
                # kanıt yok: sütun eki kaldırılır (kaynak metni ve bulgu parmak izi önceki turlarla aynı kalır)
                source = flow.source[:m.start() + 2]
            analysis.flows[index] = dataclasses.replace(flow, source=source)
            changed = True
        if changed:
            unique: dict[Any, Flow] = {}
            for flow in analysis.flows:
                unique.setdefault((flow.sink_kind, flow.line, flow.source, flow.source_line, flow.source_file, flow.sink),
                                  flow)
            analysis.flows[:] = list(unique.values())


def _mark_user_written_template_flows(results: dict[str, "Analysis"], attrs: set[str],
                                      sites: dict[str, tuple[str, int]] | None = None) -> None:
    """Şablonda kaçışsız basılan kayıtlı verinin alanı istek verisiyle yazılıyorsa akışa işaret koy."""
    if not attrs:
        return
    for analysis in results.values():
        if analysis is None:
            continue
        for index, flow in enumerate(analysis.flows):
            if flow.source_label != "stored" or flow.sink_kind != "html" or " → " not in flow.sink:
                continue
            m = _TEMPLATE_EXPR_RE.search(flow.sink.split(" → ", 1)[1])
            parts = m.group(1).split(".") if m else []
            if len(parts) >= 2 and parts[-1] in attrs:
                analysis.flows[index] = dataclasses.replace(
                    flow, source=f"{flow.source} ({_user_written_note(parts[-1], sites)})")


_PY_SAFE_MARKUP_CALLS = frozenset({"mark_safe", "Markup", "SafeString", "SafeText"})


def _add_user_written_safe_markup_flows(results: dict[str, "Analysis"], project: "_PyProject",
                                        texts: dict[str, str] | None = None) -> None:
    """Sınıf yönteminde ``mark_safe(self.alan)`` / ``Markup(self.alan)``: alan projede istek verisiyle yazılıyorsa
    kayıtlı verinin kaçışsız HTML olarak işaretlenmesi (kalıcı XSS) — nesne durumu çağıranda bilinmez, bu yüzden
    alan adı düzeyinde ayrıca denetlenir."""
    attrs = project.user_written_attrs
    if not attrs:
        return
    for relpath, module in project.modules.items():
        analysis = results.get(relpath)
        if analysis is None or not module.classes:
            continue
        text = (texts or {}).get(relpath)
        if text is not None and not any(name in text for name in _PY_SAFE_MARKUP_CALLS):
            continue  # çağrı adı kaynakta hiç geçmiyorsa sınıflar yürünmez (aynı sonuç)
        seen = {(f.line, f.sink_kind) for f in analysis.flows}
        for cls in module.classes.values():
            for node in fast_walk(cls):
                if not isinstance(node, ast.Call) or not node.args:
                    continue
                name = node.func.id if isinstance(node.func, ast.Name) else (
                    node.func.attr if isinstance(node.func, ast.Attribute) else "")
                arg = node.args[0]
                if name in _PY_SAFE_MARKUP_CALLS and isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name) \
                        and arg.value.id == "self" and arg.attr in attrs and (node.lineno, "html") not in seen:
                    analysis.flows.append(Flow(
                        "python", "html", name, node.lineno,
                        f"self.{arg.attr} ({_user_written_note(arg.attr, project.user_written_sites)})", "stored",
                        node.lineno, (),
                        relpath, relpath))
                    seen.add((node.lineno, "html"))


def _analyze_python_files_uncached(files: dict[str, str], pii: PiiClassifier | None,
                                   entrypoints: frozenset[str] = frozenset(),
                                   templates: dict[str, str] | None = None) -> dict[str, Analysis] | None:
    project = _PyProject(pii, max_steps=min(5_000_000, _PY_FILE_STEPS + _PY_STEPS_PER_PROJECT_FILE * len(files)),
                         entrypoints=entrypoints)
    project.sanitizer_version_scopes = _python_sanitizer_version_scopes(files)
    project.sanitizer_versions = project.sanitizer_version_scopes.get("", {})
    project.set_templates(templates or {})
    # Ayrıştırma ve çözümleme milyonlarca uzun ömürlü düğüm/özet üretir: döngüsel çöp toplayıcı bu
    # sırada defalarca tüm yığını tarıyordu (django: ayrıştırma süresinin ~%75'i). Motor döngüsel çöp
    # üretmez (ağaçlar/özetler analiz sonuna dek yaşar), bu yüzden toplayıcı analiz boyunca kapatılır;
    # önceki durumu geri yüklenir (iç içe/eşzamanlı çağrılarda yalnız açan çağrı yeniden açar).
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        ints: dict[int, int] = {}
        for relpath, text in files.items():
            try:
                tree = ast.parse(text)
            except (SyntaxError, ValueError, MemoryError, RecursionError):
                continue
            project.add_module(relpath, _slim_tree(tree, ints))
        tree = None
        try:
            project.run()
        except RecursionError:
            return None
        project.mark_unknown_entry_sinks()
        results = {relpath: project.analysis_for(relpath) for relpath in project.modules}
        _mark_user_written_template_flows(results, project.user_written_attrs, project.user_written_sites)
        _mark_user_written_stored_flows(results, project.user_written_attrs, project.user_written_sites)
        _add_user_written_safe_markup_flows(results, project, files)
        return results
    finally:
        # Ağaçlar ve özetler döngüsüzdür: toplayıcı kapalıyken referans sayımıyla serbest kalırlar.
        # Aksi halde toplayıcı açıldığında milyonlarca "genç" nesneyi birkaç kez tarardı (11 bin dosyada ~25 sn).
        project = None
        if was_enabled:
            gc.enable()


# ---------------------------------------------------------------------------
# JavaScript / TypeScript
# ---------------------------------------------------------------------------


@dataclass
class _Tok:
    kind: str  # id, num, str, tpl, regex, punct
    value: str
    line: int
    parts: list[list["_Tok"]] = field(default_factory=list)


_JS_PUNCTS = sorted(
    [
        ">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
        "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=",
        "%=", "&=", "|=", "^=", "**", "<<", ">>",
    ],
    key=len,
    reverse=True,
)
_JS_REGEX_PRECEDERS = frozenset({
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await",
})
_JS_ID_START = re.compile(r"[A-Za-z_$À-￿]")
_JS_ID_CHAR = re.compile(r"[A-Za-z0-9_$À-￿]")
# 19. tur hız: belirteç ayrıştırıcının karakter döngüsü yerine eşdeğer önceden derlenmiş eşleşmeler.
_JS_ID_RUN = re.compile(r"[A-Za-z0-9_$À-￿]*")
# _JS_PUNCTS uzundan kısaya sıralı; düzenli ifade seçenekleri soldan denendiği için döngüyle aynı ilk eşleşme.
_JS_PUNCT_RE = re.compile("|".join(re.escape(p) for p in _JS_PUNCTS))
_JS_WS_RUN = re.compile("[ \t\r\f\v﻿]+")
_JS_STR_STOP = {q: re.compile("[\\\\\n" + q + "]") for q in "\"'"}
_JS_TPL_STOP = re.compile("[\\\\\n`$]")
_JS_ID_START_ASCII = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_$")


def _js_id_start(ch: str) -> bool:
    """``_JS_ID_START.match(ch)`` ile aynı (tek karakter): ASCII harf/_/$ ya da U+00C0–U+FFFF."""
    return ch in _JS_ID_START_ASCII or "\u00c0" <= ch <= "\uffff"


class _JsTokenizer:
    MAX_TOKENS = 400_000

    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0
        self.line = 1
        self.count = 0

    def tokens(self, until_brace: bool = False) -> list[_Tok]:
        out: list[_Tok] = []
        depth = 0
        s = self.s
        n = len(s)
        while self.i < n:
            ch = s[self.i]
            if ch == "\n":
                self.line += 1
                self.i += 1
                continue
            if ch in " \t\r\f\v﻿":
                self.i = _JS_WS_RUN.match(s, self.i).end()  # aynı karakter kümesinden oluşan dizi tek adımda
                continue
            if ch == "/" and s.startswith("//", self.i):
                end = s.find("\n", self.i)
                self.i = n if end < 0 else end
                continue
            if ch == "/" and s.startswith("/*", self.i):
                end = s.find("*/", self.i + 2)
                end = n if end < 0 else end + 2
                self.line += s.count("\n", self.i, end)
                self.i = end
                continue
            self.count += 1
            if self.count > self.MAX_TOKENS:
                raise ValueError("belirteç sınırı")
            if until_brace:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    if depth == 0:
                        self.i += 1
                        return out
                    depth -= 1
            if ch in "\"'":
                out.append(self._string(ch))
                continue
            if ch == "`":
                out.append(self._template())
                continue
            if ch == "/" and self._regex_allowed(out):
                regex = self._regex()
                if regex is not None:
                    out.append(regex)
                    continue
            if ch in _JS_ID_START_ASCII or "\u00c0" <= ch <= "\uffff":  # = _js_id_start(ch), satır içi
                start = self.i
                self.i = _JS_ID_RUN.match(s, self.i).end()
                out.append(_Tok("id", s[start:self.i], self.line))
                continue
            if ch.isdigit() or (ch == "." and self.i + 1 < n and s[self.i + 1].isdigit()):
                start = self.i
                while self.i < n and (s[self.i].isalnum() or s[self.i] in "._"):
                    self.i += 1
                out.append(_Tok("num", s[start:self.i], self.line))
                continue
            match = _JS_PUNCT_RE.match(s, self.i)
            if match is not None:
                punct = match.group()
                out.append(_Tok("punct", punct, self.line))
                self.i += len(punct)
            else:
                out.append(_Tok("punct", ch, self.line))
                self.i += 1
        return out

    def _regex_allowed(self, out: list[_Tok]) -> bool:
        if not out:
            return True
        prev = out[-1]
        if prev.kind in {"num", "str", "tpl", "regex"}:
            return False
        if prev.kind == "id":
            return prev.value in _JS_REGEX_PRECEDERS
        return prev.value not in {")", "]", "}"}

    def _string(self, quote: str) -> _Tok:
        s = self.s
        line = self.line
        self.i += 1
        start = self.i
        stop = _JS_STR_STOP[quote]  # 19. tur: karakter döngüsü yerine bir sonraki özel karaktere atla (aynı sonuç)
        n = len(s)
        while self.i < n:
            match = stop.search(s, self.i)
            if match is None:
                self.i = n
                break
            j = match.start()
            ch = s[j]
            if ch == "\\":
                if j + 1 < n and s[j + 1] == "\n":
                    self.line += 1
                self.i = j + 2
                continue
            if ch == quote:
                self.i = j + 1
                return _Tok("str", s[start:j], line)
            self.i = j  # sonlanmamış dize (ör. JSX metni): satır sonunda kapat
            return _Tok("str", s[start:j], line)
        return _Tok("str", s[start:], line)

    def _template(self) -> _Tok:
        s = self.s
        tok = _Tok("tpl", "", self.line)
        self.i += 1
        chunk_start = self.i
        n = len(s)
        while self.i < n:
            match = _JS_TPL_STOP.search(s, self.i)  # 19. tur: bir sonraki özel karaktere atla (aynı sonuç)
            if match is None:
                self.i = n
                break
            self.i = match.start()
            ch = s[self.i]
            if ch == "\\":
                self.i += 2
                continue
            if ch == "\n":
                self.line += 1
                self.i += 1
                continue
            if ch == "`":
                tok.value += s[chunk_start:self.i]
                self.i += 1
                return tok
            if ch == "$" and self.i + 1 < n and s[self.i + 1] == "{":
                tok.value += s[chunk_start:self.i] + "${}"
                self.i += 2
                tok.parts.append(self.tokens(until_brace=True))
                chunk_start = self.i
                continue
            self.i += 1
        tok.value += s[chunk_start:]
        return tok

    def _regex(self) -> _Tok | None:
        s = self.s
        start = self.i
        i = self.i + 1
        in_class = False
        while i < len(s):
            ch = s[i]
            if ch == "\n":
                return None
            if ch == "\\":
                i += 2
                continue
            if ch == "[":
                in_class = True
            elif ch == "]":
                in_class = False
            elif ch == "/" and not in_class:
                i += 1
                while i < len(s) and s[i].isalpha():
                    i += 1
                self.i = i
                return _Tok("regex", s[start:i], self.line)
            i += 1
        return None


_JS_REQUEST_ROOTS = frozenset({"req", "request"})
_JS_REQUEST_MEMBERS = frozenset({
    "body", "query", "params", "headers", "cookies", "files", "file", "rawBody", "signedCookies", "fields",
    "url", "originalUrl", "path", "host", "hostname", "ip", "baseUrl", "nextUrl", "method", "protocol", "ips",
    "subdomains", "referrer",
})
_JS_BROWSER_SOURCES = {
    "location": frozenset({"hash", "search", "href", "pathname"}),
    "document": frozenset({"URL", "documentURI", "baseURI", "referrer", "cookie"}),
}
_JS_FULL_SANITIZERS = frozenset({
    "parseInt", "parseFloat", "Number", "Boolean", "Number.parseInt", "Number.parseFloat", "Math.floor",
    "Math.ceil", "Math.round", "Math.abs", "Math.min", "Math.max", "isNaN", "Number.isInteger", "Array.isArray",
})
_JS_CLEAN_MEMBERS = frozenset({"length", "size", "byteLength", "includes", "startsWith", "endsWith", "indexOf", "test"})
_JS_LOG_OBJECTS = frozenset({"logger", "log", "winston", "pino", "LOGGER", "Logger", "logging", "bunyan", "signale"})
_JS_LOG_METHODS = frozenset({"info", "warn", "warning", "error", "debug", "trace", "fatal", "verbose", "silly", "log", "notice", "critical"})
_JS_SQL_METHODS = frozenset({"query", "execute", "raw", "unsafe", "$queryRawUnsafe", "$executeRawUnsafe", "queryRawUnsafe", "executeRawUnsafe", "whereRaw", "orderByRaw", "havingRaw", "joinRaw"})
_JS_ROUTER_OBJECTS = frozenset({"app", "router", "server", "api", "routes", "route", "r", "fastify", "express"})
_JS_ROUTER_METHODS = frozenset({"get", "post", "put", "patch", "delete", "del", "all", "use", "options", "head"})
_JS_KEYWORDS = frozenset({
    "const", "let", "var", "function", "return", "if", "else", "for", "while", "do", "switch", "case", "break",
    "continue", "new", "typeof", "instanceof", "in", "of", "await", "async", "class", "extends", "import", "export",
    "from", "default", "try", "catch", "finally", "throw", "this", "null", "undefined", "true", "false", "yield",
    "void", "delete", "super", "static", "get", "set",
})
_OPEN = {"(": ")", "[": "]", "{": "}"}


def _is_router_call(toks: list[_Tok], i: int) -> bool:
    """toks[i] 'get/post/...' adı; önünde router benzeri nesne ve ardından '(' var mı?"""
    if not (
        toks[i].kind == "id" and toks[i].value in _JS_ROUTER_METHODS and i >= 2
        and toks[i - 1].value in {".", "?."} and i + 1 < len(toks) and toks[i + 1].value == "("
    ):
        return False
    owner = toks[i - 2]
    if owner.kind == "punct":
        return owner.value == ")"  # express.Router().get( / .route('/x').get(
    lowered = owner.value.lower()
    return owner.value in _JS_ROUTER_OBJECTS or lowered.endswith(("router", "app", "routes", "server"))


def _js_tokenize(text: str) -> list[_Tok] | None:
    try:
        return _JsTokenizer(text).tokens()
    except (ValueError, RecursionError):
        return None


def _match_close(toks: list[_Tok], i: int) -> int:
    """toks[i] açılış parantezi; eşleşen kapanış indeksini döndür (yoksa len)."""
    opener = toks[i].value
    closer = _OPEN[opener]
    depth = 0
    for j in range(i, len(toks)):
        tok = toks[j]
        if tok.kind != "punct":
            continue
        if tok.value == opener:
            depth += 1
        elif tok.value == closer:
            depth -= 1
            if depth == 0:
                return j
    return len(toks)


def _split_args(toks: list[_Tok]) -> list[list[_Tok]]:
    args: list[list[_Tok]] = []
    current: list[_Tok] = []
    depth = 0
    for tok in toks:
        if tok.kind == "punct" and tok.value in _OPEN:
            depth += 1
        elif tok.kind == "punct" and tok.value in {")", "]", "}"}:
            depth -= 1
        if depth == 0 and tok.kind == "punct" and tok.value == ",":
            args.append(current)
            current = []
            continue
        current.append(tok)
    if current:
        args.append(current)
    return args


_CONTINUATION_PUNCTS = frozenset({
    ".", "?.", "+", "-", "*", "/", "%", "**", "&&", "||", "??", "?", ":", "=", "==", "===", "!=", "!==", "<", ">",
    "<=", ">=", "&", "|", "^", "<<", ">>", ">>>", ",", "(", "[", "{", "=>", "+=", "-=", "instanceof", "in",
})


def _statement_end(toks: list[_Tok], i: int) -> int:
    """i'den başlayan ifadenin bittiği (dahil olmayan) indeks: ; veya ASI satır sonu."""
    depth = 0
    n = len(toks)
    j = i
    while j < n:
        tok = toks[j]
        if tok.kind == "punct":
            if tok.value in _OPEN:
                depth += 1
            elif tok.value in {")", "]", "}"}:
                if depth == 0:
                    return j
                depth -= 1
            elif depth == 0 and tok.value in {";", ","}:
                return j
        if depth == 0 and j + 1 < n and toks[j + 1].line > tok.line:
            nxt = toks[j + 1]
            if not (tok.kind == "punct" and tok.value in _CONTINUATION_PUNCTS) and not (
                nxt.kind == "punct" and nxt.value in _CONTINUATION_PUNCTS - {"(", "[", "{"}
            ):
                return j + 1
        j += 1
    return n


def _callee_chain(toks: list[_Tok], paren: int) -> tuple[str, int]:
    """toks[paren] '(' ise önündeki üye zincirini ('a.b.c') ve başlangıç indeksini döndür."""
    j = paren - 1
    parts: list[str] = []
    while j >= 0:
        tok = toks[j]
        if tok.kind == "id":
            parts.append(tok.value)
            if j - 1 >= 0 and toks[j - 1].kind == "punct" and toks[j - 1].value in {".", "?."}:
                j -= 2
                continue
            return ".".join(reversed(parts)), j
        if tok.kind == "punct" and tok.value == ")" and parts:
            # a(...).b(  → zinciri 'a().b' olarak gösterme; yalnızca son kısım yeterli
            return ".".join(reversed(parts)), j + 1
        break
    return ".".join(reversed(parts)), j + 1


class _JsAnalyzer:
    def __init__(self, toks: list[_Tok], *, pii: PiiClassifier | None, handler_names: frozenset[str]) -> None:
        self.toks = toks
        self.pii = pii
        self.handler_names = handler_names
        self.flows: list[Flow] = []
        self.clean: set[tuple[str, int]] = set()
        self.roots: set[str] = set(_JS_REQUEST_ROOTS)
        self.ctx_roots: set[str] = {"ctx"}
        self.env: dict[str, Taint] = {}
        self._emitted: set[tuple[str, int, str, int]] = set()

    # -- işleyici kökleri -------------------------------------------------------
    def _first_param(self, open_paren: int) -> tuple[str, list[str]]:
        """'(' indeksinden ilk parametre adı veya {destructure} içindeki adlar."""
        toks = self.toks
        j = open_paren + 1
        if j >= len(toks):
            return "", []
        tok = toks[j]
        if tok.kind == "id":
            return tok.value, []
        if tok.kind == "punct" and tok.value == "{":
            close = _match_close(toks, j)
            names = [t.value for k, t in enumerate(toks[j + 1:close], j + 1)
                     if t.kind == "id" and not (k + 1 < len(toks) and toks[k + 1].value == ":")]
            return "", names
        return "", []

    def _mark_handler_params(self) -> None:
        toks = self.toks
        n = len(toks)
        for i, tok in enumerate(toks):
            if tok.kind != "id":
                continue
            # Satır içi işleyiciler: app.get('/x', (req, res) => ..., function (req) {...})
            if _is_router_call(toks, i):
                close = _match_close(toks, i + 1)
                for k in range(i + 2, min(close, n)):
                    t = toks[k]
                    if t.kind == "punct" and t.value == "(" and self._is_function_params(k):
                        self._add_param_root(k)
                    elif t.kind == "id" and k + 1 < n and toks[k + 1].value == "=>" and toks[k - 1].value in {",", "(", "async"}:
                        self.roots.add(t.value)
            # Dosyalar arası işleyiciler: adı router çağrısında geçen fonksiyonlar
            if tok.value in self.handler_names:
                k = i + 1
                prev = toks[i - 1] if i > 0 else None
                is_definition = prev is None or prev.value in {"function", "async", "static", "{", "}", ";", ","} or (
                    prev.line < tok.line and prev.value not in {".", "?.", "new"}
                )
                if k < n and toks[k].value == "(" and is_definition and (
                    (prev is not None and prev.value == "function") or self._is_method_def(k)
                ):
                    self._add_param_root(k)
                    continue
                if k < n and toks[k].value in {"=", ":"}:
                    k += 1
                    if k < n and toks[k].value == "async":
                        k += 1
                    if k < n and toks[k].value == "function":
                        k += 1
                        if k < n and toks[k].kind == "id":
                            k += 1
                    if k < n and toks[k].value == "(":
                        self._add_param_root(k)
                    elif k < n and toks[k].kind == "id" and k + 1 < n and toks[k + 1].value == "=>":
                        self.roots.add(toks[k].value)

    def _is_method_def(self, paren: int) -> bool:
        close = _match_close(self.toks, paren)
        nxt = close + 1
        return nxt < len(self.toks) and self.toks[nxt].value == "{"

    def _is_function_params(self, paren: int) -> bool:
        toks = self.toks
        close = _match_close(toks, paren)
        if close + 1 < len(toks) and toks[close + 1].value == "=>":
            return True
        prev = toks[paren - 1] if paren > 0 else None
        return prev is not None and (prev.value == "function" or (prev.kind == "id" and paren >= 2 and toks[paren - 2].value == "function"))

    def _add_param_root(self, paren: int) -> None:
        name, destructured = self._first_param(paren)
        if name and name not in {"_"}:
            self.roots.add(name)
        for item in destructured:
            if item in _JS_REQUEST_MEMBERS:
                self.env[item] = (_Origin("request", f"{{{item}}}", self.toks[paren].line, ()),)

    # -- ifade değerlendirme -------------------------------------------------------
    def _source_at(self, toks: list[_Tok], k: int) -> tuple[str, int] | None:
        """toks[k] bir kaynak zincirinin başıysa (kaynak metni, son indeks)."""
        tok = toks[k]
        if tok.kind != "id" or (k > 0 and toks[k - 1].value in {".", "?."}):
            return None

        def member(idx: int) -> str | None:
            if idx + 1 < len(toks) and toks[idx].value in {".", "?."} and toks[idx + 1].kind == "id":
                return toks[idx + 1].value
            return None

        first = member(k + 1)
        # Dönen indeks, zincirdeki son kaynak üyesinden sonraki belirteçtir.
        if tok.value in self.roots and first in _JS_REQUEST_MEMBERS:
            return f"{tok.value}.{first}", k + 3
        if tok.value in self.ctx_roots:
            if first in {"query", "params", "headers", "cookies"}:
                return f"{tok.value}.{first}", k + 3
            if first == "request":
                second = member(k + 3)
                if second in _JS_REQUEST_MEMBERS:
                    return f"{tok.value}.request.{second}", k + 5
        if tok.value == "window" and first in {"location", "name"}:
            if first == "name":
                return "window.name", k + 3
            second = member(k + 3)
            if second in _JS_BROWSER_SOURCES["location"]:
                return f"window.location.{second}", k + 5
        if tok.value in _JS_BROWSER_SOURCES and first in _JS_BROWSER_SOURCES[tok.value]:
            return f"{tok.value}.{first}", k + 3
        return None

    def eval(self, toks: list[_Tok]) -> Taint:
        parts: list[Taint] = []
        k = 0
        n = len(toks)
        while k < n:
            tok = toks[k]
            if tok.kind == "punct" and tok.value == "=>" and k + 1 < n and toks[k + 1].value == "{":
                k = _match_close(toks, k + 1) + 1
                continue
            if tok.kind == "id" and tok.value == "function":
                m = k + 1
                while m < n and toks[m].value != "{":
                    m += 1
                k = _match_close(toks, m) + 1 if m < n else n
                continue
            if tok.kind == "tpl":
                for inner in tok.parts:
                    parts.append(self.eval(inner))
                k += 1
                continue
            if tok.kind == "id" and not (k > 0 and toks[k - 1].value in {".", "?."}):
                # Çağrı veya üye zinciri: a.b.c(...)
                j = k
                chain = [tok.value]
                while j + 2 < n and toks[j + 1].value in {".", "?."} and toks[j + 2].kind == "id":
                    chain.append(toks[j + 2].value)
                    j += 2
                name = ".".join(chain)
                if j + 1 < n and toks[j + 1].value == "(":
                    close = _match_close(toks, j + 1)
                    inner = self.eval(toks[j + 2:close])
                    base_taint = self.eval(toks[k:j - 1]) if len(chain) > 1 else _EMPTY
                    if name in _JS_FULL_SANITIZERS or chain[-1] in _JS_CLEAN_MEMBERS:
                        result: Taint = _EMPTY
                    else:
                        kinds = _named_sanitizer_kinds(name)
                        combined = _union(base_taint, inner)
                        result = _clean(combined, kinds) if kinds is not None else combined
                    parts.append(result)
                    k = close + 1
                    # zincirin devamı: .length gibi temiz üyeler sonucu temizler
                    if k + 1 < n and toks[k].value in {".", "?."} and toks[k + 1].value in _JS_CLEAN_MEMBERS:
                        parts[-1] = _EMPTY
                    continue
                source = self._source_at(toks, k)
                if source is not None:
                    text, end = source
                    taint: Taint = (_Origin("request", text, tok.line, ()),)
                    k = end
                    while k + 1 < n and toks[k].value in {".", "?."} and toks[k + 1].kind == "id":
                        if toks[k + 1].value in _JS_CLEAN_MEMBERS:
                            taint = _EMPTY
                        k += 2
                    parts.append(taint)
                    continue
                if tok.value not in _JS_KEYWORDS and not (k + 1 < n and toks[k + 1].value == ":" and k > 0 and toks[k - 1].value in {"{", ","}):
                    taint = self.env.get(tok.value, _EMPTY)
                    if self.pii:
                        for member_name in chain:
                            if self.pii(member_name):
                                taint = _union(taint, (_Origin("pii", name, tok.line, ()),))
                                break
                    if taint and chain[-1] in _JS_CLEAN_MEMBERS:
                        taint = _EMPTY
                    parts.append(taint)
                k = j + 1
                continue
            k += 1
        return _union(*parts)

    # -- hedefler -------------------------------------------------------------------
    def _emit(self, kind: str, sink: str, line: int, taint: Taint) -> None:
        self.clean.add((kind, line))
        for origin in _live(taint, kind):
            key = (kind, line, origin.source, origin.line)
            if key in self._emitted:
                continue
            self._emitted.add(key)
            self.flows.append(Flow("javascript", kind, sink, line, origin.source, origin.label, origin.line, origin.via))

    def _sql_query_arg(self, arg: list[_Tok]) -> list[_Tok]:
        if arg and arg[0].value == "{":
            close = _match_close(arg, 0)
            for idx, tok in enumerate(arg[1:close], 1):
                if tok.kind == "id" and tok.value in {"text", "sql", "query"} and idx + 1 < len(arg) and arg[idx + 1].value == ":":
                    end = _statement_end(arg, idx + 2)
                    return arg[idx + 2:end]
            return []
        return arg

    def _check_call(self, name: str, chain_start: int, paren: int) -> None:
        toks = self.toks
        close = _match_close(toks, paren)
        args = _split_args(toks[paren + 1:close])
        if not args:
            return
        line = toks[chain_start].line
        parts = name.split(".")
        last = parts[-1]
        owner = parts[-2] if len(parts) >= 2 else ""
        is_new = chain_start > 0 and toks[chain_start - 1].value == "new"
        if (owner == "console" and last in {"log", "info", "warn", "error", "debug", "trace"}) or (
            owner in _JS_LOG_OBJECTS and last in _JS_LOG_METHODS
        ):
            self._emit("log", name, line, _union(*(self.eval(arg) for arg in args)))
        elif last in _JS_SQL_METHODS and owner and owner not in {"document", "URLSearchParams"}:
            self._emit("sql", name, line, self.eval(self._sql_query_arg(args[0])))
        elif (name in {"exec", "execSync"} or (owner in {"child_process", "cp", "childProcess", "shell"} and last in {"exec", "execSync"})):
            self._emit("command", name, line, self.eval(args[0]))
        elif name in {"eval", "Function", "vm.runInNewContext", "vm.runInThisContext", "vm.runInContext"} or (is_new and name == "Function"):
            self._emit("eval", name, line, self.eval(args[-1] if name == "Function" else args[0]))
        elif name in {"setTimeout", "setInterval"} and args[0] and args[0][0].kind in {"str", "tpl", "id"}:
            first = args[0]
            if not (len(first) > 1 and first[1].value == "=>") and first[0].value not in {"function", "async"}:
                taint = self.eval(first)
                if taint:
                    self._emit("eval", name, line, taint)
        elif name in {"document.write", "document.writeln"} or last == "insertAdjacentHTML" or (
            last == "html" and owner in {"$", "jQuery", "_call_"}
        ):
            target = args[1] if last == "insertAdjacentHTML" and len(args) > 1 else args[0]
            self._emit("html", name, line, self.eval(target))
        elif name in {"RegExp"}:
            self._emit("regex", "new RegExp" if is_new else "RegExp", line, self.eval(args[0]))

    def run(self) -> None:
        toks = self.toks
        self._mark_handler_params()
        n = len(toks)
        scope_stack: list[list[tuple[str, Taint | None]]] = [[]]
        i = 0
        while i < n:
            tok = toks[i]
            if tok.kind == "punct" and tok.value == "{":
                scope_stack.append([])
            elif tok.kind == "punct" and tok.value == "}":
                if len(scope_stack) > 1:
                    for name, previous in reversed(scope_stack.pop()):
                        if previous is None:
                            self.env.pop(name, None)
                        else:
                            self.env[name] = previous
            elif tok.kind == "id" and tok.value in {"const", "let", "var"}:
                i = self._declaration(i + 1, scope_stack[-1])
                continue
            elif (
                tok.kind == "id" and tok.value in {"innerHTML", "outerHTML"} and i >= 1
                and toks[i - 1].value in {".", "?."} and i + 1 < n and toks[i + 1].value in {"=", "+="}
            ):
                end = _statement_end(toks, i + 2)
                self._emit("html", tok.value, tok.line, self.eval(toks[i + 2:end]))
            elif (
                tok.kind == "id" and i >= 2 and toks[i - 1].value in {".", "?."} and toks[i - 2].value == ")"
                and i + 1 < n and toks[i + 1].value == "("
            ):
                self._check_call(f"_call_.{tok.value}", i, i + 1)
            elif tok.kind == "id" and not (i > 0 and toks[i - 1].value in {".", "?."}):
                j = i
                chain = [tok.value]
                while j + 2 < n and toks[j + 1].value in {".", "?."} and toks[j + 2].kind == "id":
                    chain.append(toks[j + 2].value)
                    j += 2
                if j + 1 < n and toks[j + 1].kind == "punct":
                    op = toks[j + 1].value
                    if op == "(" and chain[-1] not in _JS_KEYWORDS:
                        self._check_call(".".join(chain), i, j + 1)
                    elif op in {"=", "+="} and chain[-1] in {"innerHTML", "outerHTML"} and len(chain) > 1:
                        end = _statement_end(toks, j + 2)
                        self._emit("html", chain[-1], tok.line, self.eval(toks[j + 2:end]))
                    elif op in {"=", "+="} and len(chain) == 1 and tok.value not in _JS_KEYWORDS:
                        end = _statement_end(toks, j + 2)
                        taint = self.eval(toks[j + 2:end])
                        if op == "+=":
                            taint = _union(self.env.get(tok.value, _EMPTY), taint)
                        if tok.value in self.env or taint:
                            self.env[tok.value] = _via(taint, tok.value) if taint else _EMPTY
                if tok.value == "dangerouslySetInnerHTML":
                    self._dangerously_set(i)
                i = j + 1
                continue
            i += 1

    def _dangerously_set(self, i: int) -> None:
        toks = self.toks
        for k in range(i + 1, min(i + 8, len(toks) - 2)):
            if toks[k].kind == "id" and toks[k].value == "__html" and toks[k + 1].value == ":":
                end = _statement_end(toks, k + 2)
                self._emit("html", "dangerouslySetInnerHTML", toks[i].line, self.eval(toks[k + 2:end]))
                return

    def _declaration(self, i: int, scope: list[tuple[str, Taint | None]]) -> int:
        """const/let/var bildirimini bağla; ana döngünün başlatıcıyı yeniden taraması için
        ilk başlatıcının başlangıç indeksini döndürür (iç fonksiyon gövdeleri atlanmasın)."""
        toks = self.toks
        n = len(toks)
        resume: int | None = None
        while i < n:
            names: list[str] = []
            if toks[i].kind == "id":
                names = [toks[i].value]
                i += 1
            elif toks[i].value in {"{", "["}:
                close = _match_close(toks, i)
                for k in range(i + 1, min(close, n)):
                    t = toks[k]
                    if t.kind == "id" and not (k + 1 < n and toks[k + 1].value == ":") and toks[k - 1].value != "=":
                        names.append(t.value)
                i = close + 1
            else:
                break
            # TypeScript tür açıklamasını atla: const x: Foo = ...
            if i < n and toks[i].value == ":":
                while i < n and toks[i].value not in {"=", ";", ","} and toks[i].line == toks[i - 1].line:
                    i += 1
            taint: Taint = _EMPTY
            if i < n and toks[i].value in {"=", "of", "in"}:
                if resume is None:
                    resume = i + 1
                end = _statement_end(toks, i + 1)
                taint = self.eval(toks[i + 1:end])
                i = end
            for name in names:
                scope.append((name, self.env.get(name)))
                self.env[name] = _via(taint, name) if taint else _EMPTY
            if i < n and toks[i].value == ",":
                i += 1
                continue
            break
        return resume if resume is not None else i


def collect_js_route_handlers(text: str) -> frozenset[str]:
    """``router.post('/x', ctrl.create)`` gibi çağrılardaki adlandırılmış işleyiciler."""
    toks = _js_tokenize(text)
    if not toks:
        return frozenset()
    names: set[str] = set()
    n = len(toks)
    for i, tok in enumerate(toks):
        if not _is_router_call(toks, i):
            continue
        close = _match_close(toks, i + 1)
        for arg in _split_args(toks[i + 2:close]):
            if not arg or arg[0].kind != "id":
                continue
            if any(t.kind == "punct" and t.value not in {".", "?."} for t in arg):
                continue
            last = arg[-1].value
            if last not in _JS_KEYWORDS:
                names.add(last)
    return frozenset(names)


_MINIFIED_LINE = 1_000


def is_minified_js(text: str) -> bool:
    """Küçültülmüş/paketlenmiş dosya: çok uzun satırlar baskın (tek harfli adlarla kesin
    analiz yapılamaz; CodeQL gibi bu dosyalar taint analizinden çıkarılır)."""
    if len(text) < 2_000:
        return False
    lines = text.splitlines() or [text]
    long_chars = sum(len(line) for line in lines if len(line) > _MINIFIED_LINE)
    return long_chars > 0.4 * len(text)


def analyze_javascript(
    text: str,
    *,
    pii: PiiClassifier | None = None,
    handler_names: frozenset[str] | None = None,
    filename: str = "",
) -> Analysis | None:
    if is_minified_js(text):
        return None
    names = frozenset(handler_names or ()) | _PROJECT_JS_HANDLERS.get()
    import taint_js_ast  # döngüsel içe aktarmayı önlemek için geç yükleme

    if taint_js_ast.engine_mode() != "tokens":
        relpath = filename or "<inline>.js"
        try:
            results = taint_js_ast.analyze_files({relpath: text}, pii=pii, handler_names=names)
        except taint_js_ast.JsParserUnavailable:
            results = None
            if taint_js_ast.engine_mode() == "ast":
                return None
        if results is not None and relpath in results:
            return results[relpath]
    return _analyze_javascript_tokens(text, pii=pii, handler_names=names)


def _analyze_javascript_tokens(
    text: str,
    *,
    pii: PiiClassifier | None = None,
    handler_names: frozenset[str] | None = None,
) -> Analysis | None:
    """Belirteç tabanlı (Node gerektirmeyen) yedek JS motoru."""
    toks = _js_tokenize(text)
    if toks is None:
        return None
    names = frozenset(handler_names or ()) | _PROJECT_JS_HANDLERS.get() | collect_js_route_handlers(text)
    analyzer = _JsAnalyzer(toks, pii=pii, handler_names=names)
    try:
        analyzer.run()
    except (RecursionError, IndexError):
        return None
    return Analysis("javascript", analyzer.flows, analyzer.clean)


# ---------------------------------------------------------------------------
# Ortak giriş noktaları
# ---------------------------------------------------------------------------


def language_for(filename: str) -> str | None:
    suffix = Path(filename).suffix.lower()
    if suffix in PY_SUFFIXES:
        return "python"
    if suffix in JS_SUFFIXES:
        return "javascript"
    if suffix in GO_SUFFIXES:
        return "go"
    if suffix in RUBY_SUFFIXES:
        return "ruby"
    if suffix in CLIKE_SUFFIXES:
        return _CLIKE_LANGUAGE[suffix]
    if suffix in RUST_SUFFIXES:
        return "rust"
    if suffix in CFAMILY_SUFFIXES:
        return "cpp" if suffix in _CPP_SUFFIXES else "c"
    return None


def _inherit_project_limits(result: Analysis | None, engine: str) -> Analysis | None:
    state = _PROJECT.get()
    reasons = getattr(state, "limitations", {}).get(engine, ()) if state is not None else ()
    if result is not None and reasons:
        result.mark_incomplete(*sorted(reasons))
    return result


def analyze_source(text: str, filename: str, *, pii: PiiClassifier | None = None) -> Analysis | None:
    """Desteklenen dil ve etkin analiz için :class:`Analysis`, aksi halde None."""
    if not is_enabled() or not isinstance(text, str) or len(text) > _source_limit():
        return None
    language = language_for(filename)
    if language == "python":
        state = _PROJECT.get()
        if state is not None:
            result = state.python_analysis(filename, text, pii)
            if result is not _MISS:
                return result
        return _inherit_project_limits(analyze_python(text, pii=pii, filename=filename), "python")
    if language == "javascript":
        state = _PROJECT.get()
        if state is not None:
            result = state.js_analysis(filename, text, pii)
            if result is not _MISS:
                return result
        return _inherit_project_limits(analyze_javascript(text, pii=pii, filename=filename), "javascript")
    if language in ("go", "ruby"):
        # Go / Ruby (Rails, Sinatra, ERB): saf Python belirteç tabanlı dosyalar arası motor (taint_goruby).
        import taint_goruby

        if language == "go" and filename.endswith("_test.go"):
            return Analysis(language="go")
        state = _PROJECT.get()
        if state is not None:
            result = state.goruby_analysis(filename, text, language)
            if result is not _MISS:
                return result
        relpath = filename.replace("\\", "/")
        return _inherit_project_limits(
            taint_goruby.analyze_files({relpath: text}, language).get(relpath, Analysis(language=language)), language)
    if language in ("java", "csharp", "php", "kotlin"):
        state = _PROJECT.get()
        if state is not None:
            result = state.clike_analysis(filename, text)
            if result is not _MISS:
                return result
        import taint_clike

        try:
            return _inherit_project_limits(taint_clike.analyze_single(text, filename.replace("\\", "/")), "clike")
        except RecursionError:
            return None
    if language in ("rust", "c", "cpp"):
        family = "rust" if language == "rust" else "c"
        state = _PROJECT.get()
        if state is not None:
            result = state.native_analysis(filename, text, family)
            if result is not _MISS:
                return result
        if family == "rust":
            import taint_rust as engine
        else:
            import taint_cfamily as engine
        try:
            return _inherit_project_limits(engine.analyze_single(text, filename.replace("\\", "/")), family)
        except (RecursionError, MemoryError):
            return None
    return None


_MISS: Any = object()


def cfamily_facts(filename: str, text: str) -> dict[str, Any] | None:
    """27. tur: proje analizindeyken C/C++ dosyalar arası kirlilik modeli olguları (dosya proje modelindeyse)."""
    if not is_enabled():
        return None
    state = _PROJECT.get()
    if state is None:
        return None
    try:
        entry = state.native_facts("c")
    except (RecursionError, MemoryError):
        return None
    if entry is None:
        return None
    digests, facts = entry
    relpath = filename.replace("\\", "/")
    if digests.get(relpath) != state._digest(text):
        return None
    return facts


def _walk_project_files(root: Path, skip_dirs: frozenset[str], suffixes: frozenset[str],
                        limitations: set[str] | None = None) -> Iterator[Path]:
    seen = 0
    # "Yalnız atlananlar" modunda normal taramanın incelediği dosyalar dosyalar arası analize de girmez.
    skipped_only = scan_scope.current().skipped_only
    # "Yalnız değişenler": dosyalar arası bağlam değişen dosyaların içe aktarma komşuluğuyla sınırlanır (changed_scan).
    context = scan_scope.current().context_paths
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name for name in directories
            if name.casefold() not in skip_dirs and not (Path(current) / name).is_symlink()
        )
        for name in sorted(files):
            path = Path(current) / name
            if path.suffix.lower() not in suffixes or path.is_symlink():
                continue
            if skipped_only:
                try:
                    size = path.stat().st_size
                except OSError:
                    continue
                if not scan_scope.default_skips_path(path.relative_to(root).parts, size):
                    continue
            if (context is not None and path.suffix.lower() in PY_SUFFIXES | JS_SUFFIXES
                    and path.relative_to(root).as_posix() not in context):
                continue
            seen += 1
            if seen > _project_files_limit():
                if limitations is not None:
                    limitations.add("project-files")
                return
            yield path


def project_limitations() -> tuple[str, ...]:
    """Etkin proje bağlamındaki alt motor kapsam sınırlarını kararlı sırada döndür."""
    state = _PROJECT.get()
    if state is None:
        return ()
    return tuple(
        f"{engine}: {', '.join(sorted(reasons))}"
        for engine, reasons in sorted(state.limitations.items()) if reasons
    )


def _entrypoints_from_config(text: str) -> set[str]:
    """Tek yapılandırma dosyasından Python giriş noktaları ("modül.yolu:fonksiyon").

    Connexion/OpenAPI: ``operationId: paket.modul.fonksiyon`` ya da ``x-openapi-router-controller: paket.modul``
    + noktasız ``operationId``. Sunucusuz: serverless.yml ``handler: yol/dosya.fonksiyon`` ve SAM
    ``Handler: dosya.fonksiyon``. YAML ayrıştırılmaz; yalnız bu anahtarların satırları okunur."""
    found: set[str] = set()
    if "operationId" in text and ("openapi" in text or "swagger" in text):
        controllers = sorted(set(_OPENAPI_CONTROLLER_RE.findall(text)))
        for op in _OPENAPI_OPERATION_RE.findall(text):
            if "." in op:
                module, _, func = op.rpartition(".")
                found.add(f"{module}:{func}")
                # paket.modul.Sinif.metot biçimi
                head, _, cls = module.rpartition(".")
                if head and cls[:1].isupper():
                    found.add(f"{head}:{cls}.{func}")
            for controller in controllers[:20]:
                found.add(f"{controller}:{op}")
    if "andler" in text:
        for path, func in _SERVERLESS_HANDLER_RE.findall(text):
            module = path.strip("./").replace("/", ".")
            if module and not module.endswith((".js", ".ts", ".mjs", ".cjs")):
                found.add(f"{module}:{func}")
    return found


def collect_python_entrypoints(root: Path, skip_dirs: set[str] | frozenset[str]) -> frozenset[str]:
    """Proje yapılandırmasında (OpenAPI/Connexion, serverless.yml, SAM) adı geçen Python işleyicileri."""
    if not is_enabled():
        return frozenset()
    found: set[str] = set()
    total = 0
    for index, path in enumerate(_walk_project_files(Path(root), frozenset(skip_dirs), _ENTRY_CONFIG_SUFFIXES)):
        if index >= _ENTRY_CONFIG_MAX_FILES or total > _ENTRY_CONFIG_MAX_BYTES:
            break
        text = read_text_bounded(path, _source_limit())
        if text is None:
            continue
        total += len(text)
        found |= _entrypoints_from_config(text)
        if len(found) > 5000:
            break
    return frozenset(found)


class _ProjectState:
    """Bir proje taraması boyunca paylaşılan, tembel kurulan dosyalar arası analiz."""

    def __init__(self, root: Path, skip_dirs: frozenset[str]) -> None:
        self.root = root
        self.skip_dirs = skip_dirs
        self._python: dict[Any, tuple[dict[str, str], dict[str, Analysis] | None]] = {}
        self._js: dict[Any, tuple[dict[str, str], dict[str, Analysis] | None]] = {}
        self._goruby: dict[str, tuple[dict[str, str], dict[str, Analysis] | None]] = {}
        self._clike: tuple[dict[str, str], dict[str, Analysis] | None] | None = None
        self._native: dict[str, tuple[dict[str, str], dict[str, Analysis] | None]] = {}
        self._native_facts: dict[str, tuple[dict[str, str], dict[str, Any]]] = {}
        self.limitations: dict[str, set[str]] = {}

    def _bounded(self, engine: str, reasons: set[str], results: dict[str, Analysis] | None) -> None:
        if results is None:
            reasons.add("analysis-budget")
        if results:
            for analysis in results.values():
                if not analysis.analysis_complete:
                    reasons.update(analysis.limitations)
        if not reasons:
            return
        self.limitations.setdefault(engine, set()).update(reasons)
        if results:
            for analysis in results.values():
                analysis.mark_incomplete(*sorted(reasons))

    @staticmethod
    def _digest(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()

    def _build_python(self, pii: PiiClassifier | None) -> tuple[dict[str, str], dict[str, Analysis] | None]:
        files: dict[str, str] = {}
        total = 0
        limits: set[str] = set()
        for path in _walk_project_files(self.root, self.skip_dirs, PY_SUFFIXES, limits):
            # Yalnız normal dosyalar (O_NOFOLLOW|O_NONBLOCK + fstat): FIFO/aygıt dosyası bekletemez.
            text = read_text_bounded(path, _source_limit())
            if text is None:
                continue
            total += len(text)
            if total > _project_bytes_limit():
                limits.add("project-bytes")
                break
            files[path.relative_to(self.root).as_posix()] = text
        digests = {relpath: self._digest(text) for relpath, text in files.items()}
        entrypoints = collect_python_entrypoints(self.root, self.skip_dirs)
        templates = collect_python_templates(self.root, self.skip_dirs)
        results = analyze_python_files(files, pii=pii, entrypoints=entrypoints, templates=templates)
        self._bounded("python", limits, results)
        return digests, results

    def _build_js(self, pii: PiiClassifier | None) -> tuple[dict[str, str], dict[str, Analysis] | None]:
        import taint_js_ast

        if taint_js_ast.engine_mode() == "tokens":
            return {}, None
        files: dict[str, str] = {}
        total = 0
        limits: set[str] = set()
        for path in _walk_project_files(self.root, self.skip_dirs, JS_SUFFIXES, limits):
            text = read_text_bounded(path, _source_limit())
            if text is None or is_minified_js(text):
                continue
            total += len(text)
            if total > _project_bytes_limit():
                limits.add("project-bytes")
                break
            files[path.relative_to(self.root).as_posix()] = text
        digests = {relpath: self._digest(text) for relpath, text in files.items()}
        try:
            results = taint_js_ast.analyze_files(files, pii=pii, handler_names=_PROJECT_JS_HANDLERS.get())
        except taint_js_ast.JsParserUnavailable:
            results = None
        self._bounded("javascript", limits, results)
        return digests, results

    def _build_goruby(self, language: str) -> tuple[dict[str, str], dict[str, Analysis] | None]:
        import taint_goruby

        suffixes = GO_SUFFIXES | {".mod"} if language == "go" else RUBY_SUFFIXES
        files: dict[str, str] = {}
        total = 0
        limits: set[str] = set()
        for path in _walk_project_files(self.root, self.skip_dirs, frozenset(suffixes), limits):
            name = path.name
            if name.endswith(".mod") and name != "go.mod":
                continue
            if language == "go" and name.endswith("_test.go"):
                continue
            text = read_text_bounded(path, _source_limit())
            if text is None:
                continue
            total += len(text)
            if total > _project_bytes_limit():
                limits.add("project-bytes")
                break
            files[path.relative_to(self.root).as_posix()] = text
        digests = {relpath: self._digest(text) for relpath, text in files.items() if not relpath.endswith("go.mod")}
        try:
            results = taint_goruby.analyze_files(files, language)
        except (RecursionError, MemoryError):
            results = None
        self._bounded(language, limits, results)
        return digests, results

    def goruby_analysis(self, filename: str, text: str, language: str) -> Analysis | None:
        entry = self._goruby.get(language)
        if entry is None:
            entry = self._build_goruby(language)
            self._goruby[language] = entry
        digests, results = entry
        relpath = filename.replace("\\", "/")
        if results is None or digests.get(relpath) != self._digest(text) or relpath not in results:
            return _MISS
        return results[relpath]

    def _build_clike(self) -> tuple[dict[str, str], dict[str, Analysis] | None]:
        import taint_clike

        files: dict[str, str] = {}
        mappers: dict[str, str] = {}
        total = 0
        limits: set[str] = set()
        for path in _walk_project_files(self.root, self.skip_dirs,
                                        CLIKE_SUFFIXES | frozenset({".xml", ".proto", ".twig", ".html"}), limits):
            text = read_text_bounded(path, _source_limit())
            if text is None:
                continue
            relpath = path.relative_to(self.root).as_posix()
            if path.suffix.lower() == ".twig":
                compact = text.replace(" ", "")
                if ("|raw" in compact or "autoescapefalse" in compact) and len(mappers) < 500:
                    mappers[relpath] = text  # Twig: kaçışsız çıktı içeren şablonlar (geri kalanı otomatik kaçışlı)
                continue
            if path.suffix.lower() == ".xml":
                if ("<mapper" in text or "<struts" in text) and len(mappers) < 500:
                    mappers[relpath] = text  # MyBatis eşleyicileri ve Struts2 yapılandırması
                continue
            if path.suffix.lower() == ".html":
                if ("th:utext" in text or "[(${" in text) and len(mappers) < 500:
                    mappers[relpath] = text  # Thymeleaf: kaçışsız basılan model öznitelikleri (17. tur)
                continue
            if path.suffix.lower() == ".proto":
                if "message" in text and len(mappers) < 500:
                    mappers[relpath] = text  # gRPC ileti alan türleri (sayısal alanlar dize enjeksiyonu taşımaz)
                continue
            total += len(text)
            if total > _project_bytes_limit():
                limits.add("project-bytes")
                break
            files[relpath] = text
        digests = {relpath: self._digest(text) for relpath, text in files.items()}
        if not files:
            results: dict[str, Analysis] = {}
            self._bounded("clike", limits, results)
            return digests, results
        try:
            results = taint_clike.analyze_files(files, mappers)
        except RecursionError:
            results = None
        self._bounded("clike", limits, results)
        return digests, results

    def _build_native(self, family: str) -> tuple[dict[str, str], dict[str, Analysis] | None]:
        if family == "rust":
            import taint_rust as engine
            suffixes = RUST_SUFFIXES
        else:
            import taint_cfamily as engine
            suffixes = CFAMILY_SUFFIXES
        files: dict[str, str] = {}
        total = 0
        limits: set[str] = set()
        for path in _walk_project_files(self.root, self.skip_dirs, suffixes, limits):
            text = read_text_bounded(path, _source_limit())
            if text is None:
                continue
            total += len(text)
            if total > _project_bytes_limit():
                limits.add("project-bytes")
                break
            files[path.relative_to(self.root).as_posix()] = text
        digests = {relpath: self._digest(text) for relpath, text in files.items()}
        if not files:
            results: dict[str, Analysis] = {}
            self._bounded(family, limits, results)
            return digests, results
        try:
            if family == "rust":
                results = engine.analyze_files(files)
            else:
                facts: dict[str, Any] = {"stdin_service_hint": self._inetd_service_hint()}
                # c_build yalnız metin okur ve güvenli -D/-U/include/-include bayraklarını döndürür. Aynı derleme
                # görünümü saf Python C/C++ taint önişlemcisine de verilir; proje komutu çalıştırılmaz.
                try:
                    import c_build

                    build_info = c_build.load(self.root, max_seconds=5.0)
                except (OSError, ValueError, RuntimeError):
                    build_info = None
                results = engine.analyze_files(files, facts, build_info=build_info)
                self._native_facts[family] = (digests, facts)
        except (RecursionError, MemoryError):
            results = None
        self._bounded(family, limits, results)
        return digests, results

    def _inetd_service_hint(self) -> bool:
        """Dağıtım dosyaları standart girdinin ağ bağlantısı olduğunu söylüyor mu: systemd soket etkinleştirmesi
        (``*.socket`` içinde ``Accept=yes``), xinetd hizmet tanımı ya da ``socat … EXEC:``/``tcpserver`` sarmalayıcısı."""
        seen = 0
        for current, directories, names in os.walk(self.root, followlinks=False):
            directories[:] = [d for d in directories if d.casefold() not in self.skip_dirs and not d.startswith(".")]
            for name in names:
                low = name.lower()
                if not (low.endswith((".socket", ".sh", ".conf", ".yml", ".yaml")) or low in (
                        "dockerfile", "xinetd", "entrypoint", "run", "start")):
                    continue
                seen += 1
                if seen > 400:
                    return False
                text = read_text_bounded(Path(current) / name, 200_000) or ""
                if (low.endswith(".socket") and re.search(r"(?im)^\s*Accept\s*=\s*(yes|true)", text)) or \
                        (re.search(r"(?m)^\s*socket_type\s*=", text) and re.search(r"(?m)^\s*server\s*=", text)) or \
                        re.search(r"socat\b[^\n]*\b(EXEC|SYSTEM):", text) or re.search(r"\btcpserver\b", text):
                    return True
        return False

    def native_facts(self, family: str) -> tuple[dict[str, str], dict[str, Any]] | None:
        """C/C++ dosyalar arası model olguları (bellek motoru dış girdi bilgisi); analiz gerekiyorsa kurulur."""
        if family not in self._native:
            self._native[family] = self._build_native(family)
        return self._native_facts.get(family)

    def native_analysis(self, filename: str, text: str, family: str) -> Analysis | None:
        entry = self._native.get(family)
        if entry is None:
            entry = self._native[family] = self._build_native(family)
        digests, results = entry
        relpath = filename.replace("\\", "/")
        if results is None or digests.get(relpath) != self._digest(text) or relpath not in results:
            return _MISS
        return results[relpath]

    def clike_analysis(self, filename: str, text: str) -> Analysis | None:
        if self._clike is None:
            self._clike = self._build_clike()
        digests, results = self._clike
        relpath = filename.replace("\\", "/")
        if results is None or digests.get(relpath) != self._digest(text) or relpath not in results:
            return _MISS
        return results[relpath]

    def js_analysis(self, filename: str, text: str, pii: PiiClassifier | None) -> Analysis | None:
        key = getattr(pii, "__code__", pii)
        entry = self._js.get(key)
        if entry is None:
            entry = self._build_js(pii)
            self._js[key] = entry
        digests, results = entry
        relpath = filename.replace("\\", "/")
        if results is None or digests.get(relpath) != self._digest(text) or relpath not in results:
            return _MISS
        return results[relpath]

    def python_analysis(self, filename: str, text: str, pii: PiiClassifier | None) -> Analysis | None:
        # Aynı sınıflandırıcı kodu (ör. her çağrıda yeniden oluşturulan lambda) aynı analizi paylaşır.
        key = getattr(pii, "__code__", pii)
        entry = self._python.get(key)
        if entry is None:
            entry = self._build_python(pii)
            self._python[key] = entry
        digests, results = entry
        relpath = filename.replace("\\", "/")
        if results is None or digests.get(relpath) != self._digest(text) or relpath not in results:
            return _MISS
        return results[relpath]


def project_js_handler_names(root: Path, skip_dirs: set[str] | frozenset[str]) -> frozenset[str]:
    """Proje genelinde router çağrılarında adı geçen işleyicileri topla (dosyalar arası)."""
    if not is_enabled():
        return frozenset()
    names: set[str] = set()
    seen = 0
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name for name in directories
            if name.casefold() not in skip_dirs and not (Path(current) / name).is_symlink()
        )
        for name in sorted(files):
            path = Path(current) / name
            if path.suffix.lower() not in JS_SUFFIXES or path.is_symlink():
                continue
            seen += 1
            if seen > _project_files_limit():
                return frozenset(names)
            # Yalnız normal dosyalar (O_NOFOLLOW|O_NONBLOCK + fstat): FIFO/aygıt dosyası bekletemez.
            text = read_text_bounded(path, _source_limit())
            if text is None:
                continue
            if ".get(" in text or ".post(" in text or ".put(" in text or ".delete(" in text or ".patch(" in text or ".use(" in text or ".all(" in text:
                names |= collect_js_route_handlers(text)
    return frozenset(names)
