"""Java, C# ve PHP için hızlı, dosyalar arası taint analizi (Joern'e bağımlı olmayan hafif yol).

Kapsanan çatılar: Spring (MVC/WebFlux ek açıklamaları), Servlet, JAX-RS; ASP.NET Core/MVC, Razor Pages,
WebForms (tasarımcı denetimleri); PHP (süper küreseller, include zinciri), Laravel ve Symfony istek nesneleri.

Yöntem: belirteç akışından deyim ağacı (if/döngü/switch/try), akışa duyarlı soyut yorumlama (dallar birleşir,
sabit koşullu dallar budanır), basit sabit katlama (Benchmark türü ``(7*42)-num > 200 ? … : …``, ``switch``,
``charAt``), liste/eşlem modelleri (anahtar ve sıra duyarlı ``put/get``, ``add/remove/get``), korumalar
(``is_numeric``, beyaz liste eşitliği, ``if (…) exit;``) ve ada/arite göre çözülen yöntem özetleri (parametre →
dönüş, parametre → hedef). Arındırıcılar hedef türüne göre etkilidir (ör. ``htmlspecialchars`` SQL'i korumaz;
``mysqli_real_escape_string`` yalnız tırnak içinde korur).

Çıktı :class:`taint_flow.Analysis` / :class:`taint_flow.Flow` biçimindedir; ``project_analyzer`` Python/JS ile
aynı kurallarla raporlar. Hiçbir kod çalıştırılmaz, kaynak satırı saklanmaz.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import fnmatch
import os
import re
import time
from typing import Any, Iterable

import taint_clike_lex as lex
from taint_clike_lex import Method, Tok, Unit

SUFFIXES = frozenset(lex.LANG_BY_SUFFIX)
_NOC: Any = None  # sabit yok (None sabiti için ayrı işaret gerekmez: PHP null / Java null = _NULL)
_NULL = ("<null>",)
MAX_STEPS_PER_METHOD = 40_000
MAX_SUMMARY_DEPTH = 14
MAX_INCLUDE_DEPTH = 3
MAX_PROJECT_SECONDS = max(30.0, min(3600.0, float(os.environ.get("SNIPER_TAINT_PROJECT_SECONDS", "90.0") or 90.0)))
MAX_REPORTED_CALL_DEPTH = 3


# ---------------------------------------------------------------------------
# Değer modeli
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Src:
    label: str  # request | stored | param
    desc: str
    line: int
    file: str
    param: int = -1
    via: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class T:
    src: Src
    safe: frozenset[str] = frozenset()  # arındırılmış hedef türleri; "*" hepsi; "sql?" yalnız tırnak içinde


@dataclass(frozen=True, slots=True)
class V:
    taint: frozenset[T] = frozenset()
    tag: str | None = None
    const: Any = _NOC
    items: tuple["V", ...] | None = None
    keys: tuple[tuple[Any, "V"], ...] | None = None
    type: str = ""
    prefix: str | None = None


CLEAN = V()


def _tkey(t: T) -> tuple:
    """İz sıralama anahtarı (determinizm): frozenset yinelemesi PYTHONHASHSEED'e bağlıdır; ilk gelenin kazandığı
    yerlerde (çağrı yeri bulgusu, tekilleştirme) seçim çalıştırmadan çalıştırmaya değişmesin."""
    s = t.src
    return (s.file, s.line, s.desc, s.label, s.param, s.via, tuple(sorted(t.safe)))


def _tsorted(taint: Iterable[T]) -> list[T]:
    return sorted(taint, key=_tkey)


def flow_sort_key(f: Any) -> tuple:
    """Akış listelerinin kararlı sırası: eşit (satır, tür, kaynak satırı) durumunda ekleme sırası (karma) yerine
    tam anahtar."""
    return (f.line, f.sink_kind, f.source_line, f.source_file or "", f.source, f.source_label, tuple(f.via), f.sink)


def _unsafe(t: T, kind: str) -> bool:
    return "*" not in t.safe and kind not in t.safe


def join(a: V, b: V) -> V:
    if a is b:
        return a
    if a == CLEAN and b.tag is None and b.const is _NOC:
        return V(b.taint, None, _NOC, None, None, b.type, None) if (b.items or b.keys or b.prefix) else b
    taint = a.taint | b.taint
    tag = a.tag if a.tag == b.tag else (a.tag or b.tag)
    const = a.const if (a.const is not _NOC and b.const is not _NOC and a.const == b.const
                        and type(a.const) is type(b.const)) else _NOC
    items = a.items if a.items == b.items else None
    keys = a.keys if a.keys == b.keys else None
    typ = a.type if a.type == b.type else (a.type or b.type)
    prefix = a.prefix if a.prefix == b.prefix else None
    return V(taint, tag, const, items, keys, typ, prefix)


def join_all(values: Iterable[V]) -> V:
    out = CLEAN
    first = True
    for v in values:
        out = v if first else join(out, v)
        first = False
    return out


def _deep_taint(values: Iterable[V]) -> frozenset[T]:
    """Değerlerin (dizi öğeleri/anahtarlı değerler dahil, bir düzey) taint birleşimi."""
    out: set[T] = set()
    for v in values:
        out |= v.taint
        for item in v.items or ():
            out |= item.taint
        for _key, item in v.keys or ():
            out |= item.taint
    return frozenset(out)


_PLACEHOLDER_RE = re.compile(r"\?|:(\w+)")
_UPDATE_SET_RE = re.compile(r"(?is)\bset\b(.*?)(?:\bwhere\b|$)")


def _written_placeholders(sql: str | None) -> tuple[frozenset[str], frozenset[int]]:
    """Hazırlanmış yazma deyiminde tabloya yazılan yer tutucular: (adlar, 1 tabanlı ? sıraları).

    INSERT/REPLACE: hepsi; UPDATE: yalnız SET bölümündekiler (WHERE koşulundaki değer yazılmaz)."""
    text = sql or ""
    m = _UPDATE_SET_RE.search(text) if re.match(r"(?is)\s*update\b", text) else None
    lo, hi = (m.start(1), m.end(1)) if m else (0, len(text))
    names: set[str] = set()
    positions: set[int] = set()
    for idx, ph in enumerate(_PLACEHOLDER_RE.finditer(text), 1):
        if lo <= ph.start() < hi:
            if ph.group(1):
                names.add(ph.group(1).lower())
            else:
                positions.add(idx)
    return frozenset(names), frozenset(positions)


def _bound_written(info: Any, method: str, args: list[V]) -> frozenset[T]:
    """bindParam/bindValue/bind_param/execute ile bağlanıp tabloya yazılan değerlerin taint'i."""
    names, positions = info if isinstance(info, tuple) and len(info) == 2 else (frozenset(), frozenset())
    if method in ("bindparam", "bindvalue"):
        if len(args) < 2:
            return frozenset()
        key = args[0].const
        written = (isinstance(key, str) and key.lstrip(":").lower() in names) or (isinstance(key, int) and key in positions)
        return _deep_taint([args[1]]) if written else frozenset()
    if method == "bind_param":  # mysqli: ("ss", $a, $b) — yalnız ? sıraları
        return _deep_taint([a for i, a in enumerate(args[1:], 1) if i in positions])
    # execute([..]): anahtarlı dizi adlarla, sıralı dizi ? sıralarıyla eşlenir
    out: set[T] = set()
    for arr in args[:1]:
        for i, item in enumerate(arr.items or (), 1):
            if i in positions:
                out |= item.taint
        for key, item in arr.keys or ():
            if (isinstance(key, str) and key.lstrip(":").lower() in names) or (isinstance(key, int) and key + 1 in positions):
                out |= item.taint
    return frozenset(out)


def taint_only(v: V) -> V:
    return V(v.taint) if v.taint else CLEAN


def with_safe(v: V, kinds: Iterable[str]) -> V:
    kinds = frozenset(kinds)
    if not v.taint or not kinds:
        return v
    return replace(v, taint=frozenset(T(t.src, t.safe | kinds) for t in v.taint),
                   items=None if v.items is None else tuple(with_safe(i, kinds) for i in v.items),
                   keys=None if v.keys is None else tuple((k, with_safe(x, kinds)) for k, x in v.keys))


def with_via(taint: frozenset[T], step: str) -> frozenset[T]:
    return frozenset(T(replace(t.src, via=(t.src.via + (step,))[-6:]), t.safe) for t in taint)


def join_env(*envs: dict[str, V]) -> dict[str, V]:
    envs = tuple(e for e in envs if e is not None)
    if not envs:
        return {}
    if len(envs) == 1:
        return dict(envs[0])
    keys: set[str] = set()
    for e in envs:
        keys.update(e)
    out: dict[str, V] = {}
    for k in keys:
        vals = [e.get(k) for e in envs]
        present = [v for v in vals if v is not None]
        v = join_all(present)
        if len(present) < len(vals):  # bir yolda tanımsız: sabit/etiket bilgisi kaybolur
            v = V(v.taint, v.tag, _NOC, None, None, v.type, None)
        out[k] = v
    return out


# ---------------------------------------------------------------------------
# Dil tabloları
# ---------------------------------------------------------------------------
ALL = "*"
_SANITIZE_HINTS = [
    (re.compile(r"(?i)cmd|command|shell|exec|\bos"), ("command",)),
    (re.compile(r"(?i)sql|query"), ("sql",)),
    (re.compile(r"(?i)url|redirect|ssrf|host|uri"), ("ssrf", "redirect", "ssrf_partial")),
    (re.compile(r"(?i)path|file|dir"), ("path",)),
    (re.compile(r"(?i)html|xss|script|js"), ("html",)),
    (re.compile(r"(?i)xml|xxe"), ("xxe",)),
    (re.compile(r"(?i)ldap"), ("ldap",)),
    (re.compile(r"(?i)xpath"), ("xpath",)),
]
# Yetki / nonce denetimi: bu yöntemlerdeki akışlar yalnız yetkili (yönetici) yüzeyde erişilebilir; doğrulanmış akış
# sayılmaz, ayrı düşük önemli not olarak raporlanır (Analysis.privileged_flows).
_PRIVILEGE_CALLS = frozenset({
    "current_user_can", "user_can", "author_can", "current_user_can_for_blog", "is_super_admin", "check_admin_referer",
    "check_ajax_referer", "wp_verify_nonce", "authorize", "authorizeForUser", "allows", "denies", "authorizeResource",
    "denyAccessUnlessGranted", "isGranted", "hasPermission", "isAllowed", "isAllowedAny", "isAllowedAll", "userCan",
    "checkUserRightsAny", "checkPermissions", "probablyCan", "definitelyCan", "authorizeWrite", "authorizeRead",
})
_PRIVILEGE_ANNOTATIONS = frozenset({"preauthorize", "secured", "rolesallowed", "postauthorize",
                                    # ASP.NET Core: [Authorize(Roles = "Admin")] / [AuthorizeAdmin] (yönetici)
                                    "authorize_admin", "authorizeadmin", "adminauthorize"})
# ASP.NET Core model bağlama: bu ek açıklamalı özellikler istekten doldurulur (Razor Pages / denetleyiciler / Blazor)
_CS_BOUND_PROP_ANN = frozenset({"bindproperty", "fromquery", "fromroute", "fromform", "fromheader", "frombody",
                                "supplyparameterfromquery", "supplyparameterfromform"})
_CS_MINIMAL_SOURCE_ANN = frozenset({"fromquery", "fromroute", "frombody", "fromform", "fromheader", "asparameters"})
_CS_MINIMAL_SOURCE_TYPES = frozenset({"string", "String", "StringValues", "IFormFile", "IFormFileCollection", "Uri",
                                      "object", "dynamic", "JsonElement", "JsonNode", "JsonObject", "JsonDocument"})
_CS_SERVICE_TYPE = re.compile(r"(?:Context|Service|Repository|Repo|Logger|Factory|Options|Client|Manager|Provider|"
                              r"Store|Handler|Mediator|Sender|Cache|Configuration|Environment|Accessor|Settings|Bus|"
                              r"Publisher|Dispatcher|Generator|Validator|Mapper|Encoder|Protector|Clock)$")
# EF Core: dize sabiti/ara değerli dize (FormattableString) parametreli sorgu üretir; birleştirme ham SQL olur
_CS_EF_INTERPOLATED_SAFE = frozenset({"FromSql", "FromSqlInterpolated", "ExecuteSql", "ExecuteSqlAsync",
                                      "ExecuteSqlInterpolated", "ExecuteSqlInterpolatedAsync", "SqlQuery",
                                      "ExecuteSqlCommand", "ExecuteSqlCommandAsync"})
# Kullanımdan kalkmış kod: akışlar raporlanmaz, yalnız sayılır (yönetici yetkisi notu da değildir).
_DEPRECATION_CALLS = frozenset({"_deprecated_function", "_deprecated_file", "_deprecated_hook"})
_DEPRECATION_ANNOTATIONS = frozenset({"deprecated"})
_TERMINATING = re.compile(r"(?i)^(?:wp_die|die|exit|abort|abort_if|abort_unless|wp_send_json|wp_send_json_error|"
                         r"wp_send_json_success|terminate|halt)$")
_VALIDATOR_PRED = re.compile(r"(?i)(?:^|_)(?:validate|check|verify|is_?valid|is_?safe|is_?allowed|valid|safe)(?:_|$|[A-Z])|"
                             r"^(?:isSafe|isValid|isAllowed|validate|check|verify)")
_SANITIZER_NAME = re.compile(r"(?i)(sanitiz|escape|encode|filter|clean|purif|whitelist|allowlist|validat|safe|check)")

# Java/C#: alan/yöntem sonuç türü sayı/mantık → tümüyle temiz
_CLEAN_RESULT = frozenset({
    "equals", "equalsIgnoreCase", "contains", "containsKey", "containsValue", "startsWith", "endsWith", "isEmpty",
    "isBlank", "size", "length", "count", "indexOf", "lastIndexOf", "compareTo", "compareToIgnoreCase", "hashCode",
    "matches", "hasNext", "hasMoreElements", "hasMoreTokens", "exists", "isFile", "isDirectory", "canRead",
    "intValue", "longValue", "doubleValue", "booleanValue", "Count", "Length", "Contains", "ContainsKey",
    "StartsWith", "EndsWith", "Equals", "IndexOf", "LastIndexOf", "Any", "All", "IsNullOrEmpty",
    "IsNullOrWhiteSpace", "CompareTo", "GetHashCode", "TryParse", "Exists", "HasValue", "getStatus",
    "getStatusCode", "nextInt", "nextLong", "nextDouble", "nextBoolean", "currentTimeMillis", "nanoTime",
    "getTime", "getId", "Compare", "CompareOrdinal", "IsMatch",
})
# Çözme (Base64/URL/HTML/entity): önceki doğrulama/arındırma kodlanmış biçime uygulanmıştı; çözülen değerde
# geçersizdir (CWE-180: doğrulamadan sonra kanonikleştirme). Sonuç arındırılmamış taint taşır.
_DECODE_CALLS = frozenset({"decode", "Decode", "decodeBuffer", "decodeBase64", "FromBase64String", "UrlDecode",
                           "HtmlDecode", "UnescapeDataString", "unescape", "unescapeHtml4", "unescapeJava",
                           "unescapeXml", "unescapeEcmaScript"})
_PHP_DECODE_CALLS = frozenset({"base64_decode", "urldecode", "rawurldecode", "html_entity_decode",
                               "htmlspecialchars_decode", "hex2bin", "convert_uudecode", "quoted_printable_decode"})
_PARSE_ALL = frozenset({"parseInt", "parseLong", "parseDouble", "parseFloat", "parseBoolean", "parseShort",
                        "parseByte", "toHexString", "ToInt32", "ToInt64", "ToInt16", "ToDouble", "ToDecimal",
                        "ToBoolean", "ToSingle", "ToByte", "fromString", "randomUUID", "NewGuid"})
_NUMERIC_CLASSES = frozenset({"integer", "long", "double", "float", "short", "byte", "boolean", "int", "int32",
                              "int64", "int16", "decimal", "guid", "bool", "datetime", "uint", "ulong", "biginteger",
                              "bigdecimal", "uuid", "math", "char", "character", "timespan"})

_JAVA_SAN = {
    "encodeForHTML": ("html",), "encodeForHTMLAttribute": ("html",), "encodeForJavaScript": ("html",),
    "encodeForCSS": ("html",), "encodeForURL": ("html",), "encodeForXML": ("html", "xxe"),
    "encodeForXMLAttribute": ("html",), "encodeForSQL": ("sql",), "encodeForLDAP": ("ldap",),
    "encodeForDN": ("ldap",), "encodeForXPath": ("xpath",), "encodeForOS": ("command",),
    "escapeHtml": ("html",), "escapeHtml3": ("html",), "escapeHtml4": ("html",), "escapeXml": ("html",),
    "escapeXml10": ("html",), "escapeXml11": ("html",), "escapeEcmaScript": ("html",),
    "escapeJavaScript": ("html",), "htmlEscape": ("html",), "forHtml": ("html",), "forHtmlContent": ("html",),
    "forHtmlAttribute": ("html",), "forJavaScript": ("html",), "forJavaScriptBlock": ("html",),
    "forCssString": ("html",), "forUriComponent": ("html", "path", "command"), "escapeSql": ("sql",),
    "escapeLDAPSearchFilter": ("ldap",), "quoteReplacement": (),
}
_CS_SAN = {
    "HtmlEncode": ("html",), "HtmlAttributeEncode": ("html",), "JavaScriptStringEncode": ("html",),
    "UrlEncode": ("html", "redirect"), "UrlPathEncode": ("html",),
    "EscapeDataString": ("html", "path", "command", "redirect"),
    "LdapFilterEncode": ("ldap",), "LdapDistinguishedNameEncode": ("ldap",), "XPathEncode": ("xpath",),
    "GetFileName": ("path",), "GetFileNameWithoutExtension": ("path",), "GetExtension": (ALL,),
    "SanitizeHtml": ("html",), "Sanitize": ("html",),
}
_PHP_SAN = {
    "htmlspecialchars": ("html",), "htmlentities": ("html",), "strip_tags": ("html",), "esc_html": ("html",),
    "esc_attr": ("html",), "esc_js": ("html",), "esc_textarea": ("html",), "sanitize_text_field": ("html",),
    "e": ("html",), "esc_url": ("html", "redirect"), "urlencode": ("html", "path"), "rawurlencode": ("html", "path"),
    "escapeshellarg": ("command",), "escapeshellcmd": ("command",), "basename": ("path",),
    "intval": (ALL,), "floatval": (ALL,), "boolval": (ALL,), "abs": (ALL,), "count": (ALL,), "strlen": (ALL,),
    "absint": (ALL,), "md5": (ALL,), "sha1": (ALL,), "hash": (ALL,), "crc32": (ALL,), "password_hash": (ALL,),
    "base64_encode": (ALL,), "bin2hex": (ALL,), "is_numeric": (ALL,), "ctype_digit": (ALL,), "sizeof": (ALL,),
    "pg_escape_literal": ("sql",), "uniqid": (ALL,), "time": (ALL,), "rand": (ALL,), "mt_rand": (ALL,),
    "strpos": (ALL,), "stripos": (ALL,), "preg_match": (ALL,), "in_array": (ALL,), "array_key_exists": (ALL,),
    "is_array": (ALL,), "is_string": (ALL,), "isset": (ALL,), "empty": (ALL,), "filesize": (ALL,),
    "file_exists": (ALL,), "is_file": (ALL,), "is_dir": (ALL,), "strcmp": (ALL,), "strcasecmp": (ALL,),
    "password_verify": (ALL,), "hash_equals": (ALL,), "date": (ALL,), "number_format": (ALL,),
    "wp_kses": ("html",), "wp_kses_post": ("html",), "wp_kses_data": ("html",), "esc_html__": ("html",),
    "esc_attr__": ("html",), "esc_html_x": ("html",), "esc_attr_x": ("html",), "wp_strip_all_tags": ("html",),
    "sanitize_key": (ALL,), "sanitize_title": (ALL,), "sanitize_email": (ALL,), "sanitize_file_name": ("path", "html"),
    "sanitize_html_class": (ALL,), "tag_escape": ("html",), "esc_url_raw": ("html",),
}
_PHP_SQL_ESCAPE = frozenset({"mysqli_real_escape_string", "mysql_real_escape_string", "mysql_escape_string",
                             "addslashes", "pg_escape_string", "sqlite_escape_string", "real_escape_string",
                             "escape_string", "esc_sql", "sqlite3_escape_string", "escapeString"})


@dataclass(frozen=True)
class Sink:
    kind: str
    args: tuple[int, ...] | None  # None: tüm argümanlar
    recv: tuple[str, ...] | None = None  # alıcı tanımlayıcısında aranan alt dizeler
    flag: str | None = None  # dosyada bulunması gereken işaret (ör. enableDefaultTyping)
    unless_flag: str | None = None  # dosyada varsa hedef değil (ör. setFeature)


def _s(kind: str, args: tuple[int, ...] | None = (0,), recv: tuple[str, ...] | None = None, **kw: Any) -> Sink:
    return Sink(kind, args, recv, **kw)


_XXE_RECV = ("documentbuilder", "saxparser", "xmlreader", "saxreader", "digester", "xmlparser", "saxbuilder",
             "documenthelper", "unmarshaller", "xmlinputfactory")
_JAVA_SINKS: dict[str, list[Sink]] = {
    **{n: [_s("sql")] for n in ("executeQuery", "executeUpdate", "executeLargeUpdate", "addBatch",
                                 "prepareStatement", "prepareCall", "createNativeQuery", "createSQLQuery",
                                 "nativeQuery")},
    "execute": [_s("sql", recv=("statement", "stmt", "jdbc", "template", "connection", "conn", "callable", "sql")),
                _s("eval", recv=("runner", "expressrunner"), unless_flag="setForbidInvokeSecurityRiskMethods")],
    **{n: [_s("sql", recv=("jdbc", "template"))] for n in ("query", "queryForObject", "queryForList",
                                                           "queryForMap", "queryForRowSet", "queryForLong",
                                                           "queryForInt", "queryForStream", "batchUpdate")},
    "update": [_s("sql", recv=("jdbc", "template"))],
    "createQuery": [_s("sql", recv=("session", "entitymanager", "manager", "hibernate", "em"))],
    "exec": [_s("command", None, recv=("runtime",))],
    "command": [_s("command", None, recv=("processbuilder", "pb", "builder"))],
    **{n: [_s("html", None, recv=("writer", "printwriter", "servletoutputstream", "jspwriter", "outputstream"))]
       for n in ("print", "println", "write", "format", "printf", "append")},
    "sendRedirect": [_s("redirect", recv=("resp", "response"))],
    "jsp_include": [_s("path")],  # JSP <jsp:include|forward page="<%= … %>"> (taint_clike_lex.jsp_to_java)
    "getRequestDispatcher": [_s("redirect", recv=("req", "request"))],
    "setAttribute": [_s("session", None, recv=("session",))],
    "putValue": [_s("session", None, recv=("session",))],
    "search": [_s("ldap", (0, 1), recv=("dircontext", "ctx", "ldap", "idc", "context"))],
    "evaluate": [_s("xpath", recv=("xpath", "xp")), _s("eval", recv=("groovyshell", "shell", "groovy")),
                 _s("eval", None, recv=("class:velocity",))],
    "compile": [_s("xpath", recv=("xpath", "xp"))],
    "selectNodes": [_s("xpath")], "selectSingleNode": [_s("xpath")],
    "eval": [_s("eval", recv=("engine", "scriptengine", "nashorn"))],
    "defineClass": [_s("eval", (1,))],  # ClassLoader.defineClass(ad, bayt, …): istekten gelen baytlar sınıf olur
    "parseExpression": [_s("eval", recv=("parser", "expression", "spel"), unless_flag="SimpleEvaluationContext")],
    "fromXML": [_s("deserialize", recv=("xstream",))],
    "readValue": [_s("deserialize", recv=("mapper", "objectmapper"), flag="enableDefaultTyping"),
                  _s("deserialize", recv=("mapper", "objectmapper"), flag="activateDefaultTyping")],
    "parseObject": [_s("deserialize", recv=("class:json",))],
    "parse": [_s("deserialize", recv=("class:json",)),
              _s("xxe", None, recv=_XXE_RECV, unless_flag="setFeature")],
    "build": [_s("xxe", None, recv=("saxbuilder",), unless_flag="setFeature")],
    "read": [_s("xxe", None, recv=("saxreader",), unless_flag="setFeature")],
    "parseText": [_s("xxe", None, recv=("documenthelper",), unless_flag="setFeature")],
    "unmarshal": [_s("xxe", None, recv=("unmarshaller",), unless_flag="setFeature")],
    "load": [_s("deserialize", recv=("yaml",))], "loadAll": [_s("deserialize", recv=("yaml",))],
    "loadAs": [_s("deserialize", recv=("yaml",))],
    "deserialize": [_s("deserialize", recv=("serializationutils",))],
    "lookup": [_s("deserialize", recv=("context", "initialcontext", "jndi", "jnditemplate"))],
    "doLookup": [_s("deserialize", recv=("class:initialcontext", "initialcontext", "context", "jndi"))],
    "readClassAndObject": [_s("deserialize", recv=("kryo",))],
    **{n: [_s("ssrf", recv=("resttemplate", "template", "rest"))]
       for n in ("getForObject", "getForEntity", "postForObject", "postForEntity", "exchange", "patchForObject",
                 "headForHeaders", "optionsForAllow", "postForLocation")},
    "connect": [_s("ssrf", recv=("class:jsoup",))],
    # 17. tur: Spring ResourceLoader/ApplicationContext.getResource("file:" + x) — dosya sistemi yolu
    "getResource": [_s("path", recv=("loader", "resourceloader", "context", "applicationcontext"))],
    "get": [_s("ssrf", recv=("class:httputil", "class:httprequest")), _s("path", None, recv=("class:paths",))],
    "post": [_s("ssrf", recv=("class:httputil", "class:httprequest"))],
    "of": [_s("path", None, recv=("class:path",))],
    "Get": [_s("ssrf", recv=("class:request",))], "Post": [_s("ssrf", recv=("class:request",))],
    "url": [_s("ssrf", recv=("builder",))], "uri": [_s("ssrf", recv=("webclient",))],
    **{n: [_s("path", recv=("class:fileutils", "class:files"))]
       for n in ("readFileToString", "readFileToByteArray", "readLines", "writeStringToFile", "forceDelete",
                 "copyFile", "openInputStream", "openOutputStream", "readAllBytes", "readAllLines",
                 "newInputStream", "newOutputStream", "newBufferedReader", "newBufferedWriter", "delete",
                 "lines", "readString")},
}
_JAVA_FILE_CONTENT = frozenset({"readAllBytes", "readString", "readAllLines", "lines", "newInputStream",
                                 "newBufferedReader", "readAttributes", "size", "probeContentType"})
_JAVA_REMOTE_CONTENT = frozenset({"getForObject", "getForEntity", "postForObject", "postForEntity", "exchange",
                                  "patchForObject"})
_JAVA_CTOR_SINKS: dict[str, list[Sink]] = {
    **{n: [_s("path", None)] for n in ("File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter",
                                       "RandomAccessFile", "ZipFile", "JarFile")},
    "ProcessBuilder": [_s("command", None)],
    **{n: [_s("ssrf")] for n in ("HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpHead", "HttpPatch",
                                  "HttpOptions", "GetMethod", "PostMethod", "Socket")},
    "RedirectView": [_s("redirect")],
}
_CS_SQL_CTORS = ("SqlCommand", "MySqlCommand", "SqliteCommand", "SQLiteCommand", "OleDbCommand", "OdbcCommand",
                 "NpgsqlCommand", "OracleCommand", "SqlCeCommand", "SqlDataAdapter", "MySqlDataAdapter",
                 "SqliteDataAdapter", "SQLiteDataAdapter", "OleDbDataAdapter", "OdbcDataAdapter",
                 "NpgsqlDataAdapter", "OracleDataAdapter")
_CS_SINKS: dict[str, list[Sink]] = {
    **{n: [_s("sql")] for n in ("FromSqlRaw", "ExecuteSqlRaw", "ExecuteSqlRawAsync", "SqlQuery", "SqlQueryRaw",
                                "ExecuteSqlCommand", "ExecuteSqlCommandAsync", "FromSql")},
    "ExecuteQuery": [_s("sql", recv=("context", "db", "datacontext"))],
    **{n: [_s("sql", recv=("conn", "connection", "db", "cnn", "sqlconnection", "dbconnection"))]
       for n in ("Query", "QueryAsync", "QueryFirst", "QueryFirstOrDefault", "QuerySingle", "QuerySingleOrDefault",
                 "QueryMultiple", "Execute", "ExecuteAsync", "ExecuteScalar", "ExecuteReader",
                 "QueryFirstAsync", "QueryFirstOrDefaultAsync", "ExecuteScalarAsync")},
    "Start": [_s("command", None, recv=("class:process",))],
    "Write": [_s("html", recv=("resp", "response", "writer"))],
    "Raw": [_s("html", recv=("html",))],
    **{n: [_s("redirect", recv=None)] for n in ("Redirect", "RedirectPermanent", "RedirectPreserveMethod",
                                                "RedirectPermanentPreserveMethod")},
    "Deserialize": [_s("deserialize", recv=("binaryformatter", "formatter", "netdatacontract", "losformatter",
                                            "objectstateformatter", "soapformatter", "javascriptserializer"))],
    "DeserializeObject": [_s("deserialize", recv=("javascriptserializer",), flag="SimpleTypeResolver")],
    "SelectNodes": [_s("xpath")], "SelectSingleNode": [_s("xpath")],
    "Evaluate": [_s("xpath", recv=("xpath", "navigator", "nav"))],
    "Select": [_s("xpath", recv=("xpathnavigator",)), _s("sql", (0,), recv=("tables", "datatable"))],
    "Matches": [_s("xpath", recv=("xpathnavigator",))],
    "Compute": [_s("sql", (0, 1), recv=("tables", "datatable"))],  # DataTable filtre ifadesi
    "Compile": [_s("xpath", recv=("xpath", "navigator", "nav"))],
    **{n: [_s("path", (0, 1), recv=("class:file", "class:directory"))]
       for n in ("ReadAllText", "ReadAllBytes", "ReadAllLines", "ReadLines", "WriteAllText", "WriteAllBytes",
                 "WriteAllLines", "AppendAllText", "OpenRead", "OpenWrite", "OpenText", "Open", "Delete",
                 "CreateText", "Copy", "Move", "Replace", "GetFiles", "GetDirectories", "EnumerateFiles",
                 "ReadAllTextAsync", "ReadAllBytesAsync", "WriteAllTextAsync", "AppendText")},
    "Create": [_s("path", recv=("class:file", "class:directory")),
               _s("ssrf", recv=("class:webrequest", "class:httpwebrequest"))],
    "SaveAs": [_s("path")],
    "TransmitFile": [_s("path", recv=("resp", "response"))], "WriteFile": [_s("path", recv=("resp", "response"))],
    "PhysicalFile": [_s("path")],
    **{n: [_s("ssrf", recv=("client", "http"))]
       for n in ("GetAsync", "GetStringAsync", "GetByteArrayAsync", "GetStreamAsync", "PostAsync", "PutAsync",
                 "DeleteAsync", "PatchAsync")},
    **{n: [_s("ssrf", recv=("webclient", "client", "wc"))]
       for n in ("DownloadString", "DownloadData", "DownloadFile", "UploadString", "UploadData",
                 "DownloadStringAsync", "DownloadStringTaskAsync", "DownloadDataTaskAsync")},
    "SetString": [_s("session", None, recv=("session",))],
    # Dinamik C# derleme/çalıştırma (CodeDOM); Roslyn betikleri aşağıda mevcut adlara eklenir
    "CompileAssemblyFromSource": [_s("eval", None)],
    "LoadFrom": [_s("eval", recv=("class:assembly", "assembly"))],
    "LoadFile": [_s("eval", recv=("class:assembly", "assembly"))],
}
for _name in ("EvaluateAsync", "RunAsync", "Create", "Evaluate"):
    _CS_SINKS[_name] = _CS_SINKS.get(_name, []) + [_s("eval", (0,), recv=("class:csharpscript",))]
# Sunucu tarafı şablon: şablon metninin kendisi istekten (RazorEngine, Scriban/DotLiquid/Fluid Template.Parse)
for _name, _recv in (("RunCompile", ("razor",)), ("Compile", ("razor",)), ("Parse", ("class:template",)),
                     ("ParseLiquid", ("class:template",)), ("TryParse", ("fluidparser", "parser"))):
    _CS_SINKS[_name] = _CS_SINKS.get(_name, []) + [_s("ssti", (0,), recv=_recv)]
# 19. tur: ProcessStartInfo.ArgumentList.Add(x) — süreç argümanı (sh -c ile kabuk komutu olur)
_CS_SINKS["Add"] = _CS_SINKS.get("Add", []) + [_s("command", (0,), recv=("argumentlist",))]
_CS_CTOR_SINKS: dict[str, list[Sink]] = {
    **{n: [_s("sql")] for n in _CS_SQL_CTORS},
    "ProcessStartInfo": [_s("command", None)],
    **{n: [_s("path")] for n in ("FileStream", "StreamReader", "StreamWriter", "FileInfo", "DirectoryInfo")},
    "DirectorySearcher": [_s("ldap", None)],
    "SearchRequest": [_s("ldap", (1,))],  # SearchRequest(dn, filtre, …)
    "DirectoryEntry": [_s("ldap", (0,))],  # LDAP yolu / ayırt edici ad
    "ResourceReader": [_s("deserialize", (0,))],  # .resources akışı BinaryFormatter ile çözülür
    "HtmlString": [_s("html")], "MvcHtmlString": [_s("html")],
    "RedirectResult": [_s("redirect")],
    "HttpRequestMessage": [_s("ssrf", (1,))],
}
# 25. tur: kayıtlı veride kimlik/sayı/tarih sütunları (enjeksiyon taşımaz; sütun duyarlılığı)
_CLEAN_COLUMN_RE = re.compile(r"(?:^id$|Id$|_id$|ID$|[Dd]ate$|[Tt]ime$|_at$|At$|[Cc]ount$|^age$|Age$|[Pp]rice$|"
                              r"[Aa]mount$|[Qq]uantity$|[Yy]ear$)")
# 25. tur: bellek içi depo sınıflarında varlık koleksiyonları (öğe türü kalıcı depo varlığı sayılır)
_CS_REPO_COLLECTIONS = frozenset({"List", "IList", "ICollection", "Collection", "HashSet", "ISet", "Dictionary",
                                  "IDictionary", "ConcurrentDictionary", "ConcurrentBag", "ConcurrentQueue"})
_CS_REPO_SCALARS = frozenset({"String", "Int32", "Int64", "Guid", "DateTime", "Decimal", "Double", "Boolean"})
_CS_PROP_SINKS: dict[str, list[Sink]] = {
    "CommandText": [_s("sql", ())],
    "InnerHtml": [_s("html", ())], "InnerHTML": [_s("html", ())],
    "Arguments": [_s("command", (), recv=("psi", "startinfo", "processstartinfo", "process", "info"))],
    "FileName": [_s("command", (), recv=("psi", "startinfo", "processstartinfo", "process"))],
    "Filter": [_s("ldap", (), recv=("search", "directorysearcher"))],
    "Path": [_s("ldap", (), recv=("directoryentry",))],
    "RowFilter": [_s("sql", (), recv=("dataview", "defaultview"))],
    "Location": [_s("redirect", (), recv=("responseheaders", "headers"))],  # ResponseHeaders.Location = new Uri(x)
    # WebForms SqlDataSource: arka kodda birleştirilen komut metni (SqlDataSource1.SelectCommand = "…" + x)
    **{n: [_s("sql", (), recv=("sqldatasource", "datasource"))]
       for n in ("SelectCommand", "UpdateCommand", "InsertCommand", "DeleteCommand")},
}
_WEBFORMS_INPUTS = frozenset({"TextBox", "HtmlInputText", "HiddenField", "HtmlInputHidden", "DropDownList",
                              "ListBox", "RadioButtonList", "CheckBoxList", "HtmlTextArea", "FileUpload",
                              "HtmlInputFile", "HtmlInputPassword", "HtmlSelect",
                              "RichTextBox", "MaskedTextBox", "ComboBox"})  # WinForms giriş denetimleri
_WEBFORMS_OUTPUTS = frozenset({"Label", "Literal", "LiteralControl", "HtmlGenericControl", "HtmlAnchor",
                               "HyperLink"})
_PHP_FUNC_SINKS: dict[str, list[Sink]] = {
    "mysql_query": [_s("sql")], "mssql_query": [_s("sql")], "mysqli_query": [_s("sql", (1,))],
    "mysqli_multi_query": [_s("sql", (1,))], "mysqli_real_query": [_s("sql", (1,))],
    "mysqli_prepare": [_s("sql", (1,))], "mysqli_send_query": [_s("sql", (1,))],
    "pg_query": [_s("sql", None)], "pg_send_query": [_s("sql", (1,))], "pg_prepare": [_s("sql", (2,))],
    "sqlite_query": [_s("sql", None)], "sqlsrv_query": [_s("sql", (1,))], "odbc_exec": [_s("sql", (1,))],
    "odbc_prepare": [_s("sql", (1,))], "db2_exec": [_s("sql", (1,))], "oci_parse": [_s("sql", (1,))],
    **{n: [_s("command")] for n in ("system", "exec", "shell_exec", "passthru", "popen", "proc_open",
                                    "pcntl_exec", "expect_popen")},
    "eval": [_s("eval")], "assert": [_s("eval")], "create_function": [_s("eval", None)],
    "call_user_func": [_s("eval")], "call_user_func_array": [_s("eval")],
    "printf": [_s("html", None)], "vprintf": [_s("html", None)], "print_r": [_s("html")],
    "die": [_s("html")], "exit": [_s("html")],
    **{n: [_s("path")] for n in ("file_get_contents", "fopen", "readfile", "file", "file_put_contents", "unlink",
                                 "mkdir", "rmdir", "opendir", "scandir", "dir", "parse_ini_file", "highlight_file",
                                 "show_source", "gzopen", "simplexml_load_file", "touch", "chmod", "chown",
                                 "fpassthru_file", "readlink", "glob", "is_writable_file")},
    "copy": [_s("path", (0, 1))], "rename": [_s("path", (0, 1))], "symlink": [_s("path", (0, 1))],
    "move_uploaded_file": [_s("path", (1,))],
    "curl_init": [_s("ssrf")], "fsockopen": [_s("ssrf")], "get_headers": [_s("ssrf")],
    "wp_redirect": [_s("redirect")], "wp_safe_redirect": [], "redirect": [_s("redirect")],
    "unserialize": [_s("deserialize")], "maybe_unserialize": [_s("deserialize")],
    "igbinary_unserialize": [_s("deserialize")], "yaml_parse": [_s("deserialize")],
    "ldap_search": [_s("ldap", (2,))], "ldap_list": [_s("ldap", (2,))], "ldap_read": [_s("ldap", (2,))],
}
_PHP_DB_RECV = ("db", "mysqli", "pdo", "conn", "link", "dbh", "database", "connection", "sql", "mysql")
_PHP_METHOD_SINKS: dict[str, list[Sink]] = {
    **{n: [_s("sql", recv=_PHP_DB_RECV)] for n in ("query", "multi_query", "real_query", "exec", "prepare",
                                                   "unbuffered_query", "querysingle", "exec_query")},
    **{n: [_s("sql", recv=("wpdb",))] for n in ("get_results", "get_var", "get_row", "get_col")},
    **{n: [_s("sql", recv=("class:db",))] for n in ("select", "statement", "unprepared", "insert", "update",
                                                    "delete", "affectingstatement", "raw", "selectone")},
    **{n: [_s("sql")] for n in ("whereraw", "orwhereraw", "selectraw", "orderbyraw", "havingraw", "groupbyraw",
                                "fromraw", "joinraw")},
    **{n: [_s("ssrf", recv=("class:http", "client", "guzzle"))] for n in ("get", "post", "put", "head", "patch",
                                                                         "delete", "fetch")},
    "request": [_s("ssrf", (1,), recv=("client", "guzzle", "class:http"))],
    # 19. tur: Doctrine DBAL/ORM (Symfony), PSR-7 yanıt gövdesi (Slim), Symfony AbstractController::redirect
    **{n: [_s("sql", recv=_PHP_DB_RECV + ("em", "entitymanager", "manager", "dbal", "getconnection"))]
       for n in ("executequery", "executestatement", "executeupdate", "fetchallassociative", "fetchassociative",
                 "fetchone", "fetchallnumeric", "fetchnumeric", "fetchfirstcolumn", "fetchallkeyvalue",
                 "iterateassociative", "fetchall", "fetchassoc", "fetchcolumn", "createnativequery")},
    "createquery": [_s("sql", recv=("em", "entitymanager", "manager", "getentitymanager", "getmanager"))],
    "write": [_s("html", recv=("getbody",))],  # PSR-7: $response->getBody()->write($html)
    "to": [_s("redirect", recv=("class:redirect", "redirect"))],
    "away": [_s("redirect", recv=("class:redirect", "redirect"))],
    "xpath": [_s("xpath")],
    "evaluate": [_s("xpath", recv=("xpath",))],
    # Twig: şablon metninin kendisi kullanıcı verisi (createTemplate; Twig 1 dize yükleyicisiyle render/display)
    "createtemplate": [_s("ssti", recv=("twig", "environment"))],
    "render": [_s("ssti", recv=("twig",), flag="Twig_Loader_String")],
    "display": [_s("ssti", recv=("twig",), flag="Twig_Loader_String")],
}
_PHP_URL_WRAPPER_FUNCS = frozenset({"file_get_contents", "fopen", "readfile", "file"})
_PHP_CONTROLLER_BASES = frozenset({"Controller", "AbstractController", "BaseController", "CI_Controller",
                                   "ResourceController", "ResourcePresenter", "MY_Controller"})
# Dosya içeriği okuyan PHP işlevleri ve C# File.* okuyucuları (W2-XSS: içerik HTML bağlamında saldırgan verisi değil).
_PHP_FILE_READ = frozenset({"file_get_contents", "file", "fread", "fgets", "fgetss", "stream_get_contents"})
_CS_FILE_READ = frozenset({"ReadAllText", "ReadAllTextAsync", "ReadAllLines", "ReadAllLinesAsync", "ReadLines",
                           "ReadAllBytes", "ReadAllBytesAsync"})
_URL_FIELD = re.compile(r"(?i)\[['\"][^'\"]*(?:url|uri|link|host|domain|endpoint|feed|remote)[^'\"]*['\"]\]")
_PHP_XPATH_QUERY = Sink("xpath", (0,), ("xpath",))

_REQ_JAVA = {"getParameter", "getParameterValues", "getParameterMap", "getParameterNames", "getHeader",
             "getHeaders", "getHeaderNames", "getQueryString", "getInputStream", "getReader", "getRequestURI",
             "getRequestURL", "getPathInfo", "getCookies", "getPart", "getParts", "getRemoteUser",
             "getPathTranslated", "getContentType"}
_REQ_CS_MEMBERS = {"Query", "Form", "QueryString", "Params", "Cookies", "Headers", "Path", "PathBase", "Body", "ContentType",
                   "RawUrl", "Url", "UrlReferrer", "UserAgent", "Files", "ServerVariables", "RouteValues",
                   "InputStream", "PathInfo", "Item"}
_REQ_PHP_METHODS = {"input", "query", "get", "post", "all", "only", "except", "cookie", "header", "route", "json",
                    "getcontent", "file", "string", "str", "collect", "validated", "safe", "keys", "getquerystring",
                    "getrequesturi", "getpathinfo", "getparsedbody", "getqueryparams", "getbody", "getcookieparams",
                    "getuploadedfiles", "getattribute", "getheaderline", "getheader", "getserverparams",
                    "get_param", "get_params", "get_json_params", "get_body_params", "get_query_params",
                    "get_file_params", "get_url_params", "get_body", "get_header", "get_headers",
                    # 19. tur: CodeIgniter 4 IncomingRequest
                    "getget", "getpost", "getvar", "getjson", "getrawinput", "getjsonvar", "getgetpost", "getpostget",
                    "getcookie", "getrawinputvar", "getfile", "getfiles"}
# 19. tur: CodeIgniter 3 giriş nesnesi ($this->input->get('x'))
_CI_INPUT_METHODS = frozenset({"get", "post", "get_post", "post_get", "cookie", "server", "request_headers",
                               "get_request_header", "input_stream", "user_agent", "raw_input_stream"})
# Alıcı türü bilinmeyen zincirlerde proje yöntemine değil kütüphane modeline gidilecek yaygın adlar
_COMMON_LIBRARY_METHODS = frozenset({
    "append", "toString", "ToString", "format", "Format", "get", "put", "add", "remove", "set", "equals", "length",
    "substring", "split", "replace", "replaceAll", "trim", "getBytes", "toCharArray", "toLowerCase", "toUpperCase",
    "valueOf", "next", "nextElement", "getValue", "getKey", "iterator", "stream", "map", "filter", "collect",
    "contains", "indexOf", "isEmpty", "size", "close", "flush", "write", "print", "println", "read", "readLine",
    "getName", "hashCode", "compareTo", "join", "concat", "insert", "delete", "clear", "keySet", "values",
    "entrySet", "toArray", "Add", "Contains", "Split", "Trim", "Replace", "Substring", "ToLower", "ToUpper",
})
_LOOKUP_FUNC = re.compile(r"^(?:get_|wp_cache_get|fetch_|find_|load_|lookup_|get(?:option|meta|transient|setting|"
                          r"config|instance|by|row|item)\b)")
_REQ_HELPER = re.compile(r"(?i)^(get|read|extract|fetch)?_?(cookie|cookies|param|params|parameter|parameters|header|"
                         r"headers|body|requestbody|request_body|query|querystring|input|payload|json|form)")
_SUPERGLOBAL_SRC = {"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES"}
_REDIRECT_KINDS = ("redirect", "ssrf", "ssrf_partial")  # ana makine denetimi (17. tur)
_SERVER_SRC = re.compile(r"(?i)^(HTTP_.*|QUERY_STRING|REQUEST_URI|PHP_SELF|PATH_INFO|PATH_TRANSLATED|"
                         r"REDIRECT_URL|ORIG_PATH_INFO|SCRIPT_NAME|REQUEST_METHOD_OVERRIDE|CONTENT_TYPE)$")
_STORED_JAVA = {"getString", "getNString", "getObject", "getClob", "getCharacterStream"}
_STORED_PHP = {"mysqli_fetch_assoc", "mysqli_fetch_array", "mysqli_fetch_row", "mysqli_fetch_object",
               "mysql_fetch_assoc", "mysql_fetch_array", "mysql_fetch_row", "mysql_result", "pg_fetch_assoc",
               "pg_fetch_array", "pg_fetch_row", "pg_fetch_result", "sqlite_fetch_array"}
_STORED_PHP_METHODS = {"fetch", "fetchall", "fetch_assoc", "fetch_array", "fetch_row", "fetch_object",
                       "fetchcolumn", "fetchobject"}

# Kotlin çatıları (taint_kotlin çevirisi; yalnız lehçe "kotlin" birimlerinde)
_KT_KTOR_RECEIVE = frozenset({"receiveText", "receive", "receiveParameters", "receiveMultipart", "receiveNullable",
                              "receiveStream", "receiveChannel", "receiveOrNull"})
_KT_HTML_ENCODERS = frozenset({"encodeURLPath", "encodeURLParameter", "encodeURLQueryComponent", "encodeURLPathPart",
                               "escapeHTML", "escapeHtml", "escapeHtml4", "htmlEscape", "encodeForHTML"})
_KT_REQ_METHODS = frozenset({"queryParam", "queryParams", "queryParamMap", "formParam", "formParams", "formParamMap",
                             "pathParam", "pathParamMap", "bodyAsClass", "bodyAsBytes", "bodyToMono",
                             "bodyToFlux", "uploadedFile", "uploadedFiles", "queryParamAsClass", "formParamAsClass",
                             "pathParamAsClass", "bodyValidator", "bodyAsInputStream"})
_KT_REQ_METHODS_CTX = frozenset({"body", "header", "cookie", "headerMap", "cookieMap", "queryString", "fullUrl", "url",
                                 "getParam", "query", "form", "path", "queries", "getHeader", "bodyAsString",
                                 "getBodyAsString", "getBodyAsJson", "params", "bodyString"})
_KT_CTX_NAMES = frozenset({"ctx", "context", "req", "request", "routingcontext", "rc", "serverrequest"})
# Spring WebFlux ServerRequest (işlevsel uç noktalar; Java ve Kotlin coroutine uzantıları)
_WEBFLUX_REQ = frozenset({"queryParam", "queryParams", "pathVariable", "pathVariables", "formData", "multipartData",
                          "bodyToMono", "bodyToFlux", "body", "headers", "cookies", "awaitBody", "awaitBodyOrNull",
                          "awaitFormData", "awaitMultipartData", "uri", "path", "requestPath"})
_KT_SAME_SITE = ("redirect", "ssrf", "ssrf_partial")
_KT_CLEAN_METHODS = frozenset({"toInt", "toIntOrNull", "toLong", "toLongOrNull", "toDouble", "toDoubleOrNull", "toFloat",
                               "toFloatOrNull", "toShort", "toShortOrNull", "toByte", "toByteOrNull", "toBoolean",
                               "toBooleanStrict", "toBooleanStrictOrNull", "toBigInteger", "toBigDecimal",
                               "toBigIntegerOrNull", "toBigDecimalOrNull", "toUInt", "toULong", "toUIntOrNull",
                               "toULongOrNull", "isEmpty", "isBlank", "isNotEmpty", "isNotBlank", "isNullOrEmpty",
                               "isNullOrBlank", "count", "hashCode", "equals", "compareTo", "startsWith", "endsWith",
                               "contains", "matches", "containsKey", "any", "all", "none", "coerceAtLeast",
                               "coerceAtMost", "coerceIn", "sumOf", "toUUID"})
_KT_TYPED_FACTORIES = {"newDocumentBuilder": "DocumentBuilder", "newSAXParser": "SAXParser", "getXMLReader": "XMLReader",
                       "createUnmarshaller": "Unmarshaller"}


# Struts2 eylemleri (ActionSupport / ModelDriven): istek parametreleri ayarlayıcılar üzerinden alanlara yazılır.
_STRUTS_BASES = frozenset({"ActionSupport", "ModelDriven"})
_STRUTS_FIELD_TYPES = frozenset({"String", "String[]", "List", "Object", "CharSequence"})
_STRUTS_ACTION_RE = re.compile(r"(?is)<action\b([^>]*)>(.*?)</action>")
_STRUTS_RESULT_RE = re.compile(r"(?is)<result\b([^>]*)>(.*?)</result>")
_STRUTS_ATTR_RE = re.compile(r"""(\w+)\s*=\s*["']([^"']*)["']""")
_STRUTS_EXPR_RE = re.compile(r"\$\{\s*(\w+)\s*\}")


_STRUTS_PROPERTY_RE = re.compile(r"(?is)<s:property\b([^>]*?)/?>")
_STRUTS_ITERATOR_RE = re.compile(r"(?is)<s:iterator\b([^>]*)>|</s:iterator\s*>")
_STRUTS_OGNL_NAME_RE = re.compile(r"^\s*(?:%\{\s*)?(#?[A-Za-z_][\w.]*)\s*\}?\s*$")


def struts_result_pages(texts: dict[str, str]) -> dict[str, set[str]]:
    """struts.xml: sonuç sayfası (``x.jsp``, baştaki / olmadan) → onu işleyen eylem sınıfları (basit ad).
    Yalnız sayfa (dispatcher) sonuçları; yönlendirme sonuçları sayfa işlemez."""
    out: dict[str, set[str]] = {}
    for text in texts.values():
        if "<struts" not in text:
            continue
        for am in _STRUTS_ACTION_RE.finditer(text):
            attrs = dict(_STRUTS_ATTR_RE.findall(am.group(1)))
            cls = attrs.get("class", "").rsplit(".", 1)[-1]
            if not cls:
                continue
            for rm in _STRUTS_RESULT_RE.finditer(am.group(2)):
                rattrs = dict(_STRUTS_ATTR_RE.findall(rm.group(1)))
                if rattrs.get("type", "dispatcher").lower() not in ("dispatcher", "tiles"):
                    continue
                page = rm.group(2).strip()
                if page.lower().endswith((".jsp", ".jspf")):
                    out.setdefault(page.lstrip("/"), set()).add(cls)
    return out


def struts_unescaped_properties(text: str) -> list[tuple[int, str, str | None]]:
    """JSP'de kaçışsız ``<s:property escape="false"|escapeHtml="false">``: (satır, ifade, içinde bulunduğu
    ``<s:iterator value>`` ifadesi ya da None)."""
    events: list[tuple[int, str, Any]] = []
    for m in _STRUTS_ITERATOR_RE.finditer(text):
        if m.group(0).startswith("</"):
            events.append((m.start(), "close", None))
        else:
            events.append((m.start(), "open", dict(_STRUTS_ATTR_RE.findall(m.group(1))).get("value")))
    for m in _STRUTS_PROPERTY_RE.finditer(text):
        attrs = {k.lower(): v for k, v in _STRUTS_ATTR_RE.findall(m.group(1))}
        if attrs.get("escape", "true").lower() == "false" or attrs.get("escapehtml", "true").lower() == "false":
            events.append((m.start(), "prop", attrs.get("value", "top")))
    events.sort(key=lambda e: e[0])
    stack: list[str | None] = []
    out = []
    for pos, kind, val in events:
        if kind == "open":
            stack.append(val)
        elif kind == "close":
            if stack:
                stack.pop()
        else:
            out.append((text.count("\n", 0, pos) + 1, val, stack[-1] if stack else None))
    return out


def struts_redirect_results(texts: dict[str, str]) -> dict[str, dict[str, str]]:
    """struts.xml: eylem sınıfı (basit ad) → {sonuç adı: hedefi ${alan} olan redirect/redirectAction sonucu}."""
    out: dict[str, dict[str, str]] = {}
    for text in texts.values():
        if "<struts" not in text:
            continue
        for am in _STRUTS_ACTION_RE.finditer(text):
            attrs = dict(_STRUTS_ATTR_RE.findall(am.group(1)))
            cls = attrs.get("class", "").rsplit(".", 1)[-1]
            if not cls:
                continue
            for rm in _STRUTS_RESULT_RE.finditer(am.group(2)):
                rattrs = dict(_STRUTS_ATTR_RE.findall(rm.group(1)))
                if rattrs.get("type", "").lower() not in ("redirect", "redirectaction", "redirect-action"):
                    continue
                em = _STRUTS_EXPR_RE.search(rm.group(2))
                if em:
                    out.setdefault(cls, {})[rattrs.get("name", "success")] = em.group(1)
    return out


_SPRING_MAPPINGS = {"requestmapping", "getmapping", "postmapping", "putmapping", "deletemapping", "patchmapping"}
_JAXRS = {"get", "post", "put", "delete", "patch", "path"}
_JAVA_SOURCE_ANN = {"requestparam", "pathvariable", "requestbody", "requestheader", "cookievalue", "modelattribute",
                    "requestpart", "matrixvariable", "queryparam", "pathparam", "formparam", "headerparam",
                    "cookieparam", "beanparam"}
_JAVA_FRAMEWORK_TYPES = {"Model", "ModelMap", "ModelAndView", "BindingResult", "Errors", "RedirectAttributes",
                         "Principal", "Authentication", "Locale", "TimeZone", "ZoneId", "HttpMethod",
                         "SessionStatus", "UriComponentsBuilder", "Map", "HttpHeaders", "Pageable", "Sort",
                         "ServletContext", "Writer", "OutputStream", "PrintWriter", "HttpServletResponse",
                         "ServletResponse", "HttpSession", "HttpServletRequest", "ServletRequest", "WebRequest",
                         "NativeWebRequest", "ServerHttpRequest", "ServerHttpResponse", "ServerWebExchange",
                         "SecurityContext", "UriInfo", "Request", "Response", "AsyncResponse", "ContainerRequest",
                         # gRPC: yanıt gözlemcisi / üst veri istek verisi taşımaz (istek iletisi kaynaktır)
                         "StreamObserver", "ServerCallStreamObserver", "Metadata", "ServerCall"}
# gRPC protobuf skaler türleri: sayısal/mantık alanlar (ve enum'lar) istek verisi taşısa da dize enjeksiyonu taşımaz
_PROTO_CLEAN_TYPES = frozenset({"int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32", "fixed64",
                                "sfixed32", "sfixed64", "double", "float", "bool"})
_PROTO_BLOCK = re.compile(r"\b(message|enum)\s+(\w+)\s*\{")
_PROTO_FIELD = re.compile(r"(?m)(?:^|(?<=[;{]))\s*(?:repeated\s+|optional\s+|required\s+)?(map\s*<[^>]*>|[\w.]+)\s+(\w+)\s*=\s*\d+")


def proto_messages(texts: dict[str, str]) -> tuple[dict[str, dict[str, str]], frozenset[str]]:
    """.proto dosyaları: ileti adı → {alan adı (özgün ve lowerCamel): tür}, enum adları. Yalnız alan türü için."""
    messages: dict[str, dict[str, str]] = {}
    enums: set[str] = set()
    for path, text in texts.items():
        if not path.endswith(".proto"):
            continue
        text = re.sub(r"//[^\n]*|/\*.*?\*/", "", text, flags=re.S)
        for m in _PROTO_BLOCK.finditer(text):
            if m.group(1) == "enum":
                enums.add(m.group(2))
                continue
            depth, j = 1, m.end()
            while j < len(text) and depth:
                depth += {"{": 1, "}": -1}.get(text[j], 0)
                j += 1
            fields = messages.setdefault(m.group(2), {})
            for fm in _PROTO_FIELD.finditer(text[m.end():j - 1]):
                typ, name = fm.group(1), fm.group(2)
                if typ in ("message", "enum", "oneof", "reserved", "option", "extensions"):
                    continue
                typ = typ.rsplit(".", 1)[-1]
                camel = re.sub(r"_([a-z0-9])", lambda x: x.group(1).upper(), name)
                fields.setdefault(name, typ)
                fields.setdefault(camel, typ)
    return messages, frozenset(enums)


_CS_FRAMEWORK_TYPES = {"CancellationToken", "HttpContext", "ILogger", "IServiceProvider", "ClaimsPrincipal",
                       "IConfiguration", "IWebHostEnvironment", "IHostingEnvironment"}
_TYPE_TAGS = {
    "HttpServletRequest": "req", "ServletRequest": "req", "HttpServletRequestWrapper": "req", "WebRequest": "req",
    "NativeWebRequest": "req", "HttpServletResponse": "resp", "ServletResponse": "resp", "HttpSession": "session",
    "PrintWriter": "writer", "JspWriter": "writer", "ServletOutputStream": "writer", "HttpRequest": "req",
    "HttpResponse": "resp", "ISession": "session", "Request": "req", "ServerRequestInterface": "req",
    "FormRequest": "req",
    # 18. tur: URL/URI parametresi (yardımcıya geçirilen new URL(istek)) → openConnection/openStream SSRF hedefi
    "URL": "url", "URI": "url",
}
# Yanıt olmayan çıkış akışları (dosya, bellek tamponu, şifreleme/sıkıştırma akışı): bunlara yazmak HTTP yanıtına
# yazmak değildir → XSS hedefi değil. Yalnız yanıt yazıcısını (getWriter/getOutputStream, Response.OutputStream)
# saran örnekler "writer" etiketini korur.
_NONRESP_STREAM_TYPES = frozenset({
    # Java
    "FileWriter", "FileOutputStream", "StringWriter", "CharArrayWriter", "ByteArrayOutputStream", "RandomAccessFile",
    "PipedWriter", "PipedOutputStream",
    # C#
    "StreamWriter", "StringWriter", "BinaryWriter", "XmlWriter", "XmlTextWriter", "FileStream", "MemoryStream",
    "CryptoStream", "BufferedStream", "GZipStream", "DeflateStream",
})
# Başka bir akışı saran türler: sarılan yanıt yazıcısıysa yanıt, yanıt olmayan akış/dosya adıysa yanıt değil.
_WRAPPER_STREAM_TYPES = frozenset({
    "PrintWriter", "PrintStream", "BufferedWriter", "BufferedOutputStream", "OutputStreamWriter", "DataOutputStream",
    "ObjectOutputStream", "GZIPOutputStream", "ZipOutputStream", "DeflaterOutputStream", "CipherOutputStream",
    "FilterOutputStream", "Formatter",
    "StreamWriter", "BinaryWriter", "CryptoStream", "GZipStream", "DeflateStream", "BufferedStream",
})
# Dosyaya yazan yazıcı/akış üreten fabrika çağrıları (sınıf, yöntem).
_FILE_WRITER_FACTORIES = frozenset({
    ("Files", "newBufferedWriter"), ("Files", "newOutputStream"), ("FileUtils", "openOutputStream"),
    ("File", "CreateText"), ("File", "AppendText"), ("File", "Create"), ("File", "OpenWrite"), ("File", "Open"),
})
# Yanıta yazan HTML hedeflerinin açıklamaları: yanıtın içerik türü HTML dışıysa (JSON, düz metin, ek) XSS değil.
_RESPONSE_HTML_DESCS = frozenset({"echo/print", "print", "exit/die çıktısı", "printf()", "vprintf()", "print_r()",
                                  "die()", "exit()", "print()", "println()", "write()", "format()", "append()",
                                  "Write()", "WriteAsync()"})
_SAFE_MIME = re.compile(r"(?i)^\s*(?:application/(?:[\w.+-]*json|javascript|x-javascript|ecmascript|octet-stream|pdf|zip|"
                        r"gzip|x-gzip|vnd\.[\w.+-]*|msword|x-www-form-urlencoded|x-ndjson|csv)|"
                        r"text/(?:plain|csv|css|javascript|ecmascript|x-json|tab-separated-values|calendar|event-stream)|"
                        r"image/(?:png|jpe?g|gif|webp|bmp|x-icon|vnd\.microsoft\.icon)|audio/[\w.+-]+|video/[\w.+-]+|"
                        r"font/[\w.+-]+)\s*(?:;|$)")


def _nonresp_stream(recv: "V | None") -> bool:
    """Alıcı yanıt olmayan bir akış/yazıcı mı (dosya, bellek tamponu)? Yanıt yazıcısını saranlar ("writer") hariç."""
    if recv is None or recv.tag == "writer":
        return False
    return recv.tag == "nonresp" or recv.type in _NONRESP_STREAM_TYPES


def _response_type_verdict(header: str, value: str | None) -> bool | None:
    """Yanıt başlığı yanıtı HTML dışı yapıyor mu? True: HTML dışı (JSON/düz metin/ek), False: HTML (geri alır),
    None: bilinmiyor ya da ilgisiz başlık. Değer sabit değilse (None) karar verilmez."""
    if value is None:
        return None
    h = header.strip().lower()
    v = value.strip().lower()
    if h == "content-disposition":
        return True if v.startswith("attachment") else None
    if h != "content-type" or not v:
        return None
    if _SAFE_MIME.match(v):
        return True
    return False if ("html" in v or "xml" in v) else None


_HOST_FIXED = re.compile(r"(?i)^(?:https?:)?//[^/?#\s\"']+[/?#]|^/(?!/)|^\?|^#|^<site-url>|^[\w.-]+\.(?:php|aspx?|jsp|html?|do)\b")


def _fixed_host(prefix: str | None, kind: str) -> bool:
    """Önek, hedef ana makineyi sabitliyor mu? (``https://site/``, ``/yol``, ``?q=``, ``admin_url(…)``)."""
    if not prefix:
        return False
    text = prefix.strip()
    if kind == "redirect" and text.lower().startswith("location:"):
        text = text[len("location:"):].strip()
        if not text:
            return False
    return bool(_HOST_FIXED.match(text))


_SCALAR_TYPES = {"int", "integer", "float", "double", "bool", "boolean", "void", "never", "long", "short", "byte", "char",
                 "decimal", "uint", "ulong", "ushort", "sbyte", "wp_error", "null", "false", "true", "Integer", "Long",
                 "Boolean", "Double", "Float", "Short", "Byte", "Int32", "Int64", "Boolean", "Task", "number"}


def _scalar_return(ret_type: str) -> bool:
    """Dönüş türü yalnız sayı/mantık/void/hata nesnesi mi? (PHP imzası, PHPDoc @return, Java/C# imzası)"""
    if not ret_type:
        return False
    parts = [p.strip().lstrip("?\\").rsplit("\\", 1)[-1] for p in ret_type.split("|") if p.strip()]
    return bool(parts) and all(p in _SCALAR_TYPES or p.lower() in _SCALAR_TYPES for p in parts)


def _negated_safe_class(pattern: str) -> bool:
    """Yalnız güvenli karakterlerin olumsuz sınıfı (``/[^a-z0-9_]/``): eşleşme = yasak karakter var."""
    p = pattern.strip()
    if len(p) >= 2 and p[0] in "/#~|" and p[0] in p[1:]:
        p = p[1:p.rindex(p[0])]
    return bool(re.fullmatch(r"\[\^[A-Za-z0-9_\-\\\s.]+\]", p)) and not re.search(r"[/<>'\"`;|&]", p)


def _safe_regex_literal(pattern: str) -> bool:
    """Tam eşleşen ve yalnız harf/rakam/sınırlı karakter kabul eden düzenli ifade (beyaz liste koruması)."""
    p = pattern.strip()
    if len(p) >= 2 and p[0] in "/#~" and p[0] in p[1:]:
        p = p[1:p.rindex(p[0])]
    if not (p.startswith("^") or p.startswith("\\A")) or not (p.endswith("$") or p.endswith("\\z") or p.endswith("\\Z")):
        return False
    body = p.lstrip("^").rstrip("$")
    return not re.search(r"\.(?![^\[]*\])|\\S|\\W|\[\^", body) and not re.search(r"[/<>'\"`;|&]", body)


# ---------------------------------------------------------------------------
# Deyim ağacı
# ---------------------------------------------------------------------------
class Parser:
    def __init__(self, unit: Unit) -> None:
        self.u = unit
        self.t = unit.toks
        self.p = unit.pairs
        self.php = unit.lang == "php"
        self.cache: dict[tuple[int, int], list] = {}

    def is_op(self, i: int, *values: str) -> bool:
        return i < len(self.t) and self.t[i].kind == "op" and self.t[i].value in values

    def is_id(self, i: int, *values: str) -> bool:
        if i >= len(self.t) or self.t[i].kind != "id":
            return False
        v = self.t[i].value.lower() if self.php else self.t[i].value
        return v in values

    def block(self, i: int, j: int) -> list:
        key = (i, j)
        if key not in self.cache:
            out = []
            guard = 0
            while i < j and guard < 200_000:
                guard += 1
                st, ni = self.stmt(i, j)
                if st is not None:
                    out.append(st)
                i = max(ni, i + 1)
            self.cache[key] = out
        return self.cache[key]

    def end(self, i: int, j: int) -> int:
        k = i
        while k < j:
            tok = self.t[k]
            if tok.kind == "op":
                if tok.value == ";":
                    return k
                if tok.value in ("(", "[", "{") and k in self.p:
                    k = self.p[k] + 1
                    continue
                if tok.value == "}":
                    return k
            k += 1
        return j

    def stmt(self, i: int, j: int) -> tuple[Any, int]:
        t = self.t[i]
        if t.kind == "op":
            if t.value == "{" and i in self.p:
                k = min(self.p[i], j)
                return ("block", self.block(i + 1, k)), k + 1
            if t.value in (";", "}"):
                return None, i + 1
        if t.kind == "id":
            v = t.value.lower() if self.php else t.value
            if v == "if":
                return self._if(i, j)
            if v in ("while", "for", "foreach") and self.is_op(i + 1, "("):
                return self._loop(i, j, v)
            if v == "do":
                body, k = self.stmt(i + 1, j)
                if self.is_id(k, "while") and self.is_op(k + 1, "(") and (k + 1) in self.p:
                    c = self.p[k + 1]
                    return ("dowhile", body, (k + 2, c)), self.end(c + 1, j) + 1
                return body, k
            if v == "switch" and self.is_op(i + 1, "(") and (i + 1) in self.p:
                return self._switch(i, j)
            if v == "try":
                return self._try(i, j)
            if v in ("return", "throw") or (v == "yield" and self.is_id(i + 1, "return")):
                start = i + 2 if v == "yield" else i + 1
                e = self.end(start, j)
                return (("return" if v != "throw" else "throw"), start, e), e + 1
            if v in ("break", "continue", "goto"):
                e = self.end(i, j)
                return (("break",) if v == "break" else ("continue",) if v == "continue" else None), e + 1
            if v in ("using", "lock", "synchronized", "fixed", "checked", "unchecked", "unsafe") and \
                    self.is_op(i + 1, "(") and (i + 1) in self.p:
                c = self.p[i + 1]
                body, k = self.stmt(c + 1, j) if c + 1 < j else (None, c + 1)
                return ("block", [("expr", i + 2, c)] + ([body] if body else [])), k
            if v in ("using", "const", "final", "static", "await") and not self.php and not self.is_op(i + 1, "=", ".", "(", ";"):
                e = self.end(i + 1, j)
                return ("expr", i + 1, e), e + 1
            if v in ("class", "interface", "enum", "record", "struct", "trait", "abstract") or (
                    self.php and v == "final" and self.is_id(i + 1, "class")):
                k = i
                while k < j and not self.is_op(k, "{", ";"):
                    k += 1
                if self.is_op(k, "{") and k in self.p:
                    return None, self.p[k] + 1
                return None, k + 1
            if self.php:
                r = self._php_stmt(i, j, v)
                if r is not None:
                    return r
            if v == "else":
                return None, i + 1
            if i + 1 < j and self.is_op(i + 1, ":") and not self.php and v not in ("default", "case"):
                return None, i + 2  # etiket
        e = self.end(i, j)
        return ("expr", i, e), e + 1

    def _php_stmt(self, i: int, j: int, v: str):
        if v in ("echo", "print"):
            e = self.end(i + 1, j)
            ranges = lex.split_top(self.t, self.p, i + 1, e, ",") if v == "echo" else [(i + 1, e)]
            return ("echo", ranges), e + 1
        if v in ("exit", "die"):
            e = self.end(i + 1, j)
            return ("exit", i + 1, e), e + 1
        if v in ("include", "require", "include_once", "require_once"):
            e = self.end(i + 1, j)
            return ("include", i + 1, e), e + 1
        if v == "function" and i + 1 < j and self.t[i + 1].kind == "id" or (
                v == "function" and self.is_op(i + 1, "&") and i + 2 < j and self.t[i + 2].kind == "id"):
            k = i
            while k < j and not self.is_op(k, "{", ";"):
                if self.is_op(k, "(") and k in self.p:
                    k = self.p[k]
                k += 1
            if self.is_op(k, "{") and k in self.p:
                return None, self.p[k] + 1
            return None, k + 1
        if v in ("namespace", "use", "declare", "global"):
            k = i
            while k < j and not self.is_op(k, ";", "{"):
                k += 1
            if self.is_op(k, "{") and k in self.p and v == "namespace":
                return ("block", self.block(k + 1, self.p[k])), self.p[k] + 1
            if self.is_op(k, "{") and k in self.p:
                return None, self.p[k] + 1
            return None, k + 1
        if v in ("endif", "endwhile", "endfor", "endforeach", "endswitch", "enddeclare"):
            return None, i + 1
        return None

    def _alt_block(self, i: int, j: int, stops: tuple[str, ...]) -> tuple[list, int]:
        out = []
        while i < j and not self.is_id(i, *stops):
            st, ni = self.stmt(i, j)
            if st is not None:
                out.append(st)
            i = max(ni, i + 1)
        return out, i

    def _if(self, i: int, j: int) -> tuple[Any, int]:
        if not self.is_op(i + 1, "(") or (i + 1) not in self.p:
            e = self.end(i, j)
            return ("expr", i + 1, e), e + 1
        c = self.p[i + 1]
        cond = (i + 2, c)
        if self.php and self.is_op(c + 1, ":"):
            then, k = self._alt_block(c + 2, j, ("elseif", "else", "endif"))
            then_st = ("block", then)
            if self.is_id(k, "elseif"):
                els, k2 = self._if(k, j)
                return ("if", cond, then_st, els), k2
            if self.is_id(k, "else"):
                start = k + 2 if self.is_op(k + 1, ":") else k + 1
                body, k2 = self._alt_block(start, j, ("endif",))
                return ("if", cond, then_st, ("block", body)), self.end(k2, j) + 1
            return ("if", cond, then_st, None), self.end(k, j) + 1
        then, k = self.stmt(c + 1, j) if c + 1 < j else (None, c + 1)
        els = None
        if self.is_id(k, "else"):
            if self.php and self.is_op(k + 1, ":"):
                body, k2 = self._alt_block(k + 2, j, ("endif",))
                return ("if", cond, then, ("block", body)), self.end(k2, j) + 1
            els, k = self.stmt(k + 1, j) if k + 1 < j else (None, k + 1)
        elif self.php and self.is_id(k, "elseif"):
            els, k = self._if(k, j)
        return ("if", cond, then, els), k

    def _loop(self, i: int, j: int, v: str) -> tuple[Any, int]:
        c = self.p.get(i + 1)
        if c is None:
            e = self.end(i, j)
            return ("expr", i, e), e + 1
        if self.php and self.is_op(c + 1, ":"):
            body_list, k = self._alt_block(c + 2, j, ("endwhile", "endfor", "endforeach"))
            body, k = ("block", body_list), self.end(k, j) + 1
        else:
            body, k = self.stmt(c + 1, j) if c + 1 < j else (None, c + 1)
        header = (i + 2, c)
        if v == "while":
            return ("while", header, body), k
        if v == "foreach":
            return ("foreach", header, body), k
        parts = lex.split_top(self.t, self.p, i + 2, c, ";")
        semis = [x for x in range(i + 2, c) if self.is_op(x, ";")]
        if not semis:
            return ("foreach", header, body), k  # Java gelişmiş for
        bounds = [i + 2] + [s + 1 for s in semis] + [c]
        segs = [(bounds[n], (semis + [c])[n]) for n in range(len(semis) + 1)]
        del parts
        init, cond, upd = (segs + [(c, c)] * 3)[:3]
        return ("for", init, cond, upd, body), k

    def _switch(self, i: int, j: int) -> tuple[Any, int]:
        c = self.p[i + 1]
        expr = (i + 2, c)
        if not self.is_op(c + 1, "{") or (c + 1) not in self.p:
            e = self.end(c + 1, j)
            return ("expr", i + 2, c), e + 1
        b0, b1 = c + 2, self.p[c + 1]
        cases: list[tuple[list[tuple[int, int]], bool, list, bool]] = []
        k = b0
        current: list | None = None
        while k < b1:
            if self.is_id(k, "case", "default"):
                is_default = self.is_id(k, "default")
                m = k + 1
                while m < b1 and not self.is_op(m, ":", "->", ";"):
                    if self.is_op(m, "(", "[", "{") and m in self.p:
                        m = self.p[m]
                    m += 1
                labels = [] if is_default else lex.split_top(self.t, self.p, k + 1, m, ",")
                arrow = self.is_op(m, "->")
                if arrow:
                    st, nk = self.stmt(m + 1, b1)
                    cases.append((labels, is_default, [st] if st else [], True))
                    current = None
                    k = nk
                    continue
                current = []
                cases.append((labels, is_default, current, False))
                k = m + 1
                continue
            st, nk = self.stmt(k, b1)
            if st is not None and current is not None:
                current.append(st)
            k = max(nk, k + 1)
        return ("switch", expr, cases), b1 + 1

    def _try(self, i: int, j: int) -> tuple[Any, int]:
        k = i + 1
        res = None
        if self.is_op(k, "(") and k in self.p:
            res = (k + 1, self.p[k])
            k = self.p[k] + 1
        body, k = self.stmt(k, j) if k < j else (None, k)
        catches = []
        while self.is_id(k, "catch"):
            k += 1
            param = None
            if self.is_op(k, "(") and k in self.p:
                param = (k + 1, self.p[k])
                k = self.p[k] + 1
            if self.is_id(k, "when") and self.is_op(k + 1, "(") and (k + 1) in self.p:
                k = self.p[k + 1] + 1
            cb, k = self.stmt(k, j) if k < j else (None, k)
            catches.append((param, cb))
        fin = None
        if self.is_id(k, "finally"):
            fin, k = self.stmt(k + 1, j) if k + 1 < j else (None, k + 1)
        return ("try", res, body, catches, fin), k


# ---------------------------------------------------------------------------
# Yöntem özetleri ve proje
# ---------------------------------------------------------------------------
@dataclass
class Summary:
    ret_params: dict[int, frozenset[str]] = field(default_factory=dict)  # parametre → dönüşteki arınmış türler
    ret_taint: frozenset[T] = frozenset()
    ret_tag: str | None = None
    # Döndürülen dizi kaydının anahtar yapısı: anahtar → (parametre → arınmış türler, gerçek kaynaklar)
    ret_keys: dict[Any, tuple[dict[int, frozenset[str]], frozenset[T]]] | None = None
    sinks: list[tuple[int, str, str, int, str, tuple[str, ...]]] = field(default_factory=list)
    mutates_this: bool = False
    # Parametre → yazdığı tablo ve sütunlar (C#; INSERT/UPDATE birleştirmesi): çağıran istek verisi verirse tablo
    # kayıtlı veri olur
    table_writes: list[tuple[int, str, frozenset[str] | None]] = field(default_factory=list)
    # Yöntem yanıtın içerik türünü atadı mı (W2-XSS, yardımcılar arası): True HTML dışı, False HTML, None atamadı.
    resp_type: bool | None = None


class Project:
    def __init__(self, units: dict[str, Unit], mybatis: set[str] | None = None,
                 struts: dict[str, dict[str, str]] | None = None) -> None:
        import taint_flow
        self.tf = taint_flow
        self.units = units
        self.parsers = {path: Parser(u) for path, u in units.items()}
        self.by_name: dict[str, list[tuple[Unit, Method]]] = {}
        self.classes: dict[str, list[tuple[Unit, lex.ClassInfo]]] = {}
        self.control_types: dict[str, str] = {}
        self.summaries: dict[int, Summary] = {}
        self.twig_raw: set[str] = set()  # |raw / autoescape false içeren Twig şablonlarının dosya adları
        self.in_progress: set[int] = set()
        self.flows: dict[tuple, Any] = {}
        self.mybatis = mybatis or set()
        self.th_views: dict[str, set[str]] = {}  # Thymeleaf görünüm adı → kaçışsız basılan model öznitelikleri
        # 18. tur: JSP görünüm adı → kök öznitelik → [(jsp yolu, satır, ifade)] (şablon metnindeki kaçışsız ${…} EL)
        self.jsp_views: dict[str, dict[str, list[tuple[str, int, str]]]] = {}
        # 25. tur: tüm JSP'lerdeki kaçışsız EL kullanımları kök ada göre (oturum öznitelikleri her görünümde okunur)
        self.jsp_all_uses: dict[str, list[tuple[str, int, str]]] = {}
        self.repo_entity: dict[str, str] = {}  # Spring Data depo arayüzü → varlık türü (kayıtlı veri)
        # Struts2: eylem sınıfı → {sonuç adı: yönlendirme hedefindeki ${alan}} (struts.xml)
        self.struts_results = struts or {}
        self.php_paths = sorted(p for p, u in units.items() if u.lang == "php")
        self.started = time.monotonic()
        self.depth = 0
        # İkinci derece: oturum anahtarına / tabloya yazılan istek verisi (okunduğu yerde kaynak olur)
        self.session_taint: dict[str, frozenset[T]] = {}
        # ASP.NET Core görünümleri: ViewData/ViewBag/TempData anahtarı, View(model) (denetleyici, görünüm) ve
        # model özelliği yazmaları ((tür, özellik) ve özellik adı) → Razor görünümünde okunduğu yerde kaynak.
        self.viewbag_taint: dict[str, frozenset[T]] = {}
        self.view_taint: dict[tuple[str, str, str], frozenset[T]] = {}  # (denetleyici, görünüm, model türü)
        self.model_props: dict[tuple[str, str], frozenset[T]] = {}
        self.model_props_by_name: dict[str, frozenset[T]] = {}
        self.privileged_model_writes = 0
        self.table_taint: dict[str, frozenset[T]] = {}
        # Tabloya istek verisi yazılan sütunlar (yalnız C# yazmaları sütun bildirir; None = bilinmiyor/tümü)
        self.table_cols: dict[str, frozenset[str] | None] = {}
        self.include_paths: dict[tuple[str, str], list[Unit]] = {}
        self.include_delta: dict[tuple, dict[str, V]] = {}
        self.include_runs = 0
        self.deep_dropped = 0
        self.privileged_dropped = 0  # yetkili bağlam akışı sayısı (not olarak raporlanır)
        self.deprecated_dropped = 0
        self.privileged_flows: dict[tuple, Any] = {}
        for u in units.values():
            for m in u.methods:
                key = m.name.lower() if u.lang == "php" else m.name
                self.by_name.setdefault(key, []).append((u, m))
            for c in u.classes:
                self.classes.setdefault(c.name, []).append((u, c))
                if u.lang == "csharp":
                    for name, typ in c.fields.items():
                        if typ in _WEBFORMS_INPUTS or typ in _WEBFORMS_OUTPUTS:
                            self.control_types[name] = typ
        self.struts_classes: set[str] = set()
        self.struts_fields = self._struts_action_fields()
        # Struts2 eylem sınıfının alanına yazılan istek/kayıtlı veri (JSP <s:property> okur): (sınıf, alan) → iz
        self.struts_field_taint: dict[tuple[str, str], frozenset[T]] = {}
        # Görünüm durumu (ViewBag/model özellikleri) Razor/Blazor ve WebForms işaretlemesinde okunur
        self.has_razor = any(u.razor or u.aspx for u in units.values())
        # WCF: [ServiceContract] arayüzü/sınıfı → [OperationContract] yöntem adları (uygulayan sınıfta uç nokta)
        self.wcf_contracts = self._wcf_contracts()
        # gRPC: .proto ileti alan türleri (sayısal/enum alanlar dize enjeksiyonu taşımaz); analyze_files doldurur
        self.proto: dict[str, dict[str, str]] = {}
        self.proto_enums: frozenset[str] = frozenset()
        # EF Core varlık türleri (DbSet<T>): bu türlerin özelliklerine yazılan istek verisi kayıtlı veridir
        self.db_entities: set[str] = set()
        for u in units.values():
            if u.lang != "csharp":
                continue
            toks = u.toks
            for k in range(len(toks) - 3):
                if toks[k].kind == "id" and toks[k].value in ("DbSet", "IDbSet") and toks[k + 1].value == "<" \
                        and toks[k + 2].kind == "id":
                    self.db_entities.add(lex._simple_type(toks[k + 2].value))
            # 25. tur: bellek içi depo sınıfı (CommentsRepository/…Store/…Dao) alanındaki koleksiyonun öğe türü de
            # kalıcı depo varlığıdır (tekil hizmet olarak istekler arası yaşar): List<Comment> Comments;
            in_repo = False
            for k in range(len(toks) - 4):
                tk = toks[k]
                if tk.kind == "id" and tk.value == "class" and toks[k + 1].kind == "id":
                    in_repo = bool(re.search(r"(?:Repository|Repo|Store|Dao)$", str(toks[k + 1].value)))
                    continue
                if in_repo and tk.kind == "id" and tk.value in _CS_REPO_COLLECTIONS and toks[k + 1].value == "<":
                    j = k + 2
                    if j + 2 < len(toks) and toks[j + 1].value == ",":
                        j += 2  # Dictionary<anahtar, Öğe>
                    if toks[j].kind == "id" and toks[j + 1].value == ">" and str(toks[j].value)[:1].isupper() \
                            and str(toks[j].value) not in _CS_REPO_SCALARS:
                        self.db_entities.add(lex._simple_type(toks[j].value))

    def _wcf_contracts(self) -> dict[str, frozenset[str]]:
        out: dict[str, frozenset[str]] = {}
        for u in self.units.values():
            if u.lang != "csharp":
                continue
            toks = u.toks
            if not any(t.kind == "id" and t.value.startswith("ServiceContract") for t in toks):
                continue
            for k in range(len(toks) - 1):
                if not (toks[k].kind == "id" and toks[k].value in ("interface", "class") and toks[k + 1].kind == "id"):
                    continue
                j, annotated = k - 1, False
                while j >= 0 and not (toks[j].kind == "op" and toks[j].value in (";", "{", "}")):
                    annotated = annotated or (toks[j].kind == "id" and toks[j].value.startswith("ServiceContract"))
                    j -= 1
                if not annotated:
                    continue
                b = next((x for x in range(k + 2, min(len(toks), k + 40)) if toks[x].kind == "op" and toks[x].value == "{"),
                         None)
                e = u.pairs.get(b) if b is not None else None
                if e is None:
                    continue
                ops: set[str] = set()
                for x in range(b, e):
                    if toks[x].kind == "id" and toks[x].value.startswith("OperationContract"):
                        z = x + 1
                        while z < e and not (toks[z].kind == "op" and toks[z].value == "("
                                             and toks[z - 1].kind == "id" and z > x + 1
                                             and not (toks[z - 2].kind == "op" and toks[z - 2].value == "[")):
                            z += 1
                        if z < e:
                            ops.add(str(toks[z - 1].value))
                out[str(toks[k + 1].value)] = frozenset(ops)
        return out

    def _extends(self, cls: str, targets: frozenset[str], seen: set[str] | None = None) -> bool:
        """Sınıf (proje içi kalıtım zinciriyle) ``targets`` türlerinden birini genişletiyor/uyguluyor mu?"""
        seen = set() if seen is None else seen
        if cls in seen or len(seen) > 8:
            return False
        seen.add(cls)
        for _u, info in self.classes.get(cls, ()):
            if info.bases & targets:
                return True
            if any(self._extends(base, targets, seen) for base in info.bases if base in self.classes):
                return True
        return False

    def _struts_action_fields(self) -> dict[str, dict[str, int]]:
        """Struts2 eylem sınıflarında genel ayarlayıcısı (setX) olan dize alanları: çatı istek parametrelerini
        bu alanlara yazar (params önleyicisi), alan okumaları istek girdisidir."""
        out: dict[str, dict[str, int]] = {}
        for u in self.units.values():
            if u.lang != "java" or "xwork2" not in u.text_flags and not any(
                    self._extends(c.name, _STRUTS_BASES) for c in u.classes):
                continue
            for c in u.classes:
                if not self._extends(c.name, _STRUTS_BASES):
                    continue
                self.struts_classes.add(c.name)
                for m in u.methods:
                    if m.cls != c.name or len(m.name) < 4 or not m.name.startswith("set") or len(m.params) != 1 \
                            or "public" not in m.modifiers or m.params[0].type not in _STRUTS_FIELD_TYPES:
                        continue
                    name = m.name[3].lower() + m.name[4:]
                    if name in c.fields or not c.fields:
                        out.setdefault(c.name, {})[name] = m.line
        return out

    def out_of_time(self) -> bool:
        return time.monotonic() - self.started > MAX_PROJECT_SECONDS

    def add_flow(self, flow: Any, privileged: bool = False, deprecated: bool = False) -> None:
        if deprecated:
            self.deprecated_dropped += 1  # kullanımdan kalkmış kod: raporlanmaz
            return
        if len(flow.via) > MAX_REPORTED_CALL_DEPTH:
            self.deep_dropped += 1  # çok derin özet zinciri: büyük kod tabanlarında güvenilmez
            return
        key = (flow.file, flow.line, flow.sink_kind, flow.source_file, flow.source_line, flow.source)
        if privileged:
            # Yetki/nonce denetimli (yönetici) yüzey: doğrulanmış akış değil, ayrı düşük önemli not.
            self.privileged_dropped += 1
            self.privileged_flows.setdefault(key, flow)
            return
        if key not in self.flows:
            self.flows[key] = flow

    def summary(self, unit: Unit, method: Method) -> Summary:
        key = id(method)
        if key in self.summaries:
            return self.summaries[key]
        if key in self.in_progress or self.depth >= MAX_SUMMARY_DEPTH or self.out_of_time():
            return Summary()
        self.in_progress.add(key)
        self.depth += 1
        try:
            interp = Interp(self, unit, method)
            interp.run_method()
            result = interp.summary
            result.resp_type = interp.resp_type_set
        except RecursionError:
            result = Summary()
        finally:
            self.depth -= 1
            self.in_progress.discard(key)
        self.summaries[key] = result
        return result

    def resolve(self, unit: Unit, method: Method | None, name: str, nargs: int, recv_type: str = "",
                static_cls: str = "") -> list[tuple[Unit, Method]]:
        key = name.lower() if unit.lang == "php" else name
        cands = [(u, m) for (u, m) in self.by_name.get(key, ()) if not m.toplevel and u.lang == unit.lang
                 and (len(m.params) == nargs or (u.lang == "php" and nargs <= len(m.params)))]
        if not cands:
            return []

        def pick(found: list[tuple[Unit, Method]]) -> list[tuple[Unit, Method]]:
            local = [c for c in found if c[0] is unit]
            return local or (found if len(found) <= 6 else [])

        if static_cls:
            narrowed = [c for c in cands if c[1].cls == static_cls]
            if narrowed:
                return pick(narrowed)
        if recv_type:
            narrowed = [c for c in cands if c[1].cls == recv_type or recv_type in self._bases(c[0], c[1].cls)]
            if narrowed:
                return pick(narrowed)
        if method is not None:
            same_cls = [c for c in cands if c[0] is unit and c[1].cls == method.cls]
            if same_cls:
                return same_cls
        same_unit = [c for c in cands if c[0] is unit]
        if same_unit:
            return same_unit
        return cands if len(cands) <= 6 else []

    def _bases(self, unit: Unit, cls: str | None) -> frozenset[str]:
        if not cls:
            return frozenset()
        for c in unit.classes:
            if c.name == cls:
                return c.bases
        return frozenset()

    def _second_order_state(self) -> tuple:
        if not self.has_razor:  # görünüm durumu yalnız Razor/Blazor birimlerinde okunur
            return (dict(self.session_taint), dict(self.table_taint))
        return (dict(self.session_taint), dict(self.table_taint), dict(self.viewbag_taint), dict(self.view_taint),
                dict(self.model_props))

    def run(self) -> None:
        # 25. tur: üç geçiş — kayıtlı verinin başka tabloya kopyalanması (önizleme → yorumlar) ikinci geçişte görülür,
        # o tablonun okunduğu yerler üçüncü geçişte kaynak olur. Durum değişmezse erken çıkılır.
        for _pass in range(3):
            before = self._second_order_state()
            for u in self.units.values():
                for m in u.methods:
                    if self.out_of_time():
                        return
                    self.summary(u, m)
            after = self._second_order_state()
            if after == before or not any(after) or _pass == 2:
                return  # son geçişin akışları korunur (sabit noktaya ulaşılmasa da sonuç boşaltılmaz)
            # Yazmalar okumalardan sonra görülmüş olabilir: özetler ve akışlar yeniden hesaplanır.
            self.summaries.clear()
            self.flows.clear()
            self.privileged_flows.clear()

    def compiled_patterns(self, unit: Unit) -> dict[str, str]:
        """``AD = Pattern.compile("desen", …)`` alan/değişken atamaları: ad → desen."""
        cache = self.__dict__.setdefault("_patterns", {})
        if unit.path not in cache:
            out: dict[str, str] = {}
            toks = unit.toks
            for k in range(len(toks) - 6):
                if toks[k].kind == "id" and toks[k + 1].kind == "op" and toks[k + 1].value == "=" and \
                        toks[k + 2].value == "Pattern" and toks[k + 3].value == "." and toks[k + 4].value == "compile" \
                        and toks[k + 5].value == "(" and toks[k + 6].kind == "str":
                    out[toks[k].value] = str(toks[k + 6].value)
            cache[unit.path] = out
        return cache[unit.path]

    def bound_prop(self, cls_name: str | None, prop: str, seen: set[str] | None = None) -> int | None:
        """C# sınıfında (ya da proje içi taban sınıfında) istekten bağlanan özellik mi? Satırını döndürür."""
        if not cls_name:
            return None
        if seen is None:
            cache = self.__dict__.setdefault("_bound_cache", {})
            key = (cls_name, prop)
            if key not in cache:
                cache[key] = self.bound_prop(cls_name, prop, set())
            return cache[key]
        if cls_name in seen or len(seen) > 6:
            return None
        seen.add(cls_name)
        for _u, info in self.classes.get(cls_name, ()):
            spec = info.props.get(prop)
            if spec is not None and (spec[1] & _CS_BOUND_PROP_ANN or "bindproperties" in info.annotations):
                return spec[2]
            for base in info.bases:
                if base in self.classes:
                    found = self.bound_prop(base, prop, seen)
                    if found is not None:
                        return found
        return None

    def note_viewbag(self, key: str, v: V) -> None:
        taint = frozenset(t for t in v.taint if t.src.label in ("request", "stored"))
        if taint:
            key = key.lower()
            self.viewbag_taint[key] = self.viewbag_taint.get(key, frozenset()) | taint

    def note_view(self, key: tuple[str, str, str], v: V) -> None:
        taint = frozenset(t for t in v.taint if t.src.label in ("request", "stored"))
        if taint:
            self.view_taint[key] = self.view_taint.get(key, frozenset()) | taint

    def view_model_taint(self, parent: str, stem: str, model_type: str) -> frozenset[T]:
        """Görünümün Model taint'i: aynı adlı görünüme View(model) ile verilen değerler. Görünüm bir denetleyici
        dizinindeyse (Views/Home) yalnız o denetleyici; paylaşılan/özel konumlarda (Shared, Areas, eklentiler) aynı
        adı kullanan her denetleyici. Model türleri ikisi de biliniyorsa eşleşmeli."""
        controllers = {c for c, _st, _ty in self.view_taint}
        out: frozenset[T] = frozenset()
        for (c, st, ty), taint in self.view_taint.items():
            if st != stem or (parent in controllers and c != parent):
                continue
            if ty and model_type and ty != model_type:
                continue
            out |= taint
        return out

    def note_model_prop(self, typ: str, prop: str, v: V, page_model: bool = False) -> None:
        """İstek verisi bir özelliğe yazılıyor. Yalnız iki durum görünüme taşınır (kesinlik):
        * EF varlığı (DbSet<T>) özelliği → kayıtlı veri (tür ve ad ile; foreach öğeleri ad ile eşleşir);
        * Razor Pages/Blazor sınıfının kendi özelliği (OnGet içinde ``Message = q``) → yalnız (tür, ad)."""
        if not typ or not prop or (not prop[:1].isupper() and not page_model):  # WebForms sayfa alanları küçük harfli olabilir
            return
        taint_in = [t for t in v.taint if t.src.label == "request"]
        if not taint_in:
            return
        key = (typ, prop)
        if typ in self.db_entities:
            taint = frozenset(T(Src("stored", f"{typ}.{prop} alanı (kayıtlı veri)", t.src.line, t.src.file), t.safe)
                              for t in taint_in)
            self.model_props_by_name[prop] = self.model_props_by_name.get(prop, frozenset()) | taint
        elif page_model:
            taint = frozenset(taint_in)
        else:
            return
        self.model_props[key] = self.model_props.get(key, frozenset()) | taint

    def note_session(self, key: str, v: V) -> None:
        taint = frozenset(T(t.src, t.safe) for t in v.taint if t.src.label == "request")
        if taint:
            self.session_taint[key] = self.session_taint.get(key, frozenset()) | taint

    # 25. tur: şema önekli adlar (dbo.Comments, public.users): tablo son parçadır
    _WRITE_RE = re.compile(r"(?is)\b(?:insert\s+(?:ignore\s+)?into|update|replace\s+into|merge(?:\s+into)?)\s+(?:[`\"\[]?\w+[`\"\]]?\.)?"
                           r"[`\"\[]?(\w+)")
    _READ_RE = re.compile(r"(?is)\bselect\b.*?\bfrom\s+(?:[`\"\[]?\w+[`\"\]]?\.)?[`\"\[]?(\w+)")

    def note_sql(self, v: V, columns: bool = False) -> None:
        text = v.const if isinstance(v.const, str) else v.prefix
        if not text or not v.taint:
            return
        table = self.write_table(text)
        if table:
            self.note_table_write(table, v.taint, self.write_columns(text) if columns else None)

    _SET_RE = re.compile(r"(?is)\bset\b(.*?)(?:\bwhere\b|$)")
    _INSERT_COLS_RE = re.compile(r"(?is)\binsert\s+(?:ignore\s+)?into\s+[`\"\[]?\w+[`\"\]]?\s*\(([^)]*)\)")
    _SELECT_COLS_RE = re.compile(r"(?is)\bselect\s+(.*?)\s+from\b")

    def write_columns(self, text: str) -> frozenset[str] | None:
        """UPDATE … SET a = …, b = … / INSERT INTO t (a, b): yazılan sütunlar (bilinmiyorsa None)."""
        m = self._INSERT_COLS_RE.search(text)
        if m:
            return frozenset(c.strip(" `\"[]").lower() for c in m.group(1).split(",") if c.strip()) or None
        if re.match(r"(?is)\s*update\b", text):
            m = self._SET_RE.search(text)
            cols = frozenset(x.lower() for x in re.findall(r"[`\"\[]?(\w+)[`\"\]]?\s*=", m.group(1))) if m else frozenset()
            return cols or None
        return None

    def read_columns(self, text: str | None) -> frozenset[str] | None:
        """SELECT a, t.b AS c FROM …: okunan sütunlar (``*``/işlev ya da bilinmiyorsa None)."""
        m = self._SELECT_COLS_RE.search(text) if text else None
        if not m or "*" in m.group(1) or "(" in m.group(1):
            return None
        cols = set()
        for part in m.group(1).split(","):
            part = re.sub(r"(?is)\s+as\s+\w+\s*$", "", part.strip())
            names = re.findall(r"\w+", part.split()[0] if part.split() else "")
            if not names:
                return None
            cols.add(names[-1].lower())
        return frozenset(cols) or None

    def stored_for(self, spec: str) -> frozenset[T]:
        """Okunan tablo (``tablo`` ya da ``tablo|s1,s2``): istek verisi yazılmışsa kayıtlı veri taint'i. Okunan ve
        yazılan sütunlar ikisi de biliniyor ve kesişmiyorsa (başka sütunlar) kayıtlı veri sayılmaz."""
        table, _, cols = spec.partition("|")
        taint = self.table_taint.get(table) if table else None
        if not taint:
            return frozenset()
        written = self.table_cols.get(table)
        if cols and written and not (written & frozenset(cols.split(","))):
            return frozenset()
        return taint

    def write_table(self, text: str | None) -> str | None:
        m = self._WRITE_RE.search(text) if text else None
        return m.group(1).lower() if m else None

    def note_table_write(self, table: str, taint_in: Iterable[T], cols: frozenset[str] | None = None) -> None:
        """İstek verisi tabloya yazılıyor: o tablodan okunan satırlar kayıtlı veri (ikinci derece) kaynağı olur."""
        # 25. tur: kayıtlı veri başka tabloya kopyalanıyorsa (önizleme → yorumlar) o tablo da kayıtlı veri taşır; kanıt
        # zinciri ilk yazımın yerini korur.
        taint = frozenset(T(Src("stored", f"{table} tablosu (kayıtlı veri)", t.src.line, t.src.file), t.safe - {"sql", "sql?"})
                          for t in taint_in if t.src.label == "request" or (
                              t.src.label == "stored" and not t.src.desc.startswith(f"{table} tablosu")))
        if taint:
            self.table_taint[table] = self.table_taint.get(table, frozenset()) | taint
            if cols is None or (table in self.table_cols and self.table_cols[table] is None):
                self.table_cols[table] = None
            else:
                self.table_cols[table] = (self.table_cols.get(table) or frozenset()) | cols

    def read_table(self, v: V) -> str | None:
        text = v.const if isinstance(v.const, str) else v.prefix
        if not text:
            return None
        m = self._READ_RE.search(text)
        return m.group(1).lower() if m else None

    def resolve_include(self, unit: Unit, pattern: str) -> list[Unit]:
        base_dir = unit.path.rsplit("/", 1)[0] if "/" in unit.path else ""
        key = (base_dir, pattern)
        if key not in self.include_paths:
            self.include_paths[key] = self._resolve_include(base_dir, pattern)
        return self.include_paths[key]

    def _resolve_include(self, base_dir: str, pattern: str) -> list[Unit]:
        pat = pattern.replace("\\", "/")
        literal = pat.replace("*", "")
        if len(literal.strip("/.")) < 4:
            return []
        pat = re.sub(r"^(\*|\.\./|\./|/)+", "", pat)
        while "**" in pat:
            pat = pat.replace("**", "*")
        regex = re.compile("(?:.*/)?" + fnmatch.translate(pat))
        local = re.compile(fnmatch.translate(base_dir + "/" + pat)) if base_dir else None
        out = []
        tail = pat.rsplit("/", 1)[-1]
        for path in self.php_paths:
            if "*" not in tail and not path.endswith(tail):
                continue
            if regex.match(path) or (local is not None and local.match(path)):
                out.append(self.units[path])
        return out if len(out) <= 8 else []


# ---------------------------------------------------------------------------
# Yorumlayıcı
# ---------------------------------------------------------------------------
_LOGIC = {"||", "&&", "or", "and", "xor"}
_EQUALITY = {"==", "!=", "===", "!==", "<>", "<=>"}
_RELATION = {"<", ">", "<=", ">=", "instanceof", "is"}
_ASSIGN_OPS = {"=", "+=", "-=", ".=", "??=", "*=", "/=", "%=", "|=", "&=", "^="}
_PRIMITIVES = {"int", "long", "short", "byte", "double", "float", "boolean", "char", "bool", "decimal", "uint",
               "ulong", "integer"}
_LEVELS = [{"??"}, {"||", "or", "xor"}, {"&&", "and"}, {"|"}, {"^"}, {"&"}, _EQUALITY, _RELATION,
           {"+", "-", "."}, {"*", "/", "%"}, {"**"}]


class Interp:
    def __init__(self, project: Project, unit: Unit, method: Method, include_stack: tuple[str, ...] = ()) -> None:
        self.p = project
        self.u = unit
        self.m = method
        self.t = unit.toks
        self.pairs = unit.pairs
        self.lang = unit.lang
        self.php = unit.lang == "php"
        self.kt = unit.dialect == "kotlin"  # Kotlin çevirisi (taint_kotlin): Java kuralları + Kotlin çatıları
        self.parser = project.parsers[unit.path]
        self.summary = Summary()
        self.types: dict[str, str] = {}
        self.cls = next((c for c in unit.classes if c.name == method.cls), None)
        self.breaks: list[list[dict]] = []
        self.conts: list[list[dict]] = []
        self.steps = 0
        self.include_stack = include_stack + (unit.path,)
        self.ret_values: list[V] = []
        self._location_maps: set[str] = set()  # 18. tur: Location anahtarı konmuş başlık haritaları
        self._callsite_flows: set[tuple[str, int]] = set()  # 18. tur: PHP kitaplık çağrı yeri akışları (tekil)
        self.endpoint = self._is_endpoint()
        self._model_attrs: list[tuple[str, V, int]] = []
        a, b = method.body
        # Yöntem gövdesindeki adlar: setFeature / SimpleEvaluationContext gibi engelleyiciler yöntem düzeyinde aranır.
        if method.toplevel:
            # PHP dosya üst düzeyi: iç fonksiyon/yöntem gövdeleri hariç (oradaki yetki denetimi üst düzeyi korumaz).
            inner = sorted(m.body for m in unit.methods if not m.toplevel)
            ids, k = set(), a
            for lo, hi in inner + [(b, b)]:
                if lo > k:
                    ids.update(tok.value for tok in unit.toks[k:lo] if tok.kind == "id")
                k = max(k, hi)
            self.mids = frozenset(ids)
        else:
            self.mids = frozenset(tok.value for tok in unit.toks[a:b] if tok.kind == "id")
        self.guard_kinds: set[str] = set()
        self._sink_kinds_seen: set[str] = set()
        # Yanıtın içerik türü bu yöntemde HTML dışı yapıldı mı (setContentType("application/json"),
        # header("Content-Type: text/plain"), Content-Disposition: attachment)? Sonraki yanıt yazımları XSS değil.
        self.resp_non_html = False
        self.resp_type_set: bool | None = None  # bu yöntemde atanan son içerik türü kararı (özete yazılır)
        self.deprecated = bool(self.mids & _DEPRECATION_CALLS) or bool(method.annotations & _DEPRECATION_ANNOTATIONS)
        self.privileged = bool(self.mids & _PRIVILEGE_CALLS) or bool(method.annotations & _PRIVILEGE_ANNOTATIONS) or (
            self.cls is not None and any(m.cls == method.cls and re.search(r"(?i)permissions?_?check|check_?permission",
                                                                           m.name) for m in unit.methods))
        if self.lang == "csharp" and not self.privileged and (
                (self.cls is not None and (self.cls.annotations & (_PRIVILEGE_ANNOTATIONS | {"admin"})
                                           or self.cls.name == "AdminController"))
                or "admin" in method.annotations
                or any(seg in "/" + unit.path.lower() for seg in ("/areas/admin/", "/views/admin/"))
                or ("AuthorizeAsync" in self.mids and any(re.search(r"(?i)^(manage|admin)", x) or
                                                          re.search(r"Manage[A-Z]|Admin", x) for x in self.mids))):
            # [Authorize(Roles = "Admin")], Orchard [Admin]/AdminController, Areas/Admin ve Views/Admin, işleyici
            # içinde AuthorizeAsync(…, Permissions.ManageX): yönetici yüzeyi
            self.privileged = True

    def _note_response_header(self, header: str, value: V) -> None:
        """Yanıt başlığı ataması: içerik türü/ek kararı (sabit değer ya da sabit önekle)."""
        text = value.const if isinstance(value.const, str) else value.prefix
        verdict = _response_type_verdict(header, text if isinstance(text, str) else None)
        if verdict is not None:
            self.resp_non_html = verdict
            self.resp_type_set = verdict

    def _jsonp_line(self, line: int) -> bool:
        """Satır JSONP biçimli mi: geri çağırma adının hemen ardından "(" dize sabiti ya da JSONP nesnesi/yardımcısı
        (fastjson JSONPObject, json2Jsonp …)?"""
        for tok in self.t:
            if tok.line != line:
                continue
            if tok.kind == "str" and str(tok.value).startswith("("):
                return True
            if tok.kind == "id" and "jsonp" in str(tok.value).lower():
                return True
        return False

    def _response_html_suppressed(self, kind: str, desc: str) -> bool:
        return kind == "html" and self.resp_non_html and desc in _RESPONSE_HTML_DESCS

    # -- giriş -------------------------------------------------------------
    def _is_endpoint(self) -> bool:
        m = self.m
        if self.lang == "java":
            if m.annotations & (_SPRING_MAPPINGS | _JAXRS):
                return True
            # 18. tur: Spring meta-ek açıklamalı özel eşlemeler (@XxxRequestMapping/@XxxGetMapping …) ve istek bağlama
            # ek açıklamalı parametreler (@RequestParam/@PathVariable/@RequestBody …): Spring bunları yalnız işleyici
            # yöntemlerde bağlar. Gövdesiz arayüz yöntemleri (Feign istemcileri) zaten analiz edilmez.
            if any(a.endswith("mapping") and a not in ("jsonmapping",) for a in m.annotations):
                return True
            if not self.kt and any(prm.annotations & _JAVA_SOURCE_ANN for prm in m.params):
                return True
            if self._spring_security_login():
                return True
            if self.kt and self.cls is not None and self.cls.bases & {"ContentProvider"} and \
                    m.name in ("query", "insert", "update", "delete", "openFile", "openAssetFile", "call"):
                return True  # Android içerik sağlayıcısı: başka uygulamalardan çağrılabilir (dışa açık sağlayıcı)
            if self.cls is not None and any(b.endswith("ImplBase") for b in self.cls.bases) and \
                    ("override" in m.modifiers or "override" in m.annotations):
                return True  # gRPC hizmeti (XxxImplBase / Kotlin XxxCoroutineImplBase): istek iletisi istemciden
            return False
        if self.lang == "csharp":
            if m.annotations & {"minimalapi", "razorrender", "middleware"}:
                return True  # minimal API işleyicisi / Razor görünümü / satır içi ara katman
            cls = self.cls
            if "public" in m.modifiers and m.annotations & {"webmethod", "operationcontract"}:
                return True  # ASMX/sayfa yöntemi ([WebMethod], statik olabilir) ve WCF [OperationContract]
            if cls is not None and "public" in m.modifiers and "static" not in m.modifiers and \
                    any(m.name in self.p.wcf_contracts.get(b, ()) for b in cls.bases):
                return True  # WCF hizmet sözleşmesini uygulayan sınıfın işlem yöntemi
            if cls is None or "public" not in m.modifiers or "static" in m.modifiers or "nonaction" in m.annotations:
                return False
            if cls.bases & {"PageModel"}:
                return m.name.startswith("On")
            return (cls.name.endswith("Controller") or bool(cls.bases & {"Controller", "ControllerBase", "ApiController"})
                    or "apicontroller" in cls.annotations) and m.name != cls.name
        if self.php:
            if "phproute" in m.annotations:
                return True  # 19. tur: Slim/Laravel/Lumen rota kapanışı ($app->get('/x', function (...) {...}))
            # Laravel/Symfony/CodeIgniter denetleyicileri: rota parametreleri kaynak (çatı denetleyici dizini şartı)
            return bool(self._php_controller()
                        and "private" not in m.modifiers and "protected" not in m.modifiers
                        and not m.name.startswith("__"))
        return False

    def _php_controller(self) -> bool:
        cls = self.cls
        return bool(cls and cls.bases & _PHP_CONTROLLER_BASES and "/controller" in self.u.path.lower())

    def _spring_security_login(self) -> bool:
        """18. tur: Spring Security giriş kancaları — AuthenticationProvider.authenticate(Authentication) ve
        UserDetailsService.loadUserByUsername(String): kullanıcı adı/parola giriş formundan gelir."""
        cls, m = self.cls, self.m
        if self.lang != "java" or cls is None:
            return False
        bases = cls.bases
        return (m.name == "authenticate" and "AuthenticationProvider" in bases) or \
            (m.name == "loadUserByUsername" and bool(bases & {"UserDetailsService", "UserDetailsManager"}))

    def _src(self, desc: str, line: int, label: str = "request") -> V:
        return V(frozenset({T(Src(label, desc, line, self.u.path))}))

    def run_method(self) -> None:
        env: dict[str, V] = {}
        for idx, prm in enumerate(self.m.params):
            v = V(frozenset({T(Src("param", prm.name, prm.line, self.u.path, idx))}), type=prm.type)
            tag = _TYPE_TAGS.get(prm.type)
            if tag is None and self.lang == "csharp" and prm.type in _WEBFORMS_INPUTS:
                v = replace(v, tag="control", type=prm.type)
                env[prm.name] = v
                self.types[prm.name] = prm.type
                continue
            if tag is None and self.php and not prm.type and prm.name.lower() in ("$request", "$req") and self.cls is not None \
                    and ("controller" in self.cls.name.lower() or any("controller" in b.lower() for b in self.cls.bases)):
                tag = "req"
            if tag is not None:
                v = replace(v, tag=tag)
            if self.endpoint and self._param_is_source(prm):
                v = join(v, self._src(f"{prm.name} parametresi", prm.line))
            env[prm.name] = v
            self.types[prm.name] = prm.type
        a, b = self.m.body
        stmts = [("return", a, b)] if self.m.expr_body else self.parser.block(a, b)
        try:
            self.run(stmts, env)
        except RecursionError:
            pass
        ret = join_all(self.ret_values) if self.ret_values else CLEAN
        if _scalar_return(self.m.ret_type):
            ret = V(tag=ret.tag)  # sayı/mantık/void döndüren yöntem: dönüş taint taşımaz
        for t in ret.taint:
            if t.src.label == "param":
                prev = self.summary.ret_params.get(t.src.param)
                self.summary.ret_params[t.src.param] = t.safe if prev is None else (prev & t.safe)
        self.summary.ret_taint = frozenset(t for t in ret.taint if t.src.label != "param")
        self.summary.ret_tag = ret.tag
        if self.ret_values and all(v.keys is not None for v in self.ret_values) and not _scalar_return(self.m.ret_type):
            merged: dict[Any, V] = {}
            for v in self.ret_values:
                for k, kv in v.keys:
                    merged[k] = join(merged[k], kv) if k in merged else kv
            shape = {}
            for k, kv in merged.items():
                params: dict[int, frozenset[str]] = {}
                for t in kv.taint:
                    if t.src.label == "param":
                        params[t.src.param] = t.safe if t.src.param not in params else params[t.src.param] & t.safe
                shape[k] = (params, frozenset(t for t in kv.taint if t.src.label != "param"))
            self.summary.ret_keys = shape

    def run_toplevel(self, env: dict[str, V]) -> dict[str, V]:
        stmts = self.parser.block(0, len(self.t))
        try:
            env, _ = self.run(stmts, env)
        except RecursionError:
            pass
        return env

    def _param_is_source(self, prm: lex.Param) -> bool:
        if self.lang == "java":
            if prm.annotations & _JAVA_SOURCE_ANN:
                return True
            if prm.type in ("Authentication", "String") and self._spring_security_login():
                return True  # giriş formundaki kullanıcı adı/parola
            if prm.type in _TYPE_TAGS or prm.type in _JAVA_FRAMEWORK_TYPES:
                return False
            return True
        if self.lang == "csharp":
            if "fromservices" in prm.annotations or prm.type in _CS_FRAMEWORK_TYPES or "middleware" in self.m.annotations:
                return False
            if prm.type.lower() in ("int", "long", "bool", "guid", "datetime", "decimal", "double", "float", "short",
                                    "byte", "uint", "ulong", "datetimeoffset", "timespan", "dateonly", "timeonly"):
                return False
            if "minimalapi" in self.m.annotations:
                # Minimal API: türü kayıtlı servis olan parametreler DI'dan gelir (örtük [FromServices])
                if prm.annotations & _CS_MINIMAL_SOURCE_ANN or prm.type in _CS_MINIMAL_SOURCE_TYPES or not prm.type:
                    return True
                typ = prm.type
                if (typ[:1] == "I" and typ[1:2].isupper()) or _CS_SERVICE_TYPE.search(typ):
                    return False
                return typ in self.p.classes  # proje içi DTO/record: gövde/sorgu bağlama
            return True
        if self.php:
            if prm.type in _TYPE_TAGS:
                return False
            return prm.type == "" or prm.type.lower() in ("string", "mixed", "array")
        return False

    # -- deyimler ----------------------------------------------------------
    def run(self, stmts: list, env: dict[str, V]) -> tuple[dict[str, V], str | None]:
        for s in stmts:
            env, term = self.exec(s, env)
            if term:
                return env, term
        return env, None

    def exec(self, s: Any, env: dict[str, V]) -> tuple[dict[str, V], str | None]:
        if s is None:
            return env, None
        self.steps += 1
        if self.steps > MAX_STEPS_PER_METHOD:
            return env, None
        kind = s[0]
        if kind == "expr":
            self.ev_stmt(s[1], s[2], env)
            t0 = self.t[s[1]]
            if t0.kind == "id" and (s[2] - s[1]) >= 3 and self.t[s[1] + 1].kind == "op" and self.t[s[1] + 1].value == "(" \
                    and self.pairs.get(s[1] + 1) == s[2] - 1 and _TERMINATING.match(t0.value):
                return env, "ret"
            return env, None
        if kind == "block":
            return self.run(s[1], env)
        if kind == "if":
            return self._exec_if(s, env)
        if kind in ("while", "for", "foreach", "dowhile"):
            return self._exec_loop(s, env), None
        if kind == "switch":
            return self._exec_switch(s, env)
        if kind == "try":
            return self._exec_try(s, env)
        if kind == "return":
            v = self.ev(s[1], s[2], env) if s[1] < s[2] else CLEAN
            self._on_return(v, s[1], env)
            return env, "ret"
        if kind == "throw":
            self.ev(s[1], s[2], env)
            return env, "ret"
        if kind == "exit":
            v = self.ev(s[1], s[2], env)
            if s[1] < s[2]:
                self.sink("html", "exit/die çıktısı", self._line(s[1]), v)
            return env, "ret"
        if kind == "break":
            if self.breaks:
                self.breaks[-1].append(dict(env))
            return env, "brk"
        if kind == "continue":
            if self.conts:
                self.conts[-1].append(dict(env))
            return env, "cont"
        if kind == "echo":
            for a, b in s[1]:
                v = self.ev(a, b, env)
                self.sink("html", "echo/print", self._line(a), v)
            return env, None
        if kind == "include":
            return self._exec_include(s[1], s[2], env), None
        return env, None

    def _line(self, i: int) -> int:
        return self.t[min(i, len(self.t) - 1)].line if self.t else 0

    def _exec_if(self, s: Any, env: dict[str, V]) -> tuple[dict[str, V], str | None]:
        (ca, cb), then, els = s[1], s[2], s[3]
        cv = self.ev(ca, cb, env)
        truth = self.truth(cv)
        gt, gf = self.guards(ca, cb, env)
        if truth is True:
            return self.exec(then, self.apply_guards(env, gt))
        if truth is False:
            if els is None:
                return env, None
            return self.exec(els, self.apply_guards(env, gf))
        # Yanıt içerik türü kararı (resp_non_html) ortamın parçası değildir: sonlanan dalda (wp_send_json_error();
        # exit / return) atanan tür sonraki çıktıya taşınmaz (W2-XSS).
        resp_before = (self.resp_non_html, self.resp_type_set)
        et, tt = self.exec(then, self.apply_guards(dict(env), gt))
        resp_then = (self.resp_non_html, self.resp_type_set)
        if tt:
            self.resp_non_html, self.resp_type_set = resp_before
        if els is not None:
            ef, tf_ = self.exec(els, self.apply_guards(dict(env), gf))
        else:
            ef, tf_ = self.apply_guards(dict(env), gf), None
        if tf_:
            self.resp_non_html, self.resp_type_set = resp_then if not tt else resp_before
        if tt and tf_:
            return join_env(et, ef), ("ret" if tt == tf_ == "ret" else tt)
        if tt:
            return ef, None
        if tf_:
            return et, None
        return join_env(et, ef), None

    def _exec_loop(self, s: Any, env: dict[str, V]) -> dict[str, V]:
        kind = s[0]
        self.breaks.append([])
        self.conts.append([])
        try:
            if kind == "for":
                _k, init, cond, upd, body = s
                if init[0] < init[1]:
                    self.ev_stmt(init[0], init[1], env)
                start = dict(env)
                if cond[0] < cond[1] and self.truth(self.ev(cond[0], cond[1], env)) is False:
                    return start
                e1, _ = self.exec(body, dict(start))
                e1 = join_env(start, e1, *self.conts[-1])
                e2, _ = self.exec(body, dict(e1))
                return join_env(start, e1, e2, *self.breaks[-1], *self.conts[-1])
            if kind == "dowhile":
                body, (ca, cb) = s[1], s[2]
                e1, _ = self.exec(body, dict(env))
                self.ev(ca, cb, e1)
                e2, _ = self.exec(body, join_env(e1, *self.conts[-1]))
                return join_env(e1, e2, *self.breaks[-1])
            header, body = s[1], s[2]
            if kind == "while":
                if self.truth(self.ev(header[0], header[1], env)) is False:
                    return env
                gt, _gf = self.guards(header[0], header[1], env)
                e1, _ = self.exec(body, self.apply_guards(dict(env), gt))
                e1 = join_env(env, e1, *self.conts[-1])
                e2, _ = self.exec(body, self.apply_guards(dict(e1), gt))
                return join_env(env, e1, e2, *self.breaks[-1], *self.conts[-1])
            # foreach
            bind = self._foreach_binder(header[0], header[1], env)
            e0 = dict(env)
            bind(e0)
            e1, _ = self.exec(body, e0)
            e1 = join_env(env, e1, *self.conts[-1])
            bind(e1)
            e2, _ = self.exec(body, e1)
            return join_env(env, e1, e2, *self.breaks[-1], *self.conts[-1])
        finally:
            self.breaks.pop()
            self.conts.pop()

    def _foreach_binder(self, a: int, b: int, env: dict[str, V]):
        t = self.t
        if self.php:
            as_idx = next((k for k in range(a, b) if t[k].kind == "id" and t[k].value.lower() == "as"), None)
            if as_idx is None:
                self.ev(a, b, env)
                return lambda e: None
            coll = self.ev(a, as_idx, env)
            elem = self.elem_of(coll)
            arrow = next((k for k in range(as_idx, b) if t[k].kind == "op" and t[k].value == "=>"), None)
            names = [t[k].value for k in range(as_idx + 1, b) if t[k].kind == "var"]
            key_v = taint_only(coll) if (coll.tag == "sg") else CLEAN

            def bind(e: dict[str, V]) -> None:
                if arrow is not None and len(names) >= 2:
                    e[names[0]] = key_v
                    e[names[-1]] = elem
                elif names:
                    e[names[-1]] = elem
            return bind
        sep = next((k for k in range(a, b) if (self.lang == "java" and t[k].kind == "op" and t[k].value == ":")
                    or (self.lang == "csharp" and t[k].kind == "id" and t[k].value == "in")), None)
        if sep is None:
            self.ev(a, b, env)
            return lambda e: None
        coll = self.ev(sep + 1, b, env)
        elem = self.elem_of(coll)
        names = [t[k] for k in range(a, sep) if t[k].kind == "id"]
        if not names:
            return lambda e: None
        name = names[-1].value
        typ = names[-2].value if len(names) >= 2 else ""
        if typ in ("var", "val", "final", "let"):
            typ = ""
        if typ:
            self.types[name] = lex._simple_type(typ)

        def bind(e: dict[str, V]) -> None:
            e[name] = replace(elem, type=self.types.get(name, elem.type)) if typ else elem
        return bind

    def _exec_switch(self, s: Any, env: dict[str, V]) -> tuple[dict[str, V], str | None]:
        (ea, eb), cases = s[1], s[2]
        sel = self.ev(ea, eb, env)
        self.breaks.append([])
        try:
            if not cases:
                return env, None
            start_idx: list[int]
            if sel.const is not _NOC:
                chosen = None
                for idx, (labels, _d, _st, _arrow) in enumerate(cases):
                    for la, lb in labels:
                        lv = self.ev(la, lb, env)
                        if lv.const is not _NOC and self._eq(lv.const, sel.const):
                            chosen = idx
                            break
                    if chosen is not None:
                        break
                if chosen is None:
                    chosen = next((idx for idx, c in enumerate(cases) if c[1]), None)
                if chosen is None:
                    return env, None
                start_idx = [chosen]
                has_default = True
            else:
                start_idx = list(range(len(cases)))
                has_default = any(c[1] for c in cases)
            results: list[dict[str, V]] = []
            all_ret = True
            sel_key = self.key_of(ea, eb)
            for idx in start_idx:
                e = dict(env)
                labels = cases[idx][0]
                if sel_key and len(labels) >= 1 and sel.const is _NOC:
                    consts = [self.ev(la, lb, {}) for la, lb in labels]
                    if all(c.const is not _NOC for c in consts):
                        # case 'a': seçici bu dalda sabit etiketlerden biri
                        e[sel_key] = consts[0] if len(consts) == 1 else V(const=_NOC)
                term = None
                for c in cases[idx:]:
                    e, term = self.run(c[2], e)
                    if term or c[3]:
                        break
                if term == "ret":
                    continue
                all_ret = False
                if term != "brk":
                    results.append(e)
            results.extend(self.breaks[-1])
            if not has_default:
                results.append(env)
                all_ret = False
            if not results:
                return env, ("ret" if all_ret else None)
            return join_env(*results), None
        finally:
            self.breaks.pop()

    def _exec_try(self, s: Any, env: dict[str, V]) -> tuple[dict[str, V], str | None]:
        _k, res, body, catches, fin = s
        if res is not None:
            for a, b in lex.split_top(self.t, self.pairs, res[0], res[1], ";"):
                self.ev_stmt(a, b, env)
        e1, t1 = self.exec(body, dict(env))
        outs = [] if t1 else [e1]
        all_term = bool(t1)
        for param, cb in catches:
            ec = join_env(env, e1)
            if param is not None:
                names = [t for t in self.t[param[0]:param[1]] if t.kind in ("id", "var")]
                if names:
                    ec[names[-1].value] = CLEAN
            ec, tc = self.exec(cb, ec)
            if not tc:
                outs.append(ec)
                all_term = False
        out = join_env(*outs) if outs else join_env(env, e1)
        if fin is not None:
            out, tf_ = self.exec(fin, out)
            if tf_:
                return out, tf_
        return out, ("ret" if all_term and catches else None)

    def _exec_include(self, a: int, b: int, env: dict[str, V]) -> dict[str, V]:
        v = self.ev(a, b, env)
        self.sink("path", "include/require", self._line(a), v)
        if len(self.include_stack) > MAX_INCLUDE_DEPTH or self.p.out_of_time():
            return env
        pattern = self.str_pattern(a, b, env)
        if not pattern:
            return env
        results = []
        env_key = frozenset((k, v.taint) for k, v in env.items() if v.taint)
        for unit in self.p.resolve_include(self.u, pattern):
            if unit.path in self.include_stack:
                continue
            top = next((m for m in unit.methods if m.toplevel), None)
            if top is None:
                continue
            key = (unit.path, env_key if self.p.include_runs < 4000 else frozenset())
            delta = self.p.include_delta.get(key)
            if delta is None:
                self.p.include_runs += 1
                sub = Interp(self.p, unit, top, self.include_stack)
                after = sub.run_toplevel(dict(env))
                delta = {k: v for k, v in after.items() if env.get(k) != v}
                self.p.include_delta[key] = delta
            merged = dict(env)
            merged.update(delta)
            results.append(merged)
        return join_env(*results) if results else env

    def str_pattern(self, a: int, b: int, env: dict[str, V]) -> str:
        """Dize ifadesinin dosya deseni: bilinen sabit parçalar + bilinmeyenler için ``*``."""
        out: list[str] = []
        for x, y in self._split_ops(a, b, {"."} if self.php else {"+"}):
            while x < y and self.t[x].kind == "op" and self.t[x].value == "(" and self.pairs.get(x) == y - 1:
                x, y = x + 1, y - 1
            if y - x == 1 and self.t[x].kind == "istr":
                for part in self.t[x].value:
                    if isinstance(part, str):
                        out.append(part)
                    else:
                        sub = self._eval_tokens(part, env)
                        out.append(sub.const if isinstance(sub.const, str) else "*")
                continue
            v = self.ev(x, y, env)
            if isinstance(v.const, str):
                out.append(v.const)
            elif y - x == 1 and self.t[x].kind == "id" and self.t[x].value in ("__DIR__", "__FILE__"):
                out.append("*")
            else:
                out.append("*")
        return "".join(out)

    def _on_return(self, v: V, at: int, env: dict[str, V]) -> None:
        self.ret_values.append(v)
        if self.lang == "java" and self.cls is not None and isinstance(v.const, str):
            target = self.p.struts_results.get(self.cls.name, {}).get(v.const)
            if target:
                fv = self._ident(target, at, at + 1, env)
                if fv.taint:
                    self.sink("redirect", f"Struts2 redirect sonucu ${{{target}}}", self._line(at), fv)
        if self.lang == "java" and self._model_attrs and isinstance(v.const, str) and self.p.th_views:
            raw = self.p.th_views.get(v.const.strip().lstrip("/"))
            for attr, av, aline in self._model_attrs if raw else ():
                if attr in raw:
                    self.sink("html", f"Thymeleaf th:utext ${{{attr}}} ({v.const})", aline, av)
        if self.lang == "java" and self._model_attrs and isinstance(v.const, str) and self.p.jsp_views:
            view = v.const.strip().lstrip("/")
            if view.endswith(".jsp"):
                view = view[:-4]
            uses = self.p.jsp_views.get(view) or self.p.jsp_views.get(view.rsplit("/", 1)[-1]) or {}
            for attr, av, _aline in self._model_attrs:
                for jpath, jline, expr in uses.get(attr, ()):
                    if _CLEAN_COLUMN_RE.search(expr.rsplit(".", 1)[-1]) and "." in expr \
                            and all(t.src.label == "stored" for t in av.taint):
                        continue  # 25. tur: kayıtlı kaydın kimlik/sayı/tarih alanı (${ad.createDate}) HTML taşımaz
                    self._sink_in_file("html", f"JSP EL ${{{expr}}} (kaçışsız, {v.const})", jpath, jline, av)
        if not self.endpoint or not v.taint:
            return
        line = self._line(at)
        if self.lang == "java":
            prefix = (v.prefix or "").lower()
            if prefix.startswith(("redirect:", "forward:")):
                target = prefix.split(":", 1)[1]
                # 18. tur: "forward:" sunucu içi yönlendirmedir; "redirect:/sabit/…" + girdi aynı sitede kalır
                # (açık yönlendirme değil). Yalnız hedefin başı girdiye açıksa ("redirect:" + x, "redirect:/" + x → //…).
                if prefix.startswith("forward:") or (len(target) >= 2 and target[0] == "/" and target[1] not in "/\\"):
                    return
                self.sink("redirect", '"redirect:" dönüşü', line, v)
                return
            rest = "responsebody" in self.m.annotations or bool(self.cls and self.cls.annotations & {"restcontroller"})
            stringy = self.m.ret_type != "Object" or isinstance(v.const, str) or v.prefix is not None \
                or v.type in ("String", "StringBuilder", "StringBuffer", "CharSequence")
            # 17. tur: Object dönüşü yalnız değer dize olduğunda metin olarak yazılır; liste/eşlem/varlık JSON'a çevrilir
            if rest and stringy and self.m.ret_type in ("String", "Object", "CharSequence", "StringBuilder"):
                if not self._spring_produces_non_html():
                    self.sink("html", "@ResponseBody String dönüşü", line, v)
                elif self._jsonp_line(line):
                    self.sink("jsonp", "@ResponseBody JSONP dönüşü", line, v)

    def _produces_values(self, start: int) -> list[str] | None:
        """``start`` belirtecinden geriye bildirim başlığındaki ek açıklamalarda ``produces = …`` değerleri
        (dize sabitleri ve MediaType.X adları); yoksa None."""
        t, pairs = self.t, self.pairs
        i = start - 1
        while i >= 0:
            tok = t[i]
            if tok.kind == "op" and tok.value in (";", "{", "}"):
                break
            if tok.kind == "op" and tok.value in (")", "]") and i in pairs:
                i = pairs[i] - 1
                continue
            i -= 1
        k, values, found = i + 1, [], False
        while k < start:
            tok = t[k]
            if tok.kind == "id" and tok.value == "produces" and k + 1 < start and t[k + 1].value == "=":
                found, depth, k = True, 0, k + 2
                while k < start:
                    x = t[k]
                    if x.kind == "op" and x.value in ("(", "{", "["):
                        depth += 1
                    elif x.kind == "op" and x.value in (")", "}", "]"):
                        if depth == 0:
                            break
                        depth -= 1
                    elif x.kind == "op" and x.value == "," and depth == 0:
                        break
                    elif x.kind == "str":
                        values.append(str(x.value))
                    elif x.kind == "id" and x.value not in ("MediaType", "org", "springframework", "http"):
                        values.append("@" + str(x.value))
                    k += 1
            k += 1
        return values if found else None

    def _spring_produces_non_html(self) -> bool:
        """Spring ``produces`` (yöntem, yoksa sınıf düzeyi) yalnız HTML dışı içerik türleri mi (JSON, düz metin …)?
        Bu durumda @ResponseBody dize dönüşü tarayıcıda HTML olarak işlenmez."""
        cached = getattr(self, "_produces_cache", None)
        if cached is not None:
            return cached
        values = self._produces_values(self.m.body[0] - 1)
        if values is None and self.cls is not None:
            values = self._produces_values(self.cls.start)
        verdicts = []
        for value in values or ():
            if value.startswith("@"):
                name = value[1:].upper()
                verdicts.append(False if ("HTML" in name or "XML" in name) else
                                True if any(x in name for x in ("JSON", "TEXT_PLAIN", "OCTET_STREAM", "PDF", "IMAGE_",
                                                                 "TEXT_EVENT_STREAM", "TEXT_MARKDOWN")) else None)
            else:
                verdicts.append(_response_type_verdict("content-type", value))
        result = bool(verdicts) and all(v is True for v in verdicts)
        self._produces_cache = result
        return result

    # -- korumalar ---------------------------------------------------------
    def guards(self, a: int, b: int, env: dict[str, V]) -> tuple[dict[str, tuple], dict[str, tuple]]:
        a, b = self._strip(a, b)
        # 17. tur: "/" önek denetimi yalnız aynı koşulda "//" (protokolsüz adres) de dışlanıyorsa yönlendirme koruması
        self._cond_dslash = any(tok.kind == "str" and tok.value in ("//", "\\\\", "/\\") for tok in self.t[a:b])
        true_facts, false_facts = self._guards(a, b, env)
        for facts in (true_facts, false_facts):
            for key in list(facts):
                tag = env.get(key, CLEAN).tag
                if tag and tag.startswith("hostof:") and tag[7:] not in facts:
                    facts[tag[7:]] = _REDIRECT_KINDS  # ana makine denetimi → kaynak adres yönlendirme/SSRF için güvenli
        return true_facts, false_facts

    def _guards(self, a: int, b: int, env: dict[str, V]) -> tuple[dict[str, tuple], dict[str, tuple]]:
        true_facts: dict[str, tuple] = {}
        false_facts: dict[str, tuple] = {}
        ors = self._split_ops(a, b, {"||", "or"})
        if len(ors) > 1:
            # (x == 'a' || x == 'b' || empty(x)) → doğru dalda x sabit kümede
            atoms = [self._guard_atom(x, y, env) for x, y in ors]
            if atoms and all(at and at[1] is True and at[3] == "eq" for at in atoms) and len({at[0] for at in atoms}) == 1:
                true_facts[atoms[0][0]] = (ALL,)
        if len(ors) == 1:
            ands = self._split_ops(a, b, {"&&", "and"})
            for x, y in ands:
                atom = self._guard_atom(x, y, env)
                if atom and atom[1] is not False:
                    true_facts[atom[0]] = atom[2]
            if len(ands) == 1:
                atom = self._guard_atom(a, b, env)
                if atom and atom[1] is not True:
                    false_facts[atom[0]] = atom[2]
            else:
                atoms = [self._guard_atom(x, y, env) for x, y in ands]
                if atoms and all(at and at[1] is not True for at in atoms) and len({at[0] for at in atoms}) == 1:
                    false_facts[atoms[0][0]] = atoms[0][2]  # her olumsuzlama aynı anahtarı güvenli kılar
        else:
            for x, y in ors:
                atom = self._guard_atom(x, y, env)
                if atom and atom[1] is not True:
                    false_facts[atom[0]] = atom[2]
        return true_facts, false_facts

    def _guard_atom(self, a: int, b: int, env: dict[str, V]) -> tuple | None:
        """(anahtar, olumlu_mu, güvenli_türler, biçim) — olumlu: koşul doğruysa anahtar güvenli."""
        a, b = self._strip(a, b)
        if a >= b:
            return None
        t = self.t
        if t[a].kind == "op" and t[a].value == "!":
            inner = self._guard_atom(a + 1, b, env)
            if inner is None:
                return None
            return (inner[0], None if inner[1] is None else not inner[1], inner[2], "neg")
        # Karşılaştırma: x == "lit" / x != "lit"
        for k in self._top_ops(a, b):
            op = t[k].value
            if op in ("==", "===", "!=", "!==", "<>"):
                left, right = (a, k), (k + 1, b)
                for side, other in ((left, right), (right, left)):
                    ov = self.ev(other[0], other[1], {})
                    hashed = self._hash_call(other[0], other[1])
                    if hashed is not None and side == right and self.key_of(*side) is not None:
                        # özet(x) == beklenen: bütünlük doğrulandı → x (eşitlik dalında) güvenli
                        return hashed, op in ("==", "==="), (ALL,), "hmac"
                    if ov.const is _NULL:
                        checked = self._validator_call(side[0], side[1])
                        if checked is not None:
                            # Doğrulayıcı(x) == null → geçersiz; != null → x bu türler için güvenli
                            return checked[0], op in ("!=", "!==", "<>"), checked[1], "nullcheck"
                    if ov.const is not _NOC and self.key_of(side[0], side[1]) is None:
                        sv = self._pure_value(side[0], side[1], env)
                        if sv is not None and sv.tag and sv.tag.startswith("hostof:") and \
                                (ov.const is _NULL or isinstance(ov.const, str)):
                            # uri.getHost() == null / parse_url(…)['host'] !== 'site' → kaynak adres için olgu
                            positive = op in ("==", "===")
                            return sv.tag[7:], positive, _REDIRECT_KINDS, "eq" if positive else "neq"
                    if ov.const is _NULL and self.php:
                        nkey = self.key_of(side[0], side[1])
                        if nkey:
                            positive = op in ("==", "===")  # $x === null doğruysa $x boş
                            return nkey, positive, (ALL,), "eq" if positive else "neq"
                    if ov.const is not _NOC and ov.const is not _NULL:
                        key = self.key_of(side[0], side[1])
                        if key:
                            positive = op in ("==", "===")
                            return key, positive, (ALL,), "eq" if positive else "neq"
                        if self.php and ov.const == 0 and not isinstance(ov.const, bool):
                            pref = self._prefix_call(side[0], side[1])
                            if pref is not None:
                                same = op in ("==", "===")
                                return pref[0], same, ("redirect",), "pred"
                        if self.php and (ov.const in (0, 1) or isinstance(ov.const, bool)):
                            # 17. tur: preg_match(…) !== 1 / is_numeric($x) === false gibi yüklem karşılaştırmaları
                            inner = self._guard_atom(side[0], side[1], env)
                            if inner is not None and inner[3] in ("pred", "neg") and inner[1] is not None:
                                truthy = bool(ov.const)
                                same = (op in ("==", "===")) == truthy
                                return inner[0], inner[1] if same else not inner[1], inner[2], "pred"
                return None
        bare = self.key_of(a, b)
        if bare is not None and self.php:
            return bare, False, (ALL,), "truthy"  # if ($x): yanlış dalda $x boş/0/false
        # Çağrı biçimli yüklemler
        name_idx = None
        k = a
        while k < b:  # yalnız en üst düzey çağrı (argümanlardaki iç çağrılar değil)
            if t[k].kind == "id" and k + 1 < b and t[k + 1].kind == "op" and t[k + 1].value == "(" and (k + 1) in self.pairs:
                name_idx = k
                k = self.pairs[k + 1] + 1
                continue
            if t[k].kind == "op" and t[k].value in ("(", "[") and k in self.pairs:
                k = self.pairs[k] + 1
                continue
            k += 1
        if name_idx is None:
            return None
        name = t[name_idx].value
        lname = name.lower()
        open_i = name_idx + 1
        close_i = self.pairs[open_i]
        args = lex.split_top(t, self.pairs, open_i + 1, close_i, ",")
        recv_range = (a, name_idx - 1) if name_idx - 1 > a and t[name_idx - 1].kind == "op" and \
            t[name_idx - 1].value in (".", "->", "::", "?.") else None
        if lname in ("hash_equals", "equals", "constanttimeequals", "isequal", "compare_digest") and len(args) >= 2:
            for x, y in args[:2]:
                hashed = self._hash_call(x, y)
                if hashed:
                    return hashed, True, (ALL,), "hmac"
        if args and lname == "in_array":
            key = self.key_of(*args[0]) or self._concat_var_key(*args[0])
            return (key, True, (ALL,), "pred") if key else None
        if args and (lname.endswith("exists") or lname in ("in_array", "is_registered", "post_type_exists",
                                                             "taxonomy_exists", "term_exists", "has_key", "containskey",
                                                             "iswhitelisted", "isallowed", "is_allowed")):
            key = self.key_of(*args[0])
            return (key, True, (ALL,), "pred") if key else None
        if args and _VALIDATOR_PRED.search(name) and not self._unanchored_find_validator(name):
            key = self.key_of(*args[0])
            kinds: list[str] = []
            for pattern, hint in _SANITIZE_HINTS:
                if pattern.search(name):
                    kinds.extend(hint)
            # Doğrulayıcı yüklem: kutupluluğu bilinmez (validate_file 0 = geçerli); iki dalda da güvenli sayılır.
            return (key, None, tuple(kinds) or (ALL,), "validator") if key else None
        if self.php:
            if lname == "str_starts_with" and len(args) >= 2 and getattr(self, "_cond_dslash", False):
                nv = self.ev(args[1][0], args[1][1], {})
                key = self.key_of(*args[0])
                if nv.const == "/" and key:
                    return key, True, ("redirect",), "pred"
            if lname in ("is_numeric", "is_int", "is_integer", "is_float", "ctype_digit", "ctype_alnum",
                         "ctype_alpha", "ctype_xdigit", "is_bool") and args:
                key = self.key_of(*args[0])
                return (key, True, (ALL,), "pred") if key else None
            if lname == "filter_var" and len(args) >= 2:
                flag = "".join(str(x.value) for x in t[args[1][0]:args[1][1]])
                if re.search(r"VALIDATE_(INT|FLOAT|BOOL|IP|EMAIL|MAC)", flag):
                    key = self.key_of(*args[0])
                    return (key, True, (ALL,), "pred") if key else None
            if lname == "in_array" and len(args) >= 2:
                key = self.key_of(*args[0])
                return (key, True, (ALL,), "pred") if key else None
            if lname == "preg_match" and len(args) >= 2:
                pv = self.ev(args[0][0], args[0][1], {})
                if isinstance(pv.const, str) and _safe_regex_literal(pv.const):
                    key = self.key_of(*args[1])
                    return (key, True, (ALL,), "pred") if key else None
                if isinstance(pv.const, str) and _negated_safe_class(pv.const):
                    key = self.key_of(*args[1])
                    return (key, False, (ALL,), "pred") if key else None  # yasak karakter bulunduysa geçersiz
            if lname in ("empty", "is_null") and args:
                key = self.key_of(*args[0])
                return (key, True, (ALL,), "eq") if key else None
            return None
        # Java / C#
        if name in ("startsWith", "StartsWith", "str_starts_with") and getattr(self, "_cond_dslash", False):
            target = recv_range if recv_range else (args[0] if len(args) >= 2 else None)
            needle = args[0] if recv_range and args else (args[1] if len(args) >= 2 else None)
            if target is not None and needle is not None:
                nv = self.ev(needle[0], needle[1], {})
                key = self.key_of(*target)
                if nv.const == "/" and key:
                    return key, True, ("redirect",), "pred"
        if name in ("equals", "equalsIgnoreCase", "Equals", "contentEquals") and recv_range and args:
            for one, other in ((recv_range, args[0]), (args[0], recv_range)):
                hv = self._pure_value(one[0], one[1], env)
                ov2 = self.ev(other[0], other[1], {})
                if hv is not None and hv.tag and hv.tag.startswith("hostof:") and isinstance(ov2.const, str):
                    return hv.tag[7:], True, _REDIRECT_KINDS, "eq"
            rv = self.ev(recv_range[0], recv_range[1], {})
            av = self.ev(args[0][0], args[0][1], {})
            if rv.const is not _NOC and isinstance(rv.const, str):
                key = self.key_of(*args[0])
                return (key, True, (ALL,), "eq") if key else None
            if av.const is not _NOC and isinstance(av.const, str):
                key = self.key_of(*recv_range)
                return (key, True, (ALL,), "eq") if key else None
            return None
        if name in ("isNumeric", "isDigits", "isNumber", "isAlphanumeric", "isAlpha", "isCreatable", "isParsable") and args:
            key = self.key_of(*args[0])
            return (key, True, (ALL,), "pred") if key else None
        if name in ("TryParse",) and args:
            key = self.key_of(*args[0])
            return (key, True, (ALL,), "pred") if key else None
        if name in ("IsLocalUrl", "IsUrlLocalToHost") and args:
            key = self.key_of(*args[0])
            return (key, True, ("redirect",), "pred") if key else None
        if name in ("matches",) and recv_range and args:
            pv = self.ev(args[0][0], args[0][1], {})
            if isinstance(pv.const, str) and _safe_regex_literal("^" + pv.const.lstrip("^").rstrip("$") + "$"):
                key = self.key_of(*recv_range)
                return (key, True, (ALL,), "pred") if key else None
        if name in ("IsMatch",) and len(args) >= 2:
            pv = self.ev(args[1][0], args[1][1], {})
            if isinstance(pv.const, str) and _safe_regex_literal(pv.const):
                key = self.key_of(*args[0])
                return (key, True, (ALL,), "pred") if key else None
        if name in ("contains", "Contains") and recv_range and args and recv_range[1] - recv_range[0] == 1 \
                and t[recv_range[0]].kind == "id" and re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", str(t[recv_range[0]].value)):
            key = self.key_of(*args[0])  # ALLOWED_HOSTS.Contains(x): sabit adlı izin listesi
            return (key, True, (ALL,), "pred") if key else None
        if name in ("contains", "Contains") and recv_range and args:
            rv = self.ev(recv_range[0], recv_range[1], env)
            if rv.items is not None and all(i.const is not _NOC and not i.taint for i in rv.items):
                key = self.key_of(*args[0])
                return (key, True, (ALL,), "pred") if key else None
        return None

    def _unanchored_find_validator(self, name: str) -> bool:
        """Proje içi doğrulayıcı yalnız ``Matcher.find()`` ile ve sonu çapalanmamış (``$``/``\\z`` yok) desenle
        denetliyorsa kısmi eşleşme yeter: geri kalan girdi serbesttir, doğrulayıcı arındırıcı sayılmaz (CWE-777)."""
        if self.lang != "java":
            return False
        for u, m in self.p.by_name.get(name, ()):
            if u.lang != "java":
                continue
            a, b = m.body
            ids = {tok.value for tok in u.toks[a:b] if tok.kind == "id"}
            if "find" not in ids or "matches" in ids:
                continue
            pats = self.p.compiled_patterns(u)
            used = [pats[i] for i in ids if i in pats]
            for k in range(a, b - 2):
                tok = u.toks[k]
                if tok.kind == "id" and tok.value == "compile" and u.toks[k + 1].value == "(" and u.toks[k + 2].kind == "str":
                    used.append(str(u.toks[k + 2].value))
            if used and not any(re.search(r"(?:\$|\\[zZ])\)*$", pat) for pat in used):
                return True
        return False

    def _concat_var_key(self, a: int, b: int) -> str | None:
        """``'önek' . $x`` / ``"önek" + x`` biçiminde tek değişkenli birleştirmenin değişken anahtarı."""
        parts = self._split_ops(a, b, {"."} if self.php else {"+"})
        keys = [self.key_of(x, y) for x, y in parts if not (y - x == 1 and self.t[x].kind == "str")]
        return keys[0] if len(keys) == 1 and keys[0] else None

    def _hash_call(self, a: int, b: int) -> str | None:
        """``wp_hash(x)`` / ``hash_hmac(alg, x, k)`` / ``md5(x)`` çağrısı ise x anahtarı."""
        a, b = self._strip(a, b)
        t = self.t
        if b - a < 3 or not (t[b - 1].kind == "op" and t[b - 1].value == ")") or (b - 1) not in self.pairs:
            return None
        open_i = self.pairs[b - 1]
        if open_i <= a or t[open_i - 1].kind != "id" or not re.search(r"(?i)hash|hmac|sign|digest", t[open_i - 1].value):
            return None
        args = lex.split_top(t, self.pairs, open_i + 1, b - 1, ",")
        for x, y in (args[1:2] if t[open_i - 1].value.lower() == "hash_hmac" else args[:1]):
            return self.key_of(x, y)
        return None

    def _validator_call(self, a: int, b: int) -> tuple[str, tuple[str, ...]] | None:
        """``Sınıf.doğrula(x)`` / ``doğrula(x)`` çağrısı ise (x anahtarı, güvenli türler)."""
        a, b = self._strip(a, b)
        t = self.t
        if b - a < 3 or not (t[b - 1].kind == "op" and t[b - 1].value == ")") or (b - 1) not in self.pairs:
            return None
        open_i = self.pairs[b - 1]
        if open_i <= a or t[open_i - 1].kind != "id":
            return None
        name = t[open_i - 1].value
        if not _SANITIZER_NAME.search(name):
            return None
        args = lex.split_top(t, self.pairs, open_i + 1, b - 1, ",")
        if not args:
            return None
        key = self.key_of(*args[0])
        if key is None:
            return None
        kinds: list[str] = []
        for pattern, hint in _SANITIZE_HINTS:
            if pattern.search(name):
                kinds.extend(hint)
        return key, tuple(kinds) or (ALL,)

    def apply_guards(self, env: dict[str, V], facts: dict[str, tuple]) -> dict[str, V]:
        for key, kinds in facts.items():
            cur = env.get(key)
            if cur is None:
                cur = self._eval_key(key, env)
            env[key] = with_safe(cur, kinds) if cur.taint else cur
        return env

    def _eval_key(self, key: str, env: dict[str, V]) -> V:
        toks = lex.tokenize(key, self.lang)
        return self._eval_tokens(toks, env)

    def _eval_tokens(self, toks: list[Tok], env: dict[str, V]) -> V:
        sub_unit = Unit(self.u.path, self.lang, toks, lex.match_pairs(toks), [], [], self.u.text_flags)
        sub = Interp.__new__(Interp)
        sub.__dict__.update(self.__dict__)
        sub.t = toks
        sub.pairs = sub_unit.pairs
        try:
            return sub.ev(0, len(toks), env)
        except RecursionError:
            return CLEAN

    def key_of(self, a: int, b: int) -> str | None:
        """Koruma/indeks anahtarı: yalnız değişken, alan ve sabit indeks zinciri (çağrısız)."""
        a, b = self._strip(a, b)
        if a >= b:
            return None
        parts = []
        for tok in self.t[a:b]:
            if tok.kind in ("id", "var", "num"):
                parts.append(str(tok.value))
            elif tok.kind == "str":
                parts.append("'" + tok.value + "'")
            elif tok.kind == "op" and tok.value in (".", "->", "[", "]", "?.", "::"):
                parts.append(tok.value)
            else:
                return None
        first = self.t[a]
        if first.kind not in ("id", "var"):
            return None
        return "".join(parts)

    # -- ifadeler ----------------------------------------------------------
    def _strip(self, a: int, b: int) -> tuple[int, int]:
        while a < b and self.t[a].kind == "op" and self.t[a].value == "(" and self.pairs.get(a) == b - 1:
            a, b = a + 1, b - 1
        return a, b

    def _top_ops(self, a: int, b: int) -> list[int]:
        out = []
        k = a
        t = self.t
        while k < b:
            tok = t[k]
            if tok.kind == "op":
                v = tok.value
                if v in ("(", "[", "{") and k in self.pairs:
                    k = self.pairs[k] + 1
                    continue
                if v == "<" and not self.php:
                    g = self._generic_end(k, b)
                    if g:
                        k = g
                        continue
                out.append(k)
            elif tok.kind == "id" and tok.value in ("or", "and", "xor", "instanceof", "is", "as") and (
                    self.php or tok.value in ("instanceof", "is", "as")):
                out.append(k)
            k += 1
        return out

    def _generic_end(self, k: int, b: int) -> int | None:
        t = self.t
        if k == 0 or t[k - 1].kind != "id":
            return None
        depth = 0
        m = k
        while m < b and m - k < 40:
            tok = t[m]
            if tok.kind == "op":
                if tok.value == "<":
                    depth += 1
                elif tok.value == ">":
                    depth -= 1
                    if depth == 0:
                        nxt = t[m + 1] if m + 1 < len(t) else None
                        if nxt is None or (nxt.kind == "op" and nxt.value in ("(", ")", "[", "{", ">", ",", ";", ".", "::", "?")) \
                                or nxt.kind == "id":
                            return m + 1
                        return None
                elif tok.value not in (",", ".", "?", "[", "]"):
                    return None
            elif tok.kind not in ("id",):
                return None
            m += 1
        return None

    def _split_ops(self, a: int, b: int, ops: set[str]) -> list[tuple[int, int]]:
        out = []
        start = a
        for k in self._top_ops(a, b):
            v = self.t[k].value
            if v in ops and not self._is_unary(k, start):
                out.append((start, k))
                start = k + 1
        out.append((start, b))
        return out

    def _is_unary(self, k: int, start: int) -> bool:
        if k == start:
            return True
        prev = self.t[k - 1]
        if prev.kind == "op" and prev.value not in (")", "]", "}", "++", "--"):
            return True
        if prev.kind == "id" and prev.value in ("return", "case", "and", "or", "xor", "echo", "print", "throw", "new"):
            return True
        return False

    def find_assign(self, a: int, b: int) -> int | None:
        k = a
        t = self.t
        while k < b:
            tok = t[k]
            if tok.kind == "op":
                v = tok.value
                if v in ("(", "[", "{") and k in self.pairs:
                    k = self.pairs[k] + 1
                    continue
                if v in _ASSIGN_OPS:
                    return k
                if v == "?" or (v in ("=>", "->") and not self.php):
                    return None  # üçlü / lambda: sağ taraftaki atama bu ifadenin değil
            k += 1
        return None

    def truth(self, v: V) -> bool | None:
        c = v.const
        if isinstance(c, bool):
            return c
        return None

    @staticmethod
    def _eq(a: Any, b: Any) -> bool:
        if isinstance(a, str) and isinstance(b, str):
            return a == b
        if isinstance(a, bool) or isinstance(b, bool):
            return a is b
        if isinstance(a, int) and isinstance(b, int):
            return a == b
        if isinstance(a, int) and isinstance(b, str) and len(b) == 1:
            return a == ord(b)
        if isinstance(b, int) and isinstance(a, str) and len(a) == 1:
            return b == ord(a)
        return False

    def ev_stmt(self, a: int, b: int, env: dict[str, V]) -> None:
        if a >= b:
            return
        k = self.find_assign(a, b)
        if k is None:
            if not self.php and self._decl_without_init(a, b, env):
                return
            self.ev(a, b, env)
            return
        if not self.php and k - a >= 2 and self._looks_decl(a, k):
            segs = lex.split_top(self.t, self.pairs, a, b, ",", angle=True)
            first_type = self._decl_type(segs[0][0], self.find_assign(segs[0][0], segs[0][1]) or segs[0][1])
            for n, (x, y) in enumerate(segs):
                ka = self.find_assign(x, y)
                if n == 0:
                    self.assign(x, ka, y, env) if ka is not None else None
                else:
                    if ka is None:
                        if y - x == 1 and self.t[x].kind == "id":
                            env[self.t[x].value] = CLEAN
                        continue
                    if ka - x == 1 and self.t[x].kind == "id" and first_type:
                        self.types[self.t[x].value] = first_type
                    self.assign(x, ka, y, env)
            return
        self.assign(a, k, b, env)

    def _looks_decl(self, a: int, k: int) -> bool:
        t = self.t
        last = t[k - 1]
        if last.kind != "id":
            return False
        prev = t[k - 2]
        return prev.kind == "id" and prev.value not in ("return", "new", "this", "base") or (
            prev.kind == "op" and prev.value in (">", "]", "?"))

    def _decl_type(self, a: int, k: int) -> str:
        t = self.t
        names = []
        m = a
        while m < k - 1:
            tok = t[m]
            if tok.kind == "op" and tok.value == "<":
                g = self._generic_end(m, k) if m > a else None
                if g:
                    m = g
                    continue
            if tok.kind == "op" and tok.value == "@" and m + 1 < k:
                m += 2
                continue
            if tok.kind == "id" and tok.value not in lex.PARAM_MODIFIERS_BY_LANG[self.lang] and \
                    tok.value not in ("final", "const", "static", "volatile", "transient"):
                names.append(tok.value)
            m += 1
        return lex._simple_type(names[-1]) if names else ""

    def _decl_without_init(self, a: int, b: int, env: dict[str, V]) -> bool:
        t = self.t
        if b - a < 2 or t[b - 1].kind != "id":
            return False
        for x, y in lex.split_top(t, self.pairs, a, b, ",", angle=True):
            if t[y - 1].kind == "id":
                env[t[y - 1].value] = CLEAN
        typ = self._decl_type(a, b)
        if typ:
            self.types[t[b - 1].value] = typ
        return all(tok.kind in ("id",) or (tok.kind == "op" and tok.value in ("<", ">", ",", ".", "[", "]", "?"))
                   for tok in t[a:b])

    def assign(self, a: int, k: int, b: int, env: dict[str, V]) -> V:
        op = self.t[k].value
        rv = self.ev(k + 1, b, env)
        self.store(a, k, rv, op, env)
        return rv

    def store(self, a: int, k: int, rv: V, op: str, env: dict[str, V]) -> None:
        t = self.t
        if a >= k:
            return
        last = t[k - 1]
        # PHP list()/[...] ayrıştırma
        if self.php and (t[a].kind == "id" and t[a].value.lower() == "list" or
                         (t[a].kind == "op" and t[a].value == "[" and self.pairs.get(a) == k - 1)):
            elem = self.elem_of(rv)
            for tok in t[a:k]:
                if tok.kind == "var":
                    env[tok.value] = elem
            return
        if t[a].kind == "op" and t[a].value == "(" and self.pairs.get(a) == k - 1 and not self.php:
            elem = self.elem_of(rv)
            for tok in t[a:k]:
                if tok.kind == "id" and tok.value not in ("var",):
                    env[tok.value] = elem
            return
        # Bildirim: Tür ad = …
        if not self.php and last.kind == "id" and k - a >= 2 and self._looks_decl(a, k):
            typ = self._decl_type(a, k)
            if typ and typ not in ("var", "val", "dynamic", "let", "auto"):
                self.types[last.value] = typ
                if rv.tag not in ("dbresult", "stmtw"):  # sorgu sonucu/hazır ifade: type tablo adını taşır
                    rv = replace(rv, type=typ, tag=rv.tag or _TYPE_TAGS.get(typ))
            env[last.value] = rv
            return
        key = self.key_of(a, k)
        if key is None:
            self.ev(a, k, env)
            return
        # C# özellik hedefleri ve WebForms çıktı denetimleri
        if self.lang == "csharp" and k - a >= 3 and last.kind == "id" and t[k - 2].kind == "op" and t[k - 2].value in (".", "?."):
            self._property_sink(a, k - 2, last.value, rv, env)
        if self.lang == "csharp" and t[a].kind == "id" and t[a].value == "Session" and k - a >= 3:
            self.sink("session", "Session[…]", t[a].line, rv)
        if self.lang == "java" and rv.taint and self.cls is not None and self.cls.name in self.p.struts_classes:
            # Struts2 eylem alanı (alan / this.alan): sonuç JSP'si <s:property> ile okur
            fname = t[a].value if k - a == 1 and t[a].kind == "id" and t[a].value not in env else (
                t[k - 1].value if k - a == 3 and t[a].value == "this" and t[a + 1].value == "." else None)
            if fname and fname in self.cls.fields:
                live = frozenset(x for x in rv.taint if x.src.label in ("request", "stored"))
                if live:
                    key = (self.cls.name, str(fname))
                    self.p.struts_field_taint[key] = self.p.struts_field_taint.get(key, frozenset()) | live
        if self.lang == "csharp" and not self.u.razor and rv.taint:
            self._note_cs_write(a, k, rv, env)
            if t[k - 1].kind == "op" and t[k - 1].value == "]" and (k - 1) in self.pairs:
                op_i = self.pairs[k - 1]
                key_tok = [x for x in t[op_i + 1:k - 1] if x.kind == "str"]
                if op_i > a and t[op_i - 1].kind == "id" and t[op_i - 1].value == "Headers" and key_tok \
                        and str(key_tok[0].value).lower() == "location":
                    self.sink("redirect", "Headers[\"Location\"]", t[a].line, rv)
        if self.php and key.startswith("$_SESSION["):
            self.p.note_session(key, rv)
        if self.php and key in ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE"):
            # $_POST = array_map(kaçış, $_POST): yalnız tanınan arındırıcıyla yeniden yazma kaydedilir
            if rv.tag == "sgclean":
                env["\x00sgall:" + key] = CLEAN
            elif rv.taint:
                env["\x00sgall:" + key] = V(rv.taint)
        if self.php and re.fullmatch(r"\$_(?:GET|POST|REQUEST|COOKIE)\[\$\w+\]", key):
            # 17. tur: süper küresel diziyi toplu yeniden yazma ($_POST[$k] = kaçış($v)): sonraki tüm okumalar bu
            # dönüşümün güvenli türlerini taşır (yalnız tüm yazmalar aynı türden arındırılmışsa).
            sg = key.split("[", 1)[0]
            prev = env.get("\x00sgall:" + sg)
            env["\x00sgall:" + sg] = rv if prev is None else join(prev, rv)
        simple = (k - a == 1)
        old = env.get(key)
        if op in ("+=", ".=") and old is not None:
            new = self._concat([old, rv])
        elif op == "??=" and old is not None:
            new = join(old, rv)
        elif op in ("=",):
            new = rv
        elif op in ("|=", "&=", "^=", "*=", "/=", "%=", "-="):
            new = CLEAN if old is None or not old.taint else V(old.taint)
        else:
            new = rv if old is None else join(old, rv)
        env[key] = new
        if not simple and self.lang == "csharp" and t[a].kind == "id" and t[a].value in ("ViewData", "ViewBag", "TempData"):
            return  # çatı sözlükleri: yerel değişken gibi güncellenmez (etiketleri korunur)
        if not simple:
            base_end = a + 1
            base = t[a].value
            if t[a].kind in ("id", "var"):
                if base in ("this", "$this") and a + 2 < k and t[a + 1].kind == "op" and t[a + 1].value in (".", "->"):
                    base = base + t[a + 1].value + str(t[a + 2].value)
                    base_end = a + 3
                cur = env.get(base, CLEAN) if base_end < k else CLEAN
                if base_end < k:
                    # komut nesnesinin tablo işareti (sqlcmd önekleri) özellik yazımında korunur (25. tur)
                    updated = V(cur.taint | rv.taint, cur.tag, _NOC, None, cur.keys, cur.type,
                                cur.prefix if cur.tag == "sqlcmd" else None)
                    if t[base_end].kind == "op" and t[base_end].value == "[" and self.pairs.get(base_end) == k - 1 and cur.keys is not None:
                        kv = self.ev(base_end + 1, k - 1, env)
                        if kv.const is not _NOC:
                            keys = tuple((kk, vv) for kk, vv in cur.keys if kk != kv.const) + ((kv.const, rv),)
                            updated = replace(updated, keys=keys)
                    env[base] = updated

    def _note_cs_write(self, a: int, k: int, rv: V, env: dict[str, V]) -> None:
        """Görünüme taşınan yazmalar: ViewData["k"]/TempData["k"] = v, ViewBag.K = v, model.P = v, P = v (sınıf
        özelliği). Yetkili (yönetici) bağlamdaki yazmalar kayıtlı veri sayılmaz (yönetici içeriği)."""
        t = self.t
        if self.privileged:
            self.p.privileged_model_writes += 1
            return
        if t[a].kind == "id" and t[a].value in ("ViewData", "TempData") and a + 1 < k and t[a + 1].value == "[" \
                and self.pairs.get(a + 1) == k - 1:
            kv = self.ev(a + 2, k - 1, env)
            if isinstance(kv.const, str):
                self.p.note_viewbag(kv.const, rv)
            return
        if k - a == 1 and t[a].kind == "id" and self.cls is not None and t[a].value in self.cls.props \
                and t[a].value not in env:
            self.p.note_model_prop(self.cls.name, t[a].value, rv, page_model=self._page_model_cls() or self._webforms_cls())
            return
        if k - a == 1 and t[a].kind == "id" and self.cls is not None and t[a].value in self.cls.fields \
                and t[a].value not in env and self._webforms_cls():
            # WebForms: Page_Load içinde sayfa alanına yazılan istek verisi işaretlemede (<%= alan %>) okunur
            self.p.note_model_prop(self.cls.name, t[a].value, rv, page_model=True)
            return
        if k - a >= 3 and t[k - 1].kind == "id" and t[k - 2].kind == "op" and t[k - 2].value in (".", "?."):
            prop = str(t[k - 1].value)
            if k - a == 3 and t[a].kind == "id" and t[a].value == "ViewBag":
                self.p.note_viewbag(prop, rv)
                return
            if k - a == 3 and t[a].kind == "id" and t[a].value == "this" and self.cls is not None:
                self.p.note_model_prop(self.cls.name, prop, rv,
                                       page_model=self._page_model_cls() or self._webforms_cls())
                return
            base = env.get(str(t[a].value)) if k - a == 3 and t[a].kind == "id" else None
            typ = (base.type if base is not None else "") or (self.types.get(str(t[a].value), "") if k - a == 3 else "")
            if typ:
                self.p.note_model_prop(typ, prop, rv)

    def _property_sink(self, a: int, recv_end: int, prop: str, rv: V, env: dict[str, V]) -> None:
        recv = self.ev(a, recv_end, env)
        desc = self._desc(recv, self.key_of(a, recv_end) or "")
        line = self.t[a].line
        if prop == "ContentType" and recv.tag == "resp":
            self._note_response_header("content-type", rv)  # Response.ContentType = "text/plain"
        if prop in ("Text", "InnerText") and prop == "Text":
            name = str(self.t[recv_end - 1].value)
            ctype = self.p.control_types.get(name, recv.type)
            if ctype in _WEBFORMS_OUTPUTS or name.lower().startswith(("lbl", "lit", "ltl", "label")):
                self.sink("html", f"{name}.Text", line, rv)
            return
        for spec in _CS_PROP_SINKS.get(prop, ()):
            if spec.recv is None or any(r in desc for r in spec.recv):
                self.sink(spec.kind, prop, line, rv)
        if prop == "CommandText" and self.lang == "csharp" and recv_end - a == 1 and self.t[a].kind == "id":
            # 25. tur: cmd = conn.CreateCommand(); cmd.CommandText = "INSERT …/SELECT …": komut nesnesi tabloyu taşır
            # (new SqlCommand("…") ile aynı): Parameters.AddWithValue yazar, ExecuteReader/ExecuteScalar okur.
            text = rv.const if isinstance(rv.const, str) else rv.prefix
            read = self.p.read_table(rv)
            if read:
                rcols = self.p.read_columns(text)
                read += ("|" + ",".join(sorted(rcols))) if rcols else ""
            write = self.p.write_table(text) if text else None
            if read or write:
                env[str(self.t[a].value)] = V(recv.taint, tag="sqlcmd", type=recv.type or "SqlCommand",
                                              prefix=("\x00w:" + write) if write else ("\x00r:" + read))

    def ev(self, a: int, b: int, env: dict[str, V]) -> V:
        a, b = self._strip(a, b)
        if a >= b:
            return CLEAN
        t = self.t
        # Lambda / anonim işlev: değer yok
        if (t[a].kind == "id" and t[a].value.lower() in ("function", "fn") and self.php) or self._is_lambda(a, b):
            if self.lang == "java" and not self.kt:
                self._run_java_lambda_body(a, b, env)
            return CLEAN
        k = self.find_assign(a, b)
        if k is not None and k > a:
            return self.assign(a, k, b, env)
        ops = self._top_ops(a, b)
        if ops:
            # Üçlü
            q = next((x for x in ops if t[x].value == "?" and not self._is_unary(x, a)), None)
            if q is not None:
                colon = self._ternary_colon(q, b)
                if colon is not None:
                    cond = self.ev(a, q, env)
                    tv = self.truth(cond)
                    if colon == q + 1:  # PHP ?:
                        return join(cond, self.ev(colon + 1, b, env))
                    if tv is True:
                        return self.ev(q + 1, colon, env)
                    if tv is False:
                        return self.ev(colon + 1, b, env)
                    gt, gf = self.guards(a, q, env)
                    left = self.ev(q + 1, colon, self.apply_guards(dict(env), gt) if gt else env)
                    right = self.ev(colon + 1, b, self.apply_guards(dict(env), gf) if gf else env)
                    return join(left, right)
            for level in _LEVELS:
                pos = [x for x in ops if t[x].value in level and not self._is_unary(x, a)
                       and not (t[x].value == "." and not self.php)]
                if pos:
                    return self._binary(a, b, pos, level, env)
            asx = next((x for x in ops if t[x].kind == "id" and t[x].value == "as"), None)
            if asx is not None:
                return self.ev(a, asx, env)
        return self.ev_unary(a, b, env)

    def _run_java_lambda_body(self, a: int, b: int, env: dict[str, V]) -> None:
        """18. tur: Java lambda gövdesi (``(conn) -> conn.prepareStatement("…" + id)``, ``x -> { … }``) yakalanan yerel
        değişkenlerle yerinde değerlendirilir; yalnız gövdedeki hedefler için. Lambda parametreleri temizdir, gövdenin
        dönüş değeri çevreleyen yöntemin dönüşüne karışmaz, ortam değişiklikleri dışarı sızmaz."""
        t = self.t
        arrow = next((k for k in range(a, min(b, a + 40)) if t[k].kind == "op" and t[k].value == "->"), None)
        if arrow is None or arrow + 1 >= b or getattr(self, "_lambda_depth", 0) > 3:
            return
        local = dict(env)
        for k in range(a, arrow):
            if t[k].kind == "id":
                local.pop(t[k].value, None)  # lambda parametresi dıştaki aynı adlı değişkeni gölgeler
        saved_ret = self.ret_values
        self.ret_values = []
        self._lambda_depth = getattr(self, "_lambda_depth", 0) + 1
        words = {str(x.value) for x in t[arrow:b] if x.kind == "id"}
        saved_skip = getattr(self, "_skip_path_sink", False)
        if "startsWith" in words and words & {"normalize", "getCanonicalPath", "toRealPath", "toAbsolutePath"}:
            # Doğrulayıcı lambda (Supplier<Boolean> validator = () -> normalize().startsWith(kök)): yolu yalnız
            # karşılaştırmak için kurar, dosyaya erişmez.
            self._skip_path_sink = True
        try:
            start = arrow + 1
            if t[start].kind == "op" and t[start].value == "{" and start in self.pairs:
                self.run(self.parser.block(start + 1, self.pairs[start]), local)
            else:
                self.ev(start, b, local)
        except RecursionError:
            pass
        finally:
            self._lambda_depth -= 1
            self.ret_values = saved_ret
            self._skip_path_sink = saved_skip

    def _is_lambda(self, a: int, b: int) -> bool:
        t = self.t
        if self.lang == "java":
            for k in range(a, min(b, a + 40)):
                if t[k].kind == "op" and t[k].value == "->":
                    return all(x.kind == "id" or (x.kind == "op" and x.value in ("(", ")", ",")) for x in t[a:k])
            return False
        if self.lang == "csharp":
            for k in range(a, min(b, a + 40)):
                if t[k].kind == "op" and t[k].value == "=>":
                    return all(x.kind == "id" or (x.kind == "op" and x.value in ("(", ")", ",")) for x in t[a:k])
        return False

    def _ternary_colon(self, q: int, b: int) -> int | None:
        depth = 0
        k = q + 1
        t = self.t
        while k < b:
            tok = t[k]
            if tok.kind == "op":
                if tok.value in ("(", "[", "{") and k in self.pairs:
                    k = self.pairs[k] + 1
                    continue
                if tok.value == "?":
                    depth += 1
                elif tok.value == ":":
                    if depth == 0:
                        return k
                    depth -= 1
                elif tok.value == "::":
                    pass
            k += 1
        return None

    def _binary(self, a: int, b: int, pos: list[int], level: set[str], env: dict[str, V]) -> V:
        t = self.t
        bounds = [a] + [p + 1 for p in pos]
        ends = pos + [b]
        operands = [(x, y) for x, y in zip(bounds, ends)]
        ops = [t[p].value for p in pos]
        if level is _LEVELS[0]:  # ??
            return join_all(self.ev(x, y, env) for x, y in operands)
        vals = [self.ev(x, y, env) for x, y in operands]
        if level & {"||", "&&"}:
            consts = [self.truth(v) for v in vals]
            if "||" in ops or "or" in ops:
                if any(c is True for c in consts):
                    return V(const=True)
                if all(c is False for c in consts):
                    return V(const=False)
            else:
                if any(c is False for c in consts):
                    return V(const=False)
                if all(c is True for c in consts):
                    return V(const=True)
            return CLEAN
        if level is _EQUALITY or level is _RELATION:
            if len(vals) == 2 and vals[0].const is not _NOC and vals[1].const is not _NOC:
                return V(const=self._compare(vals[0].const, ops[0], vals[1].const))
            return CLEAN
        if "+" in level:
            if "-" in ops or (self.php and "+" in ops and "." not in ops):
                return self._arith(vals, ops)
            if all(isinstance(v.const, (int, float)) and not isinstance(v.const, bool) for v in vals):
                return self._arith(vals, ops)
            return self._concat(vals)
        if level & {"*", "/", "%", "**"}:
            return self._arith(vals, ops)
        return CLEAN

    def _compare(self, x: Any, op: str, y: Any) -> bool | Any:
        try:
            if isinstance(x, str) and len(x) == 1 and isinstance(y, int):
                x = ord(x)
            if isinstance(y, str) and len(y) == 1 and isinstance(x, int):
                y = ord(y)
            if op in ("==", "==="):
                return x == y
            if op in ("!=", "!==", "<>"):
                return x != y
            if op == "<":
                return x < y
            if op == ">":
                return x > y
            if op == "<=":
                return x <= y
            if op == ">=":
                return x >= y
        except TypeError:
            return _NOC
        return _NOC

    def _arith(self, vals: list[V], ops: list[str]) -> V:
        if all(isinstance(v.const, (int, float)) and not isinstance(v.const, bool) for v in vals):
            acc = vals[0].const
            try:
                for op, v in zip(ops, vals[1:]):
                    c = v.const
                    if op == "+":
                        acc = acc + c
                    elif op == "-":
                        acc = acc - c
                    elif op == "*":
                        acc = acc * c
                    elif op == "/":
                        acc = int(acc / c) if isinstance(acc, int) and isinstance(c, int) and not self.php else acc / c
                    elif op == "%":
                        acc = acc % c
                    elif op == "**":
                        acc = acc ** c
                return V(const=acc)
            except (ZeroDivisionError, OverflowError, TypeError):
                return CLEAN
        if self.php or "-" in ops or "*" in ops or "/" in ops:
            return CLEAN
        return CLEAN

    def _concat(self, vals: list[V]) -> V:
        """Dize birleştirme: sabit katlama, önek, SQL kaçışının tırnak bağlamına göre değerlendirilmesi."""
        text_parts: list[str] = []
        taint: set[T] = set()
        all_const = True
        prefix = None
        for n, v in enumerate(vals):
            if n == 0:
                prefix = v.const if isinstance(v.const, str) else v.prefix
            if v.const is not _NOC and v.const is not _NULL:
                if isinstance(v.const, bool):
                    text_parts.append("true" if v.const else "false")
                elif isinstance(v.const, (str, int, float)):
                    text_parts.append(str(v.const))
                continue
            all_const = False
            if v.taint:
                quoted = self._in_quotes("".join(text_parts))
                for tt in v.taint:
                    if "sql?" in tt.safe:
                        safe = (tt.safe - {"sql?"}) | ({"sql"} if quoted else set())
                        taint.add(T(tt.src, frozenset(safe)))
                    else:
                        taint.add(tt)
            text_parts.append("\x00")
        if all_const:
            return V(const="".join(text_parts))
        if not prefix:
            # "$tabanUrl/$yol", Sinif::$URL . "?id=" . $x: istekten gelmeyen (yapılandırma/sabit) taban + "/", "?" ya da
            # "#" ile başlayan sabit → ana makine sabit; kullanıcı yalnız yolu/sorguyu belirler (19. tur: tüm diller;
            # önceden yalnız Kotlin).
            rest = [v for v in vals if not (isinstance(v.const, str) and v.const == "")]
            if len(rest) >= 2 and all(t.src.label == "param" for t in rest[0].taint) and rest[0].const is _NOC \
                    and isinstance(rest[1].const, str) \
                    and rest[1].const[:1] in ("/", "?", "#") and not rest[1].const.startswith("//"):
                prefix = "<site-url>" + rest[1].const
        return V(frozenset(taint), prefix=prefix if isinstance(prefix, str) else None)

    def _pure_value(self, a: int, b: int, env: dict[str, V]) -> V | None:
        """Yan etkisiz (hedef adı içermeyen) kısa zincirin değeri; koşullardaki ``uri.getHost()`` gibi ifadeler için."""
        if b - a > 24:
            return None
        names = {str(tok.value) for tok in self.t[a:b] if tok.kind == "id"}
        if not names & {"getHost", "getAuthority", "Host", "parse_url", "host", "getRawAuthority"}:
            return None
        return self.ev(a, b, dict(env))

    def _prefix_call(self, a: int, b: int) -> tuple[str] | None:
        """``strpos($x, '/')`` (=== 0 ile önek denetimi) — yalnız koşulda '//' da dışlanıyorsa."""
        a, b = self._strip(a, b)
        t = self.t
        if not getattr(self, "_cond_dslash", False) or b - a < 4 or t[a].kind != "id" \
                or str(t[a].value).lower() not in ("strpos", "stripos", "mb_strpos") or (a + 1) not in self.pairs:
            return None
        args = lex.split_top(t, self.pairs, a + 2, self.pairs[a + 1], ",")
        if len(args) < 2:
            return None
        nv = self.ev(args[1][0], args[1][1], {})
        key = self.key_of(*args[0])
        return (key,) if nv.const == "/" and key else None

    def _closure_return_call(self, a: int, b: int) -> str | None:
        """Tek deyimli PHP kapanışının döndürdüğü çağrının adı: ``function($v) { return f(…); }`` / ``fn($v) => f(…)``."""
        t = self.t
        if a >= b or t[a].kind != "id" or t[a].value.lower() not in ("function", "fn", "static"):
            return None
        for k in range(a, b - 1):
            tok = t[k]
            if (tok.kind == "id" and tok.value.lower() == "return") or (tok.kind == "op" and tok.value == "=>"):
                n = k + 1
                if n < b and t[n].kind == "op" and t[n].value == "(" and n + 1 < b and t[n + 1].kind == "id":
                    return "intval" if t[n + 1].value.lower() in ("int", "integer") else None  # (int) $v
                if n + 1 < b and t[n].kind == "id" and t[n + 1].kind == "op" and t[n + 1].value == "(":
                    return t[n].value.lower()
                return None
        return None

    _SPRINTF_SPEC = re.compile(r"%(?:(\d+)\$)?[-+ 0]*(?:'.)?\d*(?:\.\d+)?([bcdeEfFgGosuxX%])")

    def _php_sprintf(self, fmt: str, args: list[V]) -> V:
        """PHP sprintf: sayısal belirteçlerin (%d, %u, %f, %x …) argümanları temizdir; %s argümanı taint'ini taşır ve
        SQL kaçışı ("sql?") biçim dizgesinde tırnak içindeyse geçerli olur (17. tur)."""
        taint: set[T] = set()
        seq = 0
        for m in self._SPRINTF_SPEC.finditer(fmt):
            conv = m.group(2)
            if conv == "%":
                continue
            if m.group(1):
                idx = int(m.group(1))
            else:
                seq += 1
                idx = seq
            if idx >= len(args) or conv != "s":
                continue  # sayısal/karakter belirteçleri değeri sayıya çevirir
            quoted = self._in_quotes(fmt[:m.start()].replace("%%", ""))
            for tt in args[idx].taint:
                if "sql?" in tt.safe:
                    taint.add(T(tt.src, frozenset((tt.safe - {"sql?"}) | ({"sql"} if quoted else set()))))
                else:
                    taint.add(tt)
        return V(frozenset(taint), prefix=fmt.split("%")[0])

    @staticmethod
    def _in_quotes(text: str) -> bool:
        single = double = False
        escaped = False
        for ch in text:
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
            elif ch == "'" and not double:
                single = not single
            elif ch == '"' and not single:
                double = not double
        return single or double

    def ev_unary(self, a: int, b: int, env: dict[str, V]) -> V:
        t = self.t
        tok = t[a]
        if tok.kind == "op":
            v = tok.value
            if v == "!":
                inner = self.ev_unary(a + 1, b, env)
                return V(const=not inner.const) if isinstance(inner.const, bool) else CLEAN
            if v in ("-", "+", "~"):
                inner = self.ev_unary(a + 1, b, env)
                if isinstance(inner.const, (int, float)) and not isinstance(inner.const, bool):
                    return V(const=-inner.const if v == "-" else inner.const)
                return CLEAN
            if v in ("++", "--", "@", "&", "*"):
                return self.ev_unary(a + 1, b, env)
            if v == "(" and a in self.pairs:
                c = self.pairs[a]
                if c + 1 < b and self._is_cast(a + 1, c):
                    inner = self.ev_unary(c + 1, b, env)
                    return self._cast(a + 1, c, inner)
        if tok.kind == "id" and a + 1 < b and (
                (self.lang == "csharp" and tok.value in ("await", "checked", "unchecked", "ref", "out", "in", "params"))
                or (self.php and tok.value.lower() in ("clone", "yield", "await"))):
            return self.ev_unary(a + 1, b, env)
        v, k = self.chain(a, b, env)
        if k < b:
            rest = self.ev(k, b, env)
            return V(v.taint | rest.taint) if (v.taint or rest.taint) else CLEAN
        return v

    def _is_cast(self, a: int, c: int) -> bool:
        t = self.t
        if a >= c:
            return False
        inside = t[a:c]
        if not all(x.kind == "id" or (x.kind == "op" and x.value in (".", "<", ">", ",", "[", "]", "?")) for x in inside):
            return False
        if self.php:
            return len(inside) == 1 and inside[0].value.lower() in ("int", "integer", "float", "double", "bool",
                                                                       "boolean", "string", "array", "object")
        first = inside[0].value
        last_id = [x.value for x in inside if x.kind == "id"][-1]
        nxt = t[c + 1]
        if nxt.kind == "op" and nxt.value not in ("(", "!", "~", "@"):
            return False  # ardından ikili işleç: parantezli ifade
        if first in _PRIMITIVES or last_id in _PRIMITIVES:
            return True
        return last_id[:1].isupper() and (len(inside) == 1 or t[a + 1].kind == "op")

    def _cast(self, a: int, c: int, inner: V) -> V:
        names = [x.value.lower() for x in self.t[a:c] if x.kind == "id"]
        target = names[-1] if names else ""
        if target in _PRIMITIVES or target in ("int", "integer", "float", "double", "bool", "boolean") or target in _NUMERIC_CLASSES:
            if isinstance(inner.const, (int, float)) and not isinstance(inner.const, bool):
                return V(const=int(inner.const) if target in ("int", "integer", "long", "short") else inner.const)
            return CLEAN
        return replace(inner, type=lex._simple_type(self.t[c - 1].value) if self.t[c - 1].kind == "id" else inner.type)

    # -- birincil + sonek zinciri ------------------------------------------
    def chain(self, a: int, b: int, env: dict[str, V]) -> tuple[V, int]:
        t = self.t
        tok = t[a]
        k = a + 1
        names: list[str] = []
        v = CLEAN
        static_cls = ""
        if tok.kind == "str":
            v = V(const=tok.value)
        elif tok.kind == "istr":
            v = self._interp_string(tok, env)
        elif tok.kind == "bstr":
            v = self._interp_string(tok, env)
            self.sink("command", "ters tırnak komutu", tok.line, v)
            v = CLEAN
        elif tok.kind == "num":
            v = V(const=self._num(tok.value))
        elif tok.kind == "var":
            name = tok.value
            names.append(name.lower())
            if name in _SUPERGLOBAL_SRC or name == "$_SERVER":
                v = V(tag="sg", const=name)
            elif name in ("$_SESSION", "$_ENV", "$GLOBALS"):
                v = V(tag="sg_other")
            elif name == "$this":
                v = V(tag="this")
            else:
                v = env.get(name, CLEAN)
        elif tok.kind == "op":
            if tok.value == "(" and a in self.pairs:
                c = self.pairs[a]
                v = self.ev(a + 1, c, env)
                k = c + 1
            elif tok.value in ("[", "{") and a in self.pairs:
                c = self.pairs[a]
                v = self._array_literal(a + 1, c, env)
                k = c + 1
            elif tok.value == "$":
                return CLEAN, b
            else:
                return CLEAN, a + 1
        elif tok.kind == "id":
            word = tok.value
            low = word.lower()
            if low in ("true", "false"):
                v = V(const=(low == "true"))
            elif low in ("null", "nil", "none"):
                v = V(const=_NULL)
            elif word == "new" and a + 1 < b:
                v, k = self._new(a, b, env)
                names.append((v.type or "new").lower())
            elif low in ("typeof", "sizeof", "nameof", "default", "isset", "empty", "unset") and \
                    k < b and t[k].kind == "op" and t[k].value == "(" and k in self.pairs:
                inner = self.ev(k + 1, self.pairs[k], env) if low == "unset" else CLEAN
                del inner
                return CLEAN, self.pairs[k] + 1
            elif self.php and low == "array" and k < b and t[k].kind == "op" and t[k].value == "(" and k in self.pairs:
                c = self.pairs[k]
                v = self._array_literal(k + 1, c, env)
                k = c + 1
            elif self.php and low in ("print", "echo"):
                v = self.ev(a + 1, b, env)
                self.sink("html", "print", tok.line, v)
                return CLEAN, b
            elif self.php and low in ("include", "require", "include_once", "require_once"):
                v = self.ev(a + 1, b, env)
                self.sink("path", "include/require", tok.line, v)
                return CLEAN, b
            elif self.php and low in ("exit", "die"):
                if k < b and t[k].kind == "op" and t[k].value == "(" and k in self.pairs:
                    v = self.ev(k + 1, self.pairs[k], env)
                    self.sink("html", "exit/die çıktısı", tok.line, v)
                    return CLEAN, self.pairs[k] + 1
                return CLEAN, k
            elif word in ("this", "base", "super"):
                v = V(tag="this")
                names.append("this")
            elif k < b and t[k].kind == "op" and t[k].value == "(" and k in self.pairs:
                # Alıcısız çağrı
                c = self.pairs[k]
                args, ranges = self._args(k + 1, c, env)
                v = self.call(None, [], word, args, ranges, tok.line, env, a)
                names.append(word.lower() + "()")
                k = c + 1
            else:
                v = self._ident(word, a, b, env)
                names.append(low)
                if v.tag == "class":
                    static_cls = word
        else:
            return CLEAN, a + 1
        # sonekler
        while k < b:
            tok = t[k]
            if tok.kind != "op":
                break
            op = tok.value
            if op in (".", "?.", "->", "?->", "::") and k + 1 < b and t[k + 1].kind in ("id", "var"):
                if op == "." and self.php:
                    break
                member = t[k + 1].value
                m = k + 2
                if m < b and t[m].kind == "op" and t[m].value == "<" and not self.php:
                    g = self._generic_end(m, b)
                    if g and g < b and t[g].kind == "op" and t[g].value == "(":
                        m = g
                if m < b and t[m].kind == "op" and t[m].value == "(" and m in self.pairs:
                    c = self.pairs[m]
                    args, ranges = self._args(m + 1, c, env)
                    v = self.call(v, names, member, args, ranges, t[k + 1].line, env, a, static_cls=static_cls)
                    names.append(member.lower() + "()")
                    static_cls = ""
                    k = c + 1
                    continue
                v = self.member(v, names, member, t[k + 1].line, env)
                names.append(member.lower())
                if v.tag == "class":
                    static_cls = member
                k = m
                continue
            if op == "[" and k in self.pairs:
                c = self.pairs[k]
                key_text = self.key_of(a, c + 1)
                if key_text is not None and key_text in env:
                    v = env[key_text]
                    k = c + 1
                    names.append("[]")
                    continue
                idx = self.ev(k + 1, c, env)
                sg_all = env.get("\x00sgall:" + v.const) if (self.php and v.tag == "sg" and isinstance(v.const, str)) else None
                v = self.index(v, idx, tok.line)
                if sg_all is not None:
                    if not sg_all.taint:
                        v = CLEAN
                    else:
                        common = frozenset.intersection(*(tt.safe for tt in sg_all.taint))
                        v = with_safe(V(v.taint, v.tag), common) if common else v
                names.append("[]")
                k = c + 1
                continue
            if op == "(" and k in self.pairs:
                c = self.pairs[k]
                args, _r = self._args(k + 1, c, env)
                v = V(v.taint | frozenset().union(*(x.taint for x in args))) if (v.taint or any(x.taint for x in args)) else CLEAN
                k = c + 1
                continue
            if op in ("++", "--", "!"):
                k += 1
                continue
            break
        return v, k

    def _num(self, text: str) -> Any:
        s = text.replace("_", "").rstrip("lLfFdDmMuU")
        try:
            if s.lower().startswith("0x"):
                return int(s, 16)
            if "." in s or "e" in s.lower():
                return float(s)
            return int(s)
        except ValueError:
            return _NOC

    def _interp_string(self, tok: Tok, env: dict[str, V]) -> V:
        vals = []
        for part in tok.value:
            if isinstance(part, str):
                vals.append(V(const=part))
            else:
                vals.append(self._eval_tokens(part, env) if part else CLEAN)
        return self._concat(vals) if vals else V(const="")

    def _array_literal(self, a: int, b: int, env: dict[str, V]) -> V:
        items: list[V] = []
        keys: list[tuple[Any, V]] = []
        keyed = False
        for x, y in lex.split_top(self.t, self.pairs, a, b, ","):
            arrow = next((m for m in range(x, y) if self.t[m].kind == "op" and self.t[m].value == "=>"), None)
            if arrow is not None and self.php:
                kv = self.ev(x, arrow, env)
                vv = self.ev(arrow + 1, y, env)
                keyed = True
                keys.append((kv.const, vv))
                items.append(vv)
            else:
                items.append(self.ev(x, y, env))
        taint = frozenset().union(*(i.taint for i in items)) if items else frozenset()
        if keyed:
            return V(taint, keys=tuple(keys) if all(k is not _NOC for k, _ in keys) else None)
        return V(taint, items=tuple(items))

    def _args(self, a: int, b: int, env: dict[str, V]) -> tuple[list[V], list[tuple[int, int]]]:
        vals: list[V] = []
        ranges: list[tuple[int, int]] = []
        t = self.t
        for x, y in lex.split_top(t, self.pairs, a, b, ","):
            # Adlandırılmış argüman: ad: ifade
            if y - x >= 3 and t[x].kind == "id" and t[x + 1].kind == "op" and t[x + 1].value == ":":
                x += 2
            if y - x >= 2 and t[x].kind == "id" and t[x].value in ("out", "ref", "in") and self.lang == "csharp":
                names = [tok for tok in t[x + 1:y] if tok.kind == "id" and tok.value != "var"]
                if t[x].value == "out" and names:
                    env[names[-1].value] = CLEAN
                    vals.append(CLEAN)
                    ranges.append((x, y))
                    continue
                x += 1
            if y - x >= 1 and t[x].kind == "op" and t[x].value == "...":
                x += 1
            vals.append(self.ev(x, y, env))
            ranges.append((x, y))
        return vals, ranges

    def _ident(self, word: str, a: int, b: int, env: dict[str, V]) -> V:
        if word in env:
            return env[word]
        t = self.t
        if self.u.aspx and self.cls is not None:
            stored = self.p.model_props.get((self.cls.name, word))
            if stored:
                return V(stored)  # WebForms işaretlemesi: arka kodda istek verisi yazılan sayfa alanı/özelliği
        if self.lang == "java" and self.cls is not None and word in self.p.struts_fields.get(self.cls.name, ()):
            return self._src(f"Struts2 eylem alanı {word} (istek parametresi)", t[a].line)
        if self.lang == "csharp":
            if self._binds_props() and word[:1].isupper():
                line = self.p.bound_prop(self.cls.name, word)
                if line is not None:
                    return self._src(f"{word} özelliği (model bağlama)", t[a].line)
            if self.u.razor and word == "Model":
                key = self._view_key()
                taint = self.p.view_model_taint(key[0], key[1], self.u.view_model) if key else frozenset()
                return V(taint, tag="viewmodel", type=self.u.view_model)
        if self.cls is not None and word in self.cls.consts:
            return V(const=self.cls.consts[word], type="String")  # 18. tur: sabit dize alanı
        if self.cls is not None and word in self.cls.fields:
            typ = self.cls.fields[word]
            if typ in _WEBFORMS_INPUTS or typ in _WEBFORMS_OUTPUTS:
                return V(tag="control", type=typ)
            return V(tag=_TYPE_TAGS.get(typ), type=typ)
        if self.lang == "csharp":
            if word in self.p.control_types:
                return V(tag="control", type=self.p.control_types[word])
            special = {"Request": "req", "Response": "resp", "Session": "session", "HttpContext": "httpctx",
                       "Context": "httpctx", "Server": "server", "ViewBag": "viewbag", "ViewData": "viewbag",
                       "TempData": "viewbag", "Html": "html"}
            if word in special:
                return V(tag=special[word])
        if self.lang == "java" and word in ("request", "req", "httpRequest", "servletRequest") and \
                "HttpServletRequest" in self.u.text_flags:
            return V(tag="req")
        nxt_dot = a + 1 < b and t[a + 1].kind == "op" and t[a + 1].value in (".", "::")
        if word[:1].isupper() or (nxt_dot and not self.php):
            return V(tag="class", type=word)
        if self.php and nxt_dot:
            return V(tag="class", type=word)
        return CLEAN

    def _page_model_cls(self) -> bool:
        """Razor Pages modeli (PageModel) ya da Blazor bileşeni: özellikleri görünümde Model.X / X olarak okunur."""
        if self.cls is None:
            return False
        cache = self.p.__dict__.setdefault("_page_cls", {})
        if self.cls.name not in cache:
            cache[self.cls.name] = self.p._extends(self.cls.name, frozenset({"PageModel", "ComponentBase",
                                                                            "LayoutComponentBase"}))
        return cache[self.cls.name]

    def _webforms_cls(self) -> bool:
        """WebForms sayfası/denetimi/ana sayfası (arka kod sınıfı): alanları .aspx işaretlemesinde okunur."""
        if self.cls is None or self.lang != "csharp" or not self.p.has_razor:
            return False
        cache = self.p.__dict__.setdefault("_webforms_cls", {})
        if self.cls.name not in cache:
            cache[self.cls.name] = self.p._extends(self.cls.name, frozenset({"Page", "UserControl", "MasterPage"}))
        return cache[self.cls.name]

    def _binds_props(self) -> bool:
        """Bu yöntemde bağlı özellikler ([BindProperty], [SupplyParameterFromQuery]) istek verisi mi? Uç noktalar ve
        Blazor bileşenlerinin tüm yöntemleri (yaşam döngüsü/olay işleyicileri: özellik URL'den doldurulur)."""
        if self.cls is None:
            return False
        if self.endpoint or self.u.razor:
            return True
        cache = self.p.__dict__.setdefault("_component_cls", {})
        if self.cls.name not in cache:
            cache[self.cls.name] = self.p._extends(self.cls.name, frozenset({"ComponentBase", "LayoutComponentBase",
                                                                            "OwningComponentBase"}))
        return cache[self.cls.name]

    def _view_key(self) -> tuple[str, str] | None:
        """Razor görünümünün (denetleyici, görünüm) anahtarı: Views/Home/Index.cshtml → ("home", "index")."""
        parts = self.u.path.replace("\\", "/").split("/")
        if len(parts) < 2:
            return None
        return parts[-2].lower(), parts[-1].rsplit(".", 1)[0].lower()

    def _razor_member(self, recv: V, member: str, line: int) -> V | None:
        """Razor görünümünde Model.P / ViewBag.P ve tür bilinmeyen öğelerin (foreach) P özelliği."""
        if recv.tag == "viewbag":
            return V(self.p.viewbag_taint.get(member.lower(), frozenset()))
        if recv.tag == "viewmodel":
            typ = recv.type or ""
            if typ and self.p.bound_prop(typ, member) is not None:
                return self._src(f"Model.{member} (model bağlama)", line)
            # Aynı eylemin View(model) değeri (bütün nesne) + (tür, özellik) yazmaları
            return V(recv.taint | self.p.model_props.get((typ, member), frozenset()), tag="viewmodel_elem")
        if recv.tag in ("viewmodel_elem", None) and member[:1].isupper():
            found = self.p.model_props_by_name.get(member)
            if found:
                return V(recv.taint | found, tag="viewmodel_elem")
            return V(recv.taint, tag="viewmodel_elem") if recv.tag == "viewmodel_elem" or recv.taint else None
        return None

    def _desc(self, recv: V | None, names_text: str) -> str:
        parts = [names_text.lower()]
        if recv is not None:
            if recv.tag:
                parts.append(recv.tag)
                if recv.tag == "class" and recv.type:
                    parts.append("class:" + recv.type.lower())
            if recv.type:
                parts.append(recv.type.lower())
        return " ".join(parts)

    def member(self, recv: V, names: list[str], member: str, line: int, env: dict[str, V]) -> V:
        tag = recv.tag
        if self.lang == "java" and recv.type and recv.taint and recv.type in self.p.proto:
            pv = self._proto_field(recv, member)
            if pv is not None:
                return pv
        if self.kt:
            kv = self._kotlin_member(recv, names, member, line, env)
            if kv is not None:
                return kv
        if tag == "class":
            if member[:1].isupper() or self.lang == "java" and member.islower():
                if self.lang == "csharp" and member == "Request" and recv.type:
                    return V(tag="req")
                return V(tag="class", type=member)
        if self.lang == "csharp":
            if tag and tag.startswith("ds_"):
                level, _, table = tag.partition("\x00")
                nxt = {("ds_set", "Tables"): "ds_tables", ("ds_table", "Rows"): "ds_rows",
                       ("ds_table", "DefaultView"): "ds_rows", ("ds_tables", "Rows"): "ds_rows"}.get((level, member))
                if nxt:
                    return V(tag=f"{nxt}\x00{table}")
                if level == "ds_row" and member == "ItemArray":
                    return self._ds_read(tag)
                return CLEAN
            if self.u.razor:
                rv = self._razor_member(recv, member, line)
                if rv is not None:
                    return rv
            if tag == "sqlcmd" and member == "Parameters":
                return V(tag="sqlparams", prefix=recv.prefix)
            elif tag == "viewbag" or (tag == "this" and self._binds_props()
                                      and self.p.bound_prop(self.cls.name, member) is not None):
                if tag == "this":
                    return self._src(f"{member} özelliği (model bağlama)", line)
            if member == "Request":
                return V(tag="req")
            if member == "Response":
                return V(tag="resp")
            if member == "Session":
                return V(tag="session")
            if tag == "req" and member == "PathBase":
                return CLEAN  # UsePathBase ile yapılandırılmış önek (eşleşmezse boş): istemcinin serbest girdisi değil
            if tag == "req" and member in _REQ_CS_MEMBERS:
                return self._src(f"Request.{member}", line)
            if tag == "control" and member in ("Text", "Value", "SelectedValue", "FileName", "PostedFile",
                                               "SelectedItem", "InnerText", "Items") and recv.type in _WEBFORMS_INPUTS:
                return self._src(f"{names[-1] if names else 'denetim'}.{member}", line)
        if self.php and tag == "req" and member in ("query", "request", "cookies", "headers", "files", "attributes",
                                                    "server", "json"):
            return V(tag="reqbag")
        if self.php and tag == "this" and env is not None:
            key = "$this->" + member
            if key in env:
                return env[key]
        if self.php and tag == "this" and self._php_controller():
            if member == "request":
                return V(tag="req")  # CodeIgniter 4 / Laravel denetleyicisinde $this->request
            if member == "input":
                return V(tag="ci_input")  # CodeIgniter 3 giriş nesnesi
        if self.lang == "java" and tag == "this" and env is not None and ("this." + member) in env:
            return env["this." + member]
        if self.lang == "java" and tag == "this" and self.cls is not None \
                and member in self.p.struts_fields.get(self.cls.name, ()):
            return self._src(f"Struts2 eylem alanı {member} (istek parametresi)", line)
        if member in ("length", "Length", "Count", "size"):
            return CLEAN
        if recv.keys is not None:
            for kk, vv in recv.keys:
                if kk == member:
                    return vv
        return V(recv.taint) if recv.taint else (V(tag=tag) if tag in ("req", "resp", "session") else CLEAN)

    def index(self, v: V, idx: V, line: int) -> V:
        if self.lang == "csharp" and v.tag == "dbresult":
            return self._stored_read(v, "[]", line)  # reader["kolon"] / reader[1]
        if self.lang == "csharp" and v.tag and v.tag.startswith("ds_"):
            level, _, table = v.tag.partition("\x00")
            if level == "ds_row":
                return self._ds_read(v.tag)  # row["kolon"] / row[1]: kayıtlı veri
            nxt = {"ds_tables": "ds_table", "ds_set": "ds_table", "ds_rows": "ds_row", "ds_table": "ds_row"}[level]
            return V(tag=f"{nxt}\x00{table}")
        if self.lang == "csharp" and v.tag == "viewbag":
            if self.u.razor and isinstance(idx.const, str):
                return V(self.p.viewbag_taint.get(idx.const.lower(), frozenset()))
            return CLEAN
        if v.tag == "sg":
            name = v.const
            if name == "$_SERVER":
                if isinstance(idx.const, str) and _SERVER_SRC.match(idx.const):
                    src = self._src(f"$_SERVER['{idx.const}']", line)
                    if idx.const.upper() in ("REQUEST_URI", "PHP_SELF", "SCRIPT_NAME", "PATH_INFO", "QUERY_STRING",
                                             "ORIG_PATH_INFO", "REDIRECT_URL", "PATH_TRANSLATED", "HTTP_HOST",
                                             "SERVER_NAME", "HTTP_REFERER", "HTTP_X_FORWARDED_HOST"):
                        # İstemcinin kendi isteğinin yolu/ana makinesi: başka kullanıcıyı yabancı siteye yönlendiremez
                        return with_safe(src, ("redirect", "ssrf", "ssrf_partial"))
                    return src
                return CLEAN if isinstance(idx.const, str) else self._src("$_SERVER[…]", line)
            key = idx.const if isinstance(idx.const, str) else "…"
            if name == "$_FILES":
                return V(self._src(f"$_FILES['{key}']", line).taint, tag="files")
            return self._src(f"{name}['{key}']", line)
        if v.tag and v.tag.startswith("urlof:") and isinstance(idx.const, str):
            return V(v.taint, tag="hostof:" + v.tag[6:]) if idx.const == "host" else V(v.taint)
        if v.tag == "files":
            if isinstance(idx.const, str) and idx.const in ("tmp_name", "size", "error"):
                return CLEAN
            return v
        if v.tag == "sg_other":
            if isinstance(idx.const, str):
                stored = self.p.session_taint.get(f"$_SESSION['{idx.const}']")
                if stored:
                    return V(stored)
            return CLEAN
        if v.tag in ("req", "reqsrc") and (self.lang == "csharp" or self.php):
            key = idx.const if isinstance(idx.const, str) else "…"
            return self._src(f"Request[{key}]" if self.lang == "csharp" else f"$request['{key}']", line)
        if v.items is not None and isinstance(idx.const, int) and not isinstance(idx.const, bool):
            if 0 <= idx.const < len(v.items):
                return v.items[idx.const]
            return CLEAN
        if v.keys is not None and idx.const is not _NOC:
            for kk, vv in v.keys:
                if kk == idx.const:
                    return vv
            return CLEAN
        if isinstance(v.const, str) and isinstance(idx.const, int):
            return V(const=v.const[idx.const]) if 0 <= idx.const < len(v.const) else CLEAN
        return V(v.taint) if v.taint else CLEAN

    def elem_of(self, v: V) -> V:
        if v.tag and v.tag.startswith(("ds_rows\x00", "ds_tables\x00", "ds_table\x00")):
            level, _, table = v.tag.partition("\x00")
            return V(tag=f"{'ds_table' if level == 'ds_tables' else 'ds_row'}\x00{table}")
        if v.tag in ("viewmodel", "viewmodel_elem"):
            return V(v.taint, tag="viewmodel", type=v.type) if v.tag == "viewmodel" else V(v.taint, tag="viewmodel_elem")
        if v.tag == "sg":
            return self._src(f"{v.const}[…]", 0)
        if v.items is not None:
            return join_all(v.items) if v.items else CLEAN
        if v.keys is not None:
            return join_all(vv for _k, vv in v.keys) if v.keys else CLEAN
        return V(v.taint, tag=("cookie" if v.tag == "cookies" else None)) if v.taint else CLEAN

    # -- new ---------------------------------------------------------------
    def _new(self, a: int, b: int, env: dict[str, V]) -> tuple[V, int]:
        t = self.t
        k = a + 1
        names = []
        while k < b and (t[k].kind == "id" or (t[k].kind == "op" and t[k].value in (".", "::", "\\"))):
            if t[k].kind == "id":
                names.append(t[k].value)
            k += 1
        if k < b and t[k].kind == "op" and t[k].value == "<":
            g = self._generic_end(k, b)
            if g:
                k = g
        typ = lex._simple_type(names[-1]) if names else ""
        args: list[V] = []
        ranges: list[tuple[int, int]] = []
        line = t[a].line
        if k < b and t[k].kind == "op" and t[k].value == "[" and k in self.pairs:
            while k < b and t[k].kind == "op" and t[k].value == "[" and k in self.pairs:
                k = self.pairs[k] + 1
            if k < b and t[k].kind == "op" and t[k].value == "{" and k in self.pairs:
                v = self._array_literal(k + 1, self.pairs[k], env)
                return v, self.pairs[k] + 1
            return V(items=None), k
        if k < b and t[k].kind == "op" and t[k].value == "(" and k in self.pairs:
            c = self.pairs[k]
            args, ranges = self._args(k + 1, c, env)
            k = c + 1
        # 17. tur: new File(x).getName() yalnız dosya adını çıkarır (dosyaya erişmez; taban ad = yol arındırıcısı)
        name_only = typ == "File" and k + 2 < b and t[k].kind == "op" and t[k].value == "." \
            and t[k + 1].kind == "id" and t[k + 1].value == "getName"
        if typ == "File" and not name_only:
            # 18. tur: (new File(x)).getName() — parantezli biçim
            j = k
            while j < len(t) and j < k + 3 and t[j].kind == "op" and t[j].value == ")":
                j += 1
            name_only = j > k and j + 1 < len(t) and t[j].kind == "op" and t[j].value == "." \
                and t[j + 1].kind == "id" and t[j + 1].value == "getName"
        if name_only:
            self._skip_path_sink = True
        try:
            v = self.construct(typ, args, ranges, line, env)
        finally:
            self._skip_path_sink = False
        if typ in ("URI", "URL", "Uri") and v.tag is None and ranges and args and args[0].taint:
            ukey = self.key_of(*ranges[0])
            if ukey:
                v = replace(v, tag="urlof:" + ukey)  # 17. tur: ana makine denetimi için kaynak değişken izi
        if k < b and t[k].kind == "op" and t[k].value == "{" and k in self.pairs:
            c = self.pairs[k]
            if self.lang == "csharp":
                inits = []
                props: dict[str, tuple[V, int]] = {}
                for x, y in lex.split_top(t, self.pairs, k + 1, c, ","):
                    eq = next((m for m in range(x, y) if t[m].kind == "op" and t[m].value == "="), None)
                    if eq is not None and eq - x == 1 and t[x].kind == "id":
                        pv = self.ev(eq + 1, y, env)
                        props[t[x].value] = (pv, t[x].line)
                        if pv.taint and typ and not self.u.razor:
                            if self.privileged:
                                self.p.privileged_model_writes += 1
                            else:
                                self.p.note_model_prop(typ, str(t[x].value), pv)
                        for spec in _CS_PROP_SINKS.get(t[x].value, ()):
                            if spec.recv is None or any(r in typ.lower() for r in spec.recv):
                                self.sink(spec.kind, f"{typ}.{t[x].value}", t[x].line, pv)
                        inits.append(pv)
                    else:
                        inits.append(self.ev(x, y, env))
                if typ == "ContentResult" and "Content" in props and "ContentType" in props:
                    # new ContentResult { Content = x, ContentType = "text/html" }: gövde HTML olarak döner
                    ctype = props["ContentType"][0].const
                    if isinstance(ctype, str) and "html" in ctype.lower():
                        self.sink("html", "ContentResult (text/html)", props["Content"][1], props["Content"][0])
                if inits:
                    v = replace(v, taint=v.taint | frozenset().union(*(i.taint for i in inits)),
                                items=tuple(inits) if v.items is not None else v.items)
            elif self.lang == "java":
                # Anonim sınıf (new T() { … }): gövdedeki yöntemler bu dosyanın yöntemleri olarak çıkarıldı; örnek
                # üzerindeki çağrılar (new ClassLoader(){…}.x(b)) onlara çözülsün diye tür kütüphane türü sayılmaz.
                v = replace(v, type="")
            k = c + 1
        return v, k

    def _newtonsoft_typenames(self, ranges: list[tuple[int, int]]) -> bool | None:
        """DeserializeObject argümanlarında satır içi TypeNameHandling: güvensiz (All/Auto/Objects/Arrays) → True,
        None → False; ayar nesnesi değişkenle verildiyse/ayar yoksa None (dosya düzeyi bayrak)."""
        has_settings_var = False
        for a, b in ranges[1:]:
            ids = [str(x.value) for x in self.t[a:b] if x.kind == "id"]
            if "TypeNameHandling" in ids:
                k = len(ids) - 1 - ids[::-1].index("TypeNameHandling")
                val = ids[k + 1] if k + 1 < len(ids) else ""
                return val in ("All", "Auto", "Objects", "Arrays")
            if b - a == 1 and self.t[a].kind == "id" and not self.t[a].value[:1].isupper():
                has_settings_var = True
        return None if has_settings_var else False

    def _cs_stream_arg(self, a: int, b: int) -> bool:
        """Argüman bir akış mı (…Body, …InputStream, …Stream, OpenReadStream(), türü *Stream olan değişken)?"""
        toks = [x for x in self.t[a:b] if x.kind == "id"]
        if not toks:
            return False
        last = str(toks[-1].value)
        if last in ("Body", "InputStream", "BaseStream", "OpenReadStream", "GetStream", "ReadAsStreamAsync") \
                or last.endswith("Stream"):
            return True
        return b - a == 1 and self.types.get(last, "").endswith("Stream")

    def construct(self, typ: str, args: list[V], ranges: list[tuple[int, int]], line: int, env: dict[str, V]) -> V:
        lang = self.lang
        table = _JAVA_CTOR_SINKS if lang == "java" else _CS_CTOR_SINKS if lang == "csharp" else {}
        for spec in table.get(typ, ()):
            if lang == "csharp" and typ in ("StreamReader", "StreamWriter") and ranges and self._cs_stream_arg(*ranges[0]):
                continue  # new StreamReader(Request.Body / akış): dosya yolu değil
            self._check_args(spec, f"new {typ}", args, line)
        union = frozenset().union(*(x.taint for x in args)) if args else frozenset()
        if (lang == "java" and typ in ("FileReader", "FileInputStream", "RandomAccessFile")) or (
                lang == "csharp" and typ == "StreamReader" and args and ranges and not self._cs_stream_arg(*ranges[0])):
            # Dosya okuyucusu: yol istekten gelse de okunan içerik saldırganın HTML'i değildir (W2-XSS; yol hedefi
            # yukarıda denetlendi). new StreamReader(Request.Body) istek gövdesidir, olduğu gibi kalır.
            return with_safe(V(union, type=typ), ("html",))
        if lang == "java" and typ == "ModelAndView" and args and (args[0].prefix or "").lower().startswith("redirect:"):
            self.sink("redirect", "new ModelAndView(\"redirect:…\")", line, args[0])
        elif self.kt and typ == "ModelAndView" and args and not args[0].prefix:
            # Görünüm adı istekten: Thymeleaf/Freemarker şablon adı enjeksiyonu (görünüm ifadesi değerlendirilir)
            self.sink("ssti", "ModelAndView(görünüm adı)", line, args[0])
        if self.php and typ in ("SplFileObject", "SplFileInfo") and args:
            self.sink("path", f"new {typ}", line, args[0])
        if self.php and typ in ("Twig_Loader_Array", "ArrayLoader") and args:
            self.sink("ssti", f"new {typ}", line, V(_deep_taint(args)))  # dizi yükleyici: değerler şablon metnidir
        if lang == "csharp" and typ in ("XmlSerializer", "DataContractSerializer", "DataContractJsonSerializer") \
                and args and ranges and self._type_by_name(*ranges[0]):
            # new XmlSerializer(Type.GetType(saldırgan türü)): çözülecek türü istek belirliyor (CWE-502)
            self.sink("deserialize", f"new {typ}(Type.GetType(…))", line, args[0])
        if lang == "csharp" and typ == "XmlTextReader" and args \
                and not self.mids & {"Prohibit", "ProhibitDtd", "Ignore"} \
                and ("XmlUrlResolver" in self.mids or "XmlResolver" not in self.mids):
            # XmlTextReader varsayılanı DTD işler (DtdProcessing.Parse); kapatılmadan istek XML'i okunuyor (XXE)
            self.sink("xxe", "new XmlTextReader", line, args[0])
        if typ in ("URL", "URI", "Uri"):
            if lang == "csharp" and len(ranges) >= 2 and any(
                    tok.kind == "id" and tok.value == "Relative" for tok in self.t[ranges[1][0]:ranges[1][1]]):
                # new Uri(x, UriKind.Relative): mutlak adres istisna fırlatır → yönlendirme/SSRF hedefi değil
                return with_safe(V(union, tag="url", type=typ), ("redirect", "ssrf", "ssrf_partial"))
            return V(union, tag="url", type=typ)
        if lang == "csharp" and typ in ("Guid", "DateTime", "DateTimeOffset", "TimeSpan", "Version", "IPAddress"):
            return V(type=typ)  # ayrıştırılmış değer: biçimi doğrulanmış (yol/SQL/komut taşımaz)
        if lang == "csharp" and typ in _CS_SQL_CTORS and args:
            text = args[0].const if isinstance(args[0].const, str) else args[0].prefix
            read = self.p.read_table(args[0])
            if read:
                rcols = self.p.read_columns(text)
                read += ("|" + ",".join(sorted(rcols))) if rcols else ""
            write = self.p.write_table(text) if text else None
            if read or write:
                # Tablo bilgisi prefix alanında taşınır (tür bildirimi type alanını SqlCommand yapar)
                return V(union, tag="sqlcmd", type=typ, prefix=("\x00w:" + write) if write else ("\x00r:" + read))
        if not self.php and (typ in _WRAPPER_STREAM_TYPES or typ in _NONRESP_STREAM_TYPES):
            # Çıkış akışının kökeni: yanıt yazıcısını saran örnek yanıta yazar ("writer"); dosya adı/dosya,
            # bellek tamponu ya da yanıt olmayan akışı saran örnek yanıta yazmaz ("nonresp"). Kökeni bilinmeyen
            # sarmalayıcı (ör. parametre olarak gelen OutputStream) belirsiz kalır (etiketsiz; eski davranış).
            if any(x.tag in ("writer", "resp") for x in args):
                return V(union, tag="writer", type=typ)
            if typ in _NONRESP_STREAM_TYPES or any(x.tag == "nonresp" or isinstance(x.const, str) or
                                                   x.type in ("File", "FileInfo", "Path") for x in args):
                return V(union, tag="nonresp", type=typ)
            return V(union, type=typ)
        if typ in ("ObjectInputStream", "XMLDecoder"):
            return V(union, tag="ois", type=typ)
        if typ == "Yaml":
            safe = any(r for r in ranges if any(tok.kind == "id" and "SafeConstructor" in str(tok.value)
                                                for tok in self.t[r[0]:r[1]]))
            return V(tag="yaml_safe" if safe else "yaml", type=typ)
        if typ in ("ArrayList", "LinkedList", "Vector", "List", "Stack", "ArrayDeque", "HashSet", "TreeSet",
                   "LinkedHashSet"):
            if not args or (len(args) == 1 and isinstance(args[0].const, int)):
                return V(items=(), type=typ)
            return V(union, type=typ)
        if typ in ("HashMap", "TreeMap", "LinkedHashMap", "Hashtable", "Dictionary", "ConcurrentHashMap", "Properties"):
            return V(union, keys=() if not args else None, type=typ)
        if typ in ("StringBuilder", "StringBuffer"):
            if args and isinstance(args[0].const, str):
                return V(type=typ, prefix=args[0].const)
            return V(union, type=typ, tag="sb")
        if typ in ("String", "string") and args:
            return V(union, const=args[0].const if len(args) == 1 and isinstance(args[0].const, str) else _NOC, type="String")
        if typ in ("PDO", "mysqli", "SQLite3"):
            return V(tag="db", type=typ)
        if typ == "DOMXPath":
            return V(tag="xpath", type=typ)
        # Proje sınıfı kurucusu: özet uygulanır
        cands = self.p.resolve(self.u, self.m, typ if not self.php else "__construct", len(args), static_cls=typ) \
            if typ else []
        if cands:
            self._apply_summaries(cands, typ, args, line)
        return V(union, type=typ)

    def _type_by_name(self, a: int, b: int) -> bool:
        """Argüman ``Type.GetType(…)`` / ``Assembly.GetType(…)`` biçiminde addan tür çözümü mü?"""
        t = self.t
        return any(t[k].kind == "id" and t[k].value == "GetType" and k + 2 < b and t[k + 1].value == "("
                   and not (t[k + 2].kind == "op" and t[k + 2].value == ")") for k in range(a, b))

    # -- çağrılar ----------------------------------------------------------
    def _check_args(self, spec: Sink, desc: str, args: list[V], line: int, recv: V | None = None) -> None:
        if spec.flag and spec.flag not in self.u.text_flags and spec.flag not in self.mids:
            return
        if spec.unless_flag and spec.unless_flag in self.mids:
            return
        self._sink_kinds_seen.add(spec.kind)
        idxs = range(len(args)) if spec.args is None else spec.args
        for i in idxs:
            if i < len(args):
                self.sink(spec.kind, desc, line, args[i])
        if spec.args == () and recv is not None:
            self.sink(spec.kind, desc, line, recv)

    def call(self, recv: V | None, names: list[str], name: str, args: list[V], ranges: list[tuple[int, int]],
             line: int, env: dict[str, V], start: int, static_cls: str = "") -> V:
        lang = self.lang
        lname = name.lower()
        recv_text = ".".join(names)
        desc = self._desc(recv, recv_text)
        tag = recv.tag if recv is not None else None
        arg_union = frozenset().union(*(x.taint for x in args)) if args else frozenset()
        # 0) Kotlin çevirisi: yardımcılar ve Kotlin çatı kaynakları/hedefleri
        if self.kt:
            kv = self._kotlin_call(recv, names, name, args, ranges, line, desc, tag)
            if kv is not None:
                return kv
        # 0b) Java/Kotlin: Spring WebFlux (ServerRequest/ServerResponse, R2DBC) ve gRPC protobuf iletisi okumaları
        if lang == "java" and recv is not None:
            wv = self._reactive_call(recv, name, args, line, desc)
            if wv is not None:
                return wv
        # 0b2) Yerel nesnenin alanları (17. tur): x.setAd(v) → x.getAd() aynı değeri döndürür; Spring Data depoları:
        # save(varlık) istek verisini kaydeder, find*() kayıtlı veri döndürür.
        if lang == "java" and recv is not None and names:
            okey = self.key_of(start, self._recv_end(start)) if all(not n.endswith("()") for n in names) else None
            setm = re.fullmatch(r"set([A-Z]\w*)", name)
            getm = re.fullmatch(r"(?:get|is)([A-Z]\w*)", name)
            if okey and setm and len(args) == 1:
                env[f"{okey}\x00.{setm.group(1).lower()}"] = args[0]
            elif okey and getm and not args and f"{okey}\x00.{getm.group(1).lower()}" in env:
                return env[f"{okey}\x00.{getm.group(1).lower()}"]
            repo = recv.type if recv.type in self.p.repo_entity else self.types.get(names[0], "")
            if repo not in self.p.repo_entity and self.cls is not None and self.p.repo_entity:
                # 25. tur: this.depo / depo alanı (@Autowired private XRepository depo): alanın bildirilen türü
                fname = names[1] if names[0] == "this" and len(names) > 1 else names[0]
                repo = next((ftype for fn, ftype in self.cls.fields.items() if fn.lower() == fname), repo)
            entity = self.p.repo_entity.get(repo)
            if entity and name in ("save", "saveAndFlush", "saveAll", "insert") and args:
                fields = frozenset()
                if ranges:
                    akey = self.key_of(*ranges[0])
                    if akey:
                        fields = frozenset().union(*(v.taint for k, v in env.items() if k.startswith(akey + "\x00.")))
                self.p.note_table_write("jpa:" + entity.lower(), args[0].taint | fields)
                return V(args[0].taint, type=entity)
            if entity and re.match(r"(?:find|get|read|query|search|stream)", name):
                stored = self.p.stored_for("jpa:" + entity.lower())
                return V(stored, type=entity) if stored else V(type=entity)
        # 0b3) 25. tur: oturum anahtar-değer deposu — session.setAttribute("k", nesne): istek verisiyle doldurulan nesne
        # (alanları) oturumda saklanır; herhangi bir JSP'deki kaçışsız ${k.alan} sonraki isteklerde kayıtlı XSS'tir.
        if lang == "java" and name == "setAttribute" and len(args) == 2 and isinstance(args[0].const, str) \
                and "session" in desc and self.p.jsp_all_uses.get(args[0].const) and ranges and len(ranges) > 1:
            akey = self.key_of(*ranges[1])
            for jpath, jline, expr in self.p.jsp_all_uses[args[0].const]:
                parts = expr.split(".")
                if len(parts) > 1:
                    if _CLEAN_COLUMN_RE.search(parts[1]):
                        continue
                    fv = env.get(f"{akey}\x00.{parts[1].lower()}") if akey else None
                    taint = fv.taint if fv is not None else frozenset()
                else:
                    taint = args[1].taint
                live = frozenset(T(Src("stored", f"oturum özniteliği {args[0].const} (kayıtlı veri)", t.src.line,
                                       t.src.file), t.safe) for t in taint if t.src.label in ("request", "stored"))
                if live:
                    self._sink_in_file("html", f"JSP EL ${{{expr}}} (kaçışsız, oturum özniteliği)", jpath, jline,
                                       V(live))
        # 0c) Spring MVC modeli: kaçışsız Thymeleaf görünümü için öznitelikler (17. tur)
        if lang == "java" and recv is not None and (self.p.th_views or self.p.jsp_views) and \
                name in ("addAttribute", "addObject", "put") \
                and len(args) == 2 and isinstance(args[0].const, str) and args[1].taint \
                and (recv.type in ("Model", "ModelMap", "ModelAndView", "Map", "RedirectAttributes")
                     or self.types.get(names[0] if names else "", "") in ("Model", "ModelMap", "ModelAndView")):
            self._model_attrs.append((args[0].const, args[1], line))
        # 1) Kaynaklar
        if lang == "java" and tag == "req":
            if name in _REQ_JAVA:
                v = self._src(f"request.{name}()", line)
                if name == "getRemoteUser":
                    # Kimliği doğrulanmış kullanıcı adı (kapsayıcı kimlik doğrulaması): saldırganın gönderdiği HTML
                    # değildir (W2-XSS); SQL/yol gibi diğer hedeflerde kaynak olarak kalır.
                    return with_safe(v, ("html",))
                return replace(v, tag="cookies") if name == "getCookies" else v
            if name == "getSession":
                return V(tag="session")
            if name == "getRequestDispatcher" and args:
                self.sink("redirect", "getRequestDispatcher", line, args[0])
                return CLEAN
            if name in ("getAttribute", "getServletContext", "getContextPath", "getMethod", "getScheme",
                        "getServerName", "getLocalAddr", "getRemoteAddr"):
                return CLEAN
        if lang == "java" and tag == "resp" and name in ("getWriter", "getOutputStream"):
            return V(tag="writer")
        if lang == "java" and name == "getRuntime":
            return V(tag="runtime")
        if lang == "java" and tag == "session" and name == "getAttribute":
            return CLEAN
        if lang == "java" and name in ("getOptionValue", "getOptionValues", "getOptionProperties") and recv is not None:
            return self._src(f"CommandLine.{name}()", line)
        if lang == "java" and name in _STORED_JAVA and recv is not None and recv.tag == "dbresult":
            return self._stored_read(recv, name, line)
        if lang == "csharp" and recv is not None:
            mark = recv.prefix if isinstance(recv.prefix, str) and recv.prefix.startswith("\x00") else ""
            if tag == "sqlcmd" and mark.startswith("\x00r:") and name in (
                    "ExecuteReader", "ExecuteReaderAsync", "ExecuteScalar", "ExecuteScalarAsync"):
                result = V(tag="dbresult", type=mark[3:])
                return self._stored_read(result, name, line) if name.startswith("ExecuteScalar") else result
            if tag == "dbresult" and name in ("GetString", "GetValue", "GetFieldValue", "GetSqlString", "GetChars",
                                              "GetFieldValueAsync"):
                return self._stored_read(recv, name, line)
            if tag == "sqlcmd" and mark.startswith("\x00r:") and name in ("Fill", "FillAsync") and ranges:
                # DataAdapter.Fill(ds|dt): DataSet/DataTable satırları SELECT tablosundan (kayıtlı veri) okunur
                a0, b0 = ranges[0]
                if b0 - a0 == 1 and self.t[a0].kind == "id":
                    var = str(self.t[a0].value)
                    level = "ds_table" if self.types.get(var) == "DataTable" else "ds_set"
                    env[var] = V(tag=f"{level}\x00{mark[3:]}")
                return CLEAN
            if tag and tag.startswith("ds_row\x00") and name in ("Field", "GetValue"):
                return self._ds_read(tag)  # row.Field<string>("kolon")
            if tag == "sqlparams" and mark.startswith("\x00w:") and name in ("AddWithValue", "Add") and args:
                # ADO.NET parametreli yazma: bağlanan değerler tabloya yazılır (okunduğu yerde kayıtlı veri)
                self.p.note_table_write(mark[3:], frozenset().union(*(x.taint for x in args)))
                # 25. tur: yardımcı yöntemde (AddComment(uid, body)) bağlanan değer parametreden geliyorsa yazım özete
                # girer; çağıran istek verisi verdiğinde tablo kayıtlı veri olur.
                for t in _tsorted(frozenset().union(*(x.taint for x in args))):
                    if t.src.label == "param" and (t.src.param, mark[3:], None) not in self.summary.table_writes:
                        self.summary.table_writes.append((t.src.param, mark[3:], None))
        # 17. tur: yönlendirme hedefinin ana makine denetimi (parse_url/URI/URL → host karşılaştırması) için iz
        if not self.php and name in ("create", "parse") and recv is not None and recv.tag == "class" \
                and recv.type in ("URI", "Uri", "URL", "UriComponentsBuilder") and ranges and args and args[0].taint:
            ukey = self.key_of(*ranges[0])
            if ukey:
                return V(args[0].taint, tag="urlof:" + ukey, type=recv.type)
        if name in ("getHost", "getAuthority", "Host", "getRawAuthority") and recv is not None and recv.tag \
                and recv.tag.startswith("urlof:"):
            return V(recv.taint, tag="hostof:" + recv.tag[6:])
        if self.php and lname == "parse_url" and recv is None and ranges and args and args[0].taint:
            ukey = self.key_of(*ranges[0])
            if ukey:
                comp = "".join(str(x.value) for x in self.t[ranges[1][0]:ranges[1][1]]) if len(ranges) > 1 else ""
                if "PHP_URL_HOST" in comp:
                    return V(args[0].taint, tag="hostof:" + ukey)
                if not comp:
                    return V(args[0].taint, tag="urlof:" + ukey)
        # Kanonik yol + kök öneki denetimi (realpath/normalize/getCanonicalPath + startsWith/strpos): yol aşımı düzeltmesi
        if lang == "java" and name in ("normalize", "toRealPath", "getCanonicalPath", "getCanonicalFile") \
                and "startsWith" in self.mids:
            return with_safe(V((recv.taint if recv is not None else frozenset()) | arg_union), ("path",))
        if self.php and lname == "realpath" and recv is None and self.mids & {"strpos", "str_starts_with", "strncmp",
                                                                                "stripos", "strncasecmp"}:
            return with_safe(V(arg_union), ("path",))
        if lang == "csharp" and name == "GetFullPath" and recv is not None and recv.tag == "class" \
                and recv.type == "Path" and args and "StartsWith" in self.mids:
            # Path.GetFullPath + kök öneki denetimi (StartsWith): yol aşımına karşı önerilen düzeltme
            return with_safe(V(arg_union), ("path",))
        if lang == "csharp" and name == "CreateNavigator":
            return V(recv.taint if recv is not None else frozenset(), type="XPathNavigator")
        if lang == "csharp" and tag == "req" and name in ("ReadFormAsync", "GetQueryNameValuePairs", "GetValues"):
            return self._src(f"Request.{name}()", line)
        if lang == "csharp" and tag == "httpctx" and name == "GetRouteValue":
            return self._src("RouteValue", line)
        if self.php:
            if lname == "request" and recv is None:
                return self._src("request(…)", line) if args else V(tag="req")
            if tag in ("req", "reqbag") and lname in _REQ_PHP_METHODS:
                return self._src(f"$request->{name}()", line)
            if tag == "ci_input" and lname in _CI_INPUT_METHODS:
                return self._src(f"$this->input->{name}()", line)
            if lname == "redirect" and recv is not None and recv.tag == "this" and args \
                    and self.cls is not None and self.cls.bases & {"AbstractController"} \
                    and not (args[0].prefix and _HOST_FIXED.match(args[0].prefix)):
                # 19. tur: Symfony AbstractController::redirect($url) — yalnız doğrudan $this->redirect(...)
                self.sink("redirect", "$this->redirect()", line, args[0])
            if tag == "class" and recv.type.lower() in ("input", "request") and \
                    lname in _REQ_PHP_METHODS:
                return self._src(f"{recv.type}::{name}()", line)
            if recv is not None and ("request" in desc) and lname in ("getval", "gettext", "getrawval", "getarray",
                                                                     "getvalues", "getqueryvalues", "getpostvalues",
                                                                     "getqueryvaluesonly", "getheader", "getcookie",
                                                                     "getfilename", "getupload", "getrequesturl",
                                                                     "getfullrequesturl", "getglobalrequesturl"):
                return self._src(f"WebRequest->{name}()", line)  # MediaWiki WebRequest
            if recv is not None and ("request" in desc) and lname in ("getint", "getbool", "getcheck", "getfuzzybool",
                                                                     "getintornull", "getfloat", "getintarray"):
                return CLEAN
            if lname == "filter_input" and recv is None and args:
                src = self._src("filter_input()", line)
                flag = "".join(str(x.value) for x in self.t[ranges[2][0]:ranges[2][1]]) if len(ranges) >= 3 else ""
                if re.search(r"VALIDATE_(INT|FLOAT|BOOL|IP|EMAIL)|SANITIZE_NUMBER", flag):
                    return with_safe(src, (ALL,))
                if re.search(r"SPECIAL_CHARS|ENCODED", flag):
                    return with_safe(src, ("html",))
                return src
            if lname == "file_get_contents" and args and args[0].const == "php://input":
                return self._src("php://input", line)
            if lname in ("getenv",):
                return CLEAN
            if recv is None and lname in _STORED_PHP:
                return self._stored_read(args[0] if args else None, name, line)
            if recv is not None and lname in _STORED_PHP_METHODS and tag == "dbresult":
                return self._stored_read(recv, name, line)
        if self.php and recv is not None and recv.tag == "stmtw" and lname in (
                "bindparam", "bindvalue", "bind_param", "execute"):
            self.p.note_table_write(recv.type, _bound_written(recv.const, lname, args))
            return CLEAN
        if self.lang == "java" and recv is not None and recv.tag == "stmtw" and name.startswith("set") and len(args) >= 2:
            # PreparedStatement.setString(i, v): INSERT/UPDATE SET bölümündeki ? sırasına bağlanan değer tabloya yazılır
            table = recv.prefix[3:] if isinstance(recv.prefix, str) and recv.prefix.startswith("\x00w:") else recv.type
            self._note_written(table, _bound_written(recv.const, "bindvalue", args))
            return CLEAN
        if self.php and recv is None and lname == "mysqli_stmt_bind_param" and len(args) >= 3 and args[0].tag == "stmtw":
            self.p.note_table_write(args[0].type, _bound_written(args[0].const, "bind_param", args[1:]))
            return CLEAN
        if re.search(r"(?i)ssrf", name) and re.search(r"(?i)hook|check|start|valid|filter|guard|protect", name):
            self.guard_kinds.update(("ssrf", "ssrf_partial"))
            return CLEAN
        # 2) Arındırıcılar
        san = self._sanitizer(recv, desc, name, lname, args, ranges, start)
        if san is not None:
            return san
        # 3) Hedefler
        matched = self._sinks_for_call(recv, desc, name, lname, args, ranges, line, tag)
        content = self._file_content(recv, desc, name, lname, args)
        if content is not None:
            return content
        if recv is not None and recv.tag == "class" and (recv.type, name) in _FILE_WRITER_FACTORIES:
            # Files.newBufferedWriter / File.CreateText …: dönen yazıcı dosyaya yazar (HTTP yanıtı değil).
            return V(tag="nonresp", type=name)
        if "xpath" in matched:
            # XPath sorgu sonucu (DOMXPath->query/evaluate, SimpleXMLElement->xpath, XPath.evaluate, SelectNodes):
            # sorgu metni kullanıcı verisi içerse de dönen düğümler XML belgesinden gelir; istek verisi değildir.
            # Enjeksiyon hedefi yukarıda değerlendirildi (JS motorundaki XPath sonucu kuralının karşılığı).
            # Belgenin kendisi istek verisiyse (XmlDocument.Load(Request.Body)) düğümler de istek verisidir.
            doc = recv.taint if recv is not None and recv.tag != "xpath" else frozenset()
            return V(doc) if doc else CLEAN
        if "sql" in matched and name not in ("prepareStatement", "prepareCall", "prepare", "mysqli_prepare"):
            # Sorgu sonucu (satırlar) sorgu metninin taint'ini taşımaz; okunan veri kayıtlı veri olarak ele alınır.
            q = args[1] if lname in ("mysqli_query", "mysqli_prepare") and len(args) > 1 else (args[0] if args else CLEAN)
            return V(tag="dbresult", type=self.p.read_table(q) or "")
        if self.lang == "java" and name in ("prepareStatement", "prepareCall") and args:
            text = args[0].const if isinstance(args[0].const, str) else args[0].prefix
            table = self.p.write_table(text)
            if table:
                # tablo öneke de yazılır: "PreparedStatement ps = …" bildirimi türü (type) değiştirir
                return V(tag="stmtw", type=table, const=_written_placeholders(text), prefix="\x00w:" + table)
        if self.php and lname in ("mysqli_query", "mysql_query", "pg_query", "sqlite_query", "query", "prepare",
                                  "mysqli_prepare") and args:
            q = args[1] if lname in ("mysqli_query", "mysqli_prepare") and len(args) > 1 else args[0] if lname != "pg_query" else args[-1]
            table = self.p.read_table(q)
            if table:
                return V(tag="dbresult", type=table)
            if lname in ("prepare", "mysqli_prepare") and len(args) == (2 if lname == "mysqli_prepare" else 1):
                # PDO/mysqli hazırlanmış yazma deyimi: bağlanan değerler (bindParam/bindValue/bind_param/execute)
                # tabloya yazılır; okunduğu yerde kayıtlı veri kaynağıdır.
                text = q.const if isinstance(q.const, str) else q.prefix
                table = self.p.write_table(text)
                if table:
                    return V(tag="stmtw", type=table, const=_written_placeholders(text))
        # 4) Proje özetleri
        recv_type = recv.type if recv is not None else ""
        if recv is not None and recv.tag == "class" and recv.type:
            static_cls = static_cls or recv.type
        user_def = False
        library_recv = recv is not None and (
            recv.tag in ("req", "resp", "session", "writer", "sg", "reqbag", "sb", "url", "ois", "runtime")
            or (recv_type and recv_type not in self.p.classes)
            or (not recv_type and recv.tag != "class" and name in _COMMON_LIBRARY_METHODS)
            or (recv.tag == "class" and static_cls and static_cls not in self.p.classes))
        if not library_recv:
            cands = self.p.resolve(self.u, self.m, name, len(args), recv_type, static_cls)
            if cands:
                user_def = True
                res = self._apply_summaries(cands, name, args, line)
                if name in ("toString", "ToString") and not args and recv is not None and recv.taint:
                    res = V(res.taint | recv.taint)  # alanları istek verisiyle kurulmuş nesnenin metin biçimi
                if lang == "java" and not args and recv is not None and recv.taint and not res.taint \
                        and re.fullmatch(r"get[A-Z]\w*", name) and any(self._bound_object_taint(t) for t in recv.taint) \
                        and self._getter_returns_string(cands):
                    # 17. tur: istek verisiyle bağlanmış form/DTO nesnesinin (@ModelAttribute, @RequestBody) dize
                    # alıcısı istek verisini döndürür (alan bazında bağlama Spring'in veri bağlayıcısıyla yapılır)
                    res = V(frozenset(t for t in recv.taint if self._bound_object_taint(t)), type="String")
                if _SANITIZER_NAME.search(name) and arg_union and res.taint:
                    return self._heuristic_sanitize(name, res)
                return res
        if tag == "class" and recv.type and re.search(r"(?i)secur|saniti|valid|escap|encod|filter", recv.type) \
                and _SANITIZER_NAME.search(name) and arg_union:
            return self._heuristic_sanitize(name, V(arg_union))
        del user_def
        # 5) Kütüphane modelleri
        if self.php and recv is None and lname in ("get_query_var", "get_search_query", "get_query_string"):
            return self._src(f"{name}()", line)
        if self.php and (recv is None or tag == "class") and _LOOKUP_FUNC.match(lname) and not _REQ_HELPER.match(lname):
            return CLEAN  # anahtar/kimlikle arama: sonuç anahtarın taint'ini taşımaz
        if any(x.tag == "req" for x in args) and _REQ_HELPER.match(name):
            return self._src(f"{name}(request)", line)
        return self._library(recv, names, name, lname, args, ranges, line, env, start, desc)

    # -- Spring WebFlux ve gRPC ------------------------------------------------
    def _proto_field(self, recv: V, field: str) -> V | None:
        """gRPC istek iletisinin alanı: .proto'da sayısal/mantık/enum ise temiz, ileti ise türüyle taint sürer."""
        ftype = self.p.proto.get(recv.type or "", {}).get(field)
        if ftype is None:
            return None
        if ftype in _PROTO_CLEAN_TYPES or ftype in self.p.proto_enums:
            return CLEAN
        return V(recv.taint, type=ftype if ftype in self.p.proto else None)

    def _reactive_call(self, recv: V, name: str, args: list[V], line: int, desc: str) -> V | None:
        if recv.taint and recv.type in self.p.proto and not args:
            if name.startswith("has") or (name.startswith("get") and name.endswith("Count")):
                return CLEAN
            if name.startswith("get") and len(name) > 3:
                field = name[3].lower() + name[4:]
                for cand in (field, field.removesuffix("List"), field.removesuffix("Map")):
                    pv = self._proto_field(recv, cand)
                    if pv is not None:
                        return pv
        if recv.type == "ServerRequest" and name in _WEBFLUX_REQ:
            src = self._src(f"ServerRequest.{name}()", line)
            return with_safe(src, _KT_SAME_SITE) if name in ("uri", "path", "requestPath") else src
        if not args:
            return None
        if name in ("bodyValue", "syncBody", "bodyValueAndAwait") and "serverresponse" in desc \
                and self._kt_html_response():
            self.sink("html", f"ServerResponse.{name}() (text/html)", line, args[0])
            return V(tag="resp")
        if name in ("temporaryRedirect", "permanentRedirect", "seeOther") and "serverresponse" in desc:
            self.sink("redirect", f"ServerResponse.{name}()", line, args[0])
            return V(tag="resp")
        if name in ("sql", "execute") and (recv.type == "DatabaseClient" or "databaseclient" in desc):
            self.sink("sql", f"DatabaseClient.{name}()", line, args[0])  # Spring R2DBC
            return CLEAN
        return None

    # -- Kotlin (taint_kotlin çevirisi) ----------------------------------------
    def _kotlin_call(self, recv: V | None, names: list[str], name: str, args: list[V],
                     ranges: list[tuple[int, int]], line: int, desc: str, tag: str | None) -> V | None:
        """Kotlin'e özgü çağrılar; ``None`` ise Java kuralları sürer."""
        if recv is None and name == "__kt_sink" and len(args) >= 2:
            kind, sdesc = args[0].const, args[1].const
            if isinstance(kind, str) and isinstance(sdesc, str):
                for a in args[2:]:
                    self.sink(kind, sdesc, line, a)
            return CLEAN
        last = names[-1] if names else ""
        if recv is not None and name in _KT_CLEAN_METHODS:
            return CLEAN  # sayı/mantık dönüşümü ve sorgular: "12".toInt(), s.isBlank() …
        if recv is not None and name in _KT_HTML_ENCODERS:
            return with_safe(V(recv.taint | frozenset().union(*(x.taint for x in args)) if args else recv.taint), ("html",))
        if recv is not None and name == "fromString" and "uuid" in desc:
            return CLEAN
        if recv is not None and name in _KT_TYPED_FACTORIES:
            return V(type=_KT_TYPED_FACTORIES[name])  # val db = dbf.newDocumentBuilder() → tür bilinir (XXE hedefi)
        if recv is not None and name == "body" and args and "responseentity" in desc and self._kt_html_response():
            self.sink("html", "ResponseEntity.body() (text/html)", line, args[0])
            return CLEAN
        # Ktor: call.receiveText() / call.receive<T>() / call.receiveParameters() …
        if recv is not None and last == "call" and name in _KT_KTOR_RECEIVE:
            return self._src(f"call.{name}()", line)
        if tag == "ktreq" and name in ("queryString", "path", "uri", "document", "header", "host", "userAgent"):
            src = self._src(f"call.request.{name}()", line)
            return with_safe(src, _KT_SAME_SITE) if name in ("path", "uri", "document") else src
        # Javalin / http4k / Vert.x / Spring WebFlux istek yöntemleri
        if recv is not None and name in _KT_REQ_METHODS:
            return self._src(f"{last or 'ctx'}.{name}()", line)
        if recv is not None and name in _KT_REQ_METHODS_CTX and last in _KT_CTX_NAMES and \
                (len(args) <= 1 or name not in ("header", "cookie")):  # header(ad, değer): yanıt başlığı yazımı
            src = self._src(f"{last}.{name}()", line)
            # İsteğin kendi yolu/adresi: başka siteye yönlendirme/istek yapılamaz (PHP REQUEST_URI ile aynı)
            return with_safe(src, _KT_SAME_SITE) if name in ("path", "fullUrl", "url") else src
        # Android Intent / Uri
        if recv is not None and (last in ("intent", "getintent()") and re.fullmatch(r"get\w*Extra", name)):
            return self._src(f"Intent.{name}()", line)
        if recv is not None and name == "getQueryParameter":
            return self._src("Uri.getQueryParameter()", line)
        # Hedefler
        if recv is not None and recv.tag == "url" and name in ("readText", "readBytes", "openStream", "openConnection"):
            self.sink("ssrf", f"URL.{name}()", line, V(recv.taint))
            return CLEAN
        if "__kt_android" in self.u.text_flags and recv is not None and args:
            spots = self._android_sql_args(name, desc, args)
            if spots:
                for idx in spots:
                    if idx < len(args):
                        self.sink("sql", f"SQLite {name}()", line, args[idx])
                return V(tag="dbresult")
        if name in ("rawQuery", "execSQL", "compileStatement") and args:
            self.sink("sql", f"SQLiteDatabase.{name}()", line, args[0])
            return V(tag="dbresult") if name == "rawQuery" else CLEAN
        if name in ("exec", "execAndMap") and args and (
                (recv is None and ("transaction" in self.mids or "TransactionManager" in self.mids))
                or "transaction" in desc or "current()" in desc):
            self.sink("sql", f"Exposed {name}()", line, args[0])  # transaction { exec("…") }
            return V(tag="dbresult")
        if name in ("loadData", "loadDataWithBaseURL") and recv is not None and "web" in desc and args:
            self.sink("html", f"WebView.{name}()", line, args[1] if name == "loadDataWithBaseURL" and len(args) > 1 else args[0])
            return CLEAN
        if name == "evaluateJavascript" and recv is not None and "web" in desc and args:
            self.sink("eval", "WebView.evaluateJavascript()", line, args[0])
            return CLEAN
        if name in ("get", "post", "put", "delete", "head", "patch", "request", "submitForm") and recv is not None and \
                "client" in desc and args and tag not in ("req", "ktreq", "resp", "session"):
            self.sink("ssrf", f"HttpClient.{name}()", line, args[0])
            return CLEAN
        return None

    @staticmethod
    def _android_sql_args(name: str, desc: str, args: list[V]) -> tuple[int, ...]:
        """Android SQLiteDatabase / SQLiteQueryBuilder çağrılarında SQL parçası olan argümanlar."""
        builder = "querybuilder" in desc or "builder" in desc
        database = any(x in desc for x in ("database", "db", "sqlite"))
        if name == "appendWhere" and builder:
            return (0,)
        if name == "query" and builder:
            return (2, 6)  # query(db, projection, selection, args, groupBy, having, sortOrder)
        if name == "query" and database:
            shift = 1 if args and isinstance(args[0].const, bool) else 0  # query(distinct, table, …)
            return (2 + shift, 4 + shift, 5 + shift, 6 + shift)
        if name == "delete" and database:
            return (1,)
        if name == "update" and database:
            return (2,)
        return ()

    def _kt_html_response(self) -> bool:
        """Yöntem yanıtı text/html yapıyor mu (MediaType.TEXT_HTML / "text/html")?"""
        if "TEXT_HTML" in self.mids or "TEXT_HTML_VALUE" in self.mids:
            return True
        a, b = self.m.body
        return any(tok.kind == "str" and "text/html" in str(tok.value).lower() for tok in self.t[a:b])

    def _kotlin_member(self, recv: V, names: list[str], member: str, line: int, env: dict[str, V]) -> V | None:
        last = names[-1] if names else ""
        if last == "call" and recv.tag in (None, "class") and not recv.taint:  # Ktor örtük call (ApplicationCall)
            if member == "parameters":
                return self._src("call.parameters", line)
            if member == "request":
                return V(tag="ktreq")
        if recv.tag == "ktreq":
            if member in ("origin", "local"):
                return V(tag="ktreq")
            if member in ("queryParameters", "rawQueryParameters", "headers", "cookies", "uri", "path",
                          "queryString", "document"):
                src = self._src(f"call.request.{member}", line)
                return with_safe(src, _KT_SAME_SITE) if member in ("uri", "path", "document") else src
            return CLEAN
        if recv.tag in ("req", "resp", "session") and member[:1].islower() and member not in ("length", "size"):
            # Kotlin özellik sözdizimi: request.queryString → request.getQueryString()
            getter = "get" + member[:1].upper() + member[1:]
            return self.call(recv, names, getter, [], [], line, env, 0)
        if last in ("intent", "getintent()") and member in ("data", "extras", "dataString"):
            return self._src(f"Intent.{member}", line)
        return None

    def _note_written(self, table: str, taint: frozenset[T]) -> None:
        """Hazırlanmış yazmada bağlanan değer: istek verisi → tablo izi; parametre → özet (çağıran yazar)."""
        self.p.note_table_write(table, taint)
        for t in _tsorted(taint):
            if t.src.label == "param" and (t.src.param, table, None) not in self.summary.table_writes:
                self.summary.table_writes.append((t.src.param, table, None))

    def _ds_read(self, tag: str) -> V:
        """DataSet/DataTable satır değeri: SELECT tablosuna istek verisi yazıldıysa kayıtlı veri kaynağı."""
        stored = self.p.stored_for(tag.partition("\x00")[2])
        return V(stored) if stored else CLEAN

    def _stored_read(self, result: V | None, name: str, line: int) -> V:
        table = result.type if result is not None and result.tag == "dbresult" else ""
        stored = self.p.stored_for(table) if table else frozenset()
        if stored:
            return V(stored)
        return CLEAN  # tablosu bilinmeyen / istek verisi yazılmayan tablo: kayıtlı veri kaynağı sayılmaz

    def _file_content(self, recv: V | None, desc: str, name: str, lname: str, args: list[V]) -> V | None:
        """Dosya içeriği okuyucuları (yol hedefi denetlendikten sonra): yol istekten gelse de içerik HTML bağlamında
        saldırgan verisi değildir (W2-XSS; JS/Python/Java motorlarında da böyle). PHP'de URL sarmalayıcısı uzak içerik
        okuyabilir: yol sabit önekliyse ya da istek alanının adı adres bildirmiyorsa dosya sayılır."""
        union = frozenset().union(*(x.taint for x in args)) if args else frozenset()
        if self.lang == "csharp" and name in _CS_FILE_READ and "file" in desc:
            return with_safe(V(union | (recv.taint if recv is not None else frozenset())), ("html",))
        if self.php and recv is not None and lname == "render" and args and isinstance(args[0].const, str) \
                and any(x in desc for x in ("twig", "environment")) and "Twig_Loader_String" not in self.u.text_flags and "Twig_Loader_String" not in self.mids:
            # Twig varsayılanı otomatik HTML kaçışıdır: dosya şablonu |raw / autoescape false içermiyorsa render()
            # sonucu kaçışlı HTML'dir (şablon metninin kendisi istekten geliyorsa SSTI ayrı hedeftir).
            if args[0].const.rsplit("/", 1)[-1] not in self.p.twig_raw:
                return with_safe(V(union | recv.taint), ("html",))
        if self.php and recv is None and lname in _PHP_FILE_READ and args and union:
            first = args[0]
            prefix = first.prefix or (first.const if isinstance(first.const, str) else "")
            url_like = any(_URL_FIELD.search(t.src.desc) for t in first.taint)
            if (prefix and "://" not in prefix) or (not prefix and not url_like):
                return with_safe(V(union), ("html",))
        return None

    def _heuristic_sanitize(self, name: str, v: V) -> V:
        kinds: list[str] = []
        for pattern, hint in _SANITIZE_HINTS:
            if pattern.search(name):
                kinds.extend(hint)
        return with_safe(v, kinds or (ALL,))

    def _sanitizer(self, recv: V | None, desc: str, name: str, lname: str, args: list[V],
                   ranges: list[tuple[int, int]], start: int) -> V | None:
        lang = self.lang
        union = frozenset().union(*(x.taint for x in args)) if args else frozenset()
        base = V(union)
        recv_taint = recv.taint if recv is not None else frozenset()
        cls = recv.type.lower() if recv is not None and recv.tag == "class" and recv.type else ""
        if lang in ("java", "csharp"):
            if name in _PARSE_ALL or (name in ("valueOf", "Parse", "parse", "ParseExact", "TryParse") and cls in _NUMERIC_CLASSES):
                return CLEAN
            if cls in ("math",):
                return CLEAN
            if lang == "java" and name in _JAVA_SAN:
                kinds = _JAVA_SAN[name]
                if name == "encode" and "urlencoder" not in desc:
                    return None
                return with_safe(V(union | recv_taint), kinds) if kinds else V(union | recv_taint)
            if lang == "java" and name == "encode" and "urlencoder" in desc:
                return with_safe(base, ("html",))
            if lang == "java" and name in ("sanitize",) and ("policy" in desc or "sanitizer" in desc):
                return with_safe(base, ("html",))
            if lang == "java" and name == "clean" and "jsoup" in desc:
                return with_safe(base, ("html",))
            if lang == "java" and name == "getName" and recv is not None and ("file" in desc) and recv.taint:
                return with_safe(V(recv.taint), ("path",))
            if lang == "java" and name == "getFileName" and recv is not None and recv.taint:
                return with_safe(V(recv.taint), ("path",))
            if lang == "java" and name in ("getName", "getBaseName") and "filenameutils" in desc:
                return with_safe(base, ("path",))
            if lang == "csharp" and name in _CS_SAN:
                if name == "Encode" and not any(x in desc for x in ("encoder", "html", "javascript")):
                    return None
                return with_safe(V(union | recv_taint), _CS_SAN[name])
            if lang == "csharp" and name == "Encode" and any(x in desc for x in ("htmlencoder", "javascriptencoder", "urlencoder")):
                return with_safe(base, ("html",))
            if lang == "csharp" and (name == "SerializeObject" or (name in ("Serialize", "SerializeToUtf8Bytes")
                                                                   and "json" in desc)):
                # 19. tur: JSON belgesi ("{…}") HTML olarak işlenmez (yanıt gövdesine yazılsa da XSS hedefi değil)
                return with_safe(V(union | recv_taint), ("html",))
            if name in ("replace", "replaceAll", "Replace") and len(args) >= 2 and recv is not None:
                old, new = args[0].const, args[1].const
                if isinstance(old, str) and isinstance(new, str) and "<" in old and ("&lt" in new or "&#" in new):
                    return with_safe(V(recv.taint), ("html",))
            return None
        # PHP
        if recv is None and lname in _PHP_SAN:
            kinds = _PHP_SAN[lname]
            if lname in ("urlencode", "rawurlencode", "basename", "htmlspecialchars", "htmlentities", "strip_tags",
                         "escapeshellarg", "escapeshellcmd", "esc_url", "esc_html", "esc_attr", "e",
                         "sanitize_text_field", "esc_js", "esc_textarea", "pg_escape_literal", "wp_kses",
                         "wp_kses_post", "wp_kses_data", "esc_html__", "esc_attr__", "esc_html_x", "esc_attr_x",
                         "wp_strip_all_tags", "sanitize_file_name", "tag_escape", "esc_url_raw"):
                return with_safe(V(args[0].taint) if args else CLEAN, kinds)
            return CLEAN
        if (recv is None and lname in ("json_encode", "wp_json_encode")) or (
                lname == "encode" and recv is not None and recv.tag == "class" and "json" in recv.type.lower()):
            return with_safe(V(union), ("html",))  # JSON belgesi (JSON yanıtı): HTML bağlamı değil
        if lname in _PHP_SQL_ESCAPE:
            src = union | recv_taint if recv is None else union
            return with_safe(V(src), ("sql?",))
        if lname == "quote" and recv is not None and any(x in desc for x in _PHP_DB_RECV):
            return with_safe(base, ("sql",))
        if lname == "prepare" and recv is not None and len(args) >= 2 and any(x in desc for x in _PHP_DB_RECV + ("wpdb",)):
            # $wpdb->prepare($sorgu, ...$değerler): değerler yer tutucularla bağlanır; yalnız sorgu metni hedeftir.
            self.sink("sql", "->prepare()", self._line(start), args[0])
            bound = frozenset().union(*(x.taint for x in args[1:]))
            return V(args[0].taint | with_safe(V(bound), ("sql",)).taint)
        if recv is None and lname in ("add_query_arg", "remove_query_arg") and args:
            url = args[-1] if (lname == "add_query_arg" and (len(args) == 3 or (len(args) == 2 and args[0].keys is not None))) \
                or (lname == "remove_query_arg" and len(args) == 2) else None
            return V(url.taint, prefix=url.prefix if url.const is _NOC else url.const) if url is not None else V(prefix="?")
        if recv is None and re.fullmatch(r"(?:admin|home|site|network_admin|network_home|network_site|self_admin|user_admin|"
                                          r"includes|content|plugins|get_admin|get_home|get_site|wp_login|wp_logout|"
                                          r"wp_registration|get_edit_post|get_edit_user|get_permalink|get_term)_?(?:url|link)?",
                                          lname) and lname.endswith(("url", "link")):
            return V(prefix="<site-url>/")
        if lname == "filter_var" and recv is None and len(args) >= 2:
            flag = "".join(str(x.value) for x in self.t[ranges[1][0]:ranges[1][1]])
            if re.search(r"VALIDATE_(INT|FLOAT|BOOL|IP|EMAIL|MAC)|SANITIZE_NUMBER", flag):
                return CLEAN
            if re.search(r"SPECIAL_CHARS|ENCODED|STRIPPED", flag):
                return with_safe(V(args[0].taint), ("html",))
            if re.search(r"VALIDATE_URL", flag):
                return V(args[0].taint)
            return V(args[0].taint)
        if recv is None and lname in ("apply_filters", "apply_filters_deprecated", "apply_filters_ref_array") and len(args) >= 2:
            return args[1]  # kanca: yalnız süzülen değer döner (bağlam argümanları değil)
        if recv is None and lname in ("do_action", "do_action_ref_array", "add_action", "add_filter"):
            return CLEAN
        if recv is None and lname in ("array_map", "array_walk") and len(args) >= 2:
            # 17. tur: kapanışlı biçim — array_map(function($v) { return kaçış(…, $v); }, X) / fn($v) => kaçış($v);
            # süper küresel dizinin tamamı eşlenirse öğe kaynağı kullanılır ($_POST = array_map(…, $_POST)).
            if isinstance(args[0].const, str):
                cb = args[0].const.lower()
            else:
                cb = self._closure_return_call(*ranges[0]) if ranges and lname == "array_map" else None
            items = self.elem_of(args[1]) if args[1].tag == "sg" else args[1]
            if cb in ("intval", "absint", "floatval", "boolval"):
                return V(tag="sgclean") if args[1].tag == "sg" else CLEAN
            if cb in _PHP_SAN:
                return with_safe(V(items.taint), _PHP_SAN[cb])
            if cb in _PHP_SQL_ESCAPE:
                return with_safe(V(items.taint), ("sql?",))
        if lname in ("str_replace", "str_ireplace") and len(args) >= 3:
            search, rep = args[0].const, args[1].const
            out = V(args[1].taint | args[2].taint)
            if isinstance(search, str) and isinstance(rep, str) and "<" in search and "&lt" in rep:
                return with_safe(out, ("html",))
            if search == ".." and rep == "":
                return with_safe(out, ("path",))  # tüm ".." çiftleri tek geçişte silinir: üst dizine çıkılamaz
            # Not (17. tur): tek tırnağı ikileyen/kaçışlayan str_replace SQL arındırıcısı SAYILMAZ — MySQL ters eğik
            # çizgi kaçışıyla atlatılır (\' → \'' ), bilinen "add quote" atlatması.
            return out
        if lname in ("preg_replace", "preg_replace_callback") and len(args) >= 3:
            pv = args[0].const
            if lname == "preg_replace" and isinstance(pv, str) and re.search(r"[/#~][a-zA-Z]*e[a-zA-Z]*$", pv.strip()):
                self.sink("eval", "preg_replace /e", self._line(start), args[1])
            if isinstance(pv, str) and re.search(r"\[\^[a-zA-Z0-9_\\\-\s]+\]", pv) and isinstance(args[1].const, str) \
                    and args[1].const == "":
                return CLEAN  # yalnız beyaz liste karakterleri bırakan temizleme
            return V(args[1].taint | args[2].taint)
        return None

    def _sinks_for_call(self, recv: V | None, desc: str, name: str, lname: str, args: list[V],
                        ranges: list[tuple[int, int]], line: int, tag: str | None) -> set[str]:
        before = self._sink_kinds_seen
        self._sink_kinds_seen = set()
        try:
            self._sinks_for_call_inner(recv, desc, name, lname, args, ranges, line, tag)
            return self._sink_kinds_seen
        finally:
            self._sink_kinds_seen = before

    def _sinks_for_call_inner(self, recv: V | None, desc: str, name: str, lname: str, args: list[V],
                              ranges: list[tuple[int, int]], line: int, tag: str | None) -> None:
        lang = self.lang
        if lang == "java":
            if "resp" in desc and args:
                if name == "setContentType":
                    self._note_response_header("content-type", args[0])
                elif name in ("setHeader", "addHeader") and len(args) >= 2 and isinstance(args[0].const, str):
                    self._note_response_header(args[0].const, args[1])
            if name in ("readObject", "readUnshared") and recv is not None and recv.tag == "ois":
                self.sink("deserialize", f"{recv.type or 'ObjectInputStream'}.{name}()", line, V(recv.taint))
            if name in ("openConnection", "openStream", "getContent") and recv is not None and recv.tag == "url":
                self.sink("ssrf", f"URL.{name}()", line, V(recv.taint))
            # 18. tur: Spring HttpHeaders/MultiValueMap ya da yanıt oluşturucusu üzerinden Location başlığı (3xx)
            ldesc = desc.lower()
            is_hdrs = (recv is not None and recv.type in ("HttpHeaders", "MultiValueMap", "LinkedMultiValueMap")) or \
                "header" in ldesc
            if name in ("add", "set", "put", "header") and len(args) >= 2 and isinstance(args[0].const, str) and \
                    args[0].const.lower() == "location" and (is_hdrs or name == "header"):
                self.sink("redirect", f"{name}(\"Location\")", line, args[1])
                self._location_maps.add(desc.split(" ")[0].split(".")[0])
            elif name == "add" and len(args) == 1 and ldesc.endswith(".get()") and \
                    ldesc.split(".")[0] in self._location_maps:
                self.sink("redirect", "Location başlığı (başlık listesine ekleme)", line, args[0])
            elif name in ("location", "setLocation") and len(args) == 1 and \
                    (is_hdrs or "responseentity" in ldesc or "status()" in ldesc):
                self.sink("redirect", f"{name}()", line, args[0])
            if name in ("setHeader", "addHeader") and len(args) >= 2 and isinstance(args[0].const, str) and \
                    args[0].const.lower() == "location" and ("resp" in desc):
                self.sink("redirect", f"{name}(\"Location\")", line, args[1])
            if name in ("load", "loadAll", "loadAs") and recv is not None and recv.tag == "yaml_safe":
                return
            for spec in _JAVA_SINKS.get(name, ()):
                if spec.kind == "html" and _nonresp_stream(recv):
                    continue  # FileWriter/StringWriter/ByteArrayOutputStream…: dosya ya da bellek, HTTP yanıtı değil
                if spec.kind == "html" and self.kt and (recv is None or recv.tag != "writer"):
                    continue  # Kotlin: yalnız yanıt yazıcısı (response.writer / getOutputStream) HTML hedefidir
                if spec.recv is None or any(r in desc for r in spec.recv):
                    self._check_args(spec, f"{name}()", args, line, recv)
            if self.p.mybatis and name in self.p.mybatis and args:
                for a in args:
                    self.sink("sql", f"MyBatis ${{}} ({name})", line, a)
            if recv is not None and recv.tag == "class" and recv.type in ("IOUtils", "ImageIO", "Resources", "Jsoup") \
                    and any(a.tag == "url" for a in args):
                for a in args:
                    if a.tag == "url":
                        self.sink("ssrf", f"{recv.type}.{name}(URL)", line, a)
            return
        if lang == "csharp":
            if name in ("AddHeader", "AppendHeader", "Add", "Append", "TryAdd") and len(args) >= 2 and \
                    isinstance(args[0].const, str) and ("resp" in desc or "headers" in desc):
                self._note_response_header(args[0].const, args[1])
            if name in ("View", "PartialView") and recv is None and self.cls is not None and args and not self.privileged:
                ctrl = self.cls.name[:-len("Controller")] if self.cls.name.endswith("Controller") else self.cls.name
                view = args[0].const if isinstance(args[0].const, str) and len(args) >= 1 else self.m.name
                model = args[-1] if not (len(args) == 1 and isinstance(args[0].const, str)) else CLEAN
                mr = ranges[-1] if ranges else (0, 0)
                plain = mr[1] - mr[0] == 1 and self.t[mr[0]].kind == "id" and \
                    any(prm.name == self.t[mr[0]].value for prm in self.m.params)
                if not plain and model.type not in ("", "string", "String"):
                    model = CLEAN  # kurulmuş görünüm modeli: bütün nesne taint'i kesin değil (özellik bazında izlenmez)
                view = str(view).rsplit("/", 1)[-1].rsplit(".", 1)[0]
                self.p.note_view((ctrl.lower(), view.lower(), model.type or ""), model)
            if name in _CS_EF_INTERPOLATED_SAFE and ranges and ranges[0][1] - ranges[0][0] == 1 \
                    and self.t[ranges[0][0]].kind in ("istr", "str"):
                return  # EF Core FormattableString: ara değerler parametre olur (SQL enjeksiyonu değil)
            if name == "Text" and recv is not None and recv.tag == "class" and recv.type in ("Results", "TypedResults") \
                    and len(args) >= 2 and isinstance(args[1].const, str) and "html" in args[1].const.lower():
                self.sink("html", "Results.Text(…, \"text/html\")", line, args[0])
            if name == "WriteAsync" and ("resp" in desc or "response" in desc) and args and not _nonresp_stream(recv):
                self.sink("html", "WriteAsync()", line, args[0])  # HttpResponse.WriteAsync (içerik türü izlenir)
            if name in ("Add", "Append", "TryAdd", "SetCommaSeparatedValues", "AppendCommaSeparatedValues", "AddHeader",
                        "AppendHeader") and len(args) >= 2 and isinstance(args[0].const, str) \
                    and args[0].const.lower() == "location" and ("resp" in desc or "headers" in desc):
                self.sink("redirect", f"{name}(\"Location\")", line, args[1])
            if name == "DeserializeObject" and recv is not None and "jsonconvert" in desc and args:
                verdict = self._newtonsoft_typenames(ranges)
                if verdict or (verdict is None and "TypeNameHandling" in self.u.text_flags):
                    self.sink("deserialize", "JsonConvert.DeserializeObject (TypeNameHandling)", line, args[0])
            if name in ("WriteLine", "Write", "WriteAsync", "WriteLineAsync") and "standardinput" in desc and args \
                    and any(x.kind == "str" and re.search(r"(?i)(^|/|\\)(sh|bash|zsh|cmd(\.exe)?|powershell(\.exe)?|pwsh)$",
                                                          str(x.value)) for x in self.t):
                self.sink("command", "Process.StandardInput (kabuk)", line, args[0])  # kabuk sürecine komut satırı
            if name == "Create" and recv is not None and recv.tag == "class" and recv.type == "XmlReader" and args \
                    and {"DtdProcessing", "Parse"} <= self.mids:
                self.sink("xxe", "XmlReader.Create (DtdProcessing.Parse)", line, args[0])
            if name in ("Load", "LoadXml") and args and "XmlUrlResolver" in self.mids and "XmlResolver" in self.mids \
                    and recv is not None and recv.tag != "class" and ("xmldocument" in desc or "doc" in desc):
                self.sink("xxe", f"XmlDocument.{name} (XmlUrlResolver)", line, args[0])
            if name in ("NavigateTo", "Redirect", "RedirectPermanent", "RedirectPreserveMethod",
                        "RedirectPermanentPreserveMethod") and ranges and any(
                    tok.kind == "id" and tok.value in ("IsAbsoluteUri", "IsLocalUrl", "IsUrlLocalToHost")
                    for tok in self.t[ranges[0][0]:ranges[0][1]]):
                return  # url.IsAbsoluteUri ? "/" : url — yalnız göreli adres (aynı site)
            if name == "NavigateTo" and args and "nav" in desc:
                self.sink("redirect", "NavigationManager.NavigateTo()", line, args[0])
            if name in ("InvokeVoidAsync", "InvokeAsync") and len(args) >= 2 and isinstance(args[0].const, str) \
                    and args[0].const in ("eval", "Function", "setTimeout", "setInterval"):
                for x in args[1:]:
                    self.sink("eval", f"IJSRuntime.{name}(\"{args[0].const}\")", line, x)
            if name == "Start" and len(args) == 1 and args[0].type == "ProcessStartInfo":
                return  # ProcessStartInfo kurulurken (kurucu/özellikler) zaten değerlendirildi
            for spec in _CS_SINKS.get(name, ()):
                if spec.kind == "html" and _nonresp_stream(recv):
                    continue  # StreamWriter/StringWriter/MemoryStream…: dosya ya da bellek, HTTP yanıtı değil
                if spec.recv is None or any(r in desc for r in spec.recv):
                    self._check_args(spec, f"{name}()", args, line, recv)
            if name == "Content" and len(args) >= 2 and isinstance(args[1].const, str) and "html" in args[1].const.lower():
                self.sink("html", "Content(…, \"text/html\")", line, args[0])
            if name == "Redirect" and recv is not None and recv.tag not in (None, "resp", "this", "class") and "response" not in desc:
                pass
            return
        # PHP
        if recv is None:
            if lname == "header" and args:
                raw = args[0].const if isinstance(args[0].const, str) else args[0].prefix
                if isinstance(raw, str) and ":" in raw:
                    hname, _, hvalue = raw.partition(":")
                    self._note_response_header(hname, V(const=hvalue))
                prefix = (args[0].prefix or (args[0].const if isinstance(args[0].const, str) else "") or "").lower()
                if prefix.replace(" ", "").startswith("location:"):
                    self.sink("redirect", "header(\"Location: …\")", line, args[0])
            if lname == "curl_setopt" and len(args) >= 3 and len(ranges) >= 2:
                opt = "".join(str(x.value) for x in self.t[ranges[1][0]:ranges[1][1]])
                if "CURLOPT_URL" in opt:
                    self.sink("ssrf", "curl_setopt(CURLOPT_URL)", line, args[2])
            if lname == "unserialize" and len(ranges) >= 2:
                opts = " ".join(str(x.value) for x in self.t[ranges[1][0]:ranges[1][1]])
                if "allowed_classes" in opts and "false" in opts.lower():
                    return
            if lname == "assert" and args and args[0].const is _NOC and not args[0].taint:
                return
            for spec in _PHP_FUNC_SINKS.get(lname, ()):
                self._check_args(spec, f"{name}()", args, line)
            if lname in _PHP_URL_WRAPPER_FUNCS and args and ranges and not args[0].prefix and args[0].const is _NOC \
                    and not any((tok.kind == "op" and tok.value == ".") or tok.kind in ("istr", "bstr")
                                for tok in self.t[ranges[0][0]:ranges[0][1]]):
                # URL sarmalayıcıları (allow_url_fopen): adresin tamamı istekten geliyorsa (birleştirme/ara değer yok)
                # ve istek alanının adı adres bildiriyorsa (url, uri, link, host …) dosya yolunun yanında SSRF
                # hedefidir (Psalm TaintedSSRF modeli); önekli ya da ad olarak dosya bildiren yol değildir.
                url_taint = frozenset(t for t in args[0].taint if _URL_FIELD.search(t.src.desc))
                if url_taint:
                    self.sink("ssrf", f"{name}() (URL)", line, V(url_taint))
            return
        if lname in ("render", "display", "fetch") and args and "smarty" in desc and \
                (args[0].prefix or "").lower().startswith(("string:", "eval:")):
            self.sink("ssti", f"->{name}(\"string:…\")", line, args[0])  # Smarty dize şablonu
        if lname == "query" and any(x in desc for x in ("xpath",)):
            self._check_args(_PHP_XPATH_QUERY, "DOMXPath->query()", args, line)
            return
        for spec in _PHP_METHOD_SINKS.get(lname, ()):
            if spec.recv is None or any(r in desc for r in spec.recv):
                self._check_args(spec, f"->{name}()", args, line)

    @staticmethod
    def _bound_object_taint(t: T) -> bool:
        """Alanları bütünüyle istekten bağlanan (@ModelAttribute/@RequestBody uç nokta parametresi) ya da kayıtlı
        veriden okunan (Spring Data varlığı) nesnenin izi."""
        return (t.src.label == "request" and t.src.desc.endswith(" parametresi")) or \
            (t.src.label == "stored" and t.src.desc.startswith("jpa:"))

    @staticmethod
    def _getter_returns_string(cands: list[tuple[Unit, Method]]) -> bool:
        return all(m.ret_type in ("String", "CharSequence", "Object", "String[]", "List", "Optional") for _u, m in cands)

    def _apply_summaries(self, cands: list[tuple[Unit, Method]], name: str, args: list[V], line: int) -> V:
        out_taint: set[T] = set()
        ret_tag = None
        types = {self.p.summary(unit, method).resp_type for unit, method in cands}
        exits = any(any(tok.kind == "id" and _TERMINATING.match(str(tok.value)) for tok in unit.toks[method.body[0]:method.body[1]])
                    for unit, method in cands)
        if len(types) == 1 and None not in types and not exits:
            # Yardımcı çıkış yapıyorsa (json_error(); exit) içerik türü çağıranın devam eden yoluna taşınmaz.
            # json_headers(); echo $x / json(resp); resp.getWriter().print(x): yardımcı içerik türünü atadı.
            verdict = types.pop()
            self.resp_non_html = verdict
            self.resp_type_set = verdict
        for unit, method in cands:
            summ = self.p.summary(unit, method)
            for pidx, kind, sdesc, sline, sfile, via in summ.sinks:
                if pidx >= len(args) or kind in self.guard_kinds or self._response_html_suppressed(kind, sdesc):
                    continue
                for t in _tsorted(args[pidx].taint):
                    if not _unsafe(t, kind):
                        continue
                    if t.src.label == "param":
                        self.summary.sinks.append((t.src.param, kind, sdesc, sline, sfile,
                                                   (t.src.via + (method.name,) + via)[-6:]))
                    else:
                        self.p.add_flow(self.p.tf.Flow(
                            self._lang_name(unit.lang, unit.dialect), kind, sdesc, sline, t.src.desc, t.src.label, t.src.line,
                            (t.src.via + (method.name,) + via)[-6:], file=sfile, source_file=t.src.file),
                            privileged=self.privileged, deprecated=self.deprecated)
                        if self.php and method.cls is None and sfile != self.u.path and t.src.file == self.u.path and \
                                (kind, line) not in self._callsite_flows and \
                                not (kind == "redirect" and _same_site_prefix(args[pidx].prefix)):
                            # 18. tur: PHP'de include edilen ortak kitaplık işlevi (dbQuery($q) …): hedef satırına ek
                            # olarak, istek verisinin kitaplığa verildiği çağrı yerinde de raporlanır (sayfa başına
                            # enjeksiyon noktası). Hedef satırındaki bulgu ve parmak izi aynen kalır.
                            self._callsite_flows.add((kind, line))
                            self.p.add_flow(self.p.tf.Flow(
                                self._lang_name(self.lang, self.u.dialect), kind, f"{method.name}() → {sdesc}", line,
                                t.src.desc, t.src.label, t.src.line, (t.src.via + (method.name,) + via)[-6:],
                                file=self.u.path, source_file=t.src.file),
                                privileged=self.privileged, deprecated=self.deprecated)
            for pidx, table, wcols in summ.table_writes:
                if pidx < len(args):
                    self.p.note_table_write(table, args[pidx].taint, wcols)  # çağıranın istek verisi tabloya yazılıyor
                    for t in _tsorted(args[pidx].taint):
                        if t.src.label == "param" and (t.src.param, table, wcols) not in self.summary.table_writes:
                            self.summary.table_writes.append((t.src.param, table, wcols))
            for pidx, safe in summ.ret_params.items():
                if pidx < len(args):
                    for t in _tsorted(args[pidx].taint):
                        out_taint.add(T(t.src, t.safe | safe))
            out_taint.update(summ.ret_taint)
            ret_tag = ret_tag or summ.ret_tag
        if ret_tag in ("req", "param"):
            ret_tag = None
        if len(cands) == 1:
            summ = self.p.summary(*cands[0])
            if summ.ret_keys is not None:
                keys = []
                for k, (params, real) in summ.ret_keys.items():
                    kt: set[T] = set(real)
                    for pidx, safe in params.items():
                        if pidx < len(args):
                            kt.update(T(t.src, t.safe | safe) for t in args[pidx].taint)
                    keys.append((k, V(frozenset(kt))))
                return V(frozenset(out_taint), tag=ret_tag, keys=tuple(keys))
        return V(frozenset(out_taint), tag=ret_tag)

    @staticmethod
    def _lang_name(lang: str, dialect: str = "") -> str:
        return dialect or {"java": "java", "csharp": "csharp", "php": "php"}[lang]

    def _library(self, recv: V | None, names: list[str], name: str, lname: str, args: list[V],
                 ranges: list[tuple[int, int]], line: int, env: dict[str, V], start: int, desc: str) -> V:
        if self.lang == "java" and recv is not None and (
                (recv.tag == "class" and recv.type == "Files" and name in _JAVA_FILE_CONTENT)
                or (name in _JAVA_REMOTE_CONTENT and any(r in desc for r in ("resttemplate", "template", "rest")))):
            # 17. tur: dosyanın/uzak yanıtın İÇERİĞİ yolu/adresi seçen istemcinin denetiminde değildir (yol aşımı ve
            # SSRF ayrı hedeflerdir); içerik XSS/SQL kaynağı sayılmaz.
            return CLEAN
        recv_taint = recv.taint if recv is not None else frozenset()
        arg_union = frozenset().union(*(x.taint for x in args)) if args else frozenset()
        simple = bool(names) and all(not n.endswith("()") and n != "[]" for n in names)
        var_key = self.key_of(start, self._recv_end(start)) if recv is not None and simple else None
        if (not self.php and name in _DECODE_CALLS) or (self.php and recv is None and lname in _PHP_DECODE_CALLS):
            taint = recv_taint | arg_union
            return V(frozenset(T(t.src, frozenset()) for t in taint)) if taint else CLEAN
        if (self.lang != "php" and name in _CLEAN_RESULT) or (self.php and lname in _PHP_SAN):
            if recv is not None and isinstance(recv.const, str) and args and isinstance(args[0].const, str):
                if name in ("equals", "Equals", "contains", "startsWith", "endsWith", "Contains", "StartsWith", "EndsWith"):
                    op = {"equals": recv.const == args[0].const, "Equals": recv.const == args[0].const,
                          "contains": args[0].const in recv.const, "Contains": args[0].const in recv.const,
                          "startsWith": recv.const.startswith(args[0].const), "StartsWith": recv.const.startswith(args[0].const),
                          "endsWith": recv.const.endswith(args[0].const), "EndsWith": recv.const.endswith(args[0].const)}
                    return V(const=op[name])
                if name == "indexOf":
                    return V(const=recv.const.find(args[0].const))
            if name in ("length", "Length") and recv is not None and isinstance(recv.const, str):
                return V(const=len(recv.const))
            return CLEAN
        if recv is not None and self.lang != "php":
            # Dize ve koleksiyon modelleri
            if name == "charAt" and isinstance(recv.const, str) and args and isinstance(args[0].const, int):
                i = args[0].const
                return V(const=recv.const[i]) if 0 <= i < len(recv.const) else CLEAN
            if name in ("add", "addLast", "offer", "push", "addElement", "Add", "Push", "Enqueue", "AddLast") and var_key:
                cur = env.get(var_key, recv)
                if len(args) == 1:
                    items = cur.items + (args[0],) if cur.items is not None else None
                elif len(args) == 2 and isinstance(args[0].const, int) and cur.items is not None:
                    i = args[0].const
                    items = cur.items[:i] + (args[1],) + cur.items[i:]
                else:
                    items = None
                env[var_key] = replace(cur, taint=cur.taint | arg_union, items=items)
                return CLEAN
            if name in ("addAll", "AddRange", "putAll", "extend") and var_key:
                cur = env.get(var_key, recv)
                env[var_key] = V(cur.taint | arg_union, cur.tag, _NOC, None, None, cur.type)
                return CLEAN
            if name in ("remove", "RemoveAt", "poll", "pop", "removeFirst") and var_key:
                cur = env.get(var_key, recv)
                if cur.items is not None:
                    if name in ("poll", "removeFirst") or (args and isinstance(args[0].const, int) and name != "pop"):
                        i = 0 if name in ("poll", "removeFirst") else args[0].const
                        if 0 <= i < len(cur.items):
                            removed = cur.items[i]
                            rest = cur.items[:i] + cur.items[i + 1:]
                            env[var_key] = replace(cur, items=rest, taint=frozenset().union(*(x.taint for x in rest)) if rest else frozenset())
                            return removed
                    if name == "pop" and cur.items:
                        removed = cur.items[-1]
                        env[var_key] = replace(cur, items=cur.items[:-1])
                        return removed
                if cur.keys is not None and args and args[0].const is not _NOC:
                    env[var_key] = replace(cur, keys=tuple((k, v) for k, v in cur.keys if k != args[0].const))
                    return CLEAN
                return V(cur.taint) if cur.taint else CLEAN
            if name in ("get", "elementAt", "Get", "ElementAt", "getOrDefault", "GetValueOrDefault") and recv is not None:
                if recv.items is not None and args and isinstance(args[0].const, int):
                    i = args[0].const
                    return recv.items[i] if 0 <= i < len(recv.items) else CLEAN
                if recv.keys is not None and args and args[0].const is not _NOC:
                    for k, v in recv.keys:
                        if k == args[0].const:
                            return v
                    return args[1] if name == "getOrDefault" and len(args) > 1 else CLEAN
                return V(recv_taint) if recv_taint else CLEAN
            if name in ("put", "Add", "TryAdd", "set", "Set", "setProperty", "putIfAbsent") and var_key and len(args) >= 2:
                cur = env.get(var_key, recv)
                if cur.keys is not None and args[0].const is not _NOC and name != "set":
                    keys = tuple((k, v) for k, v in cur.keys if k != args[0].const) + ((args[0].const, args[1]),)
                    env[var_key] = replace(cur, taint=frozenset().union(*(v.taint for _k, v in keys)), keys=keys)
                elif cur.items is not None and name in ("set", "Set") and isinstance(args[0].const, int):
                    items = list(cur.items)
                    if 0 <= args[0].const < len(items):
                        items[args[0].const] = args[1]
                    env[var_key] = replace(cur, items=tuple(items), taint=frozenset().union(*(x.taint for x in items)) if items else frozenset())
                else:
                    env[var_key] = V(cur.taint | args[-1].taint, cur.tag, _NOC, None, None, cur.type)
                return CLEAN
            if self.lang == "csharp" and name in ("Load", "LoadXml") and var_key and arg_union:
                env[var_key] = V(recv_taint | arg_union, recv.tag, _NOC, None, None, recv.type)
                return CLEAN
            if name in ("append", "Append", "AppendLine", "AppendFormat", "insert", "Insert", "concat") and recv is not None:
                new = V(recv_taint | arg_union, recv.tag, _NOC, None, None, recv.type, recv.prefix)
                if var_key and name not in ("concat",):
                    env[var_key] = new
                elif name not in ("concat",) and len(names) >= 2 and all(
                        n.lower() in ("append()", "appendline()", "appendformat()", "insert()") for n in names[1:]) \
                        and self.t[start].kind in ("id", "var") and str(self.t[start].value) in env:
                    # 17. tur: zincirli sb.append(a).append(b): değişiklik alıcı değişkene yazılır
                    base = str(self.t[start].value)
                    cur = env[base]
                    env[base] = V(cur.taint | new.taint, cur.tag, _NOC, None, None, cur.type, cur.prefix)
                return new
            if name in ("toString", "ToString", "trim", "Trim", "strip", "substring", "Substring", "toLowerCase",
                        "toUpperCase", "ToLower", "ToUpper", "intern", "getBytes", "toCharArray", "clone", "split",
                        "Split", "next", "nextElement", "nextToken", "getValue", "getKey", "iterator", "stream",
                        "values", "keySet", "entrySet", "toArray", "ToArray", "ToList", "reverse", "Reverse",
                        "TrimStart", "TrimEnd", "PadLeft", "PadRight", "Normalize", "Value", "First",
                        "FirstOrDefault", "Last", "LastOrDefault", "Single", "SingleOrDefault", "Keys", "Values",
                        "readLine", "ReadLine", "ReadToEnd", "ReadToEndAsync", "decode", "Decode", "join"):
                if isinstance(recv.const, str) and name in ("toString", "ToString", "trim", "Trim", "toLowerCase",
                                                            "toUpperCase", "ToLower", "ToUpper"):
                    c = recv.const
                    c = c.strip() if name in ("trim", "Trim") else c.lower() if name in ("toLowerCase", "ToLower") \
                        else c.upper() if name in ("toUpperCase", "ToUpper") else c
                    return V(const=c)
                if name in ("substring", "Substring") and isinstance(recv.const, str) and all(isinstance(a.const, int) for a in args):
                    try:
                        c = recv.const[args[0].const:args[1].const] if len(args) == 2 else recv.const[args[0].const:]
                        return V(const=c)
                    except (IndexError, TypeError):
                        return CLEAN
                if recv.items is not None and name in ("iterator", "stream", "toArray", "ToArray", "ToList", "values", "Values"):
                    return V(recv_taint | arg_union, items=recv.items)
                return V(recv_taint | arg_union, tag=recv.tag if recv.tag in ("cookies",) else None,
                         prefix=recv.prefix if name in ("toString", "ToString") else None) if (recv_taint or arg_union) else (
                    V(prefix=recv.prefix) if name in ("toString", "ToString") and recv.prefix else CLEAN)
            if name in ("format", "Format", "join", "Join", "Concat", "valueOf", "copyValueOf", "asList", "of", "List",
                        "decode", "unescape", "unescapeHtml4", "toList", "singletonList", "singleton", "ofNullable",
                        "requireNonNull", "decodeBase64", "encodeBase64", "getDecoder", "getEncoder",
                        "encodeToString", "encodeBase64String", "FromBase64String", "GetString", "UrlDecode",
                        "HtmlDecode", "UnescapeDataString"):
                if name in ("asList", "of", "List", "singletonList", "toList") and recv.tag == "class":
                    return V(arg_union, items=tuple(args))
                if name in ("valueOf", "copyValueOf") and len(args) == 1:
                    return replace(args[0], type="String") if args[0].const is not _NOC else V(args[0].taint)
                if name in ("format", "Format") and args and isinstance(args[0].const, str) and len(args) > 1:
                    return V(arg_union, prefix=args[0].const.split("%")[0].split("{")[0])
                return V(arg_union | recv_taint) if (arg_union or recv_taint) else CLEAN
            if recv.tag in ("req", "resp", "session", "writer", "runtime"):
                return CLEAN
            if recv.tag == "class" and not arg_union:
                return CLEAN
            taint = recv_taint | arg_union
            return V(taint) if taint else CLEAN
        if self.php:
            if recv is None:
                if lname in ("explode", "str_split", "preg_split", "mb_split") and len(args) >= 2:
                    return V(args[1].taint)
                if lname in ("implode", "join") and args:
                    return V(arg_union)
                if lname == "array_keys" and args:
                    if args[0].keys is not None:
                        return CLEAN  # sabit anahtarlı dizinin anahtarları
                    # anahtarlar yalnız istek dizisinin kendisinden gelirse saldırgan denetiminde
                    return V(frozenset(t for t in args[0].taint if "…" in t.src.desc or t.src.desc.endswith("[]")))
                if lname == "settype" and len(args) >= 2 and ranges and isinstance(args[1].const, str) \
                        and args[1].const.lower() in ("int", "integer", "float", "double", "bool", "boolean"):
                    key = self.key_of(*ranges[0])
                    if key:
                        env[key] = CLEAN  # 17. tur: settype($x, "integer") yerinde sayıya çevirir
                    return CLEAN
                if lname in ("array_push",) and args and ranges:
                    key = self.key_of(*ranges[0])
                    if key:
                        cur = env.get(key, CLEAN)
                        env[key] = V(cur.taint | frozenset().union(*(x.taint for x in args[1:])))
                    return CLEAN
                if lname in ("sprintf", "vsprintf", "str_pad", "trim", "ltrim", "rtrim", "strtolower", "strtoupper",
                             "ucfirst", "lcfirst", "ucwords", "substr", "mb_substr", "stripslashes", "urldecode",
                             "rawurldecode", "base64_decode", "html_entity_decode", "htmlspecialchars_decode",
                             "json_decode", "nl2br", "strrev", "str_repeat", "wordwrap", "array_merge", "array_values",
                             "array_keys", "array_map", "array_filter", "array_slice", "array_reverse", "array_unique",
                             "current", "reset", "end", "next", "array_shift", "array_pop", "compact", "extract",
                             "iconv", "mb_convert_encoding", "utf8_decode", "utf8_encode", "stristr", "strstr",
                             "strrchr", "substr_replace", "str_word_count", "addcslashes", "quotemeta", "chunk_split",
                             "strtr", "vsprintf", "realpath", "dirname", "pathinfo", "parse_url", "http_build_query",
                             "serialize", "var_export", "array_combine", "array_fill_keys", "end"):
                    if lname == "sprintf" and args and isinstance(args[0].const, str) and len(args) > 1:
                        return self._php_sprintf(args[0].const, args)
                    return V(arg_union) if arg_union else CLEAN
                if lname in ("mysqli_error", "mysqli_connect_error", "mysql_error", "php_uname", "phpversion",
                             "session_id", "get_class", "gettype", "date", "microtime"):
                    return CLEAN
                return V(arg_union) if arg_union else CLEAN
            if recv.tag in ("req", "reqbag"):
                return CLEAN
            if _LOOKUP_FUNC.match(lname) or lname in ("get", "fetch", "find", "load", "read", "lookup", "first",
                                                      "value", "getitem", "offsetget", "retrieve"):
                return V(recv_taint) if recv_taint else CLEAN  # anahtarla arama: sonuç anahtarın taint'ini taşımaz
            taint = recv_taint | arg_union
            return V(taint) if taint else CLEAN
        return V(arg_union) if arg_union else CLEAN

    def _recv_end(self, start: int) -> int:
        """Zincirin son çağrısından önceki alıcı aralığının sonu (basit değişken çağrıları için)."""
        t = self.t
        k = start
        while k + 1 < len(t) and t[k].kind in ("id", "var") and t[k + 1].kind == "op" and t[k + 1].value in (".", "->", "?.", "?->"):
            if k + 3 < len(t) and t[k + 3].kind == "op" and t[k + 3].value == "(":
                return k + 1 if k == start else k + 1
            k += 2
        return start + 1

    # -- hedef bildirimi ---------------------------------------------------
    def _sink_in_file(self, kind: str, desc: str, path: str, line: int, v: V) -> None:
        """Hedef başka bir dosyada (JSP görünümü): istek kaynaklı iz o dosya/satırda raporlanır; parametre izi özetle
        çağırana taşınır (özetin hedef dosyası korunur)."""
        if not v.taint or kind in self.guard_kinds:
            return
        for t in _tsorted(v.taint):
            if not _unsafe(t, kind):
                continue
            s = t.src
            if s.label == "param":
                self.summary.sinks.append((s.param, kind, desc, line, path, s.via))
            else:
                self.p.add_flow(self.p.tf.Flow(self._lang_name(self.lang, self.u.dialect), kind, desc, line, s.desc,
                                               s.label, s.line, s.via, file=path, source_file=s.file),
                                privileged=self.privileged, deprecated=self.deprecated)

    def sink(self, kind: str, desc: str, line: int, v: V) -> None:
        if kind == "path" and getattr(self, "_skip_path_sink", False):
            return
        if kind == "sql":
            cs = self.lang == "csharp"
            self.p.note_sql(v, columns=cs)
            text = v.const if isinstance(v.const, str) else v.prefix
            # 25. tur: yardımcı işlevin parametresinden tabloya yazım tüm dillerde özete girer (PHP add_preview($text)…)
            table = self.p.write_table(text) if text and v.taint else None
            if table:
                entry_cols = self.p.write_columns(text) if cs else None
                for t in _tsorted(v.taint):
                    if t.src.label == "param" and (t.src.param, table, entry_cols) not in self.summary.table_writes:
                        self.summary.table_writes.append((t.src.param, table, entry_cols))
        if v.taint and kind == "html" and kind not in self.guard_kinds and self._response_html_suppressed(kind, desc):
            if self._jsonp_line(line):
                self.sink("jsonp", desc, line, v)  # JS/JSON yanıtında geri çağırma adı: JSONP (HTML olarak işlenmez)
            return
        if not v.taint or kind in self.guard_kinds or self._response_html_suppressed(kind, desc):
            return
        if kind in ("redirect", "ssrf") and _fixed_host(v.prefix, kind):
            if kind == "redirect":
                return  # aynı site içinde yol/sorgu: açık yönlendirme değil
            kind = "ssrf_partial"
        for t in _tsorted(v.taint):
            if not _unsafe(t, kind):
                continue
            s = t.src
            if s.label == "param":
                self.summary.sinks.append((s.param, kind, desc, line, self.u.path, s.via))
            else:
                self.p.add_flow(self.p.tf.Flow(self._lang_name(self.lang, self.u.dialect), kind, desc, line, s.desc, s.label,
                                               s.line, s.via, file=self.u.path, source_file=s.file),
                                privileged=self.privileged, deprecated=self.deprecated)


# ---------------------------------------------------------------------------
# Dış API
# ---------------------------------------------------------------------------
_MYBATIS_STMT = re.compile(r"<(select|update|delete|insert)\b[^>]*\bid\s*=\s*[\"']([\w.]+)[\"'][^>]*>(.*?)</\1>", re.S)
_MYBATIS_ANNOTATIONS = ("@Select", "@Update", "@Delete", "@Insert")


def _balanced_close(text: str, opening: int) -> int | None:
    """Return the matching ``)`` while respecting Java string/character literals."""
    depth = 0
    quote = ""
    index = opening
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\" and index + 1 < len(text):
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _mybatis_method_after(text: str, index: int) -> str | None:
    """Parse the method name following a MyBatis annotation without backtracking."""
    length = len(text)
    while True:
        while index < length and text[index].isspace():
            index += 1
        if index >= length or text[index] != "@":
            break

        # Sonraki Java ek açıklamalarını (Results, Deprecated vb.) atla.
        index += 1
        name_start = index
        while index < length and (text[index] == "_" or text[index] == "." or text[index].isalnum()):
            index += 1
        if index == name_start:
            return None
        while index < length and text[index].isspace():
            index += 1
        if index < length and text[index] == "(":
            closing = _balanced_close(text, index)
            if closing is None:
                return None
            index = closing + 1

    header_start = index
    allowed_punctuation = "<>[],."
    while index < length and text[index] != "(":
        char = text[index]
        if not (char.isspace() or char == "_" or char.isalnum() or char in allowed_punctuation):
            return None
        index += 1
    if index >= length:
        return None

    end = index
    while end > header_start and text[end - 1].isspace():
        end -= 1
    start = end
    while start > header_start and (text[start - 1] == "_" or text[start - 1].isalnum()):
        start -= 1
    return text[start:end] or None


def _mybatis_annotation_methods(text: str) -> set[str]:
    """Collect unsafe annotated methods with a single forward scan of Java source."""
    out: set[str] = set()
    index = 0
    length = len(text)
    while index < length:
        marker_at = text.find("@", index)
        if marker_at < 0:
            break
        marker = next((item for item in _MYBATIS_ANNOTATIONS if text.startswith(item, marker_at)), None)
        if marker is None:
            index = marker_at + 1
            continue
        cursor = marker_at + len(marker)
        if cursor < length and (text[cursor] == "_" or text[cursor].isalnum()):
            index = cursor
            continue
        while cursor < length and text[cursor].isspace():
            cursor += 1
        if cursor >= length or text[cursor] != "(":
            index = cursor
            continue
        closing = _balanced_close(text, cursor)
        if closing is None:
            # Kapanmamış Java ek açıklamasında kalan dosya aynı sözdizimsel yapının
            # parçasıdır. Kuyruğu tekrar tekrar taramadan güvenli biçimde bitir.
            break
        if "${" in text[cursor + 1:closing]:
            method = _mybatis_method_after(text, closing + 1)
            if method:
                out.add(method)
        index = closing + 1
    return out


def mybatis_unsafe_methods(texts: dict[str, str]) -> set[str]:
    """``${…}`` (ham ekleme) içeren MyBatis eşleme ifadelerinin yöntem adları (XML ve ek açıklama)."""
    out: set[str] = set()
    for path, text in texts.items():
        if path.endswith(".xml") and "<mapper" in text:
            for m in _MYBATIS_STMT.finditer(text):
                if "${" in m.group(3):
                    out.add(m.group(2).rsplit(".", 1)[-1])
        elif path.endswith(".java") and "${" in text:
            out.update(_mybatis_annotation_methods(text))
    return out


def _struts_jsp_flows(project: "Project", files: dict[str, str], pages: dict[str, set[str]]) -> None:
    """Struts2 sonuç JSP'sinde kaçışsız ``<s:property>``: eylem alanı istek parametresiyse (ayarlayıcı) ya da alana
    istek/kayıtlı veri yazılmışsa XSS. ``<s:iterator value="liste">`` içindeki özellik, liste alanının izini taşır."""
    if not pages or not project.struts_classes:
        return
    class_file = {c.name: path for path, u in project.units.items() if u.lang == "java" for c in u.classes}
    for path, text in files.items():
        if not path.endswith((".jsp", ".jspf")) or "<s:property" not in text:
            continue
        classes: set[str] = set()
        for page, owners in pages.items():
            if path == page or path.endswith("/" + page):
                classes |= owners
        classes &= project.struts_classes
        props = struts_unescaped_properties(text) if classes else []
        for line, expr, iterated in props:
            m = _STRUTS_OGNL_NAME_RE.match(expr or "")
            if not m:
                continue
            name = m.group(1)
            taint: set[T] = set()
            if name.startswith("#parameters.") or name.startswith("#request."):
                taint.add(T(Src("request", f"Struts2 {name} (istek parametresi)", line, path)))
            else:
                it = _STRUTS_OGNL_NAME_RE.match(iterated or "") if iterated is not None else None
                fields = [it.group(1).split(".")[0]] if it and not it.group(1).startswith("#") else []
                fields.append(name.split(".")[0])
                for cls in classes:
                    for field_name in fields[:1] if iterated is not None and fields[:-1] else fields:
                        setter = project.struts_fields.get(cls, {}).get(field_name)
                        if setter is not None:
                            taint.add(T(Src("request", f"Struts2 eylem alanı {field_name} (istek parametresi)", setter,
                                            class_file.get(cls, path))))
                        taint |= project.struts_field_taint.get((cls, field_name), frozenset())
            for t in _tsorted(taint):
                if not _unsafe(t, "html"):
                    continue
                s = t.src
                project.add_flow(project.tf.Flow(
                    "java", "html", f"Struts2 <s:property escape=false> ({name})", line, s.desc, s.label, s.line,
                    s.via, file=path, source_file=s.file))


_TH_UTEXT = re.compile(r"""th:utext\s*=\s*["']\s*\$\{\s*([A-Za-z_]\w*)""")
_TH_INLINE_RAW = re.compile(r"\[\(\s*\$\{\s*([A-Za-z_]\w*)")


_JSP_EL = re.compile(r"\$\{\s*([A-Za-z_]\w*)((?:\.\w+|\[[^\]]*\])*)\s*\}")
_JSP_FOREACH = re.compile(r"<c:forEach\b[^>]*>", re.I)
_JSP_ATTR = re.compile(r"""(\w+)\s*=\s*["']([^"']*)["']""")
_JSP_SKIP_ROOTS = frozenset({"param", "paramValues", "header", "headerValues", "cookie", "initParam", "pageContext",
                             "requestScope", "sessionScope", "applicationScope", "pageScope"})


def _same_site_prefix(prefix: str | None) -> bool:
    """Yönlendirme adresi sabit göreli önekle başlıyor ("/yol", "../yol", "./"): aynı sitede kalır."""
    if not prefix:
        return False
    return (prefix.startswith("/") and not prefix.startswith(("//", "/\\"))) or prefix.startswith(("../", "./", ".."))


def jsp_view_outputs(files: dict[str, str]) -> dict[str, dict[str, list[tuple[str, int, str]]]]:
    """18. tur: JSP görünümlerinde şablon METNİNDEKİ (etiket içi değil) ``${x}`` / ``${x.y}`` EL ifadeleri JSP'de kaçışsız
    basılır (``<c:out>``/``fn:escapeXml`` kaçışlıdır). Spring MVC görünüm adı (``return "home"`` → …/jsp/home.jsp,
    …/views/home.jsp) → kök model özniteliği → [(dosya, satır, ifade)]. ``<c:forEach var="ad" items="${ads}">`` takma adı
    kök özniteliğe (ads) çevrilir. ``param``/``header`` gibi örtük nesneler JSP→Java çevirisinde zaten ele alınır."""
    out: dict[str, dict[str, list[tuple[str, int, str]]]] = {}
    for path, text in files.items():
        low = path.replace("\\", "/")
        if not low.endswith((".jsp", ".jspf")) or "${" not in text:
            continue
        alias: dict[str, str] = {}
        page_vars = {m.group(1) for m in re.finditer(
            r"""<(?:c:url|c:set|fmt:\w+|spring:\w+|s:url)\b[^>]*\bvar\s*=\s*["'](\w+)["']""", text, re.I)}
        for fm in _JSP_FOREACH.finditer(text):
            attrs = dict(_JSP_ATTR.findall(fm.group(0)))
            im = _JSP_EL.search(attrs.get("items", ""))
            if attrs.get("var") and im:
                alias[attrs["var"]] = im.group(1)
        uses: dict[str, list[tuple[str, int, str]]] = {}
        for m in _JSP_EL.finditer(text):
            before = text[:m.start()]
            lt = before.rfind("<")
            if lt > before.rfind(">"):
                tag = re.match(r"</?\s*([\w:.-]+)", text[lt:lt + 40])
                if tag is None or ":" in tag.group(1) or tag.group(1).startswith("%"):
                    continue  # JSP etiketi özniteliği (c:out value, c:if test, forEach items …): çıktı değil / kaçışlı
                # düz HTML etiketinin özniteliği (<input value="${x}">): JSP bunu da kaçışsız basar
            root = m.group(1)
            if root in _JSP_SKIP_ROOTS or root.startswith("fn") or root in page_vars:
                continue  # örtük nesne / işlev / sayfa değişkeni (c:url var="x" model özniteliğini gölgeler)
            root = alias.get(root, root)
            uses.setdefault(root, []).append((path, text.count("\n", 0, m.start()) + 1, m.group(1) + m.group(2)))
        if not uses:
            continue
        stem = low[:-4] if low.endswith(".jsp") else low[:-5]
        keys = {stem.rsplit("/", 1)[-1]}
        for marker in ("/jsp/", "/views/", "/WEB-INF/", "/webapp/"):
            if marker in "/" + stem:
                keys.add(("/" + stem).split(marker, 1)[-1])
        for key in keys:
            bucket = out.setdefault(key, {})
            for root, items in uses.items():
                bucket.setdefault(root, []).extend(items)
    return out


def thymeleaf_unescaped(texts: dict[str, str]) -> dict[str, set[str]]:
    """Thymeleaf şablonları (…/templates/<görünüm>.html): ``th:utext="${x}"`` ve ``[(${x})]`` ile kaçışsız basılan
    model öznitelikleri (17. tur). Görünüm adı templates/ altındaki göreli yol (uzantısız)."""
    out: dict[str, set[str]] = {}
    for path, text in texts.items():
        low = path.replace("\\", "/")
        if not low.endswith(".html") or "/templates/" not in "/" + low:
            continue
        names = set(_TH_UTEXT.findall(text)) | set(_TH_INLINE_RAW.findall(text))
        if names:
            view = low.split("/templates/", 1)[-1] if "/templates/" in low else low.split("templates/", 1)[-1]
            out[view[:-5]] = names
    return out


_JPA_REPO = re.compile(r"interface\s+(\w+)\s+extends\s+(?:[\w.]+\.)?(?:JpaRepository|CrudRepository|"
                       r"PagingAndSortingRepository|ListCrudRepository|ListPagingAndSortingRepository|MongoRepository|"
                       r"ReactiveCrudRepository|Repository)\s*<\s*([A-Za-z_]\w*)")


def jpa_repositories(files: dict[str, str]) -> dict[str, str]:
    """Spring Data depoları: depo arayüzü → varlık türü (``interface R extends JpaRepository<Varlık, Id>``)."""
    out: dict[str, str] = {}
    for path, text in files.items():
        if path.endswith((".java", ".kt")) and "Repository" in text:
            for m in _JPA_REPO.finditer(text):
                out[m.group(1)] = m.group(2)
        if path.endswith(".java") and ("@Repository" in text or re.search(r"\bclass\s+\w+(?:Repository|Dao)\b", text)):
            # 25. tur: elle yazılmış depo/DAO sınıfı (JdbcTemplate/JDBC): insert(Varlık v)/save(Varlık v) imzası varlık
            # türünü verir; çağıranın istek verisiyle doldurduğu varlık yazılır, find*/get* kayıtlı veri döndürür.
            cm = re.search(r"\bclass\s+(\w+)", text)
            wm = _JAVA_REPO_WRITE.search(text)
            if cm and wm and cm.group(1) not in out and wm.group(1) not in _JAVA_REPO_SCALARS:
                out[cm.group(1)] = wm.group(1)
    return out


_JAVA_REPO_WRITE = re.compile(r"\b(?:public\s+)?[\w<>\[\]]+\s+(?:insert|save|create|add|persist|store)\w*\s*\(\s*"
                              r"(?:final\s+)?([A-Z]\w*)\s+\w+\s*\)")
_JAVA_REPO_SCALARS = frozenset({"String", "Integer", "Long", "Object", "Map", "List", "Date", "UUID"})


def analyze_files(files: dict[str, str], extra_texts: dict[str, str] | None = None) -> dict[str, Any]:
    """Proje dosyaları (göreli yol → metin) için dosya başına :class:`taint_flow.Analysis`."""
    import sys
    import taint_flow
    if sys.getrecursionlimit() < 6000:
        sys.setrecursionlimit(6000)
    units: dict[str, Unit] = {}
    for path, text in files.items():
        try:
            unit = lex.build_unit(path, text)
        except (RecursionError, ValueError, IndexError):
            unit = None
        if unit is not None:
            units[path] = unit
    mybatis = mybatis_unsafe_methods({**(extra_texts or {}), **{p: t for p, t in files.items() if p.endswith(".java")}})
    project = Project(units, mybatis, struts_redirect_results(extra_texts or {}))
    project.proto, project.proto_enums = proto_messages(extra_texts or {})
    project.twig_raw = {p.rsplit("/", 1)[-1] for p in (extra_texts or {}) if p.endswith(".twig")}
    project.th_views = thymeleaf_unescaped(extra_texts or {})
    project.jsp_views = jsp_view_outputs(files)
    for bucket in project.jsp_views.values():
        for root, items in bucket.items():
            seen = project.jsp_all_uses.setdefault(root, [])
            seen.extend(item for item in items if item not in seen)
    project.repo_entity = jpa_repositories(files)
    project.run()
    _struts_jsp_flows(project, files, struts_result_pages(extra_texts or {}))
    results: dict[str, Any] = {}
    for path, unit in units.items():
        results[path] = taint_flow.Analysis(unit.dialect or unit.lang)
    for flow in project.flows.values():
        analysis = results.get(flow.file)
        if analysis is not None:
            analysis.flows.append(flow)
    for key, flow in project.privileged_flows.items():
        analysis = results.get(flow.file)
        if analysis is not None and key not in project.flows:  # aynı akış yetkisiz yoldan da varsa yalnız o raporlanır
            analysis.privileged_flows.append(flow)
    for analysis in results.values():
        analysis.flows.sort(key=flow_sort_key)
        analysis.privileged_flows.sort(key=flow_sort_key)
    return results


def analyze_single(text: str, filename: str) -> Any:
    results = analyze_files({filename: text})
    return results.get(filename)
