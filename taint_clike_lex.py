"""Java, C# ve PHP için hızlı belirteçleyici ve yapı çıkarıcı (taint_clike motorunun ön ucu).

Saf Python, düzenli ifade tabanlı; derleyici ya da JVM gerektirmez. Amaç tam dilbilgisi değil, veri akışı
analizi için yeterli belirteç dizisi ve yöntem/sınıf sınırlarıdır:

* Yorumlar atılır, satır numaraları korunur.
* Dize sabitleri ``str`` belirteci olur; ara değerli dizgeler (C# ``$"…{x}…"``, PHP ``"…$x…"``, heredoc, ters
  tırnak) ``istr``/``bstr`` belirteci olur ve değerleri (sabit metin | alt belirteç listesi) parçalarıdır.
* PHP'de ``<?php … ?>`` dışı HTML atlanır; ``?>`` deyim sonu sayılır, ``<?=`` ``echo`` belirtecine çevrilir.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any

LANG_BY_SUFFIX = {".java": "java", ".cs": "csharp", ".php": "php", ".phtml": "php", ".jsp": "java", ".jspf": "java",
                  ".kt": "java", ".cshtml": "csharp", ".razor": "csharp",
                  ".aspx": "csharp", ".ascx": "csharp", ".master": "csharp", ".asmx": "csharp", ".ashx": "csharp"}
# Klasik ASP.NET: WebForms işaretlemesi (.aspx/.ascx/.master) satır korunarak C#'a çevrilir (aspx_to_cs);
# ASMX/ASHX dosyalarında yalnız <%@ … %> yönergesi boşaltılır, gerisi C# kodudur.
WEBFORMS_SUFFIXES = frozenset({".aspx", ".ascx", ".master"})
HANDLER_SUFFIXES = frozenset({".asmx", ".ashx"})
# Razor görünümleri (.cshtml) ve Blazor bileşenleri (.razor): satır numaraları korunarak C#'a çevrilir (razor_to_cs).
RAZOR_SUFFIXES = frozenset({".cshtml", ".razor"})
# Kotlin: taint_kotlin satır numaralarını koruyarak Java benzeri metne çevirir; Java motoru (lehçe "kotlin") çalışır.
KOTLIN_SUFFIXES = frozenset({".kt"})
JSP_SUFFIXES = frozenset({".jsp", ".jspf"})


@dataclass(frozen=True, slots=True)
class Tok:
    kind: str  # id | var | str | istr | bstr | num | op
    value: Any
    line: int


_OPS = ["===", "!==", "<=>", "??=", "...", "?->", "->", "::", "++", "--", "&&", "||", "==", "!=", "<=", ">=",
        "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", ".=", "=>", "??", "?.", "**"]
_OP_PATTERN = "|".join(re.escape(op) for op in _OPS) + r"|[{}()\[\];,.<>=+\-*/%!~?:&|^@\\]"
_NUM = r"0[xXbB][0-9a-fA-F_]+[lLuU]*|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?[fFdDlLmMuU]*|\.\d+[fFdDmM]?"

_JAVA_RE = re.compile(
    r'(?P<nl>\n)|(?P<ws>[ \t\r\f\v]+)|(?P<lc>//[^\n]*)|(?P<bc>/\*.*?(?:\*/|\Z))'
    r'|(?P<tb>"""(?:\\.|[^\\])*?""")|(?P<str>"(?:\\.|[^"\\\n])*")|(?P<chr>\'(?:\\.|[^\'\\\n])*\')'
    rf"|(?P<num>{_NUM})|(?P<id>[A-Za-z_$\u0080-\uffff][\w$\u0080-\uffff]*)|(?P<op>{_OP_PATTERN})|(?P<other>.)",
    re.S,
)
_CS_RE = re.compile(
    r'(?P<nl>\n)|(?P<ws>[ \t\r\f\v]+)|(?P<lc>//[^\n]*)|(?P<bc>/\*.*?(?:\*/|\Z))|(?P<pp>\#[^\n]*)'
    r'|(?P<iraw>\$+"""(?:.|\n)*?""")|(?P<istart>\$+@?"|@\$+")|(?P<raw>"""(?:.|\n)*?""")|(?P<vstr>@"(?:[^"]|"")*")'
    r'|(?P<str>"(?:\\.|[^"\\\n])*")|(?P<chr>\'(?:\\.|[^\'\\\n])*\')'
    rf"|(?P<num>{_NUM})|(?P<id>@?[A-Za-z_\u0080-\uffff][\w\u0080-\uffff]*)|(?P<op>{_OP_PATTERN})|(?P<other>.)",
    re.S,
)
_PHP_ID = r"[A-Za-z_\u0080-\uffff][\w\u0080-\uffff]*"
_PHP_RE = re.compile(
    r'(?P<nl>\n)|(?P<ws>[ \t\r\f\v]+)|(?P<close>\?>\n?)|(?P<attr>\#\[[^\]\n]*\])'
    r'|(?P<lc>(?://|\#)[^\n]*?(?=\?>|\n|\Z))|(?P<bc>/\*.*?(?:\*/|\Z))'
    r"|(?P<sq>'(?:\\.|[^'\\])*')|(?P<dq>\")|(?P<bt>`)|(?P<here><<<[ \t]*(?:\"|')?(?P<hid>" + _PHP_ID + r")(?:\"|')?\r?\n)"
    rf"|(?P<cast>\(\s*(?:int|integer|float|double|bool|boolean|string|array|object)\s*\))"
    rf"|(?P<num>{_NUM})|(?P<var>\$" + _PHP_ID + r")"
    r"|(?P<id>\\?" + _PHP_ID + r"(?:\\" + _PHP_ID + r")*)"
    rf"|(?P<op>{_OP_PATTERN}|\$)|(?P<other>.)",
    re.S,
)


def _unquote_c(body: str) -> str:
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t", "r": "\r", "0": "\0"}.get(m.group(1), m.group(1)), body)


def tokenize(text: str, lang: str, line: int = 1) -> list[Tok]:
    if lang == "php":
        return _tokenize_php(text, line)
    return _tokenize_c(text, lang, line)


def _tokenize_c(text: str, lang: str, line: int) -> list[Tok]:
    pattern = _CS_RE if lang == "csharp" else _JAVA_RE
    toks: list[Tok] = []
    pos, end = 0, len(text)
    while pos < end:
        m = pattern.match(text, pos)
        if m is None:  # pragma: no cover - "other" her karakteri yakalar
            break
        kind = m.lastgroup
        value = m.group()
        if kind == "nl":
            line += 1
        elif kind in ("ws",):
            pass
        elif kind in ("lc", "bc", "pp"):
            line += value.count("\n")
        elif kind == "str":
            toks.append(Tok("str", _unquote_c(value[1:-1]), line))
        elif kind == "tb" or kind == "raw":
            toks.append(Tok("str", value[3:-3], line))
            line += value.count("\n")
        elif kind == "vstr":
            toks.append(Tok("str", value[2:-1].replace('""', '"'), line))
            line += value.count("\n")
        elif kind == "chr":
            toks.append(Tok("str", _unquote_c(value[1:-1]), line))
        elif kind == "iraw":
            toks.append(_cs_raw_interpolated(value, line))
            line += value.count("\n")
        elif kind == "istart":
            tok, new_pos, new_line = _scan_cs_interpolated(text, m.end(), line, "@" in value)
            toks.append(tok)
            pos, line = new_pos, new_line
            continue
        elif kind == "num":
            toks.append(Tok("num", value, line))
        elif kind == "id":
            toks.append(Tok("id", value.lstrip("@"), line))
        elif kind == "op":
            toks.append(Tok("op", value, line))
        pos = m.end()
    return toks


def _cs_raw_interpolated(value: str, line: int) -> Tok:
    """C# 11 ham ara değerli dize: ``$\"\"\"…{x}…\"\"\"`` (N tane $ → delikler N süslü parantezle)."""
    dollars = len(value) - len(value.lstrip("$"))
    body = value[dollars + 3:-3]
    opener, closer = "{" * dollars, "}" * dollars
    parts: list[Any] = []
    k = 0
    while k < len(body):
        i = body.find(opener, k)
        if i < 0:
            parts.append(body[k:])
            break
        while body.startswith("{", i + dollars):  # fazladan süslü parantez metindir
            i += 1
        j = body.find(closer, i + dollars)
        if j < 0:
            parts.append(body[k:])
            break
        if i > k:
            parts.append(body[k:i])
        expr = body[i + dollars:j]
        parts.append(_tokenize_c(expr, "csharp", line + body[:i].count("\n")))
        k = j + dollars
    return Tok("istr", tuple(parts), line)


def _scan_cs_interpolated(text: str, pos: int, line: int, verbatim: bool) -> tuple[Tok, int, int]:
    parts: list[Any] = []
    buf: list[str] = []
    n = len(text)
    while pos < n:
        c = text[pos]
        if c == '"':
            if verbatim and text.startswith('""', pos):
                buf.append('"')
                pos += 2
                continue
            pos += 1
            break
        if c == "\\" and not verbatim and pos + 1 < n:
            buf.append(_unquote_c(text[pos:pos + 2]))
            pos += 2
            continue
        if c == "{":
            if text.startswith("{{", pos):
                buf.append("{")
                pos += 2
                continue
            depth, j = 1, pos + 1
            while j < n and depth:
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                elif text[j] == '"':
                    j = text.find('"', j + 1)
                    if j < 0:
                        j = n
                j += 1
            expr = text[pos + 1:j - 1]
            if buf:
                parts.append("".join(buf))
                buf = []
            parts.append(_tokenize_c(expr, "csharp", line))
            line += expr.count("\n")
            pos = j
            continue
        if c == "}" and text.startswith("}}", pos):
            buf.append("}")
            pos += 2
            continue
        if c == "\n":
            line += 1
        buf.append(c)
        pos += 1
    if buf:
        parts.append("".join(buf))
    return Tok("istr", tuple(parts), line), pos, line


_PHP_SIMPLE_VAR = re.compile(r"\$" + _PHP_ID + r"(?:\[[^\]\n]*\]|->" + _PHP_ID + r")?")


def _scan_php_interpolated(text: str, pos: int, line: int, end_char: str | None, heredoc_id: str | None
                           ) -> tuple[list[Any], int, int]:
    """Çift tırnak / ters tırnak / heredoc gövdesi: parçalar (metin | belirteç listesi)."""
    parts: list[Any] = []
    buf: list[str] = []
    n = len(text)
    start_line = line
    closing = re.compile(r"[ \t]*" + re.escape(heredoc_id) + r"\b") if heredoc_id else None
    at_line_start = True
    while pos < n:
        if closing is not None and at_line_start:
            m = closing.match(text, pos)
            if m:
                pos = m.end()
                break
        c = text[pos]
        at_line_start = False
        if end_char is not None and c == end_char:
            pos += 1
            break
        if c == "\\" and pos + 1 < n:
            nxt = text[pos + 1]
            buf.append({"n": "\n", "t": "\t", "r": "\r", "$": "$", '"': '"', "\\": "\\", "`": "`"}.get(nxt, "\\" + nxt))
            pos += 2
            continue
        if c == "$":
            m = _PHP_SIMPLE_VAR.match(text, pos)
            if m:
                expr = m.group()
                if "[" in expr:  # "$a[key]" içinde tırnaksız anahtar sabit dizedir
                    base, key = expr.split("[", 1)
                    key = key[:-1].strip()
                    if key and not key.startswith(("$", "'", '"')) and not key.lstrip("-").isdigit():
                        key = "'" + key + "'"
                    expr = f"{base}[{key}]"
                if buf:
                    parts.append("".join(buf))
                    buf = []
                parts.append(_tokenize_php_code(expr, line))
                pos = m.end()
                continue
            if text.startswith("${", pos):
                j = text.find("}", pos)
                if j > 0:
                    inner = text[pos + 2:j].strip()
                    expr = "$" + inner if re.fullmatch(_PHP_ID, inner) else inner
                    if buf:
                        parts.append("".join(buf))
                        buf = []
                    parts.append(_tokenize_php_code(expr, line))
                    pos = j + 1
                    continue
        if c == "{" and text.startswith("{$", pos):
            depth, j = 1, pos + 1
            while j < n and depth:
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                j += 1
            expr = text[pos + 1:j - 1]
            if buf:
                parts.append("".join(buf))
                buf = []
            parts.append(_tokenize_php_code(expr, line))
            line += expr.count("\n")
            pos = j
            continue
        if c == "\n":
            line += 1
            at_line_start = True
        buf.append(c)
        pos += 1
    if buf:
        parts.append("".join(buf))
    del start_line
    return parts, pos, line


def _tokenize_php_code(code: str, line: int) -> list[Tok]:
    toks, _ = _php_code(code, 0, line, in_string=True)
    return toks


def _tokenize_php(text: str, line: int) -> list[Tok]:
    toks: list[Tok] = []
    pos, n = 0, len(text)
    while pos < n:
        j = text.find("<?", pos)
        if j < 0:
            break
        line += text.count("\n", pos, j)
        if text.startswith("<?=", j):
            toks.append(Tok("id", "echo", line))
            pos = j + 3
        elif text.startswith("<?php", j):
            pos = j + 5
        elif text.startswith("<?xml", j):
            pos = j + 2
            continue
        else:
            pos = j + 2
        code_toks, (pos, line) = _php_code(text, pos, line, in_string=False)
        toks.extend(code_toks)
    return toks


def _php_code(text: str, pos: int, line: int, *, in_string: bool) -> tuple[list[Tok], tuple[int, int]]:
    toks: list[Tok] = []
    n = len(text)
    while pos < n:
        m = _PHP_RE.match(text, pos)
        if m is None:  # pragma: no cover
            break
        kind = m.lastgroup
        value = m.group()
        if kind == "nl":
            line += 1
        elif kind == "ws":
            pass
        elif kind == "close":
            toks.append(Tok("op", ";", line))
            line += value.count("\n")
            return toks, (m.end(), line)
        elif kind in ("lc", "bc", "attr"):
            line += value.count("\n")
        elif kind == "sq":
            body = value[1:-1].replace("\\'", "'").replace("\\\\", "\\")
            toks.append(Tok("str", body, line))
            line += value.count("\n")
        elif kind in ("dq", "bt"):
            parts, new_pos, new_line = _scan_php_interpolated(text, m.end(), line, value, None)
            tok_kind = "bstr" if kind == "bt" else ("istr" if any(not isinstance(p, str) for p in parts) else "str")
            toks.append(Tok(tok_kind, "".join(parts) if tok_kind == "str" else tuple(parts), line))
            pos, line = new_pos, new_line
            continue
        elif kind == "here":
            hid = m.group("hid")
            nowdoc = "'" in value
            body_line = line + 1
            if nowdoc:
                close = re.compile(r"^[ \t]*" + re.escape(hid) + r"\b", re.M)
                cm = close.search(text, m.end())
                end = cm.start() if cm else n
                toks.append(Tok("str", text[m.end():end], line))
                line = body_line + text.count("\n", m.end(), end)
                pos = cm.end() if cm else n
                continue
            parts, new_pos, new_line = _scan_php_interpolated(text, m.end(), body_line, None, hid)
            tok_kind = "istr" if any(not isinstance(p, str) for p in parts) else "str"
            toks.append(Tok(tok_kind, "".join(parts) if tok_kind == "str" else tuple(parts), line))
            pos, line = new_pos, new_line
            continue
        elif kind == "cast":
            toks.append(Tok("op", "(", line))
            toks.append(Tok("id", re.sub(r"[()\s]", "", value).lower(), line))
            toks.append(Tok("op", ")", line))
        elif kind == "num":
            toks.append(Tok("num", value, line))
        elif kind == "var":
            toks.append(Tok("var", value, line))
        elif kind == "id":
            toks.append(Tok("id", value, line))
        elif kind == "op":
            toks.append(Tok("op", value, line))
        pos = m.end()
    return toks, (pos, line)


# ---------------------------------------------------------------------------
# Yapı: parantez eşleme, sınıflar, yöntemler
# ---------------------------------------------------------------------------
_OPEN = {"(": ")", "[": "]", "{": "}"}
_CLOSE = {")", "]", "}"}


def match_pairs(toks: list[Tok]) -> dict[int, int]:
    """Açılış ↔ kapanış dizinleri (iki yönlü). Dengesiz kod için en iyi çaba."""
    pairs: dict[int, int] = {}
    stack: list[int] = []
    for i, t in enumerate(toks):
        if t.kind != "op":
            continue
        v = t.value
        if v in _OPEN:
            stack.append(i)
        elif v in _CLOSE:
            while stack:
                j = stack.pop()
                if _OPEN[toks[j].value] == v:
                    pairs[j] = i
                    pairs[i] = j
                    break
    return pairs


_NOT_METHOD = frozenset({
    "if", "for", "while", "switch", "catch", "using", "lock", "foreach", "return", "new", "synchronized", "sizeof",
    "typeof", "nameof", "default", "base", "this", "super", "else", "do", "try", "fixed", "checked", "unchecked",
    "when", "throw", "await", "yield", "assert", "case", "in", "is", "as", "with", "stackalloc", "function", "fn",
    "match", "isset", "unset", "empty", "array", "list", "echo", "print", "exit", "die", "eval", "include",
    "require", "include_once", "require_once", "elseif", "declare", "throws", "where", "select", "from",
})
# PHP'ye özgü dil yapıları (list(), print, echo, empty …) Java/C#'ta sıradan yöntem adıdır (ör. Struts2 list()):
# yöntem bildirimi taramasında yalnız ilgili dilin anahtar sözcükleri dışlanır.
_PHP_ONLY_WORDS = frozenset({"isset", "unset", "empty", "array", "list", "echo", "print", "exit", "die", "eval",
                             "include", "require", "include_once", "require_once", "elseif", "declare", "function",
                             "fn", "match"})
_NOT_METHOD_BY_LANG = {
    "java": _NOT_METHOD - _PHP_ONLY_WORDS - {"select", "from", "where", "with", "when", "using", "lock", "fixed",
                                             "checked", "unchecked", "stackalloc", "nameof", "is", "as", "in"},
    "csharp": _NOT_METHOD - _PHP_ONLY_WORDS,
}
_PARAM_MODIFIERS = frozenset({"final", "ref", "out", "in", "params", "this", "readonly", "scoped", "public",
                              "private", "protected", "var"})
PARAM_MODIFIERS_BY_LANG = {
    "java": frozenset({"final"}),
    "csharp": frozenset({"ref", "out", "in", "params", "this", "readonly", "scoped"}),
    "php": frozenset({"public", "private", "protected", "readonly"}),
}


@dataclass
class Param:
    name: str
    type: str
    annotations: frozenset[str]
    line: int


@dataclass
class Method:
    name: str
    cls: str | None
    params: list[Param]
    body: tuple[int, int]  # belirteç aralığı [başlangıç, bitiş)
    expr_body: bool
    line: int
    annotations: frozenset[str]
    modifiers: frozenset[str]
    ret_type: str
    toplevel: bool = False


@dataclass
class ClassInfo:
    name: str
    start: int
    end: int
    annotations: frozenset[str]
    bases: frozenset[str]
    fields: dict[str, str] = field(default_factory=dict)  # alan adı → basit tür
    # C# özellikleri: ad → (basit tür, ek açıklamalar, satır) — [BindProperty]/[FromQuery] bağlı özellikler için
    props: dict[str, tuple[str, frozenset[str], int]] = field(default_factory=dict)
    # 18. tur: sabit dize alanları (``static final String LOCATION = "Location";``) → ad → değer
    consts: dict[str, str] = field(default_factory=dict)


@dataclass
class Unit:
    path: str
    lang: str
    toks: list[Tok]
    pairs: dict[int, int]
    classes: list[ClassInfo]
    methods: list[Method]
    text_flags: frozenset[str]
    dialect: str = ""  # "kotlin": Java motoru Kotlin çevirisi üzerinde (Kotlin'e özgü kaynak/hedefler)
    razor: bool = False  # Razor görünümü/Blazor bileşeni çevirisi (razor_to_cs)
    view_model: str = ""  # Razor @model türü (genel türde iç tür: IEnumerable<BlogEntry> → BlogEntry)
    aspx: bool = False  # WebForms işaretlemesi çevirisi (aspx_to_cs): sayfa sınıfının alanları arka koddan okunur


def _simple_type(name: str) -> str:
    return name.replace("\\", ".").rsplit(".", 1)[-1]


def _skip_generic(toks: list[Tok], i: int, j: int) -> int:
    """``i`` bir ``<`` ise eşleşen ``>`` sonrasını döndür (yoksa i)."""
    if i >= j or toks[i].value != "<" or toks[i].kind != "op":
        return i
    depth = 0
    k = i
    while k < j:
        v = toks[k].value if toks[k].kind == "op" else None
        if v == "<":
            depth += 1
        elif v == ">":
            depth -= 1
            if depth == 0:
                return k + 1
        elif v in (";", "{", "}", "(", ")", "="):
            return i
        k += 1
    return i


def split_top(toks: list[Tok], pairs: dict[int, int], i: int, j: int, sep: str = ",", angle: bool = False
              ) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    start = i
    k = i
    depth_angle = 0
    while k < j:
        t = toks[k]
        if t.kind == "op":
            v = t.value
            if v in _OPEN and k in pairs:
                k = pairs[k] + 1
                continue
            if angle and v == "<":
                depth_angle += 1
            elif angle and v == ">" and depth_angle:
                depth_angle -= 1
            elif v == sep and not depth_angle:
                out.append((start, k))
                start = k + 1
        k += 1
    if start < j or out:
        out.append((start, j))
    return [r for r in out if r[0] < r[1]]


_ADMIN_ROLE = re.compile(r"(?i)admin|elevat|superuser|sysop|root|owner")


def _annotations_before(toks: list[Tok], pairs: dict[int, int], k: int, lang: str) -> tuple[set[str], set[str], str]:
    """Yöntem/sınıf adından geriye: ek açıklamalar (@X, [X]), niteleyiciler ve dönüş türü."""
    annotations: set[str] = set()
    modifiers: set[str] = set()
    ret_type = ""
    i = k - 1
    bracket_depth = 0
    while i >= 0:
        t = toks[i]
        if t.kind == "op":
            v = t.value
            if v in (";", "{", "}") and bracket_depth == 0:
                break
            if v == ")" and i in pairs:
                op = pairs[i]
                if op > 0 and toks[op - 1].kind == "id" and \
                        toks[op - 1].value.lower().removesuffix("attribute") == "authorize" and \
                        any(x.kind in ("str", "id") and _ADMIN_ROLE.search(str(x.value)) for x in toks[op:i]):
                    # [Authorize(Roles = "Admin")] / Policy = "…Admin…" / Policies.RequiresElevation
                    annotations.add("authorize_admin")
                i = op - 1
                continue
            if v == "]":
                bracket_depth += 1
            elif v == "[":
                bracket_depth = max(0, bracket_depth - 1)
                if i + 1 < k and toks[i + 1].kind == "id":
                    annotations.add(toks[i + 1].value.lower().removesuffix("attribute"))
            elif v == "," and bracket_depth and i + 1 < k and toks[i + 1].kind == "id":
                annotations.add(toks[i + 1].value.lower().removesuffix("attribute"))
            elif v == ">" and not ret_type:
                # Genel dönüş türü: Task<IActionResult> → Task
                depth = 0
                j = i
                while j >= 0:
                    if toks[j].kind == "op" and toks[j].value == ">":
                        depth += 1
                    elif toks[j].kind == "op" and toks[j].value == "<":
                        depth -= 1
                        if depth == 0:
                            break
                    j -= 1
                if j > 0 and toks[j - 1].kind == "id":
                    ret_type = toks[j - 1].value
                    i = j - 2
                    continue
        elif t.kind == "id":
            if i > 0 and toks[i - 1].kind == "op" and toks[i - 1].value == "@":
                # Paket nitelikli ek açıklama (@org.springframework….GetMapping): son ad
                j = i
                while j + 2 < k and toks[j + 1].kind == "op" and toks[j + 1].value == "." and toks[j + 2].kind == "id":
                    j += 2
                annotations.add(toks[j].value.rsplit(".", 1)[-1].lower())
            elif bracket_depth == 0:
                low = t.value.lower()
                if low in {"public", "private", "protected", "static", "final", "abstract", "virtual", "override",
                           "async", "sealed", "internal", "synchronized", "native", "default", "partial", "extern",
                           "unsafe", "new", "readonly", "strictfp", "transient", "volatile"}:
                    modifiers.add(low)
                elif not ret_type and i == k - 1:
                    ret_type = t.value
                elif not ret_type and toks[i + 1].kind == "op" and toks[i + 1].value in ("[", "."):
                    ret_type = t.value
        i -= 1
    del lang
    return annotations, modifiers, ret_type


def parse_params(toks: list[Tok], pairs: dict[int, int], i: int, j: int, lang: str) -> list[Param]:
    params: list[Param] = []
    for a, b in split_top(toks, pairs, i, j, ",", angle=lang != "php"):
        annotations: set[str] = set()
        names: list[Tok] = []
        type_name = ""
        k = a
        while k < b:
            t = toks[k]
            if t.kind == "op" and t.value == "@" and k + 1 < b and toks[k + 1].kind == "id":
                annotations.add(toks[k + 1].value.rsplit(".", 1)[-1].lower())
                k += 2
                if k < b and toks[k].kind == "op" and toks[k].value == "(" and k in pairs:
                    k = pairs[k] + 1
                continue
            if t.kind == "op" and t.value == "[" and k in pairs and lang == "csharp":
                for x in range(k + 1, pairs[k]):
                    if toks[x].kind == "id" and toks[x - 1].kind == "op" and toks[x - 1].value in ("[", ","):
                        annotations.add(toks[x].value.lower().removesuffix("attribute"))
                k = pairs[k] + 1
                continue
            if t.kind == "op" and t.value == "=":
                break
            if t.kind == "op" and t.value == "<":
                k = _skip_generic(toks, k, b)
                if toks[k - 1].value != ">":
                    k += 1
                continue
            if t.kind in ("id", "var"):
                if t.kind == "id" and (t.value.lower() if lang == "php" else t.value) in PARAM_MODIFIERS_BY_LANG[lang]:
                    k += 1
                    continue
                names.append(t)
            k += 1
        if not names:
            continue
        if lang == "php":
            var = next((t for t in reversed(names) if t.kind == "var"), None)
            if var is None:
                continue
            types = [t.value for t in names if t.kind == "id"]
            type_name = _simple_type(types[-1]) if types else ""
            params.append(Param(var.value, type_name, frozenset(annotations), var.line))
        else:
            name = names[-1]
            type_name = _simple_type(names[-2].value) if len(names) >= 2 else ""
            params.append(Param(name.value, type_name, frozenset(annotations), name.line))
    return params


def _find_classes(toks: list[Tok], pairs: dict[int, int], lang: str) -> list[ClassInfo]:
    classes: list[ClassInfo] = []
    for i, t in enumerate(toks):
        if t.kind != "id" or t.value not in ("class", "interface", "enum", "record", "struct", "trait"):
            continue
        if i + 1 >= len(toks) or toks[i + 1].kind != "id":
            continue
        if i > 0 and toks[i - 1].kind == "op" and toks[i - 1].value in (".", "::", "->"):
            continue
        name = toks[i + 1].value
        k = i + 2
        bases: set[str] = set()
        depth = 0
        while k < len(toks) and not (toks[k].kind == "op" and toks[k].value in ("{", ";")):
            if toks[k].kind == "op" and toks[k].value == "(" and k in pairs:
                k = pairs[k] + 1
                continue
            if toks[k].kind == "op" and toks[k].value in ("<", ">", ">>"):
                depth = max(0, depth + (1 if toks[k].value == "<" else -len(toks[k].value)))
                k += 1
                continue
            # Genel tür argümanları (ItemResolver<MediaBrowser.Controller.X>) ve ad alanı nitelikleri taban değil
            if depth == 0 and toks[k].kind == "id" and toks[k].value not in ("extends", "implements", "where", "new") \
                    and not (k + 1 < len(toks) and toks[k + 1].kind == "op" and toks[k + 1].value in (".", "::", "\\")):
                bases.add(_simple_type(toks[k].value))
            k += 1
        if k >= len(toks) or toks[k].value != "{" or k not in pairs:
            continue
        annotations, _mods, _ret = _annotations_before(toks, pairs, i, lang)
        classes.append(ClassInfo(name, k, pairs[k], frozenset(annotations), frozenset(bases)))
    return classes


def _class_fields(toks: list[Tok], pairs: dict[int, int], cls: ClassInfo, method_ranges: list[tuple[int, int]],
                  lang: str) -> None:
    """Sınıf gövdesindeki ``Tür ad;`` / ``Tür ad = …;`` alan bildirimleri (yöntem gövdeleri dışında)."""
    k = cls.start + 1
    blocked = sorted(method_ranges)
    bi = 0
    while k < cls.end:
        while bi < len(blocked) and blocked[bi][1] <= k:
            bi += 1
        if bi < len(blocked) and blocked[bi][0] <= k < blocked[bi][1]:
            k = blocked[bi][1]
            continue
        t = toks[k]
        if t.kind == "op" and t.value in ("{",) and k in pairs and k != cls.start:
            k = pairs[k] + 1
            continue
        if t.kind in ("id", "var") and k + 1 < cls.end and toks[k + 1].kind == "op" and toks[k + 1].value in (";", "="):
            prev = k - 1
            if prev > cls.start and toks[prev].kind == "op" and toks[prev].value == ">":
                j = prev
                depth = 0
                while j > cls.start:
                    if toks[j].value == ">":
                        depth += 1
                    elif toks[j].value == "<":
                        depth -= 1
                        if depth == 0:
                            break
                    j -= 1
                prev = j - 1
            if prev > cls.start and toks[prev].kind == "id":
                cls.fields[t.value.lstrip("$")] = _simple_type(toks[prev].value)
                if toks[k + 1].value == "=" and k + 3 < cls.end and toks[k + 2].kind == "str" and \
                        toks[k + 3].kind == "op" and toks[k + 3].value == ";" and \
                        any(toks[x].kind == "id" and toks[x].value in ("final", "const", "readonly")
                            for x in range(max(cls.start + 1, prev - 4), prev)):
                    cls.consts[t.value.lstrip("$")] = str(toks[k + 2].value)
        k += 1
    del lang


# ---------------------------------------------------------------------------
# JSP → Java (satır numaraları korunarak)
# ---------------------------------------------------------------------------
_JSP_PARAMS = "HttpServletRequest request, HttpServletResponse response, {writer} out, HttpSession session"
_JSP_OPEN = "public void _jspService{n}(" + _JSP_PARAMS + ") throws Exception {{ "
_JSP_MARK = re.compile(r"<%--|<%[@!=]?|<(jsp:(?:include|forward))\b|<[A-Za-z][\w.-]*:[A-Za-z][\w.-]*\b|[$#]\{")
_JSP_CONTENT_TYPE = re.compile(r"""contentType\s*=\s*["']\s*([\w.+-]+/[\w.+-]+)""")
_JSP_PAGE_ATTR = re.compile(r"""\bpage\s*=\s*(["'])(.*?)\1""", re.S)
_EL_REQUEST = re.compile(r"""^\s*(param|header)\s*(?:\.\s*([A-Za-z_][\w-]*)|\[\s*["']([^"']+)["']\s*\])\s*$""")


def _nl(text: str) -> str:
    return "\n" * text.count("\n")


def _jsp_end(text: str, start: int, closer: str) -> int:
    end = text.find(closer, start)
    return len(text) if end < 0 else end


def _jsp_tag_end(text: str, k: int) -> int:
    """Özel etiketin kapanan ``>`` konumu (öznitelik içindeki ``<% … %>`` ve tırnaklar atlanır)."""
    n, quote = len(text), ""
    while k < n:
        if text.startswith("<%", k):
            k = _jsp_end(text, k + 2, "%>") + 2
            continue
        c = text[k]
        if quote:
            if c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c == ">":
            return k
        k += 1
    return n


def _el_source(expr: str) -> str | None:
    """EL ifadesi doğrudan istek değeri ise (``param.x``, ``header['x']``) Java karşılığı."""
    m = _EL_REQUEST.match(expr)
    if not m:
        return None
    name = (m.group(2) or m.group(3) or "").replace('"', "")
    return f'request.{"getParameter" if m.group(1) == "param" else "getHeader"}("{name}")'


def jsp_to_java(text: str) -> str:
    """JSP sayfasını analiz edilebilir Java'ya çevirir; her parça aynı satırda kalır.

    * ``<% kod %>`` olduğu gibi, ``<%= ifade %>`` → ``out.print(ifade);`` (JSP'de ifade çıktısı kaçışsızdır),
      ``<%! bildirim %>`` sınıf düzeyine (yöntem kapatılıp yeniden açılır); yönerge ve yorumlar boşaltılır.
    * Şablon metnindeki ``${param.x}`` / ``${header.x}`` kaçışsız çıktıdır (``c:out`` / ``fn:escapeXml`` değil).
    * ``<jsp:include|forward page="<%= … %>">`` dinamik sayfa yolu: ``jsp_include(…)`` yol hedefi.
    * Diğer özel etiketlerin (``c:out``, ``c:if``, form etiketleri …) öznitelikleri çıktı sayılmaz.
    * ``contentType`` HTML değilse (JSON/düz metin) ``out`` yazıcı değildir: XSS hedefi oluşmaz.
    """
    ctype = _JSP_CONTENT_TYPE.search(text)
    html = ctype is None or any(x in ctype.group(1).lower() for x in ("html", "xml"))
    writer = "JspWriter" if html else "Object"
    count = 0
    out = ["public class __JspPage { " + _JSP_OPEN.format(n="", writer=writer)]
    k, n = 0, len(text)
    while k < n:
        m = _JSP_MARK.search(text, k)
        if m is None:
            out.append(_nl(text[k:]))
            break
        out.append(_nl(text[k:m.start()]))
        tok = m.group(0)
        if tok == "<%--":
            end = _jsp_end(text, m.end(), "--%>")
            out.append(_nl(text[m.start():end]))
            k = end + 4
        elif tok.startswith("<%"):
            end = _jsp_end(text, m.end(), "%>")
            body = text[m.end():end]
            if tok == "<%@":
                out.append(_nl(body))
            elif tok == "<%=":
                out.append(f" out.print({body}); " if body.strip() else _nl(body))
            elif tok == "<%!":
                count += 1
                out.append(" } " + body + " " + _JSP_OPEN.format(n=count, writer=writer))
            else:
                # Gövdenin son satırındaki // yorumu aynı satıra eklenecek sonraki parçayı yutmasın.
                out.append(re.sub(r"//[^\n\"']*$", "", body) + " ")
            k = end + 2
        elif tok[0] in "$#":
            depth, j = 1, m.end()
            while j < n and depth:
                depth += {"{": 1, "}": -1}.get(text[j], 0)
                j += 1
            expr = text[m.end():j - 1]
            src = _el_source(expr)
            out.append(f" out.print({src}); " if src else _nl(expr))
            k = j
        else:
            end = _jsp_tag_end(text, m.end())
            tag = text[m.start():end]
            if m.group(1):
                page = _JSP_PAGE_ATTR.search(tag)
                value = page.group(2).strip() if page else ""
                if value.startswith("<%=") and value.endswith("%>"):
                    out.append(f" jsp_include({value[3:-2]}); ")
                else:
                    src = _el_source(value[2:-1]) if value.startswith("${") and value.endswith("}") else None
                    out.append(f" jsp_include({src}); " if src else "")
            out.append(_nl(tag))
            k = end + 1
    out.append(" } }")
    return "".join(out)


# ---------------------------------------------------------------------------
# WebForms (.aspx/.ascx/.master) → C# (satır numaraları korunarak)
# ---------------------------------------------------------------------------
_ASPX_DIRECTIVE = re.compile(r"<%@.*?%>", re.S)
_ASPX_VB = re.compile(r"""<%@[^%]*\bLanguage\s*=\s*["']?(?:VB|VBScript|vb\.net)\b""", re.I)
_ASPX_MARK = re.compile(r"<%--|<%[@=:#$]?|<script\b[^>]*?\brunat\s*=\s*[\"']?server\b[^>]*>", re.I)
_ASPX_INHERITS = re.compile(r"""<%@\s*(?:Page|Control|Master)\b[^%]*?\bInherits\s*=\s*["']\s*([\w.`+]+)""", re.I | re.S)
_ASPX_OPEN = "public void __RenderAspx{n}() {{ "
_ASPX_SCRIPT_END = re.compile(r"</script\s*>", re.I)


def aspx_to_cs(text: str, path: str = "") -> str:
    """WebForms sayfası/denetimi/ana sayfası → C#; her parça aynı satırda kalır.

    * ``<%= ifade %>`` kaçışsız çıktıdır → ``Response.Write(ifade);`` (HTML hedefi).
    * ``<%: ifade %>`` (HTML kodlanır), ``<%# … %>`` veri bağlama, ``<%$ … %>`` ifade oluşturucuları, yönergeler ve
      yorumlar boşaltılır; ``<% kod %>`` olduğu gibi kalır.
    * ``<script runat="server">`` üyeleri sınıf düzeyine taşınır (JSP ``<%!`` gibi; yöntem kapatılıp yeniden açılır).
    * Sınıf adı ``Inherits`` yönergesinden: arka kod (``partial class X : Page``) ile aynı sınıf; sayfa alanlarına
      Page_Load içinde yazılan istek verisi işaretlemede okunur (taint_clike: model_props).
    """
    text = text.lstrip("\ufeff")
    m = _ASPX_INHERITS.search(text)
    stem = path.replace("\\", "/").rsplit("/", 1)[-1].split(".", 1)[0]
    cls = m.group(1).rsplit(".", 1)[-1] if m else "__Aspx_" + (re.sub(r"\W", "_", stem) or "Page")
    low = path.lower()
    base = "MasterPage" if low.endswith(".master") else "UserControl" if low.endswith(".ascx") else "Page"
    count = 0
    out = [f"public partial class {cls} : {base} {{ " + _ASPX_OPEN.format(n="")]
    k, n = 0, len(text)
    while k < n:
        mk = _ASPX_MARK.search(text, k)
        if mk is None:
            out.append(_nl(text[k:]))
            break
        out.append(_nl(text[k:mk.start()]))
        tok = mk.group(0)
        if tok == "<%--":
            end = _jsp_end(text, mk.end(), "--%>")
            out.append(_nl(text[mk.start():end]))
            k = end + 4
        elif tok.startswith("<%"):
            end = _jsp_end(text, mk.end(), "%>")
            body = text[mk.end():end]
            if tok == "<%=" and body.strip():
                out.append(f" Response.Write({body}); ")
            elif tok in ("<%@", "<%:", "<%#", "<%$", "<%="):
                out.append(_nl(body))
            else:
                out.append(re.sub(r"//[^\n\"']*$", "", body) + " ")
            k = end + 2
        else:  # <script runat="server"> … </script>: sınıf üyeleri
            out.append(_nl(tok))
            me = _ASPX_SCRIPT_END.search(text, mk.end())
            end = me.start() if me else n
            count += 1
            out.append(" } " + text[mk.end():end] + " " + _ASPX_OPEN.format(n=count))
            k = me.end() if me else n
    out.append(" } }")
    return "".join(out)


# ---------------------------------------------------------------------------
# Razor (.cshtml) / Blazor (.razor) → C# (satır numaraları korunarak)
# ---------------------------------------------------------------------------
_RAZOR_BLOCK_KEYWORDS = ("if", "foreach", "for", "while", "using", "switch", "lock", "do", "try")
_RAZOR_DIRECTIVES = ("model", "inherits", "using", "page", "inject", "layout", "namespace", "attribute", "implements",
                     "typeparam", "addTagHelper", "removeTagHelper", "tagHelperPrefix", "section", "rendermode",
                     "preservewhitespace")
_RAZOR_CODE_LINE = re.compile(r"^(?:var|if|else|foreach|for|while|switch|case|default|break|continue|return|using|try|"
                              r"catch|finally|do|await|throw|string|int|bool|long|double|decimal|object|dynamic)\b")
_RAZOR_RENDER = "public void __Render{n}() {{ "


def _razor_skip_string(text: str, k: int) -> int:
    """C# dize/karakter sabitinin sonu (k: açılış tırnağı, önünde $ / @ olabilir)."""
    quote = text[k]
    verbatim = k > 0 and text[k - 1] == "@" or k > 1 and text[k - 2:k] in ("$@", "@$")
    j = k + 1
    n = len(text)
    while j < n:
        c = text[j]
        if c == "\\" and not verbatim:
            j += 2
            continue
        if c == quote:
            if verbatim and j + 1 < n and text[j + 1] == quote:
                j += 2
                continue
            return j + 1
        if c == "\n" and not verbatim and quote == "'":
            return j
        j += 1
    return n


def _razor_match(text: str, k: int, end: int) -> int:
    """text[k] açılış parantezi/süslü/köşeli: eşinin konumu (dize ve yorum farkında); bulunamazsa end."""
    pairs = {"(": ")", "{": "}", "[": "]"}
    stack = [pairs[text[k]]]
    j = k + 1
    while j < end:
        c = text[j]
        if c in "\"'":
            j = _razor_skip_string(text, j)
            continue
        if c == "/" and text.startswith("//", j) and text[k] != "(":
            nl = text.find("\n", j)
            j = end if nl < 0 else nl
            continue
        if c == "@" and text.startswith("@*", j):
            close = text.find("*@", j + 2)
            j = end if close < 0 else close + 2
            continue
        if c in pairs:
            stack.append(pairs[c])
        elif c in ")}]":
            if stack and c == stack[-1]:
                stack.pop()
                if not stack:
                    return j
        j += 1
    return end


def _razor_raw_expr(expr: str) -> str:
    """Kaçışsız çıktı ifadesi: Html.Raw(…) / (MarkupString)… / new HtmlString(…) → C# deyimi; diğerleri boş."""
    body = expr.strip()
    if body.startswith("(MarkupString)"):
        return f"Html.Raw({body[len('(MarkupString)'):]}); "
    if "Html.Raw(" in body or "MarkupString(" in body or "HtmlString(" in body:
        return body + "; "
    return ""


class _RazorTranslator:
    def __init__(self, text: str) -> None:
        self.s = text
        self.model = ""
        self.renders = 0

    def markup(self, i: int, j: int) -> str:
        out: list[str] = []
        k = i
        s = self.s
        while k < j:
            p = s.find("@", k, j)
            if p < 0:
                out.append(_nl(s[k:j]))
                break
            out.append(_nl(s[k:p]))
            emitted, k = self.at(p, j)
            out.append(emitted)
        return "".join(out)

    def code(self, i: int, j: int) -> str:
        """Kod bağlamı (@{ … } ve denetim bloklarının gövdesi): satır başı '<' ya da düz metin işaretleme sayılır."""
        s = self.s
        out: list[str] = []
        k = i
        while k < j:
            eol = s.find("\n", k, j)
            line_end = j if eol < 0 else eol + 1
            stripped = s[k:line_end].strip()
            lead = len(s[k:line_end]) - len(s[k:line_end].lstrip())
            if not stripped:
                out.append(_nl(s[k:line_end]))
                k = line_end
                continue
            first = stripped[0]
            if first == "@" or first == "<" or (
                    not _RAZOR_CODE_LINE.match(stripped) and not any(c in stripped for c in ";(){}=")):
                if first == "<":
                    out.append(self.markup(k, line_end))
                    k = line_end
                else:
                    # '@if (…) { … }' çok satıra yayılabilir: '@' işleyicisi bitişe kadar tüketir
                    out.append(_nl(s[k:k + lead]))
                    out.append(self.markup(k + lead, line_end) if first != "@" else "")
                    if first == "@":
                        emitted, nk = self.at(k + lead, j)
                        out.append(emitted)
                        k = max(nk, k + lead + 1)
                        continue
                    k = line_end
                continue
            # C# deyimi: satırın sonuna kadar (dize/parantez farkında) olduğu gibi; satır içi '{' bloğu açarsa
            # gövdesi yine kod bağlamıdır.
            m = k
            while m < line_end:
                c = s[m]
                if c == "/" and s.startswith(("//", "/*"), m):
                    close = (line_end - 1 if s[line_end - 1:line_end] == "\n" else line_end) if s[m + 1] == "/" else \
                        (lambda e: j if e < 0 else e + 2)(s.find("*/", m + 2, j))
                    out.append(_nl(s[m:close]))
                    m = close
                    if m > line_end:
                        line_end = m
                    continue
                if c in "\"'":
                    m2 = _razor_skip_string(s, m)
                    out.append(s[m:m2])
                    m = m2
                    continue
                if c == "{":
                    close = _razor_match(s, m, j)
                    out.append("{" + self.code(m + 1, close) + ("}" if close < j else ""))
                    m = close + 1
                    if m > line_end:
                        line_end = m
                    continue
                if c == "@" and m + 1 < line_end and s[m + 1] in "\"$":
                    out.append(c)
                    m += 1
                    continue
                if c == "<" and m + 1 < line_end and (s[m + 1].isalpha() or s[m + 1] == "/") and \
                        s[k:m].rstrip()[-1:] in ("", ";", "{", "}", ")"):
                    out.append(self.markup(m, line_end))
                    m = line_end
                    break
                out.append(c)
                m += 1
            k = max(m, line_end) if m >= line_end else m
        return "".join(out)

    def block_after(self, k: int, j: int) -> tuple[str, int] | None:
        """k'dan sonra boşluk + '{' bloğu: (çevrilmiş '{…}', blok sonrası konum)."""
        s = self.s
        m = k
        while m < j and s[m] in " \t\r\n":
            m += 1
        if m >= j or s[m] != "{":
            return None
        close = _razor_match(s, m, j)
        return _nl(s[k:m]) + "{" + self.code(m + 1, close) + ("}" if close < j else ""), min(close + 1, j)

    def at(self, p: int, j: int) -> tuple[str, int]:
        s = self.s
        nxt = s[p + 1] if p + 1 < j else ""
        if nxt == "@":
            return "", p + 2
        if nxt == "*":
            close = s.find("*@", p + 2, j)
            end = j if close < 0 else close + 2
            return _nl(s[p:end]), end
        if p > 0 and (s[p - 1].isalnum() or s[p - 1] in "._-"):
            return "", p + 1  # e-posta / öznitelik içi
        if nxt == "{":
            close = _razor_match(s, p + 1, j)
            return " " + self.code(p + 2, close) + " ", min(close + 1, j)
        if nxt == "(":
            close = _razor_match(s, p + 1, j)
            expr = s[p + 2:close]
            raw = _razor_raw_expr(expr)
            return (raw + _nl(expr)[raw.count("\n"):] if raw else _nl(expr)), min(close + 1, j)
        if nxt == ":":
            eol = s.find("\n", p, j)
            end = j if eol < 0 else eol
            return self.markup(p + 2, end), end
        m = re.match(r"[A-Za-z_]\w*", s[p + 1:j])
        if not m:
            return "", p + 1
        word = m.group(0)
        k = p + 1 + len(word)
        line_start = s.rfind("\n", 0, p) + 1
        at_line_start = not s[line_start:p].strip()
        if word in ("code", "functions") and at_line_start:
            blk = self.block_after(k, j)
            if blk is not None:
                m2 = k
                while m2 < j and s[m2] != "{":
                    m2 += 1
                close = _razor_match(s, m2, j)
                self.renders += 1
                body = s[m2 + 1:close]
                return (_nl(s[p:m2]) + " } " + body + " " + _RAZOR_RENDER.format(n=self.renders)), min(close + 1, j)
        if word in _RAZOR_DIRECTIVES and at_line_start and not (word == "using" and s[k:k + 3].lstrip().startswith("(")):
            eol = s.find("\n", k, j)
            end = j if eol < 0 else eol
            arg = s[k:end].strip()
            if word == "model" and arg:
                inner = re.findall(r"[A-Za-z_][\w.]*", arg)
                self.model = inner[-1].rsplit(".", 1)[-1] if inner else ""
            if word == "section":
                # @section Ad { işaretleme } — gövde (aynı ya da sonraki satırda açılan) işaretlemedir
                m2 = k
                while m2 < j and s[m2] != "{" and (s[m2].isalnum() or s[m2] in " \t\r\n_"):
                    m2 += 1
                if m2 < j and s[m2] == "{":
                    close = _razor_match(s, m2, j)
                    return _nl(s[p:m2]) + " " + self.markup(m2 + 1, close) + " ", min(close + 1, j)
            return _nl(s[p:end]), end
        if word in _RAZOR_BLOCK_KEYWORDS:
            out = [word]
            m2 = k
            if word not in ("do", "try"):
                while m2 < j and s[m2] in " \t":
                    m2 += 1
                if m2 < j and s[m2] == "(":
                    close = _razor_match(s, m2, j)
                    out.append(s[k:close + 1])
                    k = close + 1
                else:
                    return "", p + 1
            blk = self.block_after(k, j)
            if blk is None:
                return "".join(out) + " ; ", k
            out.append(blk[0])
            k = blk[1]
            # else / else if / catch / finally / do-while devamları
            while True:
                m3 = k
                while m3 < j and s[m3] in " \t\r\n":
                    m3 += 1
                nxt_word = re.match(r"(else\s+if|else|catch|finally|while)\b", s[m3:j])
                if not nxt_word or (nxt_word.group(1) == "while" and word != "do"):
                    break
                out.append(_nl(s[k:m3]) + nxt_word.group(1))
                k = m3 + len(nxt_word.group(1))
                m4 = k
                while m4 < j and s[m4] in " \t":
                    m4 += 1
                if m4 < j and s[m4] == "(":
                    close = _razor_match(s, m4, j)
                    out.append(s[k:close + 1])
                    k = close + 1
                if nxt_word.group(1) == "while":
                    out.append(";")
                    if k < j and s[k] == ";":
                        k += 1
                    break
                blk = self.block_after(k, j)
                if blk is None:
                    break
                out.append(blk[0])
                k = blk[1]
            return " ".join([out[0]]) + "".join(out[1:]), k
        # Örtük ifade: @a.b(c)[d]?.e — kaçışlı çıktı; yalnız Html.Raw / MarkupString kaçışsız
        if word == "await":
            mm = re.match(r"\s+[A-Za-z_]\w*", s[k:j])
            if mm:
                k += len(mm.group(0))
        while k < j:
            c = s[k]
            if c in "([" :
                close = _razor_match(s, k, j)
                k = close + 1
                continue
            if c == "." and k + 1 < j and (s[k + 1].isalpha() or s[k + 1] == "_"):
                mm = re.match(r"\.[A-Za-z_]\w*", s[k:j])
                k += len(mm.group(0))
                continue
            if c == "?" and s.startswith("?.", k) and k + 2 < j and s[k + 2].isalpha():
                mm = re.match(r"\?\.[A-Za-z_]\w*", s[k:j])
                k += len(mm.group(0))
                continue
            break
        expr = s[p + 1:k]
        raw = _razor_raw_expr(expr)
        return (raw + _nl(expr)[raw.count("\n"):] if raw else _nl(expr)), k


def razor_to_cs(text: str, path: str = "") -> tuple[str, str]:
    """Razor görünümü / Blazor bileşenini analiz edilebilir C#'a çevirir: (C# metni, @model türü).

    * Yalnız kaçışsız çıktılar deyim olur: ``@Html.Raw(x)``, ``@((MarkupString)x)``, ``new HtmlString(x)``;
      ``@x`` / ``@(x)`` Razor tarafından HTML kodlanır (hedef değil).
    * ``@{ … }`` ve ``@if/@foreach/@for/@while/@using/@switch`` blokları C# olarak kalır (gövdedeki işaretleme
      satırları boşaltılır, içlerindeki ``@`` ifadeleri yine işlenir).
    * ``@code``/``@functions`` üyeleri sınıf düzeyine taşınır (JSP ``<%!`` gibi).
    """
    text = text.lstrip("\ufeff")
    tr = _RazorTranslator(text)
    try:
        body = tr.markup(0, len(text))
    except (RecursionError, IndexError, AttributeError):
        body = None
    if body is None or body.count("\n") != text.count("\n"):
        body = _razor_raw_lines(text)  # yapı çözülemedi: satır sadakati için yalnız kaçışsız çıktılar
    name = re.sub(r"\W", "_", path.rsplit("/", 1)[-1].rsplit(".", 1)[0]) or "View"
    head = f"public class __Razor_{name} {{ " + _RAZOR_RENDER.format(n="")
    return head + body + " } }", tr.model


def _razor_raw_lines(text: str) -> str:
    """Yedek çeviri: her satırdaki @Html.Raw(…) / @((MarkupString)…) ifadesi aynı satırda deyim olur."""
    out = []
    for line in text.split("\n"):
        stmts = []
        for m in re.finditer(r"@(\(\(MarkupString\)|Html\.Raw\()", line):
            start = m.start() + 1
            close = _razor_match(line, start + (0 if m.group(1).startswith("((") else len("Html.Raw")), len(line))
            expr = line[start:close + 1]
            if expr.startswith("((MarkupString)"):
                expr = expr[1:-1]
            raw = _razor_raw_expr(expr)
            if raw and "\n" not in raw:
                stmts.append(raw)
        out.append(" ".join(stmts))
    return "\n".join(out)


def _cs_properties(toks: list[Tok], pairs: dict[int, int], cls: ClassInfo, method_ranges: list[tuple[int, int]],
                   classes: list[ClassInfo]) -> None:
    """C# otomatik özellikleri (``[Ek] public Tür Ad { get; set; }``): ad → (tür, ek açıklamalar, satır)."""
    blocked = sorted(method_ranges)
    for k in range(cls.start + 1, cls.end - 1):
        t = toks[k]
        if t.kind != "id" or toks[k + 1].kind != "op" or toks[k + 1].value != "{" or (k + 1) not in pairs:
            continue
        close = pairs[k + 1]
        inner = toks[k + 2:close]
        if not any(x.kind == "id" and x.value in ("get", "set", "init") for x in inner[:6]):
            continue
        if any(lo <= k < hi for lo, hi in blocked):
            continue
        if _enclosing_class(classes, k) is not cls:
            continue  # iç içe sınıfın özelliği
        prev = toks[k - 1]
        if not (prev.kind == "id" or (prev.kind == "op" and prev.value in (">", "?", "]"))):
            continue
        if prev.kind == "id" and prev.value in ("class", "record", "struct", "interface", "enum", "new", "namespace"):
            continue
        typ = prev.value if prev.kind == "id" else ""
        if prev.kind == "op" and prev.value in (">", "?", "]"):
            j = k - 2
            while j > cls.start and not (toks[j].kind == "id" and toks[j - 1].kind in ("id", "op")
                                         and toks[j - 1].value not in ("<", ",", ".")):
                j -= 1
            typ = toks[j].value if toks[j].kind == "id" else ""
        annotations, _mods, _ret = _annotations_before(toks, pairs, k, "csharp")
        cls.props[t.value] = (_simple_type(str(typ)), frozenset(annotations), t.line)


_MINIMAL_API = re.compile(r"^Map(?:Get|Post|Put|Delete|Patch|Methods|Fallback)?$")
# 19. tur: satır içi ara katman (app.Run(async context => …), app.Use(async (ctx, next) => …)): istek HttpContext'ten
# okunur; lambda parametreleri kaynak değildir (context.Request.* kaynak kuralı uygulanır).
_MIDDLEWARE_API = frozenset({"Run", "Use", "UseWhen", "MapWhen"})
_MIDDLEWARE_CTX = frozenset({"context", "ctx", "httpContext", "httpCtx", "c", "http"})


def _cs_minimal_api(toks: list[Tok], pairs: dict[int, int], classes: list[ClassInfo], methods: list[Method]) -> None:
    """ASP.NET Core minimal API: ``app.MapGet("/x", (string q) => …)`` lambda işleyicileri uç nokta yöntemi olur;
    yöntem grubu (``app.MapGet("/x", Handlers.Get)``) adları ``minimalapi_handler`` ile işaretlenir."""
    n = len(toks)
    handler_names: set[str] = set()
    for k in range(1, n - 1):
        t = toks[k]
        if t.kind != "id" or toks[k - 1].kind != "op" or toks[k - 1].value not in (".", "?."):
            continue
        middleware = t.value in _MIDDLEWARE_API
        if not middleware and not _MINIMAL_API.match(t.value):
            continue
        if toks[k + 1].kind != "op" or toks[k + 1].value != "(" or (k + 1) not in pairs:
            continue
        close = pairs[k + 1]
        args = split_top(toks, pairs, k + 2, close, ",")
        if not args or (len(args) < 2 and not middleware):
            continue
        if not middleware:
            first = [x for x in toks[args[0][0]:args[0][1]] if not (x.kind == "id" and x.value in ("pattern",))
                     and not (x.kind == "op" and x.value == ":")]
            if not first or first[0].kind not in ("str", "istr"):
                continue  # rota deseni dize olmalı (AutoMapper .Map(…) vb. değil)
        a, b = args[-1]
        # öznitelikler ([ProducesResponseType(…)]) ve niteleyiciler (async / static)
        while a < b and ((toks[a].kind == "id" and toks[a].value in ("async", "static"))
                         or (toks[a].kind == "op" and toks[a].value == "[" and a in pairs)):
            a = pairs[a] + 1 if toks[a].value == "[" else a + 1
        if a >= b:
            continue
        arrow = next((x for x in range(a, b) if toks[x].kind == "op" and toks[x].value == "=>"), None)
        if arrow is None:
            ids = [x for x in toks[a:b] if x.kind == "id"]
            if ids and all(x.kind == "id" or (x.kind == "op" and x.value == ".") for x in toks[a:b]):
                handler_names.add(ids[-1].value)
            continue
        if toks[a].kind == "op" and toks[a].value == "(" and pairs.get(a) == arrow - 1:
            params = parse_params(toks, pairs, a + 1, arrow - 1, "csharp")
        elif arrow - a == 1 and toks[a].kind == "id":
            params = [Param(toks[a].value, "", frozenset(), toks[a].line)]
        else:
            continue
        if middleware and not (params and (params[0].type in ("HttpContext", "")
                                           and (params[0].type == "HttpContext" or params[0].name in _MIDDLEWARE_CTX))):
            continue  # Task.Run(() => …) vb. değil: ilk parametre HttpContext (context/ctx/httpContext) olmalı
        if arrow + 1 < b and toks[arrow + 1].kind == "op" and toks[arrow + 1].value == "{" and pairs.get(arrow + 1) == b - 1:
            body, expr_body = (arrow + 2, b - 1), False
        else:
            body, expr_body = (arrow + 1, b), True
        cls = _enclosing_class(classes, k)
        methods.append(Method(f"<{t.value}:{t.line}>", cls.name if cls else None, params, body, expr_body, t.line,
                              frozenset({"middleware" if middleware else "minimalapi"}), frozenset({"public"}), ""))
    if handler_names:
        for m in methods:
            if m.name in handler_names:
                m.annotations = m.annotations | {"minimalapi"}


def build_unit(path: str, text: str) -> Unit | None:
    suffix = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
    lang = LANG_BY_SUFFIX.get(suffix)
    if lang is None:
        return None
    if suffix in JSP_SUFFIXES:
        text = jsp_to_java(text)
    view_model = ""
    if suffix in RAZOR_SUFFIXES:
        text, view_model = razor_to_cs(text, path)
    elif suffix in WEBFORMS_SUFFIXES or suffix in HANDLER_SUFFIXES:
        if _ASPX_VB.search(text[:4000]):
            text = _nl(text)  # VB.NET sayfası/işleyicisi: C# motoru çözümlemez (yanlış akış üretmesin)
        elif suffix in WEBFORMS_SUFFIXES:
            text = aspx_to_cs(text, path)
        else:
            text = _ASPX_DIRECTIVE.sub(lambda m: _nl(m.group(0)), text)
    dialect = ""
    if suffix in KOTLIN_SUFFIXES:
        import taint_kotlin

        source = text
        text = taint_kotlin.kotlin_to_java(text)
        dialect = "kotlin"
        if "isExpandEntityReferences" in source:
            text += "\n// setExpandEntityReferences"
        if re.search(r"(?m)^\s*import\s+android\.", source):
            text += "\n// __kt_android"
    toks = tokenize(text, lang)
    pairs = match_pairs(toks)
    classes = _find_classes(toks, pairs, lang)
    methods: list[Method] = []
    if lang == "php":
        _php_methods(toks, pairs, classes, methods)
        _php_route_closures(toks, pairs, classes, methods)
        docs = {m.group(2).lower(): m.group(1) for m in _PHPDOC_RETURN.finditer(text)}
        for m in methods:
            if not m.ret_type and m.name.lower() in docs:
                m.ret_type = docs[m.name.lower()]
    else:
        _c_methods(toks, pairs, classes, methods, lang)
        if lang == "csharp":
            _cs_minimal_api(toks, pairs, classes, methods)
    ranges = [(m.body[0] - 1, m.body[1] + 1) for m in methods]
    for cls in classes:
        _class_fields(toks, pairs, cls, ranges, lang)
        if lang == "csharp":
            _cs_properties(toks, pairs, cls, ranges, classes)
    if suffix in RAZOR_SUFFIXES:
        for m in methods:
            if m.name.startswith("__Render"):
                m.annotations = m.annotations | {"razorrender"}
                m.modifiers = m.modifiers | {"public"}
    flags = set()
    for needle in ("setFeature", "setExpandEntityReferences", "FEATURE_SECURE_PROCESSING", "ACCESS_EXTERNAL_DTD",
                   "enableDefaultTyping", "activateDefaultTyping", "TypeNameHandling", "SimpleEvaluationContext",
                   "setForbidInvokeSecurityRiskMethods", "HttpServletRequest", "SafeConstructor",
                   "LIBXML_NOENT", "XmlResolver", "DtdProcessing.Parse", "Twig_Loader_String", "__kt_android",
                   "SimpleTypeResolver"):
        if needle in text:
            flags.add(needle)
    if lang == "csharp" and re.search(r"TypeNameHandling\s*\.\s*None\b", text) and not re.search(
            r"TypeNameHandling\s*\.\s*(All|Auto|Objects|Arrays)", text):
        flags.discard("TypeNameHandling")
    if lang == "php":
        methods.append(_php_toplevel(toks, pairs, classes, methods))
    return Unit(path, lang, toks, pairs, classes, methods, frozenset(flags), dialect, suffix in RAZOR_SUFFIXES,
                view_model, suffix in WEBFORMS_SUFFIXES)


_PHPDOC_RETURN = re.compile(r"@return\s+([\w\\|?\[\]]+)[^@]*?\*/\s*(?:(?:public|private|protected|static|final|abstract)\s+)*"
                            r"function\s+&?\s*(\w+)", re.S)


def _enclosing_class(classes: list[ClassInfo], k: int) -> ClassInfo | None:
    best = None
    for cls in classes:
        if cls.start < k < cls.end and (best is None or cls.start > best.start):
            best = cls
    return best


def _c_methods(toks: list[Tok], pairs: dict[int, int], classes: list[ClassInfo], methods: list[Method],
               lang: str) -> None:
    n = len(toks)
    not_method = _NOT_METHOD_BY_LANG.get(lang, _NOT_METHOD)
    for k in range(n - 1):
        t = toks[k]
        if t.kind != "id" or toks[k + 1].kind != "op" or toks[k + 1].value != "(" or t.value in not_method:
            continue
        if k > 0:
            p = toks[k - 1]
            if p.kind == "id":
                if p.value in ("new", "return", "await", "throw", "else", "case", "in", "is", "as", "yield", "goto"):
                    continue
            elif p.kind == "op" and p.value in (">", "]", "?"):
                pass
            elif p.kind == "op" and p.value in ("{", "}", ";"):
                cls = _enclosing_class(classes, k)
                if cls is None or cls.name != t.value:  # yalnız niteleyicisiz kurucu
                    continue
            else:
                continue
        close = pairs.get(k + 1)
        if close is None:
            continue
        j = close + 1
        if j < n and toks[j].kind == "id" and toks[j].value == "throws":
            while j < n and not (toks[j].kind == "op" and toks[j].value in ("{", ";")):
                j += 1
        elif j < n and toks[j].kind == "op" and toks[j].value == ":" and lang == "csharp":
            j += 1
            if j + 1 < n and toks[j].kind == "id" and toks[j + 1].value == "(" and (j + 1) in pairs:
                j = pairs[j + 1] + 1
        while j < n and toks[j].kind == "id" and toks[j].value == "where":
            while j < n and not (toks[j].kind == "op" and toks[j].value in ("{", ";", "=>")):
                j += 1
        if j >= n:
            continue
        if toks[j].kind == "op" and toks[j].value == "{" and j in pairs:
            body = (j + 1, pairs[j])
            expr_body = False
        elif toks[j].kind == "op" and toks[j].value == "=>" and lang == "csharp":
            e = j + 1
            while e < n and not (toks[e].kind == "op" and toks[e].value == ";"):
                if toks[e].kind == "op" and toks[e].value in _OPEN and e in pairs:
                    e = pairs[e]
                e += 1
            body = (j + 1, e)
            expr_body = True
        else:
            continue
        annotations, modifiers, ret_type = _annotations_before(toks, pairs, k, lang)
        cls = _enclosing_class(classes, k)
        methods.append(Method(t.value, cls.name if cls else None, parse_params(toks, pairs, k + 2, close, lang), body,
                              expr_body, t.line, frozenset(annotations), frozenset(modifiers), ret_type))


_PHP_ROUTE_VERBS = frozenset({"get", "post", "put", "patch", "delete", "options", "any", "map", "match"})


def _php_route_closures(toks: list[Tok], pairs: dict[int, int], classes: list[ClassInfo], methods: list[Method]) -> None:
    """19. tur: rota kapanışları — ``$app->get('/x', function (Request $r, Response $s, $args) {…})`` (Slim),
    ``Route::get('/x', function (Request $r) {…})`` (Laravel/Lumen), ``$router->post(…, fn(...) => …)``."""
    n = len(toks)
    for k in range(1, n - 2):
        t = toks[k]
        if t.kind != "id" or t.value.lower() not in _PHP_ROUTE_VERBS or toks[k - 1].kind != "op" \
                or toks[k - 1].value not in ("->", "::") or toks[k + 1].value != "(" or (k + 1) not in pairs:
            continue
        close = pairs[k + 1]
        args = split_top(toks, pairs, k + 2, close, ",")
        if len(args) < 2 or toks[args[0][0]].kind not in ("str", "istr"):
            continue
        a, b = args[-1]
        if a < b and toks[a].kind == "id" and toks[a].value.lower() == "static":
            a += 1
        if a + 1 >= b or toks[a].kind != "id" or toks[a].value.lower() not in ("function", "fn") \
                or toks[a + 1].value != "(" or (a + 1) not in pairs:
            continue
        pclose = pairs[a + 1]
        params = parse_params(toks, pairs, a + 2, pclose, "php")
        m = pclose + 1
        if m < b and toks[m].kind == "id" and toks[m].value.lower() == "use" and toks[m + 1].value == "(":
            m = pairs.get(m + 1, m) + 1
        while m < b and toks[m].kind == "op" and toks[m].value == ":" or (m < b and toks[m].kind == "id"
                                                                          and toks[m - 1].value == ":"):
            m += 1
        if m < b and toks[m].kind == "op" and toks[m].value == "{" and m in pairs:
            body, expr_body = (m + 1, pairs[m]), False
        elif m < b and toks[m].kind == "op" and toks[m].value == "=>":
            body, expr_body = (m + 1, b), True
        else:
            continue
        cls = _enclosing_class(classes, k)
        methods.append(Method(f"<route:{t.line}>", cls.name if cls else None, params, body, expr_body, t.line,
                              frozenset({"phproute"}), frozenset({"public"}), ""))


def _php_methods(toks: list[Tok], pairs: dict[int, int], classes: list[ClassInfo], methods: list[Method]) -> None:
    n = len(toks)
    for k in range(n - 2):
        t = toks[k]
        if t.kind != "id" or t.value.lower() != "function":
            continue
        j = k + 1
        if toks[j].kind == "op" and toks[j].value == "&":
            j += 1
        if j >= n or toks[j].kind != "id" or j + 1 >= n or toks[j + 1].value != "(":
            continue  # anonim işlev
        name = toks[j].value
        close = pairs.get(j + 1)
        if close is None:
            continue
        b = close + 1
        ret_type = ""
        if b + 1 < n and toks[b].kind == "op" and toks[b].value == ":":
            ret_type = "|".join(str(t.value) for t in toks[b + 1:b + 6] if t.kind == "id")
        while b < n and not (toks[b].kind == "op" and toks[b].value in ("{", ";")):
            b += 1
        if b >= n or toks[b].value != "{" or b not in pairs:
            continue
        annotations, modifiers, _ret = _annotations_before(toks, pairs, k, "php")
        cls = _enclosing_class(classes, k)
        methods.append(Method(name, cls.name if cls else None, parse_params(toks, pairs, j + 2, close, "php"),
                              (b + 1, pairs[b]), False, toks[j].line, frozenset(annotations), frozenset(modifiers),
                              ret_type))


def _php_toplevel(toks: list[Tok], pairs: dict[int, int], classes: list[ClassInfo], methods: list[Method]) -> Method:
    return Method("<top>", None, [], (0, len(toks)), False, 1, frozenset(), frozenset(), "", toplevel=True)
